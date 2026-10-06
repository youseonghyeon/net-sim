// 메시 VPN (Tailscale·ZeroTier — GL.iNet 의 Tailscale·ZeroTier 앱):
//   1. 조정 서버(Tailscale control·ZeroTier controller)에 로그인 → 내 메시 주소(100.64.x.y / 10.147.17.x)와 피어 목록(netmap: 키·주소·후보 주소·알린 대역)을 받는다.
//      피어가 들어오고 나가거나 후보 주소가 바뀌면 조정 서버가 모두에게 새 netmap 을 밀어 준다
//   2. STUN 으로 "바깥에서 본 내 주소" 를 알아 후보 주소로 알린다
//   3. 피어에게 보낼 것이 생기면: 직접 경로가 없으면 일단 릴레이(DERP·ZeroTier root)로 보내고, 동시에 홀 펀칭 —
//      피어 후보로 disco ping, 릴레이로 call-me-maybe("나에게도 ping 해 줘") → pong 이 오면 그 주소로 직접 (NAT 둘 다 symmetric 이면 릴레이에 남음)
//   4. 서브넷 라우터: 공유기가 LAN 대역을 알리면 다른 기기가 그 대역을 이 공유기로 보낸다. exit node: 인터넷 전부를 그 기기로
//   5. MagicDNS (Tailscale): "이름.tailnet.ts.net"·짧은 이름을 기기 안에서 바로 푼다 (100.100.100.100). ZeroTier 는 DNS 를 주지 않는다
// 줄인 것: 데이터 평면의 WireGuard 핸드셰이크(키는 조정 서버가 나눠 줌 — 여기서는 바로 데이터), 조정 서버 통신의 TLS·Noise(UDP 로 줄임),
// 키 만료·ACL·기기 승인, DERP 지역 선택, ZeroTier 의 L2(이더넷) 성격 — 여기서는 둘 다 IP 만 나른다, 경로 keepalive·재확인
import { sameSubnet, type Ip } from "../addr";
import { STUN_PORT, TS_PORT, ZT_PORT, type Endpoint, type Ipv4Packet, type StunMessage, type TsMessage, type TsPeerInfo, type UdpPacket } from "../packet";
import type { NodeContext } from "./node";
import { STUN_SERVERS } from "./p2p";

export type MeshNet = "tailscale" | "zerotier";
export const TS_TIMER_TAG = "ts";

/** 조정 서버·릴레이 (인터넷 노드가 흉내 — TEST-NET-2) */
export const MESH_SERVERS: Record<MeshNet, { control: Ip; controlPort: number; relay: Ip; relayPort: number; port: number; brand: string; relayName: string; controlName: string }> = {
  tailscale: { control: "198.51.100.70", controlPort: 443, relay: "198.51.100.80", relayPort: 443, port: TS_PORT, brand: "Tailscale", relayName: "DERP", controlName: "조정 서버(control)" },
  zerotier: { control: "198.51.100.71", controlPort: ZT_PORT, relay: "198.51.100.81", relayPort: ZT_PORT, port: ZT_PORT, brand: "ZeroTier", relayName: "root 릴레이", controlName: "네트워크 컨트롤러" },
};

/** 메시 주소 대역 */
export const MESH_SUBNET: Record<MeshNet, { base: string; prefix: number }> = {
  tailscale: { base: "100.64.0", prefix: 10 },
  zerotier: { base: "10.147.17", prefix: 24 },
};

const WAIT = 1500;
const RETRIES = 2;
/** 로그인이 3번 실패한 뒤 다시 시도 (배경 타이머) */
const LOGIN_RETRY = 10_000;
const DISCO_INTERVAL = 200;
const DISCO_TRIES = 5;

export interface MeshConfig {
  enabled: boolean;
  net: MeshNet;
  /** tailnet 이름 (Tailscale) 또는 네트워크 ID 16자리 (ZeroTier) */
  network: string;
  /** 기기 이름 (MagicDNS 이름) */
  name: string;
  /** 노드 키 (장치마다 고정) */
  key: string;
  /** 서브넷 라우터로 알릴 대역 */
  routes: { dest: Ip; prefix: number }[];
  /** exit node 를 내줌 */
  exitNode: boolean;
  /** 쓸 exit node (피어 이름) */
  useExitNode?: string;
}

export const DEFAULT_MESH: MeshConfig = { enabled: false, net: "tailscale", network: "", name: "", key: "", routes: [], exitNode: false };

export interface MeshIo {
  /** 바깥 쪽 내 주소 (호스트는 NIC 주소, 공유기는 WAN) */
  myIp(): Ip | undefined;
  /** 직접 붙은 서브넷인지 */
  local(dst: Ip): boolean;
  send(pkt: Ipv4Packet, ctx: NodeContext): void;
}

interface PeerState {
  info: TsPeerInfo;
  /** 직접 경로 (disco pong 으로 확인한 상대 주소) */
  path?: Endpoint;
  disco?: { txids: number[]; tries: number; tok: number };
  /** 직접 경로를 끝내 못 찾음 (릴레이로 계속) */
  relayOnly?: boolean;
  rx: number;
  tx: number;
  relayed: number;
}

const ep = (e: Endpoint) => `${e.ip}:${e.port}`;
const sameEp = (a: Endpoint | undefined, b: Endpoint | undefined) => !!a && !!b && a.ip === b.ip && a.port === b.port;
const routesLabel = (r: { dest: Ip; prefix: number }[]) => r.map((x) => `${x.dest}/${x.prefix}`).join(", ");

/** 이름 → MagicDNS 레이블 (영문 소문자·숫자·-) */
export function meshHostname(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
}

export class MeshAgent {
  config: MeshConfig = { ...DEFAULT_MESH, routes: [] };
  phase: "off" | "login" | "up" | "denied" = "off";
  denied: string | undefined;
  self: { ip: Ip; prefix: number; name: string } | undefined;
  readonly peers = new Map<string, PeerState>();
  /** 조정 서버에 알린 후보 주소 */
  endpoints: Endpoint[] = [];
  private loginTries = 0;
  private loginTok = 0;
  private stunTx = 0;
  private nextTx: number;
  private tok = 0;

  constructor(
    private readonly io: MeshIo,
    seed: string,
  ) {
    let h = 0x811c9dc5;
    for (const c of `mesh:${seed}`) h = Math.imul(h ^ c.charCodeAt(0), 0x01000193) >>> 0;
    this.nextTx = (h % 0xffff) * 0x100 + 1;
  }

  private get srv() {
    return MESH_SERVERS[this.config.net];
  }

  get brand(): string {
    return this.srv.brand;
  }

  get port(): number {
    return this.srv.port;
  }

  get up(): boolean {
    return this.config.enabled && this.phase === "up" && !!this.self;
  }

  /** 이 메시지가 내 것인가 (UDP 목적지 포트) */
  ownsPort(port: number): boolean {
    return this.config.enabled && port === this.srv.port;
  }

  /** 기다리는 STUN 응답인가 */
  ownsStun(m: StunMessage): boolean {
    return this.config.enabled && m.op === "binding-response" && m.txid === this.stunTx;
  }

  setConfig(cfg: MeshConfig, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.config)) return;
    const prev = this.config;
    const relogin = !cfg.enabled || prev.net !== cfg.net || prev.network !== cfg.network || prev.key !== cfg.key || prev.name !== cfg.name;
    if (prev.enabled && relogin && this.phase === "up") this.logout(ctx, cfg.enabled ? "설정 변경" : "끔");
    this.config = { ...cfg, routes: cfg.routes.map((r) => ({ ...r })) };
    if (!cfg.enabled) {
      this.reset();
      return;
    }
    if (relogin || this.phase !== "up") {
      this.reset();
      ctx.trace("mesh.login", "app", `${this.brand}: ${cfg.net === "zerotier" ? `네트워크 ${cfg.network || "(ID 없음)"}` : `tailnet ${cfg.network || "(없음)"}`} 에 "${cfg.name}" 이름으로 참여${cfg.routes.length ? `, 서브넷 라우터 ${routesLabel(cfg.routes)}` : ""}${cfg.exitNode ? ", exit node 내줌" : ""}${cfg.useExitNode ? `, exit node ${cfg.useExitNode} 사용` : ""}`, { mesh: cfg.net });
      this.login(ctx);
      return;
    }
    // 알린 대역·exit node 만 바뀜: 다시 로그인하지 않고 조정 서버에 알린다
    ctx.trace("mesh.login", "app", `${this.brand}: 알릴 것이 바뀜 (${cfg.routes.length ? `서브넷 ${routesLabel(cfg.routes)}` : "서브넷 없음"}${cfg.exitNode ? ", exit node" : ""}${cfg.useExitNode ? `, exit node ${cfg.useExitNode} 사용` : ""}) → 조정 서버에 알림`, { mesh: cfg.net });
    this.toControl({ kind: "ts", net: cfg.net, op: "endpoints", network: cfg.network, key: cfg.key, endpoints: this.endpoints, routes: cfg.routes, exitNode: cfg.exitNode }, ctx);
  }

  private reset(): void {
    this.phase = "off";
    this.self = undefined;
    this.denied = undefined;
    this.peers.clear();
    this.endpoints = [];
    this.loginTries = 0;
    this.loginTok++;
    this.stunTx = 0;
  }

  /** 주소를 얻음 (DHCP·Probe 끝·WAN 연결) */
  onAddress(ctx: NodeContext): void {
    if (!this.config.enabled || this.phase !== "off" || !this.io.myIp()) return;
    this.login(ctx);
  }

  /** 주소를 잃음: 조정 서버·피어와의 길을 잊는다 (주소를 다시 얻으면 다시 로그인) */
  lost(): void {
    if (!this.config.enabled) return;
    this.phase = "off";
    this.loginTok++;
    for (const p of this.peers.values()) {
      p.path = undefined;
      p.disco = undefined;
      p.relayOnly = undefined;
    }
  }

  private toControl(m: TsMessage, ctx: NodeContext): void {
    const me = this.io.myIp();
    if (!me) return;
    this.io.send({ kind: "ipv4", src: me, dst: this.srv.control, ttl: 64, payload: { kind: "udp", srcPort: this.srv.port, dstPort: this.srv.controlPort, payload: m } }, ctx);
  }

  private toRelay(m: TsMessage, ctx: NodeContext): void {
    const me = this.io.myIp();
    if (!me) return;
    this.io.send({ kind: "ipv4", src: me, dst: this.srv.relay, ttl: 64, payload: { kind: "udp", srcPort: this.srv.port, dstPort: this.srv.relayPort, payload: m } }, ctx);
  }

  private toPeer(to: Endpoint, m: TsMessage, ctx: NodeContext): void {
    const me = this.io.myIp();
    if (!me) return;
    this.io.send({ kind: "ipv4", src: me, dst: to.ip, ttl: 64, payload: { kind: "udp", srcPort: this.srv.port, dstPort: to.port, payload: m } }, ctx);
  }

  private login(ctx: NodeContext): void {
    const me = this.io.myIp();
    if (!me) return;
    const c = this.config;
    this.phase = "login";
    this.loginTries = 1;
    const tok = ++this.loginTok;
    this.endpoints = [{ ip: me, port: this.srv.port }];
    ctx.trace("mesh.login", "app", `${this.brand}: ${this.srv.controlName} ${this.srv.control} 에 로그인 (노드 키 ${c.key.slice(0, 8)}…, 후보 ${me}:${this.srv.port})`, { mesh: c.net });
    this.toControl({ kind: "ts", net: c.net, op: "login", network: c.network, name: c.name, key: c.key, endpoints: this.endpoints, routes: c.routes, exitNode: c.exitNode }, ctx);
    ctx.timer(WAIT, TS_TIMER_TAG, { mesh: "login", tok });
    this.stunTx = 0;
    this.hello(ctx);
  }

  /** 릴레이에 내 키로 자리를 잡고(받을 길), 아직 모르면 STUN 으로 바깥 주소를 알아본다 (로그인을 다시 보낼 때마다 — 앞의 것이 사라졌을 수 있다) */
  private hello(ctx: NodeContext): void {
    const me = this.io.myIp();
    if (!me) return;
    const c = this.config;
    this.toRelay({ kind: "ts", net: c.net, op: "derp-hello", key: c.key }, ctx);
    if (this.endpoints.length > 1) return;
    this.stunTx = this.nextTx++;
    this.io.send({ kind: "ipv4", src: me, dst: STUN_SERVERS[0]!, ttl: 64, payload: { kind: "udp", srcPort: this.srv.port, dstPort: STUN_PORT, payload: { kind: "stun", op: "binding-request", txid: this.stunTx } } }, ctx);
  }

  /** 내 포트로 온 STUN 응답: 바깥 주소를 후보에 더해 조정 서버에 알린다 */
  handleStun(m: StunMessage, ctx: NodeContext, frameId: number): void {
    this.stunTx = 0;
    if (!m.mapped) return;
    const mapped = m.mapped;
    if (this.endpoints.some((e) => sameEp(e, mapped))) {
      ctx.trace("mesh.endpoint", "app", `${this.brand}: STUN 이 본 내 주소 ${ep(mapped)} = 내 주소 (NAT 없음)`, { mesh: this.config.net }, frameId);
      return;
    }
    this.endpoints = [...this.endpoints.filter((e) => this.io.local(e.ip) || e.ip === this.io.myIp()), mapped];
    ctx.trace("mesh.endpoint", "app", `${this.brand}: STUN 이 본 내 바깥 주소 ${ep(mapped)} → 후보 주소로 ${this.srv.controlName}에 알림 (다른 기기가 여기로 직접 보낼 수 있게)`, { mesh: this.config.net }, frameId);
    const c = this.config;
    this.toControl({ kind: "ts", net: c.net, op: "endpoints", network: c.network, key: c.key, endpoints: this.endpoints, routes: c.routes, exitNode: c.exitNode }, ctx);
  }

  /** 내 포트로 온 메시 메시지. 풀린 원래 패킷이면 돌려준다 (목적지는 아직 메시 주소) */
  handle(pkt: Ipv4Packet, udp: UdpPacket, m: TsMessage, ctx: NodeContext, frameId: number): Ipv4Packet | null {
    const c = this.config;
    if (!c.enabled || m.net !== c.net) return null;
    const from: Endpoint = { ip: pkt.src, port: udp.srcPort };
    const fromControl = pkt.src === this.srv.control;
    const fromRelay = pkt.src === this.srv.relay;
    if (fromControl && m.op === "netmap") {
      this.applyNetmap(m, ctx, frameId);
      return null;
    }
    if (fromControl && m.op === "denied") {
      this.phase = "denied";
      this.denied = m.reason ?? "거절됨";
      this.loginTok++;
      ctx.trace("mesh.drop", "app", `${this.brand}: ${this.srv.controlName}가 거절 — ${this.denied}`, { mesh: c.net, failed: true }, frameId);
      return null;
    }
    if (fromRelay && m.op === "derp-recv" && m.msg && m.key) return this.fromPeer(m.key, m.msg, undefined, ctx, frameId);
    if (m.key && (m.op === "disco-ping" || m.op === "disco-pong" || m.op === "data")) return this.fromPeer(m.key, m, from, ctx, frameId);
    ctx.trace("mesh.drop", "app", `${this.brand}: 알 수 없는 메시지 (from ${ep(from)}) → 무시`, { mesh: c.net }, frameId);
    return null;
  }

  private applyNetmap(m: TsMessage, ctx: NodeContext, frameId: number): void {
    const c = this.config;
    const first = this.phase !== "up";
    this.phase = "up";
    this.loginTok++;
    if (m.self) this.self = { ...m.self };
    const seen = new Set<string>();
    for (const info of m.peers ?? []) {
      seen.add(info.key);
      const had = this.peers.get(info.key);
      if (!had) this.peers.set(info.key, { info, rx: 0, tx: 0, relayed: 0 });
      else {
        // 후보 주소가 바뀌면 직접 경로를 다시 찾는다 (상대가 네트워크를 옮김)
        if (JSON.stringify(had.info.endpoints) !== JSON.stringify(info.endpoints) || !info.online) {
          had.path = undefined;
          had.relayOnly = undefined;
          had.disco = undefined;
        }
        had.info = info;
      }
    }
    for (const k of [...this.peers.keys()]) if (!seen.has(k)) this.peers.delete(k);
    const online = [...this.peers.values()].filter((p) => p.info.online);
    ctx.trace(
      "mesh.netmap",
      "app",
      `${this.brand}: netmap ${first ? "받음" : "갱신"} — 내 주소 ${this.self?.ip ?? "?"}, 피어 ${online.length ? online.map((p) => `${p.info.name} ${p.info.ip}${p.info.routes.length ? ` [${routesLabel(p.info.routes)}]` : ""}${p.info.exitNode ? " (exit node)" : ""}`).join(", ") : "없음"}${this.peers.size > online.length ? ` · 오프라인 ${this.peers.size - online.length}` : ""}`,
      { mesh: c.net, peers: online.length },
      frameId,
    );
    if (c.useExitNode && !online.some((p) => p.info.name === c.useExitNode && p.info.exitNode))
      ctx.trace("mesh.drop", "app", `${this.brand}: exit node "${c.useExitNode}" 이(가) netmap 에 없거나 exit node 를 내주지 않음 → 인터넷은 평소처럼`, { mesh: c.net }, frameId);
  }

  private peerByKey(key: string): PeerState | undefined {
    return this.peers.get(key);
  }

  /** 피어가 보낸 것 (직접이면 from 이 그 주소, 릴레이면 undefined) */
  private fromPeer(key: string, m: TsMessage, from: Endpoint | undefined, ctx: NodeContext, frameId: number): Ipv4Packet | null {
    const c = this.config;
    const p = this.peerByKey(key);
    if (!p || !this.self) {
      ctx.trace("mesh.drop", "app", `${this.brand}: netmap 에 없는 노드 키 ${key.slice(0, 8)}… 의 ${m.op} → 무시 (같은 ${c.net === "zerotier" ? "네트워크" : "tailnet"} 의 기기가 아님)`, { mesh: c.net }, frameId);
      return null;
    }
    const via = from ? `직접 ${ep(from)}` : this.srv.relayName;
    if (m.op === "call-me-maybe") {
      ctx.trace("mesh.disco", "app", `${this.brand}: ${p.info.name} 이(가) ${this.srv.relayName}로 call-me-maybe → 그 후보 주소로 나도 disco ping (양쪽이 동시에 보내야 NAT 구멍이 열린다)`, { mesh: c.net }, frameId);
      if (m.endpoints) p.info = { ...p.info, endpoints: m.endpoints };
      if (!p.path) this.startDisco(p, ctx, false);
      return null;
    }
    if (m.op === "disco-ping" && from) {
      ctx.trace("mesh.disco", "app", `${this.brand}: ${p.info.name} 의 disco ping 이 ${ep(from)} 에서 직접 옴 → pong (그 주소로 직접 닿는다)`, { mesh: c.net }, frameId);
      this.toPeer(from, { kind: "ts", net: c.net, op: "disco-pong", key: c.key, txid: m.txid ?? 0, seen: from }, ctx);
      this.setPath(p, from, ctx, frameId);
      return null;
    }
    if (m.op === "disco-pong" && from) {
      if (!p.disco?.txids.includes(m.txid ?? -1) && sameEp(p.path, from)) return null;
      this.setPath(p, from, ctx, frameId);
      return null;
    }
    if (m.op === "data" && m.inner) {
      const inner = m.inner;
      const okSrc = inner.src === p.info.ip || p.info.routes.some((r) => sameSubnet(inner.src, r.dest, r.prefix)) || p.info.exitNode;
      if (!okSrc) {
        ctx.trace("mesh.drop", "L3", `${this.brand}: ${p.info.name} 에게서 온 패킷의 출발지 ${inner.src} 는 그 기기의 주소·알린 대역이 아님 → 드롭`, { mesh: c.net }, frameId);
        return null;
      }
      p.rx++;
      // 직접 받은 데이터: 상대 주소가 바뀌었으면 따라간다 (로밍)
      if (from && !sameEp(p.path, from)) p.path = from;
      ctx.trace("mesh.decap", "L3", `${this.brand}: ${p.info.name} 에게서 (${via}) ${inner.src} → ${inner.dst} 를 꺼냄`, { mesh: c.net }, frameId);
      return inner;
    }
    return null;
  }

  private setPath(p: PeerState, at: Endpoint, ctx: NodeContext, frameId?: number): void {
    const had = p.path;
    p.path = at;
    p.relayOnly = undefined;
    if (p.disco) p.disco = undefined;
    if (!sameEp(had, at))
      ctx.trace("mesh.direct", "app", `${this.brand}: ${p.info.name} 과(와) 직접 경로 ${ep(at)} 확인 → 이제 ${this.srv.relayName}를 거치지 않고 바로 보냄 (홀 펀칭 성공)`, { mesh: this.config.net, peer: p.info.name }, frameId);
  }

  /** 홀 펀칭: 상대 후보로 disco ping 을 여러 번 (callMe 면 릴레이로 call-me-maybe 도) */
  private startDisco(p: PeerState, ctx: NodeContext, callMe: boolean): void {
    const c = this.config;
    if (p.disco) return;
    const tok = ++this.tok;
    p.disco = { txids: [], tries: 0, tok };
    if (callMe) this.toRelay({ kind: "ts", net: c.net, op: "derp-send", key: c.key, to: p.info.key, msg: { kind: "ts", net: c.net, op: "call-me-maybe", key: c.key, endpoints: this.endpoints } }, ctx);
    this.discoRound(p, ctx);
  }

  /** 시도할 후보: 상대 바깥 주소, 그리고 같은 LAN 이면 상대 LAN 주소 (다른 집의 사설 주소로는 보내지 않는다) */
  private candidates(p: PeerState): Endpoint[] {
    return p.info.endpoints.filter((e) => this.io.local(e.ip) || !isPrivate(e.ip));
  }

  private discoRound(p: PeerState, ctx: NodeContext): void {
    const c = this.config;
    const d = p.disco!;
    d.tries++;
    const cands = this.candidates(p);
    for (const e of cands) {
      const txid = this.nextTx++;
      d.txids.push(txid);
      this.toPeer(e, { kind: "ts", net: c.net, op: "disco-ping", key: c.key, txid }, ctx);
    }
    if (d.tries === 1) ctx.trace("mesh.disco", "app", `${this.brand}: ${p.info.name} 의 후보 ${cands.map(ep).join(", ") || "(없음)"} 로 disco ping (홀 펀칭 시작)`, { mesh: c.net });
    ctx.timer(DISCO_INTERVAL, TS_TIMER_TAG, { mesh: "disco", key: p.info.key, tok: d.tok });
  }

  /** 이 목적지를 맡을 피어 (메시 주소 → 알린 대역 중 가장 긴 것 → exit node) */
  route(dst: Ip): PeerState | undefined {
    if (!this.up) return undefined;
    const online = [...this.peers.values()].filter((p) => p.info.online);
    const exact = online.find((p) => p.info.ip === dst);
    if (exact) return exact;
    let best: PeerState | undefined;
    let bestLen = -1;
    for (const p of online)
      for (const r of p.info.routes)
        if (r.prefix > bestLen && sameSubnet(dst, r.dest, r.prefix)) {
          best = p;
          bestLen = r.prefix;
        }
    if (best) return best;
    const exit = this.config.useExitNode;
    if (exit) return online.find((p) => p.info.name === exit && p.info.exitNode);
    return undefined;
  }

  /** 메시 대역 안인가 (내 주소 대역) */
  inMesh(dst: Ip): boolean {
    return this.up && sameSubnet(dst, this.self!.ip, this.self!.prefix);
  }

  /** 피어에게 보낸다: 직접 경로가 있으면 바로, 없으면 릴레이로 보내고 홀 펀칭을 시작 */
  send(p: PeerState, inner: Ipv4Packet, ctx: NodeContext, frameId?: number): void {
    const c = this.config;
    const data: TsMessage = { kind: "ts", net: c.net, op: "data", key: c.key, inner };
    p.tx++;
    if (p.path) {
      ctx.trace("mesh.encap", "L3", `${this.brand}: ${inner.src} → ${inner.dst} 를 ${p.info.name} 에게 직접 (${ep(p.path)})`, { mesh: c.net, direct: true }, frameId);
      this.toPeer(p.path, data, ctx);
      return;
    }
    p.relayed++;
    ctx.trace("mesh.encap", "L3", `${this.brand}: ${inner.src} → ${inner.dst} 를 ${p.info.name} 에게 — 직접 경로가 아직 없어 ${this.srv.relayName}(${this.srv.relay})로${!p.relayOnly && !p.disco ? ", 동시에 홀 펀칭 시작" : ""}`, { mesh: c.net, direct: false }, frameId);
    this.toRelay({ kind: "ts", net: c.net, op: "derp-send", key: c.key, to: p.info.key, msg: data }, ctx);
    if (!p.relayOnly) this.startDisco(p, ctx, true);
  }

  /** 기기(호스트)가 내보낼 패킷: 메시로 갈 목적지면 출발지를 메시 주소로 바꿔 보낸다. 가로챘으면 true */
  intercept(pkt: Ipv4Packet, ctx: NodeContext): boolean {
    if (!this.up) return false;
    const p0 = pkt.payload;
    if (p0.kind === "udp" && (p0.payload.kind === "ts" || p0.payload.kind === "dhcp" || p0.payload.kind === "stun")) return false;
    if (pkt.dst === "255.255.255.255" || this.io.local(pkt.dst)) return false;
    const s = this.srv;
    if (pkt.dst === s.control || pkt.dst === s.relay || STUN_SERVERS.includes(pkt.dst)) return false;
    const peer = this.route(pkt.dst);
    if (!peer) return false;
    // 피어의 바깥 주소로 가는 것(터널 자신)은 터널로 넣지 않는다
    if (peer.info.endpoints.some((e) => e.ip === pkt.dst) && pkt.dst !== peer.info.ip) return false;
    this.send(peer, { ...pkt, src: this.self!.ip }, ctx);
    return true;
  }

  /** MagicDNS: 피어 이름 (짧은 이름, 이름.tailnet.ts.net). ZeroTier 는 DNS 가 없다 */
  resolve(name: string): Ip | undefined {
    if (!this.up || this.config.net !== "tailscale") return undefined;
    const n = name.trim().toLowerCase().replace(/\.$/, "");
    const suffix = `.${meshHostname(this.config.network)}.ts.net`;
    const short = n.endsWith(suffix) ? n.slice(0, -suffix.length) : n.includes(".") ? undefined : n;
    if (!short) return undefined;
    if (short === meshHostname(this.config.name)) return this.self!.ip;
    return [...this.peers.values()].find((p) => p.info.online && meshHostname(p.info.name) === short)?.info.ip;
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const d = data as { mesh?: string; tok?: number; key?: string };
    const c = this.config;
    if (d.mesh === "login" || d.mesh === "login-bg") {
      if (d.tok !== this.loginTok || this.phase !== "login") return;
      if (d.mesh === "login" && this.loginTries <= RETRIES) {
        this.loginTries++;
        ctx.trace("mesh.login", "app", `${this.brand}: ${this.srv.controlName} 응답 없음 → 다시 로그인 (${this.loginTries}/${RETRIES + 1})`, { mesh: c.net });
        this.toControl({ kind: "ts", net: c.net, op: "login", network: c.network, name: c.name, key: c.key, endpoints: this.endpoints, routes: c.routes, exitNode: c.exitNode }, ctx);
        this.hello(ctx);
        ctx.timer(WAIT, TS_TIMER_TAG, { mesh: "login", tok: d.tok });
        return;
      }
      if (d.mesh === "login") ctx.trace("mesh.drop", "app", `${this.brand}: ${this.srv.controlName} ${this.srv.control} 에 닿지 않음 (응답 없음) — 인터넷 연결을 확인. ${LOGIN_RETRY / 1000}초마다 다시 시도 (시간이 흐를 때만)`, { mesh: c.net, failed: true });
      else {
        ctx.trace("mesh.login", "app", `${this.brand}: 다시 로그인 시도`, { mesh: c.net });
        this.toControl({ kind: "ts", net: c.net, op: "login", network: c.network, name: c.name, key: c.key, endpoints: this.endpoints, routes: c.routes, exitNode: c.exitNode }, ctx);
        this.hello(ctx);
      }
      ctx.timer(LOGIN_RETRY, TS_TIMER_TAG, { mesh: "login-bg", tok: d.tok }, true);
      return;
    }
    if (d.mesh === "disco" && d.key) {
      const p = this.peers.get(d.key);
      if (!p?.disco || p.disco.tok !== d.tok) return;
      if (p.disco.tries >= DISCO_TRIES) {
        p.disco = undefined;
        p.relayOnly = true;
        ctx.trace("mesh.relay", "app", `${this.brand}: ${p.info.name} 과(와) 직접 경로를 찾지 못함 (disco ping ${DISCO_TRIES}번에 pong 없음 — 양쪽 NAT 가 직접 받지 않음, 대개 한쪽이 symmetric) → ${this.srv.relayName}로 계속 (느리지만 늘 된다)`, { mesh: c.net, peer: p.info.name });
        return;
      }
      this.discoRound(p, ctx);
    }
  }

  /** 끔·제거: 조정 서버에 로그아웃을 알린다 */
  logout(ctx: NodeContext, why: string): void {
    if (this.phase !== "up") return;
    const c = this.config;
    ctx.trace("mesh.login", "app", `${this.brand}: 로그아웃 (${why}) → ${this.srv.controlName}가 다른 기기에 오프라인으로 알림`, { mesh: c.net });
    this.toControl({ kind: "ts", net: c.net, op: "logout", network: c.network, key: c.key }, ctx);
  }

  summary(): string | undefined {
    if (!this.config.enabled) return undefined;
    if (this.phase === "denied") return `거절 · ${this.denied ?? ""}`;
    if (this.phase !== "up" || !this.self) return this.phase === "login" ? "로그인 중" : "대기 (주소를 받으면 로그인)";
    const online = [...this.peers.values()].filter((p) => p.info.online);
    const direct = online.filter((p) => p.path).length;
    return `연결됨 · ${this.self.ip} · 피어 ${online.length}${online.length ? ` (직접 ${direct} · 릴레이 ${online.length - direct})` : ""}${this.config.useExitNode ? ` · exit node ${this.config.useExitNode}` : ""}`;
  }

  rows(): string[][] {
    return [...this.peers.values()].map((p) => [
      p.info.name,
      p.info.ip,
      p.info.online ? (p.path ? `직접 ${ep(p.path)}` : p.relayOnly ? `${this.srv.relayName} (직접 실패)` : `${this.srv.relayName}`) : "오프라인",
      [...p.info.routes.map((r) => `${r.dest}/${r.prefix}`), ...(p.info.exitNode ? ["exit node"] : [])].join(", ") || "—",
      `보냄 ${p.tx} · 받음 ${p.rx}${p.relayed ? ` · 릴레이 ${p.relayed}` : ""}`,
    ]);
  }
}

function isPrivate(ip: Ip): boolean {
  const [a, b] = ip.split(".").map(Number) as [number, number];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

// ---------- 조정 서버·릴레이 (인터넷 노드) ----------

interface NodeRec {
  name: string;
  key: string;
  ip: Ip;
  endpoints: Endpoint[];
  routes: { dest: Ip; prefix: number }[];
  exitNode: boolean;
  online: boolean;
  /** 조정 서버가 netmap 을 밀어 줄 곳 (로그인한 출발지) */
  ctl: Endpoint;
}

export interface MeshServerIo {
  send(src: Ip, srcPort: number, to: Endpoint, m: TsMessage, ctx: NodeContext): void;
}

export class MeshCoordinator {
  /** "net:network" → 기기 */
  readonly nets = new Map<string, { nodes: Map<string, NodeRec>; next: number }>();
  /** 릴레이: "net:key" → 그 기기의 릴레이 연결 주소 */
  readonly relays = new Map<string, Endpoint>();

  constructor(private readonly io: MeshServerIo) {}

  /** 조정 서버·릴레이 주소로 온 메시 메시지. 처리했으면 true */
  handle(pkt: Ipv4Packet, udp: UdpPacket, m: TsMessage, ctx: NodeContext, frameId: number): boolean {
    const s = MESH_SERVERS[m.net];
    const from: Endpoint = { ip: pkt.src, port: udp.srcPort };
    if (pkt.dst === s.control && udp.dstPort === s.controlPort) {
      this.control(m, from, ctx, frameId);
      return true;
    }
    if (pkt.dst === s.relay && udp.dstPort === s.relayPort) {
      this.relay(m, from, ctx, frameId);
      return true;
    }
    return false;
  }

  private control(m: TsMessage, from: Endpoint, ctx: NodeContext, frameId: number): void {
    const s = MESH_SERVERS[m.net];
    const network = (m.network ?? "").trim();
    const deny = (reason: string) => {
      ctx.trace("mesh.control", "app", `${s.brand} ${s.controlName}: ${m.name ?? "?"} 의 로그인 거절 — ${reason}`, { mesh: m.net }, frameId);
      this.io.send(s.control, s.controlPort, from, { kind: "ts", net: m.net, op: "denied", reason }, ctx);
    };
    if (m.op === "login") {
      if (!network) return deny(m.net === "zerotier" ? "네트워크 ID 가 비어 있음" : "tailnet(계정)이 비어 있음 — 로그인할 계정이 없다");
      if (m.net === "zerotier" && !/^[0-9a-f]{16}$/i.test(network)) return deny(`네트워크 ID "${network}" 가 16자리 16진수가 아님 — 그런 네트워크 없음`);
      const net = this.netOf(m.net, network);
      let rec = net.nodes.get(m.key ?? "");
      const prefix = MESH_SUBNET[m.net];
      if (!rec) {
        const n = net.next++;
        const ip = m.net === "tailscale" ? `100.64.${Math.floor(n / 254)}.${(n % 254) + 1}` : `${prefix.base}.${n + 1}`;
        // 같은 이름이 이미 있으면 뒤에 -1 을 붙인다 (Tailscale 의 기기 이름 규칙)
        let name = m.name ?? "device";
        if ([...net.nodes.values()].some((x) => meshHostname(x.name) === meshHostname(name))) name = `${name}-1`;
        rec = { name, key: m.key ?? "", ip, endpoints: [], routes: [], exitNode: false, online: true, ctl: from };
        net.nodes.set(rec.key, rec);
      }
      rec.online = true;
      rec.ctl = from;
      rec.endpoints = m.endpoints ?? [];
      rec.routes = m.routes ?? [];
      rec.exitNode = m.exitNode === true;
      ctx.trace("mesh.control", "app", `${s.brand} ${s.controlName}: ${rec.name} 로그인 (${network}) → 주소 ${rec.ip} · 이 ${m.net === "zerotier" ? "네트워크" : "tailnet"} 의 모든 기기에 새 netmap`, { mesh: m.net, ip: rec.ip }, frameId);
      this.push(m.net, network, ctx);
      return;
    }
    const net = this.nets.get(`${m.net}:${network}`);
    const rec = net?.nodes.get(m.key ?? "");
    if (!net || !rec) {
      ctx.trace("mesh.control", "app", `${s.brand} ${s.controlName}: 로그인하지 않은 키의 ${m.op} → 무시`, { mesh: m.net }, frameId);
      return;
    }
    if (m.op === "logout") {
      rec.online = false;
      ctx.trace("mesh.control", "app", `${s.brand} ${s.controlName}: ${rec.name} 로그아웃 → 다른 기기에 오프라인으로 알림`, { mesh: m.net }, frameId);
      this.push(m.net, network, ctx);
      return;
    }
    if (m.op === "endpoints") {
      const next = { endpoints: m.endpoints ?? rec.endpoints, routes: m.routes ?? rec.routes, exitNode: m.exitNode ?? rec.exitNode };
      rec.ctl = from;
      if (JSON.stringify(next) === JSON.stringify({ endpoints: rec.endpoints, routes: rec.routes, exitNode: rec.exitNode })) return;
      Object.assign(rec, next);
      ctx.trace("mesh.control", "app", `${s.brand} ${s.controlName}: ${rec.name} 의 후보 주소·알린 대역 갱신 (${rec.endpoints.map(ep).join(", ")}${rec.routes.length ? ` · ${routesLabel(rec.routes)}` : ""}${rec.exitNode ? " · exit node" : ""}) → 새 netmap`, { mesh: m.net }, frameId);
      this.push(m.net, network, ctx);
    }
  }

  private netOf(netKind: MeshNet, network: string) {
    const k = `${netKind}:${network}`;
    let n = this.nets.get(k);
    if (!n) {
      n = { nodes: new Map(), next: 0 };
      this.nets.set(k, n);
    }
    return n;
  }

  /** 온라인인 모든 기기에 각자의 netmap 을 밀어 준다 */
  private push(netKind: MeshNet, network: string, ctx: NodeContext): void {
    const s = MESH_SERVERS[netKind];
    const net = this.nets.get(`${netKind}:${network}`);
    if (!net) return;
    const prefix = netKind === "tailscale" ? 10 : MESH_SUBNET.zerotier.prefix;
    for (const rec of net.nodes.values()) {
      if (!rec.online) continue;
      const peers: TsPeerInfo[] = [...net.nodes.values()].filter((x) => x !== rec).map((x) => ({ name: x.name, key: x.key, ip: x.ip, endpoints: x.endpoints.map((e) => ({ ...e })), routes: x.routes.map((r) => ({ ...r })), exitNode: x.exitNode, online: x.online }));
      this.io.send(s.control, s.controlPort, rec.ctl, { kind: "ts", net: netKind, op: "netmap", network, self: { ip: rec.ip, prefix, name: rec.name }, peers }, ctx);
    }
  }

  private relay(m: TsMessage, from: Endpoint, ctx: NodeContext, frameId: number): void {
    const s = MESH_SERVERS[m.net];
    if (m.op === "derp-hello" && m.key) {
      this.relays.set(`${m.net}:${m.key}`, from);
      ctx.trace("mesh.relay", "app", `${s.brand} ${s.relayName}: 노드 키 ${m.key.slice(0, 8)}… 이(가) ${ep(from)} 에서 접속 — 이 키로 오는 것은 여기로 전해 준다`, { mesh: m.net }, frameId);
      return;
    }
    if (m.op === "derp-send" && m.to && m.msg && m.key) {
      // 보낸 기기의 연결도 새로 고친다 (NAT 매핑이 바뀌었어도 지금 보낸 길로)
      this.relays.set(`${m.net}:${m.key}`, from);
      const to = this.relays.get(`${m.net}:${m.to}`);
      if (!to) {
        ctx.trace("mesh.relay", "app", `${s.brand} ${s.relayName}: 받을 키 ${m.to.slice(0, 8)}… 의 기기가 릴레이에 접속해 있지 않음 → 드롭 (그 기기가 꺼졌거나 인터넷에 닿지 않음)`, { mesh: m.net }, frameId);
        return;
      }
      ctx.trace("mesh.relay", "app", `${s.brand} ${s.relayName}: ${m.key.slice(0, 8)}… → ${m.to.slice(0, 8)}… (${ep(to)}) 에게 전해 줌 — 내용은 암호화돼 모른다`, { mesh: m.net }, frameId);
      this.io.send(s.relay, s.relayPort, to, { kind: "ts", net: m.net, op: "derp-recv", key: m.key, msg: m.msg }, ctx);
      return;
    }
    ctx.trace("mesh.relay", "app", `${s.brand} ${s.relayName}: 알 수 없는 메시지 → 드롭`, { mesh: m.net }, frameId);
  }

  /** 상태 표 */
  rows(): string[][] {
    const out: string[][] = [];
    for (const [k, net] of this.nets) for (const r of net.nodes.values()) out.push([k.replace(":", " · "), r.name, r.ip, r.online ? "온라인" : "오프라인", r.endpoints.map(ep).join(", ") || "—"]);
    return out;
  }
}
