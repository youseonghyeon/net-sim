// OpenVPN (GL.iNet 의 OpenVPN 서버·클라이언트 앱): TLS 로 서로의 인증서를 확인하는 VPN.
// 학습 포인트:
// - PKI: 서버가 만든 CA 가 서버·클라이언트 인증서를 발급한다. 서로 상대 인증서가 "내가 믿는 CA" 의 서명인지 본다
//   (WireGuard 는 공개 키를 서로 적어 두는 방식). 한 명을 막으려면 그 인증서만 폐기(CRL) — CA·다른 사람은 그대로
// - tls-crypt: 제어 채널을 미리 나눈 키로 감싼다. 키가 없는 사람의 패킷에는 아예 답하지 않는다(포트 스캔에 보이지 않음)
// - PUSH: 서버가 가상 주소(ifconfig)·경로(route)·DNS·"전부 터널로"(redirect-gateway)를 내려 준다 (WireGuard 는 설정 파일에 적어 둔다)
// - 전송: UDP(기본 1194) 또는 TCP — TCP 443 은 "웹만 열어 둔" 방화벽을 지나간다. 그래도 DPI 는 모양(opcode)으로 알아본다
// 축소: TLS 는 메시지 세 번(ClientHello → 서버 인증서 → 클라이언트 인증서·계정 → 결과)으로, 데이터 채널 키 교환·재협상(reneg-sec)·
// 압축·tls-auth(HMAC 만)·TAP(브리지)·client-to-client·서버의 ping-restart 는 생략. TCP 모드의 TCP 는 이 모듈이 직접 흉내 낸다
// (3-way 핸드셰이크·seq/ack·FIN·RST — 재전송은 OpenVPN 제어 메시지의 재전송으로 대신, 순수 ACK 는 데이터에 얹음)
import { sameSubnet, type Ip } from "../addr";
import { OVPN_PORT, ovpnLength, type Ipv4Packet, type OvpnMessage, type TcpSegment, type UdpPacket } from "../packet";
import type { NodeContext } from "./node";
import { DEFAULT_RA_CLIENT, type RaClientConfig, type RaClientState } from "./ravpn";

export { OVPN_PORT };
export const OVPN_TIMER_TAG = "ovpn-timer";
/** 제어 메시지 재전송 간격과 횟수 (처음 + 2번) */
const OVPN_RETRY = 1000;
const OVPN_TRIES = 3;
/** keepalive 10 60: 10초 동안 보낸 게 없으면 ping, 60초 동안 받은 게 없으면 다시 연결 (ping-restart) */
export const OVPN_PING = 10_000;
export const OVPN_PING_RESTART = 60_000;
/** 서버가 다시 시작했다고 알려 오면 이만큼 뒤 다시 연결 (connect-retry) */
const OVPN_RECONNECT = 2000;

function fnv(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h || 1;
}

function hex(seed: string, bytes: number): string {
  let x = fnv(seed);
  const out: string[] = [];
  for (let i = 0; i < bytes; i++) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    out.push((x & 0xff).toString(16).padStart(2, "0").toUpperCase());
  }
  return out.join(":");
}

/** 서버가 만든 CA 의 지문 (SHA-256 지문 흉내 — 앞 8바이트). 장치마다 고정 */
export function ovpnCaOf(seed: string): string {
  return hex(`ovpn-ca:${seed}`, 8);
}

/** tls-crypt 키의 지문 (실제는 2048비트 정적 키 — 서버·클라이언트가 같은 파일을 가진다) */
export function ovpnTlsCryptOf(seed: string): string {
  return hex(`ovpn-tls-crypt:${seed}`, 6);
}

export function shortFp(fp: string): string {
  return fp.length > 11 ? `${fp.slice(0, 11)}…` : fp;
}

export type OvpnProto = "udp" | "tcp";

export interface OvpnServerConfig {
  enabled: boolean;
  proto: OvpnProto;
  port: number;
  /** 이 서버의 CA 지문 (서버 인증서·클라이언트 인증서를 발급한 CA) */
  ca: string;
  /** 터널 대역 (서버는 첫 주소, 클라이언트는 그다음부터) */
  subnet?: { ip: Ip; prefix: number };
  /** push "route <LAN>" + 집 LAN 으로 넘겨 줌 */
  lanAccess: boolean;
  /** push "redirect-gateway def1" — 클라이언트의 모든 트래픽을 터널로 */
  redirectGateway: boolean;
  /** push "dhcp-option DNS <서버 터널 주소>" */
  pushDns: boolean;
  /** tls-crypt 키 지문 (없으면 tls-crypt 안 씀) */
  tlsCrypt?: string;
  /** auth-user-pass 계정 (비면 인증서만) */
  users: { name: string; password: string }[];
  /** 폐기한 인증서의 CN (CRL) */
  revoked: string[];
}

export const DEFAULT_OVPN_SERVER: OvpnServerConfig = { enabled: false, proto: "udp", port: OVPN_PORT, ca: "", lanAccess: true, redirectGateway: false, pushDns: true, users: [], revoked: [] };

/** 노트북·폰의 OpenVPN 앱 설정 (.ovpn 파일 한 장: remote·proto·<ca>·<cert>·<tls-crypt>) */
export interface OvpnClientFields {
  proto: OvpnProto;
  port: number;
  /** <ca> — 믿는 CA 의 지문 (서버 인증서를 이것으로 확인) */
  ca: string;
  /** <cert> — 내 인증서 (CN 과 발급한 CA) */
  cert: { cn: string; ca: string };
  /** <tls-crypt> 키 지문 (없으면 안 씀) */
  tlsCrypt?: string;
}

/** 장치에게서 빌리는 것: 바깥 주소와 바깥 패킷 송신 (NAT 하지 않음) */
export interface OvpnServerIo {
  /** 바깥 출발지 (지금 쓰는 WAN 주소) */
  source(): Ip | undefined;
  send(outer: Ipv4Packet, ctx: NodeContext, frameId?: number): void;
  lan(): { ip: Ip; prefix: number } | undefined;
}

type Phase = "syn" | "reset" | "tls" | "auth" | "up" | "failed";

interface TcpState {
  /** 내가 보낼 다음 seq */
  snd: number;
  /** 상대에게서 기대하는 다음 seq */
  rcv: number;
  established: boolean;
  /** FIN 을 보냈음 */
  finSent?: boolean;
}

export interface OvpnSession {
  key: string;
  sid: number;
  peer: { ip: Ip; port: number };
  proto: OvpnProto;
  phase: Phase;
  cn?: string;
  user?: string;
  vip?: Ip;
  /** 요청 종류 → 마지막으로 보낸 답 (같은 요청이 다시 오면 그대로 다시 보낸다 — 답이 사라졌을 때) */
  replies: Map<OvpnMessage["op"], OvpnMessage>;
  rxBytes: number;
  txBytes: number;
  since: number;
  failed?: string;
  tcp?: TcpState;
}

const OP_LABEL: Record<OvpnMessage["op"], string> = {
  "reset-client": "P_CONTROL_HARD_RESET_CLIENT_V2",
  "reset-server": "P_CONTROL_HARD_RESET_SERVER_V2",
  "tls-client": "TLS ClientHello",
  "tls-server": "TLS ServerHello·서버 인증서",
  "tls-auth": "TLS 클라이언트 인증서·계정",
  "tls-ok": "TLS 완료",
  "tls-fail": "TLS 실패",
  "push-request": "PUSH_REQUEST",
  "push-reply": "PUSH_REPLY",
  data: "데이터",
  ping: "ping",
  exit: "EXIT",
};

function addrAt(net: { ip: Ip; prefix: number }, n: number): Ip {
  const parts = net.ip.split(".").map(Number);
  const v = ((((parts[0]! << 24) >>> 0) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0) & (net.prefix === 0 ? 0 : (0xffffffff << (32 - net.prefix)) >>> 0);
  const x = (v + n) >>> 0;
  return [x >>> 24, (x >>> 16) & 255, (x >>> 8) & 255, x & 255].join(".");
}

const maskOf = (prefix: number) => {
  const m = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return [m >>> 24, (m >>> 16) & 255, (m >>> 8) & 255, m & 255].join(".");
};

/** PUSH_REPLY 의 실제 문자열 (openvpn 로그의 모양) */
export function pushText(p: NonNullable<OvpnMessage["push"]>): string {
  return [
    ...(p.redirectGateway ? ["redirect-gateway def1"] : []),
    ...p.routes.map((r) => `route ${r.dest} ${maskOf(r.prefix)}`),
    ...(p.dns ? [`dhcp-option DNS ${p.dns}`] : []),
    `route-gateway ${addrAt({ ip: p.ip, prefix: p.prefix }, 1)}`,
    "topology subnet",
    "ping 10",
    "ping-restart 60",
    `ifconfig ${p.ip} ${maskOf(p.prefix)}`,
  ].join(",");
}

/** 바깥 패킷 (UDP 또는 TCP 세그먼트) */
function outerPacket(src: Ip, dst: Ip, proto: OvpnProto, sport: number, dport: number, m: OvpnMessage, tcp?: TcpState): Ipv4Packet {
  const len = ovpnLength(m, m.inner ? 84 : 0);
  if (proto === "udp") return { kind: "ipv4", src, dst, ttl: 64, payload: { kind: "udp", srcPort: sport, dstPort: dport, payload: m } as UdpPacket };
  const seg: TcpSegment = { kind: "tcp", srcPort: sport, dstPort: dport, seq: tcp!.snd, ack: tcp!.rcv, ackFlag: true, len: len + 2, ovpn: m };
  tcp!.snd += len + 2;
  return { kind: "ipv4", src, dst, ttl: 64, payload: seg };
}

function tcpFlag(src: Ip, dst: Ip, sport: number, dport: number, tcp: TcpState, flags: Partial<Pick<TcpSegment, "syn" | "fin" | "rst" | "ackFlag">>): Ipv4Packet {
  const seg: TcpSegment = { kind: "tcp", srcPort: sport, dstPort: dport, seq: tcp.snd, ack: tcp.rcv, len: 0, ...flags };
  if (flags.syn || flags.fin) tcp.snd += 1;
  return { kind: "ipv4", src, dst, ttl: 64, payload: seg };
}

// ---------- 서버 (공유기) ----------

export class OvpnServer {
  config: OvpnServerConfig = { ...DEFAULT_OVPN_SERVER, users: [], revoked: [] };
  /** "주소:포트" → 세션 */
  readonly sessions = new Map<string, OvpnSession>();
  /** CN → 가상 주소 (ifconfig-pool-persist — 다시 붙으면 같은 주소) */
  private readonly leases = new Map<string, Ip>();
  /** 최근 거절 (상태 표에 남긴다 — TCP 는 거절 뒤 연결이 닫혀 세션이 사라진다) */
  private readonly rejects: { cn: string; peer: string; user?: string; why: string }[] = [];
  private isn: number;

  constructor(
    private readonly io: OvpnServerIo,
    seed: string,
  ) {
    this.isn = fnv(`ovpn-isn:${seed}`) % 0x7fffffff;
  }

  get enabled(): boolean {
    return this.config.enabled && !!this.config.ca;
  }

  /** 서버의 터널 주소 (대역의 첫 주소) */
  get address(): Ip | undefined {
    return this.enabled && this.config.subnet ? addrAt(this.config.subnet, 1) : undefined;
  }

  /** 붙어 있는 클라이언트 수 */
  get connected(): number {
    return [...this.sessions.values()].filter((s) => s.phase === "up").length;
  }

  /** 이 가상 주소로 붙어 있는 클라이언트 */
  owner(ip: Ip): OvpnSession | undefined {
    if (!this.enabled) return undefined;
    for (const s of this.sessions.values()) if (s.phase === "up" && s.vip === ip) return s;
    return undefined;
  }

  /** 터널 대역 안인가 */
  inSubnet(ip: Ip): boolean {
    const n = this.config.subnet;
    return this.enabled && !!n && sameSubnet(ip, n.ip, n.prefix);
  }

  /** 이 패킷을 내가 받나 (전송·포트가 맞을 때) */
  listens(proto: OvpnProto, port: number): boolean {
    return this.enabled && this.config.proto === proto && this.config.port === port;
  }

  setConfig(cfg: OvpnServerConfig, ctx: NodeContext): void {
    const norm = (c: OvpnServerConfig) => JSON.stringify(c);
    if (norm(cfg) === norm(this.config)) return;
    const prev = this.config;
    this.config = { ...cfg, ...(cfg.subnet ? { subnet: { ...cfg.subnet } } : {}), users: cfg.users.map((u) => ({ ...u })), revoked: [...cfg.revoked] };
    if (JSON.stringify(prev.subnet) !== JSON.stringify(cfg.subnet)) this.leases.clear();
    // 서버가 다시 시작: 붙어 있던 클라이언트에게 알린다 (explicit-exit-notify — UDP 는 RESTART, TCP 는 연결을 끊음)
    const live = [...this.sessions.values()];
    this.sessions.clear();
    for (const s of live) this.notifyRestart(s, ctx);
    if (!this.enabled) {
      if (prev.enabled) ctx.trace("vpn.config", "sys", `OpenVPN 서버 꺼짐${live.length ? ` — 붙어 있던 ${live.length}개에 끊김을 알림` : ""}`, { ovpn: true, enabled: false });
      return;
    }
    const c = this.config;
    ctx.trace(
      "vpn.config",
      "sys",
      `OpenVPN 서버 ${prev.enabled ? "다시 시작" : "시작"}: ${c.proto.toUpperCase()} ${c.port}, 터널 ${c.subnet ? `${c.subnet.ip}/${c.subnet.prefix} (서버 ${this.address})` : "대역 없음"}, CA ${shortFp(c.ca)}${c.tlsCrypt ? ", tls-crypt" : ""}${c.users.length ? `, 계정 ${c.users.length}개` : ", 인증서만"}${c.revoked.length ? `, 폐기 ${c.revoked.length}개 (CRL)` : ""} — push: ${this.pushLabel()}${live.length ? ` · 붙어 있던 ${live.length}개는 다시 붙어야 함` : ""}`,
      { ovpn: true, enabled: true },
    );
  }

  private pushLabel(): string {
    const c = this.config;
    const lan = this.io.lan();
    return [c.redirectGateway ? "redirect-gateway def1" : "", c.lanAccess && lan ? `route ${addrAt(lan, 0)}/${lan.prefix}` : "", c.pushDns ? `DNS ${this.address}` : ""].filter(Boolean).join(", ") || "(없음)";
  }

  private notifyRestart(s: OvpnSession, ctx: NodeContext): void {
    const src = this.io.source();
    if (!src) return;
    if (s.proto === "tcp" && s.tcp) {
      this.io.send(tcpFlag(src, s.peer.ip, this.config.port, s.peer.port, s.tcp, { rst: true, ackFlag: true }), ctx);
      return;
    }
    if (s.phase !== "up") return;
    this.io.send(outerPacket(src, s.peer.ip, "udp", this.config.port, s.peer.port, { kind: "ovpn", op: "exit", sid: s.sid, reason: "restart" }), ctx);
  }

  /** 같은 인증서로 다른 기기가 붙어 밀려난 세션: 이유를 알리고 닫는다 (클라이언트는 다시 붙지 않는다 — 서로 밀어내기를 끝없이 하지 않게) */
  private kick(s: OvpnSession, ctx: NodeContext): void {
    const src = this.io.source();
    if (!src) return;
    this.io.send(outerPacket(src, s.peer.ip, s.proto, this.config.port, s.peer.port, { kind: "ovpn", op: "exit", sid: s.sid, reason: "kicked" }, s.tcp), ctx);
    if (s.proto === "tcp" && s.tcp) this.io.send(tcpFlag(src, s.peer.ip, this.config.port, s.peer.port, s.tcp, { fin: true, ackFlag: true }), ctx);
  }

  /** WAN 주소를 잃음: 세션을 말없이 비운다 (클라이언트는 ping-restart 로 알아챈다) */
  forgetAll(ctx: NodeContext, why: string): void {
    if (!this.sessions.size) return;
    const n = this.connected;
    this.sessions.clear();
    ctx.trace("vpn.drop", "L4", `OpenVPN 서버: ${why} → 세션 ${n}개를 비움 (클라이언트는 ${OVPN_PING_RESTART / 1000}초 동안 받은 게 없으면 다시 붙는다 — ping-restart)`, { ovpn: true });
  }

  /** UDP 로 온 OpenVPN. 풀린 패킷이면 돌려준다 */
  handleUdp(pkt: Ipv4Packet, srcPort: number, m: OvpnMessage, ctx: NodeContext, frameId: number): Ipv4Packet | null {
    const key = `${pkt.src}:${srcPort}`;
    return this.handleMessage(key, { ip: pkt.src, port: srcPort }, "udp", m, ctx, frameId);
  }

  /** TCP 로 온 세그먼트 (내 OpenVPN TCP 포트). 풀린 패킷이면 돌려준다 */
  handleTcp(pkt: Ipv4Packet, seg: TcpSegment, ctx: NodeContext, frameId: number): Ipv4Packet | null {
    const key = `${pkt.src}:${seg.srcPort}`;
    const src = this.io.source();
    let s = this.sessions.get(key);
    if (seg.rst) {
      if (s) {
        this.sessions.delete(key);
        ctx.trace("vpn.drop", "L4", `OpenVPN 서버: ${key} 가 TCP 연결을 RST 로 끊음 → 세션 정리${s.cn ? ` (${s.cn})` : ""}`, { ovpn: true }, frameId);
      }
      return null;
    }
    if (seg.syn && !seg.ackFlag) {
      if (!src) return null;
      // 새 연결 (같은 포트의 옛 연결이 남아 있으면 갈아 끼운다)
      const tcp: TcpState = { snd: this.isn, rcv: seg.seq + 1, established: false };
      this.isn = (this.isn + 64000) % 0x7fffffff;
      s = { key, sid: 0, peer: { ip: pkt.src, port: seg.srcPort }, proto: "tcp", phase: "syn", replies: new Map(), rxBytes: 0, txBytes: 0, since: ctx.now, tcp };
      this.sessions.set(key, s);
      ctx.trace("tcp.syn.received", "L4", `OpenVPN 서버 (TCP ${this.config.port}): ${key} 의 SYN → SYN·ACK (TCP 위로 OpenVPN 을 나른다)`, { ovpn: true }, frameId);
      this.io.send(tcpFlag(src, pkt.src, this.config.port, seg.srcPort, tcp, { syn: true, ackFlag: true }), ctx, frameId);
      return null;
    }
    if (!s?.tcp) {
      if (seg.fin || !seg.len) return null;
      ctx.trace("vpn.drop", "L4", `OpenVPN 서버: 모르는 TCP 연결 ${key} 의 데이터 → 버림 (서버가 다시 시작했거나 끊긴 연결)`, { ovpn: true }, frameId);
      return null;
    }
    const t = s.tcp;
    if (seg.ackFlag) t.established = true;
    if (seg.fin) {
      t.rcv = seg.seq + seg.len + 1;
      this.sessions.delete(key);
      if (src) this.io.send(tcpFlag(src, pkt.src, this.config.port, seg.srcPort, t, { fin: true, ackFlag: true }), ctx, frameId);
      ctx.trace("vpn.drop", "L4", `OpenVPN 서버: ${s.cn ?? key} 가 TCP 연결을 닫음 (FIN) → 세션 정리${s.vip ? `, 가상 주소 ${s.vip} 는 같은 인증서가 다시 붙을 때까지 남겨 둠` : ""}`, { ovpn: true }, frameId);
      return null;
    }
    if (!seg.ovpn) {
      if (seg.len) ctx.trace("vpn.drop", "L4", `OpenVPN 서버: ${key} 가 OpenVPN 이 아닌 데이터를 보냄 → 버림`, { ovpn: true }, frameId);
      return null;
    }
    t.rcv = Math.max(t.rcv, seg.seq + seg.len);
    return this.handleMessage(key, { ip: pkt.src, port: seg.srcPort }, "tcp", seg.ovpn, ctx, frameId);
  }

  private handleMessage(key: string, peer: { ip: Ip; port: number }, proto: OvpnProto, m: OvpnMessage, ctx: NodeContext, frameId: number): Ipv4Packet | null {
    const c = this.config;
    let s = this.sessions.get(key);
    // 데이터 채널 (세션 키로 암호화 — tls-crypt 와 무관)
    if (m.op === "data" || m.op === "ping" || m.op === "exit") {
      if (!s || s.phase !== "up" || s.sid !== m.sid) {
        if (m.op !== "exit") ctx.trace("vpn.drop", "L4", `OpenVPN 서버: 모르는 세션(${key}, sid ${m.sid})의 ${OP_LABEL[m.op]} → 버림 (서버가 다시 시작했거나 주소가 바뀜 — 클라이언트는 ping-restart 로 다시 붙는다)`, { ovpn: true }, frameId);
        return null;
      }
      if (m.op === "exit") {
        this.sessions.delete(key);
        ctx.trace("vpn.drop", "L4", `OpenVPN 서버: ${s.cn} 가 연결을 끊음 (explicit-exit-notify) → 세션 정리, 가상 주소 ${s.vip} 는 같은 인증서가 다시 붙을 때 다시 줌`, { ovpn: true, cn: s.cn }, frameId);
        return null;
      }
      if (m.op === "ping") {
        ctx.trace("vpn.keepalive", "L4", `OpenVPN 서버: ${s.cn} 의 keepalive ping → ping 으로 답함`, { ovpn: true }, frameId);
        this.reply(s, { kind: "ovpn", op: "ping", sid: s.sid }, ctx, frameId);
        return null;
      }
      const inner = m.inner;
      if (!inner) return null;
      s.rxBytes += ovpnLength(m, 84);
      if (inner.src !== s.vip) {
        ctx.trace("vpn.drop", "L3", `OpenVPN 서버: ${s.cn} 터널에서 온 패킷의 출발지 ${inner.src} 가 그 클라이언트의 가상 주소(${s.vip})가 아님 → 드롭 (iroute 없음)`, { ovpn: true, src: inner.src }, frameId);
        return null;
      }
      ctx.trace("vpn.decap", "L3", `OpenVPN 서버: ${s.cn} 터널에서 ${inner.src} → ${inner.dst} 를 꺼냄`, { ovpn: true, cn: s.cn }, frameId);
      return inner;
    }
    // 제어 채널: tls-crypt 키가 다르면 열지 못하고 침묵
    if ((m.crypt ?? "") !== (c.tlsCrypt ?? "")) {
      ctx.trace(
        "vpn.drop",
        "L4",
        c.tlsCrypt
          ? `OpenVPN 서버: ${peer.ip}:${peer.port} 의 ${OP_LABEL[m.op]} → tls-crypt 키가 ${m.crypt ? "다름" : "없음"} — 열지 못함 (tls-crypt unwrap error: packet authentication failed) → 답하지 않고 버림 (키 없는 사람에게는 서버가 있다는 것도 보이지 않는다)`
          : `OpenVPN 서버: ${peer.ip}:${peer.port} 의 ${OP_LABEL[m.op]} 가 tls-crypt 로 감싸져 있는데 서버는 tls-crypt 를 쓰지 않음 → 읽지 못하고 버림`,
        { ovpn: true, tlsCrypt: false },
        frameId,
      );
      return null;
    }
    if (m.op === "reset-client") {
      if (s && s.sid === m.sid && s.replies.has(m.op)) return this.resend(s, m, ctx, frameId);
      if (s?.phase === "up") ctx.trace("vpn.drop", "L4", `OpenVPN 서버: ${s.cn} 가 같은 주소에서 새 세션을 시작 → 옛 세션을 버림`, { ovpn: true }, frameId);
      const tcp = proto === "tcp" ? s?.tcp : undefined;
      if (proto === "tcp" && !tcp) return null;
      s = { key, sid: m.sid, peer, proto, phase: "reset", replies: new Map(), rxBytes: 0, txBytes: 0, since: ctx.now, ...(tcp ? { tcp } : {}) };
      this.sessions.set(key, s);
      ctx.trace("vpn.handshake", "L4", `OpenVPN 서버: ${peer.ip}:${peer.port} 가 세션 시작 (HARD_RESET_CLIENT, sid ${m.sid})${c.tlsCrypt ? " — tls-crypt 키가 맞음" : ""} → HARD_RESET_SERVER`, { ovpn: true, from: peer.ip, sid: m.sid }, frameId);
      this.reply(s, { kind: "ovpn", op: "reset-server", sid: m.sid }, ctx, frameId, m.op);
      return null;
    }
    if (!s || s.sid !== m.sid) {
      ctx.trace("vpn.drop", "L4", `OpenVPN 서버: 시작하지 않은 세션(${key}, sid ${m.sid})의 ${OP_LABEL[m.op]} → 버림`, { ovpn: true }, frameId);
      return null;
    }
    if (s.replies.has(m.op)) return this.resend(s, m, ctx, frameId);
    if (m.op === "tls-client") {
      s.phase = "tls";
      ctx.trace("vpn.handshake", "L4", `OpenVPN 서버: TLS ClientHello → 서버 인증서(CN=server, 발급 CA ${shortFp(c.ca)})를 보냄`, { ovpn: true }, frameId);
      this.reply(s, { kind: "ovpn", op: "tls-server", sid: s.sid, cert: { cn: "server", ca: c.ca } }, ctx, frameId, m.op);
      return null;
    }
    if (m.op === "tls-auth") {
      const cert = m.cert;
      let fail: string | undefined;
      if (!cert || cert.ca !== c.ca) fail = `VERIFY ERROR: 클라이언트 인증서${cert ? `(CN=${cert.cn})` : ""}를 발급한 CA ${cert ? shortFp(cert.ca) : "없음"} 가 이 서버의 CA(${shortFp(c.ca)})가 아님 — unable to get local issuer certificate`;
      else if (c.revoked.includes(cert.cn)) fail = `VERIFY ERROR: CN=${cert.cn} 의 인증서는 폐기됨 (CRL: certificate revoked)`;
      else if (c.users.length) {
        const u = c.users.find((x) => x.name === m.user);
        if (!u) fail = `AUTH_FAILED: 계정 ${m.user ? `"${m.user}" 이(가) 목록에 없음` : "을 보내지 않음"} (auth-user-pass)`;
        else if (u.password !== m.password) fail = `AUTH_FAILED: 계정 "${m.user}" 의 비밀번호가 다름`;
      }
      if (fail) {
        s.phase = "failed";
        s.failed = fail;
        this.rejects.push({ cn: cert?.cn ?? "?", peer: `${s.peer.ip}:${s.peer.port}`, ...(m.user ? { user: m.user } : {}), why: fail });
        if (this.rejects.length > 10) this.rejects.shift();
        ctx.trace("vpn.drop", "L4", `OpenVPN 서버: ${fail} → 거절`, { ovpn: true, failed: true }, frameId);
        this.reply(s, { kind: "ovpn", op: "tls-fail", sid: s.sid, reason: fail.startsWith("AUTH_FAILED") ? "AUTH_FAILED" : fail.includes("CRL") ? "revoked" : "verify" }, ctx, frameId, m.op);
        return null;
      }
      s.cn = cert!.cn;
      if (m.user) s.user = m.user;
      s.phase = "auth";
      ctx.trace("vpn.handshake", "L4", `OpenVPN 서버: VERIFY OK CN=${s.cn} (CA ${shortFp(c.ca)} 가 발급, 폐기 목록에 없음)${s.user ? `, 계정 ${s.user} 확인` : ""} → TLS 완료`, { ovpn: true, cn: s.cn }, frameId);
      this.reply(s, { kind: "ovpn", op: "tls-ok", sid: s.sid }, ctx, frameId, m.op);
      return null;
    }
    if (m.op === "push-request") {
      if (s.phase !== "auth") return null;
      const vip = this.allocate(s.cn!);
      if (!vip || !c.subnet) {
        ctx.trace("vpn.drop", "L4", `OpenVPN 서버: ${s.cn} 에게 줄 가상 주소가 없음 (터널 대역 ${c.subnet ? `${c.subnet.ip}/${c.subnet.prefix} 가 다 참` : "이 비어 있음"}) → 응답하지 않음`, { ovpn: true }, frameId);
        return null;
      }
      // 같은 인증서(CN)로 이미 붙어 있는 다른 세션은 내보낸다 (duplicate-cn 이 꺼져 있는 기본값 — 인증서 한 장은 한 기기)
      for (const [k, o] of this.sessions)
        if (k !== s.key && o.cn === s.cn && o.phase === "up") {
          this.sessions.delete(k);
          ctx.trace("vpn.drop", "L4", `OpenVPN 서버: 같은 인증서 CN=${s.cn} 가 ${s.peer.ip}:${s.peer.port} 에서 새로 붙음 → ${o.peer.ip}:${o.peer.port} 의 옛 세션을 끊음 (duplicate-cn 꺼짐 — 인증서 한 장은 한 기기)`, { ovpn: true }, frameId);
          this.kick(o, ctx);
        }
      s.vip = vip;
      s.phase = "up";
      const lan = this.io.lan();
      const push = {
        ip: vip,
        prefix: c.subnet.prefix,
        routes: c.lanAccess && lan ? [{ dest: addrAt(lan, 0), prefix: lan.prefix }] : [],
        ...(c.pushDns && this.address ? { dns: this.address } : {}),
        redirectGateway: c.redirectGateway,
      };
      ctx.trace("vpn.up", "L4", `OpenVPN 서버: ${s.cn} 연결됨 — PUSH_REPLY: ifconfig ${vip} ${maskOf(c.subnet.prefix)}${push.routes.map((r) => `, route ${r.dest}/${r.prefix}`).join("")}${push.dns ? `, DNS ${push.dns}` : ""}${push.redirectGateway ? ", redirect-gateway def1" : ""}`, { ovpn: true, cn: s.cn, vip, push: pushText(push) }, frameId);
      this.reply(s, { kind: "ovpn", op: "push-reply", sid: s.sid, push }, ctx, frameId, m.op);
      return null;
    }
    return null;
  }

  private allocate(cn: string): Ip | undefined {
    const n = this.config.subnet;
    if (!n) return undefined;
    const have = this.leases.get(cn);
    if (have && sameSubnet(have, n.ip, n.prefix)) return have;
    const used = new Set(this.leases.values());
    const size = n.prefix >= 31 ? 0 : 2 ** (32 - n.prefix) - 2;
    for (let i = 2; i <= Math.min(size, 1024); i++) {
      const ip = addrAt(n, i);
      if (used.has(ip)) continue;
      this.leases.set(cn, ip);
      return ip;
    }
    // 다 찼으면 붙어 있지 않은 CN 의 임대를 넘긴다
    for (const [k, ip] of this.leases) {
      if ([...this.sessions.values()].some((s) => s.cn === k && s.phase === "up")) continue;
      this.leases.delete(k);
      this.leases.set(cn, ip);
      return ip;
    }
    return undefined;
  }

  private resend(s: OvpnSession, m: OvpnMessage, ctx: NodeContext, frameId: number): null {
    const r = s.replies.get(m.op)!;
    ctx.trace("vpn.handshake", "L4", `OpenVPN 서버: 같은 ${OP_LABEL[m.op]} 가 다시 옴 (답이 사라짐) → 보냈던 ${OP_LABEL[r.op]} 를 그대로 다시 보냄`, { ovpn: true, resent: true }, frameId);
    this.reply(s, r, ctx, frameId);
    return null;
  }

  private reply(s: OvpnSession, m: OvpnMessage, ctx: NodeContext, frameId?: number, forOp?: OvpnMessage["op"]): void {
    const c = this.config;
    const msg: OvpnMessage = m.op === "data" || m.op === "ping" || m.op === "exit" || !c.tlsCrypt ? m : { ...m, crypt: c.tlsCrypt };
    if (forOp) s.replies.set(forOp, msg);
    const src = this.io.source();
    if (!src) return;
    this.io.send(outerPacket(src, s.peer.ip, s.proto, c.port, s.peer.port, msg, s.tcp), ctx, frameId);
  }

  /** 붙은 클라이언트에게 (목적지 = 가상 주소). 보냈으면 true */
  send(inner: Ipv4Packet, ctx: NodeContext, frameId?: number): boolean {
    const s = this.owner(inner.dst);
    if (!s) return false;
    const m: OvpnMessage = { kind: "ovpn", op: "data", sid: s.sid, inner };
    s.txBytes += ovpnLength(m, 84);
    ctx.trace("vpn.encap", "L3", `OpenVPN 서버: ${inner.src} → ${inner.dst} 를 ${s.cn} 터널로 (${s.proto.toUpperCase()} ${s.peer.ip}:${s.peer.port})`, { ovpn: true, cn: s.cn }, frameId);
    this.reply(s, m, ctx, frameId);
    return true;
  }

  rows(): string[][] {
    return [
      ...[...this.sessions.values()].filter((s) => s.phase === "up").map((s) => [s.cn ?? "?", `${s.peer.ip}:${s.peer.port}`, s.vip ?? "—", s.user ?? "—", `${s.proto.toUpperCase()} · 받음 ${s.rxBytes}B · 보냄 ${s.txBytes}B`]),
      ...this.rejects.map((r) => [r.cn, r.peer, "—", r.user ?? "—", `거절 · ${r.why}`]),
    ];
  }
}

// ---------- 클라이언트 (노트북·폰의 OpenVPN 앱) ----------

export interface OvpnClientIo {
  myIp(): Ip | undefined;
  send(outer: Ipv4Packet, ctx: NodeContext): void;
  local(dst: Ip): boolean;
  resolve(name: string, ctx: NodeContext, done: (ip: Ip | undefined, reason?: string) => void): void;
}

interface ClientSession {
  sid: number;
  server: Ip;
  proto: OvpnProto;
  port: number;
  lport: number;
  phase: Phase;
  /** 기다리는 요청 (재전송용) */
  pending?: OvpnMessage;
  tries: number;
  tok: number;
  tcp?: TcpState;
  push?: NonNullable<OvpnMessage["push"]>;
  lastTx: number;
  lastRx: number;
  rxBytes: number;
  txBytes: number;
}

export class OvpnClient {
  config: RaClientConfig = { ...DEFAULT_RA_CLIENT, type: "openvpn" };
  readonly dpdWaiting = false;
  private s: ClientSession | undefined;
  private failed: string | undefined;
  private resolving = false;
  private tok = 0;
  private nextSid: number;
  private attempt = 0;

  constructor(
    private readonly io: OvpnClientIo,
    seed: string,
    /** UDP 의 바깥 포트 (nobind — 장치마다 고정) */
    readonly udpPort: number,
  ) {
    this.nextSid = (fnv(`ovpn-sid:${seed}`) % 0xffff) * 0x100 + 1;
  }

  get reason(): string | undefined {
    return this.failed;
  }

  private get serverName(): string | undefined {
    const s = this.config.server;
    return s && /[a-z]/i.test(s) ? s : undefined;
  }

  get state(): RaClientState {
    if (!this.config.enabled) return "off";
    if (this.s?.phase === "up") return "up";
    if (this.s || this.resolving) return "init";
    return this.failed ? "failed" : "off";
  }

  /** 받은 가상 주소 (연결됐을 때만) */
  get vip(): Ip | undefined {
    return this.s?.phase === "up" ? this.s.push?.ip : undefined;
  }

  get dns(): Ip | undefined {
    return this.s?.phase === "up" ? this.s.push?.dns : undefined;
  }

  /** PUSH 받은 경로 (redirect-gateway 면 0.0.0.0/0) */
  get routes(): { dest: Ip; prefix: number }[] {
    const p = this.s?.phase === "up" ? this.s.push : undefined;
    if (!p) return [];
    return p.redirectGateway ? [{ dest: "0.0.0.0", prefix: 0 }] : [{ dest: addrAt({ ip: p.ip, prefix: p.prefix }, 0), prefix: p.prefix }, ...p.routes];
  }

  /** 지금 쓰는 바깥 포트들 (늦게 온 OpenVPN 을 알아보게) */
  ownsPort(proto: OvpnProto, port: number): boolean {
    return !!this.s && this.s.proto === proto && this.s.lport === port;
  }

  setConfig(cfg: RaClientConfig, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.config)) return;
    const was = this.s;
    if (was) this.close(ctx, "설정 변경");
    this.config = { ...cfg, ...(cfg.ovpn ? { ovpn: { ...cfg.ovpn, cert: { ...cfg.ovpn.cert } } } : {}) };
    this.failed = undefined;
    if (!cfg.enabled) return;
    const o = cfg.ovpn;
    if (!o || !cfg.server || !o.ca || !o.cert.cn) {
      ctx.trace("vpn.config", "sys", `OpenVPN: 설정 파일이 비어 있음 (${!cfg.server ? "서버 주소(remote)" : !o?.ca ? "CA 인증서" : "내 인증서"}) → 연결하지 않음`, { ovpn: true });
      return;
    }
    ctx.trace("vpn.config", "sys", `OpenVPN: remote ${cfg.server} ${o.port} ${o.proto}, CA ${shortFp(o.ca)}, 내 인증서 CN=${o.cert.cn}${o.tlsCrypt ? ", tls-crypt" : ""}${cfg.user ? `, 계정 ${cfg.user}` : ""}`, { ovpn: true });
    this.connect(ctx);
  }

  connect(ctx: NodeContext): void {
    if (!this.config.enabled || this.s || this.resolving || this.failed) return;
    const o = this.config.ovpn;
    const me = this.io.myIp();
    if (!o || !this.config.server || !o.ca || !o.cert.cn || !me) return;
    const name = this.serverName;
    if (name) {
      this.resolving = true;
      ctx.trace("vpn.config", "sys", `OpenVPN: 서버 이름 ${name} 을(를) 물음 (remote 가 이름)`, { ovpn: true, name });
      this.io.resolve(name, ctx, (ip, reason) => {
        this.resolving = false;
        if (this.serverName !== name || !this.config.enabled || this.s) return;
        if (!ip) {
          this.fail(ctx, `서버 이름 ${name} 을(를) 풀지 못함 (${reason ?? "?"}) — 이름(DDNS)과 DNS 설정을 확인`);
          return;
        }
        this.start(ip, ctx);
      });
      return;
    }
    this.start(this.config.server, ctx);
  }

  private start(server: Ip, ctx: NodeContext): void {
    const o = this.config.ovpn!;
    const me = this.io.myIp();
    if (!me) return;
    this.attempt++;
    const sid = this.nextSid;
    this.nextSid = (this.nextSid + 1) % 0xffffff || 1;
    const lport = o.proto === "udp" ? this.udpPort : 40000 + ((this.udpPort + this.attempt * 7) % 9000);
    this.s = { sid, server, proto: o.proto, port: o.port, lport, phase: o.proto === "tcp" ? "syn" : "reset", tries: 0, tok: ++this.tok, lastTx: ctx.now, lastRx: ctx.now, rxBytes: 0, txBytes: 0 };
    if (o.proto === "tcp") {
      this.s.tcp = { snd: fnv(`ovpn-c:${sid}`) % 0x7fffffff, rcv: 0, established: false };
      ctx.trace("vpn.handshake", "L4", `OpenVPN: TCP ${server}:${o.port} 에 연결 (SYN) — TCP 위로 OpenVPN 을 나른다`, { ovpn: true }, undefined);
      this.sendRaw(tcpFlag(me, server, lport, o.port, this.s.tcp, { syn: true }), ctx);
      this.arm(ctx);
      return;
    }
    this.request({ kind: "ovpn", op: "reset-client", sid }, ctx);
  }

  private sendRaw(outer: Ipv4Packet, ctx: NodeContext): void {
    if (this.s) this.s.lastTx = ctx.now;
    this.io.send(outer, ctx);
  }

  private wrap(m: OvpnMessage): Ipv4Packet | undefined {
    const s = this.s;
    const me = this.io.myIp();
    if (!s || !me) return undefined;
    return outerPacket(me, s.server, s.proto, s.lport, s.port, m, s.tcp);
  }

  /** 제어 요청 보내기 (답이 없으면 재전송) */
  private request(m0: OvpnMessage, ctx: NodeContext): void {
    const s = this.s!;
    const crypt = this.config.ovpn?.tlsCrypt;
    const m: OvpnMessage = crypt ? { ...m0, crypt } : m0;
    s.pending = m;
    s.tries = 1;
    if (m.op === "reset-client") ctx.trace("vpn.handshake", "L4", `OpenVPN: ${s.server}:${s.port}/${s.proto} 에 세션 시작 (HARD_RESET_CLIENT, sid ${s.sid})${crypt ? " — tls-crypt 로 감쌈" : ""}`, { ovpn: true });
    const outer = this.wrap(m);
    if (outer) this.sendRaw(outer, ctx);
    this.arm(ctx);
  }

  private arm(ctx: NodeContext): void {
    const s = this.s!;
    s.tok = ++this.tok;
    ctx.timer(OVPN_RETRY, OVPN_TIMER_TAG, { ovpn: "retry", tok: s.tok });
  }

  /** 받은 UDP OpenVPN (내 포트) */
  handleUdp(pkt: Ipv4Packet, srcPort: number, dstPort: number, m: OvpnMessage, ctx: NodeContext, frameId: number): Ipv4Packet | null {
    const s = this.s;
    if (!s || s.proto !== "udp" || dstPort !== s.lport || pkt.src !== s.server || srcPort !== s.port) {
      ctx.trace("vpn.drop", "L4", `OpenVPN ${OP_LABEL[m.op]} (from ${pkt.src}:${srcPort}) → 지금 연결의 것이 아님 (끊었거나 다시 연결한 뒤 늦게 온 패킷) → 무시`, { ovpn: true, late: true }, frameId);
      return null;
    }
    return this.handleMessage(m, ctx, frameId);
  }

  /** 받은 TCP 세그먼트 (내 OpenVPN TCP 연결) */
  handleTcp(pkt: Ipv4Packet, seg: TcpSegment, ctx: NodeContext, frameId: number): Ipv4Packet | null {
    const s = this.s;
    if (!s?.tcp || s.proto !== "tcp" || seg.dstPort !== s.lport || pkt.src !== s.server) return null;
    const t = s.tcp;
    if (seg.rst) {
      this.s = undefined;
      if (s.phase !== "up") {
        this.failed = `연결 중에 TCP 연결이 RST 로 끊김 (${s.phase === "syn" ? "그 포트를 듣는 서버가 없거나 " : ""}방화벽·DPI 가 끊었을 수 있음)`;
        ctx.trace("vpn.drop", "L4", `OpenVPN 연결 실패: ${this.failed}`, { ovpn: true, failed: true }, frameId);
        return null;
      }
      ctx.trace("vpn.drop", "L4", `OpenVPN: TCP 연결이 RST 로 끊김 (서버가 다시 시작함) → ${OVPN_RECONNECT / 1000}초 뒤 다시 연결 (connect-retry)`, { ovpn: true }, frameId);
      ctx.timer(OVPN_RECONNECT, OVPN_TIMER_TAG, { ovpn: "reconnect", tok: ++this.tok });
      this.reconnectTok = this.tok;
      return null;
    }
    if (seg.syn && seg.ackFlag && s.phase === "syn") {
      t.rcv = seg.seq + 1;
      t.established = true;
      s.lastRx = ctx.now;
      ctx.trace("vpn.handshake", "L4", `OpenVPN: TCP 연결됨 (SYN·ACK) → OpenVPN 세션 시작`, { ovpn: true }, frameId);
      s.phase = "reset";
      this.request({ kind: "ovpn", op: "reset-client", sid: s.sid }, ctx);
      return null;
    }
    if (seg.fin) {
      t.rcv = seg.seq + seg.len + 1;
      const me = this.io.myIp();
      if (me && !t.finSent) this.sendRaw(tcpFlag(me, s.server, s.lport, s.port, t, { fin: true, ackFlag: true }), ctx);
      else if (me) this.sendRaw(tcpFlag(me, s.server, s.lport, s.port, t, { ackFlag: true }), ctx);
      if (!t.finSent) {
        this.s = undefined;
        this.fail(ctx, "서버가 TCP 연결을 닫음");
      }
      return null;
    }
    if (!seg.ovpn) return null;
    t.rcv = Math.max(t.rcv, seg.seq + seg.len);
    return this.handleMessage(seg.ovpn, ctx, frameId);
  }

  private reconnectTok = 0;

  private handleMessage(m: OvpnMessage, ctx: NodeContext, frameId: number): Ipv4Packet | null {
    const s = this.s!;
    if (m.sid !== s.sid) {
      ctx.trace("vpn.drop", "L4", `OpenVPN: 다른 세션(sid ${m.sid})의 ${OP_LABEL[m.op]} → 무시 (지난 연결의 늦게 온 답)`, { ovpn: true, late: true }, frameId);
      return null;
    }
    s.lastRx = ctx.now;
    const o = this.config.ovpn!;
    if (m.op === "exit" && m.reason === "kicked") {
      this.closing = s.proto === "tcp" ? s : undefined;
      this.s = undefined;
      this.failed = "서버가 끊음 — 같은 인증서(CN)로 다른 기기가 붙음 (인증서는 기기마다 따로 발급)";
      ctx.trace("vpn.drop", "L4", `OpenVPN: ${this.failed} → 다시 붙지 않음`, { ovpn: true, failed: true }, frameId);
      return null;
    }
    if (m.op === "exit") {
      this.s = undefined;
      ctx.trace("vpn.drop", "L4", `OpenVPN: 서버가 다시 시작한다고 알려 옴 (RESTART) → ${OVPN_RECONNECT / 1000}초 뒤 다시 연결`, { ovpn: true }, frameId);
      ctx.timer(OVPN_RECONNECT, OVPN_TIMER_TAG, { ovpn: "reconnect", tok: ++this.tok });
      this.reconnectTok = this.tok;
      return null;
    }
    if (m.op === "ping") {
      ctx.trace("vpn.keepalive", "L4", `OpenVPN: 서버의 ping 수신 (살아 있음)`, { ovpn: true }, frameId);
      return null;
    }
    if (m.op === "data") {
      if (s.phase !== "up" || !m.inner) return null;
      s.rxBytes += ovpnLength(m, 84);
      const me = this.io.myIp();
      if (!me || m.inner.dst !== s.push?.ip) {
        ctx.trace("vpn.drop", "L3", `OpenVPN: 터널에서 꺼낸 패킷의 목적지 ${m.inner.dst} 가 내 가상 주소(${s.push?.ip ?? "없음"})가 아님 → 드롭`, { ovpn: true }, frameId);
        return null;
      }
      return { ...m.inner, dst: me };
    }
    // 제어 응답: 기다리던 요청의 답만
    const want: Partial<Record<OvpnMessage["op"], OvpnMessage["op"]>> = { "reset-client": "reset-server", "tls-client": "tls-server", "tls-auth": "tls-ok", "push-request": "push-reply" };
    const pend = s.pending?.op;
    const ok = pend && (want[pend] === m.op || (pend === "tls-auth" && m.op === "tls-fail"));
    if (!ok) {
      ctx.trace("vpn.drop", "L4", `OpenVPN: 기다리지 않던 ${OP_LABEL[m.op]} → 무시 (재전송한 요청의 늦게 온 답)`, { ovpn: true, late: true }, frameId);
      return null;
    }
    if ((m.crypt ?? "") !== (o.tlsCrypt ?? "")) return null;
    s.pending = undefined;
    s.tok = ++this.tok;
    if (m.op === "reset-server") {
      s.phase = "tls";
      ctx.trace("vpn.handshake", "L4", `OpenVPN: HARD_RESET_SERVER 수신 → TLS ClientHello`, { ovpn: true }, frameId);
      this.request({ kind: "ovpn", op: "tls-client", sid: s.sid }, ctx);
      return null;
    }
    if (m.op === "tls-server") {
      if (!m.cert || m.cert.ca !== o.ca) {
        this.abort(ctx, `VERIFY ERROR: 서버 인증서(CN=${m.cert?.cn ?? "?"})를 발급한 CA ${m.cert ? shortFp(m.cert.ca) : "?"} 를 믿지 않음 — 설정 파일의 <ca>(${shortFp(o.ca)})와 다름 (다른 서버이거나 서버가 CA 를 다시 만듦)`, frameId);
        return null;
      }
      ctx.trace("vpn.handshake", "L4", `OpenVPN: VERIFY OK 서버 CN=${m.cert.cn} (CA ${shortFp(o.ca)}) → 내 인증서(CN=${o.cert.cn})${this.config.user ? `와 계정 ${this.config.user}` : ""}를 보냄`, { ovpn: true }, frameId);
      s.phase = "auth";
      this.request({ kind: "ovpn", op: "tls-auth", sid: s.sid, cert: { ...o.cert }, ...(this.config.user ? { user: this.config.user, password: this.config.password ?? "" } : {}) }, ctx);
      return null;
    }
    if (m.op === "tls-fail") {
      const why = m.reason === "AUTH_FAILED" ? "AUTH_FAILED — 계정 또는 비밀번호가 틀림" : m.reason === "revoked" ? "서버가 내 인증서를 받지 않음 — 폐기된 인증서 (CRL)" : "서버가 내 인증서를 받지 않음 — 이 서버의 CA 가 발급한 인증서가 아님";
      this.abort(ctx, why, frameId);
      return null;
    }
    if (m.op === "tls-ok") {
      ctx.trace("vpn.handshake", "L4", `OpenVPN: TLS 완료 (Control Channel: TLSv1.3) → PUSH_REQUEST`, { ovpn: true }, frameId);
      this.request({ kind: "ovpn", op: "push-request", sid: s.sid }, ctx);
      return null;
    }
    if (m.op === "push-reply" && m.push) {
      s.push = m.push;
      s.phase = "up";
      const p = m.push;
      ctx.trace(
        "vpn.up",
        "L4",
        `OpenVPN: PUSH 받음 — 가상 주소 ${p.ip}/${p.prefix}${p.redirectGateway ? ", 모든 트래픽을 터널로 (redirect-gateway)" : ""}${p.routes.length ? `, 경로 ${p.routes.map((r) => `${r.dest}/${r.prefix}`).join(", ")}` : ""}${p.dns ? `, DNS ${p.dns}` : ""} → Initialization Sequence Completed`,
        { ovpn: true, vip: p.ip, push: pushText(p) },
        frameId,
      );
      this.armKeepalive(ctx);
      return null;
    }
    return null;
  }

  private armKeepalive(ctx: NodeContext): void {
    const s = this.s;
    if (!s) return;
    ctx.timer(OVPN_PING, OVPN_TIMER_TAG, { ovpn: "ping", sid: s.sid }, true);
    ctx.timer(OVPN_PING_RESTART, OVPN_TIMER_TAG, { ovpn: "restart", sid: s.sid, at: s.lastRx }, true);
  }

  private abort(ctx: NodeContext, why: string, frameId?: number): void {
    ctx.trace("vpn.drop", "L4", `OpenVPN 연결 실패: ${why}`, { ovpn: true, failed: true }, frameId);
    this.close(ctx, undefined);
    this.failed = why;
  }

  private fail(ctx: NodeContext, why: string): void {
    this.s = undefined;
    this.failed = why;
    ctx.trace("vpn.drop", "L4", `OpenVPN 연결 실패: ${why}`, { ovpn: true, failed: true });
  }

  /** 지금 세션을 닫는다 (TCP 면 FIN, UDP 로 붙어 있었으면 EXIT 알림) */
  private close(ctx: NodeContext, why: string | undefined): void {
    const s = this.s;
    if (!s) return;
    const me = this.io.myIp();
    if (me && s.proto === "tcp" && s.tcp?.established) {
      s.tcp.finSent = true;
      this.sendRaw(tcpFlag(me, s.server, s.lport, s.port, s.tcp, { fin: true, ackFlag: true }), ctx);
    } else if (me && s.phase === "up") {
      const outer = this.wrap({ kind: "ovpn", op: "exit", sid: s.sid });
      if (outer) this.sendRaw(outer, ctx);
    }
    if (why && s.phase === "up") ctx.trace("vpn.drop", "L4", `OpenVPN 끊음 (${why}) — 서버에 알림 (${s.proto === "tcp" ? "TCP FIN" : "explicit-exit-notify"})`, { ovpn: true });
    // TCP 는 서버의 FIN 에 마지막 ACK 를 보낼 수 있게 세션을 잠깐 남긴다 (phase 만 끝남으로)
    if (s.proto === "tcp" && s.tcp?.finSent) {
      this.closing = s;
      this.s = undefined;
      return;
    }
    this.s = undefined;
  }

  /** 닫는 중인 TCP 연결 (서버의 FIN 에 마지막 ACK) */
  private closing: ClientSession | undefined;

  /** 내 OpenVPN 포트로 온 것인가 (지금 연결·닫는 중인 TCP) */
  ownsTcp(seg: TcpSegment, src: Ip): boolean {
    return (!!this.s && this.s.proto === "tcp" && this.s.lport === seg.dstPort && this.s.server === src) || (!!this.closing && this.closing.lport === seg.dstPort && this.closing.server === src);
  }

  /** 닫는 중인 TCP 연결로 온 세그먼트 */
  handleClosing(pkt: Ipv4Packet, seg: TcpSegment, ctx: NodeContext): boolean {
    const c = this.closing;
    if (!c?.tcp || seg.dstPort !== c.lport || pkt.src !== c.server) return false;
    if (seg.fin) {
      c.tcp.rcv = seg.seq + seg.len + 1;
      const me = this.io.myIp();
      if (me) this.io.send(tcpFlag(me, c.server, c.lport, c.port, c.tcp, { ackFlag: true }), ctx);
      this.closing = undefined;
    }
    return true;
  }

  handleIke(): boolean {
    return false;
  }

  unwrap(): undefined {
    return undefined;
  }

  /** 내보낼 패킷: 연결돼 있고 터널로 갈 목적지면 출발지를 가상 주소로 바꿔 터널로. 가로챘으면 true */
  intercept(pkt: Ipv4Packet, ctx: NodeContext): boolean {
    const s = this.s;
    if (!s || s.phase !== "up" || !s.push) return false;
    const p = pkt.payload;
    if (p.kind === "udp" && (p.payload.kind === "ovpn" || p.payload.kind === "dhcp")) return false;
    if (p.kind === "tcp" && p.ovpn) return false;
    if (pkt.dst === s.server || pkt.dst === "255.255.255.255" || this.io.local(pkt.dst)) return false;
    const push = s.push;
    const routed = push.redirectGateway || sameSubnet(pkt.dst, push.ip, push.prefix) || push.routes.some((r) => sameSubnet(pkt.dst, r.dest, r.prefix));
    if (!routed) return false;
    const inner: Ipv4Packet = { ...pkt, src: push.ip };
    const m: OvpnMessage = { kind: "ovpn", op: "data", sid: s.sid, inner };
    s.txBytes += ovpnLength(m, 84);
    ctx.trace("vpn.encap", "L3", `OpenVPN: ${pkt.dst} 는 ${push.redirectGateway ? "redirect-gateway 라" : "PUSH 받은 경로라"} 터널로 — 출발지 ${pkt.src} → 가상 주소 ${push.ip}, ${s.proto.toUpperCase()} ${s.server}:${s.port} 로 감쌈`, { ovpn: true, dst: pkt.dst });
    const outer = this.wrap(m);
    if (outer) this.sendRaw(outer, ctx);
    return true;
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const d = data as { ovpn?: string; tok?: number; sid?: number; at?: number };
    if (d.ovpn === "reconnect") {
      if (d.tok !== this.reconnectTok || this.s || !this.config.enabled) return;
      this.failed = undefined;
      ctx.trace("vpn.config", "sys", `OpenVPN: 다시 연결 (connect-retry)`, { ovpn: true });
      this.connect(ctx);
      return;
    }
    const s = this.s;
    if (!s) return;
    if (d.ovpn === "retry") {
      if (d.tok !== s.tok || s.phase === "up") return;
      if (s.tries >= OVPN_TRIES) {
        const o = this.config.ovpn;
        const what = s.phase === "syn" ? `TCP ${s.server}:${s.port} 연결 응답 없음 (SYN timeout) — 서버가 꺼져 있거나 그 포트가 막힘` : `${s.server}:${s.port}/${s.proto} 응답 없음 (TLS key negotiation failed to occur within 3 seconds) — ${o?.tlsCrypt ? "tls-crypt 키가 다르거나, " : ""}서버가 꺼져 있거나, 전송(${s.proto.toUpperCase()})·포트가 다르거나, 방화벽이 막음`;
        this.close(ctx, undefined);
        this.fail(ctx, what);
        return;
      }
      s.tries++;
      const me = this.io.myIp();
      if (!me) return;
      if (s.phase === "syn" && s.tcp) {
        s.tcp.snd -= 1;
        ctx.trace("vpn.handshake", "L4", `OpenVPN: SYN 응답 없음 → 다시 보냄 (${s.tries}/${OVPN_TRIES})`, { ovpn: true });
        this.sendRaw(tcpFlag(me, s.server, s.lport, s.port, s.tcp, { syn: true }), ctx);
      } else if (s.pending) {
        ctx.trace("vpn.handshake", "L4", `OpenVPN: ${OP_LABEL[s.pending.op]} 응답 없음 → 다시 보냄 (${s.tries}/${OVPN_TRIES})`, { ovpn: true });
        const outer = this.wrap(s.pending);
        if (outer) this.sendRaw(outer, ctx);
      }
      s.tok = ++this.tok;
      ctx.timer(OVPN_RETRY, OVPN_TIMER_TAG, { ovpn: "retry", tok: s.tok });
      return;
    }
    if (d.sid !== s.sid || s.phase !== "up") return;
    if (d.ovpn === "ping") {
      if (ctx.now - s.lastTx >= OVPN_PING) {
        const outer = this.wrap({ kind: "ovpn", op: "ping", sid: s.sid });
        ctx.trace("vpn.keepalive", "L4", `OpenVPN: ${OVPN_PING / 1000}초 동안 보낸 게 없음 → ping (keepalive)`, { ovpn: true });
        if (outer) this.sendRaw(outer, ctx);
      }
      ctx.timer(Math.max(1, s.lastTx + OVPN_PING - ctx.now), OVPN_TIMER_TAG, { ovpn: "ping", sid: s.sid }, true);
      return;
    }
    if (d.ovpn === "restart") {
      if (s.lastRx !== d.at) {
        ctx.timer(Math.max(1, s.lastRx + OVPN_PING_RESTART - ctx.now), OVPN_TIMER_TAG, { ovpn: "restart", sid: s.sid, at: s.lastRx }, true);
        return;
      }
      ctx.trace("vpn.drop", "L4", `OpenVPN: ${OVPN_PING_RESTART / 1000}초 동안 서버에게서 받은 게 없음 (Inactivity timeout --ping-restart) → 다시 연결`, { ovpn: true });
      this.s = undefined;
      this.connect(ctx);
    }
  }

  onDpdTick(): void {}

  /** 내 주소가 바뀌거나 잃음: 연결 상태가 있는 VPN 이라 다시 붙는다 (UDP 는 float 가 없으면 서버가 새 주소를 모른다) */
  lost(ctx: NodeContext, why: string): void {
    if (!this.s) return;
    const was = this.s.phase === "up";
    this.s = undefined;
    this.closing = undefined;
    if (was) ctx.trace("vpn.drop", "L4", `OpenVPN: ${why} → 터널이 끊김 (주소를 다시 얻으면 새로 연결)`, { ovpn: true });
  }

  disconnect(ctx: NodeContext, why: string): void {
    this.close(ctx, why);
    this.failed = undefined;
  }

  reconnect(ctx: NodeContext): void {
    this.close(ctx, "다시 연결");
    this.failed = undefined;
    this.connect(ctx);
  }

  dpd(ctx: NodeContext): void {
    ctx.trace("vpn.dpd", "L4", `OpenVPN 에는 IKE DPD 가 없음 — keepalive(${OVPN_PING / 1000}초마다 ping, ${OVPN_PING_RESTART / 1000}초 동안 받은 게 없으면 다시 연결)가 같은 일을 한다`, { dpd: "none" });
  }

  summary(): string | undefined {
    if (!this.config.enabled) return undefined;
    const o = this.config.ovpn;
    if (!o || !this.config.server || !o.ca || !o.cert.cn) return "설정 필요 (서버 주소·CA·내 인증서)";
    const s = this.s;
    if (s?.phase === "up" && s.push) return `연결됨 · 가상 주소 ${s.push.ip} · ${s.push.redirectGateway ? "모든 트래픽" : s.push.routes.map((r) => `${r.dest}/${r.prefix}`).join(", ") || "터널 대역만"} 는 터널로 · ${s.proto.toUpperCase()} ${s.port}`;
    if (s || this.resolving) return `연결 중 (${s?.phase === "syn" ? "TCP 연결" : s?.phase === "reset" ? "세션 시작" : s?.phase === "tls" || s?.phase === "auth" ? "TLS·인증서 확인" : "이름 풀기"})`;
    if (this.failed) return `실패 · ${this.failed}`;
    return "대기 (주소를 받으면 연결)";
  }
}
