// 공유기의 WireGuard 클라이언트 (GL.iNet 식 VPN 게이트웨이): LAN 기기의 트래픽을 VPN 서버로 — VPN 정책(모든 기기·목록 제외·목록만),
// 출발지를 내 터널 주소로 바꾸는 NAT, 킬 스위치(끊기면 WAN 으로 새지 않게), DNS 포워더의 업스트림 질의를 터널로(DNS 유출 방지),
// 서버를 이름으로 적었으면 지금 회선으로 풀고 핸드셰이크가 실패하면 다시 푼다(reresolve)
import type { Ip } from "../addr";
import { DNS_PORT, type Ipv4Packet, type WgMessage } from "../packet";
import type { DnsResolver, DnsServer } from "./dns";
import type { Firewall } from "./firewall";
import type { Emit, NetInterface } from "./iface";
import { NatTable } from "./nat";
import type { NodeContext } from "./node";
import { WG_POLICY_LABEL, type RouterWgClientConfig } from "./routercfg";
import { DEFAULT_WG, WgInterface, prefixesLabel, type WgPeerState } from "./wg";

/** WireGuard 클라이언트가 공유기에게서 빌리는 것 */
export interface WgClientHost {
  readonly firewall: Firewall;
  /** 공유기 자신이 만든 바깥 패킷의 출발지·길 (늘 지금 회선 — 받은 회선을 기억하지 않는다) */
  source(dst?: Ip): Ip | undefined;
  send(outer: Ipv4Packet, ctx: NodeContext): void;
  /** 서버 이름을 물을 지금 회선의 리졸버 (label = 로그의 회선 이름) */
  resolverNow(ctx: NodeContext): { resolver: DnsResolver; ip: Ip | undefined; label: string; emit: Emit };
  /** 모든 회선 리졸버의 캐시에서 이 이름을 지운다 (바뀐 주소를 받으려고) */
  forget(name: string): void;
  /** 지금 회선에 주소가 있나 (설정을 바꾸면 바로 서버 이름을 푼다) */
  lineReady(): boolean;
  /** WAN1 이 링크·주소가 있나 (설정을 바꾸면 바로 잇는다) */
  wan1Ready(): boolean;
  /** LAN 대역의 기기인가 */
  inLan(ip: Ip): boolean;
  /** 드롭인으로 들어온 기기(WAN 쪽 LAN)인가 */
  fromDropIn(ip: Ip): boolean;
  /** 안쪽 기기에게 보낼 인터페이스 (드롭인 기기면 WAN) */
  insideOf(ip: Ip, ctx: NodeContext): { iface: NetInterface; emit: Emit };
  /** 드롭인 기기에게 되돌린다 (보냈으면 true) */
  toDropInClient(inner: Ipv4Packet, ttl: number, frameId: number, ctx: NodeContext): boolean;
  toLan(pkt: Ipv4Packet, ctx: NodeContext): void;
  dns(): DnsServer;
  emitLan(ctx: NodeContext): Emit;
}

export class RouterWgClient {
  /** 터널 (wgc) */
  readonly wgc: WgInterface;
  cfg: RouterWgClientConfig | undefined;
  /** LAN 기기의 출발지를 내 터널 주소로 (서버는 이 주소 하나만 안다 — AllowedIPs) */
  readonly nat = new NatTable();
  /** 바깥 UDP 포트 (설정에 ListenPort 가 없으면 임의 포트 — 여기서는 장치마다 고정) */
  readonly port: number;

  constructor(
    private readonly host: WgClientHost,
    id: string,
    port: number,
    cfg: RouterWgClientConfig | undefined,
  ) {
    this.wgc = new WgInterface({ source: (dst?: Ip) => host.source(dst), send: (outer, ctx) => host.send(outer, ctx) }, "WireGuard 클라이언트", `${id}:client`);
    this.port = port;
    this.cfg = cfg;
    this.nat.why = "VPN 서버는 이 공유기를 터널 주소 하나로만 안다(AllowedIPs) — LAN 기기 주소를 터널 주소로 바꾸고 테이블에 기록";
    // 핸드셰이크가 끝내 실패하면 서버 이름을 다시 풀어 본다 (집 공인 주소가 바뀌었을 수 있다 — GL.iNet 의 reresolve)
    this.wgc.onFail = (_p, ctx) => {
      if (this.cfg?.enabled && this.cfg.serverName) this.resolveServer(ctx, "핸드셰이크 실패 — 서버 주소가 바뀌었을 수 있어 이름을 다시 풂", true);
    };
    this.wgc.needEndpoint = (_p, ctx) => {
      if (this.cfg?.enabled && this.cfg.serverName) this.resolveServer(ctx, "보낼 패킷이 생겼는데 서버 주소를 모름 — 이름을 다시 풂");
    };
  }

  /** 설정 (만든 직후·설정 변경) — prev = 바꾸기 전 설정 */
  setConfig(c: RouterWgClientConfig | undefined, ctx: NodeContext): void {
    const prev = this.cfg;
    this.cfg = c;
    const changed = this.wgc.setConfig(
      c
        ? {
            enabled: c.enabled,
            privateKey: c.privateKey,
            ...(c.address ? { address: c.address } : {}),
            listenPort: this.port,
            peers: [{ name: "VPN 서버", publicKey: c.serverKey, ...(c.server ? { endpoint: c.server } : {}), allowedIps: c.allowedIps }],
            ...(c.obfuscate ? { obfuscate: true } : {}),
          }
        : { ...DEFAULT_WG, peers: [] },
      ctx,
    );
    if (changed && c?.enabled && c.serverName && this.host.lineReady()) this.resolveServer(ctx, "설정");
    // 킬 스위치·VPN 정책·DNS 는 터널 설정이 아니라 공유기의 길 고르기라 wgc 는 그대로 — 그래도 바뀐 것은 남긴다
    const routing = (x?: RouterWgClientConfig) => JSON.stringify(x ? { k: x.killSwitch, p: x.policy, d: x.dns } : null);
    if ((changed || (prev?.enabled && routing(prev) !== routing(c))) && c?.enabled) {
      ctx.trace("vpn.config", "sys", `WireGuard 클라이언트: ${WG_POLICY_LABEL[c.policy.mode]}${c.policy.mode !== "all" ? ` (${c.policy.devices.join(", ") || "목록 비어 있음"})` : ""} → ${prefixesLabel(c.allowedIps)} 로 가는 LAN 트래픽을 터널로. 킬 스위치 ${c.killSwitch ? "켜짐 (VPN 이 끊기면 인터넷 차단)" : "꺼짐 (VPN 이 끊기면 WAN 으로 바로 — 실제 주소가 드러남)"}${c.dns ? `, DNS 는 ${c.dns} 에 터널로` : ""}`, { wg: true, killSwitch: c.killSwitch, policy: c.policy.mode });
      if (changed && this.host.wan1Ready() && !c.serverName) this.wgc.connect(ctx);
    }
  }

  /** WAN 이 주소를 받음: 서버 이름을 풀거나 바로 잇는다 (GL.iNet 은 인터넷이 연결되면 VPN 을 자동으로 잇는다) */
  onWanAddress(ctx: NodeContext): void {
    if (!this.cfg?.enabled) return;
    if (this.cfg.serverName && !this.peer?.endpoint && !this.peer?.resolving) this.resolveServer(ctx, "WAN 연결됨");
    else this.wgc.connect(ctx);
  }

  /** VPN 서버 이름을 풀어 엔드포인트로 (캐시는 지우고 — 바뀐 주소를 받으려고) */
  private resolveServer(ctx: NodeContext, why: string, reresolve = false): void {
    const n = this.cfg?.serverName;
    const peer = this.peer;
    const { resolver, ip, label, emit } = this.host.resolverNow(ctx);
    if (!n || !peer || !ip) return;
    this.host.forget(n.name);
    this.wgc.markResolving(peer);
    ctx.trace("vpn.config", "sys", `WireGuard 클라이언트: ${why} → ${n.name} 을(를) ${label} 으로 직접 물음 (터널 밖)`, { wg: true, name: n.name });
    resolver.resolve(n.name, ctx, emit, (ip, reason) => {
      if (!this.cfg?.enabled || this.cfg.serverName?.name !== n.name) return;
      if (!ip) {
        peer.resolving = false;
        peer.failed = `서버 이름 ${n.name} 을(를) 풀지 못함 (${reason ?? "?"})`;
        const q = peer.queue.length;
        peer.queue = [];
        if (peer.prevEndpoint) {
          peer.endpoint = peer.prevEndpoint;
          peer.prevEndpoint = undefined;
        }
        ctx.trace("vpn.drop", "L4", `WireGuard 클라이언트: ${peer.failed}${q ? ` → 기다리던 패킷 ${q}개 드롭` : ""}${peer.endpoint ? ` — 전에 쓰던 ${peer.endpoint.ip} 로 계속 시도` : " — 보낼 패킷이 또 생기면 다시 풂"}. DDNS 이름과 공유기 DNS 를 확인`, { wg: true, failed: true });
        return;
      }
      ctx.trace("vpn.config", "sys", `WireGuard 클라이언트: ${n.name} = ${ip} → 엔드포인트 ${ip}:${n.port}`, { wg: true, name: n.name, ip });
      this.wgc.setEndpoint(peer, { ip, port: n.port }, ctx, reresolve ? "if-changed" : "always");
    });
  }

  /** 클라이언트 쪽 피어 (서버 하나) */
  get peer(): WgPeerState | undefined {
    return this.wgc.peers.values().next().value;
  }

  /** 끊겨(핸드셰이크 실패) 쉬는 중인지 — 킬 스위치가 꺼져 있으면 이때 WAN 으로 바로 나간다 */
  private down(): boolean {
    const p = this.peer;
    return !p || (!!p.failed && !p.pending && !p.session);
  }

  /** 이 LAN 기기의 트래픽을 VPN 으로 보내는지 (VPN 정책) */
  policyApplies(src: Ip): boolean {
    const c = this.cfg;
    if (!c?.enabled || !this.wgc.enabled) return false;
    const inside = this.host.inLan(src) || this.host.fromDropIn(src);
    if (!inside) return false;
    if (c.policy.mode === "exclude") return !c.policy.devices.includes(src);
    if (c.policy.mode === "only") return c.policy.devices.includes(src);
    return true;
  }

  /**
   * DNS 포워더의 업스트림 질의를 터널로 보내는지. client = 질의한 기기: VPN 정책에서 빠진 기기(목록 제외·목록에 없음)의 질의는
   * 그 기기의 다른 트래픽처럼 WAN 으로 (킬 스위치에 막히지 않게). LAN 밖(공유기 자신·VPN 서버의 피어)은 정책을 보지 않는다
   */
  dnsVia(client?: Ip): boolean {
    const c = this.cfg;
    if (!c?.enabled || !this.wgc.enabled || !c.address) return false;
    if (client && this.host.inLan(client) && !this.policyApplies(client)) return false;
    const up = c.dns ?? this.host.dns().config.upstream;
    if (!up || !this.wgc.route(up)) return false;
    return !(this.down() && !c.killSwitch);
  }

  /** DNS 포워더의 업스트림 질의를 터널로 (끊겨 있으면 킬 스위치가 붙잡는다 — DNS 유출 방지) */
  dnsTo(pkt: Ipv4Packet, ctx: NodeContext): void {
    const peer = this.wgc.route(pkt.dst);
    if (!peer) return;
    if (this.down()) ctx.trace("vpn.killswitch", "L3", `킬 스위치: VPN 이 끊겨 있어 DNS 질의(${pkt.dst})를 WAN 으로 내보내지 않음 → 터널이 다시 맺어지기를 기다림 (DNS 유출 방지)`, { dst: pkt.dst, killSwitch: true });
    ctx.trace("ip.forward", "L3", `DNS 포워더: 업스트림 ${pkt.dst} 질의를 VPN 터널로 (출발지 = 내 터널 주소 ${pkt.src}) — 호텔·통신사 DNS 가 내 질의를 보지 못한다`, { dst: pkt.dst, wg: true });
    this.wgc.send(peer, pkt, ctx);
  }

  /** 이 바깥 포트로 온 WireGuard 는 내 것인가 */
  listens(port: number): boolean {
    return !!this.cfg?.enabled && this.wgc.enabled && port === this.wgc.config.listenPort;
  }

  /** WAN 으로 온 내 터널의 WireGuard 메시지 */
  receive(pkt: Ipv4Packet, srcPort: number, m: WgMessage, frameId: number, ctx: NodeContext): void {
    const inner = this.wgc.handle(pkt, srcPort, m, ctx, frameId);
    if (inner) this.fromTunnel(inner, frameId, ctx);
  }

  /**
   * LAN 기기의 패킷을 터널로: 출발지를 내 터널 주소로 바꿔(NAT) 서버에 보낸다. 보냈으면 true.
   * 끊겨 있으면 킬 스위치가 켜져 있을 때만 붙잡고(다시 핸드셰이크), 꺼져 있으면 false — WAN 으로 바로 나간다
   */
  toTunnel(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): boolean {
    const c = this.cfg!;
    const peer = this.wgc.route(pkt.dst);
    if (!peer || pkt.dst === c.server?.ip || pkt.dst === peer.endpoint?.ip) return false;
    if (!c.address) {
      if (!c.killSwitch) return false;
      ctx.trace("vpn.killswitch", "L3", `킬 스위치: VPN 클라이언트에 내 터널 주소가 없어 VPN 을 쓸 수 없음 → ${pkt.src} → ${pkt.dst} 를 WAN 으로 내보내지 않음 (WireGuard 클라이언트 → 내 터널 주소)`, { src: pkt.src, dst: pkt.dst, killSwitch: true }, frameId);
      return true;
    }
    if (this.down()) {
      if (!c.killSwitch) {
        ctx.trace("vpn.leak", "L3", `VPN 이 끊겨 있음 (${peer.failed ?? "핸드셰이크 실패"}) → 킬 스위치가 꺼져 있어 ${pkt.src} → ${pkt.dst} 를 WAN 으로 바로 내보냄 — VPN 을 거치지 않아 실제 공인 주소가 드러난다. 다시 연결을 시도`, { src: pkt.src, dst: pkt.dst, killSwitch: false }, frameId);
        this.wgc.connect(ctx);
        return false;
      }
      ctx.trace("vpn.killswitch", "L3", `킬 스위치: VPN 이 끊겨 있어 ${pkt.src} → ${pkt.dst} 를 WAN 으로 내보내지 않음 → 터널이 다시 맺어지기를 기다림`, { src: pkt.src, dst: pkt.dst, killSwitch: true }, frameId);
    }
    if (pkt.ttl <= 1) {
      const side = this.host.insideOf(pkt.src, ctx);
      const notice = side.iface.timeExceeded(pkt, ctx, frameId);
      if (notice) side.iface.sendIp(notice, ctx, side.emit);
      return true;
    }
    if (!this.host.firewall.check(pkt, "out", ctx, frameId)) return true;
    const translated = this.nat.translate({ ...pkt, ttl: pkt.ttl - 1 }, c.address.ip, ctx, frameId);
    if (!translated) return true;
    ctx.trace("ip.forward", "L3", `라우팅: ${pkt.dst} 는 VPN 정책 대상 → WireGuard 클라이언트 터널로 (출발지 ${pkt.src} → 내 터널 주소 ${c.address.ip}, TTL ${pkt.ttl} → ${translated.ttl})`, { dst: pkt.dst, wg: true }, frameId);
    this.wgc.send(peer, translated, ctx, frameId);
    return true;
  }

  /** 터널로 들어온 패킷: 내 질의의 답(DNS)·나에게 온 ping, 아니면 NAT 역변환해 LAN 기기로 */
  private fromTunnel(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const c = this.cfg!;
    const me = c.address?.ip;
    if (!me || pkt.dst !== me) {
      ctx.trace("vpn.drop", "L3", `WireGuard 클라이언트: 풀린 패킷의 목적지 ${pkt.dst} 가 내 터널 주소(${me ?? "없음"})가 아님 → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    const p = pkt.payload;
    if (p.kind === "udp" && p.payload.kind === "dns" && p.payload.op === "response" && p.dstPort === DNS_PORT) {
      this.host.dns().handle(pkt, p.srcPort, p.payload, frameId, ctx, this.host.emitLan(ctx));
      return;
    }
    if (p.kind === "icmp" && p.type === "echo-request") {
      ctx.trace("icmp.echo.received", "app", `ICMP Echo 요청 수신 (from ${pkt.src}, 터널로, seq=${p.seq})`, { from: pkt.src, seq: p.seq }, frameId);
      const reply: Ipv4Packet = { kind: "ipv4", src: me, dst: pkt.src, ttl: 64, payload: { kind: "icmp", type: "echo-reply", id: p.id, seq: p.seq } };
      const peer = this.wgc.route(pkt.src);
      if (peer) this.wgc.send(peer, reply, ctx, frameId);
      return;
    }
    const restored = this.nat.restore(pkt, me, ctx, frameId);
    if (!restored) return;
    if (!this.host.firewall.check(restored, "in", ctx, frameId)) return;
    if (pkt.ttl <= 1) return;
    const inner: Ipv4Packet = { ...restored, ttl: pkt.ttl - 1 };
    if (this.host.toDropInClient(inner, pkt.ttl, frameId, ctx)) return;
    ctx.trace("ip.forward", "L3", `라우팅: VPN 터널의 응답 → NAT 역변환해 LAN 의 ${inner.dst} 로 (TTL ${pkt.ttl} → ${inner.ttl})`, { dst: inner.dst, wg: true }, frameId);
    this.host.toLan(inner, ctx);
  }

  /** 사용자의 "다시 연결" */
  reconnect(ctx: NodeContext): void {
    if (!this.cfg?.enabled) {
      ctx.trace("vpn.drop", "L4", `WireGuard 클라이언트가 꺼져 있음 → 연결할 것이 없음`, {});
      return;
    }
    this.wgc.reset();
    if (this.cfg.serverName) this.resolveServer(ctx, "다시 연결");
    else this.wgc.connect(ctx);
  }

  /** 표시용 한 줄: 상태 */
  summary(): string | undefined {
    const c = this.cfg;
    if (!c?.enabled) return undefined;
    const p = this.peer;
    const state = !p ? "설정 확인 필요" : p.session ? `연결됨 · 터널 주소 ${c.address?.ip ?? "?"}` : p.pending ? "연결 중 (핸드셰이크)" : p.resolving ? "서버 이름을 푸는 중" : p.failed ? `끊김 (${p.failed.split(" — ")[0]}) · ${c.killSwitch ? "킬 스위치로 인터넷 차단 중" : "WAN 으로 바로 나가는 중 (킬 스위치 꺼짐)"}` : "대기 (보낼 패킷이 생기면 연결)";
    const server = c.serverName ? `${c.serverName.name}${p?.endpoint ? ` = ${p.endpoint.ip}` : ""}:${c.serverName.port}` : c.server ? `${c.server.ip}:${c.server.port}` : "없음";
    return `${state} · 서버 ${server}`;
  }
}
