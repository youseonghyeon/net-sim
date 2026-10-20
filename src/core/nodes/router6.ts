// 공유기의 IPv6 (NAT 없음): WAN 은 호스트처럼 ISP 의 RA 로 주소·기본 게이트웨이를, DHCPv6-PD 로 LAN 에 나눠 줄 프리픽스를 받고,
// LAN 에는 위임받은 첫 /64 를 RA 로 알린다. 지나가는 IPv6 는 주소 그대로 — NAT 가 하던 보호는 인바운드 기본 차단(Stateful)이 대신한다
import type { Ip, Mac } from "../addr";
import { ALL_NODES, formatIp6, isLinkLocal6, isMulticast6, parseIp6, sameSubnet6, UNSPECIFIED6 } from "../addr6";
import { DHCP6_CLIENT_PORT, DNS_PORT, isNdp, type EthernetFrame, type IpPacket, type Ipv6Packet, type TcpSegment } from "../packet";
import { DHCP6_TIMER_TAG, Dhcp6PdClient } from "./dhcp6";
import type { DnsServer } from "./dns";
import { Firewall } from "./firewall";
import type { Emit } from "./iface";
import { DAD_TIMER_TAG, Ipv6Interface, NDP_TIMEOUT_TAG, RA_PERIODIC_TAG, ROUTER_EXPIRY_TAG, RS_TIMER_TAG } from "./ipv6";
import type { NodeContext } from "./node";
import type { RouterIpv6Config } from "./routercfg";

/** IPv6 가 공유기에게서 빌리는 것 */
export interface Router6Host {
  readonly firewall: Firewall;
  emitLan(ctx: NodeContext): Emit;
  emitWan(ctx: NodeContext): Emit;
  wanLinkUp(): boolean;
  /** LAN 에서 공유기 자신에게 온 TCP (관리 화면). 처리했으면 true */
  adminTcp(pkt: Ipv6Packet, seg: TcpSegment, frameId: number, ctx: NodeContext): boolean;
  /** DNS 포워더 (IPv6 로 물어도 답한다) */
  dns(): DnsServer;
  /** DNS 가로채기 대상인가 */
  hijacks(dst: Ip): boolean;
  /** 차단한 기기의 프레임이면 기록하고 true */
  blockedFrame(src: Ip, dst: Ip, frame: EthernetFrame, ctx: NodeContext): boolean;
  torEnabled(): boolean;
  /** DPI 검사 (통과면 true) */
  dpiCheck(pkt: IpPacket, dir: "out" | "in", frameId: number, ctx: NodeContext): boolean;
}

export class Router6 {
  /** LAN(라우터 — RA 로 위임받은 /64 를 알림)과 WAN(호스트처럼 ISP 의 RA 로 주소·기본 게이트웨이) */
  readonly lan6: Ipv6Interface;
  readonly wan6: Ipv6Interface;
  readonly pd: Dhcp6PdClient;
  enabled = false;
  /** IPv6 인바운드 기본 차단 (나가는 것만 허용 + Stateful) */
  readonly inbound6: Firewall;
  /** LAN 쪽 IPv6 를 시작했는지 (LAN 은 내부 브리지라 첫 포트가 붙을 때 링크 로컬 DAD) */
  private lanStarted = false;

  constructor(
    private readonly host: Router6Host,
    private readonly lanMac: Mac,
    private readonly wanMac: Mac,
    seed: number,
    cfg: RouterIpv6Config | undefined,
  ) {
    this.lan6 = new Ipv6Interface(lanMac, true, "lan");
    this.lan6.raOffReason = "ISP 에게 아직 프리픽스를 위임받지 못해(DHCPv6-PD) 알릴 프리픽스가 없음 → RA 안 함";
    this.wan6 = new Ipv6Interface(wanMac, false, "wan");
    this.pd = new Dhcp6PdClient(wanMac, this.wan6, seed, (d, ctx) => this.onDelegation(d, ctx));
    this.wan6.onLinkLocalReady = (ctx, emit) => {
      if (this.enabled) this.pd.start(ctx, emit);
    };
    // 규칙 없이 기본 차단: 들어오는 것만 검사하고(check "in"), 나가는 것은 흐름만 기억한다(remember)
    this.inbound6 = new Firewall(
      { enabled: cfg?.inboundBlock !== false, defaultPolicy: "deny", stateful: true, rules: [] },
      "IPv6 기본 방화벽",
      "바깥에서 먼저 시작한 IPv6 연결은 기본 차단 — 열려면 공유기 방화벽에 이 연결을 허용하는 인바운드 규칙(핀홀)을 넣거나 IPv6 인바운드 기본 차단을 끄세요",
    );
    if (cfg?.enabled) {
      this.enabled = true;
      this.lan6.init({ enabled: true, addrs: [] });
      this.wan6.init({ enabled: true, addrs: [], slaac: true });
    }
  }

  /** 위임받은 프리픽스가 생기거나 사라짐: LAN 에 그 첫 /64 를 주소로 두고 RA 로 알린다 (사라지면 거둠 RA) */
  private onDelegation(d: { prefix: Ip; length: number } | undefined, ctx: NodeContext): void {
    if (!this.enabled) return;
    if (!d) {
      this.lan6.configure({ enabled: true, addrs: [], ra: false }, true, ctx, this.host.emitLan(ctx));
      return;
    }
    const lanIp = formatIp6(parseIp6(d.prefix)! | 1n);
    ctx.trace("ip.config", "sys", `[lan] 위임받은 ${d.prefix}/${d.length} 의 첫 /64 를 LAN 에: 공유기 LAN 주소 ${lanIp}/64 → RA 로 알려 집 안 장치가 SLAAC 로 공인 IPv6 주소를 만든다`, { prefix: d.prefix, lan: lanIp });
    this.lan6.configure({ enabled: true, addrs: [{ ip: lanIp, prefix: 64 }], ra: true, raDns: lanIp }, true, ctx, this.host.emitLan(ctx));
  }

  /** LAN 은 내부 브리지라 따로 링크가 없다: 첫 포트가 붙을 때 LAN IPv6 를 시작 (링크 로컬 DAD) */
  startLan(ctx: NodeContext): void {
    if (!this.enabled || this.lanStarted) return;
    this.lanStarted = true;
    this.lan6.linkUp(ctx, this.host.emitLan(ctx));
  }

  /** IPv6 켜기·끄기, 인바운드 기본 차단 */
  setConfig(cfg: RouterIpv6Config, ctx: NodeContext): void {
    if (cfg.inboundBlock !== this.inbound6.config.enabled) {
      this.inbound6.config = { ...this.inbound6.config, enabled: cfg.inboundBlock };
      ctx.trace("ip.config", "sys", cfg.inboundBlock ? `IPv6 인바운드 기본 차단 켜짐: 바깥에서 먼저 시작한 IPv6 연결은 막고, 안에서 시작한 통신의 응답만 들인다 (Stateful)` : `IPv6 인바운드 기본 차단 꺼짐: NAT 가 없으니 바깥에서 집 안 장치의 IPv6 주소로 바로 들어온다 (방화벽 규칙이 없다면)`, { inboundBlock: cfg.inboundBlock });
    }
    if (cfg.enabled === this.enabled) return;
    if (!cfg.enabled) {
      this.pd.release(ctx, this.host.emitWan(ctx));
      this.lan6.configure({ enabled: false, addrs: [] }, true, ctx, this.host.emitLan(ctx));
      this.wan6.configure({ enabled: false, addrs: [] }, this.host.wanLinkUp(), ctx, this.host.emitWan(ctx));
      this.enabled = false;
      this.lanStarted = false;
      return;
    }
    this.enabled = true;
    ctx.trace("ip.config", "sys", `IPv6 켜짐: WAN 은 ISP 의 RA 로 주소·기본 게이트웨이를, DHCPv6-PD 로 LAN 에 나눠 줄 프리픽스를 받는다`, {});
    this.lan6.configure({ enabled: true, addrs: [] }, true, ctx, this.host.emitLan(ctx));
    this.lanStarted = true;
    this.wan6.configure({ enabled: true, addrs: [], slaac: true }, this.host.wanLinkUp(), ctx, this.host.emitWan(ctx));
  }

  /** 위임받은 프리픽스 안의 주소인지 */
  private inDelegated(ip: Ip): boolean {
    const d = this.pd.delegated;
    return !!d && sameSubnet6(ip, d.prefix, d.length);
  }

  /** 공유기 자신에게 온 IPv6: ping 에 답하고, DNS 질의는 포워더로 */
  private local6(pkt: Ipv6Packet, via: Ipv6Interface, emit: (f: EthernetFrame) => void, frameId: number, ctx: NodeContext): void {
    const p = pkt.payload;
    if (p.kind === "icmp6" && p.type === "echo-request") {
      ctx.trace("icmp.echo.received", "app", `ICMPv6 Echo 요청 수신 (from ${pkt.src}, seq=${p.seq})`, { from: pkt.src, seq: p.seq }, frameId);
      const src = pkt.dst === ALL_NODES ? via.sourceFor(pkt.src) : pkt.dst;
      if (!src) return;
      ctx.trace("icmp.reply.sent", "app", `ICMPv6 Echo 응답 생성 → ${pkt.src} (seq=${p.seq})`, { to: pkt.src, seq: p.seq });
      via.send({ kind: "ipv6", src, dst: pkt.src, hopLimit: 64, payload: { kind: "icmp6", type: "echo-reply", id: p.id, seq: p.seq } }, ctx, emit);
      return;
    }
    if (p.kind === "tcp" && via === this.lan6 && this.host.adminTcp(pkt, p, frameId, ctx)) return;
    if (p.kind === "udp" && p.payload.kind === "dns" && p.dstPort === DNS_PORT && via === this.lan6) {
      if (this.host.dns().config.enabled || p.payload.op === "response") this.host.dns().handle(pkt, p.srcPort, p.payload, frameId, ctx, emit);
      else ctx.trace("dns.nxdomain", "app", `DNS 포워더가 꺼져 있음 → IPv6 로 온 질의에 응답하지 않음`, {}, frameId);
      return;
    }
    if (pkt.dst === ALL_NODES) return;
    ctx.trace("ip.drop", "L4", `공유기 자신에게 온 IPv6 ${p.kind === "tcp" ? `TCP ${p.dstPort}` : p.kind === "udp" ? `UDP ${p.dstPort}` : "패킷"} → 듣는 서비스 없음, 드롭`, {}, frameId);
  }

  /** LAN 에서 온 IPv6: NDP·공유기 자신·바깥으로 (NAT 없이 주소 그대로) */
  handleLan(pkt: Ipv6Packet, frame: EthernetFrame, ctx: NodeContext): void {
    const emit = this.host.emitLan(ctx);
    if (!this.enabled || !this.lan6.enabled) {
      if (frame.dst === this.lanMac) ctx.trace("frame.drop", "L3", `IPv6 패킷 수신 → 공유기 IPv6 가 꺼져 있어 드롭 (공유기 설정에서 IPv6 를 켜세요)`, {}, frame.id);
      return;
    }
    const p = pkt.payload;
    if (isNdp(p)) {
      this.lan6.handleNdp(pkt, p, frame, ctx, emit);
      return;
    }
    if (this.lan6.owns(pkt.dst) || this.wan6.owns(pkt.dst) || pkt.dst === ALL_NODES) {
      this.local6(pkt, this.lan6, emit, frame.id, ctx);
      return;
    }
    // DNS 가로채기 (ip6tables REDIRECT): IPv6 로 바깥 DNS 에 직접 묻는 질의도 공유기가 받는다
    if (p.kind === "udp" && p.payload.kind === "dns" && p.payload.op === "query" && p.dstPort === DNS_PORT && this.host.hijacks(pkt.dst)) {
      ctx.trace("dns.hijack", "L4", `DNS 가로채기: ${pkt.src} 가 ${pkt.dst} 에 IPv6 로 직접 묻는 질의 "${p.payload.name}" → 내보내지 않고 공유기 DNS 포워더가 받음 (AdGuard 필터를 거치게)`, { from: pkt.src, to: pkt.dst }, frame.id);
      this.host.dns().handle(pkt, p.srcPort, p.payload, frame.id, ctx, emit);
      return;
    }
    if (isMulticast6(pkt.dst)) return;
    if (isLinkLocal6(pkt.src) || isLinkLocal6(pkt.dst) || pkt.src === UNSPECIFIED6) {
      ctx.trace("ip.drop", "L3", `[lan] 링크 로컬 주소(fe80::/10)가 낀 패킷은 인터넷으로 넘기지 않음 → 드롭. 공인 IPv6 주소(SLAAC)가 필요하다`, { src: pkt.src, dst: pkt.dst }, frame.id);
      return;
    }
    if (this.lan6.onLink(pkt.dst)) {
      ctx.trace("ip.drop", "L3", `목적지 ${pkt.dst} 는 LAN 안의 주소 → 공유기를 거칠 필요가 없음 (호스트끼리 직접 통신) → 드롭`, { dst: pkt.dst }, frame.id);
      return;
    }
    if (this.inDelegated(pkt.dst)) {
      // 위임받은 /56 안인데 LAN /64 가 아님: ISP 로 보내면 다시 나에게 돌아온다 (RFC 7084 WPD-5 — 쓰지 않는 위임 프리픽스는 Unreachable)
      ctx.trace("ip.no-route", "L3", `No route: ${pkt.dst} 는 위임받은 ${this.pd.delegated!.prefix}/${this.pd.delegated!.length} 안이지만 LAN(/64)에 쓰지 않는 프리픽스 → 드롭하고 Destination Unreachable (no route)`, { dst: pkt.dst }, frame.id);
      const notice = this.lan6.unreachable(pkt, "net", ctx, frame.id);
      if (notice) this.lan6.send(notice, ctx, emit);
      return;
    }
    if (pkt.hopLimit <= 1) {
      const notice = this.lan6.timeExceeded(pkt, ctx, frame.id);
      if (notice) this.lan6.send(notice, ctx, emit);
      return;
    }
    if (!this.wan6.defaultRouter) {
      ctx.trace("ip.no-route", "L3", `No route: ${pkt.dst} 로 가는 IPv6 경로가 없음 — WAN 이 ISP 의 RA 를 받지 못해 IPv6 기본 게이트웨이가 없음 (WAN 케이블·ISP 확인)`, { dst: pkt.dst }, frame.id);
      const notice = this.lan6.unreachable(pkt, "net", ctx, frame.id);
      if (notice) this.lan6.send(notice, ctx, emit);
      return;
    }
    if (this.host.blockedFrame(pkt.src, pkt.dst, frame, ctx)) return;
    if (this.host.torEnabled()) {
      // Tor 는 IPv4 회로만 — IPv6 를 그대로 내보내면 실제 주소가 드러난다. 바로 실패를 알려 기기가 IPv4(→ Tor)로 다시 시도하게
      ctx.trace("tor.drop", "L3", `Tor: ${pkt.src} → ${pkt.dst} 는 IPv6 — Tor 회로로 나르지 않음 → 버리고 Destination Unreachable (기기는 IPv4 로 다시 시도)`, { tor: true, dst: pkt.dst }, frame.id);
      const notice = this.lan6.unreachable(pkt, "net", ctx, frame.id);
      if (notice) this.lan6.send(notice, ctx, emit);
      return;
    }
    if (!this.host.dpiCheck(pkt, "out", frame.id, ctx)) return;
    if (!this.host.firewall.check(pkt, "out", ctx, frame.id)) return;
    this.inbound6.remember(pkt, ctx); // 나가는 흐름을 기억해 돌아오는 응답을 들인다
    const out: Ipv6Packet = { ...pkt, hopLimit: pkt.hopLimit - 1 };
    ctx.trace("ip.forward", "L3", `라우팅(IPv6): ${pkt.dst} → wan (IPv6 기본 게이트웨이 ${this.wan6.defaultRouter}) — NAT 없이 출발지 ${pkt.src} 가 그대로 인터넷에 보인다, Hop Limit ${pkt.hopLimit} → ${out.hopLimit}`, { dst: pkt.dst, out: "wan" }, frame.id);
    this.wan6.send(out, ctx, this.host.emitWan(ctx));
  }

  /** WAN 에서 온 IPv6: ISP 의 RA·DHCPv6 Reply, 공유기 자신, 위임받은 프리픽스(LAN)로 */
  handleWan(pkt: Ipv6Packet, frame: EthernetFrame, ctx: NodeContext): void {
    const emit = this.host.emitWan(ctx);
    if (!this.enabled || !this.wan6.enabled) {
      if (frame.dst === this.wanMac) ctx.trace("frame.drop", "L3", `[wan] IPv6 패킷 수신 → 공유기 IPv6 가 꺼져 있어 드롭`, {}, frame.id);
      return;
    }
    const p = pkt.payload;
    if (isNdp(p)) {
      this.wan6.handleNdp(pkt, p, frame, ctx, emit);
      return;
    }
    if (p.kind === "udp" && p.payload.kind === "dhcp6" && p.dstPort === DHCP6_CLIENT_PORT) {
      this.pd.handle(pkt.src, p.payload, frame.id, ctx, emit);
      return;
    }
    if (this.wan6.owns(pkt.dst) || this.lan6.owns(pkt.dst) || pkt.dst === ALL_NODES) {
      this.local6(pkt, this.wan6, emit, frame.id, ctx);
      return;
    }
    if (isMulticast6(pkt.dst)) return;
    const lanPrefix = this.lan6.addrs.find((a) => a.origin === "manual");
    if (!lanPrefix || !this.lan6.onLink(pkt.dst) || isLinkLocal6(pkt.dst)) {
      if (this.inDelegated(pkt.dst)) {
        ctx.trace("ip.no-route", "L3", `[wan] ${pkt.dst} 는 위임받은 ${this.pd.delegated!.prefix}/${this.pd.delegated!.length} 안이지만 LAN(/64)에 쓰지 않는 프리픽스 → 드롭하고 Destination Unreachable (no route)`, { dst: pkt.dst }, frame.id);
        const notice = this.wan6.unreachable(pkt, "net", ctx, frame.id);
        if (notice) this.wan6.send(notice, ctx, emit);
      } else ctx.trace("ip.drop", "L3", `[wan] 목적지 ${pkt.dst} 는 위임받은 LAN 프리픽스가 아님 → 드롭`, { dst: pkt.dst }, frame.id);
      return;
    }
    if (pkt.hopLimit <= 1) {
      const notice = this.wan6.timeExceeded(pkt, ctx, frame.id);
      if (notice) this.wan6.send(notice, ctx, emit);
      return;
    }
    if (!this.host.dpiCheck(pkt, "in", frame.id, ctx)) return;
    if (!this.host.firewall.check(pkt, "in", ctx, frame.id)) return;
    // 공유기 방화벽에 이 연결을 허용하는 인바운드 규칙이 있으면 그것이 핀홀: 기본 차단을 건너뛴다
    if (!this.host.firewall.allowsByRule(pkt, "in") && !this.inbound6.check(pkt, "in", ctx, frame.id)) return;
    const out: Ipv6Packet = { ...pkt, hopLimit: pkt.hopLimit - 1 };
    ctx.trace("ip.forward", "L3", `라우팅(IPv6): ${pkt.dst} 는 위임받은 LAN 프리픽스 → LAN 으로 (NAT 역변환 없이 주소 그대로), Hop Limit ${pkt.hopLimit} → ${out.hopLimit}`, { dst: pkt.dst, out: "lan" }, frame.id);
    this.lan6.send(out, ctx, this.host.emitLan(ctx));
  }

  /** IPv6 의 timer 면 처리하고 true */
  onTimer(tag: string, data: unknown, ctx: NodeContext): boolean {
    if (tag === DAD_TIMER_TAG) {
      if (!this.lan6.finishDad(data, ctx, this.host.emitLan(ctx))) this.wan6.finishDad(data, ctx, this.host.emitWan(ctx));
      return true;
    }
    if (tag === RS_TIMER_TAG) {
      this.wan6.onRsTimer(data, ctx, this.host.emitWan(ctx));
      return true;
    }
    if (tag === ROUTER_EXPIRY_TAG) {
      this.wan6.onRouterExpiry(data, ctx);
      return true;
    }
    if (tag === RA_PERIODIC_TAG) {
      this.lan6.onRaTick(data, ctx, this.host.emitLan(ctx));
      return true;
    }
    if (tag === DHCP6_TIMER_TAG) {
      this.pd.onTimer(data, ctx, this.host.emitWan(ctx));
      return true;
    }
    if (tag === NDP_TIMEOUT_TAG) {
      // 바깥에서 LAN 호스트로 가려던 패킷의 주인이 없음 → 보낸 이에게 Address Unreachable (WAN 으로)
      for (const pkt of this.lan6.onNsTimeout(data, ctx)) {
        if (this.lan6.onLink(pkt.src)) continue;
        const notice = this.wan6.unreachable(pkt, "host", ctx);
        if (notice) this.wan6.send(notice, ctx, this.host.emitWan(ctx));
      }
      this.wan6.onNsTimeout(data, ctx);
      return true;
    }
    return false;
  }
}
