// 게이트웨이·NAT 박스의 VPN 터널 끝: 사이트 간 VPN(vpn.ts, WireGuard 식·IPsec)과 원격 접속 VPN 서버(ravpn.ts)가
// 받은 패킷을 어느 쪽이 풀지 나누고(accept), 터널로 보낼 패킷을 감싸고(send), 풀린 원래 패킷을 장치에 돌려준다.
// 라우팅·NAT·방화벽은 장치(l3.ts)가 한다 — 여기서는 "터널 바깥 ↔ 안" 만.
import type { Ip } from "../addr";
import { IKE_PORT, NAT_T_PORT, VPN_PORT, type EspPacket, type Ipv4Packet } from "../packet";
import type { NodeContext } from "./node";
import type { RaServer } from "./ravpn";
import type { Vpn } from "./vpn";

/** 터널 끝이 장치에게서 빌리는 것 */
export interface TunnelHost {
  readonly vpn: Vpn;
  readonly ra: RaServer;
  /** 이 주소를 가진 인터페이스 (실제·가상 주소), 없으면 -1 */
  ownIndex(ip: Ip): number;
  /** 인터페이스의 대표 주소 (이중화 master 면 가상 주소) */
  addrOf(i: number): Ip | undefined;
  /** 터널 바깥(인터넷 쪽) 경로 — VPN 경로는 뺀다 */
  underlay(dst: Ip): { out: number; nextHop: Ip } | undefined;
  /** 인터페이스 i 로 넥스트 홉을 정해 보낸다 */
  sendOut(i: number, pkt: Ipv4Packet, nextHop: Ip, ctx: NodeContext): void;
  /** 풀린 패킷이 나에게 온 것일 때 (ICMP 만 답한다) */
  deliverLocal(i: number, inner: Ipv4Packet, frameId: number, ctx: NodeContext): void;
  /** 풀린 패킷을 안쪽으로 넘긴다 (NAT 하지 않음, 방화벽은 인바운드) */
  forwardInner(inner: Ipv4Packet, inPort: number, frameId: number, ctx: NodeContext): void;
}

export class TunnelEnds {
  constructor(private readonly host: TunnelHost) {}

  /**
   * 나에게 온 터널 패킷이면 처리하고 true: WireGuard(UDP 51820 의 vpn), IKE(UDP 500/4500), NAT-T ESP(UDP 4500), ESP(IP 50).
   * NAT 역변환보다 먼저 푼다. VPN 을 켜지 않은 장비(예: VPN 게이트웨이 앞의 NAT 박스)는 false — 보통 UDP 로 NAT 역변환·포트 포워딩
   */
  accept(port: number, pkt: Ipv4Packet, frameId: number, ctx: NodeContext): boolean {
    const { vpn, ra } = this.host;
    if (this.host.ownIndex(pkt.dst) < 0) return false;
    const p = pkt.payload;
    if (p.kind === "udp") {
      const m = p.payload;
      if (m.kind === "vpn" && vpn.config.enabled && vpn.mode === "wireguard") {
        this.receive(port, pkt, p.srcPort, m.inner, frameId, ctx);
        return true;
      }
      // IPsec: 원격 접속 협상이면 원격 접속 서버, 아니면 사이트 간 VPN
      if (m.kind === "ike" && (p.dstPort === IKE_PORT || p.dstPort === NAT_T_PORT)) {
        return ra.handleIke(pkt, p.srcPort, p.dstPort, m, ctx, frameId) || vpn.handleIke(pkt, p.srcPort, p.dstPort, m, ctx, frameId);
      }
      if (m.kind === "esp" && p.dstPort === NAT_T_PORT) return this.esp(port, pkt, p.srcPort, m, frameId, ctx);
      return false;
    }
    if (p.kind === "esp") return this.esp(port, pkt, undefined, p, frameId, ctx);
    return false;
  }

  /** 받은 ESP 를 원격 접속 클라이언트·모르는 원격 접속(풀 안)·사이트 간 IPsec 순으로 나눈다 */
  private esp(port: number, pkt: Ipv4Packet, srcPort: number | undefined, esp: EspPacket, frameId: number, ctx: NodeContext): boolean {
    const { vpn, ra } = this.host;
    if (ra.clientFor(pkt, esp)) {
      this.receiveRa(port, pkt, srcPort, esp, frameId, ctx);
      return true;
    }
    // 가상 주소 풀에서 온 모르는 원격 접속 ESP: INVALID_SPI 로 알려 클라이언트가 다시 접속하게
    if (ra.inPool(esp.inner.src)) {
      ra.orphan(pkt, srcPort, esp, ctx, frameId);
      return true;
    }
    if (vpn.config.enabled && vpn.mode === "ipsec") {
      this.receive(port, pkt, srcPort, esp.inner, frameId, ctx);
      return true;
    }
    return false;
  }

  /** 터널로 보낸다: 원래 패킷을 암호화해 UDP 51820(WireGuard) 또는 ESP(IPsec)에 담아 상대 공인 주소로. 바깥 패킷은 내가 만든 것이라 NAT 하지 않는다 */
  send(inner: Ipv4Packet, ctx: NodeContext, frameId?: number): void {
    const { vpn } = this.host;
    if (vpn.mode === "ipsec") {
      vpn.sendIpsec(inner, ctx, frameId);
      return;
    }
    const t = vpn.target();
    const under = t ? this.host.underlay(t.ip) : undefined;
    const src = under ? this.host.addrOf(under.out) : undefined; // 이중화 master 면 가상 주소 (넘어가도 상대가 같은 주소로 답하게)
    const outer = src ? vpn.encapsulate(inner, src) : undefined;
    if (!outer || !under) {
      ctx.trace("vpn.drop", "L3", `VPN: 상대 ${t?.ip ?? "(주소 없음)"} 로 가는 바깥 경로가 없어 터널로 보낼 수 없음 → 드롭 (상대 공인 주소와 디폴트 라우트를 확인)`, { dst: inner.dst }, frameId);
      return;
    }
    const u = outer.payload as { dstPort: number };
    ctx.trace(
      "vpn.encap",
      "L3",
      `VPN 캡슐화: ${inner.src} → ${inner.dst} 패킷을 암호화해 UDP ${outer.src}:51820 → ${outer.dst}:${u.dstPort} 안에 담음 — 인터넷 위에서는 공인 주소끼리의 UDP 로만 보이고 안쪽은 볼 수 없다`,
      { inner: `${inner.src}>${inner.dst}`, peer: outer.dst },
      frameId,
    );
    this.host.sendOut(under.out, outer, under.nextHop, ctx);
  }

  /** 받은 사이트 간 터널 패킷: 허용한 상대 대역에서 온 것만 풀어서 안으로 */
  private receive(port: number, outer: Ipv4Packet, srcPort: number | undefined, inner: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const { vpn } = this.host;
    const ipsec = vpn.mode === "ipsec";
    const noSa = ipsec ? vpn.refuseEsp() : undefined;
    const why = noSa ?? vpn.refuse(outer, inner);
    if (why) {
      ctx.trace("vpn.drop", "L3", `${ipsec ? "IPsec ESP" : "VPN 패킷"} 수신 (from ${outer.src}) → 풀지 않고 드롭: ${why}`, { from: outer.src }, frameId);
      if (noSa) vpn.onOrphanEsp(outer.src, ctx, frameId);
      return;
    }
    if (ipsec) {
      vpn.followPeer(outer.src, srcPort, ctx, frameId);
      vpn.heard(ctx.now);
      vpn.received++;
      ctx.trace(
        "vpn.decap",
        "L3",
        `IPsec 복호화: ${outer.src} 에서 온 ${srcPort !== undefined ? "UDP 4500 (NAT-T) 안의 " : ""}ESP 를 풀어 원래 패킷 ${inner.src} → ${inner.dst} 를 꺼냄 (출발지가 터널 대역 안인지 확인함)`,
        { from: outer.src, inner: `${inner.src}>${inner.dst}` },
        frameId,
      );
    } else {
      const moved = vpn.learn(outer, srcPort ?? VPN_PORT);
      ctx.trace(
        "vpn.decap",
        "L3",
        `VPN 복호화: ${outer.src}:${srcPort} 에서 온 터널 패킷을 풀어 원래 패킷 ${inner.src} → ${inner.dst} 를 꺼냄${moved ? ` — 이제 상대에게는 ${outer.src}:${srcPort} 로 답함${outer.src !== vpn.config.peer ? " (상대가 NAT 뒤라 설정한 주소와 다름)" : ""}` : ""}`,
        { from: outer.src, inner: `${inner.src}>${inner.dst}` },
        frameId,
      );
    }
    this.deliver(port, inner, frameId, ctx);
  }

  /** 원격 접속 클라이언트의 ESP: 풀어서 안으로 (안쪽 출발지 = 그 클라이언트의 가상 주소) */
  private receiveRa(port: number, outer: Ipv4Packet, srcPort: number | undefined, esp: EspPacket, frameId: number, ctx: NodeContext): void {
    const { ra } = this.host;
    const c = ra.clientFor(outer, esp)!;
    const inner = esp.inner;
    ra.follow(c, outer.src, srcPort);
    ctx.trace("vpn.decap", "L3", `원격 접속 복호화: ${outer.src} 의 ESP 를 풀어 ${inner.src}(가상 주소) → ${inner.dst} 패킷을 꺼냄`, { from: outer.src, inner: `${inner.src}>${inner.dst}` }, frameId);
    this.deliver(port, inner, frameId, ctx);
  }

  /** 풀린 패킷: 나에게 온 것이면 ICMP 만 답하고, 아니면 안쪽으로 */
  private deliver(port: number, inner: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const mine = this.host.ownIndex(inner.dst);
    if (mine >= 0) {
      if (inner.payload.kind === "icmp") this.host.deliverLocal(mine, inner, frameId, ctx);
      else ctx.trace("ip.drop", "L4", `터널로 온 ${inner.payload.kind.toUpperCase()} 가 나에게 왔지만 듣는 서비스 없음 → 드롭`, {}, frameId);
      return;
    }
    this.host.forwardInner(inner, port, frameId, ctx);
  }
}
