// 단말의 원격 접속 VPN 클라이언트 (IKEv2·L2TP/IPsec·WireGuard·OpenVPN) 의 공통 모양: 호스트는 종류를 묻지 않고 이것만 부른다.
// 전에는 호스트가 instanceof 로 9곳에서 나눴고(받기·timer·DNS·표 이름·종류 바꾸기), 각 클래스는 쓰지 않는 메서드를 빈 몸으로 흉내 냈다
import type { Ip } from "../addr";
import type { EspPacket, IkeMessage, Ipv4Packet } from "../packet";
import type { NodeContext } from "./node";
import type { RaClientConfig, RaClientState } from "./ravpn";

export type VpnKind = "ikev2" | "l2tp" | "wireguard" | "openvpn";

export interface VpnClient {
  readonly kind: VpnKind;
  /** 개요 표의 이름 */
  readonly label: string;
  config: RaClientConfig;
  readonly state: RaClientState;
  readonly vip: Ip | undefined;
  readonly routes: readonly { dest: Ip; prefix: number }[];
  readonly reason: string | undefined;
  readonly dpdWaiting: boolean;
  setConfig(cfg: RaClientConfig, ctx: NodeContext): void;
  /** 주소를 얻음: 켜져 있으면 접속 */
  connect(ctx: NodeContext): void;
  /** 사용자가 끄거나 종류를 바꿈: 서버에 알리고 끊는다 */
  disconnect(ctx: NodeContext, why: string): void;
  /** 내 주소가 바뀌거나 잃음 */
  lost(ctx: NodeContext, why: string): void;
  /** 사용자의 "다시 연결" */
  reconnect(ctx: NodeContext): void;
  /** 사용자의 "DPD 보내기" (IKEv2 만 — 나머지는 안내만) */
  dpd(ctx: NodeContext): void;
  /** 터널로 보낼 패킷이면 싣고 true (호스트의 iface.outbound) */
  intercept(pkt: Ipv4Packet, ctx: NodeContext): boolean;
  /** 이 VPN 이 알려 준 DNS (지금 그것으로 물어야 할 때만) */
  vpnDns(): Ip | undefined;
  /** 내 주소로 온 패킷이 이 VPN 의 것이면 처리: 풀린 안쪽 패킷, null = 내 것이지만 넘길 것 없음, undefined = 내 것 아님 */
  receive(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): Ipv4Packet | null | undefined;
  /** 이 VPN 의 timer 면 처리하고 true (다른 종류가 남긴 timer 는 무시) */
  timer(tag: string, data: unknown, ctx: NodeContext): boolean;
  /** 다른 종류로 바꿔 낄 때 늦게 올 수 있는 TCP 연결 ("서버:내 포트" — 호스트가 기억해 조용히 버린다) */
  lateTcp(): string[];
  summary(): string | undefined;
}

/** IPsec 클라이언트(IKEv2·L2TP/IPsec)의 받기: 서버의 IKE 응답, 터널로 온 ESP (NAT-T 면 UDP 4500 안) */
export function receiveIpsec(
  c: {
    config: RaClientConfig;
    handleIke(outer: Ipv4Packet, srcPort: number, dstPort: number, m: IkeMessage, ctx: NodeContext, frameId?: number): boolean;
    unwrap(outer: Ipv4Packet, esp: EspPacket, ctx: NodeContext, frameId: number): Ipv4Packet | undefined | null;
  },
  pkt: Ipv4Packet,
  frameId: number,
  ctx: NodeContext,
): Ipv4Packet | null | undefined {
  if (!c.config.enabled) return undefined;
  const p = pkt.payload;
  if (p.kind === "udp" && p.payload.kind === "ike" && c.handleIke(pkt, p.srcPort, p.dstPort, p.payload, ctx, frameId)) return null;
  const esp = p.kind === "esp" ? p : p.kind === "udp" && p.payload.kind === "esp" ? p.payload : undefined;
  if (!esp) return undefined;
  const inner = c.unwrap(pkt, esp, ctx, frameId);
  if (inner === undefined) ctx.trace("vpn.drop", "L3", `ESP 수신 (from ${pkt.src}) → 내 원격 접속 터널 것이 아님 → 드롭`, {}, frameId);
  return inner ?? null;
}
