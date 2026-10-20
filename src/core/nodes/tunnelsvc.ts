// 공유기의 터널 서버 (WireGuard 서버·OpenVPN 서버·메시 VPN): 붙은 기기가 공유기 안쪽의 터널 대역 주소를 쓰는 셋을 한 모양으로.
// 전에는 "내 터널 주소인가·붙은 기기인가·대역 안인가·WAN 주소가 바뀌면" 을 곳곳에서 셋을 손으로 나열했고, 한 곳에서 하나가 빠졌다
// (DNS 포워더가 메시 주소로 온 질의에 LAN 주소로 답함). 목록에 넣으면 모든 곳에 적용된다.
// L2TP 서버는 모양이 다르다: 붙은 기기에게 LAN 대역의 주소를 주고 프록시 ARP 로 LAN 기기처럼 보이게 한다 (ipTIME 식 — `lan.outbound`)
import type { Ip } from "../addr";
import type { Ipv4Packet } from "../packet";
import type { NodeContext } from "./node";

export interface TunnelService {
  /** 로그 이름 (WireGuard · OpenVPN · Tailscale/ZeroTier) */
  readonly label: string;
  /** "~ 로 붙은 기기" 의 조사까지 ("OpenVPN 으로") */
  readonly via: string;
  /** 공유기 자신의 터널 주소 (꺼져 있으면 없음) */
  address(): Ip | undefined;
  /** 이 주소로 지금 붙어 있는 기기가 있나 */
  owns(dst: Ip): boolean;
  /** 붙은 기기에게 그 터널로. 보냈으면 true */
  send(pkt: Ipv4Packet, ctx: NodeContext, frameId?: number): boolean;
  /** 터널 대역 안인데 그 주소로 붙은 기기가 없을 때의 No route 사유 (대역 밖이면 undefined) */
  noPeer(dst: Ip): string | undefined;
  /** 붙은 기기에게 허락한 것: 집 LAN, 인터넷 (internet 이 없으면 허락) */
  access(): { lanAccess: boolean; internet?: boolean };
  /** WAN 주소가 생기거나 바뀌거나 사라짐: 옛 주소로 맺은 세션을 정리한다 (할 일이 없으면 왜 없는지 적어 둔다) */
  onAddress(ctx: NodeContext): void;
}
