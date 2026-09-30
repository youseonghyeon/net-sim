// IPsec IKEv2 공용 부품: 사이트 간 VPN(vpn.ts)과 원격 접속 VPN(ravpn.ts)이 같이 쓴다.
// 두 VPN 이 다른 것은 정책(누구와 맺나, 무엇을 터널로 보내나)뿐이고, 협상의 모양은 같다:
//   IKE_SA_INIT (NAT 감지) → IKE_AUTH (PSK) → ESP (NAT 가 있으면 UDP 4500 안, NAT-T)
// 요청은 IKE_TIMEOUT 마다 IKE_RETRANSMITS 번 다시 보내고 그래도 답이 없으면 포기한다.
// 맺은 뒤의 요청(DPD: 빈 INFORMATIONAL 로 상대가 살아 있나 확인)도 같은 재전송을 쓴다.
import type { Ip } from "../addr";
import { NAT_T_PORT, type EspPacket, type IkeMessage, type Ipv4Packet } from "../packet";
import type { NodeContext } from "./node";

/** IKE 요청마다 응답을 기다리는 시간. 지나면 같은 요청을 다시 보내고(재전송), IKE_RETRANSMITS 번 뒤에도 없으면 포기 */
export const IKE_TIMEOUT = 1000;
/** 주기 DPD 간격 (strongSwan dpddelay): 상대에게서 이만큼 받은 것이 없으면 DPD 를 보낸다 */
export const DPD_INTERVAL = 10_000;
export const IKE_RETRANSMITS = 2;

export function hex(n: number): string {
  return n.toString(16).padStart(8, "0");
}

/** 결정론적 SPI: 씨앗 문자열(두 주소·시도 횟수 등)의 해시 (실제로는 난수) */
export function spiOf(seed: string): number {
  let h = 0x811c9dc5;
  for (const ch of seed) h = Math.imul(h ^ ch.charCodeAt(0), 0x01000193) >>> 0;
  return h >>> 0 || 1;
}

/** IKE 메시지를 실은 UDP 패킷 */
export function ikePacket(src: Ip, dst: Ip, srcPort: number, dstPort: number, m: IkeMessage): Ipv4Packet {
  return { kind: "ipv4", src, dst, ttl: 64, payload: { kind: "udp", srcPort, dstPort, payload: m } };
}

/** ESP 의 바깥 패킷: NAT 가 있으면 UDP 4500 안(NAT-T), 없으면 IP 프로토콜 50 그대로 */
export function espPacket(src: Ip, peer: { ip: Ip; port: number }, natT: boolean, esp: EspPacket): Ipv4Packet {
  return natT
    ? { kind: "ipv4", src, dst: peer.ip, ttl: 64, payload: { kind: "udp", srcPort: NAT_T_PORT, dstPort: peer.port, payload: esp } }
    : { kind: "ipv4", src, dst: peer.ip, ttl: 64, payload: esp };
}

/** 응답자의 NAT 감지: 상대가 적은 자기 주소가 실제 출발지와 다르면 상대 앞에, 상대가 적은 내 주소가 실제 목적지와 다르면 내 앞에 NAT */
export function natAtResponder(m: IkeMessage, outerSrc: Ip, me: Ip): { remoteNat: boolean; localNat: boolean; nat: boolean } {
  const remoteNat = m.natSrc !== outerSrc;
  const localNat = m.natDst !== me;
  return { remoteNat, localNat, nat: remoteNat || localNat };
}

/** 시작한 쪽의 NAT 감지 (응답에 적힌, 상대가 본 주소로): 이 결과면 IKE_AUTH 부터 UDP 4500 */
export function natAtInitiator(m: IkeMessage, outerSrc: Ip, me: Ip): { localNat: boolean; remoteNat: boolean; natT: boolean } {
  const localNat = m.natDst !== undefined && m.natDst !== me;
  const remoteNat = m.natSrc !== undefined && m.natSrc !== outerSrc;
  return { localNat, remoteNat, natT: m.nat === true || localNat || remoteNat };
}

/** 시작한 쪽의 요청 재전송: 마지막 요청을 기억해 timer 에 단계·요청 번호·시도 횟수를 실어 지난 timer 를 구분한다 */
export class IkeRetransmit {
  private last: { src: Ip; dst: Ip; port: number; dstPort: number; msg: IkeMessage; tries: number; id: number } | undefined;
  /** 요청 번호 (IKE 의 Message ID 격): 같은 단계의 요청이 두 번 이어져도(EAP 의 두 번째 IKE_AUTH) 앞 요청의 timer 가 뒤 요청을 끊지 않게 */
  private seq = 0;

  constructor(
    private readonly tag: string,
    private readonly send: (pkt: Ipv4Packet, ctx: NodeContext, frameId?: number) => void,
  ) {}

  /** @param dstPort 상대 포트가 내 포트와 다를 때 (NAT 뒤 상대의 매핑된 포트) */
  request(src: Ip, dst: Ip, port: number, msg: IkeMessage, ctx: NodeContext, frameId?: number, dstPort: number = port): void {
    this.transmit({ src, dst, port, dstPort, msg, tries: 0, id: ++this.seq }, ctx, frameId);
  }

  private transmit(l: NonNullable<IkeRetransmit["last"]>, ctx: NodeContext, frameId?: number): void {
    this.last = l;
    this.send(ikePacket(l.src, l.dst, l.port, l.dstPort, l.msg), ctx, frameId);
    ctx.timer(IKE_TIMEOUT, this.tag, { spi: l.msg.spi, step: l.msg.exchange, tries: l.tries, id: l.id });
  }

  /**
   * timer 가 울림: 지금 기다리는 단계·SPI·요청의 것이면 "retransmit"(아직 횟수가 남음) 또는 "giveup", 지난 것이면 "ignore".
   * retransmit 이면 이어서 resend() 를 부른다 (그 사이에 로그를 남길 수 있게)
   */
  check(data: unknown, spi: number, current: IkeMessage["exchange"] | undefined): { verdict: "ignore" | "retransmit" | "giveup"; step: string; tries: number } {
    const { spi: s, step, tries, id } = data as { spi: number; step: IkeMessage["exchange"]; tries: number; id: number };
    const last = this.last;
    if (s !== spi || step !== current || !last || last.msg.exchange !== step || last.tries !== tries || last.id !== id) return { verdict: "ignore", step, tries };
    return { verdict: tries < IKE_RETRANSMITS ? "retransmit" : "giveup", step, tries };
  }

  resend(ctx: NodeContext): void {
    const l = this.last;
    if (l) this.transmit({ ...l, tries: l.tries + 1 }, ctx);
  }

  clear(): void {
    this.last = undefined;
  }
}
