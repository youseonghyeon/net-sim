// 공유기의 SIP ALG: NAT 를 지나는 SIP 의 SDP·Contact 에 적힌 사설 주소를 공인 주소로 고치고, 음성(RTP) 포트를 받을 NAT 구멍을 연다.
// 통화가 끝나면(BYE·그 200) 구멍을 닫고, 같은 공유기 뒤 두 전화기가 서로의 구멍으로 보내면 안에서 바로 되돌린다(NAT 루프백)
import type { Ip } from "../addr";
import type { Ipv4Packet } from "../packet";
import type { Firewall } from "./firewall";
import type { NatTable } from "./nat";
import type { NodeContext } from "./node";
import { sipAlgRewrite } from "./sip";

/** SIP ALG 가 공유기에게서 빌리는 것 */
export interface SipAlgHost {
  readonly firewall: Firewall;
  /** WAN1 의 공인 주소와 NAT (NAT 루프백) */
  wanIp(): Ip | undefined;
  readonly wanNat: NatTable;
  /** LAN 으로 내보낸다 */
  toLan(pkt: Ipv4Packet, ctx: NodeContext): void;
}

export class SipAlg {
  enabled = false;
  /** 통화(Call-ID)마다 ALG 가 연 구멍 */
  private readonly pinholes = new Map<string, { nat: NatTable; publicId: number; lanIp: Ip; port: number }[]>();

  constructor(private readonly host: SipAlgHost) {}

  set(on: boolean, ctx: NodeContext): void {
    if (on === this.enabled) return;
    this.enabled = on;
    ctx.trace("ip.config", "sys", on ? "SIP ALG 켜짐: 나가는 SIP 의 SDP·Contact 에 적힌 사설 주소를 공인 주소로 고치고, 음성(RTP) 포트를 받을 NAT 구멍을 연다" : "SIP ALG 꺼짐: SIP 를 건드리지 않음 (NAT 뒤 전화기의 SDP 는 사설 주소 그대로 나간다)", { sipAlg: on });
  }

  private close(callId: string, ctx: NodeContext): void {
    const list = this.pinholes.get(callId);
    if (!list) return;
    this.pinholes.delete(callId);
    for (const h of list) {
      h.nat.closePinhole("udp", h.publicId);
      this.host.firewall.expects.delete(`udp:${h.lanIp}:${h.port}`);
    }
    ctx.trace("sip.alg", "L4", `SIP ALG: 통화 ${callId} 가 끝남 → 음성 포트로 열어 둔 구멍 ${list.map((h) => h.publicId).join(", ")} 을(를) 닫음`, { sipAlg: true });
  }

  /** LAN 기기가 내 공인 주소의 ALG 구멍으로 보낸 UDP (같은 공유기 뒤 두 전화기): 공유기 안에서 바로 그 기기에게 되돌린다 (NAT 루프백). 처리했으면 true */
  hairpin(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): boolean {
    const u = pkt.payload;
    const wanIp = this.host.wanIp();
    if (u.kind !== "udp" || !wanIp || pkt.dst !== wanIp) return false;
    const e = this.host.wanNat.entries.get(`udp:${u.dstPort}`);
    if (!e?.pinhole) return false;
    const inner: Ipv4Packet = { ...pkt, dst: e.lanIp, ttl: pkt.ttl - 1, payload: { ...u, dstPort: e.innerId } };
    ctx.trace("ip.forward", "L3", `NAT 루프백: ${pkt.src} 가 내 공인 주소 ${pkt.dst}:${u.dstPort} (SIP ALG 가 연 음성 포트)로 보냄 → 안쪽 ${e.lanIp}:${e.innerId} 로 바로 되돌림 (같은 공유기 뒤의 상대)`, { dst: e.lanIp }, frameId);
    this.host.toLan(inner, ctx);
    return true;
  }

  /** NAT 를 지난 SIP: 안쪽 주소가 적힌 SDP·Contact 를 공인 주소로 */
  rewrite(orig: Ipv4Packet, out: Ipv4Packet, publicIp: Ip, nat: NatTable, frameId: number, ctx: NodeContext): Ipv4Packet {
    const u = out.payload;
    if (u.kind !== "udp" || u.payload.kind !== "sip") return out;
    const m = u.payload;
    // 통화가 끝나면(BYE·그 200) 이 통화로 연 구멍을 닫는다
    if (m.method === "BYE" || (m.status === 200 && m.cseq === -1)) this.close(m.callId, ctx);
    const fixed = sipAlgRewrite(m, orig.src, publicIp, u.srcPort, (lanIp, port) => {
      const id = nat.openPinhole("udp", lanIp, port, ctx.now);
      const list = this.pinholes.get(m.callId) ?? [];
      list.push({ nat, publicId: id, lanIp, port });
      this.pinholes.set(m.callId, list);
      // 방화벽에도 이 음성 포트를 미리 들인다 (conntrack 의 expectation·RELATED)
      this.host.firewall.expects.add(`udp:${lanIp}:${port}`);
      return id;
    });
    if (fixed === m) return out;
    ctx.trace(
      "sip.alg",
      "L4",
      `SIP ALG: ${m.method ?? `${m.status}`} 안의 ${fixed.sdp && m.sdp ? `SDP 음성 주소 ${m.sdp.ip}:${m.sdp.port} → ${fixed.sdp.ip}:${fixed.sdp.port} (그 포트로 들어오는 음성을 ${orig.src}:${m.sdp.port} 로 넘길 NAT 구멍을 엶)` : ""}${fixed.contact && m.contact && fixed.contact.ip !== m.contact.ip ? `${fixed.sdp ? ", " : ""}Contact ${m.contact.ip} → ${fixed.contact.ip}:${fixed.contact.port}` : ""}`,
      { sipAlg: true },
      frameId,
    );
    return { ...out, payload: { ...u, payload: fixed } };
  }
}
