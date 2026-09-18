// NAT 변환 테이블. 라우터(공유기)와 NAT 박스가 공유한다. ICMP 는 id, TCP 는 포트로 구분한다.
import type { Ip } from "../addr";
import type { Ipv4Packet } from "../packet";
import type { NodeContext } from "./node";

export interface NatEntry {
  proto: "icmp" | "tcp" | "udp";
  lanIp: Ip;
  /** ICMP id 또는 내부 호스트의 TCP 포트 */
  innerId: number;
  /** 공인 쪽 ICMP id 또는 포트 */
  publicId: number;
  createdAt: number;
  lastUsed: number;
}

export const NAT_ID_START = 40000;

/** 포트 포워딩 규칙: 공인 쪽 TCP 포트로 들어온 연결을 내부 호스트로 */
export interface PortForward {
  publicPort: number;
  lanIp: Ip;
  lanPort: number;
}

export class NatTable {
  /** "proto:공인id" → 매핑 */
  readonly entries = new Map<string, NatEntry>();
  private readonly byInner = new Map<string, string>();
  private seq = NAT_ID_START;

  get size(): number {
    return this.entries.size;
  }

  values(): NatEntry[] {
    return [...this.entries.values()];
  }

  /** 안 → 밖: 출발지를 공인 주소로 바꾼다 (ICMP 는 id, TCP/UDP 는 출발 포트) */
  translate(pkt: Ipv4Packet, publicIp: Ip, ctx: NodeContext, frameId?: number): Ipv4Packet | undefined {
    const p = pkt.payload;
    const proto = p.kind;
    const innerId = p.kind === "icmp" ? p.id : p.srcPort;
    const key = `${proto}:${pkt.src}:${innerId}`;
    let natKey = this.byInner.get(key);
    if (natKey === undefined) {
      const publicId = this.seq++;
      natKey = `${proto}:${publicId}`;
      this.byInner.set(key, natKey);
      this.entries.set(natKey, { proto, lanIp: pkt.src, innerId, publicId, createdAt: ctx.now, lastUsed: ctx.now });
    }
    const entry = this.entries.get(natKey)!;
    entry.lastUsed = ctx.now;
    const unit = proto === "icmp" ? "ICMP id" : `${proto.toUpperCase()} 포트`;
    ctx.trace(
      "nat.translate",
      "L3",
      `NAT 변환: ${pkt.src} (${unit} ${innerId}) → ${publicIp} (${unit} ${entry.publicId}) — 사설 주소는 인터넷에서 쓸 수 없으므로 공인 주소로 바꾸고 테이블에 기록`,
      { proto, lanIp: pkt.src, innerId, publicId: entry.publicId },
      frameId,
    );
    return { ...pkt, src: publicIp, payload: p.kind === "icmp" ? { ...p, id: entry.publicId } : { ...p, srcPort: entry.publicId } };
  }

  /** 밖 → 안: 테이블에 있으면 목적지를 내부 호스트로 되돌린다 */
  restore(pkt: Ipv4Packet, publicIp: Ip, ctx: NodeContext, frameId?: number): Ipv4Packet | undefined {
    const p = pkt.payload;
    const proto = p.kind;
    const publicId = p.kind === "icmp" ? p.id : p.dstPort;
    const what = p.kind === "icmp" ? `ICMP id ${publicId}` : `${proto.toUpperCase()} 포트 ${publicId}`;
    const entry = this.entries.get(`${proto}:${publicId}`);
    if (!entry) {
      ctx.trace("nat.miss", "L3", `NAT 테이블에 없는 ${what} → 폐기. 내부에서 시작하지 않은 통신은 들어올 수 없음`, { proto, publicId }, frameId);
      return undefined;
    }
    entry.lastUsed = ctx.now;
    ctx.trace(
      "nat.restore",
      "L3",
      `NAT 역변환: ${publicIp} (${what}) → ${entry.lanIp} (${proto === "icmp" ? "id" : "포트"} ${entry.innerId}) — 테이블에 기록된 내부 호스트로 되돌림`,
      { proto, publicId, lanIp: entry.lanIp, innerId: entry.innerId },
      frameId,
    );
    return { ...pkt, dst: entry.lanIp, payload: p.kind === "icmp" ? { ...p, id: entry.innerId } : { ...p, dstPort: entry.innerId } };
  }

  rows(publicIp: Ip | undefined): string[][] {
    return this.values().map((e) => [
      `${e.lanIp} · ${e.proto === "icmp" ? "id" : "포트"} ${e.innerId}`,
      `${publicIp ?? "?"} · ${e.proto === "icmp" ? "id" : "포트"} ${e.publicId}`,
      `${e.lastUsed}ms`,
    ]);
  }
}
