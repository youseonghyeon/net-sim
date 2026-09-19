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
  /** 포트 포워딩 규칙 (TCP 전용). 규칙 자체가 매핑이므로 동적 항목을 만들지 않는다 */
  forwards: PortForward[] = [];
  /** 규칙으로 들어온 흐름: "내부IP:내부포트:상대IP:상대포트" → 공인 포트 (같은 내부 서버를 가리키는 규칙이 여럿일 때 구분) */
  private readonly ruleFlows = new Map<string, number>();

  setForwards(rules: PortForward[]): void {
    this.forwards = [...rules];
  }

  /** 동적 공인 id 할당. TCP/UDP 포트는 포워딩 규칙의 공인 포트와 겹치지 않게 건너뛴다 */
  private allocPublicId(proto: NatEntry["proto"]): number {
    let id = this.seq++;
    if (proto !== "icmp") while (this.forwards.some((r) => r.publicPort === id)) id = this.seq++;
    return id;
  }

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
    if (p.kind === "tcp") {
      // 포트 포워딩으로 들어온 연결의 응답: 그 흐름이 들어온 공인 포트로 되돌린다 (동적 항목 없음)
      const flowPort = this.ruleFlows.get(`${pkt.src}:${p.srcPort}:${pkt.dst}:${p.dstPort}`);
      const rule = flowPort !== undefined ? this.forwards.find((r) => r.publicPort === flowPort) : this.forwards.find((r) => r.lanIp === pkt.src && r.lanPort === p.srcPort);
      if (rule) {
        ctx.trace(
          "nat.forward.reply",
          "L3",
          `포트 포워딩 응답: ${rule.lanIp}:${rule.lanPort} → 공인 :${rule.publicPort} (규칙의 역방향)`,
          { proto, lanIp: rule.lanIp, lanPort: rule.lanPort, publicPort: rule.publicPort },
          frameId,
        );
        return { ...pkt, src: publicIp, payload: { ...p, srcPort: rule.publicPort } };
      }
    }
    const innerId = p.kind === "icmp" ? p.id : p.srcPort;
    const key = `${proto}:${pkt.src}:${innerId}`;
    let natKey = this.byInner.get(key);
    if (natKey === undefined) {
      const publicId = this.allocPublicId(proto);
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
      if (p.kind === "tcp") {
        const rule = this.forwards.find((r) => r.publicPort === p.dstPort);
        if (rule) {
          ctx.trace(
            "nat.forward.rule",
            "L3",
            `포트 포워딩 규칙 적용: 공인 :${rule.publicPort} → ${rule.lanIp}:${rule.lanPort} — 바깥에서 시작한 연결이지만 규칙이 있어 안으로 들여보냄`,
            { proto, publicPort: rule.publicPort, lanIp: rule.lanIp, lanPort: rule.lanPort },
            frameId,
          );
          this.ruleFlows.set(`${rule.lanIp}:${rule.lanPort}:${pkt.src}:${p.srcPort}`, rule.publicPort);
          if (this.ruleFlows.size > 256) this.ruleFlows.delete(this.ruleFlows.keys().next().value!);
          return { ...pkt, dst: rule.lanIp, payload: { ...p, dstPort: rule.lanPort } };
        }
      }
      const hint = p.kind === "tcp" ? " (포트 포워딩 규칙을 추가하면 열 수 있음)" : "";
      ctx.trace("nat.miss", "L3", `NAT 테이블에 없는 ${what} → 폐기. 내부에서 시작하지 않은 통신은 들어올 수 없음${hint}`, { proto, publicId }, frameId);
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

  forwardRows(_publicIp: Ip | undefined): string[][] {
    return this.forwards.map((r) => [`공인 :${r.publicPort}`, `${r.lanIp}:${r.lanPort}`]);
  }
}
