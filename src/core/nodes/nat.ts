// NAT 변환 테이블. 라우터(공유기)와 NAT 박스가 공유한다. ICMP 는 id, TCP 는 포트로 구분한다.
import type { Ip } from "../addr";
import { icmpErrorLabel, isControl, isIcmpError, type IcmpError, type Ipv4Packet, type TcpSegment } from "../packet";
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
  /** TCP: 안쪽·바깥쪽이 FIN 을 보냈는지, 끝난 시각 (양쪽 FIN 뒤 마지막 ACK, 또는 RST) */
  finOut?: boolean;
  finIn?: boolean;
  closedAt?: number;
}

export const NAT_ID_START = 40000;
/**
 * 끝난 TCP 매핑을 남겨 두는 시간 (늦게 온 재전송을 위해 — TIME_WAIT 흉내, L4 로드밸런서와 같은 2초. 실제 conntrack 은 120초).
 * 지나면 다음 패킷이 지나갈 때 치운다 (타이머 없음). ICMP·UDP 매핑은 여전히 만료되지 않는다
 */
export const NAT_TCP_TIME_WAIT = 2000;

/** 포트 포워딩 규칙: 공인 쪽 TCP 포트로 들어온 연결을 내부 호스트로 */
export interface PortForward {
  publicPort: number;
  lanIp: Ip;
  lanPort: number;
  /** 없으면 TCP (예전 저장본 호환) */
  proto?: "tcp" | "udp";
}

/** 규칙이 이 프로토콜에 해당하는지 (proto 가 없으면 TCP) */
const ruleFor = (r: PortForward, proto: string) => (r.proto ?? "tcp") === proto;

export class NatTable {
  /** "proto:공인id" → 매핑 */
  readonly entries = new Map<string, NatEntry>();
  private readonly byInner = new Map<string, string>();
  private seq = NAT_ID_START;
  /** 포트 포워딩 규칙 (TCP 전용). 규칙 자체가 매핑이므로 동적 항목을 만들지 않는다 */
  forwards: PortForward[] = [];
  /** 규칙으로 들어온 흐름: "내부IP:내부포트:상대IP:상대포트" → 공인 포트 (같은 내부 서버를 가리키는 규칙이 여럿일 때 구분) */
  private readonly ruleFlows = new Map<string, number>();
  /** 새 매핑이 생길 때 (이중화 세션 동기화) */
  onNew?: (e: NatEntry, ctx: NodeContext) => void;

  /** 다른 장비(이중화 master)가 만든 매핑을 공인 id 그대로 받아 둔다. 이후 이 장비가 할당할 id 와 겹치지 않게 한다 */
  importEntry(e: Pick<NatEntry, "proto" | "lanIp" | "innerId" | "publicId">, now: number): void {
    const natKey = `${e.proto}:${e.publicId}`;
    const innerKey = `${e.proto}:${e.lanIp}:${e.innerId}`;
    // 같은 공인 id 를 다른 내부 호스트가 쓰고 있었으면(갈라졌던 동안 양쪽이 따로 할당) 그 연결을 지우고, 같은 내부 호스트의 옛 매핑도 지운다
    const old = this.entries.get(natKey);
    if (old) this.byInner.delete(`${old.proto}:${old.lanIp}:${old.innerId}`);
    const prevKey = this.byInner.get(innerKey);
    if (prevKey && prevKey !== natKey) this.entries.delete(prevKey);
    this.entries.set(natKey, { ...e, createdAt: now, lastUsed: now });
    this.byInner.set(innerKey, natKey);
    if (e.publicId >= this.seq) this.seq = e.publicId + 1;
  }

  setForwards(rules: PortForward[]): void {
    this.forwards = [...rules];
  }

  /** 동적 공인 id 할당. TCP/UDP 포트는 포워딩 규칙의 공인 포트와 겹치지 않게 건너뛴다 */
  /** 공인 포트로 고르면 안 되는 포트 (같은 장비의 포트 공개가 받는 포트·프록시 포트) */
  reserved: ((port: number) => boolean) | undefined;

  private allocPublicId(proto: NatEntry["proto"]): number {
    let id = this.seq++;
    while ((proto !== "icmp" && (this.forwards.some((r) => r.publicPort === id) || this.reserved?.(id) === true)) || this.entries.has(`${proto}:${id}`)) id = this.seq++;
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
    if (isIcmpError(p)) return this.translateError(pkt, p, publicIp, ctx, frameId);
    if (isControl(p)) return undefined; // 멀티캐스트 광고·동기화는 NAT 대상이 아님
    if (p.kind === "esp") {
      ctx.trace("nat.miss", "L3", `ESP(IPsec) ${pkt.src} → ${pkt.dst}: ESP 에는 포트가 없어 NAT 가 누구 것인지 구분할 수 없음 → 드롭. 양쪽 VPN 이 NAT 를 감지하면 UDP 4500 (NAT-T) 로 싣는다`, { proto: "esp" }, frameId);
      return undefined;
    }
    const proto = p.kind;
    if (p.kind === "tcp" || p.kind === "udp") {
      // 포트 포워딩으로 들어온 흐름의 응답: 그 흐름이 들어온 공인 포트로 되돌린다 (동적 항목 없음)
      const flowPort = this.ruleFlows.get(`${p.kind}:${pkt.src}:${p.srcPort}:${pkt.dst}:${p.dstPort}`);
      const rule =
        flowPort !== undefined
          ? this.forwards.find((r) => r.publicPort === flowPort && ruleFor(r, p.kind))
          : this.forwards.find((r) => r.lanIp === pkt.src && r.lanPort === p.srcPort && ruleFor(r, p.kind));
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
    this.expire(ctx.now);
    let natKey = this.byInner.get(key);
    if (natKey === undefined) {
      const publicId = this.allocPublicId(proto);
      natKey = `${proto}:${publicId}`;
      this.byInner.set(key, natKey);
      this.entries.set(natKey, { proto, lanIp: pkt.src, innerId, publicId, createdAt: ctx.now, lastUsed: ctx.now });
      this.onNew?.(this.entries.get(natKey)!, ctx);
    }
    const entry = this.entries.get(natKey)!;
    entry.lastUsed = ctx.now;
    if (p.kind === "tcp") this.noteTcp(entry, p, "out", ctx.now);
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

  /**
   * 안 → 밖으로 나가는 ICMP 오류(Time Exceeded·Unreachable): 출발지만 공인 주소로 바꾼다. 안에 내장된 원래 패킷은
   * 바깥에서 들어왔던 것이므로 그 목적지(내부 호스트)를 다시 공인 주소로 되돌려 바깥 호스트가 알아보게 한다 (RFC 5508)
   */
  private translateError(pkt: Ipv4Packet, p: IcmpError, publicIp: Ip, ctx: NodeContext, frameId?: number): Ipv4Packet {
    const o = p.original;
    let original = o;
    const innerId = o.l4.kind === "icmp" ? o.l4.id : o.l4.dstPort;
    const natKey = this.byInner.get(`${o.l4.kind}:${o.dst}:${innerId}`);
    const entry = natKey ? this.entries.get(natKey) : undefined;
    if (entry) {
      original = { ...o, dst: publicIp, l4: o.l4.kind === "icmp" ? { ...o.l4, id: entry.publicId } : { ...o.l4, dstPort: entry.publicId } };
    } else if (o.l4.kind !== "icmp") {
      const port = o.l4.dstPort;
      const rule = this.forwards.find((r) => r.lanIp === o.dst && r.lanPort === port && ruleFor(r, o.l4.kind));
      if (rule) original = { ...o, dst: publicIp, l4: { ...o.l4, dstPort: rule.publicPort } };
    }
    ctx.trace("nat.translate", "L3", `NAT 변환: ${icmpErrorLabel(p)} 통지의 출발지 ${pkt.src} → ${publicIp} (안에 내장된 원래 패킷의 내부 주소도 공인 주소로)`, { proto: "icmp", lanIp: pkt.src }, frameId);
    return { ...pkt, src: publicIp, payload: { ...p, original } };
  }

  /** 밖 → 안으로 들어온 ICMP 오류(Time Exceeded·Unreachable): 내장된 원래 패킷의 공인 id/포트로 테이블을 찾아 내부 호스트에게 되돌린다 */
  private restoreError(pkt: Ipv4Packet, p: IcmpError, publicIp: Ip, ctx: NodeContext, frameId?: number): Ipv4Packet | undefined {
    const o = p.original;
    const proto = o.l4.kind;
    const publicId = o.l4.kind === "icmp" ? o.l4.id : o.l4.srcPort;
    const what = proto === "icmp" ? `ICMP id ${publicId}` : `${proto.toUpperCase()} 포트 ${publicId}`;
    const entry = this.entries.get(`${proto}:${publicId}`);
    let lanIp: Ip;
    let innerId: number;
    if (entry) {
      entry.lastUsed = ctx.now;
      lanIp = entry.lanIp;
      innerId = entry.innerId;
    } else {
      const rule = proto !== "icmp" ? this.forwards.find((r) => r.publicPort === publicId && ruleFor(r, proto)) : undefined;
      if (!rule) {
        ctx.trace("nat.miss", "L3", `${icmpErrorLabel(p)} 안의 원래 패킷(${what})이 NAT 테이블에 없음 → 드롭. 내부에서 시작한 통신의 오류 통지만 들어올 수 있음`, { proto, publicId }, frameId);
        return undefined;
      }
      lanIp = rule.lanIp;
      innerId = rule.lanPort;
    }
    ctx.trace(
      "nat.restore",
      "L3",
      `NAT 역변환: ${icmpErrorLabel(p)} 안의 원래 패킷 (${publicIp}, ${what}) → ${lanIp} (${proto === "icmp" ? "id" : "포트"} ${innerId}) — 오류 통지도 원래 보낸 내부 호스트에게 되돌림`,
      { proto, publicId, lanIp, innerId },
      frameId,
    );
    const l4 = o.l4.kind === "icmp" ? { ...o.l4, id: innerId } : { ...o.l4, srcPort: innerId };
    return { ...pkt, dst: lanIp, payload: { ...p, original: { ...o, src: lanIp, l4 } } };
  }

  /** 밖 → 안: 테이블에 있으면 목적지를 내부 호스트로 되돌린다 */
  restore(pkt: Ipv4Packet, publicIp: Ip, ctx: NodeContext, frameId?: number): Ipv4Packet | undefined {
    const p = pkt.payload;
    if (isIcmpError(p)) return this.restoreError(pkt, p, publicIp, ctx, frameId);
    if (isControl(p)) return undefined; // 멀티캐스트 광고·동기화는 NAT 대상이 아님
    if (p.kind === "esp") {
      ctx.trace("nat.miss", "L3", `ESP(IPsec) ${pkt.src} → ${pkt.dst}: ESP 에는 포트가 없어 NAT 가 누구 것인지 구분할 수 없음 → 드롭. 양쪽 VPN 이 NAT 를 감지하면 UDP 4500 (NAT-T) 로 싣는다`, { proto: "esp" }, frameId);
      return undefined;
    }
    const proto = p.kind;
    const publicId = p.kind === "icmp" ? p.id : p.dstPort;
    const what = p.kind === "icmp" ? `ICMP id ${publicId}` : `${proto.toUpperCase()} 포트 ${publicId}`;
    const entry = this.entries.get(`${proto}:${publicId}`);
    if (!entry) {
      if (p.kind === "tcp" || p.kind === "udp") {
        const rule = this.forwards.find((r) => r.publicPort === p.dstPort && ruleFor(r, p.kind));
        if (rule) {
          ctx.trace(
            "nat.forward.rule",
            "L3",
            `포트 포워딩 규칙 적용: 공인 ${p.kind.toUpperCase()} :${rule.publicPort} → ${rule.lanIp}:${rule.lanPort} — 바깥에서 시작한 ${p.kind === "tcp" ? "연결" : "UDP 패킷"}이지만 규칙이 있어 안으로 들여보냄`,
            { proto, publicPort: rule.publicPort, lanIp: rule.lanIp, lanPort: rule.lanPort },
            frameId,
          );
          this.ruleFlows.set(`${p.kind}:${rule.lanIp}:${rule.lanPort}:${pkt.src}:${p.srcPort}`, rule.publicPort);
          if (this.ruleFlows.size > 256) this.ruleFlows.delete(this.ruleFlows.keys().next().value!);
          return { ...pkt, dst: rule.lanIp, payload: { ...p, dstPort: rule.lanPort } };
        }
      }
      const hint = p.kind !== "icmp" ? ` (${p.kind.toUpperCase()} 포트 포워딩 규칙을 추가하면 열 수 있음)` : "";
      ctx.trace("nat.miss", "L3", `NAT 테이블에 없는 ${what} → 드롭. 내부에서 시작하지 않은 통신은 들어올 수 없음${hint}`, { proto, publicId }, frameId);
      return undefined;
    }
    entry.lastUsed = ctx.now;
    if (p.kind === "tcp") this.noteTcp(entry, p, "in", ctx.now);
    ctx.trace(
      "nat.restore",
      "L3",
      `NAT 역변환: ${publicIp} (${what}) → ${entry.lanIp} (${proto === "icmp" ? "id" : "포트"} ${entry.innerId}) — 테이블에 기록된 내부 호스트로 되돌림`,
      { proto, publicId, lanIp: entry.lanIp, innerId: entry.innerId },
      frameId,
    );
    return { ...pkt, dst: entry.lanIp, payload: p.kind === "icmp" ? { ...p, id: entry.innerId } : { ...p, dstPort: entry.innerId } };
  }

  /** TCP 매핑의 끝을 본다: 양쪽 FIN 뒤 마지막 ACK, 또는 RST 면 끝난 것으로 표시 (새 SYN 이면 다시 시작) */
  private noteTcp(e: NatEntry, seg: TcpSegment, dir: "in" | "out", now: number): void {
    if (seg.syn && !seg.ackFlag) {
      delete e.finOut;
      delete e.finIn;
      delete e.closedAt;
      return;
    }
    if (e.closedAt !== undefined) return;
    if (seg.rst) e.closedAt = now;
    else if (seg.fin) {
      if (dir === "out") e.finOut = true;
      else e.finIn = true;
    } else if (e.finOut && e.finIn && seg.ackFlag && seg.len === 0) e.closedAt = now;
  }

  /** 끝난 지 TIME_WAIT 가 지난 TCP 매핑을 치운다 (닫힌 연결의 매핑이 끝없이 쌓이지 않게) */
  private expire(now: number): void {
    for (const [natKey, e] of [...this.entries]) {
      if (e.closedAt === undefined || now - e.closedAt < NAT_TCP_TIME_WAIT) continue;
      this.entries.delete(natKey);
      const innerKey = `${e.proto}:${e.lanIp}:${e.innerId}`;
      if (this.byInner.get(innerKey) === natKey) this.byInner.delete(innerKey);
    }
  }

  rows(publicIp: Ip | undefined): string[][] {
    return this.values().map((e) => [
      `${e.lanIp} · ${e.proto === "icmp" ? "id" : "포트"} ${e.innerId}`,
      `${publicIp ?? "?"} · ${e.proto === "icmp" ? "id" : "포트"} ${e.publicId}`,
      `${e.lastUsed}ms`,
    ]);
  }

  forwardRows(_publicIp: Ip | undefined): string[][] {
    return this.forwards.map((r) => [`${(r.proto ?? "tcp").toUpperCase()} 공인 :${r.publicPort}`, `${r.lanIp}:${r.lanPort}`]);
  }
}
