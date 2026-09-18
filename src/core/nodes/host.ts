import { isBroadcastMac, networkOf, sameSubnet, ZERO_MAC, BROADCAST_MAC, type Ip, type Mac } from "../addr";
import { describeFrame, type ArpPacket, type EthernetFrame, type Ipv4Packet } from "../packet";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";

export interface HostConfig {
  id: string;
  mac: Mac;
  ip?: Ip;
  prefix?: number;
  gateway?: Ip;
}

interface ArpEntry {
  mac: Mac;
  learnedAt: number;
}

interface PendingPacket {
  pkt: Ipv4Packet;
  queuedAt: number;
}

/** 단말 호스트: IP 설정, ARP 캐시, ICMP ping */
export class Host implements SimNode {
  static readonly ARP_TIMEOUT = 1000;

  readonly type = "host" as const;
  readonly portCount = 1;
  readonly id: string;
  readonly mac: Mac;
  ip: Ip | undefined;
  prefix: number;
  gateway: Ip | undefined;

  readonly arpCache = new Map<Ip, ArpEntry>();
  /** nextHop IP → ARP 해석을 기다리는 패킷들 */
  readonly pending = new Map<Ip, PendingPacket[]>();
  private readonly pings = new Map<string, { sentAt: number; dst: Ip }>();
  private readonly icmpId: number;
  private icmpSeq = 0;

  constructor(cfg: HostConfig) {
    this.id = cfg.id;
    this.mac = cfg.mac;
    this.ip = cfg.ip;
    this.prefix = cfg.prefix ?? 24;
    this.gateway = cfg.gateway;
    this.icmpId = 0x1000 + Math.abs(hashCode(cfg.id)) % 0x1000;
  }

  // ---------- 사용자 동작 ----------

  ping(dst: Ip, ctx: NodeContext): void {
    if (!this.ip) {
      ctx.trace("ip.drop", "L3", `IP 주소가 없어 ping 불가 (dst ${dst})`, { dst });
      return;
    }
    const seq = ++this.icmpSeq;
    const pkt: Ipv4Packet = {
      kind: "ipv4",
      src: this.ip,
      dst,
      ttl: 64,
      payload: { kind: "icmp", type: "echo-request", id: this.icmpId, seq },
    };
    this.pings.set(pingKey(this.icmpId, seq), { sentAt: ctx.now, dst });
    ctx.trace("icmp.echo.sent", "app", `ping ${dst} (seq=${seq}) → ICMP Echo 요청 생성`, { dst, seq });
    this.sendIp(pkt, ctx);
  }

  // ---------- L3 송신 경로 ----------

  private sendIp(pkt: Ipv4Packet, ctx: NodeContext): void {
    const nextHop = this.route(pkt.dst, ctx);
    if (!nextHop) return;

    const entry = this.arpCache.get(nextHop);
    if (entry) {
      ctx.trace("arp.cache.hit", "L2", `ARP 캐시 적중: ${nextHop} → ${entry.mac}`, { ip: nextHop, mac: entry.mac });
      this.transmit(entry.mac, pkt, ctx);
      return;
    }

    const queue = this.pending.get(nextHop) ?? [];
    queue.push({ pkt, queuedAt: ctx.now });
    this.pending.set(nextHop, queue);
    ctx.trace("arp.cache.miss", "L2", `ARP 캐시에 ${nextHop} 없음 → 패킷 대기열에 보관 (${queue.length}개)`, { ip: nextHop, queued: queue.length });

    if (queue.length === 1) {
      this.sendArpRequest(nextHop, ctx);
      ctx.timer(Host.ARP_TIMEOUT, "arp-timeout", { ip: nextHop });
    }
  }

  private route(dst: Ip, ctx: NodeContext): Ip | undefined {
    const ip = this.ip!;
    if (sameSubnet(dst, ip, this.prefix)) {
      ctx.trace("ip.route", "L3", `${dst} 는 같은 서브넷 ${networkOf(ip, this.prefix)}/${this.prefix} → 직접 전달 (next hop = ${dst})`, { dst, nextHop: dst });
      return dst;
    }
    if (this.gateway) {
      ctx.trace("ip.route", "L3", `${dst} 는 다른 서브넷 → 게이트웨이 ${this.gateway} 로 전달`, { dst, nextHop: this.gateway });
      return this.gateway;
    }
    ctx.trace("ip.no-route", "L3", `${dst} 는 다른 서브넷인데 게이트웨이 설정 없음 → 폐기`, { dst });
    return undefined;
  }

  private transmit(dstMac: Mac, pkt: Ipv4Packet, ctx: NodeContext): void {
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: dstMac, payload: pkt };
    ctx.trace("frame.send", "L2", `프레임 송신: ${describeFrame(frame)} [${this.mac} → ${dstMac}]`, { src: this.mac, dst: dstMac }, frame.id);
    ctx.send(0, frame);
  }

  private sendArpRequest(targetIp: Ip, ctx: NodeContext): void {
    const arp: ArpPacket = {
      kind: "arp",
      op: "request",
      senderMac: this.mac,
      senderIp: this.ip!,
      targetMac: ZERO_MAC,
      targetIp,
    };
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: BROADCAST_MAC, payload: arp };
    ctx.trace("arp.request.sent", "L2", `ARP 요청 브로드캐스트: "${targetIp} 의 MAC은?" (나는 ${this.ip} / ${this.mac})`, { targetIp }, frame.id);
    ctx.send(0, frame);
  }

  // ---------- 수신 ----------

  receive(_port: number, frame: EthernetFrame, ctx: NodeContext): void {
    const forMe = frame.dst === this.mac;
    const bcast = isBroadcastMac(frame.dst);
    if (!forMe && !bcast) {
      ctx.trace("frame.drop", "L2", `목적지 MAC ${frame.dst} 가 내 MAC(${this.mac}) 아님 → 폐기`, { dst: frame.dst }, frame.id);
      return;
    }
    ctx.trace("frame.receive", "L2", `프레임 수신: ${describeFrame(frame)} [${frame.src} → ${bcast ? "브로드캐스트" : "내 MAC"}]`, { src: frame.src, dst: frame.dst }, frame.id);

    if (frame.payload.kind === "arp") this.handleArp(frame.payload, frame.id, ctx);
    else this.handleIp(frame.payload, frame.id, ctx);
  }

  private handleArp(arp: ArpPacket, frameId: number, ctx: NodeContext): void {
    if (!this.ip) {
      ctx.trace("frame.drop", "L2", `IP 설정이 없어 ARP 무시`, {}, frameId);
      return;
    }
    const isTarget = arp.targetIp === this.ip;

    if (arp.op === "request") {
      ctx.trace("arp.request.received", "L2", `ARP 요청 수신: "${arp.targetIp} 의 MAC은?" (보낸이 ${arp.senderIp} / ${arp.senderMac})`, { ...arp }, frameId);
    } else {
      ctx.trace("arp.reply.received", "L2", `ARP 응답 수신: ${arp.senderIp} 는 ${arp.senderMac}`, { ...arp }, frameId);
    }

    // RFC 826 merge: 이미 아는 IP이거나 나에게 온 ARP면 보낸이 정보를 캐시에 반영
    const known = this.arpCache.get(arp.senderIp);
    if (known || isTarget) {
      if (!known || known.mac !== arp.senderMac) {
        this.arpCache.set(arp.senderIp, { mac: arp.senderMac, learnedAt: ctx.now });
        ctx.trace(
          "arp.cache.update",
          "L2",
          `ARP 캐시 ${known ? "갱신" : "추가"}: ${arp.senderIp} → ${arp.senderMac} (${arp.op === "request" ? "요청의 보낸이 정보에서 학습" : "응답에서 학습"})`,
          { ip: arp.senderIp, mac: arp.senderMac },
          frameId,
        );
      }
    }

    if (arp.op === "request") {
      if (!isTarget) {
        ctx.trace("frame.drop", "L2", `${arp.targetIp} 는 내 IP(${this.ip}) 아님 → 응답 안 함`, { targetIp: arp.targetIp }, frameId);
        return;
      }
      const reply: ArpPacket = {
        kind: "arp",
        op: "reply",
        senderMac: this.mac,
        senderIp: this.ip,
        targetMac: arp.senderMac,
        targetIp: arp.senderIp,
      };
      const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: arp.senderMac, payload: reply };
      ctx.trace("arp.reply.sent", "L2", `ARP 응답 송신: "${this.ip} 는 ${this.mac}" → ${arp.senderMac} 에게 유니캐스트`, { to: arp.senderMac }, frame.id);
      ctx.send(0, frame);
      return;
    }

    // reply
    if (!isTarget) return;
    this.flushPending(arp.senderIp, ctx);
  }

  private flushPending(ip: Ip, ctx: NodeContext): void {
    const queue = this.pending.get(ip);
    if (!queue) return;
    this.pending.delete(ip);
    const entry = this.arpCache.get(ip);
    if (!entry) return;
    for (const { pkt, queuedAt } of queue) {
      ctx.trace("ip.dequeue", "L3", `ARP 해석 완료 → 대기열 패킷 전송 (${ctx.now - queuedAt}ms 대기)`, { dst: pkt.dst });
      this.transmit(entry.mac, pkt, ctx);
    }
  }

  private handleIp(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    if (pkt.dst !== this.ip) {
      ctx.trace("ip.drop", "L3", `목적지 IP ${pkt.dst} 가 내 IP(${this.ip}) 아님 → 폐기 (호스트는 포워딩 안 함)`, { dst: pkt.dst }, frameId);
      return;
    }
    const icmp = pkt.payload;
    if (icmp.type === "echo-request") {
      ctx.trace("icmp.echo.received", "app", `ICMP Echo 요청 수신 (from ${pkt.src}, seq=${icmp.seq})`, { from: pkt.src, seq: icmp.seq }, frameId);
      const reply: Ipv4Packet = {
        kind: "ipv4",
        src: this.ip,
        dst: pkt.src,
        ttl: 64,
        payload: { kind: "icmp", type: "echo-reply", id: icmp.id, seq: icmp.seq },
      };
      ctx.trace("icmp.reply.sent", "app", `ICMP Echo 응답 생성 → ${pkt.src} (seq=${icmp.seq})`, { to: pkt.src, seq: icmp.seq });
      this.sendIp(reply, ctx);
      return;
    }
    const key = pingKey(icmp.id, icmp.seq);
    const sent = this.pings.get(key);
    if (!sent) {
      ctx.trace("ip.drop", "L3", `내가 보낸 적 없는 Echo 응답 (id=${icmp.id}, seq=${icmp.seq}) → 무시`, {}, frameId);
      return;
    }
    this.pings.delete(key);
    ctx.trace("icmp.reply.received", "app", `ping 성공: ${pkt.src} seq=${icmp.seq} RTT=${ctx.now - sent.sentAt}ms`, { from: pkt.src, seq: icmp.seq, rtt: ctx.now - sent.sentAt }, frameId);
  }

  // ---------- 타이머 ----------

  onTimer(tag: string, data: unknown, ctx: NodeContext): void {
    if (tag !== "arp-timeout") return;
    const { ip } = data as { ip: Ip };
    const queue = this.pending.get(ip);
    if (!queue || this.arpCache.has(ip)) {
      ctx.trace("timer.stale", "sys", `ARP 타임아웃 타이머 만료 (${ip}) — 이미 해석됨, 무시`, { ip });
      return;
    }
    this.pending.delete(ip);
    let failedPings = 0;
    for (const { pkt } of queue) {
      if (pkt.payload.type === "echo-request" && this.pings.delete(pingKey(pkt.payload.id, pkt.payload.seq))) failedPings++;
    }
    ctx.trace(
      "arp.timeout",
      "L2",
      `ARP 응답 없음 (${ip}, ${Host.ARP_TIMEOUT}ms) → 대기 패킷 ${queue.length}개 폐기` + (failedPings ? ` / ping ${failedPings}건 실패 (Destination Host Unreachable)` : ""),
      { ip, dropped: queue.length, failedPings },
    );
  }

  // ---------- 스냅샷 ----------

  snapshot(): NodeSnapshot {
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [
        ["MAC", this.mac],
        ["IP", this.ip ? `${this.ip}/${this.prefix}` : "(없음)"],
        ["게이트웨이", this.gateway ?? "(없음)"],
      ],
      tables: [
        {
          title: "ARP 캐시",
          columns: ["IP", "MAC", "학습 시각"],
          rows: [...this.arpCache.entries()].map(([ip, e]) => [ip, e.mac, `${e.learnedAt}ms`]),
        },
        {
          title: "ARP 대기열",
          columns: ["next hop", "대기 패킷"],
          rows: [...this.pending.entries()].map(([ip, q]) => [ip, `${q.length}개`]),
        },
      ],
    };
  }
}

function pingKey(id: number, seq: number): string {
  return `${id}:${seq}`;
}

function hashCode(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}
