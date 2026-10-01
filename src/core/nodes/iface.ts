import { BROADCAST_MAC, networkOf, sameSubnet, ZERO_MAC, type Ip, type Mac } from "../addr";
import { describeFrame, icmpErrorFor, LIMITED_BROADCAST_IP, timeExceededFor, UNREACHABLE_LABEL, type ArpPacket, type EthernetFrame, type Ipv4Packet, type UnreachableCode } from "../packet";
import type { NodeContext, TimerHandle } from "./node";

export interface ArpEntry {
  mac: Mac;
  learnedAt: number;
}

interface PendingPacket {
  pkt: Ipv4Packet;
  queuedAt: number;
}

export type Emit = (frame: EthernetFrame) => void;

/** ARP Probe 의 보낸이 주소 (아직 주소를 쓰지 않는다는 뜻) */
const PROBE_SENDER = "0.0.0.0";

/**
 * IP 인터페이스 하나: MAC, IP 설정, ARP 캐시, ARP 해석 대기열.
 * 호스트와 라우터(LAN 인터페이스)가 공유한다. 프레임은 emit 콜백으로 내보낸다.
 */
export class NetInterface {
  static readonly ARP_TIMEOUT = 1000;
  /** 이 시간이 지난 ARP 항목은 다시 물어본다 */
  static readonly ARP_TTL = 60_000;
  /** 고정 주소를 쓰기 전 ARP Probe 를 보내고 기다리는 시간 (RFC 5227 의 축소판) */
  static readonly PROBE_WAIT = 200;
  /** 충돌을 방어(Gratuitous ARP)한 뒤 이 시간 안의 충돌은 기록만 한다 — 두 장비가 서로 방어하며 폭주하지 않게 */
  static readonly DEFEND_INTERVAL = 10_000;

  readonly mac: Mac;
  ip: Ip | undefined;
  prefix: number;
  gateway: Ip | undefined;
  /** 이 인터페이스가 쓸 DNS 서버 (수동 설정 또는 DHCP 옵션) */
  dns: Ip | undefined;
  /** 내 주소로 보내는 패킷을 네트워크 대신 바로 받게 하는 훅 (호스트가 설정) */
  loopback: ((pkt: Ipv4Packet, ctx: NodeContext) => void) | undefined;
  readonly arpCache = new Map<Ip, ArpEntry>();
  /** ARP Probe 로 주소 사용 여부를 확인하는 중 */
  probing = false;
  /**
   * 주소 충돌. refused = Probe 에 다른 장비가 응답해 이 주소를 쓰지 않는 상태(RFC 5227),
   * 아니면 쓰는 중에 다른 MAC 이 같은 주소를 주장한 상태(방어 중)
   */
  conflict: { mac: Mac; at: number; refused: boolean } | undefined;
  private lastDefendAt = -Infinity;
  /** nextHop IP → ARP 해석을 기다리는 패킷들 */
  readonly pending = new Map<Ip, PendingPacket[]>();
  /** 내보낼 IP 패킷을 먼저 가로챌 기회 (원격 접속 VPN 클라이언트가 사내 대역 패킷을 터널로). true 면 처리됨 */
  outbound: ((pkt: Ipv4Packet, ctx: NodeContext) => boolean) | undefined;
  /** 이중화(HA) master 일 때만: 이 인터페이스가 함께 쓰는 가상 주소·가상 MAC (ARP 응답·수신을 이것으로도 한다) */
  vip: { ip: Ip; mac: Mac } | undefined;
  /** 프록시 ARP: 이 주소들의 ARP 요청에 내 MAC 으로 대신 답한다 (공유기 VPN 서버가 VPN 클라이언트의 LAN 주소를) */
  proxyArp: ((ip: Ip) => boolean) | undefined;
  private readonly arpTimers = new Map<Ip, TimerHandle>();

  constructor(mac: Mac, cfg: { ip?: Ip; prefix?: number; gateway?: Ip; dns?: Ip } = {}) {
    this.mac = mac;
    this.ip = cfg.ip;
    this.prefix = cfg.prefix ?? 24;
    this.gateway = cfg.gateway;
    this.dns = cfg.dns;
  }

  configure(ip: Ip | undefined, prefix: number, gateway: Ip | undefined, dns?: Ip): void {
    if (ip !== this.ip) this.resetConflict();
    this.ip = ip;
    this.prefix = prefix;
    this.gateway = gateway;
    this.dns = dns;
  }

  clearAddress(): void {
    this.resetConflict();
    this.ip = undefined;
    this.gateway = undefined;
    this.dns = undefined;
  }

  private resetConflict(): void {
    this.probing = false;
    this.conflict = undefined;
    this.lastDefendAt = -Infinity;
  }

  /** 주소를 쓸 수 있는지 (있고, 충돌로 사용을 포기하지 않았음) */
  get usable(): boolean {
    return this.ip !== undefined && !this.conflict?.refused;
  }

  /** 대기열과 타이머를 모두 비운다 (링크 다운 등) */
  clearPending(): void {
    for (const t of this.arpTimers.values()) t.cancel();
    this.arpTimers.clear();
    this.pending.clear();
  }

  /** 프레임이 이 인터페이스 앞으로 온 것인지 (내 MAC 또는 브로드캐스트) */
  accepts(frame: EthernetFrame): boolean {
    return frame.dst === this.mac || frame.dst === BROADCAST_MAC || (this.vip !== undefined && frame.dst === this.vip.mac);
  }

  // ---------- 송신 ----------

  /**
   * 일반 L3 송신: 라우팅 → ARP 해석 → 프레임.
   * nextHopOverride 가 있으면(라우터가 라우팅 테이블로 이미 정한 넥스트 홉) 인터페이스 자체 라우팅을 건너뛴다.
   */
  sendIp(pkt: Ipv4Packet, ctx: NodeContext, emit: Emit, nextHopOverride?: Ip): void {
    if (this.outbound?.(pkt, ctx)) return;
    if (!this.ip) {
      ctx.trace("ip.no-address", "L3", `IP 주소가 없어 ${pkt.dst} 로 보낼 수 없음`, { dst: pkt.dst });
      return;
    }
    if (this.conflict?.refused) {
      ctx.trace("ip.no-address", "L3", `${this.ip} 는 다른 장비(${this.conflict.mac})가 쓰는 주소라 사용하지 않는 중 → ${pkt.dst} 로 보낼 수 없음. 다른 주소를 넣으세요`, { dst: pkt.dst });
      return;
    }
    if (pkt.dst === LIMITED_BROADCAST_IP) {
      this.transmit(BROADCAST_MAC, pkt, ctx, emit);
      return;
    }
    if (pkt.dst === this.ip && this.loopback) {
      this.loopback(pkt, ctx);
      return;
    }
    const nextHop = nextHopOverride ?? this.route(pkt.dst, ctx);
    if (!nextHop) return;

    const entry = this.arpCache.get(nextHop);
    if (entry && ctx.now - entry.learnedAt <= NetInterface.ARP_TTL) {
      ctx.trace("arp.cache.hit", "L2", `ARP 캐시 적중: ${nextHop} → ${entry.mac}`, { ip: nextHop, mac: entry.mac });
      this.transmit(entry.mac, pkt, ctx, emit);
      return;
    }
    if (entry) {
      this.arpCache.delete(nextHop);
      ctx.trace("arp.cache.miss", "L2", `ARP 캐시 항목 ${nextHop} 이 오래됨 (${NetInterface.ARP_TTL / 1000}초 초과) → 다시 물어봄`, { ip: nextHop });
    }

    const queue = this.pending.get(nextHop) ?? [];
    queue.push({ pkt, queuedAt: ctx.now });
    this.pending.set(nextHop, queue);
    ctx.trace("arp.cache.miss", "L2", `ARP 캐시에 ${nextHop} 없음 → 패킷 대기열에 보관 (${queue.length}개)`, { ip: nextHop, queued: queue.length });

    if (queue.length === 1) {
      this.sendArpRequest(nextHop, ctx, emit);
      this.arpTimers.set(nextHop, ctx.timer(NetInterface.ARP_TIMEOUT, "arp-timeout", { ip: nextHop }));
    }
  }

  /**
   * TTL 이 1 이하인 패킷이 이 인터페이스로 들어와 더 넘길 수 없을 때: 드롭을 기록하고 보낸 이에게 돌려줄
   * Time Exceeded 패킷(출발지 = 이 인터페이스 주소)을 만든다. 보내는 방법은 장치마다 다르므로 호출자가 보낸다.
   * 통지를 만들 수 없으면(주소 없음, ICMP 오류에 대한 오류, 출발지 0.0.0.0) undefined
   */
  timeExceeded(pkt: Ipv4Packet, ctx: NodeContext, frameId?: number): Ipv4Packet | undefined {
    const notice = this.ip ? timeExceededFor(this.ip, pkt) : undefined;
    if (!notice) {
      ctx.trace("ip.ttl-expired", "L3", `TTL ${pkt.ttl} 로 도착한 ${pkt.src} → ${pkt.dst}: 더 넘기면 0 → 드롭 (통지는 보내지 않음)`, { src: pkt.src, dst: pkt.dst }, frameId);
      return undefined;
    }
    ctx.trace(
      "icmp.ttl-exceeded",
      "L3",
      `TTL ${pkt.ttl} 로 도착한 ${pkt.src} → ${pkt.dst}: 한 홉 더 넘기면 0 → 드롭하고 ${this.ip} 이름으로 보낸 이에게 Time Exceeded 통지 (traceroute 는 이 통지로 경로의 홉을 알아낸다)`,
      { src: pkt.src, dst: pkt.dst, from: this.ip, ttl: pkt.ttl },
      frameId,
    );
    return notice;
  }

  /**
   * 더 넘길 수 없는 패킷(경로 없음·ARP 무응답·닫힌 UDP 포트)을 보낸 이에게 알릴 ICMP Destination Unreachable (출발지 = 이 인터페이스 주소).
   * 보내는 방법은 장치마다 달라 호출자가 보낸다. 만들 수 없으면(내 주소 없음, ICMP 오류·브로드캐스트에 대한 것) undefined
   */
  unreachable(pkt: Ipv4Packet, code: UnreachableCode, ctx: NodeContext, frameId?: number): Ipv4Packet | undefined {
    const notice = this.ip ? icmpErrorFor(this.ip, pkt, { type: "unreachable", code }) : undefined;
    if (!notice) return undefined;
    const why = code === "net" ? "그 목적지로 가는 경로가 없음" : code === "host" ? "그 주소의 장치가 ARP 에 응답하지 않음" : "그 UDP 포트를 듣는 프로그램이 없음";
    ctx.trace("icmp.unreachable.sent", "L3", `${pkt.src} 에게 ICMP ${UNREACHABLE_LABEL[code]} 통지 (원래 ${pkt.src} → ${pkt.dst}) — ${why}. 보낸 쪽은 timeout 을 기다리지 않고 바로 실패를 안다`, { to: pkt.src, dst: pkt.dst, code }, frameId);
    return notice;
  }

  /** IP 주소가 없어도 보낼 수 있는 브로드캐스트 (DHCP Discover/Request) */
  sendBroadcast(pkt: Ipv4Packet, ctx: NodeContext, emit: Emit): void {
    this.transmit(BROADCAST_MAC, pkt, ctx, emit);
  }

  /** ARP 없이 특정 MAC 으로 직접 (DHCP 서버가 클라이언트에게 응답할 때) */
  /** 정해진 MAC 으로 보낸다. srcMac 을 주면 그 MAC 을 출발지로 (VRRP master 의 광고는 가상 MAC — RFC 5798 7.3) */
  sendToMac(dstMac: Mac, pkt: Ipv4Packet, ctx: NodeContext, emit: Emit, srcMac: Mac = this.mac): void {
    this.transmit(dstMac, pkt, ctx, emit, srcMac);
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
    ctx.trace("ip.no-route", "L3", `${dst} 는 다른 서브넷인데 게이트웨이 설정 없음 → 드롭`, { dst });
    return undefined;
  }

  private transmit(dstMac: Mac, pkt: Ipv4Packet, ctx: NodeContext, emit: Emit, srcMac: Mac = this.mac): void {
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: srcMac, dst: dstMac, payload: pkt };
    ctx.trace("frame.send", "L2", `프레임 송신: ${describeFrame(frame)} [${srcMac} → ${dstMac === BROADCAST_MAC ? "브로드캐스트" : dstMac}]`, { src: srcMac, dst: dstMac }, frame.id);
    emit(frame);
  }

  private sendArpRequest(targetIp: Ip, ctx: NodeContext, emit: Emit): void {
    const arp: ArpPacket = { kind: "arp", op: "request", senderMac: this.mac, senderIp: this.ip!, targetMac: ZERO_MAC, targetIp };
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: BROADCAST_MAC, payload: arp };
    ctx.trace("arp.request.sent", "L2", `ARP 요청 브로드캐스트: "${targetIp} 의 MAC은?" (나는 ${this.ip} / ${this.mac})`, { targetIp }, frame.id);
    emit(frame);
  }

  /**
   * Gratuitous ARP: 주소를 새로 얻었을 때 "이 IP 는 이제 내 MAC" 이라고 알린다.
   * 같은 IP 를 옛 MAC 으로 기억하던 이웃이 캐시를 고친다.
   */
  /** 가상 주소를 가져왔을 때 Gratuitous ARP: 가상 MAC 을 출발지로 보내 스위치가 이 MAC 의 새 포트를 배우게 한다 */
  announceVip(ctx: NodeContext, emit: Emit): void {
    if (!this.vip) return;
    const { ip, mac } = this.vip;
    const arp: ArpPacket = { kind: "arp", op: "request", senderMac: mac, senderIp: ip, targetMac: ZERO_MAC, targetIp: ip };
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: mac, dst: BROADCAST_MAC, payload: arp };
    ctx.trace("arp.request.sent", "L2", `Gratuitous ARP 브로드캐스트: "가상 주소 ${ip} 는 ${mac}" — 스위치는 이 가상 MAC 이 이제 이쪽 포트에 있다고 배운다`, { ip, mac }, frame.id);
    emit(frame);
  }

  announce(ctx: NodeContext, emit: Emit): void {
    if (!this.ip || this.conflict?.refused) return;
    const arp: ArpPacket = { kind: "arp", op: "request", senderMac: this.mac, senderIp: this.ip, targetMac: ZERO_MAC, targetIp: this.ip };
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: BROADCAST_MAC, payload: arp };
    ctx.trace("arp.request.sent", "L2", `Gratuitous ARP 브로드캐스트: "${this.ip} 는 이제 ${this.mac}" — 이웃들이 옛 MAC 을 기억하고 있으면 고치도록`, { ip: this.ip }, frame.id);
    emit(frame);
  }

  /**
   * 고정 주소를 쓰기 시작할 때: 먼저 ARP Probe("이 주소 쓰는 장비 있나요?", 보낸이 0.0.0.0)로 확인하고,
   * PROBE_WAIT 동안 아무도 주장하지 않으면 Gratuitous ARP 로 알린다. 노드는 "arp-probe" 타이머에서 finishProbe 를 부른다
   */
  claim(ctx: NodeContext, emit: Emit): void {
    if (!this.ip) return;
    this.conflict = undefined;
    this.probing = true;
    const arp: ArpPacket = { kind: "arp", op: "request", senderMac: this.mac, senderIp: PROBE_SENDER, targetMac: ZERO_MAC, targetIp: this.ip };
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: BROADCAST_MAC, payload: arp };
    ctx.trace("arp.probe", "L2", `ARP Probe 브로드캐스트: "${this.ip} 를 쓰는 장비가 있나요?" (보낸이 0.0.0.0 — 아직 이 주소를 쓰지 않음) → ${NetInterface.PROBE_WAIT}ms 동안 답이 없으면 사용`, { ip: this.ip }, frame.id);
    emit(frame);
    ctx.timer(NetInterface.PROBE_WAIT, "arp-probe", { mac: this.mac });
  }

  finishProbe(ctx: NodeContext, emit: Emit): void {
    if (!this.probing) return;
    this.probing = false;
    if (this.conflict?.refused || !this.ip) return;
    ctx.trace("arp.probe", "L2", `ARP Probe 에 아무도 답하지 않음 → ${this.ip} 사용 시작`, { ip: this.ip });
    this.announce(ctx, emit);
  }

  private onConflict(otherMac: Mac, frameId: number, ctx: NodeContext, emit: Emit): void {
    const ip = this.ip!;
    if (this.probing) {
      this.probing = false;
      this.conflict = { mac: otherMac, at: ctx.now, refused: true };
      this.arpCache.clear();
      this.clearPending();
      ctx.trace("ip.conflict", "L2", `주소 충돌: ${ip} 는 이미 ${otherMac} 가 쓰는 주소 (ARP Probe 에 응답) → 이 주소를 쓰지 않음(RFC 5227). 다른 주소를 넣으세요`, { ip, mac: otherMac, refused: true }, frameId);
      return;
    }
    if (this.conflict?.refused) return;
    this.conflict = { mac: otherMac, at: ctx.now, refused: false };
    if (ctx.now - this.lastDefendAt >= NetInterface.DEFEND_INTERVAL) {
      ctx.trace("ip.conflict", "L2", `주소 충돌: ${otherMac} 도 내 IP ${ip} 를 씀 → Gratuitous ARP 로 방어 (이웃의 ARP 캐시를 내 MAC 으로 되돌림)`, { ip, mac: otherMac }, frameId);
      this.lastDefendAt = ctx.now;
      this.announce(ctx, emit);
    } else {
      ctx.trace("ip.conflict", "L2", `주소 충돌: ${otherMac} 도 내 IP ${ip} 를 씀 → ${NetInterface.DEFEND_INTERVAL / 1000}초 안에 이미 방어했으므로 기록만 (서로 방어하며 폭주하지 않게)`, { ip, mac: otherMac }, frameId);
    }
  }

  // ---------- 수신 ----------

  handleArp(arp: ArpPacket, frameId: number, ctx: NodeContext, emit: Emit): void {
    if (!this.ip) {
      ctx.trace("frame.drop", "L2", `IP 설정이 없어 ARP 무시`, {}, frameId);
      return;
    }
    // 가상 주소(HA master)로 온 요청도 내 것
    const asVip = this.vip !== undefined && arp.targetIp === this.vip.ip && arp.senderIp !== this.vip.ip;
    const asProxy = !asVip && arp.targetIp !== this.ip && arp.senderIp !== arp.targetIp && this.proxyArp?.(arp.targetIp) === true;
    const isTarget = (arp.targetIp === this.ip && !this.conflict?.refused) || asVip || asProxy;

    // 주소 충돌: 다른 MAC 이 내 주소를 보낸이로 쓴다(요청·응답·Gratuitous ARP 모두). Probe 중이면 같은 주소를 동시에 Probe 한 것도 충돌
    if (arp.senderMac !== this.mac) {
      const claimsMine = arp.senderIp === this.ip || (this.probing && arp.op === "request" && arp.senderIp === PROBE_SENDER && arp.targetIp === this.ip);
      if (claimsMine) {
        this.onConflict(arp.senderMac, frameId, ctx, emit);
        return;
      }
      // 충돌 상대가 다른 주소로 바꿔 알리면 해소. 주소를 포기했던 쪽은 다시 Probe 해서 되찾는다
      if (this.conflict && arp.senderMac === this.conflict.mac && arp.senderIp !== PROBE_SENDER) {
        const wasRefused = this.conflict.refused;
        this.conflict = undefined;
        ctx.trace(
          "ip.conflict.clear",
          "L2",
          `충돌 해소: ${arp.senderMac} 가 이제 ${arp.senderIp} 를 씀 → ${wasRefused ? `${this.ip} 를 다시 확인하고 쓴다` : `${this.ip} 는 다시 나만 쓴다`}`,
          { mac: arp.senderMac },
          frameId,
        );
        if (wasRefused) {
          this.claim(ctx, emit);
          return;
        }
      }
    }

    if (arp.op === "request" && arp.senderIp === arp.targetIp) {
      const known = this.arpCache.get(arp.senderIp);
      if (known && known.mac !== arp.senderMac) {
        this.arpCache.set(arp.senderIp, { mac: arp.senderMac, learnedAt: ctx.now });
        ctx.trace("arp.cache.update", "L2", `Gratuitous ARP 수신 → ARP 캐시 갱신: ${arp.senderIp} 는 이제 ${arp.senderMac} (이전 ${known.mac})`, { ip: arp.senderIp, mac: arp.senderMac }, frameId);
      } else {
        ctx.trace("arp.request.received", "L2", `Gratuitous ARP 수신: ${arp.senderIp} 는 ${arp.senderMac} (내 캐시엔 ${known ? "이미 같은 값" : "없음"} → 변경 없음)`, { ...arp }, frameId);
      }
      return;
    }
    if (arp.op === "request") {
      ctx.trace("arp.request.received", "L2", `ARP 요청 수신: "${arp.targetIp} 의 MAC은?" (보낸이 ${arp.senderIp} / ${arp.senderMac})`, { ...arp }, frameId);
    } else {
      ctx.trace("arp.reply.received", "L2", `ARP 응답 수신: ${arp.senderIp} 는 ${arp.senderMac}`, { ...arp }, frameId);
    }

    // RFC 826 merge: 이미 아는 IP 이거나 나에게 온 ARP 면 보낸이 정보를 캐시에 반영 (Probe 의 보낸이 0.0.0.0 은 제외)
    const known = this.arpCache.get(arp.senderIp);
    if ((known || isTarget) && arp.senderIp !== PROBE_SENDER) {
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

    // 나도 그 장치를 찾던 중이면 (서로 동시에 ARP 요청) 요청에서 배운 것으로 기다리던 패킷을 보낸다 — 응답 하나를 잃어도 대기열이 남지 않게
    if (arp.op === "request" && this.pending.has(arp.senderIp) && this.arpCache.has(arp.senderIp)) this.flushPending(arp.senderIp, ctx, emit);

    if (arp.op === "request") {
      if (!isTarget) {
        ctx.trace("frame.drop", "L2", `${arp.targetIp} 는 내 IP(${this.ip}) 아님 → 응답 안 함`, { targetIp: arp.targetIp }, frameId);
        return;
      }
      const me = asVip ? this.vip! : asProxy ? { ip: arp.targetIp, mac: this.mac } : { ip: this.ip, mac: this.mac };
      const reply: ArpPacket = { kind: "arp", op: "reply", senderMac: me.mac, senderIp: me.ip, targetMac: arp.senderMac, targetIp: arp.senderIp };
      const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: me.mac, dst: arp.senderMac, payload: reply };
      ctx.trace(
        "arp.reply.sent",
        "L2",
        `ARP 응답 송신: "${me.ip} 는 ${me.mac}"${asVip ? " (이중화 가상 주소 — master 인 내가 답함)" : asProxy ? ` (프록시 ARP — ${me.ip} 는 VPN 으로 붙은 기기라 공유기가 대신 답하고 받은 것을 터널로 넘김)` : ""} → ${arp.senderMac} 에게 유니캐스트`,
        { to: arp.senderMac, ...(asProxy ? { proxy: true } : {}) },
        frame.id,
      );
      emit(frame);
      return;
    }

    if (isTarget) this.flushPending(arp.senderIp, ctx, emit);
  }

  private flushPending(ip: Ip, ctx: NodeContext, emit: Emit): void {
    const queue = this.pending.get(ip);
    if (!queue) return;
    this.pending.delete(ip);
    this.arpTimers.get(ip)?.cancel();
    this.arpTimers.delete(ip);
    const entry = this.arpCache.get(ip);
    if (!entry) return;
    for (const { pkt, queuedAt } of queue) {
      ctx.trace("ip.dequeue", "L3", `ARP 해석 완료 → 대기열 패킷 전송 (${ctx.now - queuedAt}ms 대기)`, { dst: pkt.dst });
      this.transmit(entry.mac, pkt, ctx, emit);
    }
  }

  /** "arp-timeout" 타이머. 드롭한 패킷을 돌려준다 (호스트가 ping 실패 등을 기록할 수 있도록) */
  onArpTimeout(data: unknown, ctx: NodeContext): Ipv4Packet[] {
    const { ip } = data as { ip: Ip };
    this.arpTimers.delete(ip);
    const queue = this.pending.get(ip);
    if (!queue) return [];
    if (this.arpCache.has(ip)) {
      // 다른 길로 이미 배웠다 — 남은 대기열을 두면 다음 요청이 막힌다 (queue.length === 1 일 때만 ARP 요청을 보내므로)
      this.pending.delete(ip);
      return [];
    }
    this.pending.delete(ip);
    ctx.trace("arp.timeout", "L2", `ARP timeout: ${ip} 가 ${NetInterface.ARP_TIMEOUT}ms 동안 응답 없음 → 대기 패킷 ${queue.length}개 드롭`, { ip, dropped: queue.length });
    return queue.map((q) => q.pkt);
  }

  arpRows(): string[][] {
    return [...this.arpCache.entries()].map(([ip, e]) => [ip, e.mac, `${e.learnedAt}ms`]);
  }
}
