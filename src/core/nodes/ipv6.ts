// IPv6 인터페이스 하나: 주소 목록(링크 로컬 + 수동), 이웃 캐시, NDP(NS/NA)로 이웃 MAC 찾기, DAD(중복 주소 검사).
// IPv4 의 NetInterface(ARP) 와 나란히 붙는다. 호스트와 게이트웨이가 같이 쓴다.
//
// 학습 포인트 — ARP 와 다른 점:
// - 브로드캐스트가 없다. "이 주소의 MAC 은?" 은 그 주소에서 만든 solicited-node 멀티캐스트 그룹(ff02::1:ffXX:XXXX)에만 보내,
//   마지막 24비트가 같은 장치만 받는다 (ARP 요청은 링크의 모든 장치가 받는다)
// - NDP 는 ICMPv6(L3) 위에서 돈다. ARP 는 IP 와 따로인 L2 프로토콜이다
// - 주소마다 쓰기 전에 DAD 를 한다: 출발지 :: 로 "이 주소를 쓰는 장치가 있나?" 를 묻고 1초 동안 답(NA)이 없으면 쓴다
// - 켜기만 하면 MAC 에서 만든 링크 로컬 주소(fe80::)가 생겨, 설정 없이도 같은 링크의 이웃과 통신한다
import type { Ip, Mac } from "../addr";
import {
  ALL_NODES,
  ALL_NODES_MAC,
  ALL_ROUTERS_MAC,
  UNSPECIFIED6,
  commonPrefixLength6,
  isLinkLocal6,
  isMulticast6,
  linkLocalOf,
  multicastMac6,
  network6,
  sameSubnet6,
  solicitedNode,
} from "../addr6";
import { describeFrame, icmpv6ErrorFor, UNREACHABLE6_LABEL, type EthernetFrame, type Ipv6Packet, type NdpMessage, type UnreachableCode } from "../packet";
import type { Emit } from "./iface";
import type { NodeContext, TimerHandle } from "./node";

export const NDP_TIMEOUT_TAG = "ndp-timeout";
export const DAD_TIMER_TAG = "ndp-dad";

export interface Addr6 {
  ip: Ip;
  prefix: number;
  origin: "link-local" | "manual";
  /** tentative = DAD 중(아직 못 씀), preferred = 사용 중, duplicate = 다른 장치가 이미 써서 포기 */
  state: "tentative" | "preferred" | "duplicate";
}

export interface Neighbor {
  mac: Mac;
  learnedAt: number;
  /** NA 의 R 플래그: 이 이웃은 라우터 */
  router: boolean;
}

export interface Ipv6Settings {
  enabled: boolean;
  /** 수동 주소 (링크 로컬은 MAC 에서 자동) */
  addrs: { ip: Ip; prefix: number }[];
  gateway?: Ip;
  dns?: Ip;
}

const STATE_LABEL: Record<Addr6["state"], string> = { tentative: "DAD 중", preferred: "사용 중", duplicate: "중복 · 사용 안 함" };

export class Ipv6Interface {
  static readonly NS_TIMEOUT = 1000;
  /** 이 시간이 지난 이웃 항목은 다시 물어본다 (ARP 캐시와 같은 기준) */
  static readonly NEIGHBOR_TTL = 60_000;
  /** DAD: NS 를 보내고 기다리는 시간 (RFC 4861 RetransTimer 1초) */
  static readonly DAD_WAIT = 1000;
  static readonly HOP_LIMIT = 64;

  readonly mac: Mac;
  readonly linkLocal: Ip;
  enabled = false;
  addrs: Addr6[] = [];
  gateway: Ip | undefined;
  dns: Ip | undefined;
  readonly neighbors = new Map<Ip, Neighbor>();
  readonly pending = new Map<Ip, { pkt: Ipv6Packet; queuedAt: number }[]>();
  /** 내 주소로 보내는 패킷을 네트워크 대신 바로 받게 하는 훅 (호스트) */
  loopback: ((pkt: Ipv6Packet, ctx: NodeContext) => void) | undefined;
  private readonly nsTimers = new Map<Ip, TimerHandle>();
  private readonly dadTimers = new Map<Ip, TimerHandle>();

  /**
   * @param router 라우터면 모든 라우터 그룹(ff02::2)에 가입하고 NA 에 R 플래그를 붙인다
   * @param label 로그 앞에 붙일 인터페이스 이름 (게이트웨이처럼 인터페이스가 여럿일 때)
   */
  constructor(
    mac: Mac,
    readonly router = false,
    readonly label = "",
  ) {
    this.mac = mac;
    this.linkLocal = linkLocalOf(mac);
  }

  private get tag(): string {
    return this.label ? `[${this.label}] ` : "";
  }

  // ---------- 설정 ----------

  /** 장치를 만들 때의 첫 설정 (로그 없이, 링크가 아직 없으므로 DAD 는 링크가 살아날 때) */
  init(cfg: Ipv6Settings): void {
    if (!cfg.enabled) return;
    this.enabled = true;
    this.addrs = [
      { ip: this.linkLocal, prefix: 64, origin: "link-local", state: "tentative" },
      ...cfg.addrs.filter((a, i, all) => a.ip !== this.linkLocal && all.findIndex((b) => b.ip === a.ip) === i).map((a): Addr6 => ({ ip: a.ip, prefix: a.prefix, origin: "manual", state: "tentative" })),
    ];
    this.gateway = cfg.gateway;
    this.dns = cfg.dns;
  }

  /**
   * 설정 반영. 켜면 링크 로컬 + 수동 주소가 생기고(링크가 살아 있으면 곧바로 DAD), 끄면 모두 지운다.
   * @returns 주소가 바뀌었는지 (호스트는 연결을 정리한다)
   */
  configure(cfg: Ipv6Settings, linkUp: boolean, ctx: NodeContext, emit: Emit): boolean {
    if (!cfg.enabled) {
      if (!this.enabled) return false;
      this.enabled = false;
      this.reset();
      this.addrs = [];
      this.gateway = undefined;
      this.dns = undefined;
      ctx.trace("ip.config", "sys", `${this.tag}IPv6 꺼짐 → IPv6 주소·이웃 캐시를 모두 지움`, {});
      return true;
    }
    let changed = false;
    if (!this.enabled) {
      this.enabled = true;
      changed = true;
      this.addrs = [{ ip: this.linkLocal, prefix: 64, origin: "link-local", state: "tentative" }];
      ctx.trace(
        "ip.config",
        "sys",
        `${this.tag}IPv6 켜짐 → 링크 로컬 주소 ${this.linkLocal} 자동 생성 (fe80::/64 + MAC ${this.mac} 에서 만든 EUI-64 인터페이스 ID. 실제 OS 는 개인정보 때문에 보통 무작위 ID 를 쓴다)`,
        { ip: this.linkLocal },
      );
      if (linkUp) this.startDad(this.addrs[0]!, ctx, emit);
    }
    // 수동 주소: 없어진 것은 지우고 새것은 DAD
    const want = cfg.addrs.filter((a, i, all) => all.findIndex((b) => b.ip === a.ip) === i && a.ip !== this.linkLocal);
    for (const a of [...this.addrs]) {
      if (a.origin !== "manual") continue;
      const keep = want.find((w) => w.ip === a.ip);
      if (keep && keep.prefix === a.prefix) continue;
      this.removeAddr(a);
      changed = true;
      ctx.trace("ip.config", "sys", `${this.tag}IPv6 주소 ${a.ip}/${a.prefix} 삭제`, { ip: a.ip });
    }
    for (const w of want) {
      if (this.addrs.some((a) => a.ip === w.ip)) continue;
      const addr: Addr6 = { ip: w.ip, prefix: w.prefix, origin: "manual", state: "tentative" };
      this.addrs.push(addr);
      changed = true;
      ctx.trace("ip.config", "sys", `${this.tag}IPv6 수동 주소 ${w.ip}/${w.prefix} 추가 (${network6(w.ip, w.prefix)}/${w.prefix} 네트워크)`, { ip: w.ip, prefix: w.prefix });
      if (linkUp) this.startDad(addr, ctx, emit);
    }
    if (changed) {
      this.neighbors.clear();
      this.clearPending();
    }
    if (cfg.gateway !== this.gateway) {
      this.gateway = cfg.gateway;
      ctx.trace("ip.config", "sys", cfg.gateway ? `${this.tag}IPv6 기본 게이트웨이: ${cfg.gateway}${isLinkLocal6(cfg.gateway) ? " (라우터의 링크 로컬 주소 — IPv6 에서 흔한 방식)" : ""}` : `${this.tag}IPv6 기본 게이트웨이 없음`, { gateway: cfg.gateway });
    }
    if (cfg.dns !== this.dns) this.dns = cfg.dns;
    return changed;
  }

  private removeAddr(a: Addr6): void {
    this.addrs = this.addrs.filter((x) => x !== a);
    this.dadTimers.get(a.ip)?.cancel();
    this.dadTimers.delete(a.ip);
  }

  /** 대기열·타이머·이웃 캐시를 비운다 */
  private reset(): void {
    this.clearPending();
    for (const t of this.dadTimers.values()) t.cancel();
    this.dadTimers.clear();
    this.neighbors.clear();
  }

  clearPending(): void {
    for (const t of this.nsTimers.values()) t.cancel();
    this.nsTimers.clear();
    this.pending.clear();
  }

  /** 링크가 살아남: 모든 주소를 다시 DAD */
  linkUp(ctx: NodeContext, emit: Emit): void {
    if (!this.enabled) return;
    for (const a of this.addrs) {
      a.state = "tentative";
      this.startDad(a, ctx, emit);
    }
  }

  /** 링크 다운: 이웃·대기열을 비우고 주소는 다시 확인이 필요한 상태로 */
  linkDown(): void {
    if (!this.enabled) return;
    this.reset();
    for (const a of this.addrs) a.state = "tentative";
  }

  // ---------- 조회 ----------

  /** 쓸 수 있는(DAD 를 통과한) 내 주소인지 */
  owns(ip: Ip): boolean {
    return this.enabled && this.addrs.some((a) => a.ip === ip && a.state === "preferred");
  }

  /** 링크 로컬이 아닌 쓸 수 있는 주소 (글로벌·ULA) */
  get globals(): Addr6[] {
    return this.addrs.filter((a) => a.origin !== "link-local" && a.state === "preferred");
  }

  /** 이 프레임의 목적지 MAC 을 받는지: 내 MAC, 모든 노드 그룹, 내 주소들의 solicited-node 그룹, (라우터면) 모든 라우터 그룹 */
  accepts(dstMac: Mac): boolean {
    if (!this.enabled) return false;
    if (dstMac === this.mac || dstMac === ALL_NODES_MAC) return true;
    if (this.router && dstMac === ALL_ROUTERS_MAC) return true;
    return this.addrs.some((a) => a.state !== "duplicate" && multicastMac6(solicitedNode(a.ip)) === dstMac);
  }

  /** 목적지가 이 인터페이스의 링크(연결된 프리픽스·링크 로컬) 안인지 */
  onLink(dst: Ip): boolean {
    if (isLinkLocal6(dst)) return true;
    return this.addrs.some((a) => a.origin !== "link-local" && a.state !== "duplicate" && sameSubnet6(dst, a.ip, a.prefix));
  }

  /**
   * 출발지 주소 고르기 (RFC 6724 축소판): 링크 로컬·링크 범위 멀티캐스트면 링크 로컬, 아니면 목적지와 가장 길게 겹치는 글로벌 주소.
   * 쓸 수 있는 주소가 없으면 undefined
   */
  sourceFor(dst: Ip): Ip | undefined {
    if (!this.enabled) return undefined;
    if (isLinkLocal6(dst) || dst.startsWith("ff02:")) return this.owns(this.linkLocal) ? this.linkLocal : undefined;
    const g = this.globals;
    if (g.length === 0) return undefined;
    return [...g].sort((a, b) => commonPrefixLength6(b.ip, dst) - commonPrefixLength6(a.ip, dst))[0]!.ip;
  }

  /** 오류 통지(ICMPv6)의 출발지: 보낸 이에게 닿는 주소, 없으면 링크 로컬 */
  errorSource(to: Ip): Ip | undefined {
    return this.sourceFor(to) ?? (this.owns(this.linkLocal) ? this.linkLocal : undefined);
  }

  /** 주소가 없는 이유 (실패 문구용) */
  whyNoSource(dst: Ip): string {
    if (!this.enabled) return "IPv6 가 꺼져 있음 — IPv6 설정에서 켜세요";
    if (this.addrs.some((a) => a.state === "tentative")) return "주소를 DAD 로 확인하는 중 (1초 뒤 다시 시도하세요)";
    if (isLinkLocal6(dst)) return "링크 로컬 주소가 중복이라 쓰지 않는 중";
    if (this.addrs.some((a) => a.origin !== "link-local" && a.state === "duplicate")) return "IPv6 주소가 다른 장치와 중복이라 쓰지 않는 중 — 다른 주소를 넣으세요";
    return "IPv6 글로벌 주소가 없음 — 링크 로컬 주소(fe80::)로는 다른 네트워크로 나갈 수 없음. IPv6 주소를 넣으세요";
  }

  // ---------- 송신 ----------

  /** 링크 안의 넥스트 홉 결정: 링크 안이면 목적지 자신, 아니면 기본 게이트웨이 */
  private route(dst: Ip, ctx: NodeContext): Ip | undefined {
    if (isLinkLocal6(dst)) {
      ctx.trace("ip.route", "L3", `${this.tag}${dst} 는 링크 로컬 주소 → 같은 링크에 직접 전달 (next hop = ${dst})`, { dst, nextHop: dst });
      return dst;
    }
    const a = this.addrs.find((x) => x.origin !== "link-local" && x.state !== "duplicate" && sameSubnet6(dst, x.ip, x.prefix));
    if (a) {
      ctx.trace("ip.route", "L3", `${this.tag}${dst} 는 같은 프리픽스 ${network6(a.ip, a.prefix)}/${a.prefix} → 직접 전달 (next hop = ${dst})`, { dst, nextHop: dst });
      return dst;
    }
    if (this.gateway) {
      ctx.trace("ip.route", "L3", `${this.tag}${dst} 는 다른 네트워크 → IPv6 기본 게이트웨이 ${this.gateway} 로 전달`, { dst, nextHop: this.gateway });
      return this.gateway;
    }
    ctx.trace("ip.no-route", "L3", `${this.tag}${dst} 는 다른 네트워크인데 IPv6 기본 게이트웨이가 없음 → 드롭 (IPv6 설정에서 게이트웨이를 넣으세요)`, { dst });
    return undefined;
  }

  /**
   * IPv6 송신: 멀티캐스트면 33:33 MAC 으로 바로, 아니면 넥스트 홉을 정하고 이웃 캐시(없으면 NS 로 찾기) → 프레임.
   * nextHopOverride: 라우터가 라우팅 테이블로 이미 정한 넥스트 홉
   */
  send(pkt: Ipv6Packet, ctx: NodeContext, emit: Emit, nextHopOverride?: Ip): void {
    if (!this.enabled) {
      ctx.trace("ip.no-address", "L3", `${this.tag}IPv6 가 꺼져 있어 ${pkt.dst} 로 보낼 수 없음`, { dst: pkt.dst });
      return;
    }
    if (isMulticast6(pkt.dst)) {
      this.transmit(multicastMac6(pkt.dst), pkt, ctx, emit);
      return;
    }
    if (this.loopback && this.owns(pkt.dst)) {
      this.loopback(pkt, ctx);
      return;
    }
    const nextHop = nextHopOverride ?? this.route(pkt.dst, ctx);
    if (!nextHop) return;
    const entry = this.neighbors.get(nextHop);
    if (entry && ctx.now - entry.learnedAt <= Ipv6Interface.NEIGHBOR_TTL) {
      ctx.trace("ndp.cache.hit", "L3", `${this.tag}이웃 캐시 적중: ${nextHop} → ${entry.mac}`, { ip: nextHop, mac: entry.mac });
      this.transmit(entry.mac, pkt, ctx, emit);
      return;
    }
    if (entry) {
      this.neighbors.delete(nextHop);
      ctx.trace("ndp.cache.miss", "L3", `${this.tag}이웃 캐시 항목 ${nextHop} 이 오래됨 (${Ipv6Interface.NEIGHBOR_TTL / 1000}초 초과) → 다시 물어봄`, { ip: nextHop });
    }
    const queue = this.pending.get(nextHop) ?? [];
    queue.push({ pkt, queuedAt: ctx.now });
    this.pending.set(nextHop, queue);
    ctx.trace("ndp.cache.miss", "L3", `${this.tag}이웃 캐시에 ${nextHop} 없음 → 패킷 대기열에 보관 (${queue.length}개)`, { ip: nextHop, queued: queue.length });
    if (queue.length === 1) {
      this.sendNs(nextHop, ctx, emit);
      this.nsTimers.set(nextHop, ctx.timer(Ipv6Interface.NS_TIMEOUT, NDP_TIMEOUT_TAG, { mac: this.mac, ip: nextHop }));
    }
  }

  /** 이웃 해석: 대상의 solicited-node 그룹으로 NS */
  private sendNs(target: Ip, ctx: NodeContext, emit: Emit): void {
    const src = this.sourceFor(target) ?? this.linkLocal;
    const group = solicitedNode(target);
    const pkt: Ipv6Packet = { kind: "ipv6", src, dst: group, hopLimit: 255, payload: { kind: "icmp6", type: "ns", target, sll: this.mac } };
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: multicastMac6(group), payload: pkt };
    ctx.trace(
      "ndp.ns.sent",
      "L3",
      `${this.tag}NDP NS 멀티캐스트: "${target} 의 MAC 은?" → solicited-node 그룹 ${group} (${frame.dst}) — ARP 처럼 모두에게 브로드캐스트하지 않고 주소 끝 24비트가 같은 장치만 받는다`,
      { target, group },
      frame.id,
    );
    emit(frame);
  }

  private transmit(dstMac: Mac, pkt: Ipv6Packet, ctx: NodeContext, emit: Emit): void {
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: dstMac, payload: pkt };
    ctx.trace("frame.send", "L2", `${this.tag}프레임 송신: ${describeFrame(frame)} [${this.mac} → ${dstMac.startsWith("33:33") ? `멀티캐스트 ${dstMac}` : dstMac}]`, { src: this.mac, dst: dstMac }, frame.id);
    emit(frame);
  }

  // ---------- DAD ----------

  private startDad(a: Addr6, ctx: NodeContext, emit: Emit): void {
    a.state = "tentative";
    this.dadTimers.get(a.ip)?.cancel();
    const group = solicitedNode(a.ip);
    const pkt: Ipv6Packet = { kind: "ipv6", src: UNSPECIFIED6, dst: group, hopLimit: 255, payload: { kind: "icmp6", type: "ns", target: a.ip } };
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: multicastMac6(group), payload: pkt };
    ctx.trace(
      "ndp.dad",
      "L3",
      `${this.tag}DAD: NS 송신 "${a.ip} 를 쓰는 장치가 있나요?" (출발지 :: — 아직 이 주소를 쓰지 않음) → ${Ipv6Interface.DAD_WAIT}ms 동안 NA 가 없으면 사용`,
      { ip: a.ip, group },
      frame.id,
    );
    emit(frame);
    this.dadTimers.set(a.ip, ctx.timer(Ipv6Interface.DAD_WAIT, DAD_TIMER_TAG, { mac: this.mac, ip: a.ip }));
  }

  /** "ndp-dad" 타이머. 아무도 주장하지 않았으면 사용 시작. 처리했으면 true */
  finishDad(data: unknown, ctx: NodeContext): boolean {
    const { mac, ip } = data as { mac: Mac; ip: Ip };
    if (mac !== this.mac) return false;
    this.dadTimers.delete(ip);
    const a = this.addrs.find((x) => x.ip === ip);
    if (!a || a.state !== "tentative") return true;
    a.state = "preferred";
    ctx.trace("ndp.dad", "L3", `${this.tag}DAD 통과: ${Ipv6Interface.DAD_WAIT}ms 동안 아무도 ${ip} 를 주장하지 않음 → ${a.origin === "link-local" ? "링크 로컬 주소" : "주소"} 사용 시작`, { ip, ok: true });
    return true;
  }

  private dadFailed(a: Addr6, byMac: Mac | undefined, frameId: number, ctx: NodeContext): void {
    this.dadTimers.get(a.ip)?.cancel();
    this.dadTimers.delete(a.ip);
    a.state = "duplicate";
    ctx.trace(
      "ndp.dad.fail",
      "L3",
      `${this.tag}DAD 실패: ${a.ip} 는 이미 ${byMac ?? "다른 장치"} 가 쓰는 주소 → 이 주소를 쓰지 않음 (리눅스: "IPv6 duplicate address detected"). 다른 주소를 넣으세요`,
      { ip: a.ip, mac: byMac },
      frameId,
    );
  }

  // ---------- 수신 ----------

  /** NS/NA 처리 */
  handleNdp(pkt: Ipv6Packet, msg: NdpMessage, frame: EthernetFrame, ctx: NodeContext, emit: Emit): void {
    const mine = this.addrs.find((a) => a.ip === msg.target);
    if (msg.type === "ns") {
      const dad = pkt.src === UNSPECIFIED6;
      if (!mine || mine.state === "duplicate") {
        ctx.trace("frame.drop", "L3", `${this.tag}NDP NS (${msg.target} 의 MAC 은?) — 내 주소가 아님 → 응답 안 함 (solicited-node 그룹이 우연히 겹침)`, { target: msg.target }, frame.id);
        return;
      }
      if (mine.state === "tentative") {
        if (dad) this.dadFailed(mine, frame.src, frame.id, ctx);
        // DAD 중인 주소로 온 보통 NS 에는 답하지 않는다 (아직 내 주소가 아니므로)
        return;
      }
      if (dad) {
        // 다른 장치가 내 주소를 DAD 로 확인 중: 모든 노드 그룹으로 NA → 그쪽이 중복을 알고 포기한다
        const na: Ipv6Packet = { kind: "ipv6", src: mine.ip, dst: ALL_NODES, hopLimit: 255, payload: { kind: "icmp6", type: "na", target: mine.ip, router: this.router, solicited: false, override: true, tll: this.mac } };
        ctx.trace("ndp.na.sent", "L3", `${this.tag}DAD 방어: ${frame.src} 가 ${mine.ip} 를 쓰려고 확인함 → 이미 내가 쓰는 주소라고 모든 노드(ff02::1)에게 NA`, { target: mine.ip, to: frame.src }, frame.id);
        this.transmit(ALL_NODES_MAC, na, ctx, emit);
        return;
      }
      ctx.trace("ndp.ns.received", "L3", `${this.tag}NDP NS 수신: "${msg.target} 의 MAC 은?" (보낸이 ${pkt.src} / ${msg.sll ?? frame.src})`, { target: msg.target, from: pkt.src }, frame.id);
      if (msg.sll) this.learn(pkt.src, msg.sll, false, "NS 의 출발지 링크 계층 주소 옵션에서 학습", frame.id, ctx);
      const reply: Ipv6Packet = {
        kind: "ipv6",
        src: mine.ip,
        dst: pkt.src,
        hopLimit: 255,
        payload: { kind: "icmp6", type: "na", target: mine.ip, router: this.router, solicited: true, override: true, tll: this.mac },
      };
      ctx.trace("ndp.na.sent", "L3", `${this.tag}NDP NA 송신: "${mine.ip} 는 ${this.mac}"${this.router ? " (R 플래그: 나는 라우터)" : ""} → ${pkt.src} 에게 유니캐스트`, { target: mine.ip, to: pkt.src }, frame.id);
      this.transmit(msg.sll ?? frame.src, reply, ctx, emit);
      return;
    }
    // NA
    if (mine) {
      if (mine.state === "tentative") this.dadFailed(mine, msg.tll ?? frame.src, frame.id, ctx);
      else if (mine.state === "preferred" && (msg.tll ?? frame.src) !== this.mac)
        ctx.trace("ip.conflict", "L3", `${this.tag}주소 충돌: ${msg.tll ?? frame.src} 도 내 IPv6 주소 ${mine.ip} 를 주장 (NA) — 둘 중 하나의 주소를 바꾸세요`, { ip: mine.ip, mac: msg.tll ?? frame.src }, frame.id);
      return;
    }
    ctx.trace("ndp.na.received", "L3", `${this.tag}NDP NA 수신: ${msg.target} 는 ${msg.tll ?? "?"}${msg.router ? " (라우터)" : ""}${msg.solicited ? "" : " — 요청하지 않은 알림"}`, { target: msg.target, mac: msg.tll }, frame.id);
    const known = this.neighbors.get(msg.target);
    const waiting = this.pending.has(msg.target);
    if (!msg.tll || (!known && !waiting)) return; // 모르는 이웃의 요청하지 않은 NA 로는 캐시를 만들지 않는다 (RFC 4861)
    if (known && known.mac !== msg.tll && !msg.override) return;
    this.learn(msg.target, msg.tll, msg.router, "NA 에서 학습", frame.id, ctx);
    this.flushPending(msg.target, ctx, emit);
  }

  private learn(ip: Ip, mac: Mac, router: boolean, how: string, frameId: number, ctx: NodeContext): void {
    if (ip === UNSPECIFIED6) return;
    const known = this.neighbors.get(ip);
    this.neighbors.set(ip, { mac, learnedAt: ctx.now, router: router || (known?.router ?? false) });
    if (!known || known.mac !== mac) ctx.trace("ndp.cache.update", "L3", `${this.tag}이웃 캐시 ${known ? "갱신" : "추가"}: ${ip} → ${mac} (${how})`, { ip, mac }, frameId);
  }

  private flushPending(ip: Ip, ctx: NodeContext, emit: Emit): void {
    const queue = this.pending.get(ip);
    if (!queue) return;
    this.pending.delete(ip);
    this.nsTimers.get(ip)?.cancel();
    this.nsTimers.delete(ip);
    const entry = this.neighbors.get(ip);
    if (!entry) return;
    for (const { pkt, queuedAt } of queue) {
      ctx.trace("ip.dequeue", "L3", `${this.tag}NDP 해석 완료 → 대기열 패킷 전송 (${ctx.now - queuedAt}ms 대기)`, { dst: pkt.dst });
      this.transmit(entry.mac, pkt, ctx, emit);
    }
  }

  /** "ndp-timeout" 타이머. 드롭한 패킷을 돌려준다 (ping 실패·Address unreachable 통지용) */
  onNsTimeout(data: unknown, ctx: NodeContext): Ipv6Packet[] {
    const { mac, ip } = data as { mac: Mac; ip: Ip };
    if (mac !== this.mac) return [];
    this.nsTimers.delete(ip);
    const queue = this.pending.get(ip);
    if (!queue || this.neighbors.has(ip)) return [];
    this.pending.delete(ip);
    ctx.trace("ndp.timeout", "L3", `${this.tag}NDP timeout: ${ip} 가 ${Ipv6Interface.NS_TIMEOUT}ms 동안 NA 로 응답하지 않음 → 대기 패킷 ${queue.length}개 드롭 (Address unreachable)`, { ip, dropped: queue.length });
    return queue.map((q) => q.pkt);
  }

  /** 더 넘길 수 없는 패킷에 대한 ICMPv6 Destination Unreachable (출발지 = 이 인터페이스 주소). 못 만들면 undefined */
  unreachable(pkt: Ipv6Packet, code: UnreachableCode, ctx: NodeContext, frameId?: number): Ipv6Packet | undefined {
    const from = this.errorSource(pkt.src);
    const notice = from ? icmpv6ErrorFor(from, pkt, { type: "unreachable", code }) : undefined;
    if (!notice) return undefined;
    const why = code === "net" ? "그 목적지로 가는 경로가 없음" : code === "host" ? "그 주소의 장치가 NDP(NS)에 응답하지 않음" : "그 UDP 포트를 듣는 프로그램이 없음";
    ctx.trace("icmp.unreachable.sent", "L3", `${this.tag}${pkt.src} 에게 ICMPv6 ${UNREACHABLE6_LABEL[code]} 통지 (원래 ${pkt.src} → ${pkt.dst}) — ${why}`, { to: pkt.src, dst: pkt.dst, code }, frameId);
    return notice;
  }

  /** Hop Limit 이 다 된 패킷에 대한 ICMPv6 Time Exceeded. 못 만들면 undefined */
  timeExceeded(pkt: Ipv6Packet, ctx: NodeContext, frameId?: number): Ipv6Packet | undefined {
    const from = this.errorSource(pkt.src);
    const notice = from ? icmpv6ErrorFor(from, pkt, { type: "time-exceeded" }) : undefined;
    if (!notice) {
      ctx.trace("ip.ttl-expired", "L3", `${this.tag}Hop Limit ${pkt.hopLimit} 로 도착한 ${pkt.src} → ${pkt.dst}: 더 넘기면 0 → 드롭 (통지는 보내지 않음)`, { src: pkt.src, dst: pkt.dst }, frameId);
      return undefined;
    }
    ctx.trace(
      "icmp.ttl-exceeded",
      "L3",
      `${this.tag}Hop Limit ${pkt.hopLimit} 로 도착한 ${pkt.src} → ${pkt.dst}: 한 홉 더 넘기면 0 → 드롭하고 ${from} 이름으로 보낸 이에게 ICMPv6 Time Exceeded 통지 (IPv6 의 Hop Limit 은 IPv4 의 TTL 과 같다)`,
      { src: pkt.src, dst: pkt.dst, from, ttl: pkt.hopLimit },
      frameId,
    );
    return notice;
  }

  // ---------- 표시 ----------

  /** 주소 요약 (링크 로컬 제외, 없으면 링크 로컬) */
  summary(): string {
    const g = this.addrs.filter((a) => a.origin !== "link-local");
    const show = g.length ? g : this.addrs;
    return show.map((a) => `${a.ip}/${a.prefix}${a.state === "preferred" ? "" : ` (${STATE_LABEL[a.state]})`}`).join(", ");
  }

  addrRows(): string[][] {
    return this.addrs.map((a) => [`${a.ip}/${a.prefix}`, a.origin === "link-local" ? "링크 로컬" : "수동", STATE_LABEL[a.state]]);
  }

  neighborRows(): string[][] {
    return [...this.neighbors.entries()].map(([ip, n]) => [ip, n.mac, `${n.learnedAt}ms${n.router ? " · 라우터" : ""}`]);
  }
}
