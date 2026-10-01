// IPv6 인터페이스 하나: 주소 목록(링크 로컬 + 수동), 이웃 캐시, NDP(NS/NA)로 이웃 MAC 찾기, DAD(중복 주소 검사).
// IPv4 의 NetInterface(ARP) 와 나란히 붙는다. 호스트와 게이트웨이가 같이 쓴다.
//
// 학습 포인트 — ARP 와 다른 점:
// - 브로드캐스트가 없다. "이 주소의 MAC 은?" 은 그 주소에서 만든 solicited-node 멀티캐스트 그룹(ff02::1:ffXX:XXXX)에만 보내,
//   마지막 24비트가 같은 장치만 받는다 (ARP 요청은 링크의 모든 장치가 받는다)
// - NDP 는 ICMPv6(L3) 위에서 돈다. ARP 는 IP 와 따로인 L2 프로토콜이다
// - 주소마다 쓰기 전에 DAD 를 한다: 출발지 :: 로 "이 주소를 쓰는 장치가 있나?" 를 묻고 1초 동안 답(NA)이 없으면 쓴다
// - 켜기만 하면 MAC 에서 만든 링크 로컬 주소(fe80::)가 생겨, 설정 없이도 같은 링크의 이웃과 통신한다
// - SLAAC: 라우터가 RA 로 알린 /64 프리픽스 + 내 인터페이스 ID 로 주소를 스스로 만든다 (DHCP 서버 없이).
//   기본 게이트웨이는 RA 를 보낸 라우터의 링크 로컬 주소. 주기 RA 는 없고(시계 구조) 링크 업·설정 변경·RS 에 답할 때만 보낸다
import type { Ip, Mac } from "../addr";
import {
  ALL_NODES,
  ALL_NODES_MAC,
  ALL_ROUTERS,
  ALL_ROUTERS_MAC,
  UNSPECIFIED6,
  commonPrefixLength6,
  eui64Address,
  isLinkLocal6,
  isMulticast6,
  linkLocalOf,
  multicastMac6,
  network6,
  sameSubnet6,
  solicitedNode,
} from "../addr6";
import { describeFrame, icmpv6ErrorFor, UNREACHABLE6_LABEL, type EthernetFrame, type Ipv6Packet, type NdpMessage, type RaPrefix, type RouterAdvertisement, type UnreachableCode } from "../packet";
import type { Emit } from "./iface";
import type { NodeContext, TimerHandle } from "./node";

export const NDP_TIMEOUT_TAG = "ndp-timeout";
export const DAD_TIMER_TAG = "ndp-dad";
export const RS_TIMER_TAG = "ndp-rs";
/** NUD: DELAY 가 끝나거나 PROBE 의 NS 에 답이 없을 때 */
export const NUD_TIMER_TAG = "ndp-nud";
/** 라우터: 주기 RA (배경 타이머) */
export const RA_PERIODIC_TAG = "ndp-ra-periodic";
/** 호스트: RA 의 라우터 수명이 다함 (배경 타이머) */
export const ROUTER_EXPIRY_TAG = "ndp-router-expiry";

/** NUD 상태 (RFC 4861 7.3.2). INCOMPLETE 는 대기열(pending)로, 지운 항목은 캐시에서 빠진다 */
export type NudState = "REACHABLE" | "STALE" | "DELAY" | "PROBE";

export interface Addr6 {
  ip: Ip;
  prefix: number;
  /** slaac = RA 의 프리픽스로 스스로 만든 주소 */
  origin: "link-local" | "manual" | "slaac";
  /** tentative = DAD 중(아직 못 씀), preferred = 사용 중, duplicate = 다른 장치가 이미 써서 포기 */
  state: "tentative" | "preferred" | "duplicate";
}

export interface Neighbor {
  mac: Mac;
  learnedAt: number;
  /** NA 의 R 플래그: 이 이웃은 라우터 */
  router: boolean;
  /** NUD 를 켠 인터페이스만: 지금 상태와 PROBE 에서 보낸 NS 수 (learnedAt = 마지막으로 도달을 확인한 때) */
  state?: NudState;
  probes?: number;
}

export interface Ipv6Settings {
  enabled: boolean;
  /** 수동 주소 (링크 로컬은 MAC 에서 자동) */
  addrs: { ip: Ip; prefix: number }[];
  gateway?: Ip;
  dns?: Ip;
  /** 호스트: RA 로 주소·기본 게이트웨이·DNS 를 받는다 (SLAAC) */
  slaac?: boolean;
  /** 라우터: 이 인터페이스로 RA 를 보낸다 (프리픽스 = 수동 주소의 프리픽스) */
  ra?: boolean;
  /** 라우터: RA 의 RDNSS 옵션으로 알릴 DNS 서버 */
  raDns?: Ip;
  /** 라우터: 주기 RA (10초마다, 라우터 수명 30초 — 배경 타이머). 끄면 변화가 있을 때만 (수명 1800초) */
  raPeriodic?: boolean;
  /** 호스트: NUD (이웃 도달 확인 — REACHABLE 30초 → STALE → 쓸 때 DELAY 5초 → 유니캐스트 NS 3번) */
  nud?: boolean;
}

const STATE_LABEL: Record<Addr6["state"], string> = { tentative: "DAD 중", preferred: "사용 중", duplicate: "중복 · 사용 안 함" };
const ORIGIN_LABEL: Record<Addr6["origin"], string> = { "link-local": "링크 로컬", manual: "수동", slaac: "SLAAC" };

export class Ipv6Interface {
  static readonly NS_TIMEOUT = 1000;
  /** 이 시간이 지난 이웃 항목은 다시 물어본다 (ARP 캐시와 같은 기준) */
  static readonly NEIGHBOR_TTL = 60_000;
  /** DAD: NS 를 보내고 기다리는 시간 (RFC 4861 RetransTimer 1초) */
  static readonly DAD_WAIT = 1000;
  static readonly HOP_LIMIT = 64;
  /** RS 재전송 간격과 횟수 (RFC 4861 RTR_SOLICITATION_INTERVAL 4초, MAX_RTR_SOLICITATIONS 3) */
  static readonly RS_INTERVAL = 4000;
  static readonly RS_MAX = 3;
  /** RA 의 라우터 수명(초): 호스트는 이만큼 RA 가 없으면 그 라우터를 뺀다 (배경 타이머라 시간이 흐를 때만) */
  static readonly ROUTER_LIFETIME = 1800;
  /** 주기 RA: 간격과 그때 알리는 라우터 수명 (radvd: AdvDefaultLifetime = 3 × MaxRtrAdvInterval) */
  static readonly RA_INTERVAL = 10_000;
  /** 주기 RA 를 켜지 않은 라우터도 이만큼마다 RA 를 다시 보낸다 (radvd 기본 MaxRtrAdvInterval 600초, 수명 1800초의 1/3) */
  static readonly RA_MAX_INTERVAL = 600_000;
  static readonly RA_PERIODIC_LIFETIME = 30;
  /** NUD (RFC 4861): 확인 뒤 REACHABLE 로 보는 시간, STALE 을 쓴 뒤 직접 묻기 전 기다리는 시간, 유니캐스트 NS 횟수 */
  static readonly REACHABLE_TIME = 30_000;
  static readonly DELAY_FIRST_PROBE = 5_000;
  static readonly MAX_UNICAST_SOLICIT = 3;
  static readonly PREFIX_VALID = 86400;

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
  /** 호스트 SLAAC: RA 로 주소·기본 게이트웨이를 받는다 */
  slaac = false;
  /**
   * RA 로 배운 기본 게이트웨이 후보 (라우터의 링크 로컬 주소, 먼저 배운 것이 먼저). token = 지금 유효한 수명 타이머.
   * suspect = 닿지 않은 적이 있음 (NUD 실패·NS 무응답) — 지우지 않고 뒤로 미뤄, 의심 없는 라우터를 먼저 쓴다 (RFC 4861 6.3.6)
   */
  readonly routers = new Map<Ip, { learnedAt: number; lifetime: number; token: number; suspect?: boolean }>();
  private routerToken = 0;
  /** 호스트: NUD 를 쓰는지 */
  nud = false;
  private readonly nudTimers = new Map<Ip, TimerHandle>();
  /** 라우터: 주기 RA 를 보내는지, 지금 유효한 주기 타이머 번호 */
  raPeriodic = false;
  private raTick: number | undefined;
  private raToken = 0;
  /** RA 의 RDNSS 옵션으로 받은 DNS 서버 */
  raDnsLearned: Ip | undefined;
  /** 그 DNS 를 알려 준 라우터 (그 라우터가 거두거나 DNS 없이 다시 알리면 지운다) */
  private raDnsFrom: Ip | undefined;
  /** 프리픽스("주소/길이")마다 그것을 알린 라우터들: 모두 거둬야 그 프리픽스로 만든 주소를 지운다 */
  private readonly prefixRouters = new Map<string, Set<Ip>>();
  /** 실행 중에 주소가 사라질 때 (RA 거둠 등): 호스트가 그 주소의 연결을 정리한다 */
  onAddrRemoved: ((ip: Ip, ctx: NodeContext) => void) | undefined;
  /** 링크 로컬이 DAD 를 통과해 쓸 수 있게 됐을 때 (공유기 WAN 이 DHCPv6-PD 를 시작한다) */
  onLinkLocalReady: ((ctx: NodeContext, emit: Emit) => void) | undefined;
  private rsTries = 0;
  private rsTimer: TimerHandle | undefined;
  /** 링크가 살아 있는지 (실패 문구용) */
  private up = false;
  /** 라우터: RA 가 꺼져 있을 때 RS 에 답하지 않는 이유 (없으면 "RA 광고가 꺼져 있음") */
  raOffReason: string | undefined;
  /** 라우터: 이 인터페이스로 RA 를 보내는지, RDNSS 로 알릴 DNS */
  raOn = false;
  raDns: Ip | undefined;
  /** 지난번 RA 에 실은 프리픽스 (바뀌면 빠진 것을 유효 수명 0 으로 거둔다) */
  private advertised: RaPrefix[] = [];
  /** 지난번 RA 의 내용 (프리픽스·DNS). 설정이 바뀌어 이것과 달라지면 새 RA */
  private advertisedKey = "";

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
    this.slaac = cfg.slaac === true && !this.router;
    this.raOn = cfg.ra === true && this.router;
    this.raDns = cfg.raDns;
    this.raPeriodic = cfg.raPeriodic === true && this.router;
    this.nud = cfg.nud === true && !this.router;
  }

  /** SLAAC 호스트가 아직 RA 를 기다리는 중 (RS 를 보내고 답을 기다림) */
  get raWaiting(): boolean {
    return this.rsTimer !== undefined;
  }

  /**
   * 이미 동작 중인 장비(ISP)로 시작: 주소를 DAD 없이 곧바로 쓰고, 링크 업에도 아무것도 보내지 않는다 (RS·NS 에만 답한다).
   * 인터넷 노드가 IPv6 를 쓰지 않는 구성의 로그를 바꾸지 않으려고
   */
  startQuiet(cfg: Ipv6Settings): void {
    this.init(cfg);
    for (const a of this.addrs) a.state = "preferred";
    this.up = true;
  }

  /**
   * 기본 게이트웨이: 수동 설정, 없으면 RA 로 배운 라우터 중 닿지 않은 적이 없는 첫 라우터 (RFC 4861 6.3.6).
   * 모두 의심스러우면 목록 맨 앞 — 실패한 라우터는 뒤로 보내므로 돌아가며 고르게 된다
   */
  get defaultRouter(): Ip | undefined {
    if (this.gateway) return this.gateway;
    for (const [ip, r] of this.routers) if (!r.suspect) return ip;
    return this.routers.keys().next().value;
  }

  /** 기본 게이트웨이 후보에 닿지 않음: 지우지 않고 뒤로 미룬다 (되살아나면 RA·NA 로 다시 믿는다) */
  private suspectRouter(ip: Ip, why: string, ctx: NodeContext): void {
    const r = this.routers.get(ip);
    if (!r) return;
    this.routers.delete(ip);
    this.routers.set(ip, { ...r, suspect: true });
    const next = this.defaultRouter;
    ctx.trace(
      "slaac.router",
      "L3",
      `${this.tag}기본 게이트웨이 후보 ${ip} 에 닿지 않음 (${why}) → 목록 뒤로 미룸${next && next !== ip ? ` — 이제 ${next}` : " (다른 라우터가 없어 다음에도 다시 시도)"}. 지우지는 않아 되살아나면 다시 쓴다 (RFC 4861 6.3.6)`,
      { router: ip, suspect: true, ...(next ? { next } : {}) },
    );
  }

  /** 쓸 DNS 서버: 수동 설정, 없으면 RA 의 RDNSS */
  get effectiveDns(): Ip | undefined {
    return this.dns ?? this.raDnsLearned;
  }

  /**
   * 설정 반영. 켜면 링크 로컬 + 수동 주소가 생기고(링크가 살아 있으면 곧바로 DAD), 끄면 모두 지운다.
   * @returns 주소가 바뀌었는지 (호스트는 연결을 정리한다)
   */
  configure(cfg: Ipv6Settings, linkUp: boolean, ctx: NodeContext, emit: Emit): boolean {
    this.up = linkUp;
    if (!cfg.enabled) {
      if (!this.enabled) return false;
      if (this.raOn && linkUp) this.sendRa(ctx, emit, true);
      this.enabled = false;
      this.reset();
      this.addrs = [];
      this.gateway = undefined;
      this.dns = undefined;
      this.forgetRa();
      this.raOn = false;
      this.slaac = false;
      this.rsTries = 0;
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
      if (cfg.gateway || !cfg.slaac) ctx.trace("ip.config", "sys", cfg.gateway ? `${this.tag}IPv6 기본 게이트웨이: ${cfg.gateway}${isLinkLocal6(cfg.gateway) ? " (라우터의 링크 로컬 주소 — IPv6 에서 흔한 방식)" : ""}` : `${this.tag}IPv6 기본 게이트웨이 없음`, { gateway: cfg.gateway });
    }
    if (cfg.dns !== this.dns) this.dns = cfg.dns;
    // 호스트 NUD 켜기·끄기 (끄면 상태를 지우고 예전처럼 60초 지나면 다시 묻는다)
    const nud = cfg.nud === true && !this.router;
    if (nud !== this.nud) {
      this.nud = nud;
      ctx.trace("ip.config", "sys", nud ? `${this.tag}NUD 켜짐: 이웃을 확인한 지 ${Ipv6Interface.REACHABLE_TIME / 1000}초가 지나면 STALE, 그 이웃에게 보낼 때 ${Ipv6Interface.DELAY_FIRST_PROBE / 1000}초 기다렸다 유니캐스트 NS 로 직접 확인 — 답이 없으면 지우고, 라우터면 기본 게이트웨이에서도 뺀다` : `${this.tag}NUD 꺼짐`, { nud });
      this.clearNud();
    }
    // 호스트 SLAAC 켜기·끄기
    const slaac = cfg.slaac === true && !this.router;
    if (slaac !== this.slaac) {
      this.slaac = slaac;
      if (slaac) {
        ctx.trace("ip.config", "sys", `${this.tag}IPv6 자동 설정 (SLAAC): 라우터 광고(RA)의 프리픽스로 주소를 만들고, RA 를 보낸 라우터를 기본 게이트웨이로 쓴다`, {});
        this.rsTries = 0;
        if (linkUp && this.owns(this.linkLocal)) this.sendRs(ctx, emit);
      } else {
        changed = this.dropSlaac(ctx, "수동 설정으로 전환") || changed;
      }
    }
    // 라우터 RA: 켜기·끄기, 알릴 프리픽스·DNS 가 바뀌면 곧바로 새 RA (꺼지면 수명 0 으로 거둠)
    if (this.router) {
      const raOn = cfg.ra === true;
      const wasOn = this.raOn;
      if (raOn !== wasOn) ctx.trace("ip.config", "sys", raOn ? `${this.tag}RA 광고 켜짐: 이 링크의 호스트들이 SLAAC 로 주소를 만들 수 있게 프리픽스를 알린다` : `${this.tag}RA 광고 꺼짐`, { ra: raOn });
      this.raOn = raOn;
      this.raDns = cfg.raDns;
      const ready = linkUp && this.owns(this.linkLocal);
      // 주기 RA 켜기·끄기: 알리는 라우터 수명이 바뀌므로 곧바로 새 RA (그 RA 가 다음 주기를 건다)
      const periodic = cfg.raPeriodic === true;
      const periodicChanged = periodic !== this.raPeriodic;
      if (periodicChanged) {
        this.raPeriodic = periodic;
        this.raTick = undefined;
        if (raOn) ctx.trace("ip.config", "sys", periodic ? `${this.tag}주기 RA 켜짐: ${Ipv6Interface.RA_INTERVAL / 1000}초마다 RA, 라우터 수명 ${Ipv6Interface.RA_PERIODIC_LIFETIME}초 — 이 라우터가 말없이 사라지면 호스트가 수명이 다해 뺀다 (시간이 흐를 때만 돈다)` : `${this.tag}주기 RA 꺼짐: ${Ipv6Interface.RA_MAX_INTERVAL / 1000}초마다 RA (radvd 기본, 라우터 수명 ${Ipv6Interface.ROUTER_LIFETIME}초)`, { raPeriodic: periodic });
      }
      if (ready && raOn && (periodicChanged || this.raKey() !== this.advertisedKey)) this.sendRa(ctx, emit);
      else if (ready && !raOn && wasOn) this.sendRa(ctx, emit, true);
      if (!raOn) {
        this.advertised = [];
        this.advertisedKey = "";
      }
    }
    return changed;
  }

  private removeAddr(a: Addr6): void {
    this.addrs = this.addrs.filter((x) => x !== a);
    this.dadTimers.get(a.ip)?.cancel();
    this.dadTimers.delete(a.ip);
  }

  /** NUD 상태·타이머를 지운다 (끄거나 이웃 캐시를 비울 때) */
  private clearNud(): void {
    for (const t of this.nudTimers.values()) t.cancel();
    this.nudTimers.clear();
    for (const n of this.neighbors.values()) {
      delete n.state;
      delete n.probes;
    }
  }

  /** 대기열·타이머·이웃 캐시를 비운다 */
  private reset(): void {
    this.clearNud();
    this.clearPending();
    for (const t of this.dadTimers.values()) t.cancel();
    this.dadTimers.clear();
    this.neighbors.clear();
    this.rsTimer?.cancel();
    this.rsTimer = undefined;
  }

  /** RA 로 배운 것(SLAAC 주소·기본 게이트웨이·DNS)을 잊는다. 주소를 지웠으면 true */
  private forgetRa(): boolean {
    const had = this.addrs.some((a) => a.origin === "slaac");
    for (const a of this.addrs.filter((x) => x.origin === "slaac")) this.removeAddr(a);
    this.routers.clear();
    this.prefixRouters.clear();
    this.raDnsLearned = undefined;
    this.raDnsFrom = undefined;
    this.rsTimer?.cancel();
    this.rsTimer = undefined;
    return had;
  }

  private dropSlaac(ctx: NodeContext, why: string): boolean {
    const gone = this.addrs.filter((a) => a.origin === "slaac").map((a) => a.ip);
    const hadRouter = this.routers.size > 0;
    const removed = this.forgetRa();
    if (gone.length || hadRouter) ctx.trace("slaac.addr", "L3", `${this.tag}${why} → SLAAC 주소${gone.length ? ` ${gone.join(", ")}` : ""}·RA 로 배운 기본 게이트웨이를 지움`, { removed: gone });
    for (const ip of gone) this.onAddrRemoved?.(ip, ctx);
    return removed;
  }

  clearPending(): void {
    for (const t of this.nsTimers.values()) t.cancel();
    this.nsTimers.clear();
    this.pending.clear();
  }

  /** 링크가 살아남: 모든 주소를 다시 DAD (링크 로컬이 끝나면 호스트는 RS, 라우터는 RA) */
  linkUp(ctx: NodeContext, emit: Emit): void {
    this.up = true;
    if (!this.enabled) return;
    this.rsTries = 0;
    for (const a of this.addrs) {
      a.state = "tentative";
      this.startDad(a, ctx, emit);
    }
  }

  /** 링크 다운: 이웃·대기열을 비우고 주소는 다시 확인이 필요한 상태로. RA 로 배운 것은 잊는다 (다시 붙으면 RS 로 새로 묻는다) */
  linkDown(): void {
    this.up = false;
    if (!this.enabled) return;
    this.reset();
    this.forgetRa();
    this.advertised = [];
    this.advertisedKey = "";
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
    if (!this.up) return "링크 다운 — 케이블을 연결하세요 (다시 연결되면 주소를 DAD 로 확인한 뒤 쓴다)";
    if (this.addrs.some((a) => a.state === "tentative")) return "주소를 DAD 로 확인하는 중 (1초 뒤 다시 시도하세요)";
    if (isLinkLocal6(dst)) return "링크 로컬 주소가 중복이라 쓰지 않는 중";
    const dup = this.addrs.find((a) => a.origin !== "link-local" && a.state === "duplicate");
    if (dup?.origin === "slaac") return `SLAAC 주소 ${dup.ip} 가 다른 장치와 중복이라 쓰지 않는 중 — 그 장치의 주소를 바꾸거나 이 장치의 IPv6 를 수동으로 바꾸세요`;
    if (dup) return "IPv6 주소가 다른 장치와 중복이라 쓰지 않는 중 — 다른 주소를 넣으세요";
    if (this.slaac && this.routers.size > 0) return "RA 는 받았지만 SLAAC 로 쓸 /64 프리픽스가 없음 — 라우터 인터페이스 주소를 /64 로 하세요 (링크 로컬로는 다른 네트워크로 못 나감)";
    if (this.slaac) return "RA 를 받지 못해 SLAAC 주소가 없음 — 링크 로컬 주소(fe80::)로는 다른 네트워크로 나갈 수 없음. 이 링크 라우터의 IPv6·RA 광고를 확인하세요";
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
    const gw = this.defaultRouter;
    if (gw) {
      ctx.trace("ip.route", "L3", `${this.tag}${dst} 는 다른 네트워크 → IPv6 기본 게이트웨이 ${gw}${this.gateway ? "" : " (RA 로 배운 라우터)"} 로 전달`, { dst, nextHop: gw });
      return gw;
    }
    ctx.trace(
      "ip.no-route",
      "L3",
      `${this.tag}${dst} 는 다른 네트워크인데 IPv6 기본 게이트웨이가 없음 → 드롭 (${this.slaac ? "RA 를 보낸 라우터가 없음 — 이 링크 라우터의 RA 광고를 확인하세요" : "IPv6 설정에서 게이트웨이를 넣으세요"})`,
      { dst },
    );
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
    if (entry && this.nud) {
      // NUD: 캐시가 있으면 상태와 상관없이 보낸다. 오래된(STALE) 항목은 보내면서 확인을 시작한다
      this.nudUse(nextHop, entry, ctx);
      ctx.trace("ndp.cache.hit", "L3", `${this.tag}이웃 캐시 적중: ${nextHop} → ${entry.mac} (${entry.state})`, { ip: nextHop, mac: entry.mac, state: entry.state });
      this.transmit(entry.mac, pkt, ctx, emit);
      return;
    }
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

  /** "ndp-dad" 타이머. 아무도 주장하지 않았으면 사용 시작 — 링크 로컬이 준비되면 호스트(SLAAC)는 RS, 라우터(RA 켬)는 RA. 처리했으면 true */
  finishDad(data: unknown, ctx: NodeContext, emit: Emit): boolean {
    const { mac, ip } = data as { mac: Mac; ip: Ip };
    if (mac !== this.mac) return false;
    this.dadTimers.delete(ip);
    const a = this.addrs.find((x) => x.ip === ip);
    if (!a || a.state !== "tentative") return true;
    a.state = "preferred";
    ctx.trace("ndp.dad", "L3", `${this.tag}DAD 통과: ${Ipv6Interface.DAD_WAIT}ms 동안 아무도 ${ip} 를 주장하지 않음 → ${a.origin === "link-local" ? "링크 로컬 주소" : a.origin === "slaac" ? "SLAAC 주소" : "주소"} 사용 시작`, { ip, ok: true });
    if (a.origin === "link-local") {
      if (this.slaac && this.routers.size === 0) this.sendRs(ctx, emit);
      if (this.raOn) this.sendRa(ctx, emit);
      this.onLinkLocalReady?.(ctx, emit);
    }
    // 수동 주소는 MAC 과 무관해 장비를 바꿔 끼워도 같은 주소일 수 있다: 요청하지 않은 NA 로 알려 이웃 캐시의 옛 MAC 을 고치게 한다
    // (IPv4 의 Gratuitous ARP. 링크 로컬·SLAAC 주소는 MAC 에서 나오므로 장비가 바뀌면 주소도 바뀐다)
    if (a.origin === "manual") {
      const na: Ipv6Packet = { kind: "ipv6", src: a.ip, dst: ALL_NODES, hopLimit: 255, payload: { kind: "icmp6", type: "na", target: a.ip, router: this.router, solicited: false, override: true, tll: this.mac } };
      ctx.trace("ndp.na.sent", "L3", `${this.tag}주소 알림: 요청하지 않은 NA 를 모든 노드(ff02::1)에게 "${a.ip} 는 ${this.mac}" — 이웃 캐시에 옛 MAC 이 남아 있으면 고치도록 (IPv4 의 Gratuitous ARP)`, { target: a.ip });
      this.transmit(ALL_NODES_MAC, na, ctx, emit);
    }
    return true;
  }

  /** @param simultaneous 상대도 같은 주소를 동시에 DAD 로 확인 중 (그 DAD NS 를 받음) — RFC 4862 대로 둘 다 포기한다 */
  private dadFailed(a: Addr6, byMac: Mac | undefined, frameId: number, ctx: NodeContext, emit: Emit, simultaneous = false): void {
    this.dadTimers.get(a.ip)?.cancel();
    this.dadTimers.delete(a.ip);
    a.state = "duplicate";
    ctx.trace(
      "ndp.dad.fail",
      "L3",
      simultaneous
        ? `${this.tag}DAD 실패: ${byMac ?? "다른 장치"} 도 ${a.ip} 를 동시에 확인하는 중(그쪽 DAD NS 를 받음) → RFC 4862 대로 둘 다 이 주소를 포기 (리눅스: "IPv6 duplicate address detected"). 한쪽 주소를 바꾸세요`
        : `${this.tag}DAD 실패: ${a.ip} 는 이미 ${byMac ?? "다른 장치"} 가 쓰는 주소 (NA 로 방어함) → 이 주소를 쓰지 않음 (리눅스: "IPv6 duplicate address detected"). 다른 주소를 넣으세요`,
      { ip: a.ip, mac: byMac },
      frameId,
    );
    // 라우터가 알리던 프리픽스의 자기 주소가 중복이면 곧바로 그 프리픽스를 거두는 RA (다음 RS 를 기다리지 않게)
    if (this.raOn && a.origin === "manual" && this.raKey() !== this.advertisedKey) this.sendRa(ctx, emit);
  }

  // ---------- 수신 ----------

  /** NDP 처리: NS/NA (이웃), RS/RA (라우터) */
  handleNdp(pkt: Ipv6Packet, msg: NdpMessage, frame: EthernetFrame, ctx: NodeContext, emit: Emit): void {
    if (msg.type === "rs") {
      this.handleRs(pkt, msg.sll, frame, ctx, emit);
      return;
    }
    if (msg.type === "ra") {
      this.handleRa(pkt, msg, frame, ctx, emit);
      return;
    }
    const mine = this.addrs.find((a) => a.ip === msg.target);
    if (msg.type === "ns") {
      const dad = pkt.src === UNSPECIFIED6;
      if (!mine || mine.state === "duplicate") {
        ctx.trace("frame.drop", "L3", `${this.tag}NDP NS (${msg.target} 의 MAC 은?) — 내 주소가 아님 → 응답 안 함 (solicited-node 그룹이 우연히 겹침)`, { target: msg.target }, frame.id);
        return;
      }
      if (mine.state === "tentative") {
        if (dad) this.dadFailed(mine, frame.src, frame.id, ctx, emit, true);
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
      if (msg.sll) {
        this.learn(pkt.src, msg.sll, false, "NS 의 출발지 링크 계층 주소 옵션에서 학습", frame.id, ctx);
        // 나도 그 이웃을 찾던 중이면 (서로 동시에 NS) 여기서 배운 것으로 기다리던 패킷을 보낸다 — NA 하나를 잃어도 대기열이 남지 않게
        this.flushPending(pkt.src, ctx, emit);
      }
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
      if (mine.state === "tentative") this.dadFailed(mine, msg.tll ?? frame.src, frame.id, ctx, emit);
      else if (mine.state === "preferred" && (msg.tll ?? frame.src) !== this.mac)
        ctx.trace("ip.conflict", "L3", `${this.tag}주소 충돌: ${msg.tll ?? frame.src} 도 내 IPv6 주소 ${mine.ip} 를 주장 (NA) — 둘 중 하나의 주소를 바꾸세요`, { ip: mine.ip, mac: msg.tll ?? frame.src }, frame.id);
      return;
    }
    ctx.trace("ndp.na.received", "L3", `${this.tag}NDP NA 수신: ${msg.target} 는 ${msg.tll ?? "?"}${msg.router ? " (라우터)" : ""}${msg.solicited ? "" : " — 요청하지 않은 알림"}`, { target: msg.target, mac: msg.tll }, frame.id);
    const known = this.neighbors.get(msg.target);
    const waiting = this.pending.has(msg.target);
    if (!msg.tll || (!known && !waiting)) return; // 모르는 이웃의 요청하지 않은 NA 로는 캐시를 만들지 않는다 (RFC 4861)
    if (known && known.mac !== msg.tll && !msg.override) return;
    this.learn(msg.target, msg.tll, msg.router, "NA 에서 학습", frame.id, ctx, msg.solicited);
    this.flushPending(msg.target, ctx, emit);
  }

  // ---------- 라우터 찾기 (RS/RA) ----------

  /** 호스트: 모든 라우터(ff02::2)에게 RS. 4초 안에 RA 가 없으면 다시, 3번까지 */
  private sendRs(ctx: NodeContext, emit: Emit): void {
    this.rsTimer?.cancel();
    this.rsTries += 1;
    const pkt: Ipv6Packet = { kind: "ipv6", src: this.linkLocal, dst: ALL_ROUTERS, hopLimit: 255, payload: { kind: "icmp6", type: "rs", sll: this.mac } };
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: ALL_ROUTERS_MAC, payload: pkt };
    ctx.trace("ndp.rs.sent", "L3", `${this.tag}RS 멀티캐스트 (모든 라우터 ff02::2): "이 링크에 라우터 있나요? RA 를 보내 주세요" (${this.rsTries}/${Ipv6Interface.RS_MAX})`, { tries: this.rsTries }, frame.id);
    emit(frame);
    this.rsTimer = ctx.timer(Ipv6Interface.RS_INTERVAL, RS_TIMER_TAG, { mac: this.mac });
  }

  /** "ndp-rs" 타이머: RA 가 없으면 RS 를 다시, 3번 뒤에는 포기. 처리했으면 true */
  onRsTimer(data: unknown, ctx: NodeContext, emit: Emit): boolean {
    if ((data as { mac: Mac }).mac !== this.mac) return false;
    this.rsTimer = undefined;
    if (!this.enabled || !this.slaac || this.routers.size > 0 || this.addrs.some((a) => a.origin === "slaac")) return true;
    if (this.rsTries < Ipv6Interface.RS_MAX) {
      this.sendRs(ctx, emit);
      return true;
    }
    ctx.trace(
      "slaac.timeout",
      "L3",
      `${this.tag}RS ${Ipv6Interface.RS_MAX}번에 RA 가 없음 → SLAAC 주소·기본 게이트웨이 없이 링크 로컬만 (이 링크의 라우터가 없거나 IPv6·RA 광고가 꺼져 있음)`,
      {},
    );
    return true;
  }

  /** 라우터: 알릴 프리픽스 (수동 주소의 프리픽스, 중복으로 포기한 것 제외) */
  private raPrefixes(): RaPrefix[] {
    const out: RaPrefix[] = [];
    for (const a of this.addrs) {
      if (a.origin !== "manual" || a.state === "duplicate") continue;
      const prefix = network6(a.ip, a.prefix);
      if (!out.some((p) => p.prefix === prefix && p.length === a.prefix)) out.push({ prefix, length: a.prefix, onLink: true, autonomous: true, valid: Ipv6Interface.PREFIX_VALID });
    }
    return out;
  }

  private raKey(): string {
    return JSON.stringify([this.raPrefixes().map((p) => `${p.prefix}/${p.length}`), this.raDns ?? ""]);
  }

  /**
   * 라우터: 모든 노드(ff02::1)에게 RA. final 이면 라우터 수명 0 + 알렸던 프리픽스를 유효 수명 0 으로 (거둠).
   * 지난번에 알렸다가 빠진 프리픽스도 유효 수명 0 으로 실어 호스트가 그 주소를 지우게 한다
   */
  sendRa(ctx: NodeContext, emit: Emit, final = false, frameId?: number): void {
    if (!this.enabled || !this.owns(this.linkLocal)) return;
    const current = final ? [] : this.raPrefixes();
    const withdrawn = this.advertised.filter((p) => !current.some((c) => c.prefix === p.prefix && c.length === p.length)).map((p) => ({ ...p, valid: 0 }));
    const ra: RouterAdvertisement = {
      kind: "icmp6",
      type: "ra",
      curHopLimit: Ipv6Interface.HOP_LIMIT,
      managed: false,
      other: false,
      routerLifetime: final ? 0 : this.raPeriodic ? Ipv6Interface.RA_PERIODIC_LIFETIME : Ipv6Interface.ROUTER_LIFETIME,
      prefixes: [...current, ...withdrawn],
      ...(!final && this.raDns ? { rdnss: [this.raDns] } : {}),
      sll: this.mac,
    };
    this.advertised = current;
    this.advertisedKey = final ? "" : this.raKey();
    const pkt: Ipv6Packet = { kind: "ipv6", src: this.linkLocal, dst: ALL_NODES, hopLimit: 255, payload: ra };
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: ALL_NODES_MAC, payload: pkt };
    const prefixText = current.map((p) => `${p.prefix}/${p.length}`).join(", ");
    ctx.trace(
      "ndp.ra.sent",
      "L3",
      final
        ? `${this.tag}RA 거둠 (모든 노드 ff02::1): 라우터 수명 0 — 나(${this.linkLocal})를 기본 게이트웨이에서 빼고${withdrawn.length ? ` 프리픽스 ${withdrawn.map((p) => `${p.prefix}/${p.length}`).join(", ")} 로 만든 주소를 지우라` : ""}`
        : `${this.tag}${this.raPeriodic ? "주기 " : ""}RA 멀티캐스트 (모든 노드 ff02::1): "나(${this.linkLocal})는 이 링크의 라우터${this.raPeriodic ? ` (라우터 수명 ${Ipv6Interface.RA_PERIODIC_LIFETIME}초)` : ""}${prefixText ? `, 프리픽스 ${prefixText} 로 주소를 만드세요(SLAAC)` : this.addrs.some((a) => a.origin === "manual" && a.state === "duplicate") ? " (알릴 프리픽스 없음 — 이 인터페이스 주소가 중복이라 뺌)" : " (알릴 프리픽스 없음 — 이 인터페이스에 주소가 없음)"}${this.raDns ? `, DNS 는 ${this.raDns}` : ""}"${withdrawn.length ? ` · 빠진 프리픽스 ${withdrawn.map((p) => `${p.prefix}/${p.length}`).join(", ")} 는 유효 수명 0 으로 거둠` : ""}`,
      { prefixes: current.map((p) => `${p.prefix}/${p.length}`), final },
      frame.id,
    );
    void frameId;
    emit(frame);
    // 다음 RA 차례 (배경 타이머 — 시간이 흐를 때만): 주기 RA 면 10초, 아니면 600초 (수명 1800초가 다하기 전에 다시 알린다)
    this.raTick = undefined;
    if (!final && this.raOn) {
      this.raTick = ++this.raToken;
      ctx.timer(this.raPeriodic ? Ipv6Interface.RA_INTERVAL : Ipv6Interface.RA_MAX_INTERVAL, RA_PERIODIC_TAG, { mac: this.mac, tick: this.raTick }, true);
    }
  }

  /** 라우터: 주기 RA 차례. 처리했으면 true (다른 인터페이스의 타이머면 false) */
  onRaTick(data: unknown, ctx: NodeContext, emit: Emit): boolean {
    const { mac, tick } = data as { mac: Mac; tick: number };
    if (mac !== this.mac) return false;
    if (tick !== this.raTick) return true;
    this.raTick = undefined;
    if (!this.enabled || !this.raOn || !this.up || !this.owns(this.linkLocal)) return true;
    this.sendRa(ctx, emit);
    return true;
  }

  /** 호스트: RA 로 배운 라우터의 수명이 다함 (그동안 RA 가 없었음). 처리했으면 true */
  onRouterExpiry(data: unknown, ctx: NodeContext): boolean {
    const { mac, router, token } = data as { mac: Mac; router: Ip; token: number };
    if (mac !== this.mac) return false;
    const r = this.routers.get(router);
    if (!r || r.token !== token) return true; // 그 뒤 RA 로 수명이 다시 시작됐거나 이미 뺐다
    this.routers.delete(router);
    ctx.trace(
      "slaac.router",
      "L3",
      `${this.tag}라우터 ${router} 의 RA 가 라우터 수명(${r.lifetime}초) 동안 오지 않음 → 기본 게이트웨이에서 뺌${this.routers.size ? ` (남은 라우터 ${[...this.routers.keys()].join(", ")} 로)` : " (남은 라우터 없음 — 다른 네트워크로 못 나감)"}`,
      { router, removed: true, expired: true },
    );
    return true;
  }

  /** NUD: 이웃을 쓰려 함 — 확인한 지 오래면 STALE, STALE 을 쓰면 DELAY 로 (5초 뒤 직접 확인) */
  private nudUse(ip: Ip, entry: Neighbor, ctx: NodeContext): void {
    if ((entry.state ?? "REACHABLE") === "REACHABLE" && ctx.now - entry.learnedAt > Ipv6Interface.REACHABLE_TIME) entry.state = "STALE";
    entry.state ??= "REACHABLE";
    if (entry.state !== "STALE") return;
    entry.state = "DELAY";
    ctx.trace(
      "ndp.nud",
      "L3",
      `${this.tag}이웃 ${ip} 는 STALE (마지막 확인 ${Math.round((ctx.now - entry.learnedAt) / 1000)}초 전) → 캐시의 ${entry.mac} 로 보내고 DELAY: ${Ipv6Interface.DELAY_FIRST_PROBE / 1000}초 안에 확인이 없으면 직접 물어본다 (NUD)`,
      { ip, state: "DELAY", mac: entry.mac, ...(entry.router ? { router: true } : {}) },
    );
    this.nudTimers.get(ip)?.cancel();
    this.nudTimers.set(ip, ctx.timer(Ipv6Interface.DELAY_FIRST_PROBE, NUD_TIMER_TAG, { mac: this.mac, ip }));
  }

  /** NUD 타이머: DELAY 가 끝나면 PROBE(유니캐스트 NS), 답 없이 3번이면 지운다 (라우터면 기본 게이트웨이에서도). 처리했으면 true */
  onNudTimer(data: unknown, ctx: NodeContext, emit: Emit): boolean {
    const { mac, ip } = data as { mac: Mac; ip: Ip };
    if (mac !== this.mac) return false;
    this.nudTimers.delete(ip);
    const e = this.neighbors.get(ip);
    if (!e || (e.state !== "DELAY" && e.state !== "PROBE")) return true; // 그사이 확인됐다
    if (e.state === "DELAY") {
      e.state = "PROBE";
      e.probes = 0;
    }
    if ((e.probes ?? 0) < Ipv6Interface.MAX_UNICAST_SOLICIT) {
      e.probes = (e.probes ?? 0) + 1;
      const src = this.sourceFor(ip) ?? this.linkLocal;
      const pkt: Ipv6Packet = { kind: "ipv6", src, dst: ip, hopLimit: 255, payload: { kind: "icmp6", type: "ns", target: ip, sll: this.mac } };
      const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: e.mac, payload: pkt };
      ctx.trace("ndp.ns.sent", "L3", `${this.tag}NUD PROBE ${e.probes}/${Ipv6Interface.MAX_UNICAST_SOLICIT}: ${ip} 에게 유니캐스트 NS — "아직 ${e.mac} 에 있나요?"`, { target: ip, probe: e.probes, state: "PROBE" }, frame.id);
      emit(frame);
      this.nudTimers.set(ip, ctx.timer(Ipv6Interface.NS_TIMEOUT, NUD_TIMER_TAG, { mac: this.mac, ip }));
      return true;
    }
    this.neighbors.delete(ip);
    const wasRouter = this.routers.has(ip);
    ctx.trace(
      "ndp.timeout",
      "L3",
      `${this.tag}NUD 실패: ${ip} 가 유니캐스트 NS ${Ipv6Interface.MAX_UNICAST_SOLICIT}번에 답하지 않음 → 도달 불가로 보고 이웃 캐시에서 지움${wasRouter ? " — 라우터라 기본 게이트웨이 후보에서 뒤로 미룸" : ""}`,
      { ip, nud: "failed", ...(wasRouter ? { router: true } : {}) },
    );
    if (wasRouter) this.suspectRouter(ip, "NUD 실패", ctx);
    return true;
  }

  /** 장치를 지울 때: RA 를 보내던 인터페이스는 거둠 RA (호스트가 옛 게이트웨이·주소를 들고 있지 않게) */
  shutdown(ctx: NodeContext, emit: Emit): void {
    if (this.enabled && this.raOn) this.sendRa(ctx, emit, true);
  }

  private handleRs(pkt: Ipv6Packet, sll: Mac | undefined, frame: EthernetFrame, ctx: NodeContext, emit: Emit): void {
    if (!this.router) return; // 호스트는 모든 라우터 그룹에 가입하지 않아 오지 않는다
    if (!this.raOn) {
      ctx.trace("ndp.rs.received", "L3", `${this.tag}RS 수신 (from ${pkt.src}) — ${this.raOffReason ?? "이 인터페이스는 RA 광고가 꺼져 있어 응답 안 함 (IPv6 설정에서 RA 광고를 켜면 SLAAC 호스트가 주소를 만든다)"}`, { from: pkt.src }, frame.id);
      return;
    }
    ctx.trace("ndp.rs.received", "L3", `${this.tag}RS 수신 (from ${pkt.src}): 라우터를 찾는 호스트 → 곧바로 RA`, { from: pkt.src }, frame.id);
    if (sll && pkt.src !== UNSPECIFIED6) {
      this.learn(pkt.src, sll, false, "RS 의 출발지 링크 계층 주소 옵션에서 학습", frame.id, ctx);
      this.flushPending(pkt.src, ctx, emit);
    }
    this.sendRa(ctx, emit, false, frame.id);
  }

  private handleRa(pkt: Ipv6Packet, ra: RouterAdvertisement, frame: EthernetFrame, ctx: NodeContext, emit: Emit): void {
    const from = pkt.src;
    const summary = ra.routerLifetime === 0 ? "라우터 수명 0 (거둠)" : `프리픽스 ${ra.prefixes.filter((p) => p.valid > 0).map((p) => `${p.prefix}/${p.length}`).join(", ") || "없음"}${ra.rdnss?.length ? `, DNS ${ra.rdnss.join(", ")}` : ""}`;
    if (this.router) {
      ctx.trace("ndp.ra.received", "L3", `${this.tag}RA 수신 (from ${from}, ${summary}) — 라우터는 다른 라우터의 RA 로 주소·게이트웨이를 만들지 않음 → 무시`, { from }, frame.id);
      return;
    }
    if (!this.slaac) {
      ctx.trace("ndp.ra.received", "L3", `${this.tag}RA 수신 (from ${from}, ${summary}) — 수동 설정이라 주소·게이트웨이는 그대로 (자동(SLAAC)으로 두면 이 RA 로 주소를 만든다)`, { from }, frame.id);
      return;
    }
    if (!isLinkLocal6(from)) {
      ctx.trace("frame.drop", "L3", `${this.tag}RA 의 출발지 ${from} 가 링크 로컬이 아님 → RFC 4861 에 따라 무시`, { from }, frame.id);
      return;
    }
    ctx.trace("ndp.ra.received", "L3", `${this.tag}RA 수신: 라우터 ${from} — ${summary}`, { from, lifetime: ra.routerLifetime }, frame.id);
    this.rsTimer?.cancel();
    this.rsTimer = undefined;
    if (ra.sll) {
      this.learn(from, ra.sll, true, "RA 의 출발지 링크 계층 주소 옵션에서 학습", frame.id, ctx);
      this.flushPending(from, ctx, emit);
    }
    if (ra.routerLifetime > 0) {
      const known = this.routers.get(from);
      // 수명을 다시 잰다 (배경 타이머 — RA 가 이만큼 오지 않으면 뺀다). Map 의 순서는 그대로라 기본 게이트웨이는 바뀌지 않는다
      const token = ++this.routerToken;
      this.routers.set(from, { learnedAt: known?.learnedAt ?? ctx.now, lifetime: ra.routerLifetime, token });
      ctx.timer(ra.routerLifetime * 1000, ROUTER_EXPIRY_TAG, { mac: this.mac, router: from, token }, true);
      if (!known) {
        const first = this.routers.size === 1 && !this.gateway;
        ctx.trace("slaac.router", "L3", `${this.tag}기본 게이트웨이${first ? "" : " 후보"}: ${from} — RA 를 보낸 라우터의 링크 로컬 주소 (라우터 수명 ${ra.routerLifetime}초)`, { router: from, lifetime: ra.routerLifetime }, frame.id);
      } else if (known.suspect) {
        ctx.trace("slaac.router", "L3", `${this.tag}닿지 않던 기본 게이트웨이 후보 ${from} 의 RA 를 다시 받음 → 다시 믿는다`, { router: from, lifetime: ra.routerLifetime, restored: true }, frame.id);
      }
    } else if (this.routers.delete(from)) {
      ctx.trace("slaac.router", "L3", `${this.tag}${from} 가 라우터 수명 0 을 알림 → 기본 게이트웨이에서 뺌${this.routers.size ? ` (남은 라우터 ${[...this.routers.keys()].join(", ")})` : " (남은 라우터 없음 — 다른 네트워크로 못 나감)"}`, { router: from, removed: true }, frame.id);
    }
    for (const p of ra.prefixes) {
      if (!p.autonomous) continue;
      const existing = this.addrs.find((a) => a.origin === "slaac" && a.prefix === p.length && sameSubnet6(a.ip, p.prefix, p.length));
      const pkey = `${p.prefix}/${p.length}`;
      const by = this.prefixRouters.get(pkey) ?? new Set<Ip>();
      if (p.valid === 0) {
        by.delete(from);
        if (by.size > 0) {
          if (existing) ctx.trace("slaac.addr", "L3", `${this.tag}${from} 가 프리픽스 ${pkey} 를 거뒀지만 ${[...by].join(", ")} 가 아직 알리고 있음 → SLAAC 주소 ${existing.ip} 유지`, { ip: existing.ip, kept: true }, frame.id);
          continue;
        }
        this.prefixRouters.delete(pkey);
        if (existing) {
          this.removeAddr(existing);
          this.neighbors.clear();
          this.clearPending();
          ctx.trace("slaac.addr", "L3", `${this.tag}프리픽스 ${pkey} 를 라우터가 거둠 (유효 수명 0) → SLAAC 주소 ${existing.ip} 삭제`, { ip: existing.ip, removed: true }, frame.id);
          this.onAddrRemoved?.(existing.ip, ctx);
        }
        continue;
      }
      by.add(from);
      this.prefixRouters.set(pkey, by);
      if (p.length !== 64) {
        ctx.trace("slaac.addr", "L3", `${this.tag}프리픽스 ${p.prefix}/${p.length} 는 /64 가 아니라 SLAAC 주소를 만들 수 없음 (인터페이스 ID 가 64비트라 프리픽스는 /64 여야 한다)`, { prefix: p.prefix, length: p.length, bad: true }, frame.id);
        continue;
      }
      if (existing) continue;
      const ip = eui64Address(p.prefix, this.mac);
      if (this.addrs.some((a) => a.ip === ip)) continue;
      const addr: Addr6 = { ip, prefix: 64, origin: "slaac", state: "tentative" };
      this.addrs.push(addr);
      ctx.trace(
        "slaac.addr",
        "L3",
        `${this.tag}SLAAC: 프리픽스 ${p.prefix}/64 + 인터페이스 ID(MAC ${this.mac} 의 EUI-64) → ${ip} 생성 → DAD 로 확인 (실제 OS 는 개인정보 때문에 보통 무작위 인터페이스 ID)`,
        { ip, prefix: p.prefix },
        frame.id,
      );
      this.startDad(addr, ctx, emit);
    }
    const dns = ra.routerLifetime > 0 ? ra.rdnss?.[0] : undefined;
    if (dns && dns !== this.raDnsLearned) {
      this.raDnsLearned = dns;
      this.raDnsFrom = from;
      ctx.trace("slaac.router", "L3", `${this.tag}DNS 서버 ${dns} — RA 의 RDNSS 옵션 (DHCPv6 없이 DNS 를 알린다)`, { dns }, frame.id);
    } else if (!dns && this.raDnsLearned && this.raDnsFrom === from) {
      // 그 DNS 를 알려 준 라우터가 거두거나 DNS 없이 다시 알렸다
      ctx.trace("slaac.router", "L3", `${this.tag}${from} 의 RA 에 DNS(RDNSS)가 없음 → RA 로 받은 DNS 서버 ${this.raDnsLearned} 를 지움`, { dns: this.raDnsLearned, removed: true }, frame.id);
      this.raDnsLearned = undefined;
      this.raDnsFrom = undefined;
    }
  }

  /**
   * 이웃 캐시에 넣는다. confirmed = 요청한 NA (도달 확인). NUD 를 켰으면 RFC 4861 7.3.3 대로:
   * 확인이면 REACHABLE, 새 항목·MAC 이 바뀐 항목은 STALE, 같은 MAC 의 알림(NS·RA·요청하지 않은 NA)은 상태를 그대로 둔다
   */
  private learn(ip: Ip, mac: Mac, router: boolean, how: string, frameId: number, ctx: NodeContext, confirmed = false): void {
    if (ip === UNSPECIFIED6) return;
    const known = this.neighbors.get(ip);
    const isRouter = router || (known?.router ?? false);
    if (!this.nud) this.neighbors.set(ip, { mac, learnedAt: ctx.now, router: isRouter });
    else {
      const changed = !known || known.mac !== mac;
      const state: NudState = confirmed ? "REACHABLE" : changed ? "STALE" : (known!.state ?? "STALE");
      const was = known?.state;
      this.neighbors.set(ip, { mac, learnedAt: confirmed || changed ? ctx.now : known!.learnedAt, router: isRouter, state, probes: 0 });
      if (confirmed || changed) {
        this.nudTimers.get(ip)?.cancel();
        this.nudTimers.delete(ip);
      }
      // 요청한 NA 로 닿음을 확인한 라우터는 다시 믿는다
      const r = confirmed ? this.routers.get(ip) : undefined;
      if (r?.suspect) delete r.suspect;
      if (confirmed && (was === "DELAY" || was === "PROBE" || was === "STALE")) ctx.trace("ndp.nud", "L3", `${this.tag}이웃 ${ip} 도달 확인 (요청한 NA) → ${was} 에서 REACHABLE (${Ipv6Interface.REACHABLE_TIME / 1000}초)`, { ip, state: "REACHABLE", mac, ...(isRouter ? { router: true } : {}) }, frameId);
    }
    if (!known || known.mac !== mac) ctx.trace("ndp.cache.update", "L3", `${this.tag}이웃 캐시 ${known ? "갱신" : "추가"}: ${ip} → ${mac} (${how})`, { ip, mac, ...(this.nud ? { state: this.neighbors.get(ip)!.state } : {}) }, frameId);
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
    if (!queue) return [];
    if (this.neighbors.has(ip)) {
      // 다른 길(NS·RA)로 이미 배웠다 — 남은 대기열을 두면 다음 NS 가 막힌다
      this.pending.delete(ip);
      return [];
    }
    this.pending.delete(ip);
    ctx.trace("ndp.timeout", "L3", `${this.tag}NDP timeout: ${ip} 가 ${Ipv6Interface.NS_TIMEOUT}ms 동안 NA 로 응답하지 않음 → 대기 패킷 ${queue.length}개 드롭 (Address unreachable)`, { ip, dropped: queue.length });
    // 기본 게이트웨이 후보의 주소 해석 실패: 다음에는 다른 라우터를 먼저 (RFC 4861 6.3.6)
    if (this.routers.has(ip)) this.suspectRouter(ip, "NS 에 응답 없음", ctx);
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
    return this.addrs.map((a) => [`${a.ip}/${a.prefix}`, ORIGIN_LABEL[a.origin], STATE_LABEL[a.state]]);
  }

  neighborRows(now?: number): string[][] {
    return [...this.neighbors.entries()].map(([ip, n]) => {
      // NUD: REACHABLE 시간이 지났으면 STALE 로 보인다 (쓰기 전까지는 그대로 둔다)
      const state = n.state === "REACHABLE" && now !== undefined && now - n.learnedAt > Ipv6Interface.REACHABLE_TIME ? "STALE" : n.state;
      return [ip, n.mac, `${n.learnedAt}ms${n.router ? " · 라우터" : ""}${state ? ` · ${state}` : ""}`];
    });
  }
}
