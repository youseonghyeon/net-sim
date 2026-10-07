// DNS: 호스트 리졸버(질의·캐시)와 DNS 서버(레코드 응답, 모르는 이름은 업스트림 서버로 재귀 질의).
// 호스트의 서비스, 라우터의 포워더, 인터넷의 공인 DNS 가 같은 DnsServer 를 쓴다.
import type { Ip } from "../addr";
import { isIpv6 } from "../addr6";
import { DNS_PORT, type DnsMessage, type IpPacket, type Ipv4Packet } from "../packet";
import type { NetInterface, Emit } from "./iface";
import type { Ipv6Interface } from "./ipv6";
import type { NodeContext, TimerHandle } from "./node";

/** A = IPv4 주소, AAAA = IPv6 주소. 레코드 종류는 주소 모양으로 정한다 */
export type QType = "A" | "AAAA";

export function qtypeOf(ip: Ip): QType {
  return isIpv6(ip) ? "AAAA" : "A";
}

/** 캐시 키: A 는 이름 그대로 (예전과 같음), AAAA 는 뒤에 표시 */
/** 캐시 항목의 수명(ms): 응답의 TTL 과 캐시 기본값 중 짧은 것 */
function cacheLife(e: { ttl?: number }): number {
  return Math.min(e.ttl ?? DNS_CACHE_TTL, DNS_CACHE_TTL);
}

function cacheKey(name: string, qtype: QType): string {
  return qtype === "A" ? name : `${name} (AAAA)`;
}

/**
 * 실패의 성격: nodata = 이름은 있지만 그 종류의 레코드가 없음, retry = 서버에 닿지 못함·SERVFAIL·timeout (다른 종류로 다시 물어볼 만함).
 * 둘 다 없으면 없는 이름(NXDOMAIN)·설정 없음·취소 — 다시 물어도 소용없다
 */
export interface ResolveInfo {
  nodata?: boolean;
  retry?: boolean;
  /** 서버가 돌려준 실패 코드 (nslookup 출력용) */
  rcode?: "NXDOMAIN" | "SERVFAIL";
  /** 서버가 끝내 답하지 않음 */
  timeout?: boolean;
}

/** 리졸버 결과: 주소, 또는 실패 이유 */
export type ResolveDone = (ip: Ip | undefined, error?: string, info?: ResolveInfo) => void;

export interface DnsRecord {
  name: string;
  ip: Ip;
}

/** 리졸버가 한 번 묻고 기다리는 시간. 서버의 업스트림 질의 타임아웃(DNS_UPSTREAM_TIMEOUT)보다 길어야 SERVFAIL 이 제때 도착한다 */
export const DNS_TIMEOUT = 2000;
export const DNS_MAX_ATTEMPTS = 2;
export const DNS_UPSTREAM_TIMEOUT = 1500;
/** 캐시 유효 시간 */
export const DNS_CACHE_TTL = 60_000;
/** 재귀 질의가 서버들 사이를 이만큼 넘게 돌면 루프로 본다 */
export const DNS_MAX_HOPS = 4;
export const DNS_TIMER_TAG = "dns-timeout";
export const DNS_UPSTREAM_TIMER_TAG = "dns-upstream-timeout";

/** 인터넷 저편의 공개 이름들 (인터넷 노드의 공인 DNS 가 답한다) */
export const PUBLIC_ZONE: DnsRecord[] = [
  { name: "google.com", ip: "142.250.196.110" },
  { name: "example.com", ip: "93.184.216.34" },
  { name: "naver.com", ip: "223.130.200.104" },
  { name: "github.com", ip: "140.82.112.3" },
  { name: "cloudflare.com", ip: "104.16.132.229" },
];

/**
 * 공개 이름의 IPv6 주소 (AAAA). github.com·naver.com 은 실제로도 아직 AAAA 가 없어 NODATA — A 로 IPv4 에 간다
 */
export const PUBLIC_ZONE6: DnsRecord[] = [
  { name: "google.com", ip: "2404:6800:4004:827::200e" },
  { name: "example.com", ip: "2606:2800:21f:cb07:6820:80da:af6b:8b2c" },
  { name: "cloudflare.com", ip: "2606:4700::6810:84e5" },
];

export function normalizeName(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, "");
}

export function looksLikeName(s: string): boolean {
  return /[a-z]/i.test(s) && !/^\d+\.\d+\.\d+\.\d+$/.test(s) && !isIpv6(s);
}

interface PendingQuery {
  name: string;
  qtype: QType;
  /** 질의를 보낸 DNS 서버 */
  server: Ip;
  attempts: number;
  timer: TimerHandle;
  done: ResolveDone;
  /** VPN 이 알려 준 DNS 를 건너뛰고 원래 DNS 에 (VPN 서버 이름처럼 터널이 서기 전에 풀어야 하는 것) */
  direct?: boolean;
  /** nslookup 이 지정한 서버: 설정된 DNS 대신 이 서버에만 묻는다 */
  fixed?: Ip;
  /** nslookup: 답을 캐시에 넣지 않는다 */
  noStore?: boolean;
}

/** 호스트 쪽 리졸버: 설정된 DNS 서버에 묻고 결과를 캐시한다. DNS 서버는 IPv4 가 있으면 그쪽, 없으면 IPv6 DNS (질의 종류와 운반 버전은 따로 — AAAA 를 IPv4 로 물어도 된다) */
export class DnsResolver {
  readonly cache = new Map<string, { ip: Ip; at: number; ttl?: number }>();
  private readonly pending = new Map<number, PendingQuery>();
  private idSeq: number;
  /** 질의를 보내는 UDP 포트 (호스트마다 다름) */
  readonly port: number;

  /** DNS 서버가 내 주소일 때 질의를 직접 넘길 상대 (호스트가 DNS 서버 서비스를 켠 경우) */
  local: DnsServer | undefined;
  /** VPN 이 알려 준 DNS (연결된 동안 IPv4 DNS 보다 먼저 — L2TP/IPsec 의 IPCP DNS) */
  vpnDns: (() => Ip | undefined) | undefined;

  constructor(
    private readonly iface: NetInterface,
    seed: number,
    /** 호스트의 IPv6 (IPv6 DNS 서버에 묻거나 AAAA 를 물을 때) */
    private readonly v6?: Ipv6Interface,
  ) {
    this.idSeq = 0x100 + (Math.abs(seed) % 0x1000);
    this.port = 50000 + (Math.abs(seed) % 5000);
  }

  get server(): Ip | undefined {
    return this.pick()?.server ?? this.vpnDns?.() ?? this.iface.dns ?? this.v6?.effectiveDns;
  }

  /** 물어볼 DNS 서버와 내 출발지: IPv4 DNS 가 있고 내 IPv4 주소가 있으면 그쪽, 아니면 IPv6 DNS */
  private pick(direct = false, fixed?: Ip): { server: Ip; src: Ip } | undefined {
    if (fixed) {
      const src = isIpv6(fixed) ? this.v6?.sourceFor(fixed) : this.iface.ip;
      return src ? { server: fixed, src } : undefined;
    }
    const d4 = (direct ? undefined : this.vpnDns?.()) ?? this.iface.dns;
    if (d4 && this.iface.ip) return { server: d4, src: this.iface.ip };
    const d6 = this.v6?.effectiveDns;
    const src6 = d6 ? this.v6!.sourceFor(d6) : undefined;
    if (d6 && src6) return { server: d6, src: src6 };
    return undefined;
  }

  /** qtype = 물을 레코드 종류 (A: IPv4 주소, AAAA: IPv6 주소) */
  resolve(rawName: string, ctx: NodeContext, emit: Emit, done: ResolveDone, qtype: QType = "A", direct = false): void {
    const name = normalizeName(rawName);
    const key = cacheKey(name, qtype);
    const cached = this.cache.get(key);
    if (cached && ctx.now - cached.at <= cacheLife(cached)) {
      ctx.trace("dns.cache.hit", "app", `DNS 캐시 적중: ${name}${qtype === "AAAA" ? " AAAA" : ""} = ${cached.ip} (서버에 묻지 않음)`, { name, ip: cached.ip });
      done(cached.ip);
      return;
    }
    if (cached) this.cache.delete(key);
    this.start(name, qtype, ctx, emit, done, direct ? { direct } : {});
  }

  /**
   * nslookup: 캐시를 거치지 않고 매번 서버에 묻고, 답도 캐시에 넣지 않는다 (실제 nslookup·dig 처럼 OS 캐시와 따로).
   * server 를 주면 그 서버에만, 없으면 설정된 DNS 에. 돌려주는 값 = 물어본 서버 (못 물었으면 undefined)
   */
  lookup(rawName: string, qtype: QType, server: Ip | undefined, ctx: NodeContext, emit: Emit, done: ResolveDone): Ip | undefined {
    return this.start(normalizeName(rawName), qtype, ctx, emit, done, { noStore: true, ...(server ? { fixed: server } : {}) });
  }

  private start(name: string, qtype: QType, ctx: NodeContext, emit: Emit, done: ResolveDone, opts: Pick<PendingQuery, "direct" | "fixed" | "noStore">): Ip | undefined {
    const pick = this.pick(opts.direct, opts.fixed);
    if (!pick) {
      if (opts.fixed) {
        const v6 = isIpv6(opts.fixed);
        ctx.trace("dns.no-server", "app", `${name} 을(를) 서버 ${opts.fixed} 에 물을 수 없음: 내 ${v6 ? "IPv6 주소(그 서버로 갈 출발지)" : "IP 주소"}가 없음`, { name, server: opts.fixed });
        done(undefined, v6 ? "IPv6 주소 없음" : "IP 미설정");
      } else if (!this.iface.dns && !this.v6?.effectiveDns) {
        ctx.trace("dns.no-server", "app", `${name} 을(를) 찾을 수 없음: DNS 서버가 설정되지 않음 (수동이면 DNS 칸 입력, 자동이면 DHCP 서버가 DNS 를 안내하는지 확인)`, { name });
        done(undefined, "DNS 서버 없음");
      } else {
        ctx.trace("dns.no-server", "app", `${name} 을(를) 찾을 수 없음: 내 IP 주소가 없음`, { name });
        done(undefined, "IP 미설정");
      }
      return undefined;
    }
    const id = ++this.idSeq;
    const timer = ctx.timer(DNS_TIMEOUT, DNS_TIMER_TAG, { id });
    this.pending.set(id, { name, qtype, server: pick.server, attempts: 1, timer, done, ...opts });
    this.send(id, name, 1, ctx, emit);
    return pick.server;
  }

  private send(id: number, name: string, attempt: number, ctx: NodeContext, emit: Emit): void {
    const q = this.pending.get(id);
    const pick = this.pick(q?.direct, q?.fixed);
    if (!q || !pick) {
      this.fail(id, "DNS 설정이 사라짐", ctx);
      return;
    }
    q.server = pick.server;
    const server = pick.server;
    const qtype = q.qtype;
    const what = `"${name} 의 ${qtype === "AAAA" ? "IPv6 주소(AAAA)" : "주소"}는?"`;
    const v6 = isIpv6(server);
    if (server === this.iface.ip || (v6 && this.v6?.owns(server))) {
      // 내가 곧 DNS 서버: 네트워크로 나가지 않고 바로 묻는다 (루프백)
      const local = this.local;
      if (!local || !local.config.enabled) {
        ctx.trace("dns.no-server", "app", `DNS 서버가 내 주소(${server})인데 이 호스트의 DNS 서버 서비스가 꺼져 있음`, { name });
        this.fail(id, "내 DNS 서버 서비스 꺼짐", ctx);
        return;
      }
      ctx.trace("dns.query.sent", "app", `DNS 질의: ${what} → 내 DNS 서버 서비스 (루프백)`, { id, name, server, qtype });
      const m: DnsMessage = { kind: "dns", id, op: "query", name, ...(qtype === "AAAA" ? { qtype } : {}) };
      const pkt: IpPacket = v6
        ? { kind: "ipv6", src: pick.src, dst: server, hopLimit: 64, payload: { kind: "udp", srcPort: this.port, dstPort: DNS_PORT, payload: m } }
        : { kind: "ipv4", src: pick.src, dst: server, ttl: 64, payload: { kind: "udp", srcPort: this.port, dstPort: DNS_PORT, payload: m } };
      local.handle(pkt, this.port, m, -1, ctx, emit);
      return;
    }
    const msg: DnsMessage = { kind: "dns", id, op: "query", name, ...(qtype === "AAAA" ? { qtype } : {}) };
    // 질의 종류(A/AAAA)와 운반하는 IP 버전은 따로다: AAAA 를 IPv4 DNS 서버에 물어도 된다
    const carry = qtype === "AAAA" && !v6 ? " (IPv6 주소를 IPv4 로 묻는다 — 질의 종류와 운반 버전은 따로)" : qtype === "A" && v6 ? " (IPv4 주소를 IPv6 로 묻는다)" : "";
    ctx.trace("dns.query.sent", "app", `DNS 질의: ${what} → 서버 ${server}${carry}${attempt > 1 ? ` (재시도 ${attempt}/${DNS_MAX_ATTEMPTS})` : ""}`, { id, name, server, qtype });
    if (v6) this.v6!.send({ kind: "ipv6", src: pick.src, dst: server, hopLimit: 64, payload: { kind: "udp", srcPort: this.port, dstPort: DNS_PORT, payload: msg } }, ctx, emit);
    else this.iface.sendIp({ kind: "ipv4", src: pick.src, dst: server, ttl: 64, payload: { kind: "udp", srcPort: this.port, dstPort: DNS_PORT, payload: msg } }, ctx, emit);
  }

  handle(msg: DnsMessage, from: Ip, frameId: number, ctx: NodeContext): void {
    const q = this.pending.get(msg.id);
    if (!q || msg.op !== "response") {
      ctx.trace("dns.response.received", "app", `요청한 적 없는 DNS 응답 (id ${msg.id}) → 무시`, { id: msg.id }, frameId);
      return;
    }
    this.pending.delete(msg.id);
    q.timer.cancel();
    if (msg.answer) {
      if (!q.noStore) this.cache.set(cacheKey(q.name, q.qtype), { ip: msg.answer, at: ctx.now, ...(msg.ttl !== undefined ? { ttl: msg.ttl * 1000 } : {}) });
      ctx.trace("dns.response.received", "app", `DNS 응답: ${q.name}${q.qtype === "AAAA" ? " AAAA" : ""} = ${msg.answer} (서버 ${from}) → ${q.noStore ? "nslookup 이라 캐시에 넣지 않음" : "캐시에 저장"}`, { name: q.name, ip: msg.answer, qtype: q.qtype }, frameId);
      q.done(msg.answer);
      return;
    }
    if (msg.rcode === "NODATA") {
      ctx.trace("dns.response.received", "app", `DNS 응답: ${q.name} 은(는) 있는 이름이지만 ${q.qtype} 레코드가 없음 (NOERROR, 답 0개) — ${q.qtype === "AAAA" ? "IPv6 주소가 없는 이름" : "IPv4 주소가 없는 이름"}`, { name: q.name, qtype: q.qtype, nodata: true }, frameId);
      q.done(undefined, `${q.qtype} 레코드 없음`, { nodata: true });
      return;
    }
    ctx.trace("dns.nxdomain", "app", `DNS 응답: ${q.name} 은(는) 없는 이름 (${msg.rcode ?? "NXDOMAIN"}) — 서버 ${from} 가 모르는 이름`, { name: q.name, rcode: msg.rcode }, frameId);
    if (msg.rcode === "SERVFAIL") q.done(undefined, "DNS 서버가 업스트림 서버 응답을 받지 못함", { retry: true, rcode: "SERVFAIL" });
    else q.done(undefined, "없는 이름", { rcode: "NXDOMAIN" });
  }

  onTimeout(data: unknown, ctx: NodeContext, emit: Emit): void {
    const { id } = data as { id: number };
    const q = this.pending.get(id);
    if (!q) return;
    if (q.attempts < DNS_MAX_ATTEMPTS) {
      q.attempts += 1;
      q.timer = ctx.timer(DNS_TIMEOUT, DNS_TIMER_TAG, { id });
      ctx.trace("dns.timeout", "app", `DNS timeout: ${DNS_TIMEOUT}ms 동안 응답 없음 → 재시도`, { id, name: q.name });
      this.send(id, q.name, q.attempts, ctx, emit);
      return;
    }
    this.pending.delete(id);
    ctx.trace("dns.timeout", "app", `DNS timeout: 서버 ${q.server} 가 ${DNS_MAX_ATTEMPTS}번 물어도 응답 없음 → ${q.name} 해석 실패 (서버 주소·경로 확인)`, { id, name: q.name });
    q.done(undefined, "DNS timeout · 응답 없음", { retry: true, timeout: true });
  }

  /**
   * DNS 서버에 닿지 않는다는 ICMP Destination Unreachable: 그 서버(server = ICMP 에 담긴 원래 목적지)로 보낸 질의만 바로 실패로.
   * nslookup 이 다른 서버를 지정할 수 있어, 한 서버의 Unreachable 이 다른 서버를 기다리는 질의까지 끝내면 안 된다
   */
  onUnreachable(reason: string, ctx: NodeContext, server: Ip): boolean {
    const ids = [...this.pending.entries()].filter(([, q]) => q.server === server).map(([id]) => id);
    for (const id of ids) this.fail(id, reason, ctx, true);
    return ids.length > 0;
  }

  private fail(id: number, reason: string, ctx: NodeContext, retry = false): void {
    const q = this.pending.get(id);
    if (!q) return;
    this.pending.delete(id);
    q.timer.cancel();
    ctx.trace("dns.timeout", "app", `${q.name} 해석 중단: ${reason}`, { name: q.name });
    q.done(undefined, reason, retry ? { retry: true } : undefined);
  }

  /** 이 이름의 캐시를 지운다 (바뀐 주소를 다시 받으려고 — DDNS 이름을 다시 풀 때) */
  forget(rawName: string): void {
    const name = normalizeName(rawName);
    this.cache.delete(cacheKey(name, "A"));
    this.cache.delete(cacheKey(name, "AAAA"));
  }

  /** 링크 끊김·설정 변경: 대기 중인 질의는 실패(취소)로 끝내고 캐시를 비운다. 콜백이 새 질의를 걸어도 함께 지워지지 않게 목록을 먼저 떼어 낸다 */
  clear(reason = "취소됨"): void {
    const list = [...this.pending.values()];
    this.pending.clear();
    this.cache.clear();
    for (const q of list) {
      q.timer.cancel();
      q.done(undefined, reason);
    }
  }

  rows(): string[][] {
    return [...this.cache.entries()].map(([name, e]) => [name, e.ip, `${e.at}ms`]);
  }
}

// ---------- 서버 ----------

export interface DnsServerConfig {
  enabled: boolean;
  records: DnsRecord[];
  /** 모르는 이름을 물어볼 업스트림 DNS (재귀 질의). 비우면 NXDOMAIN */
  upstream?: Ip;
}

interface PendingUpstream {
  /** 클라이언트가 질의를 보낸 주소가 인터페이스 주소가 아니면 그 주소 (거기서 답한다) */
  replyFrom?: Ip;
  clientIp: Ip;
  clientPort: number;
  clientId: number;
  name: string;
  qtype: QType;
  timer: TimerHandle;
}

export class DnsServer {
  /** 업스트림 서버에서 받아 둔 답 */
  readonly cache = new Map<string, { ip: Ip; at: number; ttl?: number }>();
  private readonly pendingUpstream = new Map<number, PendingUpstream>();
  private idSeq = 0x7000;
  /** 지금 물어볼 업스트림을 바꿔야 할 때 (공유기 VPN 클라이언트가 연결되면 VPN 의 DNS — DNS 유출 방지). 없거나 undefined 면 설정값 */
  upstreamFor: ((client: Ip) => Ip | undefined) | undefined;
  /** 질의를 받은 주소가 이 인터페이스 주소가 아니어도 그 주소로 답해야 할 때 (VPN 터널 주소로 온 질의, DNS 가로채기) */
  answersAt: ((dst: Ip) => boolean) | undefined;
  /**
   * 질의 필터 (AdGuard Home·자녀 보호): 막으면 답할 내용(0.0.0.0·:: 또는 NXDOMAIN)과 이유. 내 레코드·캐시보다 먼저 본다.
   * 질의마다 (막았든 아니든) note 로 알린다 — 쿼리 로그
   */
  filter: ((name: string, qtype: QType, client: Ip, ctx: NodeContext) => { answer?: Ip; rcode?: "NXDOMAIN"; why: string } | undefined) | undefined;
  /** 클라이언트에게 이름의 주소를 답할 때 (DPI 가 "그 주소 = 그 앱" 을 배운다) */
  onAnswer: ((name: string, ip: Ip) => void) | undefined;

  constructor(
    public config: DnsServerConfig,
    private readonly iface: NetInterface,
    /** 로그 문구 앞에 붙는 역할 이름 (예: "공인 DNS") */
    private readonly label = "DNS 서버",
    /** 업스트림 질의를 다른 인터페이스로 내보내야 할 때 (라우터: WAN). 없으면 iface 로 보낸다 */
    /** client = 질의를 보낸 기기 (공유기 VPN 정책처럼 기기마다 다른 길로 물을 때) */
    private readonly upstreamPath?: { srcIp: (client?: Ip) => Ip | undefined; send: (pkt: Ipv4Packet, ctx: NodeContext, client?: Ip) => void },
    /** 이 서버 호스트의 IPv6 (IPv6 로 온 질의에 답하고, IPv6 업스트림에 묻는다) */
    private readonly v6?: Ipv6Interface,
  ) {}

  lookup(rawName: string, now?: number, qtype: QType = "A"): Ip | undefined {
    const name = normalizeName(rawName);
    const rec = this.config.records.find((r) => normalizeName(r.name) === name && qtypeOf(r.ip) === qtype)?.ip;
    if (rec) return rec;
    const key = cacheKey(name, qtype);
    const c = this.cache.get(key);
    if (c && (now === undefined || now - c.at <= cacheLife(c))) return c.ip;
    if (c) this.cache.delete(key);
    return undefined;
  }

  /** UDP 53 으로 온 메시지 처리 (질의 또는 업스트림 서버의 응답) */
  handle(pkt: IpPacket, srcPort: number, msg: DnsMessage, frameId: number, ctx: NodeContext, emit: Emit): void {
    if (msg.op === "response") {
      this.handleUpstreamResponse(pkt, msg, frameId, ctx, emit);
      return;
    }
    const name = normalizeName(msg.name);
    const qtype: QType = msg.qtype ?? "A";
    const tq = qtype === "AAAA" ? " AAAA" : "";
    ctx.trace("dns.query.received", "app", `${this.label}: 질의 수신 "${name}${tq}?" (from ${pkt.src})`, { name, from: pkt.src, qtype }, frameId);
    if (!this.config.enabled) {
      ctx.trace("dns.nxdomain", "app", `${this.label} 가 꺼져 있음 → 응답하지 않음`, { name }, frameId);
      return;
    }
    const replyFrom = pkt.dst !== this.iface.ip && !this.v6?.owns(pkt.dst) && this.answersAt?.(pkt.dst) ? pkt.dst : undefined;
    const answer = (m: Omit<DnsMessage, "kind" | "id" | "op" | "name">): DnsMessage => ({ kind: "dns", id: msg.id, op: "response", name: msg.name, ...(qtype === "AAAA" ? { qtype } : {}), ...m });
    const blocked = this.filter?.(name, qtype, pkt.src, ctx);
    if (blocked) {
      ctx.trace("dns.blocked", "app", `${this.label}: ${name}${tq} 은(는) ${blocked.why} → 업스트림에 묻지 않고 ${blocked.answer ?? blocked.rcode} 로 답함 → ${pkt.src}`, { name, to: pkt.src, qtype, blocked: true }, frameId);
      this.respond(pkt.src, srcPort, answer(blocked.answer ? { answer: blocked.answer } : { rcode: blocked.rcode ?? "NXDOMAIN" }), ctx, emit, replyFrom);
      return;
    }
    const ip = this.lookup(name, ctx.now, qtype);
    if (ip) {
      const fromCache = !this.config.records.some((r) => normalizeName(r.name) === name && qtypeOf(r.ip) === qtype);
      // 캐시한 답에 TTL 이 있었으면 남은 만큼만 알려 준다 (DDNS 이름처럼 짧은 TTL 이 아래 캐시까지 이어지게)
      const ce = fromCache ? this.cache.get(cacheKey(name, qtype)) : undefined;
      const ttl = ce?.ttl !== undefined ? Math.max(1, Math.round((ce.ttl - (ctx.now - ce.at)) / 1000)) : undefined;
      this.onAnswer?.(name, ip);
      ctx.trace("dns.response.sent", "app", `${this.label}: ${name}${tq} = ${ip} 응답 (${fromCache ? "업스트림 서버 답 캐시" : "내 레코드"}) → ${pkt.src}`, { name, ip, to: pkt.src, qtype });
      this.respond(pkt.src, srcPort, answer({ answer: ip, ...(ttl !== undefined ? { ttl } : {}) }), ctx, emit, replyFrom);
      return;
    }
    // 내 레코드에 이름은 있는데 그 종류가 없다: 이 이름의 주인이므로 업스트림에 묻지 않고 "없음(NODATA)"
    if (this.config.records.some((r) => normalizeName(r.name) === name)) {
      ctx.trace("dns.response.sent", "app", `${this.label}: ${name} 은(는) 내 레코드에 있지만 ${qtype} 레코드는 없음 → NOERROR, 답 0개 (NODATA) 응답 → ${pkt.src}`, { name, to: pkt.src, qtype, nodata: true });
      this.respond(pkt.src, srcPort, answer({ rcode: "NODATA" }), ctx, emit, replyFrom);
      return;
    }
    const hops = msg.hops ?? 0;
    const up = this.upstreamFor?.(pkt.src) ?? this.config.upstream;
    const upIsMe = !!up && (up === this.iface.ip || !!this.v6?.owns(up));
    if (up && !upIsMe && hops >= DNS_MAX_HOPS) {
      ctx.trace("dns.timeout", "app", `${this.label}: ${name} 질의가 서버 ${DNS_MAX_HOPS}대를 넘게 돌았음 → 서버들이 서로를 업스트림으로 가리키는 루프로 보고 SERVFAIL`, { name, hops });
      this.respond(pkt.src, srcPort, answer({ rcode: "SERVFAIL" }), ctx, emit, replyFrom);
      return;
    }
    if (up && !upIsMe) {
      const id = ++this.idSeq;
      const timer = ctx.timer(DNS_UPSTREAM_TIMEOUT, DNS_UPSTREAM_TIMER_TAG, { id });
      this.pendingUpstream.set(id, { ...(replyFrom ? { replyFrom } : {}), clientIp: pkt.src, clientPort: srcPort, clientId: msg.id, name, qtype, timer });
      ctx.trace("dns.forward", "app", `${this.label}: ${name}${tq} 은(는) 내 레코드에 없음 → 업스트림 DNS ${up} 에 대신 물어봄 (재귀 질의)`, { name, upstream: up });
      const up6 = isIpv6(up);
      const src = up6 ? this.v6?.sourceFor(up) : (this.upstreamPath?.srcIp(pkt.src) ?? this.iface.ip);
      if (!src) {
        ctx.trace("dns.timeout", "app", `${this.label}: 업스트림 DNS 에 물어볼 인터페이스에 주소가 없음 → SERVFAIL`, { name });
        this.pendingUpstream.delete(id);
        timer.cancel();
        this.respond(pkt.src, srcPort, answer({ rcode: "SERVFAIL" }), ctx, emit, replyFrom);
        return;
      }
      const m: DnsMessage = { kind: "dns", id, op: "query", name, ...(qtype === "AAAA" ? { qtype } : {}), hops: hops + 1 };
      if (up6) {
        this.v6!.send({ kind: "ipv6", src, dst: up, hopLimit: 64, payload: { kind: "udp", srcPort: DNS_PORT, dstPort: DNS_PORT, payload: m } }, ctx, emit);
        return;
      }
      const q: Ipv4Packet = { kind: "ipv4", src, dst: up, ttl: 64, payload: { kind: "udp", srcPort: DNS_PORT, dstPort: DNS_PORT, payload: m } };
      if (this.upstreamPath) this.upstreamPath.send(q, ctx, pkt.src);
      else this.iface.sendIp(q, ctx, emit);
      return;
    }
    ctx.trace("dns.nxdomain", "app", `${this.label}: ${name} 은(는) 내 레코드에 없고 업스트림 DNS 도 없음 → NXDOMAIN 응답`, { name });
    this.respond(pkt.src, srcPort, answer({ rcode: "NXDOMAIN" }), ctx, emit, replyFrom);
  }

  private handleUpstreamResponse(pkt: IpPacket, msg: DnsMessage, frameId: number, ctx: NodeContext, emit: Emit): void {
    const p = this.pendingUpstream.get(msg.id);
    if (!p) {
      ctx.trace("dns.response.received", "app", `${this.label}: 요청한 적 없는 업스트림 DNS 응답 (id ${msg.id}) → 무시`, { id: msg.id }, frameId);
      return;
    }
    this.pendingUpstream.delete(msg.id);
    p.timer.cancel();
    const tq = p.qtype === "AAAA" ? " AAAA" : "";
    if (msg.answer) {
      this.onAnswer?.(p.name, msg.answer);
      this.cache.set(cacheKey(p.name, p.qtype), { ip: msg.answer, at: ctx.now, ...(msg.ttl !== undefined ? { ttl: msg.ttl * 1000 } : {}) });
      ctx.trace("dns.response.received", "app", `${this.label}: 업스트림 DNS ${pkt.src} 의 답 ${p.name}${tq} = ${msg.answer} → 캐시`, { name: p.name, ip: msg.answer }, frameId);
      ctx.trace("dns.response.sent", "app", `${this.label}: ${p.name}${tq} = ${msg.answer} 응답 (업스트림 서버 답 전달) → ${p.clientIp}`, { name: p.name, ip: msg.answer, to: p.clientIp });
    } else if (msg.rcode === "NODATA") {
      ctx.trace("dns.response.received", "app", `${this.label}: 업스트림 DNS 의 답 — ${p.name} 은(는) ${p.qtype} 레코드가 없음 (NODATA) → 클라이언트 ${p.clientIp} 에게 그대로 전달`, { name: p.name, nodata: true }, frameId);
    } else {
      ctx.trace("dns.nxdomain", "app", `${this.label}: 업스트림 DNS 도 ${p.name} 을(를) 모름 (${msg.rcode ?? "NXDOMAIN"}) → 클라이언트 ${p.clientIp} 에게 그대로 전달`, { name: p.name }, frameId);
    }
    this.respond(p.clientIp, p.clientPort, { kind: "dns", id: p.clientId, op: "response", name: p.name, ...(p.qtype === "AAAA" ? { qtype: p.qtype } : {}), answer: msg.answer, rcode: msg.rcode, ...(msg.ttl !== undefined ? { ttl: msg.ttl } : {}) }, ctx, emit, p.replyFrom);
  }

  onTimeout(data: unknown, ctx: NodeContext, emit: Emit): void {
    const { id } = data as { id: number };
    const p = this.pendingUpstream.get(id);
    if (!p) return;
    this.pendingUpstream.delete(id);
    ctx.trace("dns.timeout", "app", `${this.label}: 업스트림 DNS ${this.upstreamFor?.(p.clientIp) ?? this.config.upstream} timeout (응답 없음) → 클라이언트에게 SERVFAIL`, { name: p.name });
    this.respond(p.clientIp, p.clientPort, { kind: "dns", id: p.clientId, op: "response", name: p.name, ...(p.qtype === "AAAA" ? { qtype: p.qtype } : {}), rcode: "SERVFAIL" }, ctx, emit, p.replyFrom);
  }

  /** 질의가 온 IP 버전으로 답한다 */
  /** 답을 다른 인터페이스로 보내야 할 때 (공유기 드롭인: WAN 쪽 기기의 질의). 보냈으면 true */
  replyVia: ((pkt: Ipv4Packet, ctx: NodeContext) => boolean) | undefined;

  private respond(to: Ip, toPort: number, msg: DnsMessage, ctx: NodeContext, emit: Emit, from?: Ip): void {
    if (isIpv6(to)) {
      const src = from ?? this.v6?.sourceFor(to);
      if (!src) return;
      this.v6!.send({ kind: "ipv6", src, dst: to, hopLimit: 64, payload: { kind: "udp", srcPort: DNS_PORT, dstPort: toPort, payload: msg } }, ctx, emit);
      return;
    }
    const pkt: Ipv4Packet = { kind: "ipv4", src: from ?? this.iface.ip!, dst: to, ttl: 64, payload: { kind: "udp", srcPort: DNS_PORT, dstPort: toPort, payload: msg } };
    if (this.replyVia?.(pkt, ctx)) return;
    this.iface.sendIp(pkt, ctx, emit);
  }

  rows(): string[][] {
    return [...this.config.records.map((r) => [r.name, r.ip, `레코드 ${qtypeOf(r.ip)}`]), ...[...this.cache.entries()].map(([n, e]) => [n, e.ip, `캐시 ${e.at}ms`])];
  }
}
