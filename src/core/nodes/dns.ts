// DNS: 호스트 리졸버(질의·캐시)와 DNS 서버(레코드 응답, 모르는 이름은 업스트림 서버로 재귀 질의).
// 호스트의 서비스, 라우터의 포워더, 인터넷의 공인 DNS 가 같은 DnsServer 를 쓴다.
import type { Ip } from "../addr";
import { DNS_PORT, type DnsMessage, type Ipv4Packet } from "../packet";
import type { NetInterface, Emit } from "./iface";
import type { NodeContext, TimerHandle } from "./node";

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

export function normalizeName(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, "");
}

export function looksLikeName(s: string): boolean {
  return /[a-z]/i.test(s) && !/^\d+\.\d+\.\d+\.\d+$/.test(s);
}

interface PendingQuery {
  name: string;
  attempts: number;
  timer: TimerHandle;
  done: (ip: Ip | undefined, error?: string) => void;
}

/** 호스트 쪽 리졸버: 설정된 DNS 서버에 묻고 결과를 캐시한다 */
export class DnsResolver {
  readonly cache = new Map<string, { ip: Ip; at: number }>();
  private readonly pending = new Map<number, PendingQuery>();
  private idSeq: number;
  /** 질의를 보내는 UDP 포트 (호스트마다 다름) */
  readonly port: number;

  /** DNS 서버가 내 주소일 때 질의를 직접 넘길 상대 (호스트가 DNS 서버 서비스를 켠 경우) */
  local: DnsServer | undefined;

  constructor(
    private readonly iface: NetInterface,
    seed: number,
  ) {
    this.idSeq = 0x100 + (Math.abs(seed) % 0x1000);
    this.port = 50000 + (Math.abs(seed) % 5000);
  }

  get server(): Ip | undefined {
    return this.iface.dns;
  }

  resolve(rawName: string, ctx: NodeContext, emit: Emit, done: (ip: Ip | undefined, error?: string) => void): void {
    const name = normalizeName(rawName);
    const cached = this.cache.get(name);
    if (cached && ctx.now - cached.at <= DNS_CACHE_TTL) {
      ctx.trace("dns.cache.hit", "app", `DNS 캐시 적중: ${name} = ${cached.ip} (서버에 묻지 않음)`, { name, ip: cached.ip });
      done(cached.ip);
      return;
    }
    if (cached) this.cache.delete(name);
    const server = this.iface.dns;
    if (!server) {
      ctx.trace("dns.no-server", "app", `${name} 을(를) 찾을 수 없음: DNS 서버가 설정되지 않음 (수동이면 DNS 칸 입력, 자동이면 DHCP 서버가 DNS 를 안내하는지 확인)`, { name });
      done(undefined, "DNS 서버 없음");
      return;
    }
    if (!this.iface.ip) {
      ctx.trace("dns.no-server", "app", `${name} 을(를) 찾을 수 없음: 내 IP 주소가 없음`, { name });
      done(undefined, "IP 미설정");
      return;
    }
    const id = ++this.idSeq;
    const timer = ctx.timer(DNS_TIMEOUT, DNS_TIMER_TAG, { id });
    this.pending.set(id, { name, attempts: 1, timer, done });
    this.send(id, name, 1, ctx, emit);
  }

  private send(id: number, name: string, attempt: number, ctx: NodeContext, emit: Emit): void {
    const server = this.iface.dns;
    if (!server || !this.iface.ip) {
      this.fail(id, "DNS 설정이 사라짐", ctx);
      return;
    }
    if (server === this.iface.ip) {
      // 내가 곧 DNS 서버: 네트워크로 나가지 않고 바로 묻는다 (루프백)
      const local = this.local;
      if (!local || !local.config.enabled) {
        ctx.trace("dns.no-server", "app", `DNS 서버가 내 주소(${server})인데 이 호스트의 DNS 서버 서비스가 꺼져 있음`, { name });
        this.fail(id, "내 DNS 서버 서비스 꺼짐", ctx);
        return;
      }
      ctx.trace("dns.query.sent", "app", `DNS 질의: "${name} 의 주소는?" → 내 DNS 서버 서비스 (루프백)`, { id, name, server });
      const q: DnsMessage = { kind: "dns", id, op: "query", name };
      const pkt: Ipv4Packet = { kind: "ipv4", src: this.iface.ip, dst: server, ttl: 64, payload: { kind: "udp", srcPort: this.port, dstPort: DNS_PORT, payload: q } };
      local.handle(pkt, this.port, q, -1, ctx, emit);
      return;
    }
    const msg: DnsMessage = { kind: "dns", id, op: "query", name };
    ctx.trace("dns.query.sent", "app", `DNS 질의: "${name} 의 주소는?" → 서버 ${server}${attempt > 1 ? ` (재시도 ${attempt}/${DNS_MAX_ATTEMPTS})` : ""}`, { id, name, server });
    const pkt: Ipv4Packet = { kind: "ipv4", src: this.iface.ip!, dst: server, ttl: 64, payload: { kind: "udp", srcPort: this.port, dstPort: DNS_PORT, payload: msg } };
    this.iface.sendIp(pkt, ctx, emit);
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
      this.cache.set(q.name, { ip: msg.answer, at: ctx.now });
      ctx.trace("dns.response.received", "app", `DNS 응답: ${q.name} = ${msg.answer} (서버 ${from}) → 캐시에 저장`, { name: q.name, ip: msg.answer }, frameId);
      q.done(msg.answer);
      return;
    }
    ctx.trace("dns.nxdomain", "app", `DNS 응답: ${q.name} 은(는) 없는 이름 (${msg.rcode ?? "NXDOMAIN"}) — 서버 ${from} 가 모르는 이름`, { name: q.name, rcode: msg.rcode }, frameId);
    q.done(undefined, msg.rcode === "SERVFAIL" ? "DNS 서버가 업스트림 서버 응답을 받지 못함" : "없는 이름");
  }

  onTimeout(data: unknown, ctx: NodeContext, emit: Emit): void {
    const { id } = data as { id: number };
    const q = this.pending.get(id);
    if (!q) return;
    if (q.attempts < DNS_MAX_ATTEMPTS) {
      q.attempts += 1;
      q.timer = ctx.timer(DNS_TIMEOUT, DNS_TIMER_TAG, { id });
      ctx.trace("dns.timeout", "app", `DNS 응답 없음 (${DNS_TIMEOUT}ms) → 재시도`, { id, name: q.name });
      this.send(id, q.name, q.attempts, ctx, emit);
      return;
    }
    this.pending.delete(id);
    ctx.trace("dns.timeout", "app", `DNS 실패: 서버 ${this.iface.dns} 가 ${DNS_MAX_ATTEMPTS}번 물어도 응답 없음 → ${q.name} 해석 실패 (서버 주소·경로 확인)`, { id, name: q.name });
    q.done(undefined, "DNS 응답 없음");
  }

  private fail(id: number, reason: string, ctx: NodeContext): void {
    const q = this.pending.get(id);
    if (!q) return;
    this.pending.delete(id);
    q.timer.cancel();
    ctx.trace("dns.timeout", "app", `${q.name} 해석 중단: ${reason}`, { name: q.name });
    q.done(undefined, reason);
  }

  /** 링크 끊김·설정 변경: 대기 중인 질의는 실패로 끝내고 캐시를 비운다 */
  clear(reason = "취소됨"): void {
    for (const q of this.pending.values()) {
      q.timer.cancel();
      q.done(undefined, reason);
    }
    this.pending.clear();
    this.cache.clear();
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
  clientIp: Ip;
  clientPort: number;
  clientId: number;
  name: string;
  timer: TimerHandle;
}

export class DnsServer {
  /** 업스트림 서버에서 받아 둔 답 */
  readonly cache = new Map<string, { ip: Ip; at: number }>();
  private readonly pendingUpstream = new Map<number, PendingUpstream>();
  private idSeq = 0x7000;

  constructor(
    public config: DnsServerConfig,
    private readonly iface: NetInterface,
    /** 로그 문구 앞에 붙는 역할 이름 (예: "공인 DNS") */
    private readonly label = "DNS 서버",
    /** 업스트림 질의를 다른 인터페이스로 내보내야 할 때 (라우터: WAN). 없으면 iface 로 보낸다 */
    private readonly upstreamPath?: { srcIp: () => Ip | undefined; send: (pkt: Ipv4Packet, ctx: NodeContext) => void },
  ) {}

  lookup(rawName: string, now?: number): Ip | undefined {
    const name = normalizeName(rawName);
    const rec = this.config.records.find((r) => normalizeName(r.name) === name)?.ip;
    if (rec) return rec;
    const c = this.cache.get(name);
    if (c && (now === undefined || now - c.at <= DNS_CACHE_TTL)) return c.ip;
    if (c) this.cache.delete(name);
    return undefined;
  }

  /** UDP 53 으로 온 메시지 처리 (질의 또는 업스트림 서버의 응답) */
  handle(pkt: Ipv4Packet, srcPort: number, msg: DnsMessage, frameId: number, ctx: NodeContext, emit: Emit): void {
    if (msg.op === "response") {
      this.handleUpstreamResponse(pkt, msg, frameId, ctx, emit);
      return;
    }
    const name = normalizeName(msg.name);
    ctx.trace("dns.query.received", "app", `${this.label}: 질의 수신 "${name}?" (from ${pkt.src})`, { name, from: pkt.src }, frameId);
    if (!this.config.enabled) {
      ctx.trace("dns.nxdomain", "app", `${this.label} 가 꺼져 있음 → 응답하지 않음`, { name }, frameId);
      return;
    }
    const ip = this.lookup(name, ctx.now);
    if (ip) {
      const fromCache = !this.config.records.some((r) => normalizeName(r.name) === name);
      ctx.trace("dns.response.sent", "app", `${this.label}: ${name} = ${ip} 응답 (${fromCache ? "업스트림 서버 답 캐시" : "내 레코드"}) → ${pkt.src}`, { name, ip, to: pkt.src });
      this.respond(pkt.src, srcPort, { kind: "dns", id: msg.id, op: "response", name: msg.name, answer: ip }, ctx, emit);
      return;
    }
    const hops = msg.hops ?? 0;
    if (this.config.upstream && this.config.upstream !== this.iface.ip && hops >= DNS_MAX_HOPS) {
      ctx.trace("dns.timeout", "app", `${this.label}: ${name} 질의가 서버 ${DNS_MAX_HOPS}대를 넘게 돌았음 → 서버들이 서로를 업스트림으로 가리키는 루프로 보고 SERVFAIL`, { name, hops });
      this.respond(pkt.src, srcPort, { kind: "dns", id: msg.id, op: "response", name: msg.name, rcode: "SERVFAIL" }, ctx, emit);
      return;
    }
    if (this.config.upstream && this.config.upstream !== this.iface.ip) {
      const id = ++this.idSeq;
      const timer = ctx.timer(DNS_UPSTREAM_TIMEOUT, DNS_UPSTREAM_TIMER_TAG, { id });
      this.pendingUpstream.set(id, { clientIp: pkt.src, clientPort: srcPort, clientId: msg.id, name, timer });
      ctx.trace("dns.forward", "app", `${this.label}: ${name} 은(는) 내 레코드에 없음 → 업스트림 DNS ${this.config.upstream} 에 대신 물어봄 (재귀 질의)`, { name, upstream: this.config.upstream });
      const src = this.upstreamPath?.srcIp() ?? this.iface.ip;
      if (!src) {
        ctx.trace("dns.timeout", "app", `${this.label}: 업스트림 DNS 에 물어볼 인터페이스에 주소가 없음 → SERVFAIL`, { name });
        this.pendingUpstream.delete(id);
        timer.cancel();
        this.respond(pkt.src, srcPort, { kind: "dns", id: msg.id, op: "response", name: msg.name, rcode: "SERVFAIL" }, ctx, emit);
        return;
      }
      const q: Ipv4Packet = { kind: "ipv4", src, dst: this.config.upstream, ttl: 64, payload: { kind: "udp", srcPort: DNS_PORT, dstPort: DNS_PORT, payload: { kind: "dns", id, op: "query", name, hops: hops + 1 } } };
      if (this.upstreamPath) this.upstreamPath.send(q, ctx);
      else this.iface.sendIp(q, ctx, emit);
      return;
    }
    ctx.trace("dns.nxdomain", "app", `${this.label}: ${name} 은(는) 내 레코드에 없고 업스트림 DNS 도 없음 → NXDOMAIN 응답`, { name });
    this.respond(pkt.src, srcPort, { kind: "dns", id: msg.id, op: "response", name: msg.name, rcode: "NXDOMAIN" }, ctx, emit);
  }

  private handleUpstreamResponse(pkt: Ipv4Packet, msg: DnsMessage, frameId: number, ctx: NodeContext, emit: Emit): void {
    const p = this.pendingUpstream.get(msg.id);
    if (!p) {
      ctx.trace("dns.response.received", "app", `${this.label}: 요청한 적 없는 업스트림 DNS 응답 (id ${msg.id}) → 무시`, { id: msg.id }, frameId);
      return;
    }
    this.pendingUpstream.delete(msg.id);
    p.timer.cancel();
    if (msg.answer) {
      this.cache.set(p.name, { ip: msg.answer, at: ctx.now });
      ctx.trace("dns.response.received", "app", `${this.label}: 업스트림 DNS ${pkt.src} 의 답 ${p.name} = ${msg.answer} → 캐시`, { name: p.name, ip: msg.answer }, frameId);
      ctx.trace("dns.response.sent", "app", `${this.label}: ${p.name} = ${msg.answer} 응답 (업스트림 서버 답 전달) → ${p.clientIp}`, { name: p.name, ip: msg.answer, to: p.clientIp });
    } else {
      ctx.trace("dns.nxdomain", "app", `${this.label}: 업스트림 DNS 도 ${p.name} 을(를) 모름 (${msg.rcode ?? "NXDOMAIN"}) → 클라이언트 ${p.clientIp} 에게 그대로 전달`, { name: p.name }, frameId);
    }
    this.respond(p.clientIp, p.clientPort, { kind: "dns", id: p.clientId, op: "response", name: p.name, answer: msg.answer, rcode: msg.rcode }, ctx, emit);
  }

  onTimeout(data: unknown, ctx: NodeContext, emit: Emit): void {
    const { id } = data as { id: number };
    const p = this.pendingUpstream.get(id);
    if (!p) return;
    this.pendingUpstream.delete(id);
    ctx.trace("dns.timeout", "app", `${this.label}: 업스트림 DNS ${this.config.upstream} 응답 없음 → 클라이언트에게 SERVFAIL`, { name: p.name });
    this.respond(p.clientIp, p.clientPort, { kind: "dns", id: p.clientId, op: "response", name: p.name, rcode: "SERVFAIL" }, ctx, emit);
  }

  private respond(to: Ip, toPort: number, msg: DnsMessage, ctx: NodeContext, emit: Emit): void {
    const pkt: Ipv4Packet = { kind: "ipv4", src: this.iface.ip!, dst: to, ttl: 64, payload: { kind: "udp", srcPort: DNS_PORT, dstPort: toPort, payload: msg } };
    this.iface.sendIp(pkt, ctx, emit);
  }

  rows(): string[][] {
    return [...this.config.records.map((r) => [r.name, r.ip, "레코드"]), ...[...this.cache.entries()].map(([n, e]) => [n, e.ip, `캐시 ${e.at}ms`])];
  }
}
