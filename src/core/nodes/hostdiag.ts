// 호스트의 진단 도구: ping(반복 ping -c N·통계), traceroute(IPv4·IPv6), nslookup. 보낸 Echo 의 id 로 내 것을 알아보고,
// Echo 응답·Time Exceeded·Destination Unreachable·ARP/NDP timeout·제 timer 로 결과를 적는다 (공개 기록은 화면과 테스트가 읽는다)
import { ipToInt, sameSubnet, type Ip } from "../addr";
import { canonIp6, isIpv6 } from "../addr6";
import {
  UNREACHABLE_FLAG,
  describeOriginal,
  type IcmpEcho,
  type IcmpTimeExceeded,
  type IcmpUnreachable,
  type Icmpv6Echo,
  type Icmpv6TimeExceeded,
  type Icmpv6Unreachable,
  type IpPacket,
  type Ipv4Packet,
  type Ipv6Packet,
} from "../packet";
import { looksLikeName, normalizeName, type DnsResolver, type QType, type ResolveInfo } from "./dns";
import type { Emit, NetInterface } from "./iface";
import { Ipv6Interface } from "./ipv6";
import type { NodeContext, TimerHandle } from "./node";
import type { MeshAgent } from "./tailscale";

export const PING_TIMEOUT = 2000;
/** 반복 ping 간격 (실제 ping 기본값 1초) */
export const PING_INTERVAL = 1000;
export const PING_MAX_COUNT = 100;
/** 보관하는 반복 ping 실행 수 */
export const PING_RUN_KEEP = 5;
/** traceroute: 홉 하나의 응답을 기다리는 시간 */
export const TRACEROUTE_TIMEOUT = 1000;
export const TRACEROUTE_MAX_HOPS = 16;
/** 보관하는 traceroute 기록 수 */
export const TRACEROUTE_KEEP = 5;
/** 보관하는 nslookup 기록 수 */
export const LOOKUP_KEEP = 5;

function isValidIp(s: string): boolean {
  try {
    ipToInt(s);
    return true;
  } catch {
    return false;
  }
}

export interface PingRecord {
  /** 사용자가 입력한 대상 (이름 또는 IP) */
  dst: string;
  /** 이름이면 해석된 주소 */
  resolved?: Ip;
  seq: number;
  sentAt: number;
  status: "pending" | "ok" | "failed";
  rtt?: number;
  reason?: string;
  /** 반복 ping(ping -c N)의 한 번이면 그 실행의 id */
  run?: number;
}

/** 반복 ping 실행 (ping -c N): 1초 간격으로 보내고, 모두 끝나면 통계 */
export interface PingRun {
  id: number;
  /** 사용자가 입력한 대상 (이름 또는 IP) */
  dst: string;
  count: number;
  /** 지금까지 보낸 수 */
  sent: number;
  /** 이름이면 처음에 한 번 해석한 주소 (이후 그 주소로) */
  resolved?: Ip;
  /** 실제로 보내는 주소 */
  target?: Ip;
  done: boolean;
  /** 첫 요청도 못 보내고 멈춤 (IP 미설정·이름 해석 실패) */
  stopped?: string;
  stats?: PingStats;
}

export interface PingStats {
  transmitted: number;
  received: number;
  /** 패킷 손실 % */
  loss: number;
  min?: number;
  avg?: number;
  max?: number;
  mdev?: number;
  /** 첫 요청부터 마지막 요청까지 (ms) */
  time: number;
}

export interface TracerouteHop {
  ttl: number;
  /** 응답한 홉의 주소. 시간 안에 응답이 없으면(*) 비어 있다 */
  ip?: Ip;
  rtt?: number;
  /** 이 홉이 Destination Unreachable 을 돌려줌 (!N 경로 없음, !H 호스트 무응답, !P 포트 닫힘) */
  flag?: string;
}

export interface TracerouteRecord {
  /** 사용자가 입력한 대상 (이름 또는 IP) */
  dst: string;
  /** 이름이면 해석된 주소 */
  resolved?: Ip;
  hops: TracerouteHop[];
  status: "running" | "done" | "failed";
  reason?: string;
  startedAt: number;
}

/** nslookup(DNS 조회) 한 번의 기록 */
export interface LookupRecord {
  seq: number;
  name: string;
  qtype: QType;
  /** 물어본 DNS 서버 (사용자가 적은 서버, 아니면 설정된 DNS). 묻지도 못했으면 비어 있다 */
  server?: Ip;
  status: "pending" | "ok" | "failed";
  answer?: Ip;
  /** 답이 0.0.0.0·:: — DNS 필터(광고 차단·자녀 보호)가 막은 이름 */
  blocked?: boolean;
  /** MagicDNS(메시 VPN)가 기기 안에서 답함 */
  magicDns?: boolean;
  startedAt: number;
  rtt?: number;
  reason?: string;
}

/** 진행 중인 traceroute 의 현재 프로브 */
interface ActiveTrace {
  rec: TracerouteRecord;
  target: Ip;
  ttl: number;
  seq: number;
  sentAt: number;
  timer?: TimerHandle;
}

/** 진단 도구가 호스트에게서 빌리는 것 */
export interface DiagHost {
  readonly iface: NetInterface;
  readonly v6: Ipv6Interface;
  readonly resolver: DnsResolver;
  readonly mesh: MeshAgent;
  emit(ctx: NodeContext): Emit;
  /** 전역 IPv6 주소가 있나 (이름을 AAAA 로 먼저 풀지) */
  hasV6Global(): boolean;
  /** 이름 → 주소 (alive 가 false 가 되면 결과를 버린다) */
  resolveName(name: string, ctx: NodeContext, done: (ip: Ip | undefined, error?: string) => void, alive?: () => boolean): void;
}

export class HostDiagnostics {
  /** ping 기록 */
  readonly pings: PingRecord[] = [];
  /** 반복 ping 실행 (최근 PING_RUN_KEEP 개) */
  readonly pingRuns: PingRun[] = [];
  private pingRunSeq = 0;
  /** traceroute 기록 (최근 TRACEROUTE_KEEP 개, 오래된 것부터) */
  readonly traceroutes: TracerouteRecord[] = [];
  /** nslookup 기록 (최근 LOOKUP_KEEP 개, 오래된 것부터) */
  readonly lookups: LookupRecord[] = [];
  private lookupSeq = 0;
  /** ping 의 ICMP id (장치마다 다름 — 받은 Echo 응답이 내 것인지 가른다) */
  private readonly icmpId: number;
  private icmpSeq = 0;
  private readonly pingTimers = new Map<number, TimerHandle>();
  /** traceroute 프로브의 ICMP id. ping 의 id(0x1000 대)와 겹치지 않게 0x2000 대 */
  private readonly trId: number;
  private trSeq = 0;
  private activeTrace: ActiveTrace | undefined;

  constructor(
    private readonly host: DiagHost,
    seed: number,
  ) {
    this.icmpId = 0x1000 + (Math.abs(seed) % 0x1000);
    this.trId = 0x2000 + (Math.abs(seed) % 0x1000);
  }

  /** 반복 ping 횟수를 1~PING_MAX_COUNT 정수로 (없거나 숫자가 아니면 1) */
  static pingCount(count?: number): number {
    return Math.min(PING_MAX_COUNT, Math.max(1, Math.floor(count ?? 1) || 1));
  }

  /** ping. count > 1 이면 반복 ping (ping -c N): 1초 간격으로 보내고 모두 끝나면 통계를 남긴다 */
  ping(target: string, ctx: NodeContext, count = 1): void {
    const seq = ++this.icmpSeq;
    const n = HostDiagnostics.pingCount(count);
    const run: PingRun | undefined = n > 1 ? { id: ++this.pingRunSeq, dst: target, count: n, sent: 1, done: false } : undefined;
    if (run) {
      this.pingRuns.push(run);
      // 끝나고 통계까지 남긴 실행만 밀어낸다 (진행 중인 실행을 지우면 다음 요청·통계를 잃는다)
      while (this.pingRuns.length > PING_RUN_KEEP) {
        const i = this.pingRuns.findIndex((r) => r.stats || r.stopped);
        if (i < 0) break;
        this.pingRuns.splice(i, 1);
      }
    }
    const rec: PingRecord = { dst: target, seq, sentAt: ctx.now, status: "pending", ...(run ? { run: run.id } : {}) };
    this.pings.push(rec);
    // 첫 요청을 못 보내면 반복도 멈춘다 (실제 ping 도 unknown host·Network unreachable 이면 바로 끝남)
    const stop = (reason: string) => {
      if (!run) return;
      run.done = true;
      run.stopped = reason;
    };
    /** 첫 요청을 보낸 뒤: 바로 실패했으면(IPv6 출발지 없음) 멈추고, 아니면 반복을 잇는다 */
    const next = (ip: Ip) => {
      if (!run) return;
      if (rec.status === "failed") stop(rec.reason ?? "보내지 못함");
      else this.continueRun(run, ip, ctx);
    };
    if (isIpv6(target)) {
      this.sendPing6(rec, canonIp6(target)!, ctx);
      next(canonIp6(target)!);
      return;
    }
    if (!this.host.iface.ip && !(looksLikeName(target) && this.host.hasV6Global())) {
      rec.status = "failed";
      rec.reason = "IP 미설정";
      ctx.trace("ip.no-address", "L3", `ping ${target} 실패: 내 IP 주소가 없음 (DHCP 로 받거나 수동 설정 필요)`, { dst: target });
      stop(rec.reason);
      return;
    }
    if (!looksLikeName(target) && !isValidIp(target)) {
      rec.status = "failed";
      rec.reason = "잘못된 주소";
      ctx.trace("ip.drop", "L3", `ping ${target} 실패: IP 주소도 이름도 아님`, { dst: target });
      stop(rec.reason);
      return;
    }
    if (looksLikeName(target)) {
      // 이름이면 먼저 DNS 로 주소를 찾고, 그 다음에 ping (IPv6 주소가 있으면 AAAA 먼저 — 폴백 없음)
      this.host.resolveName(target, ctx, (ip, err) => {
        if (!ip) {
          rec.status = "failed";
          rec.reason = err ?? "이름 해석 실패";
          ctx.trace("icmp.failed", "app", `ping ${target} 실패: 이름을 주소로 바꾸지 못함 (${rec.reason})`, { dst: target });
          stop(rec.reason);
          return;
        }
        rec.resolved = ip;
        ctx.trace("dns.resolved", "app", `${target} = ${ip} → 이제 이 주소로 ping`, { name: target, ip });
        if (isIpv6(ip)) this.sendPing6(rec, ip, ctx);
        else this.sendPing(rec, ip, ctx);
        if (run) run.resolved = ip;
        next(ip);
      });
      return;
    }
    this.sendPing(rec, target, ctx);
    next(target);
  }

  /** 반복 ping: 첫 요청을 보낸 뒤 — 남았으면 1초 뒤 다음, 다 보냈으면 끝났는지 본다 */
  private continueRun(run: PingRun, target: Ip, ctx: NodeContext): void {
    run.target = target;
    if (run.sent < run.count) ctx.timer(PING_INTERVAL, "ping-next", { run: run.id });
    this.checkRun(run, ctx);
  }

  /** 반복 ping 의 다음 요청 (이름은 다시 풀지 않고 처음 주소로) */
  private nextPing(runId: number, ctx: NodeContext): void {
    const run = this.pingRuns.find((r) => r.id === runId);
    if (!run || run.done || !run.target) return;
    const target = run.target;
    run.sent += 1;
    const rec: PingRecord = { dst: run.dst, seq: ++this.icmpSeq, sentAt: ctx.now, status: "pending", run: run.id, ...(run.resolved ? { resolved: run.resolved } : {}) };
    this.pings.push(rec);
    if (isIpv6(target)) this.sendPing6(rec, target, ctx);
    else if (!this.host.iface.ip) {
      // 도중에 주소를 잃음: 이번 요청은 실패, 다음 요청은 계속 (실제 ping 의 sendmsg: Network is unreachable)
      rec.status = "failed";
      rec.reason = "IP 미설정";
      ctx.trace("ip.no-address", "L3", `ping ${target} (seq=${rec.seq}) 실패: 내 IP 주소가 없음`, { dst: target, seq: rec.seq });
    } else this.sendPing(rec, target, ctx);
    if (run.sent < run.count) ctx.timer(PING_INTERVAL, "ping-next", { run: run.id });
    this.checkRun(run, ctx);
  }

  /** 다 보냈고 모두 답(또는 timeout)이 났으면 통계 — 마지막 결과 줄 뒤에 남도록 0ms 뒤에 */
  private checkRun(run: PingRun, ctx: NodeContext): void {
    if (run.done || run.sent < run.count) return;
    if (this.pings.some((p) => p.run === run.id && p.status === "pending")) return;
    run.done = true;
    ctx.timer(0, "ping-stats", { run: run.id });
  }

  private pingStats(runId: number, ctx: NodeContext): void {
    const run = this.pingRuns.find((r) => r.id === runId);
    if (!run) return;
    const recs = this.pings.filter((p) => p.run === run.id);
    const rtts = recs.filter((p) => p.status === "ok").map((p) => p.rtt ?? 0);
    const transmitted = recs.length;
    const received = rtts.length;
    const loss = transmitted ? ((transmitted - received) / transmitted) * 100 : 0;
    const time = recs.length ? recs.at(-1)!.sentAt - recs[0]!.sentAt : 0;
    const stats: PingStats = { transmitted, received, loss, time };
    if (received) {
      const avg = rtts.reduce((a, b) => a + b, 0) / received;
      Object.assign(stats, { min: Math.min(...rtts), avg, max: Math.max(...rtts), mdev: Math.sqrt(Math.max(0, rtts.reduce((a, b) => a + b * b, 0) / received - avg * avg)) });
    }
    run.stats = stats;
    const pct = +loss.toPrecision(6);
    const dst = run.resolved ? `${run.dst} (${run.resolved})` : run.dst;
    ctx.trace(
      "icmp.stats",
      "app",
      `ping ${dst} 통계: ${transmitted}개 보냄 → ${received}개 받음, 패킷 손실 ${pct}%${received ? ` · RTT 최소/평균/최대 ${stats.min}/${Math.round(stats.avg! * 10) / 10}/${stats.max}ms` : ""}`,
      { dst: run.dst, transmitted, received, loss: pct, time, ...(received ? { min: stats.min!, avg: stats.avg!, max: stats.max!, mdev: stats.mdev! } : {}) },
    );
  }

  private sendPing(rec: PingRecord, dst: Ip, ctx: NodeContext): void {
    const seq = rec.seq;
    rec.sentAt = ctx.now;
    if (dst === this.host.iface.ip || dst === "127.0.0.1") {
      rec.status = "ok";
      rec.rtt = 0;
      ctx.trace("icmp.reply.received", "app", `ping ${dst}: 내 주소(루프백) → 네트워크로 나가지 않고 즉시 응답`, { dst });
      return;
    }
    const pkt: Ipv4Packet = {
      kind: "ipv4",
      src: this.host.iface.ip!,
      dst,
      ttl: 64,
      payload: { kind: "icmp", type: "echo-request", id: this.icmpId, seq },
    };
    ctx.trace("icmp.echo.sent", "app", `ping ${dst} (seq=${seq}) → ICMP Echo 요청 생성`, { dst, seq });
    this.host.iface.sendIp(pkt, ctx, this.host.emit(ctx));
    this.pingTimers.set(seq, ctx.timer(PING_TIMEOUT, "ping-timeout", { seq }));
  }

  /** ping over IPv6 (ICMPv6 Echo) */
  private sendPing6(rec: PingRecord, dst: Ip, ctx: NodeContext): void {
    rec.sentAt = ctx.now;
    if (this.host.v6.owns(dst) || dst === "::1") {
      rec.status = "ok";
      rec.rtt = 0;
      ctx.trace("icmp.reply.received", "app", `ping ${dst}: 내 주소(루프백) → 네트워크로 나가지 않고 즉시 응답`, { dst });
      return;
    }
    const src = this.host.v6.sourceFor(dst);
    if (!src) {
      rec.status = "failed";
      rec.reason = this.host.v6.enabled ? "IPv6 주소 없음" : "IPv6 꺼짐";
      ctx.trace("ip.no-address", "L3", `ping ${dst} 실패: ${this.host.v6.whyNoSource(dst)}`, { dst });
      return;
    }
    const pkt: Ipv6Packet = { kind: "ipv6", src, dst, hopLimit: Ipv6Interface.HOP_LIMIT, payload: { kind: "icmp6", type: "echo-request", id: this.icmpId, seq: rec.seq } };
    ctx.trace("icmp.echo.sent", "app", `ping ${dst} (seq=${rec.seq}) → ICMPv6 Echo 요청 생성 (출발지 ${src})`, { dst, seq: rec.seq });
    this.host.v6.send(pkt, ctx, this.host.emit(ctx));
    this.pingTimers.set(rec.seq, ctx.timer(PING_TIMEOUT, "ping-timeout", { seq: rec.seq }));
  }

  private finishPing(rec: PingRecord, status: "ok" | "failed", extra: { rtt?: number; reason?: string }, ctx: NodeContext): void {
    rec.status = status;
    if (extra.rtt !== undefined) rec.rtt = extra.rtt;
    if (extra.reason) rec.reason = extra.reason;
    this.pingTimers.get(rec.seq)?.cancel();
    this.pingTimers.delete(rec.seq);
    const run = rec.run !== undefined ? this.pingRuns.find((r) => r.id === rec.run) : undefined;
    if (run) this.checkRun(run, ctx);
  }

  // ---------- nslookup ----------

  /**
   * DNS 조회(nslookup): 캐시를 거치지 않고 DNS 서버에 묻고 답을 보여 준다 (캐시에도 넣지 않음).
   * server 를 주면 그 서버에, 없으면 설정된 DNS 에. 127.0.0.1 은 내 주소(내 DNS 서버 서비스)
   */
  lookup(rawName: string, qtype: QType, server: Ip | undefined, ctx: NodeContext): void {
    const name = normalizeName(rawName);
    const rec: LookupRecord = { seq: ++this.lookupSeq, name, qtype, status: "pending", startedAt: ctx.now };
    this.lookups.push(rec);
    while (this.lookups.length > LOOKUP_KEEP) this.lookups.shift();
    const cmd = `nslookup${qtype === "AAAA" ? " -type=AAAA" : ""} ${name}`;
    const fail = (reason: string, info?: ResolveInfo) => {
      rec.status = "failed";
      rec.reason = reason;
      // rcode: NXDOMAIN·SERVFAIL·NODATA(이름은 있지만 그 종류가 없음)·timeout — 실무 출력(nslookup)의 모양을 고른다
      const rcode = info?.rcode ?? (info?.nodata ? "NODATA" : info?.timeout ? "timeout" : undefined);
      ctx.trace("dns.lookup.failed", "app", `${cmd} 실패: ${reason}`, { name, qtype, reason, ...(rec.server ? { server: rec.server } : {}), ...(rcode ? { rcode } : {}) });
    };
    if (isValidIp(name) || isIpv6(name)) {
      fail("주소로 이름을 찾는 역방향 조회(PTR)는 지원하지 않음 — 이름을 적으세요");
      return;
    }
    if (!looksLikeName(name) || !/^[a-z0-9._-]+$/.test(name)) {
      fail("이름에 쓸 수 없는 글자가 있음 (영문·숫자·점·하이픈)");
      return;
    }
    if (server !== undefined) {
      server = server.trim();
      if (server === "127.0.0.1" && this.host.iface.ip) server = this.host.iface.ip;
      else if (isIpv6(server)) {
        server = canonIp6(server)!;
        // ::1 = 내 IPv6 주소 (내 DNS 서버 서비스에 루프백). 전역 주소가 없으면 링크 로컬
        if (server === "::1") server = this.host.v6.globals[0]?.ip ?? this.host.v6.linkLocal;
      }
      else if (!isValidIp(server)) {
        fail(`DNS 서버 주소가 올바르지 않음 (${server})`);
        return;
      }
    }
    // MagicDNS: 메시 VPN 이 시스템 DNS 를 100.100.100.100(기기 안)으로 잡아 피어 이름을 바로 답한다 — 서버를 지정하지 않았을 때만
    const magic = server === undefined && qtype === "A" ? this.host.mesh.resolve(name) : undefined;
    if (magic) {
      Object.assign(rec, { status: "ok", answer: magic, server: "100.100.100.100", magicDns: true, rtt: 0 });
      ctx.trace("dns.lookup", "app", `${cmd} → ${magic} (MagicDNS 100.100.100.100 — ${this.host.mesh.brand} netmap 의 피어 이름, 기기 안에서 답함)`, { name, qtype, ip: magic, server: "100.100.100.100" });
      return;
    }
    // 물을 서버를 먼저 적어 둔다: 내 DNS 서버 서비스(루프백)는 답이 이 호출 안에서 바로 온다
    rec.server = server ?? this.host.resolver.server;
    this.host.resolver.lookup(name, qtype, server, ctx, this.host.emit(ctx), (ip, err, info) => {
      if (!ip) {
        fail(err ?? "응답 없음", info);
        return;
      }
      rec.status = "ok";
      rec.answer = ip;
      rec.rtt = ctx.now - rec.startedAt;
      if (ip === "0.0.0.0" || ip === "::") rec.blocked = true;
      ctx.trace(
        "dns.lookup",
        "app",
        `${cmd} → ${ip} (서버 ${rec.server ?? "?"}, ${rec.rtt}ms)${rec.blocked ? " — DNS 가 막은 이름 (광고 차단·자녀 보호가 이 주소로 답함)" : ""}`,
        { name, qtype, ip, server: rec.server ?? "", rtt: rec.rtt, ...(rec.blocked ? { blocked: true } : {}) },
      );
    });
  }

  // ---------- traceroute ----------

  /**
   * 경로 추적: TTL 1 부터 하나씩 Echo 요청을 보내고, 각 라우터의 Time Exceeded 로 홉을 기록한다.
   * Echo 응답이 오면 완료. 홉당 TRACEROUTE_TIMEOUT 안에 응답이 없으면 그 홉은 * 로 두고 다음 TTL.
   */
  traceroute(target: string, ctx: NodeContext): void {
    this.cancelTraceroute("새 traceroute 시작으로 취소", ctx);
    const rec: TracerouteRecord = { dst: target, hops: [], status: "running", startedAt: ctx.now };
    this.traceroutes.push(rec);
    while (this.traceroutes.length > TRACEROUTE_KEEP) this.traceroutes.shift();
    if (isIpv6(target)) {
      this.startTrace6(rec, canonIp6(target)!, ctx);
      return;
    }
    if (!this.host.iface.ip && !(looksLikeName(target) && this.host.hasV6Global())) {
      this.failTrace(rec, "IP 미설정", ctx, "DHCP 로 받거나 수동 설정 필요");
      return;
    }
    if (!looksLikeName(target) && !isValidIp(target)) {
      this.failTrace(rec, "잘못된 주소", ctx, "IP 주소도 이름도 아님");
      return;
    }
    if (looksLikeName(target)) {
      this.host.resolveName(
        target,
        ctx,
        (ip, err) => {
          if (rec.status !== "running") return; // 기다리는 동안 취소됨
          if (!ip) {
            this.failTrace(rec, err ?? "이름 해석 실패", ctx, "이름을 주소로 바꾸지 못함");
            return;
          }
          rec.resolved = ip;
          ctx.trace("dns.resolved", "app", `${target} = ${ip} → 이제 이 주소로 traceroute`, { name: target, ip });
          if (isIpv6(ip)) this.startTrace6(rec, ip, ctx);
          else this.startTrace(rec, ip, ctx);
        },
        () => rec.status === "running",
      );
      return;
    }
    this.startTrace(rec, target, ctx);
  }

  private startTrace(rec: TracerouteRecord, target: Ip, ctx: NodeContext): void {
    const ip = this.host.iface.ip!;
    if (target === ip || target === "127.0.0.1") {
      rec.hops.push({ ttl: 1, ip: target, rtt: 0 });
      rec.status = "done";
      ctx.trace("trace.done", "app", `traceroute ${rec.dst}: 내 주소(루프백) → 네트워크로 나가지 않고 1 홉으로 완료`, { dst: rec.dst, hops: 1 });
      return;
    }
    if (!sameSubnet(target, ip, this.host.iface.prefix) && !this.host.iface.gateway) {
      this.failTrace(rec, "게이트웨이 없음", ctx, `${target} 은(는) 다른 서브넷인데 게이트웨이 설정이 없음 — IP 설정에서 게이트웨이를 넣으세요`);
      return;
    }
    ctx.trace(
      "trace.start",
      "app",
      `traceroute ${rec.dst}${rec.resolved ? ` (${target})` : ""}: TTL 을 1 부터 늘려 가며 Echo 요청을 보내고, 각 라우터가 돌려주는 Time Exceeded 로 경로를 알아낸다 (최대 ${TRACEROUTE_MAX_HOPS} 홉, 홉당 ${TRACEROUTE_TIMEOUT}ms 대기)`,
      { dst: rec.dst, target },
    );
    this.activeTrace = { rec, target, ttl: 0, seq: 0, sentAt: ctx.now };
    this.sendProbe(ctx);
  }

  /** traceroute over IPv6 (traceroute6): Hop Limit 을 1 부터 늘린다 */
  private startTrace6(rec: TracerouteRecord, target: Ip, ctx: NodeContext): void {
    if (this.host.v6.owns(target) || target === "::1") {
      rec.hops.push({ ttl: 1, ip: target, rtt: 0 });
      rec.status = "done";
      ctx.trace("trace.done", "app", `traceroute ${rec.dst}: 내 주소(루프백) → 네트워크로 나가지 않고 1 홉으로 완료`, { dst: rec.dst, hops: 1 });
      return;
    }
    const src = this.host.v6.sourceFor(target);
    if (!src) {
      this.failTrace(rec, this.host.v6.enabled ? "IPv6 주소 없음" : "IPv6 꺼짐", ctx, this.host.v6.whyNoSource(target));
      return;
    }
    if (!this.host.v6.onLink(target) && !this.host.v6.defaultRouter) {
      this.failTrace(rec, "IPv6 게이트웨이 없음", ctx, `${target} 은(는) 다른 네트워크인데 IPv6 기본 게이트웨이가 없음 — IPv6 설정에서 게이트웨이를 넣으세요`);
      return;
    }
    ctx.trace(
      "trace.start",
      "app",
      `traceroute ${rec.dst}: Hop Limit 을 1 부터 늘려 가며 ICMPv6 Echo 요청을 보내고, 각 라우터가 돌려주는 ICMPv6 Time Exceeded 로 경로를 알아낸다 (최대 ${TRACEROUTE_MAX_HOPS} 홉, 홉당 ${TRACEROUTE_TIMEOUT}ms 대기)`,
      { dst: rec.dst, target },
    );
    this.activeTrace = { rec, target, ttl: 0, seq: 0, sentAt: ctx.now };
    this.sendProbe(ctx);
  }

  private sendProbe(ctx: NodeContext): void {
    const a = this.activeTrace!;
    a.ttl += 1;
    a.seq = ++this.trSeq;
    a.sentAt = ctx.now;
    if (isIpv6(a.target)) {
      const src = this.host.v6.sourceFor(a.target);
      if (!src) {
        this.failTrace(a.rec, "IPv6 주소 없음", ctx, this.host.v6.whyNoSource(a.target));
        return;
      }
      const pkt: Ipv6Packet = { kind: "ipv6", src, dst: a.target, hopLimit: a.ttl, payload: { kind: "icmp6", type: "echo-request", id: this.trId, seq: a.seq } };
      ctx.trace("trace.probe", "app", `traceroute ${a.rec.dst}: Hop Limit=${a.ttl} 로 ICMPv6 Echo 요청 송신 (seq=${a.seq}) — ${a.ttl} 번째 라우터에서 Hop Limit 이 0 이 된다`, { dst: a.rec.dst, ttl: a.ttl, seq: a.seq });
      this.host.v6.send(pkt, ctx, this.host.emit(ctx));
    } else {
      const pkt: Ipv4Packet = { kind: "ipv4", src: this.host.iface.ip!, dst: a.target, ttl: a.ttl, payload: { kind: "icmp", type: "echo-request", id: this.trId, seq: a.seq } };
      ctx.trace("trace.probe", "app", `traceroute ${a.rec.dst}: TTL=${a.ttl} 로 Echo 요청 송신 (seq=${a.seq}) — ${a.ttl} 번째 라우터에서 TTL 이 0 이 된다`, { dst: a.rec.dst, ttl: a.ttl, seq: a.seq });
      this.host.iface.sendIp(pkt, ctx, this.host.emit(ctx));
    }
    a.timer = ctx.timer(TRACEROUTE_TIMEOUT, "tr-timeout", { seq: a.seq });
  }

  /** 홉 하나를 기록한 뒤: 상한이면 실패, 아니면 다음 TTL */
  private nextProbe(ctx: NodeContext): void {
    const a = this.activeTrace!;
    if (a.ttl >= TRACEROUTE_MAX_HOPS) {
      this.failTrace(a.rec, `${TRACEROUTE_MAX_HOPS} 홉 안에 도달하지 못함`, ctx, "응답 없는 홉(*)이 시작된 장치의 경로·방화벽·주소를 확인");
      return;
    }
    this.sendProbe(ctx);
  }

  private finishTrace(a: ActiveTrace, from: Ip, ctx: NodeContext, frameId: number): void {
    a.timer?.cancel();
    const rtt = ctx.now - a.sentAt;
    a.rec.hops.push({ ttl: a.ttl, ip: from, rtt });
    a.rec.status = "done";
    this.activeTrace = undefined;
    const path = a.rec.hops.map((h) => h.ip ?? "*").join(" → ");
    ctx.trace("trace.done", "app", `traceroute ${a.rec.dst} 완료: ${from} 가 Echo 응답 (RTT ${rtt}ms) → 목적지까지 ${a.rec.hops.length} 홉 [${path}]`, { dst: a.rec.dst, hops: a.rec.hops.length, path }, frameId);
  }

  failTrace(rec: TracerouteRecord, reason: string, ctx: NodeContext, hint?: string): void {
    rec.status = "failed";
    rec.reason = reason;
    if (this.activeTrace?.rec === rec) {
      this.activeTrace.timer?.cancel();
      this.activeTrace = undefined;
    }
    ctx.trace("trace.failed", "app", `traceroute ${rec.dst} 실패: ${reason}${hint ? ` (${hint})` : ""}`, { dst: rec.dst, reason, hops: rec.hops.length });
  }

  /** 진행 중인 traceroute 를 모두 실패로 끝낸다 (이름 해석 대기 중인 것 포함) */
  /** only 가 있으면 그 조건에 맞는 것만 (예: IPv4 주소가 바뀌면 IPv4 traceroute 만) */
  cancelTraceroute(reason: string, ctx: NodeContext, only?: (rec: TracerouteRecord) => boolean): void {
    for (const rec of this.traceroutes) if (rec.status === "running" && (!only || only(rec))) this.failTrace(rec, reason, ctx);
  }

  /** Time Exceeded: 내 traceroute 프로브면 홉 하나, 내 ping 이면 실패 */
  handleTimeExceeded(pkt: IpPacket, icmp: IcmpTimeExceeded | Icmpv6TimeExceeded, frameId: number, ctx: NodeContext): void {
    const o = icmp.original;
    if (o.l4.kind === "icmp" && o.l4.id === this.trId) {
      const a = this.activeTrace;
      if (!a || a.seq !== o.l4.seq) {
        ctx.trace("ip.drop", "L3", `지난 traceroute 프로브(seq=${o.l4.seq})에 대한 Time Exceeded → 무시`, { seq: o.l4.seq }, frameId);
        return;
      }
      a.timer?.cancel();
      const rtt = ctx.now - a.sentAt;
      a.rec.hops.push({ ttl: a.ttl, ip: pkt.src, rtt });
      ctx.trace(
        "trace.hop",
        "app",
        `traceroute ${a.rec.dst}: ${pkt.src} 가 Time Exceeded 회신 (${pkt.kind === "ipv6" ? "Hop Limit" : "TTL"} ${a.ttl} 이 거기서 0 이 됨) → ${a.ttl} 번째 홉 = ${pkt.src}, RTT ${rtt}ms`,
        { dst: a.rec.dst, ttl: a.ttl, ip: pkt.src, rtt },
        frameId,
      );
      this.nextProbe(ctx);
      return;
    }
    if (o.l4.kind === "icmp" && o.l4.id === this.icmpId) {
      const seq = o.l4.seq;
      const rec = this.pings.find((p) => p.seq === seq && p.status === "pending");
      if (rec) {
        this.finishPing(rec, "failed", { reason: pkt.kind === "ipv6" ? "Hop Limit 초과" : "TTL 초과" }, ctx);
        ctx.trace(
          "icmp.ttl-received",
          "app",
          `${pkt.src} 로부터 Time Exceeded 수신 (원래 ${describeOriginal(o)}) → ping ${rec.dst} 실패: 경로 위에서 ${pkt.kind === "ipv6" ? "Hop Limit" : "TTL"} 이 다 됨 (라우팅 루프 의심 — 라우터들의 스태틱 라우팅·디폴트 라우트가 서로를 가리키는지 확인)`,
          { from: pkt.src, dst: rec.dst, seq },
          frameId,
        );
        return;
      }
    }
    ctx.trace("icmp.ttl-received", "app", `${pkt.src} 로부터 Time Exceeded 수신 (원래 ${describeOriginal(o)}) → 기다리는 traceroute/ping 이 없어 무시`, { from: pkt.src }, frameId);
  }

  /** Destination Unreachable 이 내 traceroute 프로브·ping 의 것이면 끝내고 true (done = 받은 Unreachable 기록) */
  onUnreachable(pkt: IpPacket, icmp: IcmpUnreachable | Icmpv6Unreachable, reason: string, done: (what: string) => void, ctx: NodeContext): boolean {
    const o = icmp.original;
    if (o.l4.kind === "icmp" && o.l4.id === this.trId) {
      const a = this.activeTrace;
      if (a && a.seq === o.l4.seq) {
        a.timer?.cancel();
        a.rec.hops.push({ ttl: a.ttl, ip: pkt.src, rtt: ctx.now - a.sentAt, flag: UNREACHABLE_FLAG[icmp.code] });
        done(`traceroute 는 ${a.ttl} 번째 홉 ${pkt.src} ${UNREACHABLE_FLAG[icmp.code]} 에서 끝`);
        this.failTrace(a.rec, reason, ctx, icmp.code === "net" ? "그 장치의 라우팅 테이블에 목적지 경로가 없음 — 스태틱 라우팅·디폴트 라우트·RIP 를 확인" : "그 장치 너머의 목적지 주소에 응답하는 장치가 없음");
        return true;
      }
    }
    if (o.l4.kind === "icmp" && o.l4.id === this.icmpId) {
      const seq = o.l4.seq;
      const rec = this.pings.find((p) => p.seq === seq && p.status === "pending");
      if (rec) {
        this.finishPing(rec, "failed", { reason }, ctx);
        done(`ping ${rec.dst} 실패`);
        ctx.trace("icmp.failed", "app", `ping ${rec.dst} 실패: ${reason}`, { dst: rec.dst, seq: rec.seq });
        return true;
      }
    }
    return false;
  }

  /** Echo 응답 (IPv4·IPv6): 내 traceroute 프로브면 도착, 내 ping 이면 성공 */
  echoReply(pkt: IpPacket, icmp: IcmpEcho | Icmpv6Echo, frameId: number, ctx: NodeContext): void {
    if (icmp.id === this.trId) {
      const a = this.activeTrace;
      if (a && a.seq === icmp.seq) this.finishTrace(a, pkt.src, ctx, frameId);
      else ctx.trace("ip.drop", "L3", `지난 traceroute 프로브(seq=${icmp.seq})의 Echo 응답 → 무시`, { seq: icmp.seq }, frameId);
      return;
    }
    const rec = icmp.id === this.icmpId ? this.pings.find((p) => p.seq === icmp.seq && p.status === "pending") : undefined;
    if (!rec) {
      if (pkt.kind === "ipv6") {
        const done = icmp.id === this.icmpId ? this.pings.find((p) => p.seq === icmp.seq) : undefined;
        if (done) ctx.trace("icmp.reply.received", "app", `ping ${done.dst}: ${pkt.src} 의 추가 응답 seq=${icmp.seq} (DUP! — 멀티캐스트로 보내 여러 장치가 답함)`, { from: pkt.src, seq: icmp.seq, dup: true }, frameId);
        else ctx.trace("ip.drop", "L3", `내가 보낸 적 없는 ICMPv6 Echo 응답 (id=${icmp.id}, seq=${icmp.seq}) → 무시`, {}, frameId);
      } else ctx.trace("ip.drop", "L3", `내가 보낸 적 없는 Echo 응답 (id=${icmp.id}, seq=${icmp.seq}) → 무시`, {}, frameId);
      return;
    }
    this.finishPing(rec, "ok", { rtt: ctx.now - rec.sentAt }, ctx);
    ctx.trace("icmp.reply.received", "app", `ping 성공: ${pkt.src} seq=${icmp.seq} RTT=${rec.rtt}ms`, { from: pkt.src, seq: icmp.seq, rtt: rec.rtt }, frameId);
  }

  /** 첫 홉의 주소를 끝내 못 찾아(ARP·NDP timeout) 버린 패킷 중 내 traceroute 프로브·ping 을 실패로 */
  neighborFailed(dropped: IpPacket[], nextHop: Ip, v6: boolean, ctx: NodeContext): void {
    for (const pkt of dropped) {
      const icmp = pkt.payload;
      if ((icmp.kind !== "icmp" && icmp.kind !== "icmp6") || icmp.type !== "echo-request") continue;
      if (icmp.id === this.trId) {
        const a = this.activeTrace;
        if (a && a.seq === icmp.seq) this.failTrace(a.rec, v6 ? "NDP timeout · 응답 없음" : "ARP timeout · 응답 없음", ctx, v6 ? `첫 홉 ${nextHop} 이(가) NS 에 응답하지 않음 — 케이블과 IPv6 게이트웨이 주소를 확인` : `첫 홉 ${nextHop} 이(가) 응답하지 않음 — 케이블과 게이트웨이 주소를 확인`);
        continue;
      }
      const rec = this.pings.find((p) => p.seq === icmp.seq && p.status === "pending");
      if (!rec) continue;
      this.finishPing(rec, "failed", { reason: v6 ? "NDP timeout · 응답 없음" : "ARP timeout · 응답 없음" }, ctx);
      ctx.trace("icmp.failed", "app", v6 ? `ping ${rec.dst} 실패: 그 주소를 가진 장치가 NS 에 응답하지 않음 (Address unreachable)` : `ping ${rec.dst} 실패: 그 주소를 가진 장치가 응답하지 않음 (Destination Host Unreachable)`, { dst: rec.dst, seq: rec.seq });
    }
  }

  /** 진단 도구의 timer 면 처리하고 true */
  timer(tag: string, data: unknown, ctx: NodeContext): boolean {
    switch (tag) {
      case "tr-timeout": {
        const { seq } = data as { seq: number };
        const a = this.activeTrace;
        if (!a || a.seq !== seq) return true;
        a.timer = undefined;
        a.rec.hops.push({ ttl: a.ttl });
        ctx.trace("trace.timeout", "app", `traceroute ${a.rec.dst}: ${isIpv6(a.target) ? "Hop Limit" : "TTL"}=${a.ttl} timeout (${TRACEROUTE_TIMEOUT}ms 동안 응답 없음) → ${a.ttl} 번째 홉 = * (다음 ${isIpv6(a.target) ? "Hop Limit" : "TTL"} 로 계속)`, { dst: a.rec.dst, ttl: a.ttl, seq });
        this.nextProbe(ctx);
        return true;
      }
      case "ping-next":
        this.nextPing((data as { run: number }).run, ctx);
        return true;
      case "ping-stats":
        this.pingStats((data as { run: number }).run, ctx);
        return true;
      case "ping-timeout": {
        const { seq } = data as { seq: number };
        this.pingTimers.delete(seq);
        const rec = this.pings.find((p) => p.seq === seq && p.status === "pending");
        if (!rec) return true;
        this.finishPing(rec, "failed", { reason: "timeout · 응답 없음" }, ctx);
        ctx.trace("icmp.timeout", "app", `ping ${rec.dst} timeout: ${PING_TIMEOUT}ms 동안 응답 없음 (Request timed out)`, { dst: rec.dst, seq });
        return true;
      }
    }
    return false;
  }
}
