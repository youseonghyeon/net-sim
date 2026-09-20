import { ipToInt, sameSubnet, type Ip, type Mac } from "../addr";
import { DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DNS_PORT, describeFrame, describeOriginal, type EthernetFrame, type IcmpPacket, type IcmpTimeExceeded, type Ipv4Packet } from "../packet";
import { DHCP_STATE_LABEL, DHCP_TIMER_TAG, DhcpClient, DhcpServer, type DhcpServerConfig } from "./dhcp";
import { DNS_TIMER_TAG, DNS_UPSTREAM_TIMER_TAG, DnsResolver, DnsServer, looksLikeName, type DnsServerConfig } from "./dns";
import { NetInterface } from "./iface";
import type { NodeContext, NodeSnapshot, SimNode, TimerHandle } from "./node";
import { TCP_TIMER_TAG, TcpStack } from "./tcp";

export type IpMode = "dhcp" | "static";

export interface HostConfig {
  id: string;
  mac: Mac;
  ipMode?: IpMode;
  ip?: Ip;
  prefix?: number;
  gateway?: Ip;
  /** 수동 설정일 때 쓸 DNS 서버 */
  dns?: Ip;
  /** 듣고 있는 TCP 포트 (예: 80) */
  services?: number[];
  /** 이 호스트가 DHCP 서버 역할을 할 때 */
  dhcpServer?: DhcpServerConfig;
  /** 이 호스트가 DNS 서버 역할을 할 때 */
  dnsServer?: DnsServerConfig;
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
}

export interface TracerouteHop {
  ttl: number;
  /** 응답한 홉의 주소. 시간 안에 응답이 없으면(*) 비어 있다 */
  ip?: Ip;
  rtt?: number;
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

/** 진행 중인 traceroute 의 현재 프로브 */
interface ActiveTrace {
  rec: TracerouteRecord;
  target: Ip;
  ttl: number;
  seq: number;
  sentAt: number;
  timer?: TimerHandle;
}

export { DHCP_MAX_ATTEMPTS, DHCP_TIMEOUT, DHCP_STATE_LABEL, type DhcpState } from "./dhcp";

/** 단말 호스트: 인터페이스 1개, DHCP 클라이언트, ICMP ping */
export class Host implements SimNode {
  static readonly PING_TIMEOUT = 2000;
  /** traceroute: 홉 하나의 응답을 기다리는 시간 */
  static readonly TRACEROUTE_TIMEOUT = 1000;
  static readonly TRACEROUTE_MAX_HOPS = 16;
  /** 보관하는 traceroute 기록 수 */
  static readonly TRACEROUTE_KEEP = 5;

  readonly type = "host" as const;
  readonly portCount = 1;
  readonly id: string;
  readonly iface: NetInterface;
  readonly dhcp: DhcpClient;
  readonly dhcpServer: DhcpServer;
  readonly dnsServer: DnsServer;
  readonly resolver: DnsResolver;
  readonly tcp: TcpStack;
  ipMode: IpMode;
  linkUp = false;
  readonly pings: PingRecord[] = [];
  /** traceroute 기록 (최근 TRACEROUTE_KEEP 개, 오래된 것부터) */
  readonly traceroutes: TracerouteRecord[] = [];

  private readonly icmpId: number;
  private icmpSeq = 0;
  private readonly pingTimers = new Map<number, TimerHandle>();
  /** traceroute 프로브의 ICMP id. ping 의 id(0x1000 대)와 겹치지 않게 0x2000 대 */
  private readonly trId: number;
  private trSeq = 0;
  private activeTrace: ActiveTrace | undefined;
  private readonly emit = (ctx: NodeContext) => (f: EthernetFrame) => ctx.send(0, f);

  constructor(cfg: HostConfig) {
    this.id = cfg.id;
    this.ipMode = cfg.ipMode ?? (cfg.ip ? "static" : "dhcp");
    this.iface = new NetInterface(cfg.mac, this.ipMode === "static" ? { ip: cfg.ip, prefix: cfg.prefix, gateway: cfg.gateway, dns: cfg.dns } : { prefix: cfg.prefix });
    this.icmpId = 0x1000 + (Math.abs(hashCode(cfg.id)) % 0x1000);
    this.trId = 0x2000 + (Math.abs(hashCode(cfg.id)) % 0x1000);
    this.dhcp = new DhcpClient(this.iface, hashCode(cfg.id));
    this.tcp = new TcpStack({ send: (pkt, ctx) => this.iface.sendIp(pkt, ctx, this.emit(ctx)) });
    for (const p of cfg.services ?? []) this.tcp.listening.add(p);
    this.dhcpServer = new DhcpServer(cfg.dhcpServer ?? { enabled: false, start: "", end: "" }, this.iface, false);
    this.dnsServer = new DnsServer(cfg.dnsServer ?? { enabled: false, records: [] }, this.iface);
    this.resolver = new DnsResolver(this.iface, hashCode(cfg.id));
    this.resolver.local = this.dnsServer;
    this.iface.loopback = (pkt, ctx) => this.loopback(pkt, ctx);
  }

  /** 내 주소로 보내는 패킷은 네트워크로 나가지 않고 바로 받는다 (루프백) */
  private loopback(pkt: Ipv4Packet, ctx: NodeContext): void {
    ctx.trace("ip.route", "L3", `${pkt.dst} 는 내 주소 → 루프백으로 바로 처리`, { dst: pkt.dst });
    this.handleIp(pkt, -1, ctx);
  }

  /** DNS 서버 서비스 설정 교체 */
  setDnsServer(cfg: DnsServerConfig, ctx: NodeContext): void {
    const prev = this.dnsServer.config;
    if (cfg.enabled !== prev.enabled) {
      ctx.trace("ip.config", "sys", cfg.enabled ? `DNS 서버 시작 (레코드 ${cfg.records.length}개${cfg.upstream ? `, 상위 DNS ${cfg.upstream}` : ""})` : `DNS 서버 중지`, { ...cfg });
    } else if (cfg.enabled && (JSON.stringify(cfg.records) !== JSON.stringify(prev.records) || cfg.upstream !== prev.upstream)) {
      ctx.trace("ip.config", "sys", `DNS 서버 설정 변경 (레코드 ${cfg.records.length}개${cfg.upstream ? `, 상위 DNS ${cfg.upstream}` : ""})`, { ...cfg });
    }
    this.dnsServer.config = { ...cfg, records: [...cfg.records] };
  }

  /** DHCP 서버 서비스 설정 교체 */
  setDhcpServer(cfg: DhcpServerConfig, ctx: NodeContext): void {
    const prev = this.dhcpServer.config;
    if (cfg.enabled !== prev.enabled) {
      ctx.trace("ip.config", "sys", cfg.enabled ? `DHCP 서버 시작 (범위 ${cfg.start} ~ ${cfg.end}, 게이트웨이 안내 ${cfg.router || "없음"})` : `DHCP 서버 중지`, { ...cfg });
    } else if (cfg.start !== prev.start || cfg.end !== prev.end || cfg.router !== prev.router) {
      ctx.trace("ip.config", "sys", `DHCP 서버 설정 변경 (범위 ${cfg.start} ~ ${cfg.end}, 게이트웨이 안내 ${cfg.router || "없음"})`, { ...cfg });
    }
    this.dhcpServer.setConfig(cfg, ctx);
  }

  /** 듣는 포트 목록 교체 */
  setServices(ports: number[], ctx: NodeContext): void {
    const next = new Set(ports);
    for (const p of [...this.tcp.listening]) {
      if (!next.has(p)) {
        this.tcp.listening.delete(p);
        ctx.trace("ip.config", "sys", `TCP 포트 ${p} 서비스 중지`, { port: p });
      }
    }
    for (const p of next) {
      if (!this.tcp.listening.has(p)) {
        this.tcp.listening.add(p);
        ctx.trace("ip.config", "sys", `TCP 포트 ${p} 에서 연결 받기 시작 (listen)`, { port: p });
      }
    }
  }

  get mac(): Mac {
    return this.iface.mac;
  }
  get ip(): Ip | undefined {
    return this.iface.ip;
  }
  get arpCache() {
    return this.iface.arpCache;
  }
  get pending() {
    return this.iface.pending;
  }

  // ---------- 설정 변경 (인스펙터) ----------

  configure(cfg: { ipMode: IpMode; ip?: Ip; prefix?: number; gateway?: Ip; dns?: Ip }, ctx: NodeContext): void {
    this.ipMode = cfg.ipMode;
    const before = this.iface.ip;
    if (cfg.ipMode === "static") {
      this.dhcp.stop();
      const addrChanged = cfg.ip !== this.iface.ip || (cfg.prefix ?? 24) !== this.iface.prefix;
      if (cfg.dns !== this.iface.dns) this.resolver.clear("DNS 설정 변경");
      this.iface.configure(cfg.ip || undefined, cfg.prefix ?? 24, cfg.gateway || undefined, cfg.dns || undefined);
      if (addrChanged) {
        this.dhcpServer.onInterfaceChanged(ctx);
        this.iface.arpCache.clear();
        this.iface.clearPending();
        this.tcp.abortAll("주소 변경", ctx);
        this.cancelTraceroute("주소 변경", ctx);
        if (this.linkUp && this.iface.ip) this.iface.announce(ctx, this.emit(ctx));
      }
      ctx.trace(
        "ip.config",
        "sys",
        cfg.ip ? `수동 설정 적용: ${cfg.ip}/${cfg.prefix ?? 24}${cfg.gateway ? `, 게이트웨이 ${cfg.gateway}` : ", 게이트웨이 없음"}${cfg.dns ? `, DNS ${cfg.dns}` : ", DNS 없음"}` : "수동 설정으로 전환 (IP 주소 미입력)",
        { ...cfg },
      );
      return;
    }
    this.iface.clearAddress();
    this.iface.prefix = 24;
    this.iface.arpCache.clear();
    this.iface.clearPending();
    if (before) this.tcp.abortAll("주소 변경", ctx);
    if (before) this.cancelTraceroute("주소 변경", ctx);
    ctx.trace("ip.config", "sys", `자동(DHCP) 로 전환 → 기존 주소 지움`, { ...cfg });
    if (this.linkUp) this.dhcp.start(ctx, this.emit(ctx));
    else this.dhcp.stop();
  }

  onRemove(ctx: NodeContext): void {
    if (this.linkUp) this.dhcp.release(ctx, this.emit(ctx));
  }

  onLink(_port: number, up: boolean, ctx: NodeContext): void {
    this.linkUp = up;
    if (up) {
      ctx.trace("link.up", "L1", `링크 연결됨`);
      if (this.ipMode === "dhcp") this.dhcp.start(ctx, this.emit(ctx));
      else if (this.iface.ip) this.iface.announce(ctx, this.emit(ctx));
      return;
    }
    ctx.trace("link.down", "L1", `링크 끊김`);
    this.iface.clearPending();
    this.tcp.abortAll("링크 끊김", ctx);
    this.cancelTraceroute("링크 끊김", ctx);
    this.resolver.clear("링크 끊김");
    if (this.ipMode === "dhcp") {
      const had = this.iface.ip;
      this.iface.clearAddress();
      this.dhcp.stop();
      if (had) ctx.trace("dhcp.release", "app", `링크가 끊겨 임대 주소 ${had} 해제 → 주소 없음`, { ip: had });
    }
  }

  // ---------- 사용자 동작 ----------

  ping(target: string, ctx: NodeContext): void {
    const seq = ++this.icmpSeq;
    const rec: PingRecord = { dst: target, seq, sentAt: ctx.now, status: "pending" };
    this.pings.push(rec);
    if (!this.iface.ip) {
      rec.status = "failed";
      rec.reason = "IP 주소 없음";
      ctx.trace("ip.no-address", "L3", `ping ${target} 실패: 내 IP 주소가 없음 (DHCP 로 받거나 수동 설정 필요)`, { dst: target });
      return;
    }
    if (!looksLikeName(target) && !isValidIp(target)) {
      rec.status = "failed";
      rec.reason = "잘못된 주소";
      ctx.trace("ip.drop", "L3", `ping ${target} 실패: IP 주소도 이름도 아님`, { dst: target });
      return;
    }
    if (looksLikeName(target)) {
      // 이름이면 먼저 DNS 로 주소를 찾고, 그 다음에 ping
      this.resolver.resolve(target, ctx, this.emit(ctx), (ip, err) => {
        if (!ip) {
          rec.status = "failed";
          rec.reason = err ?? "이름 해석 실패";
          ctx.trace("icmp.failed", "app", `ping ${target} 실패: 이름을 주소로 바꾸지 못함 (${rec.reason})`, { dst: target });
          return;
        }
        rec.resolved = ip;
        ctx.trace("dns.resolved", "app", `${target} = ${ip} → 이제 이 주소로 ping`, { name: target, ip });
        this.sendPing(rec, ip, ctx);
      });
      return;
    }
    this.sendPing(rec, target, ctx);
  }

  private sendPing(rec: PingRecord, dst: Ip, ctx: NodeContext): void {
    const seq = rec.seq;
    rec.sentAt = ctx.now;
    if (dst === this.iface.ip || dst === "127.0.0.1") {
      rec.status = "ok";
      rec.rtt = 0;
      ctx.trace("icmp.reply.received", "app", `ping ${dst}: 내 주소(루프백) → 네트워크로 나가지 않고 즉시 응답`, { dst });
      return;
    }
    const pkt: Ipv4Packet = {
      kind: "ipv4",
      src: this.iface.ip!,
      dst,
      ttl: 64,
      payload: { kind: "icmp", type: "echo-request", id: this.icmpId, seq },
    };
    ctx.trace("icmp.echo.sent", "app", `ping ${dst} (seq=${seq}) → ICMP Echo 요청 생성`, { dst, seq });
    this.iface.sendIp(pkt, ctx, this.emit(ctx));
    this.pingTimers.set(seq, ctx.timer(Host.PING_TIMEOUT, "ping-timeout", { seq }));
  }

  private finishPing(rec: PingRecord, status: "ok" | "failed", extra: { rtt?: number; reason?: string }): void {
    rec.status = status;
    if (extra.rtt !== undefined) rec.rtt = extra.rtt;
    if (extra.reason) rec.reason = extra.reason;
    this.pingTimers.get(rec.seq)?.cancel();
    this.pingTimers.delete(rec.seq);
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
    while (this.traceroutes.length > Host.TRACEROUTE_KEEP) this.traceroutes.shift();
    if (!this.iface.ip) {
      this.failTrace(rec, "IP 주소 없음", ctx, "DHCP 로 받거나 수동 설정 필요");
      return;
    }
    if (!looksLikeName(target) && !isValidIp(target)) {
      this.failTrace(rec, "잘못된 주소", ctx, "IP 주소도 이름도 아님");
      return;
    }
    if (looksLikeName(target)) {
      this.resolver.resolve(target, ctx, this.emit(ctx), (ip, err) => {
        if (rec.status !== "running") return; // 기다리는 동안 취소됨
        if (!ip) {
          this.failTrace(rec, err ?? "이름 해석 실패", ctx, "이름을 주소로 바꾸지 못함");
          return;
        }
        rec.resolved = ip;
        ctx.trace("dns.resolved", "app", `${target} = ${ip} → 이제 이 주소로 traceroute`, { name: target, ip });
        this.startTrace(rec, ip, ctx);
      });
      return;
    }
    this.startTrace(rec, target, ctx);
  }

  private startTrace(rec: TracerouteRecord, target: Ip, ctx: NodeContext): void {
    const ip = this.iface.ip!;
    if (target === ip || target === "127.0.0.1") {
      rec.hops.push({ ttl: 1, ip: target, rtt: 0 });
      rec.status = "done";
      ctx.trace("trace.done", "app", `traceroute ${rec.dst}: 내 주소(루프백) → 네트워크로 나가지 않고 1 홉으로 완료`, { dst: rec.dst, hops: 1 });
      return;
    }
    if (!sameSubnet(target, ip, this.iface.prefix) && !this.iface.gateway) {
      this.failTrace(rec, "게이트웨이 없음", ctx, `${target} 은(는) 다른 서브넷인데 게이트웨이 설정이 없음 — IP 설정에서 게이트웨이를 넣으세요`);
      return;
    }
    ctx.trace(
      "trace.start",
      "app",
      `traceroute ${rec.dst}${rec.resolved ? ` (${target})` : ""}: TTL 을 1 부터 늘려 가며 Echo 요청을 보내고, 각 라우터가 돌려주는 Time Exceeded 로 경로를 알아낸다 (최대 ${Host.TRACEROUTE_MAX_HOPS} 홉, 홉당 ${Host.TRACEROUTE_TIMEOUT}ms 대기)`,
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
    const pkt: Ipv4Packet = { kind: "ipv4", src: this.iface.ip!, dst: a.target, ttl: a.ttl, payload: { kind: "icmp", type: "echo-request", id: this.trId, seq: a.seq } };
    ctx.trace("trace.probe", "app", `traceroute ${a.rec.dst}: TTL=${a.ttl} 로 Echo 요청 송신 (seq=${a.seq}) — ${a.ttl} 번째 라우터에서 TTL 이 0 이 된다`, { dst: a.rec.dst, ttl: a.ttl, seq: a.seq });
    this.iface.sendIp(pkt, ctx, this.emit(ctx));
    a.timer = ctx.timer(Host.TRACEROUTE_TIMEOUT, "tr-timeout", { seq: a.seq });
  }

  /** 홉 하나를 기록한 뒤: 상한이면 실패, 아니면 다음 TTL */
  private nextProbe(ctx: NodeContext): void {
    const a = this.activeTrace!;
    if (a.ttl >= Host.TRACEROUTE_MAX_HOPS) {
      this.failTrace(a.rec, `${Host.TRACEROUTE_MAX_HOPS} 홉 안에 도달하지 못함`, ctx, "응답 없는 홉(*)이 시작된 장치의 경로·방화벽·주소를 확인");
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

  private failTrace(rec: TracerouteRecord, reason: string, ctx: NodeContext, hint?: string): void {
    rec.status = "failed";
    rec.reason = reason;
    if (this.activeTrace?.rec === rec) {
      this.activeTrace.timer?.cancel();
      this.activeTrace = undefined;
    }
    ctx.trace("trace.failed", "app", `traceroute ${rec.dst} 실패: ${reason}${hint ? ` (${hint})` : ""}`, { dst: rec.dst, reason, hops: rec.hops.length });
  }

  /** 진행 중인 traceroute 를 모두 실패로 끝낸다 (이름 해석 대기 중인 것 포함) */
  private cancelTraceroute(reason: string, ctx: NodeContext): void {
    for (const rec of this.traceroutes) if (rec.status === "running") this.failTrace(rec, reason, ctx);
  }

  private handleTimeExceeded(pkt: Ipv4Packet, icmp: IcmpTimeExceeded, frameId: number, ctx: NodeContext): void {
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
        `traceroute ${a.rec.dst}: ${pkt.src} 가 Time Exceeded 회신 (TTL ${a.ttl} 이 거기서 0 이 됨) → ${a.ttl} 번째 홉 = ${pkt.src}, RTT ${rtt}ms`,
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
        this.finishPing(rec, "failed", { reason: "TTL 초과" });
        ctx.trace(
          "icmp.ttl-received",
          "app",
          `${pkt.src} 로부터 Time Exceeded 수신 (원래 ${describeOriginal(o)}) → ping ${rec.dst} 실패: 경로 위에서 TTL 이 다 됨 (라우팅 루프 의심 — 라우터들의 정적·기본 경로가 서로를 가리키는지 확인)`,
          { from: pkt.src, dst: rec.dst, seq },
          frameId,
        );
        return;
      }
    }
    ctx.trace("icmp.ttl-received", "app", `${pkt.src} 로부터 Time Exceeded 수신 (원래 ${describeOriginal(o)}) → 기다리는 traceroute/ping 이 없어 무시`, { from: pkt.src }, frameId);
  }

  /** TCP 연결 시작 (클라이언트) */
  connect(target: string, port: number, ctx: NodeContext): void {
    if (!this.iface.ip) {
      ctx.trace("ip.no-address", "L3", `${target}:${port} 연결 실패: 내 IP 주소가 없음 (DHCP 로 받거나 수동 설정 필요)`, { dst: target, port });
      this.tcp.recordFailure("0.0.0.0", target, port, "IP 주소 없음", ctx);
      return;
    }
    if (!looksLikeName(target) && !isValidIp(target)) {
      ctx.trace("ip.drop", "L3", `${target}:${port} 연결 실패: IP 주소도 이름도 아님`, { dst: target, port });
      this.tcp.recordFailure(this.iface.ip, target, port, "잘못된 주소", ctx);
      return;
    }
    if (looksLikeName(target)) {
      this.resolver.resolve(target, ctx, this.emit(ctx), (ip, err) => {
        if (!ip) {
          ctx.trace("tcp.failed", "L4", `${target}:${port} 연결 실패: 이름을 주소로 바꾸지 못함 (${err})`, { dst: target, port });
          this.tcp.recordFailure(this.iface.ip ?? "0.0.0.0", target, port, err ?? "이름 해석 실패", ctx);
          return;
        }
        ctx.trace("dns.resolved", "app", `${target} = ${ip} → 이 주소의 ${port} 포트로 연결`, { name: target, ip });
        if (this.iface.ip) this.tcp.connect(this.iface.ip, ip, port, ctx);
      });
      return;
    }
    this.tcp.connect(this.iface.ip, target, port, ctx);
  }

  /** ipconfig /renew 에 해당 */
  renewDhcp(ctx: NodeContext): void {
    if (this.ipMode !== "dhcp") {
      ctx.trace("dhcp.ignore", "app", `수동 설정 상태라 DHCP 요청 안 함`);
      return;
    }
    if (!this.linkUp) {
      ctx.trace("link.unconnected", "L1", `케이블이 연결되어 있지 않아 DHCP 요청 불가`);
      return;
    }
    this.dhcp.start(ctx, this.emit(ctx));
  }

  // ---------- 수신 ----------

  receive(_port: number, frame: EthernetFrame, ctx: NodeContext): void {
    if (frame.vlan !== undefined) {
      ctx.trace("vlan.drop", "L2", `VLAN ${frame.vlan} 태그가 달린 프레임 → 호스트는 태그를 이해하지 못해 폐기 (스위치 포트를 액세스로 바꾸세요)`, { vlan: frame.vlan }, frame.id);
      return;
    }
    if (!this.iface.accepts(frame)) {
      ctx.trace("frame.drop", "L2", `목적지 MAC ${frame.dst} 가 내 MAC(${this.iface.mac}) 아님 → 폐기`, { dst: frame.dst }, frame.id);
      return;
    }
    ctx.trace("frame.receive", "L2", `프레임 수신: ${describeFrame(frame)} [${frame.src} → ${frame.dst === this.iface.mac ? "내 MAC" : "브로드캐스트"}]`, { src: frame.src, dst: frame.dst }, frame.id);
    if (frame.payload.kind === "arp") this.iface.handleArp(frame.payload, frame.id, ctx, this.emit(ctx));
    else this.handleIp(frame.payload, frame.id, ctx);
  }

  private handleIp(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    if (pkt.payload.kind === "udp") {
      const udp = pkt.payload;
      const m = udp.payload;
      if (m.kind === "dhcp" && udp.dstPort === DHCP_CLIENT_PORT) {
        this.dhcp.handle(m, frameId, ctx, this.emit(ctx));
        return;
      }
      if (m.kind === "dhcp" && udp.dstPort === DHCP_SERVER_PORT) {
        if (!this.dhcpServer.config.enabled) ctx.trace("dhcp.ignore", "app", `다른 호스트의 DHCP ${m.op} 브로드캐스트 — 나는 서버가 아니므로 무시`, {}, frameId);
        else if (this.ipMode !== "static") ctx.trace("dhcp.misconfigured", "app", `DHCP 서버가 켜져 있지만 내 주소가 고정이 아님(자동) → 응답하지 않음. IP 설정을 수동으로 바꾸세요`, {}, frameId);
        else this.dhcpServer.handle(m, frameId, ctx, this.emit(ctx));
        return;
      }
      if (m.kind === "dns") {
        if (pkt.dst !== this.iface.ip) {
          ctx.trace("ip.drop", "L3", `목적지 IP ${pkt.dst} 가 내 IP 아님 → 폐기`, { dst: pkt.dst }, frameId);
          return;
        }
        if (udp.dstPort === this.resolver.port) this.resolver.handle(m, pkt.src, frameId, ctx);
        else if (udp.dstPort === DNS_PORT && (this.dnsServer.config.enabled || m.op === "response")) this.dnsServer.handle(pkt, udp.srcPort, m, frameId, ctx, this.emit(ctx));
        else ctx.trace("ip.drop", "L4", `DNS 질의를 받았지만 DNS 서버 서비스가 꺼져 있음 → 폐기 (서비스에서 DNS 서버를 켜세요)`, { port: udp.dstPort }, frameId);
        return;
      }
      ctx.trace("ip.drop", "L4", `UDP 포트 ${udp.dstPort} 를 듣는 프로그램 없음 → 폐기`, { port: udp.dstPort }, frameId);
      return;
    }
    if (pkt.dst !== this.iface.ip) {
      ctx.trace("ip.drop", "L3", `목적지 IP ${pkt.dst} 가 내 IP(${this.iface.ip ?? "없음"}) 아님 → 폐기 (호스트는 포워딩 안 함)`, { dst: pkt.dst }, frameId);
      return;
    }
    if (pkt.payload.kind === "tcp") {
      this.tcp.handle(pkt, pkt.payload, ctx);
      return;
    }
    this.handleIcmp(pkt, pkt.payload, frameId, ctx);
  }

  private handleIcmp(pkt: Ipv4Packet, icmp: IcmpPacket, frameId: number, ctx: NodeContext): void {
    if (icmp.type === "time-exceeded") {
      this.handleTimeExceeded(pkt, icmp, frameId, ctx);
      return;
    }
    if (icmp.type === "echo-request") {
      ctx.trace("icmp.echo.received", "app", `ICMP Echo 요청 수신 (from ${pkt.src}, seq=${icmp.seq})`, { from: pkt.src, seq: icmp.seq }, frameId);
      const reply: Ipv4Packet = {
        kind: "ipv4",
        src: this.iface.ip!,
        dst: pkt.src,
        ttl: 64,
        payload: { kind: "icmp", type: "echo-reply", id: icmp.id, seq: icmp.seq },
      };
      ctx.trace("icmp.reply.sent", "app", `ICMP Echo 응답 생성 → ${pkt.src} (seq=${icmp.seq})`, { to: pkt.src, seq: icmp.seq });
      this.iface.sendIp(reply, ctx, this.emit(ctx));
      return;
    }
    if (icmp.id === this.trId) {
      const a = this.activeTrace;
      if (a && a.seq === icmp.seq) this.finishTrace(a, pkt.src, ctx, frameId);
      else ctx.trace("ip.drop", "L3", `지난 traceroute 프로브(seq=${icmp.seq})의 Echo 응답 → 무시`, { seq: icmp.seq }, frameId);
      return;
    }
    const rec = icmp.id === this.icmpId ? this.pings.find((p) => p.seq === icmp.seq && p.status === "pending") : undefined;
    if (!rec) {
      ctx.trace("ip.drop", "L3", `내가 보낸 적 없는 Echo 응답 (id=${icmp.id}, seq=${icmp.seq}) → 무시`, {}, frameId);
      return;
    }
    this.finishPing(rec, "ok", { rtt: ctx.now - rec.sentAt });
    ctx.trace("icmp.reply.received", "app", `ping 성공: ${pkt.src} seq=${icmp.seq} RTT=${rec.rtt}ms`, { from: pkt.src, seq: icmp.seq, rtt: rec.rtt }, frameId);
  }

  // ---------- 타이머 ----------

  onTimer(tag: string, data: unknown, ctx: NodeContext): void {
    switch (tag) {
      case "arp-timeout": {
        const { ip: nextHop } = data as { ip: Ip };
        const dropped = this.iface.onArpTimeout(data, ctx);
        for (const pkt of dropped) {
          if (pkt.payload.kind !== "icmp" || pkt.payload.type !== "echo-request") continue;
          const icmp = pkt.payload;
          if (icmp.id === this.trId) {
            const a = this.activeTrace;
            if (a && a.seq === icmp.seq) this.failTrace(a.rec, "ARP 응답 없음", ctx, `첫 홉 ${nextHop} 이(가) 응답하지 않음 — 케이블과 게이트웨이 주소를 확인`);
            continue;
          }
          const rec = this.pings.find((p) => p.seq === icmp.seq && p.status === "pending");
          if (!rec) continue;
          this.finishPing(rec, "failed", { reason: "ARP 응답 없음" });
          ctx.trace("icmp.failed", "app", `ping ${rec.dst} 실패: 그 주소를 가진 장치가 응답하지 않음 (Destination Host Unreachable)`, { dst: rec.dst, seq: rec.seq });
        }
        return;
      }
      case "tr-timeout": {
        const { seq } = data as { seq: number };
        const a = this.activeTrace;
        if (!a || a.seq !== seq) return;
        a.timer = undefined;
        a.rec.hops.push({ ttl: a.ttl });
        ctx.trace("trace.timeout", "app", `traceroute ${a.rec.dst}: TTL=${a.ttl} 에 ${Host.TRACEROUTE_TIMEOUT}ms 동안 응답 없음 → ${a.ttl} 번째 홉 = * (다음 TTL 로 계속)`, { dst: a.rec.dst, ttl: a.ttl, seq });
        this.nextProbe(ctx);
        return;
      }
      case "ping-timeout": {
        const { seq } = data as { seq: number };
        this.pingTimers.delete(seq);
        const rec = this.pings.find((p) => p.seq === seq && p.status === "pending");
        if (!rec) return;
        this.finishPing(rec, "failed", { reason: "응답 시간 초과" });
        ctx.trace("icmp.timeout", "app", `ping ${rec.dst} 실패: ${Host.PING_TIMEOUT}ms 동안 응답 없음 (Request timed out)`, { dst: rec.dst, seq });
        return;
      }
      case DHCP_TIMER_TAG:
        this.dhcp.onTimeout(data, ctx, this.emit(ctx));
        return;
      case TCP_TIMER_TAG:
        this.tcp.onTimer(data, ctx);
        return;
      case DNS_TIMER_TAG:
        this.resolver.onTimeout(data, ctx, this.emit(ctx));
        return;
      case DNS_UPSTREAM_TIMER_TAG:
        this.dnsServer.onTimeout(data, ctx, this.emit(ctx));
        return;
    }
  }

  // ---------- 스냅샷 ----------

  snapshot(): NodeSnapshot {
    const i = this.iface;
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [
        ["MAC", i.mac],
        ["IP", i.ip ? `${i.ip}/${i.prefix}` : "없음"],
        ["게이트웨이", i.gateway ?? "없음"],
        ["DNS", i.dns ?? "없음"],
        ["링크", this.linkUp ? "연결됨" : "끊김"],
        ["IP 설정", this.ipMode === "dhcp" ? `자동 (DHCP: ${DHCP_STATE_LABEL[this.dhcp.state]})` : "수동"],
        ["TCP 서비스", this.tcp.listening.size ? [...this.tcp.listening].map((p) => `포트 ${p}`).join(", ") : "없음"],
        ...(this.dhcpServer.config.enabled
          ? [["DHCP 서버", `켜짐 · ${this.dhcpServer.config.start} ~ ${this.dhcpServer.config.end}`] as [string, string]]
          : []),
        ...(this.dnsServer.config.enabled
          ? [["DNS 서버", `켜짐 · 레코드 ${this.dnsServer.config.records.length}개${this.dnsServer.config.upstream ? ` · 상위 ${this.dnsServer.config.upstream}` : ""}`] as [string, string]]
          : []),
      ],
      tables: [
        ...(this.dhcpServer.config.enabled ? [{ title: "DHCP 임대", columns: ["IP", "MAC", "시각"], rows: this.dhcpServer.rows() }] : []),
        ...(this.dnsServer.config.enabled ? [{ title: "DNS 레코드·캐시", columns: ["이름", "IP", "출처"], rows: this.dnsServer.rows() }] : []),
        ...(this.resolver.cache.size > 0 ? [{ title: "DNS 캐시 (리졸버)", columns: ["이름", "IP", "시각"], rows: this.resolver.rows() }] : []),
        { title: "TCP 연결", columns: ["상대", "상태", "보냄 / 받음"], rows: this.tcp.rows() },
        { title: "ARP 캐시", columns: ["IP", "MAC", "학습 시각"], rows: i.arpRows() },
      ],
    };
  }
}

function isValidIp(s: string): boolean {
  try {
    ipToInt(s);
    return true;
  } catch {
    return false;
  }
}

export function hashCode(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}
