import { intToIp, prefixToMask, type Ip, type Mac } from "../addr";
import {
  DHCP_CLIENT_PORT,
  DHCP_SERVER_PORT,
  describeFrame,
  LIMITED_BROADCAST_IP,
  UNSPECIFIED_IP,
  type DhcpMessage,
  type EthernetFrame,
  type IcmpPacket,
  type Ipv4Packet,
} from "../packet";
import { NetInterface } from "./iface";
import type { NodeContext, NodeSnapshot, SimNode, TimerHandle } from "./node";

export type IpMode = "dhcp" | "static";

export interface HostConfig {
  id: string;
  mac: Mac;
  ipMode?: IpMode;
  ip?: Ip;
  prefix?: number;
  gateway?: Ip;
}

export type DhcpState = "idle" | "discovering" | "requesting" | "bound" | "failed";

interface DhcpClient {
  state: DhcpState;
  xid: number;
  attempts: number;
  serverId?: Ip;
  offered?: Ip;
  prefix?: number;
  router?: Ip;
}

export interface PingRecord {
  dst: Ip;
  seq: number;
  sentAt: number;
  status: "pending" | "ok" | "failed";
  rtt?: number;
  reason?: string;
}

export const DHCP_STATE_LABEL: Record<DhcpState, string> = {
  idle: "대기",
  discovering: "서버 찾는 중",
  requesting: "주소 요청 중",
  bound: "주소 받음",
  failed: "실패",
};

/** 단말 호스트: 인터페이스 1개, DHCP 클라이언트, ICMP ping */
export class Host implements SimNode {
  static readonly DHCP_TIMEOUT = 1000;
  static readonly DHCP_MAX_ATTEMPTS = 3;
  static readonly PING_TIMEOUT = 2000;

  readonly type = "host" as const;
  readonly portCount = 1;
  readonly id: string;
  readonly iface: NetInterface;
  ipMode: IpMode;
  linkUp = false;
  dhcp: DhcpClient = { state: "idle", xid: 0, attempts: 0 };
  readonly pings: PingRecord[] = [];

  private readonly icmpId: number;
  private icmpSeq = 0;
  private xidSeq = 0;
  private dhcpTimer: TimerHandle | undefined;
  private readonly pingTimers = new Map<number, TimerHandle>();

  constructor(cfg: HostConfig) {
    this.id = cfg.id;
    this.ipMode = cfg.ipMode ?? (cfg.ip ? "static" : "dhcp");
    this.iface = new NetInterface(cfg.mac, this.ipMode === "static" ? { ip: cfg.ip, prefix: cfg.prefix, gateway: cfg.gateway } : { prefix: cfg.prefix });
    this.icmpId = 0x1000 + (Math.abs(hashCode(cfg.id)) % 0x1000);
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

  configure(cfg: { ipMode: IpMode; ip?: Ip; prefix?: number; gateway?: Ip }, ctx: NodeContext): void {
    this.ipMode = cfg.ipMode;
    if (cfg.ipMode === "static") {
      this.stopDhcp();
      this.iface.configure(cfg.ip || undefined, cfg.prefix ?? 24, cfg.gateway || undefined);
      ctx.trace(
        "ip.config",
        "sys",
        cfg.ip ? `수동 설정 적용: ${cfg.ip}/${cfg.prefix ?? 24}${cfg.gateway ? `, 게이트웨이 ${cfg.gateway}` : ", 게이트웨이 없음"}` : "수동 설정으로 전환 (IP 주소 미입력)",
        { ...cfg },
      );
      return;
    }
    this.iface.clearAddress();
    this.iface.prefix = 24;
    ctx.trace("ip.config", "sys", `자동(DHCP) 로 전환 → 기존 주소 지움`, { ...cfg });
    if (this.linkUp) this.startDhcp(ctx);
    else this.stopDhcp();
  }

  onLink(_port: number, up: boolean, ctx: NodeContext): void {
    this.linkUp = up;
    if (up) {
      ctx.trace("link.up", "L1", `링크 연결됨`);
      if (this.ipMode === "dhcp") this.startDhcp(ctx);
      return;
    }
    ctx.trace("link.down", "L1", `링크 끊김`);
    this.iface.clearPending();
    if (this.ipMode === "dhcp") {
      const had = this.iface.ip;
      this.iface.clearAddress();
      this.stopDhcp();
      if (had) ctx.trace("dhcp.release", "app", `링크가 끊겨 임대 주소 ${had} 해제 → 주소 없음`, { ip: had });
    }
  }

  // ---------- 사용자 동작 ----------

  ping(dst: Ip, ctx: NodeContext): void {
    const seq = ++this.icmpSeq;
    const rec: PingRecord = { dst, seq, sentAt: ctx.now, status: "pending" };
    this.pings.push(rec);
    if (!this.iface.ip) {
      rec.status = "failed";
      rec.reason = "IP 주소 없음";
      ctx.trace("ip.no-address", "L3", `ping ${dst} 실패: 내 IP 주소가 없음 (DHCP 로 받거나 수동 설정 필요)`, { dst });
      return;
    }
    const pkt: Ipv4Packet = {
      kind: "ipv4",
      src: this.iface.ip,
      dst,
      ttl: 64,
      payload: { kind: "icmp", type: "echo-request", id: this.icmpId, seq },
    };
    ctx.trace("icmp.echo.sent", "app", `ping ${dst} (seq=${seq}) → ICMP Echo 요청 생성`, { dst, seq });
    this.iface.sendIp(pkt, ctx, (f) => ctx.send(0, f));
    this.pingTimers.set(seq, ctx.timer(Host.PING_TIMEOUT, "ping-timeout", { seq }));
  }

  private finishPing(rec: PingRecord, status: "ok" | "failed", extra: { rtt?: number; reason?: string }): void {
    rec.status = status;
    if (extra.rtt !== undefined) rec.rtt = extra.rtt;
    if (extra.reason) rec.reason = extra.reason;
    this.pingTimers.get(rec.seq)?.cancel();
    this.pingTimers.delete(rec.seq);
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
    this.startDhcp(ctx);
  }

  // ---------- DHCP 클라이언트 ----------

  private startDhcp(ctx: NodeContext): void {
    this.iface.clearAddress();
    this.dhcpTimer?.cancel();
    this.dhcp = { state: "discovering", xid: 0x1000 + ((hashCode(this.id) + ++this.xidSeq) & 0xffff), attempts: 1 };
    this.sendDiscover(ctx);
  }

  private stopDhcp(): void {
    this.dhcpTimer?.cancel();
    this.dhcpTimer = undefined;
    this.dhcp = { state: "idle", xid: 0, attempts: 0 };
  }

  private sendDiscover(ctx: NodeContext): void {
    const d = this.dhcp;
    const msg: DhcpMessage = { kind: "dhcp", op: "discover", xid: d.xid, clientMac: this.iface.mac };
    ctx.trace(
      "dhcp.discover.sent",
      "app",
      `DHCP Discover 브로드캐스트 (시도 ${d.attempts}/${Host.DHCP_MAX_ATTEMPTS}): "IP 주소를 줄 서버 있나요?" (아직 IP 없음, 출발지 0.0.0.0)`,
      { xid: d.xid, attempt: d.attempts },
    );
    this.iface.sendBroadcast(this.dhcpPacket(msg), ctx, (f) => ctx.send(0, f));
    this.dhcpTimer?.cancel();
    this.dhcpTimer = ctx.timer(Host.DHCP_TIMEOUT, "dhcp-timeout", { xid: d.xid });
  }

  private dhcpPacket(msg: DhcpMessage): Ipv4Packet {
    return {
      kind: "ipv4",
      src: UNSPECIFIED_IP,
      dst: LIMITED_BROADCAST_IP,
      ttl: 64,
      payload: { kind: "udp", srcPort: DHCP_CLIENT_PORT, dstPort: DHCP_SERVER_PORT, payload: msg },
    };
  }

  private handleDhcp(msg: DhcpMessage, frameId: number, ctx: NodeContext): void {
    const d = this.dhcp;
    if (msg.xid !== d.xid) {
      ctx.trace("dhcp.ignore", "app", `DHCP ${msg.op} 의 xid 가 내 요청과 다름 → 무시`, { xid: msg.xid }, frameId);
      return;
    }
    switch (msg.op) {
      case "offer": {
        if (d.state !== "discovering") {
          ctx.trace("dhcp.ignore", "app", `이미 ${DHCP_STATE_LABEL[d.state]} 상태라 Offer 무시`, {}, frameId);
          return;
        }
        d.state = "requesting";
        d.offered = msg.yiaddr;
        d.serverId = msg.serverId;
        d.prefix = msg.options?.prefix ?? 24;
        d.router = msg.options?.router;
        ctx.trace(
          "dhcp.offer.received",
          "app",
          `DHCP Offer 수신: 서버 ${msg.serverId} 가 ${msg.yiaddr}/${d.prefix} 제안 (게이트웨이 ${d.router ?? "없음"})`,
          { ...msg },
          frameId,
        );
        const req: DhcpMessage = { kind: "dhcp", op: "request", xid: d.xid, clientMac: this.iface.mac, requestedIp: msg.yiaddr, serverId: msg.serverId };
        ctx.trace("dhcp.request.sent", "app", `DHCP Request 브로드캐스트: "${msg.yiaddr} 를 서버 ${msg.serverId} 에게서 받겠습니다"`, { ...req });
        this.iface.sendBroadcast(this.dhcpPacket(req), ctx, (f) => ctx.send(0, f));
        this.dhcpTimer?.cancel();
        this.dhcpTimer = ctx.timer(Host.DHCP_TIMEOUT, "dhcp-timeout", { xid: d.xid });
        return;
      }
      case "ack": {
        if (d.state !== "requesting") {
          ctx.trace("dhcp.ignore", "app", `요청 중이 아닌데 Ack 수신 → 무시`, {}, frameId);
          return;
        }
        const prefix = msg.options?.prefix ?? d.prefix ?? 24;
        const router = msg.options?.router ?? d.router;
        this.iface.configure(msg.yiaddr, prefix, router);
        d.state = "bound";
        this.dhcpTimer?.cancel();
        this.dhcpTimer = undefined;
        ctx.trace("dhcp.ack.received", "app", `DHCP Ack 수신: 서버 ${msg.serverId} 가 ${msg.yiaddr} 확정`, { ...msg }, frameId);
        ctx.trace(
          "dhcp.bound",
          "app",
          `IP 획득: ${msg.yiaddr}/${prefix} (서브넷 마스크 ${intToIp(prefixToMask(prefix))}), 게이트웨이 ${router ?? "없음"}`,
          { ip: msg.yiaddr, prefix, router },
        );
        return;
      }
      case "nak": {
        ctx.trace("dhcp.nak.received", "app", `DHCP Nak 수신: 서버가 요청을 거부 → 처음부터 다시 시도`, { ...msg }, frameId);
        this.startDhcp(ctx);
        return;
      }
      default:
        ctx.trace("dhcp.ignore", "app", `클라이언트가 처리하지 않는 DHCP ${msg.op} → 무시`, {}, frameId);
    }
  }

  // ---------- 수신 ----------

  receive(_port: number, frame: EthernetFrame, ctx: NodeContext): void {
    if (!this.iface.accepts(frame)) {
      ctx.trace("frame.drop", "L2", `목적지 MAC ${frame.dst} 가 내 MAC(${this.iface.mac}) 아님 → 폐기`, { dst: frame.dst }, frame.id);
      return;
    }
    ctx.trace("frame.receive", "L2", `프레임 수신: ${describeFrame(frame)} [${frame.src} → ${frame.dst === this.iface.mac ? "내 MAC" : "브로드캐스트"}]`, { src: frame.src, dst: frame.dst }, frame.id);
    if (frame.payload.kind === "arp") this.iface.handleArp(frame.payload, frame.id, ctx, (f) => ctx.send(0, f));
    else this.handleIp(frame.payload, frame.id, ctx);
  }

  private handleIp(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    if (pkt.payload.kind === "udp") {
      const udp = pkt.payload;
      if (udp.dstPort === DHCP_CLIENT_PORT) {
        this.handleDhcp(udp.payload, frameId, ctx);
        return;
      }
      if (udp.dstPort === DHCP_SERVER_PORT) {
        ctx.trace("dhcp.ignore", "app", `다른 호스트의 DHCP ${udp.payload.op} 브로드캐스트 — 나는 서버가 아니므로 무시`, {}, frameId);
        return;
      }
      ctx.trace("ip.drop", "L4", `UDP 포트 ${udp.dstPort} 를 듣는 프로그램 없음 → 폐기`, { port: udp.dstPort }, frameId);
      return;
    }
    if (pkt.dst !== this.iface.ip) {
      ctx.trace("ip.drop", "L3", `목적지 IP ${pkt.dst} 가 내 IP(${this.iface.ip ?? "없음"}) 아님 → 폐기 (호스트는 포워딩 안 함)`, { dst: pkt.dst }, frameId);
      return;
    }
    this.handleIcmp(pkt, pkt.payload, frameId, ctx);
  }

  private handleIcmp(pkt: Ipv4Packet, icmp: IcmpPacket, frameId: number, ctx: NodeContext): void {
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
      this.iface.sendIp(reply, ctx, (f) => ctx.send(0, f));
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
        const dropped = this.iface.onArpTimeout(data, ctx);
        for (const pkt of dropped) {
          if (pkt.payload.kind !== "icmp" || pkt.payload.type !== "echo-request") continue;
          const rec = this.pings.find((p) => p.seq === (pkt.payload as IcmpPacket).seq && p.status === "pending");
          if (!rec) continue;
          this.finishPing(rec, "failed", { reason: "ARP 응답 없음" });
          ctx.trace("icmp.failed", "app", `ping ${rec.dst} 실패: 그 주소를 가진 장치가 응답하지 않음 (Destination Host Unreachable)`, { dst: rec.dst, seq: rec.seq });
        }
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
      case "dhcp-timeout": {
        const { xid } = data as { xid: number };
        const d = this.dhcp;
        this.dhcpTimer = undefined;
        if (xid !== d.xid || (d.state !== "discovering" && d.state !== "requesting")) return;
        if (d.attempts < Host.DHCP_MAX_ATTEMPTS) {
          d.attempts += 1;
          d.state = "discovering";
          ctx.trace("dhcp.timeout", "app", `DHCP 응답 없음 (${Host.DHCP_TIMEOUT}ms) → 재시도 ${d.attempts}/${Host.DHCP_MAX_ATTEMPTS}`, { attempt: d.attempts });
          this.sendDiscover(ctx);
          return;
        }
        d.state = "failed";
        this.iface.clearAddress();
        ctx.trace(
          "dhcp.failed",
          "app",
          `DHCP 실패: 서버 응답 없음 (${Host.DHCP_MAX_ATTEMPTS}회 시도) → 주소 없음. 라우터의 DHCP 서비스를 켜거나 IP 를 수동 설정하세요`,
          {},
        );
        return;
      }
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
        ["링크", this.linkUp ? "연결됨" : "끊김"],
        ["IP 설정", this.ipMode === "dhcp" ? `자동 (DHCP: ${DHCP_STATE_LABEL[this.dhcp.state]})` : "수동"],
      ],
      tables: [{ title: "ARP 캐시", columns: ["IP", "MAC", "학습 시각"], rows: i.arpRows() }],
    };
  }
}

function hashCode(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}
