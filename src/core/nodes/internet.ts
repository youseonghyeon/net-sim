import { isPrivateIp, type Ip, type Mac } from "../addr";
import { DHCP_CLIENT_PORT, DHCP_SERVER_PORT, describeFrame, type EthernetFrame, type Ipv4Packet } from "../packet";
import { DhcpServer } from "./dhcp";
import { NetInterface, type Emit } from "./iface";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";

export interface InternetConfig {
  id: string;
  mac: Mac;
  ip?: Ip;
  prefix?: number;
  pool?: { start: Ip; end: Ip };
}

/** 이름이 알려진 공인 서버 (ping 대상 제안용) */
export const KNOWN_SERVERS: Record<Ip, string> = {
  "8.8.8.8": "Google DNS",
  "1.1.1.1": "Cloudflare DNS",
  "93.184.216.34": "example.com",
};

/**
 * 인터넷(ISP) 노드. 포트 하나로 라우터 WAN 과 연결된다.
 * ISP 게이트웨이 역할(공인 주소 DHCP 임대)과 "인터넷 저편의 서버" 역할(공인 주소로 온 ping 에 응답)을 함께 한다.
 */
export class Internet implements SimNode {
  /** 인터넷 왕복에 걸리는 시간 (경로 생략) */
  static readonly LATENCY = 30;

  readonly type = "internet" as const;
  readonly portCount = 1;
  readonly id: string;
  readonly iface: NetInterface;
  readonly dhcpServer: DhcpServer;

  constructor(cfg: InternetConfig) {
    this.id = cfg.id;
    this.iface = new NetInterface(cfg.mac, { ip: cfg.ip ?? "203.0.113.1", prefix: cfg.prefix ?? 24 });
    this.dhcpServer = new DhcpServer({ enabled: true, ...(cfg.pool ?? { start: "203.0.113.100", end: "203.0.113.199" }) }, this.iface);
  }

  private emit(ctx: NodeContext): Emit {
    return (f) => ctx.send(0, f);
  }

  onLink(_port: number, up: boolean, ctx: NodeContext): void {
    ctx.trace(up ? "link.up" : "link.down", "L1", up ? `ISP 회선 연결됨` : `ISP 회선 끊김`);
    if (!up) this.iface.clearPending();
  }

  receive(_port: number, frame: EthernetFrame, ctx: NodeContext): void {
    if (!this.iface.accepts(frame)) {
      ctx.trace("frame.drop", "L2", `목적지 MAC ${frame.dst} 가 ISP 게이트웨이 MAC 아님 → 폐기`, { dst: frame.dst }, frame.id);
      return;
    }
    ctx.trace("frame.receive", "L2", `프레임 수신: ${describeFrame(frame)} [${frame.src}]`, { src: frame.src, dst: frame.dst }, frame.id);
    if (frame.payload.kind === "arp") {
      this.iface.handleArp(frame.payload, frame.id, ctx, this.emit(ctx));
      return;
    }
    this.handleIp(frame.payload, frame.id, ctx);
  }

  private handleIp(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const emit = this.emit(ctx);
    if (pkt.payload.kind === "udp") {
      const udp = pkt.payload;
      if (udp.dstPort === DHCP_SERVER_PORT) this.dhcpServer.handle(udp.payload, frameId, ctx, emit);
      else if (udp.dstPort === DHCP_CLIENT_PORT) ctx.trace("dhcp.ignore", "app", `DHCP 클라이언트 메시지는 내 것이 아님 → 무시`, {}, frameId);
      else ctx.trace("ip.drop", "L4", `UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 폐기`, { port: udp.dstPort }, frameId);
      return;
    }
    const icmp = pkt.payload;
    if (pkt.dst === this.iface.ip) {
      if (icmp.type !== "echo-request") {
        ctx.trace("ip.drop", "L3", `요청한 적 없는 Echo 응답 → 무시`, {}, frameId);
        return;
      }
      ctx.trace("icmp.echo.received", "app", `ISP 게이트웨이가 ICMP Echo 요청 수신 (from ${pkt.src})`, { from: pkt.src }, frameId);
      const reply: Ipv4Packet = { kind: "ipv4", src: this.iface.ip, dst: pkt.src, ttl: 64, payload: { ...icmp, type: "echo-reply" } };
      ctx.trace("icmp.reply.sent", "app", `ICMP Echo 응답 생성 → ${pkt.src}`, { to: pkt.src });
      this.iface.sendIp(reply, ctx, emit);
      return;
    }
    if (isPrivateIp(pkt.dst)) {
      ctx.trace("ip.drop", "L3", `사설 주소 ${pkt.dst} 는 인터넷에서 라우팅되지 않음 → 폐기 (그래서 NAT 가 필요함)`, { dst: pkt.dst }, frameId);
      return;
    }
    if (isPrivateIp(pkt.src)) {
      ctx.trace("ip.drop", "L3", `출발지가 사설 주소 ${pkt.src} → 응답을 돌려줄 수 없어 폐기 (NAT 가 공인 주소로 바꿔야 함)`, { src: pkt.src }, frameId);
      return;
    }
    if (icmp.type !== "echo-request") {
      ctx.trace("ip.drop", "L3", `공인 주소 ${pkt.dst} 로 가는 Echo 응답 → 시뮬레이션 밖이므로 폐기`, {}, frameId);
      return;
    }
    const name = KNOWN_SERVERS[pkt.dst];
    ctx.trace(
      "inet.forward",
      "app",
      `인터넷 경로로 ${pkt.dst}${name ? ` (${name})` : ""} 에 전달 — 중간 라우터들은 생략, 왕복 ${Internet.LATENCY * 2}ms`,
      { dst: pkt.dst, src: pkt.src },
      frameId,
    );
    ctx.timer(Internet.LATENCY * 2, "inet-reply", { src: pkt.src, dst: pkt.dst, id: icmp.id, seq: icmp.seq });
  }

  onTimer(tag: string, data: unknown, ctx: NodeContext): void {
    if (tag === "arp-timeout") {
      this.iface.onArpTimeout(data, ctx);
      return;
    }
    if (tag !== "inet-reply") return;
    const { src, dst, id, seq } = data as { src: Ip; dst: Ip; id: number; seq: number };
    const name = KNOWN_SERVERS[dst];
    ctx.trace("inet.reply", "app", `${dst}${name ? ` (${name})` : ""} 가 응답 → ${src} 로 회신 (TTL 54: 중간 라우터 10개를 지났다고 가정)`, { from: dst, to: src, seq });
    const reply: Ipv4Packet = { kind: "ipv4", src: dst, dst: src, ttl: 54, payload: { kind: "icmp", type: "echo-reply", id, seq } };
    this.iface.sendIp(reply, ctx, this.emit(ctx));
  }

  snapshot(): NodeSnapshot {
    const pool = this.dhcpServer.config;
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [
        ["ISP 게이트웨이", `${this.iface.ip}/${this.iface.prefix}`],
        ["공인 주소 임대", `${pool.start} ~ ${pool.end}`],
      ],
      tables: [
        { title: "공인 주소 임대", columns: ["IP", "MAC", "시각"], rows: this.dhcpServer.rows() },
        { title: "ARP 캐시", columns: ["IP", "MAC", "학습 시각"], rows: this.iface.arpRows() },
        { title: "알려진 서버", columns: ["IP", "이름"], rows: Object.entries(KNOWN_SERVERS) },
      ],
    };
  }
}
