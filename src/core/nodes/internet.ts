import { isPrivateIp, type Ip, type Mac } from "../addr";
import { DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DNS_PORT, describeFrame, type DnsMessage, type EthernetFrame, type Ipv4Packet } from "../packet";
import { DhcpServer } from "./dhcp";
import { normalizeName, PUBLIC_ZONE } from "./dns";
import { NetInterface, type Emit } from "./iface";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";
import { TCP_TIMER_TAG, TcpStack } from "./tcp";

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
  ...Object.fromEntries(PUBLIC_ZONE.map((r) => [r.ip, r.name])),
};

/** 공인 DNS 서버 주소 (이 주소들로 온 질의에 PUBLIC_ZONE 으로 답한다) */
export const PUBLIC_DNS: Ip[] = ["8.8.8.8", "1.1.1.1"];

/**
 * 인터넷(ISP) 노드. 포트 하나로 라우터 WAN 과 연결된다.
 * ISP 게이트웨이 역할(공인 주소 DHCP 임대)과 "인터넷 저편의 서버" 역할(공인 주소로 온 ping 에 응답)을 함께 한다.
 */
export class Internet implements SimNode {
  /** 인터넷 왕복에 걸리는 시간 (경로 생략) */
  static readonly LATENCY = 30;
  /** "인터넷 저편의 클라이언트" 주소 (RFC 5737 TEST-NET-2). 바깥에서 시작하는 연결의 출발지 */
  static readonly REMOTE_CLIENT: Ip = "198.51.100.7";

  readonly type = "internet" as const;
  readonly portCount = 1;
  readonly id: string;
  readonly iface: NetInterface;
  readonly dhcpServer: DhcpServer;
  /** 인터넷 저편의 웹 서버들을 대신하는 TCP 스택 (응답은 왕복 지연 뒤에 나간다) */
  readonly tcp: TcpStack;

  constructor(cfg: InternetConfig) {
    this.id = cfg.id;
    this.iface = new NetInterface(cfg.mac, { ip: cfg.ip ?? "203.0.113.1", prefix: cfg.prefix ?? 24 });
    this.dhcpServer = new DhcpServer({ enabled: true, ...(cfg.pool ?? { start: "203.0.113.100", end: "203.0.113.199" }) }, this.iface);
    this.tcp = new TcpStack({ send: (pkt, ctx) => ctx.timer(Internet.LATENCY * 2, "inet-send", { pkt }) });
    this.tcp.listening.add(80);
  }

  private emit(ctx: NodeContext): Emit {
    return (f) => ctx.send(0, f);
  }

  /** 인터넷 저편의 클라이언트가 dst:port 로 TCP 연결을 시작한다 (포트 포워딩 시연용) */
  connectFrom(dst: Ip, port: number, ctx: NodeContext): void {
    const src = Internet.REMOTE_CLIENT;
    if (isPrivateIp(dst)) {
      ctx.trace("ip.drop", "L3", `인터넷 저편의 클라이언트 ${src} 가 ${dst}:${port} 로 연결 시도 — 사설 주소는 인터넷에서 라우팅되지 않아 보낼 수 없음 (공인 주소 + 포트 포워딩이 필요함)`, { src, dst, port });
      this.tcp.recordFailure(src, dst, port, "사설 주소는 인터넷에서 닿을 수 없음", ctx);
      return;
    }
    ctx.trace("inet.forward", "app", `인터넷 저편의 클라이언트 ${src} 가 ${dst}:${port} 로 연결 시도 (바깥에서 시작한 통신)`, { src, dst, port });
    this.tcp.connect(src, dst, port, ctx);
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
      const m = udp.payload;
      if (m.kind === "dhcp" && udp.dstPort === DHCP_SERVER_PORT) this.dhcpServer.handle(m, frameId, ctx, emit);
      else if (m.kind === "dhcp" && udp.dstPort === DHCP_CLIENT_PORT) ctx.trace("dhcp.ignore", "app", `DHCP 클라이언트 메시지는 내 것이 아님 → 무시`, {}, frameId);
      else if (m.kind === "dns" && udp.dstPort === DNS_PORT && m.op === "query") this.handleDns(pkt, udp.srcPort, m, frameId, ctx);
      else if (m.kind === "dns") ctx.trace("ip.drop", "L4", `공인 DNS 가 아닌 주소로 온 DNS 응답 → 폐기`, {}, frameId);
      else ctx.trace("ip.drop", "L4", `UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 폐기`, { port: udp.dstPort }, frameId);
      return;
    }
    const p = pkt.payload;
    if (pkt.dst === this.iface.ip) {
      if (p.kind === "tcp") {
        ctx.trace("ip.drop", "L4", `ISP 게이트웨이는 TCP 서비스를 열지 않음 → 폐기`, {}, frameId);
        return;
      }
      if (p.type !== "echo-request") {
        ctx.trace("ip.drop", "L3", `요청한 적 없는 Echo 응답 → 무시`, {}, frameId);
        return;
      }
      ctx.trace("icmp.echo.received", "app", `ISP 게이트웨이가 ICMP Echo 요청 수신 (from ${pkt.src})`, { from: pkt.src }, frameId);
      const reply: Ipv4Packet = { kind: "ipv4", src: this.iface.ip, dst: pkt.src, ttl: 64, payload: { ...p, type: "echo-reply" } };
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
    const name = KNOWN_SERVERS[pkt.dst];
    if (p.kind === "tcp") {
      const who = pkt.dst === Internet.REMOTE_CLIENT ? "클라이언트" : "서버";
      ctx.trace("inet.forward", "app", `인터넷 경로로 ${pkt.dst}${name ? ` (${name})` : ""}:${p.dstPort} 에 전달 — 중간 라우터 생략, ${who} 응답은 ${Internet.LATENCY * 2}ms 뒤 도착`, { dst: pkt.dst, src: pkt.src }, frameId);
      this.tcp.handle(pkt, p, ctx);
      return;
    }
    if (p.type !== "echo-request") {
      ctx.trace("ip.drop", "L3", `공인 주소 ${pkt.dst} 로 가는 Echo 응답 → 시뮬레이션 밖이므로 폐기`, {}, frameId);
      return;
    }
    ctx.trace(
      "inet.forward",
      "app",
      `인터넷 경로로 ${pkt.dst}${name ? ` (${name})` : ""} 에 전달 — 중간 라우터들은 생략, 왕복 ${Internet.LATENCY * 2}ms`,
      { dst: pkt.dst, src: pkt.src },
      frameId,
    );
    ctx.timer(Internet.LATENCY * 2, "inet-reply", { src: pkt.src, dst: pkt.dst, id: p.id, seq: p.seq });
  }

  /** 공인 DNS(8.8.8.8, 1.1.1.1): 공개 이름들에 답한다. 다른 공인 주소로 온 질의는 그 주소에 DNS 가 없다고 본다 */
  private handleDns(pkt: Ipv4Packet, srcPort: number, msg: DnsMessage, frameId: number, ctx: NodeContext): void {
    if (isPrivateIp(pkt.src)) {
      ctx.trace("ip.drop", "L3", `출발지가 사설 주소 ${pkt.src} 인 DNS 질의 → 응답을 돌려줄 수 없어 폐기 (NAT 필요)`, { src: pkt.src }, frameId);
      return;
    }
    if (!PUBLIC_DNS.includes(pkt.dst)) {
      ctx.trace("ip.drop", "L4", `${pkt.dst} 에는 DNS 서비스가 없음 → 폐기 (공인 DNS 는 ${PUBLIC_DNS.join(", ")})`, { dst: pkt.dst }, frameId);
      return;
    }
    const name = normalizeName(msg.name);
    ctx.trace("dns.query.received", "app", `공인 DNS ${pkt.dst}: 질의 수신 "${name}?" (from ${pkt.src}) — 답은 ${Internet.LATENCY * 2}ms 뒤`, { name, from: pkt.src }, frameId);
    ctx.timer(Internet.LATENCY * 2, "inet-dns", { server: pkt.dst, to: pkt.src, toPort: srcPort, id: msg.id, name: msg.name });
  }

  onTimer(tag: string, data: unknown, ctx: NodeContext): void {
    if (tag === "arp-timeout") {
      this.iface.onArpTimeout(data, ctx);
      return;
    }
    if (tag === "inet-dns") {
      const { server, to, toPort, id, name } = data as { server: Ip; to: Ip; toPort: number; id: number; name: string };
      const rec = PUBLIC_ZONE.find((r) => r.name === normalizeName(name));
      const msg: DnsMessage = rec ? { kind: "dns", id, op: "response", name, answer: rec.ip } : { kind: "dns", id, op: "response", name, rcode: "NXDOMAIN" };
      if (rec) ctx.trace("dns.response.sent", "app", `공인 DNS ${server}: ${normalizeName(name)} = ${rec.ip} 응답 → ${to}`, { name, ip: rec.ip });
      else ctx.trace("dns.nxdomain", "app", `공인 DNS ${server}: ${normalizeName(name)} 은(는) 등록되지 않은 이름 → NXDOMAIN (아는 이름: ${PUBLIC_ZONE.map((r) => r.name).join(", ")})`, { name });
      const reply: Ipv4Packet = { kind: "ipv4", src: server, dst: to, ttl: 54, payload: { kind: "udp", srcPort: DNS_PORT, dstPort: toPort, payload: msg } };
      this.iface.sendIp(reply, ctx, this.emit(ctx));
      return;
    }
    if (tag === TCP_TIMER_TAG) {
      this.tcp.onTimer(data, ctx);
      return;
    }
    if (tag === "inet-send") {
      const { pkt } = data as { pkt: Ipv4Packet };
      this.iface.sendIp({ ...pkt, ttl: 54 }, ctx, this.emit(ctx));
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
        ["외부 클라이언트", Internet.REMOTE_CLIENT],
      ],
      tables: [
        { title: "웹 서버 연결 (포트 80)", columns: ["상대", "상태", "보냄 / 받음"], rows: this.tcp.rows() },
        { title: "공인 주소 임대", columns: ["IP", "MAC", "시각"], rows: this.dhcpServer.rows() },
        { title: "ARP 캐시", columns: ["IP", "MAC", "학습 시각"], rows: this.iface.arpRows() },
        { title: "알려진 서버", columns: ["IP", "이름"], rows: Object.entries(KNOWN_SERVERS) },
      ],
    };
  }
}
