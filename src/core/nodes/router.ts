import { BROADCAST_MAC, intToIp, ipToInt, type Ip, type Mac } from "../addr";
import { DHCP_CLIENT_PORT, DHCP_SERVER_PORT, describeFrame, type DhcpMessage, type EthernetFrame, type IcmpPacket, type Ipv4Packet } from "../packet";
import { NetInterface } from "./iface";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";

export interface DhcpServerConfig {
  enabled: boolean;
  start: Ip;
  end: Ip;
}

export interface RouterConfig {
  id: string;
  mac: Mac;
  lanIp: Ip;
  lanPrefix?: number;
  dhcp: DhcpServerConfig;
}

interface MacEntry {
  port: number;
  learnedAt: number;
}

interface Lease {
  mac: Mac;
  at: number;
}

/**
 * 가정용 라우터: LAN 포트 4개는 내부 스위치로 브리지되고, LAN 인터페이스 하나(MAC/IP)가 그 스위치에 붙어 있다.
 * DHCP 서버를 켜고 끌 수 있다. WAN 포트(0번)는 아직 외부망 미지원.
 */
export class Router implements SimNode {
  static readonly WAN_PORT = 0;
  static readonly LAN_PORTS = [1, 2, 3, 4];
  static readonly LEASE_TIME = 86_400;

  readonly type = "router" as const;
  readonly portCount = 5;
  readonly id: string;
  readonly lan: NetInterface;
  dhcp: DhcpServerConfig;
  readonly macTable = new Map<Mac, MacEntry>();
  readonly leases = new Map<Ip, Lease>();
  private readonly offers = new Map<Mac, Ip>();

  constructor(cfg: RouterConfig) {
    this.id = cfg.id;
    this.lan = new NetInterface(cfg.mac, { ip: cfg.lanIp, prefix: cfg.lanPrefix ?? 24 });
    this.dhcp = { ...cfg.dhcp };
  }

  // ---------- 설정 변경 ----------

  configure(cfg: { lanIp: Ip; lanPrefix: number; dhcp: DhcpServerConfig }, ctx: NodeContext): void {
    if (cfg.lanIp !== this.lan.ip || cfg.lanPrefix !== this.lan.prefix) {
      this.lan.configure(cfg.lanIp, cfg.lanPrefix, undefined);
      ctx.trace("ip.config", "sys", `LAN 인터페이스 주소 변경: ${cfg.lanIp}/${cfg.lanPrefix}`, { ...cfg });
    }
    if (cfg.dhcp.enabled !== this.dhcp.enabled) {
      ctx.trace(
        "ip.config",
        "sys",
        cfg.dhcp.enabled ? `DHCP 서비스 켜짐 (범위 ${cfg.dhcp.start} ~ ${cfg.dhcp.end})` : `DHCP 서비스 꺼짐 → 이후 Discover 에 응답하지 않음`,
        { ...cfg.dhcp },
      );
    } else if (cfg.dhcp.start !== this.dhcp.start || cfg.dhcp.end !== this.dhcp.end) {
      ctx.trace("ip.config", "sys", `DHCP 범위 변경: ${cfg.dhcp.start} ~ ${cfg.dhcp.end}`, { ...cfg.dhcp });
    }
    this.dhcp = { ...cfg.dhcp };
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    const name = port === Router.WAN_PORT ? "wan" : `lan${port}`;
    if (up) {
      ctx.trace("link.up", "L1", `${name} 포트 링크 연결됨`, { port });
      return;
    }
    ctx.trace("link.down", "L1", `${name} 포트 링크 끊김`, { port });
    for (const [mac, e] of this.macTable) if (e.port === port) this.macTable.delete(mac);
  }

  // ---------- 수신: LAN 브리지 ----------

  receive(port: number, frame: EthernetFrame, ctx: NodeContext): void {
    if (port === Router.WAN_PORT) {
      ctx.trace("frame.drop", "L2", `wan 포트 수신: ${describeFrame(frame)} — 외부망은 아직 지원하지 않아 폐기`, { port }, frame.id);
      return;
    }
    ctx.trace("frame.receive", "L2", `lan${port} 수신: ${describeFrame(frame)} [${frame.src} → ${frame.dst === BROADCAST_MAC ? "브로드캐스트" : frame.dst}]`, { port, src: frame.src, dst: frame.dst }, frame.id);

    const existing = this.macTable.get(frame.src);
    if (!existing || existing.port !== port) {
      this.macTable.set(frame.src, { port, learnedAt: ctx.now });
      ctx.trace("switch.learn", "L2", `내부 스위치 MAC 테이블 학습: ${frame.src} → lan${port}`, { mac: frame.src, port }, frame.id);
    }

    if (frame.dst === BROADCAST_MAC) {
      this.floodLan(port, frame, ctx, "브로드캐스트");
      this.deliver(frame, ctx);
      return;
    }
    if (frame.dst === this.lan.mac) {
      this.deliver(frame, ctx);
      return;
    }
    const entry = this.macTable.get(frame.dst);
    if (!entry) {
      this.floodLan(port, frame, ctx, `${frame.dst} 는 MAC 테이블에 없음`);
      return;
    }
    if (entry.port === port) {
      ctx.trace("switch.filter", "L2", `목적지 ${frame.dst} 가 수신 포트와 같음 → 필터링`, { port }, frame.id);
      return;
    }
    ctx.trace("switch.forward", "L2", `내부 스위치: ${frame.dst} → lan${entry.port} 로 전달`, { dst: frame.dst, port: entry.port }, frame.id);
    ctx.send(entry.port, frame);
  }

  private floodLan(inPort: number, frame: EthernetFrame, ctx: NodeContext, reason: string): void {
    const ports = Router.LAN_PORTS.filter((p) => p !== inPort && ctx.isPortConnected(p));
    if (ports.length > 0) {
      ctx.trace("switch.flood", "L2", `${reason} → 다른 LAN 포트로 플러딩 [${ports.map((p) => `lan${p}`).join(", ")}]`, { inPort, ports, reason }, frame.id);
      for (const p of ports) ctx.send(p, frame);
    }
  }

  /** LAN 인터페이스에서 나가는 프레임: 내부 스위치 규칙으로 포트 결정 */
  private emitLan(frame: EthernetFrame, ctx: NodeContext): void {
    if (frame.dst !== BROADCAST_MAC) {
      const entry = this.macTable.get(frame.dst);
      if (entry) {
        ctx.send(entry.port, frame);
        return;
      }
    }
    for (const p of Router.LAN_PORTS) if (ctx.isPortConnected(p)) ctx.send(p, frame);
  }

  private deliver(frame: EthernetFrame, ctx: NodeContext): void {
    const emit = (f: EthernetFrame) => this.emitLan(f, ctx);
    if (frame.payload.kind === "arp") {
      this.lan.handleArp(frame.payload, frame.id, ctx, emit);
      return;
    }
    const pkt = frame.payload;
    if (pkt.payload.kind === "udp") {
      const udp = pkt.payload;
      if (udp.dstPort === DHCP_SERVER_PORT) this.handleDhcp(udp.payload, frame.id, ctx);
      else ctx.trace("ip.drop", "L4", `UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 폐기`, { port: udp.dstPort }, frame.id);
      return;
    }
    if (pkt.dst !== this.lan.ip) {
      ctx.trace("ip.drop", "L3", `목적지 ${pkt.dst} 는 내 LAN 주소가 아님 → 폐기 (다른 네트워크로의 라우팅은 아직 미지원)`, { dst: pkt.dst }, frame.id);
      return;
    }
    this.handleIcmp(pkt, pkt.payload, frame.id, ctx, emit);
  }

  private handleIcmp(pkt: Ipv4Packet, icmp: IcmpPacket, frameId: number, ctx: NodeContext, emit: (f: EthernetFrame) => void): void {
    if (icmp.type !== "echo-request") {
      ctx.trace("ip.drop", "L3", `요청한 적 없는 Echo 응답 → 무시`, {}, frameId);
      return;
    }
    ctx.trace("icmp.echo.received", "app", `ICMP Echo 요청 수신 (from ${pkt.src}, seq=${icmp.seq})`, { from: pkt.src, seq: icmp.seq }, frameId);
    const reply: Ipv4Packet = { kind: "ipv4", src: this.lan.ip!, dst: pkt.src, ttl: 64, payload: { kind: "icmp", type: "echo-reply", id: icmp.id, seq: icmp.seq } };
    ctx.trace("icmp.reply.sent", "app", `ICMP Echo 응답 생성 → ${pkt.src} (seq=${icmp.seq})`, { to: pkt.src, seq: icmp.seq });
    this.lan.sendIp(reply, ctx, emit);
  }

  // ---------- DHCP 서버 ----------

  private handleDhcp(msg: DhcpMessage, frameId: number, ctx: NodeContext): void {
    const emit = (f: EthernetFrame) => this.emitLan(f, ctx);
    if (msg.op === "discover") {
      ctx.trace("dhcp.discover.received", "app", `DHCP Discover 수신 (클라이언트 ${msg.clientMac})`, { ...msg }, frameId);
      if (!this.dhcp.enabled) {
        ctx.trace("dhcp.disabled", "app", `DHCP 서비스가 꺼져 있음 → 응답하지 않음 (클라이언트는 타임아웃 후 실패)`, {}, frameId);
        return;
      }
      const ip = this.pickAddress(msg.clientMac);
      if (!ip) {
        ctx.trace("dhcp.pool.exhausted", "app", `빌려줄 주소가 없음 (범위 ${this.dhcp.start} ~ ${this.dhcp.end} 모두 사용 중) → 응답 안 함`, {}, frameId);
        return;
      }
      this.offers.set(msg.clientMac, ip);
      const offer: DhcpMessage = {
        kind: "dhcp",
        op: "offer",
        xid: msg.xid,
        clientMac: msg.clientMac,
        yiaddr: ip,
        serverId: this.lan.ip,
        options: { prefix: this.lan.prefix, router: this.lan.ip, leaseTime: Router.LEASE_TIME },
      };
      ctx.trace("dhcp.offer.sent", "app", `DHCP Offer: ${msg.clientMac} 에게 ${ip}/${this.lan.prefix} 제안 (게이트웨이 ${this.lan.ip}) → 클라이언트 MAC 으로 유니캐스트`, { ...offer });
      this.lan.sendToMac(msg.clientMac, this.serverPacket(offer, ip), ctx, emit);
      return;
    }
    if (msg.op === "request") {
      ctx.trace("dhcp.request.received", "app", `DHCP Request 수신: ${msg.clientMac} 가 ${msg.requestedIp} 요청 (서버 ${msg.serverId})`, { ...msg }, frameId);
      if (!this.dhcp.enabled) {
        ctx.trace("dhcp.disabled", "app", `DHCP 서비스가 꺼져 있음 → 응답하지 않음`, {}, frameId);
        return;
      }
      if (msg.serverId !== this.lan.ip) {
        ctx.trace("dhcp.ignore", "app", `클라이언트가 다른 서버(${msg.serverId})를 선택 → 내 제안 철회`, {}, frameId);
        this.offers.delete(msg.clientMac);
        return;
      }
      const offered = this.offers.get(msg.clientMac);
      const leased = msg.requestedIp ? this.leases.get(msg.requestedIp) : undefined;
      const ok = msg.requestedIp && ((offered && offered === msg.requestedIp) || (leased && leased.mac === msg.clientMac));
      if (!ok) {
        const nak: DhcpMessage = { kind: "dhcp", op: "nak", xid: msg.xid, clientMac: msg.clientMac, serverId: this.lan.ip };
        ctx.trace("dhcp.nak.sent", "app", `DHCP Nak: ${msg.requestedIp} 는 ${msg.clientMac} 에게 제안한 주소가 아님 → 거부`, { ...nak });
        this.lan.sendToMac(msg.clientMac, this.serverPacket(nak, "255.255.255.255"), ctx, emit);
        return;
      }
      const ip = msg.requestedIp!;
      this.offers.delete(msg.clientMac);
      this.leases.set(ip, { mac: msg.clientMac, at: ctx.now });
      const ack: DhcpMessage = {
        kind: "dhcp",
        op: "ack",
        xid: msg.xid,
        clientMac: msg.clientMac,
        yiaddr: ip,
        serverId: this.lan.ip,
        options: { prefix: this.lan.prefix, router: this.lan.ip, leaseTime: Router.LEASE_TIME },
      };
      ctx.trace("dhcp.lease", "app", `임대 등록: ${ip} → ${msg.clientMac}`, { ip, mac: msg.clientMac });
      ctx.trace("dhcp.ack.sent", "app", `DHCP Ack: ${msg.clientMac} 에게 ${ip}/${this.lan.prefix} 확정 (게이트웨이 ${this.lan.ip})`, { ...ack });
      this.lan.sendToMac(msg.clientMac, this.serverPacket(ack, ip), ctx, emit);
      return;
    }
    ctx.trace("dhcp.ignore", "app", `서버가 처리하지 않는 DHCP ${msg.op} → 무시`, {}, frameId);
  }

  private serverPacket(msg: DhcpMessage, dst: Ip): Ipv4Packet {
    return { kind: "ipv4", src: this.lan.ip!, dst, ttl: 64, payload: { kind: "udp", srcPort: DHCP_SERVER_PORT, dstPort: DHCP_CLIENT_PORT, payload: msg } };
  }

  /** 기존 임대 → 기존 제안 → 범위 안의 첫 빈 주소 */
  private pickAddress(mac: Mac): Ip | undefined {
    for (const [ip, lease] of this.leases) if (lease.mac === mac) return ip;
    const offered = this.offers.get(mac);
    if (offered) return offered;
    let start: number, end: number;
    try {
      start = ipToInt(this.dhcp.start);
      end = ipToInt(this.dhcp.end);
    } catch {
      return undefined;
    }
    const taken = new Set([...this.leases.keys(), ...this.offers.values(), this.lan.ip]);
    for (let n = start; n <= end; n++) {
      const ip = intToIp(n);
      if (!taken.has(ip)) return ip;
    }
    return undefined;
  }

  // ---------- 스냅샷 ----------

  snapshot(): NodeSnapshot {
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [
        ["LAN MAC", this.lan.mac],
        ["LAN IP", `${this.lan.ip}/${this.lan.prefix}`],
        ["DHCP", this.dhcp.enabled ? `켜짐 · ${this.dhcp.start} ~ ${this.dhcp.end}` : "꺼짐"],
      ],
      tables: [
        {
          title: "DHCP 임대",
          columns: ["IP", "MAC", "시각"],
          rows: [...this.leases.entries()].map(([ip, l]) => [ip, l.mac, `${l.at}ms`]),
        },
        {
          title: "내부 스위치 MAC 테이블",
          columns: ["MAC", "포트", "학습 시각"],
          rows: [...this.macTable.entries()].map(([mac, e]) => [mac, `lan${e.port}`, `${e.learnedAt}ms`]),
        },
        { title: "ARP 캐시", columns: ["IP", "MAC", "학습 시각"], rows: this.lan.arpRows() },
      ],
    };
  }

  onTimer(): void {}
}
