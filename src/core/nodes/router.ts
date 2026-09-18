import { BROADCAST_MAC, sameSubnet, type Ip, type Mac } from "../addr";
import { DHCP_CLIENT_PORT, DHCP_SERVER_PORT, describeFrame, type EthernetFrame, type IcmpPacket, type Ipv4Packet } from "../packet";
import { DHCP_STATE_LABEL, DHCP_TIMER_TAG, DhcpClient, DhcpServer, type DhcpServerConfig } from "./dhcp";
import { hashCode } from "./host";
import { NetInterface, type Emit } from "./iface";
import { NAT_ID_START, NatTable } from "./nat";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";
import { guardLoop } from "./switch";

export type { DhcpServerConfig } from "./dhcp";
export type { NatEntry } from "./nat";

export interface WanConfig {
  mode: "dhcp" | "static";
  ip?: Ip;
  prefix?: number;
  gateway?: Ip;
}

export interface RouterConfig {
  id: string;
  mac: Mac;
  wanMac: Mac;
  lanIp: Ip;
  lanPrefix?: number;
  dhcp: DhcpServerConfig;
  wan?: WanConfig;
}

interface MacEntry {
  port: number;
  learnedAt: number;
}

/**
 * 가정용 라우터. LAN 포트 4개는 내부 스위치로 브리지되고 LAN 인터페이스(MAC/IP) 하나가 붙어 있다.
 * DHCP 서버(LAN), DHCP 클라이언트(WAN), 그리고 LAN ↔ WAN 사이의 NAT 를 한다.
 */
export class Router implements SimNode {
  static readonly WAN_PORT = 0;
  static readonly LAN_PORTS = [1, 2, 3, 4];
  static readonly NAT_ID_START = NAT_ID_START;

  readonly type = "router" as const;
  readonly portCount = 5;
  readonly id: string;
  readonly lan: NetInterface;
  readonly wan: NetInterface;
  readonly dhcpServer: DhcpServer;
  readonly wanClient: DhcpClient;
  wanMode: "dhcp" | "static";
  wanLinkUp = false;
  readonly macTable = new Map<Mac, MacEntry>();
  readonly nat = new NatTable();
  private readonly seen = new Map<number, number>();

  constructor(cfg: RouterConfig) {
    this.id = cfg.id;
    this.lan = new NetInterface(cfg.mac, { ip: cfg.lanIp, prefix: cfg.lanPrefix ?? 24 });
    this.dhcpServer = new DhcpServer({ ...cfg.dhcp }, this.lan);
    const wan = cfg.wan ?? { mode: "dhcp" };
    this.wanMode = wan.mode;
    this.wan = new NetInterface(cfg.wanMac, wan.mode === "static" ? { ip: wan.ip, prefix: wan.prefix ?? 24, gateway: wan.gateway } : {});
    this.wanClient = new DhcpClient(this.wan, hashCode(cfg.id) + 7, "wan");
  }

  get dhcp(): DhcpServerConfig {
    return this.dhcpServer.config;
  }
  get leases() {
    return this.dhcpServer.leases;
  }

  private emitLan(ctx: NodeContext): Emit {
    return (frame) => {
      if (frame.dst !== BROADCAST_MAC) {
        const entry = this.macTable.get(frame.dst);
        if (entry) {
          ctx.send(entry.port, frame);
          return;
        }
      }
      for (const p of Router.LAN_PORTS) if (ctx.isPortConnected(p)) ctx.send(p, frame);
    };
  }

  private emitWan(ctx: NodeContext): Emit {
    return (frame) => ctx.send(Router.WAN_PORT, frame);
  }

  // ---------- 설정 변경 ----------

  configure(cfg: { lanIp: Ip; lanPrefix: number; dhcp: DhcpServerConfig; wan: WanConfig }, ctx: NodeContext): void {
    if (cfg.lanIp !== this.lan.ip || cfg.lanPrefix !== this.lan.prefix) {
      this.lan.configure(cfg.lanIp, cfg.lanPrefix, undefined);
      this.lan.arpCache.clear();
      ctx.trace("ip.config", "sys", `LAN 인터페이스 주소 변경: ${cfg.lanIp}/${cfg.lanPrefix} (ARP 캐시 비움)`, { ...cfg });
      this.dhcpServer.onInterfaceChanged(ctx);
    }
    const d = this.dhcpServer.config;
    if (cfg.dhcp.enabled !== d.enabled) {
      ctx.trace(
        "ip.config",
        "sys",
        cfg.dhcp.enabled ? `DHCP 서비스 켜짐 (범위 ${cfg.dhcp.start} ~ ${cfg.dhcp.end})` : `DHCP 서비스 꺼짐 → 이후 Discover 에 응답하지 않음`,
        { ...cfg.dhcp },
      );
    } else if (cfg.dhcp.start !== d.start || cfg.dhcp.end !== d.end) {
      ctx.trace("ip.config", "sys", `DHCP 범위 변경: ${cfg.dhcp.start} ~ ${cfg.dhcp.end}`, { ...cfg.dhcp });
    }
    if (cfg.dhcp.start !== d.start || cfg.dhcp.end !== d.end || cfg.dhcp.enabled !== d.enabled) this.dhcpServer.setConfig(cfg.dhcp, ctx);

    const w = cfg.wan;
    const wanChanged =
      w.mode !== this.wanMode || (w.mode === "static" && (w.ip !== this.wan.ip || (w.prefix ?? 24) !== this.wan.prefix || w.gateway !== this.wan.gateway));
    if (wanChanged) {
      this.wanMode = w.mode;
      if (w.mode === "static") {
        this.wanClient.stop();
        this.wan.configure(w.ip || undefined, w.prefix ?? 24, w.gateway || undefined);
        ctx.trace("ip.config", "sys", w.ip ? `[wan] 수동 설정 적용: ${w.ip}/${w.prefix ?? 24}, 게이트웨이 ${w.gateway ?? "없음"}` : `[wan] 수동 설정으로 전환 (주소 미입력)`, { ...w });
      } else {
        this.wan.clearAddress();
        ctx.trace("ip.config", "sys", `[wan] 자동(DHCP) 로 전환 → ISP 에서 공인 주소를 받는다`, { ...w });
        if (this.wanLinkUp) this.wanClient.start(ctx, this.emitWan(ctx));
        else this.wanClient.stop();
      }
    }
  }

  onRemove(ctx: NodeContext): void {
    if (this.wanLinkUp) this.wanClient.release(ctx, this.emitWan(ctx));
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    if (port === Router.WAN_PORT) {
      this.wanLinkUp = up;
      if (up) {
        ctx.trace("link.up", "L1", `wan 포트 링크 연결됨`, { port });
        if (this.wanMode === "dhcp") this.wanClient.start(ctx, this.emitWan(ctx));
        return;
      }
      ctx.trace("link.down", "L1", `wan 포트 링크 끊김`, { port });
      this.wan.clearPending();
      if (this.wanMode === "dhcp") {
        const had = this.wan.ip;
        this.wan.clearAddress();
        this.wanClient.stop();
        if (had) ctx.trace("dhcp.release", "app", `[wan] 링크가 끊겨 공인 주소 ${had} 해제`, { ip: had });
      }
      return;
    }
    if (up) {
      ctx.trace("link.up", "L1", `lan${port} 포트 링크 연결됨`, { port });
      return;
    }
    ctx.trace("link.down", "L1", `lan${port} 포트 링크 끊김`, { port });
    for (const [mac, e] of this.macTable) if (e.port === port) this.macTable.delete(mac);
  }

  // ---------- 수신 ----------

  receive(port: number, frame: EthernetFrame, ctx: NodeContext): void {
    if (port === Router.WAN_PORT) {
      if (!this.wan.accepts(frame)) {
        ctx.trace("frame.drop", "L2", `wan 수신: 목적지 MAC ${frame.dst} 가 내 WAN MAC 아님 → 폐기`, { dst: frame.dst }, frame.id);
        return;
      }
      ctx.trace("frame.receive", "L2", `wan 수신: ${describeFrame(frame)} [${frame.src} → ${frame.dst === BROADCAST_MAC ? "브로드캐스트" : "내 WAN MAC"}]`, { src: frame.src, dst: frame.dst }, frame.id);
      if (frame.payload.kind === "arp") this.wan.handleArp(frame.payload, frame.id, ctx, this.emitWan(ctx));
      else this.handleWanIp(frame.payload, frame.id, ctx);
      return;
    }

    ctx.trace("frame.receive", "L2", `lan${port} 수신: ${describeFrame(frame)} [${frame.src} → ${frame.dst === BROADCAST_MAC ? "브로드캐스트" : frame.dst}]`, { port, src: frame.src, dst: frame.dst }, frame.id);
    if (!guardLoop(this.seen, port, frame, ctx, `lan${port}`)) return;
    frame = { ...frame, hops: (frame.hops ?? 0) + 1 };
    const existing = this.macTable.get(frame.src);
    if ((!existing || existing.port !== port) && ctx.isPortConnected(port)) {
      this.macTable.set(frame.src, { port, learnedAt: ctx.now });
      ctx.trace("switch.learn", "L2", `내부 스위치 MAC 테이블 학습: ${frame.src} → lan${port}`, { mac: frame.src, port }, frame.id);
    }
    if (frame.dst === BROADCAST_MAC) {
      this.floodLan(port, frame, ctx, "브로드캐스트");
      this.deliverLan(frame, ctx);
      return;
    }
    if (frame.dst === this.lan.mac) {
      this.deliverLan(frame, ctx);
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
    if (ports.length === 0) return;
    ctx.trace("switch.flood", "L2", `${reason} → 다른 LAN 포트로 플러딩 [${ports.map((p) => `lan${p}`).join(", ")}]`, { inPort, ports, reason }, frame.id);
    for (const p of ports) ctx.send(p, frame);
  }

  private deliverLan(frame: EthernetFrame, ctx: NodeContext): void {
    const emit = this.emitLan(ctx);
    if (frame.payload.kind === "arp") {
      this.lan.handleArp(frame.payload, frame.id, ctx, emit);
      return;
    }
    const pkt = frame.payload;
    if (pkt.payload.kind === "udp") {
      const udp = pkt.payload;
      if (udp.dstPort === DHCP_SERVER_PORT) this.dhcpServer.handle(udp.payload, frame.id, ctx, emit);
      else if (udp.dstPort === DHCP_CLIENT_PORT) ctx.trace("dhcp.ignore", "app", `LAN 쪽 DHCP 클라이언트 메시지는 내 것이 아님 → 무시`, {}, frame.id);
      else ctx.trace("ip.drop", "L4", `UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 폐기`, { port: udp.dstPort }, frame.id);
      return;
    }
    if (pkt.dst === this.lan.ip || (this.wan.ip && pkt.dst === this.wan.ip)) {
      if (pkt.payload.kind === "tcp") {
        ctx.trace("ip.drop", "L4", `라우터 자신에게 온 TCP ${pkt.payload.dstPort} 포트 → 듣는 서비스 없음, 폐기`, { port: pkt.payload.dstPort }, frame.id);
        return;
      }
      // LAN 에서 내 WAN 주소로 온 ping 도 내 것: 응답은 WAN 주소를 출발지로 LAN 쪽으로 돌려준다
      this.handleIcmp(pkt, pkt.payload, frame.id, ctx, this.lan, emit, pkt.dst);
      return;
    }
    if (pkt.dst === "255.255.255.255" || pkt.dst === "0.0.0.0" || pkt.dst.startsWith("224.") || pkt.dst.startsWith("239.")) {
      ctx.trace("ip.drop", "L3", `브로드캐스트/멀티캐스트 ${pkt.dst} 는 라우터가 다른 네트워크로 넘기지 않음 → 폐기`, { dst: pkt.dst }, frame.id);
      return;
    }
    this.forwardToWan(pkt, frame.id, ctx);
  }

  private handleWanIp(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const emit = this.emitWan(ctx);
    if (pkt.payload.kind === "udp") {
      const udp = pkt.payload;
      if (udp.dstPort === DHCP_CLIENT_PORT) this.wanClient.handle(udp.payload, frameId, ctx, emit);
      else if (udp.dstPort === DHCP_SERVER_PORT) ctx.trace("dhcp.ignore", "app", `[wan] 다른 장치의 DHCP ${udp.payload.op} → 무시`, {}, frameId);
      else ctx.trace("ip.drop", "L4", `[wan] UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 폐기`, { port: udp.dstPort }, frameId);
      return;
    }
    if (pkt.dst !== this.wan.ip) {
      ctx.trace("ip.drop", "L3", `[wan] 목적지 ${pkt.dst} 는 내 공인 주소(${this.wan.ip ?? "없음"}) 아님 → 폐기`, { dst: pkt.dst }, frameId);
      return;
    }
    const p = pkt.payload;
    if (p.kind === "icmp" && p.type === "echo-request") {
      this.handleIcmp(pkt, p, frameId, ctx, this.wan, emit);
      return;
    }
    // 바깥에서 들어온 패킷: NAT 테이블로 내부 호스트를 찾는다
    const restored = this.nat.restore(pkt, this.wan.ip, ctx, frameId);
    if (!restored) return;
    const inner: Ipv4Packet = { ...restored, ttl: pkt.ttl - 1 };
    ctx.trace("ip.forward", "L3", `라우팅: ${inner.dst} 는 LAN 안 → LAN 인터페이스로 전달 (TTL ${pkt.ttl} → ${inner.ttl})`, { dst: inner.dst }, frameId);
    this.lan.sendIp(inner, ctx, this.emitLan(ctx));
  }

  private forwardToWan(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    if (sameSubnet(pkt.dst, this.lan.ip!, this.lan.prefix)) {
      ctx.trace("ip.drop", "L3", `목적지 ${pkt.dst} 는 LAN 안의 주소 → 라우터를 거칠 필요가 없음 (호스트끼리 직접 통신) → 폐기`, { dst: pkt.dst }, frameId);
      return;
    }
    if (!this.wan.ip) {
      ctx.trace("ip.no-route", "L3", `${pkt.dst} 는 외부 주소인데 WAN 에 공인 주소가 없음 → 인터넷으로 보낼 수 없음 (WAN 케이블과 DHCP 확인)`, { dst: pkt.dst }, frameId);
      return;
    }
    if (pkt.ttl <= 1) {
      ctx.trace("ip.ttl-expired", "L3", `TTL 이 0 이 되어 폐기 (루프 방지)`, { dst: pkt.dst }, frameId);
      return;
    }
    const translated = this.nat.translate({ ...pkt, ttl: pkt.ttl - 1 }, this.wan.ip, ctx, frameId);
    if (!translated) return;
    ctx.trace("ip.forward", "L3", `라우팅: ${pkt.dst} 는 외부 → WAN 인터페이스로 전달 (TTL ${pkt.ttl} → ${translated.ttl})`, { dst: pkt.dst }, frameId);
    this.wan.sendIp(translated, ctx, this.emitWan(ctx));
  }

  private handleIcmp(pkt: Ipv4Packet, icmp: IcmpPacket, frameId: number, ctx: NodeContext, iface: NetInterface, emit: Emit, replySrc?: Ip): void {
    if (icmp.type !== "echo-request") {
      ctx.trace("ip.drop", "L3", `요청한 적 없는 Echo 응답 → 무시`, {}, frameId);
      return;
    }
    ctx.trace("icmp.echo.received", "app", `ICMP Echo 요청 수신 (from ${pkt.src}, seq=${icmp.seq})`, { from: pkt.src, seq: icmp.seq }, frameId);
    const reply: Ipv4Packet = { kind: "ipv4", src: replySrc ?? iface.ip!, dst: pkt.src, ttl: 64, payload: { kind: "icmp", type: "echo-reply", id: icmp.id, seq: icmp.seq } };
    ctx.trace("icmp.reply.sent", "app", `ICMP Echo 응답 생성 → ${pkt.src} (seq=${icmp.seq})`, { to: pkt.src, seq: icmp.seq });
    iface.sendIp(reply, ctx, emit);
  }

  // ---------- 타이머 ----------

  onTimer(tag: string, data: unknown, ctx: NodeContext): void {
    if (tag === "arp-timeout") {
      this.lan.onArpTimeout(data, ctx);
      this.wan.onArpTimeout(data, ctx);
      return;
    }
    if (tag === DHCP_TIMER_TAG && this.wanClient.ownsTimer(data)) this.wanClient.onTimeout(data, ctx, this.emitWan(ctx));
  }

  // ---------- 스냅샷 ----------

  snapshot(): NodeSnapshot {
    const wanState = this.wan.ip
      ? `${this.wan.ip}/${this.wan.prefix}`
      : !this.wanLinkUp
        ? "없음 (케이블 없음)"
        : this.wanMode === "dhcp"
          ? `없음 (DHCP: ${DHCP_STATE_LABEL[this.wanClient.state]})`
          : "없음 (수동 입력 필요)";
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [
        ["LAN IP", `${this.lan.ip}/${this.lan.prefix}`],
        ["LAN MAC", this.lan.mac],
        ["WAN IP", wanState],
        ["WAN 게이트웨이", this.wan.gateway ?? "없음"],
        ["DHCP 서비스", this.dhcp.enabled ? `켜짐 · ${this.dhcp.start} ~ ${this.dhcp.end}` : "꺼짐"],
      ],
      tables: [
        { title: "DHCP 임대", columns: ["IP", "MAC", "시각"], rows: this.dhcpServer.rows() },
        { title: "NAT 테이블", columns: ["내부", "→ 외부", "시각"], rows: this.nat.rows(this.wan.ip) },
        {
          title: "내부 스위치 MAC 테이블",
          columns: ["MAC", "포트", "학습 시각"],
          rows: [...this.macTable.entries()].map(([mac, e]) => [mac, `lan${e.port}`, `${e.learnedAt}ms`]),
        },
        { title: "ARP 캐시 (LAN)", columns: ["IP", "MAC", "학습 시각"], rows: this.lan.arpRows() },
        { title: "ARP 캐시 (WAN)", columns: ["IP", "MAC", "학습 시각"], rows: this.wan.arpRows() },
      ],
    };
  }
}
