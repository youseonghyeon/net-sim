// 순수 L3 장치: 인터페이스 N개 사이를 라우팅한다. 게이트웨이(NAT 없음)와 NAT 박스(outside 인터페이스에서 변환)가 이 클래스다.
import { networkOf, sameSubnet, type Ip, type Mac } from "../addr";
import { DHCP_CLIENT_PORT, DHCP_SERVER_PORT, describeFrame, icmpLabel, LIMITED_BROADCAST_IP, type DhcpMessage, type EthernetFrame, type IcmpPacket, type Ipv4Packet } from "../packet";
import { DHCP_STATE_LABEL, DHCP_TIMER_TAG, DhcpClient } from "./dhcp";
import { hashCode } from "./host";
import { NetInterface, type Emit } from "./iface";
import { Firewall, type FirewallConfig, type FlowDirection } from "./firewall";
import { NatTable, type PortForward } from "./nat";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";

export interface L3IfaceConfig {
  name: string;
  mac: Mac;
  mode: "static" | "dhcp";
  ip?: Ip;
  prefix?: number;
  gateway?: Ip;
  /** 이 인터페이스로 오는 DHCP 브로드캐스트를 이 서버로 유니캐스트 전달 (DHCP 릴레이, ip helper-address) */
  relay?: Ip;
}

export interface StaticRoute {
  dest: Ip;
  prefix: number;
  via: Ip;
}

/** VLAN 서브 인터페이스 (router-on-a-stick): 물리 포트 하나 위에 VLAN 마다 IP 하나 */
export interface SubIfaceConfig {
  port: number;
  vlan: number;
  ip?: Ip;
  prefix?: number;
  relay?: Ip;
}

export interface L3Config {
  id: string;
  kind: "gateway" | "nat";
  interfaces: L3IfaceConfig[];
  subinterfaces?: SubIfaceConfig[];
  /** NAT 박스: 이 인덱스의 인터페이스가 바깥(공인) 쪽 */
  outside?: number;
  routes?: StaticRoute[];
  firewall?: FirewallConfig;
  /** NAT 박스 전용: 포트 포워딩 규칙 (TCP). kind 가 "gateway" 면 무시 */
  forwards?: PortForward[];
}

interface Route {
  out: number;
  nextHop: Ip;
  kind: "connected" | "static" | "default";
}

export class L3Node implements SimNode {
  readonly type: "gateway" | "nat";
  readonly id: string;
  readonly portCount: number;
  ifaces: NetInterface[];
  names: string[];
  modes: ("static" | "dhcp")[];
  clients: (DhcpClient | undefined)[];
  linkUp: boolean[];
  readonly nat: NatTable | undefined;
  readonly outside: number | undefined;
  routes: StaticRoute[];
  /** 인터페이스별 DHCP 릴레이 대상 서버 */
  relays: (Ip | undefined)[];
  readonly firewall: Firewall;
  /** 인터페이스 i 가 붙은 물리 포트와 VLAN 태그. 물리 인터페이스는 i === port, 서브 인터페이스는 그 뒤에 붙는다 */
  meta: { port: number; vlan?: number }[];
  private readonly macBase: Mac;

  constructor(cfg: L3Config) {
    this.id = cfg.id;
    this.type = cfg.kind;
    this.portCount = cfg.interfaces.length;
    this.names = cfg.interfaces.map((i) => i.name);
    this.modes = cfg.interfaces.map((i) => i.mode);
    this.ifaces = cfg.interfaces.map((i) => new NetInterface(i.mac, i.mode === "static" ? { ip: i.ip, prefix: i.prefix ?? 24, gateway: i.gateway } : {}));
    this.clients = cfg.interfaces.map((i, idx) => (i.mode === "dhcp" ? new DhcpClient(this.ifaces[idx]!, hashCode(cfg.id) + idx * 13, i.name) : undefined));
    this.linkUp = cfg.interfaces.map(() => false);
    this.outside = cfg.kind === "nat" ? (cfg.outside ?? 0) : undefined;
    this.nat = cfg.kind === "nat" ? new NatTable() : undefined;
    this.routes = [...(cfg.routes ?? [])];
    this.relays = cfg.interfaces.map((i) => i.relay);
    this.meta = cfg.interfaces.map((_, i) => ({ port: i }));
    this.macBase = cfg.interfaces[0]?.mac ?? "02:00:00:10:00:00";
    if (this.nat && cfg.forwards) this.nat.setForwards(cfg.forwards);
    this.firewall = new Firewall(cfg.firewall);
    if (cfg.subinterfaces) this.setSubinterfaces(cfg.subinterfaces);
  }

  /** 물리 포트 + VLAN 태그로 인터페이스 인덱스 찾기 */
  private ifaceIndexFor(port: number, vlan: number | undefined): number {
    return this.meta.findIndex((m) => m.port === port && m.vlan === vlan);
  }

  /** 서브 인터페이스 목록 교체. 같은 (포트, VLAN) 은 자리에서 갱신, 나머지는 만들고 지운다 */
  setSubinterfaces(subs: SubIfaceConfig[], ctx?: NodeContext): void {
    const physical = this.portCount;
    const keep: number[] = [];
    const nextMeta: { port: number; vlan?: number }[] = this.meta.slice(0, physical);
    const nextIfaces = this.ifaces.slice(0, physical);
    const nextNames = this.names.slice(0, physical);
    const nextModes = this.modes.slice(0, physical);
    const nextClients = this.clients.slice(0, physical);
    const nextLinkUp = this.linkUp.slice(0, physical);
    const nextRelays = this.relays.slice(0, physical);
    const seen = new Set<string>();
    for (const sub of subs) {
      if (sub.port < 0 || sub.port >= physical) continue;
      const dupKey = `${sub.port}:${sub.vlan}`;
      if (seen.has(dupKey)) continue; // 같은 (포트, VLAN) 이 두 번 오면 첫 것만
      seen.add(dupKey);
      const existing = this.meta.findIndex((m, i) => i >= physical && m.port === sub.port && m.vlan === sub.vlan);
      const name = `${this.names[sub.port]}.${sub.vlan}`;
      let iface: NetInterface;
      if (existing >= 0) {
        iface = this.ifaces[existing]!;
        if (iface.ip !== sub.ip || iface.prefix !== (sub.prefix ?? 24)) {
          iface.configure(sub.ip, sub.prefix ?? 24, undefined);
          iface.arpCache.clear();
          iface.clearPending();
          ctx?.trace("ip.config", "sys", `[${name}] 서브 인터페이스 주소 변경: ${sub.ip ?? "없음"}/${sub.prefix ?? 24}`, { ...sub });
          if (ctx && iface.ip && this.linkUp[sub.port]) iface.announce(ctx, this.emit(existing, ctx));
        }
        keep.push(existing);
      } else {
        // 장치 식별 옥텟(XX:YY)은 그대로 두고 앞 세 옥텟에 포트·VLAN 을 넣어 장치 간 충돌을 막는다
        const mac = this.macBase.replace(/^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}/i, `06:${((sub.vlan >> 8) & 0xff).toString(16).padStart(2, "0")}:${(sub.vlan & 0xff).toString(16).padStart(2, "0")}:${(0x20 + sub.port).toString(16).padStart(2, "0")}`);
        iface = new NetInterface(mac, { ip: sub.ip, prefix: sub.prefix ?? 24 });
        ctx?.trace("ip.config", "sys", `[${name}] VLAN ${sub.vlan} 서브 인터페이스 생성: ${sub.ip ?? "주소 없음"}/${sub.prefix ?? 24} (${this.names[sub.port]} 로 오가는 프레임에 VLAN ${sub.vlan} 태그)`, { ...sub });
      }
      nextMeta.push({ port: sub.port, vlan: sub.vlan });
      nextIfaces.push(iface);
      nextNames.push(name);
      nextModes.push("static");
      nextClients.push(undefined);
      nextLinkUp.push(this.linkUp[sub.port] ?? false);
      nextRelays.push(sub.relay);
    }
    for (let i = physical; i < this.meta.length; i++) {
      if (!keep.includes(i)) ctx?.trace("ip.config", "sys", `[${this.names[i]}] 서브 인터페이스 삭제`, { index: i });
    }
    this.meta = nextMeta;
    this.ifaces = nextIfaces;
    this.names = nextNames;
    this.modes = nextModes;
    this.clients = nextClients;
    this.linkUp = nextLinkUp;
    this.relays = nextRelays;
  }

  setFirewall(cfg: FirewallConfig, ctx: NodeContext): void {
    this.firewall.setConfig(cfg, ctx, "");
  }

  /** 업링크(0번 인터페이스 = if0/outside) 기준 방향 */
  private flowDirection(inPort: number, outPort: number): FlowDirection {
    const uplink = this.outside ?? 0;
    if (inPort === uplink) return "in";
    if (outPort === uplink) return "out";
    return "lan";
  }

  setRoutes(routes: StaticRoute[], ctx: NodeContext): void {
    const key = (r: StaticRoute) => `${r.dest}/${r.prefix} via ${r.via}`;
    const before = new Set(this.routes.map(key));
    const after = new Set(routes.map(key));
    for (const r of routes) if (!before.has(key(r))) ctx.trace("ip.config", "sys", `스태틱 라우팅 추가: ${key(r)}`, { ...r });
    for (const r of this.routes) if (!after.has(key(r))) ctx.trace("ip.config", "sys", `스태틱 라우팅 삭제: ${key(r)}`, { ...r });
    this.routes = [...routes];
  }

  /** 포트 포워딩 규칙 교체 (NAT 박스만). 바뀐 경우에만 트레이스 */
  setForwards(rules: PortForward[], ctx: NodeContext): void {
    if (!this.nat) return;
    const key = (rs: PortForward[]) => rs.map((r) => `${r.publicPort}>${r.lanIp}:${r.lanPort}`).join(",");
    if (key(rules) === key(this.nat.forwards)) return;
    this.nat.setForwards(rules);
    ctx.trace("ip.config", "sys", `포트 포워딩 규칙 변경: ${rules.length}개`, { forwards: rules.map((r) => ({ ...r })) });
  }

  /** 인터페이스 i 로 송신. 서브 인터페이스면 VLAN 태그를 붙여 물리 포트로 */
  private emit(i: number, ctx: NodeContext): Emit {
    const m = this.meta[i] ?? { port: i };
    return (f) => {
      if (m.vlan !== undefined) {
        ctx.trace("vlan.tag", "L2", `[${this.names[i]}] 802.1Q 태그 VLAN ${m.vlan} 를 붙여 ${this.names[m.port]} 로 송신`, { vlan: m.vlan, port: m.port }, f.id);
        ctx.send(m.port, { ...f, vlan: m.vlan });
      } else ctx.send(m.port, f);
    };
  }

  // ---------- 설정 ----------

  configure(interfaces: Omit<L3IfaceConfig, "name" | "mac">[], ctx: NodeContext): void {
    interfaces.forEach((c, i) => {
      const iface = this.ifaces[i];
      if (!iface) return;
      const name = this.names[i]!;
      if ((c.relay || undefined) !== this.relays[i]) {
        this.relays[i] = c.relay || undefined;
        ctx.trace("ip.config", "sys", c.relay ? `[${name}] DHCP 릴레이 설정: 이 인터페이스의 DHCP 브로드캐스트를 ${c.relay} 로 전달` : `[${name}] DHCP 릴레이 해제`, { iface: name, relay: c.relay });
      }
      const changed =
        c.mode !== this.modes[i] || (c.mode === "static" && (c.ip !== iface.ip || (c.prefix ?? 24) !== iface.prefix || c.gateway !== iface.gateway));
      if (!changed) return;
      this.modes[i] = c.mode;
      iface.arpCache.clear();
      iface.clearPending();
      if (c.mode === "static") {
        this.clients[i]?.stop();
        this.clients[i] = undefined;
        iface.configure(c.ip || undefined, c.prefix ?? 24, c.gateway || undefined);
        ctx.trace("ip.config", "sys", c.ip ? `[${name}] 수동 설정 적용: ${c.ip}/${c.prefix ?? 24}${c.gateway ? `, 게이트웨이 ${c.gateway}` : ""}` : `[${name}] 수동 설정으로 전환 (주소 미입력)`, { iface: name, ...c });
        if (this.linkUp[i] && iface.ip) iface.announce(ctx, this.emit(i, ctx));
      } else {
        iface.clearAddress();
        const client = new DhcpClient(iface, hashCode(this.id) + i * 13, name);
        this.clients[i] = client;
        ctx.trace("ip.config", "sys", `[${name}] 자동(DHCP) 로 전환`, { iface: name });
        if (this.linkUp[i]) client.start(ctx, this.emit(i, ctx));
      }
    });
  }

  onRemove(ctx: NodeContext): void {
    this.clients.forEach((c, i) => {
      if (c && this.linkUp[i]) c.release(ctx, this.emit(i, ctx));
    });
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    const name = this.names[port]!;
    if (up) ctx.trace("link.up", "L1", `${name} 링크 연결됨`, { port });
    else ctx.trace("link.down", "L1", `${name} 링크 끊김`, { port });
    this.meta.forEach((m, i) => {
      if (m.port !== port) return;
      this.linkUp[i] = up;
      const iface = this.ifaces[i]!;
      if (up) {
        if (this.clients[i]) this.clients[i]!.start(ctx, this.emit(i, ctx));
        else if (iface.ip) iface.announce(ctx, this.emit(i, ctx));
        return;
      }
      iface.clearPending();
      if (this.clients[i]) {
        const had = iface.ip;
        iface.clearAddress();
        this.clients[i]!.stop();
        if (had) ctx.trace("dhcp.release", "app", `[${this.names[i]}] 링크가 끊겨 주소 ${had} 해제`, { ip: had });
      }
    });
  }

  // ---------- 수신 ----------

  receive(port: number, rawFrame: EthernetFrame, ctx: NodeContext): void {
    const i = this.ifaceIndexFor(port, rawFrame.vlan);
    if (i < 0) {
      if (rawFrame.vlan !== undefined) {
        const subs = this.meta.filter((m) => m.port === port && m.vlan !== undefined).map((m) => m.vlan);
        ctx.trace(
          "vlan.drop",
          "L2",
          `${this.names[port]} 에 VLAN ${rawFrame.vlan} 태그 프레임 → 해당 서브 인터페이스 없음 → 드롭 (${subs.length ? `있는 것: ${subs.join(", ")}` : "이 포트에 VLAN 서브 인터페이스를 추가하세요"})`,
          { port, vlan: rawFrame.vlan },
          rawFrame.id,
        );
      }
      return;
    }
    const frame = rawFrame.vlan !== undefined ? { ...rawFrame, vlan: undefined } : rawFrame;
    const iface = this.ifaces[i]!;
    const name = this.names[i]!;
    if (!iface.accepts(frame)) {
      ctx.trace("frame.drop", "L2", `${name} 수신: 목적지 MAC ${frame.dst} 가 내 MAC 아님 → 드롭`, { dst: frame.dst }, frame.id);
      return;
    }
    ctx.trace("frame.receive", "L2", `${name} 수신: ${describeFrame(frame)} [${frame.src}]${rawFrame.vlan !== undefined ? ` (VLAN ${rawFrame.vlan} 태그 떼어냄)` : ""}`, { port, src: frame.src, vlan: rawFrame.vlan }, frame.id);
    if (frame.payload.kind === "arp") {
      iface.handleArp(frame.payload, frame.id, ctx, this.emit(i, ctx));
      return;
    }
    this.handleIp(i, frame.payload, frame.id, ctx);
  }

  private handleIp(port: number, pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const name = this.names[port]!;
    if (pkt.payload.kind === "udp") {
      const udp = pkt.payload;
      const m = udp.payload;
      if (m.kind === "dhcp" && udp.dstPort === DHCP_CLIENT_PORT && this.clients[port]) this.clients[port]!.handle(m, frameId, ctx, this.emit(port, ctx));
      else if (m.kind === "dhcp" && udp.dstPort === DHCP_SERVER_PORT) this.handleRelay(port, pkt, m, frameId, ctx);
      else if (m.kind !== "dhcp" && this.nat && port === this.outside && pkt.dst === this.ifaces[port]!.ip) {
        // 바깥에서 공인 주소로 돌아온 UDP 응답(예: DNS) → NAT 테이블로 내부 호스트를 찾아 전달
        const restored = this.nat.restore(pkt, this.ifaces[port]!.ip!, ctx, frameId);
        if (restored) this.forward(restored, port, frameId, ctx, pkt);
      } else if (m.kind !== "dhcp" && !this.ifaces.some((i) => i.ip === pkt.dst)) this.forward(pkt, port, frameId, ctx);
      else ctx.trace("ip.drop", "L4", `[${name}] UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 드롭`, { port: udp.dstPort }, frameId);
      return;
    }
    const mine = this.ifaces.findIndex((i) => i.ip !== undefined && i.ip === pkt.dst);
    const fromOutside = this.nat !== undefined && port === this.outside;
    if (fromOutside && mine >= 0 && mine !== this.outside) {
      ctx.trace("ip.drop", "L3", `[${name}] 바깥에서 안쪽 주소 ${pkt.dst} 로 온 패킷 → 드롭. NAT 뒤의 사설 주소는 바깥에서 닿을 수 없음`, { dst: pkt.dst }, frameId);
      return;
    }
    // 바깥에서 공인 주소로 온 패킷: ping 요청만 내가 직접 받고, 나머지(응답·TCP)는 NAT 테이블로 내부 호스트를 찾는다
    if (mine >= 0 && !(fromOutside && !(pkt.payload.kind === "icmp" && pkt.payload.type === "echo-request"))) {
      if (pkt.payload.kind === "tcp") {
        ctx.trace("ip.drop", "L4", `이 장치는 TCP 서비스를 열지 않음 → 드롭`, {}, frameId);
        return;
      }
      this.handleIcmp(mine, pkt, pkt.payload, frameId, ctx);
      return;
    }
    let inner = pkt;
    if (fromOutside) {
      if (mine < 0) {
        ctx.trace("ip.drop", "L3", `[${name}] 목적지 ${pkt.dst} 는 내 공인 주소가 아님 → 드롭`, { dst: pkt.dst }, frameId);
        return;
      }
      const restored = this.nat!.restore(pkt, this.ifaces[port]!.ip!, ctx, frameId);
      if (!restored) return;
      inner = restored;
    }
    this.forward(inner, port, frameId, ctx, pkt);
  }

  /** DHCP 릴레이: 클라이언트 → 서버는 giaddr 를 붙여 유니캐스트, 서버 → 클라이언트는 giaddr 인터페이스에서 L2 유니캐스트 */
  private handleRelay(port: number, pkt: Ipv4Packet, msg: DhcpMessage, frameId: number, ctx: NodeContext): void {
    const name = this.names[port]!;
    const fromClient = msg.op === "discover" || msg.op === "request" || msg.op === "release";
    if (fromClient && !msg.giaddr) {
      const server = this.relays[port];
      const iface = this.ifaces[port]!;
      if (!server) {
        ctx.trace("dhcp.ignore", "app", `[${name}] DHCP ${msg.op} 브로드캐스트 — 이 장치는 DHCP 서버가 아니고 릴레이도 설정되지 않아 무시`, {}, frameId);
        return;
      }
      if (!iface.ip) {
        ctx.trace("dhcp.relay.miss", "app", `[${name}] DHCP 릴레이 불가: 이 인터페이스에 주소가 없어 giaddr 를 붙일 수 없음`, {}, frameId);
        return;
      }
      const relayed: DhcpMessage = { ...msg, giaddr: iface.ip };
      const out: Ipv4Packet = { kind: "ipv4", src: iface.ip, dst: server, ttl: 64, payload: { kind: "udp", srcPort: DHCP_SERVER_PORT, dstPort: DHCP_SERVER_PORT, payload: relayed } };
      ctx.trace(
        "dhcp.relay.forward",
        "app",
        `[${name}] DHCP 릴레이: 브로드캐스트 ${msg.op} 를 릴레이 에이전트 주소(giaddr)=${iface.ip} 붙여 서버 ${server} 로 유니캐스트 전달 (브로드캐스트는 서브넷을 못 넘으므로)`,
        { op: msg.op, giaddr: iface.ip, server },
        frameId,
      );
      this.sendVia(out, ctx, frameId);
      return;
    }
    if (!fromClient && msg.giaddr) {
      const back = this.ifaces.findIndex((i) => i.ip === msg.giaddr);
      if (back < 0) {
        ctx.trace("dhcp.relay.miss", "app", `[${name}] 서버 응답의 giaddr ${msg.giaddr} 가 내 인터페이스가 아님 → 드롭`, { giaddr: msg.giaddr }, frameId);
        return;
      }
      const dst = msg.op === "nak" ? LIMITED_BROADCAST_IP : (msg.yiaddr ?? LIMITED_BROADCAST_IP);
      const toClient: Ipv4Packet = { kind: "ipv4", src: this.ifaces[back]!.ip!, dst, ttl: 64, payload: { kind: "udp", srcPort: DHCP_SERVER_PORT, dstPort: DHCP_CLIENT_PORT, payload: msg } };
      ctx.trace("dhcp.relay.return", "app", `[${this.names[back]}] DHCP 릴레이: 서버 ${pkt.src} 의 ${msg.op} 를 클라이언트 ${msg.clientMac} 에게 전달`, { op: msg.op, client: msg.clientMac }, frameId);
      this.ifaces[back]!.sendToMac(msg.clientMac, toClient, ctx, this.emit(back, ctx));
      return;
    }
    ctx.trace("dhcp.ignore", "app", `[${name}] 처리하지 않는 DHCP ${msg.op}${msg.giaddr ? " (giaddr 있음)" : ""} → 무시`, {}, frameId);
  }

  private handleIcmp(port: number, pkt: Ipv4Packet, icmp: IcmpPacket, frameId: number, ctx: NodeContext): void {
    if (icmp.type !== "echo-request") {
      ctx.trace("ip.drop", "L3", `요청한 적 없는 ICMP ${icmpLabel(icmp)} → 무시`, {}, frameId);
      return;
    }
    ctx.trace("icmp.echo.received", "app", `ICMP Echo 요청 수신 (from ${pkt.src}, seq=${icmp.seq})`, { from: pkt.src, seq: icmp.seq }, frameId);
    const iface = this.ifaces[port]!;
    const reply: Ipv4Packet = { kind: "ipv4", src: iface.ip!, dst: pkt.src, ttl: 64, payload: { kind: "icmp", type: "echo-reply", id: icmp.id, seq: icmp.seq } };
    ctx.trace("icmp.reply.sent", "app", `ICMP Echo 응답 생성 → ${pkt.src} (seq=${icmp.seq})`, { to: pkt.src, seq: icmp.seq });
    this.sendVia(reply, ctx, frameId);
  }

  /** 넥스트 홉이 속한(직접 연결된) 인터페이스 */
  private ifaceFor(nextHop: Ip): number {
    return this.ifaces.findIndex((i) => i.ip !== undefined && sameSubnet(nextHop, i.ip, i.prefix));
  }

  /** 라우팅 테이블 조회: 연결된 서브넷 → 스태틱 라우팅(긴 마스크 우선) → 디폴트 라우트 */
  route(dst: Ip): Route | undefined {
    for (let i = 0; i < this.ifaces.length; i++) {
      const iface = this.ifaces[i]!;
      if (iface.ip && sameSubnet(dst, iface.ip, iface.prefix)) return { out: i, nextHop: dst, kind: "connected" };
    }
    for (const r of [...this.routes].sort((a, b) => b.prefix - a.prefix)) {
      let match = false;
      try {
        match = sameSubnet(dst, r.dest, r.prefix);
      } catch {
        match = false;
      }
      if (!match) continue;
      const out = this.ifaceFor(r.via);
      if (out >= 0) return { out, nextHop: r.via, kind: "static" };
    }
    const order = this.outside !== undefined ? [this.outside, ...this.ifaces.map((_, i) => i).filter((i) => i !== this.outside)] : this.ifaces.map((_, i) => i);
    for (const i of order) {
      const iface = this.ifaces[i]!;
      if (iface.ip && iface.gateway) return { out: i, nextHop: iface.gateway, kind: "default" };
    }
    return undefined;
  }

  /** 내가 만든 패킷(응답)을 라우팅 테이블대로 내보낸다 */
  private sendVia(pkt: Ipv4Packet, ctx: NodeContext, frameId?: number): void {
    const r = this.route(pkt.dst);
    if (!r) {
      ctx.trace("ip.no-route", "L3", `No route: ${pkt.dst} 로 가는 경로가 없음 (연결된 서브넷도, 디폴트 라우트도 없음) → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    this.ifaces[r.out]!.sendIp(pkt, ctx, this.emit(r.out, ctx), r.nextHop);
  }

  /**
   * 패킷을 라우팅 테이블대로 다른 인터페이스로 넘긴다.
   * @param received 선에서 받은 그대로의 패킷 (NAT 역변환 전). TTL 초과 통지에 내장할 원래 패킷은 보낸 이가 알아볼 수 있게 이걸 쓴다
   */
  private forward(pkt: Ipv4Packet, inPort: number, frameId: number, ctx: NodeContext, received: Ipv4Packet = pkt): void {
    if (pkt.dst === "255.255.255.255" || pkt.dst === "0.0.0.0" || pkt.dst.startsWith("224.") || pkt.dst.startsWith("239.")) {
      ctx.trace("ip.drop", "L3", `브로드캐스트/멀티캐스트 ${pkt.dst} 는 라우터가 다른 네트워크로 넘기지 않음 → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    if (pkt.ttl <= 1) {
      const notice = this.ifaces[inPort]!.timeExceeded(received, ctx, frameId);
      if (notice) this.sendVia(notice, ctx, frameId);
      return;
    }
    const r = this.route(pkt.dst);
    if (!r) {
      const noAddr = this.ifaces.findIndex((i, k) => !i.ip && (this.clients[k] !== undefined || k === this.outside || k === 0));
      const hint =
        noAddr >= 0
          ? `${this.names[noAddr]} 에 주소가 없음 (케이블과 DHCP, 또는 수동 주소를 확인)`
          : "스태틱 라우팅을 추가하거나 디폴트 라우트(업링크 게이트웨이)를 설정하세요";
      ctx.trace("ip.no-route", "L3", `No route: ${pkt.dst} 로 가는 경로가 없음 (연결된 서브넷·스태틱 라우팅·디폴트 라우트 모두 해당 없음) → 드롭. ${hint}`, { dst: pkt.dst }, frameId);
      return;
    }
    const outName = this.names[r.out]!;
    const outIface = this.ifaces[r.out]!;
    if (!this.firewall.check(pkt, this.flowDirection(inPort, r.out), ctx, frameId)) return;
    let out: Ipv4Packet = { ...pkt, ttl: pkt.ttl - 1 };
    if (this.nat && r.out === this.outside) {
      if (inPort === this.outside) {
        ctx.trace("ip.no-route", "L3", `${pkt.dst} 로 가는 안쪽 경로가 없어 바깥으로 되돌아감 → 드롭. 스태틱 라우팅을 추가하세요 (예: ${networkOf(pkt.dst, 24)}/24 via 안쪽 게이트웨이)`, { dst: pkt.dst }, frameId);
        return;
      }
      const translated = this.nat.translate(out, outIface.ip!, ctx, frameId);
      if (!translated) return;
      out = translated;
    }
    const via =
      r.kind === "connected"
        ? `${networkOf(outIface.ip!, outIface.prefix)}/${outIface.prefix} 에 직접 연결`
        : r.kind === "static"
          ? `스태틱 라우팅, 넥스트 홉 ${r.nextHop}`
          : `디폴트 라우트, 넥스트 홉 ${r.nextHop}`;
    ctx.trace("ip.forward", "L3", `라우팅: ${pkt.dst} → ${outName} (${via}), TTL ${pkt.ttl} → ${out.ttl}`, { dst: pkt.dst, out: outName, kind: r.kind }, frameId);
    outIface.sendIp(out, ctx, this.emit(r.out, ctx), r.nextHop);
  }

  // ---------- 타이머 ----------

  onTimer(tag: string, data: unknown, ctx: NodeContext): void {
    if (tag === "arp-timeout") {
      for (const iface of this.ifaces) iface.onArpTimeout(data, ctx);
      return;
    }
    if (tag === DHCP_TIMER_TAG) {
      this.clients.forEach((c, i) => {
        if (c?.ownsTimer(data)) c.onTimeout(data, ctx, this.emit(i, ctx));
      });
    }
  }

  // ---------- 스냅샷 ----------

  ifaceStatus(i: number): string {
    const iface = this.ifaces[i]!;
    if (iface.ip) return `${iface.ip}/${iface.prefix}${this.modes[i] === "dhcp" ? " (DHCP)" : ""}`;
    if (!this.linkUp[i]) return "없음 (링크 다운)";
    if (this.modes[i] === "dhcp") return `없음 (DHCP: ${DHCP_STATE_LABEL[this.clients[i]?.state ?? "idle"]})`;
    return "없음 (수동 입력 필요)";
  }

  snapshot(): NodeSnapshot {
    const routes: string[][] = [];
    this.ifaces.forEach((iface, i) => {
      if (iface.ip) routes.push([`${networkOf(iface.ip, iface.prefix)}/${iface.prefix}`, this.names[i]!, "직접 연결"]);
    });
    for (const r of this.routes) {
      const out = this.ifaceFor(r.via);
      routes.push([`${r.dest}/${r.prefix}`, out >= 0 ? this.names[out]! : "(넥스트 홉에 닿는 인터페이스 없음)", `via ${r.via}`]);
    }
    const def = this.route("0.0.0.1");
    if (def && def.kind === "default") routes.push(["0.0.0.0/0", this.names[def.out]!, `via ${def.nextHop}`]);
    const tables: NodeSnapshot["tables"] = [{ title: "라우팅 테이블", columns: ["목적지", "인터페이스", "넥스트 홉"], rows: routes }];
    if (this.firewall.config.enabled) tables.push({ title: "방화벽 규칙", columns: ["#", "규칙"], rows: this.firewall.rows() });
    if (this.nat) {
      const publicIp = this.ifaces[this.outside!]!.ip;
      tables.push({ title: "NAT 테이블", columns: ["내부", "→ 외부", "시각"], rows: this.nat.rows(publicIp) });
      tables.push({ title: "포트 포워딩", columns: ["공인 포트", "내부"], rows: this.nat.forwardRows(publicIp) });
    }
    this.ifaces.forEach((iface, i) => tables.push({ title: `ARP 캐시 (${this.names[i]})`, columns: ["IP", "MAC", "학습 시각"], rows: iface.arpRows() }));
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [
        ...this.ifaces.map((_, i) => [this.names[i]!, this.ifaceStatus(i) + (this.relays[i] ? ` · DHCP 릴레이 → ${this.relays[i]}` : "")] as [string, string]),
        ...(this.firewall.config.enabled
          ? [["방화벽", `켜짐 · 규칙 ${this.firewall.config.rules.length}개 · 기본 ${this.firewall.config.defaultPolicy === "allow" ? "허용" : "차단"}`] as [string, string]]
          : []),
      ],
      tables,
    };
  }
}
