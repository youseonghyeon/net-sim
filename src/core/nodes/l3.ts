// 순수 L3 장치: 인터페이스 N개 사이를 라우팅한다. 게이트웨이(NAT 없음)와 NAT 박스(outside 인터페이스에서 변환)가 이 클래스다.
import { networkOf, sameSubnet, type Ip, type Mac } from "../addr";
import { DHCP_CLIENT_PORT, DHCP_SERVER_PORT, describeFrame, type EthernetFrame, type IcmpPacket, type Ipv4Packet } from "../packet";
import { DHCP_STATE_LABEL, DHCP_TIMER_TAG, DhcpClient } from "./dhcp";
import { hashCode } from "./host";
import { NetInterface, type Emit } from "./iface";
import { NatTable } from "./nat";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";

export interface L3IfaceConfig {
  name: string;
  mac: Mac;
  mode: "static" | "dhcp";
  ip?: Ip;
  prefix?: number;
  gateway?: Ip;
}

export interface StaticRoute {
  dest: Ip;
  prefix: number;
  via: Ip;
}

export interface L3Config {
  id: string;
  kind: "gateway" | "nat";
  interfaces: L3IfaceConfig[];
  /** NAT 박스: 이 인덱스의 인터페이스가 바깥(공인) 쪽 */
  outside?: number;
  routes?: StaticRoute[];
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
  readonly ifaces: NetInterface[];
  readonly names: string[];
  readonly modes: ("static" | "dhcp")[];
  readonly clients: (DhcpClient | undefined)[];
  readonly linkUp: boolean[];
  readonly nat: NatTable | undefined;
  readonly outside: number | undefined;
  routes: StaticRoute[];

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
  }

  setRoutes(routes: StaticRoute[], ctx: NodeContext): void {
    const key = (r: StaticRoute) => `${r.dest}/${r.prefix} via ${r.via}`;
    const before = new Set(this.routes.map(key));
    const after = new Set(routes.map(key));
    for (const r of routes) if (!before.has(key(r))) ctx.trace("ip.config", "sys", `정적 경로 추가: ${key(r)}`, { ...r });
    for (const r of this.routes) if (!after.has(key(r))) ctx.trace("ip.config", "sys", `정적 경로 삭제: ${key(r)}`, { ...r });
    this.routes = [...routes];
  }

  private emit(port: number, ctx: NodeContext): Emit {
    return (f) => ctx.send(port, f);
  }

  // ---------- 설정 ----------

  configure(interfaces: Omit<L3IfaceConfig, "name" | "mac">[], ctx: NodeContext): void {
    interfaces.forEach((c, i) => {
      const iface = this.ifaces[i];
      if (!iface) return;
      const name = this.names[i]!;
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
    this.linkUp[port] = up;
    if (up) {
      ctx.trace("link.up", "L1", `${name} 링크 연결됨`, { port });
      if (this.clients[port]) this.clients[port]!.start(ctx, this.emit(port, ctx));
      else if (this.ifaces[port]!.ip) this.ifaces[port]!.announce(ctx, this.emit(port, ctx));
      return;
    }
    ctx.trace("link.down", "L1", `${name} 링크 끊김`, { port });
    const iface = this.ifaces[port]!;
    iface.clearPending();
    if (this.clients[port]) {
      const had = iface.ip;
      iface.clearAddress();
      this.clients[port]!.stop();
      if (had) ctx.trace("dhcp.release", "app", `[${name}] 링크가 끊겨 주소 ${had} 해제`, { ip: had });
    }
  }

  // ---------- 수신 ----------

  receive(port: number, frame: EthernetFrame, ctx: NodeContext): void {
    const iface = this.ifaces[port]!;
    const name = this.names[port]!;
    if (!iface.accepts(frame)) {
      ctx.trace("frame.drop", "L2", `${name} 수신: 목적지 MAC ${frame.dst} 가 내 MAC 아님 → 폐기`, { dst: frame.dst }, frame.id);
      return;
    }
    ctx.trace("frame.receive", "L2", `${name} 수신: ${describeFrame(frame)} [${frame.src}]`, { port, src: frame.src }, frame.id);
    if (frame.payload.kind === "arp") {
      iface.handleArp(frame.payload, frame.id, ctx, this.emit(port, ctx));
      return;
    }
    this.handleIp(port, frame.payload, frame.id, ctx);
  }

  private handleIp(port: number, pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const name = this.names[port]!;
    if (pkt.payload.kind === "udp") {
      const udp = pkt.payload;
      if (udp.dstPort === DHCP_CLIENT_PORT && this.clients[port]) this.clients[port]!.handle(udp.payload, frameId, ctx, this.emit(port, ctx));
      else if (udp.dstPort === DHCP_SERVER_PORT) ctx.trace("dhcp.ignore", "app", `[${name}] DHCP ${udp.payload.op} 브로드캐스트 — 이 장치는 DHCP 서버가 아니므로 무시`, {}, frameId);
      else ctx.trace("ip.drop", "L4", `[${name}] UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 폐기`, { port: udp.dstPort }, frameId);
      return;
    }
    const mine = this.ifaces.findIndex((i) => i.ip !== undefined && i.ip === pkt.dst);
    const fromOutside = this.nat !== undefined && port === this.outside;
    if (fromOutside && mine >= 0 && mine !== this.outside) {
      ctx.trace("ip.drop", "L3", `[${name}] 바깥에서 안쪽 주소 ${pkt.dst} 로 온 패킷 → 폐기. NAT 뒤의 사설 주소는 바깥에서 닿을 수 없음`, { dst: pkt.dst }, frameId);
      return;
    }
    // 바깥에서 공인 주소로 온 패킷: ping 요청만 내가 직접 받고, 나머지(응답·TCP)는 NAT 테이블로 내부 호스트를 찾는다
    if (mine >= 0 && !(fromOutside && !(pkt.payload.kind === "icmp" && pkt.payload.type === "echo-request"))) {
      if (pkt.payload.kind === "tcp") {
        ctx.trace("ip.drop", "L4", `이 장치는 TCP 서비스를 열지 않음 → 폐기`, {}, frameId);
        return;
      }
      this.handleIcmp(mine, pkt, pkt.payload, frameId, ctx);
      return;
    }
    let inner = pkt;
    if (fromOutside) {
      if (mine < 0) {
        ctx.trace("ip.drop", "L3", `[${name}] 목적지 ${pkt.dst} 는 내 공인 주소가 아님 → 폐기`, { dst: pkt.dst }, frameId);
        return;
      }
      const restored = this.nat!.restore(pkt, this.ifaces[port]!.ip!, ctx, frameId);
      if (!restored) return;
      inner = restored;
    }
    this.forward(inner, port, frameId, ctx);
  }

  private handleIcmp(port: number, pkt: Ipv4Packet, icmp: IcmpPacket, frameId: number, ctx: NodeContext): void {
    if (icmp.type !== "echo-request") {
      ctx.trace("ip.drop", "L3", `요청한 적 없는 Echo 응답 → 무시`, {}, frameId);
      return;
    }
    ctx.trace("icmp.echo.received", "app", `ICMP Echo 요청 수신 (from ${pkt.src}, seq=${icmp.seq})`, { from: pkt.src, seq: icmp.seq }, frameId);
    const iface = this.ifaces[port]!;
    const reply: Ipv4Packet = { kind: "ipv4", src: iface.ip!, dst: pkt.src, ttl: 64, payload: { kind: "icmp", type: "echo-reply", id: icmp.id, seq: icmp.seq } };
    ctx.trace("icmp.reply.sent", "app", `ICMP Echo 응답 생성 → ${pkt.src} (seq=${icmp.seq})`, { to: pkt.src, seq: icmp.seq });
    this.sendVia(reply, ctx, frameId);
  }

  /** 다음 홉이 속한(직접 연결된) 인터페이스 */
  private ifaceFor(nextHop: Ip): number {
    return this.ifaces.findIndex((i) => i.ip !== undefined && sameSubnet(nextHop, i.ip, i.prefix));
  }

  /** 라우팅 테이블 조회: 연결된 서브넷 → 정적 경로(긴 프리픽스 우선) → 기본 경로 */
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
      ctx.trace("ip.no-route", "L3", `${pkt.dst} 로 가는 경로 없음 (연결된 서브넷도, 기본 경로도 없음) → 폐기`, { dst: pkt.dst }, frameId);
      return;
    }
    this.ifaces[r.out]!.sendIp(pkt, ctx, this.emit(r.out, ctx), r.nextHop);
  }

  private forward(pkt: Ipv4Packet, inPort: number, frameId: number, ctx: NodeContext): void {
    if (pkt.dst === "255.255.255.255" || pkt.dst === "0.0.0.0" || pkt.dst.startsWith("224.") || pkt.dst.startsWith("239.")) {
      ctx.trace("ip.drop", "L3", `브로드캐스트/멀티캐스트 ${pkt.dst} 는 라우터가 다른 네트워크로 넘기지 않음 → 폐기`, { dst: pkt.dst }, frameId);
      return;
    }
    if (pkt.ttl <= 1) {
      ctx.trace("ip.ttl-expired", "L3", `TTL 이 0 이 되어 폐기 (루프 방지)`, { dst: pkt.dst }, frameId);
      return;
    }
    const r = this.route(pkt.dst);
    if (!r) {
      const noAddr = this.ifaces.findIndex((i, k) => !i.ip && (this.clients[k] !== undefined || k === this.outside || k === 0));
      const hint =
        noAddr >= 0
          ? `${this.names[noAddr]} 에 주소가 없음 (케이블과 DHCP, 또는 수동 주소를 확인)`
          : "정적 경로를 추가하거나 기본 경로(업링크 게이트웨이)를 설정하세요";
      ctx.trace("ip.no-route", "L3", `${pkt.dst} 로 가는 경로 없음 (연결된 서브넷·정적 경로·기본 경로 모두 해당 없음) → 폐기. ${hint}`, { dst: pkt.dst }, frameId);
      return;
    }
    const outName = this.names[r.out]!;
    const outIface = this.ifaces[r.out]!;
    let out: Ipv4Packet = { ...pkt, ttl: pkt.ttl - 1 };
    if (this.nat && r.out === this.outside) {
      if (inPort === this.outside) {
        ctx.trace("ip.no-route", "L3", `${pkt.dst} 로 가는 안쪽 경로가 없어 바깥으로 되돌아감 → 폐기. 정적 경로를 추가하세요 (예: ${networkOf(pkt.dst, 24)}/24 via 안쪽 게이트웨이)`, { dst: pkt.dst }, frameId);
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
          ? `정적 경로, 다음 홉 ${r.nextHop}`
          : `기본 경로, 다음 홉 ${r.nextHop}`;
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
    if (!this.linkUp[i]) return "없음 (케이블 없음)";
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
      routes.push([`${r.dest}/${r.prefix}`, out >= 0 ? this.names[out]! : "(다음 홉에 닿는 인터페이스 없음)", `via ${r.via}`]);
    }
    const def = this.route("0.0.0.1");
    if (def && def.kind === "default") routes.push(["0.0.0.0/0", this.names[def.out]!, `via ${def.nextHop}`]);
    const tables: NodeSnapshot["tables"] = [{ title: "라우팅 테이블", columns: ["목적지", "인터페이스", "다음 홉"], rows: routes }];
    if (this.nat) tables.push({ title: "NAT 테이블", columns: ["내부", "→ 외부", "시각"], rows: this.nat.rows(this.ifaces[this.outside!]!.ip) });
    this.ifaces.forEach((iface, i) => tables.push({ title: `ARP 캐시 (${this.names[i]})`, columns: ["IP", "MAC", "학습 시각"], rows: iface.arpRows() }));
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: this.ifaces.map((_, i) => [this.names[i]!, this.ifaceStatus(i)] as [string, string]),
      tables,
    };
  }
}
