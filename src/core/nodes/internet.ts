import { isMulticastMac, isPrivateIp, type Ip, type Mac } from "../addr";
import { ALL_NODES, canonIp6, formatIp6, isGlobal6, isIpv6, isMulticast6, parseIp6, sameSubnet6 } from "../addr6";
import {
  DHCP_CLIENT_PORT,
  DHCP_SERVER_PORT,
  DHCP6_MULTICAST_MAC,
  DHCP6_CLIENT_PORT,
  DHCP6_SERVER_PORT,
  DNS_PORT,
  describeFrame,
  icmpLabel,
  isControl,
  isNdp,
  UNREACHABLE_LABEL,
  UNREACHABLE6_LABEL,
  type Dhcp6Message,
  type DnsMessage,
  type EthernetFrame,
  type IpPacket,
  type Ipv4Packet,
  type Ipv6Packet,
  SIGNAL_PORT,
  STUN_PORT,
  type Endpoint,
  type P2pMessage,
  type StunMessage,
  type UdpPacket,
} from "../packet";
import { DhcpServer } from "./dhcp";
import { SIGNAL_SERVER, STUN_SERVERS, TURN_SERVER } from "./p2p";
import { normalizeName, PUBLIC_ZONE, PUBLIC_ZONE6 } from "./dns";
import { DAD_TIMER_TAG, Ipv6Interface, NDP_TIMEOUT_TAG, RA_PERIODIC_TAG } from "./ipv6";
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

/** 이름이 알려진 공인 IPv6 서버 */
export const KNOWN_SERVERS6: Record<Ip, string> = {
  "2001:4860:4860::8888": "Google DNS",
  "2606:4700:4700::1111": "Cloudflare DNS",
  ...Object.fromEntries(PUBLIC_ZONE6.map((r) => [r.ip, r.name])),
};

/** 공인 DNS 서버 주소 (이 주소들로 온 질의에 PUBLIC_ZONE 으로 답한다) */
export const PUBLIC_DNS: Ip[] = ["8.8.8.8", "1.1.1.1"];
export const PUBLIC_DNS6: Ip[] = ["2001:4860:4860::8888", "2606:4700:4700::1111"];

/**
 * 인터넷(ISP) 노드. 포트 하나로 라우터 WAN 과 연결된다.
 * ISP 게이트웨이 역할(공인 주소 DHCP 임대)과 "인터넷 저편의 서버" 역할(공인 주소로 온 ping 에 응답)을 함께 한다.
 */
export class Internet implements SimNode {
  /** 인터넷 왕복에 걸리는 시간 (경로 생략) */
  static readonly LATENCY = 30;
  /** "인터넷 저편의 클라이언트" 주소 (RFC 5737 TEST-NET-2). 바깥에서 시작하는 연결의 출발지 */
  static readonly REMOTE_CLIENT: Ip = "198.51.100.7";
  /** 인터넷 저편 클라이언트의 IPv6 주소 */
  static readonly REMOTE_CLIENT6: Ip = "2001:db8:beef::7";
  /** ISP 링크의 IPv6 (고객 라우터 WAN 이 여기서 RA 로 주소를 만든다) */
  static readonly ISP_V6: Ip = "2001:db8:ffff::1";
  /** DHCPv6-PD 로 나눠 줄 풀 (/40 에서 고객마다 /56) */
  static readonly PD_POOL: Ip = "2001:db8:1000::";
  static readonly PD_LENGTH = 56;

  readonly type = "internet" as const;
  readonly portCount = 1;
  readonly id: string;
  readonly iface: NetInterface;
  readonly dhcpServer: DhcpServer;
  /** 인터넷 저편의 웹 서버들을 대신하는 TCP 스택 (응답은 왕복 지연 뒤에 나간다) */
  readonly tcp: TcpStack;
  /** ISP 의 IPv6: RS 에 RA 로, NS 에 NA 로만 답한다 (먼저 보내지 않아 IPv6 를 안 쓰는 구성의 로그는 그대로) */
  readonly v6: Ipv6Interface;
  /** 고객(클라이언트 MAC)마다 한 번 정한 /56 (다시 요청하면 같은 것) */
  private readonly pdAlloc = new Map<Mac, Ip>();
  /** 지금 위임 중인 프리픽스 → 그 고객 라우터 (WAN 링크 로컬 = 넥스트 홉) */
  readonly delegations = new Map<Ip, { client: Mac; via: Ip; at: number }>();

  constructor(cfg: InternetConfig) {
    this.id = cfg.id;
    this.iface = new NetInterface(cfg.mac, { ip: cfg.ip ?? "203.0.113.1", prefix: cfg.prefix ?? 24 });
    this.dhcpServer = new DhcpServer({ enabled: true, ...(cfg.pool ?? { start: "203.0.113.100", end: "203.0.113.199" }) }, this.iface);
    this.tcp = new TcpStack({ send: (pkt, ctx) => ctx.timer(Internet.LATENCY * 2, "inet-send", { pkt }) });
    this.v6 = new Ipv6Interface(cfg.mac, true, "isp");
    this.v6.startQuiet({ enabled: true, addrs: [{ ip: Internet.ISP_V6, prefix: 64 }], ra: true, raDns: PUBLIC_DNS6[0] });
    this.tcp.listening.add(80);
    this.tcp.listening.add(22); // 인터넷 저편 서버들은 SSH 도 받는다 (오래 열린 세션 실험용)
    this.tcp.listening.add(443); // HTTPS (TLS)
    this.tcp.tlsPorts.add(443);
  }

  private emit(ctx: NodeContext): Emit {
    return (f) => ctx.send(0, f);
  }

  /** 인터넷 저편의 클라이언트가 dst:port 로 TCP 연결을 시작한다 (포트 포워딩 시연용) */
  connectFrom(rawDst: Ip, port: number, ctx: NodeContext): void {
    const dst = canonIp6(rawDst) ?? rawDst;
    if (isIpv6(dst)) {
      const src6 = Internet.REMOTE_CLIENT6;
      if (!this.route6(dst)) {
        ctx.trace("ip.drop", "L3", `인터넷 저편의 클라이언트 ${src6} 가 [${dst}]:${port} 로 연결 시도 — ISP 가 모르는 IPv6 주소 (공유기가 DHCPv6-PD 로 위임받은 프리픽스 안이어야 인터넷에서 닿는다)`, { src: src6, dst, port });
        this.tcp.recordFailure(src6, dst, port, "ISP 가 모르는 IPv6 주소", ctx);
        return;
      }
      ctx.trace("inet.forward", "app", `인터넷 저편의 클라이언트 ${src6} 가 [${dst}]:${port} 로 연결 시도 (바깥에서 시작한 통신, IPv6 — NAT 가 없어 집 안 장치의 주소로 바로 간다)`, { src: src6, dst, port });
      this.tcp.connect(src6, dst, port, ctx);
      return;
    }
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
    if (!up) {
      this.iface.clearPending();
      this.v6.clearPending();
      this.v6.neighbors.clear();
      // 위임은 IPv4 임대처럼 남겨 둔다: 스위치 너머 공유기는 회선이 끊긴 줄 모르므로 다시 이어지면 그 경로를 그대로 쓴다
    }
  }

  receive(_port: number, frame: EthernetFrame, ctx: NodeContext): void {
    // 가입하지 않은 멀티캐스트(예: 라우터끼리 주고받는 RIP)는 NIC 가 하드웨어에서 조용히 거른다. IPv6 는 모든 노드·solicited-node·모든 라우터·DHCPv6 서버 그룹
    const v6Group = this.v6.accepts(frame.dst) || frame.dst === DHCP6_MULTICAST_MAC;
    if (isMulticastMac(frame.dst) && !v6Group) return;
    if (!this.iface.accepts(frame) && !v6Group) {
      ctx.trace("frame.drop", "L2", `목적지 MAC ${frame.dst} 가 ISP 게이트웨이 MAC 아님 → 드롭`, { dst: frame.dst }, frame.id);
      return;
    }
    ctx.trace("frame.receive", "L2", `프레임 수신: ${describeFrame(frame)} [${frame.src}]`, { src: frame.src, dst: frame.dst }, frame.id);
    if (frame.payload.kind === "arp") {
      this.iface.handleArp(frame.payload, frame.id, ctx, this.emit(ctx));
      return;
    }
    if (frame.payload.kind === "ipv4") this.handleIp(frame.payload, frame.id, ctx);
    else if (frame.payload.kind === "ipv6") this.handleIp6(frame.payload, frame, ctx);
  }

  // ---------- IPv6 ----------

  /** 위임한 프리픽스 중 이 주소가 속한 것 */
  private delegationFor(ip: Ip): { prefix: Ip; via: Ip; client: Mac } | undefined {
    for (const [prefix, d] of this.delegations) if (sameSubnet6(ip, prefix, Internet.PD_LENGTH)) return { prefix, via: d.via, client: d.client };
    return undefined;
  }

  /** ISP 가 이 주소로 보낼 수 있는지: ISP 링크, 위임한 프리픽스 (넥스트 홉 = 고객 라우터) */
  private route6(dst: Ip): { nextHop?: Ip } | undefined {
    if (sameSubnet6(dst, Internet.ISP_V6, 64)) return {};
    const d = this.delegationFor(dst);
    return d ? { nextHop: d.via } : undefined;
  }

  /** 인터넷 저편에서 만든 IPv6 패킷을 고객에게 */
  private send6(pkt: Ipv6Packet, ctx: NodeContext): void {
    const r = this.route6(pkt.dst);
    if (!r) {
      ctx.trace("ip.no-route", "L3", `ISP: ${pkt.dst} 로 가는 IPv6 경로가 없음 (위임한 프리픽스·ISP 링크가 아님) → 드롭`, { dst: pkt.dst });
      return;
    }
    this.v6.send(pkt, ctx, this.emit(ctx), r.nextHop);
  }

  /** 공인 IPv6 인터넷 저편으로 보는 주소: 글로벌인데 문서용(2001:db8::/32)은 아님 */
  private static isPublic6(ip: Ip): boolean {
    return isGlobal6(ip) && !sameSubnet6(ip, "2001:db8::", 32);
  }

  private handleIp6(pkt: Ipv6Packet, frame: EthernetFrame, ctx: NodeContext): void {
    const emit = this.emit(ctx);
    const p = pkt.payload;
    if (isNdp(p)) {
      this.v6.handleNdp(pkt, p, frame, ctx, emit);
      return;
    }
    if (p.kind === "udp" && p.payload.kind === "dhcp6" && p.dstPort === DHCP6_SERVER_PORT) {
      this.handleDhcp6(pkt, p.payload, frame.id, ctx);
      return;
    }
    if (this.v6.owns(pkt.dst) || pkt.dst === ALL_NODES) {
      if (p.kind === "icmp6" && p.type === "echo-request") {
        ctx.trace("icmp.echo.received", "app", `ISP 라우터가 ICMPv6 Echo 요청 수신 (from ${pkt.src})`, { from: pkt.src }, frame.id);
        const src = pkt.dst === ALL_NODES ? Internet.ISP_V6 : pkt.dst;
        this.send6({ kind: "ipv6", src, dst: pkt.src, hopLimit: 64, payload: { kind: "icmp6", type: "echo-reply", id: p.id, seq: p.seq } }, ctx);
      } else ctx.trace("ip.drop", "L3", `ISP 라우터는 이 IPv6 패킷에 대한 서비스가 없음 → 드롭`, {}, frame.id);
      return;
    }
    if (isMulticast6(pkt.dst)) return;
    // 응답을 돌려줄 수 있는 출발지인가: ISP 가 경로를 아는 주소여야 한다 (IPv4 의 "사설 출발지" 드롭과 같은 자리)
    if (!this.route6(pkt.src) && pkt.src !== Internet.REMOTE_CLIENT6) {
      const fromPool = sameSubnet6(pkt.src, Internet.PD_POOL, 40);
      ctx.trace(
        "ip.drop",
        "L3",
        fromPool
          ? `ISP: 출발지 ${pkt.src} 는 위임 풀 안이지만 지금 이 ISP 가 위임한 기록이 없음 → 드롭. ISP 를 새로 붙였거나 기록이 사라졌는데 공유기는 옛 위임을 쓰는 중 — 공유기 WAN 케이블을 다시 꽂으면(또는 공유기 IPv6 를 껐다 켜면) 다시 위임받는다`
          : `ISP: 출발지 ${pkt.src} 는 ISP 가 위임한 프리픽스·ISP 링크의 주소가 아님 → 응답을 돌려줄 경로가 없어 드롭. 인터넷 IPv6 는 공유기가 DHCPv6-PD 로 받은 프리픽스로 나가야 한다 (게이트웨이·NAT 박스에 손으로 넣은 IPv6 는 ISP 가 모른다)`,
        { src: pkt.src },
        frame.id,
      );
      return;
    }
    if (pkt.hopLimit <= 1) {
      const notice = this.v6.timeExceeded(pkt, ctx, frame.id);
      if (notice) this.send6(notice, ctx);
      return;
    }
    // 다른 고객에게 가는 것은 그쪽 위임 경로로 (ISP 안에서 한 홉)
    const r = this.route6(pkt.dst);
    if (r) {
      const d = this.delegationFor(pkt.dst);
      ctx.trace("ip.forward", "L3", `ISP: ${pkt.dst} 는 ${d ? `고객에게 위임한 프리픽스 ${d.prefix}/${Internet.PD_LENGTH} → 그 공유기(${d.via})로` : "ISP 링크 안"}, Hop Limit ${pkt.hopLimit} → ${pkt.hopLimit - 1}`, { dst: pkt.dst }, frame.id);
      this.v6.send({ ...pkt, hopLimit: pkt.hopLimit - 1 }, ctx, emit, r.nextHop);
      return;
    }
    if (pkt.dst === Internet.REMOTE_CLIENT6 && p.kind === "tcp") {
      this.tcp.handle(pkt, p, ctx);
      return;
    }
    if (pkt.dst === Internet.REMOTE_CLIENT6 && p.kind === "icmp6" && p.type === "echo-request") {
      // 바깥 클라이언트도 인터넷 저편의 한 장치: IPv4 짝(198.51.100.7)처럼 ping 에 답한다
      ctx.trace("inet.forward", "app", `인터넷 경로로 ${pkt.dst} (외부 클라이언트) 에 전달 (IPv6) — 왕복 ${Internet.LATENCY * 2}ms`, { dst: pkt.dst, src: pkt.src }, frame.id);
      ctx.timer(Internet.LATENCY * 2, "inet-reply6", { src: pkt.src, dst: pkt.dst, id: p.id, seq: p.seq });
      return;
    }
    if (p.kind === "icmp6" && p.type === "unreachable" && pkt.dst === Internet.REMOTE_CLIENT6) {
      const reason = `${UNREACHABLE6_LABEL[p.code]} (${pkt.src})`;
      if (this.tcp.onUnreachable(p.original, reason, ctx)) ctx.trace("icmp.unreachable.received", "app", `외부 클라이언트가 ${pkt.src} 로부터 ICMPv6 ${UNREACHABLE6_LABEL[p.code]} 수신 → 연결 실패`, { from: pkt.src }, frame.id);
      return;
    }
    if (!Internet.isPublic6(pkt.dst)) {
      ctx.trace("ip.no-route", "L3", `ISP: ${pkt.dst} 는 인터넷에 없는 주소 (위임하지 않은 프리픽스·문서용 2001:db8::/32) → 드롭하고 Destination Unreachable (no route)`, { dst: pkt.dst }, frame.id);
      const notice = this.v6.unreachable(pkt, "net", ctx, frame.id);
      if (notice) this.send6(notice, ctx);
      return;
    }
    const name = KNOWN_SERVERS6[pkt.dst];
    if (p.kind === "udp" && p.payload.kind === "dns" && p.dstPort === DNS_PORT && p.payload.op === "query") {
      if (!PUBLIC_DNS6.includes(pkt.dst)) {
        ctx.trace("ip.drop", "L4", `${pkt.dst} 에는 DNS 서비스가 없음 → 드롭 (공인 IPv6 DNS 는 ${PUBLIC_DNS6.join(", ")})`, { dst: pkt.dst }, frame.id);
        return;
      }
      const m = p.payload;
      ctx.trace("dns.query.received", "app", `공인 DNS ${pkt.dst}: 질의 수신 "${normalizeName(m.name)}${m.qtype === "AAAA" ? " AAAA" : ""}?" (from ${pkt.src}, IPv6) — 답은 ${Internet.LATENCY * 2}ms 뒤`, { name: m.name, from: pkt.src }, frame.id);
      ctx.timer(Internet.LATENCY * 2, "inet-dns", { server: pkt.dst, to: pkt.src, toPort: p.srcPort, id: m.id, name: m.name, qtype: m.qtype });
      return;
    }
    if (p.kind === "tcp") {
      ctx.trace("inet.forward", "app", `인터넷 경로로 [${pkt.dst}]${name ? ` (${name})` : ""}:${p.dstPort} 에 전달 (IPv6) — 중간 라우터 생략, 서버 응답은 ${Internet.LATENCY * 2}ms 뒤 도착`, { dst: pkt.dst, src: pkt.src }, frame.id);
      this.tcp.handle(pkt, p, ctx);
      return;
    }
    if (p.kind === "icmp6" && p.type === "echo-request") {
      ctx.trace("inet.forward", "app", `인터넷 경로로 ${pkt.dst}${name ? ` (${name})` : ""} 에 전달 (IPv6) — 중간 라우터들은 생략, 왕복 ${Internet.LATENCY * 2}ms`, { dst: pkt.dst, src: pkt.src }, frame.id);
      ctx.timer(Internet.LATENCY * 2, "inet-reply6", { src: pkt.src, dst: pkt.dst, id: p.id, seq: p.seq });
      return;
    }
    ctx.trace("ip.drop", "L3", `공인 IPv6 주소 ${pkt.dst} 로 가는 패킷 → 시뮬레이션 밖이므로 드롭`, {}, frame.id);
  }

  /** DHCPv6-PD 서버: 고객 라우터마다 /56 을 위임하고 그 프리픽스로 가는 경로를 만든다 */
  private handleDhcp6(pkt: Ipv6Packet, m: Dhcp6Message, frameId: number, ctx: NodeContext): void {
    if (m.type === "release") {
      for (const [prefix, d] of this.delegations) {
        if (d.client !== m.clientId) continue;
        this.delegations.delete(prefix);
        ctx.trace("dhcp6.delegate", "app", `ISP: ${m.clientId} 가 ${prefix}/${Internet.PD_LENGTH} 를 돌려줌 → 그 프리픽스로 가는 경로 삭제`, { prefix, client: m.clientId }, frameId);
      }
      return;
    }
    if (m.type !== "solicit" && m.type !== "request") return;
    let prefix = this.pdAlloc.get(m.clientId);
    if (!prefix) {
      const base = parseIp6(Internet.PD_POOL)!;
      prefix = formatIp6(base | (BigInt(this.pdAlloc.size + 1) << BigInt(128 - Internet.PD_LENGTH)));
      this.pdAlloc.set(m.clientId, prefix);
    }
    const type = m.type === "solicit" ? "advertise" : "reply";
    if (m.type === "request") {
      this.delegations.set(prefix, { client: m.clientId, via: pkt.src, at: ctx.now });
      ctx.trace(
        "dhcp6.delegate",
        "app",
        `ISP: ${prefix}/${Internet.PD_LENGTH} 를 ${m.clientId} 에게 위임 확정 → 이 프리픽스로 오는 패킷은 그 공유기(${pkt.src})로 보내는 경로 추가 (위임 = 경로)`,
        { prefix, client: m.clientId, via: pkt.src },
        frameId,
      );
    } else ctx.trace("dhcp6.received", "app", `ISP DHCPv6 서버: ${m.clientId} 의 Solicit (IA_PD) → ${prefix}/${Internet.PD_LENGTH} 를 제안 (Advertise)`, { prefix, client: m.clientId }, frameId);
    const reply: Dhcp6Message = { kind: "dhcp6", type, xid: m.xid, clientId: m.clientId, serverId: this.iface.mac, prefix: { prefix, length: Internet.PD_LENGTH } };
    this.v6.send({ kind: "ipv6", src: this.v6.linkLocal, dst: pkt.src, hopLimit: 64, payload: { kind: "udp", srcPort: DHCP6_SERVER_PORT, dstPort: DHCP6_CLIENT_PORT, payload: reply } }, ctx, this.emit(ctx));
  }

  // ---------- P2P 를 돕는 공인 서버 (STUN·시그널링·TURN) ----------

  /** 시그널링 서버: 이름 → 등록한 기기의 바깥 주소 */
  readonly signalRegistry = new Map<string, Endpoint>();
  /** TURN: 릴레이 포트 → 할당받은 기기의 바깥 주소 */
  readonly turnAllocations = new Map<number, Endpoint>();
  private nextRelayPort = 49152;

  private serverSend(src: Ip, srcPort: number, to: Endpoint, payload: StunMessage | P2pMessage, ctx: NodeContext): void {
    this.iface.sendIp({ kind: "ipv4", src, dst: to.ip, ttl: 54, payload: { kind: "udp", srcPort, dstPort: to.port, payload } }, ctx, this.emit(ctx));
  }

  /** STUN·시그널링·TURN 서버 주소로 온 UDP. 처리했으면 true */
  private p2pServers(pkt: Ipv4Packet, udp: UdpPacket, frameId: number, ctx: NodeContext): boolean {
    const m = udp.payload;
    const from: Endpoint = { ip: pkt.src, port: udp.srcPort };
    const isServer = STUN_SERVERS.includes(pkt.dst) || pkt.dst === SIGNAL_SERVER || pkt.dst === TURN_SERVER;
    if (!isServer) return false;
    if (isPrivateIp(pkt.src)) {
      ctx.trace("ip.drop", "L3", `출발지가 사설 주소 ${pkt.src} → 응답을 돌려줄 수 없어 드롭 (NAT 가 공인 주소로 바꿔야 함)`, { src: pkt.src }, frameId);
      return true;
    }
    if (STUN_SERVERS.includes(pkt.dst) && udp.dstPort === STUN_PORT && m.kind === "stun" && m.op === "binding-request") {
      ctx.trace("p2p.stun", "app", `STUN 서버 ${pkt.dst}: Binding 요청의 출발지가 ${from.ip}:${from.port} → 그대로 알려 줌 ("바깥에서 본 당신의 주소")`, { mapped: `${from.ip}:${from.port}` }, frameId);
      this.serverSend(pkt.dst, STUN_PORT, from, { kind: "stun", op: "binding-response", txid: m.txid, mapped: from }, ctx);
      return true;
    }
    if (pkt.dst === SIGNAL_SERVER && udp.dstPort === SIGNAL_PORT && m.kind === "p2p") {
      if (m.op === "register") {
        this.signalRegistry.set(m.from, from);
        ctx.trace("p2p.signal", "app", `시그널링 서버: "${m.from}" 등록 — 연락할 주소는 ${from.ip}:${from.port} (그 기기의 NAT 바깥)`, { name: m.from, at: `${from.ip}:${from.port}` }, frameId);
        this.serverSend(SIGNAL_SERVER, SIGNAL_PORT, from, { kind: "p2p", op: "registered", from: "signal", candidates: [{ type: "srflx", ...from }] }, ctx);
        return true;
      }
      if ((m.op === "offer" || m.op === "answer" || m.op === "relay") && m.to) {
        const to = this.signalRegistry.get(m.to);
        if (!to) {
          ctx.trace("p2p.signal", "app", `시그널링 서버: "${m.to}" 는 등록돼 있지 않음 → ${m.from} 에게 오류`, { to: m.to }, frameId);
          this.serverSend(SIGNAL_SERVER, SIGNAL_PORT, from, { kind: "p2p", op: "error", from: "signal", to: m.to, error: `상대 "${m.to}" 가 시그널링 서버에 등록돼 있지 않음 (상대의 P2P 앱이 켜져 있고 인터넷에 닿는지 확인)` }, ctx);
          return true;
        }
        ctx.trace("p2p.signal", "app", `시그널링 서버: ${m.from} 의 ${m.op} 를 ${m.to} (${to.ip}:${to.port}) 에게 전달 — 두 기기는 서로의 주소를 이렇게 처음 안다`, { from: m.from, to: m.to }, frameId);
        this.serverSend(SIGNAL_SERVER, SIGNAL_PORT, to, m, ctx);
        return true;
      }
    }
    if (pkt.dst === TURN_SERVER && udp.dstPort === STUN_PORT && m.kind === "stun") {
      if (m.op === "allocate-request") {
        const key = `${from.ip}:${from.port}`;
        let port = [...this.turnAllocations].find(([, o]) => `${o.ip}:${o.port}` === key)?.[0];
        if (port === undefined) {
          port = this.nextRelayPort++;
          this.turnAllocations.set(port, from);
        }
        ctx.trace("p2p.relay", "app", `TURN 서버: ${key} 에게 릴레이 주소 ${TURN_SERVER}:${port} 할당 — 이 주소로 온 것은 ${key} 에게 전해 준다`, { relay: `${TURN_SERVER}:${port}`, owner: key }, frameId);
        this.serverSend(TURN_SERVER, STUN_PORT, from, { kind: "stun", op: "allocate-response", txid: m.txid, relayed: { ip: TURN_SERVER, port }, mapped: from }, ctx);
        return true;
      }
      if (m.op === "send" && m.peer && m.data) {
        const port = [...this.turnAllocations].find(([, o]) => o.ip === from.ip && o.port === from.port)?.[0];
        if (port === undefined) {
          ctx.trace("ip.drop", "L4", `TURN 서버: 할당받지 않은 ${from.ip}:${from.port} 의 Send → 드롭`, {}, frameId);
          return true;
        }
        ctx.trace("p2p.relay", "app", `TURN 서버: ${from.ip}:${from.port} 의 Send 를 릴레이 주소 ${TURN_SERVER}:${port} 에서 ${m.peer.ip}:${m.peer.port} 로 내보냄`, { relay: port }, frameId);
        this.serverSend(TURN_SERVER, port, m.peer, m.data, ctx);
        return true;
      }
      return false;
    }
    if (pkt.dst === TURN_SERVER && udp.dstPort !== STUN_PORT && m.kind === "p2p") {
      const owner = this.turnAllocations.get(udp.dstPort);
      if (!owner) {
        ctx.trace("ip.drop", "L4", `TURN 서버: 할당되지 않은 릴레이 포트 ${udp.dstPort} → 드롭`, { port: udp.dstPort }, frameId);
        return true;
      }
      ctx.trace("p2p.relay", "app", `TURN 서버: 릴레이 주소 ${TURN_SERVER}:${udp.dstPort} 로 ${from.ip}:${from.port} 가 보낸 것을 ${owner.ip}:${owner.port} 에게 Data 로 전해 줌`, { relay: udp.dstPort }, frameId);
      this.serverSend(TURN_SERVER, STUN_PORT, owner, { kind: "stun", op: "data", txid: 0, peer: from, data: m }, ctx);
      return true;
    }
    return false;
  }

  private handleIp(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const emit = this.emit(ctx);
    if (pkt.payload.kind === "udp") {
      const udp = pkt.payload;
      const m = udp.payload;
      if (m.kind === "dhcp" && udp.dstPort === DHCP_SERVER_PORT) this.dhcpServer.handle(m, frameId, ctx, emit);
      else if (m.kind === "dhcp" && udp.dstPort === DHCP_CLIENT_PORT) ctx.trace("dhcp.ignore", "app", `DHCP 클라이언트 메시지는 내 것이 아님 → 무시`, {}, frameId);
      else if (m.kind === "dns" && udp.dstPort === DNS_PORT && m.op === "query") this.handleDns(pkt, udp.srcPort, m, frameId, ctx);
      else if (m.kind === "dns") ctx.trace("ip.drop", "L4", `공인 DNS 가 아닌 주소로 온 DNS 응답 → 드롭`, {}, frameId);
      else if (this.p2pServers(pkt, udp, frameId, ctx)) return;
      else ctx.trace("ip.drop", "L4", `UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 드롭`, { port: udp.dstPort }, frameId);
      return;
    }
    const p = pkt.payload;
    if (isControl(p)) return;
    if (p.kind === "esp") {
      ctx.trace("ip.drop", "L3", `ESP(IPsec) ${pkt.src} → ${pkt.dst}: 이 주소에 VPN 장비가 없음 → 시뮬레이션 밖이므로 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    if (pkt.dst === this.iface.ip) {
      if (p.kind === "tcp") {
        ctx.trace("ip.drop", "L4", `ISP 게이트웨이는 TCP 서비스를 열지 않음 → 드롭`, {}, frameId);
        return;
      }
      if (p.type !== "echo-request") {
        ctx.trace("ip.drop", "L3", `요청한 적 없는 ICMP ${icmpLabel(p)} → 무시`, {}, frameId);
        return;
      }
      ctx.trace("icmp.echo.received", "app", `ISP 게이트웨이가 ICMP Echo 요청 수신 (from ${pkt.src})`, { from: pkt.src }, frameId);
      const reply: Ipv4Packet = { kind: "ipv4", src: this.iface.ip, dst: pkt.src, ttl: 64, payload: { ...p, type: "echo-reply" } };
      ctx.trace("icmp.reply.sent", "app", `ICMP Echo 응답 생성 → ${pkt.src}`, { to: pkt.src });
      this.iface.sendIp(reply, ctx, emit);
      return;
    }
    if (isPrivateIp(pkt.dst)) {
      ctx.trace("ip.drop", "L3", `사설 주소 ${pkt.dst} 는 인터넷에서 라우팅되지 않음 → 드롭 (그래서 NAT 가 필요함)`, { dst: pkt.dst }, frameId);
      return;
    }
    if (isPrivateIp(pkt.src)) {
      ctx.trace("ip.drop", "L3", `출발지가 사설 주소 ${pkt.src} → 응답을 돌려줄 수 없어 드롭 (NAT 가 공인 주소로 바꿔야 함)`, { src: pkt.src }, frameId);
      return;
    }
    // ISP 라우터(203.0.113.1)를 지나 공인 서버로 가는 것도 홉 하나: TTL 이 다 됐으면 ISP 라우터가 통지한다
    if (pkt.ttl <= 1) {
      const notice = this.iface.timeExceeded(pkt, ctx, frameId);
      if (notice) this.iface.sendIp(notice, ctx, emit);
      return;
    }
    const name = KNOWN_SERVERS[pkt.dst];
    if (p.kind === "tcp") {
      const who = pkt.dst === Internet.REMOTE_CLIENT ? "클라이언트" : "서버";
      ctx.trace("inet.forward", "app", `인터넷 경로로 ${pkt.dst}${name ? ` (${name})` : ""}:${p.dstPort} 에 전달 — 중간 라우터 생략, ${who} 응답은 ${Internet.LATENCY * 2}ms 뒤 도착`, { dst: pkt.dst, src: pkt.src }, frameId);
      this.tcp.handle(pkt, p, ctx);
      return;
    }
    if (p.type === "unreachable" && pkt.dst === Internet.REMOTE_CLIENT) {
      // 바깥 클라이언트의 연결 시도(외부 접속)가 NAT 뒤에서 닿지 않음
      const reason = `${UNREACHABLE_LABEL[p.code]} (${pkt.src})`;
      if (this.tcp.onUnreachable(p.original, reason, ctx)) ctx.trace("icmp.unreachable.received", "app", `외부 클라이언트가 ${pkt.src} 로부터 ICMP ${UNREACHABLE_LABEL[p.code]} 수신 → 연결 실패`, { from: pkt.src }, frameId);
      return;
    }
    if (p.type !== "echo-request") {
      ctx.trace("ip.drop", "L3", `공인 주소 ${pkt.dst} 로 가는 ICMP ${icmpLabel(p)} → 시뮬레이션 밖이므로 드롭`, {}, frameId);
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
    if (isPrivateIp(pkt.dst)) {
      ctx.trace("ip.drop", "L3", `사설 주소 ${pkt.dst} 로 가는 DNS 질의가 인터넷으로 나옴 → 드롭. LAN 안의 DNS 서버라면 라우터가 LAN 쪽으로 보내야 함`, { dst: pkt.dst }, frameId);
      return;
    }
    if (isPrivateIp(pkt.src)) {
      ctx.trace("ip.drop", "L3", `출발지가 사설 주소 ${pkt.src} 인 DNS 질의 → 응답을 돌려줄 수 없어 드롭 (NAT 필요)`, { src: pkt.src }, frameId);
      return;
    }
    if (!PUBLIC_DNS.includes(pkt.dst)) {
      ctx.trace("ip.drop", "L4", `${pkt.dst} 에는 DNS 서비스가 없음 → 드롭 (공인 DNS 는 ${PUBLIC_DNS.join(", ")})`, { dst: pkt.dst }, frameId);
      return;
    }
    const name = normalizeName(msg.name);
    ctx.trace("dns.query.received", "app", `공인 DNS ${pkt.dst}: 질의 수신 "${name}${msg.qtype === "AAAA" ? " AAAA" : ""}?" (from ${pkt.src}) — 답은 ${Internet.LATENCY * 2}ms 뒤`, { name, from: pkt.src }, frameId);
    ctx.timer(Internet.LATENCY * 2, "inet-dns", { server: pkt.dst, to: pkt.src, toPort: srcPort, id: msg.id, name: msg.name, qtype: msg.qtype });
  }

  onTimer(tag: string, data: unknown, ctx: NodeContext): void {
    if (tag === "arp-timeout") {
      this.iface.onArpTimeout(data, ctx);
      return;
    }
    if (tag === RA_PERIODIC_TAG) {
      // ISP 링크의 RA 다시 알림 (RS 에 한 번 답한 뒤부터 600초마다 — 공유기 WAN 이 라우터 수명을 넘기지 않게)
      this.v6.onRaTick(data, ctx, this.emit(ctx));
      return;
    }
    if (tag === DAD_TIMER_TAG) {
      this.v6.finishDad(data, ctx, this.emit(ctx));
      return;
    }
    if (tag === NDP_TIMEOUT_TAG) {
      this.v6.onNsTimeout(data, ctx);
      return;
    }
    if (tag === "inet-reply6") {
      const { src, dst, id, seq } = data as { src: Ip; dst: Ip; id: number; seq: number };
      const name = KNOWN_SERVERS6[dst];
      ctx.trace("inet.reply", "app", `${dst}${name ? ` (${name})` : ""} 가 응답 → ${src} 로 회신 (Hop Limit 54: 중간 라우터 10개를 지났다고 가정)`, { from: dst, to: src, seq });
      this.send6({ kind: "ipv6", src: dst, dst: src, hopLimit: 54, payload: { kind: "icmp6", type: "echo-reply", id, seq } }, ctx);
      return;
    }
    if (tag === "inet-dns") {
      const { server, to, toPort, id, name, qtype } = data as { server: Ip; to: Ip; toPort: number; id: number; name: string; qtype?: "A" | "AAAA" };
      const reply = (msg: DnsMessage) => {
        if (isIpv6(to)) this.send6({ kind: "ipv6", src: server, dst: to, hopLimit: 54, payload: { kind: "udp", srcPort: DNS_PORT, dstPort: toPort, payload: msg } }, ctx);
        else this.iface.sendIp({ kind: "ipv4", src: server, dst: to, ttl: 54, payload: { kind: "udp", srcPort: DNS_PORT, dstPort: toPort, payload: msg } }, ctx, this.emit(ctx));
      };
      const rec = PUBLIC_ZONE.find((r) => r.name === normalizeName(name));
      if (qtype === "AAAA") {
        // 공개 이름의 IPv6 주소: 있으면 AAAA, 이름만 있으면 NODATA (github.com·naver.com 은 실제로도 아직 IPv6 가 없다)
        const rec6 = PUBLIC_ZONE6.find((r) => r.name === normalizeName(name));
        const msg: DnsMessage = rec6 ? { kind: "dns", id, op: "response", name, qtype, answer: rec6.ip } : { kind: "dns", id, op: "response", name, qtype, rcode: rec ? "NODATA" : "NXDOMAIN" };
        if (rec6) ctx.trace("dns.response.sent", "app", `공인 DNS ${server}: ${normalizeName(name)} AAAA = ${rec6.ip} 응답 → ${to}`, { name, ip: rec6.ip, qtype });
        else ctx.trace(rec ? "dns.response.sent" : "dns.nxdomain", "app", rec ? `공인 DNS ${server}: ${normalizeName(name)} 은(는) IPv6 주소(AAAA)가 없는 사이트 → NODATA (이름은 있음 — A 로 다시 물으면 IPv4 로 간다)` : `공인 DNS ${server}: ${normalizeName(name)} 은(는) 등록되지 않은 이름 → NXDOMAIN`, { name, qtype });
        reply(msg);
        return;
      }
      const msg: DnsMessage = rec ? { kind: "dns", id, op: "response", name, answer: rec.ip } : { kind: "dns", id, op: "response", name, rcode: "NXDOMAIN" };
      if (rec) ctx.trace("dns.response.sent", "app", `공인 DNS ${server}: ${normalizeName(name)} = ${rec.ip} 응답 → ${to}`, { name, ip: rec.ip });
      else ctx.trace("dns.nxdomain", "app", `공인 DNS ${server}: ${normalizeName(name)} 은(는) 등록되지 않은 이름 → NXDOMAIN (아는 이름: ${PUBLIC_ZONE.map((r) => r.name).join(", ")})`, { name });
      reply(msg);
      return;
    }
    if (tag === TCP_TIMER_TAG) {
      this.tcp.onTimer(data, ctx);
      return;
    }
    if (tag === "inet-send") {
      const { pkt } = data as { pkt: IpPacket };
      if (pkt.kind === "ipv6") this.send6({ ...pkt, hopLimit: 54 }, ctx);
      else this.iface.sendIp({ ...pkt, ttl: 54 }, ctx, this.emit(ctx));
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
        ["ISP IPv6", `${Internet.ISP_V6}/64 · RA 로 알림 · 위임 풀 ${Internet.PD_POOL}/40 (고객마다 /${Internet.PD_LENGTH})`],
        ["외부 클라이언트 (IPv6)", Internet.REMOTE_CLIENT6],
      ],
      tables: [
        { title: "웹 서버 연결 (포트 80·443)", columns: ["상대", "상태", "보냄 / 받음"], rows: this.tcp.rows() },
        { title: "공인 주소 임대", columns: ["IP", "MAC", "시각"], rows: this.dhcpServer.rows() },
        { title: "IPv6 프리픽스 위임 (DHCPv6-PD)", columns: ["프리픽스", "고객", "넥스트 홉"], rows: [...this.delegations.entries()].map(([p, d]) => [`${p}/${Internet.PD_LENGTH}`, d.client, d.via]) },
        { title: "ARP 캐시", columns: ["IP", "MAC", "학습 시각"], rows: this.iface.arpRows() },
        { title: "알려진 서버", columns: ["IP", "이름"], rows: Object.entries(KNOWN_SERVERS) },
      ],
    };
  }
}
