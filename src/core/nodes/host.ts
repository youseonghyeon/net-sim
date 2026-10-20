import { ipToInt, isMulticastMac, sameSubnet, type Ip, type Mac } from "../addr";
import { ALL_NODES, canonIp6, isIpv6, isMulticast6 } from "../addr6";
import {
  DHCP_CLIENT_PORT,
  DHCP_SERVER_PORT,
  DNS_PORT,
  P2P_PORT,
  describeFrame,
  describeOriginal,
  isControl,
  isNdp,
  type EthernetFrame,
  type IcmpPacket,
  type Icmpv6Packet,
  type Icmpv6Unreachable,
  type IpPacket,
  type Ipv4Packet,
  type Ipv6Packet,
  UNREACHABLE_LABEL,
  UNREACHABLE6_LABEL,
  type IcmpUnreachable,
} from "../packet";
import { DHCP_STATE_LABEL, DHCP_TIMER_TAG, DhcpClient, DhcpServer, type DhcpServerConfig } from "./dhcp";
import { DNS_TIMER_TAG, DNS_UPSTREAM_TIMER_TAG, DnsResolver, DnsServer, looksLikeName, type DnsServerConfig, type QType } from "./dns";
import { NetInterface } from "./iface";
import { LB_ALGORITHM_LABEL, LB_CHECK_TAG, LB_MODE_LABEL, LB_STICKY_LABEL, LoadBalancer, type LbConfig } from "./lb";
import { ForwardProxy, type ProxyConfig } from "./proxy";
import { SshJump } from "./sshjump";
import type { NodeContext, NodeSnapshot, SimNode, TimerHandle } from "./node";
import { endpoint, HTTPS_PORT, SSH_PORT, TCP_TIMER_TAG, TcpStack, type TcpConn } from "./tcp";
import { L2tpClient } from "./l2tp";
import { P2P_TIMER_TAG, P2pAgent, type P2pConfig } from "./p2p";
import { RA_DPD_TAG, RA_TIMER_TAG, RaClient, type RaClientConfig } from "./ravpn";
import { WG_TIMER_TAG, WgClient } from "./wg";
import { OVPN_TIMER_TAG, OvpnClient } from "./openvpn";
import { ALL_HOSTS_IP, ALL_ROUTERS_IP, isMcastIp, MCAST_PORT, mcastMac, SIP_PORT } from "../packet";

/** 스트림 송출 한 번의 패킷 수 */
const STREAM_PACKETS = 5;
import { MeshAgent, TS_TIMER_TAG, type MeshConfig } from "./tailscale";
import { CALL_STATE_LABEL, SIP_TIMER_TAG, SipPhone, type SipPhoneConfig } from "./sip";
import { DAD_TIMER_TAG, Ipv6Interface, NDP_TIMEOUT_TAG, NUD_TIMER_TAG, ROUTER_EXPIRY_TAG, RS_TIMER_TAG, type Ipv6Settings } from "./ipv6";
import { HostDiagnostics, LOOKUP_KEEP, PING_INTERVAL, PING_MAX_COUNT, PING_RUN_KEEP, PING_TIMEOUT, TRACEROUTE_KEEP, TRACEROUTE_MAX_HOPS, TRACEROUTE_TIMEOUT, type LookupRecord, type PingRecord, type PingRun, type TracerouteRecord } from "./hostdiag";
export type { LookupRecord, PingRecord, PingRun, PingStats, TracerouteHop, TracerouteRecord } from "./hostdiag";


/** 루프백으로 보낸 패킷을 받는 timer (같은 시각, 지금 일 다음) */
const LOOPBACK_TAG = "loopback";
export type IpMode = "dhcp" | "static";

const NIC_SWITCH_TAG = "nic-switch";
const NIC_LABEL = ["유선(eth0)", "Wi-Fi(wlan0)"];

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
  /** 이 호스트가 로드밸런서(리버스 프록시) 역할을 할 때 */
  lb?: LbConfig;
  /** 이 호스트가 포워드 프록시(Squid 식) 역할을 할 때 */
  proxy?: ProxyConfig;
  /** SSH 점프 서버 (AllowTcpForwarding): SSH 로 로그인한 사용자가 이 서버를 거쳐 다른 서버로 (ssh -J) */
  sshJump?: boolean;
  /** 이 호스트의 HTTP 프록시 설정 (http_proxy·https_proxy): 포트 80 요청은 대신 받아 달라고, 443 은 CONNECT 터널로 이 프록시에게 부탁한다 */
  httpProxy?: HttpProxySetting;
  /** 원격 접속 VPN 클라이언트 */
  ra?: RaClientConfig;
  /** P2P 앱 (화상 통화·게임처럼 NAT 너머 상대와 직접 잇기) */
  p2p?: P2pConfig;
  /** IPv6 (없으면 꺼짐) */
  ipv6?: Ipv6Settings;
  /** 노트북: 무선 NIC(wlan0, 포트 1)의 MAC. 있으면 유선(eth0, 포트 0)과 NIC 가 둘 — 유선이 살아 있으면 유선, 아니면 무선을 쓴다 */
  wlanMac?: Mac;
}

export interface HttpProxySetting {
  server: Ip;
  port: number;
}

export { DHCP_MAX_ATTEMPTS, DHCP_TIMEOUT, DHCP_STATE_LABEL, type DhcpState } from "./dhcp";

/** 단말 호스트: 인터페이스 1개, DHCP 클라이언트, ICMP ping */
export class Host implements SimNode {
  static readonly PING_TIMEOUT = PING_TIMEOUT;
  static readonly PING_INTERVAL = PING_INTERVAL;
  static readonly PING_MAX_COUNT = PING_MAX_COUNT;
  static readonly PING_RUN_KEEP = PING_RUN_KEEP;
  static readonly TRACEROUTE_TIMEOUT = TRACEROUTE_TIMEOUT;
  static readonly TRACEROUTE_MAX_HOPS = TRACEROUTE_MAX_HOPS;
  static readonly TRACEROUTE_KEEP = TRACEROUTE_KEEP;
  static readonly LOOKUP_KEEP = LOOKUP_KEEP;

  readonly type = "host" as const;
  readonly portCount: number;
  readonly id: string;
  readonly iface: NetInterface;
  /**
   * NIC (포트 번호 순). 노트북은 유선 eth0·무선 wlan0 둘이지만 IP 스택은 하나라 한 번에 하나만 쓴다:
   * 유선이 살아 있으면 유선(실제 OS 의 인터페이스 메트릭처럼 유선 우선), 아니면 무선. 바꿔 끼우면 MAC 이 바뀌어 주소를 새로 받는다.
   * lease = 그 NIC 로 마지막에 받은 DHCP 주소 (다시 그 NIC 로 돌아오면 INIT-REBOOT 로 확인)
   */
  readonly nics: { name: string; mac: Mac; up: boolean; lease?: Ip }[];
  /** 지금 쓰는 NIC (포트 번호). 링크가 하나도 없으면 undefined */
  activeNic: number | undefined;
  /** 다른 NIC 로 바꿔 끼기를 기다리는 중 (0ms 타이머 — 같은 순간의 링크 변화를 모두 본 뒤 정한다) */
  private switching: TimerHandle | undefined;
  /** 지워지는 중 (onRemove 뒤): 링크가 차례로 끊겨도 다른 NIC 로 넘어가지 않는다 */
  private removed = false;
  readonly dhcp: DhcpClient;
  readonly dhcpServer: DhcpServer;
  readonly dnsServer: DnsServer;
  readonly resolver: DnsResolver;
  /** P2P 앱 (STUN·시그널링·홀 펀칭·TURN) */
  readonly p2p: P2pAgent;
  /** 메시 VPN 앱 (Tailscale·ZeroTier) */
  readonly mesh: MeshAgent;
  /** 인터넷 전화 (SIP) */
  readonly sip: SipPhone;
  /** VPN 종류를 바꾸기 전 OpenVPN 이 쓰던 TCP 연결 ("서버:내 포트") — 늦게 온 세그먼트를 조용히 버린다 */
  private ovpnLate: string[] = [];
  readonly tcp: TcpStack;
  /** 로드밸런서 서비스 (꺼져 있으면 아무것도 안 함) */
  readonly lb: LoadBalancer;
  readonly proxy: ForwardProxy;
  /** SSH 점프 서버 (ssh -J 의 중간) */
  readonly jump: SshJump;
  httpProxy: HttpProxySetting | undefined;
  /** 원격 접속 VPN 클라이언트: 회사 VPN 장비(IKEv2) 또는 공유기 VPN 서버(L2TP/IPsec) — 설정의 종류에 따라 바꿔 낀다 */
  ra: RaClient | L2tpClient | WgClient | OvpnClient;
  /** IPv6 (IPv4 인터페이스와 나란히, 같은 MAC) */
  readonly v6: Ipv6Interface;
  /** 웹 등 직접 응답하는 TCP 포트. 실제로 듣는 포트는 여기에 LB 포트를 더한 것 */
  private services: number[];
  /** 마지막으로 본 시뮬레이션 시각 (표시용: LB 가 빼 둔 백엔드가 언제 돌아오는지) */
  private clock = 0;
  ipMode: IpMode;
  linkUp = false;
  /** ping·traceroute·nslookup (hostdiag.ts). pings·pingRuns·traceroutes·lookups 는 그 기록 */
  readonly diag: HostDiagnostics;
  get pings(): PingRecord[] {
    return this.diag.pings;
  }
  get pingRuns(): PingRun[] {
    return this.diag.pingRuns;
  }
  get traceroutes(): TracerouteRecord[] {
    return this.diag.traceroutes;
  }
  get lookups(): LookupRecord[] {
    return this.diag.lookups;
  }
  private readonly emit = (ctx: NodeContext) => (f: EthernetFrame) => ctx.send(this.activeNic ?? 0, f);

  constructor(cfg: HostConfig) {
    this.id = cfg.id;
    this.nics = cfg.wlanMac
      ? [
          { name: "eth0", mac: cfg.mac, up: false },
          { name: "wlan0", mac: cfg.wlanMac, up: false },
        ]
      : [{ name: "eth0", mac: cfg.mac, up: false }];
    this.portCount = this.nics.length;
    this.ipMode = cfg.ipMode ?? (cfg.ip ? "static" : "dhcp");
    this.iface = new NetInterface(cfg.mac, this.ipMode === "static" ? { ip: cfg.ip, prefix: cfg.prefix, gateway: cfg.gateway, dns: cfg.dns } : { prefix: cfg.prefix });
    this.dhcp = new DhcpClient(this.iface, hashCode(cfg.id));
    this.v6 = new Ipv6Interface(cfg.mac);
    this.v6.loopback = (pkt, ctx) => this.loopback6(pkt, ctx);
    // RA 로 SLAAC 주소가 사라지면 그 주소로 묶인 연결·traceroute 를 정리한다 (설정 변경 때와 같이)
    this.v6.onAddrRemoved = (ip, ctx) => {
      this.tcp.abortAll("IPv6 주소 사라짐", ctx, (c) => c.localIp === ip);
      this.diag.cancelTraceroute("IPv6 주소 사라짐", ctx, (rec) => isIpv6(rec.resolved ?? rec.dst));
    };
    if (cfg.ipv6?.enabled) this.v6.init(cfg.ipv6);
    this.tcp = new TcpStack({
      send: (pkt, ctx) => this.sendAny(pkt, ctx),
      onRequest: (conn, ctx) => this.lb.onRequest(conn, ctx) || this.proxy.onRequest(conn, ctx),
      onFinish: (conn, ctx) => void (this.lb.onFinish(conn, ctx) || this.proxy.onFinish(conn, ctx) || this.jump.onFinish(conn, ctx) || this.happyEyeballs(conn, ctx)),
      onEstablished: (conn, ctx) => void (this.lb.onEstablished(conn, ctx) || this.jump.onEstablished(conn, ctx) || this.proxy.onEstablished(conn, ctx)),
      onRelay: (conn, seg, ctx) => void (this.jump.onRelay(conn, seg, ctx) || this.proxy.onRelay(conn, seg, ctx)),
      onChannelOpen: (conn, target, ctx) => this.jump.onChannelOpen(conn, target, ctx),
    });
    this.lb = new LoadBalancer(this.tcp, () => this.iface.ip);
    this.tcp.reservedPort = (p) => this.lb.usesNatPort(p);
    if (cfg.lb) this.lb.config = { ...cfg.lb, backends: cfg.lb.backends.map((b) => ({ ...b })) };
    // 프록시도 0.0.0.0·:: 답(DNS 필터가 막은 이름)은 그 주소로 연결하지 않는다
    this.proxy = new ForwardProxy(this.tcp, () => this.iface.ip, (name, ctx, done) =>
      this.resolver.resolve(name, ctx, this.emit(ctx), (ip, err) => (ip === "0.0.0.0" || ip === "::" ? done(undefined, `DNS 가 막은 이름 (${ip})`) : done(ip, err))),
    );
    if (cfg.proxy) this.proxy.config = { ...cfg.proxy, deny: [...cfg.proxy.deny] };
    this.jump = new SshJump(this.tcp, () => this.iface.ip, (name, ctx, done) =>
      this.resolver.resolve(name, ctx, this.emit(ctx), (ip, err) => (ip === "0.0.0.0" || ip === "::" ? done(undefined, `DNS 가 막은 이름 (${ip})`) : done(ip, err))),
    );
    this.jump.enabled = cfg.sshJump === true;
    this.httpProxy = cfg.httpProxy ? { ...cfg.httpProxy } : undefined;
    this.services = [...(cfg.services ?? [])];
    this.syncListening();
    this.dhcpServer = new DhcpServer(cfg.dhcpServer ?? { enabled: false, start: "", end: "" }, this.iface, false);
    this.dnsServer = new DnsServer(cfg.dnsServer ?? { enabled: false, records: [] }, this.iface, undefined, undefined, this.v6);
    this.resolver = new DnsResolver(this.iface, hashCode(cfg.id), this.v6);
    this.p2p = new P2pAgent({
      myIp: () => (this.iface.usable && !this.iface.probing ? this.iface.ip : undefined),
      local: (dst) => !!this.iface.ip && sameSubnet(dst, this.iface.ip, this.iface.prefix),
      send: (pkt, ctx) => this.iface.sendIp(pkt, ctx, this.emit(ctx)),
    });
    if (cfg.p2p) this.p2p.config = { ...cfg.p2p };
    this.sip = new SipPhone(
      {
        myIp: () => (this.iface.usable && !this.iface.probing ? this.iface.ip : undefined),
        send: (pkt, ctx) => this.iface.sendIp(pkt, ctx, this.emit(ctx)),
      },
      16384 + (Math.abs(hashCode(`${cfg.id}:rtp`)) % 1000) * 2,
    );
    this.mesh = new MeshAgent(
      {
        myIp: () => (this.iface.usable && !this.iface.probing ? this.iface.ip : undefined),
        local: (dst) => !!this.iface.ip && sameSubnet(dst, this.iface.ip, this.iface.prefix),
        send: (pkt, ctx) => this.iface.sendIp(pkt, ctx, this.emit(ctx)),
        // 내 메시 주소(내 MagicDNS 이름)로 가는 것은 나 자신 — 실제 주소로 바꿔 루프백
        loopback: (pkt, ctx) => this.iface.sendIp({ ...pkt, dst: this.iface.ip! }, ctx, this.emit(ctx)),
      },
      cfg.id,
    );
    this.resolver.local = this.dnsServer;
    this.iface.loopback = (pkt, ctx) => this.loopback(pkt, ctx);
    this.ra = this.makeVpnClient(cfg.ra?.type);
    if (cfg.ra) this.ra.config = { ...cfg.ra };
    // 사내 대역으로 가는 패킷은 원격 접속 터널로 (연결돼 있을 때만. L2TP/IPsec 은 모두)
    // 메시 피어·알린 대역은 원격 접속 VPN 보다 먼저 (더 구체적인 경로가 이긴다), exit node 는 원격 접속 VPN 뒤
    this.iface.outbound = (pkt, ctx) => this.mesh.intercept(pkt, ctx, false) || this.ra.intercept(pkt, ctx) || this.mesh.intercept(pkt, ctx);
    // VPN 이 알려 준 DNS (L2TP 는 IPCP, WireGuard 는 설정 파일, OpenVPN 은 PUSH)
    this.resolver.vpnDns = () => this.ra.vpnDns();
    this.diag = new HostDiagnostics(
      {
        iface: this.iface,
        v6: this.v6,
        resolver: this.resolver,
        mesh: this.mesh,
        emit: (ctx) => this.emit(ctx),
        hasV6Global: () => this.hasV6Global(),
        resolveName: (name, ctx, done, alive) => this.resolveName(name, ctx, done, alive),
      },
      hashCode(cfg.id),
    );
  }

  private makeVpnClient(type: RaClientConfig["type"]): RaClient | L2tpClient | WgClient | OvpnClient {
    const io = {
      source: () => this.iface.ip,
      send: (outer: Ipv4Packet, ctx: NodeContext) => this.iface.sendIp(outer, ctx, this.emit(ctx)),
      myIp: () => (this.iface.usable && !this.iface.probing ? this.iface.ip : undefined),
      local: (dst: Ip) => !!this.iface.ip && sameSubnet(dst, this.iface.ip, this.iface.prefix),
    };
    // 클라이언트 식별은 유선 NIC 의 MAC (노트북이 Wi-Fi 로 넘어가 있어도 같은 기기 — 서버가 같은 가상 주소를 준다)
    const cid = this.nics[0]!.mac;
    if (type === "openvpn")
      return new OvpnClient(
        {
          myIp: io.myIp,
          send: io.send,
          local: io.local,
          resolve: (name, ctx, done) => {
            this.resolver.forget(name);
            this.resolver.resolve(name, ctx, this.emit(ctx), (ip, reason) => done(ip, reason), "A", true);
          },
        },
        this.id,
        49152 + (Math.abs(hashCode(`${this.id}:ovpn`)) % 16000),
      );
    if (type === "wireguard")
      return new WgClient(
        {
          myIp: io.myIp,
          send: io.send,
          local: io.local,
          // 서버 이름은 터널 밖 DNS 로 (VPN DNS 를 건너뛰고), 바뀐 주소를 받게 캐시를 지우고
          resolve: (name, ctx, done) => {
            this.resolver.forget(name);
            this.resolver.resolve(name, ctx, this.emit(ctx), (ip, reason) => done(ip, reason), "A", true);
          },
        },
        this.id,
        49152 + (Math.abs(hashCode(`${this.id}:wg`)) % 16000),
      );
    return type === "l2tp" ? new L2tpClient(io, cid) : new RaClient(io, cid);
  }

  setP2p(cfg: P2pConfig, ctx: NodeContext): void {
    this.p2p.setConfig(cfg, ctx);
  }

  setSip(cfg: SipPhoneConfig, ctx: NodeContext): void {
    this.sip.setConfig(cfg, ctx);
  }

  setMesh(cfg: MeshConfig, ctx: NodeContext): void {
    this.mesh.setConfig(cfg, ctx);
  }

  // ---------- 멀티캐스트 (IGMP·IPTV 흉내) ----------

  /** 가입한 멀티캐스트 그룹 */
  readonly groups = new Set<Ip>();
  /** 받은 스트림 패킷 수 (그룹마다) */
  readonly streamRx = new Map<Ip, number>();
  private streamSeq = 0;

  joinGroup(group: Ip, ctx: NodeContext): void {
    if (!isMcastIp(group)) {
      ctx.trace("igmp.join", "app", `${group} 는 멀티캐스트 주소(224.0.0.0~239.255.255.255)가 아님 → 가입하지 않음`, { group });
      return;
    }
    if (!this.iface.ip) {
      ctx.trace("ip.no-address", "L3", `IP 주소가 없어 IGMP 가입을 알릴 수 없음`, { group });
      return;
    }
    this.groups.add(group);
    ctx.trace("igmp.join", "app", `멀티캐스트 그룹 ${group} 가입 → IGMP Membership Report 를 그 그룹 주소(MAC ${mcastMac(group)})로 알리고, NIC 가 이 MAC 의 프레임을 받기 시작`, { group });
    this.iface.sendToMac(mcastMac(group), { kind: "ipv4", src: this.iface.ip, dst: group, ttl: 1, payload: { kind: "igmp", type: "report", group } }, ctx, this.emit(ctx));
  }

  /** 가입한 그룹을 다시 알린다 (쿼리·링크 복구·주소를 다시 얻음 — 리눅스 ip_mc_up). only 면 그 그룹만 */
  private reportGroups(ctx: NodeContext, why: string, only?: Ip): void {
    if (!this.iface.ip || !this.groups.size) return;
    const list = only ? [only] : [...this.groups];
    ctx.trace("igmp.join", "app", `${why} → 가입한 그룹 ${list.join(", ")} 을(를) 다시 알림 (IGMP Report)`, { groups: list });
    for (const group of list) this.iface.sendToMac(mcastMac(group), { kind: "ipv4", src: this.iface.ip, dst: group, ttl: 1, payload: { kind: "igmp", type: "report", group } }, ctx, this.emit(ctx));
  }

  leaveGroup(group: Ip, ctx: NodeContext): void {
    if (!this.groups.delete(group)) {
      ctx.trace("igmp.join", "app", `그룹 ${group} 에 가입해 있지 않음`, { group });
      return;
    }
    ctx.trace("igmp.join", "app", `멀티캐스트 그룹 ${group} 탈퇴 → IGMP Leave 를 모든 라우터 주소(${ALL_ROUTERS_IP})로 알림`, { group });
    if (this.iface.ip) this.iface.sendToMac(mcastMac(ALL_ROUTERS_IP), { kind: "ipv4", src: this.iface.ip, dst: ALL_ROUTERS_IP, ttl: 1, payload: { kind: "igmp", type: "leave", group } }, ctx, this.emit(ctx));
  }

  /** 스트림 송출: 그룹 주소로 UDP 5개 (100ms 간격 — 영상 조각 흉내) */
  sendStream(group: Ip, ctx: NodeContext): void {
    if (!isMcastIp(group) || !this.iface.ip) {
      ctx.trace("mcast.send", "app", `${!this.iface.ip ? "IP 주소가 없어" : `${group} 는 멀티캐스트 주소가 아니라`} 송출하지 않음`, { group });
      return;
    }
    const id = ++this.streamSeq;
    ctx.trace("mcast.send", "app", `IPTV 송출 시작: 그룹 ${group} 로 영상 조각 ${STREAM_PACKETS}개 (받을 기기를 모른다 — 스위치가 누구에게 줄지 정한다)`, { group });
    this.streamStep(group, id, 1, ctx);
  }

  private streamStep(group: Ip, id: number, seq: number, ctx: NodeContext): void {
    if (!this.iface.ip) return;
    this.iface.sendToMac(mcastMac(group), { kind: "ipv4", src: this.iface.ip, dst: group, ttl: 4, payload: { kind: "udp", srcPort: MCAST_PORT, dstPort: MCAST_PORT, payload: { kind: "mcast", group, seq, total: STREAM_PACKETS, name: `채널 ${group}` } } }, ctx, this.emit(ctx));
    if (seq < STREAM_PACKETS) ctx.timer(100, "mcast-stream", { group, id, seq: seq + 1 });
  }

  setRemoteVpn(cfg: RaClientConfig, ctx: NodeContext): void {
    const want = cfg.type === "l2tp" || cfg.type === "wireguard" || cfg.type === "openvpn" ? cfg.type : "ikev2";
    if (want !== this.ra.kind) {
      // VPN 종류가 바뀜: 붙어 있던 연결을 끊고(서버에 알림) 다른 클라이언트로 바꿔 낀다
      if (this.ra.state === "up") this.ra.disconnect(ctx, "VPN 종류가 바뀜");
      // OpenVPN TCP 연결은 서버의 FIN·ACK 가 늦게 온다 — 새 클라이언트로 바꾼 뒤에도 호스트 TCP 로 넘기지 않게 기억
      this.ovpnLate = [...this.ovpnLate, ...this.ra.lateTcp()].slice(-16);
      this.ra = this.makeVpnClient(want);
    }
    this.ra.setConfig(cfg, ctx);
  }

  /** IPv6 설정 교체. 주소가 바뀌면 IPv6 연결·traceroute 를 정리한다 */
  setIpv6(cfg: Ipv6Settings, ctx: NodeContext): void {
    const dnsBefore = this.v6.effectiveDns;
    const changed = this.v6.configure(cfg, this.linkUp, ctx, this.emit(ctx));
    if (this.v6.effectiveDns !== dnsBefore && !this.iface.dns) this.resolver.clear("DNS 설정 변경");
    if (!changed) return;
    this.tcp.abortAll("IPv6 주소 변경", ctx, (c) => isIpv6(c.localIp));
    this.diag.cancelTraceroute("IPv6 주소 변경", ctx, (rec) => isIpv6(rec.resolved ?? rec.dst));
  }

  /** IPv4·IPv6 를 알맞은 인터페이스로 */
  private sendAny(pkt: IpPacket, ctx: NodeContext): void {
    if (pkt.kind === "ipv6") this.v6.send(pkt, ctx, this.emit(ctx));
    else this.iface.sendIp(pkt, ctx, this.emit(ctx));
  }

  /**
   * 내 주소로 보내는 패킷은 네트워크로 나가지 않고 받는다 (루프백). 보내는 자리에서 바로 받지 않고 같은 시각, 지금 일이 끝난 뒤에 받는다
   * (리눅스 loopback 의 netif_rx 백로그) — 보내는 쪽이 상태를 다 적기 전에 답이 돌아오는 재진입이 없다 (LESSONS 4h·4k)
   */
  private loopback(pkt: Ipv4Packet, ctx: NodeContext): void {
    ctx.trace("ip.route", "L3", `${pkt.dst} 는 내 주소 → 루프백으로 바로 처리`, { dst: pkt.dst });
    ctx.timer(0, LOOPBACK_TAG, pkt);
  }

  private loopback6(pkt: Ipv6Packet, ctx: NodeContext): void {
    ctx.trace("ip.route", "L3", `${pkt.dst} 는 내 IPv6 주소 → 루프백으로 바로 처리`, { dst: pkt.dst });
    ctx.timer(0, LOOPBACK_TAG, pkt);
  }

  /** DNS 서버 서비스 설정 교체 */
  setDnsServer(cfg: DnsServerConfig, ctx: NodeContext): void {
    const prev = this.dnsServer.config;
    if (cfg.enabled !== prev.enabled) {
      ctx.trace("ip.config", "sys", cfg.enabled ? `DNS 서버 시작 (레코드 ${cfg.records.length}개${cfg.upstream ? `, 업스트림 DNS ${cfg.upstream}` : ""})` : `DNS 서버 중지`, { ...cfg });
    } else if (cfg.enabled && (JSON.stringify(cfg.records) !== JSON.stringify(prev.records) || cfg.upstream !== prev.upstream)) {
      ctx.trace("ip.config", "sys", `DNS 서버 설정 변경 (레코드 ${cfg.records.length}개${cfg.upstream ? `, 업스트림 DNS ${cfg.upstream}` : ""})`, { ...cfg });
    }
    this.dnsServer.config = { ...cfg, records: [...cfg.records] };
  }

  /** DHCP 서버 서비스 설정 교체 */
  setDhcpServer(cfg: DhcpServerConfig, ctx: NodeContext): void {
    const prev = this.dhcpServer.config;
    if (cfg.enabled !== prev.enabled) {
      ctx.trace("ip.config", "sys", cfg.enabled ? `DHCP 서버 시작 (범위 ${cfg.start} ~ ${cfg.end}, 기본 게이트웨이 옵션 ${cfg.router || "없음"})` : `DHCP 서버 중지`, { ...cfg });
    } else if (cfg.start !== prev.start || cfg.end !== prev.end || cfg.router !== prev.router) {
      ctx.trace("ip.config", "sys", `DHCP 서버 설정 변경 (범위 ${cfg.start} ~ ${cfg.end}, 기본 게이트웨이 옵션 ${cfg.router || "없음"})`, { ...cfg });
    }
    this.dhcpServer.setConfig(cfg, ctx);
  }

  /** 듣는 포트 목록 교체 */
  setServices(ports: number[], ctx: NodeContext): void {
    this.services = [...ports];
    this.syncListening(ctx);
  }

  /** 로드밸런서 설정 교체 */
  setLb(cfg: LbConfig, ctx: NodeContext): void {
    this.lb.setConfig(cfg, ctx);
    this.syncListening(ctx);
    this.lb.ensureChecks(ctx);
  }

  /** 포워드 프록시 설정 교체 */
  setProxy(cfg: ProxyConfig, ctx: NodeContext): void {
    this.proxy.setConfig(cfg, ctx);
    this.syncListening(ctx);
  }

  /** SSH 점프 서버 (AllowTcpForwarding) 켜기·끄기 */
  setSshJump(on: boolean, ctx: NodeContext): void {
    this.jump.setEnabled(on, ctx);
  }

  /** HTTP 프록시 설정(http_proxy) 교체 */
  setHttpProxy(cfg: HttpProxySetting | undefined, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.httpProxy)) return;
    this.httpProxy = cfg ? { ...cfg } : undefined;
    ctx.trace("ip.config", "sys", cfg ? `HTTP 프록시 설정: http_proxy=https_proxy=http://${cfg.server}:${cfg.port} — 웹 요청(포트 80, HTTPS 443 은 CONNECT 터널)은 이 프록시에게 부탁` : "HTTP 프록시 설정 지움 — 웹 요청을 직접 보냄", { ...cfg });
  }

  /** 실제로 듣는 포트 = 서비스 포트 + (켜져 있으면) LB 포트 + 프록시 포트 */
  private syncListening(ctx?: NodeContext): void {
    const next = new Set(this.services);
    if (this.lb.config.enabled && this.lb.config.mode !== "l4") next.add(this.lb.config.port); // L4 는 TCP 로 받지 않고 주소만 바꿔 넘긴다
    if (this.proxy.config.enabled) next.add(this.proxy.config.port);
    for (const p of [...this.tcp.listening]) {
      if (!next.has(p)) {
        this.tcp.listening.delete(p);
        ctx?.trace("ip.config", "sys", `TCP 포트 ${p} 서비스 중지`, { port: p });
      }
    }
    for (const p of next) {
      if (!this.tcp.listening.has(p)) {
        this.tcp.listening.add(p);
        const role = this.lb.config.enabled && p === this.lb.config.port ? " — 로드밸런서" : this.proxy.config.enabled && p === this.proxy.config.port ? " — 프록시" : "";
        ctx?.trace("ip.config", "sys", `TCP 포트 ${p} 에서 연결 받기 시작 (listen)${role}`, { port: p });
      }
    }
    // 443 은 TLS 로 받는다 (HTTPS 서버, 로드밸런서면 TLS 를 풀고 백엔드로). 프록시 포트는 평문 HTTP (CONNECT 를 받는다)
    this.tcp.tlsPorts.clear();
    if (next.has(HTTPS_PORT) && !(this.proxy.config.enabled && this.proxy.config.port === HTTPS_PORT)) this.tcp.tlsPorts.add(HTTPS_PORT);
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
        this.addressLost(ctx, "주소 변경");
        if (this.linkUp && this.iface.ip) this.iface.claim(ctx, this.emit(ctx)); // Probe 가 끝나면 addressUp
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
    if (before) this.addressLost(ctx, "주소 변경");
    ctx.trace("ip.config", "sys", `자동(DHCP) 로 전환 → 기존 주소 지움`, { ...cfg });
    if (this.linkUp) this.dhcp.start(ctx, this.emit(ctx));
    else this.dhcp.stop();
  }

  onRemove(ctx: NodeContext): void {
    this.mesh.logout(ctx, "장치 제거");
    if (this.linkUp) this.dhcp.release(ctx, this.emit(ctx));
    // 지워지는 동안 케이블·무선이 차례로 끊긴다 — 그 사이 다른 NIC 로 넘어가 DHCP 를 보내지 않게
    this.removed = true;
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    const nic = this.nics[port];
    if (!nic || this.removed) return;
    nic.up = up;
    if (this.nics.length === 1) {
      this.activeNic = up ? 0 : undefined;
      if (up) this.stackUp(ctx, "링크 연결됨");
      else this.stackDown(ctx, "링크 다운", "링크 다운");
      return;
    }
    // 노트북: 유선이 살아 있으면 유선, 아니면 무선
    const want = this.wantNic();
    const from = this.activeNic;
    if (this.switching) {
      // 바꿔 끼기를 기다리는 중 (같은 순간의 다른 변화): 결정은 switchNic 이 한다
      ctx.trace(up ? "link.up" : "link.down", "L1", `${nic.name} ${up ? "연결됨" : "끊김"}`, { port });
      return;
    }
    if (want === from) {
      // 쓰지 않는 쪽만 바뀜 (유선을 쓰는 중에 Wi-Fi 가 붙거나 떨어짐)
      ctx.trace(
        up ? "link.up" : "link.down",
        "L1",
        up ? `${nic.name} 연결됨 → 지금 쓰는 ${NIC_LABEL[from!]} 가 우선이라 대기 (유선이 끊기면 이쪽으로 넘어감)` : `${nic.name} 끊김 (대기 중이던 연결 — 지금 쓰는 ${NIC_LABEL[from!]} 는 그대로)`,
        { port, standby: true },
      );
      return;
    }
    if (from === undefined) {
      this.useNic(want!);
      this.stackUp(ctx, `${nic.name} 링크 연결됨 → ${NIC_LABEL[want!]} 로 통신 (MAC ${this.iface.mac})`);
      return;
    }
    // 쓰던 NIC 를 내려놓는다 (원인 → 정리). 어느 NIC 로 갈지는 같은 순간의 다른 변화(장치 제거로 둘 다 끊김 등)까지 본 뒤 정한다
    if (up) ctx.trace("link.up", "L1", `${nic.name} 링크 연결됨 → 유선이 우선이라 ${NIC_LABEL[from]} 를 내려놓음`, { port });
    else ctx.trace("link.down", "L1", `${nic.name} 링크 다운${want === undefined ? " (다른 NIC 도 연결돼 있지 않음)" : ""}`, { port });
    this.stackDown(ctx, up ? "NIC 전환" : "링크 다운", null);
    this.activeNic = undefined;
    if (want !== undefined) this.switching = ctx.timer(0, NIC_SWITCH_TAG, {});
  }

  private wantNic(): number | undefined {
    return this.nics[0]!.up ? 0 : this.nics[1]?.up ? 1 : undefined;
  }

  /** 바꿔 끼기 (같은 순간의 링크 변화를 모두 본 뒤): 살아 있는 NIC 로 MAC 을 바꿔 주소를 다시 */
  private switchNic(ctx: NodeContext): void {
    this.switching = undefined;
    const want = this.wantNic();
    if (want === undefined || this.removed) return;
    const oldMac = this.iface.mac;
    this.useNic(want);
    const what =
      this.ipMode === "dhcp" ? "DHCP 로 주소를 새로 받는다" : this.iface.ip ? `수동 주소 ${this.iface.ip} 를 새 MAC 으로 다시 확인(ARP Probe)해 쓴다` : "수동 주소가 없음";
    this.stackUp(
      ctx,
      oldMac === this.iface.mac
        ? `${NIC_LABEL[want]} 로 다시 통신 (MAC ${oldMac} 그대로)`
        : `${NIC_LABEL[want]} 로 전환: 다른 NIC 라 MAC 이 ${oldMac} → ${this.iface.mac} 로 바뀜 → ${what} (${this.ra.kind === "wireguard" && this.ra.config.enabled ? "열려 있던 TCP 는 끊김 · WireGuard 는 연결 상태가 없어 다음 패킷으로 서버가 새 주소를 배운다(로밍)" : "열려 있던 TCP·VPN 은 끊김"})`,
    );
  }

  /** 노트북: 쓸 NIC 를 바꿔 낌 (링크가 내려간 상태에서) — MAC 과 그 NIC 의 DHCP 기억을 바꾼다 */
  private useNic(i: number): void {
    this.activeNic = i;
    const nic = this.nics[i]!;
    if (this.iface.mac === nic.mac) return;
    // 지금 MAC 의 NIC 가 받은 주소를 그 NIC 에 기억해 두고 (둘 다 끊긴 상태를 거쳐도), 바꿔 낄 NIC 의 기억을 꺼낸다
    const cur = this.nics.find((n) => n.mac === this.iface.mac);
    if (cur) cur.lease = this.dhcp.remembered;
    this.iface.setMac(nic.mac);
    this.v6.setMac(nic.mac);
    this.dhcp.remembered = nic.lease;
  }

  /** 링크가 살아남 (또는 다른 NIC 로 바꿔 낀 뒤): 주소 받기·IPv6·헬스 체크를 시작 */
  private stackUp(ctx: NodeContext, msg: string | null): void {
    this.linkUp = true;
    if (msg) ctx.trace("link.up", "L1", msg);
    if (this.ipMode === "dhcp") this.dhcp.start(ctx, this.emit(ctx));
    else if (this.iface.ip) this.iface.claim(ctx, this.emit(ctx));
    this.v6.linkUp(ctx, this.emit(ctx));
    this.lb.ensureChecks(ctx); // 액티브 헬스 체크 (켜져 있으면)
  }

  /**
   * 주소에 묶인 앱: 주소를 얻으면 붙고(원격 접속 VPN 접속·P2P 시그널링 등록·메시 로그인·SIP 등록), 잃으면 정리한다.
   * 새 앱은 여기 한 줄 — 주소가 바뀌는 길(고정 주소 변경·고정 → DHCP·링크 다운·DHCP 임대·ARP Probe 끝)마다 목록을 따로 두면 빠진다 (SIP 가 빠졌던 결함)
   */
  private addressApps(): { up(ctx: NodeContext): void; lost(ctx: NodeContext, why: string): void }[] {
    return [
      { up: (ctx) => this.ra.connect(ctx), lost: (ctx, why) => this.ra.lost(ctx, why) },
      { up: (ctx) => this.p2p.onAddress(ctx), lost: () => this.p2p.lost() },
      { up: (ctx) => this.mesh.onAddress(ctx), lost: () => this.mesh.lost() },
      { up: (ctx) => this.sip.onAddress(ctx), lost: (ctx) => this.sip.lost(ctx) },
    ];
  }

  /** IPv4 주소를 쓰기 시작함 (DHCP 임대·고정 주소의 ARP Probe 끝): 주소에 묶인 앱 전부와 멀티캐스트 가입 다시 알리기 */
  private addressUp(ctx: NodeContext, why: string): void {
    for (const app of this.addressApps()) app.up(ctx);
    this.reportGroups(ctx, why);
  }

  /** IPv4 주소를 잃음 (바뀜·DHCP 로 전환): 그 주소의 연결·traceroute 와 주소에 묶인 앱 전부를 정리 (IPv6 연결은 그대로) */
  private addressLost(ctx: NodeContext, why: string): void {
    this.tcp.abortAll(why, ctx, (c) => !isIpv6(c.localIp));
    this.diag.cancelTraceroute(why, ctx, (rec) => !isIpv6(rec.resolved ?? rec.dst));
    for (const app of this.addressApps()) app.lost(ctx, why);
  }

  /** 링크가 내려감 (또는 다른 NIC 로 바꿔 끼기 전): 연결·대기열을 정리하고 DHCP 주소를 내려놓는다 */
  private stackDown(ctx: NodeContext, why: string, msg: string | null): void {
    this.linkUp = false;
    if (msg) ctx.trace("link.down", "L1", msg);
    this.v6.linkDown();
    for (const app of this.addressApps()) app.lost(ctx, why);
    this.iface.clearPending();
    this.tcp.abortAll(why, ctx);
    this.diag.cancelTraceroute(why, ctx);
    this.resolver.clear(why);
    if (this.ipMode === "dhcp") {
      const had = this.iface.ip;
      this.iface.clearAddress();
      this.dhcp.stop();
      if (had) ctx.trace("dhcp.release", "app", `${why}으로 임대 주소 ${had} 해제 → IP 미설정`, { ip: had });
    }
  }

  // ---------- 사용자 동작 ----------

  /** 반복 ping 횟수를 1~PING_MAX_COUNT 정수로 (없거나 숫자가 아니면 1) */
  static pingCount(count?: number): number {
    return HostDiagnostics.pingCount(count);
  }

  /** ping. count > 1 이면 반복 ping (ping -c N) */
  ping(target: string, ctx: NodeContext, count = 1): void {
    this.diag.ping(target, ctx, count);
  }

  /** DNS 조회(nslookup) */
  lookup(rawName: string, qtype: QType, server: Ip | undefined, ctx: NodeContext): void {
    this.diag.lookup(rawName, qtype, server, ctx);
  }

  /** 경로 추적 */
  traceroute(target: string, ctx: NodeContext): void {
    this.diag.traceroute(target, ctx);
  }

  /** ICMP Destination Unreachable: 원래 패킷으로 누가 보낸 것인지 찾아 timeout 을 기다리지 않고 바로 끝낸다 */
  private handleUnreachable(pkt: IpPacket, icmp: IcmpUnreachable | Icmpv6Unreachable, frameId: number, ctx: NodeContext): void {
    const o = icmp.original;
    const label = icmp.kind === "icmp6" ? UNREACHABLE6_LABEL[icmp.code] : UNREACHABLE_LABEL[icmp.code];
    const reason = `${label} (${pkt.src})`;
    const done = (what: string) =>
      ctx.trace("icmp.unreachable.received", "app", `${pkt.src} 로부터 ${icmp.kind === "icmp6" ? "ICMPv6" : "ICMP"} ${label} 수신 (원래 ${describeOriginal(o)}) → ${what}`, { from: pkt.src, code: icmp.code }, frameId);
    if (this.diag.onUnreachable(pkt, icmp, reason, done, ctx)) return;
    if (this.tcp.onUnreachable(o, reason, ctx)) {
      done("TCP 연결 실패");
      return;
    }
    if (o.l4.kind === "udp" && o.l4.srcPort === this.resolver.port && this.resolver.onUnreachable(`DNS 서버에 닿지 않음: ${reason}`, ctx, o.dst)) {
      done("DNS 조회 실패");
      return;
    }
    done("기다리는 요청이 없어 무시");
  }

  /** TCP 연결 시작 (클라이언트) */
  connect(target: string, port: number, ctx: NodeContext, jump?: string): void {
    if (jump) {
      this.connectViaJump(target, port, jump, ctx);
      return;
    }
    if (isIpv6(target)) {
      this.connect6(canonIp6(target)!, port, ctx);
      return;
    }
    if (!this.iface.ip && !(looksLikeName(target) && this.hasV6Global())) {
      ctx.trace("ip.no-address", "L3", `${target}:${port} 연결 실패: 내 IP 주소가 없음 (DHCP 로 받거나 수동 설정 필요)`, { dst: target, port });
      this.tcp.recordFailure("0.0.0.0", target, port, "IP 미설정", ctx);
      return;
    }
    if (!looksLikeName(target) && !isValidIp(target)) {
      ctx.trace("ip.drop", "L3", `${target}:${port} 연결 실패: IP 주소도 이름도 아님`, { dst: target, port });
      this.tcp.recordFailure(this.iface.ip ?? "0.0.0.0", target, port, "잘못된 주소", ctx);
      return;
    }
    const proxy = this.proxyFor(target, port);
    if (proxy && port === HTTPS_PORT) {
      // HTTPS 는 프록시가 대신 받아 올 수 없다 (암호화) → CONNECT 로 대상까지 통로를 부탁하고 TLS 는 대상과 직접. 이름은 프록시가 찾는다
      ctx.trace("proxy.use", "app", `HTTPS 프록시 설정(https_proxy=http://${proxy.server}:${proxy.port}) → ${target}:${port} 에 직접 가지 않고 프록시에게 CONNECT 로 터널을 부탁${looksLikeName(target) ? " (이름은 프록시가 찾음)" : ""}`, { dst: target, port, proxy: `${proxy.server}:${proxy.port}`, method: "CONNECT" });
      this.tcp.connect(this.iface.ip!, proxy.server, proxy.port, ctx, { target: `${target}:${port}`, method: "CONNECT" });
      return;
    }
    if (proxy) {
      // 웹 요청은 대상에 직접 가지 않고 프록시에게 부탁한다. 이름도 풀지 않고 그대로 넘긴다 (프록시가 찾는다)
      ctx.trace("proxy.use", "app", `HTTP 프록시 설정(http_proxy=http://${proxy.server}:${proxy.port}) → ${target}:${port} 에 직접 가지 않고 프록시에게 대신 받아 달라고 부탁${looksLikeName(target) ? " (이름은 프록시가 찾음)" : ""}`, { dst: target, port, proxy: `${proxy.server}:${proxy.port}` });
      this.tcp.connect(this.iface.ip!, proxy.server, proxy.port, ctx, { target: `${target}:${port}` });
      return;
    }
    if (looksLikeName(target)) {
      this.resolveName(target, ctx, (ip, err) => {
        if (!ip) {
          ctx.trace("tcp.failed", "L4", `${target}:${port} 연결 실패: 이름을 주소로 바꾸지 못함 (${err})`, { dst: target, port });
          this.tcp.recordFailure(this.iface.ip ?? "0.0.0.0", target, port, err ?? "이름 해석 실패", ctx);
          return;
        }
        ctx.trace("dns.resolved", "app", `${target} = ${ip} → 이 주소의 ${port} 포트로 연결`, { name: target, ip });
        if (isIpv6(ip)) {
          const src = this.v6.sourceFor(ip);
          if (!src) {
            // 답을 기다리는 동안 IPv6 주소가 사라졌다 (IPv6 끔·RA 거둠): IPv4 가 있으면 A 로, 없으면 실패로 남긴다
            if (this.iface.ip) {
              ctx.trace("tcp.fallback", "L4", `${target}: IPv6 출발지 주소가 없어졌음 (${this.v6.whyNoSource(ip)}) → IPv4 주소(A)로 연결`, { dst: target, port });
              this.resolver.resolve(target, ctx, this.emit(ctx), (ip4, err) => {
                if (ip4 && this.iface.ip) this.tcp.connect(this.iface.ip, ip4, port, ctx, { site: target });
                else {
                  ctx.trace("tcp.failed", "L4", `${target}:${port} 연결 실패: ${err ?? "IPv4 주소 없음"}`, { dst: target, port });
                  this.tcp.recordFailure(this.iface.ip ?? "0.0.0.0", target, port, err ?? "IPv4 주소 없음", ctx);
                }
              });
            } else {
              ctx.trace("tcp.failed", "L4", `${target}:${port} 연결 실패: ${this.v6.whyNoSource(ip)}`, { dst: target, port });
              this.tcp.recordFailure("::", ip, port, this.v6.enabled ? "IPv6 주소 없음" : "IPv6 꺼짐", ctx);
            }
            return;
          }
          // IPv6 로 먼저 시도하고, 연결이 안 되면 같은 이름의 IPv4 주소로 다시 (Happy Eyeballs 축소판)
          const conn = this.tcp.connect(src, ip, port, ctx, { site: target });
          if (this.iface.ip && conn.state === "SYN_SENT") this.fallbacks.set(conn.id, { name: target, port });
          return;
        }
        if (this.iface.ip) this.tcp.connect(this.iface.ip, ip, port, ctx, { site: target }); // 쿠키는 적은 이름 기준 (브라우저처럼)
      });
      return;
    }
    this.tcp.connect(this.iface.ip!, target, port, ctx);
  }

  /**
   * ssh -J 점프서버 대상: 점프 서버(22)에 먼저 SSH 로그인하고, 그 세션으로 대상까지 채널을 부탁해 그 위에서 대상과 SSH.
   * 대상의 이름은 점프 서버가 푼다 (대상이 점프 서버 너머 망에 있어 내 DNS 로는 모를 수 있다). 점프 서버는 IPv4 만
   */
  private connectViaJump(target: string, port: number, jump: string, ctx: NodeContext): void {
    const fail = (why: string, reason: string) => {
      ctx.trace("ssh.jump.fail", "app", `ssh -J ${jump} ${target}: ${why}`, { dst: target, jump, role: "client" });
      this.tcp.recordFailure(this.iface.ip ?? "0.0.0.0", jump, SSH_PORT, reason, ctx);
    };
    if (!this.iface.ip) return fail("내 IP 주소가 없음 (DHCP 로 받거나 수동 설정 필요)", "IP 미설정");
    if (isIpv6(jump) || (!looksLikeName(jump) && !isValidIp(jump))) return fail(`점프 서버 ${jump} 는 IPv4 주소나 이름이 아님 (점프 서버는 IPv4 만)`, "잘못된 점프 서버 주소");
    // 대상도 IPv4 주소나 이름만 (이름은 점프 서버가 A 로 푼다) — IPv6 대상은 이 시뮬레이터의 점프가 다루지 않는다
    if (isIpv6(target) || (!looksLikeName(target) && !isValidIp(target))) return fail(`대상 ${target} 는 IPv4 주소나 이름이 아님 (SSH 점프의 대상은 IPv4 만)`, "점프 대상은 IPv4 만");
    const go = (ip: Ip) => {
      if (!this.iface.ip) return;
      ctx.trace("ssh.jump", "app", `ssh -J ${jump} ${target}${port !== SSH_PORT ? ` -p ${port}` : ""}: 대상에 바로 가지 않고 점프 서버 ${ip}:22 에 먼저 SSH 로그인한 뒤, 그 세션으로 ${target}:${port} 까지 채널을 부탁한다`, { dst: target, jump: ip, target: `${target}:${port}`, role: "client", start: true });
      this.tcp.connect(this.iface.ip, ip, SSH_PORT, ctx, { jump: `${target}:${port}` });
    };
    if (isValidIp(jump)) return go(jump);
    this.resolveName(jump, ctx, (ip, err) => (ip && !isIpv6(ip) ? go(ip) : fail(`점프 서버 이름 ${jump} 를 IPv4 주소로 바꾸지 못함 (${err ?? "IPv4 주소 없음"})`, err ?? "점프 서버 이름 해석 실패")), undefined, true);
  }

  /** 이 호스트가 IPv6 글로벌 주소를 쓸 수 있는지 (이름을 AAAA 로 먼저 물을지) */
  private hasV6Global(): boolean {
    return this.v6.enabled && this.v6.globals.length > 0;
  }

  /**
   * 이름 → 주소 (getaddrinfo 흉내): IPv6 글로벌 주소가 있으면 AAAA 먼저 (RFC 6724 기본 정책: IPv6 우선), AAAA 레코드가 없거나
   * 묻지 못하면 IPv4 주소가 있을 때 A 로 다시. 없는 이름(NXDOMAIN)이면 A 도 없으니 다시 묻지 않는다.
   * IPv6 글로벌 주소가 없으면 예전처럼 A 만 (쓸 수 없는 주소 종류는 묻지 않는다 — AI_ADDRCONFIG). v4Only 면 늘 A 만 (IPv4 만 쓰는 곳 — SSH 점프 서버)
   */
  private resolveName(name: string, ctx: NodeContext, done0: (ip: Ip | undefined, error?: string) => void, alive: () => boolean = () => true, v4Only = false): void {
    // MagicDNS: 메시 피어의 이름은 기기 안(100.100.100.100)에서 바로 푼다 — DNS 서버에 묻지 않는다
    const magic = this.mesh.resolve(name);
    if (magic) {
      ctx.trace("dns.resolved", "app", `${name} = ${magic} (MagicDNS — ${this.mesh.brand} netmap 의 피어 이름, DNS 서버에 묻지 않음)`, { name, ip: magic, magicDns: true });
      done0(magic);
      return;
    }
    // 0.0.0.0·:: 답은 DNS 필터(AdGuard 등)가 막은 이름 — 그 주소로 보내지 않는다 (브라우저도 바로 실패)
    const done = (ip: Ip | undefined, error?: string) => {
      if (ip === "0.0.0.0" || ip === "::") {
        ctx.trace("dns.resolved", "app", `${name} = ${ip} → DNS 가 막은 이름 (광고 차단·자녀 보호가 ${ip} 로 답함) — 접속하지 않음`, { name, blocked: true });
        done0(undefined, `DNS 가 막은 이름 (${ip})`);
        return;
      }
      done0(ip, error);
    };
    if (v4Only || !this.hasV6Global()) {
      this.resolver.resolve(name, ctx, this.emit(ctx), (ip, err) => done(ip, err));
      return;
    }
    this.resolver.resolve(
      name,
      ctx,
      this.emit(ctx),
      (ip6, err6, info) => {
        if (!alive()) {
          done(undefined, err6 ?? "취소됨"); // 기다리는 동안 취소됨 (예: 새 traceroute)
          return;
        }
        const a = (why: string) => {
          ctx.trace("dns.resolved", "app", `${name}: ${why} → IPv4 주소(A)로 다시 묻는다`, { name, fallback: "A" });
          this.resolver.resolve(name, ctx, this.emit(ctx), (ip, err) => done(ip, err));
        };
        if (ip6 === "::") {
          done(ip6); // DNS 필터가 막은 이름 — A 로 다시 묻지 않는다
          return;
        }
        if (ip6) {
          // RFC 6724 규칙 1: 갈 수 없는 목적지는 뒤로 — IPv6 기본 게이트웨이가 없고 같은 링크도 아니면 IPv4 로
          if (this.iface.ip && !this.v6.onLink(ip6) && !this.v6.defaultRouter) {
            a(`AAAA ${ip6} 는 있지만 IPv6 기본 게이트웨이가 없어 갈 수 없음`);
            return;
          }
          done(ip6);
          return;
        }
        // 다시 물어볼 만한 실패(NODATA·timeout·SERVFAIL·닿지 않음)일 때만. 없는 이름·설정 없음·취소는 A 도 같다
        if (!this.iface.ip || !(info?.nodata || info?.retry)) {
          done(undefined, err6);
          return;
        }
        a(info.nodata ? "AAAA 레코드가 없음" : `AAAA 를 받지 못함 (${err6})`);
      },
      "AAAA",
    );
  }

  /** Happy Eyeballs 축소판: 이름으로 연 IPv6 연결이 SYN 단계에서 실패하면(timeout·Unreachable) 같은 이름의 IPv4 주소로 다시 연결 */
  private readonly fallbacks = new Map<string, { name: string; port: number }>();

  private happyEyeballs(conn: TcpConn, ctx: NodeContext): boolean {
    const fb = this.fallbacks.get(conn.id);
    if (!fb) return false;
    this.fallbacks.delete(conn.id);
    // 연결을 맺지 못한 실패만: 무응답(timeout)·닿지 않음(Unreachable)·거부(RST) — curl·브라우저는 다음 주소로 넘어간다
    const handshake = conn.state === "FAILED" && (conn.reason?.startsWith("timeout · SYN") || conn.reason?.includes("Unreachable") || conn.reason === "연결 거부 (RST)");
    if (!handshake || !this.iface.ip) return true;
    ctx.trace(
      "tcp.fallback",
      "L4",
      `Happy Eyeballs(축소판): ${endpoint(conn.remoteIp, conn.remotePort)} IPv6 연결 실패 (${conn.reason}) → ${fb.name} 의 IPv4 주소(A)로 다시 연결. 실제 브라우저·curl 은 IPv6 를 250ms 만 기다리고 IPv4 를 함께 시작해 빠른 쪽을 쓴다`,
      { conn: conn.id, name: fb.name },
    );
    this.resolver.resolve(fb.name, ctx, this.emit(ctx), (ip, err) => {
      if (!ip || !this.iface.ip) {
        ctx.trace("tcp.failed", "L4", `${fb.name}:${fb.port} IPv4 로도 연결 못 함: ${err ?? "IPv4 주소 없음"}`, { dst: fb.name, port: fb.port });
        return;
      }
      this.tcp.connect(this.iface.ip, ip, fb.port, ctx, { site: fb.name });
    });
    return true;
  }

  /** IPv6 주소로 TCP 연결 (HTTP 프록시는 IPv4 만 다뤄 거치지 않는다) */
  private connect6(dst: Ip, port: number, ctx: NodeContext): void {
    if (isMulticast6(dst)) {
      ctx.trace("ip.drop", "L4", `[${dst}]:${port} 연결 실패: 멀티캐스트 주소로는 TCP 연결을 할 수 없음 (TCP 는 두 장치 사이의 연결)`, { dst, port });
      this.tcp.recordFailure(this.v6.sourceFor(dst) ?? "::", dst, port, "멀티캐스트 주소", ctx);
      return;
    }
    const src = this.v6.sourceFor(dst);
    if (!src) {
      const why = this.v6.whyNoSource(dst);
      ctx.trace("ip.no-address", "L3", `[${dst}]:${port} 연결 실패: ${why}`, { dst, port });
      this.tcp.recordFailure("::", dst, port, this.v6.enabled ? "IPv6 주소 없음" : "IPv6 꺼짐", ctx);
      return;
    }
    if (this.proxyFor(dst, port)) ctx.trace("proxy.use", "app", `IPv6 주소 [${dst}] 는 HTTP 프록시를 거치지 않고 직접 연결 (이 시뮬레이터의 프록시는 IPv4 만 다룸)`, { dst, port });
    this.tcp.connect(src, dst, port, ctx);
  }

  /**
   * 이 연결을 프록시에게 부탁하는지: 웹(포트 80·443) 요청이면 대상이 어디든 (브라우저·curl 의 http_proxy·https_proxy 와 같다 —
   * 같은 사무실 서버도 프록시를 거친다. 실무에서는 예외 목록(no_proxy·PAC)으로 뺀다). 내 주소는 직접
   */
  private proxyFor(target: string, port: number): HttpProxySetting | undefined {
    const p = this.httpProxy;
    if (!p || (port !== 80 && port !== HTTPS_PORT) || !this.iface.ip || target === this.iface.ip) return undefined;
    return p;
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

  receive(port: number, frame: EthernetFrame, ctx: NodeContext): void {
    this.clock = ctx.now;
    // 노트북의 쉬고 있는 NIC (유선을 쓰는 중에 붙어 있는 Wi-Fi 등) 로 온 프레임은 IP 스택에 올리지 않는다
    if (port !== (this.activeNic ?? port)) return;
    if (frame.vlan !== undefined) {
      ctx.trace("vlan.drop", "L2", `VLAN ${frame.vlan} 태그가 달린 프레임 → 호스트는 태그를 이해하지 못해 드롭 (스위치 포트를 액세스로 바꾸세요)`, { vlan: frame.vlan }, frame.id);
      return;
    }
    // 가입하지 않은 멀티캐스트(예: 라우터끼리 주고받는 RIP)는 NIC 가 하드웨어에서 조용히 거른다. IPv6 는 모든 노드·내 solicited-node 그룹에 가입한다
    // IPv4 멀티캐스트: 가입한 그룹, 모든 호스트(224.0.0.1 — IGMP 쿼리), 가입한 게 있으면 224.0.0.2(다른 기기의 Leave — 쿼리 흉내로 다시 알리려고)
    const v6Group = this.v6.accepts(frame.dst) || frame.dst === mcastMac(ALL_HOSTS_IP) || (this.groups.size > 0 && frame.dst === mcastMac(ALL_ROUTERS_IP)) || [...this.groups].some((g) => mcastMac(g) === frame.dst);
    if (isMulticastMac(frame.dst) && !v6Group) return;
    if (!this.iface.accepts(frame) && !v6Group) {
      ctx.trace("frame.drop", "L2", `목적지 MAC ${frame.dst} 가 내 MAC(${this.iface.mac}) 아님 → 드롭`, { dst: frame.dst }, frame.id);
      return;
    }
    const to = frame.dst === this.iface.mac ? "내 MAC" : isMulticastMac(frame.dst) ? `멀티캐스트 ${frame.dst}` : "브로드캐스트";
    ctx.trace("frame.receive", "L2", `프레임 수신: ${describeFrame(frame)} [${frame.src} → ${to}]`, { src: frame.src, dst: frame.dst }, frame.id);
    if (frame.payload.kind === "arp") this.iface.handleArp(frame.payload, frame.id, ctx, this.emit(ctx));
    else if (frame.payload.kind === "ipv4") this.handleIp(frame.payload, frame.id, ctx);
    else if (frame.payload.kind === "ipv6") {
      if (!this.v6.enabled) ctx.trace("frame.drop", "L3", `IPv6 패킷 수신 → 이 장치는 IPv6 가 꺼져 있어 드롭 (IPv6 설정에서 켜세요)`, {}, frame.id);
      else if (isNdp(frame.payload.payload)) this.v6.handleNdp(frame.payload, frame.payload.payload, frame, ctx, this.emit(ctx));
      else this.handleIp6(frame.payload, frame.id, ctx);
    }
  }

  private handleIp6(pkt: Ipv6Packet, frameId: number, ctx: NodeContext): void {
    if (!this.v6.owns(pkt.dst) && pkt.dst !== ALL_NODES) {
      ctx.trace("ip.drop", "L3", `목적지 ${pkt.dst} 가 내 IPv6 주소가 아님 → 드롭 (호스트는 포워딩 안 함)`, { dst: pkt.dst }, frameId);
      return;
    }
    const p = pkt.payload;
    if (p.kind === "tcp" && pkt.dst === ALL_NODES) {
      ctx.trace("ip.drop", "L4", `멀티캐스트(${pkt.dst})로 온 TCP → 드롭 (TCP 는 유니캐스트로만 연결한다, RFC 1122)`, { dst: pkt.dst }, frameId);
      return;
    }
    if (p.kind === "tcp") {
      this.tcp.handle(pkt, p, ctx);
      return;
    }
    if (p.kind === "udp" && p.payload.kind === "dns" && pkt.dst !== ALL_NODES) {
      const m = p.payload;
      if (p.dstPort === this.resolver.port) this.resolver.handle(m, pkt.src, frameId, ctx);
      else if (p.dstPort === DNS_PORT && (this.dnsServer.config.enabled || m.op === "response")) this.dnsServer.handle(pkt, p.srcPort, m, frameId, ctx, this.emit(ctx));
      else {
        ctx.trace("ip.drop", "L4", `DNS 질의를 받았지만 DNS 서버 서비스가 꺼져 있음 → 드롭 (서비스에서 DNS 서버를 켜세요)`, { port: p.dstPort }, frameId);
        const notice = this.v6.unreachable(pkt, "port", ctx, frameId);
        if (notice) this.v6.send(notice, ctx, this.emit(ctx));
      }
      return;
    }
    if (p.kind === "udp") {
      ctx.trace("ip.drop", "L4", `UDP 포트 ${p.dstPort} 를 듣는 프로그램 없음 → 드롭`, { port: p.dstPort }, frameId);
      if (pkt.dst !== ALL_NODES) {
        const notice = this.v6.unreachable(pkt, "port", ctx, frameId);
        if (notice) this.v6.send(notice, ctx, this.emit(ctx));
      }
      return;
    }
    this.handleIcmp6(pkt, p, frameId, ctx);
  }

  private handleIcmp6(pkt: Ipv6Packet, icmp: Icmpv6Packet, frameId: number, ctx: NodeContext): void {
    if (icmp.type === "time-exceeded") {
      this.diag.handleTimeExceeded(pkt, icmp, frameId, ctx);
      return;
    }
    if (icmp.type === "unreachable") {
      this.handleUnreachable(pkt, icmp, frameId, ctx);
      return;
    }
    if (icmp.type === "ns" || icmp.type === "na" || icmp.type === "rs" || icmp.type === "ra") return;
    if (icmp.type === "echo-request") {
      ctx.trace("icmp.echo.received", "app", `ICMPv6 Echo 요청 수신 (from ${pkt.src}, seq=${icmp.seq})`, { from: pkt.src, seq: icmp.seq }, frameId);
      // 멀티캐스트(ff02::1)로 온 ping 에는 내 유니캐스트 주소로 답한다
      const src = pkt.dst === ALL_NODES ? this.v6.sourceFor(pkt.src) : pkt.dst;
      if (!src) return;
      const reply: Ipv6Packet = { kind: "ipv6", src, dst: pkt.src, hopLimit: Ipv6Interface.HOP_LIMIT, payload: { kind: "icmp6", type: "echo-reply", id: icmp.id, seq: icmp.seq } };
      ctx.trace("icmp.reply.sent", "app", `ICMPv6 Echo 응답 생성 → ${pkt.src} (seq=${icmp.seq})`, { to: pkt.src, seq: icmp.seq });
      this.v6.send(reply, ctx, this.emit(ctx));
      return;
    }
    this.diag.echoReply(pkt, icmp, frameId, ctx);
  }

  private handleIp(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    // 인터넷 전화: SIP 신호(5060)·음성(RTP)
    if (pkt.dst === this.iface.ip && pkt.payload.kind === "udp" && this.sip.config.enabled) {
      const u = pkt.payload;
      if (u.payload.kind === "sip" && u.dstPort === SIP_PORT) {
        this.sip.handle(pkt, u, u.payload, ctx, frameId);
        return;
      }
      if (u.payload.kind === "rtp" && u.dstPort === this.sip.rtpPort) {
        this.sip.handleRtp(u.payload, ctx, frameId);
        return;
      }
    }
    // IGMP: 쿼리면 가입한 그룹을 다시 알리고, 다른 기기가 내 그룹을 탈퇴하면 나는 아직 보고 있다고 다시 알린다 (스누핑 스위치가 포트를 지우지 않게)
    if (pkt.payload.kind === "igmp") {
      const g = pkt.payload;
      if (g.type === "query" && this.groups.size) this.reportGroups(ctx, "IGMP 쿼리를 받음");
      else if (g.type === "leave" && pkt.src !== this.iface.ip && this.groups.has(g.group)) this.reportGroups(ctx, `다른 기기(${pkt.src})가 그룹 ${g.group} 탈퇴`, g.group);
      return;
    }
    // 멀티캐스트 스트림: 가입한 그룹이면 받는다 (NIC 가 그 MAC 을 들여보냈다)
    if (isMcastIp(pkt.dst) && pkt.payload.kind === "udp" && pkt.payload.payload.kind === "mcast") {
      const m = pkt.payload.payload;
      if (!this.groups.has(pkt.dst)) return;
      const n = (this.streamRx.get(pkt.dst) ?? 0) + 1;
      this.streamRx.set(pkt.dst, n);
      ctx.trace("mcast.recv", "app", `IPTV 수신: ${m.name} 조각 ${m.seq}/${m.total} (보낸 곳 ${pkt.src}, 이 그룹에서 받은 수 ${n})`, { group: pkt.dst, seq: m.seq }, frameId);
      return;
    }
    // 메시 VPN 앱 (Tailscale·ZeroTier): 내 포트로 온 메시 메시지와 그 STUN 응답
    if (pkt.dst === this.iface.ip && pkt.payload.kind === "udp" && this.mesh.ownsPort(pkt.payload.dstPort)) {
      const udp = pkt.payload;
      if (udp.payload.kind === "ts") {
        const inner = this.mesh.handle(pkt, udp, udp.payload, ctx, frameId);
        if (inner) {
          if (inner.dst !== this.mesh.self?.ip) ctx.trace("mesh.drop", "L3", `${this.mesh.brand}: 꺼낸 패킷의 목적지 ${inner.dst} 가 내 메시 주소(${this.mesh.self?.ip ?? "없음"})가 아님 → 드롭 (호스트는 서브넷 라우터가 아니다)`, { dst: inner.dst }, frameId);
          else this.handleIp({ ...inner, dst: this.iface.ip }, frameId, ctx);
        }
        return;
      }
      if (udp.payload.kind === "stun" && this.mesh.ownsStun(udp.payload)) {
        this.mesh.handleStun(udp.payload, ctx, frameId);
        return;
      }
    }
    // 원격 접속 VPN 앱: 서버의 IKE 응답·터널의 ESP, 내 포트로 온 WireGuard·OpenVPN (UDP), 내 OpenVPN TCP 연결의 세그먼트
    if (pkt.dst === this.iface.ip) {
      const inner = this.ra.receive(pkt, frameId, ctx);
      if (inner !== undefined) {
        if (inner) this.handleIp(inner, frameId, ctx);
        return;
      }
    }
    if (pkt.dst === this.iface.ip && pkt.payload.kind === "tcp" && this.ovpnLate.includes(`${pkt.src}:${pkt.payload.dstPort}`)) {
      ctx.trace("vpn.drop", "L4", `OpenVPN 의 지난 TCP 연결(${pkt.src}, 내 포트 ${pkt.payload.dstPort})로 늦게 온 세그먼트 → 무시 (VPN 종류를 바꿔 그 연결은 이미 닫음)`, { ovpn: true, late: true }, frameId);
      return;
    }
    // VPN 을 끈 직후·종류를 바꾼 직후 늦게 온 IKE·ESP: 지금 VPN 클라이언트가 받지 않은 것은 조용히 버린다 —
    // 호스트로 넘기면 "UDP 포트를 듣는 프로그램 없음" + ICMP Port Unreachable 이 서버로 샌다 (OS 의 IPsec 서비스는 VPN 을 꺼도 500·4500 을 쥐고 있다)
    if (pkt.dst === this.iface.ip) {
      const p = pkt.payload;
      if (p.kind === "esp" || (p.kind === "tcp" && p.ovpn) || (p.kind === "udp" && (p.payload.kind === "ike" || p.payload.kind === "esp" || p.payload.kind === "wg" || p.payload.kind === "ovpn" || p.payload.kind === "ts"))) {
        ctx.trace("vpn.drop", "L3", `${p.kind === "udp" && p.payload.kind === "ike" ? `IKE ${p.payload.exchange}` : p.kind === "udp" && p.payload.kind === "wg" ? "WireGuard" : p.kind === "udp" && p.payload.kind === "ts" ? "메시 VPN" : (p.kind === "udp" && p.payload.kind === "ovpn") || p.kind === "tcp" ? "OpenVPN" : "ESP"} 수신 (from ${pkt.src}) → 지금 VPN 연결의 것이 아님 (끊었거나 종류를 바꾼 뒤 늦게 온 패킷) → 무시`, { from: pkt.src, late: true }, frameId);
        return;
      }
    }
    if (pkt.payload.kind === "udp") {
      const udp = pkt.payload;
      const m = udp.payload;
      if (m.kind === "dhcp" && udp.dstPort === DHCP_CLIENT_PORT) {
        this.dhcp.handle(m, frameId, ctx, this.emit(ctx));
        this.addressUp(ctx, "주소를 얻음 (링크 복구·NIC 전환)");
        return;
      }
      if (udp.dstPort === P2P_PORT && pkt.dst === this.iface.ip && this.p2p.handle(pkt, udp, ctx, frameId)) return;
      if (m.kind === "dhcp" && udp.dstPort === DHCP_SERVER_PORT) {
        if (!this.dhcpServer.config.enabled) ctx.trace("dhcp.ignore", "app", `다른 호스트의 DHCP ${m.op} 브로드캐스트 — 나는 서버가 아니므로 무시`, {}, frameId);
        else if (this.ipMode !== "static") ctx.trace("dhcp.misconfigured", "app", `DHCP 서버가 켜져 있지만 내 주소가 고정이 아님(자동) → 응답하지 않음. IP 설정을 수동으로 바꾸세요`, {}, frameId);
        else this.dhcpServer.handle(m, frameId, ctx, this.emit(ctx));
        return;
      }
      if (m.kind === "dns") {
        if (pkt.dst !== this.iface.ip) {
          ctx.trace("ip.drop", "L3", `목적지 IP ${pkt.dst} 가 내 IP 아님 → 드롭`, { dst: pkt.dst }, frameId);
          return;
        }
        if (udp.dstPort === this.resolver.port) this.resolver.handle(m, pkt.src, frameId, ctx);
        else if (udp.dstPort === DNS_PORT && (this.dnsServer.config.enabled || m.op === "response")) this.dnsServer.handle(pkt, udp.srcPort, m, frameId, ctx, this.emit(ctx));
        else {
          ctx.trace("ip.drop", "L4", `DNS 질의를 받았지만 DNS 서버 서비스가 꺼져 있음 → 드롭 (서비스에서 DNS 서버를 켜세요)`, { port: udp.dstPort }, frameId);
          this.portUnreachable(pkt, ctx, frameId);
        }
        return;
      }
      ctx.trace("ip.drop", "L4", `UDP 포트 ${udp.dstPort} 를 듣는 프로그램 없음 → 드롭`, { port: udp.dstPort }, frameId);
      if (pkt.dst === this.iface.ip) this.portUnreachable(pkt, ctx, frameId);
      return;
    }
    if (pkt.dst !== this.iface.ip) {
      ctx.trace("ip.drop", "L3", `목적지 IP ${pkt.dst} 가 내 IP(${this.iface.ip ?? "없음"}) 아님 → 드롭 (호스트는 포워딩 안 함)`, { dst: pkt.dst }, frameId);
      return;
    }
    if (pkt.payload.kind === "tcp") {
      // L4 로드밸런서: 내 TCP 로 받지 않고 주소·포트만 바꿔 백엔드(또는 클라이언트)로 넘긴다
      const relayed = this.lb.l4(pkt, pkt.payload, ctx, frameId);
      if (relayed) {
        for (const out of relayed) this.iface.sendIp(out, ctx, this.emit(ctx));
        return;
      }
      this.tcp.handle(pkt, pkt.payload, ctx);
      return;
    }
    if (isControl(pkt.payload)) return; // 가입하지 않은 멀티캐스트, 다른 호스트의 IGMP 가입 알림
    if (pkt.payload.kind === "esp") {
      ctx.trace("ip.drop", "L3", `ESP(IPsec) 패킷 수신 → 호스트에는 IPsec VPN 이 없어 드롭`, {}, frameId);
      return;
    }
    this.handleIcmp(pkt, pkt.payload, frameId, ctx);
  }

  /** 닫힌 UDP 포트로 온 패킷: 보낸 이에게 Port Unreachable 로 알린다 (보낸 쪽 DNS 조회 등이 바로 실패를 안다) */
  private portUnreachable(pkt: Ipv4Packet, ctx: NodeContext, frameId: number): void {
    const notice = this.iface.unreachable(pkt, "port", ctx, frameId);
    if (notice) this.iface.sendIp(notice, ctx, this.emit(ctx));
  }

  private handleIcmp(pkt: Ipv4Packet, icmp: IcmpPacket, frameId: number, ctx: NodeContext): void {
    if (icmp.type === "time-exceeded") {
      this.diag.handleTimeExceeded(pkt, icmp, frameId, ctx);
      return;
    }
    if (icmp.type === "unreachable") {
      this.handleUnreachable(pkt, icmp, frameId, ctx);
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
    this.diag.echoReply(pkt, icmp, frameId, ctx);
  }

  // ---------- 타이머 ----------

  onTimer(tag: string, data: unknown, ctx: NodeContext): void {
    this.clock = ctx.now;
    if (this.diag.timer(tag, data, ctx)) return;
    switch (tag) {
      case LB_CHECK_TAG:
        this.lb.onTimer(data, ctx);
        return;
      case NIC_SWITCH_TAG:
        this.switchNic(ctx);
        return;
      case DAD_TIMER_TAG:
        this.v6.finishDad(data, ctx, this.emit(ctx));
        return;
      case RS_TIMER_TAG:
        this.v6.onRsTimer(data, ctx, this.emit(ctx));
        return;
      case NUD_TIMER_TAG:
        this.v6.onNudTimer(data, ctx, this.emit(ctx));
        return;
      case ROUTER_EXPIRY_TAG:
        this.v6.onRouterExpiry(data, ctx);
        return;
      case NDP_TIMEOUT_TAG:
        this.diag.neighborFailed(this.v6.onNsTimeout(data, ctx), (data as { ip: Ip }).ip, true, ctx);
        return;
      case LOOPBACK_TAG: {
        const pkt = data as IpPacket;
        if (pkt.kind === "ipv6") this.handleIp6(pkt, -1, ctx);
        else this.handleIp(pkt, -1, ctx);
        return;
      }
      case "arp-probe":
        if ((data as { mac: string }).mac === this.iface.mac) this.iface.finishProbe(ctx, this.emit(ctx));
        this.addressUp(ctx, "주소를 쓰기 시작 (링크 복구·NIC 전환)"); // 고정 주소를 쓰기 시작
        return;
      case RA_TIMER_TAG:
      case RA_DPD_TAG:
      case WG_TIMER_TAG:
      case OVPN_TIMER_TAG:
        this.ra.timer(tag, data, ctx);
        return;
      case P2P_TIMER_TAG:
        this.p2p.onTimer(data, ctx);
        return;
      case TS_TIMER_TAG:
        this.mesh.onTimer(data, ctx);
        return;
      case SIP_TIMER_TAG:
        this.sip.onTimer(data, ctx);
        return;
      case "mcast-stream": {
        const d = data as { group: Ip; id: number; seq: number };
        this.streamStep(d.group, d.id, d.seq, ctx);
        return;
      }
      case "arp-timeout":
        this.diag.neighborFailed(this.iface.onArpTimeout(data, ctx), (data as { ip: Ip }).ip, false, ctx);
        return;
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
        ["링크", this.nics.length > 1 ? this.nics.map((n, k) => `${n.name} ${k === this.activeNic ? "사용 중" : n.up ? "대기" : "끊김"}`).join(" · ") : this.linkUp ? "연결됨" : "끊김"],
        ["IP 설정", this.ipMode === "dhcp" ? `자동 (DHCP: ${DHCP_STATE_LABEL[this.dhcp.state]})` : "수동"],
        ...(this.v6.enabled
          ? ([
              ["IPv6", this.v6.summary() || "없음"],
              ["링크 로컬", this.v6.linkLocal],
              ["IPv6 게이트웨이", this.v6.defaultRouter ? `${this.v6.defaultRouter}${this.v6.gateway ? "" : " (RA)"}` : "없음"],
              ...(this.v6.slaac ? ([["IPv6 설정", `자동 (SLAAC)${this.v6.raDnsLearned ? ` · DNS ${this.v6.raDnsLearned} (RDNSS)` : ""}`]] as [string, string][]) : []),
            ] as [string, string][])
          : []),
        ["TCP 서비스", this.tcp.listening.size ? [...this.tcp.listening].map((p) => `포트 ${p}`).join(", ") : "없음"],
        ...(this.ra.config.enabled ? [[this.ra.label, this.ra.summary()!] as [string, string]] : []),
        ...(this.p2p.config.enabled ? [["P2P 앱", this.p2p.summary()!] as [string, string]] : []),
        ...(this.mesh.config.enabled ? [[this.mesh.brand, this.mesh.summary()!] as [string, string]] : []),
        ...(this.sip.config.enabled ? [["인터넷 전화", this.sip.summary()!] as [string, string]] : []),
        ...(this.groups.size ? [["멀티캐스트 그룹", [...this.groups].map((g) => `${g} (받음 ${this.streamRx.get(g) ?? 0})`).join(", ")] as [string, string]] : []),
        ...(this.dhcpServer.config.enabled
          ? [["DHCP 서버", `켜짐 · ${this.dhcpServer.config.start} ~ ${this.dhcpServer.config.end}`] as [string, string]]
          : []),
        ...(this.dnsServer.config.enabled
          ? [["DNS 서버", `켜짐 · 레코드 ${this.dnsServer.config.records.length}개${this.dnsServer.config.upstream ? ` · 업스트림 DNS ${this.dnsServer.config.upstream}` : ""}`] as [string, string]]
          : []),
        ...(this.httpProxy ? [["HTTP 프록시", `http://${this.httpProxy.server}:${this.httpProxy.port} (웹 요청 80·443)`] as [string, string]] : []),
        ...(this.proxy.config.enabled ? [["프록시", `켜짐 · 포트 ${this.proxy.config.port}${this.proxy.config.deny.length ? ` · 차단 ${this.proxy.config.deny.length}개` : ""}`] as [string, string]] : []),
        ...(this.jump.enabled ? [["SSH 점프", `허용 (AllowTcpForwarding yes)${this.services.includes(SSH_PORT) ? "" : " · SSH(22) 서비스가 꺼져 있어 로그인할 수 없음"}`] as [string, string]] : []),
        ...(this.lb.config.enabled
          ? [["로드밸런서", `켜짐 · ${LB_MODE_LABEL[this.lb.config.mode ?? "l7"]} · 포트 ${this.lb.config.port} · ${LB_ALGORITHM_LABEL[this.lb.config.algorithm]}${this.lb.config.sticky ? ` · ${LB_STICKY_LABEL[this.lb.config.sticky]}` : ""}${this.lb.config.healthCheck ? " · 액티브 헬스 체크" : ""} · 백엔드 ${this.lb.config.backends.length}대`] as [string, string]]
          : []),
      ],
      tables: [
        ...(this.sip.calls.length ? [{ title: "통화 기록", columns: ["상대", "방향", "상태", "음성 보냄 / 받음", "이유"], rows: this.sip.calls.map((c) => [c.peer, c.role === "caller" ? "건 전화" : "받은 전화", CALL_STATE_LABEL[c.state], `${c.sent} / ${c.received}`, c.reason ?? "—"]) }] : []),
        ...(this.mesh.config.enabled ? [{ title: `${this.mesh.brand} 피어 (${this.mesh.config.net === "zerotier" ? "zerotier-cli peers" : "tailscale status"})`, columns: ["이름", "메시 주소", "경로", "알린 대역", "패킷"], rows: this.mesh.rows() }] : []),
        ...(this.dhcpServer.config.enabled ? [{ title: "DHCP 임대", columns: ["IP", "MAC", "시각"], rows: this.dhcpServer.rows() }] : []),
        ...(this.dnsServer.config.enabled ? [{ title: "DNS 레코드·캐시", columns: ["이름", "IP", "출처"], rows: this.dnsServer.rows() }] : []),
        ...(this.lb.config.enabled ? [{ title: "로드밸런서 백엔드", columns: ["백엔드", "상태", "처리", "실패"], rows: this.lb.rows(this.clock) }] : []),
        ...(this.lb.config.enabled && this.lb.config.mode === "l4" ? [{ title: "L4 흐름", columns: ["클라이언트", "변환 → 백엔드"], rows: this.lb.flowRows() }] : []),
        ...(this.proxy.config.enabled ? [{ title: "프록시 요청 (access.log)", columns: ["클라이언트", "대상", "결과"], rows: this.proxy.rows() }] : []),
        ...(this.jump.enabled || this.jump.log.length ? [{ title: "SSH 점프 기록 (sshd)", columns: ["시각", "클라이언트", "대상", "결과"], rows: this.jump.rows() }] : []),
        ...(this.resolver.cache.size > 0 ? [{ title: "DNS 캐시 (리졸버)", columns: ["이름", "IP", "시각"], rows: this.resolver.rows() }] : []),
        { title: "TCP 연결", columns: ["상대", "상태", "보냄 / 받음"], rows: this.tcp.rows() },
        { title: "ARP 캐시", columns: ["IP", "MAC", "학습 시각"], rows: i.arpRows() },
        ...(this.v6.enabled
          ? [
              { title: "IPv6 주소", columns: ["주소", "출처", "상태"], rows: this.v6.addrRows() },
              { title: "이웃 캐시 (NDP)", columns: ["IPv6", "MAC", "학습 시각"], rows: this.v6.neighborRows(this.clock) },
            ]
          : []),
      ],
    };
  }
}

function isValidIp(s: string): boolean {
  if (isIpv6(s)) return true;
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
