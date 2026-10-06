import { BROADCAST_MAC, isMulticastMac, sameSubnet, type Ip, type Mac } from "../addr";
import { ALL_NODES, formatIp6, isIpv6, isLinkLocal6, isMulticast6, parseIp6, sameSubnet6, UNSPECIFIED6 } from "../addr6";
import {
  DHCP_CLIENT_PORT,
  DHCP_SERVER_PORT,
  DHCP6_CLIENT_PORT,
  DDNS_PORT,
  DNS_PORT,
  describeFrame,
  icmpLabel,
  isControl,
  isNdp,
  type DhcpMessage,
  type EspPacket,
  type EthernetFrame,
  type IcmpPacket,
  type Ipv4Packet,
  type Ipv6Packet,
} from "../packet";
import { DHCP6_STATE_LABEL, DHCP6_TIMER_TAG, Dhcp6PdClient } from "./dhcp6";
import { DAD_TIMER_TAG, Ipv6Interface, NDP_TIMEOUT_TAG, RA_PERIODIC_TAG, ROUTER_EXPIRY_TAG, RS_TIMER_TAG } from "./ipv6";
import { DHCP_STATE_LABEL, DHCP_TIMER_TAG, DhcpClient, DhcpServer, type DhcpServerConfig } from "./dhcp";
import { DNS_TIMER_TAG, DNS_UPSTREAM_TIMER_TAG, DnsResolver, DnsServer, type DnsServerConfig } from "./dns";
import { DDNS_TIMER_TAG, DdnsClient, type DdnsConfig } from "./ddns";
import { MWAN_ICMP_ID, MWAN_TIMER_TAG, MultiWan, WAN_LABEL, type WanName } from "./mwan";
import { Adguard, PARENTAL_CATEGORIES, type AdguardConfig } from "./adguard";
import { APPS, Dpi, type DpiConfig } from "./dpi";
import { Firewall, type FirewallConfig } from "./firewall";
import { L2tpServer, type L2tpServerConfig } from "./l2tp";
import { PortPublish } from "./publish";
import { hashCode } from "./host";
import { NetInterface, type Emit } from "./iface";
import { NAT_ID_START, NAT_TYPE_LABEL, NatTable, type NatType, type PortForward } from "./nat";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";
import { guardLoop } from "./switch";
import { DEFAULT_WG, WG_PORT, WG_TIMER_TAG, WgInterface, prefixesLabel, shortKey, type WgPeerState, type WgPrefix } from "./wg";

export type { DhcpServerConfig } from "./dhcp";
export type { NatEntry, PortForward } from "./nat";

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
  /** DNS 포워더 (공유기 안의 dnsmasq): LAN 의 질의를 업스트림 DNS 로 대신 물어봄 */
  dns?: DnsServerConfig;
  firewall?: FirewallConfig;
  wifi?: { enabled: boolean; ssid: string };
  /** 포트 포워딩 규칙 (TCP): 공인 포트로 들어온 연결을 LAN 호스트로 */
  forwards?: PortForward[];
  /** IPv6 (없으면 꺼짐): WAN 은 ISP 의 RA·DHCPv6-PD 로, LAN 에는 위임받은 /64 를 RA 로 */
  ipv6?: RouterIpv6Config;
  /** VPN 서버 (ipTIME 식 L2TP/IPsec, 없으면 꺼짐) */
  vpnServer?: L2tpServerConfig;
  /** NAT 종류 (없으면 full cone) */
  natType?: NatType;
  /** 헤어핀 NAT (NAT 루프백): 안에서 내 공인 주소의 포워딩 포트로 접속하면 안쪽 서버로 되돌려 준다. 없으면 꺼짐 */
  hairpin?: boolean;
  /** WireGuard 서버 (GL.iNet 식, 없으면 꺼짐) */
  wgServer?: RouterWgServerConfig;
  /** WireGuard 클라이언트 (LAN 전체를 VPN 으로, 없으면 꺼짐) */
  wgClient?: RouterWgClientConfig;
  /** DDNS (없으면 꺼짐) */
  ddns?: DdnsConfig;
  /** 멀티 WAN (없으면 꺼짐): lan4 포트를 WAN2 로 */
  wan2?: Wan2Config;
  /** WAN2 인터페이스 MAC (없으면 WAN MAC 의 4번째 옥텟을 03 으로) */
  wan2Mac?: Mac;
  /** AdGuard Home·자녀 보호 (없으면 꺼짐) */
  adguard?: AdguardConfig;
  /** DPI (없으면 꺼짐) */
  dpi?: DpiConfig;
}

/** 멀티 WAN 페일오버: lan4 = WAN2 (예비 회선), 추적 주소 */
export interface Wan2Config extends WanConfig {
  enabled: boolean;
  /** 회선이 살았는지 ping 할 주소 (비우면 링크·주소만 본다) */
  track?: Ip;
}

/** 공유기 WireGuard 서버: 밖의 노트북·폰·다른 공유기가 공개 키로 붙는다 */
export interface RouterWgServerConfig {
  enabled: boolean;
  privateKey: string;
  /** 서버의 터널 주소 (예: 10.0.0.1/24) */
  address?: { ip: Ip; prefix: number };
  listenPort: number;
  /** 피어 = 등록한 클라이언트 (공개 키 + 그 클라이언트의 터널 주소) */
  peers: { name: string; publicKey: string; ip: Ip }[];
  /** 클라이언트가 집 LAN 에 접근해도 되는지 (GL.iNet "Remote Access LAN") */
  lanAccess: boolean;
  /** 난독화 (AmneziaWG 식 — 클라이언트도 켜야 한다) */
  obfuscate?: boolean;
}

/** 공유기 WireGuard 클라이언트: LAN 기기들의 트래픽을 VPN 서버로 */
export interface RouterWgClientConfig {
  enabled: boolean;
  privateKey: string;
  /** 서버가 정해 준 내 터널 주소 */
  address?: { ip: Ip; prefix: number };
  /** 서버 주소·포트 (엔드포인트) */
  server?: { ip: Ip; port: number };
  /** 서버를 이름으로 적었으면 그 이름 (DDNS — 연결할 때 풀고, 핸드셰이크가 실패하면 다시 푼다) */
  serverName?: { name: string; port: number };
  serverKey: string;
  /** 터널로 보낼 목적지 (0.0.0.0/0 = 전부) */
  allowedIps: WgPrefix[];
  /** VPN 이 알려 준 DNS: 연결되면 DNS 포워더가 이쪽으로 터널을 통해 묻는다 (DNS 유출 방지) */
  dns?: Ip;
  /** 킬 스위치: VPN 이 끊기면 WAN 으로 바로 내보내지 않는다 (GL.iNet "Block Non-VPN Traffic") */
  killSwitch: boolean;
  /** 난독화 (AmneziaWG 식 — 서버도 켜야 한다) */
  obfuscate?: boolean;
  /** VPN 정책: 모든 기기 / 목록의 기기만 빼고 / 목록의 기기만 */
  policy: { mode: "all" | "exclude" | "only"; devices: Ip[] };
}

export const WG_POLICY_LABEL: Record<RouterWgClientConfig["policy"]["mode"], string> = { all: "모든 기기", exclude: "목록의 기기는 VPN 을 쓰지 않음", only: "목록의 기기만 VPN" };

export interface RouterIpv6Config {
  enabled: boolean;
  /** IPv6 인바운드 기본 차단 (Stateful): 안에서 시작한 통신의 응답만 들어온다. NAT 가 없으니 이것이 IPv4 의 NAT 가 하던 보호를 대신한다 */
  inboundBlock: boolean;
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
  /** 멀티 WAN 을 켜면 lan4 가 WAN2 */
  static readonly WAN2_PORT = 4;
  static readonly LAN_PORTS = [1, 2, 3, 4];
  /** 무선 단말 슬롯 (공유기의 Wi-Fi). 브리지에서는 LAN 포트와 같게 다루되 전파 송출로 표시한다 */
  static readonly RADIO_PORTS = [5, 6, 7, 8, 9, 10, 11, 12];
  static readonly BRIDGE_PORTS = [...Router.LAN_PORTS, ...Router.RADIO_PORTS];
  static readonly NAT_ID_START = NAT_ID_START;

  readonly type = "router" as const;
  readonly portCount = 13;
  /** 무선 SSID (켜져 있을 때만 단말이 붙는다) */
  wifi: { enabled: boolean; ssid: string };
  readonly id: string;
  readonly lan: NetInterface;
  readonly wan: NetInterface;
  readonly dhcpServer: DhcpServer;
  readonly wanClient: DhcpClient;
  readonly dnsForwarder: DnsServer;
  readonly firewall: Firewall;
  wanMode: "dhcp" | "static";
  wanLinkUp = false;
  readonly macTable = new Map<Mac, MacEntry>();
  readonly nat = new NatTable();
  private readonly seen = new Map<number, number>();
  /** IPv6: LAN(라우터 — RA 로 위임받은 /64 를 알림)과 WAN(호스트처럼 ISP 의 RA 로 주소·기본 게이트웨이) */
  readonly lan6: Ipv6Interface;
  readonly wan6: Ipv6Interface;
  readonly pd: Dhcp6PdClient;
  ipv6Enabled = false;
  /** IPv6 인바운드 기본 차단 (나가는 것만 허용 + Stateful) */
  readonly inbound6: Firewall;
  /** LAN 쪽 IPv6 를 시작했는지 (LAN 은 내부 브리지라 첫 포트가 붙을 때 링크 로컬 DAD) */
  private lan6Started = false;
  /** VPN 서버 (L2TP/IPsec): 붙은 노트북에게 LAN 주소를 주고, 그 주소의 ARP 에 대신 답해(프록시 ARP) 터널로 넘긴다 */
  readonly vpnServer: L2tpServer;
  /** 헤어핀 NAT (켜져 있을 때만 쓴다) — 포트 포워딩 규칙을 안쪽 클라이언트에게도 적용 (FULLNAT) */
  hairpin = false;
  /** WireGuard 서버 (wg0) */
  readonly wgs: WgInterface;
  /** WireGuard 클라이언트 (wgc) */
  readonly wgc: WgInterface;
  wgServerCfg: RouterWgServerConfig | undefined;
  wgClientCfg: RouterWgClientConfig | undefined;
  /** DDNS 클라이언트 */
  readonly ddns: DdnsClient;
  /** 멀티 WAN: lan4 를 WAN2 로 쓰는지 */
  wan2On = false;
  readonly wan2: NetInterface;
  readonly wan2Client: DhcpClient;
  wan2Mode: "dhcp" | "static" = "dhcp";
  wan2LinkUp = false;
  /** WAN2 쪽 NAT (회선마다 공인 주소가 달라 매핑도 따로) */
  readonly nat2 = new NatTable();
  readonly mwan: MultiWan;
  /** LAN 에서 본 MAC → IPv4 (ARP·IPv4 프레임의 출발지 — 자녀 보호가 IPv6 로 묻는 기기를 IPv4 주소로 알아보게) */
  private readonly lanSeen = new Map<Mac, Ip>();
  /** AdGuard Home·자녀 보호: DNS 포워더 앞의 필터 */
  readonly adguard = new Adguard();
  /** DPI: 지나가는 흐름의 앱을 알아보고 세고 막는다 */
  readonly dpi = new Dpi();
  /** 공유기 자신의 이름 해석 (VPN 서버 이름 등) — WAN 으로 DNS 포워더의 업스트림에 직접 묻는다 */
  readonly resolver: DnsResolver;
  /** VPN 클라이언트 쪽 NAT: LAN 기기의 출발지를 내 터널 주소로 (서버는 이 주소 하나만 안다 — AllowedIPs) */
  readonly natVpn = new NatTable();
  private readonly hairpinNat = new PortPublish(
    {
      owns: (ip) => ip === this.wan.ip,
      sourceFor: () => this.lan.ip,
      send: (pkt, _inPort, _frameId, ctx) => this.lan.sendIp({ ...pkt, ttl: pkt.ttl - 1 }, ctx, this.emitLan(ctx)),
    },
    true,
  );

  constructor(cfg: RouterConfig) {
    this.id = cfg.id;
    this.lan = new NetInterface(cfg.mac, { ip: cfg.lanIp, prefix: cfg.lanPrefix ?? 24 });
    this.dhcpServer = new DhcpServer({ ...cfg.dhcp }, this.lan);
    const wan = cfg.wan ?? { mode: "dhcp" };
    this.wanMode = wan.mode;
    this.wan = new NetInterface(cfg.wanMac, wan.mode === "static" ? { ip: wan.ip, prefix: wan.prefix ?? 24, gateway: wan.gateway } : {});
    this.wanClient = new DhcpClient(this.wan, hashCode(cfg.id) + 7, "wan");
    this.wan2 = new NetInterface(cfg.wan2Mac ?? cfg.wanMac.replace(/^02:00:00:01/, "02:00:00:03"), {});
    this.wan2Client = new DhcpClient(this.wan2, hashCode(cfg.id) + 13, "wan2");
    this.mwan = new MultiWan({
      ready: (w) => (w === "wan" ? this.wanLinkUp && !!this.wan.ip : this.wan2On && this.wan2LinkUp && !!this.wan2.ip),
      waiting: (w) => {
        const [up, i, mode, client] = w === "wan" ? [this.wanLinkUp, this.wan, this.wanMode, this.wanClient] : [this.wan2LinkUp, this.wan2, this.wan2Mode, this.wan2Client];
        return up && !i.ip && mode === "dhcp" && client.state !== "failed" && client.state !== "idle";
      },
      probe: (w, track, seq, ctx) => {
        const i = w === "wan" ? this.wan : this.wan2;
        if (!i.ip) return;
        ctx.trace("mwan.check", "L3", `멀티 WAN: ${WAN_LABEL[w]} 로 추적 ping → ${track} (출발지 ${i.ip}, 이 회선으로만)`, { wan: w, seq });
        i.sendIp({ kind: "ipv4", src: i.ip, dst: track, ttl: 64, payload: { kind: "icmp", type: "echo-request", id: MWAN_ICMP_ID + (w === "wan" ? 0 : 1), seq } }, ctx, w === "wan" ? this.emitWan(ctx) : this.emitWan2(ctx));
      },
      onSwitch: (from, to, why, ctx) => {
        const ip = to === "wan" ? this.wan.ip : this.wan2.ip;
        ctx.trace("mwan.switch", "L3", `멀티 WAN: ${why} → ${WAN_LABEL[from]} 에서 ${WAN_LABEL[to]} 로 전환. 새 연결은 ${WAN_LABEL[to]} 의 주소 ${ip ?? "?"} 로 NAT 되어 나간다 — 진행 중이던 연결은 출발지 주소가 바뀌어 상대에게 다른 연결로 보여 끊긴다`, { from, to });
        this.ddns.onWanAddress(ctx); // DDNS 는 지금 쓰는 회선의 주소로
      },
    });
    this.firewall = new Firewall(cfg.firewall);
    this.wifi = cfg.wifi ?? { enabled: false, ssid: "home" };
    this.lan6 = new Ipv6Interface(cfg.mac, true, "lan");
    this.lan6.raOffReason = "ISP 에게 아직 프리픽스를 위임받지 못해(DHCPv6-PD) 알릴 프리픽스가 없음 → RA 안 함";
    this.wan6 = new Ipv6Interface(cfg.wanMac, false, "wan");
    this.pd = new Dhcp6PdClient(cfg.wanMac, this.wan6, hashCode(cfg.id) + 11, (d, ctx) => this.onDelegation(d, ctx));
    this.wan6.onLinkLocalReady = (ctx, emit) => {
      if (this.ipv6Enabled) this.pd.start(ctx, emit);
    };
    // 규칙 없이 기본 차단: 들어오는 것만 검사하고(check "in"), 나가는 것은 흐름만 기억한다(remember)
    this.inbound6 = new Firewall(
      { enabled: cfg.ipv6?.inboundBlock !== false, defaultPolicy: "deny", stateful: true, rules: [] },
      "IPv6 기본 방화벽",
      "바깥에서 먼저 시작한 IPv6 연결은 기본 차단 — 열려면 공유기 방화벽에 이 연결을 허용하는 인바운드 규칙(핀홀)을 넣거나 IPv6 인바운드 기본 차단을 끄세요",
    );
    if (cfg.ipv6?.enabled) {
      this.ipv6Enabled = true;
      this.lan6.init({ enabled: true, addrs: [] });
      this.wan6.init({ enabled: true, addrs: [], slaac: true });
    }
    this.dnsForwarder = new DnsServer(
      cfg.dns ?? { enabled: true, records: [], upstream: "8.8.8.8" },
      this.lan,
      "DNS 포워더",
      {
        // VPN 클라이언트가 켜져 있으면 터널로(출발지 = 내 터널 주소), 업스트림 DNS 가 LAN 안에 있으면 LAN 으로, 아니면 WAN 으로
        srcIp: (client) => (this.dnsViaVpn(client) ? this.wgClientCfg!.address!.ip : this.upstreamInLan() ? this.lan.ip : this.wan2On && this.mwan.active === "wan2" ? this.wan2.ip : this.wan.ip),
        send: (pkt, ctx, client) => {
          if (this.dnsViaVpn(client)) this.dnsToVpn(pkt, ctx);
          else if (this.upstreamInLan()) this.lan.sendIp(pkt, ctx, this.emitLan(ctx));
          else {
            const o = this.out(ctx);
            o.iface.sendIp(pkt, ctx, o.emit);
          }
        },
      },
      this.lan6, // LAN 호스트가 IPv6(RA 의 RDNSS = 공유기 LAN 주소)로 물어도 답한다
    );
    if (cfg.forwards) {
      this.nat.setForwards(cfg.forwards);
      this.nat2.setForwards(cfg.forwards);
    }
    if (cfg.natType) this.nat.type = this.nat2.type = cfg.natType;
    // 헤어핀 NAT 가 쓰는 프록시 포트는 NAT 공인 포트로 고르지 않는다
    this.nat.reserved = (port) => this.hairpinNat.usesProxyPort(port);
    this.nat2.reserved = (port) => this.hairpinNat.usesProxyPort(port);
    this.hairpin = cfg.hairpin === true;
    this.vpnServer = new L2tpServer({
      // 공유기 자신이 만든 바깥 패킷이라 NAT·방화벽을 거치지 않는다
      send: (outer, ctx) => this.wan.sendIp(outer, ctx, this.emitWan(ctx)),
      dns: () => (this.dnsForwarder.config.enabled ? this.lan.ip : undefined),
      lan: () => (this.lan.ip ? { ip: this.lan.ip, prefix: this.lan.prefix } : undefined),
      wanIp: () => this.wan.ip,
    });
    if (cfg.vpnServer) this.vpnServer.config = { ...cfg.vpnServer, users: cfg.vpnServer.users.map((u) => ({ ...u })) };
    this.lan.proxyArp = (ip) => this.vpnServer.owns(ip);
    // LAN 으로 내보내려는 패킷의 목적지가 VPN 클라이언트면 LAN 대신 터널로 (DNS 포워더·ping 응답·NAT 역변환한 인터넷 응답)
    this.lan.outbound = (pkt, ctx) => (!!this.wan.ip && this.vpnServer.owns(pkt.dst) && this.vpnServer.sendTo(pkt, this.wan.ip, ctx)) || this.toWgPeer(pkt, ctx);
    // WireGuard: 공유기 자신이 만든 바깥 UDP 라 NAT·방화벽을 거치지 않고 WAN 으로
    // 바깥 주소는 WAN 링크가 살아 있을 때만 (수동 WAN 은 케이블 없이도 주소가 있다). 상대가 LAN 쪽이면(공유기 뒤 클라이언트가 내 공인 주소로 접속) LAN 으로
    // 멀티 WAN 이면 지금 쓰는 회선으로 (WireGuard 는 출발지가 바뀌어도 상대가 로밍으로 따라온다)
    const wgIo = {
      source: () => (this.wan2On && this.mwan.active === "wan2" ? (this.wan2LinkUp ? this.wan2.ip : undefined) : this.wanLinkUp ? this.wan.ip : undefined),
      send: (outer: Ipv4Packet, ctx: NodeContext) => {
        if (this.lan.ip && sameSubnet(outer.dst, this.lan.ip, this.lan.prefix)) this.lan.sendIp(outer, ctx, this.emitLan(ctx));
        else {
          const o = this.out(ctx);
          o.iface.sendIp(outer, ctx, o.emit);
        }
      },
    };
    this.wgs = new WgInterface(wgIo, "WireGuard 서버", `${cfg.id}:server`);
    this.wgc = new WgInterface(wgIo, "WireGuard 클라이언트", `${cfg.id}:client`);
    this.wgcPort = 49152 + (Math.abs(hashCode(`${cfg.id}:wgc`)) % 16000);
    this.natVpn.why = "VPN 서버는 이 공유기를 터널 주소 하나로만 안다(AllowedIPs) — LAN 기기 주소를 터널 주소로 바꾸고 테이블에 기록";
    // VPN 클라이언트가 켜져 있으면 DNS 포워더는 VPN 이 알려 준 DNS 에 터널로 묻는다 (DNS 유출 방지)
    this.dnsForwarder.upstreamFor = (client) => (this.dnsViaVpn(client) ? (this.wgClientCfg?.dns ?? undefined) : undefined);
    // 서버의 터널 주소(10.0.0.1)로 온 질의에는 그 주소로 답한다. DNS 가로채기로 받은 질의는 원래 물으려던 서버 주소로 (기기는 그 서버가 답한 줄 안다)
    this.dnsForwarder.answersAt = (dst) => (!!this.wgServerCfg?.enabled && dst === this.wgServerCfg.address?.ip) || this.hijacks(dst);
    // AdGuard Home·자녀 보호: 이름을 업스트림에 묻기 전에 거른다
    this.dnsForwarder.filter = (name, qtype, client, ctx) => {
      if (!this.adguard.config.enabled) return undefined;
      const v = this.adguard.check(name, this.clientV4(client));
      this.adguard.record(ctx.now, client, name, qtype, v ? `차단 · ${v.list} ${v.rule}` : "허용", !!v);
      if (!v) return undefined;
      const zero = this.adguard.config.mode === "zero";
      return { ...(zero ? { answer: qtype === "AAAA" ? "::" : "0.0.0.0" } : { rcode: "NXDOMAIN" as const }), why: `${v.list} 규칙 ${v.rule} 에 걸림 (AdGuard Home)` };
    };
    this.dnsForwarder.onAnswer = (name, ip) => this.dpi.learnDns(name, ip);
    if (cfg.dpi) this.dpi.config = { ...cfg.dpi, blockApps: [...cfg.dpi.blockApps], blockCategories: [...cfg.dpi.blockCategories] };
    if (cfg.adguard) this.adguard.config = { ...cfg.adguard, custom: [...cfg.adguard.custom], allow: [...cfg.adguard.allow], parental: cfg.adguard.parental.map((p) => ({ ...p, categories: [...p.categories] })) };
    if (cfg.wgServer) this.wgServerCfg = cfg.wgServer;
    if (cfg.wgClient) this.wgClientCfg = cfg.wgClient;
    // DDNS 는 지금 인터넷으로 내보내는 회선의 주소로 (멀티 WAN 이 넘어가면 따라간다)
    this.ddns = new DdnsClient(
      {
        wanIp: () => (this.wan2On && this.mwan.active === "wan2" ? this.wan2.ip : this.wan.ip),
        device: cfg.wanMac,
        send: (pkt, ctx) => {
          const o = this.out(ctx);
          o.iface.sendIp(pkt, ctx, o.emit);
        },
      },
      hashCode(`${cfg.id}:ddns`),
    );
    this.resolver = new DnsResolver(this.wan, hashCode(`${cfg.id}:resolver`));
    // 업스트림이 LAN 안이면 그 길은 LAN 이라 WAN 으로는 ISP 가 알려 준 DNS 에 묻는다
    this.resolver.vpnDns = () => (this.upstreamInLan() ? undefined : this.dnsForwarder.config.upstream);
    // 핸드셰이크가 끝내 실패하면 서버 이름을 다시 풀어 본다 (집 공인 주소가 바뀌었을 수 있다 — GL.iNet 의 reresolve)
    this.wgc.onFail = (_p, ctx) => {
      if (this.wgClientCfg?.enabled && this.wgClientCfg.serverName) this.resolveWgServer(ctx, "핸드셰이크 실패 — 서버 주소가 바뀌었을 수 있어 이름을 다시 풂", true);
    };
    this.wgc.needEndpoint = (_p, ctx) => {
      if (this.wgClientCfg?.enabled && this.wgClientCfg.serverName) this.resolveWgServer(ctx, "보낼 패킷이 생겼는데 서버 주소를 모름 — 이름을 다시 풂");
    };
  }

  /** VPN 서버 이름을 풀어 엔드포인트로 (캐시는 지우고 — 바뀐 주소를 받으려고) */
  private resolveWgServer(ctx: NodeContext, why: string, reresolve = false): void {
    const n = this.wgClientCfg?.serverName;
    const peer = this.wgcPeer;
    if (!n || !peer || !this.wan.ip) return;
    this.resolver.forget(n.name);
    this.wgc.markResolving(peer);
    ctx.trace("vpn.config", "sys", `WireGuard 클라이언트: ${why} → ${n.name} 을(를) WAN 으로 직접 물음 (터널 밖)`, { wg: true, name: n.name });
    this.resolver.resolve(n.name, ctx, this.emitWan(ctx), (ip, reason) => {
      if (!this.wgClientCfg?.enabled || this.wgClientCfg.serverName?.name !== n.name) return;
      if (!ip) {
        peer.resolving = false;
        peer.failed = `서버 이름 ${n.name} 을(를) 풀지 못함 (${reason ?? "?"})`;
        const q = peer.queue.length;
        peer.queue = [];
        if (peer.prevEndpoint) {
          peer.endpoint = peer.prevEndpoint;
          peer.prevEndpoint = undefined;
        }
        ctx.trace("vpn.drop", "L4", `WireGuard 클라이언트: ${peer.failed}${q ? ` → 기다리던 패킷 ${q}개 드롭` : ""}${peer.endpoint ? ` — 전에 쓰던 ${peer.endpoint.ip} 로 계속 시도` : " — 보낼 패킷이 또 생기면 다시 풂"}. DDNS 이름과 공유기 DNS 를 확인`, { wg: true, failed: true });
        return;
      }
      ctx.trace("vpn.config", "sys", `WireGuard 클라이언트: ${n.name} = ${ip} → 엔드포인트 ${ip}:${n.port}`, { wg: true, name: n.name, ip });
      this.wgc.setEndpoint(peer, { ip, port: n.port }, ctx, reresolve ? "if-changed" : "always");
    });
  }

  /** WAN 이 주소를 받거나 바뀜: DDNS 갱신, VPN 클라이언트 연결 */
  private onWanAddress(ctx: NodeContext): void {
    this.mwan.onLine("wan", ctx);
    if (!this.wan.ip) return;
    this.ddns.onWanAddress(ctx);
    if (!this.wgClientCfg?.enabled) return;
    if (this.wgClientCfg.serverName && !this.wgcPeer?.endpoint && !this.wgcPeer?.resolving) this.resolveWgServer(ctx, "WAN 연결됨");
    else this.wgc.connect(ctx);
  }

  /** WireGuard 클라이언트의 바깥 UDP 포트 (설정에 ListenPort 가 없으면 임의 포트 — 여기서는 장치마다 고정) */
  readonly wgcPort: number;

  /** DNS 가로채기 대상인지: AdGuard 의 "모든 기기의 DNS 를 공유기로" 가 켜져 있고 LAN 밖의 DNS 서버 */
  private hijacks(dst: Ip): boolean {
    const c = this.adguard.config;
    if (!c.enabled || !c.forceDns || !this.dnsForwarder.config.enabled) return false;
    if (isIpv6(dst)) return !this.lan6.owns(dst) && !this.lan6.onLink(dst) && !isLinkLocal6(dst);
    return !!this.lan.ip && !sameSubnet(dst, this.lan.ip, this.lan.prefix);
  }

  /** 자녀 보호용 기기 식별: IPv6 로 물었으면 그 기기의 IPv4 주소 (이웃 캐시 → MAC → ARP 캐시) */
  private clientV4(client: Ip): Ip {
    if (!isIpv6(client)) return client;
    const mac = this.lan6.neighbors.get(client)?.mac;
    if (!mac) return client;
    for (const [ip, e] of this.lan.arpCache) if (e.mac === mac) return ip;
    return this.lanSeen.get(mac) ?? client;
  }

  /** DPI 설정 */
  setDpi(cfg: DpiConfig, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.dpi.config)) return;
    const was = this.dpi.config.enabled;
    this.dpi.config = { ...cfg, blockApps: [...cfg.blockApps], blockCategories: [...cfg.blockCategories] };
    this.dpi.resetFlows();
    if (!cfg.enabled) {
      if (was) ctx.trace("ip.config", "sys", `DPI 꺼짐`, { dpi: false });
      return;
    }
    const blocked = [...cfg.blockCategories.map((c) => `${c} 전체`), ...cfg.blockApps.map((a) => APPS[a].label)];
    ctx.trace("ip.config", "sys", `DPI 켜짐: 지나가는 흐름마다 앱을 알아본다 (TLS SNI·DNS 로 배운 주소·프로토콜 모양·포트)${blocked.length ? ` — 막을 것: ${blocked.join(", ")} (TCP 는 RST 를 넣어 끊고 UDP 는 드롭)` : " — 막는 것 없이 세기만"}`, { dpi: true });
  }

  /**
   * DPI 검사: 지나가는 패킷의 앱을 알아보고(처음·근거가 바뀔 때 기록) 막을 앱이면 끊는다. 통과면 true.
   * dir out = LAN → 밖 (client = 출발지), in = 밖 → LAN (client = 목적지)
   */
  private dpiCheck(pkt: Ipv4Packet, dir: "out" | "in", frameId: number, ctx: NodeContext): boolean {
    const client = dir === "out" ? pkt.src : pkt.dst;
    const v = this.dpi.inspect(pkt, dir, client);
    if (!v) return true;
    const remote = dir === "out" ? pkt.dst : pkt.src;
    if (v.fresh && !v.block) ctx.trace("dpi.app", "app", `DPI: ${client} ↔ ${remote} 흐름은 ${APPS[v.app].label} (${APPS[v.app].category}) — 근거: ${v.why}`, { app: v.app, client }, frameId);
    if (!v.block) return true;
    const p = pkt.payload;
    if (p.kind === "tcp" && !p.rst) {
      // 양쪽에 RST 를 넣어 끊는다 (기기 쪽만 그려도 기기는 연결이 끊긴 것을 안다)
      ctx.trace("dpi.block", "app", `DPI 차단: ${client} ↔ ${remote} 는 ${APPS[v.app].label} (${APPS[v.app].category}, ${v.why}) → 드롭하고 기기에 RST 를 넣어 연결을 끊음`, { app: v.app, client, rst: true }, frameId);
      const toClient: Ipv4Packet =
        dir === "out"
          ? { kind: "ipv4", src: pkt.dst, dst: pkt.src, ttl: 64, payload: { kind: "tcp", srcPort: p.dstPort, dstPort: p.srcPort, seq: p.ack, ack: p.seq + p.len + (p.syn ? 1 : 0) + (p.fin ? 1 : 0), rst: true, ackFlag: true, len: 0 } }
          : { kind: "ipv4", src: pkt.src, dst: pkt.dst, ttl: 64, payload: { kind: "tcp", srcPort: p.srcPort, dstPort: p.dstPort, seq: p.seq + p.len, ack: p.ack, rst: true, ackFlag: true, len: 0 } };
      this.lan.sendIp(toClient, ctx, this.emitLan(ctx));
    } else if (v.fresh) ctx.trace("dpi.block", "app", `DPI 차단: ${client} ↔ ${remote} 는 ${APPS[v.app].label} (${APPS[v.app].category}, ${v.why}) → 드롭`, { app: v.app, client }, frameId);
    return false;
  }

  /** AdGuard Home·자녀 보호 설정 */
  setAdguard(cfg: AdguardConfig, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.adguard.config)) return;
    const was = this.adguard.config.enabled;
    this.adguard.config = { ...cfg, custom: [...cfg.custom], allow: [...cfg.allow], parental: cfg.parental.map((p) => ({ ...p, categories: [...p.categories] })) };
    if (!cfg.enabled) {
      if (was) ctx.trace("ip.config", "sys", `AdGuard Home 꺼짐 — 이름을 거르지 않음`, { adguard: false });
      return;
    }
    const kids = cfg.parental.filter((p) => p.categories.length);
    ctx.trace(
      "ip.config",
      "sys",
      `AdGuard Home: DNS 포워더 앞에서 이름을 거른다 — ${[cfg.ads ? "광고·추적 목록" : "", cfg.custom.length ? `사용자 규칙 ${cfg.custom.length}개` : "", kids.length ? `자녀 보호 ${kids.map((k) => `${k.ip}(${k.categories.map((c) => PARENTAL_CATEGORIES[c].label).join("·")})`).join(", ")}` : ""].filter(Boolean).join(", ") || "규칙 없음"}${cfg.allow.length ? `, 예외 ${cfg.allow.length}개` : ""}. 막으면 ${cfg.mode === "zero" ? "0.0.0.0" : "NXDOMAIN"} 으로 답함${cfg.forceDns ? ". DNS 가로채기 켜짐: 다른 DNS 로 가는 질의도 공유기가 받는다" : ""}${this.dnsForwarder.config.enabled ? "" : " — 그런데 DNS 포워더가 꺼져 있어 거를 질의가 오지 않음"}`,
      { adguard: true },
    );
  }

  /** WireGuard 서버·클라이언트 설정 (만든 직후·설정 변경) */
  setWg(server: RouterWgServerConfig | undefined, client: RouterWgClientConfig | undefined, ctx: NodeContext): void {
    const prev = this.wgClientCfg;
    this.wgServerCfg = server;
    this.wgClientCfg = client;
    this.applyWg(ctx, prev);
  }

  private applyWg(ctx: NodeContext, prev?: RouterWgClientConfig): void {
    const s = this.wgServerCfg;
    this.wgs.setConfig(
      s
        ? {
            enabled: s.enabled,
            privateKey: s.privateKey,
            ...(s.address ? { address: s.address } : {}),
            listenPort: s.listenPort,
            peers: s.peers.map((p) => ({ name: p.name, publicKey: p.publicKey, allowedIps: [{ dest: p.ip, prefix: 32 }] })),
            ...(s.obfuscate ? { obfuscate: true } : {}),
          }
        : { ...DEFAULT_WG, peers: [] },
      ctx,
    );
    const c = this.wgClientCfg;
    const changed = this.wgc.setConfig(
      c
        ? {
            enabled: c.enabled,
            privateKey: c.privateKey,
            ...(c.address ? { address: c.address } : {}),
            listenPort: this.wgcPort,
            peers: [{ name: "VPN 서버", publicKey: c.serverKey, ...(c.server ? { endpoint: c.server } : {}), allowedIps: c.allowedIps }],
            ...(c.obfuscate ? { obfuscate: true } : {}),
          }
        : { ...DEFAULT_WG, peers: [] },
      ctx,
    );
    if (changed && c?.enabled && c.serverName && this.wan.ip && this.wanLinkUp) this.resolveWgServer(ctx, "설정");
    // 킬 스위치·VPN 정책·DNS 는 터널 설정이 아니라 공유기의 길 고르기라 wgc 는 그대로 — 그래도 바뀐 것은 남긴다
    const routing = (x?: RouterWgClientConfig) => JSON.stringify(x ? { k: x.killSwitch, p: x.policy, d: x.dns } : null);
    if ((changed || (prev?.enabled && routing(prev) !== routing(c))) && c?.enabled) {
      ctx.trace("vpn.config", "sys", `WireGuard 클라이언트: ${WG_POLICY_LABEL[c.policy.mode]}${c.policy.mode !== "all" ? ` (${c.policy.devices.join(", ") || "목록 비어 있음"})` : ""} → ${prefixesLabel(c.allowedIps)} 로 가는 LAN 트래픽을 터널로. 킬 스위치 ${c.killSwitch ? "켜짐 (VPN 이 끊기면 인터넷 차단)" : "꺼짐 (VPN 이 끊기면 WAN 으로 바로 — 실제 주소가 드러남)"}${c.dns ? `, DNS 는 ${c.dns} 에 터널로` : ""}`, { wg: true, killSwitch: c.killSwitch, policy: c.policy.mode });
      if (changed && this.wan.ip && this.wanLinkUp && !c.serverName) this.wgc.connect(ctx);
    }
  }

  /** 클라이언트 쪽 피어 (서버 하나) */
  private get wgcPeer(): WgPeerState | undefined {
    return this.wgc.peers.values().next().value;
  }

  /** VPN 클라이언트가 끊겨(핸드셰이크 실패) 쉬는 중인지 — 킬 스위치가 꺼져 있으면 이때 WAN 으로 바로 나간다 */
  private wgcDown(): boolean {
    const p = this.wgcPeer;
    return !p || (!!p.failed && !p.pending && !p.session);
  }

  /** 이 LAN 기기의 트래픽을 VPN 클라이언트로 보내는지 (VPN 정책) */
  private policyApplies(src: Ip): boolean {
    const c = this.wgClientCfg;
    if (!c?.enabled || !this.wgc.enabled) return false;
    if (!this.lan.ip || !sameSubnet(src, this.lan.ip, this.lan.prefix)) return false;
    if (c.policy.mode === "exclude") return !c.policy.devices.includes(src);
    if (c.policy.mode === "only") return c.policy.devices.includes(src);
    return true;
  }

  /**
   * DNS 포워더의 업스트림 질의를 VPN 터널로 보내는지. client = 질의한 기기: VPN 정책에서 빠진 기기(목록 제외·목록에 없음)의 질의는
   * 그 기기의 다른 트래픽처럼 WAN 으로 (킬 스위치에 막히지 않게). LAN 밖(공유기 자신·VPN 서버의 피어)은 정책을 보지 않는다
   */
  private dnsViaVpn(client?: Ip): boolean {
    const c = this.wgClientCfg;
    if (!c?.enabled || !this.wgc.enabled || !c.address) return false;
    if (client && this.lan.ip && sameSubnet(client, this.lan.ip, this.lan.prefix) && !this.policyApplies(client)) return false;
    const up = c.dns ?? this.dnsForwarder.config.upstream;
    if (!up || !this.wgc.route(up)) return false;
    return !(this.wgcDown() && !c.killSwitch);
  }

  /** DNS 포워더의 업스트림 질의를 VPN 클라이언트 터널로 (끊겨 있으면 킬 스위치가 붙잡는다 — DNS 유출 방지) */
  private dnsToVpn(pkt: Ipv4Packet, ctx: NodeContext): void {
    const peer = this.wgc.route(pkt.dst);
    if (!peer) return;
    if (this.wgcDown()) ctx.trace("vpn.killswitch", "L3", `킬 스위치: VPN 이 끊겨 있어 DNS 질의(${pkt.dst})를 WAN 으로 내보내지 않음 → 터널이 다시 맺어지기를 기다림 (DNS 유출 방지)`, { dst: pkt.dst, killSwitch: true });
    ctx.trace("ip.forward", "L3", `DNS 포워더: 업스트림 ${pkt.dst} 질의를 VPN 터널로 (출발지 = 내 터널 주소 ${pkt.src}) — 호텔·통신사 DNS 가 내 질의를 보지 못한다`, { dst: pkt.dst, wg: true });
    this.wgc.send(peer, pkt, ctx);
  }

  /** 목적지가 WireGuard 서버의 피어(붙은 노트북 등)면 그 터널로. 보냈으면 true */
  private toWgPeer(pkt: Ipv4Packet, ctx: NodeContext, frameId?: number): boolean {
    if (!this.wgServerCfg?.enabled) return false;
    const peer = this.wgs.route(pkt.dst);
    if (!peer) return false;
    this.wgs.send(peer, pkt, ctx, frameId);
    return true;
  }

  /** 위임받은 프리픽스가 생기거나 사라짐: LAN 에 그 첫 /64 를 주소로 두고 RA 로 알린다 (사라지면 거둠 RA) */
  private onDelegation(d: { prefix: Ip; length: number } | undefined, ctx: NodeContext): void {
    if (!this.ipv6Enabled) return;
    if (!d) {
      this.lan6.configure({ enabled: true, addrs: [], ra: false }, true, ctx, this.emitLan(ctx));
      return;
    }
    const lanIp = formatIp6(parseIp6(d.prefix)! | 1n);
    ctx.trace("ip.config", "sys", `[lan] 위임받은 ${d.prefix}/${d.length} 의 첫 /64 를 LAN 에: 공유기 LAN 주소 ${lanIp}/64 → RA 로 알려 집 안 장치가 SLAAC 로 공인 IPv6 주소를 만든다`, { prefix: d.prefix, lan: lanIp });
    this.lan6.configure({ enabled: true, addrs: [{ ip: lanIp, prefix: 64 }], ra: true, raDns: lanIp }, true, ctx, this.emitLan(ctx));
  }

  /** LAN 은 내부 브리지라 따로 링크가 없다: 첫 포트가 붙을 때 LAN IPv6 를 시작 (링크 로컬 DAD) */
  private startLan6(ctx: NodeContext): void {
    if (!this.ipv6Enabled || this.lan6Started) return;
    this.lan6Started = true;
    this.lan6.linkUp(ctx, this.emitLan(ctx));
  }

  /** IPv6 켜기·끄기, 인바운드 기본 차단 */
  private setIpv6(cfg: RouterIpv6Config, ctx: NodeContext): void {
    if (cfg.inboundBlock !== this.inbound6.config.enabled) {
      this.inbound6.config = { ...this.inbound6.config, enabled: cfg.inboundBlock };
      ctx.trace("ip.config", "sys", cfg.inboundBlock ? `IPv6 인바운드 기본 차단 켜짐: 바깥에서 먼저 시작한 IPv6 연결은 막고, 안에서 시작한 통신의 응답만 들인다 (Stateful)` : `IPv6 인바운드 기본 차단 꺼짐: NAT 가 없으니 바깥에서 집 안 장치의 IPv6 주소로 바로 들어온다 (방화벽 규칙이 없다면)`, { inboundBlock: cfg.inboundBlock });
    }
    if (cfg.enabled === this.ipv6Enabled) return;
    if (!cfg.enabled) {
      this.pd.release(ctx, this.emitWan(ctx));
      this.lan6.configure({ enabled: false, addrs: [] }, true, ctx, this.emitLan(ctx));
      this.wan6.configure({ enabled: false, addrs: [] }, this.wanLinkUp, ctx, this.emitWan(ctx));
      this.ipv6Enabled = false;
      this.lan6Started = false;
      return;
    }
    this.ipv6Enabled = true;
    ctx.trace("ip.config", "sys", `IPv6 켜짐: WAN 은 ISP 의 RA 로 주소·기본 게이트웨이를, DHCPv6-PD 로 LAN 에 나눠 줄 프리픽스를 받는다`, {});
    this.lan6.configure({ enabled: true, addrs: [] }, true, ctx, this.emitLan(ctx));
    this.lan6Started = true;
    this.wan6.configure({ enabled: true, addrs: [], slaac: true }, this.wanLinkUp, ctx, this.emitWan(ctx));
  }

  private upstreamInLan(): boolean {
    const up = this.dnsForwarder.config.upstream;
    try {
      return !!up && !!this.lan.ip && sameSubnet(up, this.lan.ip, this.lan.prefix);
    } catch {
      return false;
    }
  }

  get dhcp(): DhcpServerConfig {
    return this.dhcpServer.config;
  }
  get leases() {
    return this.dhcpServer.leases;
  }

  static portName(port: number): string {
    if (port === Router.WAN_PORT) return "wan";
    if (Router.RADIO_PORTS.includes(port)) return `무선 슬롯 ${port - Router.RADIO_PORTS[0]! + 1}`;
    return `lan${port}`;
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
      for (const p of this.bridgePorts()) if (ctx.isPortConnected(p)) ctx.send(p, frame);
    };
  }

  private emitWan(ctx: NodeContext): Emit {
    return (frame) => ctx.send(Router.WAN_PORT, frame);
  }

  private emitWan2(ctx: NodeContext): Emit {
    return (frame) => ctx.send(Router.WAN2_PORT, frame);
  }

  /** LAN 브리지 포트 (멀티 WAN 이면 lan4 는 WAN2 라 빠진다) */
  private bridgePorts(): number[] {
    return this.wan2On ? Router.BRIDGE_PORTS.filter((p) => p !== Router.WAN2_PORT) : Router.BRIDGE_PORTS;
  }

  /** 지금 인터넷으로 내보내는 회선: 인터페이스·NAT·송신 */
  private out(ctx: NodeContext): { name: WanName; iface: NetInterface; nat: NatTable; emit: Emit } {
    return this.line(this.wan2On && this.mwan.active === "wan2" ? "wan2" : "wan", ctx);
  }

  private line(w: WanName, ctx: NodeContext): { name: WanName; iface: NetInterface; nat: NatTable; emit: Emit } {
    return w === "wan2" ? { name: "wan2", iface: this.wan2, nat: this.nat2, emit: this.emitWan2(ctx) } : { name: "wan", iface: this.wan, nat: this.nat, emit: this.emitWan(ctx) };
  }

  /**
   * LAN 에서 나가는 이 패킷의 회선: 이미 다른 회선의 흐름(그 회선으로 들어온 포트 포워딩의 응답, 그 회선으로 시작한 연결)이고
   * 그 회선이 살아 있으면 그쪽으로 (mwan3 의 conntrack mark — 되돌아갈 때 쓰던 연결이 끊기지 않게), 아니면 지금 회선
   */
  private outFor(pkt: Ipv4Packet, ctx: NodeContext): { name: WanName; iface: NetInterface; nat: NatTable; emit: Emit } {
    const o = this.out(ctx);
    if (!this.wan2On || o.nat.carries(pkt)) return o;
    const other: WanName = o.name === "wan" ? "wan2" : "wan";
    return this.mwan.lines[other].online && this.line(other, ctx).nat.carries(pkt) ? this.line(other, ctx) : o;
  }

  // ---------- 설정 변경 ----------

  configure(
    cfg: {
      lanIp: Ip;
      lanPrefix: number;
      dhcp: DhcpServerConfig;
      wan: WanConfig;
      dns?: DnsServerConfig;
      forwards?: PortForward[];
      firewall?: FirewallConfig;
      wifi?: { enabled: boolean; ssid: string };
      ipv6?: RouterIpv6Config;
      vpnServer?: L2tpServerConfig;
      natType?: NatType;
      hairpin?: boolean;
      wgServer?: RouterWgServerConfig;
      wgClient?: RouterWgClientConfig;
      ddns?: DdnsConfig;
      wan2?: Wan2Config;
      adguard?: AdguardConfig;
      dpi?: DpiConfig;
    },
    ctx: NodeContext,
  ): void {
    if (cfg.dpi) this.setDpi(cfg.dpi, ctx);
    if (cfg.adguard) this.setAdguard(cfg.adguard, ctx);
    if (cfg.ddns) this.ddns.setConfig(cfg.ddns, ctx);
    if (cfg.wan2) this.setWan2(cfg.wan2, ctx);
    if (cfg.wgServer || cfg.wgClient) this.setWg(cfg.wgServer, cfg.wgClient, ctx);
    if (cfg.hairpin !== undefined && cfg.hairpin !== this.hairpin) {
      this.hairpin = cfg.hairpin;
      ctx.trace("ip.config", "sys", cfg.hairpin ? `헤어핀 NAT 켜짐: 안에서 내 공인 주소의 포워딩 포트로 접속하면 안쪽 서버로 되돌려 준다 (도메인으로 집 서버에 접속하기)` : `헤어핀 NAT 꺼짐`, { hairpin: cfg.hairpin });
    }
    if (cfg.natType && cfg.natType !== this.nat.type) {
      const from = this.nat.type;
      const n = this.nat.setType(cfg.natType);
      this.nat2.setType(cfg.natType);
      ctx.trace("ip.config", "sys", `NAT 종류 변경: ${NAT_TYPE_LABEL[from]} → ${NAT_TYPE_LABEL[cfg.natType]} (지금 매핑 ${n}개는 그대로 두고 새 매핑부터 새 방식, 남은 매핑의 필터링도 새 방식)`, { natType: cfg.natType });
    }
    if (cfg.firewall) this.firewall.setConfig(cfg.firewall, ctx, "");
    if (cfg.vpnServer) this.vpnServer.setConfig(cfg.vpnServer, ctx);
    if (cfg.ipv6) this.setIpv6(cfg.ipv6, ctx);
    if (cfg.wifi && (cfg.wifi.enabled !== this.wifi.enabled || cfg.wifi.ssid !== this.wifi.ssid)) {
      this.wifi = { ...cfg.wifi };
      ctx.trace("ip.config", "sys", cfg.wifi.enabled ? `무선 켜짐: SSID "${cfg.wifi.ssid}" 송출` : `무선 꺼짐`, { ...cfg.wifi });
    }
    if (cfg.lanIp !== this.lan.ip || cfg.lanPrefix !== this.lan.prefix) {
      this.lan.configure(cfg.lanIp, cfg.lanPrefix, undefined);
      this.lan.arpCache.clear();
      this.lan.clearPending();
      ctx.trace("ip.config", "sys", `LAN 인터페이스 주소 변경: ${cfg.lanIp}/${cfg.lanPrefix} (ARP 캐시 비움)`, { ...cfg });
      this.dhcpServer.onInterfaceChanged(ctx);
      // 호스트·게이트웨이와 같이 새 주소를 Gratuitous ARP 로 알린다
      this.lan.claim(ctx, this.emitLan(ctx));
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
    if ((cfg.dhcp.dns || undefined) !== (d.dns || undefined)) {
      ctx.trace("ip.config", "sys", cfg.dhcp.dns ? `DHCP 가 안내할 DNS 서버(옵션 6): ${cfg.dhcp.dns} — 이미 주소를 받은 호스트는 DHCP 임대 갱신 뒤 반영` : `DHCP 가 안내할 DNS 서버: 공유기 자신(DNS 포워더)`, { dns: cfg.dhcp.dns });
    }
    if (cfg.dhcp.start !== d.start || cfg.dhcp.end !== d.end || cfg.dhcp.enabled !== d.enabled || (cfg.dhcp.dns || undefined) !== (d.dns || undefined)) this.dhcpServer.setConfig(cfg.dhcp, ctx);

    const w = cfg.wan;
    const wanChanged =
      w.mode !== this.wanMode || (w.mode === "static" && (w.ip !== this.wan.ip || (w.prefix ?? 24) !== this.wan.prefix || w.gateway !== this.wan.gateway));
    if (wanChanged) {
      this.wanMode = w.mode;
      if (w.mode === "static") {
        this.wanClient.stop();
        this.wan.configure(w.ip || undefined, w.prefix ?? 24, w.gateway || undefined);
        this.wan.arpCache.clear();
        this.wan.clearPending();
        ctx.trace("ip.config", "sys", w.ip ? `[wan] 수동 설정 적용: ${w.ip}/${w.prefix ?? 24}, 게이트웨이 ${w.gateway ?? "없음"}` : `[wan] 수동 설정으로 전환 (주소 미입력)`, { ...w });
        if (w.ip && this.wanLinkUp) this.wan.claim(ctx, this.emitWan(ctx));
      } else {
        this.wan.clearAddress();
        ctx.trace("ip.config", "sys", `[wan] 자동(DHCP) 로 전환 → ISP 에서 공인 주소를 받는다`, { ...w });
        if (this.wanLinkUp) this.wanClient.start(ctx, this.emitWan(ctx));
        else this.wanClient.stop();
      }
    }

    if (cfg.forwards && forwardsKey(cfg.forwards) !== forwardsKey(this.nat.forwards)) {
      this.nat.setForwards(cfg.forwards);
      this.nat2.setForwards(cfg.forwards);
      ctx.trace("ip.config", "sys", `포트 포워딩 규칙 변경: ${cfg.forwards.length}개`, { forwards: cfg.forwards.map((f) => ({ ...f })) });
    }

    if (cfg.dns) {
      const cur = this.dnsForwarder.config;
      if (cfg.dns.enabled !== cur.enabled || cfg.dns.upstream !== cur.upstream) {
        ctx.trace("ip.config", "sys", cfg.dns.enabled ? `DNS 포워더 켜짐 (업스트림 DNS ${cfg.dns.upstream ?? "없음"}) — LAN 호스트에게 내 주소를 DNS 로 안내` : `DNS 포워더 꺼짐`, { ...cfg.dns });
        this.dnsForwarder.config = { ...cfg.dns, records: [] };
      }
    }
  }

  onRemove(ctx: NodeContext): void {
    this.vpnServer.clear();
    this.ddns.release(ctx, "공유기를 치움");
    if (this.ipv6Enabled) {
      if (this.wanLinkUp) this.pd.release(ctx, this.emitWan(ctx));
      this.lan6.shutdown(ctx, this.emitLan(ctx));
    }
    if (this.wanLinkUp) this.wanClient.release(ctx, this.emitWan(ctx));
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    if (this.wan2On && port === Router.WAN2_PORT) {
      this.onWan2Link(up, ctx);
      return;
    }
    if (up && port !== Router.WAN_PORT) this.startLan6(ctx);
    if (port === Router.WAN_PORT) {
      this.wanLinkUp = up;
      if (up) {
        ctx.trace("link.up", "L1", `wan 포트 링크 연결됨`, { port });
        if (this.wanMode === "dhcp") this.wanClient.start(ctx, this.emitWan(ctx));
        else if (this.wan.ip) this.onWanAddress(ctx); // 수동 WAN: 주소는 이미 있다 — VPN 클라이언트를 잇고 DDNS 를 갱신
        this.wan6.linkUp(ctx, this.emitWan(ctx));
        return;
      }
      ctx.trace("link.down", "L1", `wan 포트 링크 다운`, { port });
      this.wan6.linkDown();
      this.mwan.onLine("wan", ctx);
      // 자동(DHCP) WAN 은 공인 주소를 잃으니 VPN 연결도 끝 — 노트북이 다음에 보내면 INVALID-SPI 로 알려 다시 접속시킨다.
      // 수동 WAN 은 주소가 그대로라 잠깐 끊겼다 이어져도 연결을 유지한다 (실제 IPsec SA 도 링크 깜빡임에 지워지지 않는다)
      if (this.wanMode === "dhcp") this.vpnServer.clear();
      // ISP 와 끊기면 위임도 끝: LAN 에서 그 프리픽스를 거둔다 (다시 이어지면 새로 요청)
      this.pd.stop(ctx, this.emitWan(ctx));
      this.wan.clearPending();
      if (this.wanMode === "dhcp") {
        const had = this.wan.ip;
        this.wan.clearAddress();
        this.wanClient.stop();
        if (had) ctx.trace("dhcp.release", "app", `[wan] 링크 다운으로 공인 주소 ${had} 해제`, { ip: had });
      }
      return;
    }
    if (Router.RADIO_PORTS.includes(port)) {
      if (!up) for (const [mac, e] of this.macTable) if (e.port === port) this.macTable.delete(mac);
      return;
    }
    if (up) {
      ctx.trace("link.up", "L1", `lan${port} 포트 링크 연결됨`, { port });
      return;
    }
    ctx.trace("link.down", "L1", `lan${port} 포트 링크 다운`, { port });
    for (const [mac, e] of this.macTable) if (e.port === port) this.macTable.delete(mac);
  }

  // ---------- 수신 ----------

  receive(port: number, frame: EthernetFrame, ctx: NodeContext): void {
    if (this.wan2On && port === Router.WAN2_PORT) {
      this.receiveWan2(frame, ctx);
      return;
    }
    if (port === Router.WAN_PORT) {
      // 가입하지 않은 멀티캐스트(예: 라우터끼리 주고받는 RIP)는 NIC 가 하드웨어에서 조용히 거른다. IPv6 는 WAN 이 가입한 그룹만
      const v6Group = this.wan6.accepts(frame.dst);
      if (isMulticastMac(frame.dst) && !v6Group) return;
      if (!this.wan.accepts(frame) && !v6Group) {
        ctx.trace("frame.drop", "L2", `wan 수신: 목적지 MAC ${frame.dst} 가 내 WAN MAC 아님 → 드롭`, { dst: frame.dst }, frame.id);
        return;
      }
      ctx.trace("frame.receive", "L2", `wan 수신: ${describeFrame(frame)} [${frame.src} → ${frame.dst === BROADCAST_MAC ? "브로드캐스트" : "내 WAN MAC"}]`, { src: frame.src, dst: frame.dst }, frame.id);
      if (frame.payload.kind === "arp") this.wan.handleArp(frame.payload, frame.id, ctx, this.emitWan(ctx));
      else if (frame.payload.kind === "ipv4") this.handleWanIp(frame.payload, frame.id, ctx);
      else if (frame.payload.kind === "ipv6") this.handleWan6(frame.payload, frame, ctx);
      return;
    }

    const pn = Router.portName(port);
    if (frame.vlan !== undefined) {
      ctx.trace("vlan.drop", "L2", `${pn} 에 VLAN ${frame.vlan} 태그 프레임 → 공유기 LAN 포트는 태그를 이해하지 못해 드롭 (스위치 쪽 포트를 액세스로)`, { port, vlan: frame.vlan }, frame.id);
      return;
    }
    ctx.trace("frame.receive", "L2", `${pn} 수신: ${describeFrame(frame)} [${frame.src} → ${frame.dst === BROADCAST_MAC ? "브로드캐스트" : frame.dst}]`, { port, src: frame.src, dst: frame.dst }, frame.id);
    if (!guardLoop(this.seen, port, frame, ctx, pn)) return;
    frame = { ...frame, hops: (frame.hops ?? 0) + 1 };
    const existing = this.macTable.get(frame.src);
    if ((!existing || existing.port !== port) && ctx.isPortConnected(port)) {
      this.macTable.set(frame.src, { port, learnedAt: ctx.now });
      ctx.trace("switch.learn", "L2", `내부 스위치 MAC 테이블 학습: ${frame.src} → ${pn}`, { mac: frame.src, port }, frame.id);
    }
    if (frame.dst === BROADCAST_MAC) {
      this.floodLan(port, frame, ctx, "브로드캐스트");
      this.deliverLan(frame, ctx);
      return;
    }
    // 멀티캐스트는 내부 스위치가 모든 LAN 포트로 뿌리고, 공유기 LAN IPv6 가 가입한 그룹(모든 노드·모든 라우터·solicited-node)이면 공유기도 받는다
    if (isMulticastMac(frame.dst)) {
      this.floodLan(port, frame, ctx, `${frame.dst} 는 MAC 테이블에 없음`);
      if (this.lan6.accepts(frame.dst) && frame.payload.kind === "ipv6") this.handleLan6(frame.payload, frame, ctx);
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
    const radio = Router.RADIO_PORTS.includes(entry.port);
    ctx.trace(
      "switch.forward",
      "L2",
      radio
        ? `내부 스위치: ${frame.dst} 는 무선 단말 → 전파로 송출 (SSID ${this.wifi.ssid}; 다른 단말도 전파는 받지만 암호화되어 읽지 못한다)`
        : `내부 스위치: ${frame.dst} → ${Router.portName(entry.port)} 로 전달`,
      { dst: frame.dst, port: entry.port },
      frame.id,
    );
    ctx.send(entry.port, frame);
  }

  private floodLan(inPort: number, frame: EthernetFrame, ctx: NodeContext, reason: string): void {
    const ports = this.bridgePorts().filter((p) => p !== inPort && ctx.isPortConnected(p));
    if (ports.length === 0) return;
    const wired = ports.filter((p) => Router.LAN_PORTS.includes(p));
    const radio = ports.filter((p) => Router.RADIO_PORTS.includes(p));
    ctx.trace(
      "switch.flood",
      "L2",
      `${reason} → 다른 LAN 포트로 플러딩 [${wired.map((p) => `lan${p}`).join(", ")}]${radio.length ? ` + 전파로 무선 단말 ${radio.length}대` : ""}`,
      { inPort, ports, reason },
      frame.id,
    );
    for (const p of ports) ctx.send(p, frame);
  }

  private deliverLan(frame: EthernetFrame, ctx: NodeContext): void {
    const emit = this.emitLan(ctx);
    const f = frame.payload;
    const seenIp = f.kind === "arp" ? f.senderIp : f.kind === "ipv4" ? f.src : undefined;
    const seenMac = f.kind === "arp" ? f.senderMac : frame.src;
    if (seenIp && this.lan.ip && seenIp !== "0.0.0.0" && sameSubnet(seenIp, this.lan.ip, this.lan.prefix)) {
      this.lanSeen.set(seenMac, seenIp);
      if (this.lanSeen.size > 512) this.lanSeen.delete(this.lanSeen.keys().next().value!);
    }
    if (frame.payload.kind === "arp") {
      this.lan.handleArp(frame.payload, frame.id, ctx, emit);
      return;
    }
    if (frame.payload.kind === "ipv6") {
      this.handleLan6(frame.payload, frame, ctx);
      return;
    }
    const pkt = frame.payload;
    if (pkt.kind !== "ipv4") return;
    if (pkt.payload.kind === "tcp" && this.hairpinTcp(pkt, frame.id, ctx)) return;
    // LAN 의 장비가 내 공인 주소로 WireGuard 를 보냄 (공유기 뒤 클라이언트): 공유기 자신의 주소라 바로 받는다
    if (pkt.dst === this.wan.ip && pkt.payload.kind === "udp" && pkt.payload.payload.kind === "wg" && this.handleWanWg(pkt, frame.id, ctx)) return;
    // 서버의 터널 주소(10.0.0.1)는 공유기 자신
    if (this.wgServerCfg?.enabled && pkt.dst === this.wgServerCfg.address?.ip) {
      const p = pkt.payload;
      if (p.kind === "icmp") {
        this.handleIcmp(pkt, p, frame.id, ctx, this.lan, emit, pkt.dst);
        return;
      }
      if (p.kind === "udp" && p.payload.kind === "dns" && p.dstPort === DNS_PORT) {
        if (this.dnsForwarder.config.enabled) this.dnsForwarder.handle(pkt, p.srcPort, p.payload, frame.id, ctx, emit);
        return;
      }
      ctx.trace("ip.drop", "L4", `공유기 자신(WireGuard 터널 주소 ${pkt.dst})에게 온 ${p.kind === "tcp" ? `TCP ${p.dstPort}` : p.kind === "udp" ? `UDP ${p.dstPort}` : p.kind} → 듣는 서비스 없음, 드롭`, {}, frame.id);
      return;
    }
    if (pkt.payload.kind === "udp") {
      const udp = pkt.payload;
      const m = udp.payload;
      if (m.kind === "dhcp" && udp.dstPort === DHCP_SERVER_PORT) this.dhcpServer.handle(m, frame.id, ctx, emit);
      else if (m.kind === "dhcp" && udp.dstPort === DHCP_CLIENT_PORT) ctx.trace("dhcp.ignore", "app", `LAN 쪽 DHCP 클라이언트 메시지는 내 것이 아님 → 무시`, {}, frame.id);
      else if (m.kind === "dhcp") ctx.trace("ip.drop", "L4", `UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 드롭`, { port: udp.dstPort }, frame.id);
      else if (pkt.dst === this.lan.ip && m.kind === "dns" && udp.dstPort === DNS_PORT) {
        if (this.dnsForwarder.config.enabled || m.op === "response") this.dnsForwarder.handle(pkt, udp.srcPort, m, frame.id, ctx, emit);
        else ctx.trace("dns.nxdomain", "app", `DNS 포워더가 꺼져 있음 → 질의에 응답하지 않음 (라우터 설정에서 켜거나 호스트 DNS 를 바꾸세요)`, {}, frame.id);
      } else if (pkt.dst === this.lan.ip) ctx.trace("ip.drop", "L4", `UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 드롭`, { port: udp.dstPort }, frame.id);
      else if (m.kind === "dns" && m.op === "query" && udp.dstPort === DNS_PORT && this.hijacks(pkt.dst)) {
        // DNS 가로채기 (iptables REDIRECT): 8.8.8.8 처럼 직접 적은 DNS 로 가던 질의를 공유기가 받아 걸러서, 그 서버가 답한 것처럼 돌려준다
        ctx.trace("dns.hijack", "L4", `DNS 가로채기: ${pkt.src} 가 ${pkt.dst} 에 직접 묻는 질의 "${m.name}" → 내보내지 않고 공유기 DNS 포워더가 받음 (AdGuard 필터를 거치게)`, { from: pkt.src, to: pkt.dst }, frame.id);
        this.dnsForwarder.handle(pkt, udp.srcPort, m, frame.id, ctx, emit);
      } else this.forwardToWan(pkt, frame.id, ctx);
      return;
    }
    if (pkt.dst === this.lan.ip || (this.wan.ip && pkt.dst === this.wan.ip) || (this.wan2On && this.wan2.ip && pkt.dst === this.wan2.ip)) {
      if (pkt.payload.kind === "tcp") {
        ctx.trace("ip.drop", "L4", `라우터 자신에게 온 TCP ${pkt.payload.dstPort} 포트 → 듣는 서비스 없음, 드롭`, { port: pkt.payload.dstPort }, frame.id);
        return;
      }
      if (isControl(pkt.payload)) return;
      if (pkt.payload.kind === "esp") {
        ctx.trace("ip.drop", "L3", `라우터 자신에게 온 ESP(IPsec) → 공유기에는 IPsec VPN 이 없어 드롭`, {}, frame.id);
        return;
      }
      // LAN 에서 내 WAN 주소로 온 ping 도 내 것: 응답은 WAN 주소를 출발지로 LAN 쪽으로 돌려준다
      this.handleIcmp(pkt, pkt.payload, frame.id, ctx, this.lan, emit, pkt.dst);
      return;
    }
    if (pkt.dst === "255.255.255.255" || pkt.dst === "0.0.0.0" || pkt.dst.startsWith("224.") || pkt.dst.startsWith("239.")) {
      ctx.trace("ip.drop", "L3", `브로드캐스트/멀티캐스트 ${pkt.dst} 는 라우터가 다른 네트워크로 넘기지 않음 → 드롭`, { dst: pkt.dst }, frame.id);
      return;
    }
    this.forwardToWan(pkt, frame.id, ctx);
  }

  /**
   * 안에서 내 공인 주소로 온 TCP: 헤어핀 NAT 가 켜져 있으면 포트 포워딩 대상으로 되돌리고(그 응답도), 꺼져 있고 그 포트에 포워딩 규칙이 있으면
   * 왜 안 되는지 남긴다. 처리했으면 true
   */
  private hairpinTcp(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): boolean {
    const seg = pkt.payload;
    if (seg.kind !== "tcp" || !this.wan.ip || (pkt.dst !== this.wan.ip && pkt.dst !== this.lan.ip)) return false;
    const rules = this.nat.forwards.filter((r) => (r.proto ?? "tcp") === "tcp");
    if (this.hairpin) {
      this.hairpinNat.rules = rules.map((r) => ({ port: r.publicPort, bind: "0.0.0.0", to: r.lanIp, toPort: r.lanPort }));
      return this.hairpinNat.handle(0, pkt, frameId, ctx);
    }
    // 꺼져 있어도 켜져 있던 동안 시작한 흐름은 끝까지 잇는다 (새 연결만 설정을 본다)
    this.hairpinNat.rules = [];
    if (this.hairpinNat.handle(0, pkt, frameId, ctx)) return true;
    const rule = pkt.dst === this.wan.ip ? rules.find((r) => r.publicPort === seg.dstPort) : undefined;
    if (!rule) return false;
    ctx.trace(
      "ip.drop",
      "L4",
      `헤어핀 NAT 꺼짐: 안쪽 ${pkt.src} 가 내 공인 주소 ${pkt.dst}:${seg.dstPort} 로 접속 → 포트 포워딩은 바깥에서 온 연결에만 적용돼 드롭 (공유기 설정에서 헤어핀 NAT 를 켜거나, 안에서는 ${rule.lanIp}:${rule.lanPort} 로 접속)`,
      { port: seg.dstPort, hairpin: false },
      frameId,
    );
    return true;
  }

  // ---------- IPv6 (NAT 없음) ----------

  /** 위임받은 프리픽스 안의 주소인지 */
  private inDelegated(ip: Ip): boolean {
    const d = this.pd.delegated;
    return !!d && sameSubnet6(ip, d.prefix, d.length);
  }

  /** 공유기 자신에게 온 IPv6: ping 에 답하고, DNS 질의는 포워더로 */
  private local6(pkt: Ipv6Packet, via: Ipv6Interface, emit: (f: EthernetFrame) => void, frameId: number, ctx: NodeContext): void {
    const p = pkt.payload;
    if (p.kind === "icmp6" && p.type === "echo-request") {
      ctx.trace("icmp.echo.received", "app", `ICMPv6 Echo 요청 수신 (from ${pkt.src}, seq=${p.seq})`, { from: pkt.src, seq: p.seq }, frameId);
      const src = pkt.dst === ALL_NODES ? via.sourceFor(pkt.src) : pkt.dst;
      if (!src) return;
      ctx.trace("icmp.reply.sent", "app", `ICMPv6 Echo 응답 생성 → ${pkt.src} (seq=${p.seq})`, { to: pkt.src, seq: p.seq });
      via.send({ kind: "ipv6", src, dst: pkt.src, hopLimit: 64, payload: { kind: "icmp6", type: "echo-reply", id: p.id, seq: p.seq } }, ctx, emit);
      return;
    }
    if (p.kind === "udp" && p.payload.kind === "dns" && p.dstPort === DNS_PORT && via === this.lan6) {
      if (this.dnsForwarder.config.enabled || p.payload.op === "response") this.dnsForwarder.handle(pkt, p.srcPort, p.payload, frameId, ctx, emit);
      else ctx.trace("dns.nxdomain", "app", `DNS 포워더가 꺼져 있음 → IPv6 로 온 질의에 응답하지 않음`, {}, frameId);
      return;
    }
    if (pkt.dst === ALL_NODES) return;
    ctx.trace("ip.drop", "L4", `공유기 자신에게 온 IPv6 ${p.kind === "tcp" ? `TCP ${p.dstPort}` : p.kind === "udp" ? `UDP ${p.dstPort}` : "패킷"} → 듣는 서비스 없음, 드롭`, {}, frameId);
  }

  /** LAN 에서 온 IPv6: NDP·공유기 자신·바깥으로 (NAT 없이 주소 그대로) */
  private handleLan6(pkt: Ipv6Packet, frame: EthernetFrame, ctx: NodeContext): void {
    const emit = this.emitLan(ctx);
    if (!this.ipv6Enabled || !this.lan6.enabled) {
      if (frame.dst === this.lan.mac) ctx.trace("frame.drop", "L3", `IPv6 패킷 수신 → 공유기 IPv6 가 꺼져 있어 드롭 (공유기 설정에서 IPv6 를 켜세요)`, {}, frame.id);
      return;
    }
    const p = pkt.payload;
    if (isNdp(p)) {
      this.lan6.handleNdp(pkt, p, frame, ctx, emit);
      return;
    }
    if (this.lan6.owns(pkt.dst) || this.wan6.owns(pkt.dst) || pkt.dst === ALL_NODES) {
      this.local6(pkt, this.lan6, emit, frame.id, ctx);
      return;
    }
    // DNS 가로채기 (ip6tables REDIRECT): IPv6 로 바깥 DNS 에 직접 묻는 질의도 공유기가 받는다
    if (p.kind === "udp" && p.payload.kind === "dns" && p.payload.op === "query" && p.dstPort === DNS_PORT && this.hijacks(pkt.dst)) {
      ctx.trace("dns.hijack", "L4", `DNS 가로채기: ${pkt.src} 가 ${pkt.dst} 에 IPv6 로 직접 묻는 질의 "${p.payload.name}" → 내보내지 않고 공유기 DNS 포워더가 받음 (AdGuard 필터를 거치게)`, { from: pkt.src, to: pkt.dst }, frame.id);
      this.dnsForwarder.handle(pkt, p.srcPort, p.payload, frame.id, ctx, emit);
      return;
    }
    if (isMulticast6(pkt.dst)) return;
    if (isLinkLocal6(pkt.src) || isLinkLocal6(pkt.dst) || pkt.src === UNSPECIFIED6) {
      ctx.trace("ip.drop", "L3", `[lan] 링크 로컬 주소(fe80::/10)가 낀 패킷은 인터넷으로 넘기지 않음 → 드롭. 공인 IPv6 주소(SLAAC)가 필요하다`, { src: pkt.src, dst: pkt.dst }, frame.id);
      return;
    }
    if (this.lan6.onLink(pkt.dst)) {
      ctx.trace("ip.drop", "L3", `목적지 ${pkt.dst} 는 LAN 안의 주소 → 공유기를 거칠 필요가 없음 (호스트끼리 직접 통신) → 드롭`, { dst: pkt.dst }, frame.id);
      return;
    }
    if (this.inDelegated(pkt.dst)) {
      // 위임받은 /56 안인데 LAN /64 가 아님: ISP 로 보내면 다시 나에게 돌아온다 (RFC 7084 WPD-5 — 쓰지 않는 위임 프리픽스는 Unreachable)
      ctx.trace("ip.no-route", "L3", `No route: ${pkt.dst} 는 위임받은 ${this.pd.delegated!.prefix}/${this.pd.delegated!.length} 안이지만 LAN(/64)에 쓰지 않는 프리픽스 → 드롭하고 Destination Unreachable (no route)`, { dst: pkt.dst }, frame.id);
      const notice = this.lan6.unreachable(pkt, "net", ctx, frame.id);
      if (notice) this.lan6.send(notice, ctx, emit);
      return;
    }
    if (pkt.hopLimit <= 1) {
      const notice = this.lan6.timeExceeded(pkt, ctx, frame.id);
      if (notice) this.lan6.send(notice, ctx, emit);
      return;
    }
    if (!this.wan6.defaultRouter) {
      ctx.trace("ip.no-route", "L3", `No route: ${pkt.dst} 로 가는 IPv6 경로가 없음 — WAN 이 ISP 의 RA 를 받지 못해 IPv6 기본 게이트웨이가 없음 (WAN 케이블·ISP 확인)`, { dst: pkt.dst }, frame.id);
      const notice = this.lan6.unreachable(pkt, "net", ctx, frame.id);
      if (notice) this.lan6.send(notice, ctx, emit);
      return;
    }
    if (!this.firewall.check(pkt, "out", ctx, frame.id)) return;
    this.inbound6.remember(pkt, ctx); // 나가는 흐름을 기억해 돌아오는 응답을 들인다
    const out: Ipv6Packet = { ...pkt, hopLimit: pkt.hopLimit - 1 };
    ctx.trace("ip.forward", "L3", `라우팅(IPv6): ${pkt.dst} → wan (IPv6 기본 게이트웨이 ${this.wan6.defaultRouter}) — NAT 없이 출발지 ${pkt.src} 가 그대로 인터넷에 보인다, Hop Limit ${pkt.hopLimit} → ${out.hopLimit}`, { dst: pkt.dst, out: "wan" }, frame.id);
    this.wan6.send(out, ctx, this.emitWan(ctx));
  }

  /** WAN 에서 온 IPv6: ISP 의 RA·DHCPv6 Reply, 공유기 자신, 위임받은 프리픽스(LAN)로 */
  private handleWan6(pkt: Ipv6Packet, frame: EthernetFrame, ctx: NodeContext): void {
    const emit = this.emitWan(ctx);
    if (!this.ipv6Enabled || !this.wan6.enabled) {
      if (frame.dst === this.wan.mac) ctx.trace("frame.drop", "L3", `[wan] IPv6 패킷 수신 → 공유기 IPv6 가 꺼져 있어 드롭`, {}, frame.id);
      return;
    }
    const p = pkt.payload;
    if (isNdp(p)) {
      this.wan6.handleNdp(pkt, p, frame, ctx, emit);
      return;
    }
    if (p.kind === "udp" && p.payload.kind === "dhcp6" && p.dstPort === DHCP6_CLIENT_PORT) {
      this.pd.handle(pkt.src, p.payload, frame.id, ctx, emit);
      return;
    }
    if (this.wan6.owns(pkt.dst) || this.lan6.owns(pkt.dst) || pkt.dst === ALL_NODES) {
      this.local6(pkt, this.wan6, emit, frame.id, ctx);
      return;
    }
    if (isMulticast6(pkt.dst)) return;
    const lanPrefix = this.lan6.addrs.find((a) => a.origin === "manual");
    if (!lanPrefix || !this.lan6.onLink(pkt.dst) || isLinkLocal6(pkt.dst)) {
      if (this.inDelegated(pkt.dst)) {
        ctx.trace("ip.no-route", "L3", `[wan] ${pkt.dst} 는 위임받은 ${this.pd.delegated!.prefix}/${this.pd.delegated!.length} 안이지만 LAN(/64)에 쓰지 않는 프리픽스 → 드롭하고 Destination Unreachable (no route)`, { dst: pkt.dst }, frame.id);
        const notice = this.wan6.unreachable(pkt, "net", ctx, frame.id);
        if (notice) this.wan6.send(notice, ctx, emit);
      } else ctx.trace("ip.drop", "L3", `[wan] 목적지 ${pkt.dst} 는 위임받은 LAN 프리픽스가 아님 → 드롭`, { dst: pkt.dst }, frame.id);
      return;
    }
    if (pkt.hopLimit <= 1) {
      const notice = this.wan6.timeExceeded(pkt, ctx, frame.id);
      if (notice) this.wan6.send(notice, ctx, emit);
      return;
    }
    if (!this.firewall.check(pkt, "in", ctx, frame.id)) return;
    // 공유기 방화벽에 이 연결을 허용하는 인바운드 규칙이 있으면 그것이 핀홀: 기본 차단을 건너뛴다
    if (!this.firewall.allowsByRule(pkt, "in") && !this.inbound6.check(pkt, "in", ctx, frame.id)) return;
    const out: Ipv6Packet = { ...pkt, hopLimit: pkt.hopLimit - 1 };
    ctx.trace("ip.forward", "L3", `라우팅(IPv6): ${pkt.dst} 는 위임받은 LAN 프리픽스 → LAN 으로 (NAT 역변환 없이 주소 그대로), Hop Limit ${pkt.hopLimit} → ${out.hopLimit}`, { dst: pkt.dst, out: "lan" }, frame.id);
    this.lan6.send(out, ctx, this.emitLan(ctx));
  }

  private handleWanIp(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const emit = this.emitWan(ctx);
    if (pkt.payload.kind === "udp" && pkt.payload.payload.kind === "dhcp") {
      const udp = pkt.payload;
      const m = udp.payload as DhcpMessage;
      if (udp.dstPort === DHCP_CLIENT_PORT) {
        this.wanClient.handle(m, frameId, ctx, emit);
        // WAN 주소를 받았으면 DDNS 갱신·VPN 클라이언트 연결 (GL.iNet 은 인터넷이 연결되면 VPN 을 자동으로 잇는다)
        this.onWanAddress(ctx);
      }
      else if (udp.dstPort === DHCP_SERVER_PORT) ctx.trace("dhcp.ignore", "app", `[wan] 다른 장치의 DHCP ${m.op} → 무시`, {}, frameId);
      else ctx.trace("ip.drop", "L4", `[wan] UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 드롭`, { port: udp.dstPort }, frameId);
      return;
    }
    if (pkt.dst !== this.wan.ip) {
      ctx.trace("ip.drop", "L3", `[wan] 목적지 ${pkt.dst} 는 내 공인 주소(${this.wan.ip ?? "없음"}) 아님 → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    // 공유기 자신이 보낸 것의 답: 멀티 WAN 추적 ping, DDNS 갱신 응답, 공유기 자신의 이름 해석 (DNS 포워더의 업스트림 답보다 먼저 — 포트가 다르다)
    {
      const u = pkt.payload;
      if (u.kind === "icmp" && u.type === "echo-reply" && u.id === MWAN_ICMP_ID && this.mwan.onReply("wan", u.seq)) {
        ctx.trace("mwan.check", "L3", `멀티 WAN: WAN1 추적 ping 응답 (${pkt.src}) → 이 회선은 인터넷이 됨`, { wan: "wan" }, frameId);
        return;
      }
      if (u.kind === "udp" && u.payload.kind === "ddns" && u.dstPort === DDNS_PORT && u.payload.op === "response") {
        this.ddns.handle(u.payload, frameId, ctx);
        return;
      }
      if (u.kind === "udp" && u.payload.kind === "dns" && u.payload.op === "response" && u.dstPort === this.resolver.port) {
        this.resolver.handle(u.payload, pkt.src, frameId, ctx);
        return;
      }
    }
    // WireGuard: 내 서버·클라이언트의 포트로 온 WireGuard 메시지는 공유기 자신이 받는다 (그 밖의 포트는 아래 NAT 역변환 — 안쪽 기기의 WireGuard)
    if (this.handleWanWg(pkt, frameId, ctx)) return;
    // VPN 서버 (L2TP/IPsec): IKE (UDP 500·4500) 와 내 SA 의 ESP 는 공유기 자신이 받는다 (포트 포워딩보다 먼저 — ipTIME 도 VPN 서버를 켜면 그 포트를 쓴다)
    if (this.vpnServer.config.enabled) {
      const p0 = pkt.payload;
      if (p0.kind === "udp" && p0.payload.kind === "ike" && this.vpnServer.handleIke(pkt, p0.srcPort, p0.dstPort, p0.payload, ctx, frameId)) return;
      const esp: EspPacket | undefined = p0.kind === "esp" ? p0 : p0.kind === "udp" && p0.payload.kind === "esp" ? p0.payload : undefined;
      if (esp) {
        const inner = this.vpnServer.receive(pkt, p0.kind === "udp" ? p0.srcPort : undefined, esp, ctx, frameId);
        if (inner) this.routeFromVpn(inner, frameId, ctx);
        if (inner !== undefined) return;
      }
    } else if (this.vpnServerHint(pkt, frameId, ctx)) return;
    // UDP 포트 포워딩 규칙이 있는 포트(예: 53 → 안쪽 DNS 서버)는 내가 받지 않고 아래 NAT 역변환으로 안에 넘긴다
    const udpForwarded = pkt.payload.kind === "udp" && this.nat.forwards.some((r) => r.proto === "udp" && r.publicPort === (pkt.payload as { dstPort: number }).dstPort);
    if (!udpForwarded && pkt.payload.kind === "udp" && pkt.payload.payload.kind === "dns" && pkt.payload.dstPort === DNS_PORT) {
      // 내가 업스트림 DNS 에 물어본 답 → 포워더가 LAN 클라이언트에게 전달
      this.dnsForwarder.handle(pkt, pkt.payload.srcPort, pkt.payload.payload, frameId, ctx, this.emitLan(ctx));
      return;
    }
    const p = pkt.payload;
    if (p.kind === "icmp" && p.type === "echo-request") {
      this.handleIcmp(pkt, p, frameId, ctx, this.wan, emit);
      return;
    }
    // 바깥에서 들어온 패킷: NAT 테이블로 내부 호스트를 찾는다
    if (pkt.ttl <= 1) {
      const notice = this.wan.timeExceeded(pkt, ctx, frameId);
      if (notice) this.wan.sendIp(notice, ctx, emit);
      return;
    }
    const restored = this.nat.restore(pkt, this.wan.ip, ctx, frameId);
    if (!restored) return;
    if (!this.dpiCheck(restored, "in", frameId, ctx)) return;
    if (!this.firewall.check(restored, "in", ctx, frameId)) return;
    if (this.wgServerCfg?.enabled && this.wgs.route(restored.dst)) {
      this.toWgPeerFwd(restored, frameId, ctx); // WireGuard 로 붙은 기기의 인터넷 응답
      return;
    }
    if (this.vpnServer.owns(restored.dst)) {
      this.toVpnClient(restored, frameId, ctx); // VPN 으로 붙은 노트북의 인터넷 응답
      return;
    }
    const inner: Ipv4Packet = { ...restored, ttl: pkt.ttl - 1 };
    ctx.trace("ip.forward", "L3", `라우팅: ${inner.dst} 는 LAN 안 → LAN 인터페이스로 전달 (TTL ${pkt.ttl} → ${inner.ttl})`, { dst: inner.dst }, frameId);
    this.lan.sendIp(inner, ctx, this.emitLan(ctx));
  }

  /**
   * VPN 서버가 꺼져 있는데 L2TP/IPsec 협상(IKE 요청)이 옴 (그 포트의 UDP 포워딩 규칙이 없을 때): "포트 포워딩 규칙을 추가하라" 대신 VPN 서버가 꺼졌다고 알린다
   */
  private vpnServerHint(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): boolean {
    // IKE 요청만 본다: ESP 는 방향을 알 수 없다 (이 공유기 뒤 노트북이 받는 응답 ESP 는 NAT 역변환으로 넘겨야 한다)
    const p = pkt.payload;
    if (p.kind !== "udp" || p.payload.kind !== "ike" || p.payload.l2tp !== true || p.payload.response) return false;
    if (this.nat.forwards.some((r) => r.proto === "udp" && r.publicPort === p.dstPort)) return false;
    ctx.trace("ip.drop", "L4", `L2TP/IPsec VPN 협상 요청 (IKE, from ${pkt.src}) → 이 공유기의 VPN 서버가 꺼져 있어 받지 않음, 드롭 (설정의 "VPN 서버" 를 켜세요)`, { from: pkt.src }, frameId);
    return true;
  }

  /** VPN 클라이언트(노트북)가 터널로 보낸 패킷: 공유기 자신·집 LAN·다른 VPN 클라이언트·인터넷 (LAN 호스트가 보낸 것처럼) */
  private routeFromVpn(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const emit = this.emitLan(ctx);
    if (pkt.dst === this.lan.ip || pkt.dst === this.wan.ip) {
      const p = pkt.payload;
      if (p.kind === "udp" && p.payload.kind === "dns" && p.dstPort === DNS_PORT && pkt.dst === this.lan.ip) {
        if (this.dnsForwarder.config.enabled) this.dnsForwarder.handle(pkt, p.srcPort, p.payload, frameId, ctx, emit);
        else ctx.trace("dns.nxdomain", "app", `DNS 포워더가 꺼져 있음 → VPN 클라이언트의 질의에 응답하지 않음`, {}, frameId);
        return;
      }
      if (p.kind === "icmp") {
        this.handleIcmp(pkt, p, frameId, ctx, this.lan, emit, pkt.dst);
        return;
      }
      ctx.trace("ip.drop", "L4", `공유기 자신에게 온 ${p.kind === "tcp" ? `TCP ${p.dstPort}` : p.kind === "udp" ? `UDP ${p.dstPort}` : p.kind} → 듣는 서비스 없음, 드롭`, {}, frameId);
      return;
    }
    if (pkt.dst === "255.255.255.255" || pkt.dst.startsWith("224.") || pkt.dst.startsWith("239.")) {
      ctx.trace("ip.drop", "L3", `VPN 클라이언트의 브로드캐스트/멀티캐스트 ${pkt.dst} → 집 LAN 으로 넘기지 않음 (L2TP 는 IP 만 나른다)`, { dst: pkt.dst }, frameId);
      return;
    }
    if (this.vpnServer.owns(pkt.dst)) {
      this.toVpnClient(pkt, frameId, ctx);
      return;
    }
    if (this.lan.ip && sameSubnet(pkt.dst, this.lan.ip, this.lan.prefix)) {
      if (pkt.ttl <= 1) {
        const notice = this.lan.timeExceeded(pkt, ctx, frameId);
        if (notice) this.lan.sendIp(notice, ctx, emit);
        return;
      }
      const inner: Ipv4Packet = { ...pkt, ttl: pkt.ttl - 1 };
      ctx.trace("ip.forward", "L3", `라우팅: VPN 클라이언트 ${pkt.src} → ${pkt.dst} 는 집 LAN 안 → LAN 인터페이스로 전달 (TTL ${pkt.ttl} → ${inner.ttl})`, { dst: pkt.dst }, frameId);
      this.lan.sendIp(inner, ctx, emit);
      return;
    }
    // 인터넷: 집 LAN 기기처럼 방화벽·NAT 를 거쳐 공유기 공인 주소로 나간다 (full tunnel — 해외에서도 집 IP)
    this.forwardToWan(pkt, frameId, ctx);
  }

  /** 목적지가 VPN 클라이언트: TTL 을 줄여 그 클라이언트의 터널로 (LAN 기기·인터넷 응답·다른 VPN 클라이언트에서) */
  private toVpnClient(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    if (pkt.ttl <= 1) {
      const notice = this.lan.timeExceeded(pkt, ctx, frameId);
      if (notice) this.lan.sendIp(notice, ctx, this.emitLan(ctx));
      return;
    }
    const inner: Ipv4Packet = { ...pkt, ttl: pkt.ttl - 1 };
    ctx.trace("ip.forward", "L3", `라우팅: ${pkt.dst} 는 VPN 으로 붙은 기기 → 그 터널로 전달 (TTL ${pkt.ttl} → ${inner.ttl})`, { dst: pkt.dst, vpn: true }, frameId);
    if (this.wan.ip) this.vpnServer.sendTo(inner, this.wan.ip, ctx, frameId);
  }

  private forwardToWan(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    // LAN 기기가 WireGuard 로 붙은 기기에게 (그 터널 주소는 LAN 밖이라 기본 게이트웨이인 공유기로 온다)
    if (this.wgServerCfg?.enabled && this.wgs.route(pkt.dst)) {
      this.toWgPeerFwd(pkt, frameId, ctx);
      return;
    }
    const tun = this.wgServerCfg?.enabled ? this.wgServerCfg.address : undefined;
    if (tun && sameSubnet(pkt.dst, tun.ip, tun.prefix)) {
      ctx.trace("ip.no-route", "L3", `No route: ${pkt.dst} 는 WireGuard 터널 대역 ${tun.ip}/${tun.prefix} 안이지만 그 주소로 등록된 피어가 없음 → 드롭하고 Destination Unreachable (net)`, { dst: pkt.dst }, frameId);
      const notice = this.lan.unreachable(pkt, "net", ctx, frameId);
      if (notice) this.lan.sendIp(notice, ctx, this.emitLan(ctx));
      return;
    }
    // LAN 기기가 VPN 클라이언트에게 (프록시 ARP 로 공유기 MAC 에 보냄)
    if (this.vpnServer.owns(pkt.dst)) {
      this.toVpnClient(pkt, frameId, ctx);
      return;
    }
    if (this.vpnServer.inPool(pkt.dst)) {
      ctx.trace("ip.drop", "L3", `목적지 ${pkt.dst} 는 VPN 할당 IP 인데 지금 그 주소로 붙어 있는 VPN 기기가 없음 (끊긴 기기에 대신 답했던 프록시 ARP 가 보낸 쪽 캐시에 남음) → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    if (sameSubnet(pkt.dst, this.lan.ip!, this.lan.prefix)) {
      ctx.trace("ip.drop", "L3", `목적지 ${pkt.dst} 는 LAN 안의 주소 → 라우터를 거칠 필요가 없음 (호스트끼리 직접 통신) → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    if (pkt.ttl <= 1) {
      const notice = this.lan.timeExceeded(pkt, ctx, frameId);
      if (notice) this.lan.sendIp(notice, ctx, this.emitLan(ctx));
      return;
    }
    if (this.policyApplies(pkt.src) && this.toWgClient(pkt, frameId, ctx)) return;
    const o = this.outFor(pkt, ctx);
    if (!o.iface.ip) {
      ctx.trace("ip.no-route", "L3", `${pkt.dst} 는 외부 주소인데 ${this.wan2On ? `${WAN_LABEL[o.name]}(지금 쓰는 회선)` : "WAN"} 에 공인 주소가 없음 → 인터넷으로 보낼 수 없음 (WAN 케이블과 DHCP 확인)`, { dst: pkt.dst }, frameId);
      const notice = this.lan.unreachable(pkt, "net", ctx, frameId);
      if (notice) this.lan.sendIp(notice, ctx, this.emitLan(ctx));
      return;
    }
    if (!this.dpiCheck(pkt, "out", frameId, ctx)) return;
    if (!this.firewall.check(pkt, "out", ctx, frameId)) return;
    const translated = o.nat.translate({ ...pkt, ttl: pkt.ttl - 1 }, o.iface.ip, ctx, frameId);
    if (!translated) return;
    ctx.trace("ip.forward", "L3", `라우팅: ${pkt.dst} 는 외부 → ${this.wan2On ? `${WAN_LABEL[o.name]}(${o.name === "wan" ? "wan" : "lan4"})` : "WAN"} 인터페이스로 전달 (TTL ${pkt.ttl} → ${translated.ttl})`, { dst: pkt.dst, out: o.name }, frameId);
    o.iface.sendIp(translated, ctx, o.emit);
  }

  // ---------- 멀티 WAN ----------

  /** 멀티 WAN 설정: 켜면 lan4 가 WAN2 (주소는 DHCP·수동), 끄면 다시 LAN 포트 */
  setWan2(cfg: Wan2Config, ctx: NodeContext): void {
    const on = cfg.enabled;
    const addrChanged = cfg.mode !== this.wan2Mode || (cfg.mode === "static" && (cfg.ip !== this.wan2.ip || (cfg.prefix ?? 24) !== this.wan2.prefix || cfg.gateway !== this.wan2.gateway));
    if (on !== this.wan2On) {
      this.wan2On = on;
      // 그 포트로 배운 MAC 은 버린다 (LAN 포트 ↔ WAN2 가 바뀜)
      for (const [mac, e] of this.macTable) if (e.port === Router.WAN2_PORT) this.macTable.delete(mac);
      if (on) {
        ctx.trace("ip.config", "sys", `멀티 WAN: lan4 포트를 WAN2(예비 회선)로 — 내부 스위치에서 빠진다`, { wan2: true });
        this.wan2LinkUp = ctx.isPortConnected(Router.WAN2_PORT);
      } else {
        this.wan2Client.stop();
        this.wan2.clearAddress();
        this.wan2LinkUp = false;
        ctx.trace("ip.config", "sys", `멀티 WAN 꺼짐: lan4 는 다시 LAN 포트`, { wan2: false });
      }
    }
    if (on && (addrChanged || this.wan2Mode !== cfg.mode || (this.wan2LinkUp && cfg.mode === "dhcp" && !this.wan2.ip && this.wan2Client.state === "idle"))) {
      this.wan2Mode = cfg.mode;
      if (cfg.mode === "static") {
        this.wan2Client.stop();
        this.wan2.configure(cfg.ip || undefined, cfg.prefix ?? 24, cfg.gateway || undefined);
        this.wan2.arpCache.clear();
        this.wan2.clearPending();
        if (cfg.ip) ctx.trace("ip.config", "sys", `[wan2] 수동 설정: ${cfg.ip}/${cfg.prefix ?? 24}, 게이트웨이 ${cfg.gateway ?? "없음"}`, { ...cfg });
        if (cfg.ip && this.wan2LinkUp) this.wan2.claim(ctx, this.emitWan2(ctx)); // 같은 주소를 쓰는 장비가 있나 (ARP Probe)
      } else {
        this.wan2.clearAddress();
        if (this.wan2LinkUp) this.wan2Client.start(ctx, this.emitWan2(ctx));
      }
    }
    this.mwan.setConfig(on, cfg.track, ctx);
    this.mwan.onLine("wan2", ctx);
  }

  /** WAN2 링크 */
  private onWan2Link(up: boolean, ctx: NodeContext): void {
    this.wan2LinkUp = up;
    if (up) {
      ctx.trace("link.up", "L1", `wan2(lan4) 포트 링크 연결됨`, { port: Router.WAN2_PORT });
      if (this.wan2Mode === "dhcp") this.wan2Client.start(ctx, this.emitWan2(ctx));
      else if (this.wan2.ip) this.wan2.claim(ctx, this.emitWan2(ctx));
    } else {
      ctx.trace("link.down", "L1", `wan2(lan4) 포트 링크 다운`, { port: Router.WAN2_PORT });
      this.wan2.clearPending();
      if (this.wan2Mode === "dhcp") {
        const had = this.wan2.ip;
        this.wan2.clearAddress();
        this.wan2Client.stop();
        if (had) ctx.trace("dhcp.release", "app", `[wan2] 링크 다운으로 주소 ${had} 해제`, { ip: had });
      }
    }
    this.mwan.onLine("wan2", ctx);
  }

  /** WAN2 로 들어온 프레임: DHCP·ARP·추적 응답·DNS 포워더의 업스트림 답·DDNS 응답·NAT 역변환 (VPN 서버·IPv6 는 WAN1 만) */
  private receiveWan2(frame: EthernetFrame, ctx: NodeContext): void {
    if (isMulticastMac(frame.dst)) return;
    if (!this.wan2.accepts(frame)) {
      ctx.trace("frame.drop", "L2", `wan2 수신: 목적지 MAC ${frame.dst} 가 내 WAN2 MAC 아님 → 드롭`, { dst: frame.dst }, frame.id);
      return;
    }
    ctx.trace("frame.receive", "L2", `wan2 수신: ${describeFrame(frame)} [${frame.src} → ${frame.dst === BROADCAST_MAC ? "브로드캐스트" : "내 WAN2 MAC"}]`, { src: frame.src, dst: frame.dst }, frame.id);
    const emit = this.emitWan2(ctx);
    const p = frame.payload;
    if (p.kind === "arp") {
      this.wan2.handleArp(p, frame.id, ctx, emit);
      return;
    }
    if (p.kind !== "ipv4") return;
    const pkt = p;
    const u = pkt.payload;
    if (u.kind === "udp" && u.payload.kind === "dhcp") {
      if (u.dstPort === DHCP_CLIENT_PORT) {
        this.wan2Client.handle(u.payload, frame.id, ctx, emit);
        this.mwan.onLine("wan2", ctx);
        if (this.mwan.active === "wan2") this.ddns.onWanAddress(ctx);
      }
      return;
    }
    if (pkt.dst !== this.wan2.ip) {
      ctx.trace("ip.drop", "L3", `[wan2] 목적지 ${pkt.dst} 는 내 WAN2 주소(${this.wan2.ip ?? "없음"}) 아님 → 드롭`, { dst: pkt.dst }, frame.id);
      return;
    }
    if (u.kind === "icmp" && u.type === "echo-reply" && u.id === MWAN_ICMP_ID + 1) {
      if (this.mwan.onReply("wan2", u.seq)) ctx.trace("mwan.check", "L3", `멀티 WAN: WAN2 추적 ping 응답 (${pkt.src}) → 이 회선은 인터넷이 됨`, { wan: "wan2" }, frame.id);
      return;
    }
    if (u.kind === "udp" && u.payload.kind === "ddns" && u.dstPort === DDNS_PORT && u.payload.op === "response") {
      this.ddns.handle(u.payload, frame.id, ctx);
      return;
    }
    // WireGuard 클라이언트·서버 (멀티 WAN 이 WAN2 로 넘어가 있을 때 오가는 것)
    if (u.kind === "udp" && u.payload.kind === "wg" && this.handleWanWg(pkt, frame.id, ctx)) return;
    const forwarded = u.kind === "udp" && this.nat2.forwards.some((r) => r.proto === "udp" && r.publicPort === u.dstPort);
    if (!forwarded && u.kind === "udp" && u.payload.kind === "dns" && u.dstPort === DNS_PORT) {
      this.dnsForwarder.handle(pkt, u.srcPort, u.payload, frame.id, ctx, this.emitLan(ctx));
      return;
    }
    if (u.kind === "icmp" && u.type === "echo-request") {
      this.handleIcmp(pkt, u, frame.id, ctx, this.wan2, emit);
      return;
    }
    if (pkt.ttl <= 1) {
      const notice = this.wan2.timeExceeded(pkt, ctx, frame.id);
      if (notice) this.wan2.sendIp(notice, ctx, emit);
      return;
    }
    const restored = this.nat2.restore(pkt, this.wan2.ip, ctx, frame.id);
    if (!restored) return;
    if (!this.dpiCheck(restored, "in", frame.id, ctx)) return;
    if (!this.firewall.check(restored, "in", ctx, frame.id)) return;
    const inner: Ipv4Packet = { ...restored, ttl: pkt.ttl - 1 };
    ctx.trace("ip.forward", "L3", `라우팅: ${inner.dst} 는 LAN 안 → LAN 인터페이스로 전달 (WAN2 로 들어옴, TTL ${pkt.ttl} → ${inner.ttl})`, { dst: inner.dst }, frame.id);
    this.lan.sendIp(inner, ctx, this.emitLan(ctx));
  }

  // ---------- WireGuard ----------

  /** WAN 으로 온 WireGuard 메시지: 내 서버·클라이언트 포트면 받는다. 처리했으면 true */
  private handleWanWg(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): boolean {
    const u = pkt.payload;
    if (u.kind !== "udp" || u.payload.kind !== "wg") return false;
    const m = u.payload;
    if (this.wgServerCfg?.enabled && this.wgs.enabled && u.dstPort === this.wgs.config.listenPort) {
      const inner = this.wgs.handle(pkt, u.srcPort, m, ctx, frameId);
      if (inner) this.routeFromWg(inner, frameId, ctx);
      return true;
    }
    if (this.wgClientCfg?.enabled && this.wgc.enabled && u.dstPort === this.wgc.config.listenPort) {
      const inner = this.wgc.handle(pkt, u.srcPort, m, ctx, frameId);
      if (inner) this.fromWgClient(inner, frameId, ctx);
      return true;
    }
    // 포워딩 규칙도 NAT 매핑도 없는 포트로 온 핸드셰이크: 서버가 꺼져 있다고 알려 준다 (아래 NAT 역변환은 "테이블에 없음" 만 남긴다)
    const forwarded = this.nat.forwards.some((r) => r.proto === "udp" && r.publicPort === u.dstPort);
    if (u.dstPort === this.wgcPort && !forwarded) {
      ctx.trace("vpn.drop", "L4", `WireGuard ${m.type === "data" ? "데이터" : m.type === "response" ? "Response" : "Initiation"} (from ${pkt.src}) → 이 공유기의 WireGuard 클라이언트가 꺼진 뒤 늦게 온 패킷 → 무시`, { from: pkt.src, late: true }, frameId);
      return true;
    }
    if (m.type !== "initiation" && !forwarded && u.dstPort === (this.wgServerCfg?.listenPort ?? WG_PORT)) {
      ctx.trace("vpn.drop", "L4", `WireGuard ${m.type === "data" ? "데이터" : "Response"} (from ${pkt.src}) → 이 공유기의 WireGuard 서버가 꺼져 있음 → 무시 (상대는 답이 없으면 새로 핸드셰이크한다)`, { from: pkt.src, late: true }, frameId);
      return true;
    }
    if (m.type === "initiation" && !forwarded && u.dstPort === (this.wgServerCfg?.listenPort ?? WG_PORT)) {
      ctx.trace("ip.drop", "L4", `WireGuard 핸드셰이크 (from ${pkt.src}) → 이 공유기의 WireGuard 서버가 꺼져 있어 받지 않음, 드롭 (설정의 "WireGuard 서버" 를 켜거나, 안쪽 서버로 UDP ${u.dstPort} 포트 포워딩)`, { from: pkt.src }, frameId);
      return true;
    }
    return false;
  }

  /** WireGuard 서버의 피어에게 (TTL 을 줄여 그 터널로) — LAN 기기·인터넷 응답·다른 피어에게서 */
  private toWgPeerFwd(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    if (pkt.ttl <= 1) {
      const notice = this.lan.timeExceeded(pkt, ctx, frameId);
      if (notice) this.lan.sendIp(notice, ctx, this.emitLan(ctx));
      return;
    }
    const inner: Ipv4Packet = { ...pkt, ttl: pkt.ttl - 1 };
    ctx.trace("ip.forward", "L3", `라우팅: ${pkt.dst} 는 WireGuard 로 붙은 기기 → 그 터널로 (TTL ${pkt.ttl} → ${inner.ttl})`, { dst: pkt.dst, wg: true }, frameId);
    this.toWgPeer(inner, ctx, frameId);
  }

  /** WireGuard 서버로 들어온 패킷 (붙은 기기가 보냄): 공유기 자신·다른 피어·집 LAN·인터넷 */
  private routeFromWg(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const emit = this.emitLan(ctx);
    const s = this.wgServerCfg!;
    const p = pkt.payload;
    if (pkt.dst === this.lan.ip || pkt.dst === this.wan.ip || pkt.dst === s.address?.ip) {
      if (p.kind === "udp" && p.payload.kind === "dns" && p.dstPort === DNS_PORT && pkt.dst !== this.wan.ip) {
        if (this.dnsForwarder.config.enabled) this.dnsForwarder.handle(pkt, p.srcPort, p.payload, frameId, ctx, emit);
        else ctx.trace("dns.nxdomain", "app", `DNS 포워더가 꺼져 있음 → WireGuard 클라이언트의 질의에 응답하지 않음`, {}, frameId);
        return;
      }
      if (p.kind === "icmp") {
        this.handleIcmp(pkt, p, frameId, ctx, this.lan, emit, pkt.dst);
        return;
      }
      ctx.trace("ip.drop", "L4", `공유기 자신에게 온 ${p.kind === "tcp" ? `TCP ${p.dstPort}` : p.kind === "udp" ? `UDP ${p.dstPort}` : p.kind} → 듣는 서비스 없음, 드롭`, {}, frameId);
      return;
    }
    if (pkt.dst === "255.255.255.255" || pkt.dst.startsWith("224.") || pkt.dst.startsWith("239.")) {
      ctx.trace("ip.drop", "L3", `WireGuard 클라이언트의 브로드캐스트/멀티캐스트 ${pkt.dst} → 넘기지 않음 (WireGuard 는 IP 만 나른다)`, { dst: pkt.dst }, frameId);
      return;
    }
    if (this.wgs.route(pkt.dst)) {
      this.toWgPeerFwd(pkt, frameId, ctx);
      return;
    }
    if (this.lan.ip && sameSubnet(pkt.dst, this.lan.ip, this.lan.prefix)) {
      if (!s.lanAccess) {
        ctx.trace("fw.deny", "L3", `WireGuard 클라이언트 ${pkt.src} → 집 LAN ${pkt.dst}: "LAN 접근 허용" 이 꺼져 있음 → 드롭 (인터넷만 이 공유기로 나갈 수 있다)`, { src: pkt.src, dst: pkt.dst }, frameId);
        return;
      }
      if (pkt.ttl <= 1) {
        const notice = this.lan.timeExceeded(pkt, ctx, frameId);
        if (notice) this.lan.sendIp(notice, ctx, emit);
        return;
      }
      const inner: Ipv4Packet = { ...pkt, ttl: pkt.ttl - 1 };
      ctx.trace("ip.forward", "L3", `라우팅: WireGuard 클라이언트 ${pkt.src} → ${pkt.dst} 는 집 LAN 안 → LAN 인터페이스로 전달 (TTL ${pkt.ttl} → ${inner.ttl})`, { dst: pkt.dst }, frameId);
      this.lan.sendIp(inner, ctx, emit);
      return;
    }
    // 인터넷: 집 LAN 기기처럼 방화벽·NAT 를 거쳐 공유기 공인 주소로 (클라이언트가 AllowedIPs 0.0.0.0/0 으로 전부 보낼 때)
    this.forwardToWan(pkt, frameId, ctx);
  }

  /**
   * LAN 기기의 패킷을 VPN 클라이언트 터널로: 출발지를 내 터널 주소로 바꿔(NAT) 서버에 보낸다. 보냈으면 true.
   * VPN 이 끊겨 있으면 킬 스위치가 켜져 있을 때만 붙잡고(다시 핸드셰이크), 꺼져 있으면 false — WAN 으로 바로 나간다
   */
  private toWgClient(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): boolean {
    const c = this.wgClientCfg!;
    const peer = this.wgc.route(pkt.dst);
    if (!peer || pkt.dst === c.server?.ip || pkt.dst === peer.endpoint?.ip) return false;
    if (!c.address) {
      if (!c.killSwitch) return false;
      ctx.trace("vpn.killswitch", "L3", `킬 스위치: VPN 클라이언트에 내 터널 주소가 없어 VPN 을 쓸 수 없음 → ${pkt.src} → ${pkt.dst} 를 WAN 으로 내보내지 않음 (WireGuard 클라이언트 → 내 터널 주소)`, { src: pkt.src, dst: pkt.dst, killSwitch: true }, frameId);
      return true;
    }
    if (this.wgcDown()) {
      if (!c.killSwitch) {
        ctx.trace("vpn.leak", "L3", `VPN 이 끊겨 있음 (${peer.failed ?? "핸드셰이크 실패"}) → 킬 스위치가 꺼져 있어 ${pkt.src} → ${pkt.dst} 를 WAN 으로 바로 내보냄 — VPN 을 거치지 않아 실제 공인 주소가 드러난다. 다시 연결을 시도`, { src: pkt.src, dst: pkt.dst, killSwitch: false }, frameId);
        this.wgc.connect(ctx);
        return false;
      }
      ctx.trace("vpn.killswitch", "L3", `킬 스위치: VPN 이 끊겨 있어 ${pkt.src} → ${pkt.dst} 를 WAN 으로 내보내지 않음 → 터널이 다시 맺어지기를 기다림`, { src: pkt.src, dst: pkt.dst, killSwitch: true }, frameId);
    }
    if (pkt.ttl <= 1) {
      const notice = this.lan.timeExceeded(pkt, ctx, frameId);
      if (notice) this.lan.sendIp(notice, ctx, this.emitLan(ctx));
      return true;
    }
    if (!this.firewall.check(pkt, "out", ctx, frameId)) return true;
    const translated = this.natVpn.translate({ ...pkt, ttl: pkt.ttl - 1 }, c.address.ip, ctx, frameId);
    if (!translated) return true;
    ctx.trace("ip.forward", "L3", `라우팅: ${pkt.dst} 는 VPN 정책 대상 → WireGuard 클라이언트 터널로 (출발지 ${pkt.src} → 내 터널 주소 ${c.address.ip}, TTL ${pkt.ttl} → ${translated.ttl})`, { dst: pkt.dst, wg: true }, frameId);
    this.wgc.send(peer, translated, ctx, frameId);
    return true;
  }

  /** VPN 클라이언트 터널로 들어온 패킷: 내 질의의 답(DNS)·나에게 온 ping, 아니면 NAT 역변환해 LAN 기기로 */
  private fromWgClient(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const c = this.wgClientCfg!;
    const me = c.address?.ip;
    if (!me || pkt.dst !== me) {
      ctx.trace("vpn.drop", "L3", `WireGuard 클라이언트: 풀린 패킷의 목적지 ${pkt.dst} 가 내 터널 주소(${me ?? "없음"})가 아님 → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    const p = pkt.payload;
    if (p.kind === "udp" && p.payload.kind === "dns" && p.payload.op === "response" && p.dstPort === DNS_PORT) {
      this.dnsForwarder.handle(pkt, p.srcPort, p.payload, frameId, ctx, this.emitLan(ctx));
      return;
    }
    if (p.kind === "icmp" && p.type === "echo-request") {
      ctx.trace("icmp.echo.received", "app", `ICMP Echo 요청 수신 (from ${pkt.src}, 터널로, seq=${p.seq})`, { from: pkt.src, seq: p.seq }, frameId);
      const reply: Ipv4Packet = { kind: "ipv4", src: me, dst: pkt.src, ttl: 64, payload: { kind: "icmp", type: "echo-reply", id: p.id, seq: p.seq } };
      const peer = this.wgc.route(pkt.src);
      if (peer) this.wgc.send(peer, reply, ctx, frameId);
      return;
    }
    const restored = this.natVpn.restore(pkt, me, ctx, frameId);
    if (!restored) return;
    if (!this.firewall.check(restored, "in", ctx, frameId)) return;
    if (pkt.ttl <= 1) return;
    const inner: Ipv4Packet = { ...restored, ttl: pkt.ttl - 1 };
    ctx.trace("ip.forward", "L3", `라우팅: VPN 터널의 응답 → NAT 역변환해 LAN 의 ${inner.dst} 로 (TTL ${pkt.ttl} → ${inner.ttl})`, { dst: inner.dst, wg: true }, frameId);
    this.lan.sendIp(inner, ctx, this.emitLan(ctx));
  }

  /** 사용자의 "다시 연결" (VPN 클라이언트) */
  wgReconnect(ctx: NodeContext): void {
    if (!this.wgClientCfg?.enabled) {
      ctx.trace("vpn.drop", "L4", `WireGuard 클라이언트가 꺼져 있음 → 연결할 것이 없음`, {});
      return;
    }
    this.wgc.reset();
    if (this.wgClientCfg.serverName) this.resolveWgServer(ctx, "다시 연결");
    else this.wgc.connect(ctx);
  }

  /** 표시용 한 줄: VPN 클라이언트 상태 */
  wgClientSummary(): string | undefined {
    const c = this.wgClientCfg;
    if (!c?.enabled) return undefined;
    const p = this.wgcPeer;
    const state = !p ? "설정 확인 필요" : p.session ? `연결됨 · 터널 주소 ${c.address?.ip ?? "?"}` : p.pending ? "연결 중 (핸드셰이크)" : p.resolving ? "서버 이름을 푸는 중" : p.failed ? `끊김 (${p.failed.split(" — ")[0]}) · ${c.killSwitch ? "킬 스위치로 인터넷 차단 중" : "WAN 으로 바로 나가는 중 (킬 스위치 꺼짐)"}` : "대기 (보낼 패킷이 생기면 연결)";
    const server = c.serverName ? `${c.serverName.name}${p?.endpoint ? ` = ${p.endpoint.ip}` : ""}:${c.serverName.port}` : c.server ? `${c.server.ip}:${c.server.port}` : "없음";
    return `${state} · 서버 ${server}`;
  }

  private handleIcmp(pkt: Ipv4Packet, icmp: IcmpPacket, frameId: number, ctx: NodeContext, iface: NetInterface, emit: Emit, replySrc?: Ip): void {
    if (icmp.type !== "echo-request") {
      ctx.trace("ip.drop", "L3", `요청한 적 없는 ICMP ${icmpLabel(icmp)} → 무시`, {}, frameId);
      return;
    }
    ctx.trace("icmp.echo.received", "app", `ICMP Echo 요청 수신 (from ${pkt.src}, seq=${icmp.seq})`, { from: pkt.src, seq: icmp.seq }, frameId);
    const reply: Ipv4Packet = { kind: "ipv4", src: replySrc ?? iface.ip!, dst: pkt.src, ttl: 64, payload: { kind: "icmp", type: "echo-reply", id: icmp.id, seq: icmp.seq } };
    ctx.trace("icmp.reply.sent", "app", `ICMP Echo 응답 생성 → ${pkt.src} (seq=${icmp.seq})`, { to: pkt.src, seq: icmp.seq });
    iface.sendIp(reply, ctx, emit);
  }

  // ---------- 타이머 ----------

  onTimer(tag: string, data: unknown, ctx: NodeContext): void {
    if (tag === WG_TIMER_TAG) {
      if (!this.wgs.onTimer(data, ctx)) this.wgc.onTimer(data, ctx);
      return;
    }
    if (tag === DDNS_TIMER_TAG) {
      this.ddns.onTimer(data, ctx);
      return;
    }
    if (tag === MWAN_TIMER_TAG) {
      this.mwan.onTimer(data, ctx);
      return;
    }
    if (tag === DNS_TIMER_TAG) {
      this.resolver.onTimeout(data, ctx, this.emitWan(ctx));
      return;
    }
    if (tag === DAD_TIMER_TAG) {
      if (!this.lan6.finishDad(data, ctx, this.emitLan(ctx))) this.wan6.finishDad(data, ctx, this.emitWan(ctx));
      return;
    }
    if (tag === RS_TIMER_TAG) {
      this.wan6.onRsTimer(data, ctx, this.emitWan(ctx));
      return;
    }
    if (tag === ROUTER_EXPIRY_TAG) {
      this.wan6.onRouterExpiry(data, ctx);
      return;
    }
    if (tag === RA_PERIODIC_TAG) {
      this.lan6.onRaTick(data, ctx, this.emitLan(ctx));
      return;
    }
    if (tag === DHCP6_TIMER_TAG) {
      this.pd.onTimer(data, ctx, this.emitWan(ctx));
      return;
    }
    if (tag === NDP_TIMEOUT_TAG) {
      // 바깥에서 LAN 호스트로 가려던 패킷의 주인이 없음 → 보낸 이에게 Address Unreachable (WAN 으로)
      for (const pkt of this.lan6.onNsTimeout(data, ctx)) {
        if (this.lan6.onLink(pkt.src)) continue;
        const notice = this.wan6.unreachable(pkt, "host", ctx);
        if (notice) this.wan6.send(notice, ctx, this.emitWan(ctx));
      }
      this.wan6.onNsTimeout(data, ctx);
      return;
    }
    if (tag === "arp-timeout") {
      // 바깥에서 들어와(포트 포워딩·NAT 역변환) LAN 호스트로 가려던 패킷의 주인이 없음 → 바깥의 보낸 이에게 Host Unreachable
      for (const pkt of this.lan.onArpTimeout(data, ctx)) {
        if (this.vpnServer.owns(pkt.src)) {
          // VPN 기기가 보낸 것: 통지는 LAN 주소에서 그 기기로 (lan.outbound 가 터널에 싣는다)
          const notice = this.lan.unreachable(pkt, "host", ctx);
          if (notice) this.lan.sendIp(notice, ctx, this.emitLan(ctx));
          continue;
        }
        if (sameSubnet(pkt.src, this.lan.ip!, this.lan.prefix)) continue;
        // 들어온 회선으로 되돌린다 (멀티 WAN: 그 흐름의 응답이 어느 회선 NAT 에 있나)
        const p0 = pkt.payload;
        const reply: Ipv4Packet = { ...pkt, src: pkt.dst, dst: pkt.src, payload: p0.kind === "tcp" || p0.kind === "udp" ? { ...p0, srcPort: p0.dstPort, dstPort: p0.srcPort } : p0 } as Ipv4Packet;
        const l = this.wan2On && this.nat2.carries(reply) ? this.line("wan2", ctx) : this.line("wan", ctx);
        if (!l.iface.ip) continue;
        const notice = this.lan.unreachable(pkt, "host", ctx);
        const out = notice ? l.nat.translate(notice, l.iface.ip, ctx) : undefined;
        if (out) l.iface.sendIp(out, ctx, l.emit);
      }
      this.wan.onArpTimeout(data, ctx);
      this.wan2.onArpTimeout(data, ctx);
      return;
    }
    if (tag === "arp-probe") {
      const mac = (data as { mac: string }).mac;
      if (mac === this.lan.mac) this.lan.finishProbe(ctx, this.emitLan(ctx));
      else if (mac === this.wan.mac) {
        this.wan.finishProbe(ctx, this.emitWan(ctx));
        this.onWanAddress(ctx);
      } else if (mac === this.wan2.mac) this.wan2.finishProbe(ctx, this.emitWan2(ctx));
      return;
    }
    if (tag === DHCP_TIMER_TAG && this.wanClient.ownsTimer(data)) {
      this.wanClient.onTimeout(data, ctx, this.emitWan(ctx));
      this.mwan.onLine("wan", ctx); // DHCP 가 끝내 실패하면 기다리던 WAN1 을 포기하고 예비 회선으로
    }
    if (tag === DHCP_TIMER_TAG && this.wan2Client.ownsTimer(data)) {
      this.wan2Client.onTimeout(data, ctx, this.emitWan2(ctx));
      this.mwan.onLine("wan2", ctx);
    }
    if (tag === DNS_UPSTREAM_TIMER_TAG) this.dnsForwarder.onTimeout(data, ctx, this.emitLan(ctx));
  }

  // ---------- 스냅샷 ----------

  snapshot(): NodeSnapshot {
    const wanState = this.wan.ip
      ? `${this.wan.ip}/${this.wan.prefix}`
      : !this.wanLinkUp
        ? "없음 (링크 다운)"
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
        ["DNS 포워더", this.dnsForwarder.config.enabled ? `켜짐 · 업스트림 ${this.dnsForwarder.config.upstream ?? "없음"}` : "꺼짐"],
        ["무선", this.wifi.enabled ? `켜짐 · SSID ${this.wifi.ssid}` : "꺼짐"],
        ["방화벽", this.firewall.config.enabled ? `켜짐 · 규칙 ${this.firewall.config.rules.length}개 · 기본 ${this.firewall.config.defaultPolicy === "allow" ? "허용" : "차단"}` : "꺼짐"],
        ["NAT", `${NAT_TYPE_LABEL[this.nat.type]}${this.hairpin ? " · 헤어핀 NAT 켜짐" : ""}`],
        ...(this.ipv6Enabled
          ? ([
              ["WAN IPv6", this.wan6.summary() || "없음"],
              ["IPv6 기본 게이트웨이", this.wan6.defaultRouter ? `${this.wan6.defaultRouter} (ISP 의 RA)` : "없음"],
              ["프리픽스 위임", this.pd.delegated ? `${this.pd.delegated.prefix}/${this.pd.delegated.length} (DHCPv6-PD)` : DHCP6_STATE_LABEL[this.pd.state]],
              ["LAN IPv6", this.lan6.addrs.some((a) => a.origin === "manual") ? `${this.lan6.summary()} · RA 로 알림` : "없음 (위임 대기)"],
              ["IPv6 인바운드 기본 차단", this.inbound6.config.enabled ? "켜짐 (Stateful — 안에서 시작한 통신의 응답만)" : "꺼짐 (바깥에서 바로 들어옴)"],
            ] as [string, string][])
          : []),
        ...(this.vpnServer.config.enabled
          ? ([["VPN 서버", `켜짐 (L2TP/IPsec) · 할당 IP ${this.vpnServer.config.poolStart} ~ ${this.vpnServer.config.poolEnd} · ${this.vpnServer.clientsLabel()}`]] as [string, string][])
          : []),
        ...(this.wgServerCfg?.enabled
          ? ([["WireGuard 서버", `켜짐 · ${this.wgServerCfg.address ? `${this.wgServerCfg.address.ip}/${this.wgServerCfg.address.prefix}` : "터널 주소 없음"} · UDP ${this.wgServerCfg.listenPort} · 공개 키 ${shortKey(this.wgs.publicKey)} · 피어 ${this.wgServerCfg.peers.length}개 중 ${this.wgs.connected}개 연결`]] as [string, string][])
          : []),
        ...(this.wgClientCfg?.enabled ? ([["WireGuard 클라이언트", this.wgClientSummary()!]] as [string, string][]) : []),
        ...(this.ddns.config.enabled ? ([["DDNS", this.ddns.summary()!]] as [string, string][]) : []),
        ...(this.dpi.config.enabled ? ([["DPI", `켜짐${this.dpi.config.blockCategories.length + this.dpi.config.blockApps.length ? ` · 차단 ${[...this.dpi.config.blockCategories, ...this.dpi.config.blockApps.map((a) => APPS[a].label)].join(", ")}` : " · 세기만"}`]] as [string, string][]) : []),
        ...(this.adguard.config.enabled ? ([["AdGuard Home", `${this.adguard.summary()}${this.adguard.config.forceDns ? " · DNS 가로채기" : ""}`]] as [string, string][]) : []),
        ...(this.wan2On
          ? ([
              ["WAN2 (lan4)", this.wan2.ip ? `${this.wan2.ip}/${this.wan2.prefix}` : !this.wan2LinkUp ? "없음 (링크 다운)" : this.wan2Mode === "dhcp" ? `없음 (DHCP: ${DHCP_STATE_LABEL[this.wan2Client.state]})` : "없음 (수동 입력 필요)"],
              ["멀티 WAN", `${WAN_LABEL[this.mwan.active]} 사용 중 · WAN1 ${this.mwan.lines.wan.online ? "살아 있음" : "끊김"} · WAN2 ${this.mwan.lines.wan2.online ? "살아 있음" : "끊김"}${this.mwan.track ? ` · 추적 ${this.mwan.track}` : " · 추적 안 함"}`],
            ] as [string, string][])
          : []),
      ],
      tables: [
        { title: "DHCP 임대", columns: ["IP", "MAC", "시각"], rows: this.dhcpServer.rows() },
        ...(this.dnsForwarder.cache.size > 0 ? [{ title: "DNS 캐시", columns: ["이름", "IP", "출처"], rows: this.dnsForwarder.rows() }] : []),
        ...(this.dpi.config.enabled ? [{ title: "DPI 앱별 트래픽", columns: ["기기", "앱", "카테고리", "트래픽"], rows: this.dpi.rows() }] : []),
        ...(this.adguard.config.enabled ? [{ title: "AdGuard 쿼리 로그", columns: ["시각", "기기", "질의", "결과"], rows: this.adguard.rows() }] : []),
        { title: this.wan2On ? "NAT 테이블 (WAN1)" : "NAT 테이블", columns: ["내부", "→ 외부", "시각"], rows: this.nat.rows(this.wan.ip) },
        ...(this.wan2On
          ? [
              { title: "NAT 테이블 (WAN2)", columns: ["내부", "→ 외부", "시각"], rows: this.nat2.rows(this.wan2.ip) },
              { title: "멀티 WAN (mwan3 status)", columns: ["회선", "상태", "사용", "추적"], rows: this.mwan.rows() },
            ]
          : []),
        ...(this.vpnServer.config.enabled ? [{ title: "VPN 접속", columns: ["사용자", "할당 IP", "접속 주소", "방식"], rows: this.vpnServer.rows() }] : []),
        ...(this.wgServerCfg?.enabled ? [{ title: "WireGuard 서버 피어 (wg show)", columns: ["피어", "공개 키", "엔드포인트", "AllowedIPs", "최근 핸드셰이크", "전송"], rows: this.wgs.rows() }] : []),
        ...(this.wgClientCfg?.enabled ? [{ title: "WireGuard 클라이언트 (wg show)", columns: ["피어", "공개 키", "엔드포인트", "AllowedIPs", "최근 핸드셰이크", "전송"], rows: this.wgc.rows() }] : []),
        ...(this.wgClientCfg?.enabled ? [{ title: "NAT 테이블 (VPN 터널)", columns: ["내부", "→ 터널 주소", "시각"], rows: this.natVpn.rows(this.wgClientCfg.address?.ip) }] : []),
        { title: "포트 포워딩", columns: ["공인 포트", "내부"], rows: this.nat.forwardRows(this.wan.ip) },
        ...(this.firewall.config.enabled ? [{ title: "방화벽 규칙", columns: ["#", "규칙"], rows: this.firewall.rows() }] : []),
        {
          title: "내부 스위치 MAC 테이블",
          columns: ["MAC", "포트", "학습 시각"],
          rows: [...this.macTable.entries()].map(([mac, e]) => [mac, Router.portName(e.port), `${e.learnedAt}ms`]),
        },
        { title: "ARP 캐시 (LAN)", columns: ["IP", "MAC", "학습 시각"], rows: this.lan.arpRows() },
        { title: "ARP 캐시 (WAN)", columns: ["IP", "MAC", "학습 시각"], rows: this.wan.arpRows() },
        ...(this.ipv6Enabled
          ? [
              { title: "IPv6 주소", columns: ["인터페이스", "주소", "상태"], rows: [...this.lan6.addrRows().map((r) => ["lan", r[0]!, `${r[1]} · ${r[2]}`]), ...this.wan6.addrRows().map((r) => ["wan", r[0]!, `${r[1]} · ${r[2]}`])] },
              { title: "이웃 캐시 (LAN)", columns: ["IPv6", "MAC", "학습 시각"], rows: this.lan6.neighborRows() },
              { title: "이웃 캐시 (WAN)", columns: ["IPv6", "MAC", "학습 시각"], rows: this.wan6.neighborRows() },
            ]
          : []),
      ],
    };
  }
}

/** 규칙 목록 비교용 키 (순서 포함) */
function forwardsKey(rules: PortForward[]): string {
  return rules.map((r) => `${r.proto ?? "tcp"}:${r.publicPort}>${r.lanIp}:${r.lanPort}`).join(",");
}
