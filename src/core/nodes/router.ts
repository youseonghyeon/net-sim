import { BROADCAST_MAC, isMulticastMac, sameSubnet, type Ip, type Mac } from "../addr";
import { ALL_NODES, formatIp6, isLinkLocal6, isMulticast6, parseIp6, sameSubnet6, UNSPECIFIED6 } from "../addr6";
import {
  DHCP_CLIENT_PORT,
  DHCP_SERVER_PORT,
  DHCP6_CLIENT_PORT,
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
import { DNS_UPSTREAM_TIMER_TAG, DnsServer, type DnsServerConfig } from "./dns";
import { Firewall, type FirewallConfig } from "./firewall";
import { L2tpServer, type L2tpServerConfig } from "./l2tp";
import { PortPublish } from "./publish";
import { hashCode } from "./host";
import { NetInterface, type Emit } from "./iface";
import { NAT_ID_START, NAT_TYPE_LABEL, NatTable, type NatType, type PortForward } from "./nat";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";
import { guardLoop } from "./switch";

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
}

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
        // 업스트림 DNS 가 LAN 안에 있으면 LAN 으로, 아니면 WAN 으로
        srcIp: () => (this.upstreamInLan() ? this.lan.ip : this.wan.ip),
        send: (pkt, ctx) => (this.upstreamInLan() ? this.lan.sendIp(pkt, ctx, this.emitLan(ctx)) : this.wan.sendIp(pkt, ctx, this.emitWan(ctx))),
      },
      this.lan6, // LAN 호스트가 IPv6(RA 의 RDNSS = 공유기 LAN 주소)로 물어도 답한다
    );
    if (cfg.forwards) this.nat.setForwards(cfg.forwards);
    if (cfg.natType) this.nat.type = cfg.natType;
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
    this.lan.outbound = (pkt, ctx) => !!this.wan.ip && this.vpnServer.owns(pkt.dst) && this.vpnServer.sendTo(pkt, this.wan.ip, ctx);
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
      for (const p of Router.BRIDGE_PORTS) if (ctx.isPortConnected(p)) ctx.send(p, frame);
    };
  }

  private emitWan(ctx: NodeContext): Emit {
    return (frame) => ctx.send(Router.WAN_PORT, frame);
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
    },
    ctx: NodeContext,
  ): void {
    if (cfg.hairpin !== undefined && cfg.hairpin !== this.hairpin) {
      this.hairpin = cfg.hairpin;
      ctx.trace("ip.config", "sys", cfg.hairpin ? `헤어핀 NAT 켜짐: 안에서 내 공인 주소의 포워딩 포트로 접속하면 안쪽 서버로 되돌려 준다 (도메인으로 집 서버에 접속하기)` : `헤어핀 NAT 꺼짐`, { hairpin: cfg.hairpin });
    }
    if (cfg.natType && cfg.natType !== this.nat.type) {
      const from = this.nat.type;
      const n = this.nat.setType(cfg.natType);
      ctx.trace("ip.config", "sys", `NAT 종류 변경: ${NAT_TYPE_LABEL[from]} → ${NAT_TYPE_LABEL[cfg.natType]} (매핑 방식이 바뀌어 NAT 매핑 ${n}개를 지움)`, { natType: cfg.natType });
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
    if (this.ipv6Enabled) {
      if (this.wanLinkUp) this.pd.release(ctx, this.emitWan(ctx));
      this.lan6.shutdown(ctx, this.emitLan(ctx));
    }
    if (this.wanLinkUp) this.wanClient.release(ctx, this.emitWan(ctx));
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    if (up && port !== Router.WAN_PORT) this.startLan6(ctx);
    if (port === Router.WAN_PORT) {
      this.wanLinkUp = up;
      if (up) {
        ctx.trace("link.up", "L1", `wan 포트 링크 연결됨`, { port });
        if (this.wanMode === "dhcp") this.wanClient.start(ctx, this.emitWan(ctx));
        this.wan6.linkUp(ctx, this.emitWan(ctx));
        return;
      }
      ctx.trace("link.down", "L1", `wan 포트 링크 다운`, { port });
      this.wan6.linkDown();
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
    const ports = Router.BRIDGE_PORTS.filter((p) => p !== inPort && ctx.isPortConnected(p));
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
      else this.forwardToWan(pkt, frame.id, ctx);
      return;
    }
    if (pkt.dst === this.lan.ip || (this.wan.ip && pkt.dst === this.wan.ip)) {
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
      if (udp.dstPort === DHCP_CLIENT_PORT) this.wanClient.handle(m, frameId, ctx, emit);
      else if (udp.dstPort === DHCP_SERVER_PORT) ctx.trace("dhcp.ignore", "app", `[wan] 다른 장치의 DHCP ${m.op} → 무시`, {}, frameId);
      else ctx.trace("ip.drop", "L4", `[wan] UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 드롭`, { port: udp.dstPort }, frameId);
      return;
    }
    if (pkt.dst !== this.wan.ip) {
      ctx.trace("ip.drop", "L3", `[wan] 목적지 ${pkt.dst} 는 내 공인 주소(${this.wan.ip ?? "없음"}) 아님 → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
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
    if (!this.firewall.check(restored, "in", ctx, frameId)) return;
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
    if (!this.wan.ip) {
      ctx.trace("ip.no-route", "L3", `${pkt.dst} 는 외부 주소인데 WAN 에 공인 주소가 없음 → 인터넷으로 보낼 수 없음 (WAN 케이블과 DHCP 확인)`, { dst: pkt.dst }, frameId);
      const notice = this.lan.unreachable(pkt, "net", ctx, frameId);
      if (notice) this.lan.sendIp(notice, ctx, this.emitLan(ctx));
      return;
    }
    if (!this.firewall.check(pkt, "out", ctx, frameId)) return;
    const translated = this.nat.translate({ ...pkt, ttl: pkt.ttl - 1 }, this.wan.ip, ctx, frameId);
    if (!translated) return;
    ctx.trace("ip.forward", "L3", `라우팅: ${pkt.dst} 는 외부 → WAN 인터페이스로 전달 (TTL ${pkt.ttl} → ${translated.ttl})`, { dst: pkt.dst }, frameId);
    this.wan.sendIp(translated, ctx, this.emitWan(ctx));
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
        if (!this.wan.ip || sameSubnet(pkt.src, this.lan.ip!, this.lan.prefix)) continue;
        const notice = this.lan.unreachable(pkt, "host", ctx);
        const out = notice ? this.nat.translate(notice, this.wan.ip, ctx) : undefined;
        if (out) this.wan.sendIp(out, ctx, this.emitWan(ctx));
      }
      this.wan.onArpTimeout(data, ctx);
      return;
    }
    if (tag === "arp-probe") {
      const mac = (data as { mac: string }).mac;
      if (mac === this.lan.mac) this.lan.finishProbe(ctx, this.emitLan(ctx));
      else if (mac === this.wan.mac) this.wan.finishProbe(ctx, this.emitWan(ctx));
      return;
    }
    if (tag === DHCP_TIMER_TAG && this.wanClient.ownsTimer(data)) this.wanClient.onTimeout(data, ctx, this.emitWan(ctx));
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
      ],
      tables: [
        { title: "DHCP 임대", columns: ["IP", "MAC", "시각"], rows: this.dhcpServer.rows() },
        ...(this.dnsForwarder.cache.size > 0 ? [{ title: "DNS 캐시", columns: ["이름", "IP", "출처"], rows: this.dnsForwarder.rows() }] : []),
        { title: "NAT 테이블", columns: ["내부", "→ 외부", "시각"], rows: this.nat.rows(this.wan.ip) },
        ...(this.vpnServer.config.enabled ? [{ title: "VPN 접속", columns: ["사용자", "할당 IP", "접속 주소", "방식"], rows: this.vpnServer.rows() }] : []),
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
