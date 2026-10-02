// 순수 L3 장치: 인터페이스 N개 사이를 라우팅한다. 게이트웨이(NAT 없음)와 NAT 박스(outside 인터페이스에서 변환)가 이 클래스다.
import { isMulticastMac, networkOf, sameSubnet, type Ip, type Mac } from "../addr";
import { ALL_NODES, ALL_ROUTERS, isLinkLocal6, isMulticast6, network6, sameSubnet6, UNSPECIFIED6 } from "../addr6";
import {
  DHCP_CLIENT_PORT,
  DHCP_SERVER_PORT,
  describeFrame,
  icmpLabel,
  LIMITED_BROADCAST_IP,
  RIP_MULTICAST_MAC,
  RIP_PORT,
  VRRP_MULTICAST_MAC,
  PFSYNC_MULTICAST_MAC,
  type DhcpMessage,
  type EthernetFrame,
  type IcmpPacket,
  type Ipv4Packet,
  type Ipv6Packet,
  icmpv6Label,
  isNdp,
} from "../packet";
import { DHCP_STATE_LABEL, DHCP_TIMER_TAG, DhcpClient } from "./dhcp";
import { hashCode } from "./host";
import { NetInterface, type Emit } from "./iface";
import { Firewall, type FirewallConfig, type FlowDirection } from "./firewall";
import { NAT_TYPE_LABEL, NatTable, type NatType, type PortForward } from "./nat";
import { PortPublish, type PublishRule } from "./publish";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";
import { Rip, RIP_TIMER_TAG, type RipConfig } from "./rip";
import { HA_TIMER_TAG, Ha, type HaConfig } from "./ha";
import { IKE_TIMER_TAG, VPN_DPD_TAG, VPN_MODE_LABEL, Vpn, type VpnConfig } from "./vpn";
import { RaServer, type RaServerConfig } from "./ravpn";
import { TunnelEnds } from "./l3tunnel";
import { HA_SYNC_TAG, SessionSync } from "./hasync";
import { DAD_TIMER_TAG, Ipv6Interface, NDP_TIMEOUT_TAG, RA_PERIODIC_TAG } from "./ipv6";


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
  /** 동적 라우팅 (RIPv2 축소판) */
  rip?: RipConfig;
  /** 사이트 간 VPN (WireGuard 식) */
  vpn?: VpnConfig;
  /** IPv6 라우팅 (없으면 꺼짐) */
  ipv6?: L3Ipv6Config;
  /** 게이트웨이의 NAT (MASQUERADE): 켜면 if0 이 바깥(outside) — 도커 호스트·맥처럼 라우터가 아닌 컴퓨터가 안쪽 네트워크를 내보낼 때. NAT 박스는 늘 켜짐 */
  nat?: { enabled: boolean };
  /** 포트 공개 (docker -p 식, 장비 자신의 어느 주소로 와도) */
  publish?: PublishRule[];
  /** NAT 종류 (없으면 full cone) */
  natType?: NatType;
  /** 헤어핀 NAT (NAT 루프백). 없으면 꺼짐 */
  hairpin?: boolean;
}

/** 게이트웨이·NAT 박스의 IPv6: 켜면 물리 인터페이스마다 링크 로컬이 생기고, 인터페이스별 수동 주소와 IPv6 스태틱 라우팅(::/0 = 디폴트 라우트)으로 전달한다 */
export interface L3Ipv6Config {
  enabled: boolean;
  /** 물리 인터페이스별 주소 (인덱스 = 인터페이스). ip 가 없으면 링크 로컬만. ra = 이 인터페이스로 RA 를 보냄 (SLAAC) */
  interfaces: { ip?: Ip; prefix?: number; ra?: boolean }[];
  routes: StaticRoute[];
  /** RA 의 RDNSS 로 알릴 DNS 서버 */
  raDns?: Ip;
  /** 주기 RA (10초, 라우터 수명 30초 — 배경 타이머) */
  raPeriodic?: boolean;
}

interface Route6 {
  out: number;
  nextHop: Ip;
  kind: "connected" | "static" | "default";
  prefix: number;
}

interface Route {
  out: number;
  nextHop: Ip;
  kind: "connected" | "static" | "default" | "rip" | "vpn" | "ra";
  /** RIP 경로의 홉 수 */
  metric?: number;
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
  nat: NatTable | undefined;
  outside: number | undefined;
  /** NAT 종류 (NAT 를 켤 때 쓴다) */
  natType: NatType = "full-cone";
  /** 헤어핀 NAT: 안에서 바깥 주소의 포워딩 포트로 온 연결을 안쪽 서버로 되돌림 */
  hairpin = false;
  private readonly hairpinNat: PortPublish = new PortPublish(
    {
      owns: (ip) => this.outside !== undefined && ip === this.addrOf(this.outside),
      sourceFor: (dst) => {
        const r = this.route(dst);
        return r && r.kind !== "vpn" && r.kind !== "ra" ? this.addrOf(r.out) : undefined;
      },
      send: (pkt, _inPort, frameId, ctx) => this.sendPublished(pkt, frameId, ctx),
    },
    true,
  );
  routes: StaticRoute[];
  /** 인터페이스별 DHCP 릴레이 대상 서버 */
  relays: (Ip | undefined)[];
  readonly firewall: Firewall;
  /** 동적 라우팅 (RIP). 꺼져 있으면 아무것도 보내지 않는다 */
  readonly rip: Rip;
  /** 사이트 간 VPN 터널 */
  readonly ha: Ha = new Ha({
    ifaceCount: () => this.ifaces.length,
    ifaceName: (i) => this.names[i]!,
    ifaceIp: (i) => (this.ifaces[i]?.usable ? this.ifaces[i]!.ip : undefined),
    linkUp: (i) => this.linkUp[i] === true,
    send: (i, pkt, ctx, srcMac) => this.ifaces[i]!.sendToMac(VRRP_MULTICAST_MAC, pkt, ctx, this.emit(i, ctx), srcMac),
    setVip: (i, vip, ctx) => {
      const iface = this.ifaces[i];
      if (!iface) return;
      iface.vip = vip;
      if (vip) iface.announceVip(ctx, this.emit(i, ctx));
      this.rip.kick(ctx); // RIP 넥스트 홉(가상 주소)을 다시 알린다
    },
    onBackupSeen: (ctx) => this.sessionSync.bulk(ctx),
    onHandover: (ctx) => this.sessionSync.bulk(ctx, true),
    // 세션 동기화는 IPsec SA 를 복사하지 않는다: 물러난 장비가 옛 SA 를 들고 있으면 DPD·ESP 에 엉뚱하게 답하므로 비운다
    onResign: (ctx) => {
      this.vpn.dropSa(ctx, "이중화 master 에서 물러남");
      this.ra.dropAll(ctx, "이중화 master 에서 물러남");
    },
  });
  /** 포트 공개 (docker -p 식): 내 주소로 온 TCP 를 안쪽 대상으로 (FULLNAT) */
  readonly publish: PortPublish = new PortPublish({
    owns: (ip) => this.ownIndex(ip) >= 0,
    sourceFor: (dst) => {
      const r = this.route(dst);
      return r && r.kind !== "vpn" && r.kind !== "ra" ? this.addrOf(r.out) : undefined;
    },
    send: (pkt, _inPort, frameId, ctx) => this.sendPublished(pkt, frameId, ctx),
  });
  /** 이중화 세션 동기화 (pfsync 식) */
  private readonly sessionSync: SessionSync = new SessionSync({
    ha: this.ha,
    nat: () => this.nat,
    firewall: () => this.firewall,
    syncIface: () => {
      const ifs = this.ha.config.vips.map((v, i) => (v && this.linkUp[i] && this.ifaces[i]?.usable ? i : -1)).filter((i) => i >= 0);
      return ifs.find((i) => i !== this.outside) ?? ifs[0];
    },
    ifaceIp: (i) => this.ifaces[i]?.ip,
    ifaceName: (i) => this.names[i]!,
    send: (i, pkt, ctx) => this.ifaces[i]!.sendToMac(PFSYNC_MULTICAST_MAC, pkt, ctx, this.emit(i, ctx)),
  });
  /** VPN 이 장치에 부탁하는 바깥 송신 (사이트 간·원격 접속이 같이 쓴다): 바깥 경로로, NAT 하지 않음, 출발지는 가상 주소 우선 */
  private readonly tunnelIo = {
    source: (dst: Ip) => {
      const u = this.underlay(dst);
      return u ? this.addrOf(u.out) : undefined;
    },
    /** 가상 주소가 아닌 이 장비의 실제 주소 (이중화 쌍의 SPI 가 겹치지 않게) */
    realSource: (dst: Ip) => {
      const u = this.underlay(dst);
      return u ? this.ifaces[u.out]?.ip : undefined;
    },
    send: (outer: Ipv4Packet, ctx: NodeContext, frameId?: number) => {
      const u = this.underlay(outer.dst);
      if (!u) {
        ctx.trace("vpn.drop", "L3", `VPN: 상대 ${outer.dst} 로 가는 바깥 경로가 없음 → 드롭 (디폴트 라우트를 확인)`, { dst: outer.dst }, frameId);
        return;
      }
      this.ifaces[u.out]!.sendIp(outer, ctx, this.emit(u.out, ctx), u.nextHop);
    },
  };
  /** 원격 접속 VPN 서버 */
  readonly ra: RaServer = new RaServer(this.tunnelIo);
  readonly vpn: Vpn = new Vpn(this.tunnelIo);
  /** 사이트 간·원격 접속 VPN 의 터널 끝 (받은 터널 패킷 나누기·풀기, 터널로 보내기) */
  private readonly tunnels = new TunnelEnds({
    vpn: this.vpn,
    ra: this.ra,
    ownIndex: (ip) => this.ownIndex(ip),
    addrOf: (i) => this.addrOf(i),
    underlay: (dst) => this.underlay(dst),
    sendOut: (i, pkt, nextHop, ctx) => this.ifaces[i]!.sendIp(pkt, ctx, this.emit(i, ctx), nextHop),
    deliverLocal: (i, inner, frameId, ctx) => this.handleIcmp(i, inner, inner.payload as IcmpPacket, frameId, ctx),
    publishLocal: (port, inner, frameId, ctx) => this.publish.handle(port, inner, frameId, ctx),
    forwardInner: (inner, inPort, frameId, ctx) => this.forward(inner, inPort, frameId, ctx, inner, true),
  });
  /** 인터페이스 i 가 붙은 물리 포트와 VLAN 태그. 물리 인터페이스는 i === port, 서브 인터페이스는 그 뒤에 붙는다 */
  meta: { port: number; vlan?: number }[];
  private readonly macBase: Mac;
  /** 물리 인터페이스별 IPv6 (서브 인터페이스에는 없다) */
  readonly v6: Ipv6Interface[];
  ipv6Enabled = false;
  /** IPv6 스태틱 라우팅 (prefix 0 = 디폴트 라우트 ::/0) */
  routes6: StaticRoute[] = [];

  constructor(cfg: L3Config) {
    this.id = cfg.id;
    this.type = cfg.kind;
    this.portCount = cfg.interfaces.length;
    this.names = cfg.interfaces.map((i) => i.name);
    this.modes = cfg.interfaces.map((i) => i.mode);
    this.ifaces = cfg.interfaces.map((i) => new NetInterface(i.mac, i.mode === "static" ? { ip: i.ip, prefix: i.prefix ?? 24, gateway: i.gateway } : {}));
    this.clients = cfg.interfaces.map((i, idx) => (i.mode === "dhcp" ? new DhcpClient(this.ifaces[idx]!, hashCode(cfg.id) + idx * 13, i.name) : undefined));
    this.linkUp = cfg.interfaces.map(() => false);
    const natOn = cfg.kind === "nat" || cfg.nat?.enabled === true;
    this.outside = cfg.kind === "nat" ? (cfg.outside ?? 0) : natOn ? 0 : undefined;
    this.nat = natOn ? new NatTable() : undefined;
    this.natType = cfg.natType ?? "full-cone";
    this.hairpin = cfg.hairpin === true;
    if (this.nat) this.nat.type = this.natType;
    if (cfg.publish) this.publish.rules = cfg.publish.map((r) => ({ ...r }));
    this.routes = [...(cfg.routes ?? [])];
    this.relays = cfg.interfaces.map((i) => i.relay);
    this.meta = cfg.interfaces.map((_, i) => ({ port: i }));
    this.macBase = cfg.interfaces[0]?.mac ?? "02:00:00:10:00:00";
    this.v6 = cfg.interfaces.map((c) => new Ipv6Interface(c.mac, true, c.name));
    if (cfg.ipv6?.enabled) {
      this.ipv6Enabled = true;
      this.v6.forEach((v, i) => {
        const c = cfg.ipv6!.interfaces[i];
        v.init({ enabled: true, addrs: c?.ip ? [{ ip: c.ip, prefix: c.prefix ?? 64 }] : [], ra: c?.ra === true, raDns: cfg.ipv6!.raDns, raPeriodic: cfg.ipv6!.raPeriodic === true });
      });
      this.routes6 = [...cfg.ipv6.routes];
    }
    if (this.nat && cfg.forwards) this.nat.setForwards(cfg.forwards);
    this.firewall = new Firewall(cfg.firewall);
    // 이중화 세션 동기화: master 가 새로 만든 매핑·흐름을 backup 에 복사한다
    if (this.nat) this.wireNat(this.nat);
    this.firewall.onFlow = (key, ctx) => this.sessionSync.queue({ nat: [], flows: [key] }, ctx);
    if (cfg.subinterfaces) this.setSubinterfaces(cfg.subinterfaces);
    const self = this; // 객체 리터럴 getter 안의 this 는 그 객체라 별칭으로 잡는다
    this.rip = new Rip({
      get ifaceCount() {
        return self.ifaces.length;
      },
      ifaceName: (i) => this.names[i]!,
      ifaceIp: (i) => this.ifaces[i]?.ip,
      ifacePrefix: (i) => this.ifaces[i]?.prefix ?? 24,
      participates: (i) => this.ripParticipates(i),
      staticDefaultOut: () => {
        const d = this.staticDefault();
        return d && this.linkUp[d.out] && this.ifaces[d.out]!.usable ? d.out : undefined;
      },
      advertisedNextHop: (i) => this.ifaces[i]?.vip?.ip,
      send: (i, pkt, ctx) => this.ifaces[i]!.sendToMac(RIP_MULTICAST_MAC, pkt, ctx, this.emit(i, ctx)),
    });
    if (cfg.rip) this.rip.config = { ...cfg.rip };
    if (cfg.vpn) this.vpn.config = { ...cfg.vpn, remote: cfg.vpn.remote.map((r) => ({ ...r })) };
  }

  setVpn(cfg: VpnConfig, ctx: NodeContext): void {
    this.vpn.setConfig(cfg, ctx);
  }

  /** 게이트웨이의 NAT 켜기·끄기 (NAT 박스는 늘 켜짐). 켜면 if0 이 바깥 — 안쪽에서 나가는 것의 출발지를 if0 주소로 바꾼다 */
  setNat(cfg: { enabled: boolean } | undefined, ctx: NodeContext): void {
    if (this.type === "nat") return;
    const on = cfg?.enabled === true;
    if (on === (this.nat !== undefined)) return;
    if (on) {
      // if0 은 이제 NAT 바깥이라 RIP 에서 빠진다 — 그 전에 이웃에게 if0 으로 알렸던 경로를 철회한다
      this.rip.retire(0, ctx);
      this.nat = new NatTable();
      this.nat.type = this.natType;
      this.outside = 0;
      this.wireNat(this.nat);
      ctx.trace("ip.config", "sys", `NAT 켜짐 (MASQUERADE): ${this.names[0]} 로 나가는 패킷의 출발지를 ${this.names[0]} 주소로 바꾸고, 바깥에서 안쪽 주소로 바로 오는 것은 막음`, { nat: true });
    } else {
      const n = this.nat!.entries.size;
      this.nat = undefined;
      this.outside = undefined;
      ctx.trace("ip.config", "sys", `NAT 꺼짐 → 주소를 바꾸지 않고 라우팅만 (NAT 매핑 ${n}개 지움)`, { nat: false });
    }
    this.rip.kick(ctx); // NAT outside 는 RIP 에 참여하지 않는다
  }

  setHairpin(on: boolean, ctx: NodeContext): void {
    if (on === this.hairpin) return;
    this.hairpin = on;
    ctx.trace("ip.config", "sys", on ? `헤어핀 NAT 켜짐: 안에서 바깥 주소의 포워딩 포트로 접속하면 안쪽 서버로 되돌려 준다` : `헤어핀 NAT 꺼짐`, { hairpin: on });
  }

  /** 안에서 내 바깥 주소로 온 TCP (헤어핀 NAT). 처리했으면 true */
  private hairpinTcp(port: number, pkt: Ipv4Packet, frameId: number, ctx: NodeContext): boolean {
    const seg = pkt.payload;
    if (seg.kind !== "tcp" || !this.nat || this.outside === undefined || port === this.outside) return false;
    const rules = this.nat.forwards.filter((r) => (r.proto ?? "tcp") === "tcp");
    if (this.hairpin) {
      this.hairpinNat.rules = rules.map((r) => ({ port: r.publicPort, bind: "0.0.0.0", to: r.lanIp, toPort: r.lanPort }));
      return this.hairpinNat.handle(port, pkt, frameId, ctx);
    }
    const outsideIp = this.addrOf(this.outside);
    const rule = pkt.dst === outsideIp ? rules.find((r) => r.publicPort === seg.dstPort) : undefined;
    if (!rule) return false;
    ctx.trace(
      "ip.drop",
      "L4",
      `헤어핀 NAT 꺼짐: 안쪽 ${pkt.src} 가 바깥 주소 ${pkt.dst}:${seg.dstPort} 로 접속 → 포트 포워딩은 바깥에서 온 연결에만 적용돼 드롭 (헤어핀 NAT 를 켜거나, 안에서는 ${rule.lanIp}:${rule.lanPort} 로 접속)`,
      { port: seg.dstPort, hairpin: false },
      frameId,
    );
    return true;
  }

  setNatType(type: NatType, ctx: NodeContext): void {
    if (type === this.natType) return;
    const from = this.natType;
    this.natType = type;
    const n = this.nat ? this.nat.setType(type) : 0;
    ctx.trace("ip.config", "sys", `NAT 종류 변경: ${NAT_TYPE_LABEL[from]} → ${NAT_TYPE_LABEL[type]}${this.nat ? ` (매핑 방식이 바뀌어 NAT 매핑 ${n}개를 지움)` : ""}`, { natType: type });
  }

  setPublish(rules: PublishRule[], ctx: NodeContext): void {
    this.publish.setRules(rules, ctx);
  }

  /** NAT 테이블 고리: 이중화 세션 동기화, 공인 포트로 포트 공개 포트를 고르지 않기 */
  private wireNat(nat: NatTable): void {
    nat.onNew = (e, c) => this.sessionSync.queue({ nat: [e], flows: [] }, c);
    nat.reserved = (port) => this.publish.reserved(port);
  }

  /**
   * 포트 공개가 바꾼 패킷을 보낸다: 장비 자신의 프로세스(docker-proxy)가 받고 다시 여는 연결이라 방화벽(지나가는 패킷 검사)·NAT 를 거치지 않는다
   * (실제 도커가 ufw 규칙을 우회하는 것과 같은 모양). TTL 이 다하면 통지 없이 드롭 — 출발지가 나 자신이라 통지가 나에게 돌아온다
   */
  private sendPublished(pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    if (pkt.ttl <= 1) {
      ctx.trace("ip.drop", "L3", `포트 공개: ${pkt.dst} 로 넘기려는 패킷의 TTL 이 다함 → 드롭 (공개 규칙이 서로를 가리키는 순환인지 확인)`, { dst: pkt.dst }, frameId);
      return;
    }
    const out: Ipv4Packet = { ...pkt, ttl: pkt.ttl - 1 };
    const r = this.route(pkt.dst);
    if (!r) {
      ctx.trace("ip.no-route", "L3", `포트 공개: ${pkt.dst} 로 가는 경로가 없음 → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    if (r.kind === "ra") {
      this.ra.sendTo(out, ctx, frameId);
      return;
    }
    if (r.kind === "vpn") {
      this.tunnels.send(out, ctx, frameId);
      return;
    }
    ctx.trace("ip.forward", "L3", `포트 공개: ${pkt.dst} → ${this.names[r.out]} (넥스트 홉 ${r.nextHop}), TTL ${pkt.ttl} → ${out.ttl}`, { dst: pkt.dst, out: this.names[r.out], kind: r.kind }, frameId);
    this.ifaces[r.out]!.sendIp(out, ctx, this.emit(r.out, ctx), r.nextHop);
  }

  /** IPv6 설정 교체: 인터페이스 주소는 바뀐 것만, 스태틱 라우팅은 추가·삭제를 기록 */
  setIpv6(cfg: L3Ipv6Config, ctx: NodeContext): void {
    this.ipv6Enabled = cfg.enabled;
    this.v6.forEach((v, i) => {
      const c = cfg.interfaces[i];
      v.configure({ enabled: cfg.enabled, addrs: c?.ip ? [{ ip: c.ip, prefix: c.prefix ?? 64 }] : [], ra: c?.ra === true, raDns: cfg.raDns, raPeriodic: cfg.raPeriodic === true }, this.linkUp[i] === true, ctx, this.emit(i, ctx));
    });
    const routes = cfg.enabled ? cfg.routes : [];
    const key = (r: StaticRoute) => `${r.dest}/${r.prefix} via ${r.via}`;
    const before = new Set(this.routes6.map(key));
    const after = new Set(routes.map(key));
    for (const r of routes) if (!before.has(key(r))) ctx.trace("ip.config", "sys", `IPv6 스태틱 라우팅 추가: ${key(r)}${r.prefix === 0 ? " (디폴트 라우트)" : ""}`, { ...r });
    for (const r of this.routes6) if (!after.has(key(r))) ctx.trace("ip.config", "sys", `IPv6 스태틱 라우팅 삭제: ${key(r)}`, { ...r });
    this.routes6 = [...routes];
  }

  /** 터널의 바깥(인터넷 쪽) 경로: VPN 경로를 빼고 찾는다 (상대 공인 주소가 터널 대역에 걸려 되돌아가지 않게) */
  private underlay(dst: Ip): Route | undefined {
    const r = this.route(dst, false);
    return r && r.kind !== "vpn" ? r : undefined;
  }

  setRa(cfg: RaServerConfig, ctx: NodeContext): void {
    this.ra.setConfig(cfg, ctx);
  }

  /** RIP 를 주고받는 인터페이스: 주소가 확정됨(Probe 끝·충돌 없음)·링크 업·NAT outside 아님 */
  private ripParticipates(i: number): boolean {
    const iface = this.ifaces[i];
    if (!iface?.ip || !iface.usable || iface.probing || !this.linkUp[i]) return false;
    return !(this.nat && i === this.outside);
  }

  setRip(cfg: RipConfig, ctx: NodeContext): void {
    this.rip.setConfig(cfg, ctx);
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
    /** 서브 인터페이스 옛 번호 → 새 번호 (RIP 경로의 나가는 인터페이스를 다시 매기기 위해) */
    const moved = new Map<number, number>();
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
          if (ctx && iface.ip) this.rip?.retire(existing, ctx);
          iface.configure(sub.ip, sub.prefix ?? 24, undefined);
          iface.arpCache.clear();
          iface.clearPending();
          ctx?.trace("ip.config", "sys", `[${name}] 서브 인터페이스 주소 변경: ${sub.ip ?? "없음"}/${sub.prefix ?? 24}`, { ...sub });
          if (ctx && iface.ip && this.linkUp[sub.port]) iface.claim(ctx, this.emit(existing, ctx));
        }
        keep.push(existing);
        moved.set(existing, nextMeta.length);
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
      if (keep.includes(i)) continue;
      if (ctx) this.rip?.retire(i, ctx); // 사라지기 전에 옛 주소로 철회
      ctx?.trace("ip.config", "sys", `[${this.names[i]}] 서브 인터페이스 삭제`, { index: i });
    }
    this.rip?.remap((old) => (old < physical ? old : moved.get(old)));
    this.meta = nextMeta;
    this.ifaces = nextIfaces;
    this.names = nextNames;
    this.modes = nextModes;
    this.clients = nextClients;
    this.linkUp = nextLinkUp;
    this.relays = nextRelays;
    if (ctx) this.rip?.kick(ctx);
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
    const key = (rs: PortForward[]) => rs.map((r) => `${r.proto ?? "tcp"}:${r.publicPort}>${r.lanIp}:${r.lanPort}`).join(",");
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
      if (iface.ip && (c.mode !== "static" || c.ip !== iface.ip || (c.prefix ?? 24) !== iface.prefix)) this.rip?.retire(i, ctx);
      this.modes[i] = c.mode;
      iface.arpCache.clear();
      iface.clearPending();
      if (c.mode === "static") {
        this.clients[i]?.stop();
        this.clients[i] = undefined;
        iface.configure(c.ip || undefined, c.prefix ?? 24, c.gateway || undefined);
        ctx.trace("ip.config", "sys", c.ip ? `[${name}] 수동 설정 적용: ${c.ip}/${c.prefix ?? 24}${c.gateway ? `, 게이트웨이 ${c.gateway}` : ""}` : `[${name}] 수동 설정으로 전환 (주소 미입력)`, { iface: name, ...c });
        if (this.linkUp[i] && iface.ip) iface.claim(ctx, this.emit(i, ctx));
      } else {
        iface.clearAddress();
        const client = new DhcpClient(iface, hashCode(this.id) + i * 13, name);
        this.clients[i] = client;
        ctx.trace("ip.config", "sys", `[${name}] 자동(DHCP) 로 전환`, { iface: name });
        if (this.linkUp[i]) client.start(ctx, this.emit(i, ctx));
      }
    });
    this.rip.kick(ctx);
    this.ha.onLinks(ctx); // 주소가 바뀌거나 없어지면 이중화 우선순위도 바뀐다
  }

  onRemove(ctx: NodeContext): void {
    this.v6.forEach((v, i) => v.shutdown(ctx, this.emit(i, ctx)));
    this.ha.shutdown(ctx);
    this.rip.shutdown(ctx);
    this.clients.forEach((c, i) => {
      if (c && this.linkUp[i]) c.release(ctx, this.emit(i, ctx));
    });
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    const name = this.names[port]!;
    if (up) ctx.trace("link.up", "L1", `${name} 링크 연결됨`, { port });
    else ctx.trace("link.down", "L1", `${name} 링크 다운`, { port });
    if (up) this.v6[port]?.linkUp(ctx, this.emit(port, ctx));
    else this.v6[port]?.linkDown();
    this.meta.forEach((m, i) => {
      if (m.port !== port) return;
      this.linkUp[i] = up;
      const iface = this.ifaces[i]!;
      if (up) {
        if (this.clients[i]) this.clients[i]!.start(ctx, this.emit(i, ctx));
        else if (iface.ip) iface.claim(ctx, this.emit(i, ctx));
        return;
      }
      iface.clearPending();
      if (this.clients[i]) {
        const had = iface.ip;
        iface.clearAddress();
        this.clients[i]!.stop();
        if (had) ctx.trace("dhcp.release", "app", `[${this.names[i]}] 링크 다운으로 주소 ${had} 해제`, { ip: had });
      }
    });
    this.rip.kick(ctx); // 링크가 죽으면 그쪽 경로를 철회, 살아나면 이웃에게 묻는다
    this.ha.onLinks(ctx); // 이중화: 추적하는 인터페이스가 죽으면 master 를 넘긴다
  }

  // ---------- 이중화 (HA) ----------

  /** 이 주소를 가진 인터페이스 (실제 주소 또는 HA master 로 가진 가상 주소). 없으면 -1 */
  private ownIndex(ip: Ip): number {
    return this.ifaces.findIndex((i) => (i.ip !== undefined && i.ip === ip) || i.vip?.ip === ip);
  }

  /** 인터페이스의 대표 주소: HA master 면 가상 주소 (NAT 공인 주소·VPN 터널 끝이 이것) */
  private addrOf(i: number): Ip | undefined {
    const f = this.ifaces[i];
    return f?.vip?.ip ?? f?.ip;
  }

  setHa(cfg: HaConfig, ctx: NodeContext): void {
    this.ha.setConfig(cfg, ctx);
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
    // 멀티캐스트: RIP 를 켰으면 RIP 그룹(224.0.0.9)만 받고, 나머지는 NIC 가 조용히 거른다
    const ripFrame = frame.dst === RIP_MULTICAST_MAC && this.rip.config.enabled;
    const vrrpFrame = (frame.dst === VRRP_MULTICAST_MAC && this.ha.config.enabled) || (frame.dst === PFSYNC_MULTICAST_MAC && this.ha.config.enabled && this.ha.config.sync === true);
    // IPv6 는 물리 인터페이스만 (서브 인터페이스는 IPv4 전용)
    const v6 = i < this.portCount ? this.v6[i] : undefined;
    const v6Group = v6?.accepts(frame.dst) === true;
    if (isMulticastMac(frame.dst) && !ripFrame && !vrrpFrame && !v6Group) return;
    if (!ripFrame && !vrrpFrame && !v6Group && !iface.accepts(frame)) {
      ctx.trace("frame.drop", "L2", `${name} 수신: 목적지 MAC ${frame.dst} 가 내 MAC 아님 → 드롭`, { dst: frame.dst }, frame.id);
      return;
    }
    ctx.trace("frame.receive", "L2", `${name} 수신: ${describeFrame(frame)} [${frame.src}]${rawFrame.vlan !== undefined ? ` (VLAN ${rawFrame.vlan} 태그 떼어냄)` : ""}`, { port, src: frame.src, vlan: rawFrame.vlan }, frame.id);
    if (frame.payload.kind === "arp") {
      iface.handleArp(frame.payload, frame.id, ctx, this.emit(i, ctx));
      return;
    }
    if (frame.payload.kind === "ipv4") this.handleIp(i, frame.payload, frame.id, ctx);
    else if (frame.payload.kind === "ipv6") {
      if (!v6?.enabled) ctx.trace("frame.drop", "L3", `${name} 에 IPv6 패킷 → ${v6 ? "이 장치는 IPv6 가 꺼져 있어" : "VLAN 서브 인터페이스는 IPv6 를 다루지 않아"} 드롭`, {}, frame.id);
      else if (isNdp(frame.payload.payload)) v6.handleNdp(frame.payload, frame.payload.payload, frame, ctx, this.emit(i, ctx));
      else this.handleIp6(i, frame.payload, frame.id, ctx);
    }
  }

  // ---------- IPv6 ----------

  /** 이 IPv6 주소를 가진 인터페이스. 링크 로컬은 받은 인터페이스 것만 (링크마다 따로라서). 없으면 -1 */
  private own6(ip: Ip, inIdx: number): number {
    if (isLinkLocal6(ip)) return this.v6[inIdx]?.owns(ip) ? inIdx : -1;
    return this.v6.findIndex((v) => v.owns(ip));
  }

  private handleIp6(i: number, pkt: Ipv6Packet, frameId: number, ctx: NodeContext): void {
    const name = this.names[i]!;
    const mine = this.own6(pkt.dst, i);
    const p = pkt.payload;
    if (mine >= 0 || pkt.dst === ALL_NODES || pkt.dst === ALL_ROUTERS) {
      if (p.kind === "icmp6" && p.type === "echo-request") {
        ctx.trace("icmp.echo.received", "app", `ICMPv6 Echo 요청 수신 (from ${pkt.src}, seq=${p.seq})`, { from: pkt.src, seq: p.seq }, frameId);
        const src = mine >= 0 ? pkt.dst : this.v6[i]!.sourceFor(pkt.src);
        if (!src) return;
        const reply: Ipv6Packet = { kind: "ipv6", src, dst: pkt.src, hopLimit: Ipv6Interface.HOP_LIMIT, payload: { kind: "icmp6", type: "echo-reply", id: p.id, seq: p.seq } };
        ctx.trace("icmp.reply.sent", "app", `ICMPv6 Echo 응답 생성 → ${pkt.src} (seq=${p.seq})`, { to: pkt.src, seq: p.seq });
        this.sendVia6(reply, ctx, frameId, i);
        return;
      }
      if (p.kind === "icmp6") ctx.trace("ip.drop", "L3", `요청한 적 없는 ICMPv6 ${icmpv6Label(p)} → 무시`, {}, frameId);
      else if (p.kind === "tcp") ctx.trace("ip.drop", "L4", `이 장치는 TCP 서비스를 열지 않음 → 드롭`, {}, frameId);
      else ctx.trace("ip.drop", "L4", `[${name}] UDP 포트 ${p.dstPort} 를 듣는 서비스 없음 → 드롭`, { port: p.dstPort }, frameId);
      return;
    }
    if (this.v6.some((v) => v.addrs.some((a) => a.ip === pkt.dst && a.state !== "preferred"))) {
      ctx.trace("ip.drop", "L3", `[${name}] ${pkt.dst} 는 내 주소지만 아직 쓰지 못함 (DAD 중이거나 중복) → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    this.forward6(pkt, i, frameId, ctx);
  }

  /** IPv6 라우팅 테이블 조회: 연결된 프리픽스 → IPv6 스태틱 라우팅 중 긴 마스크 (::/0 이 디폴트 라우트) */
  route6(dst: Ip): Route6 | undefined {
    for (let i = 0; i < this.v6.length; i++) {
      const v = this.v6[i]!;
      if (!v.enabled) continue;
      const a = v.addrs.find((x) => x.origin !== "link-local" && x.state !== "duplicate" && sameSubnet6(dst, x.ip, x.prefix));
      if (a) return { out: i, nextHop: dst, kind: "connected", prefix: a.prefix };
    }
    let best: Route6 | undefined;
    for (const r of this.routes6) {
      if (!sameSubnet6(dst, r.dest, r.prefix) || (best && best.prefix >= r.prefix)) continue;
      const out = this.ifaceFor6(r.via);
      if (out >= 0) best = { out, nextHop: r.via, kind: r.prefix === 0 ? "default" : "static", prefix: r.prefix };
    }
    return best;
  }

  /** IPv6 넥스트 홉이 속한(직접 연결된) 인터페이스 */
  private ifaceFor6(nextHop: Ip): number {
    return this.v6.findIndex((v) => v.enabled && v.addrs.some((a) => a.origin !== "link-local" && a.state !== "duplicate" && sameSubnet6(nextHop, a.ip, a.prefix)));
  }

  /** 내가 만든 IPv6 패킷을 내보낸다. 링크 로컬·멀티캐스트 목적지는 경로가 아니라 그 인터페이스(via)로 */
  private sendVia6(pkt: Ipv6Packet, ctx: NodeContext, frameId?: number, via?: number): void {
    if ((isLinkLocal6(pkt.dst) || isMulticast6(pkt.dst)) && via !== undefined) {
      this.v6[via]!.send(pkt, ctx, this.emit(via, ctx));
      return;
    }
    const r = this.route6(pkt.dst);
    if (!r) {
      ctx.trace("ip.no-route", "L3", `No route: ${pkt.dst} 로 가는 IPv6 경로가 없음 → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    this.v6[r.out]!.send(pkt, ctx, this.emit(r.out, ctx), r.nextHop);
  }

  /** IPv6 전달: NAT 없이 주소 그대로, Hop Limit 만 줄인다. 링크 로컬은 넘기지 않는다 */
  private forward6(pkt: Ipv6Packet, inPort: number, frameId: number, ctx: NodeContext): void {
    const name = this.names[inPort]!;
    if (isMulticast6(pkt.dst)) {
      ctx.trace("ip.drop", "L3", `[${name}] 멀티캐스트 ${pkt.dst} 는 라우터가 다른 링크로 넘기지 않음 → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    if (pkt.src === UNSPECIFIED6) {
      ctx.trace("ip.drop", "L3", `[${name}] 출발지가 :: 인 패킷은 넘기지 않음 → 드롭`, {}, frameId);
      return;
    }
    if (isLinkLocal6(pkt.src) || isLinkLocal6(pkt.dst)) {
      const which = isLinkLocal6(pkt.dst) ? `목적지 ${pkt.dst}` : `출발지 ${pkt.src}`;
      ctx.trace("ip.drop", "L3", `[${name}] ${which} 는 링크 로컬 주소(fe80::/10) — 그 링크 안에서만 쓰는 주소라 라우터가 다른 링크로 넘기지 않음 → 드롭. 다른 네트워크와는 글로벌 주소로 통신하세요`, { src: pkt.src, dst: pkt.dst }, frameId);
      return;
    }
    if (pkt.hopLimit <= 1) {
      const notice = this.v6[inPort]!.timeExceeded(pkt, ctx, frameId);
      if (notice) this.sendVia6(notice, ctx, frameId, inPort);
      return;
    }
    const r = this.route6(pkt.dst);
    if (!r) {
      ctx.trace(
        "ip.no-route",
        "L3",
        `No route: ${pkt.dst} 로 가는 IPv6 경로가 없음 (연결된 프리픽스·IPv6 스태틱 라우팅·디폴트 라우트 ::/0 모두 해당 없음) → 드롭. IPv6 스태틱 라우팅에 경로나 ::/0 을 추가하세요`,
        { dst: pkt.dst },
        frameId,
      );
      const notice = this.v6[inPort]!.unreachable(pkt, "net", ctx, frameId);
      if (notice) this.sendVia6(notice, ctx, frameId, inPort);
      return;
    }
    if (!this.firewall.check(pkt, this.flowDirection(inPort, r.out), ctx, frameId)) return;
    const out: Ipv6Packet = { ...pkt, hopLimit: pkt.hopLimit - 1 };
    const outIface = this.v6[r.out]!;
    const conn = outIface.addrs.find((a) => a.origin !== "link-local" && sameSubnet6(pkt.dst, a.ip, a.prefix));
    const via =
      r.kind === "connected" && conn
        ? `${network6(conn.ip, conn.prefix)}/${conn.prefix} 에 직접 연결`
        : r.kind === "default"
          ? `디폴트 라우트 ::/0, 넥스트 홉 ${r.nextHop}`
          : `IPv6 스태틱 라우팅, 넥스트 홉 ${r.nextHop}`;
    // NAT 박스라도 IPv6 는 변환하지 않는다: 바깥에서 안쪽 주소로 바로 들어올 수 있어 막는 것은 방화벽 몫
    const natNote =
      this.nat && r.out === this.outside
        ? " — IPv6 는 NAT 하지 않고 주소 그대로 (글로벌 주소라 바꿀 필요가 없다)"
        : this.nat && inPort === this.outside
          ? " — IPv6 는 NAT 가 없어 바깥에서 안쪽 주소로 바로 들어온다 (막으려면 방화벽 인바운드 규칙)"
          : "";
    ctx.trace("ip.forward", "L3", `라우팅(IPv6): ${pkt.dst} → ${this.names[r.out]} (${via}), Hop Limit ${pkt.hopLimit} → ${out.hopLimit}${natNote}`, { dst: pkt.dst, out: this.names[r.out], kind: r.kind }, frameId);
    outIface.send(out, ctx, this.emit(r.out, ctx), r.nextHop);
  }

  private handleIp(port: number, pkt: Ipv4Packet, frameId: number, ctx: NodeContext): void {
    const name = this.names[port]!;
    // 나에게 온 VPN 터널 패킷(WireGuard·IKE·ESP)은 NAT 역변환보다 먼저 푼다 (지나가는 것·VPN 을 안 켠 장비면 아래에서 보통 패킷처럼)
    if (this.tunnels.accept(port, pkt, frameId, ctx)) return;
    if (pkt.payload.kind === "udp") {
      const udp = pkt.payload;
      const m = udp.payload;
      if (m.kind === "rip") {
        if (udp.dstPort === RIP_PORT) this.rip.handle(port, pkt.src, m, frameId, ctx);
        return;
      }
      const toMe = pkt.dst === "255.255.255.255" || this.ownIndex(pkt.dst) >= 0;
      // 내 DHCP 클라이언트로 온 응답(Offer/Ack 는 아직 내 것이 아닌 주소로 올 수 있다)은 목적지와 무관하게 받는다
      const forMyClient = m.kind === "dhcp" && udp.dstPort === DHCP_CLIENT_PORT && this.clients[port] !== undefined;
      if (!toMe && !forMyClient) {
        // NAT 박스: 바깥에서 안쪽 사설 주소로 직접 온 UDP 는 TCP·ICMP 와 똑같이 막는다 (NAT 우회 방지)
        if (this.nat && port === this.outside) {
          ctx.trace("ip.drop", "L3", `[${name}] 바깥에서 내 공인 주소가 아닌 ${pkt.dst} 로 온 UDP → 드롭. NAT 뒤의 주소는 바깥에서 직접 닿을 수 없음`, { dst: pkt.dst }, frameId);
          return;
        }
        // 다른 라우터를 거쳐 가는 릴레이된 DHCP 를 포함해, 나에게 온 게 아닌 UDP 는 일반 패킷처럼 전달한다
        this.forward(pkt, port, frameId, ctx);
        return;
      }
      if (m.kind === "dhcp" && udp.dstPort === DHCP_CLIENT_PORT && this.clients[port]) {
        this.clients[port]!.handle(m, frameId, ctx, this.emit(port, ctx));
        this.rip.kick(ctx); // 주소를 받았으면 RIP 가 그 네트워크를 광고한다
        this.ha.onLinks(ctx); // 이중화: 주소가 생기거나 없어지면 우선순위가 바뀐다
      }
      else if (m.kind === "dhcp" && udp.dstPort === DHCP_SERVER_PORT) this.handleRelay(port, pkt, m, frameId, ctx);
      else if (m.kind !== "dhcp" && this.nat && port === this.outside && this.ownIndex(pkt.dst) === port) {
        // 바깥에서 공인 주소로 돌아온 UDP 응답(예: DNS) → NAT 테이블로 내부 호스트를 찾아 전달
        const restored = this.nat.restore(pkt, pkt.dst, ctx, frameId);
        if (restored) this.forward(restored, port, frameId, ctx, pkt);
      } else if (m.kind !== "dhcp" && this.ownIndex(pkt.dst) < 0) this.forward(pkt, port, frameId, ctx);
      else ctx.trace("ip.drop", "L4", `[${name}] UDP 포트 ${udp.dstPort} 를 듣는 서비스 없음 → 드롭`, { port: udp.dstPort }, frameId);
      return;
    }
    if (pkt.payload.kind === "pfsync") {
      this.sessionSync.receive(port, pkt, pkt.payload, frameId, ctx);
      return;
    }
    if (pkt.payload.kind === "vrrp") {
      // 이중화 광고 (224.0.0.18 멀티캐스트): 라우터는 넘기지 않는다
      if (this.ha.config.enabled) this.ha.handle(port, pkt.src, pkt.payload, frameId, ctx);
      return;
    }
    // 포트 공개 (docker -p): 내 주소의 공개 포트로 온 TCP 와 그 응답 — NAT 역변환보다 먼저
    if (pkt.payload.kind === "tcp" && this.publish.handle(port, pkt, frameId, ctx)) return;
    if (pkt.payload.kind === "tcp" && this.hairpinTcp(port, pkt, frameId, ctx)) return;
    const mine = this.ownIndex(pkt.dst);
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
      if (pkt.payload.kind === "esp") {
        ctx.trace("vpn.drop", "L3", `ESP(IPsec) 수신 (from ${pkt.src}) → 이 장치는 IPsec VPN 을 켜지 않아 드롭`, { from: pkt.src }, frameId);
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
      const restored = this.nat!.restore(pkt, this.addrOf(port)!, ctx, frameId);
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
    // 응답은 요청받은 주소로 (가상 주소로 온 ping 은 가상 주소가 답한다)
    const reply: Ipv4Packet = { kind: "ipv4", src: pkt.dst, dst: pkt.src, ttl: 64, payload: { kind: "icmp", type: "echo-reply", id: icmp.id, seq: icmp.seq } };
    ctx.trace("icmp.reply.sent", "app", `ICMP Echo 응답 생성 → ${pkt.src} (seq=${icmp.seq})`, { to: pkt.src, seq: icmp.seq });
    this.sendVia(reply, ctx, frameId);
  }

  /** 넥스트 홉이 속한(직접 연결된) 인터페이스 */
  private ifaceFor(nextHop: Ip): number {
    return this.ifaces.findIndex((i) => i.ip !== undefined && sameSubnet(nextHop, i.ip, i.prefix));
  }

  /**
   * 라우팅 테이블 조회: 연결된 서브넷 → 스태틱 라우팅·RIP 중 긴 마스크(같으면 스태틱이 우선, 관리 거리 1 < 120)
   * → 디폴트 라우트(업링크 게이트웨이) → RIP 로 배운 디폴트 라우트
   */
  route(dst: Ip, includeVpn = true): Route | undefined {
    for (let i = 0; i < this.ifaces.length; i++) {
      const iface = this.ifaces[i]!;
      if (iface.ip && sameSubnet(dst, iface.ip, iface.prefix)) return { out: i, nextHop: dst, kind: "connected" };
    }
    const matches = (dest: Ip, prefix: number) => {
      try {
        return sameSubnet(dst, dest, prefix);
      } catch {
        return false;
      }
    };
    let best: (Route & { prefix: number }) | undefined;
    for (const r of this.routes) {
      if (!matches(r.dest, r.prefix) || (best && best.prefix >= r.prefix)) continue;
      const out = this.ifaceFor(r.via);
      if (out >= 0) best = { out, nextHop: r.via, kind: "static", prefix: r.prefix };
    }
    for (const r of this.rip.rows()) {
      if (r.prefix === 0 || !matches(r.dest, r.prefix)) continue;
      if (best && (best.prefix > r.prefix || (best.prefix === r.prefix && (best.kind === "static" || (best.metric ?? 99) <= r.metric)))) continue;
      best = { out: r.out, nextHop: r.nextHop, kind: "rip", metric: r.metric, prefix: r.prefix };
    }
    // 원격 접속 클라이언트의 가상 주소: 그 클라이언트 터널로 (/32 라 가장 구체적)
    if (includeVpn && this.ra.owns(dst)) {
      const peer = this.ra.clients.get(dst)!.peer.ip;
      return { out: this.underlay(peer)?.out ?? this.outside ?? 0, nextHop: peer, kind: "ra" };
    }
    // VPN 으로 가는 상대 대역: 스태틱과 같은 급 (같은 마스크면 스태틱이 우선)
    const tunnel = includeVpn ? this.vpn.match(dst) : undefined;
    if (tunnel && (!best || tunnel.prefix > best.prefix)) {
      const under = this.underlay(this.vpn.target()!.ip);
      return { out: under?.out ?? this.outside ?? 0, nextHop: this.vpn.target()!.ip, kind: "vpn" };
    }
    if (best) return { out: best.out, nextHop: best.nextHop, kind: best.kind, metric: best.metric };
    const def = this.staticDefault();
    if (def) return def;
    const ripDefault = this.rip.rows().find((r) => r.prefix === 0);
    if (ripDefault) return { out: ripDefault.out, nextHop: ripDefault.nextHop, kind: "rip", metric: ripDefault.metric };
    return undefined;
  }

  /** 업링크 게이트웨이로 가는 디폴트 라우트 (NAT 박스는 outside 가 먼저) */
  private staticDefault(): Route | undefined {
    const order = this.outside !== undefined ? [this.outside, ...this.ifaces.map((_, i) => i).filter((i) => i !== this.outside)] : this.ifaces.map((_, i) => i);
    for (const i of order) {
      const iface = this.ifaces[i]!;
      if (iface.ip && iface.gateway) return { out: i, nextHop: iface.gateway, kind: "default" };
    }
    return undefined;
  }

  /** 전달하려던 패킷이 ARP 무응답으로 버려짐: 보낸 이 쪽 인터페이스에서 Host Unreachable (NAT 바깥이면 원래 패킷을 공인 주소로 되돌려) */
  private hostUnreachable(pkt: Ipv4Packet, dropIface: NetInterface, ctx: NodeContext): void {
    if (this.ownIndex(pkt.src) >= 0) return; // 내가 만든 패킷(또는 NAT 가 바꾼 것)은 통지할 상대가 없다
    const back = this.route(pkt.src);
    // 터널 너머에서 온 패킷이면 안쪽(LAN) 주소로 보내고 NAT 하지 않는다 — 공인 주소면 상대가 AllowedIPs 로 버린다
    const tunnel = back?.kind === "vpn" || back?.kind === "ra";
    const from = back && !tunnel ? this.ifaces[back.out]! : dropIface;
    let notice = from.unreachable(pkt, "host", ctx);
    if (!notice) return;
    const outside = this.outside;
    const publicIp = outside !== undefined ? this.addrOf(outside) : undefined;
    if (this.nat && !tunnel && back?.out === outside && publicIp) notice = this.nat.translate(notice, publicIp, ctx);
    if (notice) this.sendVia(notice, ctx);
  }

  /** 내가 만든 패킷(응답)을 라우팅 테이블대로 내보낸다 */
  private sendVia(pkt: Ipv4Packet, ctx: NodeContext, frameId?: number): void {
    const r = this.route(pkt.dst);
    if (r?.kind === "vpn") {
      this.tunnels.send(pkt, ctx, frameId);
      return;
    }
    if (r?.kind === "ra") {
      this.ra.sendTo(pkt, ctx, frameId);
      return;
    }
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
  /**
   * ICMP 통지(Time Exceeded·Unreachable)를 보낼 인터페이스: 보통은 패킷이 들어온 곳.
   * 터널에서 풀린 패킷이면 안쪽(LAN) 인터페이스 주소로 — 공인 주소로 보내면 상대가 자기 사설 대역에서 온 게 아니라며 버린다(AllowedIPs)
   */
  private noticeFrom(pkt: Ipv4Packet, inPort: number, tunnel: boolean): NetInterface {
    if (!tunnel) return this.ifaces[inPort]!;
    const r = this.route(pkt.dst, false);
    const i = r && r.out !== this.outside && this.ifaces[r.out]?.ip ? r.out : this.ifaces.findIndex((f, k) => f.ip !== undefined && k !== this.outside);
    return this.ifaces[i >= 0 ? i : inPort]!;
  }

  /** @param tunnel VPN 터널에서 풀려 나온 패킷 (바깥에서 왔지만 NAT 하지 않는다. 방화벽은 인바운드로 본다) */
  /** @param natDone 포트 공개처럼 이미 주소를 바꾼 패킷 — 바깥으로 나가도 NAT 변환을 다시 하지 않는다 */
  private forward(pkt: Ipv4Packet, inPort: number, frameId: number, ctx: NodeContext, received: Ipv4Packet = pkt, tunnel = false, natDone = false): void {
    if (pkt.dst === "255.255.255.255" || pkt.dst === "0.0.0.0" || pkt.dst.startsWith("224.") || pkt.dst.startsWith("239.")) {
      ctx.trace("ip.drop", "L3", `브로드캐스트/멀티캐스트 ${pkt.dst} 는 라우터가 다른 네트워크로 넘기지 않음 → 드롭`, { dst: pkt.dst }, frameId);
      return;
    }
    if (pkt.ttl <= 1) {
      const notice = this.noticeFrom(pkt, inPort, tunnel).timeExceeded(received, ctx, frameId);
      if (notice) this.sendVia(notice, ctx, frameId);
      return;
    }
    const r = this.route(pkt.dst);
    if (!r) {
      const noAddr = this.ifaces.findIndex((i, k) => !i.ip && (this.clients[k] !== undefined || k === this.outside || k === 0));
      const hint =
        noAddr >= 0
          ? `${this.names[noAddr]} 에 주소가 없음 (케이블과 DHCP, 또는 수동 주소를 확인)`
          : this.rip.config.enabled
            ? "RIP 이웃에게서 이 경로를 배우지 못함 — 이웃 라우터도 RIP 를 켰는지, 그 네트워크를 가진 라우터까지 이어지는지 확인하세요"
            : "스태틱 라우팅을 추가하거나 디폴트 라우트(업링크 게이트웨이)를 설정하세요. 라우터가 여럿이면 RIP(동적 라우팅)를 켜도 됩니다";
      ctx.trace("ip.no-route", "L3", `No route: ${pkt.dst} 로 가는 경로가 없음 (연결된 서브넷·스태틱 라우팅·디폴트 라우트 모두 해당 없음) → 드롭. ${hint}`, { dst: pkt.dst }, frameId);
      const notice = this.noticeFrom(pkt, inPort, tunnel).unreachable(received, "net", ctx, frameId);
      if (notice) this.sendVia(notice, ctx, frameId);
      return;
    }
    if (r.kind === "ra") {
      if (!this.firewall.check(pkt, tunnel ? "lan" : "out", ctx, frameId)) return;
      ctx.trace("ip.forward", "L3", `라우팅: ${pkt.dst} 는 원격 접속 클라이언트의 가상 주소 → 그 클라이언트 터널로 (NAT 하지 않음), TTL ${pkt.ttl} → ${pkt.ttl - 1}`, { dst: pkt.dst, out: "원격 접속", kind: r.kind }, frameId);
      this.ra.sendTo({ ...pkt, ttl: pkt.ttl - 1 }, ctx, frameId);
      return;
    }
    if (r.kind === "vpn") {
      // 사설 대역끼리: NAT 하지 않고 터널로. 방화벽은 터널로 나가는 것을 아웃바운드로 본다 (Stateful 이면 돌아오는 응답도 통과)
      if (!this.firewall.check(pkt, tunnel ? "lan" : "out", ctx, frameId)) return;
      ctx.trace("ip.forward", "L3", `라우팅: ${pkt.dst} 는 VPN 상대 대역 → 터널로 (NAT 하지 않음), TTL ${pkt.ttl} → ${pkt.ttl - 1}`, { dst: pkt.dst, out: "VPN", kind: r.kind }, frameId);
      this.tunnels.send({ ...pkt, ttl: pkt.ttl - 1 }, ctx, frameId);
      return;
    }
    const outName = this.names[r.out]!;
    const outIface = this.ifaces[r.out]!;
    // 터널에서 풀려 들어온 것은 인바운드 (상대 사이트가 연 연결은 인바운드 허용 규칙이 있어야 들어온다)
    if (!this.firewall.check(pkt, tunnel ? "in" : this.flowDirection(inPort, r.out), ctx, frameId)) return;
    let out: Ipv4Packet = { ...pkt, ttl: pkt.ttl - 1 };
    if (this.nat && r.out === this.outside && !natDone) {
      if (inPort === this.outside && !tunnel) {
        ctx.trace("ip.no-route", "L3", `${pkt.dst} 로 가는 안쪽 경로가 없어 바깥으로 되돌아감 → 드롭. 스태틱 라우팅을 추가하세요 (예: ${networkOf(pkt.dst, 24)}/24 via 안쪽 게이트웨이)`, { dst: pkt.dst }, frameId);
        const notice = this.noticeFrom(pkt, inPort, tunnel).unreachable(received, "net", ctx, frameId);
        if (notice) this.sendVia(notice, ctx, frameId);
        return;
      }
      const translated = this.nat.translate(out, this.addrOf(r.out)!, ctx, frameId);
      if (!translated) return;
      out = translated;
    }
    const via =
      r.kind === "connected"
        ? `${networkOf(outIface.ip!, outIface.prefix)}/${outIface.prefix} 에 직접 연결`
        : r.kind === "static"
          ? `스태틱 라우팅, 넥스트 홉 ${r.nextHop}`
          : r.kind === "rip"
            ? `RIP 로 배운 경로 ${r.metric}홉, 넥스트 홉 ${r.nextHop}`
            : `디폴트 라우트, 넥스트 홉 ${r.nextHop}`;
    ctx.trace("ip.forward", "L3", `라우팅: ${pkt.dst} → ${outName} (${via}), TTL ${pkt.ttl} → ${out.ttl}`, { dst: pkt.dst, out: outName, kind: r.kind }, frameId);
    outIface.sendIp(out, ctx, this.emit(r.out, ctx), r.nextHop);
  }

  // ---------- 타이머 ----------

  onTimer(tag: string, data: unknown, ctx: NodeContext): void {
    if (tag === DAD_TIMER_TAG) {
      for (let i = 0; i < this.v6.length; i++) if (this.v6[i]!.finishDad(data, ctx, this.emit(i, ctx))) break;
      return;
    }
    if (tag === RA_PERIODIC_TAG) {
      for (let i = 0; i < this.v6.length; i++) if (this.v6[i]!.onRaTick(data, ctx, this.emit(i, ctx))) break;
      return;
    }
    if (tag === NDP_TIMEOUT_TAG) {
      for (const v of this.v6) {
        // 넘기려던 패킷의 목적지(또는 넥스트 홉)가 NS 에 응답하지 않음 → 보낸 이에게 Address Unreachable
        for (const pkt of v.onNsTimeout(data, ctx)) {
          if (this.v6.some((x) => x.owns(pkt.src)) || isLinkLocal6(pkt.src)) continue;
          const back = this.route6(pkt.src);
          const notice = (back ? this.v6[back.out]! : v).unreachable(pkt, "host", ctx);
          if (notice) this.sendVia6(notice, ctx);
        }
      }
      return;
    }
    if (tag === "arp-timeout") {
      for (const iface of this.ifaces) {
        // 넘기려던 패킷의 목적지(또는 넥스트 홉)가 ARP 에 응답하지 않음 → 보낸 이에게 Host Unreachable
        for (const pkt of iface.onArpTimeout(data, ctx)) this.hostUnreachable(pkt, iface, ctx);
      }
      return;
    }
    if (tag === "arp-probe") {
      const i = this.ifaces.findIndex((f) => f.mac === (data as { mac: string }).mac);
      if (i >= 0) this.ifaces[i]!.finishProbe(ctx, this.emit(i, ctx));
      this.rip.kick(ctx);
      this.ha.onLinks(ctx);
      return;
    }
    if (tag === RIP_TIMER_TAG) {
      this.rip.onTimer(ctx);
      return;
    }
    if (tag === HA_SYNC_TAG) {
      this.sessionSync.flush(ctx);
      return;
    }
    if (tag === HA_TIMER_TAG) {
      this.ha.onTimer(data, ctx);
      return;
    }
    if (tag === VPN_DPD_TAG) {
      this.vpn.onDpdTick(data, ctx);
      return;
    }
    if (tag === IKE_TIMER_TAG) {
      this.vpn.onTimer(data, ctx);
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
      if (iface.ip) routes.push([`${networkOf(iface.ip, iface.prefix)}/${iface.prefix}`, this.names[i]!, "-", "직접 연결"]);
    });
    for (const r of this.routes) {
      const out = this.ifaceFor(r.via);
      routes.push([`${r.dest}/${r.prefix}`, out >= 0 ? this.names[out]! : "(넥스트 홉에 닿는 인터페이스 없음)", r.via, "스태틱"]);
    }
    for (const r of this.rip.rows()) routes.push([`${r.dest}/${r.prefix}`, this.names[r.out]!, r.nextHop, `RIP ${r.metric}홉`]);
    if (this.vpn.config.enabled && this.vpn.config.peer) for (const r of this.vpn.config.remote) routes.push([`${r.dest}/${r.prefix}`, "VPN 터널", this.vpn.target()!.ip, "VPN"]);
    const def = this.staticDefault();
    if (def) routes.push(["0.0.0.0/0", this.names[def.out]!, def.nextHop, "디폴트 라우트"]);
    const tables: NodeSnapshot["tables"] = [{ title: "라우팅 테이블", columns: ["목적지", "인터페이스", "넥스트 홉", "출처"], rows: routes }];
    if (this.ipv6Enabled) {
      const r6: string[][] = [];
      this.v6.forEach((v, i) => {
        for (const a of v.addrs) if (a.origin !== "link-local" && a.state !== "duplicate") r6.push([`${network6(a.ip, a.prefix)}/${a.prefix}`, this.names[i]!, "-", "직접 연결"]);
      });
      for (const r of this.routes6) {
        const out = this.ifaceFor6(r.via);
        r6.push([`${r.dest}/${r.prefix}`, out >= 0 ? this.names[out]! : "(넥스트 홉에 닿는 인터페이스 없음)", r.via, r.prefix === 0 ? "디폴트 라우트" : "스태틱"]);
      }
      tables.push({ title: "IPv6 라우팅 테이블", columns: ["목적지", "인터페이스", "넥스트 홉", "출처"], rows: r6 });
      tables.push({ title: "IPv6 주소", columns: ["인터페이스", "주소", "상태"], rows: this.v6.flatMap((v, i) => v.addrRows().map((row) => [this.names[i]!, row[0]!, `${row[1]} · ${row[2]}`])) });
    }
    if (this.firewall.config.enabled) tables.push({ title: "방화벽 규칙", columns: ["#", "규칙"], rows: this.firewall.rows() });
    if (this.ra.config.enabled) tables.push({ title: "원격 접속 클라이언트", columns: ["사용자", "가상 주소", "바깥 주소", "방식"], rows: this.ra.rows() });
    if (this.nat) {
      const publicIp = this.ifaces[this.outside!]!.ip;
      tables.push({ title: "NAT 테이블", columns: ["내부", "→ 외부", "시각"], rows: this.nat.rows(publicIp) });
      tables.push({ title: "포트 포워딩", columns: ["공인 포트", "내부"], rows: this.nat.forwardRows(publicIp) });
    }
    if (this.publish.rules.length) tables.push({ title: "포트 공개 (docker -p)", columns: ["받는 주소:포트", "→ 대상", "연결"], rows: this.publish.rows() });
    this.ifaces.forEach((iface, i) => tables.push({ title: `ARP 캐시 (${this.names[i]})`, columns: ["IP", "MAC", "학습 시각"], rows: iface.arpRows() }));
    if (this.ipv6Enabled) this.v6.forEach((v, i) => tables.push({ title: `이웃 캐시 (${this.names[i]})`, columns: ["IPv6", "MAC", "학습 시각"], rows: v.neighborRows() }));
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [
        ...this.ifaces.map((_, i) => [this.names[i]!, this.ifaceStatus(i) + (this.relays[i] ? ` · DHCP 릴레이 → ${this.relays[i]}` : "")] as [string, string]),
        ...(this.ipv6Enabled ? this.v6.map((v, i) => [`${this.names[i]} IPv6`, v.summary() || "링크 로컬만"] as [string, string]) : []),
        ...(this.vpn.config.enabled
          ? [
              [
                "VPN",
                this.vpn.mode === "ipsec"
                  ? `${VPN_MODE_LABEL.ipsec} · ${this.vpn.saSummary()} · 보냄 ${this.vpn.sent} / 받음 ${this.vpn.received}`
                  : `${VPN_MODE_LABEL.wireguard} · 상대 ${this.vpn.target() ? `${this.vpn.target()!.ip}:${this.vpn.target()!.port}` : "없음"}${this.vpn.endpoint && this.vpn.endpoint.ip !== this.vpn.config.peer ? " (NAT 뒤에서 온 주소)" : ""} · 보냄 ${this.vpn.sent} / 받음 ${this.vpn.received}`,
              ] as [string, string],
            ]
          : []),
        ...(this.ha.config.enabled ? [["이중화", this.ha.summary()!] as [string, string]] : []),
        ...(this.ra.config.enabled ? [["원격 접속 VPN 서버", `켜짐 · 풀 ${this.ra.config.poolStart} ~ ${this.ra.config.poolEnd}${this.ra.config.users?.length ? ` · 계정 ${this.ra.config.users.length}개 (EAP)` : ""} · ${this.ra.clientsLabel()}`] as [string, string]] : []),
        ...(this.rip.config.enabled ? [["RIP", `켜짐 · 배운 경로 ${this.rip.rows().length}개${this.rip.config.defaultRoute ? " · 디폴트 라우트 광고" : ""}`] as [string, string]] : []),
        ...(this.firewall.config.enabled
          ? [["방화벽", `켜짐 · 규칙 ${this.firewall.config.rules.length}개 · 기본 ${this.firewall.config.defaultPolicy === "allow" ? "허용" : "차단"}`] as [string, string]]
          : []),
        ...(this.nat ? [["NAT", `${NAT_TYPE_LABEL[this.natType]}${this.hairpin ? " · 헤어핀 NAT 켜짐" : ""}`] as [string, string]] : []),
      ],
      tables,
    };
  }
}
