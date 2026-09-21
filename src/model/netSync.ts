// 토폴로지(편집 모델) → Network(코어) 변환과 diff 동기화. 신호·DOM 에 의존하지 않아 유닛 테스트가 가능하다.
import { ipToInt } from "../core/addr";
import { Network } from "../core/network";
import { AccessPoint } from "../core/nodes/ap";
import { FirewallBridge } from "../core/nodes/fwbridge";
import { Host } from "../core/nodes/host";
import { Hub } from "../core/nodes/hub";
import { Internet } from "../core/nodes/internet";
import { L3Node } from "../core/nodes/l3";
import type { SimNode } from "../core/nodes/node";
import { Router } from "../core/nodes/router";
import { Switch, type PortVlan } from "../core/nodes/switch";
import { validCidr } from "../core/nodes/firewall";
import {
  DEFAULT_DHCP_SERVER,
  DEFAULT_DNS_SERVER,
  DEFAULT_FIREWALL_SETTINGS,
  DEFAULT_ROUTER_DNS,
  DEFAULT_ROUTER_WIFI,
  DEFAULT_WAN,
  DEFAULT_WIFI_BASE,
  DEVICE_SPECS,
  defaultL3,
  wirelessLinks,
  type Device,
  type FirewallSettings,
  type Topology,
  type WirelessLink,
  type SwitchSettings,
} from "./topology";

/** 유선 케이블 지연 */
export const CABLE_LATENCY = 10;
/** 무선 링크의 지연 (유선보다 느리게) */
export const WIFI_LATENCY = 20;

interface SyncedDevice {
  net: string;
  services: string;
}

export class NetworkSync {
  net = new Network();
  private syncedConfig = new Map<string, SyncedDevice>();
  private syncedCables = new Map<string, number>();
  /** 동기화된 무선 링크 id → 단말 id (끊김 트레이스와 재시도용) */
  private syncedWireless = new Map<string, string>();

  /** 새 네트워크로 시작 (시계·로그 0) */
  reset(): void {
    this.net = new Network();
    this.syncedConfig = new Map();
    this.syncedCables = new Map();
    this.syncedWireless = new Map();
  }

  /**
   * 토폴로지를 네트워크에 diff 로 반영한다. 위치 이동처럼 시뮬레이션과 무관한 변경은 건드리지 않는다 (패널 재렌더 방지).
   * @param settleTime 첫 변경 직전에 네트워크를 진행시킬 시각(사용자 개입 시각). 기본은 현재 시각
   * @returns 시뮬레이션에 영향을 준 변경이 있었는지
   */
  sync(t: Topology, settleTime: () => number = () => this.net.now): boolean {
    const net = this.net;
    let changed = false;
    const settle = () => {
      if (!changed) net.runUntil(settleTime());
      changed = true;
    };

    // 장치 제거가 케이블 제거보다 먼저: 케이블이 아직 꽂힌 상태에서 onRemove(DHCP Release)가 나가야 한다
    const deviceIds = new Set(t.devices.map((d) => d.id));
    for (const id of [...this.syncedConfig.keys()]) {
      if (!deviceIds.has(id)) {
        settle();
        net.removeNode(id);
        this.syncedConfig.delete(id);
      }
    }
    // 무선 연결은 위치·SSID 에서 파생된 "보이지 않는 케이블" 로 다룬다
    const wl = wirelessLinks(t);
    const links: { id: string; a: { device: string; port: number }; b: { device: string; port: number }; loss?: number; latency: number; wireless?: WirelessLink }[] = [
      ...t.cables.map((c) => ({ ...c, latency: CABLE_LATENCY })),
      ...wl.map((l) => ({ id: l.id, a: { device: l.client, port: 0 }, b: { device: l.base, port: l.slot }, latency: WIFI_LATENCY, wireless: l })),
    ];
    const cableIds = new Set(links.map((c) => c.id));
    for (const id of [...this.syncedCables.keys()]) {
      if (!cableIds.has(id)) {
        settle();
        const wlClient = this.syncedWireless.get(id);
        if (wlClient !== undefined) {
          const still = wl.find((l) => l.client === wlClient);
          if (net.hasNode(wlClient)) {
            net.contextFor(wlClient).trace("wifi.disassociate", "L1", still ? `무선 연결 변경: 다른 기지/슬롯으로 옮겨 붙음 → 다시 연결` : `무선 연결 끊김 (범위 밖이거나 SSID/무선 설정이 바뀜)`, {});
          }
          this.syncedWireless.delete(id);
        }
        net.disconnect(id);
        this.syncedCables.delete(id);
      }
    }
    for (const d of t.devices) {
      const key: SyncedDevice = { net: configKey(d), services: JSON.stringify({ s: d.host?.services ?? [], d: effectiveDhcpServer(d), n: effectiveDnsServer(d) }) };
      const prev = this.syncedConfig.get(d.id);
      if (prev === undefined) {
        settle();
        net.addNode(makeNode(d));
      } else {
        if (prev.net !== key.net) {
          settle();
          applyConfig(net, d);
        }
        if (prev.services !== key.services) {
          settle();
          const node = net.nodes.get(d.id);
          if (node instanceof Host) {
            node.setServices(d.host?.services ?? [], net.contextFor(d.id));
            const dhcp = effectiveDhcpServer(d, node);
            if (dhcp) node.setDhcpServer(dhcp, net.contextFor(d.id));
            const dns = effectiveDnsServer(d);
            if (dns) node.setDnsServer(dns, net.contextFor(d.id));
          }
        }
      }
      if (prev === undefined || prev.net !== key.net || prev.services !== key.services) this.syncedConfig.set(d.id, key);
    }
    for (const c of links) {
      const loss = c.loss ?? 0;
      const prevLoss = this.syncedCables.get(c.id);
      if (prevLoss === undefined) {
        settle();
        try {
          if (c.wireless) {
            const baseName = t.devices.find((d) => d.id === c.wireless!.base)?.name ?? c.wireless.base;
            net.contextFor(c.a.device).trace("wifi.associate", "L1", `무선 연결: ${baseName} 에 붙음 (거리 ${c.wireless.distance}px, 슬롯 ${c.b.port}) → DHCP 시작`, { ...c.wireless });
            this.syncedWireless.set(c.id, c.a.device);
          }
          net.connect(c.a.device, c.a.port, c.b.device, c.b.port, c.latency, c.id);
          net.setLinkLoss(c.id, loss);
        } catch (e) {
          console.warn("cable sync failed", c, e);
          if (c.wireless) {
            // 슬롯이 아직 옛 링크에 잡혀 있는 등의 일시적 실패: 다음 동기화에서 다시 시도한다
            this.syncedWireless.delete(c.id);
            if (net.hasNode(c.a.device)) net.contextFor(c.a.device).trace("wifi.no-base", "L1", `무선 연결 실패: ${e instanceof Error ? e.message : String(e)} → 다음 변경 때 다시 시도`, {});
            continue;
          }
        }
        this.syncedCables.set(c.id, loss); // 실패해도 기록해 매 변경마다 재시도하지 않는다
      } else if (prevLoss !== loss) {
        settle();
        net.setLinkLoss(c.id, loss);
        this.syncedCables.set(c.id, loss);
      }
    }
    return changed;
  }

}

function validIp(s: string | undefined): string | undefined {
  if (!s) return undefined;
  try {
    ipToInt(s);
    return s;
  } catch {
    return undefined;
  }
}

/** 입력 중인 불완전한 주소는 "없음" 으로 취급해 시뮬레이션에 넘긴다 */
export function effectiveHost(d: Device) {
  const h = d.host!;
  return {
    ipMode: h.ipMode,
    ip: h.ipMode === "static" ? validIp(h.ip) : undefined,
    prefix: h.prefix,
    gateway: h.ipMode === "static" ? validIp(h.gateway) : undefined,
    dns: h.ipMode === "static" ? validIp(h.dns) : undefined,
  };
}

export function effectiveDnsServer(d: Device) {
  if (!d.host) return undefined;
  const c = d.host.dnsServer ?? DEFAULT_DNS_SERVER;
  return {
    enabled: c.enabled,
    records: c.records.filter((r) => r.name.trim() && validIp(r.ip)).map((r) => ({ name: r.name.trim().toLowerCase(), ip: r.ip })),
    upstream: validIp(c.upstream),
  };
}

export function effectiveFirewall(f: FirewallSettings | undefined) {
  const c = f ?? DEFAULT_FIREWALL_SETTINGS;
  return {
    enabled: c.enabled,
    defaultPolicy: c.defaultPolicy,
    stateful: c.stateful,
    rules: c.rules
      .filter((r) => (!r.src || validCidr(r.src)) && (!r.dst || validCidr(r.dst)) && (!r.dstPort || /^\d+$/.test(r.dstPort)))
      .map((r) => ({
        action: r.action,
        proto: r.proto,
        direction: r.direction,
        src: r.src.trim() || undefined,
        dst: r.dst.trim() || undefined,
        dstPort: r.dstPort ? Math.min(65535, Math.max(1, Number(r.dstPort))) : undefined,
      })),
  };
}

export function effectiveForwards(rules: { publicPort: number; lanIp: string; lanPort: number }[] | undefined) {
  return (rules ?? [])
    .filter((f) => validIp(f.lanIp) && f.publicPort >= 1 && f.publicPort <= 65535 && f.lanPort >= 1 && f.lanPort <= 65535)
    .map((f) => ({ publicPort: f.publicPort, lanIp: f.lanIp, lanPort: f.lanPort }));
}

export function effectiveRouter(d: Device, current?: Router) {
  const r = d.router!;
  const w = r.wan ?? DEFAULT_WAN;
  const dns = r.dns ?? DEFAULT_ROUTER_DNS;
  return {
    lanIp: validIp(r.lanIp) ?? current?.lan.ip ?? "192.168.0.1",
    lanPrefix: r.lanPrefix,
    dhcp: { enabled: r.dhcp.enabled, start: validIp(r.dhcp.start) ?? current?.dhcp.start ?? r.dhcp.start, end: validIp(r.dhcp.end) ?? current?.dhcp.end ?? r.dhcp.end },
    wan: w.ipMode === "static" ? { mode: "static" as const, ip: validIp(w.ip), prefix: w.prefix, gateway: validIp(w.gateway) } : { mode: "dhcp" as const },
    dns: { enabled: dns.enabled, records: [], upstream: validIp(dns.upstream) },
    forwards: effectiveForwards(r.forwards),
    firewall: effectiveFirewall(r.firewall),
    wifi: { ...(r.wifi ?? DEFAULT_ROUTER_WIFI), ssid: (r.wifi ?? DEFAULT_ROUTER_WIFI).ssid.trim() || "home" },
  };
}

/** 라우터 WAN 인터페이스 MAC: LAN MAC 의 4번째 옥텟을 01 로 */
function wanMacOf(mac: string): string {
  return mac.replace(/^02:00:00:00/, "02:00:00:01");
}

/** 게이트웨이/NAT 의 i 번째 인터페이스 MAC: 4번째 옥텟을 1i 로 */
function l3MacOf(mac: string, i: number): string {
  return mac.replace(/^02:00:00:00/, `02:00:00:${(0x10 + i).toString(16)}`);
}

export function effectiveDhcpServer(d: Device, current?: Host) {
  if (!d.host) return undefined;
  const c = d.host.dhcpServer ?? DEFAULT_DHCP_SERVER;
  const cur = current?.dhcpServer.config;
  return {
    enabled: c.enabled,
    start: validIp(c.start) ?? cur?.start ?? "",
    end: validIp(c.end) ?? cur?.end ?? "",
    router: validIp(c.router),
    dns: validIp(c.dns),
    extraPools: (c.extraPools ?? [])
      .filter((p) => validIp(p.start) && validIp(p.end) && p.prefix >= 1 && p.prefix <= 32)
      .map((p) => ({ start: p.start, end: p.end, prefix: p.prefix, router: validIp(p.router), dns: validIp(p.dns) })),
  };
}

export function effectiveSwitchVlans(d: Device): Map<number, PortVlan> {
  const out = new Map<number, PortVlan>();
  const v = (d.switch ?? ({ vlans: {} } as SwitchSettings)).vlans;
  for (const [k, val] of Object.entries(v)) {
    const port = Number(k);
    if (val === "trunk") out.set(port, "trunk");
    else if (Number.isInteger(val) && val >= 1 && val <= 4094) out.set(port, val);
  }
  return out;
}

export function effectiveL3(d: Device) {
  const spec = DEVICE_SPECS[d.kind];
  const l3 = d.l3 ?? defaultL3(d.kind);
  return {
    interfaces: spec.ports.map((p, i) => {
      const c = l3.interfaces[i] ?? { ipMode: "static" as const, ip: "", prefix: 24, gateway: "" };
      const relay = validIp(c.relay);
      return c.ipMode === "dhcp"
        ? { mode: "dhcp" as const, relay }
        : { mode: "static" as const, ip: validIp(c.ip), prefix: c.prefix, gateway: validIp(c.gateway), relay };
    }),
    routes: (l3.routes ?? []).filter((r) => validIp(r.dest) && validIp(r.via) && r.prefix >= 1 && r.prefix <= 32).map((r) => ({ dest: r.dest, prefix: r.prefix, via: r.via })),
    forwards: effectiveForwards(l3.forwards),
    firewall: effectiveFirewall(l3.firewall),
    subinterfaces: (l3.subinterfaces ?? [])
      .filter((s) => Number.isInteger(s.vlan) && s.vlan >= 1 && s.vlan <= 4094 && s.port >= 1 && s.port < spec.ports.length && !spec.ports[s.port]!.radio)
      .map((s) => ({ port: s.port, vlan: s.vlan, ip: validIp(s.ip), prefix: s.prefix, relay: validIp(s.relay) })),
  };
}

export function effectiveApSsid(d: Device): string {
  return (d.ap ?? DEFAULT_WIFI_BASE).ssid.trim() || "home";
}

export function configKey(d: Device): string {
  if (d.kind === "ap") return JSON.stringify({ mac: d.mac, ssid: effectiveApSsid(d) });
  if (d.kind === "firewall") return JSON.stringify({ mac: d.mac, fw: effectiveFirewall(d.firewall) });
  if (d.kind === "switch") return JSON.stringify({ mac: d.mac, vlans: [...effectiveSwitchVlans(d).entries()] });
  if (d.host) return JSON.stringify({ mac: d.mac, host: effectiveHost(d) });
  if (d.router) return JSON.stringify({ mac: d.mac, router: effectiveRouter(d) });
  if (DEVICE_SPECS[d.kind].role === "l3") return JSON.stringify({ mac: d.mac, l3: effectiveL3(d) });
  return d.mac;
}

export function makeNode(d: Device): SimNode {
  const spec = DEVICE_SPECS[d.kind];
  if (spec.role === "switch") {
    const sw = new Switch(d.id, spec.ports.map((p) => p.name));
    const v = effectiveSwitchVlans(d);
    for (const [p, m] of v) sw.portVlan.set(p, m);
    return sw;
  }
  if (spec.role === "hub") return new Hub(d.id, spec.ports.map((p) => p.name));
  if (spec.role === "ap") return new AccessPoint(d.id, effectiveApSsid(d));
  if (spec.role === "firewall") return new FirewallBridge(d.id, effectiveFirewall(d.firewall));
  if (spec.role === "router") return new Router({ id: d.id, mac: d.mac, wanMac: wanMacOf(d.mac), ...effectiveRouter(d) });
  if (spec.role === "internet") return new Internet({ id: d.id, mac: d.mac });
  if (spec.role === "l3") {
    const cfg = effectiveL3(d);
    return new L3Node({
      id: d.id,
      kind: d.kind === "nat" ? "nat" : "gateway",
      outside: 0,
      interfaces: cfg.interfaces.map((c, i) => ({ name: spec.ports[i]!.name, mac: l3MacOf(d.mac, i), ...c })),
      routes: cfg.routes,
      forwards: cfg.forwards,
      firewall: cfg.firewall,
      subinterfaces: cfg.subinterfaces,
    });
  }
  return new Host({ id: d.id, mac: d.mac, ...effectiveHost(d), services: d.host?.services ?? [], dhcpServer: effectiveDhcpServer(d), dnsServer: effectiveDnsServer(d) });
}

export function applyConfig(net: Network, d: Device): void {
  const node = net.nodes.get(d.id);
  if (node instanceof Host && d.host) node.configure(effectiveHost(d), net.contextFor(d.id));
  else if (node instanceof Switch) node.setVlans(effectiveSwitchVlans(d), net.contextFor(d.id));
  else if (node instanceof FirewallBridge) node.configure(effectiveFirewall(d.firewall), net.contextFor(d.id));
  else if (node instanceof AccessPoint) {
    node.ssid = effectiveApSsid(d);
    net.contextFor(d.id).trace("ip.config", "sys", `SSID 변경: "${node.ssid}"`, { ssid: node.ssid });
  } else if (node instanceof Router && d.router) node.configure(effectiveRouter(d, node), net.contextFor(d.id));
  else if (node instanceof L3Node) {
    const cfg = effectiveL3(d);
    node.configure(cfg.interfaces, net.contextFor(d.id));
    node.setRoutes(cfg.routes, net.contextFor(d.id));
    node.setForwards(cfg.forwards, net.contextFor(d.id));
    node.setFirewall(cfg.firewall, net.contextFor(d.id));
    node.setSubinterfaces(cfg.subinterfaces, net.contextFor(d.id));
  }
}
