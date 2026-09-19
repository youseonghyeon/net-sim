// 편집 중인 토폴로지를 항상 살아 있는 시뮬레이션(Network)에 동기화하고, 시뮬레이션 시계를 돌린다.
import { effect, signal } from "@preact/signals";
import { ipToInt } from "../core/addr";
import { Network, type ActionSpec, type Transmission } from "../core/network";
import { AccessPoint } from "../core/nodes/ap";
import { DHCP_MAX_ATTEMPTS, DHCP_STATE_LABEL, Host } from "../core/nodes/host";
import { Hub } from "../core/nodes/hub";
import { Internet } from "../core/nodes/internet";
import { L3Node } from "../core/nodes/l3";
import type { SimNode } from "../core/nodes/node";
import { Router } from "../core/nodes/router";
import { Switch, type PortVlan } from "../core/nodes/switch";
import { topology } from "./store";
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

/** 무선 링크의 지연 (유선 10ms 보다 느리게) */
const WIFI_LATENCY = 20;

/** 1x 재생 속도에서 실제 1초당 흐르는 시뮬레이션 시간(ms). 링크 10ms 가 0.4초 */
const BASE_RATE = 25;
const TRACE_CAP = 4000;

/** 화면에 보이는 시뮬레이션 시각. 이벤트 사이를 부드럽게 이동하며, 조용할 때는 멈춘다 */
export const simTime = signal(0);
export const running = signal(true);
export const speed = signal(1);
/** 트레이스나 노드 상태가 바뀔 때마다 증가 → 패널이 다시 읽는다 */
export const simVersion = signal(0);
/** 사용자에게 보여줄 시뮬레이션 알림 (폭주 정지, 내부 오류) */
export const simNotice = signal<string | null>(null);
/** 한 화면 프레임에 처리할 수 있는 이벤트 상한. 넘으면 폭주로 보고 일시정지 */
const EVENT_BURST_LIMIT = 4000;

interface SyncedDevice {
  net: string;
  services: string;
}

class SimController {
  net = new Network();
  private syncedConfig = new Map<string, SyncedDevice>();
  private syncedCables = new Map<string, number>();
  /** 동기화된 무선 링크 id → 단말 id (끊김 트레이스와 재시도용) */
  private syncedWireless = new Map<string, string>();
  private lastFrame = 0;

  constructor() {
    effect(() => this.sync(topology.value));
    requestAnimationFrame(this.frame);
  }

  /** 시계와 로그를 0 으로 되돌리고 현재 토폴로지로 다시 시작 */
  reset(): void {
    this.net = new Network();
    this.syncedConfig = new Map();
    this.syncedCables = new Map();
    this.syncedWireless = new Map();
    simTime.value = 0;
    this.sync(topology.peek());
  }

  /** 케이블에서 다음 프레임 1개를 유실시킨다 (실험) */
  dropNext(cableId: string): void {
    this.net.dropNextOn(cableId);
    this.bump();
  }

  // ---------- 토폴로지 → 네트워크 동기화 ----------

  /** 위치 이동처럼 시뮬레이션과 무관한 변경은 건드리지 않는다 (패널 재렌더 방지) */
  private sync(t: Topology): void {
    const net = this.net;
    let changed = false;
    const settle = () => {
      if (!changed) net.runUntil(this.settleTime());
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
      ...t.cables.map((c) => ({ ...c, latency: 10 })),
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
    if (changed) this.bump();
  }

  // ---------- 시계 ----------

  private readonly frame = (ts: number): void => {
    const dt = this.lastFrame ? Math.min(100, ts - this.lastFrame) : 0;
    this.lastFrame = ts;
    if (running.value) {
      try {
        this.advance(dt);
      } catch (e) {
        console.error("simulation error", e);
        running.value = false;
        simNotice.value = `시뮬레이션 내부 오류로 일시정지했습니다: ${e instanceof Error ? e.message : String(e)}`;
      }
    }
    requestAnimationFrame(this.frame);
  };

  private advance(dtMs: number): void {
    const net = this.net;
    let t = simTime.peek();
    if (net.peekNextTime() === undefined && net.inFlight(t).length === 0) return; // 조용함: 시계 정지
    t += (dtMs * BASE_RATE * speed.peek()) / 1000;
    let changed = false;
    let processed = 0;
    for (;;) {
      const next = net.peekNextTime();
      if (next === undefined) break;
      if (next > t) {
        if (net.inFlight(t).length > 0) break; // 패킷이 움직이는 중이면 애니메이션을 기다린다
        t = next; // 아무것도 안 움직이면 다음 이벤트로 점프
      }
      net.step();
      changed = true;
      if (++processed > EVENT_BURST_LIMIT) {
        running.value = false;
        simNotice.value = `이벤트가 폭주해 일시정지했습니다 (한 번에 ${EVENT_BURST_LIMIT}개 초과). 케이블이 두 경로로 이어진 L2 루프가 있는지 확인하세요`;
        t = net.now;
        break;
      }
    }
    simTime.value = t;
    if (changed) this.bump();
    net.pruneTransmissions(t - 5000);
  }

  /** 일시정지 상태에서 이벤트 하나 진행 */
  step(): void {
    const net = this.net;
    if (net.peekNextTime() === undefined) return;
    net.step();
    simTime.value = net.now;
    this.bump();
  }

  act(action: ActionSpec): void {
    const net = this.net;
    net.runUntil(this.settleTime());
    net.scheduleAction(net.now, action);
    net.runUntil(net.now);
    this.bump();
  }

  /** 사용자 개입 시각: 애니메이션 시계를 정수 ms 로 올려서 이후 이벤트 시각이 깔끔하게 떨어지게 한다 */
  private settleTime(): number {
    const t = Math.max(this.net.now, Math.ceil(simTime.peek()));
    if (t !== simTime.peek()) simTime.value = t;
    return t;
  }

  clearLog(): void {
    this.net.trace.length = 0;
    this.bump();
  }

  private bump(): void {
    if (this.net.trace.length > TRACE_CAP) this.net.trace.splice(0, this.net.trace.length - TRACE_CAP + 500);
    simVersion.value = simVersion.peek() + 1;
  }

  // ---------- 조회 ----------

  node(id: string): SimNode | undefined {
    return this.net.nodes.get(id);
  }

  inFlight(): Transmission[] {
    return this.net.inFlight(simTime.peek());
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
function effectiveHost(d: Device) {
  const h = d.host!;
  return {
    ipMode: h.ipMode,
    ip: h.ipMode === "static" ? validIp(h.ip) : undefined,
    prefix: h.prefix,
    gateway: h.ipMode === "static" ? validIp(h.gateway) : undefined,
    dns: h.ipMode === "static" ? validIp(h.dns) : undefined,
  };
}

function effectiveDnsServer(d: Device) {
  if (!d.host) return undefined;
  const c = d.host.dnsServer ?? DEFAULT_DNS_SERVER;
  return {
    enabled: c.enabled,
    records: c.records.filter((r) => r.name.trim() && validIp(r.ip)).map((r) => ({ name: r.name.trim().toLowerCase(), ip: r.ip })),
    upstream: validIp(c.upstream),
  };
}

function effectiveFirewall(f: FirewallSettings | undefined) {
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

function effectiveForwards(rules: { publicPort: number; lanIp: string; lanPort: number }[] | undefined) {
  return (rules ?? [])
    .filter((f) => validIp(f.lanIp) && f.publicPort >= 1 && f.publicPort <= 65535 && f.lanPort >= 1 && f.lanPort <= 65535)
    .map((f) => ({ publicPort: f.publicPort, lanIp: f.lanIp, lanPort: f.lanPort }));
}

function effectiveRouter(d: Device, current?: Router) {
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

function effectiveDhcpServer(d: Device, current?: Host) {
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

function effectiveSwitchVlans(d: Device): Map<number, PortVlan> {
  const out = new Map<number, PortVlan>();
  const v = (d.switch ?? ({ vlans: {} } as SwitchSettings)).vlans;
  for (const [k, val] of Object.entries(v)) {
    const port = Number(k);
    if (val === "trunk") out.set(port, "trunk");
    else if (Number.isInteger(val) && val >= 1 && val <= 4094) out.set(port, val);
  }
  return out;
}

function effectiveL3(d: Device) {
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

function effectiveApSsid(d: Device): string {
  return (d.ap ?? DEFAULT_WIFI_BASE).ssid.trim() || "home";
}

function configKey(d: Device): string {
  if (d.kind === "ap") return JSON.stringify({ mac: d.mac, ssid: effectiveApSsid(d) });
  if (d.kind === "switch") return JSON.stringify({ mac: d.mac, vlans: [...effectiveSwitchVlans(d).entries()] });
  if (d.host) return JSON.stringify({ mac: d.mac, host: effectiveHost(d) });
  if (d.router) return JSON.stringify({ mac: d.mac, router: effectiveRouter(d) });
  if (DEVICE_SPECS[d.kind].role === "l3") return JSON.stringify({ mac: d.mac, l3: effectiveL3(d) });
  return d.mac;
}

function makeNode(d: Device): SimNode {
  const spec = DEVICE_SPECS[d.kind];
  if (spec.role === "switch") {
    const sw = new Switch(d.id, spec.ports.map((p) => p.name));
    const v = effectiveSwitchVlans(d);
    for (const [p, m] of v) sw.portVlan.set(p, m);
    return sw;
  }
  if (spec.role === "hub") return new Hub(d.id, spec.ports.map((p) => p.name));
  if (spec.role === "ap") return new AccessPoint(d.id, effectiveApSsid(d));
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

function applyConfig(net: Network, d: Device): void {
  const node = net.nodes.get(d.id);
  if (node instanceof Host && d.host) node.configure(effectiveHost(d), net.contextFor(d.id));
  else if (node instanceof Switch) node.setVlans(effectiveSwitchVlans(d), net.contextFor(d.id));
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

export const sim = new SimController();

export function togglePlay(): void {
  running.value = !running.value;
}

/** 호스트의 화면 표시용 주소 상태 */
export function hostStatus(id: string): { text: string; tone: "ok" | "warn" | "muted"; mono: boolean } | null {
  const node = sim.node(id);
  if (node instanceof Host) {
    if (node.ip) return { text: `${node.ip}/${node.iface.prefix}`, tone: "ok", mono: true };
    if (!node.linkUp) return { text: DEVICE_SPECS[topology.peek().devices.find((d) => d.id === id)?.kind ?? "pc"].ports[0]?.radio ? "무선 연결 없음" : "케이블 없음", tone: "muted", mono: false };
    if (node.ipMode === "static") return { text: "IP 없음 · 수동 입력 필요", tone: "warn", mono: false };
    switch (node.dhcp.state) {
      case "discovering":
      case "requesting":
        return { text: `DHCP 요청 중 (${node.dhcp.attempts}/${DHCP_MAX_ATTEMPTS})`, tone: "warn", mono: false };
      case "failed":
        return { text: "DHCP 실패 · IP 없음", tone: "warn", mono: false };
      default:
        return { text: "IP 없음", tone: "warn", mono: false };
    }
  }
  if (node instanceof Router) return { text: `${node.lan.ip}/${node.lan.prefix}`, tone: "ok", mono: true };
  if (node instanceof Internet) return { text: `ISP ${node.iface.ip}/${node.iface.prefix}`, tone: "ok", mono: true };
  if (node instanceof AccessPoint) return { text: `SSID ${node.ssid} · 단말 ${node.stations.size}대`, tone: "ok", mono: false };
  if (node instanceof L3Node) {
    // 아래쪽(안쪽) 물리 인터페이스 요약. 서브 인터페이스가 있으면 "if1.10/.20" 처럼 접는다
    const parts: string[] = [];
    let ok = true;
    for (let p = 1; p < node.portCount; p++) {
      const iface = node.ifaces[p]!;
      const subs = node.meta.map((m, i) => ({ m, i })).filter(({ m, i }) => i >= node.portCount && m.port === p);
      if (iface.ip) parts.push(iface.ip);
      else if (subs.length) parts.push(`${node.names[p]}.${subs.map(({ m }) => m.vlan).join("/")}`);
      else {
        parts.push(`${node.names[p]} 없음`);
        ok = false;
      }
    }
    return { text: parts.join(" · "), tone: ok ? "ok" : "warn", mono: true };
  }
  return null;
}

/** 타일에 붙는 서비스 배지: 어느 상자에서 어떤 소프트웨어가 도는지 */
export function serviceBadges(id: string): string[] {
  const node = sim.node(id);
  const out: string[] = [];
  if (node instanceof Host) {
    if (node.dhcpServer.config.enabled) out.push("DHCP");
    if (node.dnsServer.config.enabled) out.push("DNS");
    if (node.tcp.listening.has(80)) out.push("웹");
  } else if (node instanceof Router) {
    if (node.dhcp.enabled) out.push("DHCP");
    if (node.dnsForwarder.config.enabled) out.push("DNS");
    out.push(node.nat.forwards.length > 0 ? "NAT+포워딩" : "NAT");
    if (node.firewall.config.enabled) out.push("방화벽");
    if (node.wifi.enabled) out.push(`Wi-Fi ${node.wifi.ssid}`);
  } else if (node instanceof L3Node) {
    if (node.relays.some(Boolean)) out.push("DHCP 릴레이");
    if (node.nat) out.push(node.nat.forwards.length > 0 ? "NAT+포워딩" : "NAT");
    if (node.firewall.config.enabled) out.push("방화벽");
  } else if (node instanceof Internet) {
    out.push("ISP DHCP", "DNS", "웹");
  } else if (node instanceof Switch && node.vlanAware) {
    out.push("VLAN");
  }
  return out;
}

/** 라우터 타일의 WAN 줄 */
export function wanStatus(id: string): { text: string; tone: "ok" | "warn" | "muted"; mono: boolean } | null {
  const node = sim.node(id);
  if (node instanceof L3Node) {
    const name = node.names[0]!;
    const up = node.ifaces[0]!;
    if (up.ip) return { text: `${name} ${up.ip}`, tone: "ok", mono: true };
    if (!node.linkUp[0]) return { text: `${name} 연결 없음`, tone: "muted", mono: false };
    if (!node.clients[0]) return { text: `${name} 주소 수동 입력 필요`, tone: "warn", mono: false };
    return { text: `${name} ${DHCP_STATE_LABEL[node.clients[0].state]}`, tone: node.clients[0].state === "failed" ? "warn" : "muted", mono: false };
  }
  if (!(node instanceof Router)) return null;
  if (node.wan.ip) return { text: `WAN ${node.wan.ip}`, tone: "ok", mono: true };
  if (!node.wanLinkUp) return { text: "WAN 연결 없음", tone: "muted", mono: false };
  if (node.wanMode === "static") return { text: "WAN 주소 수동 입력 필요", tone: "warn", mono: false };
  return { text: `WAN ${DHCP_STATE_LABEL[node.wanClient.state]}`, tone: node.wanClient.state === "failed" ? "warn" : "muted", mono: false };
}
