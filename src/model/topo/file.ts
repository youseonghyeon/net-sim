// 저장·불러오기: JSON 문서로 내보내고, 불러온 것(이전 버전·손으로 고친 것)을 지금 모양으로 정리
import { normalizeFirewall, normalizeVlans, normalizeWifiBase } from "../normalize";
import { type Cable, type Device, type InternetSettings, type Topology, ZONE_MIN, ZONE_TINTS, type Zone, nextMac } from "./device";
import { DEFAULT_DHCP_SERVER, DEFAULT_ROUTER_WIFI, DEFAULT_WAN, DEFAULT_WIFI_BASE, type RouterDdnsSettings, type RouterDpiSettings, type RouterIpv6Settings, type RouterSettings, type WifiClientSettings, defaultL3, natTypeOf, normalizeAdguard, normalizeHa, normalizeHostExtras, normalizeIpv6L3, normalizeMesh, normalizeOvpnServer, normalizePublish, normalizeRaClient, normalizeRaServer, normalizeRouterVpn, normalizeRoutes, normalizeVpn, normalizeWan2, normalizeWgClient, normalizeWgServer } from "./settings";
import { DEVICE_SPECS } from "./specs";

/** 저장·공유용 JSON 문서 */
export interface TopologyFile {
  app: "net-sim";
  version: 1;
  devices: Device[];
  cables: Cable[];
  zones?: Zone[];
}

export function serializeTopology(t: Topology): string {
  const doc: TopologyFile = { app: "net-sim", version: 1, devices: t.devices, cables: t.cables, ...(t.zones?.length ? { zones: t.zones } : {}) };
  return JSON.stringify(doc, null, 2);
}

/** JSON 문자열 → 토폴로지. 형식이 틀리면 사용자에게 보일 이유를 돌려준다 */
export function parseTopology(text: string): { topology?: Topology; error?: string } {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { error: "JSON 으로 읽을 수 없습니다. net-sim 에서 내려받은 .json 파일인지 확인하세요" };
  }
  if (!raw || typeof raw !== "object") return { error: "JSON 최상위가 객체가 아닙니다" };
  const doc = raw as Partial<TopologyFile>;
  if (!Array.isArray(doc.devices) || !Array.isArray(doc.cables)) return { error: "devices 와 cables 배열이 있어야 합니다. net-sim 에서 내려받은 파일인지 확인하세요" };
  const ids = new Set<string>();
  for (const d of doc.devices as unknown[]) {
    if (!d || typeof d !== "object") return { error: "devices 항목이 객체가 아닙니다" };
    const dev = d as Partial<Device>;
    if (typeof dev.id !== "string" || !dev.id) return { error: "id 가 없는 장치가 있습니다" };
    if (ids.has(dev.id)) return { error: `장치 id 가 겹칩니다: ${dev.id}` };
    ids.add(dev.id);
    if (typeof dev.kind !== "string" || !(dev.kind in DEVICE_SPECS)) return { error: `모르는 장치 종류입니다: ${String(dev.kind)} (${dev.id}). 이 버전에서 지원하는 종류: ${Object.keys(DEVICE_SPECS).join(", ")}` };
    if (typeof dev.x !== "number" || typeof dev.y !== "number" || !Number.isFinite(dev.x) || !Number.isFinite(dev.y)) return { error: `좌표가 숫자가 아닙니다: ${dev.id}` };
    if (typeof dev.name !== "string") return { error: `이름이 없는 장치가 있습니다: ${dev.id}` };
  }
  for (const c of doc.cables as unknown[]) {
    const cab = c as Partial<Cable>;
    if (!cab || typeof cab.id !== "string" || !cab.a || !cab.b || typeof cab.a.device !== "string" || typeof cab.b.device !== "string" || !Number.isInteger(cab.a.port) || !Number.isInteger(cab.b.port)) {
      return { error: "케이블 항목 형식이 틀립니다 (id, a{device,port}, b{device,port})" };
    }
  }
  // 나머지(없는 설정, 사라진 장치를 가리키는 케이블, 겹치는 포트)는 normalizeTopology 가 기본값으로 채우거나 버린다
  return { topology: normalizeTopology({ devices: doc.devices as Device[], cables: doc.cables as Cable[], zones: Array.isArray(doc.zones) ? (doc.zones as Zone[]) : [] }) };
}

/** 저장된 토폴로지의 누락 필드 보정 (이전 버전에서 저장한 데이터) */
export function normalizeTopology(t: Topology): Topology {
  const devices: Device[] = [];
  // 모르는 장치 종류(다른 버전의 저장본)는 버린다
  const known = t.devices.filter((d) => d && typeof d.kind === "string" && d.kind in DEVICE_SPECS);
  for (const d of known) {
    const fixed: Device = { ...d };
    // MAC 이 비어 있으면 입력 전체(뒤 장치 포함)와 겹치지 않게
    if (!fixed.mac) fixed.mac = nextMac([...known, ...devices]);
    const spec = DEVICE_SPECS[fixed.kind];
    if (spec.role === "host") {
      if (!fixed.host) fixed.host = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "", services: fixed.kind === "server" ? [80] : [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
      else {
        fixed.host = {
          ...fixed.host,
          services: fixed.host.services ?? (fixed.kind === "server" ? [80] : []),
          dhcpServer: fixed.host.dhcpServer ?? { ...DEFAULT_DHCP_SERVER },
          ...(fixed.host.ra ? { ra: normalizeRaClient(fixed.host.ra) } : {}),
        };
      }
    }
    if (fixed.host) fixed.host = normalizeHostExtras(fixed.host);
    if (spec.role === "ap") fixed.ap = normalizeWifiBase(fixed.ap, DEFAULT_WIFI_BASE);
    if (spec.role === "internet" && fixed.internet) fixed.internet = { net: typeof (fixed.internet as Partial<InternetSettings>).net === "string" ? fixed.internet.net : "" };
    if (spec.role === "firewall") fixed.firewall = normalizeFirewall(fixed.firewall, true);
    if (spec.role === "switch") fixed.switch = { ...(fixed.switch ?? {}), vlans: normalizeVlans(fixed.switch?.vlans) };
    if (fixed.switch && fixed.switch.igmpSnooping !== undefined) fixed.switch = { ...fixed.switch, igmpSnooping: fixed.switch.igmpSnooping === true };
    if (fixed.switch?.stp) {
      const st = fixed.switch.stp as Partial<{ enabled: boolean; priority: number }>;
      const prio = typeof st.priority === "number" && Number.isInteger(st.priority) && st.priority >= 0 && st.priority <= 61440 ? st.priority - (st.priority % 4096) : 32768;
      fixed.switch = { ...fixed.switch, stp: { enabled: st.enabled === true, priority: prio } };
    }
    if (fixed.kind === "phone" && !fixed.wifi) fixed.wifi = { ssid: "home" };
    // 무선 단말 설정은 스마트폰·노트북만 (손으로 고친 JSON 의 ssid·enabled 를 타입대로)
    if (fixed.wifi) {
      const w = fixed.wifi as Partial<WifiClientSettings>;
      fixed.wifi = fixed.kind === "phone" || fixed.kind === "laptop" ? { ssid: typeof w.ssid === "string" ? w.ssid : "", ...(w.enabled === false && fixed.kind === "laptop" ? { enabled: false } : {}) } : undefined;
      if (!fixed.wifi) delete fixed.wifi;
    }
    if (spec.role === "l3") {
      const def = defaultL3(fixed.kind);
      if (!fixed.l3) fixed.l3 = def;
      else {
        const ifs = fixed.l3.interfaces ?? [];
        fixed.l3 = {
          ...fixed.l3,
          interfaces: def.interfaces.map((d, i) => (ifs[i] ? { ...d, ...ifs[i] } : d)),
          routes: fixed.l3.routes ?? [],
          ...(fixed.l3.firewall ? { firewall: normalizeFirewall(fixed.l3.firewall) } : {}),
          ...(fixed.l3.vpn ? { vpn: normalizeVpn(fixed.l3.vpn) } : {}),
          ...(fixed.l3.ha ? { ha: normalizeHa(fixed.l3.ha) } : {}),
          ...(fixed.l3.ra ? { ra: normalizeRaServer(fixed.l3.ra) } : {}),
          ...(fixed.l3.ipv6 ? { ipv6: normalizeIpv6L3(fixed.l3.ipv6) } : {}),
          ...(fixed.l3.nat ? { nat: { enabled: (fixed.l3.nat as { enabled?: unknown }).enabled === true } } : {}),
          ...(fixed.l3.publish ? { publish: normalizePublish(fixed.l3.publish) } : {}),
          natType: natTypeOf(fixed.l3.natType),
          hairpin: fixed.l3.hairpin === true ? true : undefined,
        };
      }
    }
    if (spec.role === "router") {
      if (!fixed.router) fixed.router = { lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.199" }, wan: { ...DEFAULT_WAN } };
      else {
        const r = fixed.router;
        fixed.router = {
          ...r,
          lanIp: r.lanIp ?? "192.168.0.1",
          lanPrefix: r.lanPrefix ?? 24,
          // 예전/손상 저장본에는 dhcp 가 없을 수 있다 (타입상 필수지만 JSON 은 믿을 수 없다)
          dhcp: (r.dhcp as RouterSettings["dhcp"] | undefined) ?? { enabled: true, start: "192.168.0.100", end: "192.168.0.199" },
          wan: r.wan ?? { ...DEFAULT_WAN },
          ...(r.firewall ? { firewall: normalizeFirewall(r.firewall) } : {}),
          ...(r.wifi ? { wifi: normalizeWifiBase(r.wifi, DEFAULT_ROUTER_WIFI) } : {}),
          ...(r.ipv6 ? { ipv6: { enabled: (r.ipv6 as Partial<RouterIpv6Settings>).enabled === true, inboundBlock: (r.ipv6 as Partial<RouterIpv6Settings>).inboundBlock !== false } } : {}),
          ...(r.vpnServer ? { vpnServer: normalizeRouterVpn(r.vpnServer) } : {}),
          ...(r.wgServer ? { wgServer: normalizeWgServer(r.wgServer) } : {}),
          ...(r.wgClient ? { wgClient: normalizeWgClient(r.wgClient) } : {}),
          ...(r.ovpnServer ? { ovpnServer: normalizeOvpnServer(r.ovpnServer) } : {}),
          ...(r.mesh && typeof r.mesh === "object" ? { mesh: normalizeMesh(r.mesh) } : {}),
          ...(r.admin && typeof r.admin === "object"
            ? { admin: { enabled: r.admin.enabled === true, remote: r.admin.remote === true, allow: typeof r.admin.allow === "string" ? r.admin.allow : "", ssh: r.admin.ssh !== false } }
            : {}),
          ...(r.cloud === true ? { cloud: true } : {}),
          ...(r.dropIn === true ? { dropIn: true } : {}),
          ...(r.igmpSnooping === true ? { igmpSnooping: true } : {}),
          ...(r.sipAlg === true ? { sipAlg: true } : {}),
          ...(r.tor === true ? { tor: true } : {}),
          ...(r.samba && typeof r.samba === "object" ? { samba: { enabled: r.samba.enabled === true, wan: r.samba.wan === true } } : {}),
          ...(Array.isArray(r.blocked) ? { blocked: r.blocked.filter((x): x is string => typeof x === "string") } : {}),
          ...(r.wan2 ? { wan2: normalizeWan2(r.wan2) } : {}),
          ...(Array.isArray(r.routes) ? { routes: normalizeRoutes(r.routes) } : {}),
          ...(r.adguard ? { adguard: normalizeAdguard(r.adguard) } : {}),
          ...(r.dpi ? { dpi: { enabled: (r.dpi as Partial<RouterDpiSettings>).enabled === true, blockApps: Array.isArray(r.dpi.blockApps) ? r.dpi.blockApps.filter((x): x is string => typeof x === "string") : [], blockCategories: Array.isArray(r.dpi.blockCategories) ? r.dpi.blockCategories.filter((x): x is string => typeof x === "string") : [] } } : {}),
          ...(r.ddns ? { ddns: { enabled: (r.ddns as Partial<RouterDdnsSettings>).enabled === true, name: typeof (r.ddns as Partial<RouterDdnsSettings>).name === "string" ? r.ddns.name : "" } } : {}),
          natType: natTypeOf(r.natType),
          hairpin: r.hairpin === true ? true : undefined,
        };
      }
    }
    devices.push(fixed);
  }
  const ids = new Set(devices.map((d) => d.id));
  const usedPort = new Set<string>();
  const cables: Cable[] = [];
  for (const c of t.cables) {
    if (!ids.has(c.a.device) || !ids.has(c.b.device)) continue;
    const da = devices.find((d) => d.id === c.a.device)!;
    const db = devices.find((d) => d.id === c.b.device)!;
    // 없는 포트(예전 스펙·음수)와 무선 포트(케이블 금지)는 버린다
    const portOk = (d: Device, port: number) => Number.isInteger(port) && port >= 0 && port < DEVICE_SPECS[d.kind].ports.length && !DEVICE_SPECS[d.kind].ports[port]!.radio;
    if (!portOk(da, c.a.port) || !portOk(db, c.b.port) || c.a.device === c.b.device) continue;
    const ka = `${c.a.device}:${c.a.port}`;
    const kb = `${c.b.device}:${c.b.port}`;
    if (usedPort.has(ka) || usedPort.has(kb) || ka === kb) continue; // 같은 포트에 두 케이블: 앞의 것만 남긴다
    usedPort.add(ka);
    usedPort.add(kb);
    cables.push(c);
  }
  const zones: Zone[] = (t.zones ?? [])
    .filter((z) => z && typeof z.id === "string" && [z.x, z.y, z.w, z.h].every((n) => typeof n === "number" && Number.isFinite(n)))
    .map((z) => ({
      id: z.id,
      label: typeof z.label === "string" ? z.label : "영역",
      x: z.x,
      y: z.y,
      w: Math.max(ZONE_MIN, z.w),
      h: Math.max(ZONE_MIN, z.h),
      tint: ZONE_TINTS.some((tt) => tt.id === z.tint) ? z.tint : "gray",
    }));
  return zones.length > 0 ? { devices, cables, zones } : { devices, cables };
}
