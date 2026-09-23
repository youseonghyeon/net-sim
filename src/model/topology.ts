// 편집 가능한 토폴로지 모델. 시뮬레이션 코어(src/core)와 분리되어 있고, 실행 시 코어 Network 로 변환된다.

export type DeviceKind = "pc" | "laptop" | "phone" | "server" | "switch" | "hub" | "ap" | "router" | "gateway" | "nat" | "firewall" | "internet";
export type Role = "host" | "switch" | "hub" | "ap" | "router" | "l3" | "internet" | "firewall";
export type PortSide = "top" | "bottom";

export interface PortSpec {
  name: string;
  side: PortSide;
  /** 무선 슬롯: 케이블을 꽂을 수 없고 화면에 포트로 그리지 않는다 */
  radio?: boolean;
}

/** 무선 전파가 닿는 거리 (캔버스 픽셀). 이 안에 있고 SSID 가 같으면 붙는다 */
export const WIFI_RANGE = 300;
const radioSlots = (n: number): PortSpec[] => Array.from({ length: n }, (_, i) => ({ name: `무선 ${i + 1}`, side: "top" as const, radio: true }));

export interface DeviceSpec {
  kind: DeviceKind;
  label: string;
  role: Role;
  width: number;
  height: number;
  ports: PortSpec[];
  namePrefix: string;
}

const lanPorts = (n: number, side: PortSide, prefix = "eth", from = 0): PortSpec[] =>
  Array.from({ length: n }, (_, i) => ({ name: `${prefix}${from + i}`, side }));

export const DEVICE_SPECS: Record<DeviceKind, DeviceSpec> = {
  pc: { kind: "pc", label: "PC", role: "host", width: 64, height: 64, ports: [{ name: "eth0", side: "top" }], namePrefix: "pc" },
  laptop: { kind: "laptop", label: "노트북", role: "host", width: 64, height: 64, ports: [{ name: "eth0", side: "top" }], namePrefix: "laptop" },
  phone: { kind: "phone", label: "스마트폰", role: "host", width: 44, height: 64, ports: [{ name: "wlan0", side: "top", radio: true }], namePrefix: "phone" },
  server: { kind: "server", label: "서버", role: "host", width: 64, height: 64, ports: [{ name: "eth0", side: "top" }], namePrefix: "srv" },
  switch: {
    kind: "switch",
    label: "스위치",
    role: "switch",
    width: 152,
    height: 44,
    // 실물처럼 포트는 아래쪽 한 줄. 라우터/게이트웨이도 이 줄에 꽂는다
    ports: lanPorts(8, "bottom", "eth", 1),
    namePrefix: "sw",
  },
  hub: {
    kind: "hub",
    label: "허브",
    role: "hub",
    width: 120,
    height: 44,
    ports: lanPorts(4, "bottom", "port", 1),
    namePrefix: "hub",
  },
  ap: {
    kind: "ap",
    label: "무선 AP",
    role: "ap",
    width: 120,
    height: 44,
    // eth0 하나 + 무선 슬롯 8개 (코어 AccessPoint 의 포트 배치와 같다)
    ports: [{ name: "eth0", side: "top" }, ...radioSlots(8)],
    namePrefix: "ap",
  },
  router: {
    kind: "router",
    label: "라우터",
    role: "router",
    width: 152,
    height: 62,
    // wan, lan1~4, 무선 슬롯 8개 (코어 Router.RADIO_PORTS = 5..12)
    ports: [{ name: "wan", side: "top" }, ...lanPorts(4, "bottom", "lan", 1), ...radioSlots(8)],
    namePrefix: "rt",
  },
  gateway: {
    kind: "gateway",
    label: "게이트웨이",
    role: "l3",
    width: 152,
    height: 62,
    ports: [
      { name: "if0", side: "top" },
      { name: "if1", side: "bottom" },
      { name: "if2", side: "bottom" },
    ],
    namePrefix: "gw",
  },
  nat: {
    kind: "nat",
    label: "NAT",
    role: "l3",
    width: 152,
    height: 62,
    ports: [
      { name: "outside", side: "top" },
      { name: "inside", side: "bottom" },
    ],
    namePrefix: "nat",
  },
  firewall: {
    kind: "firewall",
    label: "방화벽",
    role: "firewall",
    width: 152,
    height: 62,
    // 투명(브리지) 방화벽: 위 = outside(인터넷 방향), 아래 = inside(보호할 쪽). IP 없음
    ports: [
      { name: "outside", side: "top" },
      { name: "inside", side: "bottom" },
    ],
    namePrefix: "fw",
  },
  internet: {
    kind: "internet",
    label: "인터넷",
    role: "internet",
    width: 152,
    height: 48,
    ports: [{ name: "isp", side: "bottom" }],
    namePrefix: "internet",
  },
};

/** 팔레트 묶음: 패킷이 나가는 순서(단말 → 스위칭 → 라우팅·경계 → 인터넷) */
export const PALETTE_GROUPS: { label: string; kinds: DeviceKind[] }[] = [
  { label: "단말", kinds: ["pc", "laptop", "phone", "server"] },
  { label: "스위칭", kinds: ["hub", "switch", "ap"] },
  { label: "라우팅·경계", kinds: ["router", "gateway", "nat", "firewall", "internet"] },
];
export const PALETTE_ORDER: DeviceKind[] = PALETTE_GROUPS.flatMap((g) => g.kinds);

export interface DhcpPoolSettings {
  start: string;
  end: string;
  prefix: number;
  router: string;
  dns?: string;
}

export interface DhcpServerSettings {
  enabled: boolean;
  start: string;
  end: string;
  /** 클라이언트에게 안내할 게이트웨이 (비우면 안내 없음) */
  router: string;
  /** 클라이언트에게 안내할 DNS (비우면 안내 없음) */
  dns?: string;
  /** 릴레이를 거쳐 오는 다른 서브넷용 풀 */
  extraPools?: DhcpPoolSettings[];
}

export interface DnsRecordSettings {
  name: string;
  ip: string;
}

export interface DnsServerSettings {
  enabled: boolean;
  records: DnsRecordSettings[];
  /** 모르는 이름을 물어볼 업스트림 DNS */
  upstream: string;
}

export const DEFAULT_DNS_SERVER: DnsServerSettings = { enabled: false, records: [], upstream: "" };

export interface HostSettings {
  ipMode: "dhcp" | "static";
  ip: string;
  prefix: number;
  gateway: string;
  /** 수동 설정일 때 DNS 서버 */
  dns?: string;
  /** 듣는 TCP 포트 (웹 서버 = 80) */
  services: number[];
  /** 이 호스트가 DHCP 서버 역할을 할 때 */
  dhcpServer: DhcpServerSettings;
  /** 이 호스트가 DNS 서버 역할을 할 때 */
  dnsServer?: DnsServerSettings;
}

export const DEFAULT_DHCP_SERVER: DhcpServerSettings = { enabled: false, start: "192.168.0.100", end: "192.168.0.199", router: "192.168.0.1" };

/** 게이트웨이/NAT 의 인터페이스 하나 */
export interface IfaceSettings {
  ipMode: "dhcp" | "static";
  ip: string;
  prefix: number;
  gateway: string;
  /** DHCP 릴레이 대상 서버 주소 (비우면 릴레이 없음) */
  relay?: string;
}

export interface StaticRouteSettings {
  dest: string;
  prefix: number;
  via: string;
}

export interface SubIfaceSettings {
  /** 물리 인터페이스 인덱스 (if1 = 1, if2 = 2) */
  port: number;
  vlan: number;
  ip: string;
  prefix: number;
  relay: string;
}

export interface L3Settings {
  interfaces: IfaceSettings[];
  routes: StaticRouteSettings[];
  /** NAT 박스의 포트 포워딩 규칙 */
  forwards?: PortForwardSettings[];
  firewall?: FirewallSettings;
  /** 게이트웨이의 VLAN 서브 인터페이스 (router-on-a-stick) */
  subinterfaces?: SubIfaceSettings[];
}

/** 스위치 포트별 VLAN: 숫자(액세스) 또는 "trunk". 없으면 VLAN 1 */
export interface SwitchSettings {
  vlans: Record<number, number | "trunk">;
}

export interface WanSettings {
  ipMode: "dhcp" | "static";
  ip: string;
  prefix: number;
  gateway: string;
}

export interface PortForwardSettings {
  publicPort: number;
  lanIp: string;
  lanPort: number;
}

export interface FirewallRuleSettings {
  action: "allow" | "deny";
  proto: "any" | "icmp" | "tcp" | "udp";
  direction: "in" | "out" | "any";
  src: string;
  dst: string;
  /** 비우면 모든 포트 */
  dstPort: string;
}

export interface FirewallSettings {
  enabled: boolean;
  defaultPolicy: "allow" | "deny";
  stateful: boolean;
  rules: FirewallRuleSettings[];
}

export const DEFAULT_FIREWALL_SETTINGS: FirewallSettings = { enabled: false, defaultPolicy: "allow", stateful: true, rules: [] };

export interface RouterSettings {
  lanIp: string;
  lanPrefix: number;
  dhcp: { enabled: boolean; start: string; end: string };
  wan: WanSettings;
  /** DNS 포워더 (공유기 안의 dnsmasq) */
  dns?: { enabled: boolean; upstream: string };
  /** 포트 포워딩 규칙 */
  forwards?: PortForwardSettings[];
  firewall?: FirewallSettings;
  wifi?: WifiBaseSettings;
}

export const DEFAULT_ROUTER_DNS = { enabled: true, upstream: "8.8.8.8" };

/** 무선 기지(AP·공유기)의 설정 */
export interface WifiBaseSettings {
  enabled: boolean;
  ssid: string;
}
/** 무선 단말의 설정 */
export interface WifiClientSettings {
  ssid: string;
}
export const DEFAULT_WIFI_BASE: WifiBaseSettings = { enabled: true, ssid: "home" };
export const DEFAULT_ROUTER_WIFI: WifiBaseSettings = { enabled: false, ssid: "home" };

export const DEFAULT_WAN: WanSettings = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" };

export interface Device {
  id: string;
  kind: DeviceKind;
  name: string;
  /** 장치의 MAC (스위치는 사용하지 않지만 일관되게 부여) */
  mac: string;
  x: number;
  y: number;
  host?: HostSettings;
  router?: RouterSettings;
  l3?: L3Settings;
  /** 무선 AP 장치 */
  ap?: WifiBaseSettings;
  /** 스위치 VLAN */
  switch?: SwitchSettings;
  /** 무선 단말 (스마트폰) */
  wifi?: WifiClientSettings;
  /** 투명 방화벽 장비의 규칙 */
  firewall?: FirewallSettings;
}

export interface PortRef {
  device: string;
  port: number;
}

export interface Cable {
  id: string;
  a: PortRef;
  b: PortRef;
  /** 0~1 프레임 손실률 (실험용) */
  loss?: number;
}

/** 영역: 장치 뒤에 그리는 라벨 붙은 네모. "집 안", "도커 호스트" 처럼 묶음을 표시하는 주석이라 시뮬레이션에는 영향이 없다 */
export interface Zone {
  id: string;
  label: string;
  x: number;
  y: number;
  w: number;
  h: number;
  tint: ZoneTint;
}
export type ZoneTint = "gray" | "blue" | "green" | "amber";
export const ZONE_TINTS: { id: ZoneTint; label: string }[] = [
  { id: "gray", label: "회색" },
  { id: "blue", label: "파랑" },
  { id: "green", label: "초록" },
  { id: "amber", label: "노랑" },
];
export const ZONE_MIN = 96;

export interface Topology {
  devices: Device[];
  cables: Cable[];
  /** 없으면 [] 로 본다 (예전 저장본 호환) */
  zones?: Zone[];
}

export const EMPTY_TOPOLOGY: Topology = { devices: [], cables: [] };

/** 장치 타일 중심이 영역 안에 있으면 "영역 안" */
export function zoneContains(z: Zone, d: Device): boolean {
  const s = DEVICE_SPECS[d.kind];
  const cx = d.x + s.width / 2;
  const cy = d.y + s.height / 2;
  return cx >= z.x && cx <= z.x + z.w && cy >= z.y && cy <= z.y + z.h;
}

/** 영역 안의 장치 id */
export function devicesInZone(t: Topology, z: Zone): string[] {
  return t.devices.filter((d) => zoneContains(z, d)).map((d) => d.id);
}

/** 장치 묶음을 감싸는 영역 사각형 (호스트는 아래 이름 줄까지 포함, 여백 pad) */
export function zoneAround(t: Topology, ids: string[], pad = 32): { x: number; y: number; w: number; h: number } | null {
  const picked = t.devices.filter((d) => ids.includes(d.id));
  if (picked.length === 0) return null;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const d of picked) {
    const s = DEVICE_SPECS[d.kind];
    const host = s.role === "host";
    // 호스트는 타일 아래 이름·주소 줄이 타일보다 넓다
    minX = Math.min(minX, d.x - (host ? 20 : 0));
    minY = Math.min(minY, d.y - 12);
    maxX = Math.max(maxX, d.x + s.width + (host ? 20 : 0));
    maxY = Math.max(maxY, d.y + s.height + (host ? 44 : 12));
  }
  return { x: snap(minX - pad), y: snap(minY - pad - 12), w: snap(maxX - minX + pad * 2), h: snap(maxY - minY + pad * 2 + 12) };
}

export function specOf(device: Device): DeviceSpec {
  return DEVICE_SPECS[device.kind];
}

let idSeq = 0;
export function newId(prefix: string): string {
  idSeq += 1;
  return `${prefix}_${Date.now().toString(36)}${idSeq.toString(36)}`;
}

/** 같은 종류 중 비어 있는 가장 작은 번호로 이름을 만든다 (pc-1, pc-2 …) */
export function nextName(kind: DeviceKind, devices: Device[]): string {
  const prefix = DEVICE_SPECS[kind].namePrefix;
  const used = new Set(devices.map((d) => d.name));
  for (let i = 1; ; i++) {
    const name = `${prefix}-${i}`;
    if (!used.has(name)) return name;
  }
}

/** 02:00:00:00:XX:YY 형식으로, 기존 장치와 겹치지 않는 다음 MAC */
export function nextMac(devices: Device[]): string {
  let max = 0;
  for (const d of devices) {
    const m = /^02:00:00:00:([0-9a-f]{2}):([0-9a-f]{2})$/i.exec(d.mac ?? "");
    if (m) max = Math.max(max, parseInt(m[1]! + m[2]!, 16));
  }
  const n = max + 1;
  const hex = n.toString(16).padStart(4, "0");
  return `02:00:00:00:${hex.slice(0, 2)}:${hex.slice(2)}`;
}

export function createDevice(kind: DeviceKind, x: number, y: number, devices: Device[]): Device {
  const spec = DEVICE_SPECS[kind];
  const device: Device = { id: newId(kind), kind, name: nextName(kind, devices), mac: nextMac(devices), x, y };
  if (spec.role === "host") device.host = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "", services: kind === "server" ? [80] : [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  if (spec.role === "router") {
    device.router = { lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.199" }, wan: { ...DEFAULT_WAN } };
  }
  if (spec.role === "l3") device.l3 = defaultL3(kind);
  if (spec.role === "switch") device.switch = { vlans: {} };
  if (spec.role === "ap") device.ap = { ...DEFAULT_WIFI_BASE };
  if (spec.role === "firewall") device.firewall = { ...DEFAULT_FIREWALL_SETTINGS, enabled: true, rules: [] };
  if (kind === "phone") device.wifi = { ssid: "home" };
  return device;
}

// ---------- 무선 연결 (파생 상태) ----------

export interface WirelessLink {
  /** 케이블처럼 쓰이는 id: wl_<단말 id>_<기지 id>_<슬롯>. 기지나 슬롯이 바뀌면 다른 링크로 취급된다 */
  id: string;
  client: string;
  base: string;
  /** 기지의 무선 슬롯 포트 번호 */
  slot: number;
  distance: number;
}

/** 기지별 슬롯 할당. 단말이 떨어졌다 다시 붙어도 같은 슬롯을 주어 다른 단말이 흔들리지 않게 한다 */
const slotTable = new Map<string, Map<string, number>>();

function radioSlotPorts(d: Device): number[] {
  return specOf(d).ports.map((p, i) => (p.radio ? i : -1)).filter((i) => i >= 0);
}

export function baseSsid(d: Device): WifiBaseSettings | undefined {
  if (d.kind === "ap") return d.ap ?? DEFAULT_WIFI_BASE;
  if (d.router) return d.router.wifi ?? DEFAULT_ROUTER_WIFI;
  return undefined;
}

function center(d: Device): { x: number; y: number } {
  const s = specOf(d);
  return { x: d.x + s.width / 2, y: d.y + s.height / 2 };
}

/** 무선 단말마다 SSID 가 같고 범위 안인 가장 가까운 기지에 붙인다 */
export function wirelessLinks(t: Topology): WirelessLink[] {
  const bases = t.devices.filter((d) => {
    const b = baseSsid(d);
    return b !== undefined && b.enabled && b.ssid.trim() !== "";
  });
  const out: WirelessLink[] = [];
  const taken = new Map<string, Set<number>>();
  for (const b of bases) taken.set(b.id, new Set());
  for (const c of t.devices) {
    if (!c.wifi) continue;
    const ssid = c.wifi.ssid.trim();
    if (!ssid) continue;
    const cc = center(c);
    let best: { base: Device; distance: number } | undefined;
    for (const b of bases) {
      if (baseSsid(b)!.ssid.trim() !== ssid) continue;
      const bc = center(b);
      const distance = Math.hypot(bc.x - cc.x, bc.y - cc.y);
      if (distance > WIFI_RANGE) continue;
      if (!best || distance < best.distance) best = { base: b, distance };
    }
    if (!best) continue;
    const slots = radioSlotPorts(best.base);
    const table = slotTable.get(best.base.id) ?? new Map<string, number>();
    slotTable.set(best.base.id, table);
    const used = taken.get(best.base.id)!;
    let slot = table.get(c.id);
    if (slot === undefined || used.has(slot) || !slots.includes(slot)) {
      slot = slots.find((p) => !used.has(p));
      if (slot === undefined) continue; // 슬롯 부족
      table.set(c.id, slot);
    }
    used.add(slot);
    out.push({ id: `wl_${c.id}_${best.base.id}_${slot}`, client: c.id, base: best.base.id, slot, distance: Math.round(best.distance) });
  }
  return out;
}

/** 단말이 왜 안 붙는지 (인스펙터 안내용) */
export function wirelessStatus(t: Topology, client: Device): { linked?: WirelessLink; reason?: string } {
  const link = wirelessLinks(t).find((l) => l.client === client.id);
  if (link) return { linked: link };
  const ssid = client.wifi?.ssid.trim() ?? "";
  if (!ssid) return { reason: "연결할 SSID 를 입력하세요" };
  const same = t.devices.filter((d) => baseSsid(d)?.ssid.trim() === ssid);
  if (same.length === 0) return { reason: `SSID "${ssid}" 를 송출하는 AP 나 공유기가 없습니다` };
  const on = same.filter((d) => baseSsid(d)!.enabled);
  if (on.length === 0) return { reason: `SSID "${ssid}" 의 무선이 꺼져 있습니다` };
  const cc = center(client);
  const inRange = on.filter((d) => Math.hypot(center(d).x - cc.x, center(d).y - cc.y) <= WIFI_RANGE);
  if (inRange.length === 0) return { reason: `SSID "${ssid}" 는 있지만 전파 범위(${WIFI_RANGE}px) 밖입니다. 단말을 AP 쪽으로 옮기세요` };
  return { reason: `범위 안의 기지 ${inRange.map((d) => d.name).join(", ")} 에 빈 무선 슬롯이 없습니다 (기지당 ${radioSlotPorts(inRange[0]!).length}대)` };
}

export function defaultL3(kind: DeviceKind): L3Settings {
  if (kind === "nat") {
    return {
      interfaces: [
        { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" },
        { ipMode: "static", ip: "192.168.0.1", prefix: 24, gateway: "" },
      ],
      routes: [],
    };
  }
  return {
    interfaces: [
      { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "192.168.1.1", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "192.168.2.1", prefix: 24, gateway: "" },
    ],
    routes: [],
  };
}

/** 포트가 타일 가장자리에서 튀어나온 위치 (케이블이 붙는 점) */
export function portAnchor(device: Device, port: number): { x: number; y: number; side: PortSide } {
  const spec = specOf(device);
  const p = spec.ports[port];
  if (!p) throw new Error(`${device.name} has no port ${port}`);
  if (p.radio) {
    // 무선 슬롯: 타일 위쪽 가운데 (전파 링크가 여기서 나간다)
    return { x: device.x + spec.width / 2, y: device.y - PORT_DEPTH, side: "top" };
  }
  const siblings = spec.ports.filter((q) => q.side === p.side && !q.radio);
  const index = siblings.indexOf(p);
  const gap = 14;
  const x = device.x + spec.width / 2 + (index - (siblings.length - 1) / 2) * gap;
  const y = p.side === "top" ? device.y - PORT_DEPTH : device.y + spec.height + PORT_DEPTH;
  return { x, y, side: p.side };
}

export const PORT_DEPTH = 6;
export const PORT_WIDTH = 8;

export function usedPorts(topology: Topology, deviceId: string): Set<number> {
  const used = new Set<number>();
  for (const c of topology.cables) {
    if (c.a.device === deviceId) used.add(c.a.port);
    if (c.b.device === deviceId) used.add(c.b.port);
  }
  return used;
}

/**
 * 비어 있는 포트 중 상대 장치를 향한 쪽(상대가 위에 있으면 top)을 우선 고른다.
 * 케이블이 포트에서 수직으로 나가므로, 이렇게 해야 선이 자연스럽게 상대를 향한다.
 */
/**
 * 장치 묶음을 복제한다: 새 id·이름·MAC, 설정은 깊은 복사, 묶음 안에서 서로 잇는 케이블만 따라온다.
 * @returns 붙여 넣을 장치·케이블 (원본 토폴로지에는 아직 없음)
 */
export function cloneDevices(t: Topology, ids: string[], offset: { x: number; y: number }, existing: Device[] = t.devices): { devices: Device[]; cables: Cable[] } {
  const picked = t.devices.filter((d) => ids.includes(d.id));
  const pool = [...existing];
  const idMap = new Map<string, string>();
  const devices: Device[] = [];
  for (const d of picked) {
    const copy: Device = { ...structuredClone(d), id: newId(d.kind), name: nextName(d.kind, pool), mac: nextMac(pool), x: snap(d.x + offset.x), y: snap(d.y + offset.y) };
    idMap.set(d.id, copy.id);
    devices.push(copy);
    pool.push(copy);
  }
  const cables: Cable[] = t.cables
    .filter((c) => idMap.has(c.a.device) && idMap.has(c.b.device))
    .map((c) => ({ ...c, id: newId("cable"), a: { device: idMap.get(c.a.device)!, port: c.a.port }, b: { device: idMap.get(c.b.device)!, port: c.b.port } }));
  return { devices, cables };
}

export type AlignMode = "left" | "top" | "spread-x" | "spread-y";

/** 여러 장치를 정렬한다. spread 는 양 끝은 두고 사이 간격을 같게 */
export function alignDevices(t: Topology, ids: string[], mode: AlignMode): Topology {
  const picked = t.devices.filter((d) => ids.includes(d.id));
  if (picked.length < 2) return t;
  const pos = new Map<string, { x: number; y: number }>();
  if (mode === "left") {
    const x = Math.min(...picked.map((d) => d.x));
    for (const d of picked) pos.set(d.id, { x, y: d.y });
  } else if (mode === "top") {
    const y = Math.min(...picked.map((d) => d.y));
    for (const d of picked) pos.set(d.id, { x: d.x, y });
  } else {
    const key = mode === "spread-x" ? "x" : "y";
    const size = (d: Device) => (mode === "spread-x" ? specOf(d).width : specOf(d).height);
    const sorted = [...picked].sort((a, b) => a[key] - b[key]);
    const first = sorted[0]!;
    const last = sorted[sorted.length - 1]!;
    const span = last[key] - first[key] - sorted.slice(0, -1).reduce((acc, d) => acc + size(d), 0);
    const gap = span / (sorted.length - 1);
    let cursor = first[key];
    for (const d of sorted) {
      pos.set(d.id, { x: mode === "spread-x" ? snap(cursor) : d.x, y: mode === "spread-y" ? snap(cursor) : d.y });
      cursor += size(d) + gap;
    }
  }
  return { ...t, devices: t.devices.map((d) => (pos.has(d.id) ? { ...d, ...pos.get(d.id)! } : d)) };
}

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

/** 두 장치를 잇는 케이블의 양 끝 포트를 정한다. 못 잇는 이유는 사용자에게 보일 문장으로 돌려준다 */
export function planCable(t: Topology, aId: string, bId: string): { a: PortRef; b: PortRef } | { error: string } {
  if (aId === bId) return { error: "같은 장치끼리는 연결할 수 없습니다" };
  const a = t.devices.find((d) => d.id === aId);
  const b = t.devices.find((d) => d.id === bId);
  if (!a || !b) return { error: "장치를 찾을 수 없습니다" };
  for (const d of [a, b]) {
    if (DEVICE_SPECS[d.kind].ports.every((p) => p.radio)) return { error: `${d.name} 은(는) 무선 전용이라 케이블을 꽂을 수 없습니다. SSID 를 맞추고 AP 근처로 옮기세요` };
  }
  if (t.cables.some((c) => (c.a.device === aId && c.b.device === bId) || (c.a.device === bId && c.b.device === aId))) {
    return { error: `${a.name} 와 ${b.name} 는 이미 연결되어 있습니다. 두 번째 케이블은 L2 루프(브로드캐스트 폭주)를 만듭니다` };
  }
  const pa = freePort(t, aId, b.y);
  const pb = freePort(t, bId, a.y);
  if (pa === undefined) return { error: `${a.name} 에 빈 포트가 없습니다` };
  if (pb === undefined) return { error: `${b.name} 에 빈 포트가 없습니다` };
  return { a: { device: aId, port: pa }, b: { device: bId, port: pb } };
}

export function freePort(topology: Topology, deviceId: string, peerY?: number): number | undefined {
  const device = topology.devices.find((d) => d.id === deviceId);
  if (!device) return undefined;
  const used = usedPorts(topology, deviceId);
  const spec = specOf(device);
  const preferred: PortSide = peerY !== undefined && peerY < device.y ? "top" : "bottom";
  const order = spec.ports
    .map((_, i) => i)
    .filter((i) => !spec.ports[i]!.radio)
    .sort((a, b) => Number(spec.ports[b]!.side === preferred) - Number(spec.ports[a]!.side === preferred));
  return order.find((i) => !used.has(i));
}

export function cableAt(topology: Topology, ref: PortRef): Cable | undefined {
  return topology.cables.find((c) => samePort(c.a, ref) || samePort(c.b, ref));
}

export function samePort(a: PortRef, b: PortRef): boolean {
  return a.device === b.device && a.port === b.port;
}

export function peerOf(cable: Cable, deviceId: string): PortRef {
  return cable.a.device === deviceId ? cable.b : cable.a;
}

export function snap(v: number, grid = 8): number {
  return Math.round(v / grid) * grid;
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
        };
      }
    }
    if (spec.role === "ap" && !fixed.ap) fixed.ap = { ...DEFAULT_WIFI_BASE };
    if (spec.role === "firewall") fixed.firewall = fixed.firewall ? { ...DEFAULT_FIREWALL_SETTINGS, ...fixed.firewall, rules: fixed.firewall.rules ?? [] } : { ...DEFAULT_FIREWALL_SETTINGS, enabled: true, rules: [] };
    if (spec.role === "switch" && !fixed.switch) fixed.switch = { vlans: {} };
    if (fixed.kind === "phone" && !fixed.wifi) fixed.wifi = { ssid: "home" };
    if (spec.role === "l3") {
      const def = defaultL3(fixed.kind);
      if (!fixed.l3) fixed.l3 = def;
      else {
        const ifs = fixed.l3.interfaces ?? [];
        fixed.l3 = {
          ...fixed.l3,
          interfaces: def.interfaces.map((d, i) => (ifs[i] ? { ...d, ...ifs[i] } : d)),
          routes: fixed.l3.routes ?? [],
          ...(fixed.l3.firewall ? { firewall: { ...DEFAULT_FIREWALL_SETTINGS, ...fixed.l3.firewall, rules: fixed.l3.firewall.rules ?? [] } } : {}),
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
          ...(r.firewall ? { firewall: { ...DEFAULT_FIREWALL_SETTINGS, ...r.firewall, rules: r.firewall.rules ?? [] } } : {}),
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

/** 기능 단위 구성 예제: 인터넷 → NAT 박스 → 게이트웨이 → 스위치 2대(서브넷 2개) + DHCP 서버 호스트 */
export function examplePartsTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const inet = add("internet", 344, -232);
  const nat = add("nat", 344, -80);
  nat.l3 = {
    interfaces: [
      { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "10.0.0.1", prefix: 24, gateway: "" },
    ],
    routes: [{ dest: "192.168.0.0", prefix: 16, via: "10.0.0.2" }],
    // 바깥에서 공인 :80 으로 오면 오른쪽 서브넷의 웹 서버로
    forwards: [{ publicPort: 80, lanIp: "192.168.2.20", lanPort: 80 }],
  };
  const gw = add("gateway", 344, 80);
  gw.l3 = {
    interfaces: [
      { ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" },
      { ipMode: "static", ip: "192.168.1.1", prefix: 24, gateway: "" },
      // 오른쪽 서브넷엔 DHCP 서버가 없어 왼쪽의 dhcp-srv 로 릴레이한다
      { ipMode: "static", ip: "192.168.2.1", prefix: 24, gateway: "", relay: "192.168.1.2" },
    ],
    routes: [],
  };
  const sw1 = add("switch", 120, 256);
  const sw2 = add("switch", 568, 256);
  const dhcp = add("server", 24, 424);
  dhcp.name = "dhcp-srv";
  dhcp.host = {
    ipMode: "static",
    ip: "192.168.1.2",
    prefix: 24,
    gateway: "192.168.1.1",
    dns: "192.168.1.2",
    services: [],
    dhcpServer: {
      enabled: true,
      start: "192.168.1.100",
      end: "192.168.1.199",
      router: "192.168.1.1",
      dns: "192.168.1.2",
      extraPools: [{ start: "192.168.2.100", end: "192.168.2.199", prefix: 24, router: "192.168.2.1", dns: "192.168.1.2" }],
    },
    // 같은 서버가 DNS 도 맡는다: 내부 이름은 레코드로, 공개 이름은 8.8.8.8 에 재귀 질의
    dnsServer: { enabled: true, records: [{ name: "web.home", ip: "192.168.2.20" }], upstream: "8.8.8.8" },
  };
  const pc1 = add("pc", 200, 424);
  const laptop = add("laptop", 520, 424); // 릴레이를 거쳐 dhcp-srv 에서 주소를 받는다
  const web = add("server", 700, 424);
  web.host = { ipMode: "static", ip: "192.168.2.20", prefix: 24, gateway: "192.168.2.1", dns: "192.168.1.2", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: nat.id, port: 0 } },
    { id: newId("cable"), a: { device: nat.id, port: 1 }, b: { device: gw.id, port: 0 } },
    { id: newId("cable"), a: { device: gw.id, port: 1 }, b: { device: sw1.id, port: 0 } },
    { id: newId("cable"), a: { device: gw.id, port: 2 }, b: { device: sw2.id, port: 0 } },
    { id: newId("cable"), a: { device: sw1.id, port: 2 }, b: { device: dhcp.id, port: 0 } },
    { id: newId("cable"), a: { device: sw1.id, port: 5 }, b: { device: pc1.id, port: 0 } },
    { id: newId("cable"), a: { device: sw2.id, port: 3 }, b: { device: laptop.id, port: 0 } },
    { id: newId("cable"), a: { device: sw2.id, port: 6 }, b: { device: web.id, port: 0 } },
  ];
  return { devices, cables };
}

/** VLAN 예제: 인터넷 → NAT → 게이트웨이(if1 트렁크) → 스위치(VLAN 10: pc 2대, VLAN 20: 웹 서버 + 노트북) */
export function exampleVlanTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const inet = add("internet", 344, -232);
  const nat = add("nat", 344, -80);
  nat.l3 = {
    interfaces: [
      { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "10.0.0.1", prefix: 24, gateway: "" },
    ],
    routes: [{ dest: "192.168.0.0", prefix: 16, via: "10.0.0.2" }],
  };
  const gw = add("gateway", 344, 80);
  gw.l3 = {
    interfaces: [
      { ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" },
      { ipMode: "static", ip: "", prefix: 24, gateway: "" }, // if1 은 트렁크: 주소 없이 서브 인터페이스만
      { ipMode: "static", ip: "", prefix: 24, gateway: "" },
    ],
    routes: [],
    // router-on-a-stick: 트렁크 하나 위에 VLAN 마다 게이트웨이 주소
    subinterfaces: [
      { port: 1, vlan: 10, ip: "192.168.10.1", prefix: 24, relay: "" },
      { port: 1, vlan: 20, ip: "192.168.20.1", prefix: 24, relay: "" },
    ],
  };
  const sw = add("switch", 344, 256);
  sw.switch = { vlans: { 0: "trunk", 1: 10, 2: 10, 5: 20, 6: 20 } };
  const pc1 = add("pc", 120, 424);
  const pc2 = add("pc", 260, 424);
  const laptop = add("laptop", 460, 424);
  const web = add("server", 600, 424);
  const staticHost = (d: Device, ip: string, gw: string, services: number[] = []) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway: gw, dns: "8.8.8.8", services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  staticHost(pc1, "192.168.10.10", "192.168.10.1");
  staticHost(pc2, "192.168.10.11", "192.168.10.1");
  staticHost(laptop, "192.168.20.10", "192.168.20.1");
  staticHost(web, "192.168.20.20", "192.168.20.1", [80]);
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: nat.id, port: 0 } },
    { id: newId("cable"), a: { device: nat.id, port: 1 }, b: { device: gw.id, port: 0 } },
    { id: newId("cable"), a: { device: gw.id, port: 1 }, b: { device: sw.id, port: 0 } }, // 트렁크
    { id: newId("cable"), a: { device: sw.id, port: 1 }, b: { device: pc1.id, port: 0 } }, // VLAN 10
    { id: newId("cable"), a: { device: sw.id, port: 2 }, b: { device: pc2.id, port: 0 } }, // VLAN 10
    { id: newId("cable"), a: { device: sw.id, port: 5 }, b: { device: laptop.id, port: 0 } }, // VLAN 20
    { id: newId("cable"), a: { device: sw.id, port: 6 }, b: { device: web.id, port: 0 } }, // VLAN 20
  ];
  return { devices, cables };
}

/** 인터넷 + 공유기(라우터) + 스위치 + 호스트 3대 예제 */
export function exampleTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const inet = add("internet", 344, -40);
  const rt = add("router", 344, 96);
  const sw = add("switch", 344, 272);
  const pc = add("pc", 200, 440);
  const laptop = add("laptop", 388, 440);
  const srv = add("server", 576, 440);
  // 웹 서버는 고정 주소로 두고 라우터가 공인 :80 을 여기로 포워딩한다
  srv.host = { ipMode: "static", ip: "192.168.0.20", prefix: 24, gateway: "192.168.0.1", dns: "192.168.0.1", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  rt.router = { ...rt.router!, forwards: [{ publicPort: 80, lanIp: "192.168.0.20", lanPort: 80 }], wifi: { enabled: true, ssid: "home" } };
  // 공유기의 Wi-Fi 에 붙는 스마트폰 (링크 다운, 전파 범위 안)
  add("phone", 600, 120);
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: rt.id, port: 0 } }, // isp ↔ wan
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 0 } }, // lan1 ↔ eth1
    { id: newId("cable"), a: { device: sw.id, port: 2 }, b: { device: pc.id, port: 0 } }, // eth2
    { id: newId("cable"), a: { device: sw.id, port: 4 }, b: { device: laptop.id, port: 0 } }, // eth4
    { id: newId("cable"), a: { device: sw.id, port: 6 }, b: { device: srv.id, port: 0 } }, // eth6
  ];
  return { devices, cables };
}

/** 가장 단순한 예제: PC 2대 + 스위치, 수동 IP. ARP 와 ping 만 본다 */
export function exampleStarterTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const sw = add("switch", 344, 96);
  const pc1 = add("pc", 232, 280);
  const pc2 = add("pc", 544, 280);
  pc1.host = { ipMode: "static", ip: "192.168.0.10", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  pc2.host = { ipMode: "static", ip: "192.168.0.11", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: sw.id, port: 1 }, b: { device: pc1.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 6 }, b: { device: pc2.id, port: 0 } },
  ];
  return { devices, cables };
}

/** 게이트웨이 2단: NAT 아래에 라우터 전용 서브넷(10.0.0.0/24)을 두고 게이트웨이 둘이 각자 서브넷을 맡는다 */
export function exampleTwoGatewaysTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const inet = add("internet", 344, -232);
  const nat = add("nat", 344, -80);
  nat.l3 = {
    interfaces: [
      { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "10.0.0.1", prefix: 24, gateway: "" },
    ],
    // 게이트웨이마다 그 뒤 서브넷으로 돌아가는 경로. 이게 없으면 응답이 여기서 드롭된다
    routes: [
      { dest: "192.168.1.0", prefix: 24, via: "10.0.0.2" },
      { dest: "192.168.5.0", prefix: 24, via: "10.0.0.3" },
    ],
  };
  const sw0 = add("switch", 344, 80); // 라우터들만 사는 서브넷
  const gw1 = add("gateway", 96, 248);
  const gw2 = add("gateway", 592, 248);
  const gwCfg = (ifIp: string, lanIp: string, otherDest: string, otherVia: string): L3Settings => ({
    interfaces: [
      { ipMode: "static", ip: ifIp, prefix: 24, gateway: "10.0.0.1" },
      { ipMode: "static", ip: lanIp, prefix: 24, gateway: "" },
      { ipMode: "static", ip: "", prefix: 24, gateway: "" },
    ],
    // 옆 게이트웨이 뒤 서브넷은 NAT 를 거치지 않고 같은 스위치에서 바로 넘긴다
    routes: [{ dest: otherDest, prefix: 24, via: otherVia }],
  });
  gw1.l3 = gwCfg("10.0.0.2", "192.168.1.1", "192.168.5.0", "10.0.0.3");
  gw2.l3 = gwCfg("10.0.0.3", "192.168.5.1", "192.168.1.0", "10.0.0.2");
  const sw1 = add("switch", 96, 424);
  const sw2 = add("switch", 592, 424);
  const pc1 = add("pc", 24, 592);
  const pc2 = add("pc", 184, 592);
  const pc3 = add("pc", 520, 592);
  const srv = add("server", 680, 592);
  const staticHost = (d: Device, ip: string, gw: string, services: number[] = []) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway: gw, dns: "8.8.8.8", services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  staticHost(pc1, "192.168.1.10", "192.168.1.1");
  staticHost(pc2, "192.168.1.11", "192.168.1.1");
  staticHost(pc3, "192.168.5.10", "192.168.5.1");
  staticHost(srv, "192.168.5.20", "192.168.5.1", [80]);
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: nat.id, port: 0 } },
    { id: newId("cable"), a: { device: nat.id, port: 1 }, b: { device: sw0.id, port: 3 } },
    { id: newId("cable"), a: { device: sw0.id, port: 0 }, b: { device: gw1.id, port: 0 } },
    { id: newId("cable"), a: { device: sw0.id, port: 7 }, b: { device: gw2.id, port: 0 } },
    { id: newId("cable"), a: { device: gw1.id, port: 1 }, b: { device: sw1.id, port: 3 } },
    { id: newId("cable"), a: { device: gw2.id, port: 1 }, b: { device: sw2.id, port: 3 } },
    { id: newId("cable"), a: { device: sw1.id, port: 0 }, b: { device: pc1.id, port: 0 } },
    { id: newId("cable"), a: { device: sw1.id, port: 5 }, b: { device: pc2.id, port: 0 } },
    { id: newId("cable"), a: { device: sw2.id, port: 1 }, b: { device: pc3.id, port: 0 } },
    { id: newId("cable"), a: { device: sw2.id, port: 6 }, b: { device: srv.id, port: 0 } },
  ];
  return { devices, cables };
}

/** 집 두 곳 잇기: 인터넷 없이 게이트웨이 둘을 if0 끼리 직접 잇고, 서로의 서브넷을 스태틱 라우팅으로 안다 */
export function exampleTwoHomesTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const gw1 = add("gateway", 96, 200);
  const gw2 = add("gateway", 592, 200);
  const gwCfg = (linkIp: string, lanIp: string, otherDest: string, otherVia: string): L3Settings => ({
    interfaces: [
      { ipMode: "static", ip: linkIp, prefix: 24, gateway: "" }, // if0: 두 집 사이 링크(10.0.0.0/24). 인터넷이 없으니 디폴트 라우트도 없다
      { ipMode: "static", ip: lanIp, prefix: 24, gateway: "" },
      { ipMode: "static", ip: "", prefix: 24, gateway: "" },
    ],
    routes: [{ dest: otherDest, prefix: 24, via: otherVia }], // 상대 집 서브넷은 상대 게이트웨이로
  });
  gw1.l3 = gwCfg("10.0.0.1", "192.168.1.1", "192.168.2.0", "10.0.0.2");
  gw2.l3 = gwCfg("10.0.0.2", "192.168.2.1", "192.168.1.0", "10.0.0.1");
  const sw1 = add("switch", 96, 376);
  const sw2 = add("switch", 592, 376);
  const pc1 = add("pc", 24, 544);
  const pc2 = add("pc", 184, 544);
  const pc3 = add("pc", 520, 544);
  const pc4 = add("pc", 680, 544);
  const staticHost = (d: Device, ip: string, gw: string) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway: gw, services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  staticHost(pc1, "192.168.1.10", "192.168.1.1");
  staticHost(pc2, "192.168.1.11", "192.168.1.1");
  staticHost(pc3, "192.168.2.10", "192.168.2.1");
  staticHost(pc4, "192.168.2.11", "192.168.2.1");
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: gw1.id, port: 0 }, b: { device: gw2.id, port: 0 } }, // if0 ↔ if0
    { id: newId("cable"), a: { device: gw1.id, port: 1 }, b: { device: sw1.id, port: 3 } },
    { id: newId("cable"), a: { device: gw2.id, port: 1 }, b: { device: sw2.id, port: 3 } },
    { id: newId("cable"), a: { device: sw1.id, port: 0 }, b: { device: pc1.id, port: 0 } },
    { id: newId("cable"), a: { device: sw1.id, port: 5 }, b: { device: pc2.id, port: 0 } },
    { id: newId("cable"), a: { device: sw2.id, port: 1 }, b: { device: pc3.id, port: 0 } },
    { id: newId("cable"), a: { device: sw2.id, port: 6 }, b: { device: pc4.id, port: 0 } },
  ];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "집 A 192.168.1.0/24", tint: "blue", ...zoneAround(t, [gw1.id, sw1.id, pc1.id, pc2.id], 24)! },
    { id: newId("zone"), label: "집 B 192.168.2.0/24", tint: "green", ...zoneAround(t, [gw2.id, sw2.id, pc3.id, pc4.id], 24)! },
  ];
  return t;
}

/** 백본: 집 세 곳의 게이트웨이 if0 을 스위치 하나(10.0.0.0/24, 라우터만 사는 서브넷)에 모은다. 인터넷 없음 */
export function exampleBackboneTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const bb = add("switch", 368, 40);
  bb.name = "sw-backbone";
  const homes = [
    { x: 48, link: "10.0.0.1", lan: "192.168.1", bbPort: 0 },
    { x: 368, link: "10.0.0.2", lan: "192.168.2", bbPort: 3 },
    { x: 688, link: "10.0.0.3", lan: "192.168.3", bbPort: 7 },
  ];
  const cables: Cable[] = [];
  const zones: Zone[] = [];
  const tints: ZoneTint[] = ["blue", "green", "amber"];
  homes.forEach((h, i) => {
    const gw = add("gateway", h.x, 216);
    gw.l3 = {
      interfaces: [
        { ipMode: "static", ip: h.link, prefix: 24, gateway: "" }, // if0: 백본 쪽. 인터넷이 없으니 디폴트 라우트 없음
        { ipMode: "static", ip: `${h.lan}.1`, prefix: 24, gateway: "" },
        { ipMode: "static", ip: "", prefix: 24, gateway: "" },
      ],
      // 다른 집 서브넷마다 그 집 게이트웨이의 백본 주소로
      routes: homes.filter((o) => o !== h).map((o) => ({ dest: `${o.lan}.0`, prefix: 24, via: o.link })),
    };
    const sw = add("switch", h.x, 392);
    const a = add(i === 2 ? "server" : "pc", h.x - 40, 560);
    const b = add("pc", h.x + 120, 560);
    a.host = { ipMode: "static", ip: `${h.lan}.10`, prefix: 24, gateway: `${h.lan}.1`, services: i === 2 ? [80] : [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
    b.host = { ipMode: "static", ip: `${h.lan}.11`, prefix: 24, gateway: `${h.lan}.1`, services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
    cables.push(
      { id: newId("cable"), a: { device: gw.id, port: 0 }, b: { device: bb.id, port: h.bbPort } },
      { id: newId("cable"), a: { device: gw.id, port: 1 }, b: { device: sw.id, port: 3 } },
      { id: newId("cable"), a: { device: sw.id, port: 0 }, b: { device: a.id, port: 0 } },
      { id: newId("cable"), a: { device: sw.id, port: 6 }, b: { device: b.id, port: 0 } },
    );
    zones.push({ id: newId("zone"), label: `집 ${i + 1} ${h.lan}.0/24`, tint: tints[i]!, ...zoneAround({ devices, cables: [] }, [gw.id, sw.id, a.id, b.id], 20)! });
  });
  zones.push({ id: newId("zone"), label: "백본 10.0.0.0/24 (라우터만)", tint: "gray", ...zoneAround({ devices, cables: [] }, [bb.id], 20)! });
  return { devices, cables, zones };
}

/**
 * 도커 호스트를 부품으로: 집 LAN 의 PC 한 대(docker-host) 안에 브리지 네트워크(172.18.0.0/16)와 컨테이너 3개.
 * NAT 박스 = 호스트의 iptables(MASQUERADE + -p DNAT), 스위치 = 브리지(veth 가 꽂히는 곳), 서버 = 컨테이너, DNS 서버 = embedded DNS(실제로는 127.0.0.11).
 */
export function exampleDockerTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const inet = add("internet", 344, -232);
  const rt = add("router", 344, -80);
  const sw = add("switch", 344, 96);
  const pc = add("pc", 120, 264); // 같은 집 LAN 의 다른 PC
  const host = add("nat", 568, 264); // 도커가 돌아가는 컴퓨터. outside = 그 컴퓨터의 LAN NIC, inside = 브리지 게이트웨이
  host.name = "docker-host";
  host.l3 = {
    interfaces: [
      { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" }, // 공유기에서 주소를 받는다 (컴퓨터 한 대일 뿐)
      { ipMode: "static", ip: "172.18.0.1", prefix: 16, gateway: "" }, // 사용자 정의 브리지 "app" 의 게이트웨이
    ],
    routes: [],
    // docker run -p 8080:80 web
    forwards: [{ publicPort: 8080, lanIp: "172.18.0.2", lanPort: 80 }],
  };
  const br = add("switch", 568, 440);
  br.name = "bridge (app)";
  const web = add("server", 456, 608);
  const db = add("server", 616, 608);
  const dns = add("server", 776, 608);
  web.name = "web";
  db.name = "db";
  dns.name = "embedded-dns";
  const container = (d: Device, ip: string, services: number[]) => {
    d.host = { ipMode: "static", ip, prefix: 16, gateway: "172.18.0.1", dns: "172.18.0.53", services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  container(web, "172.18.0.2", [80]);
  container(db, "172.18.0.3", [5432]);
  container(dns, "172.18.0.53", []);
  // 같은 사용자 정의 네트워크의 컨테이너는 이름으로 찾는다. 모르는 이름은 호스트가 쓰는 DNS 로 넘긴다
  dns.host!.dnsServer = {
    enabled: true,
    records: [
      { name: "web", ip: "172.18.0.2" },
      { name: "db", ip: "172.18.0.3" },
    ],
    upstream: "8.8.8.8",
  };
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: rt.id, port: 0 } },
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 3 } },
    { id: newId("cable"), a: { device: sw.id, port: 0 }, b: { device: pc.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 7 }, b: { device: host.id, port: 0 } }, // 호스트 NIC
    { id: newId("cable"), a: { device: host.id, port: 1 }, b: { device: br.id, port: 3 } }, // 브리지 게이트웨이
    { id: newId("cable"), a: { device: br.id, port: 0 }, b: { device: web.id, port: 0 } }, // veth
    { id: newId("cable"), a: { device: br.id, port: 4 }, b: { device: db.id, port: 0 } },
    { id: newId("cable"), a: { device: br.id, port: 7 }, b: { device: dns.id, port: 0 } },
  ];
  const t: Topology = { devices, cables };
  // 영역: 점선 네모 안은 전부 "컴퓨터 한 대(docker-host) 안" 이라는 뜻
  t.zones = [
    { id: newId("zone"), label: "docker-host 한 대 안 (브리지 네트워크 app)", tint: "blue", ...zoneAround(t, [host.id, br.id, web.id, db.id, dns.id])! },
    { id: newId("zone"), label: "집 LAN 192.168.0.0/24", tint: "gray", ...zoneAround(t, [rt.id, sw.id, pc.id], 24)! },
  ];
  return t;
}

/** 허브 vs 스위치: 같은 공유기 아래 한쪽은 허브, 한쪽은 스위치. ping 이 어디까지 퍼지는지 비교 */
export function exampleHubTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const rt = add("router", 344, 0);
  const hub = add("hub", 112, 200);
  const sw = add("switch", 560, 200);
  const pc1 = add("pc", 40, 376);
  const pc2 = add("pc", 200, 376);
  const pc3 = add("pc", 504, 376);
  const pc4 = add("pc", 664, 376);
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: hub.id, port: 1 } },
    { id: newId("cable"), a: { device: rt.id, port: 4 }, b: { device: sw.id, port: 3 } },
    { id: newId("cable"), a: { device: hub.id, port: 0 }, b: { device: pc1.id, port: 0 } },
    { id: newId("cable"), a: { device: hub.id, port: 3 }, b: { device: pc2.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 0 }, b: { device: pc3.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 7 }, b: { device: pc4.id, port: 0 } },
  ];
  return { devices, cables };
}

/** 방화벽: 공유기가 나가는 TCP 80 만 막는다. ping 은 되고 웹 연결만 차단되는 걸 본다 */
export function exampleFirewallTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const inet = add("internet", 344, -40);
  const rt = add("router", 344, 96);
  rt.router = {
    ...rt.router!,
    firewall: {
      enabled: true,
      defaultPolicy: "allow",
      stateful: true,
      rules: [
        { action: "deny", proto: "tcp", direction: "out", src: "", dst: "", dstPort: "80" },
        { action: "deny", proto: "icmp", direction: "in", src: "", dst: "", dstPort: "" },
      ],
    },
  };
  const sw = add("switch", 344, 272);
  const pc = add("pc", 232, 440);
  const laptop = add("laptop", 456, 440);
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: rt.id, port: 0 } },
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 2 }, b: { device: pc.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 5 }, b: { device: laptop.id, port: 0 } },
  ];
  return { devices, cables };
}

/** 방화벽 장비: 스위치와 서버 사이에 투명 방화벽을 끼워 서버로 오는 ping 만 막는다. 주소는 하나도 안 바꾼다 */
export function exampleFirewallApplianceTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const rt = add("router", 344, -40);
  const sw = add("switch", 344, 136);
  const pc = add("pc", 120, 320);
  const laptop = add("laptop", 264, 320);
  const fw = add("firewall", 520, 304);
  fw.firewall = {
    enabled: true,
    defaultPolicy: "allow",
    stateful: true,
    // outside(스위치 쪽)에서 서버로 들어오는 ping 만 차단. TCP 80 은 열려 있고, 서버가 먼저 시작한 통신의 응답은 Stateful 로 통과
    rules: [{ action: "deny", proto: "icmp", direction: "in", src: "", dst: "", dstPort: "" }],
  };
  const srv = add("server", 564, 488);
  srv.host = { ipMode: "static", ip: "192.168.0.20", prefix: 24, gateway: "192.168.0.1", dns: "192.168.0.1", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 3 } },
    { id: newId("cable"), a: { device: sw.id, port: 0 }, b: { device: pc.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 2 }, b: { device: laptop.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 7 }, b: { device: fw.id, port: 0 } }, // outside ← 스위치
    { id: newId("cable"), a: { device: fw.id, port: 1 }, b: { device: srv.id, port: 0 } }, // inside → 서버
  ];
  const t: Topology = { devices, cables };
  t.zones = [{ id: newId("zone"), label: "방화벽 뒤 (보호 구역)", tint: "amber", ...zoneAround(t, [fw.id, srv.id], 20)! }];
  return t;
}

/** 무선 로밍: 같은 SSID 의 AP 두 대. 스마트폰을 끌어 옮기면 가까운 AP 로 갈아탄다 */
export function exampleRoamingTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const rt = add("router", 344, 0);
  const sw = add("switch", 344, 176);
  const ap1 = add("ap", 16, 352);
  const ap2 = add("ap", 704, 352);
  ap1.ap = { enabled: true, ssid: "office" };
  ap2.ap = { enabled: true, ssid: "office" };
  const phone = add("phone", 56, 544);
  phone.wifi = { ssid: "office" };
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 3 } },
    { id: newId("cable"), a: { device: sw.id, port: 0 }, b: { device: ap1.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 7 }, b: { device: ap2.id, port: 0 } },
  ];
  return { devices, cables };
}

export type ExampleId = "starter" | "router" | "parts" | "homes" | "backbone" | "gateways" | "hub" | "vlan" | "firewall" | "fwbox" | "roaming" | "docker";

export interface ExampleSpec {
  id: ExampleId;
  /** 메뉴 묶음 */
  group: string;
  label: string;
  /** 불러온 뒤 무엇을 해 보면 되는지 한 줄 */
  blurb: string;
  build: () => Topology;
}

export const EXAMPLES: Record<ExampleId, ExampleSpec> = {
  starter: { id: "starter", group: "기본", label: "PC 2대 + 스위치 (수동 IP)", blurb: "pc-1 에서 pc-2 로 ping 하면 ARP 로 MAC 을 찾은 뒤 ICMP 가 오갑니다.", build: exampleStarterTopology },
  router: { id: "router", group: "기본", label: "공유기 하나로 (DHCP + NAT + 포트 포워딩 + Wi-Fi)", blurb: "케이블만 꽂으면 DHCP 로 주소를 받고, google.com 으로 ping 하면 DNS → NAT 를 거칩니다.", build: exampleTopology },
  parts: { id: "parts", group: "기능 단위", label: "기능 단위로 (NAT 박스 + 게이트웨이 + DHCP/DNS 서버)", blurb: "공유기를 상자별로 뜯은 구성. 노트북은 게이트웨이 릴레이로 다른 서브넷의 DHCP 서버에서 주소를 받습니다.", build: examplePartsTopology },
  homes: {
    id: "homes",
    group: "기능 단위",
    label: "집 두 곳 잇기 (게이트웨이 ↔ 게이트웨이, 인터넷 없음)",
    blurb: "pc-1 → 192.168.2.10 은 gw-1 → gw-2 두 홉을 지납니다. \"경로\" 로 홉을 확인하고, gw-1 의 스태틱 라우팅을 지우면 No route 로 실패합니다.",
    build: exampleTwoHomesTopology,
  },
  backbone: {
    id: "backbone",
    group: "기능 단위",
    label: "백본 스위치로 집 세 곳 잇기 (라우터 전용 서브넷)",
    blurb: "게이트웨이 셋의 if0 이 sw-backbone(10.0.0.0/24) 에서 만납니다. 게이트웨이마다 다른 두 집으로 가는 스태틱 라우팅이 있고, 하나를 지우면 그 집만 못 갑니다.",
    build: exampleBackboneTopology,
  },
  gateways: { id: "gateways", group: "기능 단위", label: "게이트웨이 2단 (라우터 전용 서브넷 + 스태틱 라우팅)", blurb: "pc-1 → 192.168.5.10 은 gw-1 이 스태틱 라우팅으로 gw-2 에 바로 넘기고, 인터넷은 NAT 로 올라갑니다. NAT 의 스태틱 라우팅을 지우면 응답이 돌아오지 못합니다.", build: exampleTwoGatewaysTopology },
  hub: { id: "hub", group: "L2", label: "허브 vs 스위치", blurb: "pc-1 → pc-2 ping 이 허브의 모든 포트(공유기까지)로 복제되는 것과, pc-3 → pc-4 가 스위치에서 그 포트로만 가는 것을 비교하세요.", build: exampleHubTopology },
  vlan: { id: "vlan", group: "L2", label: "VLAN 으로 나눈 사무실 (트렁크 + 서브 인터페이스)", blurb: "같은 스위치인데 VLAN 10 과 20 은 게이트웨이 서브 인터페이스를 거쳐야 통신됩니다.", build: exampleVlanTopology },
  firewall: { id: "firewall", group: "서비스", label: "방화벽 (ping 은 되고 웹은 막힘)", blurb: "pc-1 에서 example.com 으로 ping 은 되지만 TCP 80 연결은 공유기 방화벽 규칙 1 에서 차단됩니다. 규칙 2(인바운드 ICMP 차단)는 바깥에서 먼저 시작한 ping 을 막는 규칙이고, 안에서 시작한 ping 의 응답은 Stateful 검사로 통과합니다.", build: exampleFirewallTopology },
  fwbox: {
    id: "fwbox",
    group: "서비스",
    label: "방화벽 장비 (서버 앞에 끼운 투명 방화벽)",
    blurb: "pc-1 → srv-1 ping 은 fw-1 에서 차단되지만 TCP 80 연결은 됩니다. srv-1 → pc-1 ping 은 응답이 Stateful 검사로 돌아오고, srv-1 → pc-1 traceroute 는 1홉 — fw-1 은 IP 가 없어 홉에 안 보입니다.",
    build: exampleFirewallApplianceTopology,
  },
  docker: {
    id: "docker",
    group: "서비스",
    label: "도커 호스트를 부품으로 (브리지 + MASQUERADE + -p + embedded DNS)",
    blurb: "pc-1 에서 172.18.0.2 로 ping 은 실패하지만(호스트 뒤 사설망), docker-host 의 LAN 주소:8080 으로 TCP 연결은 -p 포워딩으로 web 에 닿습니다. web 에서 db 는 이름으로, google.com 은 MASQUERADE 로 나갑니다.",
    build: exampleDockerTopology,
  },
  roaming: { id: "roaming", group: "무선", label: "무선 로밍 (같은 SSID 의 AP 두 대)", blurb: "phone-1 을 오른쪽 AP 쪽으로 끌면 가까운 AP 로 갈아타고 DHCP 로 새로 임대받습니다.", build: exampleRoamingTopology },
};

export const EXAMPLE_LIST: ExampleSpec[] = Object.values(EXAMPLES);

/** 장치 포트의 VLAN 모드 (스위치가 아니면 undefined) */
export function portVlanOf(d: Device, port: number): number | "trunk" | undefined {
  if (d.kind !== "switch") return undefined;
  return d.switch?.vlans[port] ?? 1;
}

/** VLAN 번호 → 캔버스 색 인덱스 (1 은 기본색). 같은 번호는 항상 같은 색 */
export const VLAN_COLORS = ["#e0a526", "#2ba84a", "#2b8fd6", "#8b5cf6", "#e05a8a", "#14b8a6", "#f97316"];
export function vlanColor(vlan: number): string {
  return VLAN_COLORS[(vlan - 1) % VLAN_COLORS.length]!;
}
