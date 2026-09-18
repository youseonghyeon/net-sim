// 편집 가능한 토폴로지 모델. 시뮬레이션 코어(src/core)와 분리되어 있고, 실행 시 코어 Network 로 변환된다.

export type DeviceKind = "pc" | "laptop" | "server" | "switch" | "hub" | "router" | "gateway" | "nat" | "internet";
export type Role = "host" | "switch" | "hub" | "router" | "l3" | "internet";
export type PortSide = "top" | "bottom";

export interface PortSpec {
  name: string;
  side: PortSide;
}

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
  router: {
    kind: "router",
    label: "라우터",
    role: "router",
    width: 152,
    height: 62,
    ports: [{ name: "wan", side: "top" }, ...lanPorts(4, "bottom", "lan", 1)],
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

export const PALETTE_ORDER: DeviceKind[] = ["pc", "laptop", "server", "hub", "switch", "router", "gateway", "nat", "internet"];

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
  /** 모르는 이름을 물어볼 상위 DNS */
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

export interface L3Settings {
  interfaces: IfaceSettings[];
  routes: StaticRouteSettings[];
  /** NAT 박스의 포트 포워딩 규칙 */
  forwards?: PortForwardSettings[];
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

export interface RouterSettings {
  lanIp: string;
  lanPrefix: number;
  dhcp: { enabled: boolean; start: string; end: string };
  wan: WanSettings;
  /** DNS 포워더 (공유기 안의 dnsmasq) */
  dns?: { enabled: boolean; upstream: string };
  /** 포트 포워딩 규칙 */
  forwards?: PortForwardSettings[];
}

export const DEFAULT_ROUTER_DNS = { enabled: true, upstream: "8.8.8.8" };

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

export interface Topology {
  devices: Device[];
  cables: Cable[];
}

export const EMPTY_TOPOLOGY: Topology = { devices: [], cables: [] };

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
  return device;
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
  const siblings = spec.ports.filter((q) => q.side === p.side);
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
export function freePort(topology: Topology, deviceId: string, peerY?: number): number | undefined {
  const device = topology.devices.find((d) => d.id === deviceId);
  if (!device) return undefined;
  const used = usedPorts(topology, deviceId);
  const spec = specOf(device);
  const preferred: PortSide = peerY !== undefined && peerY < device.y ? "top" : "bottom";
  const order = spec.ports.map((_, i) => i).sort((a, b) => Number(spec.ports[b]!.side === preferred) - Number(spec.ports[a]!.side === preferred));
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
  for (const d of t.devices) {
    const fixed: Device = { ...d };
    if (!fixed.mac) fixed.mac = nextMac(devices);
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
    if (spec.role === "l3") {
      const def = defaultL3(fixed.kind);
      if (!fixed.l3) fixed.l3 = def;
      else fixed.l3 = { interfaces: def.interfaces.map((d, i) => fixed.l3!.interfaces[i] ?? d), routes: fixed.l3.routes ?? [] };
    }
    if (spec.role === "router") {
      if (!fixed.router) fixed.router = { lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.199" }, wan: { ...DEFAULT_WAN } };
      else if (!fixed.router.wan) fixed.router = { ...fixed.router, wan: { ...DEFAULT_WAN } };
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
    if (c.a.port >= DEVICE_SPECS[da.kind].ports.length || c.b.port >= DEVICE_SPECS[db.kind].ports.length) continue; // 예전 스펙의 포트
    const ka = `${c.a.device}:${c.a.port}`;
    const kb = `${c.b.device}:${c.b.port}`;
    if (usedPort.has(ka) || usedPort.has(kb) || ka === kb) continue; // 같은 포트에 두 케이블: 앞의 것만 남긴다
    usedPort.add(ka);
    usedPort.add(kb);
    cables.push(c);
  }
  return { devices, cables };
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
  rt.router = { ...rt.router!, forwards: [{ publicPort: 80, lanIp: "192.168.0.20", lanPort: 80 }] };
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: rt.id, port: 0 } }, // isp ↔ wan
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 0 } }, // lan1 ↔ eth1
    { id: newId("cable"), a: { device: sw.id, port: 2 }, b: { device: pc.id, port: 0 } }, // eth2
    { id: newId("cable"), a: { device: sw.id, port: 4 }, b: { device: laptop.id, port: 0 } }, // eth4
    { id: newId("cable"), a: { device: sw.id, port: 6 }, b: { device: srv.id, port: 0 } }, // eth6
  ];
  return { devices, cables };
}
