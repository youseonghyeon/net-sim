// 편집 가능한 토폴로지 모델. 시뮬레이션 코어(src/core)와 분리되어 있고, 실행 시 코어 Network 로 변환된다.

export type DeviceKind = "pc" | "laptop" | "server" | "switch" | "router" | "internet";
export type Role = "host" | "switch" | "router" | "internet";
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
    ports: [{ name: "uplink", side: "top" }, ...lanPorts(8, "bottom", "eth", 1)],
    namePrefix: "sw",
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

export const PALETTE_ORDER: DeviceKind[] = ["pc", "laptop", "server", "switch", "router", "internet"];

export interface HostSettings {
  ipMode: "dhcp" | "static";
  ip: string;
  prefix: number;
  gateway: string;
}

export interface WanSettings {
  ipMode: "dhcp" | "static";
  ip: string;
  prefix: number;
  gateway: string;
}

export interface RouterSettings {
  lanIp: string;
  lanPrefix: number;
  dhcp: { enabled: boolean; start: string; end: string };
  wan: WanSettings;
}

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
}

export interface PortRef {
  device: string;
  port: number;
}

export interface Cable {
  id: string;
  a: PortRef;
  b: PortRef;
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
  if (spec.role === "host") device.host = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" };
  if (spec.role === "router") {
    device.router = { lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.199" }, wan: { ...DEFAULT_WAN } };
  }
  return device;
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
    if (spec.role === "host" && !fixed.host) fixed.host = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" };
    if (spec.role === "router") {
      if (!fixed.router) fixed.router = { lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.199" }, wan: { ...DEFAULT_WAN } };
      else if (!fixed.router.wan) fixed.router = { ...fixed.router, wan: { ...DEFAULT_WAN } };
    }
    devices.push(fixed);
  }
  const ids = new Set(devices.map((d) => d.id));
  const cables = t.cables.filter((c) => ids.has(c.a.device) && ids.has(c.b.device));
  return { devices, cables };
}

/** 인터넷 + 라우터 + 스위치 + 호스트 3대 예제 */
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
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: rt.id, port: 0 } }, // isp ↔ wan
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 0 } }, // lan1 ↔ uplink
    { id: newId("cable"), a: { device: sw.id, port: 2 }, b: { device: pc.id, port: 0 } }, // eth2
    { id: newId("cable"), a: { device: sw.id, port: 4 }, b: { device: laptop.id, port: 0 } }, // eth4
    { id: newId("cable"), a: { device: sw.id, port: 6 }, b: { device: srv.id, port: 0 } }, // eth6
  ];
  return { devices, cables };
}
