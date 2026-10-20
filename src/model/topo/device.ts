// 장치·케이블·영역·토폴로지의 모양, 새 장치 만들기(id·이름·MAC), 영역 계산
import { snap } from "./cables";
import { DEFAULT_DHCP_SERVER, DEFAULT_FIREWALL_SETTINGS, DEFAULT_LB_SETTINGS, DEFAULT_WAN, DEFAULT_WIFI_BASE, type FirewallSettings, type HostSettings, type L3Settings, ROUTER_WAN2_PORT, type RouterSettings, type SwitchSettings, type WifiBaseSettings, type WifiClientSettings, defaultL3 } from "./settings";
import { DEVICE_SPECS, type DeviceKind, type DeviceSpec } from "./specs";

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
  /** 인터넷 노드(ISP) */
  internet?: InternetSettings;
}

/** 인터넷 노드: ISP 대역 (가입자마다 /29 를 나눠 준다). 없으면 203.0.113.0/24 */
export interface InternetSettings {
  net: string;
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

/** 멀티 WAN 을 켠 공유기의 스펙: lan4 의 이름이 wan2 (위치는 그대로) */
let routerWan2Spec: DeviceSpec | undefined;

export function specOf(device: Device): DeviceSpec {
  if (device.kind === "router" && device.router?.wan2?.enabled) {
    const base = DEVICE_SPECS.router;
    routerWan2Spec ??= { ...base, ports: base.ports.map((p, i) => (i === ROUTER_WAN2_PORT ? { ...p, name: "wan2" } : p)) };
    return routerWan2Spec;
  }
  return DEVICE_SPECS[device.kind];
}

let idSeq = 0;
export function newId(prefix: string): string {
  idSeq += 1;
  return `${prefix}_${Date.now().toString(36)}${idSeq.toString(36)}`;
}

/** 골든 트레이스 테스트용: id 순번을 처음부터 (Date.now 를 고정해 두면 예제마다 같은 id — 키·포트·xid 가 id 해시에서 나온다) */
export function resetIdSequence(): void {
  idSeq = 0;
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
  if (kind === "lb") device.host!.lb = { ...DEFAULT_LB_SETTINGS, enabled: true, backends: [] };
  return device;
}
