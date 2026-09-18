import { computed, effect, signal } from "@preact/signals";
import {
  createDevice,
  DEVICE_SPECS,
  EMPTY_TOPOLOGY,
  exampleTopology,
  freePort,
  newId,
  normalizeTopology,
  snap,
  type Cable,
  type Device,
  type DeviceKind,
  type PortRef,
  type Topology,
} from "./topology";

export type Selection = { type: "device"; id: string } | { type: "cable"; id: string } | null;
export type Tool = "select" | "cable";
export type Theme = "light" | "dark";

const TOPOLOGY_KEY = "net-sim.topology.v1";
const THEME_KEY = "net-sim.theme";

function load<T>(key: string): T | undefined {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : undefined;
  } catch {
    return undefined;
  }
}

function save(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* 저장 불가 환경(프라이빗 창 등)은 조용히 무시 */
  }
}

const saved = load<Topology>(TOPOLOGY_KEY);
export const topology = signal<Topology>(saved ? normalizeTopology(saved) : EMPTY_TOPOLOGY);
export const selection = signal<Selection>(null);
export const tool = signal<Tool>("select");
export const theme = signal<Theme>(load<Theme>(THEME_KEY) ?? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
export const viewport = signal({ x: 0, y: 0, k: 1 });
export const logOpen = signal(false);
/** 증가할 때마다 캔버스가 내용에 맞춰 뷰포트를 다시 잡는다 */
export const fitRequest = signal(0);

export function requestFit(): void {
  fitRequest.value += 1;
}

export const selectedDevice = computed<Device | undefined>(() => {
  const s = selection.value;
  return s?.type === "device" ? topology.value.devices.find((d) => d.id === s.id) : undefined;
});
export const selectedCable = computed<Cable | undefined>(() => {
  const s = selection.value;
  return s?.type === "cable" ? topology.value.cables.find((c) => c.id === s.id) : undefined;
});

effect(() => save(TOPOLOGY_KEY, topology.value));
effect(() => {
  save(THEME_KEY, theme.value);
  document.documentElement.dataset.theme = theme.value;
});

// ---------- 편집 동작 ----------

/** 다른 장치와 겹치면 아래로 비켜 놓는다 (클릭으로 추가할 때 화면 중앙이 이미 차 있는 경우) */
function nudgeFree(kind: DeviceKind, x: number, y: number, devices: Device[]): { x: number; y: number } {
  const spec = DEVICE_SPECS[kind];
  const overlaps = (px: number, py: number) =>
    devices.some((d) => {
      const s = DEVICE_SPECS[d.kind];
      return px < d.x + s.width + 16 && px + spec.width + 16 > d.x && py < d.y + s.height + 48 && py + spec.height + 48 > d.y;
    });
  let ny = y;
  for (let i = 0; i < 20 && overlaps(x, ny); i++) ny += 112;
  return { x, y: ny };
}

export function addDevice(kind: DeviceKind, x: number, y: number, avoidOverlap = false): Device {
  const t = topology.value;
  const pos = avoidOverlap ? nudgeFree(kind, snap(x), snap(y), t.devices) : { x: snap(x), y: snap(y) };
  const device = createDevice(kind, pos.x, pos.y, t.devices);
  topology.value = { ...t, devices: [...t.devices, device] };
  selection.value = { type: "device", id: device.id };
  return device;
}

export function moveDevice(id: string, x: number, y: number): void {
  const t = topology.value;
  topology.value = { ...t, devices: t.devices.map((d) => (d.id === id ? { ...d, x, y } : d)) };
}

export function updateDevice(id: string, patch: (d: Device) => Device): void {
  const t = topology.value;
  topology.value = { ...t, devices: t.devices.map((d) => (d.id === id ? patch(d) : d)) };
}

export function removeDevice(id: string): void {
  const t = topology.value;
  topology.value = {
    devices: t.devices.filter((d) => d.id !== id),
    cables: t.cables.filter((c) => c.a.device !== id && c.b.device !== id),
  };
  if (selection.value?.type === "device" && selection.value.id === id) selection.value = null;
}

/** 두 장치를 잇는다. 포트는 상대를 향한 빈 포트를 자동 선택. 실패 사유를 문자열로 돌려준다 */
export function connectDevices(aId: string, bId: string): { cable?: Cable; error?: string } {
  const t = topology.value;
  if (aId === bId) return { error: "같은 장치끼리는 연결할 수 없습니다" };
  const a = t.devices.find((d) => d.id === aId);
  const b = t.devices.find((d) => d.id === bId);
  if (!a || !b) return { error: "장치를 찾을 수 없습니다" };
  const pa = freePort(t, aId, b.y);
  const pb = freePort(t, bId, a.y);
  if (pa === undefined) return { error: `${a.name} 에 빈 포트가 없습니다` };
  if (pb === undefined) return { error: `${b.name} 에 빈 포트가 없습니다` };
  return { cable: addCable({ device: aId, port: pa }, { device: bId, port: pb }) };
}

export function addCable(a: PortRef, b: PortRef): Cable {
  const t = topology.value;
  const cable: Cable = { id: newId("cable"), a, b };
  topology.value = { ...t, cables: [...t.cables, cable] };
  selection.value = { type: "cable", id: cable.id };
  return cable;
}

export function removeCable(id: string): void {
  const t = topology.value;
  topology.value = { ...t, cables: t.cables.filter((c) => c.id !== id) };
  if (selection.value?.type === "cable" && selection.value.id === id) selection.value = null;
}

export function removeSelected(): void {
  const s = selection.value;
  if (!s) return;
  if (s.type === "device") removeDevice(s.id);
  else removeCable(s.id);
}

export function loadExample(): void {
  topology.value = exampleTopology();
  selection.value = null;
  requestFit();
}

export function clearAll(): void {
  topology.value = EMPTY_TOPOLOGY;
  selection.value = null;
}

export function toggleTheme(): void {
  theme.value = theme.value === "dark" ? "light" : "dark";
}
