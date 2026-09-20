import { computed, effect, signal } from "@preact/signals";
import { lintTopology, type LintIssue } from "./lint";
import {
  alignDevices,
  cloneDevices,
  createDevice,
  DEVICE_SPECS,
  EMPTY_TOPOLOGY,
  EXAMPLES,
  newId,
  normalizeTopology,
  parseTopology,
  planCable,
  serializeTopology,
  snap,
  type AlignMode,
  type Cable,
  type Device,
  type DeviceKind,
  type ExampleId,
  type PortRef,
  type Topology,
} from "./topology";

/** 선택: 장치 하나 / 장치 여러 개 / 케이블 하나 */
export type Selection = { type: "device"; id: string } | { type: "devices"; ids: string[] } | { type: "cable"; id: string } | null;

/** 선택된 장치 id 목록 (단일·다중 공통) */
export function selectedDeviceIds(sel: Selection): string[] {
  if (!sel) return [];
  if (sel.type === "device") return [sel.id];
  if (sel.type === "devices") return sel.ids;
  return [];
}

/** 장치 id 목록을 선택 상태로: 0개 → 없음, 1개 → 단일, 여러 개 → 다중 */
export function selectionOf(ids: string[]): Selection {
  if (ids.length === 0) return null;
  if (ids.length === 1) return { type: "device", id: ids[0]! };
  return { type: "devices", ids };
}
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
// 브라우저 API 는 있을 때만 (vitest 에서는 없다)
const prefersDark = typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: dark)").matches;
export const theme = signal<Theme>(load<Theme>(THEME_KEY) ?? (prefersDark ? "dark" : "light"));
export const viewport = signal({ x: 0, y: 0, k: 1 });
export const logOpen = signal(false);
/** 증가할 때마다 캔버스가 내용에 맞춰 뷰포트를 다시 잡는다 */
export const fitRequest = signal(0);

export function requestFit(): void {
  fitRequest.value += 1;
}

// ---------- 되돌리기 ----------

const HISTORY_CAP = 100;
let past: Topology[] = [];
let future: Topology[] = [];
/** 드래그 중에는 시작 시점 한 번만 기록한다 */
let coalescing = false;
export const canUndo = signal(false);
export const canRedo = signal(false);

function refreshHistoryFlags(): void {
  canUndo.value = past.length > 0;
  canRedo.value = future.length > 0;
}

/** 모든 편집은 여기를 거친다: 이전 상태를 기록하고 다시 실행 스택은 비운다 */
function setTopology(next: Topology): void {
  if (!coalescing) {
    past.push(topology.peek());
    if (past.length > HISTORY_CAP) past.shift();
    future = [];
  }
  topology.value = next;
  refreshHistoryFlags();
}

/** 연속 변경(드래그)의 시작. 끝날 때 endCoalesce() */
export function beginCoalesce(): void {
  if (coalescing) return;
  past.push(topology.peek());
  if (past.length > HISTORY_CAP) past.shift();
  future = [];
  coalescing = true;
  refreshHistoryFlags();
}

export function endCoalesce(): void {
  coalescing = false;
}

export function undo(): void {
  const prev = past.pop();
  if (!prev) return;
  future.push(topology.peek());
  topology.value = prev;
  pruneSelection();
  refreshHistoryFlags();
}

export function redo(): void {
  const next = future.pop();
  if (!next) return;
  past.push(topology.peek());
  topology.value = next;
  pruneSelection();
  refreshHistoryFlags();
}

/** 되돌린 뒤 사라진 장치·케이블은 선택에서 뺀다 */
function pruneSelection(): void {
  const t = topology.peek();
  const s = selection.peek();
  if (!s) return;
  if (s.type === "cable") {
    if (!t.cables.some((c) => c.id === s.id)) selection.value = null;
    return;
  }
  const alive = selectedDeviceIds(s).filter((id) => t.devices.some((d) => d.id === id));
  if (alive.length !== selectedDeviceIds(s).length) selection.value = selectionOf(alive);
}

export const selectedDevice = computed<Device | undefined>(() => {
  const s = selection.value;
  return s?.type === "device" ? topology.value.devices.find((d) => d.id === s.id) : undefined;
});
/** 구성 검사 결과. 토폴로지가 바뀔 때만 다시 계산한다 */
export const lintIssues = computed<LintIssue[]>(() => lintTopology(topology.value));

export const selectedCable = computed<Cable | undefined>(() => {
  const s = selection.value;
  return s?.type === "cable" ? topology.value.cables.find((c) => c.id === s.id) : undefined;
});

effect(() => save(TOPOLOGY_KEY, topology.value));
effect(() => {
  save(THEME_KEY, theme.value);
  if (typeof document !== "undefined") document.documentElement.dataset.theme = theme.value;
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
  setTopology({ ...t, devices: [...t.devices, device] });
  selection.value = { type: "device", id: device.id };
  return device;
}

/** 여러 장치를 같은 양만큼 옮긴다 (드래그 시작 위치 기준) */
export function moveDevices(starts: Map<string, { x: number; y: number }>, dx: number, dy: number): void {
  const t = topology.value;
  setTopology({ ...t, devices: t.devices.map((d) => (starts.has(d.id) ? { ...d, x: snap(starts.get(d.id)!.x + dx), y: snap(starts.get(d.id)!.y + dy) } : d)) });
}

export function updateDevice(id: string, patch: (d: Device) => Device): void {
  const t = topology.value;
  setTopology({ ...t, devices: t.devices.map((d) => (d.id === id ? patch(d) : d)) });
}

/** 여러 장치에 같은 패치를 적용한다 (일괄 설정) */
export function updateDevices(ids: string[], patch: (d: Device) => Device): void {
  const t = topology.value;
  const set = new Set(ids);
  setTopology({ ...t, devices: t.devices.map((d) => (set.has(d.id) ? patch(d) : d)) });
}

export function removeDevice(id: string): void {
  removeDevices([id]);
}

export function removeDevices(ids: string[]): void {
  const t = topology.value;
  const set = new Set(ids);
  setTopology({
    devices: t.devices.filter((d) => !set.has(d.id)),
    cables: t.cables.filter((c) => !set.has(c.a.device) && !set.has(c.b.device)),
  });
  const remaining = selectedDeviceIds(selection.value).filter((id) => !set.has(id));
  if (selection.value && selection.value.type !== "cable") selection.value = selectionOf(remaining);
}

export function alignSelected(mode: AlignMode): void {
  const ids = selectedDeviceIds(selection.value);
  if (ids.length < 2) return;
  setTopology(alignDevices(topology.value, ids, mode));
}

export function selectAll(): void {
  selection.value = selectionOf(topology.value.devices.map((d) => d.id));
}

/** Shift+클릭: 선택에 넣거나 뺀다 */
export function toggleDeviceSelection(id: string): void {
  const ids = selectedDeviceIds(selection.value);
  selection.value = selectionOf(ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id]);
}

// ---------- 복사·붙여넣기 ----------

/** 붙여넣기 비켜 놓는 거리: 호스트 타일(64) + 이름 줄(46) 보다 크게 */
const PASTE_OFFSET = 112;
let clipboard: { topology: Topology; ids: string[] } | null = null;
let pasteCount = 0;

/** 선택한 장치를 클립보드에 담는다. 담은 개수를 돌려준다 */
export function copySelected(): number {
  const ids = selectedDeviceIds(selection.value);
  if (ids.length === 0) return 0;
  clipboard = { topology: topology.value, ids };
  pasteCount = 0;
  return ids.length;
}

/** 클립보드의 장치를 조금 비켜서 붙여 넣고 그것들을 선택한다 */
export function paste(): Device[] {
  if (!clipboard) return [];
  pasteCount += 1;
  const offset = PASTE_OFFSET * pasteCount;
  const t = topology.value;
  const { devices, cables } = cloneDevices(clipboard.topology, clipboard.ids, { x: offset, y: offset });
  if (devices.length === 0) return [];
  setTopology({ devices: [...t.devices, ...devices], cables: [...t.cables, ...cables] });
  selection.value = selectionOf(devices.map((d) => d.id));
  return devices;
}

/** 복사 + 붙여넣기 한 번에 (⌘D) */
export function duplicateSelected(): Device[] {
  if (copySelected() === 0) return [];
  return paste();
}

/** 두 장치를 잇는다. 포트는 상대를 향한 빈 포트를 자동 선택. 실패 사유를 문자열로 돌려준다 */
export function connectDevices(aId: string, bId: string): { cable?: Cable; error?: string } {
  const plan = planCable(topology.value, aId, bId);
  if ("error" in plan) return { error: plan.error };
  return { cable: addCable(plan.a, plan.b) };
}

export function addCable(a: PortRef, b: PortRef): Cable {
  const t = topology.value;
  const cable: Cable = { id: newId("cable"), a, b };
  setTopology({ ...t, cables: [...t.cables, cable] });
  selection.value = { type: "cable", id: cable.id };
  return cable;
}

export function updateCable(id: string, patch: (c: Cable) => Cable): void {
  const t = topology.value;
  setTopology({ ...t, cables: t.cables.map((c) => (c.id === id ? patch(c) : c)) });
}

export function removeCable(id: string): void {
  const t = topology.value;
  setTopology({ ...t, cables: t.cables.filter((c) => c.id !== id) });
  if (selection.value?.type === "cable" && selection.value.id === id) selection.value = null;
}

export function removeSelected(): void {
  const s = selection.value;
  if (!s) return;
  if (s.type === "cable") removeCable(s.id);
  else removeDevices(selectedDeviceIds(s));
}

export type { ExampleId } from "./topology";

export function loadExample(which: ExampleId = "router"): void {
  setTopology(EXAMPLES[which].build());
  selection.value = null;
  requestFit();
}

export function clearAll(): void {
  setTopology(EMPTY_TOPOLOGY);
  selection.value = null;
}

// ---------- 저장·불러오기 (JSON) ----------

export function exportJson(): string {
  return serializeTopology(topology.value);
}

/** JSON 파일 내용으로 토폴로지를 바꾼다. 실패 사유를 돌려준다 */
export function importJson(text: string): { error?: string; devices?: number } {
  const r = parseTopology(text);
  if (!r.topology) return { error: r.error };
  setTopology(r.topology);
  selection.value = null;
  requestFit();
  return { devices: r.topology.devices.length };
}

export function toggleTheme(): void {
  theme.value = theme.value === "dark" ? "light" : "dark";
}
