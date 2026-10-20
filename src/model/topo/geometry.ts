// 캔버스 기하와 편집: 포트가 붙는 점, 쓰는 포트, 장치 묶음 복제·정렬
import { snap } from "./cables";
import { type Cable, type Device, type Topology, newId, nextMac, nextName, specOf } from "./device";
import { type PortSide } from "./specs";

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
    // WireGuard 개인 키는 장치의 신원이라 복사하지 않는다 (MAC 처럼 새로 — 새 id 에서 만든 키)
    if (copy.router?.wgServer?.privateKey) delete copy.router.wgServer.privateKey;
    if (copy.router?.wgClient?.privateKey) delete copy.router.wgClient.privateKey;
    if (copy.host?.ra?.wg?.privateKey) delete copy.host.ra.wg.privateKey;
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
