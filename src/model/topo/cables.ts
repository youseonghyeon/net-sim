// 케이블: 꽂을 수 있는지·빈 포트·상대 포트, 스위치 포트의 VLAN 색
import { type Cable, type Device, type PortRef, type Topology, specOf } from "./device";
import { usedPorts } from "./geometry";
import { DEVICE_SPECS, type PortSide } from "./specs";

/** 두 장치를 잇는 케이블의 양 끝 포트를 정한다. 못 잇는 이유는 사용자에게 보일 문장으로 돌려준다 */
/** 이 포트에 케이블을 꽂을 수 있는지. 안 되면 이유 (except: 옮기는 중인 케이블은 자기 자리를 비운 것으로 본다) */
export function portProblem(t: Topology, ref: PortRef, except?: string): string | undefined {
  const d = t.devices.find((x) => x.id === ref.device);
  if (!d) return "장치를 찾을 수 없습니다";
  const p = specOf(d).ports[ref.port];
  if (!p) return `${d.name} 에는 ${ref.port + 1}번째 포트가 없습니다`;
  if (p.radio) return `${d.name} ${p.name} 은(는) 무선 슬롯이라 케이블을 꽂을 수 없습니다`;
  const busy = t.cables.find((c) => c.id !== except && ((c.a.device === ref.device && c.a.port === ref.port) || (c.b.device === ref.device && c.b.port === ref.port)));
  if (busy) return `${d.name} ${p.name} 에는 이미 케이블이 꽂혀 있습니다. 다른 포트를 고르거나 그 케이블을 먼저 빼세요`;
  return undefined;
}

/**
 * 두 장치를 잇는 케이블의 양 끝 포트를 정한다. aPort/bPort 를 주면 그 포트를 쓰고(포트 칸 위에 놓은 경우), 없으면 상대를 향한 빈 포트를 고른다.
 * 못 잇는 이유는 사용자에게 보일 문장으로 돌려준다
 */
export function planCable(t: Topology, aId: string, bId: string, aPort?: number, bPort?: number): { a: PortRef; b: PortRef } | { error: string } {
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
  const pa = aPort ?? freePort(t, aId, b.y);
  const pb = bPort ?? freePort(t, bId, a.y);
  if (pa === undefined) return { error: `${a.name} 에 빈 포트가 없습니다` };
  if (pb === undefined) return { error: `${b.name} 에 빈 포트가 없습니다` };
  const ra = { device: aId, port: pa };
  const rb = { device: bId, port: pb };
  const why = portProblem(t, ra) ?? portProblem(t, rb);
  if (why) return { error: why };
  return { a: ra, b: rb };
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
