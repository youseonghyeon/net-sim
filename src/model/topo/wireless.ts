// 무선 연결 (파생 상태): 위치·SSID 로 단말이 붙을 기지와 슬롯을 정한다 — "보이지 않는 케이블"
import { type Device, type Topology, specOf } from "./device";
import { DEFAULT_ROUTER_WIFI, DEFAULT_WIFI_BASE, type WifiBaseSettings } from "./settings";
import { WIFI_RANGE } from "./specs";

// ---------- 무선 연결 (파생 상태) ----------

export interface WirelessLink {
  /** 케이블처럼 쓰이는 id: wl_<단말 id>_<기지 id>_<슬롯>. 기지나 슬롯이 바뀌면 다른 링크로 취급된다 */
  id: string;
  client: string;
  base: string;
  /** 기지의 무선 슬롯 포트 번호 */
  slot: number;
  distance: number;
  /** 단말의 무선 포트 번호 (스마트폰 0, 노트북 1 — 노트북의 0 은 유선 eth0) */
  clientPort: number;
  /** 노트북의 유선에 케이블이 꽂혀 있어 이 무선 연결은 대기 중 (유선 우선 — 케이블을 빼면 이쪽으로 넘어감) */
  standby?: boolean;
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
  const taken = new Map<string, Set<number>>();
  for (const b of bases) taken.set(b.id, new Set());
  // 단말마다 가장 가까운 기지부터 정한다
  const cands: { c: Device; order: number; base: Device; distance: number; clientPort: number; standby: boolean }[] = [];
  t.devices.forEach((c, order) => {
    if (!c.wifi || c.wifi.enabled === false) return;
    const ssid = c.wifi.ssid.trim();
    if (!ssid) return;
    const clientPort = specOf(c).ports.findIndex((p) => p.radio);
    if (clientPort < 0) return;
    const cc = center(c);
    let best: { base: Device; distance: number } | undefined;
    for (const b of bases) {
      if (baseSsid(b)!.ssid.trim() !== ssid) continue;
      const bc = center(b);
      const distance = Math.hypot(bc.x - cc.x, bc.y - cc.y);
      if (distance > WIFI_RANGE) continue;
      if (!best || distance < best.distance) best = { base: b, distance };
    }
    if (!best) return;
    // 노트북 유선에 케이블이 꽂혀 있으면 이 무선 연결은 대기 (유선 우선)
    const standby = clientPort > 0 && t.cables.some((k) => (k.a.device === c.id && k.a.port !== clientPort) || (k.b.device === c.id && k.b.port !== clientPort));
    cands.push({ c, order, base: best.base, distance: best.distance, clientPort, standby });
  });
  // 슬롯: 먼저 각자 쓰던 슬롯을 지켜 주고(새 단말이 끼어들어도 붙어 있던 단말이 흔들리지 않게), 남은 단말은 빈 슬롯을 받는다 —
  // 이때 쓰는 연결이 대기 연결(노트북 유선 사용 중)보다 먼저
  const slotOf = new Map<Device, number>();
  for (const k of cands) {
    const slot = slotTable.get(k.base.id)?.get(k.c.id);
    const used = taken.get(k.base.id)!;
    if (slot === undefined || used.has(slot) || !radioSlotPorts(k.base).includes(slot)) continue;
    used.add(slot);
    slotOf.set(k.c, slot);
  }
  for (const k of [...cands].sort((a, b) => Number(a.standby) - Number(b.standby) || a.order - b.order)) {
    if (slotOf.has(k.c)) continue;
    const used = taken.get(k.base.id)!;
    const slot = radioSlotPorts(k.base).find((p) => !used.has(p));
    if (slot === undefined) continue; // 슬롯 부족
    used.add(slot);
    slotOf.set(k.c, slot);
    const table = slotTable.get(k.base.id) ?? new Map<string, number>();
    slotTable.set(k.base.id, table);
    table.set(k.c.id, slot);
  }
  const out: WirelessLink[] = [];
  for (const k of cands) {
    const slot = slotOf.get(k.c);
    if (slot === undefined) continue;
    out.push({ id: `wl_${k.c.id}_${k.base.id}_${slot}`, client: k.c.id, base: k.base.id, slot, distance: Math.round(k.distance), clientPort: k.clientPort, ...(k.standby ? { standby: true } : {}) });
  }
  return out;
}

/** 단말이 왜 안 붙는지 (인스펙터 안내용) */
export function wirelessStatus(t: Topology, client: Device): { linked?: WirelessLink; reason?: string } {
  const link = wirelessLinks(t).find((l) => l.client === client.id);
  if (link) return { linked: link };
  if (client.wifi?.enabled === false) return { reason: "Wi-Fi 가 꺼져 있습니다" };
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
