// 규칙 모듈이 함께 쓰는 것: 이슈 타입, 규칙에 넘기는 문맥(토폴로지·세그먼트 모델·add), 문구 도우미, 마무리(합치기·정렬).
import type { Device, Topology } from "../topology";
import { contains, type Subnet } from "./addr";
import type { GwIface, Model } from "./segments";

export interface LintIssue {
  /** 배지를 붙일 장치 */
  deviceId: string;
  /** error = 통신이 확실히 안 됨, warn = 될 수도 있지만 의심 */
  severity: "error" | "warn";
  /** 안정적인 식별자 (예: "dhcp.no-router") */
  code: string;
  /** 무엇이 잘못됐는지 (한 문장) */
  message: string;
  /** 어떻게 고치는지 (인스펙터 어느 칸인지 구체적으로) */
  fix: string;
  /** 관련 장치 id */
  related?: string[];
}

/** 규칙 함수가 받는 문맥. 규칙은 `add` 로만 이슈를 낸다 (실행 순서 = lint.ts 의 호출 순서) */
export interface LintContext {
  t: Topology;
  m: Model;
  add: (i: LintIssue) => void;
}

// ---------- 규칙 도우미 ----------

const SEVERITY_RANK = { error: 0, warn: 1 } as const;

export function names(devices: Device[]): string {
  return devices.map((d) => d.name).join(", ");
}

export function uniqueDevices(list: { device: Device }[], exclude?: Device): Device[] {
  const seen = new Set<string>();
  const out: Device[] = [];
  for (const { device } of list) {
    if (device === exclude || seen.has(device.id)) continue;
    seen.add(device.id);
    out.push(device);
  }
  return out;
}

/** 후보 라우터 인터페이스 중 참조 주소와 같은 서브넷인 것을 우선, 없으면 주소를 아는 첫 번째 */
export function pickGw(gws: GwIface[], ref: string | undefined): GwIface | undefined {
  const known = gws.filter((g) => g.ip && g.subnet);
  if (ref) {
    const same = known.find((g) => contains(g.subnet!, ref));
    if (same) return same;
  }
  return known[0] ?? gws[0];
}

/** Y(게이트웨이) 뒤에 있는 서브넷들: Y 의 안쪽 인터페이스 + 그 아래 또 다른 게이트웨이 뒤까지 (NAT 박스 뒤는 주소가 바뀌므로 제외) */
export function subnetsBehind(y: Device, m: Model, visited: Set<string>): { subnet: Subnet; owner: Device }[] {
  if (visited.has(y.id)) return [];
  visited.add(y.id);
  const out: { subnet: Subnet; owner: Device }[] = [];
  for (const g of m.allGws) {
    if (g.device !== y || !g.inside) continue;
    if (g.subnet) out.push({ subnet: g.subnet, owner: y });
    for (const z of m.gwsOf(g.key)) {
      if (z.device !== y && z.uplink && z.device.kind === "gateway") out.push(...subnetsBehind(z.device, m, visited));
    }
  }
  return out;
}

/** RIP 를 켠 L3 장치 (규칙 6·7·12 가 "경로를 광고로 배울 수 있으면 침묵" 에 쓴다) */
export const ripOn = (d: Device) => d.l3?.rip?.enabled === true;

/** 같은 (장치, code) 는 하나로 합치고, error → warn, 그다음 장치 순서로 정렬 */
export function finalize(issues: LintIssue[], t: Topology): LintIssue[] {
  const index = new Map(t.devices.map((d, i) => [d.id, i]));
  const seen = new Map<string, LintIssue>();
  const kept: LintIssue[] = [];
  for (const i of issues) {
    const k = `${i.deviceId}\u0000${i.code}`;
    const prev = seen.get(k);
    if (prev) {
      if (i.related) prev.related = [...new Set([...(prev.related ?? []), ...i.related])];
      continue;
    }
    const copy = { ...i, related: i.related?.filter((r) => r !== i.deviceId) };
    if (!copy.related || copy.related.length === 0) delete copy.related;
    seen.set(k, copy);
    kept.push(copy);
  }
  return kept
    .map((i, n) => ({ i, n }))
    .sort((a, b) => SEVERITY_RANK[a.i.severity] - SEVERITY_RANK[b.i.severity] || (index.get(a.i.deviceId) ?? 0) - (index.get(b.i.deviceId) ?? 0) || a.n - b.n)
    .map((x) => x.i);
}
