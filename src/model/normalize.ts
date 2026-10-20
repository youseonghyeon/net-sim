// 불러오기 정리용 조합기: 저장본(손으로 고친 JSON·예전 저장본)의 값은 타입을 믿을 수 없다 — 칸이 없거나 엉뚱한 타입이어도
// 늘 완전한 값을 돌려준다. 정리하지 않은 칸 하나가 동기화에서 TypeError 로 앱을 멈추게 했다(tests/import-robust.test.ts).
import type { DnsServerSettings, FirewallRuleSettings, FirewallSettings, LbSettings, WifiBaseSettings } from "./topology";

export type Obj = Record<string, unknown>;

export const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
export const str = (v: unknown, d = ""): string => (typeof v === "string" ? v : typeof v === "number" ? String(v) : d);
export const bool = (v: unknown, d = false): boolean => (typeof v === "boolean" ? v : d);
export function int(v: unknown, lo: number, hi: number, d: number): number {
  const n = typeof v === "string" && v.trim() !== "" ? Number(v) : v;
  return typeof n === "number" && Number.isInteger(n) && n >= lo && n <= hi ? n : d;
}
export const oneOf = <T extends string>(v: unknown, allowed: readonly T[], d: T): T => (allowed.includes(v as T) ? (v as T) : d);
/** 배열이면 객체 항목만 정리해서, 아니면 빈 배열 */
export const list = <T>(v: unknown, item: (o: Obj) => T): T[] => (Array.isArray(v) ? v.filter(isObj).map(item) : []);

export function normalizeFirewallRule(o: Obj): FirewallRuleSettings {
  return {
    action: oneOf(o.action, ["allow", "deny"] as const, "allow"),
    proto: oneOf(o.proto, ["any", "icmp", "tcp", "udp", "esp"] as const, "any"),
    direction: oneOf(o.direction, ["in", "out", "any"] as const, "any"),
    src: str(o.src),
    dst: str(o.dst),
    dstPort: str(o.dstPort),
  };
}

/** 방화벽 설정 (투명 방화벽 장비·공유기·게이트웨이 공통). enabled 가 없으면 dfltEnabled */
export function normalizeFirewall(v: unknown, dfltEnabled = false): FirewallSettings {
  const o = isObj(v) ? v : {};
  return {
    enabled: bool(o.enabled, dfltEnabled),
    defaultPolicy: oneOf(o.defaultPolicy, ["allow", "deny"] as const, "allow"),
    stateful: bool(o.stateful, true),
    rules: list(o.rules, normalizeFirewallRule),
  };
}

export function normalizeDnsServer(v: unknown): DnsServerSettings {
  const o = isObj(v) ? v : {};
  return { enabled: bool(o.enabled), records: list(o.records, (r) => ({ name: str(r.name), ip: str(r.ip) })), upstream: str(o.upstream) };
}

/** 로드밸런서의 필수 칸 (세션 고정·헬스 체크 같은 선택 칸은 normalizeHostExtras 가) */
export function normalizeLbBase(v: Obj): Pick<LbSettings, "enabled" | "port" | "algorithm" | "backends" | "mode"> {
  return {
    enabled: bool(v.enabled),
    port: int(v.port, 1, 65535, 80),
    algorithm: oneOf(v.algorithm, ["round-robin", "least-conn"] as const, "round-robin"),
    backends: list(v.backends, (b) => ({ ip: str(b.ip), port: int(b.port, 1, 65535, 80) })),
    ...(v.mode === "l4" ? { mode: "l4" as const } : {}),
  };
}

/** 무선 기지국(공유기·AP) 설정 */
export function normalizeWifiBase(v: unknown, d: WifiBaseSettings): WifiBaseSettings {
  const o = isObj(v) ? v : {};
  return { enabled: bool(o.enabled, d.enabled), ssid: str(o.ssid, d.ssid) };
}

/** 스위치 포트별 VLAN: 숫자(1~4094) 또는 "trunk" 만 남긴다 */
export function normalizeVlans(v: unknown): Record<number, number | "trunk"> {
  const out: Record<number, number | "trunk"> = {};
  if (!isObj(v)) return out;
  for (const [k, x] of Object.entries(v)) {
    const port = Number(k);
    if (!Number.isInteger(port) || port < 0) continue;
    if (x === "trunk") out[port] = "trunk";
    else if (typeof x === "number" && Number.isInteger(x) && x >= 1 && x <= 4094) out[port] = x;
  }
  return out;
}
