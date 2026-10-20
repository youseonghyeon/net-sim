// 주소·대역 읽기 (한 곳): 시뮬레이션 반영(netSync)·구성 검사(lint)·화면 칸 검증(inspector)이 같은 기준을 쓴다.
// 화면은 통과시키는데 시뮬레이션은 조용히 버리는 값이 생기지 않게 (예: "10.0.0.2/24/5" 를 화면만 받던 것)
import { ipToInt } from "../core/addr";

/** IPv4 주소면 그대로, 아니면 undefined (네 칸, 칸마다 0~255 십진수) */
export function ip4(s: string | undefined): string | undefined {
  if (!s) return undefined;
  try {
    ipToInt(s);
    return s;
  } catch {
    return undefined;
  }
}

/** "a.b.c.d/p" (길이가 없으면 dflt, 칸 사이 공백 허용) — 주소는 적은 그대로 */
export function parseCidr(text: string | undefined, dflt: number): { ip: string; prefix: number } | undefined {
  const m = /^\s*([0-9.]+)\s*(?:\/\s*(\d{1,2}))?\s*$/.exec(text ?? "");
  if (!m || !ip4(m[1])) return undefined;
  const prefix = m[2] === undefined ? dflt : Number(m[2]);
  return prefix >= 0 && prefix <= 32 ? { ip: m[1]!, prefix } : undefined;
}

/** 쉼표·공백으로 적은 대역 목록: 읽을 수 있는 것만 */
export function parseCidrList(text: string | undefined): { dest: string; prefix: number }[] {
  return (text ?? "")
    .split(/[,\s]+/)
    .map((x) => parseCidr(x, 32))
    .filter((x): x is { ip: string; prefix: number } => !!x)
    .map((x) => ({ dest: x.ip, prefix: x.prefix }));
}

/** 읽을 수 없는 대역 목록 항목 (화면의 오류 표시용) */
export function badCidrs(text: string | undefined): string[] {
  return (text ?? "")
    .split(/[,\s]+/)
    .filter(Boolean)
    .filter((x) => !parseCidr(x, 32));
}

export const isPort = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= 65535;

/** 호스트 이름 (DDNS 같은 서버 이름 칸) */
export const isHostname = (s: string): boolean => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$/i.test(s);

/** 숫자 칸의 글자 → lo~hi 정수 (소수는 반올림, 읽을 수 없거나 0 이면 dflt). 프리픽스에 24.5 같은 값이 저장되던 것을 막는다 */
export function toInt(raw: string, lo: number, hi: number, dflt: number): number {
  return Math.min(hi, Math.max(lo, Math.round(Number(raw)) || dflt));
}
