// ---------- 주소 도우미 (core/addr 와 같은 기준이지만 예외 대신 undefined) ----------

export function ipInt(s: string | undefined): number | undefined {
  if (!s) return undefined;
  const parts = s.split(".");
  if (parts.length !== 4) return undefined;
  let n = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return undefined;
    const v = Number(p);
    if (v > 255) return undefined;
    n = n * 256 + v;
  }
  return n;
}

export function validIp(s: string | undefined): string | undefined {
  return ipInt(s) === undefined ? undefined : s;
}

function validPrefix(p: number): boolean {
  return Number.isInteger(p) && p >= 1 && p <= 32;
}

function maskOf(prefix: number): number {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

export interface Subnet {
  net: number;
  prefix: number;
}

/** ip 와 prefix 가 모두 유효할 때만 서브넷 */
export function subnetOf(ip: string | undefined, prefix: number): Subnet | undefined {
  const n = ipInt(ip);
  if (n === undefined || !validPrefix(prefix)) return undefined;
  return { net: (n & maskOf(prefix)) >>> 0, prefix };
}

export function contains(s: Subnet, ip: string): boolean {
  const n = ipInt(ip);
  return n !== undefined && ((n & maskOf(s.prefix)) >>> 0) === s.net;
}

/** outer 가 inner 를 통째로 포함하는가 (같은 서브넷도 포함) */
export function covers(outer: Subnet, inner: Subnet): boolean {
  return outer.prefix <= inner.prefix && ((inner.net & maskOf(outer.prefix)) >>> 0) === outer.net;
}

export function overlaps(a: Subnet, b: Subnet): boolean {
  return covers(a, b) || covers(b, a);
}

export function fmtSubnet(s: Subnet): string {
  return `${intToIp(s.net)}/${s.prefix}`;
}

/** 로드밸런서 백엔드·포트 포워딩의 포트: 시뮬레이션(netSync effectiveLb)과 같은 기준 1~65535 */
export const validPort = (n: number) => Number.isInteger(n) && n >= 1 && n <= 65535;
