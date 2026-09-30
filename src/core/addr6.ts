// IPv6 주소 유틸. 주소는 IPv4 처럼 사람이 읽는 문자열로 다루되, 늘 RFC 5952 의 표준 표기(소문자·앞자리 0 생략·가장 긴 0 묶음을 ::)로 맞춰 문자열 비교가 곧 주소 비교가 되게 한다.
import type { Ip, Mac } from "./addr";

/** 모든 노드 (ff02::1): IPv6 에는 브로드캐스트가 없어 "링크의 모두에게" 는 이 멀티캐스트로 보낸다 */
export const ALL_NODES: Ip = "ff02::1";
/** 모든 라우터 (ff02::2): Router Solicitation 의 목적지 */
export const ALL_ROUTERS: Ip = "ff02::2";
/** 지정되지 않은 주소 (::) — DAD 의 NS 처럼 아직 주소가 없을 때의 출발지 */
export const UNSPECIFIED6: Ip = "::";
export const ALL_NODES_MAC: Mac = "33:33:00:00:00:01";
export const ALL_ROUTERS_MAC: Mac = "33:33:00:00:00:02";

const MAX = (1n << 128n) - 1n;

/** 문자열 → 128비트 정수. 형식이 틀리면 undefined (IPv4 가 끼인 표기 ::ffff:1.2.3.4 는 받지 않는다) */
export function parseIp6(s: string): bigint | undefined {
  const t = s.trim().toLowerCase();
  if (!t.includes(":") || /[^0-9a-f:]/.test(t)) return undefined;
  const halves = t.split("::");
  if (halves.length > 2) return undefined;
  const groups = (part: string) => (part === "" ? [] : part.split(":"));
  const head = groups(halves[0]!);
  const tail = halves.length === 2 ? groups(halves[1]!) : [];
  const all = [...head, ...tail];
  if (all.some((g) => g.length === 0 || g.length > 4)) return undefined;
  if (halves.length === 1 ? head.length !== 8 : all.length > 7) return undefined;
  const fill = halves.length === 2 ? 8 - all.length : 0;
  const words = [...head, ...Array<string>(fill).fill("0"), ...tail];
  let n = 0n;
  for (const w of words) n = (n << 16n) | BigInt(parseInt(w, 16));
  return n;
}

/** 128비트 정수 → RFC 5952 표기 (가장 긴 0 묶음 둘 이상을 ::, 같으면 앞쪽) */
export function formatIp6(n: bigint): Ip {
  const words: number[] = [];
  for (let i = 7; i >= 0; i--) words.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (words[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && words[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = (ws: number[]) => ws.map((w) => w.toString(16)).join(":");
  if (bestLen < 2) return hex(words);
  return `${hex(words.slice(0, bestStart))}::${hex(words.slice(bestStart + bestLen))}`;
}

/** 표준 표기로 바꾼다. IPv6 가 아니면 undefined */
export function canonIp6(s: string | undefined): Ip | undefined {
  if (!s) return undefined;
  const n = parseIp6(s);
  return n === undefined ? undefined : formatIp6(n);
}

export function isIpv6(s: string): boolean {
  return parseIp6(s) !== undefined;
}

function mask(prefix: number): bigint {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) throw new Error(`invalid prefix: ${prefix}`);
  return prefix === 0 ? 0n : (MAX << BigInt(128 - prefix)) & MAX;
}

/** 프리픽스(네트워크 부분)만 남긴 주소: network6("2001:db8:1::10", 64) = "2001:db8:1::" */
export function network6(ip: Ip, prefix: number): Ip {
  const n = parseIp6(ip);
  if (n === undefined) throw new Error(`invalid ipv6: ${ip}`);
  return formatIp6(n & mask(prefix));
}

/** 두 주소가 같은 프리픽스 안인지. 형식이 틀리면 false */
export function sameSubnet6(a: Ip, b: Ip, prefix: number): boolean {
  const x = parseIp6(a);
  const y = parseIp6(b);
  if (x === undefined || y === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;
  const m = mask(prefix);
  return (x & m) === (y & m);
}

/** 앞에서부터 같은 비트 수 (출발지 주소 고르기: 목적지와 가장 길게 겹치는 주소) */
export function commonPrefixLength6(a: Ip, b: Ip): number {
  const x = parseIp6(a);
  const y = parseIp6(b);
  if (x === undefined || y === undefined) return 0;
  let d = x ^ y;
  let n = 128;
  while (d > 0n) {
    d >>= 1n;
    n--;
  }
  return n;
}

/**
 * EUI-64 인터페이스 ID: MAC 48비트 가운데에 ff:fe 를 끼우고, 첫 옥텟의 U/L 비트(0x02)를 뒤집는다.
 * 02:00:00:00:00:05 → 0000:00ff:fe00:0005 (U/L 비트가 켜진 로컬 MAC 이라 뒤집으면 00)
 */
export function eui64(mac: Mac): bigint {
  const b = mac.split(":").map((x) => parseInt(x, 16));
  if (b.length !== 6 || b.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) throw new Error(`invalid mac: ${mac}`);
  const bytes = [b[0]! ^ 0x02, b[1]!, b[2]!, 0xff, 0xfe, b[3]!, b[4]!, b[5]!];
  let n = 0n;
  for (const x of bytes) n = (n << 8n) | BigInt(x);
  return n;
}

/** 프리픽스(/64) + EUI-64 로 만든 주소 (SLAAC, 링크 로컬) */
export function eui64Address(prefix: Ip, mac: Mac): Ip {
  const p = parseIp6(prefix);
  if (p === undefined) throw new Error(`invalid ipv6: ${prefix}`);
  return formatIp6((p & mask(64)) | eui64(mac));
}

/** 링크 로컬 주소: fe80::/64 + EUI-64. IPv6 를 켠 인터페이스는 설정 없이도 늘 이 주소를 갖는다 */
export function linkLocalOf(mac: Mac): Ip {
  return eui64Address("fe80::", mac);
}

/** Solicited-node 멀티캐스트 주소: ff02::1:ff + 주소의 마지막 24비트. NS 는 브로드캐스트 대신 여기로 간다 */
export function solicitedNode(ip: Ip): Ip {
  const n = parseIp6(ip);
  if (n === undefined) throw new Error(`invalid ipv6: ${ip}`);
  return formatIp6(0xff020000000000000000000000000000n | 0x1ff000000n | (n & 0xffffffn));
}

/** IPv6 멀티캐스트 주소 → 이더넷 MAC: 33:33 + 주소의 마지막 32비트 */
export function multicastMac6(ip: Ip): Mac {
  const n = parseIp6(ip);
  if (n === undefined) throw new Error(`invalid ipv6: ${ip}`);
  const low = Number(n & 0xffffffffn);
  const bytes = [0x33, 0x33, (low >>> 24) & 255, (low >>> 16) & 255, (low >>> 8) & 255, low & 255];
  return bytes.map((x) => x.toString(16).padStart(2, "0")).join(":");
}

/** 멀티캐스트 (ff00::/8) */
export function isMulticast6(ip: Ip): boolean {
  return ip.startsWith("ff");
}

/** 링크 로컬 (fe80::/10): 그 링크 안에서만 쓰고 라우터가 넘기지 않는다 */
export function isLinkLocal6(ip: Ip): boolean {
  const n = parseIp6(ip);
  return n !== undefined && n >> 118n === 0x3fan;
}

/** 고유 로컬 주소 (ULA, fc00::/7 — 보통 fd00::/8): IPv4 의 사설 주소에 해당, 인터넷에서 라우팅되지 않는다 */
export function isUla6(ip: Ip): boolean {
  const n = parseIp6(ip);
  return n !== undefined && n >> 121n === 0x7en;
}

/** 글로벌 유니캐스트 (2000::/3): 인터넷에서 라우팅되는 주소 */
export function isGlobal6(ip: Ip): boolean {
  const n = parseIp6(ip);
  return n !== undefined && n >> 125n === 1n;
}

/** 주소 종류 (화면 설명용) */
export function scopeLabel6(ip: Ip): string {
  if (ip === UNSPECIFIED6) return "지정되지 않은 주소";
  if (isMulticast6(ip)) return "멀티캐스트";
  if (isLinkLocal6(ip)) return "링크 로컬";
  if (isUla6(ip)) return "고유 로컬 (ULA)";
  if (isGlobal6(ip)) return "글로벌";
  return "기타";
}
