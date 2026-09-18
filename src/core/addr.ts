// 주소 타입과 서브넷 계산 유틸. 모든 주소는 사람이 읽는 문자열로 다룬다.

export type Ip = string; // "10.0.0.1"
export type Mac = string; // "02:00:00:00:00:01"

export const BROADCAST_MAC: Mac = "ff:ff:ff:ff:ff:ff";
export const ZERO_MAC: Mac = "00:00:00:00:00:00";

export function ipToInt(ip: Ip): number {
  const parts = ip.split(".");
  if (parts.length !== 4) throw new Error(`invalid ip: ${ip}`);
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!/^\d+$/.test(p) || v > 255) throw new Error(`invalid ip: ${ip}`);
    n = n * 256 + v;
  }
  return n;
}

export function intToIp(n: number): Ip {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

export function prefixToMask(prefix: number): number {
  if (prefix < 0 || prefix > 32) throw new Error(`invalid prefix: ${prefix}`);
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

export function networkOf(ip: Ip, prefix: number): Ip {
  return intToIp((ipToInt(ip) & prefixToMask(prefix)) >>> 0);
}

export function broadcastOf(ip: Ip, prefix: number): Ip {
  const mask = prefixToMask(prefix);
  return intToIp((ipToInt(ip) | (~mask >>> 0)) >>> 0);
}

export function sameSubnet(a: Ip, b: Ip, prefix: number): boolean {
  return networkOf(a, prefix) === networkOf(b, prefix);
}

export function isBroadcastMac(mac: Mac): boolean {
  return mac.toLowerCase() === BROADCAST_MAC;
}
