// ISP(인터넷 노드) 대역: 직접 입력·무작위. 가입자에게 /29 씩 나눠 주므로 /16 ~ /28, 사설·특수 대역과 인터넷 노드가 흉내 내는 서버 주소는 쓸 수 없다
import { intToIp, ipToInt, networkOf, sameSubnet } from "../core/addr";
import { DEFAULT_ISP_NET, SUBSCRIBER_PREFIX, simulatedPublicIps, KNOWN_SERVERS } from "../core/nodes/internet";

/** 공인 인터넷에서 쓰지 않는 대역 (RFC 6890 중 시뮬레이터가 다루는 것) */
const NON_PUBLIC: { ip: string; prefix: number; label: string }[] = [
  { ip: "0.0.0.0", prefix: 8, label: "this network" },
  { ip: "10.0.0.0", prefix: 8, label: "사설" },
  { ip: "100.64.0.0", prefix: 10, label: "CGNAT 공유" },
  { ip: "127.0.0.0", prefix: 8, label: "루프백" },
  { ip: "169.254.0.0", prefix: 16, label: "링크 로컬" },
  { ip: "172.16.0.0", prefix: 12, label: "사설" },
  { ip: "192.0.0.0", prefix: 24, label: "IETF 예약" },
  { ip: "192.168.0.0", prefix: 16, label: "사설" },
  { ip: "198.18.0.0", prefix: 15, label: "벤치마크" },
  { ip: "224.0.0.0", prefix: 4, label: "멀티캐스트" },
  { ip: "240.0.0.0", prefix: 4, label: "예약" },
];

export const ISP_MIN_PREFIX = 16;
export const ISP_MAX_PREFIX = SUBSCRIBER_PREFIX - 1;

/** "a.b.c.d/p" (길이가 없으면 /24) → 네트워크 주소로 */
export function parseIspNet(text: string | undefined): { ip: string; prefix: number } | undefined {
  const m = /^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?\s*$/.exec(text ?? "");
  if (!m) return undefined;
  const parts = m.slice(1, 5).map(Number);
  if (parts.some((n) => n > 255)) return undefined;
  const prefix = m[5] === undefined ? 24 : Number(m[5]);
  if (prefix > 32) return undefined;
  return { ip: networkOf(parts.join("."), prefix), prefix };
}

/** ISP 대역으로 쓸 수 없는 이유. 쓸 수 있으면 undefined */
export function ispNetProblem(text: string | undefined): string | undefined {
  const net = parseIspNet(text);
  if (!net) return `"${(text ?? "").trim()}" 은 대역이 아님 (예: 203.0.113.0/24)`;
  if (net.prefix < ISP_MIN_PREFIX || net.prefix > ISP_MAX_PREFIX) return `길이는 /${ISP_MIN_PREFIX} ~ /${ISP_MAX_PREFIX} — 가입자마다 /${SUBSCRIBER_PREFIX} 를 나눠 준다`;
  const bad = NON_PUBLIC.find((r) => sameSubnet(net.ip, r.ip, Math.min(net.prefix, r.prefix)));
  if (bad) return `${bad.label} 대역 ${bad.ip}/${bad.prefix} 과 겹침 — ISP 대역은 공인 대역만`;
  const server = simulatedPublicIps().find((ip) => sameSubnet(ip, net.ip, net.prefix));
  if (server) return `인터넷 노드가 흉내 내는 공인 서버 ${server}${KNOWN_SERVERS[server] ? ` (${KNOWN_SERVERS[server]})` : ""} 와 겹침 — 다른 대역`;
  return undefined;
}

/** 시뮬레이터가 쓰는 ISP 대역: 쓸 수 있으면 그것, 아니면 기본값 (구성 검사 isp.net-invalid) */
export function effectiveIspNet(text: string | undefined): { ip: string; prefix: number } {
  if (text === undefined || ispNetProblem(text)) return { ...DEFAULT_ISP_NET };
  return parseIspNet(text)!;
}

/** 무작위 공인 /24 (사설·특수 대역·흉내 서버와 겹치지 않는 것) */
export function randomIspNet(rand: () => number = Math.random): string {
  for (;;) {
    const n = (Math.floor(rand() * 223) + 1) * 2 ** 24 + Math.floor(rand() * 256) * 2 ** 16 + Math.floor(rand() * 256) * 2 ** 8;
    const text = `${intToIp(n)}/24`;
    if (!ispNetProblem(text)) return text;
  }
}

/** 그 대역의 ISP 게이트웨이(첫 가입자 대역의 첫 주소) — 표시용 */
export function ispGatewayOf(net: { ip: string; prefix: number }): string {
  return intToIp(ipToInt(net.ip) + 1);
}
