// 계층별 패킷 모델. 실제 바이트가 아니라 "학습에 필요한 필드"만 담는다.
import type { Ip, Mac } from "./addr";

export interface EthernetFrame {
  kind: "ethernet";
  id: number; // 추적용 ID (같은 패킷이 여러 링크를 지나도 유지)
  src: Mac;
  dst: Mac;
  payload: ArpPacket | Ipv4Packet;
  /** 스위치를 거친 횟수. 실제 이더넷엔 없지만 L2 루프 폭주를 막기 위한 안전장치 */
  hops?: number;
  /** 802.1Q VLAN 태그. 트렁크 링크 위에서만 붙는다 */
  vlan?: number;
}

/** 이 횟수를 넘긴 프레임은 루프로 간주해 버린다 */
export const MAX_L2_HOPS = 16;

export interface ArpPacket {
  kind: "arp";
  op: "request" | "reply";
  senderMac: Mac;
  senderIp: Ip;
  targetMac: Mac;
  targetIp: Ip;
}

export interface Ipv4Packet {
  kind: "ipv4";
  src: Ip;
  dst: Ip;
  ttl: number;
  payload: IcmpPacket | UdpPacket | TcpSegment | EspPacket | VrrpPacket;
}

export interface TcpSegment {
  kind: "tcp";
  srcPort: number;
  dstPort: number;
  seq: number;
  ack: number;
  syn?: boolean;
  ackFlag?: boolean;
  fin?: boolean;
  rst?: boolean;
  /** 데이터 길이(바이트). SYN/FIN 은 seq 를 1 소비하지만 len 에는 넣지 않는다 */
  len: number;
  /** 데이터 내용 요약 (예: "GET /", "HTTP 200 (1/3)") */
  data?: string;
  /** 응답을 실제로 만든 서버 (로드밸런서가 붙이는 X-Served-By 헤더 흉내). 학습용 표시 */
  origin?: string;
  /** 요청이 거친 로드밸런서 수 (HTTP Via 헤더 흉내). 로드밸런서끼리 순환하면 이 값으로 끊는다 */
  via?: number;
}

export interface IcmpEcho {
  kind: "icmp";
  type: "echo-request" | "echo-reply";
  id: number;
  seq: number;
}

/**
 * ICMP Time Exceeded (TTL 이 0 이 되어 라우터가 드롭했음을 보낸 이에게 알림).
 * 실제 ICMP 는 원래 IP 헤더 + 데이터 앞 8바이트를 싣는다. 여기서는 그에 해당하는 식별 정보만 담는다.
 * traceroute 는 이 메시지의 출발지(= 드롭한 라우터)로 경로를 알아낸다.
 */
export interface IcmpTimeExceeded {
  kind: "icmp";
  type: "time-exceeded";
  original: OriginalPacket;
}

/** Time Exceeded 가 내장하는 원래 패킷의 식별 정보 */
export interface OriginalPacket {
  src: Ip;
  dst: Ip;
  /** ICMP Echo 면 id/seq, TCP/UDP 면 포트 (원 패킷 앞 8바이트에 해당) */
  l4: { kind: "icmp"; id: number; seq: number } | { kind: "tcp" | "udp"; srcPort: number; dstPort: number };
}

/**
 * ICMP Destination Unreachable: 라우터나 목적지가 "여기서 더 못 간다" 를 보낸 이에게 알린다. 원래 패킷 식별 정보를 싣는다.
 * net(코드 0) = 경로 없음, host(코드 1) = 그 주소에 ARP 응답이 없음, port(코드 3) = 그 UDP 포트를 듣는 프로그램이 없음
 */
export interface IcmpUnreachable {
  kind: "icmp";
  type: "unreachable";
  code: UnreachableCode;
  original: OriginalPacket;
}

export type UnreachableCode = "net" | "host" | "port";

export const UNREACHABLE_LABEL: Record<UnreachableCode, string> = {
  net: "Destination Net Unreachable",
  host: "Destination Host Unreachable",
  port: "Destination Port Unreachable",
};
/** traceroute 가 홉 뒤에 붙이는 표시 (!N, !H, !P) */
export const UNREACHABLE_FLAG: Record<UnreachableCode, string> = { net: "!N", host: "!H", port: "!P" };

/** 원래 패킷을 싣는 ICMP 오류 (보낸 이에게 돌려주는 통지) */
export type IcmpError = IcmpTimeExceeded | IcmpUnreachable;

export type IcmpPacket = IcmpEcho | IcmpError;

export function isTimeExceeded(p: Ipv4Packet["payload"]): p is IcmpTimeExceeded {
  return p.kind === "icmp" && p.type === "time-exceeded";
}

export function isIcmpError(p: Ipv4Packet["payload"]): p is IcmpError {
  return p.kind === "icmp" && (p.type === "time-exceeded" || p.type === "unreachable");
}

/** ICMP 오류의 이름 (로그용) */
export function icmpErrorLabel(p: IcmpError): string {
  return p.type === "time-exceeded" ? "Time Exceeded" : UNREACHABLE_LABEL[p.code];
}

/**
 * TTL 이 다 된 패킷을 드롭한 라우터가 보낸 이에게 돌려줄 Time Exceeded 패킷.
 * ICMP 오류에 대한 오류(RFC 1122)나 출발지가 없는(0.0.0.0) 패킷에는 만들지 않는다 → undefined.
 */
export function timeExceededFor(from: Ip, dropped: Ipv4Packet): Ipv4Packet | undefined {
  return icmpErrorFor(from, dropped, { type: "time-exceeded" });
}

/**
 * 드롭한 패킷을 보낸 이에게 돌려줄 ICMP 오류. ICMP 오류에 대한 오류(RFC 1122), 출발지가 없는(0.0.0.0) 패킷,
 * 브로드캐스트·멀티캐스트로 간 패킷에는 만들지 않는다 → undefined
 */
export function icmpErrorFor(from: Ip, dropped: Ipv4Packet, err: { type: "time-exceeded" } | { type: "unreachable"; code: UnreachableCode }): Ipv4Packet | undefined {
  if (dropped.src === UNSPECIFIED_IP || dropped.dst === LIMITED_BROADCAST_IP || /^2(2[4-9]|3\d)\./.test(dropped.dst)) return undefined;
  const p = dropped.payload;
  let l4: OriginalPacket["l4"];
  if (p.kind === "icmp") {
    if (p.type !== "echo-request" && p.type !== "echo-reply") return undefined;
    l4 = { kind: "icmp", id: p.id, seq: p.seq };
  } else if (p.kind === "esp" || p.kind === "vrrp") return undefined; // 터널 바깥 패킷의 오류는 VPN 장비가 쓰지 않으므로 생략 (터널은 IKE timeout 으로 알아챈다)
  else l4 = { kind: p.kind, srcPort: p.srcPort, dstPort: p.dstPort };
  const original = { src: dropped.src, dst: dropped.dst, l4 };
  const payload: IcmpError = err.type === "time-exceeded" ? { kind: "icmp", type: "time-exceeded", original } : { kind: "icmp", type: "unreachable", code: err.code, original };
  return { kind: "ipv4", src: from, dst: dropped.src, ttl: 64, payload };
}

/** 원래 패킷 정보를 사람이 읽는 형태로: "192.168.0.100 → 8.8.8.8 Echo seq=3" */
export function describeOriginal(o: OriginalPacket): string {
  const tail = o.l4.kind === "icmp" ? `Echo seq=${o.l4.seq}` : `${o.l4.kind.toUpperCase()} :${o.l4.srcPort} → :${o.l4.dstPort}`;
  return `${o.src} → ${o.dst} ${tail}`;
}

/** ICMP 메시지 종류 라벨 */
export function icmpLabel(p: IcmpPacket): string {
  if (isIcmpError(p)) return icmpErrorLabel(p);
  return p.type === "echo-request" ? "Echo 요청" : "Echo 응답";
}

export interface UdpPacket {
  kind: "udp";
  srcPort: number;
  dstPort: number;
  payload: DhcpMessage | DnsMessage | RipMessage | VpnMessage | IkeMessage | EspPacket;
}

/**
 * VPN 터널 데이터 (WireGuard 식): 원래 IP 패킷을 암호화해 UDP 51820 안에 싣는다.
 * 중간 장비에게는 공인 주소끼리의 UDP 로만 보이고, 안쪽(사설 주소·내용)은 암호화되어 보이지 않는다.
 * inner 는 받는 쪽이 복호화했을 때의 원래 패킷 (시뮬레이터는 실제로 암호화하지 않고 "암호화됨" 으로 표시만 한다)
 */
export interface VpnMessage {
  kind: "vpn";
  inner: Ipv4Packet;
}

export const VPN_PORT = 51820;

/**
 * IPsec ESP (IP 프로토콜 50): 원래 IP 패킷을 암호화해 담는다. 포트가 없어서 NAT 가 변환할 수 없다 —
 * 그래서 두 끝 사이에 NAT 가 있으면 UDP 4500 안에 싣는다 (NAT-T). UdpPacket 의 payload 로도 쓰인다.
 * spi 는 이 터널(SA)의 번호, seq 는 재전송 공격을 막는 일련번호 (시뮬레이터는 표시만 한다)
 */
export interface EspPacket {
  kind: "esp";
  spi: number;
  seq: number;
  inner: Ipv4Packet;
}

/**
 * IKEv2 (UDP 500, NAT 가 있으면 4500): IPsec 터널을 맺는 협상. 요청·응답 두 번이면 끝난다.
 * IKE_SA_INIT: 암호 방식 합의 + NAT 감지 (보낸 쪽이 적은 자기 주소·상대 주소가 받은 헤더와 다르면 중간에 NAT)
 * IKE_AUTH: 사전 공유 키(PSK)로 서로 인증하고 터널(SA)을 만든다
 */
export interface IkeMessage {
  kind: "ike";
  exchange: "IKE_SA_INIT" | "IKE_AUTH";
  response: boolean;
  /** 이 협상의 번호 (시작한 쪽이 정함) */
  spi: number;
  /** NAT 감지용: 보낸 쪽이 알고 있는 자기 주소·상대 주소 (실제로는 해시) */
  natSrc?: Ip;
  natDst?: Ip;
  /** 응답: 중간에 NAT 가 있다고 판단함 → 이후는 UDP 4500 (NAT-T) */
  nat?: boolean;
  /** IKE_AUTH 요청: 사전 공유 키로 만든 인증 값 (시뮬레이터는 키 문자열을 그대로 비교) */
  auth?: string;
  /** IKE_AUTH 응답의 실패 알림 */
  error?: "AUTHENTICATION_FAILED";
}

/**
 * VRRP 광고 (IP 프로토콜 112, 224.0.0.18): 이중화 쌍이 "나는 이 가상 주소의 master(또는 후보)이고 우선순위는 N" 을 알린다.
 * 우선순위 0 = master 가 물러남 (backup 이 곧바로 이어받으라는 뜻)
 */
export interface VrrpPacket {
  kind: "vrrp";
  vrid: number;
  priority: number;
  /** 이 세그먼트의 가상 주소 */
  vip: Ip;
  /** 우선순위가 같을 때 가르는 장비 식별 주소 (VIP 를 둔 첫 인터페이스의 실제 주소 — 인터페이스마다 판단이 엇갈리지 않게) */
  rid: Ip;
  /** master 가 아닌 후보의 알림 (시작·복구 때). 이것만으로는 backup 이 기다림을 멈추지 않는다 */
  candidate?: boolean;
}

export const VRRP_MULTICAST_IP: Ip = "224.0.0.18";
export const VRRP_MULTICAST_MAC: Mac = "01:00:5e:00:00:12";

export const IKE_PORT = 500;
export const NAT_T_PORT = 4500;

/**
 * RIPv2 메시지 (RFC 2453 축소판). 경로마다 목적지·프리픽스·메트릭(홉 수, 16 = 도달 불가)만 담는다.
 * Request: "당신의 경로를 전부 알려 주세요" (시작할 때), Response: 내 라우팅 테이블 광고
 */
export interface RipMessage {
  kind: "rip";
  command: "request" | "response";
  entries: RipEntry[];
}

export interface RipEntry {
  dest: Ip;
  prefix: number;
  metric: number;
  /** RIPv2 넥스트 홉: 보낸 이 대신 이 주소로 보내라 (이중화 master 는 가상 주소를 적는다 — 넘어가도 경로가 그대로) */
  nextHop?: Ip;
}

export const RIP_PORT = 520;
/** RIPv2 는 224.0.0.9 멀티캐스트로 보낸다 (MAC 01:00:5e:00:00:09). 라우터만 가입하므로 호스트 NIC 는 조용히 거른다 */
export const RIP_MULTICAST_IP: Ip = "224.0.0.9";
export const RIP_MULTICAST_MAC: Mac = "01:00:5e:00:00:09";
export const RIP_INFINITY = 16;

export interface DnsMessage {
  kind: "dns";
  id: number;
  op: "query" | "response";
  /** 질의 이름 (예: example.com) */
  name: string;
  /** 응답: 찾은 주소. 없으면 rcode */
  answer?: Ip;
  rcode?: "NXDOMAIN" | "SERVFAIL";
  /** 재귀 질의가 서버를 거친 횟수 (루프 방지) */
  hops?: number;
}

export const DNS_PORT = 53;

export type DhcpOp = "discover" | "offer" | "request" | "ack" | "nak" | "release";

export interface DhcpMessage {
  kind: "dhcp";
  op: DhcpOp;
  xid: number;
  clientMac: Mac;
  /** 서버가 제안/확정한 클라이언트 주소 (offer/ack) */
  yiaddr?: Ip;
  /** 서버 식별자 = 서버의 IP (offer/request/ack/nak) */
  serverId?: Ip;
  /** 클라이언트가 요청하는 주소 (request) */
  requestedIp?: Ip;
  /** 릴레이 에이전트(게이트웨이)의 주소. 서버는 이 주소로 어느 서브넷 풀에서 줄지 정하고, 응답도 여기로 보낸다 */
  giaddr?: Ip;
  options?: { prefix?: number; router?: Ip; dns?: Ip; leaseTime?: number };
}

export const DHCP_SERVER_PORT = 67;
export const DHCP_CLIENT_PORT = 68;
export const UNSPECIFIED_IP: Ip = "0.0.0.0";
export const LIMITED_BROADCAST_IP: Ip = "255.255.255.255";

export type Layer = "L1" | "L2" | "L3" | "L4" | "app" | "sys";

export type FrameCategory = "arp" | "icmp" | "dhcp" | "tcp" | "dns" | "rip" | "vpn" | "vrrp";

const ESP_LABEL = (e: EspPacket) => `ESP SPI 0x${e.spi.toString(16).padStart(8, "0")} seq=${e.seq} (암호화됨 · 안: ${e.inner.src} → ${e.inner.dst})`;
const IKE_LABEL = (m: IkeMessage) => `IKE ${m.exchange} ${m.response ? (m.error ? `응답 (${m.error})` : "응답") : "요청"}`;

const DHCP_LABEL: Record<DhcpOp, string> = { discover: "Discover", offer: "Offer", request: "Request", ack: "Ack", nak: "Nak", release: "Release" };

/** UI 라벨/로그용 짧은 설명 */
export function describeFrame(frame: EthernetFrame): string {
  const p = frame.payload;
  if (p.kind === "arp") {
    return p.op === "request" ? `ARP 요청 (${p.targetIp}?)` : `ARP 응답 (${p.senderIp}=${p.senderMac})`;
  }
  const inner = p.payload;
  if (inner.kind === "icmp") {
    if (inner.type === "time-exceeded" || inner.type === "unreachable") return `ICMP ${icmpErrorLabel(inner)} (원래 ${describeOriginal(inner.original)})`;
    return inner.type === "echo-request" ? `ICMP Echo 요청 seq=${inner.seq}` : `ICMP Echo 응답 seq=${inner.seq}`;
  }
  if (inner.kind === "tcp") return `TCP ${tcpFlags(inner)} seq=${inner.seq} ack=${inner.ack}${inner.len ? ` len=${inner.len}` : ""}`;
  if (inner.kind === "esp") return ESP_LABEL(inner);
  if (inner.kind === "vrrp") return `VRRP 광고 (그룹 ${inner.vrid}, 우선순위 ${inner.priority}${inner.priority === 0 ? " — 물러남" : ""}, 가상 주소 ${inner.vip})`;
  const d = inner.payload;
  if (d.kind === "esp") return `UDP 4500 (NAT-T) · ${ESP_LABEL(d)}`;
  if (d.kind === "ike") return IKE_LABEL(d);
  if (d.kind === "dns") return d.op === "query" ? `DNS 질의 (${d.name}?)` : `DNS 응답 (${d.name} = ${d.answer ?? d.rcode})`;
  if (d.kind === "rip") return d.command === "request" ? "RIP Request (전체 경로 요청)" : `RIP Response (경로 ${d.entries.length}개)`;
  if (d.kind === "vpn") return `VPN 터널 (암호화됨 · 안: ${d.inner.src} → ${d.inner.dst})`;
  return `DHCP ${DHCP_LABEL[d.op]}${d.yiaddr ? ` (${d.yiaddr})` : ""}`;
}

/** 세그먼트 플래그를 사람이 읽는 형태로: SYN, SYN·ACK, ACK, FIN·ACK, RST, DATA */
export function tcpFlags(t: TcpSegment): string {
  if (t.rst) return "RST";
  if (t.syn) return t.ackFlag ? "SYN·ACK" : "SYN";
  if (t.fin) return t.ackFlag ? "FIN·ACK" : "FIN";
  if (t.len > 0) return "DATA";
  return "ACK";
}

/** 캔버스 위 패킷에 붙는 짧은 라벨 */
export function shortLabel(frame: EthernetFrame): string {
  const p = frame.payload;
  if (p.kind === "arp") return p.op === "request" ? "ARP 요청" : "ARP 응답";
  const inner = p.payload;
  if (inner.kind === "icmp") return inner.type === "echo-request" ? "ping 요청" : inner.type === "echo-reply" ? "ping 응답" : inner.type === "time-exceeded" ? "TTL 초과" : "도달 불가";
  if (inner.kind === "tcp") return inner.len > 0 ? `${inner.data ?? "DATA"} ${inner.len}B` : tcpFlags(inner);
  if (inner.kind === "vrrp") return inner.priority === 0 ? "VRRP 물러남" : `VRRP ${inner.priority}`;
  if (inner.kind === "esp" || inner.payload.kind === "esp") return "ESP 터널";
  if (inner.payload.kind === "ike") return inner.payload.exchange === "IKE_SA_INIT" ? "IKE 협상" : "IKE 인증";
  if (inner.payload.kind === "dns") return inner.payload.op === "query" ? "DNS 질의" : "DNS 응답";
  if (inner.payload.kind === "rip") return inner.payload.command === "request" ? "RIP 요청" : "RIP 광고";
  if (inner.payload.kind === "vpn") return "VPN 터널";
  return `DHCP ${DHCP_LABEL[inner.payload.op]}`;
}

/** 패킷 종류 태그 (UI 색상 구분용) */
export function frameCategory(frame: EthernetFrame): FrameCategory {
  const p = frame.payload;
  if (p.kind === "arp") return "arp";
  if (p.payload.kind === "icmp") return "icmp";
  if (p.payload.kind === "tcp") return "tcp";
  if (p.payload.kind === "esp") return "vpn";
  if (p.payload.kind === "vrrp") return "vrrp";
  const k = p.payload.payload.kind;
  return k === "dns" ? "dns" : k === "rip" ? "rip" : k === "vpn" || k === "esp" || k === "ike" ? "vpn" : "dhcp";
}
