// 계층별 패킷 모델. 실제 바이트가 아니라 "학습에 필요한 필드"만 담는다.
import type { Ip, Mac } from "./addr";

export interface EthernetFrame {
  kind: "ethernet";
  id: number; // 추적용 ID (같은 패킷이 여러 링크를 지나도 유지)
  src: Mac;
  dst: Mac;
  payload: ArpPacket | Ipv4Packet | Ipv6Packet | BpduPacket;
  /** 스위치를 거친 횟수. 실제 이더넷엔 없지만 L2 루프 폭주를 막기 위한 안전장치 */
  hops?: number;
  /** 802.1Q VLAN 태그. 트렁크 링크 위에서만 붙는다 */
  vlan?: number;
}

/** 이 횟수를 넘긴 프레임은 루프로 간주해 버린다 */
export const MAX_L2_HOPS = 16;

/** 브리지 ID: 우선순위(작을수록 앞) + MAC (같으면 작은 MAC) */
export interface BridgeId {
  prio: number;
  mac: Mac;
}

/**
 * STP BPDU (802.1D Configuration BPDU 축소판, 목적지 MAC 01:80:c2:00:00:00, IP 없이 이더넷 위에 바로):
 * "내가 아는 루트는 root, 거기까지 비용 cost, 보낸 나는 bridge 의 port 번 포트"
 */
export interface BpduPacket {
  kind: "bpdu";
  root: BridgeId;
  cost: number;
  bridge: BridgeId;
  port: number;
  /** 루트에서 몇 번 전달됐는지 (Message Age). 20 을 넘으면 버린다 — 루트가 사라졌을 때 옛 정보가 끝없이 돌지 않게 */
  age: number;
  /** Topology Change: 경로가 바뀌었으니 MAC 테이블을 비우라는 알림 (번호로 한 번씩만 퍼뜨린다) */
  tc?: number;
}

export const STP_MULTICAST_MAC: Mac = "01:80:c2:00:00:00";
export const STP_MAX_AGE = 20;

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
  payload: IcmpPacket | UdpPacket | TcpSegment | EspPacket | VrrpPacket | PfsyncPacket;
}

/** IPv4 안에 실리는 것 (프로토콜 번호로 구분) */
export type IpPayload = Ipv4Packet["payload"];

/**
 * IPv6 패킷. IPv4 의 TTL 은 Hop Limit 이 되고, 체크섬·단편화 필드는 없다(라우터는 단편화하지 않는다).
 * 헤더는 40바이트 고정, 안에 실린 것은 Next Header 번호로 구분한다 (ICMPv6 58, TCP 6, UDP 17)
 */
export interface Ipv6Packet {
  kind: "ipv6";
  src: Ip;
  dst: Ip;
  hopLimit: number;
  payload: Ipv6Payload;
}

export type Ipv6Payload = Icmpv6Packet | UdpPacket | TcpSegment;

/** IPv4·IPv6 둘 다 (방화벽·TCP 처럼 두 버전을 같이 다루는 곳) */
export type IpPacket = Ipv4Packet | Ipv6Packet;

export const IP6_NEXT_HEADER: Record<Ipv6Payload["kind"], { num: number; label: string }> = {
  icmp6: { num: 58, label: "ICMPv6" },
  tcp: { num: 6, label: "TCP" },
  udp: { num: 17, label: "UDP" },
};

/** ICMPv6 Echo (ping): IPv4 의 ICMP Echo 와 같지만 타입 번호가 128/129 */
export interface Icmpv6Echo {
  kind: "icmp6";
  type: "echo-request" | "echo-reply";
  id: number;
  seq: number;
}

/** ICMPv6 Time Exceeded (타입 3): Hop Limit 이 0 이 되어 라우터가 드롭했음 */
export interface Icmpv6TimeExceeded {
  kind: "icmp6";
  type: "time-exceeded";
  original: OriginalPacket;
}

/**
 * ICMPv6 Destination Unreachable (타입 1). 코드: net = 0 (no route to destination), host = 3 (address unreachable — NDP 에 응답 없음),
 * port = 4 (port unreachable)
 */
export interface Icmpv6Unreachable {
  kind: "icmp6";
  type: "unreachable";
  code: UnreachableCode;
  original: OriginalPacket;
}

export type Icmpv6Error = Icmpv6TimeExceeded | Icmpv6Unreachable;

/**
 * Neighbor Solicitation (NDP, ICMPv6 타입 135): ARP 요청에 해당. "target 의 MAC 은?" 을 브로드캐스트 대신
 * target 의 solicited-node 멀티캐스트 주소로 보낸다. 출발지가 :: 이고 sll 이 없으면 DAD (이 주소를 쓰는 장치가 있나?)
 */
export interface NeighborSolicitation {
  kind: "icmp6";
  type: "ns";
  target: Ip;
  /** Source Link-Layer Address 옵션 (보낸 이의 MAC). DAD 에는 없다 */
  sll?: Mac;
}

/**
 * Neighbor Advertisement (NDP, ICMPv6 타입 136): ARP 응답에 해당. "target 은 tll 이다".
 * R = 보낸 이가 라우터, S = 요청(NS)에 대한 답, O = 캐시에 있는 값을 덮어써라
 */
export interface NeighborAdvertisement {
  kind: "icmp6";
  type: "na";
  target: Ip;
  router: boolean;
  solicited: boolean;
  override: boolean;
  /** Target Link-Layer Address 옵션 */
  tll?: Mac;
}

/** Router Solicitation (NDP, ICMPv6 타입 133): 호스트가 "라우터 있으면 RA 를 보내 주세요" 를 모든 라우터(ff02::2)에게 */
export interface RouterSolicitation {
  kind: "icmp6";
  type: "rs";
  sll?: Mac;
}

/** RA 의 프리픽스 정보 옵션 (옵션 3) */
export interface RaPrefix {
  prefix: Ip;
  length: number;
  /** L: 이 프리픽스는 링크 안 (직접 전달) */
  onLink: boolean;
  /** A: 이 프리픽스로 SLAAC 주소를 만들어도 된다 */
  autonomous: boolean;
  /** 유효 수명(초). 0 = 이 프리픽스를 거둔다 (주소를 지우라) */
  valid: number;
}

/**
 * Router Advertisement (NDP, ICMPv6 타입 134): 라우터가 "나는 이 링크의 라우터, 프리픽스는 이것" 을 알린다.
 * 호스트는 프리픽스 + 자기 인터페이스 ID 로 주소를 만들고(SLAAC), 보낸 라우터의 링크 로컬 주소를 기본 게이트웨이로 쓴다
 */
export interface RouterAdvertisement {
  kind: "icmp6";
  type: "ra";
  curHopLimit: number;
  /** M: 주소는 DHCPv6 로 받아라 (여기서는 늘 0) */
  managed: boolean;
  /** O: 주소 말고 다른 정보(DNS 등)는 DHCPv6 로 (여기서는 늘 0 — DNS 는 RDNSS 옵션으로) */
  other: boolean;
  /** 라우터 수명(초). 0 = 나를 기본 게이트웨이로 쓰지 말라 */
  routerLifetime: number;
  prefixes: RaPrefix[];
  /** RDNSS 옵션 (옵션 25, RFC 8106): DNS 서버 */
  rdnss?: Ip[];
  sll?: Mac;
}

export type NdpMessage = NeighborSolicitation | NeighborAdvertisement | RouterSolicitation | RouterAdvertisement;

export type Icmpv6Packet = Icmpv6Echo | Icmpv6Error | NdpMessage;

export function isNdp(p: Ipv6Payload): p is NdpMessage {
  return p.kind === "icmp6" && (p.type === "ns" || p.type === "na" || p.type === "rs" || p.type === "ra");
}

export function isIcmpv6Error(p: Ipv6Payload): p is Icmpv6Error {
  return p.kind === "icmp6" && (p.type === "time-exceeded" || p.type === "unreachable");
}

/** IPv4·IPv6 의 ICMP 오류 (보낸 이에게 돌려주는 통지) */
export function isIcmpErrorAny(p: IpPacket["payload"]): p is IcmpError | Icmpv6Error {
  return (p.kind === "icmp" || p.kind === "icmp6") && (p.type === "time-exceeded" || p.type === "unreachable");
}

export const UNREACHABLE6_LABEL: Record<UnreachableCode, string> = {
  net: "Destination Unreachable (no route)",
  host: "Destination Unreachable (address unreachable)",
  port: "Destination Unreachable (port unreachable)",
};

export const UNREACHABLE6_CODE: Record<UnreachableCode, number> = { net: 0, host: 3, port: 4 };

export function icmpv6ErrorLabel(p: Icmpv6Error): string {
  return p.type === "time-exceeded" ? "Time Exceeded" : UNREACHABLE6_LABEL[p.code];
}

/**
 * 드롭한 IPv6 패킷을 보낸 이에게 돌려줄 ICMPv6 오류. ICMPv6 오류·NDP 에 대한 것, 출발지가 :: 인 것,
 * 멀티캐스트로 간 것에는 만들지 않는다 → undefined
 */
export function icmpv6ErrorFor(from: Ip, dropped: Ipv6Packet, err: { type: "time-exceeded" } | { type: "unreachable"; code: UnreachableCode }): Ipv6Packet | undefined {
  if (dropped.src === "::" || dropped.dst.startsWith("ff")) return undefined;
  const p = dropped.payload;
  let l4: OriginalPacket["l4"];
  if (p.kind === "icmp6") {
    if (p.type !== "echo-request" && p.type !== "echo-reply") return undefined;
    l4 = { kind: "icmp", id: p.id, seq: p.seq };
  } else l4 = { kind: p.kind, srcPort: p.srcPort, dstPort: p.dstPort };
  const original = { src: dropped.src, dst: dropped.dst, l4 };
  const payload: Icmpv6Error = err.type === "time-exceeded" ? { kind: "icmp6", type: "time-exceeded", original } : { kind: "icmp6", type: "unreachable", code: err.code, original };
  return { kind: "ipv6", src: from, dst: dropped.src, hopLimit: 64, payload };
}

/** ICMPv6 메시지 종류 라벨 */
export function icmpv6Label(p: Icmpv6Packet): string {
  if (p.type === "time-exceeded" || p.type === "unreachable") return icmpv6ErrorLabel(p);
  if (p.type === "ns") return "Neighbor Solicitation";
  if (p.type === "na") return "Neighbor Advertisement";
  if (p.type === "rs") return "Router Solicitation";
  if (p.type === "ra") return "Router Advertisement";
  return p.type === "echo-request" ? "Echo 요청" : "Echo 응답";
}

/**
 * IP 프로토콜 번호와 이름. 새 종류를 넣으면 여기와 아래 두 판별 함수부터 본다 —
 * 장비들은 종류를 하나하나 나열하지 않고 "포트가 있나(hasPorts)", "라우터끼리의 제어 멀티캐스트인가(isControl)" 로 나눈다.
 */
export const IP_PROTO: Record<IpPayload["kind"], { num: number; label: string }> = {
  icmp: { num: 1, label: "ICMP" },
  tcp: { num: 6, label: "TCP" },
  udp: { num: 17, label: "UDP" },
  esp: { num: 50, label: "ESP — 포트 없음" },
  vrrp: { num: 112, label: "VRRP" },
  pfsync: { num: 240, label: "pfsync" },
};

/** 포트가 있는 전송 계층 (TCP·UDP) — NAT 가 포트로 구분하고, 방화벽 규칙의 포트 칸이 뜻을 가진다 */
export function hasPorts(p: IpPayload | Ipv6Payload): p is TcpSegment | UdpPacket {
  return p.kind === "tcp" || p.kind === "udp";
}

/** 라우터끼리만 주고받는 제어 멀티캐스트 (VRRP·pfsync): 호스트·공유기·인터넷은 조용히 거르고, NAT·ICMP 오류와 무관 */
export function isControl(p: IpPayload): p is VrrpPacket | PfsyncPacket {
  return p.kind === "vrrp" || p.kind === "pfsync";
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
  /** 요청의 Cookie 헤더 (예: "SERVERID=192.168.0.11:80") */
  cookie?: string;
  /** 응답의 Set-Cookie 헤더 — 로드밸런서의 쿠키 세션 고정 */
  setCookie?: string;
  /** 프록시에게 보낸 요청의 대상 (절대 URI "GET http://example.com/" 의 호스트:포트, CONNECT 면 터널을 열 곳) */
  target?: string;
  /** 요청 메서드 (없으면 GET). CONNECT = 프록시에게 대상까지 TCP 터널을 열어 달라는 요청 (HTTPS) */
  method?: "CONNECT";
  /** TLS 레코드 (포트 443, TLS 1.3 축소판). "app" 이면 data 는 두 끝만 푸는 안쪽 내용 */
  tls?: TlsRecord;
  /** TLS ClientHello 의 SNI (접속할 이름 — 암호화 전이라 중간 장비도 본다) */
  sni?: string;
}

/** TLS 레코드 종류: 핸드셰이크 세 번(ClientHello → ServerHello·인증서·Finished → Finished) 뒤로는 응용 데이터(암호화) */
export type TlsRecord = "client-hello" | "server-hello" | "finished" | "app";

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
  } else if (!hasPorts(p)) return undefined; // ESP(터널은 IKE timeout 으로 알아챈다)·제어 멀티캐스트에는 오류를 만들지 않는다
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
  payload: DhcpMessage | DnsMessage | RipMessage | VpnMessage | IkeMessage | EspPacket | Dhcp6Message;
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
 * IKE_AUTH: 사전 공유 키(PSK)로 서로 인증하고 터널(SA)을 만든다. 원격 접속 서버가 계정을 요구하면 IKE_AUTH 가 한 번 더 오간다 (EAP)
 */
export interface IkeMessage {
  kind: "ike";
  /** INFORMATIONAL: 원격 접속 클라이언트가 연결을 끊을 때 (Delete), DPD (빈 INFORMATIONAL), INVALID_SPI 알림 */
  exchange: "IKE_SA_INIT" | "IKE_AUTH" | "INFORMATIONAL";
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
  error?: "AUTHENTICATION_FAILED" | "INTERNAL_ADDRESS_FAILURE" | "INVALID_SPI";
  /** 원격 접속(클라이언트 ↔ 서버) 협상 — 사이트 간 VPN 과 구분 */
  ra?: boolean;
  /** 원격 접속: 클라이언트 식별 (다시 붙으면 같은 가상 주소를 준다) */
  cid?: string;
  /** 원격 접속 IKE_AUTH 응답: 서버가 준 가상 주소 (Configuration Payload INTERNAL_IP4_ADDRESS) */
  assigned?: Ip;
  /** 원격 접속 IKE_AUTH 응답: 터널로 보낼 사내 대역 (split tunnel, INTERNAL_IP4_SUBNET) */
  routes?: { dest: Ip; prefix: number }[];
  /** 원격 접속 IKE_AUTH 요청의 IDi: 사용자 이름 (계정 인증을 쓸 때) */
  user?: string;
  /** 원격 접속 계정 인증 (EAP-MSCHAPv2 축소판): 서버의 요청(challenge) → 클라이언트의 응답 → 성공/실패 */
  eap?: "request" | "response" | "success" | "failure";
  /** EAP 응답: 비밀번호로 만든 응답 값 (시뮬레이터는 비밀번호 문자열을 그대로 비교) */
  eapSecret?: string;
  /** 빈 INFORMATIONAL (DPD, Dead Peer Detection): 상대가 살아 있고 이 SA 를 아는지 확인. Delete 가 아니다 */
  dpd?: boolean;
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

/**
 * 세션 동기화 (pfsync 식, IP 프로토콜 240, 224.0.0.240): 이중화 master 가 새로 만든 NAT 매핑·방화벽 흐름을 backup 에 복사해 둔다.
 * 넘어가도 backup 이 같은 공인 포트·같은 흐름으로 이어 가므로 진행 중인 연결이 끊기지 않는다
 */
export interface PfsyncPacket {
  kind: "pfsync";
  vrid: number;
  /** 새 NAT 매핑 (공인 id 까지 그대로 복사) */
  nat: { proto: "icmp" | "tcp" | "udp"; lanIp: Ip; innerId: number; publicId: number }[];
  /** 새 방화벽 흐름 (Stateful 검사의 흐름 키) */
  flows: string[];
  /** 전체 복사 (새 backup 이 들어왔을 때) */
  bulk?: boolean;
  /** 넘겨줌: 둘 다 master 였다가 물러나는 쪽이 보낸 전체 복사 — 받는 쪽은 master 여도 받는다 */
  handover?: boolean;
}

export const PFSYNC_MULTICAST_IP: Ip = "224.0.0.240";
export const PFSYNC_MULTICAST_MAC: Mac = "01:00:5e:00:00:f0";

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
  /** 질의 종류: A = IPv4 주소, AAAA = IPv6 주소. 없으면 A */
  qtype?: "A" | "AAAA";
  /** 응답: 찾은 주소. 없으면 rcode */
  answer?: Ip;
  /** NODATA = 이름은 있지만 그 종류의 레코드가 없음 (실제로는 NOERROR 에 답 0개) */
  rcode?: "NXDOMAIN" | "SERVFAIL" | "NODATA";
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

/**
 * DHCPv6 (UDP 546 클라이언트 / 547 서버). 여기서는 프리픽스 위임(DHCPv6-PD, RFC 8415 IA_PD)만:
 * 공유기(클라이언트)가 ISP(서버)에게 Solicit → Advertise → Request → Reply 로 /56 을 받아 LAN 에 /64 를 나눠 알린다.
 * 첫 두 메시지는 모든 DHCP 서버 그룹(ff02::1:2)으로, 클라이언트는 링크 로컬 주소로 보낸다
 */
export interface Dhcp6Message {
  kind: "dhcp6";
  type: "solicit" | "advertise" | "request" | "reply" | "release";
  xid: number;
  /** 옵션 1 Client ID (DUID-LL: 클라이언트 MAC) */
  clientId: Mac;
  /** 옵션 2 Server ID (DUID-LL: 서버 MAC) */
  serverId?: Mac;
  /** 옵션 25 IA_PD 안의 옵션 26 IAPREFIX: 위임하는(받는) 프리픽스 */
  prefix?: { prefix: Ip; length: number };
  /** 옵션 13 Status Code: 위임할 프리픽스가 없음 */
  status?: "NoPrefixAvail";
}

export const DHCP6_CLIENT_PORT = 546;
export const DHCP6_SERVER_PORT = 547;
/** 모든 DHCPv6 릴레이·서버 (All_DHCP_Relay_Agents_and_Servers) */
export const DHCP6_MULTICAST: Ip = "ff02::1:2";
export const DHCP6_MULTICAST_MAC: Mac = "33:33:00:01:00:02";

export const DHCP_SERVER_PORT = 67;
export const DHCP_CLIENT_PORT = 68;
export const UNSPECIFIED_IP: Ip = "0.0.0.0";
export const LIMITED_BROADCAST_IP: Ip = "255.255.255.255";

export type Layer = "L1" | "L2" | "L3" | "L4" | "app" | "sys";

export type FrameCategory = "arp" | "icmp" | "dhcp" | "tcp" | "dns" | "rip" | "vpn" | "vrrp" | "stp";

/** 브리지 ID 표기: 우선순위.MAC (예: 32768.02:00:00:00:00:05) */
export function bridgeIdLabel(b: BridgeId): string {
  return `${b.prio}.${b.mac}`;
}

const ESP_LABEL = (e: EspPacket) => `ESP SPI 0x${e.spi.toString(16).padStart(8, "0")} seq=${e.seq} (암호화됨 · 안: ${e.inner.src} → ${e.inner.dst})`;
const IKE_LABEL = (m: IkeMessage) =>
  `IKE ${m.exchange} ${m.response ? (m.error ? `응답 (${m.error})` : "응답") : "요청"}${m.ra ? " · 원격 접속" : ""}${m.eap ? ` · EAP ${m.eap === "request" ? "요청" : m.eap === "response" ? "응답" : m.eap === "success" ? "성공" : "실패"}` : ""}${m.dpd ? " · DPD" : ""}`;

const DHCP_LABEL: Record<DhcpOp, string> = { discover: "Discover", offer: "Offer", request: "Request", ack: "Ack", nak: "Nak", release: "Release" };

/** UI 라벨/로그용 짧은 설명 */
export function describeFrame(frame: EthernetFrame): string {
  const p = frame.payload;
  if (p.kind === "arp") {
    return p.op === "request" ? `ARP 요청 (${p.targetIp}?)` : `ARP 응답 (${p.senderIp}=${p.senderMac})`;
  }
  if (p.kind === "bpdu") return `STP BPDU (루트 ${bridgeIdLabel(p.root)}, 비용 ${p.cost}, 보낸 스위치 ${bridgeIdLabel(p.bridge)} 포트 ${p.port})`;
  if (p.kind === "ipv6") return describeIpv6(p);
  const inner = p.payload;
  if (inner.kind === "icmp") {
    if (inner.type === "time-exceeded" || inner.type === "unreachable") return `ICMP ${icmpErrorLabel(inner)} (원래 ${describeOriginal(inner.original)})`;
    return inner.type === "echo-request" ? `ICMP Echo 요청 seq=${inner.seq}` : `ICMP Echo 응답 seq=${inner.seq}`;
  }
  if (inner.kind === "tcp") return `TCP ${tcpFlags(inner)} seq=${inner.seq} ack=${inner.ack}${inner.len ? ` len=${inner.len}` : ""}`;
  if (inner.kind === "esp") return ESP_LABEL(inner);
  if (inner.kind === "pfsync") return `세션 동기화 (pfsync${inner.bulk ? " 전체" : ""}: NAT 매핑 ${inner.nat.length}개, 흐름 ${inner.flows.length}개)`;
  if (inner.kind === "vrrp") return `VRRP 광고 (그룹 ${inner.vrid}, 우선순위 ${inner.priority}${inner.priority === 0 ? " — 물러남" : ""}, 가상 주소 ${inner.vip})`;
  const d = inner.payload;
  if (d.kind === "esp") return `UDP 4500 (NAT-T) · ${ESP_LABEL(d)}`;
  if (d.kind === "ike") return IKE_LABEL(d);
  if (d.kind === "dns") return d.op === "query" ? `DNS 질의 (${d.name}${d.qtype === "AAAA" ? " AAAA" : ""}?)` : `DNS 응답 (${d.name}${d.qtype === "AAAA" ? " AAAA" : ""} = ${d.answer ?? (d.rcode === "NODATA" ? "레코드 없음" : d.rcode)})`;
  if (d.kind === "rip") return d.command === "request" ? "RIP Request (전체 경로 요청)" : `RIP Response (경로 ${d.entries.length}개)`;
  if (d.kind === "vpn") return `VPN 터널 (암호화됨 · 안: ${d.inner.src} → ${d.inner.dst})`;
  if (d.kind === "dhcp6") return dhcp6Label(d);
  return `DHCP ${DHCP_LABEL[d.op]}${d.yiaddr ? ` (${d.yiaddr})` : ""}`;
}

const DHCP6_LABEL: Record<Dhcp6Message["type"], string> = { solicit: "Solicit", advertise: "Advertise", request: "Request", reply: "Reply", release: "Release" };

function dhcp6Label(d: Dhcp6Message): string {
  return `DHCPv6 ${DHCP6_LABEL[d.type]}${d.prefix ? ` (프리픽스 위임 ${d.prefix.prefix}/${d.prefix.length})` : d.status ? ` (${d.status})` : " (프리픽스 위임 요청)"}`;
}

/** IPv6 패킷 설명 (로그용) */
function describeIpv6(p: Ipv6Packet): string {
  const inner = p.payload;
  if (inner.kind === "icmp6") {
    if (inner.type === "ns") return p.src === "::" ? `NDP NS — DAD (${inner.target} 를 쓰는 장치가 있나?)` : `NDP NS (${inner.target} 의 MAC 은?)`;
    if (inner.type === "na") return `NDP NA (${inner.target} = ${inner.tll ?? "?"}${inner.router ? ", 라우터" : ""})`;
    if (inner.type === "rs") return `NDP RS (라우터 있나요?)`;
    if (inner.type === "ra")
      return `NDP RA (${inner.routerLifetime === 0 ? "라우터 수명 0 — 거둠" : `프리픽스 ${inner.prefixes.filter((x) => x.valid > 0).map((x) => `${x.prefix}/${x.length}`).join(", ") || "없음"}`}${inner.rdnss?.length ? `, DNS ${inner.rdnss.join(", ")}` : ""})`;
    if (inner.type === "time-exceeded" || inner.type === "unreachable") return `ICMPv6 ${icmpv6ErrorLabel(inner)} (원래 ${describeOriginal(inner.original)})`;
    return inner.type === "echo-request" ? `ICMPv6 Echo 요청 seq=${inner.seq}` : `ICMPv6 Echo 응답 seq=${inner.seq}`;
  }
  if (inner.kind === "tcp") return `TCP ${tcpFlags(inner)} seq=${inner.seq} ack=${inner.ack}${inner.len ? ` len=${inner.len}` : ""} (IPv6)`;
  const d = inner.payload;
  if (d.kind === "dns") return d.op === "query" ? `DNS 질의 (${d.name}${d.qtype === "AAAA" ? " AAAA" : ""}?) (IPv6)` : `DNS 응답 (${d.name}${d.qtype === "AAAA" ? " AAAA" : ""} = ${d.answer ?? (d.rcode === "NODATA" ? "레코드 없음" : d.rcode)}) (IPv6)`;
  if (d.kind === "dhcp6") return dhcp6Label(d);
  return `UDP ${inner.srcPort} → ${inner.dstPort} (IPv6)`;
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
  if (p.kind === "bpdu") return "BPDU";
  if (p.kind === "ipv6") {
    const i6 = p.payload;
    if (i6.kind === "icmp6") return i6.type === "ns" ? (p.src === "::" ? "DAD" : "NS") : i6.type === "na" ? "NA" : i6.type === "rs" ? "RS" : i6.type === "ra" ? "RA" : i6.type === "echo-request" ? "ping6 요청" : i6.type === "echo-reply" ? "ping6 응답" : i6.type === "time-exceeded" ? "Hop Limit 초과" : "도달 불가";
    if (i6.kind === "tcp") return i6.len > 0 ? `${i6.data ?? "DATA"} ${i6.len}B` : tcpFlags(i6);
    if (i6.payload.kind === "dhcp6") return `DHCPv6 ${DHCP6_LABEL[i6.payload.type]}`;
    return i6.payload.kind === "dns" ? (i6.payload.op === "query" ? "DNS 질의" : "DNS 응답") : "UDP";
  }
  const inner = p.payload;
  if (inner.kind === "icmp") return inner.type === "echo-request" ? "ping 요청" : inner.type === "echo-reply" ? "ping 응답" : inner.type === "time-exceeded" ? "TTL 초과" : "도달 불가";
  if (inner.kind === "tcp") return inner.len > 0 ? `${inner.data ?? "DATA"} ${inner.len}B` : tcpFlags(inner);
  if (inner.kind === "pfsync") return "세션 동기화";
  if (inner.kind === "vrrp") return inner.priority === 0 ? "VRRP 물러남" : `VRRP ${inner.priority}`;
  if (inner.kind === "esp" || inner.payload.kind === "esp") return "ESP 터널";
  if (inner.payload.kind === "ike") return inner.payload.dpd ? "DPD" : inner.payload.eap ? "EAP 인증" : inner.payload.exchange === "IKE_SA_INIT" ? "IKE 협상" : inner.payload.exchange === "IKE_AUTH" ? "IKE 인증" : "IKE 알림";
  if (inner.payload.kind === "dns") return inner.payload.op === "query" ? "DNS 질의" : "DNS 응답";
  if (inner.payload.kind === "rip") return inner.payload.command === "request" ? "RIP 요청" : "RIP 광고";
  if (inner.payload.kind === "vpn") return "VPN 터널";
  if (inner.payload.kind === "dhcp6") return `DHCPv6 ${DHCP6_LABEL[inner.payload.type]}`;
  return `DHCP ${DHCP_LABEL[inner.payload.op]}`;
}

/** 패킷 종류 태그 (UI 색상 구분용) */
export function frameCategory(frame: EthernetFrame): FrameCategory {
  const p = frame.payload;
  if (p.kind === "arp") return "arp";
  if (p.kind === "bpdu") return "stp";
  if (p.kind === "ipv6") {
    // NDP 는 ARP 와 같은 역할(이웃 주소 해석)이라 같은 색
    const i6 = p.payload;
    // RS·RA 는 주소를 알려 주는 역할이라 DHCP 와 같은 색
    if (i6.kind === "icmp6") return i6.type === "ns" || i6.type === "na" ? "arp" : i6.type === "rs" || i6.type === "ra" ? "dhcp" : "icmp";
    if (i6.kind === "tcp") return "tcp";
    return i6.payload.kind === "dns" ? "dns" : "dhcp";
  }
  if (p.payload.kind === "icmp") return "icmp";
  if (p.payload.kind === "tcp") return "tcp";
  if (p.payload.kind === "esp") return "vpn";
  if (isControl(p.payload)) return "vrrp";
  const k = p.payload.payload.kind;
  return k === "dns" ? "dns" : k === "rip" ? "rip" : k === "vpn" || k === "esp" || k === "ike" ? "vpn" : "dhcp";
}
