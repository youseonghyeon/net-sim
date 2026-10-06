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
  payload: IcmpPacket | UdpPacket | TcpSegment | EspPacket | VrrpPacket | PfsyncPacket | IgmpPacket;
}

/**
 * IGMP (IPv4 멀티캐스트 그룹 가입): 호스트가 "그룹 G 를 받고 싶다"(Membership Report, 목적지 = 그 그룹)·"그만 받겠다"(Leave, 224.0.0.2)를 알린다.
 * IGMP 스누핑 스위치는 이것을 엿들어 그룹마다 받을 포트를 배우고, 멀티캐스트를 그 포트로만 보낸다. 쿼리어·만료는 생략
 */
export interface IgmpPacket {
  kind: "igmp";
  type: "report" | "leave" | "query";
  /** query 는 0.0.0.0 (모든 그룹 — General Query) */
  group: Ip;
}

export const ALL_HOSTS_IP: Ip = "224.0.0.1";

/** 멀티캐스트 스트림 (IPTV 흉내): UDP 로 그룹 주소에 보낸다 */
export interface McastData {
  kind: "mcast";
  group: Ip;
  seq: number;
  total: number;
  /** 채널 이름 */
  name: string;
}

export const MCAST_PORT = 5004;

/**
 * SIP (인터넷 전화의 신호): 등록(REGISTER)·전화 걸기(INVITE → 180 Ringing → 200 OK → ACK)·끊기(BYE).
 * SDP(sdp) 에 "내 음성은 이 주소:포트로 보내 달라" 를 적는다 — NAT 뒤 전화기는 사설 주소를 적어 상대가 보낼 곳을 모른다 (SIP ALG 가 고치는 것)
 */
export interface SipMessage {
  kind: "sip";
  method?: "REGISTER" | "INVITE" | "ACK" | "BYE";
  status?: 100 | 180 | 200 | 404 | 486;
  /** REGISTER 의 Expires (0 = 등록 해제) */
  expires?: number;
  callId: string;
  from: string;
  to: string;
  cseq: number;
  /** Contact 헤더 (나에게 연락할 주소) */
  contact?: Endpoint;
  /** SDP 의 미디어 주소 (c= 와 m=audio 포트) */
  sdp?: { ip: Ip; port: number };
  /** SIP ALG 가 고쳐 쓴 메시지 (표시용) */
  alg?: { ip: Ip; port: number };
}

/** RTP (음성 조각) */
export interface RtpPacket {
  kind: "rtp";
  callId: string;
  seq: number;
  from: string;
}

/**
 * Tor 셀 (양파 라우팅): 공유기가 가드·중간·출구 세 릴레이의 키로 세 겹 감싼 원래 패킷. 릴레이마다 한 겹씩 벗긴다
 * (실제는 TLS 위 512바이트 셀·TCP 스트림 — 여기서는 UDP 로 줄이고 IP 패킷째 나른다)
 */
export interface TorCell {
  kind: "tor";
  op: "create" | "created" | "data" | "destroy";
  circ: number;
  /** 남은 암호화 겹 수 (공유기가 보낼 때 3) */
  layers: number;
  inner?: Ipv4Packet;
}

export const TOR_PORT = 9001;
export const TOR_GUARD: Ip = "198.51.100.131";
export const TOR_MIDDLE: Ip = "198.51.100.132";
export const TOR_EXIT: Ip = "198.51.100.133";

export const SIP_PORT = 5060;
export const SIP_SERVER: Ip = "198.51.100.120";
export const SIP_DOMAIN = "voip.example";

export function sipLabel(m: SipMessage): string {
  if (m.status) return `SIP ${m.status} ${m.status === 200 ? "OK" : m.status === 180 ? "Ringing" : m.status === 100 ? "Trying" : m.status === 486 ? "Busy Here" : "Not Found"}${m.sdp ? " (SDP)" : ""}`;
  if (m.method === "REGISTER" && m.expires === 0) return `SIP REGISTER ${m.from} (해제)`;
  return `SIP ${m.method} ${m.method === "REGISTER" ? m.from : `${m.from} → ${m.to}`}${m.sdp ? ` (SDP ${m.sdp.ip}:${m.sdp.port})` : ""}`;
}
export const ALL_ROUTERS_IP: Ip = "224.0.0.2";

/** IPv4 멀티캐스트 주소 → MAC (01:00:5e + 주소의 아래 23비트) */
export function mcastMac(ip: Ip): Mac {
  const [, b, c, d] = ip.split(".").map(Number) as [number, number, number, number];
  const h = (n: number) => n.toString(16).padStart(2, "0");
  return `01:00:5e:${h(b & 0x7f)}:${h(c)}:${h(d)}`;
}

/** 224.0.0.0/4 */
export function isMcastIp(ip: Ip): boolean {
  const a = Number(ip.split(".")[0]);
  return a >= 224 && a <= 239;
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
  igmp: { num: 2, label: "IGMP" },
};

/** 포트가 있는 전송 계층 (TCP·UDP) — NAT 가 포트로 구분하고, 방화벽 규칙의 포트 칸이 뜻을 가진다 */
export function hasPorts(p: IpPayload | Ipv6Payload): p is TcpSegment | UdpPacket {
  return p.kind === "tcp" || p.kind === "udp";
}

/** 라우터끼리만 주고받는 제어 멀티캐스트 (VRRP·pfsync): 호스트·공유기·인터넷은 조용히 거르고, NAT·ICMP 오류와 무관 */
export function isControl(p: IpPayload): p is VrrpPacket | PfsyncPacket | IgmpPacket {
  return p.kind === "vrrp" || p.kind === "pfsync" || p.kind === "igmp";
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
  /** OpenVPN TCP 모드: 이 세그먼트가 나르는 OpenVPN 메시지 (TCP 스트림 위의 OpenVPN 패킷) */
  ovpn?: OvpnMessage;
  /**
   * 헬스 체크 연결의 SYN (시뮬레이터 안에서만 쓰는 표시 — 실제 패킷에는 없다). 받은 서버도 그 연결의 재전송을 배경 타이머로 걸어,
   * 주기 체크가 일반 타이머를 끝없이 이어 시계를 멈추지 못하게 하는 일을 막는다
   */
  probe?: boolean;
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
  payload: DhcpMessage | DnsMessage | RipMessage | VpnMessage | IkeMessage | EspPacket | Dhcp6Message | L2tpPacket | StunMessage | P2pMessage | WgMessage | DdnsMessage | OvpnMessage | TsMessage | CloudMessage | McastData | SipMessage | RtpPacket | TorCell;
}

/** STUN·TURN (UDP 3478) */
export const STUN_PORT = 3478;
/** P2P 앱이 쓰는 UDP 포트 (예: Tailscale 41641) */
export const P2P_PORT = 41641;
/** 시그널링 서버 포트 (실제로는 보통 HTTPS·웹소켓 — 여기서는 UDP 로 줄임) */
export const SIGNAL_PORT = 8443;

export interface Endpoint {
  ip: Ip;
  port: number;
}

/**
 * STUN·TURN (RFC 5389·5766 축소판, UDP 3478)
 * - binding: "바깥에서 본 내 주소:포트는?" → 서버가 본 출발지를 mapped 로 (XOR-MAPPED-ADDRESS)
 * - allocate: TURN 서버에 릴레이 주소를 하나 받는다 (relayed)
 * - send: 릴레이 주소에서 상대(peer)에게 data 를 내보내 달라 / data: 릴레이 주소로 상대가 보낸 것을 전해 줌
 */
export interface StunMessage {
  kind: "stun";
  op: "binding-request" | "binding-response" | "allocate-request" | "allocate-response" | "send" | "data";
  txid: number;
  mapped?: Endpoint;
  relayed?: Endpoint;
  peer?: Endpoint;
  data?: P2pMessage;
}

/** P2P 후보 주소 (ICE 축소판): host = 내 사설 주소, srflx = STUN 이 알려 준 바깥 주소, relay = TURN 릴레이 주소 */
export interface P2pCandidate extends Endpoint {
  type: "host" | "srflx" | "relay";
}

/**
 * P2P 앱 메시지 (UDP 41641 과 시그널링 서버 8443)
 * - register·registered·unregister: 시그널링 서버에 이름 등록·해제 / offer·answer·relay·busy: 시그널링 서버를 거쳐 후보 교환·거절
 * - punch·punch-ack: 상대 후보로 직접 보내 NAT 에 구멍을 뚫고 확인 (홀 펀칭)
 */
export interface P2pMessage {
  kind: "p2p";
  op: "register" | "registered" | "unregister" | "offer" | "answer" | "relay" | "busy" | "punch" | "punch-ack" | "error";
  from: string;
  to?: string;
  candidates?: P2pCandidate[];
  /** 내가 짐작한 NAT 종류 (STUN 두 곳의 결과로) */
  nat?: "none" | "cone" | "symmetric";
  error?: string;
  seq?: number;
}

export const L2TP_PORT = 1701;

/**
 * L2TP (UDP 1701): 공유기 VPN(ipTIME 식 L2TP/IPsec)의 안쪽 겹. IPsec(ESP 전송 모드)이 이 UDP 1701 을 암호화해 감싸고,
 * L2TP 는 그 안에 PPP 를 실어 나른다 — PPP 가 계정 확인(CHAP)과 주소 할당(IPCP)을 하고, 그 뒤로는 IP 패킷을 싣는다.
 * control: 터널(SCCRQ/SCCRP)·세션(ICRQ/ICRP) 열기와 끊기(CDN·StopCCN). 실제 3단계 핸드셰이크(…CN)는 줄였다
 */
export interface L2tpPacket {
  kind: "l2tp";
  /** 터널·세션 번호 (0 = 아직 없음) */
  tunnelId: number;
  sessionId: number;
  control?: "SCCRQ" | "SCCRP" | "ICRQ" | "ICRP" | "CDN" | "StopCCN";
  ppp?: PppFrame;
}

/** PPP: L2TP 세션 위에서 링크 설정(LCP)·인증(CHAP)·주소(IPCP) 뒤 IP 를 싣는다 */
export type PppFrame =
  | { proto: "lcp"; code: "configure-request" }
  /** CHAP (MS-CHAPv2 축소판): 서버의 challenge → 클라이언트의 response(사용자·비밀번호로 만든 값) → success / failure */
  | { proto: "chap"; code: "challenge" | "response" | "success" | "failure"; user?: string; secret?: string }
  /** IPCP: 클라이언트가 주소를 요청(0.0.0.0) → 서버가 줄 주소·DNS 로 Ack (주소가 없으면 Nak) */
  | { proto: "ipcp"; code: "configure-request" | "configure-ack" | "configure-nak"; ip?: Ip; dns?: Ip }
  | { proto: "ip"; packet: Ipv4Packet };

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
 * WireGuard (UDP, 기본 51820): 공개 키로 서로를 알아보는 VPN. 메시지는 네 가지뿐이다.
 * - initiation (148바이트): 시작한 쪽이 보낸다. 자기 정적 공개 키는 응답자 공개 키로 암호화돼 응답자만 읽을 수 있고,
 *   mac1 은 응답자 공개 키로 만든다 — 응답자 공개 키를 잘못 알고 있으면 응답자는 읽지도 않고 버린다
 * - response (92바이트): 응답자가 보낸다. 이것으로 세션 키가 생긴다 (1-RTT)
 * - data (32바이트 + 암호화된 원래 패킷): receiver = 받는 쪽이 정한 세션 번호. inner 가 없으면 keepalive (32바이트)
 * 시뮬레이터는 암호화하지 않고 키 문자열을 그대로 싣는다 (화면에는 "암호화됨" 으로만 보인다)
 */
export interface WgMessage {
  kind: "wg";
  /** junk: 난독화(AmneziaWG 식)가 핸드셰이크 앞에 섞는 쓰레기 패킷 — 받는 쪽은 버린다 */
  type: "initiation" | "response" | "data" | "junk";
  /** 난독화: 머리·크기를 흐트러뜨려 DPI 가 WireGuard 로 알아보지 못하게 (양쪽이 같이 켜야 서로 알아본다) */
  obf?: boolean;
  /** 보낸 쪽이 정한 자기 세션 번호 (sender index) */
  sender?: number;
  /** 받는 쪽의 세션 번호 (response·data) */
  receiver?: number;
  /** initiation: 시작한 쪽의 정적 공개 키 (실제로는 암호화돼 응답자만 읽음) */
  static?: string;
  /** initiation: 시작한 쪽이 알고 있는 응답자 공개 키 (실제로는 이 키로 만든 mac1) */
  to?: string;
  /** data: 일련번호 (재전송 공격 방지) */
  counter?: number;
  /** data: 복호화했을 때의 원래 패킷. 없으면 keepalive */
  inner?: Ipv4Packet;
}

/**
 * DDNS 갱신 (GL.iNet 의 glddns.com·ipTIME 의 iptime.org 같은 서비스): 공유기가 "이 이름은 지금 내 주소" 를 알린다.
 * 서버는 요청의 출발지 주소(공유기 앞에 NAT 가 있으면 그 NAT 의 공인 주소)를 그 이름의 A 레코드로 둔다.
 * 실제는 HTTPS GET /nic/update?hostname=… (dyndns2 프로토콜) — 여기서는 UDP 8245 의 메시지 한 쌍으로 줄였다.
 * 답: good(바꿈) · nochg(그대로) · badauth(다른 기기가 등록한 이름) · notfqdn(이 서비스의 이름이 아님)
 */
export interface DdnsMessage {
  kind: "ddns";
  /** release: 이 기기가 이름을 내려놓음 (DDNS 를 끄거나 장치를 치울 때 — 다른 기기가 그 이름을 쓸 수 있게) */
  op: "update" | "response" | "release";
  id: number;
  hostname: string;
  /** 기기 식별 (GL.iNet 은 기기마다 이름이 정해져 있다 — 여기서는 WAN MAC) */
  device?: string;
  result?: "good" | "nochg" | "badauth" | "notfqdn";
  /** 서버가 등록한 주소 */
  ip?: Ip;
}

export const DDNS_PORT = 8245;

export function ddnsLabel(m: DdnsMessage): string {
  return m.op === "release" ? `DDNS 이름 내려놓기 (${m.hostname})` : m.op === "update" ? `DDNS 갱신 요청 (${m.hostname})` : `DDNS 응답 (${m.hostname}: ${m.result}${m.ip ? ` ${m.ip}` : ""})`;
}

/**
 * OpenVPN (UDP 또는 TCP, 기본 1194): TLS 로 서로의 인증서를 확인하는 VPN.
 * - reset-client·reset-server: 세션 시작 (P_CONTROL_HARD_RESET_*_V2)
 * - tls-client·tls-server·tls-auth·tls-ok·tls-fail: 제어 채널 위의 TLS — 서버 인증서(CA 확인) → 클라이언트 인증서·계정 → 결과
 * - push-request·push-reply: 서버가 주소(ifconfig)·경로(route)·DNS·전부 터널로(redirect-gateway)를 내려 준다
 * - data: 원래 IP 패킷 (P_DATA_V2), ping: keepalive, exit: 클라이언트가 끊음 (explicit-exit-notify)
 * crypt: tls-crypt 키 (같은 키가 아니면 받는 쪽이 열지 못하고 침묵 — 실제로는 HMAC), 시뮬레이터는 키 지문을 그대로 싣는다
 */
export interface OvpnMessage {
  kind: "ovpn";
  op: "reset-client" | "reset-server" | "tls-client" | "tls-server" | "tls-auth" | "tls-ok" | "tls-fail" | "push-request" | "push-reply" | "data" | "ping" | "exit";
  /** 클라이언트 세션 번호 */
  sid: number;
  /** tls-crypt 키 지문 (없으면 tls-crypt 안 씀) */
  crypt?: string;
  /** tls-server: 서버 인증서 / tls-auth: 클라이언트 인증서 — 발급한 CA 의 지문 */
  cert?: { cn: string; ca: string };
  /** tls-auth: 계정 (auth-user-pass) */
  user?: string;
  password?: string;
  /** tls-fail 의 이유 */
  reason?: string;
  /** push-reply */
  push?: { ip: Ip; prefix: number; routes: { dest: Ip; prefix: number }[]; dns?: Ip; redirectGateway: boolean };
  /** data */
  inner?: Ipv4Packet;
  /** 클라이언트 식별 (다시 붙으면 같은 주소) */
  cid?: string;
}

export const OVPN_PORT = 1194;

/** 메시 VPN 의 피어 정보 (조정 서버가 netmap 으로 나눠 준다) */
export interface TsPeerInfo {
  name: string;
  key: string;
  ip: Ip;
  /** 그 기기의 후보 주소 (LAN 주소:포트, STUN 으로 안 바깥 주소:포트) */
  endpoints: Endpoint[];
  /** 서브넷 라우터로 알린 대역 */
  routes: { dest: Ip; prefix: number }[];
  /** exit node 를 내주는지 */
  exitNode: boolean;
  online: boolean;
}

/**
 * Tailscale·ZeroTier (메시 VPN): 조정 서버(control·controller)가 기기들의 키·주소·후보 주소를 나눠 주고(netmap),
 * 기기끼리는 직접(UDP 홀 펀칭 — disco ping/pong) 또는 릴레이(DERP·ZeroTier root)를 거쳐 WireGuard 식으로 주고받는다.
 * - login·netmap·endpoints·logout: 조정 서버와 (실제는 HTTPS·Noise — 여기서는 UDP 로 줄임)
 * - derp-hello·derp-send·derp-recv: 릴레이 서버에 내 키로 자리를 잡고, 상대 키로 보내 달라고 맡긴다
 * - call-me-maybe: 릴레이로 "내 후보 주소로 ping 해 달라" (양쪽이 동시에 보내야 NAT 구멍이 뚫린다)
 * - disco-ping·disco-pong: 후보 주소로 직접 닿는지 확인 (pong 에 "내가 본 당신 주소")
 * - data: 원래 IP 패킷 (WireGuard 로 암호화 — 두 끝만 푼다)
 */
export interface TsMessage {
  kind: "ts";
  net: "tailscale" | "zerotier";
  op: "login" | "netmap" | "endpoints" | "logout" | "denied" | "derp-hello" | "derp-send" | "derp-recv" | "call-me-maybe" | "disco-ping" | "disco-pong" | "data";
  /** tailnet 이름·ZeroTier 네트워크 ID */
  network?: string;
  name?: string;
  /** 보낸 기기의 노드 키 */
  key?: string;
  /** 받을 기기의 노드 키 (DERP) */
  to?: string;
  endpoints?: Endpoint[];
  routes?: { dest: Ip; prefix: number }[];
  exitNode?: boolean;
  self?: { ip: Ip; prefix: number; name: string };
  peers?: TsPeerInfo[];
  txid?: number;
  /** disco-pong: ping 을 보낸 쪽 주소 (받은 쪽이 본 것) */
  seen?: Endpoint;
  reason?: string;
  inner?: Ipv4Packet;
  /** DERP 로 맡긴 메시지 */
  msg?: TsMessage;
}

/**
 * GoodCloud (GL.iNet 원격 관리 클라우드): 공유기가 먼저 클라우드에 연결(register)해 두고 그 연결을 유지(keepalive)하면,
 * 관리자가 클라우드 화면에서 누른 요청(manage)이 그 연결로 공유기에 닿고 공유기가 상태(status)로 답한다 — 포트 포워딩 없이
 */
export interface CloudMessage {
  kind: "cloud";
  op: "register" | "registered" | "keepalive" | "manage" | "status";
  /** 기기 식별 (MAC) */
  device: string;
  name?: string;
  txid?: number;
  status?: { wan: Ip; clients: number; vpn: string };
}

export const CLOUD_PORT = 443;
export const CLOUD_SERVER: Ip = "198.51.100.90";

export function cloudLabel(m: CloudMessage): string {
  const op: Record<CloudMessage["op"], string> = { register: "기기 등록", registered: "등록됨", keepalive: "연결 유지", manage: "원격 관리 요청", status: "상태 응답" };
  return `GoodCloud ${op[m.op]}`;
}

export const TS_PORT = 41641;
export const ZT_PORT = 9993;

export function tsLabel(m: TsMessage): string {
  const brand = m.net === "zerotier" ? "ZeroTier" : "Tailscale";
  const relay = m.net === "zerotier" ? "root 릴레이" : "DERP";
  const op: Record<TsMessage["op"], string> = {
    login: "로그인",
    netmap: "netmap (피어 목록)",
    endpoints: "후보 주소 알림",
    logout: "로그아웃",
    denied: "거절",
    "derp-hello": `${relay} 접속`,
    "derp-send": `${relay} 로 보냄`,
    "derp-recv": `${relay} 가 전해 줌`,
    "call-me-maybe": "call-me-maybe",
    "disco-ping": "disco ping",
    "disco-pong": "disco pong",
    data: "데이터",
  };
  if (m.op === "data" && m.inner) return `${brand} 데이터 (암호화됨 · 안: ${m.inner.src} → ${m.inner.dst})`;
  if ((m.op === "derp-send" || m.op === "derp-recv") && m.msg) return `${brand} ${op[m.op]} · ${tsLabel(m.msg).replace(`${brand} `, "")}`;
  return `${brand} ${op[m.op]}`;
}

/** 메시 VPN 메시지의 UDP 길이 (근사) */
export function tsLength(m: TsMessage, innerLength: number): number {
  if (m.op === "data") return 32 + innerLength;
  if (m.op === "derp-send" || m.op === "derp-recv") return 40 + (m.msg ? tsLength(m.msg, m.msg.inner ? innerLength : 0) : 0);
  if (m.op === "netmap") return 120 + (m.peers?.length ?? 0) * 96;
  if (m.op === "disco-ping" || m.op === "disco-pong") return 62;
  return 80 + (m.endpoints?.length ?? 0) * 18;
}

export function ovpnLabel(m: OvpnMessage): string {
  const op: Record<OvpnMessage["op"], string> = {
    "reset-client": "세션 시작 (HARD_RESET_CLIENT)",
    "reset-server": "세션 시작 응답 (HARD_RESET_SERVER)",
    "tls-client": "TLS ClientHello",
    "tls-server": "TLS ServerHello·서버 인증서",
    "tls-auth": "TLS 클라이언트 인증서·계정",
    "tls-ok": "TLS 완료",
    "tls-fail": "TLS 실패",
    "push-request": "PUSH_REQUEST",
    "push-reply": "PUSH_REPLY (주소·경로·DNS)",
    data: "데이터",
    ping: "ping (keepalive)",
    exit: "끊음 (exit-notify)",
  };
  return m.op === "data" && m.inner ? `OpenVPN 데이터 (암호화됨 · 안: ${m.inner.src} → ${m.inner.dst})` : `OpenVPN ${op[m.op]}${m.crypt ? " · tls-crypt" : ""}`;
}

/** OpenVPN 메시지의 길이 (근사) */
export function ovpnLength(m: OvpnMessage, innerLength: number): number {
  const base = m.op === "data" ? 24 + innerLength : m.op === "tls-server" ? 1200 : m.op === "tls-auth" ? 900 : m.op === "push-reply" ? 180 : m.op === "ping" ? 40 : 60;
  return base + (m.crypt ? 32 : 0);
}

/** WireGuard 메시지의 UDP 길이 (실제 형식의 크기) */
export function wgLength(m: WgMessage, innerLength: number): number {
  // 난독화는 메시지마다 앞에 쓰레기 바이트를 붙여 크기가 늘 다르다 (여기서는 고정 값으로 흉내)
  const pad = m.obf ? 37 : 0;
  if (m.type === "junk") return 64 + ((m.sender ?? 0) % 64);
  if (m.type === "initiation") return 148 + pad;
  if (m.type === "response") return 92 + pad;
  // data: 머리 16 + 암호화된 원래 패킷(16바이트 단위로 채움) + 인증 태그 16
  return 32 + pad + (m.inner ? Math.ceil(innerLength / 16) * 16 : 0);
}

export function wgLabel(m: WgMessage): string {
  if (m.type === "junk") return "UDP (난독화 — 쓰레기 패킷)";
  if (m.obf) return `UDP (난독화된 WireGuard ${m.type === "initiation" ? "핸드셰이크 시작" : m.type === "response" ? "핸드셰이크 응답" : m.inner ? "데이터" : "keepalive"} — 밖에서는 모양을 알아볼 수 없음)`;
  if (m.type === "initiation") return `WireGuard 핸드셰이크 시작 (Initiation, 보낸 세션 ${m.sender})`;
  if (m.type === "response") return `WireGuard 핸드셰이크 응답 (Response, 세션 ${m.sender} ↔ ${m.receiver})`;
  return m.inner ? `WireGuard 데이터 (세션 ${m.receiver} · 암호화됨 · 안: ${m.inner.src} → ${m.inner.dst})` : `WireGuard keepalive (세션 ${m.receiver})`;
}

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
  /** 전송 모드 (L2TP/IPsec): 두 끝 사이의 UDP 1701 만 보호한다 — inner 는 같은 두 장치 사이의 원래 패킷 */
  transport?: boolean;
}

/**
 * IKEv2 (UDP 500, NAT 가 있으면 4500): IPsec 터널을 맺는 협상. 요청·응답 두 번이면 끝난다.
 * IKE_SA_INIT: 암호 방식 합의 + NAT 감지 (보낸 쪽이 적은 자기 주소·상대 주소가 받은 헤더와 다르면 중간에 NAT)
 * IKE_AUTH: 사전 공유 키(PSK)로 서로 인증하고 터널(SA)을 만든다. 원격 접속 서버가 계정을 요구하면 IKE_AUTH 가 한 번 더 오간다 (EAP)
 */
export interface IkeMessage {
  kind: "ike";
  /**
   * INFORMATIONAL: 원격 접속 클라이언트가 연결을 끊을 때 (Delete), DPD (빈 INFORMATIONAL), INVALID_SPI 알림.
   * MAIN_MODE·QUICK_MODE: IKEv1 (L2TP/IPsec) — Main Mode 로 NAT 감지·PSK 인증(실제 6개 메시지를 두 번의 요청·응답으로 줄임),
   * Quick Mode 로 UDP 1701 을 보호할 ESP SA (전송 모드)
   */
  exchange: "IKE_SA_INIT" | "IKE_AUTH" | "INFORMATIONAL" | "MAIN_MODE" | "QUICK_MODE";
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
  /** L2TP/IPsec (IKEv1) 협상 — 공유기 VPN 서버 */
  l2tp?: boolean;
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
  nat: { proto: "icmp" | "tcp" | "udp"; lanIp: Ip; innerId: number; publicId: number; dest?: string }[];
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
  /** 응답의 TTL(초): 캐시가 이만큼만 기억한다. 없으면 캐시 기본값(60초). DDNS 이름은 주소가 바뀌므로 짧다 */
  ttl?: number;
}

export const DNS_PORT = 53;

export type DhcpOp = "discover" | "offer" | "request" | "ack" | "nak" | "release" | "forcerenew";

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

const ESP_LABEL = (e: EspPacket) =>
  `ESP SPI 0x${e.spi.toString(16).padStart(8, "0")} seq=${e.seq} (암호화됨 · ${e.transport ? `전송 모드 · 안: UDP 1701 L2TP${l2tpInnerLabel(e.inner)}` : `안: ${e.inner.src} → ${e.inner.dst}`})`;

/** ESP 전송 모드 안의 L2TP 를 짧게 (로그용) */
function l2tpInnerLabel(inner: Ipv4Packet): string {
  const u = inner.payload;
  return u.kind === "udp" && u.payload.kind === "l2tp" ? l2tpPartLabel(u.payload) : "";
}

/** L2TP 한 개를 짧게: 제어 메시지·PPP 단계, 데이터면 PPP 안의 IP */
export function l2tpPartLabel(l: L2tpPacket): string {
  if (l.control) return ` ${l.control}`;
  const p = l.ppp;
  if (!p) return "";
  if (p.proto === "ip") return ` · PPP · ${p.packet.src} → ${p.packet.dst}`;
  return ` · PPP ${p.proto.toUpperCase()} ${p.code}`;
}
const IKE_LABEL = (m: IkeMessage) =>
  `IKE ${m.exchange} ${m.response ? (m.error ? `응답 (${m.error})` : "응답") : "요청"}${m.ra ? " · 원격 접속" : ""}${m.eap ? ` · EAP ${m.eap === "request" ? "요청" : m.eap === "response" ? "응답" : m.eap === "success" ? "성공" : "실패"}` : ""}${m.dpd ? " · DPD" : ""}`;

const DHCP_LABEL: Record<DhcpOp, string> = { discover: "Discover", offer: "Offer", request: "Request", ack: "Ack", nak: "Nak", release: "Release", forcerenew: "FORCERENEW" };

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
  if (inner.kind === "igmp") return inner.type === "report" ? `IGMP Membership Report (그룹 ${inner.group} 가입)` : inner.type === "query" ? "IGMP General Query (가입한 그룹을 알려 달라)" : `IGMP Leave (그룹 ${inner.group} 탈퇴)`;
  const d = inner.payload;
  if (d.kind === "esp") return `UDP 4500 (NAT-T) · ${ESP_LABEL(d)}`;
  if (d.kind === "ike") return IKE_LABEL(d);
  if (d.kind === "dns") return d.op === "query" ? `DNS 질의 (${d.name}${d.qtype === "AAAA" ? " AAAA" : ""}?)` : `DNS 응답 (${d.name}${d.qtype === "AAAA" ? " AAAA" : ""} = ${d.answer ?? (d.rcode === "NODATA" ? "레코드 없음" : d.rcode)})`;
  if (d.kind === "rip") return d.command === "request" ? "RIP Request (전체 경로 요청)" : `RIP Response (경로 ${d.entries.length}개)`;
  if (d.kind === "vpn") return `VPN 터널 (암호화됨 · 안: ${d.inner.src} → ${d.inner.dst})`;
  if (d.kind === "wg") return wgLabel(d);
  if (d.kind === "ddns") return ddnsLabel(d);
  if (d.kind === "ovpn") return ovpnLabel(d);
  if (d.kind === "ts") return tsLabel(d);
  if (d.kind === "cloud") return cloudLabel(d);
  if (d.kind === "sip") return sipLabel(d);
  if (d.kind === "tor") return d.op === "data" ? `Tor 셀 (암호 ${d.layers}겹 — 안은 아무도 다 보지 못함)` : `Tor 회로 ${d.op === "create" ? "만들기 (CREATE)" : d.op === "created" ? "만들어짐 (CREATED)" : "닫기 (DESTROY)"}`;
  if (d.kind === "rtp") return `RTP 음성 조각 ${d.seq} (${d.from})`;
  if (d.kind === "mcast") return `멀티캐스트 ${d.name} ${d.seq}/${d.total} → 그룹 ${d.group}`;
  if (d.kind === "dhcp6") return dhcp6Label(d);
  if (d.kind === "l2tp") return `L2TP${l2tpPartLabel(d)}`;
  if (d.kind === "stun") return stunLabel(d);
  if (d.kind === "p2p") return p2pLabel(d);
  return `DHCP ${DHCP_LABEL[d.op]}${d.yiaddr ? ` (${d.yiaddr})` : ""}`;
}

const STUN_OP_LABEL: Record<StunMessage["op"], string> = {
  "binding-request": "STUN Binding 요청",
  "binding-response": "STUN Binding 응답",
  "allocate-request": "TURN Allocate 요청",
  "allocate-response": "TURN Allocate 응답",
  send: "TURN Send",
  data: "TURN Data",
};

export function stunLabel(m: StunMessage): string {
  const extra = m.mapped && m.op === "binding-response" ? ` (바깥에서 본 주소 ${m.mapped.ip}:${m.mapped.port})` : m.relayed ? ` (릴레이 주소 ${m.relayed.ip}:${m.relayed.port})` : m.peer ? ` (상대 ${m.peer.ip}:${m.peer.port}${m.data ? ` · 안: ${p2pLabel(m.data)}` : ""})` : "";
  return `${STUN_OP_LABEL[m.op]}${extra}`;
}

const P2P_OP_LABEL: Record<P2pMessage["op"], string> = {
  register: "등록",
  registered: "등록됨",
  unregister: "등록 해제",
  busy: "거절 (busy)",
  offer: "연결 제안 (offer)",
  answer: "연결 응답 (answer)",
  relay: "릴레이 주소 알림",
  punch: "홀 펀칭",
  "punch-ack": "홀 펀칭 확인",
  error: "오류",
};

export function p2pLabel(m: P2pMessage): string {
  const who = m.to ? ` ${m.from} → ${m.to}` : ` ${m.from}`;
  const cands = m.candidates?.length ? ` · 후보 ${m.candidates.map((c) => `${c.type} ${c.ip}:${c.port}`).join(", ")}` : "";
  return `P2P ${P2P_OP_LABEL[m.op]}${who}${cands}${m.error ? ` (${m.error})` : ""}`;
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
  if (inner.kind === "igmp") return inner.type === "report" ? "IGMP 가입" : inner.type === "query" ? "IGMP 쿼리" : "IGMP 탈퇴";
  if (inner.kind === "esp" || inner.payload.kind === "esp") return "ESP 터널";
  if (inner.payload.kind === "ike") {
    const m = inner.payload;
    if (m.exchange === "MAIN_MODE") return m.auth !== undefined || m.response && m.error ? "IKE 인증 (Main Mode)" : "IKE 협상 (Main Mode)";
    if (m.exchange === "QUICK_MODE") return "IKE Quick Mode";
    return m.dpd ? "DPD" : m.eap ? "EAP 인증" : m.exchange === "IKE_SA_INIT" ? "IKE 협상" : m.exchange === "IKE_AUTH" ? "IKE 인증" : "IKE 알림";
  }
  if (inner.payload.kind === "dns") return inner.payload.op === "query" ? "DNS 질의" : "DNS 응답";
  if (inner.payload.kind === "rip") return inner.payload.command === "request" ? "RIP 요청" : "RIP 광고";
  if (inner.payload.kind === "vpn") return "VPN 터널";
  if (inner.payload.kind === "ts") return inner.payload.net === "zerotier" ? "ZeroTier" : "Tailscale";
  if (inner.payload.kind === "cloud") return "GoodCloud";
  if (inner.payload.kind === "mcast") return "멀티캐스트";
  if (inner.payload.kind === "sip") return inner.payload.status ? `SIP ${inner.payload.status}` : `SIP ${inner.payload.method}`;
  if (inner.payload.kind === "rtp") return "RTP";
  if (inner.payload.kind === "tor") return "Tor";
  if (inner.payload.kind === "ovpn") return inner.payload.op === "data" ? "OpenVPN" : "OpenVPN 제어";
  if (inner.payload.kind === "ddns") return inner.payload.op === "update" ? "DDNS 갱신" : inner.payload.op === "release" ? "DDNS 내려놓기" : "DDNS 응답";
  if (inner.payload.kind === "wg") return inner.payload.obf || inner.payload.type === "junk" ? "UDP" : inner.payload.type === "data" ? (inner.payload.inner ? "WireGuard" : "keepalive") : "WG 핸드셰이크";
  if (inner.payload.kind === "dhcp6") return `DHCPv6 ${DHCP6_LABEL[inner.payload.type]}`;
  if (inner.payload.kind === "l2tp") return "L2TP";
  if (inner.payload.kind === "stun") return inner.payload.op.startsWith("binding") ? "STUN" : "TURN";
  if (inner.payload.kind === "p2p") return inner.payload.op === "punch" || inner.payload.op === "punch-ack" ? "홀 펀칭" : "시그널링";
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
  return k === "dns" || k === "ddns" ? "dns" : k === "rip" ? "rip" : k === "vpn" || k === "esp" || k === "ike" || k === "wg" || k === "ovpn" || k === "ts" ? "vpn" : "dhcp";
}
