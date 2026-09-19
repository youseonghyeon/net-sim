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
  payload: IcmpPacket | UdpPacket | TcpSegment;
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
}

export interface IcmpPacket {
  kind: "icmp";
  type: "echo-request" | "echo-reply";
  id: number;
  seq: number;
}

export interface UdpPacket {
  kind: "udp";
  srcPort: number;
  dstPort: number;
  payload: DhcpMessage | DnsMessage;
}

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

export type FrameCategory = "arp" | "icmp" | "dhcp" | "tcp" | "dns";

const DHCP_LABEL: Record<DhcpOp, string> = { discover: "Discover", offer: "Offer", request: "Request", ack: "Ack", nak: "Nak", release: "Release" };

/** UI 라벨/로그용 짧은 설명 */
export function describeFrame(frame: EthernetFrame): string {
  const p = frame.payload;
  if (p.kind === "arp") {
    return p.op === "request" ? `ARP 요청 (${p.targetIp}?)` : `ARP 응답 (${p.senderIp}=${p.senderMac})`;
  }
  const inner = p.payload;
  if (inner.kind === "icmp") {
    return inner.type === "echo-request" ? `ICMP Echo 요청 seq=${inner.seq}` : `ICMP Echo 응답 seq=${inner.seq}`;
  }
  if (inner.kind === "tcp") return `TCP ${tcpFlags(inner)} seq=${inner.seq} ack=${inner.ack}${inner.len ? ` len=${inner.len}` : ""}`;
  const d = inner.payload;
  if (d.kind === "dns") return d.op === "query" ? `DNS 질의 (${d.name}?)` : `DNS 응답 (${d.name} = ${d.answer ?? d.rcode})`;
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
  if (inner.kind === "icmp") return inner.type === "echo-request" ? "ping 요청" : "ping 응답";
  if (inner.kind === "tcp") return inner.len > 0 ? `${inner.data ?? "DATA"} ${inner.len}B` : tcpFlags(inner);
  if (inner.payload.kind === "dns") return inner.payload.op === "query" ? "DNS 질의" : "DNS 응답";
  return `DHCP ${DHCP_LABEL[inner.payload.op]}`;
}

/** 패킷 종류 태그 (UI 색상 구분용) */
export function frameCategory(frame: EthernetFrame): FrameCategory {
  const p = frame.payload;
  if (p.kind === "arp") return "arp";
  if (p.payload.kind === "icmp") return "icmp";
  if (p.payload.kind === "tcp") return "tcp";
  return p.payload.payload.kind === "dns" ? "dns" : "dhcp";
}
