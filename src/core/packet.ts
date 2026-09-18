// 계층별 패킷 모델. 실제 바이트가 아니라 "학습에 필요한 필드"만 담는다.
import type { Ip, Mac } from "./addr";

export interface EthernetFrame {
  kind: "ethernet";
  id: number; // 추적용 ID (같은 패킷이 여러 링크를 지나도 유지)
  src: Mac;
  dst: Mac;
  payload: ArpPacket | Ipv4Packet;
}

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
  payload: IcmpPacket | UdpPacket;
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
  payload: DhcpMessage;
}

export type DhcpOp = "discover" | "offer" | "request" | "ack" | "nak";

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
  options?: { prefix?: number; router?: Ip; leaseTime?: number };
}

export const DHCP_SERVER_PORT = 67;
export const DHCP_CLIENT_PORT = 68;
export const UNSPECIFIED_IP: Ip = "0.0.0.0";
export const LIMITED_BROADCAST_IP: Ip = "255.255.255.255";

export type Layer = "L1" | "L2" | "L3" | "L4" | "app" | "sys";

export type FrameCategory = "arp" | "icmp" | "dhcp";

const DHCP_LABEL: Record<DhcpOp, string> = { discover: "Discover", offer: "Offer", request: "Request", ack: "Ack", nak: "Nak" };

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
  const d = inner.payload;
  return `DHCP ${DHCP_LABEL[d.op]}${d.yiaddr ? ` (${d.yiaddr})` : ""}`;
}

/** 캔버스 위 패킷에 붙는 짧은 라벨 */
export function shortLabel(frame: EthernetFrame): string {
  const p = frame.payload;
  if (p.kind === "arp") return p.op === "request" ? "ARP 요청" : "ARP 응답";
  const inner = p.payload;
  if (inner.kind === "icmp") return inner.type === "echo-request" ? "ping 요청" : "ping 응답";
  return `DHCP ${DHCP_LABEL[inner.payload.op]}`;
}

/** 패킷 종류 태그 (UI 색상 구분용) */
export function frameCategory(frame: EthernetFrame): FrameCategory {
  const p = frame.payload;
  if (p.kind === "arp") return "arp";
  return p.payload.kind === "icmp" ? "icmp" : "dhcp";
}
