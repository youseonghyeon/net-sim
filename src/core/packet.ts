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
  payload: IcmpPacket;
}

export interface IcmpPacket {
  kind: "icmp";
  type: "echo-request" | "echo-reply";
  id: number;
  seq: number;
}

export type Layer = "L1" | "L2" | "L3" | "L4" | "app" | "sys";

/** UI 라벨/로그용 짧은 설명 */
export function describeFrame(frame: EthernetFrame): string {
  const p = frame.payload;
  if (p.kind === "arp") {
    return p.op === "request" ? `ARP 요청 (${p.targetIp}?)` : `ARP 응답 (${p.senderIp}=${p.senderMac})`;
  }
  const icmp = p.payload;
  return icmp.type === "echo-request" ? `ICMP Echo 요청 seq=${icmp.seq}` : `ICMP Echo 응답 seq=${icmp.seq}`;
}

/** 패킷 종류 태그 (UI 색상 구분용) */
export function frameCategory(frame: EthernetFrame): "arp" | "icmp" {
  return frame.payload.kind === "arp" ? "arp" : "icmp";
}
