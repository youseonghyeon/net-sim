// 패킷 색 분류: UDP 안의 종류마다 표로 (빠지면 컴파일 오류). 전에는 if 사슬의 기본값으로 Tor·SIP·STUN·L2TP 가 DHCP 색이었다
import { describe, expect, it } from "vitest";
import { frameCategory, type EthernetFrame, type UdpPacket } from "../src/core/packet";

const udp = (payload: UdpPacket["payload"]): EthernetFrame => ({ kind: "ethernet", id: 1, src: "02:00:00:00:00:01", dst: "02:00:00:00:00:02", payload: { kind: "ipv4", src: "10.0.0.1", dst: "10.0.0.2", ttl: 64, payload: { kind: "udp", srcPort: 1, dstPort: 2, payload } } });

describe("패킷 색 분류", () => {
  it("앱 트래픽(SIP·RTP·STUN·P2P·GoodCloud·멀티캐스트)은 DHCP 색이 아니라 앱 색", () => {
    expect(frameCategory(udp({ kind: "sip", method: "INVITE", callId: "c", from: "a", to: "b" } as UdpPacket["payload"]))).toBe("app");
    expect(frameCategory(udp({ kind: "rtp", callId: "c", seq: 1 } as UdpPacket["payload"]))).toBe("app");
    expect(frameCategory(udp({ kind: "stun", op: "binding-request", txid: 1 } as UdpPacket["payload"]))).toBe("app");
    expect(frameCategory(udp({ kind: "mcast", group: "239.1.1.1", seq: 1 } as UdpPacket["payload"]))).toBe("app");
  });
  it("터널(L2TP·Tor·WireGuard·IKE)은 VPN 색, DHCP 는 DHCP 색", () => {
    expect(frameCategory(udp({ kind: "l2tp" } as UdpPacket["payload"]))).toBe("vpn");
    expect(frameCategory(udp({ kind: "tor", op: "create", circ: 1, layers: 0 } as UdpPacket["payload"]))).toBe("vpn");
    expect(frameCategory(udp({ kind: "wg", type: "initiation" } as UdpPacket["payload"]))).toBe("vpn");
    expect(frameCategory(udp({ kind: "dhcp", op: "discover", xid: 1, clientMac: "02:00:00:00:00:01" }))).toBe("dhcp");
  });
});
