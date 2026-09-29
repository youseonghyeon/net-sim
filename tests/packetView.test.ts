// 패킷 상세 보기: tcpdump 표기·계층별 헤더·실무 명령 출력이 실제 도구의 모양과 같은지
import { describe, expect, it } from "vitest";
import type { EthernetFrame } from "../src/core/packet";
import { NetworkSync } from "../src/model/netSync";
import { EXAMPLES } from "../src/model/examples";
import { headerLayers, practitionerLines, tcpdumpLine } from "../src/model/packetView";

const A = "02:00:00:00:00:01";
const B = "02:00:00:00:00:02";
const ip = (payload: any, src = "192.168.0.100", dst = "8.8.8.8", ttl = 64): EthernetFrame => ({ kind: "ethernet", id: 1, src: A, dst: B, payload: { kind: "ipv4", src, dst, ttl, payload } });

describe("tcpdump 한 줄", () => {
  it("ARP 요청·응답", () => {
    const req: EthernetFrame = { kind: "ethernet", id: 1, src: A, dst: "ff:ff:ff:ff:ff:ff", payload: { kind: "arp", op: "request", senderMac: A, senderIp: "192.168.0.100", targetMac: "00:00:00:00:00:00", targetIp: "192.168.0.1" } };
    expect(tcpdumpLine(req)).toBe(`${A} > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806): ARP, Request who-has 192.168.0.1 tell 192.168.0.100, length 28`);
  });
  it("ICMP echo, TCP SYN/데이터, DNS 질의·응답, DHCP, Unreachable, VLAN 태그", () => {
    expect(tcpdumpLine(ip({ kind: "icmp", type: "echo-request", id: 4660, seq: 1 }))).toContain("IP 192.168.0.100 > 8.8.8.8: ICMP echo request, id 4660, seq 1, length 64");
    expect(tcpdumpLine(ip({ kind: "tcp", srcPort: 49152, dstPort: 80, seq: 1000, ack: 0, syn: true, len: 0 }))).toContain("IP 192.168.0.100.49152 > 8.8.8.8.80: Flags [S], seq 1000, length 0");
    expect(tcpdumpLine(ip({ kind: "tcp", srcPort: 49152, dstPort: 80, seq: 1001, ack: 3001, ackFlag: true, len: 100, data: "GET /" }))).toContain("Flags [P.], seq 1001:1101, ack 3001, length 100: HTTP: GET / HTTP/1.1");
    expect(tcpdumpLine(ip({ kind: "udp", srcPort: 53001, dstPort: 53, payload: { kind: "dns", id: 7, op: "query", name: "google.com" } }))).toContain("IP 192.168.0.100.53001 > 8.8.8.8.53: 7+ A? google.com.");
    expect(tcpdumpLine(ip({ kind: "udp", srcPort: 53, dstPort: 53001, payload: { kind: "dns", id: 7, op: "response", name: "google.com", answer: "142.250.196.110" } }))).toContain("7 1/0/0 A 142.250.196.110");
    expect(tcpdumpLine(ip({ kind: "udp", srcPort: 68, dstPort: 67, payload: { kind: "dhcp", op: "discover", xid: 1, clientMac: A } }, "0.0.0.0", "255.255.255.255"))).toContain(`BOOTP/DHCP, Request from ${A}`);
    expect(tcpdumpLine(ip({ kind: "icmp", type: "unreachable", code: "net", original: { src: "192.168.1.10", dst: "192.168.2.10", l4: { kind: "icmp", id: 1, seq: 1 } } }, "192.168.1.1", "192.168.1.10"))).toContain("ICMP net 192.168.2.10 unreachable");
    expect(tcpdumpLine({ ...ip({ kind: "icmp", type: "echo-request", id: 1, seq: 1 }), vlan: 10 })).toContain("802.1Q vlan 10");
  });
});

describe("계층별 헤더", () => {
  it("DHCP Offer 는 옵션 번호와 함께", () => {
    const layers = headerLayers(ip({ kind: "udp", srcPort: 67, dstPort: 68, payload: { kind: "dhcp", op: "offer", xid: 255, clientMac: A, yiaddr: "192.168.0.100", serverId: "192.168.0.1", options: { prefix: 24, router: "192.168.0.1", dns: "192.168.0.1", leaseTime: 86400 } } }, "192.168.0.1", "192.168.0.100"));
    expect(layers.map((l) => l.title)).toEqual(["이더넷 (L2)", "IPv4 (L3)", "UDP (L4)", "DHCP (앱)"]);
    const dhcp = Object.fromEntries(layers[3]!.rows);
    expect(dhcp["옵션 53 메시지 종류"]).toBe("2 (Offer)");
    expect(dhcp["옵션 3 기본 게이트웨이"]).toBe("192.168.0.1");
    expect(Object.fromEntries(layers[1]!.rows)["프로토콜"]).toBe("17 (UDP)");
  });
  it("ICMP 오류는 타입/코드 번호와 안에 담긴 원래 패킷", () => {
    const layers = headerLayers(ip({ kind: "icmp", type: "unreachable", code: "host", original: { src: "192.168.1.10", dst: "192.168.2.99", l4: { kind: "icmp", id: 1, seq: 3 } } }));
    const icmp = Object.fromEntries(layers[2]!.rows);
    expect(icmp["타입 / 코드"]).toContain("3 / 1");
    expect(icmp["안에 담긴 원래 패킷"]).toContain("192.168.2.99");
  });
});

describe("실무 명령 출력 (시뮬레이션 로그에서)", () => {
  it("공유기 예제에서 ping google.com: NAT 변환은 시스코 debug ip nat 형식, 받은/내보낸 프레임이 다르면 둘 다 tcpdump", () => {
    const t = EXAMPLES.router.build();
    const s = new NetworkSync();
    s.sync(t);
    s.net.runToIdle();
    const pc = t.devices.find((d) => d.name === "pc-1")!.id;
    // 첫 ping 은 공유기가 ISP 게이트웨이 ARP 를 기다렸다 나중에 보내 "받고 내보낸" 연결이 없다 → ARP 가 준비된 두 번째로 본다
    s.net.scheduleAction(s.net.now, { kind: "ping", nodeId: pc, dst: "8.8.8.8" });
    s.net.runToIdle();
    const from = s.net.trace.length;
    s.net.scheduleAction(s.net.now, { kind: "ping", nodeId: pc, dst: "8.8.8.8" });
    s.net.runToIdle();
    const nat = s.net.trace.slice(from).find((e) => e.kind === "nat.translate" && e.packetId !== undefined)!;
    const frames = s.net.framesAt(nat.packetId!, nat.nodeId, nat.time);
    expect(frames.received).toBeDefined();
    expect(frames.sent).toBeDefined();
    const lines = practitionerLines(nat, frames);
    const debug = lines.find((l) => l.tool.includes("debug ip nat"))!;
    expect(debug.line).toMatch(/^NAT: s=192\.168\.0\.1\d\d->203\.0\.113\.\d+, d=8\.8\.8\.8 \[\d+\]$/);
    expect(lines.filter((l) => l.tool.startsWith("tcpdump")).length).toBe(2);
    expect(lines.find((l) => l.tool.includes("conntrack"))!.line).toMatch(/^\[NEW\] icmp +1 30 src=192\.168\.0\.1\d\d dst=8\.8\.8\.8 type=8 code=0 id=\d+ \[UNREPLIED\] src=8\.8\.8\.8 dst=203\.0\.113\.\d+ type=0 code=0 id=\d+$/);
    const reply = s.net.trace.slice(from).find((e) => e.kind === "icmp.reply.received")!;
    const ping = practitionerLines(reply, s.net.framesAt(reply.packetId!, reply.nodeId, reply.time)).find((l) => l.tool === "ping")!;
    expect(ping.line).toMatch(/^64 bytes from 8\.8\.8\.8: icmp_seq=\d+ ttl=\d+ time=\d+ ms$/);
  });
});

describe("IPsec", () => {
  const inner = { kind: "ipv4", src: "192.168.1.10", dst: "192.168.2.10", ttl: 63, payload: { kind: "icmp", type: "echo-request", id: 1, seq: 1 } };
  it("tcpdump: ESP 는 포트 없이 spi·seq, NAT-T 는 UDP-encap, IKE 는 isakmp", () => {
    expect(tcpdumpLine(ip({ kind: "esp", spi: 0xabcd, seq: 1, inner }, "203.0.113.11", "203.0.113.22"))).toMatch(/IP 203\.0\.113\.11 > 203\.0\.113\.22: ESP\(spi=0x0000abcd,seq=0x1\), length \d+$/);
    expect(tcpdumpLine(ip({ kind: "udp", srcPort: 4500, dstPort: 4500, payload: { kind: "esp", spi: 1, seq: 2, inner } }, "203.0.113.11", "203.0.113.22"))).toContain("203.0.113.11.4500 > 203.0.113.22.4500: UDP-encap: ESP(spi=0x00000001,seq=0x2)");
    expect(tcpdumpLine(ip({ kind: "udp", srcPort: 500, dstPort: 500, payload: { kind: "ike", exchange: "IKE_SA_INIT", response: false, spi: 1 } }, "203.0.113.11", "203.0.113.22"))).toContain("isakmp: parent_sa ikev2_init[I]");
    expect(tcpdumpLine(ip({ kind: "udp", srcPort: 4500, dstPort: 4500, payload: { kind: "ike", exchange: "IKE_AUTH", response: true, spi: 1 } }, "203.0.113.22", "203.0.113.11"))).toContain("NONESP-encap: isakmp: child_sa  ikev2_auth[R]");
  });
  it("헤더: ESP 는 프로토콜 50, 그 아래 터널 안 원래 패킷", () => {
    const titles = headerLayers(ip({ kind: "esp", spi: 1, seq: 1, inner }, "203.0.113.11", "203.0.113.22"));
    expect(titles.map((l) => l.title)).toEqual(["이더넷 (L2)", "IPv4 (L3)", "ESP (IPsec)", "터널 안 · IPv4 (L3)", "터널 안 · ICMP"]);
    expect(titles[1]!.rows.find((r) => r[0] === "프로토콜")![1]).toContain("50 (ESP");
  });
});

describe("VRRP", () => {
  it("tcpdump 와 헤더: 프로토콜 112, 그룹·우선순위·가상 주소", () => {
    const f = ip({ kind: "vrrp", vrid: 10, priority: 200, vip: "192.168.0.1" }, "192.168.0.2", "224.0.0.18", 255);
    expect(tcpdumpLine(f)).toContain("IP 192.168.0.2 > 224.0.0.18: VRRPv3, Advertisement, vrid 10, prio 200, intvl 100cs, length 12");
    const layers = headerLayers(f);
    expect(layers.map((l) => l.title)).toEqual(["이더넷 (L2)", "IPv4 (L3)", "VRRP"]);
    expect(layers[2]!.rows.find((r) => r[0].startsWith("가상 라우터"))![1]).toContain("00:00:5e:00:01:0a");
  });
});
