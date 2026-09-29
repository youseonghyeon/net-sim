// 패킷 상세 보기: tcpdump 표기·계층별 헤더·실무 명령 출력이 실제 도구의 모양과 같은지
import { describe, expect, it } from "vitest";
import type { EthernetFrame } from "../src/core/packet";
import type { TraceEvent } from "../src/core/trace";
import { NetworkSync } from "../src/model/netSync";
import { EXAMPLES, exampleRemoteVpnTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";
import { headerLayers, practitionerLines, tcpdumpLine } from "../src/model/packetView";
import { loadTopology } from "./helpers";

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

describe("strongSwan (원격 접속 계정 인증·DPD)", () => {
  const LAPTOP = "재택 노트북";
  const FW = "회사 VPN 방화벽";
  type Loaded = ReturnType<typeof loadTopology>;
  /** 그 장치가 받은/보낸 프레임과 함께 strongSwan 줄만 */
  const swan = (x: Loaded, e: TraceEvent) => practitionerLines(e, e.packetId !== undefined ? x.s.net.framesAt(e.packetId, e.nodeId, e.time) : {}).filter((l) => l.tool.startsWith("strongSwan")).map((l) => l.line);
  const patch = (laptop: object = {}, server: object = {}): Topology => {
    const t = exampleRemoteVpnTopology();
    return { ...t, devices: t.devices.map((d) => (d.name === LAPTOP ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, ...laptop } } } : d.l3?.ra ? { ...d, l3: { ...d.l3, ra: { ...d.l3.ra, ...server } } } : d)) };
  };
  const serverFail = (x: Loaded) => x.s.net.trace.find((e) => e.kind === "vpn.drop" && e.nodeId === x.id(FW) && e.details?.eap === "failure")!;

  it("비밀번호가 틀림: EAP-MS-CHAPv2 verification failed, retry (n) 뒤 failed for peer <IKE ID = 사용자 이름>", () => {
    const x = loadTopology(patch({ password: "wrong" }));
    expect(swan(x, serverFail(x))).toEqual(["12[IKE] EAP-MS-CHAPv2 verification failed, retry (1)", "12[IKE] EAP method EAP_MSCHAPV2 failed for peer kim"]);
  });

  it("목록에 없는 사용자: no EAP key found for hosts '<서버 ID>' - '<사용자>'", () => {
    const x = loadTopology(patch({ user: "park", password: "park-pass" }));
    expect(swan(x, serverFail(x))).toEqual(["12[IKE] no EAP key found for hosts '203.0.113.11' - 'park'", "12[IKE] EAP method EAP_MSCHAPV2 failed for peer park"]);
  });

  it("DPD 의 Message ID: EAP 로 붙으면 IKE_AUTH 가 두 번(1·2)이라 3, PSK 만이면 2", () => {
    for (const [t, mid] of [[patch(), 3], [patch({}, { users: [] }), 2]] as const) {
      const x = loadTopology(t);
      const tr = x.act({ kind: "vpn-dpd", nodeId: x.id(LAPTOP) }).filter((e) => e.kind === "vpn.dpd");
      expect(tr.map((e) => swan(x, e))).toEqual([
        ["15[IKE] sending DPD request", `15[ENC] generating INFORMATIONAL request ${mid} [ ]`],
        [`16[ENC] parsed INFORMATIONAL request ${mid} [ ]`, `16[ENC] generating INFORMATIONAL response ${mid} [ ]`],
        [`16[ENC] parsed INFORMATIONAL response ${mid} [ ]`],
      ]);
    }
  });

  it("재전송: EAP 응답(두 번째 IKE_AUTH)은 message ID 2, 서버가 지난 응답을 다시 보낼 때는 그 요청의 ID", () => {
    const run = (t: Topology, dropAt: (x: Loaded, e: TraceEvent) => boolean) => {
      const x = loadTopology(t);
      const home = x.t.devices.find((d) => d.name === "집 공유기")!.id;
      const isp = x.t.devices.find((d) => d.name === "통신사 구간")!.id;
      const wan = x.t.cables.find((c) => [c.a.device, c.b.device].includes(home) && [c.a.device, c.b.device].includes(isp))!;
      const from = x.s.net.trace.length;
      x.s.net.scheduleAction(x.s.net.now, { kind: "ra-reconnect", nodeId: x.id(LAPTOP) });
      while (!x.s.net.trace.slice(from).some((e) => dropAt(x, e))) x.s.net.step();
      x.s.net.dropNextOn(wan.id);
      x.s.net.runToIdle();
      return { x, tr: x.s.net.trace.slice(from) };
    };
    // 노트북의 EAP 응답이 사라짐 → 노트북 재전송
    const a = run(patch(), (x, e) => e.kind === "vpn.eap" && e.nodeId === x.id(LAPTOP));
    expect(swan(a.x, a.tr.find((e) => e.nodeId === a.x.id(LAPTOP) && e.details?.retransmit !== undefined)!)).toEqual(["11[IKE] retransmit 1 of request with message ID 2"]);
    // 서버의 마지막 응답이 사라짐 → 서버가 같은 응답을 다시
    for (const [t, id] of [[patch(), 2], [patch({}, { users: [] }), 1]] as const) {
      const b = run(t, (x, e) => e.kind === "vpn.up" && e.nodeId === x.id(FW));
      expect(swan(b.x, b.tr.find((e) => e.nodeId === b.x.id(FW) && e.details?.resent === true)!)).toEqual([`13[IKE] received retransmit of request with ID ${id}, retransmitting response`]);
    }
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

describe("STP BPDU", () => {
  it("tcpdump 는 802.3 + LLC, 헤더는 루트·비용·보낸 브리지", () => {
    const f: EthernetFrame = { kind: "ethernet", id: 1, src: A, dst: "01:80:c2:00:00:00", payload: { kind: "bpdu", root: { prio: 4096, mac: "02:00:00:00:00:01" }, cost: 4, bridge: { prio: 8192, mac: "02:00:00:00:00:02" }, port: 2, age: 1 } };
    expect(tcpdumpLine(f)).toContain("802.3, length 60: LLC, dsap STP (0x42) Individual, ssap STP (0x42) Command, ctrl 0x03: STP 802.1d, Config, Flags [none], bridge-id 2000.02:00:00:00:00:02.8003");
    const layers = headerLayers(f);
    expect(layers.map((l) => l.title)).toEqual(["이더넷 (L2)", "STP BPDU (Configuration)"]);
    expect(layers[1]!.rows[0]![1]).toContain("4096.02:00:00:00:00:01");
  });
});

describe("프록시·쿠키", () => {
  it("curl -v 의 프록시 줄, Squid access.log, 요청 줄의 절대 URI·Cookie 헤더", async () => {
    const { exampleProxyTopology } = await import("../src/model/examples");
    const { loadTopology } = await import("./helpers");
    const { s, id, act } = loadTopology(exampleProxyTopology());
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "example.com", port: 80 });
    const use = tr.find((e) => e.kind === "proxy.use")!;
    expect(practitionerLines(use, {}).map((l) => l.line)).toEqual(["* Uses proxy env variable http_proxy == 'http://192.168.0.10:3128'", "> GET http://example.com/ HTTP/1.1"]);
    const relay = tr.find((e) => e.kind === "proxy.relay")!;
    expect(practitionerLines(relay, {}).find((l) => l.tool === "Squid access.log")!.line).toMatch(/^\d+\.\d{3} +0 192\.168\.0\.1\d\d TCP_MISS\/200 3000 GET http:\/\/example\.com\/ - HIER_DIRECT\/93\.184\.216\.34 text\/html$/);
    const deny = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "naver.com", port: 80 }).find((e) => e.kind === "proxy.deny")!;
    expect(practitionerLines(deny, {}).find((l) => l.tool === "Squid access.log")!.line).toContain("TCP_DENIED/403 200 GET http://naver.com/ - HIER_NONE/-");
    void s;
  });

  it("프록시에게 보낸 요청: tcpdump 는 절대 URI, 헤더는 요청 대상·Cookie, 응답은 Set-Cookie", () => {
    const req = ip({ kind: "tcp", srcPort: 49152, dstPort: 3128, seq: 1001, ack: 3001, ackFlag: true, len: 100, data: "GET http://example.com/", target: "example.com:80", cookie: "SERVERID=192.168.0.11:80" }, "192.168.0.101", "192.168.0.10", 64);
    expect(tcpdumpLine(req)).toContain("IP 192.168.0.101.49152 > 192.168.0.10.3128: Flags [P.]");
    expect(tcpdumpLine(req)).toContain("HTTP: GET http://example.com/ HTTP/1.1");
    const rows = headerLayers(req).at(-1)!.rows;
    expect(rows.find((r) => r[0] === "목적지 포트")![1]).toBe("3128 (HTTP 프록시)");
    expect(rows.find((r) => r[0] === "요청 대상 (절대 URI)")![1]).toContain("http://example.com/");
    expect(rows.find((r) => r[0] === "Cookie")![1]).toBe("SERVERID=192.168.0.11:80");
    const res = ip({ kind: "tcp", srcPort: 80, dstPort: 49152, seq: 3001, ack: 1101, ackFlag: true, len: 1000, data: "HTTP 200 (1/3)", setCookie: "SERVERID=192.168.0.11:80" }, "192.168.0.20", "192.168.0.101", 64);
    expect(headerLayers(res).at(-1)!.rows.find((r) => r[0] === "Set-Cookie")![1]).toContain("SERVERID=192.168.0.11:80; path=/");
  });
});
