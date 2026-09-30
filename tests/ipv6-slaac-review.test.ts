// IPv6 2단계(SLAAC) 리뷰(clean context)가 찾은 결함의 회귀 테스트와 확인한 정상 동작.
import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { Host } from "../src/core/nodes/host";
import { L3Node, type L3Ipv6Config } from "../src/core/nodes/l3";
import { Switch } from "../src/core/nodes/switch";
import { FirewallBridge } from "../src/core/nodes/fwbridge";
import { exampleSlaacTopology, exampleTwoGatewaysTopology } from "../src/model/examples";
import { builder, cable } from "../src/model/examples/build";
import { DEFAULT_DHCP_SERVER, DEFAULT_IPV6_HOST, type Topology } from "../src/model/topology";
import { lintTopology } from "../src/model/lint";
import { practitionerLines } from "../src/model/packetView";
import { hostStatusOf, ipv6StatusOf } from "../src/model/status";
import { loadTopology } from "./helpers";

const PC = "02:00:00:00:00:0a";
const PC2 = "02:00:00:00:00:0c";
const SRV = "02:00:00:00:00:0b";
const PC_SLAAC = "2001:db8:1::ff:fe00:a";
const GW_IF1_LL = "fe80::ff:fe11:1";

function gwNode(id: string, macByte: string, if1: { ip?: string; prefix?: number; ra?: boolean }, raDns?: string) {
  return new L3Node({
    id,
    kind: "gateway",
    interfaces: [
      { name: "if0", mac: `02:00:00:10:00:${macByte}`, mode: "static" },
      { name: "if1", mac: `02:00:00:11:00:${macByte}`, mode: "static" },
      { name: "if2", mac: `02:00:00:12:00:${macByte}`, mode: "static" },
    ],
    ipv6: { enabled: true, interfaces: [{}, { ip: if1.ip ?? "2001:db8:1::1", prefix: if1.prefix ?? 64, ra: if1.ra ?? true }, { ip: "2001:db8:2::1", prefix: 64 }], routes: [], raDns },
  });
}
const gwCfg = (p: { ip?: string; prefix?: number; ra?: boolean; enabled?: boolean; raDns?: string } = {}): L3Ipv6Config => ({
  enabled: p.enabled ?? true,
  interfaces: [{}, { ip: p.ip ?? "2001:db8:1::1", prefix: p.prefix ?? 64, ra: p.ra ?? true }, { ip: "2001:db8:2::1", prefix: 64 }],
  routes: [],
  ...(p.raDns ? { raDns: p.raDns } : {}),
});

/** pc(SLAAC) ─ sw1 ─ gw(if1 RA) ─ sw2 ─ srv(수동, 22·80) */
function slaacNet(opts: { ra?: boolean; prefix?: number; raDns?: string } = {}) {
  const net = new Network();
  net.addNode(new Switch("sw1", 4));
  net.addNode(new Switch("sw2", 4));
  net.addNode(gwNode("gw", "01", { ra: opts.ra, prefix: opts.prefix }, opts.raDns));
  net.addNode(new Host({ id: "pc", mac: PC, ipMode: "static", ipv6: { enabled: true, addrs: [], slaac: true } }));
  net.addNode(new Host({ id: "srv", mac: SRV, ipMode: "static", services: [22, 80], ipv6: { enabled: true, addrs: [{ ip: "2001:db8:2::10", prefix: 64 }], gateway: "2001:db8:2::1" } }));
  net.connect("pc", 0, "sw1", 0);
  net.connect("gw", 1, "sw1", 1);
  net.connect("gw", 2, "sw2", 1);
  net.connect("srv", 0, "sw2", 0);
  net.runToIdle();
  return net;
}

function act(net: Network, action: Parameters<Network["scheduleAction"]>[1]) {
  const from = net.trace.length;
  net.scheduleAction(net.now, action);
  net.runToIdle();
  return net.trace.slice(from);
}

function since<T>(net: Network, f: () => T) {
  const from = net.trace.length;
  f();
  net.runToIdle();
  return net.trace.slice(from);
}

describe("고친 결함 1 IPv6 를 껐다 켜면 RS 횟수가 이어진다 (rsTries 초기화 안 됨)", () => {
  it("RS 3번 timeout 뒤 IPv6 끔 → 켬: RS 가 (1/3) 부터 3번 나가야 한다", () => {
    const net = slaacNet({ ra: false });
    const pc = net.getHost("pc");
    pc.setIpv6({ enabled: false, addrs: [] }, net.contextFor("pc"));
    net.runToIdle();
    const t = since(net, () => pc.setIpv6({ enabled: true, addrs: [], slaac: true }, net.contextFor("pc")));
    const rs = t.filter((e) => e.nodeId === "pc" && e.kind === "ndp.rs.sent").map((e) => e.summary);
    // 관찰: ["... (4/3)"] 한 번만 보내고 곧바로 slaac.timeout
    expect(rs[0]).toContain("(1/3)");
    expect(rs).toHaveLength(3);
  });
});

describe("고친 결함 2 RA 로 SLAAC 주소가 사라져도 그 주소의 TCP 연결이 남는다", () => {
  function sshUp() {
    const net = slaacNet();
    const pc = net.getHost("pc");
    act(net, { kind: "tcp-connect", nodeId: "pc", dst: "2001:db8:2::10", port: 22 });
    const conn = [...pc.tcp.conns.values()].at(-1)!;
    expect(conn.localIp).toBe(PC_SLAAC);
    expect(conn.state).toBe("ESTABLISHED");
    return { net, pc, conn };
  }
  it("RA 광고를 끄면(거둠 RA) 주소가 지워지는데 SSH 세션은 ESTABLISHED 그대로", () => {
    const { net, pc, conn } = sshUp();
    (net.nodes.get("gw") as L3Node).setIpv6(gwCfg({ ra: false }), net.contextFor("gw"));
    net.runToIdle();
    expect(pc.v6.globals).toEqual([]);
    // 기대: 수동 설정 변경(setIpv6)·IPv4 주소 변경처럼 "주소 변경" 으로 정리. 관찰: ESTABLISHED
    expect(conn.state).not.toBe("ESTABLISHED");
  });
  it("라우터 프리픽스를 바꾸면(주소 교체) 옛 주소로 묶인 세션이 남아, 해제하면 없는 주소로 FIN 을 보낸다", () => {
    const { net, pc, conn } = sshUp();
    const id = [...pc.tcp.conns.entries()].find(([, c]) => c === conn)![0];
    (net.nodes.get("gw") as L3Node).setIpv6(gwCfg({ ip: "2001:db8:9::1" }), net.contextFor("gw"));
    net.runToIdle();
    expect(pc.v6.globals.map((a) => a.ip)).toEqual(["2001:db8:9::ff:fe00:a"]);
    const stateAfterRenumber = conn.state;
    const logFrom = net.now;
    act(net, { kind: "tcp-close", nodeId: "pc", conn: id });
    // pc 가 보낸 IPv6 패킷 중 출발지가 이제 없는 옛 SLAAC 주소인 것 (FIN 과 재전송)
    const ghost = [...net.frameLog.values()]
      .flat()
      .filter((x) => x.from === "pc" && x.departAt >= logFrom && x.frame.payload.kind === "ipv6" && x.frame.payload.src === PC_SLAAC).length;
    // 관찰: { stateAfterRenumber: "ESTABLISHED", ghost: 5 } — 게이트웨이는 돌아오는 ACK 를 "No route" 로 드롭
    expect({ stateAfterRenumber, ghost }).toEqual({ stateAfterRenumber: expect.not.stringMatching(/ESTABLISHED/), ghost: 0 });
  });
});

describe("고친 결함 3 거둠 RA·RDNSS 삭제 뒤에도 RA 로 배운 DNS 가 남는다", () => {
  it("RA 광고를 끄면 게이트웨이·주소는 지우는데 DNS(RDNSS)는 그대로 — 개요에 계속 보인다", () => {
    const net = slaacNet({ raDns: "2001:db8:2::53" });
    const pc = net.getHost("pc");
    expect(pc.v6.raDnsLearned).toBe("2001:db8:2::53");
    (net.nodes.get("gw") as L3Node).setIpv6(gwCfg({ ra: false }), net.contextFor("gw"));
    net.runToIdle();
    expect(pc.v6.defaultRouter).toBeUndefined();
    const overview = pc.snapshot().info.find(([k]) => k === "IPv6 설정")?.[1];
    // 관찰: "자동 (SLAAC) · DNS 2001:db8:2::53 (RDNSS)"
    expect({ dns: pc.v6.raDnsLearned, overview }).toEqual({ dns: undefined, overview: "자동 (SLAAC)" });
  });
  it("라우터에서 RA 의 DNS 칸을 비워도 호스트는 옛 DNS 를 계속 쓴다", () => {
    const net = slaacNet({ raDns: "2001:db8:2::53" });
    const pc = net.getHost("pc");
    (net.nodes.get("gw") as L3Node).setIpv6(gwCfg({}), net.contextFor("gw"));
    net.runToIdle();
    expect(pc.v6.raDnsLearned).toBeUndefined();
  });
});

describe("고친 결함 4 RA 를 받았는데(/64 아님·프리픽스 없음) 타일은 'RA 없음'", () => {
  it("/56 프리픽스 RA 를 받아 기본 게이트웨이까지 배운 호스트", () => {
    const net = slaacNet({ prefix: 56 });
    const pc = net.getHost("pc");
    expect(pc.v6.defaultRouter).toBe(GW_IF1_LL); // RA 는 받았다
    const tile = hostStatusOf(pc, false);
    const ping = act(net, { kind: "ping", nodeId: "pc", dst: "2001:db8:2::10" }).find((e) => e.kind === "ip.no-address")?.summary;
    // 관찰: 타일 "RA 없음 · 링크 로컬만", ping "RA 를 받지 못해 SLAAC 주소가 없음 … RA 광고를 확인하세요" — RA 를 받았는데 없다고 말하고, 진짜 원인(/56)은 안 보인다
    expect({ tile: tile?.text, ping }).toEqual({ tile: expect.not.stringContaining("RA 없음"), ping: expect.not.stringContaining("RA 를 받지 못해") });
  });
});

describe("고친 결함 4b SLAAC 주소가 DAD 중복일 때 안내가 '다른 주소를 넣으세요' (자동 모드엔 주소 칸이 없음)", () => {
  it("수동 호스트가 pc 의 EUI-64 주소를 먼저 씀", () => {
    const net = slaacNet();
    const pc = net.getHost("pc");
    const link = [...net.links.values()].find((l) => l.a.node === "pc" || l.b.node === "pc")!;
    net.disconnect(link.id);
    net.addNode(new Host({ id: "squat", mac: "02:00:00:00:00:0d", ipMode: "static", ipv6: { enabled: true, addrs: [{ ip: PC_SLAAC, prefix: 64 }] } }));
    net.connect("squat", 0, "sw1", 2);
    net.runToIdle();
    net.connect("pc", 0, "sw1", 0);
    net.runToIdle();
    expect(pc.v6.addrs.find((a) => a.ip === PC_SLAAC)?.state).toBe("duplicate");
    const why = act(net, { kind: "ping", nodeId: "pc", dst: "2001:db8:2::10" }).find((e) => e.kind === "ip.no-address")?.summary;
    // 관찰: "IPv6 주소가 다른 장치와 중복이라 쓰지 않는 중 — 다른 주소를 넣으세요"
    expect(why).not.toContain("다른 주소를 넣으세요");
  });
});

describe("고친 결함 5 라우터를 기본 게이트웨이에서 뺀 기록에 'default via … expires 1799sec' 실무 줄", () => {
  it("거둠 RA 의 slaac.router 트레이스 → ip -6 route 추가 줄이 붙는다", () => {
    const net = slaacNet();
    const t = since(net, () => (net.nodes.get("gw") as L3Node).setIpv6(gwCfg({ ra: false }), net.contextFor("gw")));
    const removed = t.find((e) => e.nodeId === "pc" && e.kind === "slaac.router" && e.summary.includes("기본 게이트웨이에서 뺌"))!;
    expect(removed).toBeDefined();
    const lines = practitionerLines(removed, {}).map((l) => l.line);
    // 관찰: ["default via fe80::ff:fe11:1 dev eth0 proto ra metric 1024 expires 1799sec hoplimit 64 pref medium"]
    expect(lines.join("\n")).not.toContain("expires 1799sec");
  });
});

describe("고친 결함 6 라우터 주소가 DAD 중복이면 RA 문구가 '이 인터페이스에 주소가 없음'", () => {
  it("gw if1 의 2001:db8:1::1 을 이미 수동 호스트가 쓰는 링크 (RA 에 프리픽스가 빠지는 것 자체는 일관됨 — 라우터도 그 프리픽스로 라우팅 안 함)", () => {
    const net = new Network();
    net.addNode(new Switch("sw1", 6));
    net.addNode(new Host({ id: "squat", mac: SRV, ipMode: "static", ipv6: { enabled: true, addrs: [{ ip: "2001:db8:1::1", prefix: 64 }] } }));
    net.addNode(new Host({ id: "pc", mac: PC, ipMode: "static", ipv6: { enabled: true, addrs: [], slaac: true } }));
    net.connect("squat", 0, "sw1", 0);
    net.runToIdle();
    net.addNode(gwNode("gw", "01", {}));
    net.connect("gw", 1, "sw1", 1);
    net.connect("pc", 0, "sw1", 2);
    net.runToIdle();
    const gw = net.nodes.get("gw") as L3Node;
    const pc = net.getHost("pc");
    expect(gw.v6[1]!.addrs.find((a) => a.ip === "2001:db8:1::1")?.state).toBe("duplicate");
    expect(pc.v6.globals).toEqual([]);
    const ra = net.trace.find((e) => e.nodeId === "gw" && e.kind === "ndp.ra.sent")!.summary;
    // 관찰: "... (알릴 프리픽스 없음 — 이 인터페이스에 주소가 없음)" — 주소는 있고, DAD 중복이라 뺀 것
    expect(ra).not.toContain("이 인터페이스에 주소가 없음");
  });
});

// ---------- 확인했더니 괜찮았던 것 ----------

describe("OK 상태 기계", () => {
  it("OK slaac → 수동(주소 없음) → slaac: RS 대기 취소, 다시 RS 로 받음", () => {
    const net = slaacNet({ ra: false });
    const pc = net.getHost("pc");
    pc.setIpv6({ enabled: true, addrs: [] }, net.contextFor("pc"));
    net.runToIdle();
    expect(pc.v6.raWaiting).toBe(false);
    (net.nodes.get("gw") as L3Node).setIpv6(gwCfg(), net.contextFor("gw"));
    net.runToIdle();
    expect(pc.v6.globals).toEqual([]); // 수동이라 RA 무시
    pc.setIpv6({ enabled: true, addrs: [], slaac: true }, net.contextFor("pc"));
    net.runToIdle();
    expect(pc.v6.globals.map((a) => a.ip)).toEqual([PC_SLAAC]);
  });

  it("OK 두 라우터(다른 프리픽스) 중 하나가 거두면 남은 라우터·주소로", () => {
    const net = new Network();
    net.addNode(new Switch("sw1", 6));
    net.addNode(gwNode("r1", "01", { ip: "2001:db8:1::1" }));
    net.addNode(gwNode("r2", "02", { ip: "2001:db8:7::1" }));
    net.addNode(new Host({ id: "pc", mac: PC, ipMode: "static", ipv6: { enabled: true, addrs: [], slaac: true } }));
    net.connect("r1", 1, "sw1", 0);
    net.connect("r2", 1, "sw1", 1);
    net.connect("pc", 0, "sw1", 2);
    net.runToIdle();
    const pc = net.getHost("pc");
    expect(pc.v6.globals.map((a) => a.ip).sort()).toEqual(["2001:db8:1::ff:fe00:a", "2001:db8:7::ff:fe00:a"]);
    const first = pc.v6.defaultRouter;
    const r1 = net.nodes.get("r1") as L3Node;
    r1.setIpv6(gwCfg({ ra: false }), net.contextFor("r1"));
    net.runToIdle();
    expect(first).toBe(GW_IF1_LL);
    expect(pc.v6.defaultRouter).toBe("fe80::ff:fe11:2");
    expect(pc.v6.globals.map((a) => a.ip)).toEqual(["2001:db8:7::ff:fe00:a"]);
  });

  it("OK 라우터 IPv6 를 끄면 거둠 RA", () => {
    const net = slaacNet();
    (net.nodes.get("gw") as L3Node).setIpv6(gwCfg({ enabled: false }), net.contextFor("gw"));
    net.runToIdle();
    expect(net.getHost("pc").v6.defaultRouter).toBeUndefined();
    expect(net.getHost("pc").v6.globals).toEqual([]);
  });

  it("OK 라우터 링크 다운/업 → DAD 뒤 RA 다시 (중복 RA 없음)", () => {
    const net = slaacNet();
    const link = [...net.links.values()].find((l) => (l.a.node === "gw" && l.a.port === 1) || (l.b.node === "gw" && l.b.port === 1))!;
    net.disconnect(link.id);
    net.runToIdle();
    const t = since(net, () => net.connect("gw", 1, "sw1", 1));
    expect(t.filter((e) => e.nodeId === "gw" && e.kind === "ndp.ra.sent")).toHaveLength(1);
  });

  it("OK 투명 방화벽 너머의 SLAAC 호스트도 RA 를 받는다 (RS/RA 는 NDP 라 통과)", () => {
    const net = new Network();
    net.addNode(new Switch("sw1", 4));
    net.addNode(gwNode("gw", "01", {}));
    net.addNode(new FirewallBridge("fw", { enabled: true, defaultPolicy: "deny", stateful: true, rules: [] }));
    net.addNode(new Host({ id: "pc", mac: PC, ipMode: "static", ipv6: { enabled: true, addrs: [], slaac: true } }));
    net.connect("gw", 1, "fw", 0);
    net.connect("fw", 1, "sw1", 0);
    net.connect("pc", 0, "sw1", 1);
    net.runToIdle();
    expect(net.getHost("pc").v6.globals.map((a) => a.ip)).toEqual([PC_SLAAC]);
  });

  it("OK 예제: 모델에서 게이트웨이를 지우면(케이블도 같이 빠짐) 거둠 RA 가 전달된다", () => {
    const t = exampleSlaacTopology();
    const L = loadTopology(t);
    const pc1 = L.host("pc-1");
    expect(pc1.v6.globals).toHaveLength(1);
    const gw = t.devices.find((d) => d.name === "gw-1")!;
    L.apply({ ...t, devices: t.devices.filter((d) => d.id !== gw.id), cables: t.cables.filter((c) => c.a.device !== gw.id && c.b.device !== gw.id) });
    expect(pc1.v6.globals).toEqual([]);
    expect(pc1.v6.defaultRouter).toBeUndefined();
    expect(ipv6StatusOf(pc1)?.text).toBe("IPv6 RA 없음 · 링크 로컬만");
  });

  it("OK 예제 구성 검사: 관계없는 설정 변경(방화벽 등)으로 RA 가 다시 나가지 않는다", () => {
    const t = exampleSlaacTopology();
    const L = loadTopology(t);
    const gw = t.devices.find((d) => d.name === "gw-1")!;
    const next = structuredClone(t);
    next.devices.find((d) => d.id === gw.id)!.l3!.routes = [{ dest: "10.9.0.0", prefix: 16, via: "10.0.0.2" }];
    const tr = L.apply(next);
    expect(tr.filter((e) => e.kind === "ndp.ra.sent")).toEqual([]);
    expect(lintTopology(t)).toEqual([]);
  });
});

describe("고친 결함 7 같은 프리픽스를 알리는 라우터 둘 중 하나가 거두면, 남은 라우터가 아직 알리는데도 주소를 지운다", () => {
  it("r1·r2 둘 다 2001:db8:1::/64 RA → r1 RA 끔 → pc 의 SLAAC 주소가 사라지고 다시 RS 도 안 한다", () => {
    const net = new Network();
    net.addNode(new Switch("sw1", 6));
    net.addNode(gwNode("r1", "01", { ip: "2001:db8:1::1" }));
    net.addNode(gwNode("r2", "02", { ip: "2001:db8:1::2" }));
    net.addNode(new Host({ id: "pc", mac: PC, ipMode: "static", ipv6: { enabled: true, addrs: [], slaac: true } }));
    net.connect("r1", 1, "sw1", 0);
    net.connect("r2", 1, "sw1", 1);
    net.connect("pc", 0, "sw1", 2);
    net.runToIdle();
    const pc = net.getHost("pc");
    expect(pc.v6.globals.map((a) => a.ip)).toEqual([PC_SLAAC]);
    const r1 = net.nodes.get("r1") as L3Node;
    r1.setIpv6(gwCfg({ ip: "2001:db8:1::1", ra: false }), net.contextFor("r1"));
    net.runToIdle();
    expect(pc.v6.defaultRouter).toBe("fe80::ff:fe11:2"); // r2 는 남았다
    // 관찰: [] — r2 가 같은 프리픽스를 알리는 중인데 주소가 없어 다른 네트워크로 못 나간다
    expect(pc.v6.globals.map((a) => a.ip)).toEqual([PC_SLAAC]);
  });
});

describe("고친 결함 6b 라우터 주소를 이미 쓰는 주소로 바꾸면: 곧바로 RA 로 알렸다가(DAD 전), 나중에 다른 호스트의 RS 에 거둔다", () => {
  it("다른 호스트가 링크에 붙기만 해도 pc 의 SLAAC 주소가 지워진다", () => {
    const net = slaacNet();
    net.addNode(new Host({ id: "squat", mac: "02:00:00:00:00:0d", ipMode: "static", ipv6: { enabled: true, addrs: [{ ip: "2001:db8:5::1", prefix: 64 }] } }));
    net.connect("squat", 0, "sw1", 2);
    net.runToIdle();
    const pc = net.getHost("pc");
    const gw = net.nodes.get("gw") as L3Node;
    gw.setIpv6(gwCfg({ ip: "2001:db8:5::1" }), net.contextFor("gw"));
    net.runToIdle();
    expect(gw.v6[1]!.addrs.find((a) => a.ip === "2001:db8:5::1")?.state).toBe("duplicate");
    const mid = pc.v6.globals.map((a) => a.ip);
    net.addNode(new Host({ id: "pc2", mac: PC2, ipMode: "static", ipv6: { enabled: true, addrs: [], slaac: true } }));
    const t = since(net, () => net.connect("pc2", 0, "sw1", 3));
    const ra = t.find((e) => e.nodeId === "gw" && e.kind === "ndp.ra.sent")?.summary;
    // 관찰: mid = ["2001:db8:5::ff:fe00:a"], 그 뒤 [] — pc2 의 RS 에 대한 RA 가 "알릴 프리픽스 없음 — 이 인터페이스에 주소가 없음 · 빠진 프리픽스 2001:db8:5::/64 거둠"
    expect({ mid, after: pc.v6.globals.map((a) => a.ip), ra }).toEqual({ mid, after: mid, ra: expect.not.stringContaining("거둠") });
  });
});

describe("구성 검사·동작 일치 점검 (SLAAC)", () => {
  const none = { ipMode: "static" as const, ip: "", prefix: 24, gateway: "" };
  it("OK AP 너머 무선 단말(SLAAC): 검사 조용, 실제로 주소도 받음", () => {
    const { devices, add } = builder();
    const gw = add("gateway", 300, 60);
    const sw = add("switch", 300, 200);
    const ap = add("ap", 300, 320);
    ap.ap = { enabled: true, ssid: "office" };
    const phone = add("phone", 360, 420);
    phone.wifi = { ssid: "office" };
    gw.l3 = { interfaces: [none, none, none], routes: [], ipv6: { enabled: true, interfaces: [{ ip: "", prefix: 64 }, { ip: "2001:db8:1::1", prefix: 64, ra: true }, { ip: "", prefix: 64 }], routes: [] } };
    phone.host = { ipMode: "static", ip: "", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER }, ipv6: { enabled: true, mode: "slaac", ip: "", prefix: 64, gateway: "" } };
    const t: Topology = { devices, cables: [cable(gw, 1, sw, 0), cable(sw, 1, ap, 0)] };
    expect(lintTopology(t).filter((i) => i.code.startsWith("ipv6"))).toEqual([]);
    const L = loadTopology(t);
    expect(L.host(phone.name).v6.globals).toHaveLength(1);
  });

  it("기록(미탐, 오탐 아님): 트렁크 너머 액세스 VLAN 10 의 SLAAC 호스트는 RA 를 못 받는데 검사는 조용", () => {
    const { devices, add } = builder();
    const gw = add("gateway", 300, 60);
    const sw = add("switch", 300, 200);
    const pc = add("pc", 300, 400);
    sw.switch = { vlans: { 0: "trunk", 1: 10 } };
    gw.l3 = {
      interfaces: [none, none, none],
      routes: [],
      subinterfaces: [{ port: 1, vlan: 10, ip: "10.0.10.1", prefix: 24, relay: "" }],
      ipv6: { enabled: true, interfaces: [{ ip: "", prefix: 64 }, { ip: "2001:db8:1::1", prefix: 64, ra: true }, { ip: "", prefix: 64 }], routes: [] },
    };
    pc.host = { ipMode: "static", ip: "10.0.10.10", prefix: 24, gateway: "10.0.10.1", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER }, ipv6: { enabled: true, mode: "slaac", ip: "", prefix: 64, gateway: "" } };
    const t: Topology = { devices, cables: [cable(gw, 1, sw, 0), cable(sw, 1, pc, 0)] };
    const lint = lintTopology(t).filter((i) => i.code.startsWith("ipv6")).map((i) => i.code);
    const L = loadTopology(t);
    const got = L.host(pc.name).v6.globals.length;
    expect({ got, lint, v6: ipv6StatusOf(L.host(pc.name))?.text }).toEqual({ got: 0, lint: [], v6: "IPv6 RA 없음 · 링크 로컬만" });
  });

  it("기록: IPv4 게이트웨이 예제에서 PC 의 IPv6 만 켜면(기본 = 자동) PC 마다 ipv6.router-off 오류 — 문구는 사실", () => {
    const t = exampleTwoGatewaysTopology();
    for (const d of t.devices) if (d.kind === "pc" && d.host) d.host.ipv6 = { ...DEFAULT_IPV6_HOST };
    const codes = lintTopology(t).filter((i) => i.code.startsWith("ipv6")).map((i) => `${i.code}/${i.severity}`);
    expect(new Set(codes)).toEqual(new Set(["ipv6.router-off/error"]));
  });
});
