import { describe, expect, it } from "vitest";
import {
  canonIp6,
  commonPrefixLength6,
  isGlobal6,
  isLinkLocal6,
  isUla6,
  linkLocalOf,
  multicastMac6,
  network6,
  parseIp6,
  sameSubnet6,
  solicitedNode,
} from "../src/core/addr6";
import { Network } from "../src/core/network";
import { FirewallBridge } from "../src/core/nodes/fwbridge";
import { Host } from "../src/core/nodes/host";
import { L3Node } from "../src/core/nodes/l3";
import { Switch } from "../src/core/nodes/switch";
import type { EthernetFrame } from "../src/core/packet";
import type { TraceEvent } from "../src/core/trace";
import { exampleIpv6BasicsTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import { headerLayers, practitionerLines, tcpdumpLine } from "../src/model/packetView";
import type { Topology } from "../src/model/topology";
import { loadTopology } from "./helpers";

describe("IPv6 주소 유틸", () => {
  it("RFC 5952 표준 표기: 소문자, 앞자리 0 생략, 가장 긴 0 묶음(같으면 앞쪽)을 ::", () => {
    expect(canonIp6("2001:0DB8:0000:0000:0000:0000:0000:0001")).toBe("2001:db8::1");
    expect(canonIp6("2001:db8:0:0:1:0:0:1")).toBe("2001:db8::1:0:0:1");
    expect(canonIp6("2001:db8:0:1:0:0:0:1")).toBe("2001:db8:0:1::1");
    expect(canonIp6("2001:db8:1:1:1:1:0:1")).toBe("2001:db8:1:1:1:1:0:1"); // 0 하나는 줄이지 않는다
    expect(canonIp6("::")).toBe("::");
    expect(canonIp6("::1")).toBe("::1");
    expect(canonIp6("fe80::")).toBe("fe80::");
  });

  it("형식이 틀리면 undefined (:: 두 번, 다섯 자리, 16진수 아님, 그룹 9개, IPv4)", () => {
    for (const bad of ["1::2::3", "12345::", "g::1", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "192.168.0.1", "", ":1:2:3:4:5:6:7"]) expect(parseIp6(bad)).toBeUndefined();
  });

  it("EUI-64 링크 로컬: MAC 가운데 ff:fe, U/L 비트 뒤집기", () => {
    expect(linkLocalOf("02:00:00:00:00:05")).toBe("fe80::ff:fe00:5");
    expect(linkLocalOf("00:1a:2b:3c:4d:5e")).toBe("fe80::21a:2bff:fe3c:4d5e");
  });

  it("solicited-node 멀티캐스트와 그 MAC (33:33 + 끝 32비트)", () => {
    expect(solicitedNode("2001:db8::1:2345:6789")).toBe("ff02::1:ff45:6789");
    expect(multicastMac6("ff02::1:ff45:6789")).toBe("33:33:ff:45:67:89");
    expect(multicastMac6("ff02::1")).toBe("33:33:00:00:00:01");
  });

  it("프리픽스·범위 판별", () => {
    expect(sameSubnet6("2001:db8:1::10", "2001:db8:1::ffff", 64)).toBe(true);
    expect(sameSubnet6("2001:db8:1::10", "2001:db8:2::10", 64)).toBe(false);
    expect(network6("2001:db8:1::10", 64)).toBe("2001:db8:1::");
    expect(isLinkLocal6("fe80::1")).toBe(true);
    expect(isLinkLocal6("febf::1")).toBe(true);
    expect(isLinkLocal6("fec0::1")).toBe(false);
    expect(isGlobal6("2001:db8::1")).toBe(true);
    expect(isUla6("fd00::1")).toBe(true);
    expect(isGlobal6("fd00::1")).toBe(false);
    expect(commonPrefixLength6("2001:db8:1::1", "2001:db8:1::2")).toBe(126);
  });
});

const PC = "02:00:00:00:00:0a";
const SRV = "02:00:00:00:00:0b";

function host(id: string, mac: string, ip6?: string, gw?: string, extra: Partial<ConstructorParameters<typeof Host>[0]> = {}) {
  return new Host({ id, mac, ipMode: "static", ipv6: { enabled: true, addrs: ip6 ? [{ ip: ip6, prefix: 64 }] : [], gateway: gw }, ...extra });
}

/** pc ─ sw1 ─ gw(if1 2001:db8:1::1, if2 2001:db8:2::1) ─ sw2 ─ srv */
function twoLans(opts: { pcGw?: string; srvServices?: number[] } = {}) {
  const net = new Network();
  net.addNode(new Switch("sw1", 4));
  net.addNode(new Switch("sw2", 4));
  net.addNode(
    new L3Node({
      id: "gw",
      kind: "gateway",
      interfaces: [
        { name: "if0", mac: "02:00:00:10:00:01", mode: "static" },
        { name: "if1", mac: "02:00:00:11:00:01", mode: "static" },
        { name: "if2", mac: "02:00:00:12:00:01", mode: "static" },
      ],
      ipv6: { enabled: true, interfaces: [{}, { ip: "2001:db8:1::1", prefix: 64 }, { ip: "2001:db8:2::1", prefix: 64 }], routes: [] },
    }),
  );
  net.addNode(host("pc", PC, "2001:db8:1::10", opts.pcGw ?? "2001:db8:1::1"));
  net.addNode(host("srv", SRV, "2001:db8:2::10", "2001:db8:2::1", { services: opts.srvServices ?? [] }));
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

describe("NDP·DAD (같은 링크)", () => {
  function sameLink(bEnabled = true) {
    const net = new Network();
    net.addNode(new Switch("sw", 4));
    net.addNode(host("a", PC, "2001:db8:1::10"));
    net.addNode(bEnabled ? host("b", SRV, "2001:db8:1::20") : new Host({ id: "b", mac: SRV, ipMode: "static" }));
    net.connect("a", 0, "sw", 0);
    net.connect("b", 0, "sw", 1);
    net.runToIdle();
    return net;
  }

  it("링크 업 → 링크 로컬·수동 주소를 DAD 로 확인한 뒤 사용", () => {
    const net = sameLink();
    const a = net.getHost("a");
    expect(a.v6.addrs.map((x) => [x.ip, x.state])).toEqual([
      ["fe80::ff:fe00:a", "preferred"],
      ["2001:db8:1::10", "preferred"],
    ]);
    // DAD 의 NS 는 출발지 :: 로, 그 주소의 solicited-node 그룹으로
    const dad = net.trace.filter((e) => e.nodeId === "a" && e.kind === "ndp.dad");
    expect(dad.map((e) => e.details?.ip)).toEqual(["fe80::ff:fe00:a", "2001:db8:1::10", "fe80::ff:fe00:a", "2001:db8:1::10"]);
  });

  it("ping6: ARP 없이 NS(solicited-node 멀티캐스트) → NA(유니캐스트) → Echo", () => {
    const net = sameLink();
    const t = act(net, { kind: "ping", nodeId: "a", dst: "2001:db8:1::20" });
    const seq = t.filter((e) => e.nodeId !== "sw" && !["link.transmit", "frame.send", "frame.receive"].includes(e.kind)).map((e) => `${e.nodeId}:${e.kind}`);
    expect(seq).toEqual([
      "a:action",
      "a:icmp.echo.sent",
      "a:ip.route",
      "a:ndp.cache.miss",
      "a:ndp.ns.sent",
      "b:ndp.ns.received",
      "b:ndp.cache.update",
      "b:ndp.na.sent",
      "a:ndp.na.received",
      "a:ndp.cache.update",
      "a:ip.dequeue",
      "b:icmp.echo.received",
      "b:icmp.reply.sent",
      "b:ip.route",
      "b:ndp.cache.hit",
      "a:icmp.reply.received",
    ]);
    expect(t.some((e) => e.kind.startsWith("arp."))).toBe(false);
    expect(net.getHost("a").pings[0]!.status).toBe("ok");
    // 스위치는 solicited-node 멀티캐스트를 브로드캐스트처럼 뿌린다
    expect(t.find((e) => e.nodeId === "sw" && e.kind === "switch.flood")?.summary).toContain("멀티캐스트 33:33:ff:00:00:20");
  });

  it("링크 로컬로 ping: 출발지도 링크 로컬", () => {
    const net = sameLink();
    act(net, { kind: "ping", nodeId: "a", dst: "fe80::ff:fe00:b" });
    expect(net.getHost("a").pings[0]!.status).toBe("ok");
    expect(net.getHost("b").v6.neighbors.has("fe80::ff:fe00:a")).toBe(true);
  });

  it("IPv6 가 꺼진 상대는 NS 를 거른다 → NDP timeout → ping 실패", () => {
    const net = sameLink(false);
    const t = act(net, { kind: "ping", nodeId: "a", dst: "2001:db8:1::20" });
    expect(t.some((e) => e.nodeId === "b" && e.kind === "ndp.ns.received")).toBe(false);
    expect(t.some((e) => e.nodeId === "a" && e.kind === "ndp.timeout")).toBe(true);
    expect(net.getHost("a").pings[0]).toMatchObject({ status: "failed", reason: "NDP timeout · 응답 없음" });
  });

  it("DAD 중복: 이미 쓰는 장치가 모든 노드 그룹으로 NA → 새 장치는 그 주소를 포기", () => {
    const net = sameLink();
    net.addNode(host("c", "02:00:00:00:00:0c", "2001:db8:1::20"));
    net.connect("c", 0, "sw", 2);
    net.runToIdle();
    const c = net.getHost("c");
    expect(c.v6.addrs.find((x) => x.ip === "2001:db8:1::20")?.state).toBe("duplicate");
    expect(net.getHost("b").v6.owns("2001:db8:1::20")).toBe(true);
    expect(net.trace.some((e) => e.nodeId === "b" && e.kind === "ndp.na.sent" && e.summary.includes("DAD 방어"))).toBe(true);
    act(net, { kind: "ping", nodeId: "c", dst: "2001:db8:1::10" });
    expect(c.pings[0]).toMatchObject({ status: "failed", reason: "IPv6 주소 없음" });
  });

  it("글로벌 주소 없이 링크 로컬만 있으면 다른 네트워크로 못 나간다", () => {
    const net = new Network();
    net.addNode(new Switch("sw", 4));
    net.addNode(host("a", PC, undefined, "fe80::1"));
    net.connect("a", 0, "sw", 0);
    net.runToIdle();
    const t = act(net, { kind: "ping", nodeId: "a", dst: "2001:db8:9::1" });
    expect(t.find((e) => e.kind === "ip.no-address")?.summary).toContain("링크 로컬 주소(fe80::)로는 다른 네트워크로 나갈 수 없음");
  });
});

describe("IPv6 라우팅 (게이트웨이)", () => {
  it("다른 프리픽스로 ping: 게이트웨이가 Hop Limit 을 줄여 NAT 없이 넘긴다", () => {
    const net = twoLans();
    const t = act(net, { kind: "ping", nodeId: "pc", dst: "2001:db8:2::10" });
    expect(net.getHost("pc").pings[0]!.status).toBe("ok");
    const fwd = t.filter((e) => e.nodeId === "gw" && e.kind === "ip.forward").map((e) => e.summary);
    expect(fwd[0]).toBe("라우팅(IPv6): 2001:db8:2::10 → if2 (2001:db8:2::/64 에 직접 연결), Hop Limit 64 → 63");
    expect(fwd).toHaveLength(2);
  });

  it("기본 게이트웨이를 라우터의 링크 로컬 주소로 둬도 된다 (IPv6 에서 흔한 방식)", () => {
    const net = twoLans({ pcGw: "fe80::ff:fe11:1" });
    act(net, { kind: "ping", nodeId: "pc", dst: "2001:db8:2::10" });
    expect(net.getHost("pc").pings[0]!.status).toBe("ok");
    expect(net.getHost("pc").v6.neighbors.get("fe80::ff:fe11:1")?.router).toBe(true);
  });

  it("traceroute6: 게이트웨이 → 목적지 두 홉", () => {
    const net = twoLans();
    act(net, { kind: "traceroute", nodeId: "pc", dst: "2001:db8:2::10" });
    const rec = net.getHost("pc").traceroutes[0]!;
    expect(rec.status).toBe("done");
    expect(rec.hops.map((h) => h.ip)).toEqual(["2001:db8:1::1", "2001:db8:2::10"]);
  });

  it("경로 없음 → ICMPv6 Destination Unreachable (no route) 로 바로 실패", () => {
    const net = twoLans();
    const t = act(net, { kind: "ping", nodeId: "pc", dst: "2001:db8:9::1" });
    expect(t.some((e) => e.nodeId === "gw" && e.kind === "ip.no-route")).toBe(true);
    expect(net.getHost("pc").pings[0]).toMatchObject({ status: "failed", reason: "Destination Unreachable (no route) (2001:db8:1::1)" });
  });

  it("목적지가 NS 에 답하지 않음 → 게이트웨이가 Address Unreachable", () => {
    const net = twoLans();
    act(net, { kind: "ping", nodeId: "pc", dst: "2001:db8:2::99" });
    expect(net.getHost("pc").pings[0]).toMatchObject({ status: "failed", reason: "Destination Unreachable (address unreachable) (2001:db8:1::1)" });
  });

  it("디폴트 라우트 ::/0: 두 게이트웨이를 거쳐 간다", () => {
    const net = twoLans();
    const gw = net.nodes.get("gw") as L3Node;
    // 뒤쪽 서브넷 2001:db8:3::/64 을 가진 두 번째 게이트웨이를 if2 쪽에
    net.addNode(
      new L3Node({
        id: "gw2",
        kind: "gateway",
        interfaces: [
          { name: "if0", mac: "02:00:00:10:00:02", mode: "static" },
          { name: "if1", mac: "02:00:00:11:00:02", mode: "static" },
        ],
        ipv6: { enabled: true, interfaces: [{ ip: "2001:db8:2::2", prefix: 64 }, { ip: "2001:db8:3::1", prefix: 64 }], routes: [{ dest: "::", prefix: 0, via: "2001:db8:2::1" }] },
      }),
    );
    net.addNode(host("far", "02:00:00:00:00:0f", "2001:db8:3::10", "2001:db8:3::1"));
    net.connect("gw2", 0, "sw2", 2);
    net.connect("far", 0, "gw2", 1);
    net.runToIdle();
    gw.setIpv6({ enabled: true, interfaces: [{}, { ip: "2001:db8:1::1", prefix: 64 }, { ip: "2001:db8:2::1", prefix: 64 }], routes: [{ dest: "2001:db8:3::", prefix: 64, via: "2001:db8:2::2" }] }, net.contextFor("gw"));
    act(net, { kind: "traceroute", nodeId: "pc", dst: "2001:db8:3::10" });
    expect(net.getHost("pc").traceroutes[0]!.hops.map((h) => h.ip)).toEqual(["2001:db8:1::1", "2001:db8:2::2", "2001:db8:3::10"]);
  });

  it("링크 로컬 주소는 라우터를 넘지 않는다", () => {
    const net = twoLans();
    // 링크 로컬은 늘 "같은 링크" 로 보므로 pc 는 NS 를 자기 링크에만 보내고, 게이트웨이는 넘기지 않는다
    const t = act(net, { kind: "ping", nodeId: "pc", dst: "fe80::ff:fe00:b" });
    expect(t.some((e) => e.nodeId === "srv")).toBe(false);
    expect(net.getHost("pc").pings[0]!.status).toBe("failed");
  });

  it("방화벽의 ICMP 규칙은 ICMPv6 에도 걸린다 (IPv6 주소 CIDR 포함)", () => {
    const net = twoLans();
    const gw = net.nodes.get("gw") as L3Node;
    gw.setFirewall({ enabled: true, defaultPolicy: "allow", stateful: true, rules: [{ action: "deny", proto: "icmp", direction: "any", dst: "2001:db8:2::/64" }] }, net.contextFor("gw"));
    const t = act(net, { kind: "ping", nodeId: "pc", dst: "2001:db8:2::10" });
    expect(t.find((e) => e.kind === "fw.deny")?.summary).toContain("ICMPv6 ping 요청 2001:db8:1::10 → 2001:db8:2::10");
    expect(net.getHost("pc").pings[0]!.status).toBe("failed");
  });

  it("TCP over IPv6: [주소]:80 으로 연결해 응답을 받는다", () => {
    const net = twoLans({ srvServices: [80] });
    act(net, { kind: "tcp-connect", nodeId: "pc", dst: "2001:db8:2::10", port: 80 });
    const conn = [...net.getHost("pc").tcp.conns.values()][0]!;
    expect(conn.id).toBe("[2001:db8:1::10]:49152-[2001:db8:2::10]:80");
    expect(conn.state).toBe("CLOSED");
    expect(conn.bytesReceived).toBe(3000);
  });

  it("NAT 박스도 IPv6 는 변환하지 않는다: 바깥에서 안쪽 글로벌 주소로 바로 들어온다", () => {
    const net = new Network();
    net.addNode(new Switch("wan", 4));
    net.addNode(
      new L3Node({
        id: "nat",
        kind: "nat",
        outside: 0,
        interfaces: [
          { name: "outside", mac: "02:00:00:10:00:01", mode: "static", ip: "203.0.113.2", prefix: 24 },
          { name: "inside", mac: "02:00:00:11:00:01", mode: "static", ip: "192.168.0.1", prefix: 24 },
        ],
        ipv6: { enabled: true, interfaces: [{ ip: "2001:db8:ff::2", prefix: 64 }, { ip: "2001:db8:1::1", prefix: 64 }], routes: [] },
      }),
    );
    net.addNode(host("in", PC, "2001:db8:1::10", "2001:db8:1::1"));
    net.addNode(host("out", SRV, "2001:db8:ff::99", "2001:db8:ff::2"));
    net.connect("nat", 0, "wan", 0);
    net.connect("out", 0, "wan", 1);
    net.connect("in", 0, "nat", 1);
    net.runToIdle();
    const t = act(net, { kind: "ping", nodeId: "out", dst: "2001:db8:1::10" });
    expect(net.getHost("out").pings[0]!.status).toBe("ok");
    expect(t.find((e) => e.nodeId === "nat" && e.kind === "ip.forward")?.summary).toContain("IPv6 는 NAT 가 없어 바깥에서 안쪽 주소로 바로 들어온다");
    expect(t.some((e) => e.kind === "nat.translate" || e.kind === "nat.restore")).toBe(false);
  });
});

describe("투명 방화벽과 IPv6", () => {
  it("NDP 는 ARP 처럼 통과, 그 밖의 IPv6 는 규칙대로", () => {
    const net = new Network();
    net.addNode(new FirewallBridge("fw", { enabled: true, defaultPolicy: "allow", stateful: true, rules: [{ action: "deny", proto: "tcp", direction: "in", dstPort: 80 }] }));
    net.addNode(host("a", PC, "2001:db8:1::10"));
    net.addNode(host("b", SRV, "2001:db8:1::20", undefined, { services: [80] }));
    net.connect("a", 0, "fw", 0);
    net.connect("b", 0, "fw", 1);
    net.runToIdle();
    act(net, { kind: "ping", nodeId: "a", dst: "2001:db8:1::20" });
    expect(net.getHost("a").pings[0]!.status).toBe("ok");
    const t = act(net, { kind: "tcp-connect", nodeId: "a", dst: "2001:db8:1::20", port: 80 });
    expect(t.some((e) => e.nodeId === "fw" && e.kind === "fw.deny")).toBe(true);
  });
});

describe("예제 IPv6 기초", () => {
  it("설명대로: NDP ping, 경로 2홉, TCP 80, 링크 로컬은 라우터를 못 넘음", () => {
    const L = loadTopology(exampleIpv6BasicsTopology());
    const pc1 = L.host("pc-1");
    L.act({ kind: "ping", nodeId: pc1.id, dst: "2001:db8:1::11" });
    expect(pc1.pings.at(-1)!.status).toBe("ok");
    L.act({ kind: "traceroute", nodeId: pc1.id, dst: "2001:db8:2::10" });
    expect(pc1.traceroutes.at(-1)!.hops.map((h) => h.ip)).toEqual(["2001:db8:1::1", "2001:db8:2::10"]);
    L.act({ kind: "tcp-connect", nodeId: pc1.id, dst: "2001:db8:2::10", port: 80 });
    expect([...pc1.tcp.conns.values()].at(-1)).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    // pc-2 는 게이트웨이가 링크 로컬
    const pc2 = L.host("pc-2");
    L.act({ kind: "ping", nodeId: pc2.id, dst: "2001:db8:2::10" });
    expect(pc2.pings.at(-1)!.status).toBe("ok");
    expect(pc2.v6.gateway?.startsWith("fe80::")).toBe(true);
    L.act({ kind: "ping", nodeId: pc1.id, dst: "fe80::ff:fe00:6" });
    expect(pc1.pings.at(-1)!.status).toBe("failed");
    expect(lintTopology(exampleIpv6BasicsTopology())).toEqual([]);
  });
});

describe("구성 검사 (IPv6)", () => {
  function base() {
    const t = exampleIpv6BasicsTopology();
    const byName = (n: string) => t.devices.find((d) => d.name === n)!;
    return { t, byName };
  }
  const codesOf = (t: Topology, name: string) => lintTopology(t).filter((i) => i.deviceId === t.devices.find((d) => d.name === name)!.id).map((i) => i.code);

  it("주소 중복", () => {
    const { t, byName } = base();
    byName("pc-2").host!.ipv6!.ip = "2001:db8:1::10";
    expect(codesOf(t, "pc-1")).toContain("ipv6.duplicate");
    expect(codesOf(t, "pc-2")).toContain("ipv6.duplicate");
  });
  it("게이트웨이가 내 프리픽스 밖", () => {
    const { t, byName } = base();
    byName("pc-1").host!.ipv6!.gateway = "2001:db8:2::1";
    expect(codesOf(t, "pc-1")).toEqual(["ipv6.gateway-off-link"]);
  });
  it("게이트웨이가 이 링크의 라우터 주소가 아님 (링크 로컬 오타 포함)", () => {
    const { t, byName } = base();
    byName("pc-1").host!.ipv6!.gateway = "2001:db8:1::99";
    byName("pc-2").host!.ipv6!.gateway = "fe80::1";
    expect(codesOf(t, "pc-1")).toEqual(["ipv6.gateway-unknown"]);
    expect(codesOf(t, "pc-2")).toEqual(["ipv6.gateway-unknown"]);
  });
  it("라우터 IPv6 꺼짐", () => {
    const { t, byName } = base();
    byName("gw-1").l3!.ipv6!.enabled = false;
    expect(codesOf(t, "pc-1")).toEqual(["ipv6.router-off"]);
  });
  it("라우터 프리픽스 밖 주소", () => {
    const { t, byName } = base();
    byName("pc-1").host!.ipv6 = { ...byName("pc-1").host!.ipv6!, ip: "2001:db8:9::10", gateway: byName("pc-2").host!.ipv6!.gateway }; // gw-1 if1 의 링크 로컬
    expect(codesOf(t, "pc-1")).toEqual(["ipv6.prefix-mismatch"]);
  });
  it("IPv6 를 안 켠 구성은 조용하다", () => {
    const { t, byName } = base();
    for (const n of ["pc-1", "pc-2", "srv-1"]) byName(n).host!.ipv6!.enabled = false;
    byName("gw-1").l3!.ipv6!.enabled = false;
    expect(lintTopology(t).filter((i) => i.code.startsWith("ipv6."))).toEqual([]);
  });
});

describe("패킷 상세 (IPv6)", () => {
  const f = (payload: any, src: string, dst: string, dstMac = "02:00:00:00:00:0b", hopLimit = 64): EthernetFrame => ({ kind: "ethernet", id: 1, src: PC, dst: dstMac, payload: { kind: "ipv6", src, dst, hopLimit, payload } });
  it("tcpdump: NS·NA·DAD·echo·TCP·unreachable", () => {
    expect(tcpdumpLine(f({ kind: "icmp6", type: "ns", target: "2001:db8:1::20", sll: PC }, "2001:db8:1::10", "ff02::1:ff00:20", "33:33:ff:00:00:20", 255))).toBe(
      `${PC} > 33:33:ff:00:00:20, ethertype IPv6 (0x86dd): 2001:db8:1::10 > ff02::1:ff00:20: ICMP6, neighbor solicitation, who has 2001:db8:1::20, length 32`,
    );
    expect(tcpdumpLine(f({ kind: "icmp6", type: "ns", target: "2001:db8:1::20" }, "::", "ff02::1:ff00:20", "33:33:ff:00:00:20", 255))).toContain(":: > ff02::1:ff00:20: ICMP6, neighbor solicitation, who has 2001:db8:1::20, length 24");
    expect(tcpdumpLine(f({ kind: "icmp6", type: "na", target: "2001:db8:1::20", router: false, solicited: true, override: true, tll: SRV }, "2001:db8:1::20", "2001:db8:1::10"))).toContain("ICMP6, neighbor advertisement, tgt is 2001:db8:1::20, length 32");
    expect(tcpdumpLine(f({ kind: "icmp6", type: "echo-request", id: 4660, seq: 1 }, "2001:db8:1::10", "2001:db8:2::10"))).toContain("2001:db8:1::10 > 2001:db8:2::10: ICMP6, echo request, id 4660, seq 1, length 64");
    expect(tcpdumpLine(f({ kind: "tcp", srcPort: 49152, dstPort: 80, seq: 1000, ack: 0, syn: true, len: 0 }, "2001:db8:1::10", "2001:db8:2::10"))).toContain("2001:db8:1::10.49152 > 2001:db8:2::10.80: Flags [S], seq 1000, length 0");
    expect(tcpdumpLine(f({ kind: "icmp6", type: "unreachable", code: "net", original: { src: "2001:db8:1::10", dst: "2001:db8:9::1", l4: { kind: "icmp", id: 1, seq: 1 } } }, "2001:db8:1::1", "2001:db8:1::10"))).toContain("ICMP6, destination unreachable, unreachable route 2001:db8:9::1");
  });
  it("헤더: IPv6 는 Hop Limit·Next Header, NS 는 타입 135 와 옵션", () => {
    const layers = headerLayers(f({ kind: "icmp6", type: "ns", target: "2001:db8:1::20", sll: PC }, "2001:db8:1::10", "ff02::1:ff00:20", "33:33:ff:00:00:20", 255));
    expect(layers.map((l) => l.title)).toEqual(["이더넷 (L2)", "IPv6 (L3)", "ICMPv6 · NDP"]);
    expect(Object.fromEntries(layers[0]!.rows)["EtherType"]).toBe("0x86DD (IPv6)");
    expect(Object.fromEntries(layers[1]!.rows)["Next Header"]).toBe("58 (ICMPv6)");
    expect(Object.fromEntries(layers[2]!.rows)["타입 / 코드"]).toContain("135 / 0");
    expect(Object.fromEntries(layers[2]!.rows)["옵션 1 출발지 링크 계층 주소"]).toBe(PC);
  });
  it("실무 출력: ip -6 neigh, DAD 실패 커널 로그, ping(IPv6)", () => {
    const ev = (kind: string, details: Record<string, unknown>) => ({ seq: 0, time: 0, nodeId: "a", kind, layer: "L3", summary: "", details }) as TraceEvent;
    expect(practitionerLines(ev("ndp.cache.update", { ip: "2001:db8:1::20", mac: SRV }), {})[0]!.line).toBe(`2001:db8:1::20 dev eth0 lladdr ${SRV} REACHABLE`);
    expect(practitionerLines(ev("ndp.dad.fail", { ip: "2001:db8:1::20", mac: SRV }), {})[0]!.line).toBe(`IPv6: eth0: IPv6 duplicate address 2001:db8:1::20 used by ${SRV} detected!`);
    const reply = f({ kind: "icmp6", type: "echo-reply", id: 1, seq: 3 }, "2001:db8:2::10", "2001:db8:1::10", PC, 63);
    expect(practitionerLines(ev("icmp.reply.received", { seq: 3, rtt: 80 }), { received: reply })[0]!.line).toBe("64 bytes from 2001:db8:2::10: icmp_seq=3 ttl=63 time=80 ms");
  });
});
