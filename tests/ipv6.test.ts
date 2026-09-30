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
import { exampleDualStackTopology, exampleIpv6BasicsTopology, exampleSlaacTopology } from "../src/model/examples";
import { l3MacOf } from "../src/model/netSync";
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

describe("SLAAC (RS/RA)", () => {
  const GW_IF1_LL = "fe80::ff:fe11:1";
  /** pc(SLAAC) ─ sw1 ─ gw(if1 2001:db8:1::1 RA 켬) ─ sw2 ─ srv(수동) */
  function slaacNet(opts: { ra?: boolean; prefix?: number; raDns?: string } = {}) {
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
        ipv6: { enabled: true, interfaces: [{}, { ip: "2001:db8:1::1", prefix: opts.prefix ?? 64, ra: opts.ra ?? true }, { ip: "2001:db8:2::1", prefix: 64 }], routes: [], raDns: opts.raDns },
      }),
    );
    net.addNode(new Host({ id: "pc", mac: PC, ipMode: "static", ipv6: { enabled: true, addrs: [], slaac: true } }));
    net.addNode(host("srv", SRV, "2001:db8:2::10", "2001:db8:2::1"));
    net.connect("pc", 0, "sw1", 0);
    net.connect("gw", 1, "sw1", 1);
    net.connect("gw", 2, "sw2", 1);
    net.connect("srv", 0, "sw2", 0);
    net.runToIdle();
    return net;
  }
  const gwCfg = (patch: { ip?: string; ra?: boolean; enabled?: boolean } = {}) => ({
    enabled: patch.enabled ?? true,
    interfaces: [{}, { ip: patch.ip ?? "2001:db8:1::1", prefix: 64, ra: patch.ra ?? true }, { ip: "2001:db8:2::1", prefix: 64 }],
    routes: [],
  });

  it("RA 의 /64 프리픽스 + EUI-64 로 주소를 만들고, RA 를 보낸 라우터의 링크 로컬이 기본 게이트웨이", () => {
    const net = slaacNet({ raDns: "2001:db8:2::53" });
    const pc = net.getHost("pc");
    expect(pc.v6.addrs.map((a) => [a.ip, a.origin, a.state])).toEqual([
      ["fe80::ff:fe00:a", "link-local", "preferred"],
      ["2001:db8:1::ff:fe00:a", "slaac", "preferred"],
    ]);
    expect(pc.v6.defaultRouter).toBe(GW_IF1_LL);
    expect(pc.v6.raDnsLearned).toBe("2001:db8:2::53");
    const kinds = net.trace.filter((e) => e.nodeId === "pc" && (e.kind.startsWith("slaac") || e.kind.startsWith("ndp.r"))).map((e) => e.kind);
    expect(kinds).toContain("ndp.ra.received");
    expect(kinds).toContain("slaac.addr");
    expect(kinds).toContain("slaac.router");
    act(net, { kind: "ping", nodeId: "pc", dst: "2001:db8:2::10" });
    expect(pc.pings[0]!.status).toBe("ok");
  });

  it("RA 광고가 꺼져 있으면 RS 3번 뒤 포기 → 링크 로컬만", () => {
    const net = slaacNet({ ra: false });
    const pc = net.getHost("pc");
    expect(net.trace.filter((e) => e.nodeId === "pc" && e.kind === "ndp.rs.sent")).toHaveLength(3);
    expect(net.trace.some((e) => e.nodeId === "gw" && e.kind === "ndp.rs.received" && e.summary.includes("RA 광고가 꺼져 있어"))).toBe(true);
    expect(net.trace.some((e) => e.nodeId === "pc" && e.kind === "slaac.timeout")).toBe(true);
    expect(pc.v6.globals).toEqual([]);
    const t = act(net, { kind: "ping", nodeId: "pc", dst: "2001:db8:2::10" });
    expect(t.find((e) => e.kind === "ip.no-address")?.summary).toContain("RA 를 받지 못해 SLAAC 주소가 없음");
  });

  it("라우터가 나중에 RA 를 켜면 곧바로 RA → 주소가 생긴다", () => {
    const net = slaacNet({ ra: false });
    (net.nodes.get("gw") as L3Node).setIpv6(gwCfg(), net.contextFor("gw"));
    net.runToIdle();
    expect(net.getHost("pc").v6.globals.map((a) => a.ip)).toEqual(["2001:db8:1::ff:fe00:a"]);
  });

  it("/64 가 아닌 프리픽스로는 SLAAC 주소를 만들지 않는다", () => {
    const net = slaacNet({ prefix: 56 });
    expect(net.getHost("pc").v6.globals).toEqual([]);
    expect(net.trace.find((e) => e.nodeId === "pc" && e.kind === "slaac.addr")?.summary).toContain("/64 가 아니라 SLAAC 주소를 만들 수 없음");
  });

  it("프리픽스를 바꾸면 옛 프리픽스는 유효 수명 0 으로 거두고 새 주소를 만든다", () => {
    const net = slaacNet();
    (net.nodes.get("gw") as L3Node).setIpv6(gwCfg({ ip: "2001:db8:9::1" }), net.contextFor("gw"));
    net.runToIdle();
    expect(net.getHost("pc").v6.globals.map((a) => a.ip)).toEqual(["2001:db8:9::ff:fe00:a"]);
  });

  it("RA 를 끄거나 라우터를 지우면 수명 0 RA → 기본 게이트웨이·주소를 지운다", () => {
    const net = slaacNet();
    (net.nodes.get("gw") as L3Node).setIpv6(gwCfg({ ra: false }), net.contextFor("gw"));
    net.runToIdle();
    const pc = net.getHost("pc");
    expect(pc.v6.defaultRouter).toBeUndefined();
    expect(pc.v6.globals).toEqual([]);
    const net2 = slaacNet();
    net2.removeNode("gw");
    net2.runToIdle();
    expect(net2.getHost("pc").v6.defaultRouter).toBeUndefined();
  });

  it("RA 를 껐다 다시 켜면 주소·게이트웨이를 다시 받는다", () => {
    const net = slaacNet();
    const gw = net.nodes.get("gw") as L3Node;
    gw.setIpv6(gwCfg({ ra: false }), net.contextFor("gw"));
    net.runToIdle();
    gw.setIpv6(gwCfg({ ra: true }), net.contextFor("gw"));
    net.runToIdle();
    expect(net.getHost("pc").v6.globals.map((a) => a.ip)).toEqual(["2001:db8:1::ff:fe00:a"]);
    expect(net.getHost("pc").v6.defaultRouter).toBe(GW_IF1_LL);
  });

  it("수동 설정 호스트는 RA 로 주소를 만들지 않는다", () => {
    const net = slaacNet();
    const srvLike = net.getHost("pc");
    srvLike.setIpv6({ enabled: true, addrs: [{ ip: "2001:db8:1::77", prefix: 64 }], gateway: "2001:db8:1::1" }, net.contextFor("pc"));
    net.runToIdle();
    expect(srvLike.v6.addrs.map((a) => a.origin)).toEqual(["link-local", "manual"]);
    expect(srvLike.v6.defaultRouter).toBe("2001:db8:1::1");
  });

  it("링크 다운이면 RA 로 배운 것을 잊고, 다시 붙으면 RS 로 새로 받는다", () => {
    const net = slaacNet();
    const link = [...net.links.values()].find((l) => l.a.node === "pc" || l.b.node === "pc")!;
    net.disconnect(link.id);
    expect(net.getHost("pc").v6.globals).toEqual([]);
    net.connect("pc", 0, "sw1", 0);
    net.runToIdle();
    expect(net.getHost("pc").v6.globals.map((a) => a.ip)).toEqual(["2001:db8:1::ff:fe00:a"]);
  });
});

describe("예제 IPv6 자동 주소 (SLAAC)", () => {
  it("설명대로: 자동 호스트가 RA 로 주소·게이트웨이를 받고 서버로 ping·TCP, RA 를 끄면 사라진다", () => {
    const t = exampleSlaacTopology();
    expect(lintTopology(t)).toEqual([]);
    const L = loadTopology(t);
    const pc1 = L.host("pc-1");
    expect(pc1.v6.globals.map((a) => a.ip)).toEqual(["2001:db8:1::ff:fe00:1"]);
    expect(pc1.v6.defaultRouter).toBe(linkLocalOf(l3MacOf(t.devices.find((d) => d.name === "gw-1")!.mac, 1)));
    L.act({ kind: "ping", nodeId: pc1.id, dst: "2001:db8:2::10" });
    expect(pc1.pings.at(-1)!.status).toBe("ok");
    L.act({ kind: "tcp-connect", nodeId: pc1.id, dst: "2001:db8:2::10", port: 80 });
    expect([...pc1.tcp.conns.values()].at(-1)).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    // 서버(수동)는 RA 를 받아도 주소를 만들지 않는다
    expect(L.host("srv-1").v6.addrs.map((a) => a.origin)).toEqual(["link-local", "manual"]);
    const gw = t.devices.find((d) => d.name === "gw-1")!;
    const next = structuredClone(t);
    next.devices.find((d) => d.id === gw.id)!.l3!.ipv6!.interfaces[1]!.ra = false;
    L.apply(next);
    expect(pc1.v6.globals).toEqual([]);
    expect(pc1.v6.defaultRouter).toBeUndefined();
  });

  it("구성 검사: RA 가 없는 링크의 자동 호스트, /64 가 아닌 RA 프리픽스", () => {
    const t = exampleSlaacTopology();
    const gw = t.devices.find((d) => d.name === "gw-1")!;
    gw.l3!.ipv6!.interfaces[1]!.ra = false;
    const issues = lintTopology(t);
    expect(issues.filter((i) => i.code === "ipv6.slaac-no-ra").map((i) => t.devices.find((d) => d.id === i.deviceId)!.name).sort()).toEqual(["laptop-1", "pc-1"]);
    gw.l3!.ipv6!.interfaces[1] = { ip: "2001:db8:1::1", prefix: 56, ra: true };
    expect(lintTopology(t).map((i) => i.code)).toEqual(["ipv6.ra-prefix"]);
  });
});

describe("패킷 상세 (RS/RA)", () => {
  const f = (payload: any, src: string, dst: string, dstMac: string): EthernetFrame => ({ kind: "ethernet", id: 1, src: PC, dst: dstMac, payload: { kind: "ipv6", src, dst, hopLimit: 255, payload } });
  const ra = { kind: "icmp6", type: "ra", curHopLimit: 64, managed: false, other: false, routerLifetime: 1800, prefixes: [{ prefix: "2001:db8:1::", length: 64, onLink: true, autonomous: true, valid: 86400 }], rdnss: ["2001:db8:1::53"], sll: PC };
  it("tcpdump: router solicitation·advertisement", () => {
    expect(tcpdumpLine(f({ kind: "icmp6", type: "rs", sll: PC }, "fe80::ff:fe00:a", "ff02::2", "33:33:00:00:00:02"))).toContain("fe80::ff:fe00:a > ff02::2: ICMP6, router solicitation, length 16");
    expect(tcpdumpLine(f(ra, "fe80::ff:fe11:1", "ff02::1", "33:33:00:00:00:01"))).toContain("fe80::ff:fe11:1 > ff02::1: ICMP6, router advertisement, length 80");
  });
  it("헤더: RA 의 플래그·라우터 수명·프리픽스 정보·RDNSS", () => {
    const rows = Object.fromEntries(headerLayers(f(ra, "fe80::ff:fe11:1", "ff02::1", "33:33:00:00:00:01"))[2]!.rows);
    expect(rows["타입 / 코드"]).toBe("134 / 0 (Router Advertisement)");
    expect(rows["옵션 3 프리픽스 정보"]).toContain("2001:db8:1::/64 · L=1 A=1");
    expect(rows["옵션 25 RDNSS"]).toContain("2001:db8:1::53");
  });
  it("실무 출력: SLAAC 주소는 ip -6 addr, RA 기본 경로는 ip -6 route", () => {
    const ev = (kind: string, details: Record<string, unknown>) => ({ seq: 0, time: 0, nodeId: "a", kind, layer: "L3", summary: "", details }) as TraceEvent;
    expect(practitionerLines(ev("slaac.addr", { ip: "2001:db8:1::ff:fe00:a" }), {})[0]!.line).toBe("inet6 2001:db8:1::ff:fe00:a/64 scope global dynamic");
    expect(practitionerLines(ev("slaac.router", { router: "fe80::ff:fe11:1" }), {})[0]!.line).toContain("default via fe80::ff:fe11:1 dev eth0 proto ra");
  });
});

describe("듀얼 스택 (A·AAAA·Happy Eyeballs)", () => {
  const conns = (h: Host) => [...h.tcp.conns.values()].filter((c) => c.role === "client");
  it("설명대로: AAAA 우선, AAAA 없으면 A, IPv6 만 쓰는 노트북은 IPv6 DNS 로, 방화벽을 켜면 IPv4 로 다시", () => {
    const t = exampleDualStackTopology();
    expect(lintTopology(t)).toEqual([]);
    const L = loadTopology(t);
    const pc = L.host("pc-1");
    // AAAA 를 IPv4 DNS 서버에 묻고 IPv6 로 연결
    let tr = L.act({ kind: "tcp-connect", nodeId: pc.id, dst: "web.corp", port: 80 });
    expect(tr.find((e) => e.nodeId === pc.id && e.kind === "dns.query.sent")?.summary).toContain("IPv6 주소를 IPv4 로 묻는다");
    expect(conns(pc).at(-1)).toMatchObject({ remoteIp: "2001:db8:2::10", state: "CLOSED", bytesReceived: 3000 });
    // old.corp: AAAA 없음(NODATA) → A → IPv4
    tr = L.act({ kind: "tcp-connect", nodeId: pc.id, dst: "old.corp", port: 80 });
    expect(tr.some((e) => e.nodeId === pc.id && e.kind === "dns.resolved" && e.summary.includes("AAAA 레코드가 없음 → IPv4 주소(A)로 다시"))).toBe(true);
    expect(conns(pc).at(-1)).toMatchObject({ remoteIp: "192.168.2.20", state: "CLOSED", bytesReceived: 3000 });
    // 노트북: IPv4 없음 → RDNSS 로 받은 IPv6 DNS 에 IPv6 로 묻는다
    const lap = L.host("laptop-1");
    expect(lap.v6.raDnsLearned).toBe("2001:db8:2::53");
    tr = L.act({ kind: "ping", nodeId: lap.id, dst: "web.corp" });
    expect(lap.pings.at(-1)).toMatchObject({ status: "ok", resolved: "2001:db8:2::10" });
    const q = tr.find((e) => e.nodeId === lap.id && e.kind === "dns.query.sent")!;
    expect(q.summary).toContain("→ 서버 2001:db8:2::53");
    // old.corp 는 IPv4 뿐이라 IPv6 만 쓰는 노트북은 못 간다
    L.act({ kind: "ping", nodeId: lap.id, dst: "old.corp" });
    expect(lap.pings.at(-1)!.status).toBe("failed");
    // 방화벽 켜기 → IPv6 SYN 이 막혀 timeout → IPv4 로 다시
    const next = structuredClone(t);
    next.devices.find((d) => d.name === "gw-1")!.l3!.firewall!.enabled = true;
    L.apply(next);
    tr = L.act({ kind: "tcp-connect", nodeId: pc.id, dst: "web.corp", port: 80 });
    expect(tr.some((e) => e.kind === "fw.deny")).toBe(true);
    expect(tr.some((e) => e.nodeId === pc.id && e.kind === "tcp.fallback")).toBe(true);
    const last2 = conns(pc).slice(-2);
    expect(last2[0]).toMatchObject({ remoteIp: "2001:db8:2::10", state: "FAILED" });
    expect(last2[1]).toMatchObject({ remoteIp: "192.168.2.10", state: "CLOSED", bytesReceived: 3000 });
  });

  it("IPv6 글로벌 주소가 없는 호스트는 예전처럼 A 만 묻는다 (AAAA 질의 없음)", () => {
    const t = exampleDualStackTopology();
    t.devices.find((d) => d.name === "pc-1")!.host!.ipv6!.enabled = false;
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.host("pc-1").id, dst: "web.corp" });
    expect(tr.filter((e) => e.kind === "dns.query.sent").map((e) => e.details?.qtype)).toEqual(["A"]);
    expect(L.host("pc-1").pings.at(-1)).toMatchObject({ status: "ok", resolved: "192.168.2.10" });
  });

  it("DNS 서버는 이름이 있는데 그 종류가 없으면 NODATA, 이름이 없으면 NXDOMAIN (AAAA 도 A 도)", () => {
    const L = loadTopology(exampleDualStackTopology());
    const pc = L.host("pc-1");
    L.act({ kind: "ping", nodeId: pc.id, dst: "nobody.corp" });
    expect(pc.pings.at(-1)).toMatchObject({ status: "failed", reason: "없는 이름" });
    // 없는 이름이면 A 로 다시 묻지 않는다
    expect(L.s.net.trace.filter((e) => e.nodeId === pc.id && e.kind === "dns.query.sent" && e.summary.includes("nobody.corp")).length).toBe(1);
  });

  it("tcpdump·헤더: AAAA 질의·응답·NODATA", () => {
    const f = (payload: any): EthernetFrame => ({ kind: "ethernet", id: 1, src: PC, dst: SRV, payload: { kind: "ipv4", src: "192.168.1.10", dst: "192.168.2.53", ttl: 64, payload: { kind: "udp", srcPort: 53001, dstPort: 53, payload } } });
    expect(tcpdumpLine(f({ kind: "dns", id: 7, op: "query", name: "web.corp", qtype: "AAAA" }))).toContain("7+ AAAA? web.corp.");
    expect(tcpdumpLine(f({ kind: "dns", id: 7, op: "response", name: "web.corp", qtype: "AAAA", answer: "2001:db8:2::10" }))).toContain("7 1/0/0 AAAA 2001:db8:2::10");
    expect(tcpdumpLine(f({ kind: "dns", id: 7, op: "response", name: "old.corp", qtype: "AAAA", rcode: "NODATA" }))).toContain("7 0/0/0");
    const rows = Object.fromEntries(headerLayers(f({ kind: "dns", id: 7, op: "response", name: "old.corp", qtype: "AAAA", rcode: "NODATA" }))[3]!.rows);
    expect(rows["응답"]).toContain("NOERROR, 답 0개");
  });
});
