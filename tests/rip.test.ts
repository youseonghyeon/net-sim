// 동적 라우팅 (RIPv2 축소판): 수렴, 링크 절단 후 재수렴, poison reverse, 끄기(철회), NAT outside 제외, 디폴트 라우트 광고
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { L3Node } from "../src/core/nodes/l3";
import { NetworkSync } from "../src/model/netSync";
import { createDevice, exampleBackboneTopology, examplePartsTopology, exampleRipTopology, newId, type Cable, type Device, type DeviceKind, type Topology } from "../src/model/topology";

function byName(t: Topology, name: string): Device {
  const d = t.devices.find((x) => x.name === name);
  if (!d) throw new Error(`no device named ${name}`);
  return d;
}
function gw(s: NetworkSync, t: Topology, name: string): L3Node {
  return s.net.nodes.get(byName(t, name).id) as L3Node;
}
function host(s: NetworkSync, t: Topology, name: string): Host {
  return s.net.nodes.get(byName(t, name).id) as Host;
}
/** 경로 목록을 "목적지 via 넥스트홉 메트릭" 으로 정렬해서 */
function ripRoutes(n: L3Node): string[] {
  return n.rip
    .rows()
    .map((r) => `${r.dest}/${r.prefix} via ${r.nextHop} ${r.metric}`)
    .sort();
}
function ping(s: NetworkSync, t: Topology, from: string, dst: string) {
  s.net.scheduleAction(s.net.now, { kind: "ping", nodeId: byName(t, from).id, dst });
  s.net.runToIdle();
  return host(s, t, from).pings.at(-1)!;
}
function traceroute(s: NetworkSync, t: Topology, from: string, dst: string) {
  s.net.scheduleAction(s.net.now, { kind: "traceroute", nodeId: byName(t, from).id, dst });
  s.net.runToIdle();
  return host(s, t, from).traceroutes.at(-1)!;
}
function setup() {
  const t = exampleRipTopology();
  const s = new NetworkSync();
  s.sync(t);
  s.net.runToIdle();
  return { s, t };
}

describe("RIP: 스태틱 라우팅 없이 이웃에게서 경로를 배운다", () => {
  it("삼각형이 수렴하면 게이트웨이마다 다른 두 LAN 을 1홉으로, 반대편 링크를 2홉 이하로 안다", () => {
    const { s, t } = setup();
    expect(ripRoutes(gw(s, t, "gw-a"))).toEqual([
      "10.0.23.0/24 via 10.0.12.2 1",
      "192.168.2.0/24 via 10.0.12.2 1",
      "192.168.3.0/24 via 10.0.13.3 1",
    ]);
    expect(ripRoutes(gw(s, t, "gw-b"))).toEqual([
      "10.0.13.0/24 via 10.0.12.1 1",
      "192.168.1.0/24 via 10.0.12.1 1",
      "192.168.3.0/24 via 10.0.23.3 1",
    ]);
    expect(ping(s, t, "pc-a", "192.168.3.10").status).toBe("ok");
    expect(ping(s, t, "pc-b", "192.168.1.10").status).toBe("ok");
    const tr = traceroute(s, t, "pc-a", "192.168.3.10");
    expect(tr.hops.map((h) => h.ip)).toEqual(["192.168.1.1", "10.0.13.3", "192.168.3.10"]);
  });

  it("gw-a ↔ gw-c 케이블을 뽑으면 철회 후 gw-b 경유로 다시 수렴하고, 통신이 이어진다", () => {
    const { s, t } = setup();
    const a = byName(t, "gw-a").id;
    const c = byName(t, "gw-c").id;
    const cut: Topology = { ...t, cables: t.cables.filter((x) => !([x.a.device, x.b.device].includes(a) && [x.a.device, x.b.device].includes(c))) };
    s.sync(cut);
    s.net.runToIdle();
    expect(ripRoutes(gw(s, cut, "gw-a"))).toEqual([
      "10.0.23.0/24 via 10.0.12.2 1",
      "192.168.2.0/24 via 10.0.12.2 1",
      "192.168.3.0/24 via 10.0.12.2 2",
    ]);
    expect(ripRoutes(gw(s, cut, "gw-c"))).toContain("192.168.1.0/24 via 10.0.23.2 2");
    const tr = traceroute(s, cut, "pc-a", "192.168.3.10");
    expect(tr.hops.map((h) => h.ip)).toEqual(["192.168.1.1", "10.0.12.2", "10.0.23.3", "192.168.3.10"]);
    // 철회 → 재학습이 로그에 남는다
    const kinds = s.net.trace.map((e) => e.kind);
    expect(kinds).toContain("rip.withdraw");
    // 다시 꽂으면 1홉 경로로 돌아온다
    s.sync(t);
    s.net.runToIdle();
    expect(ripRoutes(gw(s, t, "gw-a"))).toContain("192.168.3.0/24 via 10.0.13.3 1");
  });

  it("poison reverse: 이웃에게서 배운 경로는 그 이웃 쪽으로 메트릭 16 으로 광고한다", () => {
    const { s, t } = setup();
    const aId = byName(t, "gw-a").id;
    const resp = s.net.trace.filter((e) => e.nodeId === aId && e.kind === "rip.response" && (e.details as { iface: string }).iface === "if1").at(-1)!;
    const entries = (resp.details as { entries: { dest: string; metric: number }[] }).entries;
    // if1 은 gw-b 쪽: gw-b 에게서 배운 192.168.2.0 은 16, gw-c 에게서 배운 192.168.3.0 은 2
    expect(entries.find((e) => e.dest === "192.168.2.0")?.metric).toBe(16);
    expect(entries.find((e) => e.dest === "192.168.3.0")?.metric).toBe(2);
    // 보내는 인터페이스 자신의 서브넷(10.0.12.0)은 광고하지 않는다
    expect(entries.some((e) => e.dest === "10.0.12.0")).toBe(false);
  });

  it("호스트는 RIP 멀티캐스트를 조용히 거른다 (드롭 로그가 남지 않음)", () => {
    const { s, t } = setup();
    const pcA = byName(t, "pc-a").id;
    const mine = s.net.trace.filter((e) => e.nodeId === pcA);
    expect(mine.some((e) => e.summary.includes("01:00:5e") || e.summary.includes("RIP"))).toBe(false);
    // 스위치는 멀티캐스트를 플러딩하므로 프레임 자체는 pc-a 포트까지 온다
    expect(s.net.trace.some((e) => e.kind === "switch.flood" && e.summary.includes("01:00:5e:00:00:09"))).toBe(true);
  });

  it("RIP 를 끄면 이웃에게 철회를 보내 이웃의 경로가 사라지고, 통신이 끊긴다", () => {
    const { s, t } = setup();
    const off: Topology = { ...t, devices: t.devices.map((d) => (d.name === "gw-c" ? { ...d, l3: { ...d.l3!, rip: { enabled: false } } } : d)) };
    s.sync(off);
    s.net.runToIdle();
    expect(ripRoutes(gw(s, off, "gw-c"))).toEqual([]);
    expect(ripRoutes(gw(s, off, "gw-a")).some((r) => r.startsWith("192.168.3.0"))).toBe(false);
    expect(ping(s, off, "pc-a", "192.168.3.10").status).not.toBe("ok");
  });

  it("같은 목적지에 스태틱 라우팅이 있으면 스태틱이 우선 (관리 거리)", () => {
    const { s, t } = setup();
    const withStatic: Topology = {
      ...t,
      devices: t.devices.map((d) => (d.name === "gw-a" ? { ...d, l3: { ...d.l3!, routes: [{ dest: "192.168.3.0", prefix: 24, via: "10.0.12.2" }] } } : d)),
    };
    s.sync(withStatic);
    s.net.runToIdle();
    expect(gw(s, withStatic, "gw-a").route("192.168.3.10")).toMatchObject({ kind: "static", nextHop: "10.0.12.2" });
  });

  it("NAT 박스가 디폴트 라우트를 광고하면 게이트웨이는 스태틱 설정 없이 인터넷으로 나가고, outside 로는 RIP 를 보내지 않는다", () => {
    const base = examplePartsTopology();
    const t: Topology = {
      ...base,
      devices: base.devices.map((d) => {
        if (d.kind === "nat") return { ...d, l3: { ...d.l3!, routes: [], rip: { enabled: true, defaultRoute: true } } };
        if (d.kind === "gateway") return { ...d, l3: { ...d.l3!, interfaces: d.l3!.interfaces.map((c, i) => (i === 0 ? { ...c, gateway: "" } : c)), rip: { enabled: true } } };
        return d;
      }),
    };
    const s = new NetworkSync();
    s.sync(t);
    s.net.runToIdle();
    const nat = s.net.nodes.get(t.devices.find((d) => d.kind === "nat")!.id) as L3Node;
    const g = s.net.nodes.get(t.devices.find((d) => d.kind === "gateway")!.id) as L3Node;
    expect(ripRoutes(g)).toContain("0.0.0.0/0 via 10.0.0.1 1");
    expect(ripRoutes(nat)).toEqual(expect.arrayContaining(["192.168.1.0/24 via 10.0.0.2 1", "192.168.2.0/24 via 10.0.0.2 1"]));
    const pc = t.devices.find((d) => d.kind === "pc")!;
    s.net.scheduleAction(s.net.now, { kind: "ping", nodeId: pc.id, dst: "8.8.8.8" });
    s.net.runToIdle();
    expect((s.net.nodes.get(pc.id) as Host).pings.at(-1)!.status).toBe("ok");
    // outside(0번) 인터페이스로는 RIP 를 보내지 않는다 — 사설 경로를 ISP 에 새지 않게
    const outsideName = nat.names[0];
    const natSends = s.net.trace.filter((e) => e.nodeId === nat.id && (e.kind === "rip.response" || e.kind === "rip.request"));
    expect(natSends.length).toBeGreaterThan(0);
    expect(natSends.some((e) => (e.details as { iface: string }).iface === outsideName)).toBe(false);
  });

  it("라우터를 지우면 이웃에게 철회를 보내고, 이웃의 경로가 사라진다", () => {
    const { s, t } = setup();
    const gone: Topology = { ...t, devices: t.devices.filter((d) => d.name !== "gw-c"), cables: t.cables.filter((c) => ![c.a.device, c.b.device].includes(byName(t, "gw-c").id)) };
    s.sync(gone);
    s.net.runToIdle();
    expect(ripRoutes(gw(s, gone, "gw-a")).some((r) => r.startsWith("192.168.3.0"))).toBe(false);
    expect(ripRoutes(gw(s, gone, "gw-b")).some((r) => r.startsWith("192.168.3.0"))).toBe(false);
  });
});

// 리뷰에서 재현된 결함의 회귀 테스트 (2026-09-28)
describe("RIP: 업데이트가 반드시 멈추고, 주소·인터페이스 변화에 옛 경로가 남지 않는다", () => {
  function builder() {
    const devices: Device[] = [];
    const cables: Cable[] = [];
    const add = (kind: DeviceKind, name: string) => {
      const d = createDevice(kind, devices.length * 120, 0, devices);
      d.name = name;
      devices.push(d);
      return d;
    };
    const link = (a: Device, ap: number, b: Device, bp: number) => cables.push({ id: newId("cable"), a: { device: a.id, port: ap }, b: { device: b.id, port: bp } });
    const staticIfs = (...ips: string[]) => ips.map((ip) => ({ ipMode: "static" as const, ip, prefix: 24, gateway: "" }));
    return { devices, cables, add, link, staticIfs, t: () => ({ devices, cables }) as Topology };
  }

  it("게이트웨이 4대 일렬(A-B-C-D)도 수렴 후 멈춘다 (poison reverse 끼리 핑퐁하지 않음)", () => {
    const b = builder();
    const [A, B, C, D] = ["A", "B", "C", "D"].map((n) => b.add("gateway", n)) as [Device, Device, Device, Device];
    A.l3 = { interfaces: b.staticIfs("10.1.0.1", "10.0.1.1", ""), routes: [], rip: { enabled: true } };
    B.l3 = { interfaces: b.staticIfs("10.0.1.2", "10.0.2.1", ""), routes: [], rip: { enabled: true } };
    C.l3 = { interfaces: b.staticIfs("10.0.2.2", "10.0.3.1", ""), routes: [], rip: { enabled: true } };
    D.l3 = { interfaces: b.staticIfs("10.0.3.2", "10.4.0.1", ""), routes: [], rip: { enabled: true } };
    const swA = b.add("switch", "swA");
    const swD = b.add("switch", "swD");
    b.link(swA, 1, A, 0);
    b.link(A, 1, B, 0);
    b.link(B, 1, C, 0);
    b.link(C, 1, D, 0);
    b.link(D, 1, swD, 1);
    const s = new NetworkSync();
    s.sync(b.t());
    expect(() => s.net.runToIdle(20_000)).not.toThrow();
    expect(s.net.now).toBeLessThan(5_000);
    expect(ripRoutes(s.net.nodes.get(A.id) as L3Node)).toContain("10.4.0.0/24 via 10.0.1.2 3");
    expect(ripRoutes(s.net.nodes.get(D.id) as L3Node)).toContain("10.1.0.0/24 via 10.0.3.1 3");
  });

  it("백본 예제를 스태틱 대신 RIP 로 돌려도 멈추고 집끼리 통신된다", () => {
    const base = exampleBackboneTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.kind === "gateway" ? { ...d, l3: { ...d.l3!, routes: [], rip: { enabled: true } } } : d)) };
    const s = new NetworkSync();
    s.sync(t);
    expect(() => s.net.runToIdle(20_000)).not.toThrow();
    const hosts = t.devices.filter((d) => d.kind === "pc");
    const first = hosts[0]!;
    const last = hosts.at(-1)!;
    const dst = (s.net.nodes.get(last.id) as Host).ip!;
    s.net.scheduleAction(s.net.now, { kind: "ping", nodeId: first.id, dst });
    expect(() => s.net.runToIdle(20_000)).not.toThrow();
    expect((s.net.nodes.get(first.id) as Host).pings.at(-1)!.status).toBe("ok");
  });

  it("이웃이 같은 서브넷 안에서 주소를 바꾸면 옛 넥스트 홉을 버리고 새 주소로 다시 배운다", () => {
    const { s, t } = setup();
    const moved: Topology = {
      ...t,
      devices: t.devices.map((d) => (d.name === "gw-c" ? { ...d, l3: { ...d.l3!, interfaces: d.l3!.interfaces.map((c, i) => (i === 0 ? { ...c, ip: "10.0.13.9" } : c)) } } : d)),
    };
    s.sync(moved);
    s.net.runToIdle();
    const a = ripRoutes(gw(s, moved, "gw-a"));
    expect(a.some((r) => r.includes("via 10.0.13.3"))).toBe(false);
    expect(a).toContain("192.168.3.0/24 via 10.0.13.9 1");
    expect(ping(s, moved, "pc-a", "192.168.3.10").status).toBe("ok");
  });

  it("VLAN 서브 인터페이스 하나를 지우면 양쪽 모두 남은 VLAN 으로 다시 수렴한다", () => {
    const b = builder();
    const G1 = b.add("gateway", "G1");
    const G2 = b.add("gateway", "G2");
    const vlanPair = (x: string) => [
      { port: 1, vlan: 10, ip: `10.10.0.${x}`, prefix: 24, relay: "" },
      { port: 1, vlan: 20, ip: `10.20.0.${x}`, prefix: 24, relay: "" },
    ];
    G1.l3 = { interfaces: b.staticIfs("", "", "10.1.0.1"), routes: [], subinterfaces: vlanPair("1"), rip: { enabled: true } };
    G2.l3 = { interfaces: b.staticIfs("", "", "10.2.0.1"), routes: [], subinterfaces: vlanPair("2"), rip: { enabled: true } };
    const sw1 = b.add("switch", "sw1");
    const sw2 = b.add("switch", "sw2");
    b.link(G1, 1, G2, 1); // 태그 프레임이 오가는 직결 트렁크
    b.link(G1, 2, sw1, 1);
    b.link(G2, 2, sw2, 1);
    const s = new NetworkSync();
    const t = b.t();
    s.sync(t);
    s.net.runToIdle();
    expect(ripRoutes(s.net.nodes.get(G1.id) as L3Node).some((r) => r.startsWith("10.2.0.0/24"))).toBe(true);
    const cut: Topology = { ...t, devices: t.devices.map((d) => (d.id === G2.id ? { ...d, l3: { ...d.l3!, subinterfaces: [{ port: 1, vlan: 20, ip: "10.20.0.2", prefix: 24, relay: "" }] } } : d)) };
    s.sync(cut);
    expect(() => s.net.runToIdle(20_000)).not.toThrow();
    expect(ripRoutes(s.net.nodes.get(G1.id) as L3Node)).toContain("10.2.0.0/24 via 10.20.0.2 1");
    expect(ripRoutes(s.net.nodes.get(G2.id) as L3Node)).toContain("10.1.0.0/24 via 10.20.0.1 1");
  });

  it("디폴트 라우트 광고: 업링크 케이블이 빠지면 0.0.0.0/0 을 철회한다", () => {
    const base = examplePartsTopology();
    const t: Topology = {
      ...base,
      devices: base.devices.map((d) => {
        if (d.kind === "nat") return { ...d, l3: { ...d.l3!, routes: [], rip: { enabled: true, defaultRoute: true } } };
        if (d.kind === "gateway") return { ...d, l3: { ...d.l3!, interfaces: d.l3!.interfaces.map((c, i) => (i === 0 ? { ...c, gateway: "" } : c)), rip: { enabled: true } } };
        return d;
      }),
    };
    const s = new NetworkSync();
    s.sync(t);
    s.net.runToIdle();
    const g = s.net.nodes.get(t.devices.find((d) => d.kind === "gateway")!.id) as L3Node;
    expect(ripRoutes(g)).toContain("0.0.0.0/0 via 10.0.0.1 1");
    const inet = t.devices.find((d) => d.kind === "internet")!.id;
    const unplugged: Topology = { ...t, cables: t.cables.filter((c) => c.a.device !== inet && c.b.device !== inet) };
    s.sync(unplugged);
    s.net.runToIdle();
    expect(ripRoutes(g).some((r) => r.startsWith("0.0.0.0/0"))).toBe(false);
  });
});
