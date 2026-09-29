// 이중화 (VRRP 식): 우선순위로 master 선출, 가상 주소·가상 MAC, 링크 다운·장치 제거 시 backup 이 이어받음, 복구되면 preempt
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { L3Node } from "../src/core/nodes/l3";
import { lintTopology } from "../src/model/lint";
import { NetworkSync } from "../src/model/netSync";
import { exampleHaTopology, exampleVpnTopology } from "../src/model/examples";
import { createDevice, type Device } from "../src/model/topology";
import type { Topology } from "../src/model/topology";

function load(t: Topology = exampleHaTopology()) {
  const s = new NetworkSync();
  s.sync(t);
  s.net.runToIdle();
  const id = (name: string) => t.devices.find((d) => d.name === name)!.id;
  const host = (name: string) => s.net.nodes.get(id(name)) as Host;
  const l3 = (name: string) => s.net.nodes.get(id(name)) as L3Node;
  const act = (a: Parameters<typeof s.net.scheduleAction>[1]) => {
    const from = s.net.trace.length;
    s.net.scheduleAction(s.net.now, a);
    s.net.runToIdle();
    return s.net.trace.slice(from);
  };
  const apply = (next: Topology) => {
    const from = s.net.trace.length;
    s.sync(next);
    s.net.runToIdle();
    return s.net.trace.slice(from);
  };
  return { s, t, id, host, l3, act, apply };
}

const withoutCable = (t: Topology, a: string, b: string): Topology => {
  const ids = (n: string) => t.devices.find((d) => d.name === n)!.id;
  return { ...t, cables: t.cables.filter((c) => !([c.a.device, c.b.device].includes(ids(a)) && [c.a.device, c.b.device].includes(ids(b)))) };
};

describe("이중화 (HA)", () => {
  it("우선순위가 높은 방화벽 A 가 master, 호스트는 가상 주소로 나가고 NAT 는 가상 공인 주소로 바꾼다", () => {
    const { t, host, l3, act, id } = load();
    expect(lintTopology(t)).toEqual([]);
    expect(l3("방화벽 A").ha.state).toBe("master");
    expect(l3("방화벽 B").ha.state).toBe("backup");
    const tr = act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("ok");
    const nat = tr.find((e) => e.kind === "nat.translate")!;
    expect(nat.nodeId).toBe(id("방화벽 A"));
    expect(nat.summary).toContain("203.0.113.10");
    // 호스트의 ARP 캐시: 게이트웨이(가상 주소) = 가상 MAC
    expect(host("pc-1").iface.arpCache.get("192.168.0.1")?.mac).toBe("00:00:5e:00:01:0a");
  });

  it("master 의 바깥 케이블을 뽑으면 물러나고(인터페이스 추적) B 가 이어받아 ping 이 계속된다. 되돌리면 A 가 다시 가져간다", () => {
    const { t, host, l3, act, apply, id } = load();
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    const down = apply(withoutCable(t, "방화벽 A", "outside 스위치"));
    expect(down.some((e) => e.kind === "ha.backup" && e.nodeId === id("방화벽 A"))).toBe(true);
    expect(down.some((e) => e.kind === "ha.master" && e.nodeId === id("방화벽 B"))).toBe(true);
    expect(l3("방화벽 B").ha.state).toBe("master");
    const tr = act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("ok");
    expect(tr.find((e) => e.kind === "nat.translate")!.nodeId).toBe(id("방화벽 B"));
    // 호스트는 아무것도 바꾸지 않았다 (같은 가상 MAC)
    expect(host("pc-1").iface.arpCache.get("192.168.0.1")?.mac).toBe("00:00:5e:00:01:0a");
    const back = apply(t);
    expect(back.some((e) => e.kind === "ha.master" && e.nodeId === id("방화벽 A"))).toBe(true);
    expect(l3("방화벽 A").ha.state).toBe("master");
    expect(l3("방화벽 B").ha.state).toBe("backup");
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("안쪽 케이블이 끊겨도 넘어가고, master 장치를 지워도 B 가 이어받는다", () => {
    const { t, host, l3, act, apply, id } = load();
    apply(withoutCable(t, "방화벽 A", "inside 스위치"));
    expect(l3("방화벽 B").ha.state).toBe("master");
    act({ kind: "ping", nodeId: id("pc-2"), dst: "8.8.8.8" });
    expect(host("pc-2").pings.at(-1)!.status).toBe("ok");
    const x = load();
    const gone: Topology = { ...x.t, devices: x.t.devices.filter((d) => d.name !== "방화벽 A"), cables: x.t.cables.filter((c) => c.a.device !== x.id("방화벽 A") && c.b.device !== x.id("방화벽 A")) };
    x.apply(gone);
    expect(x.l3("방화벽 B").ha.state).toBe("master");
    x.act({ kind: "ping", nodeId: x.id("pc-1"), dst: "8.8.8.8" });
    expect(x.host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("가상 주소로 ping 하면 master 가 가상 주소로 답한다", () => {
    const { host, act, id } = load();
    const tr = act({ kind: "ping", nodeId: id("pc-1"), dst: "192.168.0.1" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "icmp.echo.received" && e.nodeId === id("방화벽 A"))).toBe(true);
  });

  it("구성 검사: 그룹 번호 불일치·가상 주소 불일치·호스트가 실제 주소를 게이트웨이로·짝 없음", () => {
    const base = exampleHaTopology();
    const patch = (name: string, f: (d: Topology["devices"][number]) => Topology["devices"][number]): Topology => ({ ...base, devices: base.devices.map((d) => (d.name === name ? f(d) : d)) });
    const codes = (t: Topology) => lintTopology(t).map((i) => i.code);
    expect(codes(patch("방화벽 B", (d) => ({ ...d, l3: { ...d.l3!, ha: { ...d.l3!.ha!, vrid: 11 } } })))).toContain("ha.vrid-mismatch");
    expect(codes(patch("방화벽 B", (d) => ({ ...d, l3: { ...d.l3!, ha: { ...d.l3!.ha!, vips: ["203.0.113.10", "192.168.0.254"] } } })))).toContain("ha.vip-mismatch");
    expect(codes(patch("pc-1", (d) => ({ ...d, host: { ...d.host!, gateway: "192.168.0.2" } })))).toContain("ha.host-real-gw");
    expect(codes(patch("방화벽 B", (d) => ({ ...d, l3: { ...d.l3!, ha: { ...d.l3!.ha!, enabled: false } } })))).toContain("ha.no-peer");
    expect(codes(patch("방화벽 A", (d) => ({ ...d, l3: { ...d.l3!, ha: { ...d.l3!.ha!, vips: ["203.0.113.10", "10.9.9.1"] } } })))).toContain("ha.vip-outside-subnet");
  });

  it("그룹 번호가 다르면 서로를 짝으로 보지 않아 둘 다 master 가 된다 (구성 검사가 경고하는 이유)", () => {
    const base = exampleHaTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "방화벽 B" ? { ...d, l3: { ...d.l3!, ha: { ...d.l3!.ha!, vrid: 11 } } } : d)) };
    const { l3 } = load(t);
    expect(l3("방화벽 A").ha.state).toBe("master");
    expect(l3("방화벽 B").ha.state).toBe("master");
  });

  // ---------- 리뷰에서 나온 경우들 ----------
  const setL3 = (t: Topology, name: string, f: (l3: NonNullable<Device["l3"]>) => NonNullable<Device["l3"]>): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? { ...d, l3: f(d.l3!) } : d)) });
  const masters = (x: ReturnType<typeof load>) => x.t.devices.filter((d) => d.l3?.ha?.enabled && x.l3(d.name).ha.state === "master").map((d) => d.name);

  it("리뷰: 우선순위가 같고 인터페이스마다 주소 크기 순서가 엇갈려도 한 대만 master (광고가 끝없이 오가지 않음)", () => {
    let t = exampleHaTopology();
    const iface = (ip: string, gateway = "") => ({ ipMode: "static" as const, ip, prefix: 24, gateway });
    t = setL3(t, "방화벽 A", (l) => ({ ...l, interfaces: [iface("203.0.113.11", "203.0.113.1"), iface("192.168.0.3")], ha: { ...l.ha!, priority: 100 } }));
    t = setL3(t, "방화벽 B", (l) => ({ ...l, interfaces: [iface("203.0.113.12", "203.0.113.1"), iface("192.168.0.2")], ha: { ...l.ha!, priority: 100 } }));
    const x = load(t);
    expect(x.s.net.trace.length).toBeLessThan(2000);
    expect(masters(x)).toHaveLength(1);
    x.act({ kind: "ping", nodeId: x.id("pc-1"), dst: "8.8.8.8" });
    expect(x.host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("리뷰: master 의 케이블 두 개를 한 번에 빼도 B 가 이어받는다", () => {
    const x = load();
    x.apply(withoutCable(withoutCable(x.t, "방화벽 A", "outside 스위치"), "방화벽 A", "inside 스위치"));
    expect(masters(x)).toEqual(["방화벽 B"]);
    x.act({ kind: "ping", nodeId: x.id("pc-1"), dst: "8.8.8.8" });
    expect(x.host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("리뷰: 바깥 인터페이스가 DHCP 여도 주소를 받으면 선출이 시작된다", () => {
    let t = exampleHaTopology();
    for (const n of ["방화벽 A", "방화벽 B"]) t = setL3(t, n, (l) => ({ ...l, interfaces: [{ ipMode: "dhcp", ip: "", prefix: 24, gateway: "" }, l.interfaces[1]!] }));
    const x = load(t);
    expect(masters(x)).toEqual(["방화벽 A"]);
    x.act({ kind: "ping", nodeId: x.id("pc-1"), dst: "8.8.8.8" });
    expect(x.host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("리뷰: master 가 설정을 바꿔 다시 시작해도 master 가 비는 시간이 짧다 (backup 이 먼저 이어받음)", () => {
    const x = load();
    const tr = x.apply(setL3(x.t, "방화벽 A", (l) => ({ ...l, ha: { ...l.ha!, priority: 201 } })));
    const resign = tr.find((e) => e.kind === "ha.backup" && e.nodeId === x.id("방화벽 A"))!;
    const bUp = tr.find((e) => e.kind === "ha.master" && e.nodeId === x.id("방화벽 B"))!;
    const aUp = tr.find((e) => e.kind === "ha.master" && e.nodeId === x.id("방화벽 A"))!;
    expect(bUp.time - resign.time).toBeLessThan(1000);
    expect(aUp.time).toBeGreaterThan(bUp.time);
    expect(masters(x)).toEqual(["방화벽 A"]);
  });

  it("리뷰: 갈라졌던 망이 다시 이어지면 master 가 둘인 상태가 정리된다", () => {
    const base = exampleHaTopology();
    const devices = [...base.devices];
    const out2 = { ...createDevice("switch", 600, -168, devices), name: "outside 스위치 2" };
    devices.push(out2);
    const in2 = { ...createDevice("switch", 600, 136, devices), name: "inside 스위치 2" };
    devices.push(in2);
    const id = (n: string) => devices.find((d) => d.name === n)!.id;
    const cables = base.cables.filter((c) => ![c.a.device, c.b.device].includes(id("방화벽 B")));
    cables.push(
      { id: "b0", a: { device: out2.id, port: 1 }, b: { device: id("방화벽 B"), port: 0 } },
      { id: "b1", a: { device: id("방화벽 B"), port: 1 }, b: { device: in2.id, port: 1 } },
      { id: "j0", a: { device: out2.id, port: 7 }, b: { device: id("outside 스위치"), port: 7 } },
      { id: "j1", a: { device: in2.id, port: 7 }, b: { device: id("inside 스위치"), port: 7 } },
    );
    const t: Topology = { devices, cables };
    const x = load(t);
    expect(masters(x)).toEqual(["방화벽 A"]);
    const split: Topology = { ...t, cables: t.cables.filter((c) => c.id !== "j0" && c.id !== "j1") };
    x.apply(setL3(split, "방화벽 B", (l) => ({ ...l, ha: { ...l.ha!, priority: 101 } }))); // 갈라진 채 B 가 다시 시작 → B 도 master
    expect(masters(x).sort()).toEqual(["방화벽 A", "방화벽 B"]);
    x.apply(setL3(t, "방화벽 B", (l) => ({ ...l, ha: { ...l.ha!, priority: 101 } })));
    expect(masters(x)).toEqual(["방화벽 A"]);
  });

  it("리뷰: 서로 다른 쌍이 같은 그룹 번호를 쓰면 구성 검사가 '다른 번호' 를 안내한다", () => {
    const base = exampleHaTopology();
    const devices = [...base.devices];
    const mk = (name: string, ip: string, prio: number) => {
      const d = { ...createDevice("nat", 700, -24, devices), name };
      d.l3 = { interfaces: [{ ipMode: "static", ip, prefix: 24, gateway: "203.0.113.1" }, { ipMode: "static", ip: prio === 200 ? "10.0.0.2" : "10.0.0.3", prefix: 24, gateway: "" }], routes: [], ha: { enabled: true, vrid: 10, priority: prio, vips: ["203.0.113.20", "10.0.0.1"] } };
      devices.push(d);
      return d;
    };
    const c = mk("방화벽 C", "203.0.113.21", 200);
    const d = mk("방화벽 D", "203.0.113.22", 100);
    const sw = base.devices.find((x) => x.name === "outside 스위치")!;
    const cables = [...base.cables, { id: "c0", a: { device: sw.id, port: 0 }, b: { device: c.id, port: 0 } }, { id: "d0", a: { device: sw.id, port: 2 }, b: { device: d.id, port: 0 } }];
    const codes = lintTopology({ devices, cables }).map((i) => i.code);
    expect(codes).toContain("ha.vrid-shared");
    expect(codes).not.toContain("ha.vip-mismatch");
  });

  it("리뷰: 이중화 쌍의 WireGuard 터널은 가상 주소로 나가고, master 가 사라져도 상대가 이어서 답한다 (구성 검사도 조용)", () => {
    const base = exampleVpnTopology();
    const devices = base.devices.map((d) =>
      d.name === "사무실 A NAT"
        ? { ...d, l3: { ...d.l3!, interfaces: [{ ipMode: "static" as const, ip: "203.0.113.13", prefix: 24, gateway: "" }, { ipMode: "static" as const, ip: "192.168.1.2", prefix: 24, gateway: "" }], ha: { enabled: true, vrid: 1, priority: 200, vips: ["203.0.113.11", "192.168.1.1"] } } }
        : d,
    );
    const a1 = devices.find((d) => d.name === "사무실 A NAT")!;
    const a2 = { ...createDevice("nat", 60, 48, devices), name: "사무실 A NAT 2" };
    a2.l3 = { ...a1.l3!, interfaces: [{ ipMode: "static", ip: "203.0.113.14", prefix: 24, gateway: "" }, { ipMode: "static", ip: "192.168.1.3", prefix: 24, gateway: "" }], ha: { ...a1.l3!.ha!, priority: 100 } };
    devices.push(a2);
    const isp = devices.find((d) => d.name === "통신사 구간")!;
    const swA = devices.find((d) => d.name === "sw-a")!;
    const t: Topology = { devices, cables: [...base.cables, { id: "a20", a: { device: isp.id, port: 2 }, b: { device: a2.id, port: 0 } }, { id: "a21", a: { device: a2.id, port: 1 }, b: { device: swA.id, port: 5 } }] };
    expect(lintTopology(t).map((i) => i.code)).not.toContain("vpn.shared-peer");
    const x = load(t);
    const tr = x.act({ kind: "ping", nodeId: x.id("pc-a"), dst: "192.168.2.10" });
    expect(x.host("pc-a").pings.at(-1)!.status).toBe("ok");
    expect(tr.find((e) => e.kind === "vpn.encap")!.summary).toContain("203.0.113.11:51820");
    x.apply({ ...t, devices: t.devices.filter((d) => d.id !== a1.id), cables: t.cables.filter((c) => c.a.device !== a1.id && c.b.device !== a1.id) });
    x.act({ kind: "ping", nodeId: x.id("pc-b"), dst: "192.168.1.10" });
    expect(x.host("pc-b").pings.at(-1)!.status).toBe("ok");
  });

  it("리뷰: RIP 와 함께 쓰면 master 가 넥스트 홉으로 가상 주소를 알려, 넘어가도 돌아오는 경로가 이어진다", () => {
    const devices: Device[] = [];
    const add = (kind: Parameters<typeof createDevice>[0], name: string) => {
      const d = { ...createDevice(kind, 0, 0, devices), name };
      devices.push(d);
      return d;
    };
    const iface = (ip: string, gateway = "") => ({ ipMode: "static" as const, ip, prefix: 24, gateway });
    const rip = { enabled: true, defaultRoute: false };
    const r = add("gateway", "R");
    r.l3 = { interfaces: [iface("10.0.0.1"), iface("10.9.0.1"), iface("")], routes: [], rip };
    const core = add("switch", "core");
    const ga = add("gateway", "GA");
    ga.l3 = { interfaces: [iface("10.0.0.2"), iface("192.168.0.2"), iface("")], routes: [], rip, ha: { enabled: true, vrid: 5, priority: 200, vips: ["10.0.0.10", "192.168.0.1"] } };
    const gb = add("gateway", "GB");
    gb.l3 = { interfaces: [iface("10.0.0.3"), iface("192.168.0.3"), iface("")], routes: [], rip, ha: { enabled: true, vrid: 5, priority: 100, vips: ["10.0.0.10", "192.168.0.1"] } };
    const inside = add("switch", "inside");
    const pr = add("pc", "pc-r");
    pr.host = { ...pr.host!, ipMode: "static", ip: "10.9.0.10", prefix: 24, gateway: "10.9.0.1" };
    const p1 = add("pc", "pc-1");
    p1.host = { ...p1.host!, ipMode: "static", ip: "192.168.0.10", prefix: 24, gateway: "192.168.0.1" };
    const cable = (id: string, a: Device, ap: number, b: Device, bp: number) => ({ id, a: { device: a.id, port: ap }, b: { device: b.id, port: bp } });
    const t: Topology = { devices, cables: [cable("1", r, 0, core, 0), cable("2", core, 1, ga, 0), cable("3", core, 2, gb, 0), cable("4", ga, 1, inside, 0), cable("5", gb, 1, inside, 1), cable("6", inside, 2, p1, 0), cable("7", r, 1, pr, 0)] };
    const x = load(t);
    x.act({ kind: "ping", nodeId: x.id("pc-r"), dst: "192.168.0.10" });
    expect(x.host("pc-r").pings.at(-1)!.status).toBe("ok");
    x.apply({ ...t, cables: t.cables.filter((c) => c.id !== "2") });
    expect(x.l3("GB").ha.state).toBe("master");
    x.act({ kind: "ping", nodeId: x.id("pc-r"), dst: "192.168.0.10" });
    expect(x.host("pc-r").pings.at(-1)!.status).toBe("ok");
    x.act({ kind: "ping", nodeId: x.id("pc-1"), dst: "10.9.0.10" });
    expect(x.host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("리뷰: 지운 장치를 되돌려도 지우기 전의 타이머가 새 장치에서 발동하지 않는다", () => {
    const t = exampleHaTopology();
    const s = new NetworkSync();
    s.sync(t);
    s.net.runUntil(1500);
    const idA = t.devices.find((d) => d.name === "방화벽 A")!.id;
    s.sync({ ...t, devices: t.devices.filter((d) => d.id !== idA), cables: t.cables.filter((c) => c.a.device !== idA && c.b.device !== idA) });
    s.net.runUntil(1800);
    const from = s.net.trace.length;
    s.sync(t);
    s.net.runToIdle();
    const aUp = s.net.trace.slice(from).find((e) => e.kind === "ha.master" && e.nodeId === idA)!;
    expect(aUp.time).toBeGreaterThanOrEqual(1800 + 200);
    expect(aUp.time).not.toBe(3219);
  });
});
