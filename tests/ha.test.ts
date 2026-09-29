// 이중화 (VRRP 식): 우선순위로 master 선출, 가상 주소·가상 MAC, 링크 다운·장치 제거 시 backup 이 이어받음, 복구되면 preempt
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { L3Node } from "../src/core/nodes/l3";
import { lintTopology } from "../src/model/lint";
import { NetworkSync } from "../src/model/netSync";
import { exampleHaTopology } from "../src/model/examples";
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
});
