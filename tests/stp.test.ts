// STP: 루트 선출, 한 포트 차단으로 루프 제거, 링크가 끊기면 막았던 포트가 열려 다른 길로
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { Switch } from "../src/core/nodes/switch";
import { lintTopology } from "../src/model/lint";
import { NetworkSync } from "../src/model/netSync";
import { exampleStpTopology } from "../src/model/examples";
import { createDevice, type Device, type Topology } from "../src/model/topology";

function load(t: Topology = exampleStpTopology()) {
  const s = new NetworkSync();
  s.sync(t);
  s.net.runToIdle();
  const id = (name: string) => t.devices.find((d) => d.name === name)!.id;
  const host = (name: string) => s.net.nodes.get(id(name)) as Host;
  const sw = (name: string) => s.net.nodes.get(id(name)) as Switch;
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
  return { s, t, id, host, sw, act, apply };
}

describe("STP", () => {
  it("core-1 이 루트, access-1 의 core-2 쪽 포트가 대체 포트(차단), 루프 없이 ping 이 간다", () => {
    const { t, id, host, sw, act, s } = load();
    expect(lintTopology(t)).toEqual([]);
    expect(sw("core-1").stp.isRoot).toBe(true);
    expect(sw("core-2").stp.roles[0]).toBe("root");
    expect(sw("access-1").stp.roles[1]).toBe("root");
    expect(sw("access-1").stp.roles[6]).toBe("alternate");
    expect(sw("core-2").stp.roles[2]).toBe("designated");
    const tr = act({ kind: "ping", nodeId: id("pc-1"), dst: "192.168.0.21" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "switch.loop")).toBe(false);
    expect(s.net.trace.length).toBeLessThan(3000);
  });

  it("쓰던 링크(core-1 ↔ access-1)를 지우면 대체 포트가 루트 포트가 되어 다른 길로 간다", () => {
    const x = load();
    const c1 = x.id("core-1");
    const ac = x.id("access-1");
    const tr = x.apply({ ...x.t, cables: x.t.cables.filter((c) => !([c.a.device, c.b.device].includes(c1) && [c.a.device, c.b.device].includes(ac))) });
    expect(x.sw("access-1").stp.roles[6]).toBe("root");
    expect(tr.some((e) => e.kind === "stp.tc")).toBe(true);
    x.act({ kind: "ping", nodeId: x.id("pc-1"), dst: "192.168.0.21" });
    expect(x.host("pc-1").pings.at(-1)!.status).toBe("ok");
    x.act({ kind: "ping", nodeId: x.id("pc-1"), dst: "192.168.0.22" });
    expect(x.host("pc-1").pings.at(-1)!.status).toBe("ok");
    // 되돌리면 다시 막힌다
    x.apply(x.t);
    expect(x.sw("access-1").stp.roles[6]).toBe("alternate");
  });

  it("루트 스위치를 지우면 다음으로 작은 core-2 가 루트가 되고 (Message Age 로 옛 정보가 끝나고) 통신이 이어진다", () => {
    const x = load();
    const c1 = x.id("core-1");
    x.apply({ ...x.t, devices: x.t.devices.filter((d) => d.id !== c1), cables: x.t.cables.filter((c) => c.a.device !== c1 && c.b.device !== c1) });
    expect(x.sw("core-2").stp.isRoot).toBe(true);
    expect(x.sw("access-1").stp.roles[6]).toBe("root");
    x.act({ kind: "ping", nodeId: x.id("pc-1"), dst: "192.168.0.21" });
    expect(x.host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("STP 를 끄면 루프가 생겨 브로드캐스트가 돌다가 안전장치(switch.loop)에 걸린다 — 구성 검사가 경고한다", () => {
    const base = exampleStpTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.switch ? { ...d, switch: { ...d.switch, stp: { enabled: false, priority: 32768 } } } : d)) };
    expect(lintTopology(t).map((i) => i.code)).toContain("switch.loop-no-stp");
    const { id, act } = load(t);
    const tr = act({ kind: "ping", nodeId: id("pc-1"), dst: "192.168.0.21" });
    expect(tr.some((e) => e.kind === "switch.loop")).toBe(true);
  });

  // ---------- 리뷰에서 나온 경우들 ----------
  /** 이름·종류·STP 우선순위로 장비를 만들고 케이블을 잇는 작은 조립기 */
  function build(spec: { sw: [string, number | undefined][]; hubs?: string[]; hosts?: [string, string][]; cables: [string, number, string, number][] }): Topology {
    const devices: Device[] = [];
    for (const [name, prio] of spec.sw) {
      const d = { ...createDevice("switch", 0, 0, devices), name };
      d.switch = { vlans: {}, ...(prio !== undefined ? { stp: { enabled: true, priority: prio } } : {}) };
      devices.push(d);
    }
    for (const name of spec.hubs ?? []) devices.push({ ...createDevice("hub", 0, 0, devices), name });
    for (const [name, ip] of spec.hosts ?? []) {
      const d = { ...createDevice("pc", 0, 0, devices), name };
      d.host = { ...d.host!, ipMode: "static", ip, prefix: 24, gateway: "" };
      devices.push(d);
    }
    const id = (n: string) => devices.find((d) => d.name === n)!.id;
    return { devices, cables: spec.cables.map(([a, ap, b, bp], k) => ({ id: `c${k}`, a: { device: id(a), port: ap }, b: { device: id(b), port: bp } })) };
  }

  it("리뷰: 허브 한 대에 STP 스위치 셋이 물려도 수렴한다 (더 나쁜 정보로 덮어쓰지 않음)", () => {
    const t = build({ sw: [["x", 4096], ["y", 32768], ["z", 32768]], hubs: ["hub"], cables: [["x", 0, "hub", 0], ["y", 0, "hub", 1], ["z", 0, "hub", 2]] });
    const x = load(t); // runToIdle 가 한도에 걸리면 예외
    expect(x.sw("x").stp.isRoot).toBe(true);
    expect(x.sw("y").stp.roles[0]).toBe("root");
    expect(x.s.net.trace.length).toBeLessThan(500);
  });

  it("리뷰: 경로가 바뀌면 Topology Change 가 퍼져 다른 스위치도 MAC 테이블을 비워, 트래픽이 바로 새 길로 간다", () => {
    const t = build({
      sw: [["s0", 4096], ["s1", 32768], ["s2", 32768]],
      hosts: [["h1", "10.0.0.1"], ["h2", "10.0.0.2"]],
      cables: [["s0", 0, "s1", 0], ["s0", 1, "s2", 0], ["s1", 1, "s2", 1], ["s1", 5, "h1", 0], ["s2", 5, "h2", 0]],
    });
    const x = load(t);
    x.act({ kind: "ping", nodeId: x.id("h1"), dst: "10.0.0.2" });
    const tr = x.apply({ ...t, cables: t.cables.filter((c) => c.id !== "c1") }); // s0–s2 제거
    expect(tr.filter((e) => e.kind === "stp.tc").map((e) => e.nodeId).sort()).toEqual([x.id("s0"), x.id("s1"), x.id("s2")].sort());
    x.act({ kind: "ping", nodeId: x.id("h1"), dst: "10.0.0.2" });
    expect(x.host("h1").pings.at(-1)!.status).toBe("ok");
  });

  it("리뷰: STP 를 한 번도 안 켠 스위치는 설정을 바꿔도 BPDU·STP 로그를 내지 않는다", () => {
    const base = exampleStpTopology();
    const plain = { ...createDevice("switch", 0, 0, base.devices), name: "plain" };
    const t: Topology = { devices: [...base.devices, plain], cables: [...base.cables, { id: "p0", a: { device: plain.id, port: 0 }, b: { device: base.devices.find((d) => d.name === "core-2")!.id, port: 5 } }] };
    const x = load(t);
    const tr = x.apply({ ...t, devices: t.devices.map((d) => (d.id === plain.id ? { ...d, switch: { vlans: { 3: 20 } } } : d)) });
    expect(tr.some((e) => e.nodeId === plain.id && e.kind.startsWith("stp."))).toBe(false);
    expect(x.sw("core-1").stp.isRoot).toBe(true);
  });

  it("리뷰: 루트 스위치가 STP 를 끄면 이웃에게 정보를 거두라고 알려, 남은 스위치들이 새 루트를 뽑는다", () => {
    const x = load();
    x.apply({ ...x.t, devices: x.t.devices.map((d) => (d.name === "core-1" ? { ...d, switch: { vlans: {}, stp: { enabled: false, priority: 4096 } } } : d)) });
    expect(x.sw("core-2").stp.isRoot).toBe(true);
  });

  it("리뷰: 허브 너머의 루트를 지워도(허브는 링크 변화를 전하지 않음) 거둠 BPDU 로 새 루트를 뽑는다", () => {
    const t = build({ sw: [["x", 4096], ["y", 32768]], hubs: ["hub"], cables: [["x", 0, "hub", 0], ["y", 0, "hub", 1], ["x", 1, "y", 1]] });
    const x = load(t);
    expect(x.sw("x").stp.isRoot).toBe(true);
    const xid = x.id("x");
    x.apply({ ...t, devices: t.devices.filter((d) => d.id !== xid), cables: t.cables.filter((c) => c.a.device !== xid && c.b.device !== xid) });
    expect(x.sw("y").stp.isRoot).toBe(true);
  });

  it("리뷰: 구성 검사는 고리에 실제로 속한 스위치만, 공유기 LAN 두 포트로 만든 고리도 잡는다", () => {
    const base = exampleStpTopology();
    const plain = { ...createDevice("switch", 0, 0, base.devices), name: "leaf" };
    const leafT: Topology = { devices: [...base.devices, plain], cables: [...base.cables, { id: "l0", a: { device: plain.id, port: 0 }, b: { device: base.devices.find((d) => d.name === "access-1")!.id, port: 7 } }] };
    expect(lintTopology(leafT).map((i) => i.code)).not.toContain("switch.loop-no-stp");
    const devices: Device[] = [];
    const rt = { ...createDevice("router", 0, 0, devices), name: "rt" };
    devices.push(rt);
    const sw = { ...createDevice("switch", 0, 0, devices), name: "sw" };
    devices.push(sw);
    const loopT: Topology = { devices, cables: [{ id: "r1", a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 0 } }, { id: "r2", a: { device: rt.id, port: 2 }, b: { device: sw.id, port: 1 } }] };
    expect(lintTopology(loopT).map((i) => i.code)).toContain("switch.loop-no-stp");
  });

  it("리뷰: 그물(스위치 6대 풀 메시)에서 루트를 지워도 BPDU 가 모아 보내져 이벤트가 과하지 않다", () => {
    const names = ["m0", "m1", "m2", "m3", "m4", "m5"];
    const cables: [string, number, string, number][] = [];
    for (let i = 0; i < names.length; i++) for (let j = i + 1; j < names.length; j++) cables.push([names[i]!, j - 1 < 0 ? 0 : j - 1, names[j]!, i]);
    const t = build({ sw: names.map((n, i) => [n, i === 0 ? 4096 : 32768] as [string, number]), cables });
    const x = load(t);
    const from = x.s.net.trace.length;
    const m0 = x.id("m0");
    x.apply({ ...t, devices: t.devices.filter((d) => d.id !== m0), cables: t.cables.filter((c) => c.a.device !== m0 && c.b.device !== m0) });
    expect(x.s.net.trace.length - from).toBeLessThan(4000);
    expect(names.slice(1).filter((n) => x.sw(n).stp.isRoot)).toHaveLength(1);
  });
});
