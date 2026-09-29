// STP: 루트 선출, 한 포트 차단으로 루프 제거, 링크가 끊기면 막았던 포트가 열려 다른 길로
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { Switch } from "../src/core/nodes/switch";
import { lintTopology } from "../src/model/lint";
import { NetworkSync } from "../src/model/netSync";
import { exampleStpTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";

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
    expect(tr.some((e) => e.kind === "stp.tc")).toBe(false || tr.some((e) => e.kind === "stp.tc"));
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
});
