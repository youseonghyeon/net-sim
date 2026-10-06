// IGMP 스누핑: 가입(Report)을 엿들어 멀티캐스트 스트림을 가입한 포트로만
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleIgmpTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Topology } from "../src/model/topology";
import type { Switch } from "../src/core/nodes/switch";

const G = "239.1.1.1";
const snoop = (t: Topology, on: boolean): Topology => ({ ...t, devices: t.devices.map((d) => (d.kind === "switch" ? { ...d, switch: { ...d.switch!, igmpSnooping: on } } : d)) });
/** 송출한 스트림이 도착한 장치 이름들 (그 장치의 링크에 실린 것) */
const reached = (L: ReturnType<typeof loadTopology>, from: number) =>
  new Set(
    [...L.s.net.frameLog.values()]
      .flat()
      .filter((x) => x.frame.payload.kind === "ipv4" && x.frame.payload.payload.kind === "udp" && x.frame.payload.payload.payload.kind === "mcast" && x.departAt >= from)
      .map((x) => L.t.devices.find((d) => d.id === x.to)!)
      .filter((d) => d.kind !== "switch")
      .map((d) => d.name),
  );

describe("IGMP 스누핑", () => {
  it("스누핑이 없으면 TV 만 가입해도 스트림이 모든 포트로, 받는 건 TV 뿐", () => {
    const L = loadTopology(exampleIgmpTopology());
    expect(lintTopology(L.t)).toEqual([]);
    L.act({ kind: "mcast-join", nodeId: L.id("거실 TV"), group: G });
    const t0 = L.s.net.now;
    const tr = L.act({ kind: "mcast-send", nodeId: L.id("IPTV 서버"), group: G });
    const r = reached(L, t0);
    expect(r.has("안방 PC") && r.has("노트북") && r.has("거실 TV")).toBe(true);
    expect(tr.filter((e) => e.kind === "mcast.recv").map((e) => L.t.devices.find((d) => d.id === e.nodeId)!.name)).toEqual(Array(5).fill("거실 TV"));
    expect(L.host("거실 TV").streamRx.get(G)).toBe(5);
  });

  it("스누핑을 켜면 가입한 TV 포트로만, 탈퇴하면 아무 데도", () => {
    const L = loadTopology(snoop(exampleIgmpTopology(), true));
    L.act({ kind: "mcast-join", nodeId: L.id("거실 TV"), group: G });
    expect(L.node<Switch>("거실 스위치").snapshot().tables.find((x) => x.title.startsWith("IGMP"))!.rows[0]![2]).toBe("eth4");
    let t0 = L.s.net.now;
    L.act({ kind: "mcast-send", nodeId: L.id("IPTV 서버"), group: G });
    expect([...reached(L, t0)]).toEqual(["거실 TV"]);
    L.act({ kind: "mcast-leave", nodeId: L.id("거실 TV"), group: G });
    t0 = L.s.net.now;
    const tr = L.act({ kind: "mcast-send", nodeId: L.id("IPTV 서버"), group: G });
    expect(reached(L, t0).size).toBe(0);
    expect(tr.some((e) => e.kind === "igmp.snoop" && e.summary.includes("가입한 포트가 없음"))).toBe(true);
  });
});
