// 드롭인 게이트웨이: 기존 LAN 에 WAN 만 꽂은 Brume 이 그 LAN 기기의 게이트웨이가 된다 (한 팔 라우터 + NAT)
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleDropInTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Topology } from "../src/model/topology";

describe("드롭인 게이트웨이", () => {
  it("아이 PC(게이트웨이 = Brume)만 Brume 의 DPI 에 걸리고, 아빠 PC 는 기존 공유기로 바로", () => {
    const L = loadTopology(exampleDropInTopology());
    expect(lintTopology(L.t)).toEqual([]);
    let tr = L.act({ kind: "tcp-connect", nodeId: L.id("아이 PC"), dst: "roblox.com", port: 443 });
    expect(L.lastConn("아이 PC").state).toBe("FAILED");
    expect(tr.some((e) => e.kind === "dpi.block" && e.summary.includes("Roblox"))).toBe(true);
    expect(tr.some((e) => e.kind === "ip.forward" && e.summary.includes("드롭인 게이트웨이"))).toBe(true);
    tr = L.act({ kind: "tcp-connect", nodeId: L.id("아빠 PC"), dst: "roblox.com", port: 443 });
    expect(L.lastConn("아빠 PC").state).toBe("CLOSED");
    expect(tr.some((e) => e.nodeId === L.id("Brume 3 (드롭인)") && e.kind === "ip.forward")).toBe(false);
  });

  it("막지 않는 곳은 Brume 을 거쳐 NAT 되어 돌아온다 (ping 8.8.8.8 — 응답이 WAN 쪽 기기로 되돌아감)", () => {
    const L = loadTopology(exampleDropInTopology());
    const tr = L.act({ kind: "ping", nodeId: L.id("아이 PC"), dst: "8.8.8.8" });
    expect(L.host("아이 PC").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.nodeId === L.id("Brume 3 (드롭인)") && e.kind === "nat.translate")).toBe(true);
    expect(tr.some((e) => e.summary.includes("WAN 인터페이스로 되돌려 전달"))).toBe(true);
  });

  it("드롭인을 끄면 Brume 은 자기 주소가 아닌 패킷을 버린다 (아이 PC 는 인터넷에 못 나감)", () => {
    const base = exampleDropInTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.router?.dropIn ? { ...d, router: { ...d.router, dropIn: false } } : d)) };
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id("아이 PC"), dst: "8.8.8.8" });
    expect(L.host("아이 PC").pings.at(-1)!.status).toBe("failed");
  });

  it("드롭인으로 오는 기기도 기기 차단(MAC)이 걸린다", () => {
    const base = exampleDropInTopology();
    const kid = base.devices.find((d) => d.name === "아이 PC")!;
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.router?.dropIn ? { ...d, router: { ...d.router, blocked: [kid.mac] } } : d)) };
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id("아이 PC"), dst: "8.8.8.8" });
    expect(L.host("아이 PC").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.kind === "fw.deny" && e.summary.includes("기기 차단"))).toBe(true);
  });
});
