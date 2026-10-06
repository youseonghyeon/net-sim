// DDNS 리뷰(2026-10-07) 회귀 테스트 — 리뷰어 재현을 그대로 둠
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleWireguardTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import type { Topology } from "../src/model/topology";
const log = (..._a: unknown[]): void => {};

const fmt = (tr: { nodeId: string; kind: string; summary: string }[], f: (k: string) => boolean = () => true) =>
  tr.filter((e) => f(e.kind) && !e.kind.startsWith("frame.") && !e.kind.startsWith("link.") && !e.kind.startsWith("arp.") && !e.kind.startsWith("switch.")).map((e) => `${e.nodeId}:${e.kind} ${e.summary}`).join("\n");

type R = NonNullable<Topology["devices"][number]["router"]>;
const setR = (t: Topology, name: string, f: (r: R) => R): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? { ...d, router: f(d.router!) } : d)) });

function routerByName(ddnsOn: boolean): Topology {
  let t = exampleWireguardTopology();
  t = setR(t, "집 Brume 3", (r) => ({ ...r, wan: { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" }, ddns: { enabled: ddnsOn, name: "myhome" } }));
  t = setR(t, "여행용 공유기", (r) => ({ ...r, wgClient: { ...r.wgClient!, server: "myhome.glddns.com" } }));
  t = { ...t, devices: t.devices.map((d) => (d.name === "출장 폰" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, server: "myhome.glddns.com" } } } : d)) };
  return t;
}

describe("router WG client by name", () => {
  it("works when DDNS is on", () => {
    const t = routerByName(true);
    log("lint", lintTopology(t).map((i) => i.code));
    const L = loadTopology(t);
    log("travel:", L.node<Router>("여행용 공유기").wgClientSummary());
    L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "192.168.8.20" });
    expect(L.host("여행 노트북").pings.at(-1)!.status).toBe("ok");
  });

  it("name unknown at start, DDNS enabled later → router client never retries on traffic", () => {
    const on = routerByName(true);
    const off = setR(on, "집 Brume 3", (r) => ({ ...r, ddns: { enabled: false, name: "myhome" } }));
    const L = loadTopology(off);
    log("travel:", L.node<Router>("여행용 공유기").wgClientSummary());
    L.apply(on);
    L.s.net.runUntil(L.s.net.now + 60_000);
    const tr = L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "192.168.8.20" });
    log(fmt(tr, (k) => k.startsWith("vpn") || k.startsWith("ping")).split("\n").slice(0, 6).join("\n"));
    expect(L.host("여행 노트북").pings.at(-1)!.status).toBe("ok");
  });
});
