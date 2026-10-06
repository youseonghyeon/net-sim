// DDNS 리뷰(2026-10-07) 회귀 테스트 — 리뷰어 재현을 그대로 둠
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleDdnsTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";
const log = (..._a: unknown[]): void => {};

const fmt = (tr: { nodeId: string; kind: string; summary: string }[], f: (k: string) => boolean = () => true) =>
  tr.filter((e) => f(e.kind) && !e.kind.startsWith("frame.") && !e.kind.startsWith("link.") && !e.kind.startsWith("arp.") && !e.kind.startsWith("switch.")).map((e) => `${e.nodeId}:${e.kind} ${e.summary}`).join("\n");

type R = NonNullable<Topology["devices"][number]["router"]>;
const setR = (t: Topology, name: string, f: (r: R) => R): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? { ...d, router: f(d.router!) } : d)) });

describe("transient DNS failure during reresolve", () => {
  it("phone loses endpoint for good after one failed reresolve", () => {
    const base = exampleDdnsTopology();
    const L = loadTopology(base);
    expect(L.host("카페 폰").ra.state).toBe("up");
    // home WG server down + cafe DNS forwarder down (both transient)
    let t1 = setR(base, "집 Brume 3", (r) => ({ ...r, wgServer: { ...r.wgServer!, enabled: false } }));
    t1 = setR(t1, "카페 공유기", (r) => ({ ...r, dns: { enabled: false, upstream: "" } }));
    L.apply(t1);
    const from = L.s.net.trace.length;
    L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "192.168.8.20" });
    L.s.net.runUntil(L.s.net.now + 60_000);
    log("outage:\n" + fmt(L.s.net.trace.slice(from), (k) => k.startsWith("vpn") || k.startsWith("dns")));
    // everything back
    L.apply(base);
    L.s.net.runUntil(L.s.net.now + 5_000);
    const tr = L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "192.168.8.20" });
    log("after recovery:\n" + fmt(tr, (k) => k.startsWith("vpn") || k.startsWith("ping") || k.startsWith("dns")));
    L.s.net.runUntil(L.s.net.now + 30_000);
    const tr2 = L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "192.168.8.20" });
    log("later:\n" + fmt(tr2, (k) => k.startsWith("vpn") || k.startsWith("ping")));
    expect(L.host("카페 폰").pings.at(-1)!.status).toBe("ok");
  });
});
