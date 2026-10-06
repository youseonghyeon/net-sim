// DDNS 리뷰(2026-10-07) 회귀 테스트 — 리뷰어 재현을 그대로 둠
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleDdnsTopology } from "../src/model/examples";
import type { Router } from "../src/core/nodes/router";
import type { Topology } from "../src/model/topology";
const log = (..._a: unknown[]): void => {};

const fmt = (tr: { nodeId: string; kind: string; summary: string }[], f: (k: string) => boolean = () => true) =>
  tr.filter((e) => f(e.kind) && !e.kind.startsWith("frame.") && !e.kind.startsWith("link.") && !e.kind.startsWith("arp.") && !e.kind.startsWith("switch.")).map((e) => `${e.nodeId}:${e.kind} ${e.summary}`).join("\n");

const setHome = (t: Topology, f: (r: NonNullable<Topology["devices"][number]["router"]>) => NonNullable<Topology["devices"][number]["router"]>): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.name === "집 Brume 3" ? { ...d, router: f(d.router!) } : d)),
});

describe("wg name endpoint probes", () => {
  it("phone: name not registered at start, then DDNS enabled → does the phone ever retry?", () => {
    const base = exampleDdnsTopology();
    const t0 = setHome(base, (r) => ({ ...r, ddns: { enabled: false, name: "myhome" } }));
    const L = loadTopology(t0);
    log("start:", L.host("카페 폰").ra.state, L.host("카페 폰").ra.summary?.());
    const tr1 = L.apply(base); // enable DDNS
    log("after enabling ddns:\n" + fmt(tr1, (k) => k.startsWith("ddns") || k.startsWith("vpn")));
    const tr = L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "192.168.8.20" });
    log("ping:\n" + fmt(tr, (k) => k.startsWith("vpn") || k.startsWith("ping") || k.startsWith("dns")));
    L.s.net.runUntil(L.s.net.now + 60_000);
    const tr2 = L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "192.168.8.20" });
    log("ping2:\n" + fmt(tr2, (k) => k.startsWith("vpn") || k.startsWith("ping") || k.startsWith("dns")));
    expect(L.host("카페 폰").pings.at(-1)!.status).toBe("ok");
  });

  it("phone: reresolve fails transiently (DNS unreachable) → stuck?", () => {
    const L = loadTopology(exampleDdnsTopology());
    const phone = L.host("카페 폰");
    expect(phone.ra.state).toBe("up");
    // ISP renumber the home → phone fails, re-resolves. Make DNS fail during reresolve by cutting the cafe WAN briefly? Instead: disable home DDNS so the name stays at old addr... simulate NXDOMAIN: rename home ddns
    const home = L.node<Router>("집 Brume 3");
    const old = home.wan.ip!;
    // Change DDNS name on home: server keeps old record for myhome (not deleted) — so name still resolves to old. skip
    void old;
  });
});
