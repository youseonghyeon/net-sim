// DDNS 리뷰(2026-10-07) 회귀 테스트 — 리뷰어 재현을 그대로 둠
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleDdnsTopology } from "../src/model/examples";
import type { Router } from "../src/core/nodes/router";
import type { Internet } from "../src/core/nodes/internet";
import type { Topology } from "../src/model/topology";
const log = (..._a: unknown[]): void => {};

const fmt = (tr: { nodeId: string; kind: string; summary: string }[], f: (k: string) => boolean = () => true) =>
  tr.filter((e) => f(e.kind) && !e.kind.startsWith("frame.") && !e.kind.startsWith("link.") && !e.kind.startsWith("arp.") && !e.kind.startsWith("switch.")).map((e) => `${e.nodeId}:${e.kind} ${e.summary}`).join("\n");

type R = NonNullable<Topology["devices"][number]["router"]>;
const setR = (t: Topology, name: string, f: (r: R) => R): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? { ...d, router: f(d.router!) } : d)) });

describe("DDNS client state machine", () => {
  it("WAN link goes down while an update is pending → client stuck (pending never cleared)", () => {
    const base = exampleDdnsTopology();
    const L = loadTopology(base);
    const { s } = L;
    const home = L.node<Router>("집 Brume 3");
    const hid = L.id("집 Brume 3");
    const wanCable = base.cables.find((c) => (c.a.device === hid && c.a.port === 0) || (c.b.device === hid && c.b.port === 0))!;
    const renamed = setR(base, "집 Brume 3", (r) => ({ ...r, ddns: { enabled: true, name: "myhome2" } }));
    const lossy: Topology = { ...renamed, cables: renamed.cables.map((c) => (c === wanCable ? { ...c, loss: 1 } : c)) };
    const from = s.net.trace.length;
    s.sync(lossy);
    s.net.runUntil(s.net.now + 500);
    // unplug WAN while the update waits for its answer
    s.sync({ ...renamed, cables: renamed.cables.filter((c) => c !== wanCable) });
    s.net.runToIdle();
    // plug back (no loss)
    s.sync(renamed);
    s.net.runToIdle();
    s.net.runUntil(s.net.now + 11 * 60_000);
    log(fmt(s.net.trace.slice(from), (k) => k.startsWith("ddns") || k.startsWith("dhcp.bound")));
    log("state", home.ddns.state, home.ddns.summary(), "server:", L.node<Internet>("internet-1").ddns.lookup("myhome2.glddns.com"));
    expect(home.ddns.state).toBe("ok");
  });

  it("badauth: the winner is deleted from the topology → loser never succeeds (and lint is clean)", () => {
    const base = exampleDdnsTopology();
    const t = setR(base, "카페 공유기", (r) => ({ ...r, ddns: { enabled: true, name: "myhome" } }));
    const L = loadTopology(t);
    const cafe = L.node<Router>("카페 공유기");
    const home = L.node<Router>("집 Brume 3");
    const loserName = cafe.ddns.state === "failed" ? "카페 공유기" : "집 Brume 3";
    const winnerName = loserName === "카페 공유기" ? "집 Brume 3" : "카페 공유기";
    log("loser:", loserName);
    // user follows the lint advice: turn DDNS off on the winner
    const t2 = setR(t, winnerName, (r) => ({ ...r, ddns: { enabled: false, name: "myhome" } }));
    L.apply(t2);
    L.s.net.runUntil(L.s.net.now + 11 * 60_000);
    const loser = loserName === "카페 공유기" ? cafe : home;
    log("loser state", loser.ddns.state, loser.ddns.reason);
    void home;
    expect(loser.ddns.state).toBe("ok");
  });
});
