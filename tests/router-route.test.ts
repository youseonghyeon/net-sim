// 공유기 경로 판단: WAN 과 LAN 이 같은 대역(공유기 뒤 공유기를 둘 다 192.168.0.x)이면 디폴트 라우트를 못 써 인터넷이 안 된다.
// DHCP 는 공유기 자신의 WAN 주소를 LAN 기기에 빌려주지 않는다
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { builder, cable } from "../src/model/examples/build";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import type { Topology } from "../src/model/topology";

/** 사용자 보고 구성 (net-sim-2026-10-08.json): internet → rt-1 → rt-2(WAN 자동) → srv-1(DHCP). 두 공유기 LAN 이 모두 192.168.0.1/24 */
function doubleRouter(rt2Lan = "192.168.0.1"): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 0, -300);
  const rt1 = add("router", 0, -150);
  const rt2 = add("router", 0, 0);
  rt2.router = { ...rt2.router!, lanIp: rt2Lan, lanPrefix: 24, dhcp: { enabled: true, start: rt2Lan.replace(/\.1$/, ".2"), end: rt2Lan.replace(/\.1$/, ".253") } };
  rt1.router = { ...rt1.router!, lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.2", end: "192.168.0.253" } };
  const srv = add("server", 0, 150);
  return { devices, cables: [cable(inet, 0, rt1, 0), cable(rt2, 0, rt1, 1), cable(srv, 0, rt2, 1)] };
}
const codes = (t: Topology) => lintTopology(t).map((i) => `${t.devices.find((d) => d.id === i.deviceId)!.name}:${i.code}`);

describe("공유기 경로 판단 (WAN·LAN 같은 대역)", () => {
  it("rt-2 의 WAN 이 rt-1 에게 192.168.0.x 를 받으면 넥스트 홉 192.168.0.1 이 내 LAN 주소 → srv-1 의 인터넷 ping 은 No route", () => {
    const L = loadTopology(doubleRouter());
    const rt2 = L.node<Router>("rt-2");
    expect(rt2.wan.ip).toMatch(/^192\.168\.0\./);
    expect(rt2.defaultRouteProblem()).toContain("내 LAN 주소");
    const tr = L.act({ kind: "ping", nodeId: L.id("srv-1"), dst: "8.8.8.8" });
    expect(L.host("srv-1").pings.at(-1)!.status).toBe("failed");
    const noRoute = tr.find((e) => e.nodeId === L.id("rt-2") && e.kind === "ip.no-route");
    expect(noRoute?.summary).toMatch(/넥스트 홉 192\.168\.0\.1 가 내 LAN 주소/);
    // NAT 를 거치지 않고(매핑을 만들지 않고) 보낸 이에게 Destination Unreachable
    expect(tr.some((e) => e.nodeId === L.id("rt-2") && e.kind === "nat.translate")).toBe(false);
    expect(tr.some((e) => e.nodeId === L.id("srv-1") && e.kind === "icmp.unreachable.received")).toBe(true);
    expect(tr.some((e) => e.nodeId === L.id("rt-1"))).toBe(false);
  });

  it("공유기 자신이 WAN 으로 보내는 것도 막힌다: DNS 포워더의 업스트림 질의", () => {
    const L = loadTopology(doubleRouter());
    const tr = L.act({ kind: "ping", nodeId: L.id("srv-1"), dst: "google.com" });
    expect(L.host("srv-1").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.nodeId === L.id("rt-2") && e.kind === "ip.no-route" && /8\.8\.8\.8/.test(e.summary) && /내 LAN 주소/.test(e.summary))).toBe(true);
    expect(tr.some((e) => e.nodeId === L.id("rt-1"))).toBe(false);
  });

  it("DHCP 는 공유기 자신의 WAN 주소를 LAN 기기에 빌려주지 않는다 (WAN 주소가 먼저 정해진 경우 — 수동 WAN 192.168.0.2)", () => {
    const t = doubleRouter();
    t.devices = t.devices.map((d) => (d.name === "rt-2" ? { ...d, router: { ...d.router!, wan: { ipMode: "static", ip: "192.168.0.2", prefix: 24, gateway: "192.168.0.1" } } } : d));
    const L = loadTopology(t);
    expect(L.node<Router>("rt-2").wan.ip).toBe("192.168.0.2");
    expect(L.host("srv-1").iface.ip).toBe("192.168.0.3");
  });

  it("구성 검사 router.wan-lan-overlap: WAN 이 받을 대역(rt-1 DHCP)과 LAN 이 같음 → rt-2 LAN 을 바꾸면 사라지고 인터넷이 된다", () => {
    const bad = doubleRouter();
    expect(codes(bad)).toEqual(["rt-2:router.wan-lan-overlap"]);
    const issue = lintTopology(bad)[0]!;
    expect(issue.severity).toBe("error");
    expect(issue.fix).toContain("192.168.1.1");
    const good = doubleRouter("192.168.1.1");
    expect(codes(good)).toEqual([]);
    const L = loadTopology(good);
    expect(L.node<Router>("rt-2").defaultRouteProblem()).toBeUndefined();
    L.act({ kind: "ping", nodeId: L.id("srv-1"), dst: "8.8.8.8" });
    expect(L.host("srv-1").pings.at(-1)!.status).toBe("ok");
  });

  it("구성 검사: 수동 WAN 의 넥스트 홉이 LAN 대역 안이면 error, 대역이 겹쳐도 넥스트 홉이 LAN 밖이면 침묵 (리눅스도 나간다)", () => {
    const base = doubleRouter("192.168.1.1");
    const withWan = (ip: string, prefix: number, gateway: string): Topology => ({
      ...base,
      devices: base.devices.map((d) => (d.name === "rt-2" ? { ...d, router: { ...d.router!, wan: { ipMode: "static", ip, prefix, gateway } } } : d)),
    });
    expect(codes(withWan("192.168.1.50", 24, "192.168.1.1"))).toContain("rt-2:router.wan-lan-overlap");
    expect(codes(withWan("192.168.0.50", 16, "192.168.0.1"))).not.toContain("rt-2:router.wan-lan-overlap");
  });
});
