// 멀티 WAN 페일오버 (mwan3 식): lan4 = WAN2, 추적 ping(5초·배경 타이머)으로 장애 감지 → 예비 회선으로, 살아나면 되돌아감
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleMultiWanTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import type { Internet } from "../src/core/nodes/internet";
import { specOf, type Topology } from "../src/model/topology";

const load = (t: Topology = exampleMultiWanTopology()) => loadTopology(t);
const wan1Cable = (L: ReturnType<typeof load>) => L.t.cables.find((c) => c.b.device === L.id("사무실 Brume 3") && c.b.port === 0)!;

describe("멀티 WAN 페일오버", () => {
  it("lan4 가 WAN2 가 되고(포트 이름 wan2), 켜질 때는 WAN1 을 기다려 넘어가지 않는다", () => {
    const { t, node, s, id } = load();
    expect(lintTopology(t)).toEqual([]);
    const r = node<Router>("사무실 Brume 3");
    expect(specOf(t.devices.find((d) => d.name === "사무실 Brume 3")!).ports[4]!.name).toBe("wan2");
    expect(r.wan2.ip).toMatch(/^192\.168\.43\./);
    expect(r.mwan.active).toBe("wan");
    expect(s.net.trace.some((e) => e.nodeId === id("사무실 Brume 3") && e.kind === "mwan.switch")).toBe(false);
  });

  it("WAN1 이 링크는 살아 있는데 인터넷이 안 되면(손실 100%) 추적 ping 3번 실패 뒤 WAN2 로, 되살리면 2번 답한 뒤 WAN1 로", () => {
    const L = load();
    const { node, host, id, act, s } = L;
    const r = node<Router>("사무실 Brume 3");
    s.net.setLinkLoss(wan1Cable(L).id, 1);
    s.net.runUntil(s.net.now + 10_000);
    expect(r.mwan.active).toBe("wan"); // 아직 2번 실패
    s.net.runUntil(s.net.now + 10_000);
    expect(r.mwan.active).toBe("wan2");
    const tr = act({ kind: "ping", nodeId: id("사무실 PC"), dst: "8.8.8.8" });
    expect(host("사무실 PC").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.nodeId === id("휴대폰 핫스팟") && e.kind === "nat.translate")).toBe(true);
    s.net.setLinkLoss(wan1Cable(L).id, 0);
    s.net.runUntil(s.net.now + 15_000);
    expect(r.mwan.active).toBe("wan");
  });

  it("WAN1 케이블을 지우면 기다리지 않고 바로 WAN2 로", () => {
    const L = load();
    const tr = L.apply({ ...L.t, cables: L.t.cables.filter((c) => c !== wan1Cable(L)) });
    expect(tr.some((e) => e.kind === "mwan.switch" && e.summary.includes("WAN1 에서 WAN2"))).toBe(true);
    L.act({ kind: "ping", nodeId: L.id("사무실 PC"), dst: "8.8.8.8" });
    expect(L.host("사무실 PC").pings.at(-1)!.status).toBe("ok");
  });

  it("넘어가면 진행 중이던 TCP 는 끊긴다 — 출발지 주소가 바뀌어 서버에게는 모르는 연결", () => {
    const L = load();
    const { id, act, apply, lastConn } = L;
    act({ kind: "tcp-connect", nodeId: id("사무실 PC"), dst: "93.184.216.34", port: 22 });
    expect(lastConn("사무실 PC").ssh?.open).toBe(true);
    apply({ ...L.t, cables: L.t.cables.filter((c) => c !== wan1Cable(L)) });
    const conn = lastConn("사무실 PC");
    const tr = act({ kind: "tcp-close", nodeId: id("사무실 PC"), conn: conn.id });
    // 서버는 새 출발지(핫스팟 공인 주소)의 FIN 을 모르는 연결로 보고 RST
    expect(tr.some((e) => e.nodeId === id("internet-1") && e.kind === "tcp.rst.sent" && e.summary.includes("연결 없는 세그먼트"))).toBe(true);
    expect(tr.some((e) => e.nodeId === id("사무실 PC") && e.kind === "tcp.rst.received")).toBe(true);
  });

  it("추적 주소를 비우면 링크·주소만 본다 (손실 100% 장애는 모름)", () => {
    const base = exampleMultiWanTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.router?.wan2 ? { ...d, router: { ...d.router, wan2: { ...d.router.wan2, track: "" } } } : d)) };
    const L = load(t);
    L.s.net.setLinkLoss(wan1Cable(L).id, 1);
    L.s.net.runUntil(L.s.net.now + 30_000);
    expect(L.node<Router>("사무실 Brume 3").mwan.active).toBe("wan");
    expect(L.s.net.trace.some((e) => e.kind === "mwan.check")).toBe(false);
  });

  it("DDNS 는 지금 쓰는 회선을 따라간다 (WAN2 로 넘어가면 핫스팟의 공인 주소로 갱신)", () => {
    const base = exampleMultiWanTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.router?.wan2 ? { ...d, router: { ...d.router, ddns: { enabled: true, name: "office" } } } : d)) };
    const L = load(t);
    const inet = L.node<Internet>("internet-1");
    expect(inet.ddns.lookup("office.glddns.com")).toBe(L.node<Router>("사무실 Brume 3").wan.ip);
    L.apply({ ...L.t, cables: L.t.cables.filter((c) => c !== wan1Cable(L)) });
    expect(inet.ddns.lookup("office.glddns.com")).toBe(L.node<Router>("휴대폰 핫스팟").wan.ip);
  });

  it("멀티 WAN 을 끄면 lan4 는 다시 LAN 포트 (핫스팟과 같은 브리지 — 구성 검사가 DHCP 서버 둘을 짚는다)", () => {
    const base = exampleMultiWanTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.router?.wan2 ? { ...d, router: { ...d.router, wan2: { ...d.router.wan2, enabled: false } } } : d)) };
    expect(lintTopology(t).length).toBeGreaterThan(0);
    const L = load(base);
    const tr = L.apply(t);
    expect(tr.some((e) => e.summary.includes("lan4 는 다시 LAN 포트"))).toBe(true);
  });
});
