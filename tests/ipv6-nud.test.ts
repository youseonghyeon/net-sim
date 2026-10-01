// IPv6 라우터가 말없이 사라질 때 호스트가 알아채는 두 길 (둘 다 기본 꺼짐):
// - 주기 RA (라우터 설정): 10초마다 RA, 라우터 수명 30초 → RA 가 30초 동안 없으면 호스트가 그 라우터를 뺀다 (배경 타이머)
// - NUD (호스트 설정): 확인한 지 30초 지나면 STALE → 쓸 때 DELAY 5초 → 유니캐스트 NS 3번 → 답이 없으면 지우고 라우터면 뺀다
// 같은 링크에 라우터가 둘이면 남은 라우터로 넘어간다 (VRRP 없이 IPv6 가 하는 기본 이중화)
import { describe, expect, it } from "vitest";
import { exampleSlaacTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import { createDevice, type Device, type Topology } from "../src/model/topology";
import { linkLocalOf } from "../src/core/addr6";
import { l3MacOf } from "../src/model/netSync";
import { practitionerLines } from "../src/model/packetView";
import { loadTopology } from "./helpers";

const TARGET = "2001:db8:2::2"; // gw-b 의 서버 쪽 주소 — 어느 라우터로 가도 닿는다

/** SLAAC 예제에 같은 링크(2001:db8:1::/64)로 RA 를 보내는 두 번째 게이트웨이 gw-b 를 더한다 */
function twoRouters(o: { periodic?: boolean; nud?: boolean } = {}): Topology {
  const t = exampleSlaacTopology();
  const gw = t.devices.find((d) => d.kind === "gateway")!;
  const none = { ipMode: "static" as const, ip: "", prefix: 24, gateway: "" };
  const b: Device = {
    ...createDevice("gateway", gw.x + 240, gw.y, t.devices),
    name: "gw-b",
    l3: {
      interfaces: [none, none, none],
      routes: [],
      ipv6: { enabled: true, interfaces: [{ ip: "", prefix: 64 }, { ip: "2001:db8:1::2", prefix: 64, ra: true }, { ip: TARGET, prefix: 64 }], routes: [], ...(o.periodic ? { raPeriodic: true } : {}) },
    },
  };
  const devices = t.devices.map((d) => {
    if (d === gw && o.periodic) return { ...d, l3: { ...d.l3!, ipv6: { ...d.l3!.ipv6!, raPeriodic: true } } };
    if (d.name === "pc-1" && o.nud) return { ...d, host: { ...d.host!, ipv6: { ...d.host!.ipv6!, nud: true } } };
    return d;
  });
  const sw1 = t.devices.find((d) => d.name === "sw-1")!;
  const sw2 = t.devices.find((d) => d.name === "sw-2")!;
  return {
    ...t,
    devices: [...devices, b],
    cables: [...t.cables, { id: "c-b1", a: { device: b.id, port: 1 }, b: { device: sw1.id, port: 6 } }, { id: "c-b2", a: { device: b.id, port: 2 }, b: { device: sw2.id, port: 6 } }],
  };
}
const gwA = (t: Topology) => t.devices.find((d) => d.kind === "gateway" && d.name !== "gw-b")!;
/** gw-a 를 말없이 죽인다: 케이블은 그대로, 손실 100% (링크는 살아 있어 RA 거둠도 없다) */
const silenceA = (l: ReturnType<typeof loadTopology>) => {
  const a = gwA(l.t).id;
  for (const c of l.t.cables) if (c.a.device === a || c.b.device === a) l.s.net.setLinkLoss(c.id, 1);
};
const routerA = (t: Topology) => linkLocalOf(l3MacOf(gwA(t).mac, 1));
const routerB = (t: Topology) => linkLocalOf(l3MacOf(t.devices.find((d) => d.name === "gw-b")!.mac, 1));

describe("IPv6 라우터가 말없이 사라질 때", () => {
  it("둘 다 꺼져 있으면(기본) 호스트는 죽은 라우터를 계속 쓴다", () => {
    const t = twoRouters();
    expect(lintTopology(t)).toEqual([]);
    const l = loadTopology(t);
    expect(l.host("pc-1").v6.defaultRouter).toBe(routerA(t));
    silenceA(l);
    l.s.net.runUntil(l.s.net.now + 60_000);
    l.act({ kind: "ping", nodeId: l.id("pc-1"), dst: TARGET });
    expect(l.host("pc-1").pings.at(-1)!.status).toBe("failed");
    expect(l.host("pc-1").v6.defaultRouter).toBe(routerA(t));
  });

  it("주기 RA: RA 가 라우터 수명(30초) 동안 오지 않으면 그 라우터를 빼고 다른 라우터로", () => {
    const t = twoRouters({ periodic: true });
    const l = loadTopology(t);
    expect(l.host("pc-1").v6.defaultRouter).toBe(routerA(t));
    // 살아 있는 동안은 아무리 시간이 흘러도 그대로 (10초마다 RA 로 수명이 다시 시작)
    l.s.net.runUntil(l.s.net.now + 45_000);
    expect(l.host("pc-1").v6.defaultRouter).toBe(routerA(t));
    silenceA(l);
    const from = l.s.net.trace.length;
    l.s.net.runUntil(l.s.net.now + 35_000);
    const gone = l.s.net.trace.slice(from).find((e) => e.nodeId === l.id("pc-1") && e.kind === "slaac.router" && e.details?.expired === true)!;
    expect(gone.summary).toContain("라우터 수명(30초) 동안 오지 않음");
    expect(l.host("pc-1").v6.defaultRouter).toBe(routerB(t));
    l.act({ kind: "ping", nodeId: l.id("pc-1"), dst: TARGET });
    expect(l.host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("NUD: 보낼 때 STALE → DELAY → PROBE 3번 → 실패면 라우터를 빼고 다음 라우터로 (ping 몇 번 실패하다 넘어감)", () => {
    const t = twoRouters({ nud: true });
    const l = loadTopology(t);
    const pc = l.id("pc-1");
    l.act({ kind: "ping", nodeId: pc, dst: TARGET });
    expect(l.host("pc-1").pings.at(-1)!.status).toBe("ok");
    silenceA(l);
    l.s.net.runUntil(l.s.net.now + 31_000); // REACHABLE 시간이 지남
    const from = l.s.net.trace.length;
    const results: string[] = [];
    for (let k = 0; k < 3; k++) {
      l.act({ kind: "ping", nodeId: pc, dst: TARGET }); // NUD 의 DELAY·PROBE 타이머가 시간을 민다
      results.push(l.host("pc-1").pings.at(-1)!.status);
    }
    const a = routerA(t);
    const nud = l.s.net.trace.slice(from).filter((e) => e.nodeId === pc && (e.details?.ip === a || e.details?.target === a) && (e.kind === "ndp.nud" || (e.kind === "ndp.ns.sent" && e.details?.probe !== undefined) || e.kind === "ndp.timeout"));
    expect(nud.map((e) => (e.kind === "ndp.ns.sent" ? `probe${e.details!.probe}` : `${e.kind}${e.details?.state ? `:${e.details.state}` : ""}`))).toEqual(["ndp.nud:DELAY", "probe1", "probe2", "probe3", "ndp.timeout"]);
    // 첫 ping 은 죽은 A 로 가서 실패 — 그 사이 NUD 가 DELAY·PROBE 를 마쳐 A 를 빼고, 다음 ping 부터 B 로 가서 성공
    expect(results).toEqual(["failed", "ok", "ok"]);
    expect(l.host("pc-1").v6.defaultRouter).toBe(routerB(t));
  });

  it("NUD: 살아 있는 라우터는 PROBE 의 NA 로 다시 REACHABLE (지우지 않음)", () => {
    const t = twoRouters({ nud: true });
    const l = loadTopology(t);
    const pc = l.id("pc-1");
    l.act({ kind: "ping", nodeId: pc, dst: TARGET });
    l.s.net.runUntil(l.s.net.now + 31_000);
    const from = l.s.net.trace.length;
    l.act({ kind: "ping", nodeId: pc, dst: TARGET });
    l.s.net.runUntil(l.s.net.now + 10_000);
    const tr = l.s.net.trace.slice(from).filter((e) => e.nodeId === pc && e.kind === "ndp.nud").map((e) => e.details?.state);
    expect(tr).toEqual(["DELAY", "REACHABLE"]);
    expect(l.host("pc-1").v6.defaultRouter).toBe(routerA(t));
    expect(l.host("pc-1").v6.neighbors.get(routerA(t))?.state).toBe("REACHABLE");
    expect(l.host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("기본 꺼짐은 조용하다: 주기 RA·NUD 가 꺼져 있으면 runToIdle 이 끝나고 RA 는 처음 한 번뿐", () => {
    const l = loadTopology(twoRouters());
    const from = l.s.net.trace.length;
    l.s.net.runUntil(l.s.net.now + 120_000);
    expect(l.s.net.trace.slice(from).some((e) => e.kind === "ndp.ra.sent")).toBe(false);
    expect(l.s.net.peekNextTime()).toBeUndefined();
  });

  it("주기 RA 를 켜면 10초마다 RA (배경 타이머 — 조용하면 시계는 멈춘다)", () => {
    const l = loadTopology(twoRouters({ periodic: true }));
    expect(l.s.net.peekNextTime()).toBeUndefined();
    const from = l.s.net.trace.length;
    l.s.net.runUntil(l.s.net.now + 30_500);
    const ras = l.s.net.trace.slice(from).filter((e) => e.kind === "ndp.ra.sent" && e.nodeId === gwA(l.t).id);
    // gw-a 는 두 인터페이스에서 RA (LAN·서버 쪽) × 3번
    expect(ras.length).toBe(6);
    expect(ras[0]!.summary).toContain("주기 RA");
  });

  it("ip -6 neigh 상태가 표에 보인다", () => {
    const t = twoRouters({ nud: true });
    const l = loadTopology(t);
    l.act({ kind: "ping", nodeId: l.id("pc-1"), dst: TARGET });
    const row = () => l.host("pc-1").v6.neighborRows(l.s.net.now).find((r) => r[0] === routerA(t))!;
    expect(row()[2]).toContain("REACHABLE");
    l.s.net.runUntil(l.s.net.now + 31_000);
    expect(row()[2]).toContain("STALE");
    // 실무 출력: ip -6 neigh 의 상태 칸 (RA 로 배운 라우터는 처음부터 STALE 이라 첫 ping 때도 같은 확인을 거친다 — RFC 4861)
    const from = l.s.net.trace.length;
    l.act({ kind: "ping", nodeId: l.id("pc-1"), dst: TARGET });
    l.s.net.runUntil(l.s.net.now + 10_000);
    const lines = l.s.net.trace.slice(from).filter((e) => e.kind === "ndp.nud" && e.nodeId === l.id("pc-1")).map((e) => practitionerLines(e, {})[0]!.line);
    const mac = l.host("pc-1").v6.neighbors.get(routerA(t))!.mac;
    expect(lines).toEqual([`${routerA(t)} dev eth0 lladdr ${mac} router DELAY`, `${routerA(t)} dev eth0 lladdr ${mac} router REACHABLE`]);
  });
});
