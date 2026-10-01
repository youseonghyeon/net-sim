// 리뷰: 7d5d7c6 "feat(ipv6): NUD·주기 RA·라우터 수명" 의 결함 재현 (모두 지금 코드에서 실패해야 한다)
import { describe, expect, it } from "vitest";
import { exampleDualStackHomeTopology, exampleSlaacTopology } from "../src/model/examples";
import { createDevice, type Device, type Topology } from "../src/model/topology";
import { linkLocalOf } from "../src/core/addr6";
import { l3MacOf } from "../src/model/netSync";
import { practitionerLines } from "../src/model/packetView";
import { loadTopology } from "./helpers";

const TARGET = "2001:db8:2::2"; // gw-b 의 서버 쪽 주소 — 어느 라우터로 가도 닿는다

/** tests/ipv6-nud.test.ts 와 같은 구성: SLAAC 예제 + 같은 링크로 RA 를 보내는 gw-b */
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
const gwB = (t: Topology) => t.devices.find((d) => d.name === "gw-b")!;
const routerA = (t: Topology) => linkLocalOf(l3MacOf(gwA(t).mac, 1));
const routerB = (t: Topology) => linkLocalOf(l3MacOf(t.devices.find((d) => d.name === "gw-b")!.mac, 1));
type L = ReturnType<typeof loadTopology>;
/** 장치의 모든 케이블 손실률 (1 = 말없이 죽음, 0 = 되살아남) */
const lossOf = (l: L, dev: Device, rate: number) => {
  for (const c of l.t.cables) if (c.a.device === dev.id || c.b.device === dev.id) l.s.net.setLinkLoss(c.id, rate);
};
/** pc-1 의 NUD 가 그 라우터를 실패로 끝낼 때까지: REACHABLE 시간이 지난 뒤 ping 한 번 → DELAY 5초 + PROBE 3번 */
const nudFail = (l: L, dst: string) => {
  l.s.net.runUntil(l.s.net.now + 31_000);
  l.act({ kind: "ping", nodeId: l.id("pc-1"), dst });
  l.s.net.runUntil(l.s.net.now + 10_000);
};

describe("NUD 실패를 기본 게이트웨이 목록 삭제로 처리 (RFC 4861 6.3.6 은 목록에 두고 다음 선택 때 뒤로 미룬다)", () => {
  it("라우터가 하나뿐: 잠깐 말없이 끊겼다(손실 100%) 되살아나도, NUD 실패로 지운 기본 게이트웨이가 돌아오지 않는다 (주기 RA 꺼짐)", () => {
    const t = twoRouters({ nud: true });
    const single: Topology = { ...t, devices: t.devices.filter((d) => d.name !== "gw-b"), cables: t.cables.filter((c) => c.id !== "c-b1" && c.id !== "c-b2") };
    const l = loadTopology(single);
    const pc = l.id("pc-1");
    l.act({ kind: "ping", nodeId: pc, dst: "2001:db8:2::10" });
    expect(l.host("pc-1").pings.at(-1)!.status).toBe("ok");
    lossOf(l, gwA(single), 1);
    nudFail(l, "2001:db8:2::10");
    // 라우터가 되살아남 — 실제 호스트는 목록에 남은 라우터를 다시 NS 로 찾아 곧바로 복구된다
    lossOf(l, gwA(single), 0);
    l.act({ kind: "ping", nodeId: pc, dst: "2001:db8:2::10" });
    // 관찰: v6.routers 가 비어 "IPv6 기본 게이트웨이가 없음 → 드롭" — 이 라우터는 다시 RA 를 보낼 일이 없어(주기 RA 꺼짐, RS 도 다시 안 보냄) 영영 복구되지 않는다
    expect({ gw: l.host("pc-1").v6.defaultRouter, ping: l.host("pc-1").pings.at(-1)!.status }).toEqual({ gw: routerA(single), ping: "ok" });
  });

  it("라우터 둘: A 가 NUD 실패로 빠진 뒤 되살아났는데, 이번엔 B 가 죽으면 살아 있는 A 로 돌아가지 못한다", () => {
    const t = twoRouters({ nud: true });
    const l = loadTopology(t);
    const pc = l.id("pc-1");
    l.act({ kind: "ping", nodeId: pc, dst: TARGET });
    lossOf(l, gwA(t), 1);
    nudFail(l, TARGET); // A 실패 → B 로
    l.act({ kind: "ping", nodeId: pc, dst: TARGET });
    expect(l.host("pc-1").pings.at(-1)!.status).toBe("ok");
    lossOf(l, gwA(t), 0); // A 복구
    // B 가 죽는다 (TARGET 은 B 의 주소라 A 를 거쳐도 닿지 않으므로, A 뒤의 서버로 확인)
    lossOf(l, gwB(t), 1);
    nudFail(l, "2001:db8:2::10");
    l.act({ kind: "ping", nodeId: pc, dst: "2001:db8:2::10" });
    expect({ gw: l.host("pc-1").v6.defaultRouter, ping: l.host("pc-1").pings.at(-1)!.status }).toEqual({ gw: routerA(t), ping: "ok" });
  });
});

describe("기본 설정(주기 RA·NUD 꺼짐)에서도 라우터 수명 1800초가 지나면 살아 있는 라우터를 잃는다 (예전엔 만료 없음)", () => {
  it("SLAAC 예제: 아무것도 바꾸지 않고 30분(+10초 180번) 지나면 pc-1 이 기본 게이트웨이를 잃는다", () => {
    const l = loadTopology(exampleSlaacTopology());
    const pc = l.id("pc-1");
    l.act({ kind: "ping", nodeId: pc, dst: "2001:db8:2::10" });
    expect(l.host("pc-1").pings.at(-1)!.status).toBe("ok");
    l.s.net.runUntil(l.s.net.now + 1_801_000);
    l.act({ kind: "ping", nodeId: pc, dst: "2001:db8:2::10" });
    // 관찰: "라우터 … 의 RA 가 라우터 수명(1800초) 동안 오지 않음 → 기본 게이트웨이에서 뺌" — 게이트웨이는 주기 RA 가 꺼져 다시 알리지 않는다
    expect({ gw: l.host("pc-1").v6.defaultRouter !== undefined, ping: l.host("pc-1").pings.at(-1)!.status }).toEqual({ gw: true, ping: "ok" });
  });

  it("듀얼 스택 집: 30분 뒤 공유기 WAN 이 ISP 기본 게이트웨이를 잃어 집 IPv6 인터넷이 끊긴다 (ISP·공유기에는 주기 RA 설정도 없다)", () => {
    const l = loadTopology(exampleDualStackHomeTopology());
    const pc = l.id("pc-1");
    l.act({ kind: "ping", nodeId: pc, dst: "2001:4860:4860::8888" });
    expect(l.host("pc-1").pings.at(-1)!.status).toBe("ok");
    l.s.net.runUntil(l.s.net.now + 1_801_000);
    l.act({ kind: "ping", nodeId: pc, dst: "2001:4860:4860::8888" });
    const rt = l.s.net.nodes.get(l.t.devices.find((d) => d.kind === "router")!.id) as unknown as { wan6: { defaultRouter: string | undefined } };
    expect({ wanGw: rt.wan6.defaultRouter !== undefined, ping: l.host("pc-1").pings.at(-1)!.status }).toEqual({ wanGw: true, ping: "ok" });
  });
});

describe("ip -6 실무 출력이 새 수명·NUD 상태와 어긋남", () => {
  it("주기 RA(라우터 수명 30초)로 배운 기본 게이트웨이의 ip -6 route 줄이 expires 1799sec", () => {
    const l = loadTopology(twoRouters({ periodic: true }));
    const ev = l.s.net.trace.find((e) => e.nodeId === l.id("pc-1") && e.kind === "slaac.router" && e.details?.router !== undefined && !e.details?.removed)!;
    expect(ev.summary).toContain("라우터 수명 30초");
    const line = practitionerLines(ev, {})[0]!.line;
    expect(line).not.toContain("expires 1799sec");
  });

  it("NUD 를 켠 호스트가 RA 로 배운 라우터는 STALE 인데 ip -6 neigh 줄은 REACHABLE", () => {
    const t = twoRouters({ nud: true });
    const l = loadTopology(t);
    const pc = l.id("pc-1");
    const state = l.host("pc-1").v6.neighbors.get(routerA(t))!.state;
    expect(state).toBe("STALE");
    const ev = l.s.net.trace.find((e) => e.nodeId === pc && e.kind === "ndp.cache.update" && e.details?.ip === routerA(t))!;
    const line = practitionerLines(ev, {})[0]!.line;
    expect(line.endsWith(` ${state}`)).toBe(true);
  });
});

describe("기본 라우터 선택이 도달성을 보지 않음 (RFC 4861 6.3.6: INCOMPLETE·항목 없는 라우터보다 도달 가능한 라우터, 모두 모르면 라운드 로빈)", () => {
  it("NUD 켬: 이웃 캐시가 비워진 뒤 첫 라우터가 말없이 죽으면, 주소 해석(NS) 실패만 되풀이하고 살아 있는 두 번째 라우터로 넘어가지 않는다", () => {
    // gw-b 는 자기만의 프리픽스(2001:db8:3::/64)를 알린다 → 나중에 바꾸면 pc-1 의 그 SLAAC 주소가 지워지며 이웃 캐시가 비워진다
    const base = twoRouters({ nud: true });
    const withB = (ip: string): Topology => ({
      ...base,
      devices: base.devices.map((d) => (d.name === "gw-b" ? { ...d, l3: { ...d.l3!, ipv6: { ...d.l3!.ipv6!, interfaces: d.l3!.ipv6!.interfaces.map((x, i) => (i === 1 ? { ...x, ip } : x)) } } } : d)),
    });
    const l = loadTopology(withB("2001:db8:3::2"));
    const pc = l.id("pc-1");
    l.apply(withB("2001:db8:4::2"));
    expect(l.host("pc-1").v6.neighbors.size).toBe(0); // 프리픽스를 거둔 RA 로 이웃 캐시가 비워짐
    lossOf(l, gwA(l.t), 1);
    const results: string[] = [];
    for (let k = 0; k < 3; k++) {
      l.act({ kind: "ping", nodeId: pc, dst: TARGET });
      results.push(l.host("pc-1").pings.at(-1)!.status);
    }
    // 고친 뒤: A 의 NS 실패로 A 를 뒤로 미루고 다음 ping 부터 B 로 보낸다 (RFC 4861 6.3.6).
    // 이 구성에서는 B 의 LAN 프리픽스를 2001:db8:4::/64 로 바꿔 B 가 pc-1(2001:db8:1::) 로 돌아갈 경로가 없어 ping 자체는 실패한다 — 선택만 본다
    expect(results[0]).toBe("failed");
    expect(l.host("pc-1").v6.defaultRouter).toBe(routerB(l.t));
    const viaB = l.s.net.trace.filter((e) => e.nodeId === pc && e.kind === "ip.route" && e.summary.includes(routerB(l.t)));
    expect(viaB.length).toBeGreaterThan(0);
  });
});
