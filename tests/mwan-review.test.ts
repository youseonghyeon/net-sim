// 멀티 WAN 리뷰(2026-10-07) 회귀 테스트 — 리뷰어 재현을 그대로 둠
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleMultiWanTopology, exampleWireguardTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import { createDevice, newId, type Topology, type RouterSettings } from "../src/model/topology";

const BRUME = "사무실 Brume 3";
const withBrume = (t: Topology, f: (r: RouterSettings) => RouterSettings): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.name === BRUME ? { ...d, router: f(d.router!) } : d)),
});
const dump = (tr: { nodeId: string; kind: string; summary: string }[], filt?: (e: { nodeId: string; kind: string }) => boolean) =>
  tr.filter((e) => !filt || filt(e)).map((e) => `${e.nodeId.slice(0, 10)} ${e.kind} ${e.summary}`).join("\n");
void lintTopology;
void dump;
const log = (..._a: unknown[]): void => {};

describe("review: WAN1 DHCP 실패", () => {
  for (const track of ["", "8.8.8.8"]) {
    it(`WAN1 DHCP 실패 (track=${track || "없음"}) → WAN2 로 넘어가나`, () => {
      const base = withBrume(exampleMultiWanTopology(), (r) => ({ ...r, wan2: { ...r.wan2!, track } }));
      const dead = createDevice("switch", 0, 0, base.devices);
      dead.name = "죽은 모뎀";
      const brume = base.devices.find((d) => d.name === BRUME)!;
      const t: Topology = {
        ...base,
        devices: [...base.devices, dead],
        cables: [...base.cables.filter((c) => !(c.b.device === brume.id && c.b.port === 0)), { id: newId("cable"), a: { device: dead.id, port: 1 }, b: { device: brume.id, port: 0 } }],
      };
      const L = loadTopology(t);
      const r = L.node<Router>(BRUME);
      L.s.net.runUntil(L.s.net.now + 30_000);
      log("wan1", r.wanClient.state, r.wan.ip, "wan2", r.wan2.ip, "active", r.mwan.active, JSON.stringify(r.mwan.lines));
      L.act({ kind: "ping", nodeId: L.id("사무실 PC"), dst: "8.8.8.8" });
      log("ping", L.host("사무실 PC").pings.at(-1)!.status);
      expect(r.mwan.active).toBe("wan2");
    });
  }
});

const wan1CableOf = (t: Topology) => {
  const b = t.devices.find((d) => d.name === BRUME)!;
  return t.cables.find((c) => c.b.device === b.id && c.b.port === 0)!;
};
/** WAN2 를 핫스팟 대신 통신사 스위치에 바로 (공인 주소) */
const wan2OnIsp = (): Topology => {
  const t = exampleMultiWanTopology();
  const b = t.devices.find((d) => d.name === BRUME)!;
  const isp = t.devices.find((d) => d.name === "통신사 구간")!;
  return { ...t, cables: [...t.cables.filter((c) => !(c.b.device === b.id && c.b.port === 4)), { id: newId("cable"), a: { device: isp.id, port: 5 }, b: { device: b.id, port: 4 } }] };
};

describe("review: 들어오는 WAN2", () => {
  it("WAN2 공인 주소로 포트 포워딩", () => {
    let t = wan2OnIsp();
    t = { ...t, devices: t.devices.map((d) => (d.name === "사무실 PC" ? { ...d, host: { ...d.host!, ipMode: "static", ip: "192.168.8.50", prefix: 24, gateway: "192.168.8.1", services: [80] } } : d)) };
    t = withBrume(t, (r) => ({ ...r, forwards: [{ publicPort: 8080, lanIp: "192.168.8.50", lanPort: 80 }] }));
    const L = loadTopology(t);
    const r = L.node<Router>(BRUME);
    log("wan", r.wan.ip, "wan2", r.wan2.ip);
    const tr = L.act({ kind: "inet-connect", nodeId: L.id("internet-1"), dst: r.wan2.ip!, port: 8080 });
    const inet = L.node<import("../src/core/nodes/internet").Internet>("internet-1");
    log(dump(tr, (e) => e.kind.startsWith("nat") || e.kind.startsWith("tcp") || e.kind.startsWith("ip.")).slice(0, 3000));
    expect([...inet.tcp.conns.values()].at(-1)?.state).toBe("CLOSED");
  });

  it("WAN2 로 나가는 traceroute 의 Time Exceeded 가 돌아온다", () => {
    const t = exampleMultiWanTopology();
    const L = loadTopology(t);
    L.apply({ ...L.t, cables: L.t.cables.filter((c) => c !== wan1CableOf(L.t)) });
    expect(L.node<Router>(BRUME).mwan.active).toBe("wan2");
    L.act({ kind: "traceroute", nodeId: L.id("사무실 PC"), dst: "8.8.8.8" });
    const rec = L.host("사무실 PC").traceroutes.at(-1)!;
    log(JSON.stringify(rec.hops));
    expect(rec.status).toBe("done");
  });

  for (const cut of [false, true]) {
    it(`LAN PC 가 공유기 자신의 WAN2 주소로 ping (WAN2 사용 중=${cut})`, () => {
      const L = loadTopology(exampleMultiWanTopology());
      if (cut) L.apply({ ...L.t, cables: L.t.cables.filter((c) => c !== wan1CableOf(L.t)) });
      const r = L.node<Router>(BRUME);
      const tr = L.act({ kind: "ping", nodeId: L.id("사무실 PC"), dst: r.wan2.ip! });
      log(dump(tr, (e) => !e.kind.startsWith("frame") && !e.kind.startsWith("switch")).slice(0, 2500));
      expect(L.host("사무실 PC").pings.at(-1)!.status).toBe("ok");
    });
  }
});

describe("review: 추적", () => {
  it("추적 주소가 두 회선 모두에서 안 닿음 (사설 주소) → 전환이 반복되지 않고 WAN1 에 머묾", () => {
    const L = loadTopology(withBrume(exampleMultiWanTopology(), (r) => ({ ...r, wan2: { ...r.wan2!, track: "10.255.255.1" } })));
    const from = L.s.net.trace.length;
    L.s.net.runUntil(L.s.net.now + 60_000);
    const tr = L.s.net.trace.slice(from);
    log(dump(tr, (e) => e.kind === "mwan.switch" || e.kind === "mwan.down" || e.kind === "mwan.up"));
    const r = L.node<Router>(BRUME);
    expect(tr.filter((e) => e.kind === "mwan.switch").length).toBe(0);
    expect(r.mwan.active).toBe("wan");
    L.act({ kind: "ping", nodeId: L.id("사무실 PC"), dst: "8.8.8.8" });
    expect(L.host("사무실 PC").pings.at(-1)!.status).toBe("ok");
  });

  it("runToIdle 이 끝난다 (추적 켜고 두 회선 다 끊김)", () => {
    const L = loadTopology(exampleMultiWanTopology());
    const b = L.id(BRUME);
    L.apply({ ...L.t, cables: L.t.cables.filter((c) => c.b.device !== b || (c.b.port !== 0 && c.b.port !== 4)) });
    L.s.net.runUntil(L.s.net.now + 30_000);
    L.s.net.runToIdle();
    expect(L.node<Router>(BRUME).mwan.active).toBe("wan");
  });
});

describe("review: WireGuard 클라이언트 공유기 + 멀티 WAN", () => {
  it("여행용 공유기 WAN1(호텔)을 뽑으면 WAN2(핫스팟)로 터널이 다시 맺어지나", () => {
    const t = exampleWireguardTopology();
    const travel = t.devices.find((d) => d.name === "여행용 공유기")!;
    const isp = t.devices.find((d) => d.name === "통신사 구간")!;
    const hs = createDevice("router", 0, 0, t.devices);
    hs.name = "핫스팟";
    hs.router = { ...hs.router!, lanIp: "192.168.43.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.43.100", end: "192.168.43.199" } };
    const t2: Topology = {
      ...t,
      devices: [...t.devices.map((d) => (d.id === travel.id ? { ...d, router: { ...d.router!, wan2: { enabled: true, ipMode: "dhcp" as const, ip: "", prefix: 24, gateway: "", track: "8.8.8.8" } } } : d)), hs],
      cables: [...t.cables, { id: newId("cable"), a: { device: isp.id, port: 5 }, b: { device: hs.id, port: 0 } }, { id: newId("cable"), a: { device: hs.id, port: 1 }, b: { device: travel.id, port: 4 } }],
    };
    const L = loadTopology(t2);
    L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "8.8.8.8" });
    log("before", L.host("여행 노트북").pings.at(-1)!.status);
    L.apply({ ...L.t, cables: L.t.cables.filter((c) => !(c.b.device === travel.id && c.b.port === 0)) });
    const r = L.node<Router>("여행용 공유기");
    log("active", r.mwan.active, "wan2", r.wan2.ip);
    const tr = L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "8.8.8.8" });
    L.s.net.runUntil(L.s.net.now + 10_000);
    const tr2 = L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "8.8.8.8" });
    log(dump([...tr, ...tr2], (e) => e.nodeId === travel.id && (e.kind.startsWith("vpn") || e.kind.startsWith("ip.") || e.kind.startsWith("mwan"))).slice(0, 3000));
    expect(L.host("여행 노트북").pings.at(-1)!.status).toBe("ok");
  });
});

describe("review: 구성 검사", () => {
  it("WAN2 를 통신사 스위치에 바로(공인 DHCP)", () => {
    log(JSON.stringify(lintTopology(wan2OnIsp())));
    expect(lintTopology(wan2OnIsp())).toEqual([]);
  });
  it("WAN2 수동 주소 (핫스팟 대역)", () => {
    const t = withBrume(exampleMultiWanTopology(), (r) => ({ ...r, wan2: { ...r.wan2!, ipMode: "static", ip: "192.168.43.50", prefix: 24, gateway: "192.168.43.1" } }));
    log(JSON.stringify(lintTopology(t)));
    expect(lintTopology(t)).toEqual([]);
    const L = loadTopology(t);
    L.apply({ ...L.t, cables: L.t.cables.filter((c) => c !== wan1CableOf(L.t)) });
    L.act({ kind: "ping", nodeId: L.id("사무실 PC"), dst: "8.8.8.8" });
    expect(L.host("사무실 PC").pings.at(-1)!.status).toBe("ok");
  });
  it("WAN2 쪽 스위치와 LAN 스위치가 이어져도 공유기 lan4 는 브리지가 아니므로 고리가 아님", () => {
    // Brume lan1 → 사무실 스위치, Brume lan4(WAN2) → 핫스팟 스위치, 두 스위치 사이 케이블 (L2 로는 고리 아님 — WAN2 는 브리지에서 빠짐)
    const t = exampleMultiWanTopology();
    const b = t.devices.find((d) => d.name === BRUME)!;
    const hsr = t.devices.find((d) => d.name === "휴대폰 핫스팟")!;
    const pc = t.devices.find((d) => d.name === "사무실 PC")!;
    const s1 = createDevice("switch", 0, 0, t.devices);
    const s2 = createDevice("switch", 0, 0, [...t.devices, s1]);
    const cables = t.cables.filter((c) => !(c.b.device === b.id && c.b.port === 4) && !(c.a.device === b.id && c.a.port === 1));
    const t2: Topology = {
      ...t,
      devices: [...t.devices, s1, s2],
      cables: [
        ...cables,
        { id: newId("cable"), a: { device: b.id, port: 1 }, b: { device: s1.id, port: 1 } },
        { id: newId("cable"), a: { device: s1.id, port: 2 }, b: { device: pc.id, port: 0 } },
        { id: newId("cable"), a: { device: b.id, port: 4 }, b: { device: s2.id, port: 1 } },
        { id: newId("cable"), a: { device: hsr.id, port: 1 }, b: { device: s2.id, port: 2 } },
        { id: newId("cable"), a: { device: s1.id, port: 3 }, b: { device: s2.id, port: 3 } },
      ],
    };
    const codes = lintTopology(t2).map((i) => i.code);
    log(codes);
    expect(codes).not.toContain("switch.loop-no-stp");
  });
});

describe("review: 기타", () => {
  for (const which of ["wan", "wan2"] as const) {
    it(`포트 포워딩 대상이 없을 때 Host Unreachable (${which} 로 들어옴)`, () => {
      const t = withBrume(wan2OnIsp(), (r) => ({ ...r, forwards: [{ publicPort: 8080, lanIp: "192.168.8.77", lanPort: 80 }] }));
      const L = loadTopology(t);
      const r = L.node<Router>(BRUME);
      const ip = which === "wan" ? r.wan.ip! : r.wan2.ip!;
      const tr = L.act({ kind: "inet-connect", nodeId: L.id("internet-1"), dst: ip, port: 8080 });
      const inet = L.node<import("../src/core/nodes/internet").Internet>("internet-1");
      const c = [...inet.tcp.conns.values()].at(-1)!;
      log(which, c.state, c.reason, tr.filter((e) => e.kind.startsWith("icmp.unreach")).map((e) => e.nodeId.slice(0, 8) + " " + e.summary));
      expect(tr.some((e) => e.kind === "icmp.unreachable.received")).toBe(true);
    });
  }

  it("추적 주소를 여러 번 바꿔도 5초에 회선당 추적 ping 하나", () => {
    const base = exampleMultiWanTopology();
    const L = loadTopology(base);
    for (const tk of ["1.1.1.1", "8.8.4.4", "8.8.8.8", "1.1.1.1"]) L.apply(withBrume(L.t, (r) => ({ ...r, wan2: { ...r.wan2!, track: tk } })));
    const from = L.s.net.trace.length;
    L.s.net.runUntil(L.s.net.now + 20_000);
    const sends = L.s.net.trace.slice(from).filter((e) => e.kind === "mwan.check" && e.summary.includes("로 추적 ping →"));
    log(sends.map((e) => `${e.time} ${e.summary}`).join("\n"));
    expect(sends.length).toBe(8);
  });

  it("WAN2 가 공인 DHCP 일 때 ISP 가 WAN2 주소를 바꾸면 (FORCERENEW) WAN2 로 계속 나간다", () => {
    const L = loadTopology(wan2OnIsp());
    L.apply({ ...L.t, cables: L.t.cables.filter((c) => c !== wan1CableOf(L.t)) });
    const r = L.node<Router>(BRUME);
    expect(r.mwan.active).toBe("wan2");
    const old = r.wan2.ip!;
    const tr = L.act({ kind: "isp-renumber", nodeId: L.id("internet-1"), ip: old });
    log(old, "→", r.wan2.ip, dump(tr, (e) => e.nodeId === L.id(BRUME) && (e.kind.startsWith("dhcp") || e.kind.startsWith("mwan") || e.kind.startsWith("ddns"))));
    L.act({ kind: "ping", nodeId: L.id("사무실 PC"), dst: "8.8.8.8" });
    expect(L.host("사무실 PC").pings.at(-1)!.status).toBe("ok");
    expect(r.wan2.ip).not.toBe(old);
  });
});

describe("review: WAN2 수동 주소 충돌", () => {
  it("WAN2 수동 주소가 핫스팟 LAN 주소와 같으면 (WAN1 수동처럼) ARP Probe 로 충돌을 알아채나", () => {
    const t = withBrume(exampleMultiWanTopology(), (r) => ({ ...r, wan2: { ...r.wan2!, ipMode: "static", ip: "192.168.43.1", prefix: 24, gateway: "192.168.43.1" } }));
    const L = loadTopology(t);
    const r = L.node<Router>(BRUME);
    const tr = L.s.net.trace.filter((e) => e.nodeId === L.id(BRUME) && (e.kind.startsWith("arp.probe") || e.kind.includes("conflict")));
    log(JSON.stringify(r.wan2.conflict), tr.map((e) => e.kind + " " + e.summary));
    expect(r.wan2.conflict).toBeTruthy();
  });
});

describe("review: 실행 중 켜고 끄기", () => {
  it("꺼진 상태로 시작 → 켬 → 끔 → 켬, 매번 핫스팟 주소를 받고 WAN1 을 끊으면 WAN2 로", () => {
    const off = withBrume(exampleMultiWanTopology(), (r) => ({ ...r, wan2: { ...r.wan2!, enabled: false } }));
    const on = withBrume(off, (r) => ({ ...r, wan2: { ...r.wan2!, enabled: true } }));
    const L = loadTopology(off);
    const r = L.node<Router>(BRUME);
    const pcIp0 = L.host("사무실 PC").iface.ip;
    L.apply(on);
    log("pc ip before enable", pcIp0, "wan2", r.wan2.ip, r.wan2Client.state);
    L.apply(off);
    L.apply(on);
    log("after toggles wan2", r.wan2.ip, r.wan2Client.state, r.mwan.active);
    expect(r.wan2.ip).toMatch(/^192\.168\.43\./);
    L.apply({ ...on, cables: on.cables.filter((c) => c.id !== wan1CableOf(on).id) });
    expect(r.mwan.active).toBe("wan2");
    L.act({ kind: "dhcp-renew", nodeId: L.id("사무실 PC") });
    L.act({ kind: "ping", nodeId: L.id("사무실 PC"), dst: "8.8.8.8" });
    log("pc", L.host("사무실 PC").iface.ip, L.host("사무실 PC").pings.at(-1)!.status);
  });
});
