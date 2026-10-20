// 멀티 WAN 정책 규칙 (mwan3 rule): 출발지 대역 → 회선. VPN 은 WAN1 으로 받고 터널에서 풀린 인터넷 트래픽은 WAN2 로
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleMultiWanPolicyTopology, exampleWireguardTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import { NetworkSync } from "../src/model/netSync";
import type { Router } from "../src/core/nodes/router";
import { createDevice, newId, parseTopology, serializeTopology, type Device, type MwanRuleSetting, type Topology } from "../src/model/topology";

const patchDev = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });
const withRules = (t: Topology, rules: MwanRuleSetting[]) => patchDev(t, "집 Brume 3", (d) => ({ ...d, router: { ...d.router!, wan2: { ...d.router!.wan2!, rules } } }));
const portCable = (t: Topology, dev: string, port: number) => t.cables.find((c) => (c.a.device === dev && c.a.port === port) || (c.b.device === dev && c.b.port === port))!;
const load = (t: Topology = exampleMultiWanPolicyTopology()) => loadTopology(t);

describe("멀티 WAN 정책 규칙", () => {
  it("예제: VPN 대역(10.0.0.0/24)의 인터넷 트래픽은 WAN2 로, 바깥 WireGuard 는 WAN1 으로, 집 LAN 은 WAN1 으로", () => {
    const L = load();
    expect(L.lint()).toEqual([]);
    const r = L.node<Router>("집 Brume 3");
    expect(r.mwan.active).toBe("wan");
    expect(L.host("카페 폰").ra.state).toBe("up");
    const tr = L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "8.8.8.8" });
    expect(L.host("카페 폰").pings.at(-1)!.status).toBe("ok");
    const brume = tr.filter((e) => e.nodeId === L.id("집 Brume 3"));
    // 풀린 ping 은 규칙으로 WAN2, 5G 라우터가 다시 NAT
    const fwd = brume.find((e) => e.kind === "ip.forward" && e.details!.out === "wan2")!;
    expect(fwd.summary).toContain("mwan3 규칙 1(10.0.0.0/24 → WAN2)");
    expect(fwd.details!.rule).toBe(1);
    expect(tr.some((e) => e.nodeId === L.id("5G 라우터") && e.kind === "nat.translate")).toBe(true);
    // 응답은 WAN2 로 들어와 터널로 돌아간다 (바깥 UDP 는 WAN1 주소에서)
    const enc = brume.filter((e) => e.kind === "vpn.encap");
    expect(enc.length).toBeGreaterThan(0);
    expect(enc.every((e) => e.summary.includes(`UDP 203.0.113.10:51820`))).toBe(true);
    expect(r.mwan.hits).toEqual([1]);
    expect(r.mwan.ruleRows()).toEqual([["1", "10.0.0.0/24", "WAN2", "그 회선으로", "1"]]);
    // 집 NAS 는 규칙이 없어 WAN1
    const tr2 = L.act({ kind: "ping", nodeId: L.id("집 NAS"), dst: "8.8.8.8" });
    expect(L.host("집 NAS").pings.at(-1)!.status).toBe("ok");
    const f2 = tr2.find((e) => e.nodeId === L.id("집 Brume 3") && e.kind === "ip.forward" && e.details!.dst === "8.8.8.8")!;
    expect(f2.details!.out).toBe("wan");
    expect(f2.summary).not.toContain("mwan3 규칙");
    expect(r.mwan.hits).toEqual([1]);
  });

  it("규칙을 지우면 폰의 인터넷 트래픽도 지금 회선(WAN1)으로", () => {
    const L = load(withRules(exampleMultiWanPolicyTopology(), []));
    const tr = L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "8.8.8.8" });
    expect(L.host("카페 폰").pings.at(-1)!.status).toBe("ok");
    expect(tr.find((e) => e.nodeId === L.id("집 Brume 3") && e.kind === "ip.forward" && e.details!.dst === "8.8.8.8")!.details!.out).toBe("wan");
    expect(tr.some((e) => e.nodeId === L.id("5G 라우터") && e.kind === "nat.translate")).toBe(false);
  });

  it("규칙의 회선(WAN2)이 끊기면 지금 회선으로 (요약에 그 이유)", () => {
    const t = exampleMultiWanPolicyTopology();
    const L = load(t);
    const lte = portCable(t, L.id("집 Brume 3"), 4);
    L.apply({ ...t, cables: t.cables.filter((c) => c.id !== lte.id) });
    const tr = L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "8.8.8.8" });
    expect(L.host("카페 폰").pings.at(-1)!.status).toBe("ok");
    const fwd = tr.find((e) => e.nodeId === L.id("집 Brume 3") && e.kind === "ip.forward" && e.details!.dst === "8.8.8.8")!;
    expect(fwd.details!.out).toBe("wan");
    expect(fwd.summary).toContain("WAN2 이 끊겨 지금 회선으로");
    expect(L.node<Router>("집 Brume 3").mwan.ruleRows()[0]![3]).toBe("끊김 → WAN1");
  });

  it("규칙으로 WAN2 에서 시작한 흐름은 규칙을 지워도 그 회선에 붙어 있다 (conntrack)", () => {
    const L = load();
    L.act({ kind: "tcp-connect", nodeId: L.id("카페 폰"), dst: "8.8.8.8", port: 53 });
    const r = L.node<Router>("집 Brume 3");
    expect(r.w2.nat.size).toBeGreaterThan(0);
    expect(r.w2.nat.values().some((e) => e.lanIp === "10.0.0.2" && e.proto === "tcp")).toBe(true);
    const syn = { kind: "ipv4" as const, src: "10.0.0.2", dst: "8.8.8.8", ttl: 64, payload: { kind: "tcp" as const, srcPort: L.lastConn("카페 폰").localPort, dstPort: 53, seq: 0, ack: 0, len: 0 } };
    L.apply(withRules(L.t, []));
    expect(r.mwan.rules).toEqual([]);
    expect(r.w2.nat.carries(syn as never)).toBe(true);
    expect(r.w1.nat.carries(syn as never)).toBe(false);
  });

  it("멀티 WAN 이 꺼져 있으면 규칙은 쓰지 않는다", () => {
    const t = patchDev(exampleMultiWanPolicyTopology(), "집 Brume 3", (d) => ({ ...d, router: { ...d.router!, wan2: { ...d.router!.wan2!, enabled: false } } }));
    const L = load(t);
    expect(L.node<Router>("집 Brume 3").mwan.ruleFor("10.0.0.2")).toBeUndefined();
    const tr = L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "8.8.8.8" });
    expect(L.host("카페 폰").pings.at(-1)!.status).toBe("ok");
    expect(tr.find((e) => e.nodeId === L.id("집 Brume 3") && e.kind === "ip.forward" && e.details!.dst === "8.8.8.8")!.summary).not.toContain("mwan3");
  });
});

describe("WireGuard 서버는 받은 회선으로 답한다", () => {
  it("폰이 WAN2(5G 라우터의 포트 포워딩)로 붙으면 WAN1 이 지금 회선이어도 WAN2 로 답한다 — 로밍 없음", () => {
    const L = load();
    const lteIp = L.node<Router>("5G 라우터").wan.ip!;
    let t = patchDev(L.t, "5G 라우터", (d) => ({ ...d, router: { ...d.router!, forwards: [{ publicPort: 51820, lanIp: "192.168.225.100", lanPort: 51820, proto: "udp" }] } }));
    t = patchDev(t, "카페 폰", (d) => ({ ...d, host: { ...d.host!, ra: { ...d.host!.ra!, server: lteIp } } }));
    const L2 = load(t);
    expect(L2.node<Router>("5G 라우터").wan.ip).toBe(lteIp);
    expect(L2.node<Router>("집 Brume 3").mwan.active).toBe("wan");
    const tr = L2.act({ kind: "ping", nodeId: L2.id("카페 폰"), dst: "192.168.8.20" });
    expect(L2.host("카페 폰").pings.at(-1)!.status).toBe("ok");
    const enc = tr.filter((e) => e.nodeId === L2.id("집 Brume 3") && e.kind === "vpn.encap");
    expect(enc.length).toBeGreaterThan(0);
    expect(enc.every((e) => e.summary.includes("UDP 192.168.225.100:51820"))).toBe(true);
    expect(tr.some((e) => e.nodeId === L2.id("카페 폰") && e.kind === "vpn.roam")).toBe(false);
  });

  it("받은 회선(WAN1)이 끊기면 지금 회선(WAN2)에서 보내고 폰이 로밍으로 따라온다", () => {
    const t = exampleMultiWanPolicyTopology();
    const L = load(t);
    L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "8.8.8.8" });
    const wan1 = portCable(t, L.id("집 Brume 3"), 0);
    L.apply({ ...t, cables: t.cables.filter((c) => c.id !== wan1.id) });
    expect(L.node<Router>("집 Brume 3").mwan.active).toBe("wan2");
    const tr = L.act({ kind: "ping", nodeId: L.id("집 NAS"), dst: "10.0.0.2" });
    expect(L.host("집 NAS").pings.at(-1)!.status).toBe("ok");
    expect(tr.find((e) => e.nodeId === L.id("집 Brume 3") && e.kind === "vpn.encap")!.summary).toContain("UDP 192.168.225.100:51820");
    expect(tr.some((e) => e.nodeId === L.id("카페 폰") && e.kind === "vpn.roam")).toBe(true);
  });
});

describe("멀티 WAN 정책 규칙: 모델·구성 검사", () => {
  it("저장·불러오기에서 규칙이 남고, 읽을 수 없는 출발지는 시뮬레이션에서 빠진다", () => {
    const t = withRules(exampleMultiWanPolicyTopology(), [
      { src: "10.0.0.0/24", line: "wan2" },
      { src: "10.0.0", line: "wan" },
      { src: "192.168.8.50", line: "wan2" },
      { src: "192.168.8.77/24", line: "wan" },
    ]);
    const back = parseTopology(serializeTopology(t)).topology!;
    expect(back.devices.find((d) => d.name === "집 Brume 3")!.router!.wan2!.rules).toEqual(t.devices.find((d) => d.name === "집 Brume 3")!.router!.wan2!.rules);
    const s = new NetworkSync();
    s.sync(t);
    s.net.runToIdle();
    const r = s.net.nodes.get(t.devices.find((d) => d.name === "집 Brume 3")!.id) as Router;
    expect(r.mwan.rules.map((x) => `${x.src.ip}/${x.src.prefix}:${x.line}`)).toEqual(["10.0.0.0/24:wan2", "192.168.8.50/32:wan2", "192.168.8.0/24:wan"]);
    expect(r.mwan.ruleFor("192.168.8.50")!.index).toBe(1);
    expect(r.mwan.ruleFor("192.168.8.51")!.rule.line).toBe("wan");
  });

  it("mwan.rule-invalid: 비었거나 대역이 아닌 출발지 (멀티 WAN 을 켰을 때만)", () => {
    const bad = withRules(exampleMultiWanPolicyTopology(), [
      { src: "", line: "wan2" },
      { src: "10.0.0.0/33", line: "wan2" },
      { src: " 10.0.0.0 / 24 ", line: "wan2" },
      { src: "10.0.0.0/24/8", line: "wan2" },
      { src: "10.0. 0.0/24", line: "wan2" },
    ]);
    const issues = lintTopology(bad).filter((i) => i.code === "mwan.rule-invalid");
    expect(issues.map((i) => i.message)).toEqual([expect.stringContaining(`규칙 1번(비어 있음), 2번("10.0.0.0/33"), 4번("10.0.0.0/24/8"), 5번("10.0. 0.0/24") 의 출발지는 대역이 아님`)]);
    const off = patchDev(bad, "집 Brume 3", (d) => ({ ...d, router: { ...d.router!, wan2: { ...d.router!.wan2!, enabled: false } } }));
    expect(lintTopology(off).filter((i) => i.code === "mwan.rule-invalid")).toEqual([]);
  });
});

// 리뷰(2026-10-19) 회귀
describe("review: 멀티 WAN 정책 규칙", () => {
  it("두 회선 주소가 같으면(같은 대역의 모뎀 두 대) WireGuard 답은 지금 회선으로 — 끊긴 WAN2 로 보내지 않는다", () => {
    const t = patchDev(exampleMultiWanPolicyTopology(), "집 Brume 3", (d) => ({ ...d, router: { ...d.router!, wan2: { ...d.router!.wan2!, ipMode: "static", ip: "203.0.113.10", prefix: 29, gateway: "203.0.113.9" } } })); // WAN1 이 ISP 에서 받는 주소와 같게
    const L = load(t);
    const lte = portCable(t, L.id("집 Brume 3"), 4);
    L.apply({ ...t, cables: t.cables.filter((c) => c.id !== lte.id) });
    expect(L.node<Router>("집 Brume 3").mwan.active).toBe("wan");
    L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "192.168.8.20" });
    expect(L.host("카페 폰").pings.at(-1)!.status).toBe("ok");
  });

  it("VPN 기기가 공유기의 WAN2 주소로 ping 하면 공유기가 답한다", () => {
    const L = load();
    const wan2 = L.node<Router>("집 Brume 3").wan2.ip!;
    L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: wan2 });
    expect(L.host("카페 폰").pings.at(-1)!.status).toBe("ok");
  });

  it("공유기의 WireGuard 클라이언트는 받은 회선을 기억하지 않는다 — WAN1 이 살아나면 WAN1 에서 보낸다", () => {
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
    const wan1 = portCable(L.t, travel.id, 0);
    L.apply({ ...L.t, cables: L.t.cables.filter((c) => c.id !== wan1.id) });
    L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "8.8.8.8" });
    L.apply(t2);
    L.s.net.runUntil(L.s.net.now + 30_000);
    const r = L.node<Router>("여행용 공유기");
    expect(r.mwan.active).toBe("wan");
    const tr = L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "8.8.8.8" });
    expect(L.host("여행 노트북").pings.at(-1)!.status).toBe("ok");
    const enc = tr.filter((e) => e.nodeId === travel.id && e.kind === "vpn.encap");
    expect(enc.length).toBeGreaterThan(0);
    expect(enc.every((e) => e.summary.includes(`UDP ${r.wan.ip}:`))).toBe(true);
  });
});
