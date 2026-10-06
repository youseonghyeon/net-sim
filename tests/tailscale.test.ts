// 메시 VPN (Tailscale·ZeroTier): 조정 서버 로그인·netmap, STUN·홀 펀칭(disco)·DERP 릴레이, 서브넷 라우터, exit node, MagicDNS
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleTailscaleTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import type { MeshSettings, Topology } from "../src/model/topology";
import { headerLayers } from "../src/model/packetView";

const LAPTOP = "카페 노트북";
const PC = "회사 PC";
const HOME = "집 Brume 3";
const mesh = (t: Topology, name: string, p: Partial<MeshSettings>): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.name !== name ? d : d.host ? { ...d, host: { ...d.host, mesh: { ...d.host.mesh!, ...p } } } : { ...d, router: { ...d.router!, mesh: { ...d.router!.mesh!, ...p } } })),
});
const codes = (t: Topology) => lintTopology(t).map((i) => `${t.devices.find((d) => d.id === i.deviceId)!.name}:${i.code}`);

describe("Tailscale", () => {
  it("예제: 셋이 로그인해 netmap 을 받고, 노트북 → 집은 홀 펀칭으로 직접, → 회사 PC 는 DERP 릴레이, 집 NAS 는 서브넷 라우터로", () => {
    const L = loadTopology(exampleTailscaleTopology());
    expect(lintTopology(L.t)).toEqual([]);
    const lap = L.host(LAPTOP);
    expect(lap.mesh.summary()).toContain("100.64.0.");
    // MagicDNS 이름으로 회사 PC
    let tr = L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "work-pc" });
    expect(lap.pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "dns.resolved" && e.summary.includes("MagicDNS"))).toBe(true);
    expect(tr.some((e) => e.kind === "mesh.relay" && e.summary.includes("직접 경로를 찾지 못함"))).toBe(true);
    // 서브넷 라우터: 집 NAS (Tailscale 을 깔지 않은 기기)
    tr = L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "192.168.8.20" });
    expect(lap.pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "mesh.direct" && e.summary.includes("home-brume"))).toBe(true);
    const rows = Object.fromEntries(lap.mesh.rows().map((r) => [r[0], r[2]]));
    expect(rows["home-brume"]).toMatch(/^직접 203\.0\.113\./);
    expect(rows["work-pc"]).toContain("DERP");
    // 두 번째부터는 직접
    tr = L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "192.168.8.20" });
    expect(tr.some((e) => e.kind === "mesh.encap" && e.summary.includes("직접"))).toBe(true);
    expect(tr.some((e) => e.kind === "mesh.relay")).toBe(false);
  });

  it("회사 PC(symmetric) → 집(NAT 없음)은 pong 이 출발지로 돌아가 직접 경로가 된다", () => {
    const L = loadTopology(exampleTailscaleTopology());
    L.act({ kind: "ping", nodeId: L.id(PC), dst: "home-brume" });
    expect(L.host(PC).pings.at(-1)!.status).toBe("ok");
    expect(L.host(PC).mesh.rows().find((r) => r[0] === "home-brume")![2]).toMatch(/^직접/);
  });

  it("exit node: 노트북이 home-brume 을 exit node 로 쓰면 인터넷이 집 공인 주소로 나간다, exit node 를 끄면 드롭", () => {
    const t = mesh(exampleTailscaleTopology(), LAPTOP, { useExitNode: "home-brume" });
    expect(lintTopology(t)).toEqual([]);
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "8.8.8.8" });
    expect(L.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.nodeId === L.id(HOME) && e.kind === "nat.translate" && e.summary.includes("100.64.0."))).toBe(true);
    const off = mesh(L.t, HOME, { exitNode: false });
    expect(codes(off)).toContain(`${LAPTOP}:mesh.exit-unknown`);
    L.apply(off);
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "8.8.8.8" });
    // netmap 에서 exit node 가 사라져 평소처럼 카페로 나간다
    expect(L.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
  });

  it("tailnet 이름이 다르면 서로 못 본다 (구성 검사 mesh.alone)", () => {
    const t = mesh(exampleTailscaleTopology(), PC, { network: "famliy" });
    expect(codes(t)).toContain(`${PC}:mesh.alone`);
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "work-pc" });
    expect(L.host(LAPTOP).pings.at(-1)!.status).toBe("failed");
  });

  it("끄면 로그아웃 → 다른 기기의 netmap 에서 오프라인, 늦게 온 메시지는 Port Unreachable 로 새지 않는다", () => {
    const L = loadTopology(exampleTailscaleTopology());
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "work-pc" });
    const tr = L.apply(mesh(L.t, PC, { enabled: false }));
    expect(tr.some((e) => e.kind === "mesh.control" && e.summary.includes("로그아웃"))).toBe(true);
    expect(L.host(LAPTOP).mesh.rows().find((r) => r[0] === "work-pc")![2]).toBe("오프라인");
    expect(L.s.net.trace.some((e) => e.nodeId === L.id(PC) && e.kind === "icmp.unreachable.sent")).toBe(false);
  });

  it("공유기 끼리 서브넷 라우터: 회사 공유기가 LAN 을 알리면 Tailscale 을 깔지 않은 회사 PC 도 집 NAS 에 닿는다", () => {
    let t = mesh(exampleTailscaleTopology(), PC, { enabled: false });
    t = { ...t, devices: t.devices.map((d) => (d.name === "회사 공유기" ? { ...d, router: { ...d.router!, mesh: { enabled: true, net: "tailscale", network: "family", name: "office", advertiseLan: true } } } : d)) };
    expect(lintTopology(t)).toEqual([]);
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id(PC), dst: "192.168.8.20" });
    expect(L.host(PC).pings.at(-1)!.status).toBe("ok");
    expect(L.node<Router>("회사 공유기").mesh.rows().find((r) => r[0] === "home-brume")).toBeDefined();
  });

  it("DPI 가 VPN 을 막는 망에서는 조정 서버 로그인이 막힌다", () => {
    const base = exampleTailscaleTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "카페 공유기" ? { ...d, router: { ...d.router!, dpi: { enabled: true, blockApps: [], blockCategories: ["VPN"] } } } : d)) };
    const L = loadTopology(t);
    expect(L.host(LAPTOP).mesh.up).toBe(false);
    expect(L.s.net.trace.some((e) => e.kind === "dpi.block" && e.summary.includes("Tailscale"))).toBe(true);
  });

  it("패킷 상세: DERP 로 맡긴 데이터는 릴레이 층·받을 키·터널 안 원래 패킷", () => {
    const L = loadTopology(exampleTailscaleTopology());
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "work-pc" });
    const f = [...L.s.net.frameLog.values()].flat().map((x) => x.frame).find((fr) => fr.payload.kind === "ipv4" && fr.payload.payload.kind === "udp" && fr.payload.payload.payload.kind === "ts" && fr.payload.payload.payload.op === "derp-send" && !!fr.payload.payload.payload.msg?.inner)!;
    const layers = headerLayers(f);
    expect(layers.some((l) => l.title === "Tailscale" && l.rows.some(([k]) => k === "받을 노드 키"))).toBe(true);
    expect(layers.some((l) => l.title.startsWith("터널 안"))).toBe(true);
  });
});

describe("ZeroTier", () => {
  const zt = (id: string): Topology => {
    let t = exampleTailscaleTopology();
    for (const n of [LAPTOP, PC]) t = mesh(t, n, { net: "zerotier", network: id });
    return mesh(t, HOME, { enabled: false });
  };
  it("같은 네트워크 ID 의 두 기기가 10.147.17.x 를 받고 root 릴레이로 통신, 이름(MagicDNS)은 없다", () => {
    const t = zt("8056c2e21c000001");
    expect(lintTopology(t)).toEqual([]);
    const L = loadTopology(t);
    const pc = L.host(PC).mesh.self!.ip;
    expect(pc).toMatch(/^10\.147\.17\./);
    const tr = L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: pc });
    expect(L.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.summary.includes("root 릴레이"))).toBe(true);
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "work-pc" });
    expect(L.host(LAPTOP).pings.at(-1)!.status).toBe("failed");
  });

  it("네트워크 ID 가 16자리 16진수가 아니면 컨트롤러가 거절", () => {
    const t = zt("family");
    expect(codes(t)).toContain(`${LAPTOP}:mesh.zt-id-invalid`);
    const L = loadTopology(t);
    expect(L.host(LAPTOP).mesh.summary()).toContain("거절");
  });
});
