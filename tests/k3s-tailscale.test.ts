// k3s 안의 Tailscale: pod → flannel MASQUERADE(symmetric) → 집 공유기 NAT, 이중 NAT 에서 직접/DERP 가 갈리는 이유
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleK3sTailscaleTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { NatTypeSetting, Topology } from "../src/model/topology";

const LAPTOP = "카페 노트북";
const POD = "tailscale pod";
const NODE = "k3s 노드";
const nodeNat = (t: Topology, natType: NatTypeSetting): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.name === NODE ? { ...d, l3: { ...d.l3!, natType } } : d)),
});

describe("k3s 안의 Tailscale (이중 NAT)", () => {
  it("예제: 노드 NAT 가 symmetric 이라 노트북 ↔ pod 는 홀 펀칭 실패 → DERP 릴레이, 그래도 ping 은 된다", () => {
    const L = loadTopology(exampleK3sTailscaleTopology());
    expect(lintTopology(L.t)).toEqual([]);
    expect(L.host(POD).mesh.summary()).toContain("100.64.0.");
    // pod 가 STUN 으로 본 바깥 주소는 집 공유기의 공인 주소 (NAT 두 겹을 지난 뒤)
    const home = L.s.net.trace.find((e) => e.nodeId === L.id(POD) && e.kind === "mesh.endpoint");
    expect(home?.summary).toMatch(/바깥 주소 203\.0\.113\./);
    const tr = L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "k3s-ts" });
    expect(L.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "mesh.relay" && e.summary.includes("직접 경로를 찾지 못함"))).toBe(true);
    expect(tr.some((e) => e.kind === "mesh.direct")).toBe(false);
    expect(L.host(LAPTOP).mesh.rows().find((r) => r[0] === "k3s-ts")![2]).toContain("DERP");
    // 노드는 상대마다 다른 바깥 포트를 썼다 (symmetric)
    expect(tr.some((e) => e.nodeId === L.id(NODE) && e.kind === "nat.translate")).toBe(true);
  });

  it("pod 쪽에서 먼저 보내도 DERP", () => {
    const L = loadTopology(exampleK3sTailscaleTopology());
    L.act({ kind: "ping", nodeId: L.id(POD), dst: "laptop" });
    expect(L.host(POD).pings.at(-1)!.status).toBe("ok");
    expect(L.host(POD).mesh.rows().find((r) => r[0] === "laptop")![2]).toContain("DERP");
  });

  it("노드 NAT 가 port-restricted 면 NAT 가 두 겹이어도 직접 연결", () => {
    const t = nodeNat(exampleK3sTailscaleTopology(), "port-restricted");
    expect(lintTopology(t)).toEqual([]);
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "k3s-ts" });
    expect(L.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "mesh.direct")).toBe(true);
    expect(L.host(LAPTOP).mesh.rows().find((r) => r[0] === "k3s-ts")![2]).toMatch(/^직접 203\.0\.113\./);
    expect(L.host(POD).mesh.rows().find((r) => r[0] === "laptop")![2]).toMatch(/^직접 203\.0\.113\./);
  });

  it("예제를 연 채로 노드 NAT 를 port-restricted 로 바꾸면: 바로는 DERP 그대로, 30초 흘려 STUN·홀 펀칭을 다시 하면 직접", () => {
    const L = loadTopology(exampleK3sTailscaleTopology());
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "k3s-ts" });
    L.apply(nodeNat(L.t, "port-restricted"));
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "k3s-ts" });
    expect(L.host(LAPTOP).mesh.rows().find((r) => r[0] === "k3s-ts")![2]).toContain("DERP");
    for (let i = 0; i < 3; i++) L.s.net.runUntil(L.s.net.now + 10_000); // 상단바 "+10초" 세 번
    const tr = L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "k3s-ts" });
    expect(L.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "mesh.direct")).toBe(true);
    expect(L.host(LAPTOP).mesh.rows().find((r) => r[0] === "k3s-ts")![2]).toMatch(/^직접 203\.0\.113\./);
  });
});
