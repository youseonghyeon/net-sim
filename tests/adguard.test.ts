// AdGuard Home·자녀 보호 (DNS 필터): 차단 목록·사용자 규칙·예외·기기별 카테고리·DNS 가로채기·쿼리 로그
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleAdguardTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import type { RouterAdguardSettings, Topology } from "../src/model/topology";

const load = (t: Topology = exampleAdguardTopology()) => loadTopology(t);
const patch = (t: Topology, p: Partial<RouterAdguardSettings>): Topology => ({ ...t, devices: t.devices.map((d) => (d.router?.adguard ? { ...d, router: { ...d.router, adguard: { ...d.router.adguard, ...p } } } : d)) });

describe("AdGuard Home", () => {
  it("광고 이름은 0.0.0.0 으로 답해 접속하지 않고, 쿼리 로그·통계에 남는다", () => {
    const { t, id, act, host, node } = load();
    const tr = act({ kind: "ping", nodeId: id("아빠 PC"), dst: "doubleclick.net" });
    const rec = host("아빠 PC").pings.at(-1)!;
    expect(rec.status).toBe("failed");
    expect(rec.reason).toContain("DNS 가 막은 이름");
    expect(tr.some((e) => e.kind === "dns.blocked" && e.summary.includes("0.0.0.0"))).toBe(true);
    // 업스트림(8.8.8.8)에 묻지 않았다
    expect(tr.some((e) => e.kind === "dns.forward")).toBe(false);
    const r = node<Router>("집 Brume 3");
    expect(r.adguard.stats).toEqual({ total: 1, blocked: 1 });
    expect(r.snapshot().tables.find((x) => x.title === "AdGuard 쿼리 로그")!.rows[0]![3]).toContain("광고·추적");
    expect(lintTopology(t)).toEqual([]);
  });

  it("다른 이름은 그대로 (허용으로 기록), NXDOMAIN 모드면 없는 이름으로 답한다", () => {
    const L = load();
    L.act({ kind: "ping", nodeId: L.id("아빠 PC"), dst: "naver.com" });
    expect(L.host("아빠 PC").pings.at(-1)!.status).toBe("ok");
    const L2 = load(patch(exampleAdguardTopology(), { mode: "nxdomain" }));
    const tr = L2.act({ kind: "ping", nodeId: L2.id("아빠 PC"), dst: "doubleclick.net" });
    expect(tr.some((e) => e.kind === "dns.blocked" && e.summary.includes("NXDOMAIN"))).toBe(true);
    expect(L2.host("아빠 PC").pings.at(-1)!.reason).toContain("없는 이름");
  });

  it("하위 이름도 막고, 예외 규칙이 이긴다", () => {
    const L = load(patch(exampleAdguardTopology(), { custom: ["naver.com"], allow: ["www.naver.com"] }));
    L.act({ kind: "ping", nodeId: L.id("아빠 PC"), dst: "naver.com" });
    expect(L.host("아빠 PC").pings.at(-1)!.status).toBe("failed");
    const tr = L.act({ kind: "ping", nodeId: L.id("아빠 PC"), dst: "www.naver.com" });
    expect(tr.some((e) => e.kind === "dns.blocked")).toBe(false);
  });

  it("자녀 보호: 아이 태블릿만 SNS·게임이 막히고 동영상은 된다", () => {
    const { id, act, host } = load();
    act({ kind: "ping", nodeId: id("아이 태블릿"), dst: "roblox.com" });
    expect(host("아이 태블릿").pings.at(-1)!.status).toBe("failed");
    act({ kind: "ping", nodeId: id("아이 태블릿"), dst: "instagram.com" });
    expect(host("아이 태블릿").pings.at(-1)!.status).toBe("failed");
    act({ kind: "ping", nodeId: id("아이 태블릿"), dst: "youtube.com" });
    expect(host("아이 태블릿").pings.at(-1)!.status).toBe("ok");
    act({ kind: "ping", nodeId: id("아빠 PC"), dst: "roblox.com" });
    expect(host("아빠 PC").pings.at(-1)!.status).toBe("ok");
  });

  it("DNS 를 8.8.8.8 로 직접 적은 스마트 TV: DNS 가로채기가 공유기로 받아 막고(TV 는 8.8.8.8 이 답한 줄 앎), 끄면 걸러지지 않는다", () => {
    const L = load();
    let tr = L.act({ kind: "ping", nodeId: L.id("스마트 TV"), dst: "doubleclick.net" });
    expect(L.host("스마트 TV").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.kind === "dns.hijack")).toBe(true);
    expect(tr.some((e) => e.nodeId === L.id("스마트 TV") && e.kind === "dns.response.received" && e.summary.includes("서버 8.8.8.8"))).toBe(true);
    const off = patch(L.t, { forceDns: false });
    expect(lintTopology(off).map((i) => `${off.devices.find((d) => d.id === i.deviceId)!.name}:${i.code}`)).toEqual(["스마트 TV:adguard.bypass"]);
    L.apply(off);
    L.host("스마트 TV").resolver.clear();
    tr = L.act({ kind: "ping", nodeId: L.id("스마트 TV"), dst: "doubleclick.net" });
    expect(L.host("스마트 TV").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "dns.hijack")).toBe(false);
  });
});
