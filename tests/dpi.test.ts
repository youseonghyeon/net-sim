// DPI 와 VPN 난독화: 흐름의 앱 알아보기(SNI·DNS 로 배운 주소·모양·포트)·통계·차단(RST 주입), WireGuard 난독화로 VPN 차단 지나가기
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleDpiTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import type { Topology } from "../src/model/topology";

const load = (t: Topology = exampleDpiTopology()) => loadTopology(t);
const obfuscate = (t: Topology, laptop: boolean, server: boolean): Topology => ({
  ...t,
  devices: t.devices.map((d) =>
    d.name === "직원 노트북" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, wg: { ...d.host!.ra!.wg!, obfuscate: laptop } } } } : d.router?.wgServer ? { ...d, router: { ...d.router, wgServer: { ...d.router.wgServer, obfuscate: server } } } : d,
  ),
});

describe("DPI", () => {
  it("WireGuard 는 첫 패킷 모양(148바이트 Initiation)으로 들켜 막힌다", () => {
    const { t, host, s, id } = load();
    expect(lintTopology(t)).toEqual([]);
    expect(host("직원 노트북").ra.state).toBe("failed");
    expect(s.net.trace.some((e) => e.nodeId === id("회사 공유기") && e.kind === "dpi.block" && e.summary.includes("WireGuard 모양"))).toBe(true);
  });

  it("양쪽 난독화를 켜면 알아볼 수 없는 UDP 가 되어 지나가고, 한쪽만 켜면 구성 검사가 짚고 서버는 침묵한다", () => {
    const L = load(obfuscate(exampleDpiTopology(), true, true));
    expect(lintTopology(L.t)).toEqual([]);
    expect(L.host("직원 노트북").ra.state).toBe("up");
    expect(L.s.net.trace.some((e) => e.kind === "dpi.app" && e.summary.includes("알 수 없음"))).toBe(true);
    L.act({ kind: "ping", nodeId: L.id("직원 노트북"), dst: "192.168.8.20" });
    expect(L.host("직원 노트북").pings.at(-1)!.status).toBe("ok");
    const half = obfuscate(exampleDpiTopology(), true, false);
    expect(lintTopology(half).map((i) => i.code)).toEqual(["wg.obfuscation-mismatch"]);
    const H = load(half);
    expect(H.host("직원 노트북").ra.state).toBe("failed");
    expect(H.s.net.trace.some((e) => e.nodeId === H.id("집 Brume 3") && e.kind === "vpn.drop" && e.summary.includes("난독화"))).toBe(true);
  });

  it("'알 수 없음' 까지 막으면 난독화한 VPN 도 막힌다", () => {
    const base = obfuscate(exampleDpiTopology(), true, true);
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.router?.dpi ? { ...d, router: { ...d.router, dpi: { ...d.router.dpi, blockCategories: [...d.router.dpi.blockCategories, "알 수 없음"] } } } : d)) };
    expect(load(t).host("직원 노트북").ra.state).toBe("failed");
  });

  it("roblox.com 은 DNS 로 배운 주소로 게임이라 SYN 에서 RST, youtube.com 은 통과하고 앱별로 센다", () => {
    const { id, act, lastConn, node } = load();
    let tr = act({ kind: "tcp-connect", nodeId: id("직원 PC"), dst: "roblox.com", port: 443 });
    expect(lastConn("직원 PC").state).toBe("FAILED");
    expect(tr.some((e) => e.kind === "dpi.block" && e.summary.includes("Roblox") && e.summary.includes("DNS 로 배운 주소"))).toBe(true);
    tr = act({ kind: "tcp-connect", nodeId: id("직원 PC"), dst: "youtube.com", port: 443 });
    expect(lastConn("직원 PC").state).toBe("CLOSED");
    const rows = node<Router>("회사 공유기").dpi.rows();
    expect(rows.some((r) => r[1] === "YouTube" && r[2] === "동영상")).toBe(true);
    expect(rows.some((r) => r[1] === "Roblox · 차단")).toBe(true);
  });

  it("DNS 를 공유기 밖에 직접 적은 기기는 주소를 배울 수 없어 처음엔 HTTPS 로 보다가, TLS SNI 를 보고 게임이라 연결 중간에 RST", () => {
    const base = exampleDpiTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "직원 PC" ? { ...d, host: { ...d.host!, ipMode: "static", ip: "10.30.0.50", prefix: 24, gateway: "10.30.0.1", dns: "8.8.8.8" } } : d)) };
    const { id, act, lastConn } = load(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("직원 PC"), dst: "roblox.com", port: 443 });
    expect(tr.some((e) => e.kind === "dpi.app" && e.summary.includes("HTTPS (이름 모름)"))).toBe(true);
    expect(tr.some((e) => e.kind === "dpi.block" && e.summary.includes("TLS SNI roblox.com"))).toBe(true);
    expect(lastConn("직원 PC").state).toBe("FAILED");
  });
});
