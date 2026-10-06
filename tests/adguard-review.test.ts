// AdGuard 리뷰(2026-10-07) 회귀 테스트: 프록시 경유, IPv6 로 묻는 기기(자녀 보호·DNS 가로채기), LAN DNS 서버 경유 오탐, IPv6 게이트웨이 없는 :: 답
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleAdguardTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import { createDevice, DEFAULT_DHCP_SERVER, type Device, type Topology } from "../src/model/topology";

const sw = (t: Topology) => t.devices.find((d) => d.name === "거실 스위치")!;
function addHost(t: Topology, name: string, port: number, host: NonNullable<Device["host"]>, kind: "pc" | "server" = "pc"): Topology {
  const d = createDevice(kind, 0, 400, t.devices);
  d.name = name;
  d.host = host;
  return { ...t, devices: [...t.devices, d], cables: [...t.cables, { id: `c-${name}`, a: { device: sw(t).id, port }, b: { device: d.id, port: 0 } }] };
}
const withRouter6 = (t: Topology): Topology => ({ ...t, devices: t.devices.map((d) => (d.router?.adguard ? { ...d, router: { ...d.router, ipv6: { enabled: true, inboundBlock: true } } } : d)) });

describe("AdGuard 리뷰", () => {
  it("프록시 서버도 0.0.0.0 답이면 그 주소로 연결하지 않고 바로 503", () => {
    let t = exampleAdguardTopology();
    t = addHost(t, "프록시", 3, { ipMode: "static", ip: "192.168.8.20", prefix: 24, gateway: "192.168.8.1", dns: "192.168.8.1", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER }, proxy: { enabled: true, port: 3128, deny: [] } }, "server");
    t = addHost(t, "PC2", 4, { ipMode: "static", ip: "192.168.8.30", prefix: 24, gateway: "192.168.8.1", dns: "192.168.8.1", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER }, httpProxy: { enabled: true, server: "192.168.8.20", port: 3128 } });
    const L = loadTopology(t);
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("PC2"), dst: "doubleclick.net", port: 80 });
    expect(tr.some((e) => e.summary.includes("0.0.0.0) 에") && e.kind.startsWith("proxy"))).toBe(false);
    expect(tr.some((e) => e.summary.includes("DNS 가 막은 이름"))).toBe(true);
    expect(L.s.net.now).toBeLessThan(2000);
  });

  it("아이 기기가 IPv6 로 DNS 를 물어도 자녀 보호가 걸린다 (이웃 캐시 → MAC → IPv4)", () => {
    let t = withRouter6(exampleAdguardTopology());
    t = { ...t, devices: t.devices.map((d) => (d.name === "아이 태블릿" ? { ...d, host: { ...d.host!, dns: "", ipv6: { enabled: true, mode: "slaac", ip: "", prefix: 64, gateway: "" } } } : d)) };
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id("아이 태블릿"), dst: "roblox.com" });
    expect(tr.some((e) => e.kind === "dns.blocked" && e.summary.includes("자녀 보호"))).toBe(true);
    expect(L.host("아이 태블릿").pings.at(-1)!.status).toBe("failed");
  });

  it("DNS 가로채기는 IPv6 로 바깥 DNS 에 직접 묻는 질의도 받는다", () => {
    let t = withRouter6(exampleAdguardTopology());
    // 수동 IPv6 + 바깥 IPv6 DNS 직접 (IPv4 DNS 없음 — 리졸버가 IPv6 DNS 에 묻는다)
    t = { ...t, devices: t.devices.map((d) => (d.name === "스마트 TV" ? { ...d, host: { ...d.host!, dns: "", ipv6: { enabled: true, mode: "static", ip: "2001:db8:1000:100::60", prefix: 64, gateway: "2001:db8:1000:100::1", dns: "2001:4860:4860::8888" } } } : d)) };
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id("스마트 TV"), dst: "doubleclick.net" });
    expect(tr.some((e) => e.kind === "dns.hijack" && e.summary.includes("IPv6"))).toBe(true);
    expect(L.host("스마트 TV").pings.at(-1)!.status).toBe("failed");
    // 가로채기를 끄면 구성 검사가 IPv6 DNS 도 짚는다
    const off: Topology = { ...t, devices: t.devices.map((d) => (d.router?.adguard ? { ...d, router: { ...d.router, adguard: { ...d.router.adguard, forceDns: false } } } : d)) };
    expect(lintTopology(off).map((i) => i.code)).toContain("adguard.bypass");
  });

  it("DNS 가 LAN 의 DNS 서버이고 그 서버가 공유기에 되물으면 adguard.bypass 오탐이 없다", () => {
    let t = exampleAdguardTopology();
    t = { ...t, devices: t.devices.map((d) => (d.router?.adguard ? { ...d, router: { ...d.router, adguard: { ...d.router.adguard, forceDns: false } } } : d)) };
    t = addHost(t, "사내 DNS", 3, { ipMode: "static", ip: "192.168.8.10", prefix: 24, gateway: "192.168.8.1", dns: "192.168.8.1", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER }, dnsServer: { enabled: true, records: [], upstream: "192.168.8.1" } }, "server");
    t = addHost(t, "PC2", 4, { ipMode: "static", ip: "192.168.8.30", prefix: 24, gateway: "192.168.8.1", dns: "192.168.8.10", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } });
    const codes = lintTopology(t).map((i) => `${t.devices.find((d) => d.id === i.deviceId)!.name}:${i.code}`);
    expect(codes).not.toContain("PC2:adguard.bypass");
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id("PC2"), dst: "doubleclick.net" });
    expect(L.host("PC2").pings.at(-1)!.status).toBe("failed");
  });

  it("IPv6 게이트웨이 없는 듀얼 스택 기기: :: 답이면 A 로 다시 묻지 않고 바로 막힌 이름", () => {
    let t = withRouter6(exampleAdguardTopology());
    t = { ...t, devices: t.devices.map((d) => (d.name === "아빠 PC" ? { ...d, host: { ...d.host!, ipv6: { enabled: true, mode: "static", ip: "2001:db8:1000:100::50", prefix: 64, gateway: "" } } } : d)) };
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id("아빠 PC"), dst: "doubleclick.net" });
    expect(L.host("아빠 PC").pings.at(-1)!.reason).toContain("DNS 가 막은 이름");
    expect(tr.filter((e) => e.kind === "dns.blocked").length).toBe(1);
    expect(L.node<Router>("집 Brume 3").adguard.stats.blocked).toBe(1);
  });
});
