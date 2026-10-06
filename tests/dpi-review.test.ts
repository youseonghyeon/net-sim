// DPI 리뷰(2026-10-07) 회귀 테스트: 흐름 기억(난독화 뒤 다시 연결), IPv6, VPN 클라이언트 터널, 바깥에서 시작한 흐름, 서버 반쯤 열림, 분류·표시
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleDpiTopology, exampleDualStackHomeTopology } from "../src/model/examples";
import { Dpi } from "../src/core/nodes/dpi";
import type { Router } from "../src/core/nodes/router";
import type { Host } from "../src/core/nodes/host";
import type { Internet } from "../src/core/nodes/internet";
import type { Ipv4Packet } from "../src/core/packet";
import { headerLayers } from "../src/model/packetView";
import { wgPublicKeyOf, type Topology } from "../src/model/topology";

const obfuscate = (t: Topology, laptop: boolean, server: boolean): Topology => ({
  ...t,
  devices: t.devices.map((d) =>
    d.name === "직원 노트북" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, wg: { ...d.host!.ra!.wg!, obfuscate: laptop } } } } : d.router?.wgServer ? { ...d, router: { ...d.router, wgServer: { ...d.router.wgServer, obfuscate: server } } } : d,
  ),
});
const withRouter = (t: Topology, name: string, patch: object): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name && d.router ? { ...d, router: { ...d.router, ...patch } } : d)) });

describe("DPI 리뷰", () => {
  it("막힌 뒤 양쪽 난독화를 켜고 다시 연결하면 지나간다 (같은 포트의 흐름도 지금 모양으로 다시 본다)", () => {
    const t0 = exampleDpiTopology();
    const L = loadTopology(t0);
    expect(L.host("직원 노트북").ra.state).toBe("failed");
    L.apply(obfuscate(t0, true, true));
    L.act({ kind: "ra-reconnect", nodeId: L.id("직원 노트북") });
    expect(L.host("직원 노트북").ra.state).toBe("up");
  });

  it("IPv6 흐름도 검사한다", () => {
    const base = exampleDualStackHomeTopology();
    const rt = base.devices.find((d) => d.kind === "router")!;
    const pc = base.devices.find((d) => d.kind === "pc")!;
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.id === rt.id ? { ...d, router: { ...d.router!, dpi: { enabled: true, blockApps: ["ssh"], blockCategories: [] } } } : d)) };
    const L = loadTopology(t);
    const h = L.s.net.nodes.get(pc.id) as Host;
    L.s.net.scheduleAction(L.s.net.now, { kind: "tcp-connect", nodeId: pc.id, dst: "2404:6800:4004:827::200e", port: 22 });
    L.s.net.runToIdle();
    const c = [...h.tcp.conns.values()].filter((x) => x.role === "client").at(-1)!;
    expect(c.state).toBe("FAILED");
    expect(L.s.net.trace.some((e) => e.kind === "dpi.block" && e.summary.includes("SSH"))).toBe(true);
  });

  it("공유기의 WireGuard 클라이언트 터널로 가는 흐름도 먼저 검사한다", () => {
    const base = exampleDpiTopology();
    const office = base.devices.find((d) => d.name === "회사 공유기")!;
    const home = base.devices.find((d) => d.name === "집 Brume 3")!;
    const t: Topology = {
      ...base,
      devices: base.devices.map((d) => {
        if (d.id === office.id) return { ...d, router: { ...d.router!, wgClient: { enabled: true, server: "203.0.113.30", port: 51820, serverKey: wgPublicKeyOf(home, "server"), address: "10.0.0.3/32", allowedIps: "0.0.0.0/0", dns: "", killSwitch: false, policy: { mode: "all" as const, devices: [] } } } };
        if (d.id === home.id) return { ...d, router: { ...d.router!, wgServer: { ...d.router!.wgServer!, peers: [...d.router!.wgServer!.peers, { name: "회사", publicKey: wgPublicKeyOf(office, "client"), ip: "10.0.0.3" }] } } };
        if (d.name === "직원 노트북") return { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, enabled: false } } };
        return d;
      }),
    };
    const L = loadTopology(t);
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("직원 PC"), dst: "roblox.com", port: 443 });
    expect(L.lastConn("직원 PC").state).toBe("FAILED");
    expect(tr.some((e) => e.kind === "dpi.block" && e.summary.includes("Roblox"))).toBe(true);
  });

  it("바깥에서 시작한 흐름(포트 포워딩)은 드롭만 — 기록은 흐름당 한 번", () => {
    let t = exampleDpiTopology();
    t = withRouter(t, "회사 공유기", { dpi: { enabled: false, blockApps: [], blockCategories: [] } });
    t = withRouter(t, "집 Brume 3", { dpi: { enabled: true, blockApps: ["ssh"], blockCategories: [] }, forwards: [{ publicPort: 22, lanIp: "192.168.8.20", lanPort: 22 }] });
    t = { ...t, devices: t.devices.map((d) => (d.name === "집 NAS" ? { ...d, host: { ...d.host!, services: [80, 22] } } : d)) };
    const L = loadTopology(t);
    const tr = L.act({ kind: "inet-connect", nodeId: L.id("internet-1"), dst: "203.0.113.30", port: 22 });
    const blocks = tr.filter((e) => e.kind === "dpi.block");
    expect(blocks.length).toBe(1);
    expect(blocks[0]!.summary).toContain("바깥에서 시작한 흐름");
    expect(tr.some((e) => e.nodeId === L.id("집 NAS") && e.kind.startsWith("tcp.rst"))).toBe(false);
  });

  it("SNI 로 막은 연결은 서버 쪽에도 RST 를 넣어 반쯤 열린 채 남지 않는다", () => {
    const base = exampleDpiTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "직원 PC" ? { ...d, host: { ...d.host!, ipMode: "static", ip: "10.30.0.50", prefix: 24, gateway: "10.30.0.1", dns: "8.8.8.8" } } : d)) };
    const L = loadTopology(t);
    L.act({ kind: "tcp-connect", nodeId: L.id("직원 PC"), dst: "roblox.com", port: 443 });
    const inet = L.node<Internet>("internet-1");
    expect([...inet.tcp.conns.values()].some((c) => c.role === "server" && c.state === "ESTABLISHED")).toBe(false);
    // 재분류된 흐름의 수는 새 앱으로 옮겨 한 줄
    expect(L.node<Router>("회사 공유기").dpi.rows().filter((r) => r[0] === "10.30.0.50" && r[1].startsWith("HTTPS"))).toEqual([]);
  });

  it("사이트 간 VPN(WireGuard 식)·DDNS·DHCP 도 알아보고, 패킷 상세는 난독화 메시지를 WireGuard 로 풀지 않는다", () => {
    const dpi = new Dpi();
    dpi.config = { enabled: true, blockApps: [], blockCategories: ["VPN"] };
    const inner: Ipv4Packet = { kind: "ipv4", src: "10.1.0.5", dst: "10.2.0.5", ttl: 64, payload: { kind: "icmp", type: "echo-request", id: 1, seq: 1 } };
    const pkt: Ipv4Packet = { kind: "ipv4", src: "192.168.0.10", dst: "203.0.113.9", ttl: 64, payload: { kind: "udp", srcPort: 51820, dstPort: 51820, payload: { kind: "vpn", inner } } };
    expect(dpi.inspect(pkt, "out", "192.168.0.10", 0)).toMatchObject({ app: "wireguard", block: true });
    const L = loadTopology(obfuscate(exampleDpiTopology(), true, true));
    const frames = [...L.s.net.frameLog.values()].flat().map((x) => x.frame);
    const junk = frames.find((f) => f.payload.kind === "ipv4" && f.payload.payload.kind === "udp" && f.payload.payload.payload.kind === "wg" && f.payload.payload.payload.type === "junk")!;
    const obf = frames.find((f) => f.payload.kind === "ipv4" && f.payload.payload.kind === "udp" && f.payload.payload.payload.kind === "wg" && f.payload.payload.payload.obf && f.payload.payload.payload.type === "initiation")!;
    expect(headerLayers(junk).some((l) => l.title === "UDP 내용 (난독화)")).toBe(true);
    expect(headerLayers(obf).some((l) => l.title === "WireGuard")).toBe(false);
  });
});
