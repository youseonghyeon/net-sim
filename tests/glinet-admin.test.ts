// 공유기 관리 (GL.iNet 시스템 메뉴): 관리 화면 접근 제어, 기기 차단, GoodCloud 원격 관리
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleWireguardTopology } from "../src/model/examples";
import type { Router } from "../src/core/nodes/router";
import type { Internet } from "../src/core/nodes/internet";
import type { RouterSettings, Topology } from "../src/model/topology";
import { lintTopology } from "../src/model/lint";
import { exampleDropInTopology } from "../src/model/examples";

const HOME = "집 Brume 3";
const NAS = "집 NAS";
const router = (t: Topology, name: string, p: Partial<RouterSettings>): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? { ...d, router: { ...d.router!, ...p } } : d)) });
const admin = (t: Topology, p: Partial<NonNullable<RouterSettings["admin"]>> = {}) => router(t, HOME, { admin: { enabled: true, remote: false, allow: "", ssh: true, ...p } });

describe("관리 화면 접근 제어", () => {
  it("켜면 LAN 의 NAS 가 관리 화면(HTTP 80)·SSH 에 닿는다, 꺼져 있으면 듣는 서비스 없음", () => {
    const off = loadTopology(exampleWireguardTopology());
    let tr = off.act({ kind: "tcp-connect", nodeId: off.id(NAS), dst: "192.168.8.1", port: 80 });
    expect(tr.some((e) => e.summary.includes("듣는 서비스 없음"))).toBe(true);
    const L = loadTopology(admin(exampleWireguardTopology()));
    tr = L.act({ kind: "tcp-connect", nodeId: L.id(NAS), dst: "192.168.8.1", port: 80 });
    expect(L.lastConn(NAS).state).toBe("CLOSED");
    expect(L.lastConn(NAS).bytesReceived).toBeGreaterThan(0);
    L.act({ kind: "tcp-connect", nodeId: L.id(NAS), dst: "192.168.8.1", port: 22 });
    expect(L.lastConn(NAS).state).toBe("ESTABLISHED");
    expect(L.node<Router>(HOME).admin.rows().length).toBeGreaterThan(0);
  });

  it("허용 목록 밖의 LAN 기기는 드롭, 목록 안이면 된다", () => {
    const L = loadTopology(admin(exampleWireguardTopology(), { allow: "192.168.8.50/32" }));
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id(NAS), dst: "192.168.8.1", port: 443 });
    expect(tr.some((e) => e.kind === "fw.deny" && e.summary.includes("허용 목록"))).toBe(true);
    expect(L.lastConn(NAS).state).toBe("FAILED");
    const ok = loadTopology(admin(exampleWireguardTopology(), { allow: "192.168.8.0/24" }));
    ok.act({ kind: "tcp-connect", nodeId: ok.id(NAS), dst: "192.168.8.1", port: 443 });
    expect(ok.lastConn(NAS).state).toBe("CLOSED");
  });

  it("인터넷에서 공인 주소의 관리 화면: 기본은 드롭, 원격 접근을 켜면 열린다, 그 포트를 포워딩하면 포워딩이 이긴다", () => {
    let L = loadTopology(admin(exampleWireguardTopology()));
    let tr = L.act({ kind: "inet-connect", nodeId: L.id("internet-1"), dst: "203.0.113.30", port: 443 });
    expect(tr.some((e) => e.kind === "fw.deny" && e.summary.includes("WAN 에서의 관리 접근이 꺼져"))).toBe(true);
    L = loadTopology(admin(exampleWireguardTopology(), { remote: true }));
    tr = L.act({ kind: "inet-connect", nodeId: L.id("internet-1"), dst: "203.0.113.30", port: 443 });
    expect(tr.some((e) => e.kind === "fw.allow" && e.summary.includes("WAN 원격 접근"))).toBe(true);
    expect(L.node<Router>(HOME).admin.rows().some((r) => r.join(" ").includes("198.51.100.7"))).toBe(true);
    const fwd = router(admin(exampleWireguardTopology(), { remote: true }), HOME, { forwards: [{ publicPort: 443, lanIp: "192.168.8.20", lanPort: 80 }] });
    L = loadTopology(fwd);
    tr = L.act({ kind: "inet-connect", nodeId: L.id("internet-1"), dst: "203.0.113.30", port: 443 });
    expect(tr.some((e) => e.summary.includes("관리 접근 제어"))).toBe(false);
    expect(tr.some((e) => e.nodeId === L.id(NAS) && e.kind === "tcp.syn.received")).toBe(true);
  });
});

describe("기기 차단", () => {
  it("차단한 MAC 은 인터넷으로 못 나가지만 LAN·공유기와는 통신한다", () => {
    const base = exampleWireguardTopology();
    const nas = base.devices.find((d) => d.name === NAS)!;
    const L = loadTopology(router(base, HOME, { blocked: [nas.mac] }));
    const tr = L.act({ kind: "ping", nodeId: L.id(NAS), dst: "8.8.8.8" });
    expect(L.host(NAS).pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.kind === "fw.deny" && e.summary.includes("기기 차단"))).toBe(true);
    L.act({ kind: "ping", nodeId: L.id(NAS), dst: "192.168.8.1" });
    expect(L.host(NAS).pings.at(-1)!.status).toBe("ok");
  });
});

describe("GoodCloud", () => {
  it("호텔 NAT 뒤의 여행용 공유기도 먼저 연 연결로 원격 관리를 받는다 (포트 포워딩 없이)", () => {
    const L = loadTopology(router(exampleWireguardTopology(), "여행용 공유기", { cloud: true }));
    const travel = L.node<Router>("여행용 공유기");
    expect(travel.cloud.registered).toBe(true);
    const tr = L.act({ kind: "cloud-manage", nodeId: L.id("internet-1"), device: travel.cloud.device });
    expect(tr.some((e) => e.kind === "cloud.manage")).toBe(true);
    expect(tr.some((e) => e.kind === "cloud.server" && e.summary.includes("상태 받음"))).toBe(true);
    expect(L.node<Internet>("internet-1").cloud.rows()[0]![3]).toContain("WAN");
  });

  it("GoodCloud 를 끄면 등록이 남아 있어도 요청에 답하지 않아 timeout", () => {
    const t = router(exampleWireguardTopology(), "여행용 공유기", { cloud: true });
    const L = loadTopology(t);
    const dev = L.node<Router>("여행용 공유기").cloud.device;
    L.apply(router(t, "여행용 공유기", { cloud: false }));
    const tr = L.act({ kind: "cloud-manage", nodeId: L.id("internet-1"), device: dev });
    expect(tr.some((e) => e.kind === "cloud.server" && e.summary.includes("응답 없음"))).toBe(true);
  });
});

describe("구성 검사 (공유기 관리)", () => {
  it("관리 화면을 WAN 에 열면 admin.remote-open, 드롭인인데 WAN 이 자동이면 dropin.wan-dhcp", () => {
    const codes = (t: Topology) => lintTopology(t).map((i) => i.code);
    expect(codes(admin(exampleWireguardTopology()))).not.toContain("admin.remote-open");
    expect(codes(admin(exampleWireguardTopology(), { remote: true }))).toContain("admin.remote-open");
    const di = exampleDropInTopology();
    const auto: Topology = { ...di, devices: di.devices.map((d) => (d.router?.dropIn ? { ...d, router: { ...d.router, wan: { ipMode: "dhcp" as const, ip: "", prefix: 24, gateway: "" } } } : d)) };
    expect(codes(auto)).toContain("dropin.wan-dhcp");
  });
});


describe("네트워크 저장소 (Samba)", () => {
  it("LAN 의 NAS 가 공유기 SMB(445)에 접속하고, 인터넷에서는 막힌다, WAN 을 열면 구성 검사 samba.wan-open", () => {
    const t = router(exampleWireguardTopology(), HOME, { samba: { enabled: true, wan: false } });
    const L = loadTopology(t);
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id(NAS), dst: "192.168.8.1", port: 445 });
    expect(L.lastConn(NAS).state).toBe("CLOSED");
    expect(tr.some((e) => e.summary.includes("SMB 파일 목록"))).toBe(true);
    const tr2 = L.act({ kind: "inet-connect", nodeId: L.id("internet-1"), dst: "203.0.113.30", port: 445 });
    expect(tr2.some((e) => e.kind === "fw.deny" && e.summary.includes("SMB"))).toBe(true);
    expect(lintTopology(router(t, HOME, { samba: { enabled: true, wan: true } })).map((i) => i.code)).toContain("samba.wan-open");
    expect(lintTopology(router(t, HOME, { forwards: [{ publicPort: 445, lanIp: "192.168.8.20", lanPort: 445 }] })).map((i) => i.code)).toContain("nat.forward-smb");
  });
});
