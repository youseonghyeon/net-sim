// 공유기 스태틱 라우트 (LuCI Static Routes)·WAN2 "디폴트 라우트로 쓰지 않음"·직접 연결된 대역은 그 회선으로 (mwan3_connected)
// 예제: 망분리 사무실 재택 접속 (WireGuard 공유기) — 재택 노트북 → WireGuard → 사무실 공유기 → WAN2(내부망) → IPsec → NCP
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { builder, cable } from "../src/model/examples/build";
import { exampleMultiWanPolicyTopology, exampleSeparatedRemoteTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import { practitionerLines } from "../src/model/packetView";
import type { Router } from "../src/core/nodes/router";
import { DEFAULT_DHCP_SERVER, DEFAULT_ROUTER_WG_CLIENT, parseTopology, serializeTopology, type Device, type RouterRouteSetting, type Topology } from "../src/model/topology";

const OFFICE = "사무실 공유기";
const patchDev = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });
const patchRouter = (t: Topology, f: (r: NonNullable<Device["router"]>) => NonNullable<Device["router"]>) => patchDev(t, OFFICE, (d) => ({ ...d, router: f(d.router!) }));
const withRoutes = (t: Topology, routes: RouterRouteSetting[]) => patchRouter(t, (r) => ({ ...r, routes }));
const lintOf = (t: Topology, code: string) => lintTopology(t).filter((i) => i.code === code).map((i) => i.message);
/** 사무실 공유기 LAN 에 PC 하나 (DHCP) */
const withLanPc = (t: Topology): Topology => {
  const { devices, add } = builder();
  devices.push(...t.devices);
  const pc = add("pc", 360, 200, "사무실 LAN PC");
  const office = t.devices.find((d) => d.name === OFFICE)!;
  return { ...t, devices, cables: [...t.cables, cable(office, 1, pc, 0)] };
};
const withoutWan1 = (t: Topology): Topology => {
  const id = t.devices.find((d) => d.name === OFFICE)!.id;
  return { ...t, cables: t.cables.filter((c) => !((c.a.device === id && c.a.port === 0) || (c.b.device === id && c.b.port === 0))) };
};

describe("예제: 망분리 사무실 재택 접속 (WireGuard 공유기)", () => {
  it("구성 검사 0, 재택 노트북 WireGuard 연결", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    expect(lintTopology(L.t)).toEqual([]);
    expect(L.host("재택 노트북").ra.state).toBe("up");
  });

  it("노트북 → 192.168.111.11 ping: 스태틱 라우트로 WAN2, 출발지 10.50.10.18 로 MASQUERADE, IPsec 으로 NCP", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    const tr = L.act({ kind: "ping", nodeId: L.id("재택 노트북"), dst: "192.168.111.11" });
    expect(L.host("재택 노트북").pings.at(-1)!.status).toBe("ok");
    const fwd = tr.find((e) => e.nodeId === L.id(OFFICE) && e.kind === "ip.forward" && e.details?.dst === "192.168.111.11")!;
    expect(fwd.details).toMatchObject({ out: "wan2", route: "192.168.111.0/24", via: "10.50.10.254", iface: "wan2" });
    expect(fwd.summary).toContain("스태틱 라우트 192.168.111.0/24 → 넥스트 홉 10.50.10.254, WAN2(lan4)");
    expect(fwd.summary).toContain("mwan3 정책을 거치지 않음, 10.50.10.18 로 MASQUERADE");
    const nat = tr.find((e) => e.nodeId === L.id(OFFICE) && e.kind === "nat.translate")!;
    expect(nat.summary).toContain("10.1.0.2 (ICMP");
    expect(nat.summary).toContain("→ 10.50.10.18");
    expect(nat.summary).not.toContain("공인 주소");
    // NCP 서버가 받은 ping 의 출발지는 사무실 공유기의 WAN2 주소
    expect(L.wire("dev-1").some((p) => p.src === "10.50.10.18")).toBe(true);
    expect(L.wire("dev-1").some((p) => p.src === "10.1.0.2")).toBe(false);
    // 기존 IPsec 터널을 지난다
    expect(tr.some((e) => e.nodeId === L.id("내부망 방화벽 NAT") && e.kind === "ip.forward" && e.summary.includes("VPN 상대 대역"))).toBe(true);
  });

  it("노트북 → dev-1 SSH 와 내부망 PC 1 SSH (내부망은 WAN2 에 직접 연결된 대역)", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    L.act({ kind: "tcp-connect", nodeId: L.id("재택 노트북"), dst: "192.168.111.11", port: 22 });
    expect(L.lastConn("재택 노트북").ssh?.open).toBe(true);
    expect(L.serverConns("dev-1").at(-1)!.remoteIp).toBe("10.50.10.18");
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("재택 노트북"), dst: "10.50.10.1", port: 22 });
    expect(L.lastConn("재택 노트북").ssh?.open).toBe(true);
    expect(L.serverConns("내부망 PC 1").at(-1)!.remoteIp).toBe("10.50.10.18");
    const fwd = tr.find((e) => e.nodeId === L.id(OFFICE) && e.kind === "ip.forward" && e.details?.dst === "10.50.10.1")!;
    expect(fwd.details).toMatchObject({ out: "wan2", connected: "10.50.10.0/24" });
    expect(fwd.summary).toContain("WAN2(lan4) 에 직접 연결된 대역(10.50.10.0/24)");
  });

  it("노트북 WireGuard 를 끄면 닿지 않는다 (사설 주소가 집 인터넷으로 나가 드롭)", () => {
    const t = patchDev(exampleSeparatedRemoteTopology(), "재택 노트북", (d) => ({ ...d, host: { ...d.host!, ra: { ...d.host!.ra!, enabled: false } } }));
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id("재택 노트북"), dst: "192.168.111.11" });
    expect(L.host("재택 노트북").pings.at(-1)!.status).not.toBe("ok");
  });

  it("표: 라우팅 테이블 (main) — 직접 연결·디폴트 라우트(WAN1 만)·스태틱", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    const table = L.s.net.nodes.get(L.id(OFFICE))!.snapshot().tables!.find((x) => x.title === "라우팅 테이블 (main)")!;
    expect(table.rows).toEqual([
      ["lan", "192.168.8.0/24", "", "직접 연결"],
      ["wan", "203.0.113.0/24", "", "직접 연결"],
      ["wan", "0.0.0.0/0", "203.0.113.1", "디폴트 라우트"],
      ["wan2", "10.50.10.0/24", "", "직접 연결"],
      ["wan2", "192.168.111.0/24", "10.50.10.254", "스태틱"],
      ["wan2", "192.168.112.0/24", "10.50.10.254", "스태틱"],
      ["wan2", "192.168.113.0/24", "10.50.10.254", "스태틱"],
      ["wan2", "172.21.4.0/24", "10.50.10.254", "스태틱"],
    ]);
    const mwan = L.s.net.nodes.get(L.id(OFFICE))!.snapshot().tables!.find((x) => x.title === "멀티 WAN (mwan3 status)")!;
    expect(mwan.rows[1]).toEqual(["WAN2", "연결됨", "mwan3 에서 뺌 (디폴트 라우트로 안 씀)", "추적 안 함"]);
  });

  it("실무 출력: 스태틱 라우트로 나간 전달은 LuCI 라우트 줄", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    const tr = L.act({ kind: "ping", nodeId: L.id("재택 노트북"), dst: "192.168.111.11" });
    const fwd = tr.find((e) => e.nodeId === L.id(OFFICE) && e.kind === "ip.forward" && e.details?.route !== undefined)!;
    const line = practitionerLines(fwd, L.s.net.framesAt(fwd.packetId!, fwd.nodeId, fwd.time)).find((l) => l.tool === "OpenWrt LuCI 상태 → 라우트")!.line;
    expect(line).toBe("Network  Target              IPv4 gateway     Metric  Table\nwan2     192.168.111.0/24    10.50.10.254     0       main");
  });
});

describe("WAN2 디폴트 라우트로 쓰지 않음", () => {
  it("WAN1 이 끊겨도 인터넷 트래픽은 WAN2(내부망)로 넘어가지 않는다", () => {
    const L = loadTopology(withLanPc(exampleSeparatedRemoteTopology()));
    const r = L.node<Router>(OFFICE);
    L.apply(withoutWan1(L.t));
    expect(r.mwan.active).toBe("wan");
    const tr = L.act({ kind: "ping", nodeId: L.id("사무실 LAN PC"), dst: "8.8.8.8" });
    expect(L.host("사무실 LAN PC").pings.at(-1)!.status).not.toBe("ok");
    expect(tr.some((e) => e.nodeId === L.id(OFFICE) && e.kind === "ip.forward" && e.details?.out === "wan2")).toBe(false);
    expect(L.wire("내부망 스위치 1").some((p) => p.dst === "8.8.8.8")).toBe(false);
    // 스태틱 라우트·직접 연결된 대역은 그대로 WAN2
    L.act({ kind: "ping", nodeId: L.id("사무실 LAN PC"), dst: "192.168.111.11" });
    expect(L.host("사무실 LAN PC").pings.at(-1)!.status).toBe("ok");
  });

  it("비교: 디폴트 라우트로 쓰면 WAN1 이 끊길 때 인터넷 트래픽이 WAN2(내부망)로 넘어간다 (페일오버)", () => {
    const t = patchRouter(withLanPc(exampleSeparatedRemoteTopology()), (r) => ({ ...r, wan2: { ...r.wan2!, defaultRoute: undefined, gateway: "10.50.10.254" } }));
    const L = loadTopology(t);
    L.apply(withoutWan1(L.t));
    expect(L.node<Router>(OFFICE).mwan.active).toBe("wan2");
    const tr = L.act({ kind: "ping", nodeId: L.id("사무실 LAN PC"), dst: "8.8.8.8" });
    expect(tr.some((e) => e.nodeId === L.id(OFFICE) && e.kind === "ip.forward" && e.details?.out === "wan2" && e.details?.dst === "8.8.8.8")).toBe(true);
    expect(lintOf(L.t, "mwan.rule-no-default")).toEqual([]);
  });

  it("WAN2 를 가리키는 정책 규칙은 WAN1 로 (요약에 이유), 구성 검사 mwan.rule-no-default", () => {
    const t = patchRouter(withLanPc(exampleSeparatedRemoteTopology()), (r) => ({ ...r, wan2: { ...r.wan2!, rules: [{ src: "192.168.8.0/24", line: "wan2" }] } }));
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id("사무실 LAN PC"), dst: "8.8.8.8" });
    expect(L.host("사무실 LAN PC").pings.at(-1)!.status).toBe("ok");
    const fwd = tr.find((e) => e.nodeId === L.id(OFFICE) && e.kind === "ip.forward" && e.details?.dst === "8.8.8.8")!;
    expect(fwd.details!.out).toBe("wan");
    expect(fwd.summary).toContain("이지만 WAN2을 디폴트 라우트로 쓰지 않아 지금 회선으로");
    expect(L.node<Router>(OFFICE).mwan.ruleRows()[0]![3]).toBe("디폴트 라우트로 안 씀 → WAN1");
    expect(lintOf(L.t, "mwan.rule-no-default")).toEqual([expect.stringContaining("멀티 WAN 정책 규칙 1번(192.168.8.0/24) 은 WAN2 로 보내지만 WAN2 를 디폴트 라우트로 쓰지 않음")]);
  });
});

describe("스태틱 라우트", () => {
  it("넥스트 홉이 그 인터페이스 대역 밖이면 쓰이지 않는다 (디폴트 라우트로 나가 닿지 않음) + 구성 검사", () => {
    const t = withRoutes(exampleSeparatedRemoteTopology(), [{ iface: "wan2", dest: "192.168.111.0/24", via: "10.60.0.1" }]);
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id("재택 노트북"), dst: "192.168.111.11" });
    expect(L.host("재택 노트북").pings.at(-1)!.status).not.toBe("ok");
    expect(tr.find((e) => e.nodeId === L.id(OFFICE) && e.kind === "ip.forward" && e.details?.dst === "192.168.111.11")!.details!.out).toBe("wan");
    const rows = L.s.net.nodes.get(L.id(OFFICE))!.snapshot().tables!.find((x) => x.title === "라우팅 테이블 (main)")!.rows;
    expect(rows.at(-1)).toEqual(["wan2", "192.168.111.0/24", "10.60.0.1", "스태틱 — 쓰이지 않음 (넥스트 홉이 wan2 대역(10.50.10.0/24) 밖)"]);
    expect(lintOf(L.t, "router.route-invalid")).toEqual([expect.stringContaining("스태틱 라우트 1번(넥스트 홉 10.60.0.1 가 WAN2 대역(10.50.10.0/24) 밖)")]);
  });

  it("구성 검사: 대상·넥스트 홉 형식, 멀티 WAN 이 꺼진 WAN2, 내 주소를 넥스트 홉으로 — 한 메시지로", () => {
    const base = exampleSeparatedRemoteTopology();
    const bad = withRoutes(base, [
      { iface: "wan2", dest: "", via: "10.50.10.254" },
      { iface: "wan2", dest: "192.168.111.0/33", via: "10.50.10.254" },
      { iface: "wan2", dest: "192.168.112.0/24", via: "x" },
      { iface: "wan2", dest: "192.168.113.0/24", via: "10.50.10.18" },
      { iface: "wan", dest: "198.51.100.0/24", via: "203.0.113.1" },
    ]);
    expect(lintOf(bad, "router.route-invalid")).toEqual([
      '스태틱 라우트 1번(대상이 비어 있음), 2번(대상 "192.168.111.0/33" 이 대역이 아님), 3번(넥스트 홉 "x" 이 주소가 아님), 4번(넥스트 홉 10.50.10.18 가 공유기 자신의 WAN2 주소) → 그 경로는 쓰이지 않아 그 대역도 디폴트 라우트(지금 회선)로 나감',
    ]);
    const off = patchRouter(withRoutes(base, [{ iface: "wan2", dest: "192.168.111.0/24", via: "10.50.10.254" }]), (r) => ({ ...r, wan2: { ...r.wan2!, enabled: false } }));
    expect(lintOf(off, "router.route-invalid")).toEqual([expect.stringContaining("1번(멀티 WAN 이 꺼져 WAN2 가 없음)")]);
    // WAN2 가 자동(DHCP)이면 대역을 몰라 넥스트 홉은 보지 않는다
    const dhcp = patchRouter(withRoutes(base, [{ iface: "wan2", dest: "192.168.111.0/24", via: "10.60.0.1" }]), (r) => ({ ...r, wan2: { ...r.wan2!, ipMode: "dhcp", ip: "" } }));
    expect(lintOf(dhcp, "router.route-invalid")).toEqual([]);
  });

  it("LAN 대역보다 긴 스태틱 라우트가 먼저 (longest prefix match)", () => {
    let t = withRoutes(exampleSeparatedRemoteTopology(), [{ iface: "wan2", dest: "192.168.8.128/25", via: "10.50.10.254" }]);
    t = patchDev(t, "재택 노트북", (d) => ({ ...d, host: { ...d.host!, ra: { ...d.host!.ra!, wg: { ...d.host!.ra!.wg!, allowedIps: `${d.host!.ra!.wg!.allowedIps}, 192.168.8.0/24` } } } }));
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id("재택 노트북"), dst: "192.168.8.200" });
    const fwd = tr.find((e) => e.nodeId === L.id(OFFICE) && e.kind === "ip.forward" && e.details?.dst === "192.168.8.200")!;
    expect(fwd.details).toMatchObject({ out: "wan2", route: "192.168.8.128/25" });
  });

  it("수동 주소 WAN2 의 케이블이 빠져도 경로는 남는다 (force_link 1) — 사설 대역이 WAN1(ISP)로 새지 않고 끊긴 WAN2 에서 버려진다", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    const id = L.id(OFFICE);
    L.apply({ ...L.t, cables: L.t.cables.filter((c) => !((c.a.device === id && c.a.port === 4) || (c.b.device === id && c.b.port === 4))) });
    const tr = L.act({ kind: "ping", nodeId: L.id("재택 노트북"), dst: "192.168.111.11" });
    expect(L.host("재택 노트북").pings.at(-1)!.status).not.toBe("ok");
    expect(tr.find((e) => e.nodeId === id && e.kind === "ip.forward" && e.details?.dst === "192.168.111.11")!.details!.out).toBe("wan2");
    expect(L.wire("internet-1").some((p) => p.dst === "192.168.111.11")).toBe(false);
  });

  it("모델: 저장·불러오기에 스태틱 라우트와 디폴트 라우트 끔이 남는다", () => {
    const t = exampleSeparatedRemoteTopology();
    const back = parseTopology(serializeTopology(t)).topology!;
    const r = back.devices.find((d) => d.name === OFFICE)!.router!;
    expect(r.routes).toEqual(t.devices.find((d) => d.name === OFFICE)!.router!.routes);
    expect(r.wan2!.defaultRoute).toBe(false);
  });
});

// 리뷰(2026-10-19) 회귀
describe("review: 스태틱 라우트·main 테이블", () => {
  it("멀티 WAN 예제: WAN1 이 손실 100% 로 끊겨도 WireGuard 서버는 WAN2 로 답하고 폰이 로밍으로 따라온다 (평평한 인터넷의 WAN1 대역에 묶지 않음)", () => {
    const t = exampleMultiWanPolicyTopology();
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "8.8.8.8" });
    const r = L.node<Router>("집 Brume 3");
    const id = L.id("집 Brume 3");
    L.apply({ ...L.t, cables: L.t.cables.map((c) => ((c.a.device === id && c.a.port === 0) || (c.b.device === id && c.b.port === 0) ? { ...c, loss: 100 } : c)) });
    L.s.net.runUntil(L.s.net.now + 30_000);
    expect(r.mwan.active).toBe("wan2");
    const tr = L.act({ kind: "ping", nodeId: L.id("집 NAS"), dst: "10.0.0.2" });
    expect(L.host("집 NAS").pings.at(-1)!.status).toBe("ok");
    expect(tr.find((e) => e.nodeId === L.id("집 Brume 3") && e.kind === "vpn.encap")!.summary).toContain("UDP 192.168.225.100:51820");
  });

  it("공유기의 WireGuard 클라이언트도 서버가 main 테이블 경로 뒤면 그 회선에서 보낸다", () => {
    const t = patchRouter(exampleSeparatedRemoteTopology(), (r) => ({ ...r, wgClient: { ...DEFAULT_ROUTER_WG_CLIENT, server: "10.50.10.1", serverKey: "x".repeat(43) + "=", address: "10.9.0.2/32", allowedIps: "10.9.0.0/24" } }));
    const L = loadTopology(t);
    const init = L.wire("내부망 스위치 1").filter((p) => p.payload.kind === "udp" && p.payload.payload.kind === "wg");
    expect(init.length).toBeGreaterThan(0);
    expect(init[0]!.src).toBe("10.50.10.18");
    expect(L.wire("internet-1").some((p) => p.dst === "10.50.10.1")).toBe(false);
  });

  it("스태틱 라우트 0.0.0.0/0 은 쓰지 않는다 (디폴트 라우트는 mwan3 정책) + 구성 검사", () => {
    const t = withRoutes(withLanPc(exampleSeparatedRemoteTopology()), [{ iface: "wan2", dest: "0.0.0.0/0", via: "10.50.10.254" }]);
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id("사무실 LAN PC"), dst: "8.8.8.8" });
    expect(L.host("사무실 LAN PC").pings.at(-1)!.status).toBe("ok");
    expect(tr.find((e) => e.nodeId === L.id(OFFICE) && e.kind === "ip.forward" && e.details?.dst === "8.8.8.8")!.details!.out).toBe("wan");
    expect(lintOf(L.t, "router.route-invalid")).toEqual([expect.stringContaining("1번(대상이 0.0.0.0/0(디폴트 라우트)")]);
  });

  it("디폴트 라우트로 쓰지 않는 WAN2 의 게이트웨이는 쓰지 않는다: 경로 없는 상대에게 하는 답은 main 디폴트(WAN1)로", () => {
    // 내부망 게이트웨이 if2 뒤에 10.60.0.0/24 서버 하나
    const withSrv = (t: Topology): Topology => {
      const { devices, add } = builder();
      devices.push(...t.devices.map((d) => (d.name === "내부망 게이트웨이" ? { ...d, l3: { ...d.l3!, interfaces: [d.l3!.interfaces[0]!, d.l3!.interfaces[1]!, { ipMode: "static" as const, ip: "10.60.0.1", prefix: 24, gateway: "" }] } } : d)));
      const srv = add("server", 900, 600, "사내 서버");
      srv.host = { ipMode: "static", ip: "10.60.0.10", prefix: 24, gateway: "10.60.0.1", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
      return { ...t, devices, cables: [...t.cables, cable(t.devices.find((d) => d.name === "내부망 게이트웨이")!, 2, srv, 0)] };
    };
    const t = withRoutes(patchRouter(withSrv(exampleSeparatedRemoteTopology()), (r) => ({ ...r, wan2: { ...r.wan2!, gateway: "10.50.10.254" } })), []);
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id("사내 서버"), dst: "10.50.10.18" });
    expect(L.host("사내 서버").pings.at(-1)!.status).not.toBe("ok");
    expect(tr.some((e) => e.nodeId === L.id(OFFICE) && e.kind === "ip.forward" && e.summary.includes("WAN2 는 디폴트 라우트로 쓰지 않아"))).toBe(true);
    // 스태틱 라우트가 있으면 그 길로 답한다
    const L2 = loadTopology(withRoutes(withSrv(exampleSeparatedRemoteTopology()), [{ iface: "wan2", dest: "10.60.0.0/24", via: "10.50.10.254" }]));
    L2.act({ kind: "ping", nodeId: L2.id("사내 서버"), dst: "10.50.10.18" });
    expect(L2.host("사내 서버").pings.at(-1)!.status).toBe("ok");
  });

  it("넥스트 홉을 비우면 on-link: 그 인터페이스에서 대상에게 직접 ARP (구성 검사는 조용)", () => {
    const t = withRoutes(exampleSeparatedRemoteTopology(), [{ iface: "wan2", dest: "10.70.0.0/24", via: "" }]);
    const L = loadTopology(t);
    expect(lintOf(L.t, "router.route-invalid")).toEqual([]);
    const tr = L.act({ kind: "ping", nodeId: L.id("재택 노트북"), dst: "10.70.0.5" });
    const fwd = tr.find((e) => e.nodeId === L.id(OFFICE) && e.kind === "ip.forward" && e.details?.dst === "10.70.0.5");
    // 노트북의 AllowedIPs 밖이라 터널로 오지 않는다 — 공유기 LAN PC 로 확인
    expect(fwd).toBeUndefined();
    const L3 = loadTopology(withRoutes(withLanPc(exampleSeparatedRemoteTopology()), [{ iface: "wan2", dest: "10.70.0.0/24", via: "" }]));
    const tr3 = L3.act({ kind: "ping", nodeId: L3.id("사무실 LAN PC"), dst: "10.70.0.5" });
    const f3 = tr3.find((e) => e.nodeId === L3.id(OFFICE) && e.kind === "ip.forward" && e.details?.dst === "10.70.0.5")!;
    expect(f3.summary).toContain("넥스트 홉 없음(on-link), WAN2(lan4)");
    expect(tr3.some((e) => e.nodeId === L3.id(OFFICE) && e.kind === "arp.request.sent" && e.summary.includes("10.70.0.5"))).toBe(true);
    const rows = L3.s.net.nodes.get(L3.id(OFFICE))!.snapshot().tables!.find((x) => x.title === "라우팅 테이블 (main)")!.rows;
    expect(rows.at(-1)).toEqual(["wan2", "10.70.0.0/24", "", "스태틱 (on-link)"]);
  });

  it("이미 있는 흐름(SSH 의 뒤 세그먼트)은 MASQUERADE 가 아니라 NAT 테이블대로라고 적는다", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("재택 노트북"), dst: "192.168.111.11", port: 22 });
    const fwds = tr.filter((e) => e.nodeId === L.id(OFFICE) && e.kind === "ip.forward" && e.details?.dst === "192.168.111.11");
    expect(fwds[0]!.summary).toContain("10.50.10.18 로 MASQUERADE");
    expect(fwds.slice(1).every((e) => e.summary.includes("이미 있는 흐름이라 NAT 테이블대로"))).toBe(true);
  });
});
