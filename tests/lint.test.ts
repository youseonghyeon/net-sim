import { describe, expect, it } from "vitest";
import { l2Segments, lintTopology, type LintIssue } from "../src/model/lint";
import {
  DEFAULT_DHCP_SERVER,
  createDevice,
  newId,
  type Cable,
  type Device,
  type DeviceKind,
  type HostSettings,
  type Topology,
} from "../src/model/topology";
import { exampleHaTopology, exampleTopology, examplePartsTopology, exampleVlanTopology } from "../src/model/examples";
import { loadTopology } from "./helpers";

/** createDevice + newId("cable") 로 토폴로지를 조립하는 도우미 */
function build() {
  const devices: Device[] = [];
  const cables: Cable[] = [];
  const add = (kind: DeviceKind, x = 0, y = 0) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const link = (a: Device, ap: number, b: Device, bp: number) => {
    cables.push({ id: newId("cable"), a: { device: a.id, port: ap }, b: { device: b.id, port: bp } });
  };
  const t: Topology = { devices, cables };
  return { t, add, link };
}

function staticHost(d: Device, ip: string, gateway: string, extra: Partial<HostSettings> = {}): Device {
  d.host = { ...d.host!, ipMode: "static", ip, gateway, ...extra };
  return d;
}

function codes(issues: LintIssue[], deviceId?: string): string[] {
  return issues.filter((i) => deviceId === undefined || i.deviceId === deviceId).map((i) => i.code);
}

function issue(issues: LintIssue[], deviceId: string, code: string): LintIssue {
  const found = issues.find((i) => i.deviceId === deviceId && i.code === code);
  if (!found) throw new Error(`no issue ${code} on ${deviceId}; got ${JSON.stringify(issues.map((i) => [i.deviceId, i.code]))}`);
  return found;
}

/** NAT(if1 10.0.0.1) 아래 게이트웨이(if0 10.0.0.2, 디폴트 라우트 10.0.0.1), NAT 에 돌아오는 경로까지 갖춘 올바른 2단 구성 */
function twoTier() {
  const b = build();
  const inet = b.add("internet");
  const nat = b.add("nat");
  nat.l3 = {
    interfaces: [
      { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "10.0.0.1", prefix: 24, gateway: "" },
    ],
    routes: [{ dest: "192.168.0.0", prefix: 16, via: "10.0.0.2" }],
  };
  const gw = b.add("gateway");
  gw.l3 = {
    interfaces: [
      { ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" },
      { ipMode: "static", ip: "192.168.1.1", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "192.168.2.1", prefix: 24, gateway: "" },
    ],
    routes: [],
  };
  const sw = b.add("switch");
  b.link(inet, 0, nat, 0);
  b.link(nat, 1, gw, 0);
  b.link(gw, 1, sw, 0);
  return { ...b, inet, nat, gw, sw };
}

describe("lint: 예제 3종은 이슈가 없다 (오탐 방지 기준)", () => {
  it("공유기 예제", () => expect(lintTopology(exampleTopology())).toEqual([]));
  it("기능 단위 예제 (NAT → 게이트웨이 → 릴레이 + DHCP 서버 호스트)", () => expect(lintTopology(examplePartsTopology())).toEqual([]));
  it("VLAN 예제 (트렁크 + 서브 인터페이스)", () => expect(lintTopology(exampleVlanTopology())).toEqual([]));
});

describe("l2Segments: 장치 인터페이스 단위 브로드캐스트 도메인", () => {
  it("공유기 LAN 포트·무선 슬롯은 한 세그먼트, WAN 은 별개, 스마트폰은 무선으로 LAN 에 붙는다", () => {
    const t = exampleTopology();
    const seg = l2Segments(t);
    const rt = t.devices.find((d) => d.kind === "router")!;
    const pc = t.devices.find((d) => d.kind === "pc")!;
    const phone = t.devices.find((d) => d.kind === "phone")!;
    const inet = t.devices.find((d) => d.kind === "internet")!;
    const lan = seg.get(`${rt.id}:1`)!;
    expect(seg.get(`${rt.id}:4`)).toBe(lan);
    expect(seg.get(`${rt.id}:7`)).toBe(lan); // 무선 슬롯
    expect(seg.get(`${pc.id}:0`)).toBe(lan); // 스위치 통과
    expect(seg.get(`${phone.id}:0`)).toBe(lan); // 무선 링크
    expect(seg.get(`${rt.id}:0`)).not.toBe(lan);
    expect(seg.get(`${inet.id}:0`)).toBe(seg.get(`${rt.id}:0`));
  });

  it("VLAN: 액세스 VLAN 별로 나뉘고, 게이트웨이 서브 인터페이스는 트렁크를 거쳐 그 VLAN 에 붙는다", () => {
    const t = exampleVlanTopology();
    const seg = l2Segments(t);
    const gw = t.devices.find((d) => d.kind === "gateway")!;
    const [pc1, pc2] = t.devices.filter((d) => d.kind === "pc");
    const laptop = t.devices.find((d) => d.kind === "laptop")!;
    expect(seg.get(`${pc1!.id}:0`)).toBe(seg.get(`${pc2!.id}:0`));
    expect(seg.get(`${pc1!.id}:0`)).not.toBe(seg.get(`${laptop.id}:0`));
    expect(seg.get(`${gw.id}:1@10`)).toBe(seg.get(`${pc1!.id}:0`));
    expect(seg.get(`${gw.id}:1@20`)).toBe(seg.get(`${laptop.id}:0`));
    expect(seg.get(`${gw.id}:1`)).not.toBe(seg.get(`${pc1!.id}:0`)); // 물리 인터페이스(태그 없음)는 트렁크에서 고립
  });

  it("스위치 사이 트렁크는 VLAN 마다 통과시키고, 허브는 전부 합친다", () => {
    const b = build();
    const sw1 = b.add("switch");
    const sw2 = b.add("switch");
    sw1.switch = { vlans: { 0: "trunk", 1: 10, 2: 20 } };
    sw2.switch = { vlans: { 0: "trunk", 1: 10, 2: 20 } };
    const a10 = b.add("pc");
    const b10 = b.add("pc");
    const a20 = b.add("pc");
    const hub = b.add("hub");
    const h1 = b.add("pc");
    b.link(sw1, 0, sw2, 0);
    b.link(sw1, 1, a10, 0);
    b.link(sw2, 1, b10, 0);
    b.link(sw1, 2, a20, 0);
    b.link(sw2, 2, hub, 0);
    b.link(hub, 1, h1, 0);
    const seg = l2Segments(b.t);
    expect(seg.get(`${a10.id}:0`)).toBe(seg.get(`${b10.id}:0`));
    expect(seg.get(`${a10.id}:0`)).not.toBe(seg.get(`${a20.id}:0`));
    expect(seg.get(`${a20.id}:0`)).toBe(seg.get(`${h1.id}:0`)); // VLAN 20 → 트렁크 → sw2 VLAN 20 → 허브
  });
});

describe("규칙 1 dhcp.no-router", () => {
  it("게이트웨이가 있는 세그먼트의 호스트 DHCP 서버가 게이트웨이를 안 알려주면 경고하고 그 주소를 추천한다", () => {
    const b = build();
    const gw = b.add("gateway");
    const sw = b.add("switch");
    const srv = staticHost(b.add("server"), "192.168.1.2", "192.168.1.1", { dns: "8.8.8.8", dhcpServer: { enabled: true, start: "192.168.1.100", end: "192.168.1.199", router: "", dns: "8.8.8.8" } });
    b.link(gw, 1, sw, 0);
    b.link(sw, 1, srv, 0);
    const i = issue(lintTopology(b.t), srv.id, "dhcp.no-router");
    expect(i.severity).toBe("warn");
    expect(i.fix).toContain("192.168.1.1");
    expect(i.related).toEqual([gw.id]);
  });

  it("게이트웨이를 안내하면 (그리고 DNS 도) 이슈가 없고, 게이트웨이 장치가 없는 세그먼트에선 지적하지 않는다", () => {
    const b = build();
    const gw = b.add("gateway");
    const sw = b.add("switch");
    const srv = staticHost(b.add("server"), "192.168.1.2", "192.168.1.1", { dns: "8.8.8.8", dhcpServer: { enabled: true, start: "192.168.1.100", end: "192.168.1.199", router: "192.168.1.1", dns: "8.8.8.8" } });
    b.link(gw, 1, sw, 0);
    b.link(sw, 1, srv, 0);
    expect(lintTopology(b.t)).toEqual([]);
    // 게이트웨이 없는 독립 LAN: 게이트웨이 안내가 없어도 정상
    const c = build();
    const sw2 = c.add("switch");
    const srv2 = staticHost(c.add("server"), "192.168.1.2", "", { dhcpServer: { enabled: true, start: "192.168.1.100", end: "192.168.1.199", router: "" } });
    c.link(sw2, 1, srv2, 0);
    c.link(sw2, 2, c.add("pc"), 0);
    expect(lintTopology(c.t)).toEqual([]);
  });

  it("추가 풀(릴레이용)도 검사하고 풀 서브넷 안의 라우터 인터페이스를 추천한다", () => {
    const t = examplePartsTopology();
    const srv = t.devices.find((d) => d.name === "dhcp-srv")!;
    const gw = t.devices.find((d) => d.kind === "gateway")!;
    srv.host!.dhcpServer.extraPools![0]!.router = "";
    const i = issue(lintTopology(t), srv.id, "dhcp.no-router");
    expect(i.message).toContain("192.168.2.0/24");
    expect(i.fix).toContain("192.168.2.1");
    expect(i.related).toEqual([gw.id]);
  });
});

describe("규칙 2 dhcp.no-dns", () => {
  it("게이트웨이는 안내하는데 DNS 가 비면 경고한다 (자기 DNS 서비스가 켜져 있으면 자기 주소를 추천)", () => {
    const b = build();
    const gw = b.add("gateway");
    const sw = b.add("switch");
    const srv = staticHost(b.add("server"), "192.168.1.2", "192.168.1.1", {
      dns: "192.168.1.2",
      dhcpServer: { enabled: true, start: "192.168.1.100", end: "192.168.1.199", router: "192.168.1.1", dns: "" },
      dnsServer: { enabled: true, records: [], upstream: "8.8.8.8" },
    });
    b.link(gw, 1, sw, 0);
    b.link(sw, 1, srv, 0);
    const issues = lintTopology(b.t);
    expect(codes(issues, srv.id)).toEqual(["dhcp.no-dns"]);
    expect(issue(issues, srv.id, "dhcp.no-dns").fix).toContain("192.168.1.2");
    // 추가 풀도 같은 검사
    const t = examplePartsTopology();
    const dhcp = t.devices.find((d) => d.name === "dhcp-srv")!;
    dhcp.host!.dhcpServer.extraPools![0]!.dns = "";
    expect(codes(lintTopology(t), dhcp.id)).toEqual(["dhcp.no-dns"]);
  });

  it("DNS 를 안내하면 경고하지 않고, 게이트웨이가 비었을 땐 규칙 1 만 낸다", () => {
    const b = build();
    const gw = b.add("gateway");
    const sw = b.add("switch");
    const srv = staticHost(b.add("server"), "192.168.1.2", "192.168.1.1", { dns: "8.8.8.8", dhcpServer: { enabled: true, start: "192.168.1.100", end: "192.168.1.199", router: "192.168.1.1", dns: "8.8.8.8" } });
    b.link(gw, 1, sw, 0);
    b.link(sw, 1, srv, 0);
    expect(codes(lintTopology(b.t), srv.id)).toEqual([]);
    srv.host!.dhcpServer.router = "";
    srv.host!.dhcpServer.dns = "";
    expect(codes(lintTopology(b.t), srv.id)).toEqual(["dhcp.no-router"]);
  });
});

describe("규칙 3 host.gateway-outside-subnet", () => {
  it("수동 호스트의 게이트웨이가 자기 서브넷 밖이면 error", () => {
    const b = build();
    const pc = staticHost(b.add("pc"), "192.168.1.10", "192.168.2.1");
    const i = issue(lintTopology(b.t), pc.id, "host.gateway-outside-subnet");
    expect(i.severity).toBe("error");
    expect(i.message).toContain("192.168.1.0/24");
  });

  it("같은 서브넷이면 통과하고, 입력 중인 값(\"192.168.1.\")은 지적하지 않는다", () => {
    const b = build();
    const pc = staticHost(b.add("pc"), "192.168.1.10", "192.168.1.1");
    expect(lintTopology(b.t)).toEqual([]);
    pc.host!.gateway = "192.168.1.";
    expect(lintTopology(b.t)).toEqual([]);
    pc.host!.gateway = "";
    expect(lintTopology(b.t)).toEqual([]);
  });
});

describe("규칙 4 host.no-gateway-in-segment", () => {
  it("게이트웨이 주소가 같은 세그먼트의 어떤 라우터 주소와도 다르면 경고하고 실제 주소를 추천한다", () => {
    const b = build();
    const gw = b.add("gateway");
    const sw = b.add("switch");
    const pc = staticHost(b.add("pc"), "192.168.1.10", "192.168.1.254");
    b.link(gw, 1, sw, 0);
    b.link(sw, 1, pc, 0);
    const issues = lintTopology(b.t);
    expect(codes(issues, pc.id)).toEqual(["host.no-gateway-in-segment"]);
    const i = issue(issues, pc.id, "host.no-gateway-in-segment");
    expect(i.fix).toContain("192.168.1.1");
    expect(i.related).toEqual([gw.id]);
  });

  it("라우터 주소와 일치하면 통과, 주소를 아직 모르는(DHCP) 라우터 인터페이스가 섞여 있으면 보수적으로 침묵", () => {
    const b = build();
    const gw = b.add("gateway");
    const sw = b.add("switch");
    const pc = staticHost(b.add("pc"), "192.168.1.10", "192.168.1.1");
    b.link(gw, 1, sw, 0);
    b.link(sw, 1, pc, 0);
    expect(lintTopology(b.t)).toEqual([]);
    // NAT if1 + 게이트웨이 if0(DHCP, 주소 모름) 세그먼트의 호스트: 게이트웨이가 DHCP 로 받을 주소일 수 있다
    const c = twoTier();
    c.gw.l3!.interfaces[0] = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" };
    const pc2 = staticHost(c.add("pc"), "10.0.0.50", "10.0.0.7");
    const sw2 = c.add("switch");
    c.t.cables.splice(1, 1); // nat ↔ gw 직결을 스위치 경유로
    c.link(c.nat, 1, sw2, 0);
    c.link(sw2, 1, c.gw, 0);
    c.link(sw2, 2, pc2, 0);
    expect(codes(lintTopology(c.t), pc2.id)).toEqual([]);
  });

  it("같은 세그먼트에 아래 게이트웨이 업링크(if0)와 NAT 안쪽이 있으면 장치 순서와 무관하게 안쪽 인터페이스를 추천한다", () => {
    const b = build();
    const gw = b.add("gateway"); // 먼저 추가 → 세그먼트 목록에서 업링크 if0 이 앞에 온다
    gw.l3!.interfaces[0] = { ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" };
    const nat = b.add("nat");
    nat.l3!.interfaces[1] = { ipMode: "static", ip: "10.0.0.1", prefix: 24, gateway: "" };
    const sw = b.add("switch");
    const pc = staticHost(b.add("pc"), "10.0.0.50", "10.0.0.9");
    const srv = staticHost(b.add("server"), "10.0.0.5", "10.0.0.1", { dns: "8.8.8.8", dhcpServer: { enabled: true, start: "10.0.0.100", end: "10.0.0.199", router: "10.0.0.9", dns: "8.8.8.8" } });
    b.link(nat, 1, sw, 0);
    b.link(gw, 0, sw, 1);
    b.link(pc, 0, sw, 2);
    b.link(srv, 0, sw, 3);
    const issues = lintTopology(b.t);
    expect(issue(issues, pc.id, "host.no-gateway-in-segment").fix).toContain(`10.0.0.1 (${nat.name} inside)`);
    expect(issue(issues, srv.id, "dhcp.gateway-mismatch").fix).toContain(`10.0.0.1 (${nat.name} inside)`);
    srv.host!.dhcpServer.router = "";
    expect(issue(lintTopology(b.t), srv.id, "dhcp.no-router").fix).toContain("10.0.0.1");
  });

  it("게이트웨이 주소가 라우터가 아닌 호스트 주소면 ARP timeout 이 아니라 그 호스트가 드롭한다고 안내한다 (시뮬레이션으로 확인)", () => {
    const b = build();
    const gw = b.add("gateway");
    const sw = b.add("switch");
    const pc = staticHost(b.add("pc"), "192.168.1.10", "192.168.1.20");
    const other = staticHost(b.add("pc"), "192.168.1.20", "192.168.1.1");
    b.link(gw, 1, sw, 0);
    b.link(sw, 1, pc, 0);
    b.link(sw, 2, other, 0);
    const i = issue(lintTopology(b.t), pc.id, "host.no-gateway-in-segment");
    expect(i.message).toContain(`${other.name} 가 ARP 에 응답`);
    expect(i.message).toContain("드롭");
    expect(i.message).not.toContain("ARP timeout");
    const sim = loadTopology(b.t);
    const tr = sim.act({ kind: "ping", nodeId: pc.id, dst: "10.9.9.9" });
    expect(tr.some((e) => e.nodeId === other.id && e.kind === "ip.drop")).toBe(true);
    expect(tr.some((e) => e.kind === "arp.timeout")).toBe(false);
  });

  it("그 주소의 장비가 없으면 ARP timeout, DHCP 범위 안 주소면 그 주소를 받은 단말이 드롭할 수도 있다고 안내한다", () => {
    const b = build();
    const gw = b.add("gateway");
    const sw = b.add("switch");
    const pc = staticHost(b.add("pc"), "192.168.1.10", "192.168.1.254");
    b.link(gw, 1, sw, 0);
    b.link(sw, 1, pc, 0);
    const i = issue(lintTopology(b.t), pc.id, "host.no-gateway-in-segment");
    expect(i.message).toContain("그 주소로 ARP 에 응답하는 장비가 없어 ARP timeout");
    const sim = loadTopology(b.t);
    expect(sim.act({ kind: "ping", nodeId: pc.id, dst: "10.9.9.9" }).some((e) => e.nodeId === pc.id && e.kind === "arp.timeout")).toBe(true);
    // 같은 세그먼트 DHCP 서버의 범위 안: 그 주소를 받은 단말이 있을 수 있다
    const srv = staticHost(b.add("server"), "192.168.1.2", "192.168.1.1", { dns: "8.8.8.8", dhcpServer: { enabled: true, start: "192.168.1.100", end: "192.168.1.199", router: "192.168.1.1", dns: "8.8.8.8" } });
    b.link(sw, 2, srv, 0);
    pc.host!.gateway = "192.168.1.150";
    const j = issue(lintTopology(b.t), pc.id, "host.no-gateway-in-segment");
    expect(j.message).toContain("DHCP 로 받은 단말");
    expect(j.message).toContain("ARP timeout");
  });
});

describe("규칙 5 segment.no-router", () => {
  it("라우터 인터페이스가 없는 세그먼트에서 호스트가 게이트웨이를 설정하면 경고", () => {
    const b = build();
    const sw = b.add("switch");
    const pc = staticHost(b.add("pc"), "192.168.1.10", "192.168.1.1");
    const pc2 = staticHost(b.add("pc"), "192.168.1.11", "");
    b.link(sw, 1, pc, 0);
    b.link(sw, 2, pc2, 0);
    const issues = lintTopology(b.t);
    expect(codes(issues)).toEqual(["segment.no-router"]);
    expect(issue(issues, pc.id, "segment.no-router").message).toContain("게이트웨이 장치가 없음");
  });

  it("DHCP 서버가 게이트웨이를 안내할 때도 같은 검사, 게이트웨이를 안 쓰면 통과, 케이블이 없으면 침묵", () => {
    const b = build();
    const sw = b.add("switch");
    const srv = staticHost(b.add("server"), "192.168.1.2", "", { dhcpServer: { enabled: true, start: "192.168.1.100", end: "192.168.1.199", router: "192.168.1.1", dns: "8.8.8.8" } });
    b.link(sw, 1, srv, 0);
    b.link(sw, 2, b.add("pc"), 0);
    expect(codes(lintTopology(b.t))).toEqual(["segment.no-router"]);
    srv.host!.dhcpServer.router = "";
    expect(lintTopology(b.t)).toEqual([]);
    // 케이블 없는 수동 호스트: 타일 상태 문구가 이미 보여주므로 조용히
    const c = build();
    staticHost(c.add("pc"), "192.168.1.10", "192.168.1.1");
    expect(lintTopology(c.t)).toEqual([]);
  });
});

describe("규칙 6 l3.uplink-no-default", () => {
  it("업링크가 수동이고 주소는 있는데 디폴트 라우트가 없으면 error, 위쪽 라우터 주소를 추천", () => {
    const c = twoTier();
    c.gw.l3!.interfaces[0]!.gateway = "";
    const i = issue(lintTopology(c.t), c.gw.id, "l3.uplink-no-default");
    expect(i.severity).toBe("error");
    expect(i.fix).toContain("10.0.0.1");
    expect(i.related).toEqual([c.nat.id]);
  });

  it("디폴트 라우트가 있으면 통과, 케이블이 없거나 게이트웨이끼리 if0 을 맞댄 백본이면 침묵", () => {
    const c = twoTier();
    expect(lintTopology(c.t)).toEqual([]);
    // if0 링크 다운
    const b = build();
    const gw = b.add("gateway");
    gw.l3!.interfaces[0] = { ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "" };
    expect(lintTopology(b.t)).toEqual([]);
    // if0 ↔ if0 백본: 서로 스태틱 라우팅으로 오간다
    const gw2 = b.add("gateway");
    gw2.l3!.interfaces[0] = { ipMode: "static", ip: "10.0.0.3", prefix: 24, gateway: "" };
    gw2.l3!.interfaces[1]!.ip = "192.168.3.1";
    gw2.l3!.interfaces[2]!.ip = "192.168.4.1";
    b.link(gw, 0, gw2, 0);
    expect(codes(lintTopology(b.t))).toEqual([]);
  });
});

describe("RIP 를 켜면 경로 규칙은 침묵한다 (광고로 배울 경로는 토폴로지만으로 알 수 없음)", () => {
  it("NAT 와 아래 게이트웨이 둘 다 RIP 면 no-return-route 가 사라지고, 한쪽만 켜면 그대로", () => {
    const c = twoTier();
    c.nat.l3!.routes = [];
    c.nat.l3!.rip = { enabled: true };
    expect(codes(lintTopology(c.t), c.nat.id)).toContain("l3.no-return-route"); // 게이트웨이는 아직 꺼짐
    c.gw.l3!.rip = { enabled: true };
    expect(codes(lintTopology(c.t), c.nat.id)).not.toContain("l3.no-return-route");
  });

  it("업링크 디폴트 라우트가 없어도 위쪽 라우터가 모두 RIP 면 경고하지 않는다", () => {
    const c = twoTier();
    c.gw.l3!.interfaces[0]!.gateway = "";
    expect(codes(lintTopology(c.t), c.gw.id)).toContain("l3.uplink-no-default");
    c.gw.l3!.rip = { enabled: true };
    expect(codes(lintTopology(c.t), c.gw.id)).toContain("l3.uplink-no-default"); // 위쪽 NAT 는 RIP 꺼짐
    c.nat.l3!.rip = { enabled: true, defaultRoute: true };
    expect(codes(lintTopology(c.t), c.gw.id)).not.toContain("l3.uplink-no-default");
  });
});

describe("규칙 7 l3.no-return-route", () => {
  it("NAT 안쪽에 게이트웨이가 있는데 그 뒤 서브넷 스태틱 라우팅이 없으면 NAT 에 error, 커버되지 않은 서브넷만 나열", () => {
    const c = twoTier();
    c.nat.l3!.routes = [];
    const issues = lintTopology(c.t);
    const i = issue(issues, c.nat.id, "l3.no-return-route");
    expect(i.severity).toBe("error");
    expect(i.message).toContain("192.168.1.0/24");
    expect(i.message).toContain("192.168.2.0/24");
    expect(i.fix).toContain("넥스트 홉 10.0.0.2");
    expect(i.related).toEqual([c.gw.id]);
    expect(codes(issues, c.gw.id)).toEqual([]);
    // 한쪽만 커버
    c.nat.l3!.routes = [{ dest: "192.168.1.0", prefix: 24, via: "10.0.0.2" }];
    const j = issue(lintTopology(c.t), c.nat.id, "l3.no-return-route");
    expect(j.message).not.toContain("192.168.1.0/24");
    expect(j.message).toContain("192.168.2.0/24");
  });

  it("포함하는 스태틱 라우팅이 있으면 통과, 아래가 NAT 박스면 경로가 필요 없다", () => {
    const c = twoTier();
    expect(lintTopology(c.t)).toEqual([]);
    // 게이트웨이 대신 NAT 박스: 주소가 바뀌어 돌아오므로 위쪽 NAT 에 경로 불필요
    const b = build();
    const top = b.add("nat");
    top.l3!.interfaces[1]!.ip = "10.0.0.1";
    top.l3!.routes = [];
    const inner = b.add("nat");
    inner.l3!.interfaces[0] = { ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" };
    b.link(top, 1, inner, 0);
    expect(lintTopology(b.t)).toEqual([]);
  });

  it("공유기 아래 게이트웨이: 공유기는 스태틱 라우팅이 없으므로 장치를 바꾸라고 안내", () => {
    const b = build();
    const rt = b.add("router");
    const sw = b.add("switch");
    const gw = b.add("gateway");
    gw.l3!.interfaces[0] = { ipMode: "static", ip: "192.168.0.2", prefix: 24, gateway: "192.168.0.1" };
    b.link(rt, 1, sw, 0);
    b.link(sw, 1, gw, 0);
    const i = issue(lintTopology(b.t), rt.id, "l3.no-return-route");
    expect(i.fix).toContain("공유기");
    expect(i.related).toEqual([gw.id]);
  });

  it("게이트웨이 2단(전이): 맨 위 NAT 는 아래아래 서브넷까지 알아야 한다", () => {
    const c = twoTier();
    const gw2 = c.add("gateway");
    gw2.l3 = {
      interfaces: [
        { ipMode: "static", ip: "192.168.1.2", prefix: 24, gateway: "192.168.1.1" },
        { ipMode: "static", ip: "172.16.1.1", prefix: 24, gateway: "" },
        { ipMode: "static", ip: "172.16.2.1", prefix: 24, gateway: "" },
      ],
      routes: [],
    };
    c.link(c.sw, 1, gw2, 0);
    const issues = lintTopology(c.t);
    const top = issue(issues, c.nat.id, "l3.no-return-route");
    expect(top.message).toContain("172.16.1.0/24");
    expect(top.message).not.toContain("192.168.1.0/24"); // 이미 /16 으로 커버
    expect(top.fix).toContain("넥스트 홉 10.0.0.2"); // NAT 에선 여전히 gw-1 이 넥스트 홉
    const mid = issue(issues, c.gw.id, "l3.no-return-route");
    expect(mid.fix).toContain("넥스트 홉 192.168.1.2");
    // 둘 다 경로를 넣으면 조용
    c.nat.l3!.routes.push({ dest: "172.16.0.0", prefix: 16, via: "10.0.0.2" });
    c.gw.l3!.routes.push({ dest: "172.16.0.0", prefix: 16, via: "192.168.1.2" });
    expect(lintTopology(c.t)).toEqual([]);
  });
});

describe("규칙 8 l3.subnet-overlap", () => {
  it("한 장치의 인터페이스 서브넷이 겹치면 error (서브 인터페이스 포함)", () => {
    const b = build();
    const gw = b.add("gateway");
    gw.l3!.interfaces[2]!.ip = "192.168.1.9";
    const i = issue(lintTopology(b.t), gw.id, "l3.subnet-overlap");
    expect(i.severity).toBe("error");
    expect(i.message).toContain("if1 192.168.1.0/24");
    expect(i.message).toContain("if2 192.168.1.0/24");
    // /16 이 /24 를 품는 경우와 서브 인터페이스
    gw.l3!.interfaces[2]!.ip = "10.5.0.1";
    gw.l3!.interfaces[2]!.prefix = 16;
    gw.l3!.subinterfaces = [{ port: 1, vlan: 10, ip: "10.5.7.1", prefix: 24, relay: "" }];
    expect(issue(lintTopology(b.t), gw.id, "l3.subnet-overlap").message).toContain("if1.10");
  });

  it("기본 구성(192.168.1.0/24, 192.168.2.0/24)은 통과", () => {
    const b = build();
    b.add("gateway");
    b.add("nat");
    expect(lintTopology(b.t)).toEqual([]);
  });
});

describe("규칙 9 segment.two-dhcp", () => {
  it("공유기 DHCP 와 호스트 DHCP 서버가 같은 세그먼트에 있으면 둘 다 경고", () => {
    const b = build();
    const rt = b.add("router");
    const sw = b.add("switch");
    const srv = staticHost(b.add("server"), "192.168.0.2", "192.168.0.1", { dns: "192.168.0.1", dhcpServer: { enabled: true, start: "192.168.0.100", end: "192.168.0.199", router: "192.168.0.1", dns: "192.168.0.1" } });
    b.link(rt, 1, sw, 0);
    b.link(sw, 1, srv, 0);
    const issues = lintTopology(b.t);
    expect(codes(issues)).toEqual(["segment.two-dhcp", "segment.two-dhcp"]);
    expect(issue(issues, rt.id, "segment.two-dhcp").related).toEqual([srv.id]);
    expect(issue(issues, srv.id, "segment.two-dhcp").fix).toContain(rt.name);
  });

  it("하나만 켜져 있으면 통과, 주소를 DHCP 로 받는 호스트의 DHCP 서비스는 동작하지 않으므로 세지 않는다", () => {
    const b = build();
    const rt = b.add("router");
    const sw = b.add("switch");
    const srv = staticHost(b.add("server"), "192.168.0.2", "192.168.0.1", { dns: "192.168.0.1" });
    b.link(rt, 1, sw, 0);
    b.link(sw, 1, srv, 0);
    expect(lintTopology(b.t)).toEqual([]);
    const pc = b.add("pc");
    pc.host!.dhcpServer = { ...DEFAULT_DHCP_SERVER, enabled: true };
    b.link(sw, 2, pc, 0);
    expect(codes(lintTopology(b.t))).toEqual([]);
  });
});

describe("규칙 10 segment.duplicate-ip", () => {
  it("같은 세그먼트에 같은 수동 IP 가 둘이면 양쪽에 error (호스트·공유기 LAN·L3 인터페이스 모두 대상)", () => {
    const b = build();
    const rt = b.add("router");
    const sw = b.add("switch");
    const pc = staticHost(b.add("pc"), "192.168.0.1", "");
    b.link(rt, 1, sw, 0);
    b.link(sw, 1, pc, 0);
    const issues = lintTopology(b.t);
    expect(codes(issues, pc.id)).toContain("segment.duplicate-ip");
    expect(codes(issues, rt.id)).toContain("segment.duplicate-ip");
    expect(issue(issues, pc.id, "segment.duplicate-ip").related).toEqual([rt.id]);
    expect(issue(issues, pc.id, "segment.duplicate-ip").severity).toBe("error");
  });

  it("주소가 다르면 통과, 다른 VLAN(세그먼트)이면 같은 주소여도 통과", () => {
    const b = build();
    const sw = b.add("switch");
    sw.switch = { vlans: { 1: 10, 2: 20 } };
    const a = staticHost(b.add("pc"), "192.168.0.10", "");
    const c = staticHost(b.add("pc"), "192.168.0.10", "");
    b.link(sw, 1, a, 0);
    b.link(sw, 2, c, 0);
    expect(lintTopology(b.t)).toEqual([]);
    sw.switch = { vlans: {} };
    expect(codes(lintTopology(b.t))).toEqual(["segment.duplicate-ip", "segment.duplicate-ip"]);
    c.host!.ip = "192.168.0.11";
    expect(lintTopology(b.t)).toEqual([]);
  });
});

describe("규칙 11 segment.mixed-subnet", () => {
  it("호스트 수동 주소가 같은 세그먼트 라우터의 서브넷 밖이면 경고", () => {
    const b = build();
    const rt = b.add("router");
    const sw = b.add("switch");
    const pc = staticHost(b.add("pc"), "192.168.5.10", "");
    b.link(rt, 1, sw, 0);
    b.link(sw, 1, pc, 0);
    const issues = lintTopology(b.t);
    expect(codes(issues, pc.id)).toEqual(["segment.mixed-subnet"]);
    expect(issue(issues, pc.id, "segment.mixed-subnet").fix).toContain("192.168.0.0/24");
  });

  it("서브넷 안이면 통과, 게이트웨이까지 틀렸으면 규칙 3 만 내고 겹치지 않는다", () => {
    const b = build();
    const rt = b.add("router");
    const sw = b.add("switch");
    const pc = staticHost(b.add("pc"), "192.168.0.10", "192.168.0.1");
    b.link(rt, 1, sw, 0);
    b.link(sw, 1, pc, 0);
    expect(lintTopology(b.t)).toEqual([]);
    pc.host!.ip = "192.168.5.10";
    expect(codes(lintTopology(b.t), pc.id)).toEqual(["host.gateway-outside-subnet"]);
  });

  it("게이트웨이 업링크(if0) 수동 주소가 위쪽 라우터 서브넷 밖이어도 경고", () => {
    const c = twoTier();
    c.gw.l3!.interfaces[0] = { ipMode: "static", ip: "10.0.1.2", prefix: 24, gateway: "10.0.1.1" };
    const i = issue(lintTopology(c.t), c.gw.id, "segment.mixed-subnet");
    expect(i.message).toContain("if0");
    expect(i.fix).toContain("10.0.0.0/24");
    expect(i.related).toEqual([c.nat.id]);
  });
});

describe("규칙 12 relay.unreachable", () => {
  it("릴레이 대상이 어느 인터페이스 서브넷에도 없고 정적·디폴트 라우트도 없으면 경고", () => {
    const b = build();
    const gw = b.add("gateway");
    gw.l3!.interfaces[0] = { ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "" };
    gw.l3!.interfaces[2]!.relay = "172.16.0.5";
    const i = issue(lintTopology(b.t), gw.id, "relay.unreachable");
    expect(i.message).toContain("if2");
    expect(i.message).toContain("172.16.0.5");
    // 서브 인터페이스의 릴레이도 같은 검사
    gw.l3!.interfaces[2]!.relay = "";
    gw.l3!.subinterfaces = [{ port: 1, vlan: 10, ip: "192.168.10.1", prefix: 24, relay: "172.16.0.5" }];
    expect(issue(lintTopology(b.t), gw.id, "relay.unreachable").message).toContain("if1.10");
  });

  it("인터페이스 서브넷 안·스태틱 라우팅·디폴트 라우트(수동 게이트웨이 또는 DHCP 인터페이스) 중 하나라도 있으면 통과", () => {
    const b = build();
    const gw = b.add("gateway");
    gw.l3!.interfaces[0] = { ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "" };
    gw.l3!.interfaces[2]!.relay = "192.168.1.2"; // if1 서브넷 안
    expect(lintTopology(b.t)).toEqual([]);
    gw.l3!.interfaces[2]!.relay = "172.16.0.5";
    gw.l3!.routes = [{ dest: "172.16.0.0", prefix: 16, via: "10.0.0.1" }];
    expect(lintTopology(b.t)).toEqual([]);
    gw.l3!.routes = [];
    gw.l3!.interfaces[0]!.gateway = "10.0.0.1";
    expect(lintTopology(b.t)).toEqual([]);
    gw.l3!.interfaces[0] = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" };
    expect(lintTopology(b.t)).toEqual([]);
  });
});

describe("규칙 13 VLAN 배선", () => {
  it("vlan.host-on-trunk: 트렁크 포트에 꽂힌 호스트·공유기·허브·AP 는 error", () => {
    const b = build();
    const sw = b.add("switch");
    sw.switch = { vlans: { 1: "trunk", 2: "trunk", 3: "trunk", 4: "trunk", 5: 10 } };
    const pc = b.add("pc");
    const rt = b.add("router");
    const hub = b.add("hub");
    const ap = b.add("ap");
    const ok = b.add("pc");
    b.link(sw, 1, pc, 0);
    b.link(sw, 2, rt, 1);
    b.link(sw, 3, hub, 0);
    b.link(sw, 4, ap, 0);
    b.link(sw, 5, ok, 0);
    const issues = lintTopology(b.t);
    for (const d of [pc, rt, hub, ap]) {
      const i = issue(issues, d.id, "vlan.host-on-trunk");
      expect(i.severity).toBe("error");
      expect(i.related).toEqual([sw.id]);
    }
    expect(issue(issues, pc.id, "vlan.host-on-trunk").fix).toContain("eth2"); // 포트 인덱스 1 = eth2
    expect(codes(issues, ok.id)).toEqual([]);
    // 트렁크에 고립된 호스트에게 세그먼트 규칙(게이트웨이 없음 등)을 덧붙이지 않는다
    staticHost(pc, "192.168.0.10", "192.168.0.1");
    expect(codes(lintTopology(b.t), pc.id)).toEqual(["vlan.host-on-trunk"]);
  });

  it("vlan.subif-not-trunk: 서브 인터페이스가 있는 포트의 상대가 트렁크가 아니면 error, 트렁크면 통과", () => {
    const t = exampleVlanTopology();
    const gw = t.devices.find((d) => d.kind === "gateway")!;
    const sw = t.devices.find((d) => d.kind === "switch")!;
    sw.switch!.vlans[0] = 10;
    const issues = lintTopology(t);
    const i = issue(issues, gw.id, "vlan.subif-not-trunk");
    expect(i.severity).toBe("error");
    expect(i.fix).toContain("트렁크");
    expect(i.related).toEqual([sw.id]);
    sw.switch!.vlans[0] = "trunk";
    expect(lintTopology(t)).toEqual([]);
    // 케이블이 없으면 침묵
    const b = build();
    const g = b.add("gateway");
    g.l3!.subinterfaces = [{ port: 1, vlan: 10, ip: "192.168.10.1", prefix: 24, relay: "" }];
    expect(lintTopology(b.t)).toEqual([]);
  });
});

describe("규칙 21 dhcp.gateway-mismatch", () => {
  /** 게이트웨이 if1(192.168.1.1) 아래 스위치에 DHCP 서버 호스트 */
  function dhcpLan(router: string) {
    const b = build();
    const gw = b.add("gateway");
    const sw = b.add("switch");
    const srv = staticHost(b.add("server"), "192.168.1.2", "192.168.1.1", { dns: "8.8.8.8", dhcpServer: { enabled: true, start: "192.168.1.100", end: "192.168.1.199", router, dns: "8.8.8.8" } });
    b.link(gw, 1, sw, 0);
    b.link(sw, 1, srv, 0);
    b.link(sw, 2, b.add("pc"), 0);
    return { ...b, gw, sw, srv };
  }

  it("기본 게이트웨이 옵션(3)이 세그먼트의 어떤 라우터 주소와도 다르면 경고하고 실제 주소를 추천한다", () => {
    const { t, gw, srv } = dhcpLan("192.168.1.254");
    const issues = lintTopology(t);
    expect(codes(issues, srv.id)).toEqual(["dhcp.gateway-mismatch"]);
    const i = issue(issues, srv.id, "dhcp.gateway-mismatch");
    expect(i.severity).toBe("warn");
    expect(i.message).toContain("192.168.1.254");
    expect(i.message).toContain("192.168.1.1");
    expect(i.message).not.toContain("풀 서브넷");
    expect(i.fix).toContain("기본 게이트웨이 칸을 192.168.1.1 (");
    expect(i.fix).toContain("DHCP 임대 갱신");
    expect(i.related).toEqual([gw.id]);
  });

  it("옵션이 풀 서브넷 밖이면 그 사실을 덧붙이되 이슈는 하나, 옵션이 비면 규칙 1 만", () => {
    const x = dhcpLan("10.0.0.1");
    const issues = lintTopology(x.t);
    expect(codes(issues, x.srv.id)).toEqual(["dhcp.gateway-mismatch"]);
    expect(issue(issues, x.srv.id, "dhcp.gateway-mismatch").message).toContain("풀 서브넷 192.168.1.0/24 밖");
    const y = dhcpLan("");
    expect(codes(lintTopology(y.t), y.srv.id)).toEqual(["dhcp.no-router"]);
    const z = dhcpLan("192.168.1.1");
    expect(lintTopology(z.t)).toEqual([]);
  });

  it("이중화 쌍의 가상 주소나 실제 주소를 안내하면 통과, 둘 다 아니면 가상 주소를 추천한다", () => {
    const t = exampleHaTopology();
    const swIn = t.devices.find((d) => d.name === "inside 스위치")!;
    const fwA = t.devices.find((d) => d.name === "방화벽 A")!;
    const fwB = t.devices.find((d) => d.name === "방화벽 B")!;
    const srv = createDevice("server", 0, 0, t.devices);
    t.devices.push(srv);
    staticHost(srv, "192.168.0.5", "192.168.0.1", { dns: "8.8.8.8", dhcpServer: { enabled: true, start: "192.168.0.100", end: "192.168.0.199", router: "192.168.0.1", dns: "8.8.8.8" } });
    t.cables.push({ id: newId("cable"), a: { device: swIn.id, port: 3 }, b: { device: srv.id, port: 0 } });
    expect(lintTopology(t)).toEqual([]);
    srv.host!.dhcpServer.router = "192.168.0.3"; // 방화벽 B 의 실제 주소: 그 장비가 게이트웨이로 응답은 한다
    expect(codes(lintTopology(t), srv.id)).toEqual([]);
    srv.host!.dhcpServer.router = "192.168.0.9";
    const i = issue(lintTopology(t), srv.id, "dhcp.gateway-mismatch");
    expect(i.message).toContain("192.168.0.1(가상 주소)");
    expect(i.fix).toContain("192.168.0.1 (방화벽 A");
    expect(i.fix).toContain("가상 주소");
    expect(i.related).toEqual([fwA.id, fwB.id]);
  });

  it("주소를 모르는(DHCP) 라우터 인터페이스가 세그먼트에 있으면 침묵, 케이블이 없어도 침묵", () => {
    const c = twoTier();
    c.gw.l3!.interfaces[0] = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" };
    const sw2 = c.add("switch");
    c.t.cables.splice(1, 1); // nat ↔ gw 직결을 스위치 경유로
    c.link(c.nat, 1, sw2, 0);
    c.link(sw2, 1, c.gw, 0);
    const srv = staticHost(c.add("server"), "10.0.0.5", "10.0.0.1", { dns: "8.8.8.8", dhcpServer: { enabled: true, start: "10.0.0.100", end: "10.0.0.199", router: "10.0.0.7", dns: "8.8.8.8" } });
    c.link(sw2, 2, srv, 0);
    expect(codes(lintTopology(c.t), srv.id)).toEqual([]);
    // 케이블 없는 DHCP 서버
    const b = build();
    b.add("gateway");
    const lone = staticHost(b.add("server"), "192.168.1.2", "", { dhcpServer: { enabled: true, start: "192.168.1.100", end: "192.168.1.199", router: "192.168.1.254", dns: "8.8.8.8" } });
    expect(codes(lintTopology(b.t), lone.id)).toEqual([]);
  });

  it("릴레이용 추가 풀: 풀 서브넷의 라우터 인터페이스(giaddr)가 있는 세그먼트 기준으로 검사한다", () => {
    const t = examplePartsTopology();
    const srv = t.devices.find((d) => d.name === "dhcp-srv")!;
    const gw = t.devices.find((d) => d.kind === "gateway")!;
    const pool = srv.host!.dhcpServer.extraPools![0]!;
    pool.router = "192.168.2.254";
    const issues = lintTopology(t);
    expect(codes(issues, srv.id)).toEqual(["dhcp.gateway-mismatch"]);
    const i = issue(issues, srv.id, "dhcp.gateway-mismatch");
    expect(i.message).toContain("추가 풀 192.168.2.0/24");
    expect(i.message).toContain("192.168.2.254");
    expect(i.fix).toContain("추가 풀 1");
    expect(i.fix).toContain("192.168.2.1 (");
    expect(i.related).toEqual([gw.id]);
    // 다른 서브넷(if1)의 라우터 주소는 이 풀의 게이트웨이가 될 수 없다
    pool.router = "192.168.1.1";
    expect(issue(lintTopology(t), srv.id, "dhcp.gateway-mismatch").message).toContain("풀 서브넷 밖");
    pool.router = "192.168.2.1";
    expect(lintTopology(t)).toEqual([]);
  });

  it("추가 풀: 릴레이 인터페이스 주소를 모르거나 풀 서브넷에 라우터 인터페이스가 없으면 침묵", () => {
    const t = examplePartsTopology();
    const srv = t.devices.find((d) => d.name === "dhcp-srv")!;
    const gw = t.devices.find((d) => d.kind === "gateway")!;
    const pool = srv.host!.dhcpServer.extraPools![0]!;
    pool.router = "192.168.2.254";
    gw.l3!.interfaces[2] = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "", relay: "192.168.1.2" };
    expect(codes(lintTopology(t), srv.id)).toEqual([]);
    const t2 = examplePartsTopology();
    const srv2 = t2.devices.find((d) => d.name === "dhcp-srv")!;
    srv2.host!.dhcpServer.extraPools!.push({ start: "172.16.0.100", end: "172.16.0.199", prefix: 24, router: "172.16.0.1", dns: "8.8.8.8" });
    expect(codes(lintTopology(t2), srv2.id)).toEqual([]);
  });

  it("옵션(3)이 DHCP 서버 자신의 주소면 ARP timeout 이 아니라 서버가 받아 드롭한다고 안내한다 (시뮬레이션으로 확인)", () => {
    const { t, srv } = dhcpLan("192.168.1.2");
    const pc = t.devices.find((d) => d.kind === "pc")!;
    const i = issue(lintTopology(t), srv.id, "dhcp.gateway-mismatch");
    expect(i.message).toContain("주소는 받지만");
    expect(i.message).toContain(`${srv.name} 가 ARP 에 응답`);
    expect(i.message).not.toContain("ARP timeout");
    const sim = loadTopology(t);
    expect(sim.host(pc.name).iface.gateway).toBe("192.168.1.2");
    const tr = sim.act({ kind: "ping", nodeId: pc.id, dst: "10.9.9.9" });
    expect(tr.some((e) => e.nodeId === srv.id && e.kind === "ip.drop")).toBe(true);
    expect(tr.some((e) => e.kind === "arp.timeout")).toBe(false);
    // 옵션이 이 서버의 풀 범위 안이면 그 주소를 받은 단말일 수도 있다
    srv.host!.dhcpServer.router = "192.168.1.150";
    expect(issue(lintTopology(t), srv.id, "dhcp.gateway-mismatch").message).toContain("DHCP 로 받은 단말");
  });

  it("기본 풀과 추가 풀이 둘 다 틀리면 (장치, code) 하나로 합쳐지더라도 한 이슈에 둘 다 드러난다", () => {
    const t = examplePartsTopology();
    const srv = t.devices.find((d) => d.name === "dhcp-srv")!;
    const pool = srv.host!.dhcpServer.extraPools![0]!;
    srv.host!.dhcpServer.router = "192.168.1.254";
    pool.router = "192.168.2.254";
    const issues = lintTopology(t).filter((i) => i.deviceId === srv.id);
    expect(codes(issues)).toEqual(["dhcp.gateway-mismatch"]);
    const i = issues[0]!;
    expect(i.message).toContain("옵션(3) 192.168.1.254");
    expect(i.message).toContain("추가 풀 192.168.2.0/24 의 기본 게이트웨이 옵션(3) 192.168.2.254");
    expect(i.fix).toContain("기본 게이트웨이 칸을 192.168.1.1 (");
    expect(i.fix).toContain("추가 풀 1 → 게이트웨이 칸을 192.168.2.1 (");
    // 게이트웨이 칸이 둘 다 비어도 마찬가지
    srv.host!.dhcpServer.router = "";
    pool.router = "";
    const j = lintTopology(t).filter((x) => x.deviceId === srv.id);
    expect(codes(j)).toEqual(["dhcp.no-router"]);
    expect(j[0]!.message).toContain("DHCP 로 주소는 나가지만");
    expect(j[0]!.message).toContain("추가 풀 192.168.2.0/24");
    expect(j[0]!.fix).toContain("192.168.1.1");
    expect(j[0]!.fix).toContain("192.168.2.1");
  });
});

describe("규칙 23 dhcp.range-invalid (서버가 Discover 에 응답하지 않는 범위)", () => {
  /** 게이트웨이 if1(192.168.1.1) 아래 스위치에 DHCP 서버 호스트(192.168.1.2/prefix) + DHCP 로 받는 pc */
  function lanWithRange(start: string, end: string, router: string, prefix = 24) {
    const b = build();
    const gw = b.add("gateway");
    const sw = b.add("switch");
    const srv = staticHost(b.add("server"), "192.168.1.2", "192.168.1.1", { prefix, dns: "8.8.8.8", dhcpServer: { enabled: true, start, end, router, dns: "8.8.8.8" } });
    const pc = b.add("pc");
    b.link(gw, 1, sw, 0);
    b.link(sw, 1, srv, 0);
    b.link(sw, 2, pc, 0);
    return { ...b, gw, sw, srv, pc };
  }

  it("범위가 서버 서브넷 밖이면 '주소는 받지만' 하는 gateway-mismatch 대신 range-invalid 만 — 시뮬레이션에서도 서버가 응답하지 않는다", () => {
    const x = lanWithRange("192.168.5.100", "192.168.5.199", "192.168.5.1");
    const issues = lintTopology(x.t);
    expect(codes(issues, x.srv.id)).toEqual(["dhcp.range-invalid"]);
    const i = issue(issues, x.srv.id, "dhcp.range-invalid");
    expect(i.severity).toBe("error");
    expect(i.message).toContain("192.168.5.100 ~ 192.168.5.199");
    expect(i.message).toContain("192.168.1.0/24 밖");
    expect(i.message).toContain("응답하지 않아");
    expect(i.fix).toContain("192.168.1.0/24 안으로");
    const sim = loadTopology(x.t);
    expect(sim.s.net.trace.some((e) => e.nodeId === x.srv.id && e.kind === "dhcp.misconfigured")).toBe(true);
    expect(sim.host(x.pc.name).iface.ip).toBeUndefined();
  });

  it("시작 > 끝도 같은 규칙, 범위가 잘못되면 게이트웨이·DNS 안내 규칙과 추가 풀 규칙은 모두 침묵", () => {
    const r = lanWithRange("192.168.1.199", "192.168.1.100", "192.168.1.1");
    expect(codes(lintTopology(r.t), r.srv.id)).toEqual(["dhcp.range-invalid"]);
    expect(issue(lintTopology(r.t), r.srv.id, "dhcp.range-invalid").message).toContain("끝 주소 192.168.1.100 보다 큼");
    const sim = loadTopology(r.t);
    expect(sim.host(r.pc.name).iface.ip).toBeUndefined();
    const e = lanWithRange("192.168.5.100", "192.168.5.199", "");
    e.srv.host!.dhcpServer.dns = "";
    expect(codes(lintTopology(e.t), e.srv.id)).toEqual(["dhcp.range-invalid"]);
    // 서버는 릴레이로 온 요청에도 응답하지 않는다 → 추가 풀의 게이트웨이 문제도 말하지 않음
    const t = examplePartsTopology();
    const srv = t.devices.find((d) => d.name === "dhcp-srv")!;
    srv.host!.dhcpServer.start = "10.9.9.100";
    srv.host!.dhcpServer.end = "10.9.9.199";
    srv.host!.dhcpServer.extraPools![0]!.router = "192.168.2.254";
    const issues = lintTopology(t).filter((i) => i.deviceId === srv.id);
    expect(codes(issues)).toEqual(["dhcp.range-invalid"]);
    expect(issues[0]!.message).toContain("추가 풀");
  });

  it("추가 풀이 서버 서브넷 밖인 건 정상(릴레이용), /0 서버는 어느 범위든 안, 입력 중인 범위는 침묵", () => {
    expect(lintTopology(examplePartsTopology())).toEqual([]);
    const z = lanWithRange("10.0.0.100", "10.0.0.199", "10.0.0.1", 0);
    expect(codes(lintTopology(z.t), z.srv.id)).not.toContain("dhcp.range-invalid");
    expect(loadTopology(z.t).host(z.pc.name).iface.ip).toBe("10.0.0.100"); // 코어도 /0 서버는 응답
    const p = lanWithRange("192.168.5.", "192.168.5.199", "192.168.1.1");
    expect(codes(lintTopology(p.t), p.srv.id)).toEqual([]);
    // 서버 IP 를 입력 중이면 코어 서버는 응답하지 않는다("서버 자신의 IP 주소가 없음") → "주소는 나가지만" 류 안내도 하지 않음
    const q = lanWithRange("192.168.1.100", "192.168.1.199", "");
    q.srv.host!.ip = "192.168.1.";
    expect(codes(lintTopology(q.t), q.srv.id)).toEqual([]);
    expect(loadTopology(q.t).host(q.pc.name).iface.ip).toBeUndefined();
  });
});

describe("규칙 22 host.prefix-mismatch", () => {
  /** 게이트웨이 if1(192.168.1.1/24) 아래 스위치에 수동 호스트 */
  function lan(prefix: number, gateway = "192.168.1.1", ip = "192.168.1.10") {
    const b = build();
    const gw = b.add("gateway");
    const sw = b.add("switch");
    const pc = staticHost(b.add("pc"), ip, gateway, { prefix });
    b.link(gw, 1, sw, 0);
    b.link(sw, 1, pc, 0);
    return { ...b, gw, sw, pc };
  }

  it("호스트 프리픽스가 라우터보다 짧으면 라우터 서브넷 밖 주소를 ARP 로 직접 찾다가 실패한다고 경고", () => {
    const { t, gw, pc } = lan(16);
    const issues = lintTopology(t);
    expect(codes(issues, pc.id)).toEqual(["host.prefix-mismatch"]);
    const i = issue(issues, pc.id, "host.prefix-mismatch");
    expect(i.severity).toBe("warn");
    expect(i.message).toContain("/16");
    expect(i.message).toContain("짧음");
    expect(i.message).toContain("192.168.0.0/16 안이지만 192.168.1.0/24 밖");
    expect(i.message).toContain("ARP timeout");
    expect(i.fix).toContain("서브넷을 /24 로");
    expect(i.related).toEqual([gw.id]);
  });

  it("더 길면 같은 서브넷 일부를 게이트웨이로 돌려 보냄: 게이트웨이는 우회, 공유기는 드롭, 게이트웨이 없으면 드롭", () => {
    const x = lan(28);
    const i = issue(lintTopology(x.t), x.pc.id, "host.prefix-mismatch");
    expect(i.message).toContain("김");
    expect(i.message).toContain("같은 서브넷 192.168.1.0/24 인데 192.168.1.0/28 밖");
    expect(i.message).toContain("우회");
    // 공유기: LAN 안 주소를 게이트웨이로 받으면 드롭한다
    const b = build();
    const rt = b.add("router");
    const sw = b.add("switch");
    const pc = staticHost(b.add("pc"), "192.168.0.10", "192.168.0.1", { prefix: 28 });
    b.link(rt, 1, sw, 0);
    b.link(sw, 1, pc, 0);
    const j = issue(lintTopology(b.t), pc.id, "host.prefix-mismatch");
    expect(j.message).toContain("공유기");
    expect(j.message).toContain("드롭");
    expect(j.related).toEqual([rt.id]);
    pc.host!.gateway = "";
    expect(issue(lintTopology(b.t), pc.id, "host.prefix-mismatch").message).toContain("게이트웨이 설정이 없어 드롭");
  });

  it("프리픽스가 같으면 통과, DHCP 로 받는 호스트는 침묵, 게이트웨이가 서브넷 밖이면 규칙 3 만", () => {
    expect(lintTopology(lan(24).t)).toEqual([]);
    const d = lan(16);
    d.pc.host!.ipMode = "dhcp"; // 칸에 남은 옛 값은 쓰이지 않는다
    expect(lintTopology(d.t)).toEqual([]);
    const o = lan(28, "192.168.1.1", "192.168.1.100"); // /28 이면 192.168.1.96/28 → 게이트웨이 .1 이 밖
    expect(codes(lintTopology(o.t), o.pc.id)).toEqual(["host.gateway-outside-subnet"]);
  });

  it("라우터 서브넷 밖 IP 는 규칙 11 만, 같은 길이의 라우터가 하나라도 있거나 서브넷을 모르는 라우터가 끼면 침묵", () => {
    const m = lan(16, "", "192.168.5.10");
    expect(codes(lintTopology(m.t), m.pc.id)).toEqual(["segment.mixed-subnet"]);
    // 같은 세그먼트에 /16 라우터도 있으면 호스트가 그쪽에 맞춘 것일 수 있다
    const two = lan(16);
    const nat = two.add("nat");
    nat.l3!.interfaces[1] = { ipMode: "static", ip: "192.168.200.1", prefix: 16, gateway: "" };
    two.link(nat, 1, two.sw, 2);
    expect(codes(lintTopology(two.t), two.pc.id)).toEqual([]);
    // NAT if1 + 게이트웨이 if0(DHCP, 서브넷 모름) 세그먼트의 /16 호스트
    const c = twoTier();
    c.gw.l3!.interfaces[0] = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" };
    const sw2 = c.add("switch");
    c.t.cables.splice(1, 1);
    c.link(c.nat, 1, sw2, 0);
    c.link(sw2, 1, c.gw, 0);
    const pc = staticHost(c.add("pc"), "10.0.0.50", "10.0.0.1", { prefix: 16 });
    c.link(sw2, 2, pc, 0);
    expect(codes(lintTopology(c.t), pc.id)).toEqual([]);
  });

  it("게이트웨이 규칙(규칙 4)에 걸린 호스트는 내지 않는다 — 세그먼트에 없는 게이트웨이로 '돌려 보냄' 이라고 쓰지 않게", () => {
    const x = lan(28, "192.168.1.5"); // 192.168.1.10/28, 게이트웨이 .5 는 내 서브넷 안이지만 그런 라우터가 없다
    expect(codes(lintTopology(x.t), x.pc.id)).toEqual(["host.no-gateway-in-segment"]);
  });

  it("/0 호스트도 잡는다 (모든 주소를 같은 네트워크로 보고 ARP) — 다른 규칙은 그대로", () => {
    const x = lan(0);
    const issues = lintTopology(x.t);
    expect(codes(issues)).toEqual(["host.prefix-mismatch"]);
    const i = issue(issues, x.pc.id, "host.prefix-mismatch");
    expect(i.message).toContain("/0");
    expect(i.message).toContain("짧음");
    expect(i.message).toContain("ARP timeout");
    expect(i.fix).toContain("서브넷을 /24 로");
    const sim = loadTopology(x.t);
    expect(sim.act({ kind: "ping", nodeId: x.pc.id, dst: "10.9.9.9" }).some((e) => e.nodeId === x.pc.id && e.kind === "arp.timeout")).toBe(true);
    // 라우터 서브넷 밖 /0 호스트는 여전히 규칙 11 만
    const m = lan(0, "", "10.5.5.5");
    expect(codes(lintTopology(m.t), m.pc.id)).toEqual(["segment.mixed-subnet"]);
  });
});

describe("결과 정리", () => {
  it("같은 (장치, code) 는 하나로 합치고 error 가 warn 보다 먼저, 그다음 장치 순서", () => {
    const b = build();
    const rt = b.add("router");
    const sw = b.add("switch");
    const pcA = staticHost(b.add("pc"), "192.168.5.10", ""); // warn (mixed-subnet)
    const pcB = staticHost(b.add("pc"), "192.168.0.1", ""); // error (duplicate-ip, rt 도)
    b.link(rt, 1, sw, 0);
    b.link(sw, 1, pcA, 0);
    b.link(sw, 2, pcB, 0);
    const issues = lintTopology(b.t);
    expect(issues.map((i) => [i.severity, i.deviceId, i.code])).toEqual([
      ["error", rt.id, "segment.duplicate-ip"],
      ["error", pcB.id, "segment.duplicate-ip"],
      ["warn", pcA.id, "segment.mixed-subnet"],
    ]);
    for (const i of issues) expect(i.related ?? []).not.toContain(i.deviceId);
    const keys = issues.map((i) => `${i.deviceId}/${i.code}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("빈 토폴로지와 케이블 없는 기본 장치들은 이슈가 없다", () => {
    expect(lintTopology({ devices: [], cables: [] })).toEqual([]);
    const b = build();
    for (const k of ["pc", "laptop", "phone", "server", "switch", "hub", "ap", "router", "gateway", "nat", "internet"] as DeviceKind[]) b.add(k);
    expect(lintTopology(b.t)).toEqual([]);
  });
});
