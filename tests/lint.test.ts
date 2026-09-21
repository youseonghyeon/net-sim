import { describe, expect, it } from "vitest";
import { l2Segments, lintTopology, type LintIssue } from "../src/model/lint";
import {
  DEFAULT_DHCP_SERVER,
  createDevice,
  exampleTopology,
  examplePartsTopology,
  exampleVlanTopology,
  newId,
  type Cable,
  type Device,
  type DeviceKind,
  type HostSettings,
  type Topology,
} from "../src/model/topology";

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
