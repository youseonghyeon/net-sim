import { describe, expect, it } from "vitest";
import { effectiveDnsServer, effectiveFirewall, effectiveForwards, effectiveL3, effectiveSwitchVlans } from "../src/model/netSync";
import { lintTopology } from "../src/model/lint";
import { createDevice, devicesInZone, EXAMPLE_LIST, normalizeTopology, planCable, zoneAround, type Device, type Topology } from "../src/model/topology";

describe("normalizeTopology", () => {
  it("저장된 게이트웨이의 서브 인터페이스·방화벽·포워딩 설정을 잃지 않는다", () => {
    const devices: Device[] = [];
    const gw = createDevice("gateway", 0, 0, devices);
    const l3In: NonNullable<Device["l3"]> = {
      ...gw.l3!,
      subinterfaces: [{ port: 1, vlan: 10, ip: "192.168.10.1", prefix: 24, relay: "" }],
      firewall: { enabled: true, defaultPolicy: "deny", stateful: true, rules: [] },
      forwards: [{ publicPort: 8080, lanIp: "192.168.10.5", lanPort: 80 }],
    };
    gw.l3 = l3In;
    devices.push(gw);
    const out = normalizeTopology({ devices, cables: [] });
    const l3 = out.devices[0]!.l3!;
    expect(l3.subinterfaces).toEqual(l3In.subinterfaces);
    expect(l3.firewall?.defaultPolicy).toBe("deny");
    expect(l3.forwards).toHaveLength(1);
    expect(l3.interfaces).toHaveLength(l3In.interfaces.length);
  });
});

describe("planCable: 케이블 연결 검증", () => {
  function mk() {
    const devices: Device[] = [];
    const add = (kind: Parameters<typeof createDevice>[0]) => {
      const d = createDevice(kind, 0, devices.length * 200, devices);
      devices.push(d);
      return d;
    };
    return { devices, add };
  }

  it("빈 포트를 골라 잇고, 같은 두 장치 사이 두 번째 케이블은 L2 루프라 거부한다", () => {
    const { devices, add } = mk();
    const sw = add("switch");
    const pc = add("pc");
    const t: Topology = { devices, cables: [] };
    const plan = planCable(t, pc.id, sw.id);
    expect("error" in plan).toBe(false);
    if ("error" in plan) return;
    expect(plan.a).toEqual({ device: pc.id, port: 0 });
    expect(plan.b.device).toBe(sw.id);
    t.cables.push({ id: "c1", a: plan.a, b: plan.b });
    const again = planCable(t, sw.id, pc.id);
    expect("error" in again && again.error).toContain("이미 연결");
    expect("error" in planCable(t, pc.id, pc.id)).toBe(true);
  });

  it("무선 전용 단말과 포트가 다 찬 장치는 이유를 말하며 거부한다", () => {
    const { devices, add } = mk();
    const phone = add("phone");
    const pc = add("pc");
    const pc2 = add("pc");
    const sw = add("switch");
    const t: Topology = { devices, cables: [{ id: "c1", a: { device: pc.id, port: 0 }, b: { device: sw.id, port: 0 } }] };
    const wl = planCable(t, phone.id, sw.id);
    expect("error" in wl && wl.error).toContain("무선 전용");
    const full = planCable(t, pc.id, pc2.id);
    expect("error" in full && full.error).toContain("빈 포트가 없습니다");
    expect("error" in planCable(t, "nope", sw.id)).toBe(true);
  });
});

describe("effective*: 입력 중인 값을 시뮬레이션용으로 정리한다", () => {
  it("방화벽: 형식이 틀린 CIDR·포트 규칙은 빼고, 포트는 1..65535 로 자른다", () => {
    const out = effectiveFirewall({
      enabled: true,
      defaultPolicy: "deny",
      stateful: false,
      rules: [
        { action: "allow", proto: "tcp", direction: "in", src: "", dst: "192.168.0.0/24", dstPort: "80" },
        { action: "deny", proto: "any", direction: "any", src: "10.0.0.0/", dst: "", dstPort: "" },
        { action: "deny", proto: "udp", direction: "out", src: "", dst: "", dstPort: "abc" },
        { action: "allow", proto: "tcp", direction: "out", src: "", dst: "", dstPort: "99999" },
      ],
    });
    expect(out.rules).toEqual([
      { action: "allow", proto: "tcp", direction: "in", src: undefined, dst: "192.168.0.0/24", dstPort: 80 },
      { action: "allow", proto: "tcp", direction: "out", src: undefined, dst: undefined, dstPort: 65535 },
    ]);
  });

  it("포트 포워딩·스태틱 라우팅·서브 인터페이스: 불완전한 항목은 빠지고 무선 슬롯 포트엔 서브 인터페이스를 못 둔다", () => {
    expect(effectiveForwards([{ publicPort: 80, lanIp: "192.168.0.", lanPort: 80 }, { publicPort: 0, lanIp: "192.168.0.2", lanPort: 80 }, { publicPort: 8080, lanIp: "192.168.0.2", lanPort: 80 }])).toEqual([
      { publicPort: 8080, lanIp: "192.168.0.2", lanPort: 80 },
    ]);
    const gw = createDevice("gateway", 0, 0, []);
    gw.l3 = {
      ...gw.l3!,
      routes: [{ dest: "10.0.0.0", prefix: 8, via: "192.168.0.254" }, { dest: "10.0", prefix: 8, via: "192.168.0.254" }, { dest: "10.0.0.0", prefix: 40, via: "192.168.0.254" }],
      subinterfaces: [
        { port: 1, vlan: 10, ip: "192.168.10.1", prefix: 24, relay: "" },
        { port: 0, vlan: 20, ip: "10.0.0.1", prefix: 24, relay: "" }, // 업링크엔 불가
        { port: 1, vlan: 5000, ip: "192.168.50.1", prefix: 24, relay: "" }, // 범위 밖
        { port: 1, vlan: 30, ip: "192.168.30.", prefix: 24, relay: "192.168.1.2" }, // 주소 입력 중
      ],
    };
    const l3 = effectiveL3(gw);
    expect(l3.routes).toEqual([{ dest: "10.0.0.0", prefix: 8, via: "192.168.0.254" }]);
    expect(l3.subinterfaces).toEqual([
      { port: 1, vlan: 10, ip: "192.168.10.1", prefix: 24, relay: undefined },
      { port: 1, vlan: 30, ip: undefined, prefix: 24, relay: "192.168.1.2" },
    ]);
  });

  it("스위치 VLAN: 1..4094 와 trunk 만 남는다", () => {
    const sw = createDevice("switch", 0, 0, []);
    sw.switch = { vlans: { 0: "trunk", 1: 10, 2: 0, 3: 4095, 4: 2.5 as number } };
    expect([...effectiveSwitchVlans(sw).entries()]).toEqual([
      [0, "trunk"],
      [1, 10],
    ]);
  });

  it("호스트 DNS 서버: 이름은 소문자로 정리하고 주소가 틀린 레코드는 뺀다", () => {
    const srv = createDevice("server", 0, 0, []);
    srv.host = { ...srv.host!, dnsServer: { enabled: true, records: [{ name: " Web.Home ", ip: "192.168.0.20" }, { name: "", ip: "192.168.0.21" }, { name: "x", ip: "bad" }], upstream: "8.8.8." } };
    expect(effectiveDnsServer(srv)).toEqual({ enabled: true, records: [{ name: "web.home", ip: "192.168.0.20" }], upstream: undefined });
  });
});

describe("예제 토폴로지", () => {
  it("모든 예제는 구성 검사 이슈가 없고, 케이블은 존재하는 장치의 유효한 포트만 가리킨다", () => {
    for (const ex of EXAMPLE_LIST) {
      const t = ex.build();
      expect(lintTopology(t), ex.id).toEqual([]);
      expect(normalizeTopology(t).cables.length, ex.id).toBe(t.cables.length); // 정규화가 버리는 케이블이 없다
      expect(new Set(t.devices.map((d) => d.name)).size, ex.id).toBe(t.devices.length);
    }
  });
});

describe("영역 (주석 네모)", () => {
  it("normalize 가 영역을 보존하고 깨진 항목은 버리며, 최소 크기를 지킨다", () => {
    const pc = createDevice("pc", 100, 100, []);
    const t: Topology = {
      devices: [pc],
      cables: [],
      zones: [
        { id: "z1", label: "집 안", x: 0, y: 0, w: 40, h: 40, tint: "blue" },
        { id: "z2", label: "x", x: Number.NaN, y: 0, w: 100, h: 100, tint: "gray" },
        { id: "z3", label: "", x: 0, y: 0, w: 200, h: 200, tint: "purple" as never },
      ],
    };
    const out = normalizeTopology(t);
    expect(out.zones).toHaveLength(2);
    expect(out.zones![0]).toMatchObject({ id: "z1", w: 96, h: 96, tint: "blue" }); // ZONE_MIN
    expect(out.zones![1]).toMatchObject({ id: "z3", tint: "gray" });
    expect(normalizeTopology({ devices: [], cables: [] }).zones).toBeUndefined();
  });

  it("zoneAround 는 장치 묶음(호스트 이름 줄 포함)을 감싸고, devicesInZone 은 타일 중심으로 판단한다", () => {
    const devices: Device[] = [];
    const a = createDevice("pc", 100, 100, devices);
    devices.push(a);
    const b = createDevice("switch", 300, 100, devices);
    devices.push(b);
    const c = createDevice("pc", 900, 900, devices);
    devices.push(c);
    const t: Topology = { devices, cables: [] };
    const r = zoneAround(t, [a.id, b.id])!;
    expect(r.x).toBeLessThan(100);
    expect(r.y).toBeLessThan(88);
    expect(r.x + r.w).toBeGreaterThan(300 + 152);
    expect(r.y + r.h).toBeGreaterThan(100 + 64 + 44);
    const z = { id: "z", label: "영역", tint: "gray" as const, ...r };
    expect(devicesInZone(t, z)).toEqual([a.id, b.id]);
    expect(zoneAround(t, [])).toBeNull();
  });
});
