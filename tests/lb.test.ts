// 로드밸런서 (리버스 프록시): 라운드 로빈·최소 연결, 패시브 헬스 체크(실패 → 10초 빼고 다음 백엔드), 502, 서버 토글과 전용 장비가 같은 동작
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { NetworkSync } from "../src/model/netSync";
import { loadTopology } from "./helpers";
import { createDevice, DEFAULT_DHCP_SERVER, newId, type Cable, type Device, type Topology } from "../src/model/topology";

/** 스위치 하나에 pc-1, LB(장비 또는 서버 토글), web-1..3 */
function lan(form: "device" | "server", backends = ["192.168.0.11", "192.168.0.12", "192.168.0.13"], algorithm: "round-robin" | "least-conn" = "round-robin") {
  const devices: Device[] = [];
  const cables: Cable[] = [];
  const sw = createDevice("switch", 0, 0, devices);
  devices.push(sw);
  let port = 0;
  const add = (kind: Parameters<typeof createDevice>[0], name: string, ip: string, services: number[] = []) => {
    const d = createDevice(kind, 0, 0, devices);
    d.name = name;
    d.host = { ...d.host!, ipMode: "static", ip, prefix: 24, gateway: "", services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
    devices.push(d);
    cables.push({ id: newId("cable"), a: { device: sw.id, port: port++ }, b: { device: d.id, port: 0 } });
    return d;
  };
  add("pc", "pc-1", "192.168.0.100");
  const lb = add(form === "device" ? "lb" : "server", "lb", "192.168.0.10");
  lb.host!.lb = { enabled: true, port: 80, algorithm, backends: backends.map((ip) => ({ ip, port: 80 })) };
  add("server", "web-1", "192.168.0.11", [80]);
  add("server", "web-2", "192.168.0.12", [80]);
  add("server", "web-3", "192.168.0.13", [80]);
  const x = loadTopology({ devices, cables });
  const pc = x.host("pc-1");
  const get = () => {
    x.act({ kind: "tcp-connect", nodeId: x.id("pc-1"), dst: "192.168.0.10", port: 80 });
    return [...pc.tcp.conns.values()].at(-1)!;
  };
  return { t: x.t, s: x.s, id: x.id, get };
}

describe("로드밸런서", () => {
  for (const form of ["device", "server"] as const) {
    it(`${form === "device" ? "전용 장비" : "서버 토글"}: 라운드 로빈으로 web-1 → web-2 → web-3 → web-1 이 차례로 응답한다`, () => {
      const { get } = lan(form);
      const served = [get(), get(), get(), get()].map((c) => {
        expect(c).toMatchObject({ state: "CLOSED", remoteIp: "192.168.0.10", bytesReceived: 3000 });
        return c.servedBy;
      });
      expect(served).toEqual(["192.168.0.11", "192.168.0.12", "192.168.0.13", "192.168.0.11"]);
    });
  }

  it("백엔드 입장에서 클라이언트는 LB 다 (리버스 프록시)", () => {
    const { s, id, get } = lan("device");
    get();
    const web1 = s.net.nodes.get(id("web-1")) as Host;
    expect([...web1.tcp.conns.values()].at(-1)).toMatchObject({ role: "server", remoteIp: "192.168.0.10" });
  });

  it("패시브 헬스 체크: 서비스가 없는 백엔드는 거부(RST) → 10초 빼고 같은 요청을 다음 백엔드로, 다음 요청도 건너뛴다", () => {
    const { t, s, get } = lan("device");
    // web-2 의 웹 서비스를 끈다
    const off: Topology = { ...t, devices: t.devices.map((d) => (d.name === "web-2" ? { ...d, host: { ...d.host!, services: [] } } : d)) };
    s.sync(off);
    s.net.runToIdle();
    const a = get(); // web-1
    const b = get(); // web-2 차례 → 거부 → web-3 로
    const c = get(); // web-2 는 빠져 있어 web-1
    expect([a.servedBy, b.servedBy, c.servedBy]).toEqual(["192.168.0.11", "192.168.0.13", "192.168.0.11"]);
    expect(b.bytesReceived).toBe(3000);
    expect(s.net.trace.some((e) => e.kind === "lb.down" && e.summary.includes("192.168.0.12:80"))).toBe(true);
  });

  it("살아 있는 백엔드가 없으면 502 Bad Gateway 를 돌려준다", () => {
    const { get, s } = lan("device", ["192.168.0.99"]); // 없는 주소 → ARP timeout 으로 SYN 이 나가지 못함
    const c = get();
    expect(c.state).toBe("CLOSED");
    expect(c.bytesReceived).toBe(200);
    expect(s.net.trace.some((e) => e.kind === "lb.fail")).toBe(true);
  });

  it("최소 연결: 진행 중인 연결이 가장 적은 백엔드를 고른다 (동시에 두 요청이면 서로 다른 백엔드)", () => {
    const { s, id, t } = lan("device", undefined, "least-conn");
    const pc = s.net.nodes.get(id("pc-1")) as Host;
    s.net.scheduleAction(s.net.now, { kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.10", port: 80 });
    s.net.scheduleAction(s.net.now, { kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.10", port: 80 });
    s.net.runToIdle();
    const two = [...pc.tcp.conns.values()].slice(-2).map((c) => c.servedBy);
    expect(new Set(two).size).toBe(2);
    expect(t).toBeDefined();
  });
});

import { lintTopology } from "../src/model/lint";

describe("구성 검사: 로드밸런서", () => {
  it("백엔드가 없으면 lb.no-backend, 백엔드 서버가 포트를 안 열면 lb.backend-closed, 고치면 사라진다", () => {
    const { t } = lan("device", []);
    const lbId = t.devices.find((d) => d.name === "lb")!.id;
    expect(lintTopology(t).filter((i) => i.deviceId === lbId).map((i) => i.code)).toEqual(["lb.no-backend"]);
    const withClosed: Topology = {
      ...t,
      devices: t.devices.map((d) => {
        if (d.id === lbId) return { ...d, host: { ...d.host!, lb: { ...d.host!.lb!, backends: [{ ip: "192.168.0.11", port: 80 }, { ip: "192.168.0.12", port: 8080 }] } } };
        return d;
      }),
    };
    const issues = lintTopology(withClosed).filter((i) => i.deviceId === lbId);
    expect(issues.map((i) => i.code)).toEqual(["lb.backend-closed"]);
    expect(issues[0]!.message).toContain("192.168.0.12:8080");
  });
});

import { Internet } from "../src/core/nodes/internet";
import { Router } from "../src/core/nodes/router";
import { exampleLoadBalancerTopology } from "../src/model/examples";

describe("예제: 로드밸런서 (서버 토글 vs 전용 장비)", () => {
  it("구성 검사 이슈 없음, nginx 서버는 web-1·web-2 를 번갈아, 바깥 요청은 포트 포워딩 → lb-1 → 웹 서버", () => {
    const t = exampleLoadBalancerTopology();
    expect(lintTopology(t)).toEqual([]);
    const s = new NetworkSync();
    s.sync(t);
    s.net.runToIdle();
    const id = (name: string) => t.devices.find((d) => d.name === name)!.id;
    const pc = s.net.nodes.get(id("pc-1")) as Host;
    const served: (string | undefined)[] = [];
    for (let k = 0; k < 3; k++) {
      s.net.scheduleAction(s.net.now, { kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.10", port: 80 });
      s.net.runToIdle();
      served.push([...pc.tcp.conns.values()].at(-1)!.servedBy);
    }
    expect(served).toEqual(["192.168.0.11", "192.168.0.12", "192.168.0.11"]);
    const wan = (s.net.nodes.get(id("공유기")) as Router).wan.ip!;
    s.net.scheduleAction(s.net.now, { kind: "inet-connect", nodeId: id("internet-1"), dst: wan, port: 80 });
    s.net.runToIdle();
    const inbound = [...(s.net.nodes.get(id("internet-1")) as Internet).tcp.conns.values()].at(-1)!;
    expect(inbound).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    expect(inbound.servedBy).toMatch(/^192\.168\.0\.1[123]$/);
  });
});

import { probeTargets } from "../src/model/reach";

// 리뷰(2026-09-29)에서 재현된 결함의 회귀 테스트
describe("로드밸런서: 순환·중단·루프백·상태 전달", () => {
  type Spec = { name: string; kind?: "pc" | "server" | "lb"; ip: string; services?: number[]; lb?: { port?: number; algorithm?: "round-robin" | "least-conn"; backends: string[] } };
  function net(specs: Spec[]) {
    const devices: Device[] = [];
    const cables: Cable[] = [];
    const sw = createDevice("switch", 0, 0, devices);
    devices.push(sw);
    const sw2 = createDevice("switch", 0, 0, devices); // 포트가 8개라 둘을 잇는다
    devices.push(sw2);
    cables.push({ id: newId("cable"), a: { device: sw.id, port: 7 }, b: { device: sw2.id, port: 7 } });
    specs.forEach((sp, i) => {
      const d = createDevice(sp.kind ?? "server", 0, 0, devices);
      d.name = sp.name;
      d.host = { ...d.host!, ipMode: "static", ip: sp.ip, prefix: 24, gateway: "", services: sp.services ?? [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
      if (sp.lb) d.host.lb = { enabled: true, port: sp.lb.port ?? 80, algorithm: sp.lb.algorithm ?? "round-robin", backends: sp.lb.backends.map((b) => ({ ip: b.split(":")[0]!, port: Number(b.split(":")[1] ?? 80) })) };
      devices.push(d);
      cables.push({ id: newId("cable"), a: { device: (i < 7 ? sw : sw2).id, port: i % 7 }, b: { device: d.id, port: 0 } });
    });
    const x = loadTopology({ devices, cables }, { maxEvents: 20_000 });
    const connect = (from: string, dst: string, port = 80) => {
      x.act({ kind: "tcp-connect", nodeId: x.id(from), dst, port });
      return x.lastConn(from);
    };
    return { t: x.t, s: x.s, id: x.id, connect };
  }

  it("같은 호스트의 다른 포트를 백엔드로 (nginx → localhost 앱): 루프백 TCP 가 성공한다", () => {
    const { connect } = net([
      { name: "pc-1", kind: "pc", ip: "192.168.0.100" },
      { name: "app", ip: "192.168.0.10", services: [8080], lb: { backends: ["192.168.0.10:8080"] } },
    ]);
    const got = connect("pc-1", "192.168.0.10");
    expect(got).toMatchObject({ state: "CLOSED", bytesReceived: 3000, servedBy: "192.168.0.10", status: "HTTP 200" });
    // LB 없이 자기 자신에게 TCP 연결도
    expect(connect("app", "192.168.0.10", 8080)).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
  });

  it("LB 끼리 서로를 백엔드로 두면 Via 로 끊겨 508 Loop Detected, 구성 검사 lb.loop", () => {
    const { t, connect } = net([
      { name: "pc-1", kind: "pc", ip: "192.168.0.100" },
      { name: "lb1", kind: "lb", ip: "192.168.0.20", lb: { backends: ["192.168.0.21"] } },
      { name: "lb2", kind: "lb", ip: "192.168.0.21", lb: { backends: ["192.168.0.20"] } },
    ]);
    expect(connect("pc-1", "192.168.0.20")).toMatchObject({ state: "CLOSED", status: "HTTP 508 Loop Detected" });
    const loops = lintTopology(t).filter((i) => i.code === "lb.loop").map((i) => t.devices.find((d) => d.id === i.deviceId)!.name);
    expect(loops.sort()).toEqual(["lb1", "lb2"]);
  });

  it("자기 자신을 백엔드로 두어도 끝난다 (508)", () => {
    const { connect } = net([
      { name: "pc-1", kind: "pc", ip: "192.168.0.100" },
      { name: "lb1", kind: "lb", ip: "192.168.0.20", lb: { backends: ["192.168.0.20:80"] } },
    ]);
    expect(connect("pc-1", "192.168.0.20").status).toBe("HTTP 508 Loop Detected");
  });

  it("뒤 LB 의 502 는 200 으로 바뀌지 않고 그대로 전달된다", () => {
    const { connect } = net([
      { name: "pc-1", kind: "pc", ip: "192.168.0.100" },
      { name: "lb1", kind: "lb", ip: "192.168.0.20", lb: { backends: ["192.168.0.21"] } },
      { name: "lb2", kind: "lb", ip: "192.168.0.21", lb: { backends: [] } },
    ]);
    const c = connect("pc-1", "192.168.0.20");
    expect(c.status).toBe("HTTP 502 Bad Gateway");
    expect(c.servedBy).toBe("192.168.0.21");
  });

  it("요청을 맡아 둔 LB 가 주소를 바꿔 중단돼도 클라이언트는 영원히 기다리지 않는다 (응답 timeout)", () => {
    const { t, s, id } = net([
      { name: "pc-1", kind: "pc", ip: "192.168.0.100" },
      { name: "lb1", kind: "lb", ip: "192.168.0.20", lb: { backends: ["192.168.0.99", "192.168.0.11"] } },
      { name: "web", ip: "192.168.0.11", services: [80] },
    ]);
    s.net.scheduleAction(s.net.now, { kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    for (let k = 0; k < 400; k++) s.net.step(); // LB 가 없는 .99 에 SYN 을 다시 보내는 중
    const moved = { ...t, devices: t.devices.map((d) => (d.name === "lb1" ? { ...d, host: { ...d.host!, ip: "192.168.0.30" } } : d)) };
    s.sync(moved);
    s.net.runToIdle(20_000);
    const c = [...(s.net.nodes.get(id("pc-1")) as Host).tcp.conns.values()].at(-1)!;
    expect(c.state).not.toBe("ESTABLISHED");
  });

  it("진단 자동완성: 502 를 주는 LB 는 닿지 않는 후보, 순환 LB 가 있어도 다른 후보는 제대로 판정", () => {
    const { t, id } = net([
      { name: "pc-1", kind: "pc", ip: "192.168.0.100" },
      { name: "empty", kind: "lb", ip: "192.168.0.20", lb: { backends: [] } },
      { name: "lb1", kind: "lb", ip: "192.168.0.21", lb: { backends: ["192.168.0.22"] } },
      { name: "lb2", kind: "lb", ip: "192.168.0.22", lb: { backends: ["192.168.0.21"] } },
      { name: "web", ip: "192.168.0.11", services: [80] },
    ]);
    const r = probeTargets(t, id("pc-1"), "tcp", 80);
    const by = (v: string) => r.candidates.find((c) => c.value === v);
    expect(by("192.168.0.20")).toMatchObject({ ok: false });
    expect(by("192.168.0.20")!.reason).toContain("HTTP 502");
    expect(by("192.168.0.11")).toMatchObject({ ok: true });
  });

  it("구성 검사는 시뮬레이션과 같은 기준: 포트 0 백엔드는 없는 것으로 보고 lb.no-backend", () => {
    const { t } = net([{ name: "lb1", kind: "lb", ip: "192.168.0.20", lb: { backends: ["192.168.0.11:0"] } }, { name: "web", ip: "192.168.0.11", services: [80] }]);
    const codes = lintTopology(t).filter((i) => i.deviceId === t.devices.find((d) => d.name === "lb1")!.id).map((i) => i.code);
    expect(codes).toEqual(["lb.no-backend"]);
  });
});
