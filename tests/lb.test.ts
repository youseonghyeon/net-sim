// 로드밸런서 (리버스 프록시): 라운드 로빈·최소 연결, 패시브 헬스 체크(실패 → 10초 빼고 다음 백엔드), 502, 서버 토글과 전용 장비가 같은 동작
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { NetworkSync } from "../src/model/netSync";
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
  const t: Topology = { devices, cables };
  const s = new NetworkSync();
  s.sync(t);
  s.net.runToIdle();
  const id = (name: string) => t.devices.find((d) => d.name === name)!.id;
  const pc = s.net.nodes.get(id("pc-1")) as Host;
  const get = () => {
    s.net.scheduleAction(s.net.now, { kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.10", port: 80 });
    s.net.runToIdle();
    return [...pc.tcp.conns.values()].at(-1)!;
  };
  return { t, s, id, get };
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
