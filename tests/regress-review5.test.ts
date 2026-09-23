import { lintTopology } from "../src/model/lint";
import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { FirewallBridge } from "../src/core/nodes/fwbridge";
import { Host } from "../src/core/nodes/host";
import { L3Node } from "../src/core/nodes/l3";
import { Switch } from "../src/core/nodes/switch";
import { NetworkSync } from "../src/model/netSync";
import {
  addDevice,
  beginCoalesce,
  canRedo,
  canUndo,
  clearAll,
  copySelected,
  endCoalesce,
  importJson,
  moveDevices,
  paste,
  redo,
  removeDevices,
  selection,
  topology,
  undo,
  zoneAroundSelected,
} from "../src/model/store";
import { createDevice, newId, normalizeTopology, type Device, type Topology } from "../src/model/topology";
// 5차 리뷰(2026-09-23)에서 재현된 코어 버그의 회귀 테스트

describe("5차 리뷰 회귀", () => {
  it("DHCP 릴레이가 중간 게이트웨이를 하나 더 거쳐도 서버까지 갔다가 돌아온다", () => {
    // c(dhcp) ─ g1(if1 192.168.1.1, 릴레이 → 10.0.1.10) ─ g2 ─ srv(10.0.1.10)
    const net = new Network();
    net.addNode(new Host({ id: "c", mac: "02:00:00:00:00:0c", ipMode: "dhcp" }));
    net.addNode(
      new L3Node({
        id: "g1",
        kind: "gateway",
        interfaces: [
          { name: "if0", mac: "02:00:00:10:00:01", mode: "static", ip: "10.0.0.1", prefix: 24, gateway: "10.0.0.2" },
          { name: "if1", mac: "02:00:00:11:00:01", mode: "static", ip: "192.168.1.1", prefix: 24, relay: "10.0.1.10" },
        ],
      }),
    );
    net.addNode(
      new L3Node({
        id: "g2",
        kind: "gateway",
        interfaces: [
          { name: "if0", mac: "02:00:00:10:00:02", mode: "static", ip: "10.0.0.2", prefix: 24 },
          { name: "if1", mac: "02:00:00:11:00:02", mode: "static", ip: "10.0.1.1", prefix: 24 },
        ],
        routes: [{ dest: "192.168.1.0", prefix: 24, via: "10.0.0.1" }],
      }),
    );
    net.addNode(
      new Host({
        id: "srv",
        mac: "02:00:00:00:00:05",
        ipMode: "static",
        ip: "10.0.1.10",
        prefix: 24,
        gateway: "10.0.1.1",
        dhcpServer: { enabled: true, start: "10.0.1.100", end: "10.0.1.110", extraPools: [{ start: "192.168.1.100", end: "192.168.1.110", prefix: 24, router: "192.168.1.1" }] },
      }),
    );
    net.connect("c", 0, "g1", 1);
    net.connect("g1", 0, "g2", 0);
    net.connect("g2", 1, "srv", 0);
    net.runToIdle();
    expect(net.getHost("c").ip).toMatch(/^192\.168\.1\.1\d\d$/);
    expect(net.trace.some((e) => e.nodeId === "g2" && e.kind === "dhcp.ignore")).toBe(false);
  });

  it("NAT 박스는 바깥에서 안쪽 사설 주소로 직접 온 UDP(DNS)도 드롭한다", () => {
    const net = new Network();
    net.addNode(new Host({ id: "evil", mac: "02:00:00:00:00:0e", ipMode: "static", ip: "203.0.113.50", prefix: 24, gateway: "203.0.113.2", dns: "192.168.1.10" }));
    net.addNode(
      new L3Node({
        id: "nat",
        kind: "nat",
        outside: 0,
        interfaces: [
          { name: "outside", mac: "02:00:00:10:00:03", mode: "static", ip: "203.0.113.2", prefix: 24 },
          { name: "inside", mac: "02:00:00:11:00:03", mode: "static", ip: "192.168.1.1", prefix: 24 },
        ],
      }),
    );
    net.addNode(new Host({ id: "ns", mac: "02:00:00:00:00:0f", ipMode: "static", ip: "192.168.1.10", prefix: 24, gateway: "192.168.1.1", dnsServer: { enabled: true, records: [{ name: "secret.lan", ip: "192.168.1.99" }] } }));
    net.connect("evil", 0, "nat", 0);
    net.connect("nat", 1, "ns", 0);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "evil", dst: "secret.lan" });
    net.runToIdle();
    const p = net.getHost("evil").pings.at(-1)!;
    expect(p.status).toBe("failed");
    expect(p.resolved).toBeUndefined();
    expect(net.trace.some((e) => e.nodeId === "nat" && e.kind === "ip.drop" && e.summary.includes("UDP"))).toBe(true);
  });

  it("투명 방화벽이 한 스위치의 두 VLAN 을 이어도 루프로 오판하지 않는다", () => {
    const net = new Network();
    const sw = net.addNode(new Switch("sw", 4));
    sw.setVlans(
      new Map([
        [0, 10],
        [1, 10],
        [2, 20],
        [3, 20],
      ]),
      net.contextFor("sw"),
    );
    net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "10.0.0.1", prefix: 24 }));
    net.addNode(new Host({ id: "b", mac: "02:00:00:00:00:0b", ipMode: "static", ip: "10.0.0.2", prefix: 24 }));
    net.addNode(new FirewallBridge("fw", { enabled: false, defaultPolicy: "allow", stateful: true, rules: [] }));
    net.connect("a", 0, "sw", 0);
    net.connect("sw", 1, "fw", 0);
    net.connect("fw", 1, "sw", 2);
    net.connect("b", 0, "sw", 3);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "10.0.0.2" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)).toMatchObject({ status: "ok" });
    expect(net.trace.some((e) => e.kind === "switch.loop")).toBe(false);
  });

  it("같은 VLAN 안의 진짜 루프(케이블 두 개)는 여전히 잡는다", () => {
    const net = new Network();
    net.addNode(new Switch("s1", 4));
    net.addNode(new Switch("s2", 4));
    net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "10.0.0.1", prefix: 24 }));
    net.connect("a", 0, "s1", 0);
    net.connect("s1", 1, "s2", 0);
    net.connect("s1", 2, "s2", 1);
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "10.0.0.9" });
    net.runToIdle();
    expect(net.trace.some((e) => e.kind === "switch.loop")).toBe(true);
  });
});

// ---------- 모델 층 ----------


function resetStore() {
  clearAll();
  while (canUndo.value) undo();
  while (canRedo.value) redo();
  clearAll();
  while (canUndo.value) undo();
}

describe("5차 리뷰 회귀: 모델", () => {
  it("장치를 지우거나 붙여 넣어도 영역이 사라지지 않는다", () => {
    resetStore();
    const a = addDevice("pc", 0, 0);
    const b = addDevice("pc", 200, 0);
    selection.value = { type: "devices", ids: [a.id, b.id] };
    zoneAroundSelected("집");
    removeDevices([a.id]);
    expect(topology.value.zones).toHaveLength(1);
    selection.value = { type: "device", id: b.id };
    copySelected();
    paste();
    expect(topology.value.zones).toHaveLength(1);
  });

  it("한 번 복사해 여러 번 붙여 넣어도 이름·MAC 이 겹치지 않는다 (중간에 장치를 추가해도)", () => {
    resetStore();
    const a = addDevice("pc", 0, 0);
    selection.value = { type: "device", id: a.id };
    copySelected();
    addDevice("pc", 500, 500);
    paste();
    paste();
    const pcs = topology.value.devices;
    expect(new Set(pcs.map((d) => d.name)).size).toBe(pcs.length);
    expect(new Set(pcs.map((d) => d.mac)).size).toBe(pcs.length);
  });

  it("드래그 도중 되돌리기는 무시되고, 아무것도 안 바뀐 드래그·입력은 되돌리기 단계를 남기지 않는다", () => {
    resetStore();
    const a = addDevice("pc", 0, 0);
    const starts = new Map([[a.id, { x: 0, y: 0 }]]);
    beginCoalesce();
    moveDevices(starts, 80, 0);
    undo(); // 무시
    moveDevices(starts, 160, 0);
    endCoalesce();
    expect(topology.value.devices[0]!.x).toBe(160);
    undo();
    expect(topology.value.devices[0]!.x).toBe(0); // 드래그 전으로 (장치 추가 전이 아님)
    expect(topology.value.devices).toHaveLength(1);
    redo();
    expect(canRedo.value).toBe(false);
    // 빈 드래그
    const before = topology.value;
    beginCoalesce();
    endCoalesce();
    undo();
    expect(topology.value).not.toBe(before); // 빈 단계가 없으니 한 단계 전(이동 전)으로 간다
    expect(topology.value.devices[0]!.x).toBe(0);
  });

  it("깨진 저장본·JSON 을 받아도 예외 없이 정리한다", () => {
    const t = normalizeTopology({
      devices: [
        { id: "m", kind: "modem" as never, name: "m", mac: "", x: 0, y: 0 },
        { id: "a", kind: "pc", name: "a", mac: "", x: 0, y: 0 },
        { id: "b", kind: "pc", name: "b", mac: "02:00:00:00:00:01", x: 0, y: 0 },
        { id: "g", kind: "gateway", name: "g", mac: "02:00:00:00:00:02", x: 0, y: 0, l3: {} as never },
        { id: "r", kind: "router", name: "r", mac: "02:00:00:00:00:03", x: 0, y: 0, router: { lanIp: "192.168.0.1", lanPrefix: 24 } as never },
        { id: "f", kind: "firewall", name: "f", mac: "02:00:00:00:00:04", x: 0, y: 0, firewall: { enabled: true } as never },
        { id: "p", kind: "phone", name: "p", mac: "02:00:00:00:00:05", x: 0, y: 0 },
      ],
      cables: [
        { id: "c1", a: { device: "a", port: -1 }, b: { device: "g", port: 1 } },
        { id: "c2", a: { device: "p", port: 0 }, b: { device: "g", port: 2 } }, // 무선 포트
        { id: "c3", a: { device: "b", port: 0 }, b: { device: "r", port: 1 } },
      ],
    });
    expect(t.devices.map((d) => d.id)).toEqual(["a", "b", "g", "r", "f", "p"]);
    expect(new Set(t.devices.map((d) => d.mac)).size).toBe(t.devices.length);
    expect(t.cables.map((c) => c.id)).toEqual(["c3"]);
    expect(() => lintTopology(t)).not.toThrow();
    const s = new NetworkSync();
    expect(() => s.sync(t)).not.toThrow();
    resetStore();
    expect(importJson(JSON.stringify({ devices: [{ id: "x", kind: "gateway", name: "x", x: 0, y: 0, l3: { interfaces: null } }], cables: [] })).error).toBeUndefined();
  });

  it("투명 방화벽 두 대를 직렬로 끼워도 구성 검사가 세그먼트를 이어서 본다", () => {
    const devices: Device[] = [];
    const add = (kind: Parameters<typeof createDevice>[0]) => {
      const d = createDevice(kind, 0, devices.length * 150, devices);
      devices.push(d);
      return d;
    };
    const gw = add("gateway");
    const f1 = add("firewall");
    const f2 = add("firewall");
    const sw = add("switch");
    const pc = add("pc");
    gw.l3!.interfaces[1] = { ipMode: "static", ip: "192.168.1.1", prefix: 24, gateway: "" };
    pc.host = { ...pc.host!, ipMode: "static", ip: "192.168.1.10", gateway: "192.168.1.1" };
    const t: Topology = {
      devices,
      cables: [
        { id: newId("cable"), a: { device: gw.id, port: 1 }, b: { device: f1.id, port: 0 } },
        { id: newId("cable"), a: { device: f1.id, port: 1 }, b: { device: f2.id, port: 0 } },
        { id: newId("cable"), a: { device: f2.id, port: 1 }, b: { device: sw.id, port: 0 } },
        { id: newId("cable"), a: { device: sw.id, port: 1 }, b: { device: pc.id, port: 0 } },
      ],
    };
    expect(lintTopology(t).filter((i) => i.deviceId === pc.id)).toEqual([]);
    // 끝이 한쪽만 연결된 방화벽이 루프 없이 처리된다
    const loop: Topology = { devices, cables: [...t.cables, { id: "x", a: { device: f1.id, port: 0 }, b: { device: f2.id, port: 1 } }] };
    expect(() => lintTopology(normalizeTopology(loop))).not.toThrow();
  });
});
