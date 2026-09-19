import { describe, expect, it } from "vitest";
import { AccessPoint } from "../src/core/nodes/ap";
import { createDevice, WIFI_RANGE, wirelessLinks, wirelessStatus, type Device } from "../src/model/topology";
import { Host } from "../src/core/nodes/host";
import { Router } from "../src/core/nodes/router";
import { buildHomeLan } from "../src/core/scenarios/homeLan";

/** homeLan + 스위치 아래 AP + 무선 단말 2대(DHCP) */
function withAp() {
  const net = buildHomeLan();
  net.addNode(new AccessPoint("ap", "home"));
  net.addNode(new Host({ id: "ph1", mac: "02:00:00:00:00:a1", ipMode: "dhcp" }));
  net.addNode(new Host({ id: "ph2", mac: "02:00:00:00:00:a2", ipMode: "dhcp" }));
  net.connect("ap", 0, "sw", 1, 10, "ap-sw");
  net.connect("ph1", 0, "ap", 1, 20, "wl-ph1"); // 무선 연결 = 슬롯 1
  net.connect("ph2", 0, "ap", 2, 20, "wl-ph2");
  net.runToIdle();
  return net;
}

describe("무선 AP", () => {
  it("무선 단말이 AP 를 거쳐 라우터에서 DHCP 로 주소를 받는다", () => {
    const net = withAp();
    expect(net.getHost("ph1").ip).toBe("192.168.0.100");
    expect(net.getHost("ph2").ip).toBe("192.168.0.101");
    const ap = net.nodes.get("ap") as AccessPoint;
    expect(ap.stations.size).toBe(2);
    expect(net.trace.some((e) => e.nodeId === "ap" && e.kind === "wifi.air" && e.summary.includes("브로드캐스트"))).toBe(true);
  });

  it("유선 → 아는 단말 유니캐스트는 그 단말에게만 송출된다", () => {
    const net = withAp();
    net.connect("srv", 0, "sw", 2);
    net.runToIdle();
    const before = net.transmissions.length;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "srv", dst: "192.168.0.100" });
    net.runToIdle();
    const later = net.transmissions.slice(before);
    const toPh2Icmp = later.filter((t) => t.to.node === "ph2" && t.frame.payload.kind === "ipv4" && t.frame.payload.payload.kind === "icmp");
    expect(toPh2Icmp).toHaveLength(0);
    expect(net.getHost("srv").pings.at(-1)?.status).toBe("ok");
    expect(net.trace.some((e) => e.nodeId === "ap" && e.summary.includes("암호화되어 읽지 못한다"))).toBe(true);
  });

  it("단말끼리는 AP 가 중계한다 (직접 통신하지 않음)", () => {
    const net = withAp();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "ph1", dst: "192.168.0.101" });
    net.runToIdle();
    expect(net.getHost("ph1").pings.at(-1)?.status).toBe("ok");
    expect(net.trace.some((e) => e.nodeId === "ap" && e.kind === "switch.forward" && e.summary.includes("단말 ↔ 단말 중계"))).toBe(true);
    // 스위치(유선)로는 ICMP 가 나가지 않는다
    expect(net.trace.some((e) => e.nodeId === "sw" && e.kind === "frame.receive" && e.summary.includes("ICMP"))).toBe(false);
  });

  it("무선 연결이 끊기면(범위 밖) 단말이 주소를 잃고 AP 단말 목록에서 빠진다", () => {
    const net = withAp();
    net.disconnect("wl-ph1");
    net.runToIdle();
    expect(net.getHost("ph1").ip).toBeUndefined();
    expect((net.nodes.get("ap") as AccessPoint).stations.size).toBe(1);
  });

  it("무선 단말에서 인터넷으로 나간다 (AP → 스위치 → 라우터 NAT)", () => {
    const net = buildHomeLan(true, true);
    net.addNode(new AccessPoint("ap", "home"));
    net.addNode(new Host({ id: "ph1", mac: "02:00:00:00:00:a1", ipMode: "dhcp" }));
    net.connect("ap", 0, "sw", 1);
    net.connect("ph1", 0, "ap", 1, 20);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "ph1", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.getHost("ph1").pings.at(-1)?.status).toBe("ok");
  });
});

describe("무선 공유기 (라우터 라디오 슬롯)", () => {
  it("라우터 무선 슬롯에 붙은 단말이 주소를 받고 유선 호스트와 통신한다", () => {
    const net = buildHomeLan(true, true);
    const rt = net.nodes.get("rt") as Router;
    rt.configure({ lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.101" }, wan: { mode: "dhcp" }, wifi: { enabled: true, ssid: "home" } }, net.contextFor("rt"));
    net.addNode(new Host({ id: "ph1", mac: "02:00:00:00:00:a1", ipMode: "dhcp" }));
    net.connect("ph1", 0, "rt", Router.RADIO_PORTS[0]!, 20, "wl-ph1");
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    expect(net.getHost("ph1").ip).toBeDefined();
    expect(net.getHost("pc1").ip).toBeDefined();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "ph1", dst: net.getHost("pc1").ip! });
    net.runToIdle();
    expect(net.getHost("ph1").pings.at(-1)?.status).toBe("ok");
    expect(net.trace.some((e) => e.nodeId === "rt" && e.summary.includes("전파로 송출"))).toBe(true);
    net.scheduleAction(net.now, { kind: "ping", nodeId: "ph1", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.getHost("ph1").pings.at(-1)?.status).toBe("ok");
  });
});

describe("무선 연결 모델 (SSID + 범위)", () => {
  function mk(kind: Parameters<typeof createDevice>[0], x: number, y: number, list: Device[]) {
    const d = createDevice(kind, x, y, list);
    list.push(d);
    return d;
  }

  it("SSID 가 같고 범위 안이면 가장 가까운 기지에 붙고, 슬롯은 안정적이다", () => {
    const devices: Device[] = [];
    const ap1 = mk("ap", 0, 0, devices);
    const ap2 = mk("ap", 600, 0, devices);
    const p1 = mk("phone", 100, 100, devices);
    const p2 = mk("phone", 550, 100, devices);
    const far = mk("phone", 100, 900, devices);
    const other = mk("phone", 120, 120, devices);
    other.wifi = { ssid: "office" };
    const t = { devices, cables: [] };
    const links = wirelessLinks(t);
    expect(links.find((l) => l.client === p1.id)?.base).toBe(ap1.id);
    expect(links.find((l) => l.client === p2.id)?.base).toBe(ap2.id);
    expect(links.find((l) => l.client === far.id)).toBeUndefined();
    expect(links.find((l) => l.client === other.id)).toBeUndefined();
    expect(wirelessStatus(t, far).reason).toContain("범위");
    expect(wirelessStatus(t, other).reason).toContain("없습니다");

    // p1 이 떨어졌다 돌아와도 같은 슬롯
    const slot1 = links.find((l) => l.client === p1.id)!.slot;
    p1.y = 2000;
    expect(wirelessLinks(t).find((l) => l.client === p1.id)).toBeUndefined();
    p1.y = 100;
    expect(wirelessLinks(t).find((l) => l.client === p1.id)!.slot).toBe(slot1);
  });

  it("로밍(다른 기지로 옮겨 붙음)하면 링크 id 가 바뀐다 — 시뮬레이션 diff 가 재연결을 보게 하기 위해", () => {
    const devices: Device[] = [];
    const ap1 = mk("ap", 0, 0, devices);
    const ap2 = mk("ap", 400, 0, devices);
    const p = mk("phone", 100, 50, devices);
    const t = { devices, cables: [] };
    const before = wirelessLinks(t).find((l) => l.client === p.id)!;
    expect(before.base).toBe(ap1.id);
    expect(before.id).toContain(ap1.id);
    p.x = 300;
    const after = wirelessLinks(t).find((l) => l.client === p.id)!;
    expect(after.base).toBe(ap2.id);
    expect(after.id).not.toBe(before.id);
  });

  it("범위 안 기지의 슬롯이 다 차면 그 이유를 알려준다", () => {
    const devices: Device[] = [];
    mk("ap", 0, 0, devices);
    const phones = Array.from({ length: 9 }, (_, i) => mk("phone", 50 + i * 5, 80, devices));
    const t = { devices, cables: [] };
    const links = wirelessLinks(t);
    expect(links).toHaveLength(8); // AP_RADIO_SLOTS
    const left = phones.find((ph) => !links.some((l) => l.client === ph.id))!;
    expect(wirelessStatus(t, left).reason).toContain("빈 무선 슬롯이 없습니다");
  });

  it("공유기 무선이 꺼져 있으면 붙지 않고, 켜면 붙는다", () => {
    const devices: Device[] = [];
    const rt = mk("router", 0, 0, devices);
    const p = mk("phone", 60, 150, devices);
    const t = { devices, cables: [] };
    expect(wirelessLinks(t)).toHaveLength(0);
    expect(wirelessStatus(t, p).reason).toContain("꺼져");
    rt.router!.wifi = { enabled: true, ssid: "home" };
    const l = wirelessLinks(t)[0]!;
    expect(l.base).toBe(rt.id);
    expect(l.slot).toBeGreaterThanOrEqual(5); // Router.RADIO_PORTS
    expect(l.distance).toBeLessThan(WIFI_RANGE);
  });
});
