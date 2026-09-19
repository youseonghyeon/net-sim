import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { L3Node } from "../src/core/nodes/l3";
import { Switch, type PortVlan } from "../src/core/nodes/switch";
import { Network } from "../src/core/network";

function vlans(entries: [number, PortVlan][]): Map<number, PortVlan> {
  return new Map(entries);
}

/** 스위치 하나: 포트0 트렁크(→ 게이트웨이), 포트1·2 VLAN 10, 포트3·4 VLAN 20 */
function oneSwitch() {
  const net = new Network();
  const sw = net.addNode(new Switch("sw", 6));
  sw.setVlans(vlans([[0, "trunk"], [1, 10], [2, 10], [3, 20], [4, 20]]), net.contextFor("sw"));
  net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "192.168.10.10", prefix: 24, gateway: "192.168.10.1" }));
  net.addNode(new Host({ id: "b", mac: "02:00:00:00:00:0b", ipMode: "static", ip: "192.168.10.11", prefix: 24, gateway: "192.168.10.1" }));
  net.addNode(new Host({ id: "c", mac: "02:00:00:00:00:0c", ipMode: "static", ip: "192.168.20.10", prefix: 24, gateway: "192.168.20.1", services: [80] }));
  net.addNode(new Host({ id: "d", mac: "02:00:00:00:00:0d", ipMode: "static", ip: "192.168.10.12", prefix: 24 })); // VLAN 20 포트에 꽂힌 10번대 주소
  net.connect("a", 0, "sw", 1);
  net.connect("b", 0, "sw", 2);
  net.connect("c", 0, "sw", 3);
  net.connect("d", 0, "sw", 4);
  net.runToIdle();
  return { net, sw };
}

describe("VLAN 스위치", () => {
  it("같은 VLAN 끼리는 통신되고, 다른 VLAN 의 같은 서브넷 주소는 ARP 조차 닿지 않는다", () => {
    const { net } = oneSwitch();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "192.168.10.11" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)?.status).toBe("ok");
    // d 는 같은 서브넷 주소지만 VLAN 20 포트 → 브로드캐스트 도메인이 달라 ARP 응답 없음
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "192.168.10.12" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)).toMatchObject({ status: "failed", reason: "ARP 응답 없음" });
    expect(net.trace.some((e) => e.nodeId === "sw" && e.kind === "switch.flood" && e.summary.includes("다른 VLAN 포트"))).toBe(true);
    // d 는 같은 VLAN 20 의 c 프레임은 받지만 a(VLAN 10) 의 프레임은 한 번도 받지 않는다
    expect(net.transmissions.some((t) => t.to.node === "d" && t.frame.src === "02:00:00:00:00:0a")).toBe(false);
  });

  it("MAC 테이블은 VLAN 별로 따로 관리된다", () => {
    const { net, sw } = oneSwitch();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "192.168.10.11" });
    net.runToIdle();
    expect(sw.macTable.get("10:02:00:00:00:00:0a")?.port).toBe(1);
    expect(sw.macTable.get("20:02:00:00:00:00:0a")).toBeUndefined();
    expect(sw.vlanAware).toBe(true);
  });

  it("트렁크로 이어진 스위치 두 대 사이에서 VLAN 이 유지된다 (태그 붙이고 떼기)", () => {
    const net = new Network();
    const s1 = net.addNode(new Switch("s1", 4));
    const s2 = net.addNode(new Switch("s2", 4));
    s1.setVlans(vlans([[0, "trunk"], [1, 10], [2, 20]]), net.contextFor("s1"));
    s2.setVlans(vlans([[0, "trunk"], [1, 10], [2, 20]]), net.contextFor("s2"));
    net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "10.0.0.1", prefix: 24 }));
    net.addNode(new Host({ id: "b", mac: "02:00:00:00:00:0b", ipMode: "static", ip: "10.0.0.2", prefix: 24 }));
    net.addNode(new Host({ id: "c", mac: "02:00:00:00:00:0c", ipMode: "static", ip: "10.0.0.3", prefix: 24 }));
    net.connect("s1", 0, "s2", 0, 10, "trunk");
    net.connect("a", 0, "s1", 1); // VLAN 10
    net.connect("b", 0, "s2", 1); // VLAN 10
    net.connect("c", 0, "s2", 2); // VLAN 20
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "10.0.0.2" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)?.status).toBe("ok");
    const tagged = net.transmissions.filter((t) => t.linkId === "trunk" && t.frame.vlan === 10);
    expect(tagged.length).toBeGreaterThan(0);
    expect(net.transmissions.every((t) => t.linkId === "trunk" || t.frame.vlan === undefined)).toBe(true); // 액세스 링크엔 태그 없음
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "10.0.0.3" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)?.status).toBe("failed");
  });

  it("트렁크에 태그 없는 프레임이 오면(상대가 액세스 포트) 폐기하고 안내한다", () => {
    const net = new Network();
    const s1 = net.addNode(new Switch("s1", 4));
    net.addNode(new Switch("s2", 4)); // 기본: 모두 액세스 VLAN 1
    s1.setVlans(vlans([[0, "trunk"], [1, 1]]), net.contextFor("s1"));
    net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "10.0.0.1", prefix: 24 }));
    net.addNode(new Host({ id: "b", mac: "02:00:00:00:00:0b", ipMode: "static", ip: "10.0.0.2", prefix: 24 }));
    net.connect("s1", 0, "s2", 0);
    net.connect("a", 0, "s1", 1);
    net.connect("b", 0, "s2", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "b", dst: "10.0.0.1" });
    net.runToIdle();
    expect(net.getHost("b").pings.at(-1)?.status).toBe("failed");
    expect(net.trace.some((e) => e.nodeId === "s1" && e.kind === "vlan.drop" && e.summary.includes("태그 없는"))).toBe(true);
    // 반대 방향: s1 이 태그를 붙여 보낸 프레임을 s2 액세스 포트가 폐기
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "10.0.0.2" });
    net.runToIdle();
    expect(net.trace.some((e) => e.nodeId === "s2" && e.kind === "vlan.drop" && e.summary.includes("액세스 포트"))).toBe(true);
    // 호스트에 태그 프레임이 직접 가면 호스트도 폐기
    net.addNode(new Host({ id: "h", mac: "02:00:00:00:00:0e", ipMode: "static", ip: "10.0.0.9", prefix: 24 }));
    net.connect("h", 0, "s1", 2);
    s1.setVlans(vlans([[0, "trunk"], [1, 1], [2, "trunk"]]), net.contextFor("s1"));
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "10.0.0.9" });
    net.runToIdle();
    expect(net.trace.some((e) => e.nodeId === "h" && e.kind === "vlan.drop")).toBe(true);
  });
});

describe("게이트웨이 서브 인터페이스 (router-on-a-stick)", () => {
  function stick() {
    const { net } = oneSwitch();
    net.addNode(
      new L3Node({
        id: "gw",
        kind: "gateway",
        interfaces: [
          { name: "if0", mac: "02:00:00:10:00:02", mode: "static", ip: "10.0.0.2", prefix: 24 },
          { name: "if1", mac: "02:00:00:11:00:02", mode: "static" },
          { name: "if2", mac: "02:00:00:12:00:02", mode: "static" },
        ],
        subinterfaces: [
          { port: 1, vlan: 10, ip: "192.168.10.1", prefix: 24 },
          { port: 1, vlan: 20, ip: "192.168.20.1", prefix: 24 },
        ],
      }),
    );
    net.connect("gw", 1, "sw", 0); // 트렁크
    net.runToIdle();
    return net;
  }

  it("VLAN 10 호스트가 VLAN 20 호스트와 게이트웨이 서브 인터페이스를 거쳐 통신한다", () => {
    const net = stick();
    const gw = net.nodes.get("gw") as L3Node;
    expect(gw.names).toContain("if1.10");
    expect(gw.names).toContain("if1.20");
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "192.168.20.10" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)?.status).toBe("ok");
    expect(net.trace.some((e) => e.nodeId === "gw" && e.kind === "ip.forward" && e.summary.includes("if1.20"))).toBe(true);
    expect(net.trace.some((e) => e.nodeId === "gw" && e.kind === "vlan.tag" && e.summary.includes("VLAN 20"))).toBe(true);
    // TCP 도
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "a", dst: "192.168.20.10", port: 80 });
    net.runToIdle();
    expect([...net.getHost("a").tcp.conns.values()].at(-1)?.state).toBe("CLOSED");
    expect(net.pendingEvents).toBe(0);
  });

  it("서브 인터페이스가 없는 VLAN 의 프레임은 게이트웨이가 폐기하고 안내한다", () => {
    const net = stick();
    const gw = net.nodes.get("gw") as L3Node;
    gw.setSubinterfaces([{ port: 1, vlan: 10, ip: "192.168.10.1", prefix: 24 }], net.contextFor("gw"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c", dst: "192.168.10.10" });
    net.runToIdle();
    expect(net.getHost("c").pings.at(-1)?.status).toBe("failed");
    expect(net.trace.some((e) => e.nodeId === "gw" && e.kind === "vlan.drop" && e.summary.includes("VLAN 20"))).toBe(true);
  });

  it("DHCP 릴레이가 서브 인터페이스에도 동작한다", () => {
    const net = stick();
    const gw = net.nodes.get("gw") as L3Node;
    // VLAN 10 에 DHCP 서버, VLAN 20 클라이언트는 if1.20 의 릴레이를 거쳐 받는다
    net.getHost("b").setDhcpServer({ enabled: true, start: "192.168.10.100", end: "192.168.10.101", router: "192.168.10.1", extraPools: [{ start: "192.168.20.100", end: "192.168.20.101", prefix: 24, router: "192.168.20.1" }] }, net.contextFor("b"));
    gw.setSubinterfaces([{ port: 1, vlan: 10, ip: "192.168.10.1", prefix: 24 }, { port: 1, vlan: 20, ip: "192.168.20.1", prefix: 24, relay: "192.168.10.11" }], net.contextFor("gw"));
    net.addNode(new Host({ id: "e", mac: "02:00:00:00:00:0e", ipMode: "dhcp" }));
    net.connect("e", 0, "sw", 5);
    (net.nodes.get("sw") as Switch).setVlans(vlans([[0, "trunk"], [1, 10], [2, 10], [3, 20], [4, 20], [5, 20]]), net.contextFor("sw"));
    net.runToIdle();
    const e = net.getHost("e");
    expect(e.ip).toBe("192.168.20.100");
    expect(e.iface.gateway).toBe("192.168.20.1");
  });
});
