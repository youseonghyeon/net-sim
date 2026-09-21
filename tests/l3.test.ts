import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { Host } from "../src/core/nodes/host";
import { Internet } from "../src/core/nodes/internet";
import { L3Node } from "../src/core/nodes/l3";
import { Switch } from "../src/core/nodes/switch";

/**
 * 기능 단위 구성:
 *   inet ── nat(outside dhcp / inside 10.0.0.1, 스태틱 라우팅 192.168.0.0/16 via 10.0.0.2) ── gw(if0 10.0.0.2 gw 10.0.0.1 / if1 192.168.1.1 / if2 192.168.2.1)
 *   gw.if1 ── sw1 ── a(192.168.1.10), dhcpsrv(192.168.1.2, DHCP 서버: .100~.101, 게이트웨이 안내 192.168.1.1), c(dhcp)
 *   gw.if2 ── sw2 ── b(192.168.2.10)
 */
function build() {
  const net = new Network();
  net.addNode(new Internet({ id: "inet", mac: "02:00:00:ff:00:01" }));
  net.addNode(
    new L3Node({
      id: "nat",
      kind: "nat",
      outside: 0,
      interfaces: [
        { name: "outside", mac: "02:00:00:10:00:01", mode: "dhcp" },
        { name: "inside", mac: "02:00:00:11:00:01", mode: "static", ip: "10.0.0.1", prefix: 24 },
      ],
      routes: [{ dest: "192.168.0.0", prefix: 16, via: "10.0.0.2" }],
    }),
  );
  net.addNode(
    new L3Node({
      id: "gw",
      kind: "gateway",
      interfaces: [
        { name: "if0", mac: "02:00:00:10:00:02", mode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" },
        { name: "if1", mac: "02:00:00:11:00:02", mode: "static", ip: "192.168.1.1", prefix: 24 },
        { name: "if2", mac: "02:00:00:12:00:02", mode: "static", ip: "192.168.2.1", prefix: 24 },
      ],
    }),
  );
  net.addNode(new Switch("sw1", ["uplink", "e1", "e2", "e3"]));
  net.addNode(new Switch("sw2", ["uplink", "e1", "e2"]));
  net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "192.168.1.10", prefix: 24, gateway: "192.168.1.1" }));
  net.addNode(new Host({ id: "b", mac: "02:00:00:00:00:0b", ipMode: "static", ip: "192.168.2.10", prefix: 24, gateway: "192.168.2.1" }));
  net.addNode(
    new Host({
      id: "dhcpsrv",
      mac: "02:00:00:00:00:0d",
      ipMode: "static",
      ip: "192.168.1.2",
      prefix: 24,
      gateway: "192.168.1.1",
      dhcpServer: { enabled: true, start: "192.168.1.100", end: "192.168.1.101", router: "192.168.1.1" },
    }),
  );
  net.addNode(new Host({ id: "c", mac: "02:00:00:00:00:0c", ipMode: "dhcp" }));
  net.connect("inet", 0, "nat", 0, 10, "inet-nat");
  net.connect("nat", 1, "gw", 0, 10, "nat-gw");
  net.connect("gw", 1, "sw1", 0, 10, "gw-sw1");
  net.connect("gw", 2, "sw2", 0, 10, "gw-sw2");
  net.connect("a", 0, "sw1", 1);
  net.connect("dhcpsrv", 0, "sw1", 2);
  net.connect("b", 0, "sw2", 1);
  net.runToIdle();
  return net;
}

describe("게이트웨이 / NAT 박스 / DHCP 서버 호스트", () => {
  it("NAT 박스 outside 가 ISP 에서 공인 주소를 받는다", () => {
    const net = build();
    const nat = net.nodes.get("nat") as L3Node;
    expect(nat.ifaces[0]!.ip).toBe("203.0.113.100");
    expect(nat.ifaces[0]!.gateway).toBe("203.0.113.1");
  });

  it("게이트웨이가 두 서브넷 사이를 라우팅한다 (a → b), TTL 은 1 줄어든다", () => {
    const net = build();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "192.168.2.10" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)).toMatchObject({ status: "ok" });
    const fwd = net.trace.filter((e) => e.nodeId === "gw" && e.kind === "ip.forward");
    expect(fwd.length).toBeGreaterThanOrEqual(2); // 요청 if1→if2, 응답 if2→if1
    expect(fwd[0]!.summary).toContain("if2");
    const arrived = net.transmissions.find((t) => t.to.node === "b" && t.frame.payload.kind === "ipv4" && t.frame.payload.payload.kind === "icmp");
    expect(arrived?.frame.payload.kind === "ipv4" && arrived.frame.payload.ttl).toBe(63);
  });

  it("LAN 호스트가 인터넷으로 ping 하면 게이트웨이 → NAT 박스 → 인터넷을 거쳐 돌아온다", () => {
    const net = build();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)).toMatchObject({ status: "ok" });
    const nat = net.nodes.get("nat") as L3Node;
    expect(nat.nat!.size).toBe(1);
    expect(nat.nat!.values()[0]).toMatchObject({ lanIp: "192.168.1.10", proto: "icmp" });
    const kinds = net.trace.map((e) => `${e.nodeId}:${e.kind}`);
    const order = ["gw:ip.forward", "nat:nat.translate", "nat:ip.forward", "inet:inet.reply", "nat:nat.restore", "nat:ip.forward", "gw:ip.forward", "a:icmp.reply.received"];
    let idx = -1;
    for (const k of order) {
      const next = kinds.indexOf(k, idx + 1);
      expect(next, `expected ${k} after ${idx}`).toBeGreaterThan(idx);
      idx = next;
    }
  });

  it("DHCP 서버 호스트가 주소와 게이트웨이를 안내하고, 그 호스트가 다른 서브넷과 통신한다", () => {
    const net = build();
    net.connect("c", 0, "sw1", 3);
    net.runToIdle();
    const c = net.getHost("c");
    expect(c.ip).toBe("192.168.1.100");
    expect(c.iface.gateway).toBe("192.168.1.1");
    expect(net.getHost("dhcpsrv").dhcpServer.leases.size).toBe(1);
    // 게이트웨이도 DHCP 서버도 아닌 장치들은 Discover 를 무시한다
    expect(net.trace.some((e) => e.nodeId === "gw" && e.kind === "dhcp.ignore")).toBe(true);
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c", dst: "192.168.2.10" });
    net.runToIdle();
    expect(c.pings.at(-1)).toMatchObject({ status: "ok" });
  });

  it("DHCP 서버가 게이트웨이를 안내하지 않으면 다른 서브넷으로 못 나간다", () => {
    const net = build();
    net.getHost("dhcpsrv").setDhcpServer({ enabled: true, start: "192.168.1.100", end: "192.168.1.101" }, net.contextFor("dhcpsrv"));
    net.connect("c", 0, "sw1", 3);
    net.runToIdle();
    const c = net.getHost("c");
    expect(c.ip).toBe("192.168.1.100");
    expect(c.iface.gateway).toBeUndefined();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c", dst: "192.168.2.10" });
    net.runToIdle();
    expect(net.trace.some((e) => e.nodeId === "c" && e.kind === "ip.no-route")).toBe(true);
    expect(c.pings.at(-1)?.status).toBe("failed");
  });

  it("게이트웨이에 디폴트 라우트가 없으면 외부 주소는 No route 로 드롭된다", () => {
    const net = build();
    const gw = net.nodes.get("gw") as L3Node;
    gw.configure(
      [
        { mode: "static", ip: "10.0.0.2", prefix: 24 },
        { mode: "static", ip: "192.168.1.1", prefix: 24 },
        { mode: "static", ip: "192.168.2.1", prefix: 24 },
      ],
      net.contextFor("gw"),
    );
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.trace.some((e) => e.nodeId === "gw" && e.kind === "ip.no-route")).toBe(true);
    expect(net.getHost("a").pings.at(-1)?.status).toBe("failed");
  });

  it("NAT 박스에 안쪽 스태틱 라우팅이 없으면 응답이 되돌아가지 못한다", () => {
    const net = build();
    const nat = net.nodes.get("nat") as L3Node;
    nat.setRoutes([], net.contextFor("nat"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.trace.some((e) => e.nodeId === "nat" && e.kind === "ip.no-route" && e.summary.includes("스태틱 라우팅"))).toBe(true);
    expect(net.getHost("a").pings.at(-1)?.status).toBe("failed");
  });

  it("DHCP 릴레이: 다른 서브넷의 호스트가 게이트웨이 릴레이를 거쳐 서버 한 대에서 주소를 받는다", () => {
    const net = build();
    const gw = net.nodes.get("gw") as L3Node;
    gw.configure(
      [
        { mode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" },
        { mode: "static", ip: "192.168.1.1", prefix: 24 },
        { mode: "static", ip: "192.168.2.1", prefix: 24, relay: "192.168.1.2" },
      ],
      net.contextFor("gw"),
    );
    net.getHost("dhcpsrv").setDhcpServer(
      {
        enabled: true,
        start: "192.168.1.100",
        end: "192.168.1.101",
        router: "192.168.1.1",
        extraPools: [{ start: "192.168.2.100", end: "192.168.2.101", prefix: 24, router: "192.168.2.1" }],
      },
      net.contextFor("dhcpsrv"),
    );
    net.addNode(new Host({ id: "d", mac: "02:00:00:00:00:0e", ipMode: "dhcp" }));
    net.connect("d", 0, "sw2", 2);
    net.runToIdle();

    const d = net.getHost("d");
    expect(d.ip).toBe("192.168.2.100");
    expect(d.iface.prefix).toBe(24);
    expect(d.iface.gateway).toBe("192.168.2.1");
    expect(net.getHost("dhcpsrv").dhcpServer.leases.get("192.168.2.100")?.mac).toBe("02:00:00:00:00:0e");

    const kinds = net.trace.map((e) => `${e.nodeId}:${e.kind}`);
    const order = ["d:dhcp.discover.sent", "gw:dhcp.relay.forward", "dhcpsrv:dhcp.discover.received", "dhcpsrv:dhcp.offer.sent", "gw:dhcp.relay.return", "d:dhcp.offer.received", "gw:dhcp.relay.forward", "dhcpsrv:dhcp.ack.sent", "gw:dhcp.relay.return", "d:dhcp.bound"];
    let idx = -1;
    for (const k of order) {
      const next = kinds.indexOf(k, idx + 1);
      expect(next, `expected ${k} after ${idx}`).toBeGreaterThan(idx);
      idx = next;
    }
    // 받은 주소로 다른 서브넷과 통신
    net.scheduleAction(net.now, { kind: "ping", nodeId: "d", dst: "192.168.1.10" });
    net.runToIdle();
    expect(d.pings.at(-1)).toMatchObject({ status: "ok" });
    expect(net.pendingEvents).toBe(0);
  });

  it("릴레이는 있는데 서버에 그 서브넷 풀이 없으면 서버가 설정 오류로 응답하지 않는다", () => {
    const net = build();
    const gw = net.nodes.get("gw") as L3Node;
    gw.configure(
      [
        { mode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" },
        { mode: "static", ip: "192.168.1.1", prefix: 24 },
        { mode: "static", ip: "192.168.2.1", prefix: 24, relay: "192.168.1.2" },
      ],
      net.contextFor("gw"),
    );
    net.addNode(new Host({ id: "d", mac: "02:00:00:00:00:0e", ipMode: "dhcp" }));
    net.connect("d", 0, "sw2", 2);
    net.runToIdle();
    expect(net.getHost("d").ip).toBeUndefined();
    expect(net.trace.some((e) => e.nodeId === "dhcpsrv" && e.kind === "dhcp.misconfigured" && e.summary.includes("풀이 없음"))).toBe(true);
  });

  it("NAT 박스를 거쳐 TCP 로 인터넷 웹 서버와 통신한다", () => {
    const net = build();
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "b", dst: "93.184.216.34", port: 80 });
    net.runToIdle();
    const conn = [...net.getHost("b").tcp.conns.values()][0]!;
    expect(conn.state).toBe("CLOSED");
    expect(conn.bytesReceived).toBe(3000);
    expect(net.pendingEvents).toBe(0);
  });
});
