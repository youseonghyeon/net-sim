import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { Host } from "../src/core/nodes/host";
import { Internet } from "../src/core/nodes/internet";
import { L3Node } from "../src/core/nodes/l3";
import { Router } from "../src/core/nodes/router";
import { Switch } from "../src/core/nodes/switch";
import { buildHomeLan } from "../src/core/scenarios/homeLan";

/** 인터넷 저편 클라이언트의 연결 기록 (inet 노드 TCP 스택의 client 역할) */
function remoteClientConns(net: Network) {
  const inet = net.nodes.get("inet") as Internet;
  return [...inet.tcp.conns.values()].filter((c) => c.role === "client");
}

function orderOf(net: Network, order: string[]): void {
  const kinds = net.trace.map((e) => `${e.nodeId}:${e.kind}`);
  let idx = -1;
  for (const k of order) {
    const next = kinds.indexOf(k, idx + 1);
    expect(next, `expected ${k} after index ${idx}`).toBeGreaterThan(idx);
    idx = next;
  }
}

/** 가정용 LAN: 라우터(WAN DHCP) + 스위치 + 웹 서버 srv(192.168.0.50:80) + 인터넷. 안정화까지 돌린다 */
function buildHome(): { net: Network; rt: Router } {
  const net = buildHomeLan(true, true);
  net.connect("srv", 0, "sw", 2);
  net.runToIdle();
  const rt = net.nodes.get("rt") as Router;
  expect(rt.wan.ip).toBe("203.0.113.100");
  return { net, rt };
}

function baseRouterConfig(rt: Router) {
  return { lanIp: rt.lan.ip!, lanPrefix: rt.lan.prefix, dhcp: rt.dhcp, wan: { mode: "dhcp" as const } };
}

describe("포트 포워딩 — 가정용 라우터", () => {
  it("규칙이 없으면 바깥에서 시작한 TCP 연결은 NAT 미스로 버려진다", () => {
    const { net, rt } = buildHome();
    net.scheduleAction(net.now, { kind: "inet-connect", nodeId: "inet", dst: rt.wan.ip!, port: 80 });
    net.runToIdle();

    const client = remoteClientConns(net)[0]!;
    expect(client.localIp).toBe(Internet.REMOTE_CLIENT);
    expect(client.state).toBe("FAILED");
    const miss = net.trace.filter((e) => e.nodeId === "rt" && e.kind === "nat.miss");
    expect(miss.length).toBeGreaterThan(0);
    expect(miss[0]!.summary).toContain("포트 포워딩");
    expect(net.trace.some((e) => e.nodeId === "inet" && e.kind === "action" && e.summary.includes("인터넷에서"))).toBe(true);
    // 서버는 SYN 을 본 적이 없다
    expect(net.getHost("srv").tcp.conns.size).toBe(0);
    expect(net.pendingEvents).toBe(0);
  });

  it("규칙(:80 → 192.168.0.50:80)이 있으면 바깥 클라이언트가 LAN 웹 서버와 통신한다", () => {
    const { net, rt } = buildHome();
    const before = net.trace.length;
    rt.configure({ ...baseRouterConfig(rt), forwards: [{ publicPort: 80, lanIp: "192.168.0.50", lanPort: 80 }] }, net.contextFor("rt"));
    expect(net.trace.slice(before).filter((e) => e.nodeId === "rt" && e.kind === "ip.config").map((e) => e.summary)).toEqual(["포트 포워딩 규칙 변경: 1개"]);
    // 같은 규칙을 다시 넣으면 트레이스가 없다
    const again = net.trace.length;
    rt.configure({ ...baseRouterConfig(rt), forwards: [{ publicPort: 80, lanIp: "192.168.0.50", lanPort: 80 }] }, net.contextFor("rt"));
    expect(net.trace.length).toBe(again);

    net.scheduleAction(net.now, { kind: "inet-connect", nodeId: "inet", dst: rt.wan.ip!, port: 80 });
    net.runToIdle();

    const client = remoteClientConns(net)[0]!;
    expect(client.state).toBe("CLOSED");
    expect(client.bytesReceived).toBe(3000);
    expect(client.remoteIp).toBe("203.0.113.100");
    expect(client.remotePort).toBe(80);

    const server = [...net.getHost("srv").tcp.conns.values()][0]!;
    expect(server.role).toBe("server");
    expect(server.state).toBe("CLOSED");
    expect(server.remoteIp).toBe(Internet.REMOTE_CLIENT);
    expect(server.bytesReceived).toBe(100);

    orderOf(net, ["inet:inet.forward", "inet:tcp.connect", "rt:nat.forward.rule", "rt:ip.forward", "srv:tcp.syn.received", "rt:nat.forward.reply", "rt:ip.forward", "inet:tcp.synack.received", "srv:tcp.closed", "inet:tcp.closed"]);
    // 규칙이 곧 매핑: 동적 NAT 항목은 만들지 않는다
    expect(rt.nat.size).toBe(0);
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "nat.miss")).toBe(false);
    // 인터넷으로 나간 응답의 출발지는 공인 주소:80
    const out = net.transmissions.find((t) => t.from.node === "rt" && t.to.node === "inet" && t.frame.payload.kind === "ipv4" && t.frame.payload.payload.kind === "tcp");
    expect(out?.frame.payload.kind === "ipv4" && out.frame.payload.src).toBe("203.0.113.100");
    expect(out?.frame.payload.kind === "ipv4" && out.frame.payload.payload.kind === "tcp" && out.frame.payload.payload.srcPort).toBe(80);
    expect(net.pendingEvents).toBe(0);

    const table = rt.snapshot().tables.find((t) => t.title === "포트 포워딩");
    expect(table?.columns).toEqual(["공인 포트", "내부"]);
    expect(table?.rows).toEqual([["공인 :80", "192.168.0.50:80"]]);
  });

  it("공인 포트가 다른 규칙(:8080 → :80): 8080 은 열리고 80 은 막힌다", () => {
    const { net, rt } = buildHome();
    rt.configure({ ...baseRouterConfig(rt), forwards: [{ publicPort: 8080, lanIp: "192.168.0.50", lanPort: 80 }] }, net.contextFor("rt"));

    net.scheduleAction(net.now, { kind: "inet-connect", nodeId: "inet", dst: rt.wan.ip!, port: 8080 });
    net.runToIdle();
    const ok = remoteClientConns(net).find((c) => c.remotePort === 8080)!;
    expect(ok.state).toBe("CLOSED");
    expect(ok.bytesReceived).toBe(3000);
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "nat.miss")).toBe(false);

    net.scheduleAction(net.now, { kind: "inet-connect", nodeId: "inet", dst: rt.wan.ip!, port: 80 });
    net.runToIdle();
    const blocked = remoteClientConns(net).find((c) => c.remotePort === 80)!;
    expect(blocked.state).toBe("FAILED");
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "nat.miss" && e.summary.includes("TCP 포트 80"))).toBe(true);
    expect(net.pendingEvents).toBe(0);
  });

  it("규칙을 지우면 다시 막힌다", () => {
    const { net, rt } = buildHome();
    rt.configure({ ...baseRouterConfig(rt), forwards: [{ publicPort: 80, lanIp: "192.168.0.50", lanPort: 80 }] }, net.contextFor("rt"));
    rt.configure({ ...baseRouterConfig(rt), forwards: [] }, net.contextFor("rt"));
    expect(net.trace.filter((e) => e.nodeId === "rt" && e.summary.startsWith("포트 포워딩 규칙 변경")).map((e) => e.summary)).toEqual(["포트 포워딩 규칙 변경: 1개", "포트 포워딩 규칙 변경: 0개"]);
    net.scheduleAction(net.now, { kind: "inet-connect", nodeId: "inet", dst: rt.wan.ip!, port: 80 });
    net.runToIdle();
    expect(remoteClientConns(net)[0]!.state).toBe("FAILED");
  });

  it("동적 NAT 는 규칙의 공인 포트를 건너뛰어 할당한다", () => {
    const { net, rt } = buildHome();
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    rt.configure({ ...baseRouterConfig(rt), forwards: [{ publicPort: Router.NAT_ID_START, lanIp: "192.168.0.50", lanPort: 80 }] }, net.contextFor("rt"));
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1", dst: "93.184.216.34", port: 80 });
    net.runToIdle();
    const conn = [...net.getHost("pc1").tcp.conns.values()][0]!;
    expect(conn.state).toBe("CLOSED");
    expect(conn.bytesReceived).toBe(3000);
    expect(rt.nat.values().map((e) => e.publicId)).toEqual([Router.NAT_ID_START + 1]);
  });

  it("사설 주소로 inet-connect 하면 인터넷 노드에서 바로 실패로 기록된다", () => {
    const { net } = buildHome();
    const before = net.trace.length;
    net.scheduleAction(net.now, { kind: "inet-connect", nodeId: "inet", dst: "192.168.0.50", port: 80 });
    net.runToIdle();
    const client = remoteClientConns(net)[0]!;
    expect(client.state).toBe("FAILED");
    expect(client.reason).toContain("사설 주소");
    const after = net.trace.slice(before);
    expect(after.some((e) => e.nodeId === "inet" && e.kind === "ip.drop" && e.summary.includes("포트 포워딩"))).toBe(true);
    // 케이블로는 아무것도 나가지 않는다
    expect(after.some((e) => e.kind === "link.transmit")).toBe(false);
    expect(net.pendingEvents).toBe(0);
  });

  it("inet-connect 는 인터넷 노드에만 쓸 수 있다", () => {
    const { net } = buildHome();
    net.scheduleAction(net.now, { kind: "inet-connect", nodeId: "rt", dst: "203.0.113.1", port: 80 });
    expect(() => net.runToIdle()).toThrow(/not an internet node/);
  });
});

/**
 * 기능 단위 구성 (tests/l3.test.ts 와 같은 모양):
 *   inet ── nat(outside dhcp / inside 10.0.0.1, 스태틱 라우팅 192.168.0.0/16 via 10.0.0.2) ── gw(if0 10.0.0.2 gw 10.0.0.1 / if1 192.168.1.1 / if2 192.168.2.1)
 *   gw.if1 ── sw1 ── a(192.168.1.10)
 *   gw.if2 ── sw2 ── b(192.168.2.10), web(192.168.2.20, 포트 80)
 */
function buildParts(): Network {
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
  net.addNode(new Host({ id: "web", mac: "02:00:00:00:00:1e", ipMode: "static", ip: "192.168.2.20", prefix: 24, gateway: "192.168.2.1", services: [80] }));
  net.connect("inet", 0, "nat", 0, 10, "inet-nat");
  net.connect("nat", 1, "gw", 0, 10, "nat-gw");
  net.connect("gw", 1, "sw1", 0, 10, "gw-sw1");
  net.connect("gw", 2, "sw2", 0, 10, "gw-sw2");
  net.connect("a", 0, "sw1", 1);
  net.connect("b", 0, "sw2", 1);
  net.connect("web", 0, "sw2", 2);
  net.runToIdle();
  return net;
}

describe("포트 포워딩 — NAT 박스", () => {
  it("규칙이 없으면 NAT 박스가 바깥에서 온 SYN 을 버린다", () => {
    const net = buildParts();
    const nat = net.nodes.get("nat") as L3Node;
    net.scheduleAction(net.now, { kind: "inet-connect", nodeId: "inet", dst: nat.ifaces[0]!.ip!, port: 80 });
    net.runToIdle();
    expect(remoteClientConns(net)[0]!.state).toBe("FAILED");
    expect(net.trace.some((e) => e.nodeId === "nat" && e.kind === "nat.miss" && e.summary.includes("포트 포워딩"))).toBe(true);
    expect(net.getHost("web").tcp.conns.size).toBe(0);
    expect(net.pendingEvents).toBe(0);
  });

  it("규칙(:80 → 192.168.2.20:80)이 있으면 두 홉 안쪽의 웹 서버와 통신한다", () => {
    const net = buildParts();
    const nat = net.nodes.get("nat") as L3Node;
    expect(nat.ifaces[0]!.ip).toBe("203.0.113.100");
    nat.setForwards([{ publicPort: 80, lanIp: "192.168.2.20", lanPort: 80 }], net.contextFor("nat"));
    expect(net.trace.filter((e) => e.nodeId === "nat" && e.kind === "ip.config").at(-1)?.summary).toBe("포트 포워딩 규칙 변경: 1개");

    net.scheduleAction(net.now, { kind: "inet-connect", nodeId: "inet", dst: "203.0.113.100", port: 80 });
    net.runToIdle();

    const client = remoteClientConns(net)[0]!;
    expect(client.state).toBe("CLOSED");
    expect(client.bytesReceived).toBe(3000);
    const server = [...net.getHost("web").tcp.conns.values()][0]!;
    expect(server.state).toBe("CLOSED");
    expect(server.remoteIp).toBe(Internet.REMOTE_CLIENT);

    orderOf(net, ["inet:tcp.connect", "nat:nat.forward.rule", "nat:ip.forward", "gw:ip.forward", "web:tcp.syn.received", "gw:ip.forward", "nat:nat.forward.reply", "nat:ip.forward", "inet:tcp.synack.received", "web:tcp.closed", "inet:tcp.closed"]);
    expect(nat.nat!.size).toBe(0);
    expect(net.pendingEvents).toBe(0);

    const table = nat.snapshot().tables.find((t) => t.title === "포트 포워딩");
    expect(table?.rows).toEqual([["공인 :80", "192.168.2.20:80"]]);
  });

  it("게이트웨이(NAT 없음)에는 규칙을 넣어도 무시된다", () => {
    const net = buildParts();
    const gw = net.nodes.get("gw") as L3Node;
    const before = net.trace.length;
    gw.setForwards([{ publicPort: 80, lanIp: "192.168.2.20", lanPort: 80 }], net.contextFor("gw"));
    expect(net.trace.length).toBe(before);
    expect(gw.snapshot().tables.some((t) => t.title === "포트 포워딩")).toBe(false);
  });
});

describe("포트 포워딩 리뷰 반영", () => {
  it("같은 내부 서버를 가리키는 규칙이 둘이어도 각 연결의 응답이 들어온 공인 포트로 돌아간다", async () => {
    const { buildHomeLan } = await import("../src/core/scenarios/homeLan");
    const { Router } = await import("../src/core/nodes/router");
    const { Internet } = await import("../src/core/nodes/internet");
    const net = buildHomeLan(true, true);
    net.connect("srv", 0, "sw", 2);
    net.runToIdle();
    const rt = net.nodes.get("rt") as InstanceType<typeof Router>;
    rt.configure(
      {
        lanIp: "192.168.0.1",
        lanPrefix: 24,
        dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.101" },
        wan: { mode: "dhcp" },
        forwards: [
          { publicPort: 80, lanIp: "192.168.0.50", lanPort: 80 },
          { publicPort: 8080, lanIp: "192.168.0.50", lanPort: 80 },
        ],
      },
      net.contextFor("rt"),
    );
    net.scheduleAction(net.now, { kind: "inet-connect", nodeId: "inet", dst: rt.wan.ip!, port: 8080 });
    net.runToIdle();
    const inet = net.nodes.get("inet") as InstanceType<typeof Internet>;
    const conn = [...inet.tcp.conns.values()].find((c) => c.remotePort === 8080)!;
    expect(conn.state).toBe("CLOSED");
    expect(conn.bytesReceived).toBe(3000);
  });
});
