import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { buildHomeLan } from "../src/core/scenarios/homeLan";

/** homeLan + DNS 서버 호스트(ns, 192.168.0.53) + 수동 IP 클라이언트(c1, DNS 설정 있음) */
function build(clientDns = "192.168.0.53") {
  const net = buildHomeLan();
  net.addNode(
    new Host({
      id: "ns",
      mac: "02:00:00:00:00:53",
      ipMode: "static",
      ip: "192.168.0.53",
      prefix: 24,
      gateway: "192.168.0.1",
      dnsServer: { enabled: true, records: [{ name: "srv.local", ip: "192.168.0.50" }, { name: "ns.local", ip: "192.168.0.53" }] },
    }),
  );
  net.addNode(new Host({ id: "c1", mac: "02:00:00:00:00:c1", ipMode: "static", ip: "192.168.0.60", prefix: 24, gateway: "192.168.0.1", dns: clientDns || undefined }));
  net.connect("ns", 0, "sw", 1);
  net.connect("srv", 0, "sw", 2);
  net.connect("c1", 0, "sw", 3);
  net.runToIdle();
  return net;
}

describe("DNS", () => {
  it("이름으로 ping 하면 DNS 질의 → 응답 → 해석된 주소로 ping 이 나간다", () => {
    const net = build();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: "srv.local" });
    net.runToIdle();
    const c1 = net.getHost("c1");
    expect(c1.pings.at(-1)).toMatchObject({ status: "ok", resolved: "192.168.0.50" });
    const kinds = net.trace.map((e) => `${e.nodeId}:${e.kind}`);
    const order = ["c1:dns.query.sent", "ns:dns.query.received", "ns:dns.response.sent", "c1:dns.response.received", "c1:dns.resolved", "c1:icmp.echo.sent", "c1:icmp.reply.received"];
    let idx = -1;
    for (const k of order) {
      const next = kinds.indexOf(k, idx + 1);
      expect(next, `expected ${k} after ${idx}`).toBeGreaterThan(idx);
      idx = next;
    }
    expect(c1.resolver.cache.get("srv.local")?.ip).toBe("192.168.0.50");
    expect(net.pendingEvents).toBe(0);
  });

  it("두 번째부터는 캐시로 바로 ping 한다", () => {
    const net = build();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: "srv.local" });
    net.runToIdle();
    const before = net.trace.length;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: "SRV.local" });
    net.runToIdle();
    const later = net.trace.slice(before).map((e) => e.kind);
    expect(later).toContain("dns.cache.hit");
    expect(later).not.toContain("dns.query.sent");
    expect(net.getHost("c1").pings.at(-1)?.status).toBe("ok");
  });

  it("없는 이름은 NXDOMAIN 으로 실패한다", () => {
    const net = build();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: "nope.local" });
    net.runToIdle();
    expect(net.getHost("c1").pings.at(-1)).toMatchObject({ status: "failed", reason: "없는 이름" });
    expect(net.trace.some((e) => e.nodeId === "ns" && e.kind === "dns.nxdomain")).toBe(true);
  });

  it("DNS 서버 설정이 없으면 질의조차 못 하고 실패한다", () => {
    const net = build("");
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: "srv.local" });
    net.runToIdle();
    expect(net.getHost("c1").pings.at(-1)).toMatchObject({ status: "failed", reason: "DNS 서버 없음" });
    expect(net.trace.some((e) => e.nodeId === "c1" && e.kind === "dns.no-server")).toBe(true);
  });

  it("DNS 서버가 응답하지 않으면 재시도 후 실패한다", () => {
    const net = build("192.168.0.99");
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: "srv.local" });
    net.runToIdle();
    expect(net.getHost("c1").pings.at(-1)).toMatchObject({ status: "failed", reason: "DNS 응답 없음" });
    expect(net.trace.filter((e) => e.nodeId === "c1" && e.kind === "dns.query.sent")).toHaveLength(2);
  });

  it("이름으로 TCP 연결하면 해석 뒤 handshake 가 진행된다", () => {
    const net = build();
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "c1", dst: "srv.local", port: 80 });
    net.runToIdle();
    const conn = [...net.getHost("c1").tcp.conns.values()][0]!;
    expect(conn.remoteIp).toBe("192.168.0.50");
    expect(conn.state).toBe("CLOSED");
    expect(conn.bytesReceived).toBe(3000);
  });

  it("DHCP 서버가 안내한 DNS 로 이름을 해석한다", () => {
    const net = build();
    // ns 호스트에 DHCP 서버도 켜서 DNS 를 안내하게 하고, 라우터 DHCP 는 끈다
    const rt = net.nodes.get("rt") as import("../src/core/nodes/router").Router;
    rt.configure({ lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: false, start: "192.168.0.100", end: "192.168.0.101" }, wan: { mode: "dhcp" } }, net.contextFor("rt"));
    net.getHost("ns").setDhcpServer({ enabled: true, start: "192.168.0.110", end: "192.168.0.111", router: "192.168.0.1", dns: "192.168.0.53" }, net.contextFor("ns"));
    net.connect("pc1", 0, "sw", 4);
    net.runToIdle();
    const pc1 = net.getHost("pc1");
    expect(pc1.ip).toBe("192.168.0.110");
    expect(pc1.iface.dns).toBe("192.168.0.53");
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "srv.local" });
    net.runToIdle();
    expect(pc1.pings.at(-1)).toMatchObject({ status: "ok", resolved: "192.168.0.50" });
  });

  it("DNS 서버가 모르는 이름은 업스트림 DNS 에 재귀 질의해 답을 전달한다", () => {
    const net = build();
    // 업스트림 DNS 역할의 호스트 하나 더
    net.addNode(new Host({ id: "root", mac: "02:00:00:00:00:99", ipMode: "static", ip: "192.168.0.99", prefix: 24, dnsServer: { enabled: true, records: [{ name: "far.example", ip: "192.168.0.50" }] } }));
    net.connect("root", 0, "sw", 4);
    net.runToIdle();
    net.getHost("ns").setDnsServer({ enabled: true, records: [{ name: "srv.local", ip: "192.168.0.50" }], upstream: "192.168.0.99" }, net.contextFor("ns"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: "far.example" });
    net.runToIdle();
    expect(net.getHost("c1").pings.at(-1)).toMatchObject({ status: "ok", resolved: "192.168.0.50" });
    expect(net.trace.some((e) => e.nodeId === "ns" && e.kind === "dns.forward")).toBe(true);
    expect(net.getHost("ns").dnsServer.cache.get("far.example")?.ip).toBe("192.168.0.50");
  });
});

describe("DNS: 라우터 포워더와 공인 DNS", () => {
  it("DHCP 호스트가 라우터를 DNS 로 받고, google.com 은 라우터 → 8.8.8.8 로 재귀 질의해 해석한다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    const pc1 = net.getHost("pc1");
    expect(pc1.iface.dns).toBe("192.168.0.1");
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "google.com" });
    net.runToIdle();
    expect(pc1.pings.at(-1)).toMatchObject({ status: "ok", resolved: "142.250.196.110" });
    const kinds = net.trace.map((e) => `${e.nodeId}:${e.kind}`);
    const order = ["pc1:dns.query.sent", "rt:dns.query.received", "rt:dns.forward", "inet:dns.query.received", "inet:dns.response.sent", "rt:dns.response.received", "rt:dns.response.sent", "pc1:dns.response.received", "pc1:icmp.echo.sent", "pc1:icmp.reply.received"];
    let idx = -1;
    for (const k of order) {
      const next = kinds.indexOf(k, idx + 1);
      expect(next, `expected ${k} after ${idx}`).toBeGreaterThan(idx);
      idx = next;
    }
    // 라우터가 캐시했으므로 두 번째 호스트의 질의는 상위로 안 간다
    net.connect("pc2", 0, "sw", 2);
    net.runToIdle();
    const before = net.trace.length;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc2", dst: "google.com" });
    net.runToIdle();
    expect(net.trace.slice(before).some((e) => e.nodeId === "rt" && e.kind === "dns.forward")).toBe(false);
    expect(net.getHost("pc2").pings.at(-1)?.status).toBe("ok");
    expect(net.pendingEvents).toBe(0);
  });

  it("공인 DNS 가 모르는 이름은 NXDOMAIN 이 라우터를 거쳐 호스트까지 전달된다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "nope.example" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)).toMatchObject({ status: "failed", reason: "없는 이름" });
  });

  it("인터넷이 없으면 라우터 포워더는 업스트림 응답을 못 받아 SERVFAIL 을 돌려준다", () => {
    const net = buildHomeLan(true, false);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "google.com" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)?.status).toBe("failed");
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "dns.timeout")).toBe(true);
  });

  it("호스트가 8.8.8.8 을 직접 DNS 로 쓰면 UDP NAT 를 거쳐 답을 받는다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    const pc1 = net.getHost("pc1");
    pc1.configure({ ipMode: "static", ip: "192.168.0.60", prefix: 24, gateway: "192.168.0.1", dns: "8.8.8.8" }, net.contextFor("pc1"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "example.com" });
    net.runToIdle();
    expect(pc1.pings.at(-1)).toMatchObject({ status: "ok", resolved: "93.184.216.34" });
    const rt = net.nodes.get("rt") as import("../src/core/nodes/router").Router;
    expect(rt.nat.values().some((e) => e.proto === "udp")).toBe(true);
  });
});

describe("DNS 리뷰 반영", () => {
  it("NAT 박스 뒤 호스트가 8.8.8.8 을 직접 DNS 로 써도 응답이 UDP NAT 역변환으로 돌아온다", async () => {
    const { Internet } = await import("../src/core/nodes/internet");
    const { L3Node } = await import("../src/core/nodes/l3");
    const { Switch } = await import("../src/core/nodes/switch");
    const { Network } = await import("../src/core/network");
    const net = new Network();
    net.addNode(new Internet({ id: "inet", mac: "02:00:00:ff:00:01" }));
    net.addNode(
      new L3Node({
        id: "nat",
        kind: "nat",
        outside: 0,
        interfaces: [
          { name: "outside", mac: "02:00:00:10:00:01", mode: "dhcp" },
          { name: "inside", mac: "02:00:00:11:00:01", mode: "static", ip: "192.168.0.1", prefix: 24 },
        ],
      }),
    );
    net.addNode(new Switch("sw", 4));
    net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "192.168.0.10", prefix: 24, gateway: "192.168.0.1", dns: "8.8.8.8" }));
    net.connect("inet", 0, "nat", 0);
    net.connect("nat", 1, "sw", 0);
    net.connect("a", 0, "sw", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "example.com" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)).toMatchObject({ status: "ok", resolved: "93.184.216.34" });
  });

  it("질의 대기 중 DNS 설정을 지우면 예외 없이 실패로 끝난다", () => {
    const net = build("192.168.0.99"); // 응답 없는 서버
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: "srv.local" });
    net.runUntil(net.now + 100);
    const c1 = net.getHost("c1");
    c1.configure({ ipMode: "static", ip: "192.168.0.60", prefix: 24, gateway: "192.168.0.1", dns: undefined }, net.contextFor("c1"));
    expect(() => net.runToIdle()).not.toThrow();
    expect(c1.pings.at(-1)).toMatchObject({ status: "failed", reason: "DNS 설정 변경" });
    expect(net.pendingEvents).toBe(0);
  });

  it("IP 도 이름도 아닌 대상은 예외 없이 즉시 실패한다", () => {
    const net = build();
    for (const bad of ["192.168.0", "999.1.1.1", "1.2.3.4.5"]) {
      net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: bad });
      expect(() => net.runToIdle()).not.toThrow();
      expect(net.getHost("c1").pings.at(-1)).toMatchObject({ dst: bad, status: "failed", reason: "잘못된 주소" });
    }
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "c1", dst: "192.168.0", port: 80 });
    expect(() => net.runToIdle()).not.toThrow();
    expect([...net.getHost("c1").tcp.conns.values()].at(-1)?.state).toBe("FAILED");
  });

  it("서버 두 대가 서로를 업스트림으로 가리켜도 무한 루프 없이 SERVFAIL 로 끝난다", () => {
    const net = build();
    net.addNode(new Host({ id: "root", mac: "02:00:00:00:00:99", ipMode: "static", ip: "192.168.0.99", prefix: 24, dnsServer: { enabled: true, records: [], upstream: "192.168.0.53" } }));
    net.connect("root", 0, "sw", 4);
    net.runToIdle();
    net.getHost("ns").setDnsServer({ enabled: true, records: [], upstream: "192.168.0.99" }, net.contextFor("ns"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: "loop.example" });
    const events = net.runToIdle(20000);
    expect(events).toBeLessThan(500);
    expect(net.getHost("c1").pings.at(-1)?.status).toBe("failed");
    expect(net.trace.some((e) => e.kind === "dns.timeout" && e.summary.includes("루프"))).toBe(true);
  });

  it("DNS 서버 호스트가 자기 주소를 DNS 로 쓰면 루프백으로 해석한다", () => {
    const net = build();
    const ns = net.getHost("ns");
    ns.configure({ ipMode: "static", ip: "192.168.0.53", prefix: 24, gateway: "192.168.0.1", dns: "192.168.0.53" }, net.contextFor("ns"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "ns", dst: "srv.local" });
    net.runToIdle();
    expect(ns.pings.at(-1)).toMatchObject({ status: "ok", resolved: "192.168.0.50" });
    expect(net.trace.some((e) => e.nodeId === "ns" && e.kind === "dns.query.sent" && e.summary.includes("루프백"))).toBe(true);
  });

  it("링크가 끊기면 대기 중이던 이름 해석은 실패로 끝난다 (영구 대기 없음)", () => {
    const net = build("192.168.0.99");
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: "srv.local" });
    net.runUntil(net.now + 100);
    const link = [...net.links.values()].find((l) => l.a.node === "c1" || l.b.node === "c1")!;
    net.disconnect(link.id);
    net.runToIdle();
    expect(net.getHost("c1").pings.at(-1)).toMatchObject({ status: "failed", reason: "링크 끊김" });
  });

  it("업스트림 DNS 무응답이면 SERVFAIL 이 리졸버가 포기하기 전에 도착해 원인이 정확히 남는다", () => {
    const net = buildHomeLan(true, false);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "google.com" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)).toMatchObject({ status: "failed", reason: "DNS 서버가 업스트림 서버 응답을 받지 못함" });
  });

  it("라우터 업스트림 DNS 를 LAN 안의 서버로 두면 LAN 쪽으로 물어본다", () => {
    const net = build();
    const rt = net.nodes.get("rt") as import("../src/core/nodes/router").Router;
    rt.configure(
      { lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.101" }, wan: { mode: "dhcp" }, dns: { enabled: true, records: [], upstream: "192.168.0.53" } },
      net.contextFor("rt"),
    );
    net.connect("pc1", 0, "sw", 4);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "srv.local" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)).toMatchObject({ status: "ok", resolved: "192.168.0.50" });
  });
});
