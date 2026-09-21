import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { FirewallBridge } from "../src/core/nodes/fwbridge";
import { Host } from "../src/core/nodes/host";
import { Router } from "../src/core/nodes/router";
import { Switch } from "../src/core/nodes/switch";
import type { FirewallConfig } from "../src/core/nodes/firewall";

/** rt ── sw ── pc1 / sw ── fw(outside) … fw(inside) ── srv */
function build(fw: Partial<FirewallConfig> = {}) {
  const net = new Network();
  net.addNode(new Router({ id: "rt", mac: "02:00:00:00:ff:01", wanMac: "02:00:00:01:ff:01", lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.110" } }));
  net.addNode(new Switch("sw", 4));
  net.addNode(new Host({ id: "pc1", mac: "02:00:00:00:00:01", ipMode: "dhcp" }));
  net.addNode(new FirewallBridge("fw", { enabled: true, defaultPolicy: "allow", stateful: true, rules: [{ action: "deny", proto: "icmp", direction: "in" }], ...fw }));
  net.addNode(new Host({ id: "srv", mac: "02:00:00:00:00:02", ipMode: "static", ip: "192.168.0.20", prefix: 24, gateway: "192.168.0.1", services: [80] }));
  net.connect("rt", 1, "sw", 0);
  net.connect("sw", 1, "pc1", 0);
  net.connect("sw", 2, "fw", FirewallBridge.OUTSIDE);
  net.connect("fw", FirewallBridge.INSIDE, "srv", 0);
  net.runToIdle();
  return net;
}

describe("투명 방화벽 장비", () => {
  it("주소·경로를 바꾸지 않고도 서버로 오는 ping 만 막고 TCP 80 은 통과시킨다", () => {
    const net = build();
    expect(net.getHost("pc1").ip).toMatch(/^192\.168\.0\.1\d\d$/); // pc1 은 방화벽 바깥이라 DHCP 와 무관
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "192.168.0.20" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)).toMatchObject({ status: "failed" });
    expect(net.trace.some((e) => e.nodeId === "fw" && e.kind === "fw.deny" && e.summary.includes("인바운드"))).toBe(true);
    // ARP 는 통과했으므로 pc1 은 srv 의 MAC 을 안다
    expect(net.getHost("pc1").iface.arpCache.has("192.168.0.20")).toBe(true);
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1", dst: "192.168.0.20", port: 80 });
    net.runToIdle();
    expect([...net.getHost("pc1").tcp.conns.values()].at(-1)).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
  });

  it("서버가 먼저 시작한 ping 의 응답은 인바운드 차단 규칙에 걸리지만 Stateful 로 통과한다", () => {
    const net = build();
    const pc = net.getHost("pc1").ip!;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "srv", dst: pc });
    net.runToIdle();
    expect(net.getHost("srv").pings.at(-1)).toMatchObject({ status: "ok" });
    expect(net.trace.some((e) => e.nodeId === "fw" && e.kind === "fw.established")).toBe(true);
    // Stateful 을 끄면 응답이 막힌다
    (net.nodes.get("fw") as FirewallBridge).configure({ enabled: true, defaultPolicy: "allow", stateful: false, rules: [{ action: "deny", proto: "icmp", direction: "in" }] }, net.contextFor("fw"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "srv", dst: pc });
    net.runToIdle();
    expect(net.getHost("srv").pings.at(-1)).toMatchObject({ status: "failed" });
  });

  it("방화벽을 끄면 전부 통과하고, traceroute 홉에는 나타나지 않는다", () => {
    const net = build({ enabled: false });
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "192.168.0.20" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)).toMatchObject({ status: "ok" });
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc1", dst: "192.168.0.20" });
    net.runToIdle();
    expect(net.getHost("pc1").traceroutes.at(-1)).toMatchObject({ status: "done", hops: [{ ip: "192.168.0.20" }] }); // 같은 서브넷: 한 홉, 방화벽은 없음
  });

  it("기본 정책 차단이면 안쪽 DHCP 호스트는 UDP 67/68 허용 규칙이 있어야 주소를 받는다 (DHCP 는 IP 라 규칙 대상)", () => {
    const net = build({ defaultPolicy: "deny", rules: [] });
    net.addNode(new Host({ id: "pc2", mac: "02:00:00:00:00:03", ipMode: "dhcp" }));
    net.addNode(new Switch("sw2", 4));
    // fw inside 쪽에 스위치를 두고 srv 와 pc2 를 붙인다
    net.disconnect([...net.links.values()].find((l) => l.b.node === "srv" || l.a.node === "srv")!.id);
    net.connect("fw", FirewallBridge.INSIDE, "sw2", 0);
    net.connect("sw2", 1, "srv", 0);
    net.connect("sw2", 2, "pc2", 0);
    net.runToIdle();
    expect(net.getHost("pc2").ip).toBeUndefined();
    expect(net.trace.some((e) => e.nodeId === "fw" && e.kind === "fw.deny" && e.summary.includes("UDP"))).toBe(true);
    (net.nodes.get("fw") as FirewallBridge).configure(
      { enabled: true, defaultPolicy: "deny", stateful: true, rules: [{ action: "allow", proto: "udp", direction: "any", dstPort: 67 }, { action: "allow", proto: "udp", direction: "any", dstPort: 68 }] },
      net.contextFor("fw"),
    );
    net.scheduleAction(net.now, { kind: "dhcp-renew", nodeId: "pc2" });
    net.runToIdle();
    expect(net.getHost("pc2").ip).toMatch(/^192\.168\.0\.1\d\d$/);
  });

  it("한쪽 케이블이 없으면 드롭하고, 기본 정책 차단이면 허용 규칙 없는 것은 전부 막힌다", () => {
    const net = build({ defaultPolicy: "deny", rules: [{ action: "allow", proto: "tcp", direction: "any", dstPort: 80 }] });
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1", dst: "192.168.0.20", port: 80 });
    net.runToIdle();
    expect([...net.getHost("pc1").tcp.conns.values()].at(-1)).toMatchObject({ state: "CLOSED" });
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "192.168.0.20" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)).toMatchObject({ status: "failed" });
    net.disconnect([...net.links.values()].find((l) => l.a.node === "fw" || l.b.node === "fw")!.id);
    net.runToIdle();
    const before = net.trace.length;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "srv", dst: "192.168.0.1" });
    net.runToIdle();
    expect(net.trace.slice(before).some((e) => e.nodeId === "fw" && e.kind === "link.unconnected")).toBe(true);
  });
});
