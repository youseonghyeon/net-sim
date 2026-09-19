import { describe, expect, it } from "vitest";
import { cidrContains, validCidr, type FirewallConfig, type FirewallRule } from "../src/core/nodes/firewall";
import { Host } from "../src/core/nodes/host";
import { Internet } from "../src/core/nodes/internet";
import { L3Node } from "../src/core/nodes/l3";
import { Router } from "../src/core/nodes/router";
import { Switch } from "../src/core/nodes/switch";
import { Network } from "../src/core/network";
import { buildHomeLan } from "../src/core/scenarios/homeLan";

const rtBase = { lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.101" }, wan: { mode: "dhcp" as const } };
const fw = (rules: FirewallRule[], extra: Partial<FirewallConfig> = {}): FirewallConfig => ({ enabled: true, defaultPolicy: "allow", stateful: true, rules, ...extra });

function home() {
  const net = buildHomeLan(true, true);
  net.connect("pc1", 0, "sw", 1);
  net.connect("srv", 0, "sw", 2);
  net.runToIdle();
  return { net, rt: net.nodes.get("rt") as Router };
}

describe("방화벽: CIDR", () => {
  it("cidrContains / validCidr", () => {
    expect(cidrContains("192.168.0.0/24", "192.168.0.77")).toBe(true);
    expect(cidrContains("192.168.0.0/24", "192.168.1.1")).toBe(false);
    expect(cidrContains("192.168.0.20", "192.168.0.20")).toBe(true);
    expect(cidrContains("192.168.0.20", "192.168.0.21")).toBe(false);
    expect(cidrContains("bad", "1.2.3.4")).toBe(false);
    expect(validCidr("10.0.0.0/8")).toBe(true);
    expect(validCidr("10.0.0.0/33")).toBe(false);
    expect(validCidr("")).toBe(false);
    // "x.x.x.x/" 는 prefix 0(모두 일치)로 읽히면 안 된다
    expect(validCidr("10.0.0.0/")).toBe(false);
    expect(cidrContains("10.0.0.0/", "1.2.3.4")).toBe(false);
  });
});

describe("방화벽: 라우터", () => {
  it("나가는 ICMP 를 차단하면 외부 ping 이 라우터에서 막힌다", () => {
    const { net, rt } = home();
    rt.configure({ ...rtBase, firewall: fw([{ action: "deny", proto: "icmp", direction: "out" }]) }, net.contextFor("rt"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)?.status).toBe("failed");
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "fw.deny" && e.summary.includes("규칙 1"))).toBe(true);
    expect(net.trace.some((e) => e.nodeId === "inet" && e.kind === "inet.forward")).toBe(false);
  });

  it("상태 추적: 들어오는 모든 것을 차단해도 안에서 시작한 ping 의 응답은 돌아온다", () => {
    const { net, rt } = home();
    rt.configure({ ...rtBase, firewall: fw([{ action: "deny", proto: "any", direction: "in" }]) }, net.contextFor("rt"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)?.status).toBe("ok");
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "fw.established")).toBe(true);
  });

  it("상태 추적을 끄면 같은 규칙에 응답이 막힌다", () => {
    const { net, rt } = home();
    rt.configure({ ...rtBase, firewall: fw([{ action: "deny", proto: "any", direction: "in" }], { stateful: false }) }, net.contextFor("rt"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)?.status).toBe("failed");
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "fw.deny" && e.summary.includes("ping 응답"))).toBe(true);
  });

  it("포트 포워딩이 있어도 들어오는 TCP 80 차단 규칙이 이긴다", () => {
    const { net, rt } = home();
    rt.configure(
      { ...rtBase, forwards: [{ publicPort: 80, lanIp: "192.168.0.50", lanPort: 80 }], firewall: fw([{ action: "deny", proto: "tcp", direction: "in", dstPort: 80 }]) },
      net.contextFor("rt"),
    );
    net.scheduleAction(net.now, { kind: "inet-connect", nodeId: "inet", dst: rt.wan.ip!, port: 80 });
    net.runToIdle();
    const inet = net.nodes.get("inet") as Internet;
    expect([...inet.tcp.conns.values()].at(-1)?.state).toBe("FAILED");
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "nat.forward.rule")).toBe(true); // 포워딩은 됐고
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "fw.deny" && e.summary.includes("192.168.0.50:80"))).toBe(true); // 그 뒤 방화벽이 막음
    expect(net.trace.some((e) => e.nodeId === "srv" && e.kind === "tcp.syn.received")).toBe(false);
  });

  it("기본 정책 차단 + TCP 80 허용: 웹은 되고 ping 은 안 된다", () => {
    const { net, rt } = home();
    rt.configure({ ...rtBase, firewall: fw([{ action: "allow", proto: "tcp", direction: "out", dstPort: 80 }], { defaultPolicy: "deny" }) }, net.contextFor("rt"));
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1", dst: "93.184.216.34", port: 80 });
    net.runToIdle();
    expect([...net.getHost("pc1").tcp.conns.values()].at(-1)?.state).toBe("CLOSED");
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)?.status).toBe("failed");
    expect(net.trace.some((e) => e.kind === "fw.deny" && e.summary.includes("기본 정책 차단"))).toBe(true);
    expect(net.trace.some((e) => e.kind === "fw.allow" && e.summary.includes("규칙 1"))).toBe(true);
  });

  it("출발지 CIDR 로 특정 호스트만 외부 차단", () => {
    const { net, rt } = home();
    net.connect("pc2", 0, "sw", 3);
    net.runToIdle();
    const pc1Ip = net.getHost("pc1").ip!;
    rt.configure({ ...rtBase, firewall: fw([{ action: "deny", proto: "any", direction: "out", src: pc1Ip }]) }, net.contextFor("rt"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "8.8.8.8" });
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc2", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)?.status).toBe("failed");
    expect(net.getHost("pc2").pings.at(-1)?.status).toBe("ok");
  });

  it("방화벽이 꺼져 있으면 규칙이 있어도 모두 통과한다", () => {
    const { net, rt } = home();
    rt.configure({ ...rtBase, firewall: { ...fw([{ action: "deny", proto: "any", direction: "any" }]), enabled: false } }, net.contextFor("rt"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)?.status).toBe("ok");
    expect(net.trace.some((e) => e.kind === "fw.deny")).toBe(false);
  });
});

describe("방화벽: 게이트웨이(서브넷 간)", () => {
  function two() {
    const net = new Network();
    net.addNode(
      new L3Node({
        id: "gw",
        kind: "gateway",
        interfaces: [
          { name: "if0", mac: "02:00:00:10:00:02", mode: "static", ip: "10.0.0.2", prefix: 24 },
          { name: "if1", mac: "02:00:00:11:00:02", mode: "static", ip: "192.168.1.1", prefix: 24 },
          { name: "if2", mac: "02:00:00:12:00:02", mode: "static", ip: "192.168.2.1", prefix: 24 },
        ],
      }),
    );
    net.addNode(new Switch("s1", 4));
    net.addNode(new Switch("s2", 4));
    net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "192.168.1.10", prefix: 24, gateway: "192.168.1.1" }));
    net.addNode(new Host({ id: "b", mac: "02:00:00:00:00:0b", ipMode: "static", ip: "192.168.2.10", prefix: 24, gateway: "192.168.2.1", services: [80] }));
    net.connect("gw", 1, "s1", 0);
    net.connect("gw", 2, "s2", 0);
    net.connect("a", 0, "s1", 1);
    net.connect("b", 0, "s2", 1);
    net.runToIdle();
    return { net, gw: net.nodes.get("gw") as L3Node };
  }

  it("서브넷 간 트래픽은 방향 '모든 방향' 규칙으로만 걸린다", () => {
    const { net, gw } = two();
    gw.setFirewall(fw([{ action: "deny", proto: "icmp", direction: "in" }]), net.contextFor("gw"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "192.168.2.10" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)?.status).toBe("ok"); // in/out 은 업링크 기준이라 안 걸림

    gw.setFirewall(fw([{ action: "deny", proto: "icmp", direction: "any", dst: "192.168.2.0/24" }]), net.contextFor("gw"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "192.168.2.10" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)?.status).toBe("failed");
    expect(net.trace.some((e) => e.nodeId === "gw" && e.kind === "fw.deny" && e.summary.includes("서브넷 간"))).toBe(true);
  });

  it("TCP 80 만 허용하고 나머지 차단 (기본 정책 차단): 웹은 되고 ping 은 막힘, 응답은 상태 추적으로 통과", () => {
    const { net, gw } = two();
    gw.setFirewall(fw([{ action: "allow", proto: "tcp", direction: "any", dst: "192.168.2.10", dstPort: 80 }], { defaultPolicy: "deny" }), net.contextFor("gw"));
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "a", dst: "192.168.2.10", port: 80 });
    net.runToIdle();
    expect([...net.getHost("a").tcp.conns.values()].at(-1)).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "192.168.2.10" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)?.status).toBe("failed");
    expect(net.pendingEvents).toBe(0);
  });
});
