import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { type FirewallConfig } from "../src/core/nodes/firewall";
import { Host } from "../src/core/nodes/host";
import { Internet } from "../src/core/nodes/internet";
import { L3Node } from "../src/core/nodes/l3";
import { Router } from "../src/core/nodes/router";
import { Switch } from "../src/core/nodes/switch";
import { buildHomeLan } from "../src/core/scenarios/homeLan";
import type { TraceKind } from "../src/core/trace";

/** 가정용 LAN: 라우터(NAT) + 스위치 + pc1(DHCP) + 인터넷. 안정화까지 돌린다 */
function home() {
  const net = buildHomeLan(true, true);
  net.connect("pc1", 0, "sw", 1);
  net.runToIdle();
  const rt = net.nodes.get("rt") as Router;
  expect(net.getHost("pc1").ip).toBe("192.168.0.100");
  expect(rt.wan.ip).toBe("203.0.113.100");
  return { net, rt };
}

/**
 * 기능 단위 2단 구성 (tests/l3.test.ts 와 같은 모양):
 *   inet ── nat(outside dhcp / inside 10.0.0.1, 스태틱 라우팅 192.168.0.0/16 via 10.0.0.2) ── gw(if0 10.0.0.2 / if1 192.168.1.1) ── sw ── a(192.168.1.10)
 */
function twoStage() {
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
      ],
    }),
  );
  net.addNode(new Switch("sw", 4));
  net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "192.168.1.10", prefix: 24, gateway: "192.168.1.1" }));
  net.connect("inet", 0, "nat", 0, 10, "inet-nat");
  net.connect("nat", 1, "gw", 0, 10, "nat-gw");
  net.connect("gw", 1, "sw", 0, 10, "gw-sw");
  net.connect("a", 0, "sw", 1);
  net.runToIdle();
  return net;
}

function kinds(net: Network, from: number, filter: (k: TraceKind) => boolean): string[] {
  return net.trace
    .slice(from)
    .filter((e) => filter(e.kind))
    .map((e) => `${e.nodeId}:${e.kind}`);
}

const KEY = (k: TraceKind) => k.startsWith("trace.") || k === "icmp.ttl-exceeded" || k === "nat.translate" || k === "nat.restore" || k === "inet.reply";

function hopIps(host: Host) {
  return host.traceroutes.at(-1)!.hops.map((h) => h.ip ?? "*");
}

describe("traceroute", () => {
  it("(a) 가정용 LAN 에서 8.8.8.8: 라우터 → ISP → 서버 순으로 홉이 기록되고 완료된다", () => {
    const { net } = home();
    const from = net.trace.length;
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();

    const rec = net.getHost("pc1").traceroutes.at(-1)!;
    expect(rec.status).toBe("done");
    expect(rec.dst).toBe("8.8.8.8");
    expect(rec.resolved).toBeUndefined();
    expect(rec.hops.map((h) => h.ttl)).toEqual([1, 2, 3]);
    expect(hopIps(net.getHost("pc1"))).toEqual(["192.168.0.1", "203.0.113.1", "8.8.8.8"]);
    // 먼 홉일수록 RTT 가 길다 (8.8.8.8 은 인터넷 왕복 60ms 가 더 걸린다)
    const rtts = rec.hops.map((h) => h.rtt!);
    expect(rtts.every((r) => r > 0)).toBe(true);
    expect(rtts[2]!).toBeGreaterThan(rtts[1]!);

    expect(kinds(net, from, KEY)).toEqual([
      "pc1:trace.start",
      "pc1:trace.probe",
      "rt:icmp.ttl-exceeded",
      "pc1:trace.hop",
      "pc1:trace.probe",
      "rt:nat.translate",
      "inet:icmp.ttl-exceeded",
      "rt:nat.restore",
      "pc1:trace.hop",
      "pc1:trace.probe",
      "rt:nat.translate",
      "inet:inet.reply",
      "rt:nat.restore",
      "pc1:trace.done",
    ]);
    // TTL 초과 드롭은 traceroute 의 정상 동작: 붉은 "ip.ttl-expired" 는 나오지 않는다
    expect(net.trace.slice(from).some((e) => e.kind === "ip.ttl-expired")).toBe(false);
    expect(net.trace.slice(from).find((e) => e.nodeId === "rt" && e.kind === "icmp.ttl-exceeded")!.summary).toContain("192.168.0.1");
    // 타이머가 남지 않는다
    expect(net.pendingEvents).toBe(0);
  });

  it("(b) 게이트웨이 + NAT 박스 2단: NAT 를 통과해 홉이 모두 보인다", () => {
    const net = twoStage();
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "a", dst: "8.8.8.8" });
    net.runToIdle();
    const a = net.getHost("a");
    expect(a.traceroutes.at(-1)!.status).toBe("done");
    expect(hopIps(a)).toEqual(["192.168.1.1", "10.0.0.1", "203.0.113.1", "8.8.8.8"]);
    // ISP 의 Time Exceeded 는 NAT 박스가 내장된 원래 패킷의 id 로 테이블을 찾아 안쪽 호스트에게 되돌린다
    expect(net.trace.some((e) => e.nodeId === "nat" && e.kind === "nat.restore" && e.summary.includes("Time Exceeded"))).toBe(true);
    const nat = net.nodes.get("nat") as L3Node;
    expect(nat.nat!.size).toBe(1); // traceroute 전체가 NAT 항목 하나
    expect(net.pendingEvents).toBe(0);
  });

  it("(c) 이름으로: google.com 을 먼저 해석하고 그 주소까지 추적한다", () => {
    const { net } = home();
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc1", dst: "google.com" });
    net.runToIdle();
    const rec = net.getHost("pc1").traceroutes.at(-1)!;
    expect(rec).toMatchObject({ status: "done", dst: "google.com", resolved: "142.250.196.110" });
    expect(hopIps(net.getHost("pc1"))).toEqual(["192.168.0.1", "203.0.113.1", "142.250.196.110"]);
    const ks = net.trace.map((e) => `${e.nodeId}:${e.kind}`);
    expect(ks.indexOf("pc1:dns.resolved")).toBeLessThan(ks.indexOf("pc1:trace.start"));
  });

  it("(d) 도달 불가(10.9.9.9): 첫 홉 뒤로 * 가 이어지다 16 홉에서 실패하고 이유가 남는다", () => {
    const { net } = home();
    const t0 = net.now;
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc1", dst: "10.9.9.9" });
    net.runToIdle();
    const rec = net.getHost("pc1").traceroutes.at(-1)!;
    expect(rec.status).toBe("failed");
    expect(rec.reason).toBe(`${Host.TRACEROUTE_MAX_HOPS} 홉 안에 도달하지 못함`);
    expect(rec.hops).toHaveLength(Host.TRACEROUTE_MAX_HOPS);
    expect(hopIps(net.getHost("pc1"))).toEqual(["192.168.0.1", ...Array(15).fill("*")]);
    expect(rec.hops[1]).toEqual({ ttl: 2 }); // 응답 없는 홉엔 ip/rtt 가 없다
    // 인터넷이 사설 주소를 버린 이유가 로그에 있다
    expect(net.trace.some((e) => e.nodeId === "inet" && e.kind === "ip.drop" && e.summary.includes("사설 주소"))).toBe(true);
    expect(net.trace.filter((e) => e.nodeId === "pc1" && e.kind === "trace.timeout")).toHaveLength(15);
    expect(net.trace.some((e) => e.nodeId === "pc1" && e.kind === "trace.failed")).toBe(true);
    // 홉당 1000ms 씩 15번 기다렸다
    expect(net.now - t0).toBeGreaterThanOrEqual(15 * Host.TRACEROUTE_TIMEOUT);
    expect(net.pendingEvents).toBe(0);
  });

  it("(e) Stateful 검사 방화벽이 들어오는 모든 것을 막아도 Time Exceeded 는 응답으로 통과한다", () => {
    const { net, rt } = home();
    const fw: FirewallConfig = { enabled: true, defaultPolicy: "allow", stateful: true, rules: [{ action: "deny", proto: "any", direction: "in" }] };
    rt.configure({ lanIp: "192.168.0.1", lanPrefix: 24, dhcp: rt.dhcp, wan: { mode: "dhcp" }, firewall: fw }, net.contextFor("rt"));
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.getHost("pc1").traceroutes.at(-1)!.status).toBe("done");
    expect(hopIps(net.getHost("pc1"))).toEqual(["192.168.0.1", "203.0.113.1", "8.8.8.8"]);
    const est = net.trace.filter((e) => e.nodeId === "rt" && e.kind === "fw.established");
    expect(est.some((e) => e.summary.includes("Time Exceeded") && e.summary.includes("오류 통지"))).toBe(true);
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "fw.deny")).toBe(false);

    // Stateful 검사를 끄면 같은 규칙에 Time Exceeded 가 막혀 홉이 * 가 된다
    rt.configure({ lanIp: "192.168.0.1", lanPrefix: 24, dhcp: rt.dhcp, wan: { mode: "dhcp" }, firewall: { ...fw, stateful: false } }, net.contextFor("rt"));
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();
    expect(hopIps(net.getHost("pc1")).slice(0, 3)).toEqual(["192.168.0.1", "*", "*"]);
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "fw.deny" && e.summary.includes("Time Exceeded"))).toBe(true);
  });

  it("ping 과 traceroute 를 동시에 돌려도 서로 섞이지 않는다", () => {
    const { net } = home();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "8.8.8.8" });
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();
    const pc1 = net.getHost("pc1");
    expect(pc1.pings.at(-1)).toMatchObject({ status: "ok" });
    expect(pc1.traceroutes.at(-1)!.status).toBe("done");
    expect(hopIps(pc1)).toEqual(["192.168.0.1", "203.0.113.1", "8.8.8.8"]);
    expect(net.pendingEvents).toBe(0);
  });

  it("진행 중에 다시 시작하면 이전 것은 취소되고, 기록은 최근 5개만 남는다", () => {
    const { net } = home();
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc1", dst: "10.9.9.9" });
    net.scheduleAction(net.now + 1500, { kind: "traceroute", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();
    const pc1 = net.getHost("pc1");
    expect(pc1.traceroutes).toHaveLength(2);
    expect(pc1.traceroutes[0]).toMatchObject({ dst: "10.9.9.9", status: "failed", reason: "새 traceroute 시작으로 취소" });
    expect(pc1.traceroutes[0]!.hops.length).toBeLessThan(Host.TRACEROUTE_MAX_HOPS);
    expect(pc1.traceroutes[1]!.status).toBe("done");
    expect(hopIps(pc1)).toEqual(["192.168.0.1", "203.0.113.1", "8.8.8.8"]);
    expect(net.pendingEvents).toBe(0);

    for (let i = 0; i < 5; i++) {
      net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc1", dst: "8.8.8.8" });
      net.runToIdle();
    }
    expect(pc1.traceroutes).toHaveLength(Host.TRACEROUTE_KEEP);
    expect(pc1.traceroutes.every((r) => r.status === "done")).toBe(true);
  });

  it("내 주소는 1 홉으로 즉시 완료, IP 가 없으면 실패", () => {
    const { net } = home();
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc1", dst: "192.168.0.100" });
    net.runToIdle();
    expect(net.getHost("pc1").traceroutes.at(-1)).toMatchObject({ status: "done", hops: [{ ttl: 1, ip: "192.168.0.100", rtt: 0 }] });
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc2", dst: "8.8.8.8" }); // pc2 는 케이블이 없어 주소 없음
    net.runToIdle();
    expect(net.getHost("pc2").traceroutes.at(-1)).toMatchObject({ status: "failed", reason: "IP 미설정" });
  });

  it("첫 홉(게이트웨이)이 ARP 에 응답하지 않으면 16 홉을 기다리지 않고 바로 실패한다", () => {
    const net = new Network();
    net.addNode(new Switch("sw", 4));
    net.addNode(new Host({ id: "h", mac: "02:00:00:00:00:01", ipMode: "static", ip: "10.0.0.5", prefix: 24, gateway: "10.0.0.254" }));
    net.connect("h", 0, "sw", 0);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "h", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.getHost("h").traceroutes.at(-1)).toMatchObject({ status: "failed", reason: "ARP 응답 없음", hops: [] });
    expect(net.trace.find((e) => e.kind === "trace.failed")!.summary).toContain("10.0.0.254");
    expect(net.pendingEvents).toBe(0);
  });

  it("라우팅 루프에 걸린 ping 은 Time Exceeded 로 실패 이유를 안다", () => {
    // gw 는 디폴트 라우트로 nat 에, nat 는 172.16.0.0/16 을 다시 gw 로 보낸다 → 172.16.0.1 은 둘 사이를 맴돈다
    const net = twoStage();
    const nat = net.nodes.get("nat") as L3Node;
    nat.setRoutes(
      [
        { dest: "192.168.0.0", prefix: 16, via: "10.0.0.2" },
        { dest: "172.16.0.0", prefix: 16, via: "10.0.0.2" },
      ],
      net.contextFor("nat"),
    );
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "172.16.0.1" });
    net.runToIdle();
    expect(net.getHost("a").pings.at(-1)).toMatchObject({ status: "failed", reason: "TTL 초과" });
    expect(net.trace.some((e) => e.nodeId === "a" && e.kind === "icmp.ttl-received" && e.summary.includes("라우팅 루프"))).toBe(true);
    expect(net.trace.filter((e) => e.kind === "icmp.ttl-exceeded")).toHaveLength(1);
    expect(net.pendingEvents).toBe(0);
  });
});

describe("traceroute: WAN 없는 라우터", () => {
  it("라우터가 인터넷에 못 나가도 1 번째 홉은 라우터, 그 뒤는 * 로 보인다", () => {
    const net = buildHomeLan(true, false);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();
    const rec = net.getHost("pc1").traceroutes.at(-1)!;
    expect(rec.status).toBe("failed");
    expect(hopIps(net.getHost("pc1")).slice(0, 3)).toEqual(["192.168.0.1", "*", "*"]);
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "ip.no-route" && e.summary.includes("WAN"))).toBe(true);
    expect(net.pendingEvents).toBe(0);
  });
});
