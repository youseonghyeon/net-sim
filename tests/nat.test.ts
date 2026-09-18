import { describe, expect, it } from "vitest";
import { Internet } from "../src/core/nodes/internet";
import { Router } from "../src/core/nodes/router";
import { buildHomeLan } from "../src/core/scenarios/homeLan";

describe("WAN + NAT", () => {
  it("라우터 WAN 이 ISP 에서 DHCP 로 공인 주소를 받는다", () => {
    const net = buildHomeLan(true, true);
    net.runToIdle();
    const rt = net.nodes.get("rt") as Router;
    expect(rt.wan.ip).toBe("203.0.113.100");
    expect(rt.wan.gateway).toBe("203.0.113.1");
    expect(rt.wanClient.state).toBe("bound");
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "dhcp.bound" && e.summary.startsWith("[wan]"))).toBe(true);
  });

  it("LAN 호스트가 8.8.8.8 로 ping 하면 NAT 를 거쳐 응답이 돌아온다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();

    const pc1 = net.getHost("pc1");
    expect(pc1.pings.at(-1)).toMatchObject({ status: "ok" });
    const rt = net.nodes.get("rt") as Router;
    expect(rt.nat.size).toBe(1);
    const entry = [...rt.nat.values()][0]!;
    expect(entry.lanIp).toBe("192.168.0.100");
    expect(entry.publicId).toBe(Router.NAT_ID_START);

    const kinds = net.trace.map((e) => `${e.nodeId}:${e.kind}`);
    const order = ["rt:nat.translate", "rt:ip.forward", "inet:inet.forward", "inet:inet.reply", "rt:nat.restore", "rt:ip.forward", "pc1:icmp.reply.received"];
    let idx = -1;
    for (const k of order) {
      const next = kinds.indexOf(k, idx + 1);
      expect(next, `expected ${k} after index ${idx}`).toBeGreaterThan(idx);
      idx = next;
    }
    // 인터넷으로 나간 패킷의 출발지는 공인 주소, TTL 은 하나 줄어 있다
    const out = net.transmissions.find((t) => t.from.node === "rt" && t.to.node === "inet" && t.frame.payload.kind === "ipv4" && t.frame.payload.payload.kind === "icmp");
    expect(out?.frame.payload.kind === "ipv4" && out.frame.payload.src).toBe("203.0.113.100");
    expect(out?.frame.payload.kind === "ipv4" && out.frame.payload.ttl).toBe(63);
    expect(net.pendingEvents).toBe(0);
  });

  it("두 호스트가 같은 ICMP id 로 나가도 공인 id 가 달라 각자에게 돌아온다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.connect("pc2", 0, "sw", 2);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "1.1.1.1" });
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc2", dst: "1.1.1.1" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)?.status).toBe("ok");
    expect(net.getHost("pc2").pings.at(-1)?.status).toBe("ok");
    const rt = net.nodes.get("rt") as Router;
    expect(rt.nat.size).toBe(2);
  });

  it("WAN 에 주소가 없으면 외부 ping 은 라우터에서 막힌다", () => {
    const net = buildHomeLan(true, false);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "ip.no-route")).toBe(true);
    expect(net.getHost("pc1").pings.at(-1)).toMatchObject({ status: "failed", reason: "응답 시간 초과" });
  });

  it("사설 주소로 향하는 패킷은 인터넷에서 버려진다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "10.9.9.9" });
    net.runToIdle();
    expect(net.trace.some((e) => e.nodeId === "inet" && e.kind === "ip.drop" && e.summary.includes("사설 주소"))).toBe(true);
    expect(net.getHost("pc1").pings.at(-1)?.status).toBe("failed");
  });

  it("바깥에서 라우터 공인 주소로 오는 ping 에는 응답하지만, NAT 에 없는 응답은 버린다", () => {
    const net = buildHomeLan(true, true);
    net.runToIdle();
    const inet = net.nodes.get("inet") as Internet;
    const rt = net.nodes.get("rt") as Router;
    // ISP 가 라우터 공인 주소로 ping
    const ctx = net.contextFor("inet");
    inet.iface.sendIp({ kind: "ipv4", src: "203.0.113.1", dst: "203.0.113.100", ttl: 64, payload: { kind: "icmp", type: "echo-request", id: 1, seq: 1 } }, ctx, (f) => ctx.send(0, f));
    net.runToIdle();
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "icmp.reply.sent")).toBe(true);
    // 요청한 적 없는 Echo 응답이 공인 주소로 오면 NAT 미스
    inet.iface.sendIp({ kind: "ipv4", src: "203.0.113.1", dst: "203.0.113.100", ttl: 64, payload: { kind: "icmp", type: "echo-reply", id: 12345, seq: 1 } }, net.contextFor("inet"), (f) => net.contextFor("inet").send(0, f));
    net.runToIdle();
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "nat.miss")).toBe(true);
    expect(rt.nat.size).toBe(0);
  });

  it("WAN 케이블을 뽑으면 공인 주소를 잃고 외부 통신이 막힌다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.disconnect("inet-rt");
    const rt = net.nodes.get("rt") as Router;
    expect(rt.wan.ip).toBeUndefined();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)?.status).toBe("failed");
  });
});
