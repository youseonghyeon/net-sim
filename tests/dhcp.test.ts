import { describe, expect, it } from "vitest";
import { DHCP_MAX_ATTEMPTS, DHCP_TIMEOUT } from "../src/core/nodes/host";
import { Router } from "../src/core/nodes/router";
import { buildHomeLan } from "../src/core/scenarios/homeLan";

const kindsOf = (net: ReturnType<typeof buildHomeLan>, from = 0) => net.trace.slice(from).map((e) => `${e.nodeId}:${e.kind}`);

describe("DHCP", () => {
  it("케이블을 꽂으면 Discover → Offer → Request → Ack 로 주소를 받는다", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1, 10, "pc1-sw");
    net.runToIdle();

    const pc1 = net.getHost("pc1");
    expect(pc1.ip).toBe("192.168.0.100");
    expect(pc1.iface.prefix).toBe(24);
    expect(pc1.iface.gateway).toBe("192.168.0.1");
    expect(pc1.dhcp.state).toBe("bound");

    const rt = net.nodes.get("rt") as Router;
    expect(rt.leases.get("192.168.0.100")?.mac).toBe("02:00:00:00:00:01");

    const dhcp = kindsOf(net).filter((k) => k.includes(":dhcp.") && !k.includes("ignore"));
    expect(dhcp).toEqual([
      "pc1:dhcp.discover.sent",
      "rt:dhcp.discover.received",
      "rt:dhcp.offer.sent",
      "pc1:dhcp.offer.received",
      "pc1:dhcp.request.sent",
      "rt:dhcp.request.received",
      "rt:dhcp.lease",
      "rt:dhcp.ack.sent",
      "pc1:dhcp.ack.received",
      "pc1:dhcp.bound",
    ]);
    // Offer/Ack 는 클라이언트 MAC 으로 유니캐스트 → 스위치가 플러딩하지 않고 학습한 포트로 전달
    expect(net.trace.filter((e) => e.nodeId === "sw" && e.kind === "switch.forward")).toHaveLength(2);
    expect(net.pendingEvents).toBe(0);
  });

  it("두 번째 호스트는 다음 주소를 받고, 풀이 차면 세 번째는 실패한다", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.connect("pc2", 0, "sw", 2);
    net.runToIdle();
    expect(net.getHost("pc2").ip).toBe("192.168.0.101");

    const before = net.trace.length;
    net.connect("pc3", 0, "sw", 3);
    net.runToIdle();
    const later = kindsOf(net, before);
    expect(later).toContain("rt:dhcp.pool.exhausted");
    expect(later).toContain("pc3:dhcp.failed");
    expect(net.getHost("pc3").ip).toBeUndefined();
  });

  it("DHCP 가 꺼져 있으면 3번 시도 후 실패하고, 수동 설정하면 ping 이 된다", () => {
    const net = buildHomeLan(false);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();

    const pc1 = net.getHost("pc1");
    expect(pc1.ip).toBeUndefined();
    expect(pc1.dhcp.state).toBe("failed");
    expect(net.trace.filter((e) => e.kind === "dhcp.discover.sent")).toHaveLength(DHCP_MAX_ATTEMPTS);
    expect(net.trace.filter((e) => e.kind === "dhcp.disabled")).toHaveLength(DHCP_MAX_ATTEMPTS);
    expect(net.now).toBe(DHCP_TIMEOUT * DHCP_MAX_ATTEMPTS);

    // IP 없이 ping → 즉시 실패
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "192.168.0.1" });
    net.runToIdle();
    expect(pc1.pings.at(-1)).toMatchObject({ status: "failed", reason: "IP 미설정" });

    // 수동 설정 후 라우터 ping 성공
    pc1.configure({ ipMode: "static", ip: "192.168.0.50", prefix: 24, gateway: "192.168.0.1" }, net.contextFor("pc1"));
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "192.168.0.1" });
    net.runToIdle();
    expect(pc1.pings.at(-1)).toMatchObject({ status: "ok", rtt: 80 });
    expect(net.pendingEvents).toBe(0);
  });

  it("실패 후 DHCP 를 켜고 다시 요청하면 주소를 받는다", () => {
    const net = buildHomeLan(false);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    const rt = net.nodes.get("rt") as Router;
    rt.configure({ lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.101" }, wan: { mode: "dhcp" } }, net.contextFor("rt"));
    net.scheduleAction(net.now, { kind: "dhcp-renew", nodeId: "pc1" });
    net.runToIdle();
    expect(net.getHost("pc1").ip).toBe("192.168.0.100");
  });

  it("케이블을 뽑으면 주소를 잃고, 다시 꽂으면 같은 주소를 받는다", () => {
    const net = buildHomeLan();
    const link = net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.disconnect(link.id);
    const pc1 = net.getHost("pc1");
    expect(pc1.ip).toBeUndefined();
    expect(pc1.linkUp).toBe(false);
    expect(net.trace.some((e) => e.kind === "dhcp.release")).toBe(true);

    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    expect(pc1.ip).toBe("192.168.0.100");
  });

  it("전송 중에 케이블이 빠지면 프레임이 손실되고 클라이언트는 재시도한다", () => {
    const net = buildHomeLan();
    const link = net.connect("pc1", 0, "sw", 1);
    // Discover 가 링크 위에 있는 동안(0~10ms) 케이블 제거
    net.runUntil(5);
    net.disconnect(link.id);
    net.runToIdle();
    expect(net.trace.some((e) => e.kind === "link.lost")).toBe(true);
    expect(net.trace.some((e) => e.nodeId === "sw" && e.kind === "frame.receive")).toBe(false);
    expect(net.getHost("pc1").dhcp.state).toBe("idle");
  });

  it("DHCP 로 받은 호스트끼리 ping 이 된다 (ARP 포함)", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1);
    net.connect("pc2", 0, "sw", 2);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "192.168.0.101" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)).toMatchObject({ status: "ok" });
  });

  it("호스트를 제거하면 케이블도 사라지고 남은 이벤트가 그 노드로 배달되지 않는다", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1);
    net.runUntil(5);
    net.removeNode("pc1");
    expect(net.links.size).toBe(1);
    expect(() => net.runToIdle()).not.toThrow();
    expect(net.nodes.has("pc1")).toBe(false);
  });
});

describe("DHCP 서브넷 변경", () => {
  it("LAN 주소를 바꾸면 옛 임대는 무효화되고 다시 요청 시 새 서브넷 주소를 받는다", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    expect(net.getHost("pc1").ip).toBe("192.168.0.100");

    const rt = net.nodes.get("rt") as Router;
    rt.configure(
      { lanIp: "192.168.127.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.127.100", end: "192.168.127.101" }, wan: { mode: "dhcp" } },
      net.contextFor("rt"),
    );
    expect(rt.leases.size).toBe(0);
    expect(net.trace.some((e) => e.kind === "dhcp.lease" && e.summary.includes("무효화"))).toBe(true);

    net.scheduleAction(net.now, { kind: "dhcp-renew", nodeId: "pc1" });
    net.runToIdle();
    const pc1 = net.getHost("pc1");
    expect(pc1.ip).toBe("192.168.127.100");
    expect(pc1.iface.gateway).toBe("192.168.127.1");
  });

  it("LAN 주소만 바뀌고 범위가 옛 서브넷에 남아 있으면 설정 오류로 응답하지 않는다", () => {
    const net = buildHomeLan();
    const rt = net.nodes.get("rt") as Router;
    rt.configure({ lanIp: "192.168.127.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.101" }, wan: { mode: "dhcp" } }, net.contextFor("rt"));
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    expect(net.getHost("pc1").ip).toBeUndefined();
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "dhcp.misconfigured")).toBe(true);
  });
});
