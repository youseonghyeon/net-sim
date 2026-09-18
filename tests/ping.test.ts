import { describe, expect, it } from "vitest";
import { NetInterface } from "../src/core/nodes/iface";
import { singleSubnet } from "../src/core/scenarios/singleSubnet";
import type { TraceKind } from "../src/core/trace";

function kinds(net: ReturnType<typeof singleSubnet.build>, filter?: (k: TraceKind) => boolean, from = 0): string[] {
  return net.trace.slice(from).filter((e) => !filter || filter(e.kind)).map((e) => `${e.nodeId}:${e.kind}`);
}

/** 케이블 연결 직후의 Gratuitous ARP 가 끝난 뒤의 네트워크 */
function settled() {
  const net = singleSubnet.build();
  net.runToIdle();
  return net;
}

describe("단일 서브넷 ping", () => {
  it("첫 ping: ARP 요청/응답 후 ICMP 왕복, 캐시와 MAC 테이블이 채워진다", () => {
    const net = settled();
    const from = net.trace.length;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "h1", dst: "10.0.0.2" });
    net.runToIdle();

    const h1 = net.getHost("h1");
    const h2 = net.getHost("h2");
    const h3 = net.getHost("h3");
    expect(h1.arpCache.get("10.0.0.2")?.mac).toBe("02:00:00:00:00:02");
    expect(h2.arpCache.get("10.0.0.1")?.mac).toBe("02:00:00:00:00:01"); // 요청의 보낸이 정보에서 학습
    expect(h3.arpCache.size).toBe(0); // 자기 IP 아닌 ARP 요청은 학습하지 않음
    expect(h1.pending.size).toBe(0);

    // 케이블 연결 시 Gratuitous ARP 로 세 호스트 모두 MAC 테이블에 학습돼 있다
    const sw = net.nodes.get("sw1")!.snapshot();
    expect(sw.tables[0]!.rows.map((r) => r[0]).sort()).toEqual(["02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"]);

    const key = kinds(net, (k) => k.startsWith("arp.") || k.startsWith("icmp.") || k === "switch.flood" || k === "switch.forward", from);
    expect(key).toEqual([
      "h1:icmp.echo.sent",
      "h1:arp.cache.miss",
      "h1:arp.request.sent",
      "sw1:switch.flood",
      "h2:arp.request.received",
      "h2:arp.cache.update",
      "h2:arp.reply.sent",
      "h3:arp.request.received",
      "sw1:switch.forward",
      "h1:arp.reply.received",
      "h1:arp.cache.update",
      "sw1:switch.forward",
      "h2:icmp.echo.received",
      "h2:icmp.reply.sent",
      "h2:arp.cache.hit",
      "sw1:switch.forward",
      "h1:icmp.reply.received",
    ]);

    // RTT = ARP 왕복(40ms) + ICMP 왕복(40ms) 대기 포함 → 80ms
    const done = net.trace.find((e) => e.kind === "icmp.reply.received")!;
    expect(done.details?.rtt).toBe(80);
  });

  it("두 번째 ping 은 ARP 없이 바로 간다", () => {
    const net = singleSubnet.build();
    net.scheduleAction(0, { kind: "ping", nodeId: "h1", dst: "10.0.0.2" });
    net.runToIdle();
    const before = net.trace.length;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "h1", dst: "10.0.0.2" });
    net.runToIdle();
    const after = net.trace.slice(before).map((e) => e.kind);
    expect(after).not.toContain("arp.request.sent");
    expect(after).toContain("arp.cache.hit");
    expect(after.filter((k) => k === "switch.flood")).toHaveLength(0);
    expect(net.trace.at(-1)?.details?.rtt).toBe(40);
    expect(net.pendingEvents).toBe(0);
  });

  it("없는 호스트로 ping → ARP 타임아웃, 대기 패킷 폐기", () => {
    const net = singleSubnet.build();
    net.scheduleAction(0, { kind: "ping", nodeId: "h2", dst: "10.0.0.99" });
    net.runToIdle();
    const timeout = net.trace.find((e) => e.kind === "arp.timeout");
    expect(timeout).toBeDefined();
    expect(timeout!.time).toBe(NetInterface.ARP_TIMEOUT);
    expect(net.trace.some((e) => e.kind === "icmp.failed")).toBe(true);
    expect(net.getHost("h2").pending.size).toBe(0);
    expect(net.getHost("h2").pings.at(-1)?.status).toBe("failed");
    expect(net.trace.some((e) => e.kind === "icmp.reply.received")).toBe(false);
    // ping 타임아웃 타이머는 취소되어 남은 이벤트가 없어야 한다
    expect(net.pendingEvents).toBe(0);
  });

  it("다른 서브넷인데 게이트웨이 없음 → 즉시 폐기, 프레임 송신 없음", () => {
    const net = settled();
    const before = net.transmissions.length;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "h1", dst: "8.8.8.8" });
    net.runToIdle();
    expect(net.trace.some((e) => e.kind === "ip.no-route")).toBe(true);
    expect(net.transmissions).toHaveLength(before);
  });

  it("같은 동작을 같은 시각에 다시 넣으면 결정론적으로 같은 트레이스가 나온다", () => {
    const run = () => {
      const net = singleSubnet.build();
      net.scheduleAction(0, { kind: "ping", nodeId: "h1", dst: "10.0.0.2" });
      net.scheduleAction(5, { kind: "ping", nodeId: "h3", dst: "10.0.0.2" });
      net.runToIdle();
      return net.trace.map((e) => `${e.time}:${e.nodeId}:${e.kind}`);
    };
    expect(run()).toEqual(run());
  });
});
