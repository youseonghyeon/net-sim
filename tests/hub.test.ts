import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { Host } from "../src/core/nodes/host";
import { Hub } from "../src/core/nodes/hub";
import type { EthernetFrame } from "../src/core/packet";

/** 호스트 3대(정적 IP)가 4포트 허브 하나에 물린 서브넷. Gratuitous ARP 가 끝난 뒤 상태 */
function settledStar() {
  const net = new Network();
  const hub = net.addNode(new Hub("hub", 4));
  net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "10.0.0.1", prefix: 24 }));
  net.addNode(new Host({ id: "b", mac: "02:00:00:00:00:0b", ipMode: "static", ip: "10.0.0.2", prefix: 24 }));
  net.addNode(new Host({ id: "c", mac: "02:00:00:00:00:0c", ipMode: "static", ip: "10.0.0.3", prefix: 24 }));
  net.connect("a", 0, "hub", 0);
  net.connect("b", 0, "hub", 1);
  net.connect("c", 0, "hub", 2);
  net.runToIdle();
  return { net, hub };
}

describe("Hub", () => {
  it("유니캐스트 ping 응답도 모든 포트로 반복돼 제3의 호스트가 받고 버린다 (학습 없음)", () => {
    const { net, hub } = settledStar();
    const from = net.trace.length;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "10.0.0.2" });
    net.runToIdle();

    expect(net.getHost("a").pings.at(-1)?.status).toBe("ok");
    expect(net.pendingEvents).toBe(0);

    // b → a 유니캐스트 ICMP 응답이 c 에게도 배달됐다
    expect(
      net.transmissions.some(
        (t) => t.to.node === "c" && t.frame.payload.kind === "ipv4" && t.frame.payload.payload.kind === "icmp" && t.frame.payload.payload.type === "echo-reply",
      ),
    ).toBe(true);
    // c 는 "내 MAC 아님" 으로 폐기
    const after = net.trace.slice(from);
    expect(after.some((e) => e.nodeId === "c" && e.kind === "frame.drop" && e.summary.includes("내 MAC"))).toBe(true);

    // 허브 트레이스만 있고 스위치식 학습/전달은 없다
    expect(after.some((e) => e.nodeId === "hub" && e.kind === "hub.repeat")).toBe(true);
    expect(net.trace.some((e) => e.kind === "switch.learn")).toBe(false);
    expect(net.trace.some((e) => e.kind === "switch.forward")).toBe(false);
    expect(net.trace.some((e) => e.kind === "switch.flood")).toBe(false);

    // 스냅샷: MAC 테이블 없음
    const snap = hub.snapshot();
    expect(snap.type).toBe("hub");
    expect(snap.tables).toEqual([]);
    expect(snap.info).toContainEqual(["MAC 테이블", "없음 (허브는 학습하지 않음)"]);
  });

  it("출발지 포트만 연결돼 있으면 반복할 포트가 없다고 기록하고 아무것도 보내지 않는다", () => {
    const net = new Network();
    const hub = net.addNode(new Hub("hub", 4));
    net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "10.0.0.1", prefix: 24 }));
    net.connect("a", 0, "hub", 0);
    net.runToIdle(); // Gratuitous ARP 가 허브까지 도달

    const frame: EthernetFrame = {
      kind: "ethernet",
      id: 9999,
      src: "02:00:00:00:00:0a",
      dst: "ff:ff:ff:ff:ff:ff",
      payload: { kind: "arp", op: "request", senderMac: "02:00:00:00:00:0a", senderIp: "10.0.0.1", targetMac: "00:00:00:00:00:00", targetIp: "10.0.0.2" },
    };
    const before = net.transmissions.length;
    const traceFrom = net.trace.length;
    hub.receive(0, frame, net.contextFor("hub"));

    const repeats = net.trace.slice(traceFrom).filter((e) => e.nodeId === "hub" && e.kind === "hub.repeat");
    expect(repeats).toHaveLength(1);
    expect(repeats[0]!.summary).toContain("반복할 포트 없음");
    expect(net.transmissions.slice(before).filter((t) => t.from.node === "hub")).toHaveLength(0);
    expect(net.trace.slice(traceFrom).some((e) => e.kind === "link.unconnected")).toBe(false);
  });

  it("허브 두 대를 케이블 두 개로 이어 루프를 만들어도 폭주하지 않는다 (스위치와 같은 루프 안전장치)", () => {
    const net = new Network();
    net.addNode(new Hub("h1", 4));
    net.addNode(new Hub("h2", 4));
    net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "10.0.0.1", prefix: 24 }));
    net.addNode(new Host({ id: "b", mac: "02:00:00:00:00:0b", ipMode: "static", ip: "10.0.0.2", prefix: 24 }));
    net.connect("h1", 0, "h2", 0);
    net.connect("h1", 1, "h2", 1); // 루프
    net.connect("a", 0, "h1", 2);
    net.connect("b", 0, "h2", 2);
    net.runToIdle(20_000);
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "10.0.0.2" });
    const events = net.runToIdle(20_000);
    expect(events).toBeLessThan(2000);
    expect(net.getHost("a").pings.at(-1)?.status).toBe("ok");
    expect(net.trace.some((e) => e.kind === "switch.loop")).toBe(true);
    expect(net.pendingEvents).toBe(0);
  });
});
