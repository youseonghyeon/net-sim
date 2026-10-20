// ARP timeout 은 그 timer 를 건 인터페이스의 대기열만 버린다 — 장치는 인터페이스마다 onArpTimeout 을 부르므로
// (공유기 LAN·WAN, 게이트웨이의 여러 인터페이스) 같은 주소를 기다리던 다른 인터페이스의 패킷이 먼저 버려지면 안 된다
import { describe, expect, it } from "vitest";
import { NetInterface } from "../src/core/nodes/iface";
import type { NodeContext } from "../src/core/nodes/node";
import type { Ipv4Packet } from "../src/core/packet";

function fakeCtx() {
  const timers: { tag: string; data: unknown }[] = [];
  const ctx: NodeContext = {
    now: 0,
    send: () => {},
    isPortConnected: () => true,
    timer: (_d, tag, data) => {
      timers.push({ tag, data });
      return { cancel: () => {} };
    },
    trace: () => {},
    nextPacketId: () => 1,
  };
  return { ctx, timers };
}

const ping = (src: string, dst: string): Ipv4Packet => ({ kind: "ipv4", src, dst, ttl: 64, payload: { kind: "icmp", type: "echo-request", id: 1, seq: 1 } });

describe("ARP timeout", () => {
  it("다른 인터페이스가 같은 주소를 기다리는 대기열은 그대로 둔다", () => {
    const { ctx, timers } = fakeCtx();
    const a = new NetInterface("02:00:00:00:00:0a", { ip: "10.0.0.1", prefix: 24 });
    const b = new NetInterface("02:00:00:00:00:0b", { ip: "10.0.0.2", prefix: 24 });
    a.sendIp(ping("10.0.0.1", "10.0.0.9"), ctx, () => {});
    b.sendIp(ping("10.0.0.2", "10.0.0.9"), ctx, () => {});
    const [ta] = timers.filter((t) => t.tag === "arp-timeout");
    // a 의 timer 가 울림: 장치는 모든 인터페이스에 넘긴다
    expect(a.onArpTimeout(ta!.data, ctx)).toHaveLength(1);
    expect(b.onArpTimeout(ta!.data, ctx)).toHaveLength(0);
    expect(b.pending.get("10.0.0.9")).toHaveLength(1);
  });
});
