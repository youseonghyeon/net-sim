// 호스트 리졸버는 물은 서버의 주소에서 온 답만 받는다 (glibc res_send·nslookup "reply from unexpected source").
// 서버가 다른 주소에서 답하면(여러 주소를 가진 공유기가 LAN 주소로 답함) 기다리다 timeout — 시뮬레이션이 그 결함을 덮지 않게
import { describe, expect, it } from "vitest";
import { DnsResolver } from "../src/core/nodes/dns";
import { NetInterface } from "../src/core/nodes/iface";
import type { NodeContext } from "../src/core/nodes/node";

function fakeCtx() {
  const traces: string[] = [];
  const ctx: NodeContext = {
    now: 0,
    send: () => {},
    isPortConnected: () => true,
    timer: () => ({ cancel: () => {} }),
    trace: (_k, _l, summary) => void traces.push(summary),
    nextPacketId: () => 1,
  };
  return { ctx, traces };
}

describe("DnsResolver", () => {
  it("물은 서버가 아닌 주소에서 온 답은 버리고, 물은 서버의 답은 받는다", () => {
    const r = new DnsResolver(new NetInterface("02:00:00:00:00:10", { ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1", dns: "10.0.0.53" }), 0);
    const { ctx, traces } = fakeCtx();
    const got: (string | undefined)[] = [];
    r.lookup("example.com", "A", undefined, ctx, () => {}, (ip) => void got.push(ip));
    const answer = { kind: "dns", id: 0x101, op: "response", name: "example.com", answer: "1.2.3.4" } as const; // 질의 id = seed 0 의 첫 번호
    r.handle(answer, "10.0.0.1", 1, ctx);
    expect(got).toEqual([]);
    expect(traces.some((s) => s.includes("10.0.0.53 가 아닌 10.0.0.1 에서 옴 → 무시"))).toBe(true);
    r.handle(answer, "10.0.0.53", 1, ctx);
    expect(got).toEqual(["1.2.3.4"]);
  });
});
