// 배경 타이머: 스스로 시계를 움직이지 않고, 다른 일로 시간이 그 시각을 지나갈 때만 발화한다 (주기 광고·헬스 체크·DPD 용)
import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import type { EthernetFrame } from "../src/core/packet";
import type { NodeContext, NodeSnapshot, SimNode, TimerHandle } from "../src/core/nodes/node";
import { advanceClock } from "../src/model/simClock";

/** 배경 타이머를 1초마다 다시 거는 장치 (주기 광고 흉내). 일반 타이머도 걸 수 있다 */
class Ticker implements SimNode {
  readonly type = "host" as const;
  readonly portCount = 1;
  readonly fired: { tag: string; at: number }[] = [];
  handle?: TimerHandle;
  constructor(readonly id: string) {}
  receive(_port: number, _frame: EthernetFrame, ctx: NodeContext): void {
    this.fired.push({ tag: "rx", at: ctx.now });
  }
  start(ctx: NodeContext): void {
    this.handle = ctx.timer(1000, "tick", undefined, true);
  }
  onTimer(tag: string, _data: unknown, ctx: NodeContext): void {
    this.fired.push({ tag, at: ctx.now });
    if (tag === "tick") this.handle = ctx.timer(1000, "tick", undefined, true);
    if (tag === "send") ctx.send(0, { kind: "ethernet", id: ctx.nextPacketId(), src: "02:00:00:00:00:01", dst: "ff:ff:ff:ff:ff:ff", payload: { kind: "arp", op: "request", senderMac: "02:00:00:00:00:01", senderIp: "10.0.0.1", targetMac: "00:00:00:00:00:00", targetIp: "10.0.0.2" } });
  }
  snapshot(): NodeSnapshot {
    return { id: this.id, type: this.type, label: this.id, info: [], tables: [] };
  }
}

function setup() {
  const net = new Network();
  const a = net.addNode(new Ticker("a"));
  const b = net.addNode(new Ticker("b"));
  net.connect("a", 0, "b", 0);
  // ctx 는 Network 안에서만 만든다: 타이머를 거는 일반 이벤트를 하나 넣어 그 안에서 시작
  const ctxOf = (id: string) => (net as unknown as { ctx(id: string): NodeContext }).ctx(id);
  a.start(ctxOf("a"));
  return { net, a, b, ctxOf };
}
const ticks = (t: Ticker) => t.fired.filter((f) => f.tag === "tick").map((f) => f.at);

describe("배경 타이머", () => {
  it("조용하면 시계가 가지 않는다: runToIdle 은 배경 타이머만 남으면 멈추고, advanceClock 도 정지", () => {
    const { net, a } = setup();
    expect(net.runToIdle()).toBe(0);
    expect(ticks(a)).toEqual([]);
    expect(net.now).toBe(0);
    expect(advanceClock(net, 0, 16, 1)).toBeNull();
    expect(net.peekBackgroundTime()).toBe(1000);
  });

  it("runUntil 로 시간을 흘려보내면 그 사이 배경 타이머가 차례로 발화한다", () => {
    const { net, a } = setup();
    net.runUntil(3500);
    expect(ticks(a)).toEqual([1000, 2000, 3000]);
    expect(net.now).toBe(3500);
  });

  it("일반 이벤트가 시간을 밀면 그보다 이른 배경 타이머가 먼저 발화하고, 같은 시각이면 일반 이벤트 먼저", () => {
    const { net, a, ctxOf } = setup();
    ctxOf("a").timer(2500, "normal");
    ctxOf("a").timer(2000, "same");
    net.runToIdle();
    expect(a.fired.map((f) => `${f.tag}@${f.at}`)).toEqual(["tick@1000", "same@2000", "tick@2000", "normal@2500"]);
    // 마지막 일반 이벤트 뒤로는 가지 않는다
    expect(net.now).toBe(2500);
  });

  it("취소한 배경 타이머와 지운 장치의 배경 타이머는 발화하지 않는다", () => {
    const { net, a, b, ctxOf } = setup();
    a.handle!.cancel();
    const h = ctxOf("b");
    b.start(h);
    net.removeNode("b");
    net.runUntil(5000);
    expect(ticks(a)).toEqual([]);
    expect(ticks(b)).toEqual([]);
    expect(net.peekBackgroundTime()).toBeUndefined();
  });

  it("애니메이션 중(패킷이 링크 위) 시계가 지나간 배경 타이머는 그 프레임에 발화한다", () => {
    const { net, a, b, ctxOf } = setup();
    // 링크 지연을 길게: 1초 넘게 걸리는 프레임
    const link = [...net.links.values()][0]!;
    link.latency = 1500;
    ctxOf("a").timer(0, "send");
    net.step(); // send 처리: 프레임이 링크 위로
    expect(net.inFlight(net.now)).toHaveLength(1);
    // 1x 에서 1초 = 40초 실제라 크게 진행: 1200ms 까지 (도착 1500 전)
    const r = advanceClock(net, net.now, (1200 * 1000) / 25, 1)!;
    expect(r.time).toBeCloseTo(1200);
    expect(ticks(a)).toEqual([1000]);
    expect(b.fired).toEqual([]);
    const r2 = advanceClock(net, r.time, (400 * 1000) / 25, 1)!;
    expect(r2.changed).toBe(true);
    expect(b.fired.map((f) => f.at)).toEqual([1500]);
  });

  it("runUntil 의 이벤트 상한을 넘으면 예외 (시간 흘려보내기 중 폭주 방지)", () => {
    const { net } = setup();
    expect(() => net.runUntil(100_000, 10)).toThrow(/exceeded 10 events/);
  });
});
