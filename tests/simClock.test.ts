import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { Host } from "../src/core/nodes/host";
import { Switch } from "../src/core/nodes/switch";
import { buildHomeLan } from "../src/core/scenarios/homeLan";
import { advanceClock, BASE_RATE, settleTimeOf } from "../src/model/simClock";

describe("애니메이션 시계", () => {
  it("대기 이벤트도 움직이는 패킷도 없으면 시계가 멈춘다 (null)", () => {
    const net = new Network();
    expect(advanceClock(net, 0, 16, 1)).toBeNull();
    const lan = buildHomeLan(true, false);
    lan.runToIdle();
    expect(advanceClock(lan, lan.now, 16, 1)).toBeNull();
  });

  it("패킷이 링크 위에 있으면 실제 시간 × 재생 속도만큼만 흐르고, 도착 전에는 이벤트를 앞당기지 않는다", () => {
    const net = buildHomeLan(true, false);
    net.connect("pc1", 0, "sw", 1); // 연결 직후 DHCP Discover 가 10ms 링크 위에 오른다
    net.runUntil(0);
    expect(net.inFlight(0).length).toBeGreaterThan(0);
    const r = advanceClock(net, 0, 100, 1)!; // 100ms 실제 → 2.5ms 시뮬레이션
    expect(r.time).toBeCloseTo((100 * BASE_RATE) / 1000);
    expect(r.changed).toBe(false); // 아직 도착 전
    const r2 = advanceClock(net, r.time, 100, 4)!; // 4배속: +10ms → 첫 배달 처리
    expect(r2.time).toBeCloseTo(r.time + 10);
    expect(r2.changed).toBe(true);
  });

  it("움직이는 패킷 없이 타이머만 기다릴 때는 그 시각으로 점프한다", () => {
    const net = new Network();
    const sw = net.addNode(new Switch("sw", 2));
    void sw;
    net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a" })); // DHCP 서버 없음 → 재시도 타이머만 남는다
    net.connect("a", 0, "sw", 0);
    net.runUntil(50); // Discover 왕복이 끝나고 재시도 타이머만 대기
    expect(net.inFlight(50)).toHaveLength(0);
    const next = net.peekNextTime()!;
    expect(next).toBeGreaterThan(50);
    const r = advanceClock(net, 50, 16, 1)!;
    expect(r.time).toBeGreaterThanOrEqual(next);
    expect(r.changed).toBe(true);
  });

  it("한 프레임의 이벤트가 상한을 넘으면 burst 로 멈추고 시각은 네트워크 현재 시각", () => {
    const net = new Network();
    net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a" }));
    net.addNode(new Host({ id: "b", mac: "02:00:00:00:00:0b" }));
    net.connect("a", 0, "b", 0);
    const r = advanceClock(net, 0, 1000, 1000, 2)!; // 상한 2
    expect(r.burst).toBe(true);
    expect(r.time).toBe(net.now);
  });

  it("사용자 개입 시각은 정수 ms 로 올리고 네트워크 시각보다 뒤로 가지 않는다", () => {
    const net = new Network();
    expect(settleTimeOf(net, 12.3)).toBe(13);
    net.runUntil(40);
    expect(settleTimeOf(net, 12.3)).toBe(40);
  });
});
