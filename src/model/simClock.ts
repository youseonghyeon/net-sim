// 애니메이션 시계: 패킷이 링크 위에 있을 때만 흐르고, 대기 이벤트만 있으면 그 시각으로 점프, 아무것도 없으면 정지.
// 신호·DOM 에 의존하지 않아 유닛 테스트가 가능하다.
import type { Network } from "../core/network";

/** 1x 재생 속도에서 실제 1초당 흐르는 시뮬레이션 시간(ms). 링크 10ms 가 0.4초 */
export const BASE_RATE = 25;
/** 한 화면 프레임에 처리할 수 있는 이벤트 상한. 넘으면 폭주로 보고 일시정지 */
export const EVENT_BURST_LIMIT = 4000;

export interface ClockResult {
  /** 새 표시 시각 */
  time: number;
  /** 이벤트를 하나라도 처리했는지 */
  changed: boolean;
  /** 이벤트 상한을 넘겨 중단했는지 (호출자가 일시정지한다) */
  burst: boolean;
}

/**
 * 화면 프레임 하나만큼 시계를 진행한다.
 * @param time 현재 표시 시각
 * @param dtMs 실제 경과 시간(ms)
 * @returns 조용해서(대기 이벤트도, 움직이는 패킷도 없음) 아무것도 하지 않았으면 null
 */
export function advanceClock(net: Network, time: number, dtMs: number, speed: number, burstLimit = EVENT_BURST_LIMIT): ClockResult | null {
  if (net.peekNextTime() === undefined && net.inFlight(time).length === 0) return null; // 조용함: 시계 정지
  let t = time + (dtMs * BASE_RATE * speed) / 1000;
  let changed = false;
  let processed = 0;
  for (;;) {
    const next = net.peekNextTime();
    if (next === undefined) break;
    if (next > t) {
      if (net.inFlight(t).length > 0) break; // 패킷이 움직이는 중이면 애니메이션을 기다린다
      t = next; // 아무것도 안 움직이면 다음 이벤트로 점프
    }
    net.step();
    changed = true;
    if (++processed > burstLimit) return { time: net.now, changed, burst: true };
  }
  return { time: t, changed, burst: false };
}

/** 사용자 개입 시각: 애니메이션 시계를 정수 ms 로 올려서 이후 이벤트 시각이 깔끔하게 떨어지게 한다 */
export function settleTimeOf(net: Network, shown: number): number {
  return Math.max(net.now, Math.ceil(shown));
}
