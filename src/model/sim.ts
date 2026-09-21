// 편집 중인 토폴로지를 항상 살아 있는 시뮬레이션(Network)에 동기화하고, 시뮬레이션 시계를 돌린다.
// 순수 로직은 netSync.ts(diff 동기화) · simClock.ts(시계) · status.ts(표시 문구) 에 있고, 여기는 신호와 rAF 만 다룬다.
import { effect, signal } from "@preact/signals";
import type { ActionSpec, Transmission } from "../core/network";
import type { SimNode } from "../core/nodes/node";
import { NetworkSync } from "./netSync";
import { advanceClock, EVENT_BURST_LIMIT, settleTimeOf } from "./simClock";
import { hostStatusOf, serviceBadgesOf, wanStatusOf, type StatusLine } from "./status";
import { topology } from "./store";
import { DEVICE_SPECS, type Topology } from "./topology";

const TRACE_CAP = 4000;

/** 화면에 보이는 시뮬레이션 시각. 이벤트 사이를 부드럽게 이동하며, 조용할 때는 멈춘다 */
export const simTime = signal(0);
export const running = signal(true);
export const speed = signal(1);
/** 트레이스나 노드 상태가 바뀔 때마다 증가 → 패널이 다시 읽는다 */
export const simVersion = signal(0);
/** 사용자에게 보여줄 시뮬레이션 알림 (폭주 정지, 내부 오류) */
export const simNotice = signal<string | null>(null);

class SimController {
  private readonly syncer = new NetworkSync();
  private lastFrame = 0;

  get net() {
    return this.syncer.net;
  }

  constructor() {
    effect(() => this.sync(topology.value));
    requestAnimationFrame(this.frame);
  }

  /** 시계와 로그를 0 으로 되돌리고 현재 토폴로지로 다시 시작 */
  reset(): void {
    this.syncer.reset();
    simTime.value = 0;
    this.sync(topology.peek());
  }

  /** 케이블에서 다음 프레임 1개를 손실시킨다 (실험) */
  dropNext(cableId: string): void {
    this.net.dropNextOn(cableId);
    this.bump();
  }

  private sync(t: Topology): void {
    if (this.syncer.sync(t, () => this.settleTime())) this.bump();
  }

  // ---------- 시계 ----------

  private readonly frame = (ts: number): void => {
    const dt = this.lastFrame ? Math.min(100, ts - this.lastFrame) : 0;
    this.lastFrame = ts;
    if (running.value) {
      try {
        this.advance(dt);
      } catch (e) {
        console.error("simulation error", e);
        running.value = false;
        simNotice.value = `시뮬레이션 내부 오류로 일시정지했습니다: ${e instanceof Error ? e.message : String(e)}`;
      }
    }
    requestAnimationFrame(this.frame);
  };

  private advance(dtMs: number): void {
    const r = advanceClock(this.net, simTime.peek(), dtMs, speed.peek());
    if (!r) return;
    if (r.burst) {
      running.value = false;
      simNotice.value = `이벤트가 폭주해 일시정지했습니다 (한 번에 ${EVENT_BURST_LIMIT}개 초과). 케이블이 두 경로로 이어진 L2 루프가 있는지 확인하세요`;
    }
    simTime.value = r.time;
    if (r.changed) this.bump();
    this.net.pruneTransmissions(r.time - 5000);
  }

  /** 일시정지 상태에서 이벤트 하나 진행 */
  step(): void {
    const net = this.net;
    if (net.peekNextTime() === undefined) return;
    net.step();
    simTime.value = net.now;
    this.bump();
  }

  act(action: ActionSpec): void {
    const net = this.net;
    net.runUntil(this.settleTime());
    net.scheduleAction(net.now, action);
    net.runUntil(net.now);
    this.bump();
  }

  private settleTime(): number {
    const t = settleTimeOf(this.net, simTime.peek());
    if (t !== simTime.peek()) simTime.value = t;
    return t;
  }

  clearLog(): void {
    this.net.trace.length = 0;
    this.bump();
  }

  private bump(): void {
    if (this.net.trace.length > TRACE_CAP) this.net.trace.splice(0, this.net.trace.length - TRACE_CAP + 500);
    simVersion.value = simVersion.peek() + 1;
  }

  // ---------- 조회 ----------

  node(id: string): SimNode | undefined {
    return this.net.nodes.get(id);
  }

  inFlight(): Transmission[] {
    return this.net.inFlight(simTime.peek());
  }
}

export const sim = new SimController();

export function togglePlay(): void {
  running.value = !running.value;
}

/** 호스트의 화면 표시용 주소 상태 */
export function hostStatus(id: string): StatusLine | null {
  const kind = topology.peek().devices.find((d) => d.id === id)?.kind ?? "pc";
  return hostStatusOf(sim.node(id), !!DEVICE_SPECS[kind].ports[0]?.radio);
}

/** 타일에 붙는 서비스 배지: 어느 상자에서 어떤 소프트웨어가 도는지 */
export function serviceBadges(id: string): string[] {
  return serviceBadgesOf(sim.node(id));
}

/** 라우터 타일의 WAN 줄 */
export function wanStatus(id: string): StatusLine | null {
  return wanStatusOf(sim.node(id));
}
