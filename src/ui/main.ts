import type { ActionSpec, Network } from "../core/network";
import type { Scenario } from "../core/scenarios/index";
import { scenarios } from "../core/scenarios/singleSubnet";
import { $, esc } from "./dom";
import { InspectorView } from "./inspector";
import { LogView } from "./log";
import { TopologyView } from "./topology";

/** 1x 재생 속도에서 실제 1초당 흐르는 시뮬레이션 시간(ms) */
const BASE_RATE = 25;

class App {
  private scenario: Scenario;
  private net: Network;
  /** 화면에 표시 중인 시뮬레이션 시각. net.now 와 다음 이벤트 사이를 부드럽게 이동 */
  private viewTime = 0;
  private playing = false;
  private speed = 1;
  private activeNode: string | undefined;
  private lastFrameTs = 0;

  private readonly topology = new TopologyView();
  private readonly inspector = new InspectorView();
  private readonly log = new LogView(() => this.renderPanels());

  private readonly btnPlay = $<HTMLButtonElement>("#btn-play");
  private readonly clock = $("#clock");

  constructor() {
    this.scenario = scenarios[0]!;
    this.net = this.scenario.build();
    this.bind();
    this.reset();
    requestAnimationFrame(this.frame);
  }

  // ---------- 상태 전이 ----------

  private reset(): void {
    this.net = this.scenario.build();
    this.viewTime = 0;
    this.playing = false;
    this.activeNode = undefined;
    this.inspector.reset();
    this.log.reset();
    this.topology.rebuild(this.net, this.scenario.layout);
    this.renderQuickActions();
    $("#scenario-desc").textContent = this.scenario.description;
    this.renderPanels();
    this.syncPlayButton();
  }

  private doAction(spec: ActionSpec): void {
    const t = Math.max(this.viewTime, this.net.now);
    this.viewTime = t;
    const from = this.net.trace.length;
    this.net.scheduleAction(t, spec);
    this.net.runUntil(t);
    this.afterStep(from);
  }

  private stepNext(): void {
    if (this.net.peekNextTime() === undefined) return;
    const from = this.net.trace.length;
    this.net.step();
    this.viewTime = this.net.now;
    this.afterStep(from);
  }

  /** 되감기: 시나리오를 다시 만들고 기록된 동작을 재투입한 뒤 (현재-1) 개 이벤트까지 재실행 */
  private stepPrev(): void {
    const target = this.net.eventCount - 1;
    if (target < 0) return;
    const fresh = this.scenario.build();
    for (const a of this.net.actions) fresh.scheduleAction(a.time, a.action);
    let from = 0;
    for (let i = 0; i < target; i++) {
      from = fresh.trace.length;
      fresh.step();
    }
    this.net = fresh;
    this.viewTime = fresh.now;
    this.playing = false;
    this.inspector.reset();
    this.log.reset();
    this.afterStep(from);
    this.syncPlayButton();
  }

  private togglePlay(): void {
    if (!this.playing && this.net.peekNextTime() === undefined && this.net.inFlight(this.viewTime).length === 0) return;
    this.playing = !this.playing;
    this.syncPlayButton();
  }

  /** 재생 중 매 프레임: viewTime 을 전진시키고 지나친 이벤트를 처리. 아무것도 안 움직이면 다음 이벤트로 점프 */
  private advance(dtMs: number): void {
    this.viewTime += (dtMs * BASE_RATE * this.speed) / 1000;
    let from = -1;
    for (;;) {
      const next = this.net.peekNextTime();
      const idle = this.net.inFlight(this.viewTime).length === 0;
      if (next === undefined) {
        if (idle) {
          this.viewTime = this.net.now;
          this.playing = false;
          this.syncPlayButton();
        }
        break;
      }
      if (next > this.viewTime) {
        if (!idle) break;
        this.viewTime = next;
      }
      from = this.net.trace.length;
      this.net.step();
    }
    if (from >= 0) this.afterStep(from);
  }

  private afterStep(traceFrom: number): void {
    if (this.net.trace.length > traceFrom) this.activeNode = this.net.trace.at(-1)?.nodeId;
    this.log.currentFrom = traceFrom;
    this.renderPanels();
  }

  // ---------- 렌더 ----------

  private renderPanels(): void {
    this.inspector.render(this.net, this.activeNode);
    this.log.render(this.net);
  }

  private renderQuickActions(): void {
    const wrap = $("#quick-actions");
    wrap.innerHTML = this.scenario.quickActions.map((q, i) => `<button class="action" data-i="${i}">${esc(q.label)}</button>`).join("");
  }

  private syncPlayButton(): void {
    this.btnPlay.textContent = this.playing ? "⏸ 일시정지" : "▶ 재생";
    this.btnPlay.classList.toggle("active", this.playing);
  }

  private readonly frame = (ts: number): void => {
    const dt = this.lastFrameTs ? Math.min(100, ts - this.lastFrameTs) : 0;
    this.lastFrameTs = ts;
    if (this.playing) this.advance(dt);
    this.topology.update(this.net.inFlight(this.viewTime), this.viewTime, this.activeNode);
    this.clock.textContent = `t = ${Math.round(this.viewTime)} ms · 이벤트 ${this.net.eventCount} · 대기 ${this.net.pendingEvents}`;
    requestAnimationFrame(this.frame);
  };

  // ---------- 입력 ----------

  private bind(): void {
    const sel = $<HTMLSelectElement>("#scenario");
    sel.innerHTML = scenarios.map((s) => `<option value="${esc(s.id)}">${esc(s.title)}</option>`).join("");
    sel.addEventListener("change", () => {
      this.scenario = scenarios.find((s) => s.id === sel.value) ?? scenarios[0]!;
      this.reset();
    });

    $("#quick-actions").addEventListener("click", (e) => {
      const btn = (e.target as HTMLElement).closest<HTMLButtonElement>("button[data-i]");
      if (!btn) return;
      const q = this.scenario.quickActions[Number(btn.dataset.i)];
      if (q) this.doAction(q.action);
    });

    $("#btn-reset").addEventListener("click", () => this.reset());
    $("#btn-prev").addEventListener("click", () => this.stepPrev());
    $("#btn-next").addEventListener("click", () => this.stepNext());
    this.btnPlay.addEventListener("click", () => this.togglePlay());
    const speed = $<HTMLSelectElement>("#speed");
    speed.addEventListener("change", () => (this.speed = Number(speed.value)));

    window.addEventListener("keydown", (e) => {
      if ((e.target as HTMLElement).tagName === "SELECT") return;
      switch (e.key) {
        case " ":
          e.preventDefault();
          this.togglePlay();
          break;
        case "ArrowRight":
          this.stepNext();
          break;
        case "ArrowLeft":
          this.stepPrev();
          break;
        case "r":
        case "R":
          this.reset();
          break;
      }
    });
  }
}

new App();
