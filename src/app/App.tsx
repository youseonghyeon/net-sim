import { useSignal } from "@preact/signals";
import { useEffect, useRef } from "preact/hooks";
import { running, sim, simNotice, simTime, speed, togglePlay } from "../model/sim";
import { clearAll, loadExample, removeSelected, theme, toggleTheme, topology } from "../model/store";
import { Canvas } from "./Canvas";
import { Icon } from "./Icons";
import { Inspector } from "./Inspector";
import { LogDrawer } from "./LogDrawer";
import { Palette } from "./Palette";

export function App() {
  const notice = useSignal<string | null>(null);
  const timer = useRef<number>(0);

  function showNotice(msg: string): void {
    notice.value = msg;
    clearTimeout(timer.current);
    timer.current = window.setTimeout(() => (notice.value = null), 2600);
  }

  useEffect(() => {
    // 시뮬레이션 쪽 알림은 토스트로 (자동으로 사라지지 않게 길게)
    return simNotice.subscribe((msg) => {
      if (msg) {
        notice.value = msg;
        clearTimeout(timer.current);
        timer.current = window.setTimeout(() => {
          notice.value = null;
          simNotice.value = null;
        }, 8000);
      }
    });
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT") return;
      if (e.key === "Delete" || e.key === "Backspace") {
        e.preventDefault();
        removeSelected();
      } else if (e.key === " ") {
        e.preventDefault();
        togglePlay();
      } else if (e.key === "." || e.key === "ArrowRight") {
        if (!running.value) sim.step();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const t = topology.value;
  const isRunning = running.value;
  return (
    <div class="app">
      <header class="topbar">
        <div class="brand">
          <Icon name="mark" size={18} />
          <span>net-sim</span>
        </div>
        <div class="topbar-center">
          <div class="transport">
            <button class="icon-btn" onClick={togglePlay} title={isRunning ? "일시정지 (Space)" : "재생 (Space)"}>
              <Icon name={isRunning ? "pause" : "play"} size={18} />
            </button>
            <button class="icon-btn" onClick={() => sim.step()} disabled={isRunning} title="다음 이벤트 (→)">
              <Icon name="step" size={18} />
            </button>
            <select class="speed" value={String(speed.value)} onChange={(e) => (speed.value = Number(e.currentTarget.value))} title="재생 속도">
              <option value="0.5">0.5×</option>
              <option value="1">1×</option>
              <option value="2">2×</option>
              <option value="4">4×</option>
            </select>
            <span class="clock mono" title="시뮬레이션 시각. 패킷이 움직일 때만 흐릅니다">
              {Math.round(simTime.value).toLocaleString()} ms
            </span>
          </div>
        </div>
        <div class="topbar-right">
          <span class="doc-meta">
            장치 {t.devices.length} · 케이블 {t.cables.length}
          </span>
          <span class="vsep" />
          <select
            class="btn ghost example"
            value=""
            onChange={(e) => {
              const v = e.currentTarget.value as "" | "router" | "parts" | "vlan";
              e.currentTarget.value = "";
              if (!v) return;
              loadExample(v);
              sim.reset();
            }}
            title="예제 네트워크 불러오기"
          >
            <option value="">예제 불러오기</option>
            <option value="router">공유기 하나로 (라우터 + 포트 포워딩)</option>
            <option value="parts">기능 단위로 (NAT + 게이트웨이 + DHCP/DNS 서버)</option>
            <option value="vlan">VLAN 으로 나눈 사무실 (트렁크 + 서브 인터페이스)</option>
          </select>
          <button
            class="btn ghost"
            onClick={() => {
              clearAll();
              sim.reset();
            }}
            disabled={t.devices.length === 0}
          >
            비우기
          </button>
          <button class="icon-btn" onClick={toggleTheme} title={theme.value === "dark" ? "라이트 테마" : "다크 테마"}>
            <Icon name={theme.value === "dark" ? "sun" : "moon"} size={18} />
          </button>
        </div>
      </header>
      <div class="body">
        <Palette />
        <Canvas onNotice={showNotice} />
        <Inspector />
      </div>
      <LogDrawer />
      {notice.value && <div class="toast">{notice.value}</div>}
    </div>
  );
}
