import { useSignal } from "@preact/signals";
import { useEffect, useRef } from "preact/hooks";
import { running, sim, simNotice, simTime, speed, togglePlay } from "../model/sim";
import {
  canRedo,
  canUndo,
  clearAll,
  copySelected,
  duplicateSelected,
  exportJson,
  importJson,
  INSPECTOR_RAIL,
  inspectorOpen,
  inspectorWidth,
  loadExample,
  paste,
  redo,
  removeSelected,
  selectAll,
  selection,
  theme,
  toggleInspector,
  toggleTheme,
  topology,
  undo,
} from "../model/store";
import { EXAMPLE_LIST, EXAMPLES, type ExampleId } from "../model/topology";
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

  const fileInput = useRef<HTMLInputElement>(null);

  function download(): void {
    const blob = new Blob([exportJson()], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `net-sim-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function upload(file: File): void {
    file.text().then((text) => {
      const r = importJson(text);
      if (r.error) showNotice(`불러오지 못했습니다: ${r.error}`);
      else {
        sim.reset();
        showNotice(`${file.name} 에서 장치 ${r.devices}개를 불러왔습니다.`);
      }
    });
  }

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT") return;
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.key === "\\") {
        e.preventDefault();
        toggleInspector();
      } else if (mod && e.key.toLowerCase() === "z") {
        e.preventDefault();
        if (e.shiftKey) redo();
        else undo();
      } else if (mod && e.key.toLowerCase() === "c") {
        const n = copySelected();
        if (n) showNotice(`장치 ${n}개를 복사했습니다. ⌘V 로 붙여 넣습니다.`);
      } else if (mod && e.key.toLowerCase() === "v") {
        e.preventDefault();
        paste();
      } else if (mod && e.key.toLowerCase() === "d") {
        e.preventDefault();
        duplicateSelected();
      } else if (mod && e.key.toLowerCase() === "a") {
        e.preventDefault();
        selectAll();
      } else if (e.key === "Escape") {
        selection.value = null;
      } else if (e.key === "Delete" || e.key === "Backspace") {
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
          <button class="icon-btn" onClick={undo} disabled={!canUndo.value} title="되돌리기 (⌘Z)">
            <Icon name="undo" size={18} />
          </button>
          <button class="icon-btn" onClick={redo} disabled={!canRedo.value} title="다시 실행 (⌘⇧Z)">
            <Icon name="redo" size={18} />
          </button>
          <select
            class="btn ghost example"
            value=""
            onChange={(e) => {
              const v = e.currentTarget.value as "" | ExampleId;
              e.currentTarget.value = "";
              if (!v) return;
              loadExample(v);
              sim.reset();
              showNotice(EXAMPLES[v].blurb);
            }}
            title="예제 네트워크 불러오기"
          >
            <option value="">예제 불러오기</option>
            {[...new Set(EXAMPLE_LIST.map((x) => x.group))].map((g) => (
              <optgroup key={g} label={g}>
                {EXAMPLE_LIST.filter((x) => x.group === g).map((x) => (
                  <option key={x.id} value={x.id}>
                    {x.label}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
          <button class="icon-btn" onClick={download} disabled={t.devices.length === 0} title="JSON 으로 내려받기">
            <Icon name="download" size={18} />
          </button>
          <button class="icon-btn" onClick={() => fileInput.current?.click()} title="JSON 불러오기">
            <Icon name="upload" size={18} />
          </button>
          <input
            ref={fileInput}
            type="file"
            accept=".json,application/json"
            hidden
            onChange={(e) => {
              const f = e.currentTarget.files?.[0];
              e.currentTarget.value = "";
              if (f) upload(f);
            }}
          />
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
      <div class="body" style={{ "--inspector-w": `${inspectorOpen.value ? inspectorWidth.value : INSPECTOR_RAIL}px` }}>
        <Palette />
        <Canvas onNotice={showNotice} />
        <Inspector />
      </div>
      <LogDrawer />
      {notice.value && <div class="toast">{notice.value}</div>}
    </div>
  );
}
