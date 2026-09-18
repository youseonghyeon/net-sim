import { useSignal } from "@preact/signals";
import { useEffect, useRef } from "preact/hooks";
import { clearAll, loadExample, logOpen, removeSelected, theme, toggleTheme, topology } from "../model/store";
import { Canvas } from "./Canvas";
import { Icon } from "./Icons";
import { Inspector } from "./Inspector";
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
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT") return;
      if (e.key === "Delete" || e.key === "Backspace") {
        e.preventDefault();
        removeSelected();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const t = topology.value;
  return (
    <div class="app">
      <header class="topbar">
        <div class="brand">
          <Icon name="mark" size={18} />
          <span>net-sim</span>
        </div>
        <div class="topbar-center">
          <span class="doc-title">내 네트워크</span>
          <span class="doc-meta">
            장치 {t.devices.length} · 케이블 {t.cables.length}
          </span>
        </div>
        <div class="topbar-right">
          <button class="btn ghost" onClick={loadExample}>
            예제 불러오기
          </button>
          <button class="btn ghost" onClick={clearAll} disabled={t.devices.length === 0}>
            비우기
          </button>
          <span class="vsep" />
          <button class="btn primary" disabled title="시뮬레이션은 다음 단계에서 켜집니다">
            실행
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
      <footer class={`log${logOpen.value ? " open" : ""}`}>
        <button class="log-head" onClick={() => (logOpen.value = !logOpen.value)}>
          <Icon name="chevron" size={16} class="chev" />
          <span>이벤트 로그</span>
          <span class="count">0</span>
        </button>
        {logOpen.value && (
          <div class="log-body">
            <p>시뮬레이션을 실행하면 각 장치가 무엇을 보고 어떤 결정을 내렸는지 여기에 순서대로 기록됩니다.</p>
          </div>
        )}
      </footer>
      {notice.value && <div class="toast">{notice.value}</div>}
    </div>
  );
}
