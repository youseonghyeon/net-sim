import { useSignal } from "@preact/signals";
import { useEffect } from "preact/hooks";
import { addDevice, tool, viewport } from "../model/store";
import { DEVICE_SPECS, PALETTE_ORDER, type DeviceKind } from "../model/topology";
import { Icon } from "./Icons";

interface Ghost {
  kind: DeviceKind;
  x: number;
  y: number;
}

export function Palette() {
  const ghost = useSignal<Ghost | null>(null);

  /** 팔레트 항목을 누른 채 캔버스로 끌면 그 자리에 추가, 그냥 클릭하면 화면 중앙에 추가 */
  function onPointerDown(kind: DeviceKind, e: PointerEvent): void {
    if (e.button !== 0) return;
    e.preventDefault();
    const start = { x: e.clientX, y: e.clientY };
    let dragging = false;
    const move = (ev: PointerEvent) => {
      if (!dragging && Math.hypot(ev.clientX - start.x, ev.clientY - start.y) > 4) dragging = true;
      if (dragging) ghost.value = { kind, x: ev.clientX, y: ev.clientY };
    };
    const cleanup = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      window.removeEventListener("pointercancel", cancel);
      ghost.value = null;
    };
    // 취소(터치 취소·창 전환)되면 아무것도 추가하지 않고 고스트만 치운다
    const cancel = () => cleanup();
    const up = (ev: PointerEvent) => {
      cleanup();
      const svg = document.getElementById("canvas-svg")!;
      const rect = svg.getBoundingClientRect();
      const v = viewport.value;
      const spec = DEVICE_SPECS[kind];
      if (!dragging) {
        const cx = (rect.width / 2 - v.x) / v.k - spec.width / 2;
        const cy = (rect.height / 2 - v.y) / v.k - spec.height / 2;
        addDevice(kind, cx, cy, true);
        return;
      }
      const inside = ev.clientX >= rect.left && ev.clientX <= rect.right && ev.clientY >= rect.top && ev.clientY <= rect.bottom;
      if (!inside) return;
      const x = (ev.clientX - rect.left - v.x) / v.k - spec.width / 2;
      const y = (ev.clientY - rect.top - v.y) / v.k - spec.height / 2;
      addDevice(kind, x, y);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
    window.addEventListener("pointercancel", cancel);
  }

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable) return;
      if (e.key === "Escape") tool.value = "select";
      // ⌘C/⌘V/⌘Z 는 복사·붙여넣기·되돌리기라 도구를 바꾸지 않는다. e.code 로 판정해 한글 입력 상태(ㅍ/ㅊ/ㅋ)에서도 동작
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.code === "KeyV") tool.value = "select";
      else if (e.code === "KeyC") tool.value = "cable";
      else if (e.code === "KeyZ") tool.value = "zone";
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const g = ghost.value;
  return (
    <aside class="palette">
      <div class="palette-group">
        <button class={`tool${tool.value === "select" ? " on" : ""}`} onClick={() => (tool.value = "select")} title="선택 · 이동 (V)">
          <Icon name="cursor" />
          <span>선택</span>
        </button>
        <button class={`tool${tool.value === "cable" ? " on" : ""}`} onClick={() => (tool.value = "cable")} title="케이블 연결 (C) — 장치에서 장치로 끌기">
          <Icon name="cable" />
          <span>케이블</span>
        </button>
        <button class={`tool${tool.value === "zone" ? " on" : ""}`} onClick={() => (tool.value = "zone")} title="영역 (Z) — 빈 곳에서 끌어 '집 안', '도커 호스트' 같은 묶음을 표시">
          <Icon name="zone" />
          <span>영역</span>
        </button>
      </div>
      <div class="palette-sep" />
      <div class="palette-group">
        {PALETTE_ORDER.map((kind) => (
          <button key={kind} class="tool item" onPointerDown={(e) => onPointerDown(kind, e)} title={`${DEVICE_SPECS[kind].label} 추가 — 캔버스로 끌어다 놓기`}>
            <Icon name={kind} />
            <span>{DEVICE_SPECS[kind].label}</span>
          </button>
        ))}
      </div>
      {g && (
        <div class="drag-ghost" style={{ left: g.x, top: g.y }}>
          <Icon name={g.kind} size={24} />
        </div>
      )}
    </aside>
  );
}
