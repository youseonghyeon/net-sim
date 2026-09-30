// 진단 대상 입력칸 + 자동완성 목록. 후보는 뒤에서 돌린 복제 시뮬레이션 결과(닿는지·홉 수)로,
// 출발 호스트에서 본 위치(같은 서브넷 / 다른 서브넷 / 인터넷 / 이름)별로 묶어 보여준다. 닿지 않는 후보는 접어서 이유와 함께.
import { useSignal } from "@preact/signals";
import { useRef } from "preact/hooks";
import { REACH_GROUP_LABEL, type ReachCandidate, type ReachGroup, type ReachResult } from "../model/reach";

const GROUPS: ReachGroup[] = ["same", "routed", "internet", "ipv6", "name"];

export function TargetPicker({
  value,
  onInput,
  onSubmit,
  placeholder,
  load,
}: {
  value: string;
  onInput: (v: string) => void;
  onSubmit: () => void;
  placeholder: string;
  /** 목록을 열 때 부른다 (복제 시뮬레이션 — 결과는 캐시된다) */
  load: () => ReachResult;
}) {
  const open = useSignal(false);
  const result = useSignal<ReachResult | null>(null);
  const showBad = useSignal(false);
  const active = useSignal(0);
  /** 열자마자 입력칸의 기존 값으로 거르면 후보가 하나만 남으므로, 열린 뒤 사용자가 친 글자로만 거른다 */
  const filter = useSignal("");
  const wrap = useRef<HTMLDivElement>(null);

  const openList = () => {
    if (open.value) return;
    result.value = load();
    filter.value = "";
    active.value = 0;
    open.value = true;
  };
  const close = () => {
    open.value = false;
    showBad.value = false;
  };

  const q = filter.value.trim().toLowerCase();
  const all = result.value?.candidates ?? [];
  const match = (c: ReachCandidate) => !q || c.value.toLowerCase().includes(q) || c.label.toLowerCase().includes(q) || (c.resolved ?? "").includes(q);
  const good = all.filter((c) => c.ok && match(c));
  const bad = all.filter((c) => !c.ok && match(c));
  // 키보드로 고를 수 있는 순서: 닿는 후보, 펼쳤으면 닿지 않는 후보
  const flat = [...good, ...(showBad.value ? bad : [])];
  const pick = (c: ReachCandidate) => {
    onInput(c.value);
    close();
  };

  const row = (c: ReachCandidate) => {
    const idx = flat.indexOf(c);
    return (
      <li
        key={`${c.group}-${c.value}`}
        class={`picker-item${c.ok ? "" : " bad"}${idx === active.value ? " active" : ""}`}
        onMouseDown={(e) => {
          e.preventDefault(); // 입력칸 blur 보다 먼저 고른다
          pick(c);
        }}
        onMouseEnter={() => idx >= 0 && (active.value = idx)}
      >
        <span class="picker-label">{c.label}</span>
        <span class="picker-value mono">{c.resolved ? `${c.value} → ${c.resolved}` : c.value}</span>
        <span class="picker-meta">{c.ok ? (c.hops !== undefined ? `${c.hops}홉` : "") : c.reason}</span>
      </li>
    );
  };

  return (
    <div class="picker" ref={wrap}>
      <input
        class="input mono"
        value={value}
        placeholder={placeholder}
        onFocus={openList}
        onClick={openList}
        onBlur={close}
        onInput={(e) => {
          const v = e.currentTarget.value;
          onInput(v);
          filter.value = v;
          active.value = 0;
          if (!open.value) openList();
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown" && open.value) {
            e.preventDefault();
            active.value = Math.min(flat.length - 1, active.value + 1);
          } else if (e.key === "ArrowUp" && open.value) {
            e.preventDefault();
            active.value = Math.max(0, active.value - 1);
          } else if (e.key === "Enter") {
            e.preventDefault();
            const c = open.value && q ? flat[active.value] : undefined;
            if (c) pick(c);
            else {
              close();
              onSubmit();
            }
          } else if (e.key === "Escape") {
            close();
          }
        }}
      />
      {open.value && result.value && (
        <div class="picker-list" role="listbox">
          {result.value.note && <p class="picker-note">{result.value.note}</p>}
          {GROUPS.map((g) => {
            const items = good.filter((c) => c.group === g);
            if (items.length === 0) return null;
            return (
              <section key={g}>
                <h5>{REACH_GROUP_LABEL[g]}</h5>
                <ul>{items.map(row)}</ul>
              </section>
            );
          })}
          {good.length === 0 && !result.value.note && <p class="picker-note">{q ? "일치하는 닿는 후보가 없습니다" : "닿는 후보가 없습니다"}</p>}
          {bad.length > 0 && (
            <section class="picker-bad">
              <button
                class="picker-toggle"
                onMouseDown={(e) => {
                  e.preventDefault();
                  showBad.value = !showBad.value;
                }}
              >
                {showBad.value ? "▾" : "▸"} 닿지 않는 후보 {bad.length}개
              </button>
              {showBad.value && <ul>{bad.map(row)}</ul>}
            </section>
          )}
        </div>
      )}
    </div>
  );
}
