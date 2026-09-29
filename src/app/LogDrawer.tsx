import { effect, signal } from "@preact/signals";
import { Component } from "preact";
import { useEffect, useRef } from "preact/hooks";
import type { Layer } from "../core/packet";
import { BAD_KINDS, type TraceEvent } from "../core/trace";
import { sim, simVersion } from "../model/sim";
import { LOG_MIN, logHeight, logOpen, selectedDeviceIds, selection, setLogHeight, topology } from "../model/store";
import { Icon } from "./Icons";
import { PacketDetail } from "./PacketDetail";

const LAYERS: Layer[] = ["L1", "L2", "L3", "L4", "app", "sys"];
const LAYER_HINT: Record<Layer, string> = {
  L1: "물리 · 링크 전송",
  L2: "이더넷 · ARP · 스위칭",
  L3: "IP · 라우팅 · NAT · 방화벽",
  L4: "UDP · TCP",
  app: "DHCP · DNS · ping",
  sys: "설정 · 사용자 동작",
};
/**
 * 로그 창에 그리는 줄 수. 처음엔 최근 500줄, "이전 기록 더 보기" 로 2000줄씩 늘린다 (보관은 sim.ts 의 TRACE_CAP 까지).
 * 패킷이 폭주하면 로그가 초당 수천 줄씩 바뀌므로, 기본 창을 크게 잡으면 화면이 밀린다 (perf-check --log)
 */
const FIRST_ROWS = 500;
const PAGE_ROWS = 2000;
const shownRows = signal(FIRST_ROWS);

/**
 * 로그 창 갱신 신호: 시뮬레이션은 한 프레임에도 여러 번 바뀌지만 로그는 200ms 에 한 번이면 충분하다.
 * 이벤트마다 수천 줄을 다시 그리면 패킷이 많을 때 화면이 버벅인다 (perf-check --log 로 측정)
 */
const LOG_REFRESH_MS = 200;
const logTick = signal(0);
let refreshPending = false;
effect(() => {
  void simVersion.value;
  if (refreshPending) return;
  refreshPending = true;
  setTimeout(() => {
    refreshPending = false;
    logTick.value++;
  }, LOG_REFRESH_MS);
});

const enabledLayers = signal<Set<Layer>>(new Set<Layer>(["L2", "L3", "L4", "app", "sys"]));
/** 선택한 장치의 로그만 보기 */
const onlySelected = signal(false);
const expanded = signal<Set<number>>(new Set());

function categoryOf(e: TraceEvent): "arp" | "dhcp" | "icmp" | "tcp" | "dns" | "rip" | "vpn" | "vrrp" | "" {
  if (e.kind.startsWith("arp.")) return "arp";
  if (e.kind.startsWith("dhcp.")) return "dhcp";
  if (e.kind.startsWith("icmp.")) return "icmp";
  if (e.kind.startsWith("tcp.")) return "tcp";
  if (e.kind.startsWith("dns.")) return "dns";
  if (e.kind.startsWith("rip.")) return "rip";
  if (e.kind.startsWith("vpn.")) return "vpn";
  if (e.kind.startsWith("ha.")) return "vrrp";
  return "";
}

export function LogDrawer() {
  void logTick.value;
  const open = logOpen.value;
  const layers = enabledLayers.value;
  const names = new Map(topology.value.devices.map((d) => [d.id, d.name]));
  const all = sim.net.trace;
  const picked = new Set(selectedDeviceIds(selection.value));
  const filterByDevice = onlySelected.value && picked.size > 0;
  // 접혀 있으면 거르지도 않는다 (이벤트마다 다시 그려지므로)
  const matched = open ? all.filter((e) => layers.has(e.layer) && (!filterByDevice || picked.has(e.nodeId))) : [];
  const rows = matched.slice(-shownRows.value);
  const hidden = matched.length - rows.length;
  const listRef = useRef<HTMLOListElement>(null);
  /** "더 보기" 로 위에 줄이 붙을 때 보던 자리를 유지하기 위한 이전 높이 */
  const keepFrom = useRef<number | null>(null);
  const stick = useRef(true);
  // 위쪽 가장자리를 끌어 높이 조절. 최소보다 한참 아래로 끌면 접는다 (인스펙터 폭 조절과 같은 방식)
  const resizing = useRef<{ y: number; h: number } | null>(null);
  const onResizeDown = (e: PointerEvent) => {
    if (e.button !== 0) return;
    e.preventDefault();
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    resizing.current = { y: e.clientY, h: logHeight.peek() };
  };
  const onResizeMove = (e: PointerEvent) => {
    const r = resizing.current;
    if (!r) return;
    const h = r.h + (r.y - e.clientY);
    if (h < LOG_MIN - 70) {
      resizing.current = null;
      (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
      setLogHeight(r.h); // 다시 열면 끌기 전 높이로
      logOpen.value = false;
      return;
    }
    setLogHeight(h);
  };
  const onResizeUp = () => {
    resizing.current = null;
  };

  useEffect(() => {
    const el = listRef.current;
    if (!el) return;
    if (keepFrom.current !== null) {
      el.scrollTop += el.scrollHeight - keepFrom.current;
      keepFrom.current = null;
      return;
    }
    if (stick.current) el.scrollTop = el.scrollHeight;
  }, [rows.length, open]);
  const showMore = () => {
    keepFrom.current = listRef.current?.scrollHeight ?? null;
    shownRows.value += PAGE_ROWS;
  };

  const toggleLayer = (l: Layer) => {
    const next = new Set(layers);
    if (next.has(l)) next.delete(l);
    else next.add(l);
    enabledLayers.value = next;
  };

  return (
    <footer class={`log${open ? " open" : ""}`} style={{ "--log-h": `${logHeight.value}px` }}>
      {open && <div class="log-resize" onPointerDown={onResizeDown} onPointerMove={onResizeMove} onPointerUp={onResizeUp} onPointerCancel={onResizeUp} title="끌어서 높이 조절 (끝까지 올리면 상단바 아래까지)" />}
      <div class="log-head">
        <button class="log-toggle" onClick={() => (logOpen.value = !open)}>
          <Icon name="chevron" size={16} class="chev" />
          <span>이벤트 로그</span>
          <span class="count mono">{all.length}</span>
        </button>
        {open && (
          <>
            <div class="layer-filters">
              {LAYERS.map((l) => (
                <button key={l} class={`chip${layers.has(l) ? " on" : ""}`} onClick={() => toggleLayer(l)} title={LAYER_HINT[l]}>
                  {l}
                </button>
              ))}
            </div>
            <button
              class={`chip${filterByDevice ? " on" : ""}`}
              onClick={() => (onlySelected.value = !onlySelected.value)}
              disabled={picked.size === 0}
              title={picked.size === 0 ? "캔버스에서 장치를 선택하면 그 장치의 로그만 볼 수 있습니다" : "선택한 장치의 로그만 보기"}
            >
              {picked.size === 0 ? "선택한 장치만" : `선택한 장치만 (${[...picked].map((id) => names.get(id) ?? id).slice(0, 2).join(", ")}${picked.size > 2 ? ` 외 ${picked.size - 2}` : ""})`}
            </button>
            <button class="btn ghost small" onClick={() => sim.clearLog()} disabled={all.length === 0}>
              지우기
            </button>
          </>
        )}
      </div>
      {open && (
        <ol
          ref={listRef}
          class="log-list"
          onScroll={(e) => {
            const el = e.currentTarget;
            stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
          }}
        >
          {hidden > 0 && (
            <li class="log-more">
              <button class="btn ghost small" onClick={showMore}>
                이전 기록 {Math.min(hidden, PAGE_ROWS).toLocaleString()}개 더 보기 (남은 {hidden.toLocaleString()}개)
              </button>
            </li>
          )}
          {rows.length === 0 ? (
            <li class="log-empty">{filterByDevice ? "선택한 장치의 기록이 없습니다." : "아직 기록이 없습니다. 장치를 연결하거나 ping 을 보내면 각 장치가 무엇을 보고 어떤 결정을 내렸는지 순서대로 남습니다."}</li>
          ) : (
            rows.map((e) => <LogRow key={e.seq} e={e} name={names.get(e.nodeId)} open={expanded.value.has(e.seq)} />)
          )}
        </ol>
      )}
    </footer>
  );
}

function toggleRow(seq: number): void {
  const next = new Set(expanded.value);
  if (next.has(seq)) next.delete(seq);
  else next.add(seq);
  expanded.value = next;
}

/**
 * 로그 한 줄. 이벤트는 한 번 기록되면 바뀌지 않으므로, 이름·펼침이 그대로면 다시 그리지 않는다.
 * (수천 줄을 갱신마다 전부 비교하면 패킷이 많을 때 프레임이 밀린다 — perf-check --log)
 */
class LogRow extends Component<{ e: TraceEvent; name: string | undefined; open: boolean }> {
  override shouldComponentUpdate(next: { e: TraceEvent; name: string | undefined; open: boolean }): boolean {
    return next.e !== this.props.e || next.name !== this.props.name || next.open !== this.props.open;
  }
  override render() {
    const { e, name, open } = this.props;
    const cat = categoryOf(e);
    const bad = BAD_KINDS.has(e.kind);
    return (
      <li class={`row${bad ? " bad" : ""}${e.kind === "action" ? " action" : ""}${open ? " open" : ""}`} onClick={() => toggleRow(e.seq)}>
        <span class="t mono">{e.time}ms</span>
        <button
          class="who"
          title="캔버스에서 이 장치 선택"
          onClick={(ev) => {
            ev.stopPropagation();
            if (name !== undefined) selection.value = { type: "device", id: e.nodeId };
          }}
        >
          {name ?? e.nodeId}
        </button>
        <span class="layer mono">{e.layer}</span>
        <span class="summary">
          {cat && <i class={`cat ${cat}`} />}
          {e.summary}
        </span>
        {open && <PacketDetail e={e} name={name} />}
      </li>
    );
  }
}
