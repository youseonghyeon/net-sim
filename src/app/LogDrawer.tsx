import { signal } from "@preact/signals";
import { useEffect, useRef } from "preact/hooks";
import type { Layer } from "../core/packet";
import { BAD_KINDS, type TraceEvent } from "../core/trace";
import { sim, simVersion } from "../model/sim";
import { logOpen, topology } from "../model/store";
import { Icon } from "./Icons";

const LAYERS: Layer[] = ["L1", "L2", "L3", "L4", "app", "sys"];
const LAYER_HINT: Record<Layer, string> = {
  L1: "물리 · 링크 전송",
  L2: "이더넷 · ARP · 스위칭",
  L3: "IP · 라우팅 · NAT · 방화벽",
  L4: "UDP · TCP",
  app: "DHCP · DNS · ping",
  sys: "설정 · 사용자 동작",
};
const MAX_ROWS = 400;

const enabledLayers = signal<Set<Layer>>(new Set<Layer>(["L2", "L3", "L4", "app", "sys"]));
const expanded = signal<Set<number>>(new Set());

function categoryOf(e: TraceEvent): "arp" | "dhcp" | "icmp" | "tcp" | "dns" | "" {
  if (e.kind.startsWith("arp.")) return "arp";
  if (e.kind.startsWith("dhcp.")) return "dhcp";
  if (e.kind.startsWith("icmp.")) return "icmp";
  if (e.kind.startsWith("tcp.")) return "tcp";
  if (e.kind.startsWith("dns.")) return "dns";
  return "";
}

export function LogDrawer() {
  void simVersion.value;
  const open = logOpen.value;
  const layers = enabledLayers.value;
  const names = new Map(topology.value.devices.map((d) => [d.id, d.name]));
  const all = sim.net.trace;
  const rows = all.filter((e) => layers.has(e.layer)).slice(-MAX_ROWS);
  const listRef = useRef<HTMLOListElement>(null);
  const stick = useRef(true);

  useEffect(() => {
    const el = listRef.current;
    if (el && stick.current) el.scrollTop = el.scrollHeight;
  }, [rows.length, open]);

  const toggleLayer = (l: Layer) => {
    const next = new Set(layers);
    if (next.has(l)) next.delete(l);
    else next.add(l);
    enabledLayers.value = next;
  };
  const toggleRow = (seq: number) => {
    const next = new Set(expanded.value);
    if (next.has(seq)) next.delete(seq);
    else next.add(seq);
    expanded.value = next;
  };

  return (
    <footer class={`log${open ? " open" : ""}`}>
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
          {rows.length === 0 ? (
            <li class="log-empty">아직 기록이 없습니다. 장치를 연결하거나 ping 을 보내면 각 장치가 무엇을 보고 어떤 결정을 내렸는지 순서대로 남습니다.</li>
          ) : (
            rows.map((e) => {
              const cat = categoryOf(e);
              const bad = BAD_KINDS.has(e.kind);
              const isOpen = expanded.value.has(e.seq);
              return (
                <li key={e.seq} class={`row${bad ? " bad" : ""}${e.kind === "action" ? " action" : ""}${isOpen ? " open" : ""}`} onClick={() => toggleRow(e.seq)}>
                  <span class="t mono">{e.time}ms</span>
                  <span class="who">{names.get(e.nodeId) ?? e.nodeId}</span>
                  <span class="layer mono">{e.layer}</span>
                  <span class="summary">
                    {cat && <i class={`cat ${cat}`} />}
                    {e.summary}
                  </span>
                  {isOpen && <pre class="details">{JSON.stringify({ kind: e.kind, packetId: e.packetId, ...e.details }, null, 2)}</pre>}
                </li>
              );
            })
          )}
        </ol>
      )}
    </footer>
  );
}
