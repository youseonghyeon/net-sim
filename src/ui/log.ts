import type { Network } from "../core/network";
import type { Layer } from "../core/packet";
import type { TraceEvent } from "../core/trace";
import { $, esc } from "./dom";

const LAYERS: Layer[] = ["L1", "L2", "L3", "L4", "app", "sys"];
const BAD_KINDS = new Set(["frame.drop", "ip.drop", "ip.no-route", "arp.timeout", "link.unconnected"]);

export class LogView {
  private readonly list = $("#log");
  private readonly filters = $("#layer-filters");
  private readonly enabled = new Set<Layer>(["L2", "L3", "L4", "app", "sys"]);
  private expanded = new Set<number>();
  private lastRendered = -1;
  /** 이 seq 이상이 "현재 스텝" 으로 강조된다 */
  currentFrom = 0;

  constructor(private readonly onChange: () => void) {
    this.filters.innerHTML = LAYERS.map(
      (l) => `<label class="${this.enabled.has(l) ? "on" : ""}"><input type="checkbox" data-layer="${l}" ${this.enabled.has(l) ? "checked" : ""}/>${l}</label>`,
    ).join("");
    this.filters.addEventListener("change", (e) => {
      const input = e.target as HTMLInputElement;
      const layer = input.dataset.layer as Layer;
      if (input.checked) this.enabled.add(layer);
      else this.enabled.delete(layer);
      input.parentElement!.classList.toggle("on", input.checked);
      this.lastRendered = -1;
      this.onChange();
    });
    this.list.addEventListener("click", (e) => {
      const li = (e.target as HTMLElement).closest("li");
      if (!li) return;
      const seq = Number(li.dataset.seq);
      if (this.expanded.has(seq)) this.expanded.delete(seq);
      else this.expanded.add(seq);
      this.lastRendered = -1;
      this.onChange();
    });
  }

  reset(): void {
    this.expanded = new Set();
    this.lastRendered = -1;
    this.currentFrom = 0;
  }

  render(net: Network): void {
    // 되감기로 트레이스가 줄었거나 필터가 바뀌면 전체 재렌더
    if (net.trace.length < this.lastRendered) this.lastRendered = -1;
    if (this.lastRendered === net.trace.length) {
      this.markCurrent();
      return;
    }
    this.list.innerHTML = net.trace
      .filter((e) => this.enabled.has(e.layer))
      .map((e) => this.row(e, net))
      .join("");
    this.lastRendered = net.trace.length;
    this.markCurrent();
    this.list.scrollTop = this.list.scrollHeight;
  }

  private markCurrent(): void {
    for (const li of this.list.querySelectorAll<HTMLLIElement>("li")) {
      li.classList.toggle("current", Number(li.dataset.seq) >= this.currentFrom);
    }
  }

  private row(e: TraceEvent, net: Network): string {
    const nodeType = net.nodes.get(e.nodeId)?.type ?? "";
    const cls = [
      e.kind === "action" ? "action" : "",
      BAD_KINDS.has(e.kind) ? "bad" : "",
      e.kind.startsWith("arp.") ? "arp" : e.kind.startsWith("icmp.") ? "icmp" : "",
    ]
      .filter(Boolean)
      .join(" ");
    const details = this.expanded.has(e.seq)
      ? `<pre>${esc(JSON.stringify({ kind: e.kind, packetId: e.packetId, ...e.details }, null, 2))}</pre>`
      : "";
    return (
      `<li class="${cls}" data-seq="${e.seq}">` +
      `<span class="t">${e.time}ms</span>` +
      `<span class="node ${nodeType}">${esc(e.nodeId)}</span>` +
      `<span class="layer">${e.layer}</span>` +
      `<span class="summary">${esc(e.summary)}</span>${details}</li>`
    );
  }
}
