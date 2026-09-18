import type { Network } from "../core/network";
import { $, esc } from "./dom";

export class InspectorView {
  private readonly root = $("#inspector");
  private seenRows = new Map<string, Set<string>>();

  reset(): void {
    this.seenRows = new Map();
  }

  /** 노드 상태 테이블을 다시 그린다. 이전 렌더 이후 새로 생긴 행은 강조 */
  render(net: Network, activeNode: string | undefined): void {
    const nextSeen = new Map<string, Set<string>>();
    const html = [...net.nodes.values()]
      .map((n) => {
        const s = n.snapshot();
        const info = s.info.map(([k, v]) => `<span>${esc(k)}</span><b class="mono">${esc(v)}</b>`).join("");
        const tables = s.tables
          .map((t) => {
            const key = `${s.id}/${t.title}`;
            const prev = this.seenRows.get(key) ?? new Set<string>();
            const cur = new Set<string>();
            const rows = t.rows.length
              ? t.rows
                  .map((r) => {
                    const rk = r.join(" | ");
                    cur.add(rk);
                    const cls = prev.has(rk) ? "" : ' class="row-new"';
                    return `<tr${cls}>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`;
                  })
                  .join("")
              : `<tr><td class="empty" colspan="${t.columns.length}">비어 있음</td></tr>`;
            nextSeen.set(key, cur);
            return (
              `<table><caption>${esc(t.title)}</caption>` +
              `<thead><tr>${t.columns.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead>` +
              `<tbody>${rows}</tbody></table>`
            );
          })
          .join("");
        return (
          `<div class="card${s.id === activeNode ? " active" : ""}">` +
          `<h3>${esc(s.label)} <span class="type">${esc(s.type)}</span></h3>` +
          `<div class="info">${info}</div>${tables}</div>`
        );
      })
      .join("");
    this.root.innerHTML = html;
    this.seenRows = nextSeen;
  }
}
