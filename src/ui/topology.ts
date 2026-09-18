import type { Endpoint, Network, Transmission } from "../core/network";
import { describeFrame, frameCategory } from "../core/packet";
import type { NodeLayout } from "../core/scenarios/index";
import { $, esc } from "./dom";

const SVG_NS = "http://www.w3.org/2000/svg";
const HOST_W = 110;
const HOST_H = 58;
const SWITCH_W = 150;
const SWITCH_H = 44;

export class TopologyView {
  private readonly linksG = $<SVGGElement>("#links");
  private readonly nodesG = $<SVGGElement>("#nodes");
  private readonly packetsG = $<SVGGElement>("#packets");
  private layout: Record<string, NodeLayout> = {};
  /** "node:port" → 링크가 붙는 좌표. 스위치는 포트마다 아래쪽 변에 분산 */
  private anchors = new Map<string, NodeLayout>();

  /** 정적 부분(링크·노드)을 다시 그린다. 시나리오 변경/리셋 시 호출 */
  rebuild(net: Network, layout: Record<string, NodeLayout>): void {
    this.layout = layout;
    this.anchors = new Map();
    for (const n of net.nodes.values()) {
      const p = this.pos(n.id);
      for (let port = 0; port < n.portCount; port++) {
        const a =
          n.type === "switch"
            ? { x: p.x - SWITCH_W / 2 + ((port + 0.5) * SWITCH_W) / n.portCount, y: p.y + SWITCH_H / 2 }
            : { x: p.x, y: p.y - HOST_H / 2 };
        this.anchors.set(`${n.id}:${port}`, a);
      }
    }
    this.linksG.innerHTML = net.links
      .map((l) => {
        const a = this.anchor(l.a);
        const b = this.anchor(l.b);
        const la = portLabelPos(a, net.nodes.get(l.a.node)!.type === "switch");
        const lb = portLabelPos(b, net.nodes.get(l.b.node)!.type === "switch");
        return (
          `<line class="link" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>` +
          `<text class="port-label" x="${la.x}" y="${la.y}" text-anchor="middle">p${l.a.port}</text>` +
          `<text class="port-label" x="${lb.x}" y="${lb.y}" text-anchor="middle">p${l.b.port}</text>`
        );
      })
      .join("");

    this.nodesG.innerHTML = [...net.nodes.values()]
      .map((n) => {
        const p = this.pos(n.id);
        const snap = n.snapshot();
        if (n.type === "switch") {
          return (
            `<g class="node switch" data-id="${esc(n.id)}" transform="translate(${p.x - SWITCH_W / 2},${p.y - SWITCH_H / 2})">` +
            `<rect width="${SWITCH_W}" height="${SWITCH_H}"/>` +
            `<text class="name" x="${SWITCH_W / 2}" y="20">${esc(n.id)}</text>` +
            `<text class="mac" x="${SWITCH_W / 2}" y="35">L2 switch</text></g>`
          );
        }
        const ip = snap.info.find(([k]) => k === "IP")?.[1] ?? "";
        const mac = snap.info.find(([k]) => k === "MAC")?.[1] ?? "";
        return (
          `<g class="node host" data-id="${esc(n.id)}" transform="translate(${p.x - HOST_W / 2},${p.y - HOST_H / 2})">` +
          `<rect width="${HOST_W}" height="${HOST_H}"/>` +
          `<text class="name" x="${HOST_W / 2}" y="19">${esc(n.id)}</text>` +
          `<text class="ip" x="${HOST_W / 2}" y="35">${esc(ip)}</text>` +
          `<text class="mac" x="${HOST_W / 2}" y="49">${esc(mac)}</text></g>`
        );
      })
      .join("");
  }

  /** 이동 중 패킷과 활성 노드 하이라이트를 갱신. 매 프레임 호출 */
  update(inFlight: Transmission[], viewTime: number, activeNode: string | undefined): void {
    for (const g of this.nodesG.querySelectorAll<SVGGElement>(".node")) {
      g.classList.toggle("active", g.dataset.id === activeNode);
    }
    const frag = document.createDocumentFragment();
    for (const tx of inFlight) {
      const a = this.anchor(tx.from);
      const b = this.anchor(tx.to);
      const f = Math.min(1, Math.max(0, (viewTime - tx.departAt) / (tx.arriveAt - tx.departAt)));
      const x = a.x + (b.x - a.x) * f;
      const y = a.y + (b.y - a.y) * f;
      const g = document.createElementNS(SVG_NS, "g");
      g.setAttribute("class", `packet ${frameCategory(tx.frame)}`);
      g.setAttribute("transform", `translate(${x},${y})`);
      const c = document.createElementNS(SVG_NS, "circle");
      c.setAttribute("r", "9");
      const t = document.createElementNS(SVG_NS, "text");
      t.setAttribute("y", "-14");
      t.textContent = describeFrame(tx.frame);
      g.append(c, t);
      frag.append(g);
    }
    this.packetsG.replaceChildren(frag);
  }

  private pos(id: string): NodeLayout {
    const p = this.layout[id];
    if (!p) throw new Error(`no layout for node ${id}`);
    return p;
  }

  private anchor(ep: Endpoint): NodeLayout {
    const a = this.anchors.get(`${ep.node}:${ep.port}`);
    if (!a) throw new Error(`no anchor for ${ep.node}:${ep.port}`);
    return a;
  }
}

/** 포트 라벨은 노드 밖으로 살짝 띄운다 (스위치는 아래, 호스트는 위) */
function portLabelPos(anchor: NodeLayout, isSwitch: boolean): NodeLayout {
  return { x: anchor.x, y: isSwitch ? anchor.y + 13 : anchor.y - 5 };
}
