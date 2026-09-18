import { useSignal } from "@preact/signals";
import { useEffect, useRef } from "preact/hooks";
import { frameCategory, shortLabel } from "../core/packet";
import { hostStatus, sim, simTime, simVersion, wanStatus } from "../model/sim";
import { connectDevices, fitRequest, loadExample, moveDevice, selection, tool, topology, viewport } from "../model/store";
import { freePort, PORT_DEPTH, PORT_WIDTH, portAnchor, snap, specOf, usedPorts, type Cable, type Device, type PortSide } from "../model/topology";
import { GlyphInSvg } from "./Icons";

type Drag =
  | { type: "move"; id: string; ox: number; oy: number }
  | { type: "pan"; sx: number; sy: number; vx: number; vy: number; moved: boolean }
  | { type: "cable"; from: string; target?: string };

interface Draft {
  from: string;
  x: number;
  y: number;
  target?: string;
}

export function Canvas({ onNotice }: { onNotice: (msg: string) => void }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const dragRef = useRef<Drag | null>(null);
  const draft = useSignal<Draft | null>(null);

  const t = topology.value;
  const v = viewport.value;
  const sel = selection.value;

  function toCanvas(clientX: number, clientY: number): { x: number; y: number } {
    const rect = svgRef.current!.getBoundingClientRect();
    const vp = viewport.value;
    return { x: (clientX - rect.left - vp.x) / vp.k, y: (clientY - rect.top - vp.y) / vp.k };
  }

  function deviceAt(clientX: number, clientY: number): string | undefined {
    for (const el of document.elementsFromPoint(clientX, clientY)) {
      const g = el.closest?.("[data-device]") as SVGGElement | null;
      if (g) return g.dataset.device;
    }
    return undefined;
  }

  function onPointerDown(e: PointerEvent): void {
    if (e.button !== 0 && e.button !== 1) return;
    const target = e.target as Element;
    const deviceEl = target.closest("[data-device]") as SVGGElement | null;
    const cableEl = target.closest("[data-cable]") as SVGGElement | null;
    svgRef.current!.setPointerCapture(e.pointerId);

    if (deviceEl && e.button === 0) {
      const id = deviceEl.dataset.device!;
      if (tool.value === "cable" || e.shiftKey) {
        const p = toCanvas(e.clientX, e.clientY);
        dragRef.current = { type: "cable", from: id };
        draft.value = { from: id, x: p.x, y: p.y };
      } else {
        selection.value = { type: "device", id };
        const d = topology.value.devices.find((x) => x.id === id)!;
        const p = toCanvas(e.clientX, e.clientY);
        dragRef.current = { type: "move", id, ox: p.x - d.x, oy: p.y - d.y };
      }
      return;
    }
    if (cableEl && e.button === 0) {
      selection.value = { type: "cable", id: cableEl.dataset.cable! };
      dragRef.current = null;
      return;
    }
    dragRef.current = { type: "pan", sx: e.clientX, sy: e.clientY, vx: v.x, vy: v.y, moved: false };
  }

  function onPointerMove(e: PointerEvent): void {
    const d = dragRef.current;
    if (!d) return;
    if (d.type === "move") {
      const p = toCanvas(e.clientX, e.clientY);
      moveDevice(d.id, snap(p.x - d.ox), snap(p.y - d.oy));
    } else if (d.type === "pan") {
      const dx = e.clientX - d.sx;
      const dy = e.clientY - d.sy;
      if (Math.abs(dx) + Math.abs(dy) > 2) d.moved = true;
      viewport.value = { ...viewport.value, x: d.vx + dx, y: d.vy + dy };
    } else {
      const p = toCanvas(e.clientX, e.clientY);
      const over = deviceAt(e.clientX, e.clientY);
      d.target = over && over !== d.from ? over : undefined;
      draft.value = { from: d.from, x: p.x, y: p.y, target: d.target };
    }
  }

  function onPointerUp(): void {
    const d = dragRef.current;
    dragRef.current = null;
    if (!d) return;
    if (d.type === "pan" && !d.moved) selection.value = null;
    if (d.type === "cable") {
      draft.value = null;
      if (d.target) {
        const r = connectDevices(d.from, d.target);
        if (r.error) onNotice(r.error);
      }
    }
  }

  // 내용에 맞춰 보기: 장치 전체의 경계 상자를 화면 중앙에, 필요하면 축소
  useEffect(() => {
    const devices = topology.value.devices;
    if (devices.length === 0) return;
    const rect = svgRef.current!.getBoundingClientRect();
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const d of devices) {
      const s = specOf(d);
      minX = Math.min(minX, d.x);
      minY = Math.min(minY, d.y - 12);
      maxX = Math.max(maxX, d.x + s.width);
      maxY = Math.max(maxY, d.y + s.height + (s.role === "host" ? 44 : 12));
    }
    const pad = 80;
    const k = Math.min(1, (rect.width - pad * 2) / (maxX - minX), (rect.height - pad * 2) / (maxY - minY));
    viewport.value = {
      k,
      x: (rect.width - (maxX - minX) * k) / 2 - minX * k,
      y: (rect.height - (maxY - minY) * k) / 2 - minY * k,
    };
  }, [fitRequest.value]);

  useEffect(() => {
    const svg = svgRef.current!;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const vp = viewport.value;
      if (e.ctrlKey || e.metaKey) {
        const rect = svg.getBoundingClientRect();
        const cx = e.clientX - rect.left;
        const cy = e.clientY - rect.top;
        const k = Math.min(3, Math.max(0.25, vp.k * Math.exp(-e.deltaY * 0.01)));
        viewport.value = { k, x: cx - (cx - vp.x) * (k / vp.k), y: cy - (cy - vp.y) * (k / vp.k) };
      } else {
        viewport.value = { ...vp, x: vp.x - e.deltaX, y: vp.y - e.deltaY };
      }
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, []);

  const byId = new Map(t.devices.map((d) => [d.id, d]));
  const dr = draft.value;
  const draftPath = dr ? draftCablePath(dr, byId) : null;

  return (
    <div class={`canvas-wrap tool-${tool.value}`}>
      <svg
        id="canvas-svg"
        ref={svgRef}
        class="canvas"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
      >
        <defs>
          <pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse" patternTransform={`translate(${v.x},${v.y}) scale(${v.k})`}>
            <circle cx="1" cy="1" r="1" class="grid-dot" />
          </pattern>
        </defs>
        <rect class="grid-bg" width="100%" height="100%" fill="url(#grid)" />
        <g transform={`translate(${v.x},${v.y}) scale(${v.k})`}>
          <g class="cables">
            {t.cables.map((c) => (
              <CableView key={c.id} cable={c} byId={byId} selected={sel?.type === "cable" && sel.id === c.id} />
            ))}
          </g>
          <g class="devices">
            {t.devices.map((d) => (
              <DeviceView
                key={d.id}
                d={d}
                used={usedPorts(t, d.id)}
                selected={sel?.type === "device" && sel.id === d.id}
                targeted={dr?.target === d.id}
                source={dr?.from === d.id}
              />
            ))}
          </g>
          {draftPath && (
            <g class="draft">
              <path d={draftPath} />
            </g>
          )}
          <PacketLayer byId={byId} cables={t.cables} />
        </g>
      </svg>
      {t.devices.length === 0 && (
        <div class="empty">
          <p>왼쪽 팔레트에서 장치를 끌어다 놓거나, 예제로 시작하세요.</p>
          <button
            class="btn"
            onClick={() => {
              loadExample();
              sim.reset();
            }}
          >
            예제 네트워크 불러오기
          </button>
        </div>
      )}
      <div class="legend">
        <span>
          <i class="arp" />
          ARP
        </span>
        <span>
          <i class="dhcp" />
          DHCP
        </span>
        <span>
          <i class="icmp" />
          ping
        </span>
      </div>
      <div class="zoom">{Math.round(v.k * 100)}%</div>
    </div>
  );
}

function DeviceView({ d, used, selected, targeted, source }: { d: Device; used: Set<number>; selected: boolean; targeted: boolean; source: boolean }) {
  const spec = specOf(d);
  const wide = spec.role !== "host";
  const glyph = wide ? 24 : 28;
  void simVersion.value; // 시뮬레이션 상태가 바뀌면 다시 읽는다
  const addr = hostStatus(d.id);
  const wan = wanStatus(d.id);
  return (
    <g
      data-device={d.id}
      class={`device ${spec.role}${wide ? " wide" : ""}${selected ? " selected" : ""}${targeted ? " targeted" : ""}${source ? " source" : ""}`}
      transform={`translate(${d.x},${d.y})`}
    >
      <rect class="tile" width={spec.width} height={spec.height} rx={10} />
      <g class="glyph">
        <GlyphInSvg name={d.kind} x={wide ? 14 : (spec.width - glyph) / 2} y={(spec.height - glyph) / 2} size={glyph} />
      </g>
      {spec.ports.map((p, i) => {
        const a = portAnchor(d, i);
        const lx = a.x - d.x - PORT_WIDTH / 2;
        const ly = p.side === "top" ? a.y - d.y : a.y - d.y - PORT_DEPTH;
        return (
          <rect key={p.name} class={`port${used.has(i) ? " used" : ""}`} x={lx} y={ly} width={PORT_WIDTH} height={PORT_DEPTH} rx={1.5}>
            <title>{p.name}</title>
          </rect>
        );
      })}
      {wide ? (
        <>
          <text class="name" x={50} y={addr ? 20 : spec.height / 2 + 5}>
            {d.name}
          </text>
          {addr && (
            <text class={`${addr.mono ? "addr" : "status"} ${addr.tone}`} x={50} y={35}>
              {addr.text}
            </text>
          )}
          {wan && (
            <text class={`${wan.mono ? "addr" : "status"} ${wan.tone}`} x={50} y={50}>
              {wan.text}
            </text>
          )}
        </>
      ) : (
        <>
          <text class="name" x={spec.width / 2} y={spec.height + 24}>
            {d.name}
          </text>
          {addr && (
            <text class={`${addr.mono ? "addr" : "status"} ${addr.tone}`} x={spec.width / 2} y={spec.height + 39}>
              {addr.text}
            </text>
          )}
        </>
      )}
    </g>
  );
}

function CableView({ cable, byId, selected }: { cable: Cable; byId: Map<string, Device>; selected: boolean }) {
  const a = byId.get(cable.a.device);
  const b = byId.get(cable.b.device);
  if (!a || !b) return null;
  const pa = portAnchor(a, cable.a.port);
  const pb = portAnchor(b, cable.b.port);
  const d = cablePath(pa, pb);
  return (
    <g data-cable={cable.id} class={`cable${selected ? " selected" : ""}`}>
      <path class="hit" d={d} />
      <path class="wire" d={d} />
    </g>
  );
}

type Anchor = { x: number; y: number; side: PortSide };
type Curve = { x0: number; y0: number; x1: number; y1: number; x2: number; y2: number; x3: number; y3: number };

/** 포트에서 수직으로 나갔다가 상대 포트로 수직으로 들어가는 베지어 */
function cableCurve(a: Anchor, b: Anchor): Curve {
  const dist = Math.hypot(b.x - a.x, b.y - a.y);
  const lead = Math.min(90, Math.max(28, dist * 0.45));
  const ay = a.side === "top" ? a.y - lead : a.y + lead;
  const by = b.side === "top" ? b.y - lead : b.y + lead;
  return { x0: a.x, y0: a.y, x1: a.x, y1: ay, x2: b.x, y2: by, x3: b.x, y3: b.y };
}

function cablePath(a: Anchor, b: Anchor): string {
  const c = cableCurve(a, b);
  return `M${c.x0},${c.y0} C${c.x1},${c.y1} ${c.x2},${c.y2} ${c.x3},${c.y3}`;
}

function pointOn(c: Curve, t: number): { x: number; y: number } {
  const u = 1 - t;
  const w0 = u * u * u, w1 = 3 * u * u * t, w2 = 3 * u * t * t, w3 = t * t * t;
  return { x: w0 * c.x0 + w1 * c.x1 + w2 * c.x2 + w3 * c.x3, y: w0 * c.y0 + w1 * c.y1 + w2 * c.y2 + w3 * c.y3 };
}

/** 링크 위를 이동 중인 패킷. 매 프레임 simTime 을 구독한다 */
function PacketLayer({ byId, cables }: { byId: Map<string, Device>; cables: Cable[] }) {
  const now = simTime.value;
  const cableById = new Map(cables.map((c) => [c.id, c]));
  const items = sim.inFlight().map((tx) => {
    const cable = cableById.get(tx.linkId);
    if (!cable) return null;
    const a = byId.get(cable.a.device);
    const b = byId.get(cable.b.device);
    if (!a || !b) return null;
    const curve = cableCurve(portAnchor(a, cable.a.port), portAnchor(b, cable.b.port));
    const frac = Math.min(1, Math.max(0, (now - tx.departAt) / (tx.arriveAt - tx.departAt)));
    const p = pointOn(curve, tx.from.node === cable.a.device ? frac : 1 - frac);
    return (
      <g key={tx.id} class={`packet ${frameCategory(tx.frame)}`} transform={`translate(${p.x},${p.y})`}>
        <circle r={7} />
        <text y={-13}>{shortLabel(tx.frame)}</text>
      </g>
    );
  });
  return <g class="packets">{items}</g>;
}

function draftCablePath(dr: Draft, byId: Map<string, Device>): string | null {
  const from = byId.get(dr.from);
  if (!from) return null;
  const t = topology.value;
  const port = freePort(t, dr.from, dr.y);
  const start: Anchor = port !== undefined ? portAnchor(from, port) : { x: from.x + specOf(from).width / 2, y: from.y + specOf(from).height / 2, side: "bottom" };
  let end: Anchor = { x: dr.x, y: dr.y, side: dr.y < start.y ? "bottom" : "top" };
  if (dr.target) {
    const target = byId.get(dr.target);
    const tp = target ? freePort(t, dr.target, from.y) : undefined;
    if (target && tp !== undefined) end = portAnchor(target, tp);
  }
  return cablePath(start, end);
}
