import type * as preact from "preact";
import { useSignal } from "@preact/signals";
import { useEffect, useRef } from "preact/hooks";
import { frameCategory, shortLabel } from "../core/packet";
import { hostStatus, serviceBadges, sim, simTime, simVersion, wanStatus } from "../model/sim";
import { beginCoalesce, connectDevices, endCoalesce, fitRequest, lintIssues, loadExample, moveDevices, selectedDeviceIds, selection, selectionOf, toggleDeviceSelection, tool, topology, viewport } from "../model/store";
import type { LintIssue } from "../model/lint";
import {
  baseSsid,
  freePort,
  portVlanOf,
  vlanColor,
  PORT_DEPTH,
  PORT_WIDTH,
  portAnchor,
  specOf,
  usedPorts,
  WIFI_RANGE,
  wirelessLinks,
  type Cable,
  type Device,
  type PortSide,
  type WirelessLink,
} from "../model/topology";
import { GlyphInSvg } from "./Icons";

type Drag =
  /** 선택된 장치들을 함께 옮긴다. starts = 드래그 시작 시 각 장치 위치 */
  | { type: "move"; starts: Map<string, { x: number; y: number }>; sx: number; sy: number; moved: boolean }
  | { type: "pan"; sx: number; sy: number; vx: number; vy: number; moved: boolean }
  | { type: "cable"; from: string; target?: string; sx: number; sy: number; moved: boolean }
  /** 빈 곳에서 끌어 영역 선택 (캔버스 좌표) */
  | { type: "marquee"; x0: number; y0: number; x1: number; y1: number };

/** 마퀴 사각형 안에 타일이 걸치는 장치 */
function devicesInRect(devices: Device[], x0: number, y0: number, x1: number, y1: number): string[] {
  const left = Math.min(x0, x1), right = Math.max(x0, x1), top = Math.min(y0, y1), bottom = Math.max(y0, y1);
  return devices.filter((d) => {
    const s = specOf(d);
    return d.x < right && d.x + s.width > left && d.y < bottom && d.y + s.height > top;
  }).map((d) => d.id);
}

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
  const marquee = useSignal<{ x0: number; y0: number; x1: number; y1: number } | null>(null);

  const t = topology.value;
  const v = viewport.value;
  const sel = selection.value;
  const selectedIds = new Set(selectedDeviceIds(sel));

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

    // ⌥(Alt) 를 누른 채 끌거나 가운데 버튼이면 팬. 그 외 빈 곳 끌기는 영역 선택
    const panning = e.button === 1 || e.altKey;
    if (deviceEl && e.button === 0 && !panning) {
      const id = deviceEl.dataset.device!;
      if (tool.value === "cable" || e.shiftKey) {
        // Shift+끌기 = 케이블, Shift+클릭(안 움직임) = 선택 토글 (pointerup 에서 판정)
        const p = toCanvas(e.clientX, e.clientY);
        dragRef.current = { type: "cable", from: id, sx: e.clientX, sy: e.clientY, moved: false };
        draft.value = { from: id, x: p.x, y: p.y };
      } else {
        // 이미 다중 선택에 든 장치를 잡으면 묶음째 옮기고, 아니면 그 장치만 선택
        const ids = selectedIds.has(id) ? [...selectedIds] : [id];
        if (!selectedIds.has(id)) selection.value = { type: "device", id };
        const starts = new Map<string, { x: number; y: number }>();
        for (const d of topology.value.devices) if (ids.includes(d.id)) starts.set(d.id, { x: d.x, y: d.y });
        dragRef.current = { type: "move", starts, sx: e.clientX, sy: e.clientY, moved: false };
      }
      return;
    }
    if (cableEl && e.button === 0 && !panning) {
      selection.value = { type: "cable", id: cableEl.dataset.cable! };
      dragRef.current = null;
      return;
    }
    if (!panning) {
      const p = toCanvas(e.clientX, e.clientY);
      dragRef.current = { type: "marquee", x0: p.x, y0: p.y, x1: p.x, y1: p.y };
      return;
    }
    dragRef.current = { type: "pan", sx: e.clientX, sy: e.clientY, vx: v.x, vy: v.y, moved: false };
  }

  function onPointerMove(e: PointerEvent): void {
    const d = dragRef.current;
    if (!d) return;
    if (d.type === "move") {
      const k = viewport.value.k;
      const dx = (e.clientX - d.sx) / k;
      const dy = (e.clientY - d.sy) / k;
      if (!d.moved) {
        if (Math.abs(dx) + Math.abs(dy) < 2) return;
        d.moved = true;
        beginCoalesce(); // 드래그 한 번 = 되돌리기 한 단계
      }
      moveDevices(d.starts, dx, dy);
    } else if (d.type === "marquee") {
      const p = toCanvas(e.clientX, e.clientY);
      d.x1 = p.x;
      d.y1 = p.y;
      marquee.value = { x0: d.x0, y0: d.y0, x1: p.x, y1: p.y };
    } else if (d.type === "pan") {
      const dx = e.clientX - d.sx;
      const dy = e.clientY - d.sy;
      if (Math.abs(dx) + Math.abs(dy) > 2) d.moved = true;
      viewport.value = { ...viewport.value, x: d.vx + dx, y: d.vy + dy };
    } else {
      if (Math.abs(e.clientX - d.sx) + Math.abs(e.clientY - d.sy) > 3) d.moved = true;
      const p = toCanvas(e.clientX, e.clientY);
      const over = deviceAt(e.clientX, e.clientY);
      d.target = over && over !== d.from ? over : undefined;
      draft.value = { from: d.from, x: p.x, y: p.y, target: d.target };
    }
  }

  function onPointerUp(e: PointerEvent): void {
    const d = dragRef.current;
    dragRef.current = null;
    if (!d) return;
    if (d.type === "move") {
      if (d.moved) endCoalesce();
      return;
    }
    if (d.type === "marquee") {
      marquee.value = null;
      const tiny = Math.abs(d.x1 - d.x0) < 4 && Math.abs(d.y1 - d.y0) < 4;
      const ids = tiny ? [] : devicesInRect(topology.value.devices, d.x0, d.y0, d.x1, d.y1);
      // Shift 를 누른 채 영역 선택하면 기존 선택에 더한다
      selection.value = selectionOf(e.shiftKey ? [...new Set([...selectedDeviceIds(selection.value), ...ids])] : ids);
      return;
    }
    if (d.type === "pan" && !d.moved) selection.value = null;
    if (d.type === "cable") {
      draft.value = null;
      if (d.target) {
        const r = connectDevices(d.from, d.target);
        if (r.error) onNotice(r.error);
      } else if (!d.moved && tool.value !== "cable") {
        toggleDeviceSelection(d.from);
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
    const k = Math.max(0.25, Math.min(1, (rect.width - pad * 2) / (maxX - minX), (rect.height - pad * 2) / (maxY - minY)));
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
  const issuesByDevice = new Map<string, LintIssue[]>();
  for (const i of lintIssues.value) issuesByDevice.set(i.deviceId, [...(issuesByDevice.get(i.deviceId) ?? []), i]);
  const dr = draft.value;
  const draftPath = dr ? draftCablePath(dr, byId) : null;
  const wl = wirelessLinks(t);
  const bases = t.devices.filter((d) => {
    const b = baseSsid(d);
    return b !== undefined && b.enabled;
  });

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
          <g class="coverage">
            {bases.map((b) => {
              const s = specOf(b);
              return <circle key={b.id} class="wifi-range" cx={b.x + s.width / 2} cy={b.y + s.height / 2} r={WIFI_RANGE} />;
            })}
          </g>
          <g class="cables">
            {t.cables.map((c) => (
              <CableView key={c.id} cable={c} byId={byId} selected={sel?.type === "cable" && sel.id === c.id} />
            ))}
            {wl.map((l) => {
              const seg = wirelessSegment(l, byId);
              if (!seg) return null;
              return <line key={l.id} class="wifi-link" x1={seg.a.x} y1={seg.a.y} x2={seg.b.x} y2={seg.b.y} />;
            })}
          </g>
          <g class="devices">
            {t.devices.map((d) => (
              <DeviceView
                key={d.id}
                d={d}
                used={usedPorts(t, d.id)}
                selected={selectedIds.has(d.id)}
                targeted={dr?.target === d.id}
                source={dr?.from === d.id}
                issues={issuesByDevice.get(d.id)}
              />
            ))}
          </g>
          {draftPath && (
            <g class="draft">
              <path d={draftPath} />
            </g>
          )}
          <PacketLayer byId={byId} cables={t.cables} wireless={wl} />
          {marquee.value && (
            <rect
              class="marquee"
              x={Math.min(marquee.value.x0, marquee.value.x1)}
              y={Math.min(marquee.value.y0, marquee.value.y1)}
              width={Math.abs(marquee.value.x1 - marquee.value.x0)}
              height={Math.abs(marquee.value.y1 - marquee.value.y0)}
            />
          )}
        </g>
      </svg>
      {t.devices.length === 0 && (
        <div class="canvas-empty">
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
        <span>
          <i class="tcp" />
          TCP
        </span>
        <span>
          <i class="dns" />
          DNS
        </span>
      </div>
      <div class="zoom">{Math.round(v.k * 100)}%</div>
    </div>
  );
}

function DeviceView({ d, used, selected, targeted, source, issues }: { d: Device; used: Set<number>; selected: boolean; targeted: boolean; source: boolean; issues?: LintIssue[] }) {
  const spec = specOf(d);
  const wide = spec.role !== "host";
  const glyph = wide ? 24 : 28;
  void simVersion.value; // 시뮬레이션 상태가 바뀌면 다시 읽는다
  const addr = hostStatus(d.id);
  const wan = wanStatus(d.id);
  const badges = serviceBadges(d.id);
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
      {badges.length > 0 && <ServiceBadges badges={badges} width={spec.width} below={wide ? undefined : spec.height + 46} />}
      {issues && issues.length > 0 && <LintBadge issues={issues} />}
      {spec.ports.map((p, i) => {
        if (p.radio) return null;
        const a = portAnchor(d, i);
        const lx = a.x - d.x - PORT_WIDTH / 2;
        const ly = p.side === "top" ? a.y - d.y : a.y - d.y - PORT_DEPTH;
        const v = portVlanOf(d, i);
        const vlanStyle = v !== undefined && v !== 1 && v !== "trunk" ? { fill: vlanColor(v), stroke: vlanColor(v) } : undefined;
        const title = v === undefined ? p.name : v === "trunk" ? `${p.name} · 트렁크` : `${p.name} · VLAN ${v}`;
        return (
          <rect key={p.name} class={`port${used.has(i) ? " used" : ""}${v === "trunk" ? " trunk" : ""}`} x={lx} y={ly} width={PORT_WIDTH} height={PORT_DEPTH} rx={1.5} style={vlanStyle}>
            <title>{title}</title>
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

/** 구성 검사 배지: 타일 왼쪽 위 모서리. 오류가 하나라도 있으면 빨강, 아니면 노랑. 자세한 건 인스펙터 */
function LintBadge({ issues }: { issues: LintIssue[] }) {
  const severity = issues.some((i) => i.severity === "error") ? "error" : "warn";
  return (
    <g class={`lint-badge ${severity}`} transform="translate(-2,-2)">
      <circle r={8} />
      <text y={3.5}>!</text>
      <title>{issues.map((i) => `${i.severity === "error" ? "오류" : "주의"}: ${i.message}`).join("\n")}</title>
    </g>
  );
}

/**
 * 서비스 배지. 넓은 타일은 오른쪽 위 모서리에 걸치고(오른쪽 정렬),
 * 호스트 타일은 위쪽 포트·케이블과 겹치지 않게 주소 줄 아래에 가운데 정렬로 둔다.
 */
function ServiceBadges({ badges, width, below }: { badges: string[]; width: number; below?: number }) {
  const h = 16;
  const pad = 6;
  const gap = 4;
  const widths = badges.map((b) => Math.round(textWidth(b)) + pad * 2);
  const items: preact.JSX.Element[] = [];
  if (below !== undefined) {
    const total = widths.reduce((a, w) => a + w, 0) + (badges.length - 1) * gap;
    let x = (width - total) / 2;
    badges.forEach((b, i) => {
      items.push(badge(b, x, below, widths[i]!, h));
      x += widths[i]! + gap;
    });
    return <g>{items}</g>;
  }
  // 넓은 타일: 오른쪽 위 모서리에서 왼쪽으로 채우되, 위쪽 포트(가운데) 영역에 닿으면 한 줄 위로 올린다
  const limit = width / 2 + 10;
  let x = width + 4;
  let y = -h / 2 - 2;
  [...badges].reverse().forEach((b, k) => {
    const w = widths[badges.length - 1 - k]!;
    if (x - w < limit && x !== width + 4) {
      x = width + 4;
      y -= h + gap;
    }
    x -= w;
    items.push(badge(b, x, y, w, h));
    x -= gap;
  });
  return <g>{items}</g>;
}

function badge(label: string, x: number, y: number, w: number, h: number) {
  return (
    <g key={label} class="badge" transform={`translate(${x},${y})`}>
      <rect width={w} height={h} rx={h / 2} />
      <text x={w / 2} y={h / 2 + 3.5}>
        {label}
      </text>
    </g>
  );
}

function textWidth(s: string): number {
  let w = 0;
  for (const ch of s) w += ch.charCodeAt(0) > 0x2e80 ? 10.5 : ch === " " ? 3.2 : 6.4;
  return w;
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

/**
 * 포트에서 수직으로 나갔다가 상대 포트로 수직으로 들어가는 베지어.
 * 상대가 포트 방향의 반대편(예: 아래쪽 포트인데 상대가 위)에 있으면 짧게만 나갔다가 굽는다 — 스위치 아래 포트에서 위의 라우터로 가는 케이블.
 */
function cableCurve(a: Anchor, b: Anchor): Curve {
  const dist = Math.hypot(b.x - a.x, b.y - a.y);
  const lead = Math.min(90, Math.max(28, dist * 0.45));
  const leadFor = (from: Anchor, to: Anchor) => {
    const towardPort = from.side === "top" ? to.y < from.y : to.y > from.y;
    return towardPort ? lead : 8;
  };
  const la = leadFor(a, b);
  const lb = leadFor(b, a);
  const ay = a.side === "top" ? a.y - la : a.y + la;
  const by = b.side === "top" ? b.y - lb : b.y + lb;
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

/** 무선 링크의 양 끝점: 단말 위쪽 안테나 ↔ 기지 타일 중심 */
function wirelessSegment(l: WirelessLink, byId: Map<string, Device>): { a: { x: number; y: number }; b: { x: number; y: number } } | null {
  const c = byId.get(l.client);
  const b = byId.get(l.base);
  if (!c || !b) return null;
  const cs = specOf(c);
  const bs = specOf(b);
  return { a: { x: c.x + cs.width / 2, y: c.y - PORT_DEPTH }, b: { x: b.x + bs.width / 2, y: b.y + bs.height / 2 } };
}

/** 링크 위를 이동 중인 패킷. 매 프레임 simTime 을 구독한다 */
function PacketLayer({ byId, cables, wireless }: { byId: Map<string, Device>; cables: Cable[]; wireless: WirelessLink[] }) {
  const now = simTime.value;
  const cableById = new Map(cables.map((c) => [c.id, c]));
  const wlById = new Map(wireless.map((l) => [l.id, l]));
  const items = sim.inFlight().map((tx) => {
    const frac = Math.min(1, Math.max(0, (now - tx.departAt) / (tx.arriveAt - tx.departAt)));
    let p: { x: number; y: number };
    const wlink = wlById.get(tx.linkId);
    if (wlink) {
      const seg = wirelessSegment(wlink, byId);
      if (!seg) return null;
      const f = tx.from.node === wlink.client ? frac : 1 - frac;
      p = { x: seg.a.x + (seg.b.x - seg.a.x) * f, y: seg.a.y + (seg.b.y - seg.a.y) * f };
    } else {
      const cable = cableById.get(tx.linkId);
      if (!cable) return null;
      const a = byId.get(cable.a.device);
      const b = byId.get(cable.b.device);
      if (!a || !b) return null;
      const curve = cableCurve(portAnchor(a, cable.a.port), portAnchor(b, cable.b.port));
      p = pointOn(curve, tx.from.node === cable.a.device ? frac : 1 - frac);
    }
    const lost = tx.lost && tx.lostAt !== undefined;
    const fade = lost ? Math.max(0.15, 1 - (now - tx.departAt) / (tx.lostAt! - tx.departAt)) : 1;
    return (
      <g key={tx.id} class={`packet ${frameCategory(tx.frame)}${lost ? " lost" : ""}`} transform={`translate(${p.x},${p.y})`} opacity={fade}>
        <circle r={7} />
        {lost && <path d="M-3.5,-3.5 L3.5,3.5 M3.5,-3.5 L-3.5,3.5" />}
        <text y={-13}>{lost ? `${shortLabel(tx.frame)} 손실` : shortLabel(tx.frame)}</text>
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
