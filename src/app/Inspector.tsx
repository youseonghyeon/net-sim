// 오른쪽 속성 패널: 선택(장치·다중·케이블·영역·없음)에 따라 패널을 고르고, 단일 장치는 개요/설정/진단/표 탭으로 나눈다.
// 섹션 구현은 ./inspector/* 에 있다 (ui: 공용 부품, panels: 장치 외 패널, l3·rules·host·router: 설정, diag: 진단·표).
import { useRef } from "preact/hooks";
import { hostStatus, serviceBadges, sim, simVersion, wanStatus } from "../model/sim";
import { signal } from "@preact/signals";
import {
  beginCoalesce,
  endCoalesce,
  INSPECTOR_MIN,
  INSPECTOR_WIDE,
  inspectorOpen,
  inspectorWidth,
  lintIssues,
  removeDevice,
  selectedCable,
  selectedDevice,
  selectedZone,
  selection,
  setInspectorWidth,
  toggleInspector,
  toggleInspectorWide,
  topology,
  updateDevice,
} from "../model/store";
import { cableAt, DEFAULT_FIREWALL_SETTINGS, defaultL3, peerOf, specOf, type Device } from "../model/topology";
import { Icon } from "./Icons";
import { DiagSection, InternetDiagSection, LiveTables, StatusSection } from "./inspector/diag";
import { HostSection, ServiceSection, WifiBaseSection, WifiClientSection } from "./inspector/host";
import { L3Section, VlanSection } from "./inspector/l3";
import { CablePanel, LintSection, MultiPanel, NetworkPanel, ZonePanel, deviceName, portName } from "./inspector/panels";
import { RouterSection } from "./inspector/router";
import { FirewallSection } from "./inspector/rules";
import { Field, Section } from "./inspector/ui";

export function Inspector() {
  const device = selectedDevice.value;
  const cable = selectedCable.value;
  const zone = selectedZone.value;
  const sel = selection.value;
  const width = inspectorWidth.value;
  const wide = width >= INSPECTOR_WIDE - 40;
  const resizing = useRef(false);
  const startWidth = useRef(width);
  if (!inspectorOpen.value) {
    return (
      <aside class="inspector collapsed">
        <button class="icon-btn" onClick={toggleInspector} title="속성 패널 펼치기 (⌘\)">
          <Icon name="panel" size={18} />
        </button>
      </aside>
    );
  }
  // 왼쪽 가장자리를 끌어 폭 조절. 패널 오른쪽 끝은 창에 붙어 있으므로 폭 = 창 오른쪽 - 포인터 x
  const onResizeDown = (e: PointerEvent) => {
    e.preventDefault();
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    resizing.current = true;
    startWidth.current = inspectorWidth.peek();
  };
  const onResizeMove = (e: PointerEvent) => {
    if (!resizing.current) return;
    const w = window.innerWidth - e.clientX;
    // 최소 폭보다 한참 더 오른쪽으로 끌면 아예 접는다 (레일의 펼치기 버튼으로 다시 연다)
    if (w < INSPECTOR_MIN - 70) {
      resizing.current = false;
      (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
      setInspectorWidth(startWidth.current); // 다시 펼치면 끌기 전 폭으로
      toggleInspector();
      return;
    }
    setInspectorWidth(w);
  };
  const onResizeUp = () => {
    resizing.current = false;
  };
  return (
    <aside class={`inspector${wide ? " wide" : ""}`}>
      <div class="inspector-resize" onPointerDown={onResizeDown} onPointerMove={onResizeMove} onPointerUp={onResizeUp} onPointerCancel={onResizeUp} title="끌어서 폭 조절" />
      {/* 입력칸 하나를 편집하는 동안의 변경은 되돌리기 한 단계로 묶는다 (한 글자마다 한 단계가 쌓이지 않게) */}
      <div
        class="inspector-scroll"
        onFocusIn={(e) => {
          const el = e.target as HTMLElement;
          if (el.tagName === "INPUT" || el.tagName === "SELECT") beginCoalesce();
        }}
        onFocusOut={(e) => {
          const el = e.target as HTMLElement;
          if (el.tagName === "INPUT" || el.tagName === "SELECT") endCoalesce();
        }}
      >
        <div class="inspector-tools">
          <button class="icon-btn" onClick={toggleInspectorWide} title={wide ? "보통 폭" : "넓게"}>
            <Icon name="widen" size={16} />
          </button>
          <button class="icon-btn" onClick={toggleInspector} title="속성 패널 접기 (⌘\)">
            <Icon name="panel" size={16} />
          </button>
        </div>
        {sel?.type === "devices" ? <MultiPanel key={sel.ids.join()} ids={sel.ids} /> : device ? <DevicePanel key={device.id} d={device} /> : cable ? <CablePanel c={cable} /> : zone ? <ZonePanel z={zone} /> : <NetworkPanel />}
      </div>
    </aside>
  );
}

// ---------- 공통 조각 ----------

type DeviceTab = "overview" | "config" | "diag" | "tables";

const TAB_LABEL: Record<DeviceTab, string> = { overview: "개요", config: "설정", diag: "진단", tables: "표" };

/** 마지막으로 본 탭 (장치를 바꿔도 가능하면 유지) */
const deviceTab = signal<DeviceTab>("overview");

/** 장치 역할 묶음 (팔레트와 같은 분류) — 타일·패널의 역할 색 */
export function roleGroupOf(d: Device): "end" | "switching" | "routing" {
  const role = specOf(d).role;
  if (role === "host") return "end";
  if (role === "switch" || role === "hub" || role === "ap") return "switching";
  return "routing";
}

function DevicePanel({ d }: { d: Device }) {
  void simVersion.value;
  const spec = specOf(d);
  const t = topology.value;
  const hasDiag = !!d.host || spec.role === "internet";
  const node = sim.node(d.id);
  const hasTables = !!node && node.snapshot().tables.length > 0;
  const tabs: DeviceTab[] = ["overview", "config", ...(hasDiag ? (["diag"] as const) : []), ...(hasTables || node ? (["tables"] as const) : [])];
  const tab = tabs.includes(deviceTab.value) ? deviceTab.value : "overview";
  const addr = hostStatus(d.id);
  const wan = wanStatus(d.id);
  const badges = serviceBadges(d.id);
  const issues = lintIssues.value.filter((i) => i.deviceId === d.id);
  const worst = issues.some((i) => i.severity === "error") ? "error" : issues.length ? "warn" : addr?.tone === "warn" || wan?.tone === "warn" ? "warn" : "ok";
  const hasConfig =
    !!d.host || !!d.router || spec.role === "l3" || d.kind === "switch" || d.kind === "ap" || d.kind === "firewall" || !!d.wifi;
  return (
    <>
      <header class={`panel-head device-head role-${roleGroupOf(d)}`}>
        <span class="head-icon">
          <Icon name={d.kind} size={18} />
        </span>
        <div>
          <h2>{d.name}</h2>
          <p>
            {spec.label}
            <span class={`state-dot ${worst}`} title={worst === "ok" ? "정상" : worst === "warn" ? "확인 필요" : "오류"} />
          </p>
        </div>
      </header>
      <nav class="tabs" role="tablist">
        {tabs.map((k) => (
          <button key={k} role="tab" aria-selected={tab === k} class={tab === k ? "on" : ""} onClick={() => (deviceTab.value = k)}>
            {TAB_LABEL[k]}
            {k === "overview" && issues.length > 0 && <span class={`tab-count ${worst}`}>{issues.length}</span>}
          </button>
        ))}
      </nav>
      {tab === "overview" && (
        <>
          <section class="summary">
            {wan && <SummaryLine line={wan} />}
            {addr && <SummaryLine line={addr} primary={!wan} />}
            {badges.length > 0 && (
              <div class="summary-badges">
                {badges.map((b) => (
                  <span key={b} class="pill">
                    {b}
                  </span>
                ))}
              </div>
            )}
          </section>
          {issues.length > 0 && <LintSection issues={issues} withNames={false} />}
          {d.wifi && <WifiClientSection d={d} />}
          {spec.ports.some((p) => !p.radio) && (
            <Section title="포트">
              {spec.ports.map((p, i) => {
                if (p.radio) return null;
                const c = cableAt(t, { device: d.id, port: i });
                const peer = c ? peerOf(c, d.id) : undefined;
                return (
                  <div key={p.name} class="port-row">
                    <span class={`dot${peer ? " up" : ""}`} />
                    <span class="mono">{p.name}</span>
                    {peer ? (
                      <span class="peer">
                        {deviceName(peer.device)} <span class="mono">{portName(peer.device, peer.port)}</span>
                      </span>
                    ) : (
                      <span class="peer none">연결 안 됨</span>
                    )}
                  </div>
                );
              })}
            </Section>
          )}
          {d.kind === "firewall" && (
            <Section title="동작 방식">
              <p class="note">
                투명(브리지) 방화벽입니다. IP 주소가 없어 ping 대상도, traceroute 홉도 아니고, 주소·경로·서브넷을 바꾸지 않은 채 케이블 사이에 끼웁니다. 위 포트 outside 에서 들어오는 패킷이 인바운드,
                아래 inside 에서 outside 로 나가는 패킷이 아웃바운드입니다. ARP 는 IP 가 아니라(L2) 규칙과 무관하게 통과하지만, DHCP·DNS 는 IP(UDP) 라 규칙에 걸립니다 — 기본 정책을 차단으로 두면 UDP 67/68 허용 규칙이 있어야 안쪽 호스트가 주소를 받습니다.
              </p>
            </Section>
          )}
          <Section>
            <Field label="이름">
              <input class="input" value={d.name} onInput={(e) => updateDevice(d.id, (x) => ({ ...x, name: e.currentTarget.value }))} />
            </Field>
            <button class="btn danger" onClick={() => removeDevice(d.id)}>
              <Icon name="trash" size={16} />
              장치 삭제
            </button>
          </Section>
        </>
      )}
      {tab === "config" && (
        <>
          {!hasConfig && (
            <Section>
              <p class="note">이 장치는 설정할 것이 없습니다. {spec.role === "hub" ? "허브는 받은 프레임을 모든 포트로 반복할 뿐입니다." : spec.role === "internet" ? "인터넷 노드는 ISP 역할을 고정으로 합니다." : ""}</p>
            </Section>
          )}
          {d.kind === "ap" && <WifiBaseSection d={d} />}
          {d.kind === "firewall" && (
            <FirewallSection value={d.firewall ?? { ...DEFAULT_FIREWALL_SETTINGS, enabled: true }} onChange={(v) => updateDevice(d.id, (x) => ({ ...x, firewall: v }))} uplinkName="outside" />
          )}
          {d.kind === "switch" && <VlanSection d={d} />}
          {d.host && <HostSection d={d} h={d.host} />}
          {d.host && <ServiceSection d={d} h={d.host} />}
          {d.router && <RouterSection d={d} r={d.router} />}
          {spec.role === "l3" && <L3Section d={d} l3={d.l3 ?? defaultL3(d.kind)} />}
        </>
      )}
      {tab === "diag" && (
        <>
          {d.host && <DiagSection d={d} />}
          {spec.role === "internet" && <InternetDiagSection d={d} />}
        </>
      )}
      {tab === "tables" && (
        <>
          <StatusSection d={d} />
          <LiveTables d={d} />
        </>
      )}
    </>
  );
}

/** 개요 탭의 주소·상태 한 줄 */
function SummaryLine({ line, primary }: { line: { text: string; tone: "ok" | "warn" | "muted"; mono: boolean }; primary?: boolean }) {
  return (
    <div class={`summary-line ${line.tone}${primary ? " primary" : ""}`}>
      <span class={`state-dot ${line.tone === "ok" ? "ok" : line.tone === "warn" ? "warn" : "muted"}`} />
      <span class={line.mono ? "mono" : ""}>{line.text}</span>
    </div>
  );
}
