import type { ComponentChildren } from "preact";
import { useRef } from "preact/hooks";
import { ipToInt, prefixToMask, intToIp } from "../core/addr";
import { Host } from "../core/nodes/host";
import { Internet, KNOWN_SERVERS } from "../core/nodes/internet";
import type { SnapshotTable as SnapshotTableData } from "../core/nodes/node";
import { Router } from "../core/nodes/router";
import { sim, simVersion } from "../model/sim";
import { removeCable, removeDevice, selectedCable, selectedDevice, topology, updateDevice } from "../model/store";
import { cableAt, DEFAULT_WAN, peerOf, specOf, type Cable, type Device, type HostSettings, type RouterSettings, type WanSettings } from "../model/topology";
import { Icon } from "./Icons";

export function Inspector() {
  const device = selectedDevice.value;
  const cable = selectedCable.value;
  return (
    <aside class="inspector">
      {device ? <DevicePanel d={device} /> : cable ? <CablePanel c={cable} /> : <NetworkPanel />}
    </aside>
  );
}

// ---------- 공통 조각 ----------

function Section({ title, children }: { title?: string; children: ComponentChildren }) {
  return (
    <section class="section">
      {title && <h3>{title}</h3>}
      {children}
    </section>
  );
}

function Field({ label, children, error }: { label: string; children: ComponentChildren; error?: string }) {
  return (
    <div class={`field${error ? " has-error" : ""}`}>
      <label>{label}</label>
      <div class="control">
        {children}
        {error && <div class="error">{error}</div>}
      </div>
    </div>
  );
}

function validIp(s: string): boolean {
  try {
    ipToInt(s);
    return true;
  } catch {
    return false;
  }
}

function ipError(s: string, required: boolean): string | undefined {
  if (!s) return required ? "필요한 값입니다" : undefined;
  return validIp(s) ? undefined : "예: 192.168.0.10";
}

function deviceName(id: string): string {
  return topology.value.devices.find((d) => d.id === id)?.name ?? "?";
}

function portName(id: string, port: number): string {
  const d = topology.value.devices.find((x) => x.id === id);
  return d ? (specOf(d).ports[port]?.name ?? `#${port}`) : `#${port}`;
}

// ---------- 패널 ----------

function NetworkPanel() {
  const t = topology.value;
  return (
    <>
      <header class="panel-head">
        <Icon name="mark" />
        <div>
          <h2>네트워크</h2>
          <p>선택한 장치나 케이블의 설정이 여기에 표시됩니다.</p>
        </div>
      </header>
      <Section>
        <div class="stat-row">
          <span>장치</span>
          <b>{t.devices.length}</b>
        </div>
        <div class="stat-row">
          <span>케이블</span>
          <b>{t.cables.length}</b>
        </div>
      </Section>
      <Section title="사용법">
        <ul class="hints">
          <li>팔레트의 장치를 캔버스로 끌어다 놓습니다.</li>
          <li>케이블 도구(C)로 장치에서 장치로 끌면 빈 포트끼리 연결됩니다.</li>
          <li>Shift 를 누른 채 끌어도 케이블이 연결됩니다.</li>
          <li>휠로 이동, ⌘ + 휠로 확대·축소.</li>
        </ul>
      </Section>
    </>
  );
}

function CablePanel({ c }: { c: Cable }) {
  return (
    <>
      <header class="panel-head">
        <Icon name="cable" />
        <div>
          <h2>케이블</h2>
          <p>양쪽 포트를 잇는 이더넷 케이블</p>
        </div>
      </header>
      <Section title="연결">
        <div class="stat-row">
          <span>{deviceName(c.a.device)}</span>
          <b class="mono">{portName(c.a.device, c.a.port)}</b>
        </div>
        <div class="stat-row">
          <span>{deviceName(c.b.device)}</span>
          <b class="mono">{portName(c.b.device, c.b.port)}</b>
        </div>
      </Section>
      <Section>
        <button class="btn danger" onClick={() => removeCable(c.id)}>
          <Icon name="trash" size={16} />
          케이블 제거
        </button>
      </Section>
    </>
  );
}

function DevicePanel({ d }: { d: Device }) {
  const spec = specOf(d);
  const t = topology.value;
  return (
    <>
      <header class="panel-head">
        <Icon name={d.kind} />
        <div>
          <h2>{d.name}</h2>
          <p>{spec.label}</p>
        </div>
      </header>
      <Section>
        <Field label="이름">
          <input class="input" value={d.name} onInput={(e) => updateDevice(d.id, (x) => ({ ...x, name: e.currentTarget.value }))} />
        </Field>
      </Section>
      <StatusSection d={d} />
      <Section title="포트">
        {spec.ports.map((p, i) => {
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
      {d.host && <HostSection d={d} h={d.host} />}
      {d.router && <RouterSection d={d} r={d.router} />}
      {d.host && <DiagSection d={d} />}
      <LiveTables d={d} />
      <Section>
        <button class="btn danger" onClick={() => removeDevice(d.id)}>
          <Icon name="trash" size={16} />
          장치 삭제
        </button>
      </Section>
    </>
  );
}

function HostSection({ d, h }: { d: Device; h: HostSettings }) {
  const set = (patch: Partial<HostSettings>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, ...patch } }));
  const isStatic = h.ipMode === "static";
  return (
    <Section title="IP 설정">
      <div class="segmented" role="radiogroup">
        <button class={h.ipMode === "dhcp" ? "on" : ""} onClick={() => set({ ipMode: "dhcp" })}>
          자동 (DHCP)
        </button>
        <button class={isStatic ? "on" : ""} onClick={() => set({ ipMode: "static" })}>
          수동
        </button>
      </div>
      {isStatic ? (
        <>
          <Field label="IP 주소" error={ipError(h.ip, true)}>
            <input class="input mono" value={h.ip} placeholder="192.168.0.10" onInput={(e) => set({ ip: e.currentTarget.value })} />
          </Field>
          <Field label="서브넷">
            <div class="prefix">
              <span class="mono">/</span>
              <input
                class="input mono"
                type="number"
                min={0}
                max={32}
                value={h.prefix}
                onInput={(e) => set({ prefix: Math.min(32, Math.max(0, Number(e.currentTarget.value) || 0)) })}
              />
              <span class="mono muted">{intToIp(prefixToMask(h.prefix))}</span>
            </div>
          </Field>
          <Field label="게이트웨이" error={ipError(h.gateway, false)}>
            <input class="input mono" value={h.gateway} placeholder="192.168.0.1" onInput={(e) => set({ gateway: e.currentTarget.value })} />
          </Field>
        </>
      ) : (
        <p class="note">연결된 네트워크의 DHCP 서버에서 IP 주소, 서브넷, 게이트웨이를 받습니다. DHCP 가 없으면 주소 없이 남습니다.</p>
      )}
    </Section>
  );
}

function RouterSection({ d, r }: { d: Device; r: RouterSettings }) {
  const set = (patch: Partial<RouterSettings>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, ...patch } }));
  const setDhcp = (patch: Partial<RouterSettings["dhcp"]>) => set({ dhcp: { ...r.dhcp, ...patch } });
  return (
    <>
      <Section title="LAN 인터페이스">
        <Field label="IP 주소" error={ipError(r.lanIp, true)}>
          <input class="input mono" value={r.lanIp} onInput={(e) => set({ lanIp: e.currentTarget.value })} />
        </Field>
        <Field label="서브넷">
          <div class="prefix">
            <span class="mono">/</span>
            <input
              class="input mono"
              type="number"
              min={0}
              max={32}
              value={r.lanPrefix}
              onInput={(e) => set({ lanPrefix: Math.min(32, Math.max(0, Number(e.currentTarget.value) || 0)) })}
            />
            <span class="mono muted">{intToIp(prefixToMask(r.lanPrefix))}</span>
          </div>
        </Field>
      </Section>
      <Section title="DHCP 서비스">
        <label class="toggle-row">
          <span>{r.dhcp.enabled ? "켜짐" : "꺼짐"}</span>
          <span class={`toggle${r.dhcp.enabled ? " on" : ""}`} role="switch" aria-checked={r.dhcp.enabled} tabIndex={0}
            onClick={() => setDhcp({ enabled: !r.dhcp.enabled })}
            onKeyDown={(e) => { if (e.key === " " || e.key === "Enter") { e.preventDefault(); setDhcp({ enabled: !r.dhcp.enabled }); } }}
          />
        </label>
        {r.dhcp.enabled ? (
          <>
            <Field label="시작 주소" error={ipError(r.dhcp.start, true)}>
              <input class="input mono" value={r.dhcp.start} onInput={(e) => setDhcp({ start: e.currentTarget.value })} />
            </Field>
            <Field label="끝 주소" error={ipError(r.dhcp.end, true)}>
              <input class="input mono" value={r.dhcp.end} onInput={(e) => setDhcp({ end: e.currentTarget.value })} />
            </Field>
            <p class="note">자동(DHCP) 로 설정된 호스트가 연결되면 이 범위에서 주소를 빌려줍니다. 게이트웨이는 LAN 주소로 안내합니다.</p>
          </>
        ) : (
          <p class="note">꺼져 있으면 호스트는 주소를 받지 못합니다. 각 호스트에서 IP 를 수동으로 설정해야 통신할 수 있습니다.</p>
        )}
      </Section>
      <WanSection d={d} w={r.wan ?? DEFAULT_WAN} />
    </>
  );
}

function WanSection({ d, w }: { d: Device; w: WanSettings }) {
  const set = (patch: Partial<WanSettings>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, wan: { ...(x.router!.wan ?? DEFAULT_WAN), ...patch } } }));
  const isStatic = w.ipMode === "static";
  return (
    <Section title="WAN 인터페이스">
      <div class="segmented" role="radiogroup">
        <button class={!isStatic ? "on" : ""} onClick={() => set({ ipMode: "dhcp" })}>
          자동 (DHCP)
        </button>
        <button class={isStatic ? "on" : ""} onClick={() => set({ ipMode: "static" })}>
          수동
        </button>
      </div>
      {isStatic ? (
        <>
          <Field label="공인 IP" error={ipError(w.ip, true)}>
            <input class="input mono" value={w.ip} placeholder="203.0.113.50" onInput={(e) => set({ ip: e.currentTarget.value })} />
          </Field>
          <Field label="서브넷">
            <div class="prefix">
              <span class="mono">/</span>
              <input
                class="input mono"
                type="number"
                min={0}
                max={32}
                value={w.prefix}
                onInput={(e) => set({ prefix: Math.min(32, Math.max(0, Number(e.currentTarget.value) || 0)) })}
              />
              <span class="mono muted">{intToIp(prefixToMask(w.prefix))}</span>
            </div>
          </Field>
          <Field label="게이트웨이" error={ipError(w.gateway, true)}>
            <input class="input mono" value={w.gateway} placeholder="203.0.113.1" onInput={(e) => set({ gateway: e.currentTarget.value })} />
          </Field>
        </>
      ) : (
        <p class="note">wan 포트에 인터넷을 연결하면 ISP 에서 공인 주소와 게이트웨이를 받습니다. LAN 의 사설 주소는 이 공인 주소로 NAT 됩니다.</p>
      )}
    </Section>
  );
}

// ---------- 시뮬레이션 상태 ----------

function StatusSection({ d }: { d: Device }) {
  void simVersion.value;
  const node = sim.node(d.id);
  if (!node || node.type === "switch") return null;
  const snap = node.snapshot();
  return (
    <Section title="현재 상태">
      {snap.info.map(([k, v]) => (
        <div key={k} class="stat-row">
          <span>{k}</span>
          <b class="mono">{v}</b>
        </div>
      ))}
    </Section>
  );
}

function LiveTables({ d }: { d: Device }) {
  void simVersion.value;
  const node = sim.node(d.id);
  if (!node) return null;
  return (
    <>
      {node.snapshot().tables.map((t) => (
        <Section key={t.title} title={t.title}>
          <SnapshotTable t={t} />
        </Section>
      ))}
    </>
  );
}

function SnapshotTable({ t }: { t: SnapshotTableData }) {
  return (
    <table class="table">
      <thead>
        <tr>
          {t.columns.map((c) => (
            <th key={c}>{c}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {t.rows.length === 0 ? (
          <tr>
            <td class="empty" colSpan={t.columns.length}>
              비어 있음
            </td>
          </tr>
        ) : (
          t.rows.map((r, i) => (
            <tr key={i}>
              {r.map((c, j) => (
                <td key={j} class="mono">
                  {c}
                </td>
              ))}
            </tr>
          ))
        )}
      </tbody>
    </table>
  );
}

/** ping 과 DHCP 다시 요청 */
function DiagSection({ d }: { d: Device }) {
  void simVersion.value;
  const node = sim.node(d.id);
  const input = useRef<HTMLInputElement>(null);
  if (!(node instanceof Host)) return null;

  const targets: { ip: string; name: string }[] = [];
  let hasInternet = false;
  for (const other of topology.value.devices) {
    if (other.id === d.id) continue;
    const n = sim.node(other.id);
    if (n instanceof Internet) hasInternet = true;
    const ip = n instanceof Host ? n.ip : n instanceof Router ? n.lan.ip : undefined;
    if (ip) targets.push({ ip, name: other.name });
  }
  if (hasInternet) for (const [ip, name] of Object.entries(KNOWN_SERVERS)) targets.push({ ip, name });
  const send = () => {
    const dst = input.current?.value.trim();
    if (!dst || !validIp(dst)) {
      input.current?.focus();
      return;
    }
    sim.act({ kind: "ping", nodeId: d.id, dst });
  };
  return (
    <Section title="진단">
      <div class="ping-row">
        <input
          ref={input}
          class="input mono"
          list={`targets-${d.id}`}
          placeholder="ping 보낼 주소"
          defaultValue={targets[0]?.ip ?? ""}
          onKeyDown={(e) => {
            if (e.key === "Enter") send();
          }}
        />
        <datalist id={`targets-${d.id}`}>
          {targets.map((t) => (
            <option key={t.ip} value={t.ip}>
              {t.name}
            </option>
          ))}
        </datalist>
        <button class="btn" onClick={send}>
          <Icon name="send" size={14} />
          ping
        </button>
      </div>
      {node.pings.length > 0 && (
        <ul class="ping-log">
          {node.pings.slice(-5).reverse().map((p) => (
            <li key={p.seq} class={p.status}>
              <span class="mono">{p.dst}</span>
              <span>{p.status === "ok" ? `응답 ${p.rtt}ms` : p.status === "failed" ? `실패 · ${p.reason}` : "응답 기다리는 중"}</span>
            </li>
          ))}
        </ul>
      )}
      {node.ipMode === "dhcp" && (
        <button class="btn wide" onClick={() => sim.act({ kind: "dhcp-renew", nodeId: d.id })} disabled={!node.linkUp}>
          <Icon name="refresh" size={14} />
          DHCP 다시 요청
        </button>
      )}
    </Section>
  );
}
