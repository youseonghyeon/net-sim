import type { ComponentChildren } from "preact";
import { ipToInt, prefixToMask, intToIp } from "../core/addr";
import { removeCable, removeDevice, selectedCable, selectedDevice, topology, updateDevice } from "../model/store";
import { cableAt, peerOf, specOf, type Cable, type Device, type HostSettings, type RouterSettings } from "../model/topology";
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
    </>
  );
}
