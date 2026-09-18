import type { ComponentChildren } from "preact";
import { useRef } from "preact/hooks";
import { ipToInt, prefixToMask, intToIp, sameSubnet } from "../core/addr";
import { Host } from "../core/nodes/host";
import { Internet, KNOWN_SERVERS } from "../core/nodes/internet";
import { L3Node } from "../core/nodes/l3";
import type { SnapshotTable as SnapshotTableData } from "../core/nodes/node";
import { Router } from "../core/nodes/router";
import { sim, simVersion } from "../model/sim";
import { removeCable, removeDevice, selectedCable, selectedDevice, topology, updateCable, updateDevice } from "../model/store";
import {
  cableAt,
  DEFAULT_DHCP_SERVER,
  DEFAULT_WAN,
  defaultL3,
  peerOf,
  specOf,
  type Cable,
  type Device,
  type HostSettings,
  type IfaceSettings,
  type L3Settings,
  type RouterSettings,
  type WanSettings,
} from "../model/topology";
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
      <Section title="실험: 패킷 유실">
        <Field label="손실률">
          <select class="input" value={String(Math.round((c.loss ?? 0) * 100))} onChange={(e) => updateCable(c.id, (x) => ({ ...x, loss: Number(e.currentTarget.value) / 100 }))}>
            <option value="0">없음</option>
            <option value="10">10%</option>
            <option value="30">30%</option>
            <option value="50">50%</option>
          </select>
        </Field>
        <button class="btn wide" onClick={() => sim.dropNext(c.id)}>
          다음 패킷 1개 유실시키기
        </button>
        <p class="note">유실된 패킷은 케이블 중간에서 사라집니다. TCP 는 ACK 가 안 오면 재전송하고, ping 은 시간 초과로 실패합니다.</p>
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
      {d.host && <ServiceSection d={d} h={d.host} />}
      {d.router && <RouterSection d={d} r={d.router} />}
      {spec.role === "l3" && <L3Section d={d} l3={d.l3 ?? defaultL3(d.kind)} />}
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

function Toggle({ on, onToggle }: { on: boolean; onToggle: () => void }) {
  return (
    <span
      class={`toggle${on ? " on" : ""}`}
      role="switch"
      aria-checked={on}
      tabIndex={0}
      onClick={onToggle}
      onKeyDown={(e) => {
        if (e.key === " " || e.key === "Enter") {
          e.preventDefault();
          onToggle();
        }
      }}
    />
  );
}

/** 인터페이스 하나의 IP 설정 (자동/수동 + 주소·서브넷·게이트웨이). 호스트·WAN·게이트웨이가 공유 */
function IfaceFields({ value, onChange, gatewayLabel = "게이트웨이", dhcpNote }: { value: IfaceSettings; onChange: (patch: Partial<IfaceSettings>) => void; gatewayLabel?: string; dhcpNote: string }) {
  const isStatic = value.ipMode === "static";
  return (
    <>
      <div class="segmented" role="radiogroup">
        <button class={!isStatic ? "on" : ""} onClick={() => onChange({ ipMode: "dhcp" })}>
          자동 (DHCP)
        </button>
        <button class={isStatic ? "on" : ""} onClick={() => onChange({ ipMode: "static" })}>
          수동
        </button>
      </div>
      {isStatic ? (
        <>
          <Field label="IP 주소" error={ipError(value.ip, true)}>
            <input class="input mono" value={value.ip} placeholder="192.168.0.1" onInput={(e) => onChange({ ip: e.currentTarget.value })} />
          </Field>
          <Field label="서브넷">
            <div class="prefix">
              <span class="mono">/</span>
              <input
                class="input mono"
                type="number"
                min={0}
                max={32}
                value={value.prefix}
                onInput={(e) => onChange({ prefix: Math.min(32, Math.max(0, Number(e.currentTarget.value) || 0)) })}
              />
              <span class="mono muted">{intToIp(prefixToMask(value.prefix))}</span>
            </div>
          </Field>
          <Field label={gatewayLabel} error={ipError(value.gateway, false)}>
            <input class="input mono" value={value.gateway} placeholder="비우면 없음" onInput={(e) => onChange({ gateway: e.currentTarget.value })} />
          </Field>
        </>
      ) : (
        <p class="note">{dhcpNote}</p>
      )}
    </>
  );
}

/** 다른 수동 인터페이스와 서브넷이 겹치면 그 인터페이스 이름 */
function subnetClash(l3: L3Settings, names: string[], i: number): string | undefined {
  const me = l3.interfaces[i];
  if (!me || me.ipMode !== "static" || !validIp(me.ip)) return undefined;
  for (let k = 0; k < l3.interfaces.length; k++) {
    const o = l3.interfaces[k];
    if (k === i || !o || o.ipMode !== "static" || !validIp(o.ip)) continue;
    if (sameSubnet(me.ip, o.ip, Math.min(me.prefix, o.prefix))) return names[k];
  }
  return undefined;
}

function routeError(l3: L3Settings, r: L3Settings["routes"][number]): string | undefined {
  if (!validIp(r.dest) || !validIp(r.via)) return "목적지와 다음 홉 주소가 필요합니다";
  if (r.prefix < 1) return "프리픽스는 1 이상 (기본 경로는 업링크의 기본 경로 칸에)";
  const statics = l3.interfaces.filter((f) => f.ipMode === "static" && validIp(f.ip));
  if (statics.some((f) => f.ip === r.via)) return "다음 홉이 내 주소입니다";
  if (statics.length > 0 && !statics.some((f) => sameSubnet(r.via, f.ip, f.prefix))) return "다음 홉이 연결된 서브넷 안에 없습니다";
  return undefined;
}

function L3Section({ d, l3 }: { d: Device; l3: L3Settings }) {
  const spec = specOf(d);
  const isNat = d.kind === "nat";
  const names = spec.ports.map((p) => p.name);
  const setIface = (i: number, patch: Partial<IfaceSettings>) =>
    updateDevice(d.id, (x) => {
      const cur = x.l3 ?? defaultL3(x.kind);
      const interfaces = cur.interfaces.map((f, k) => (k === i ? { ...f, ...patch } : f));
      return { ...x, l3: { ...cur, interfaces } };
    });
  const setRoutes = (routes: L3Settings["routes"]) => updateDevice(d.id, (x) => ({ ...x, l3: { ...(x.l3 ?? defaultL3(x.kind)), routes } }));
  return (
    <>
      {spec.ports.map((p, i) => {
        const v = l3.interfaces[i] ?? { ipMode: "static" as const, ip: "", prefix: 24, gateway: "" };
        const isUp = p.side === "top";
        const title = isNat ? (i === 0 ? "outside 인터페이스 (공인 쪽)" : "inside 인터페이스 (사설 쪽)") : `${p.name} 인터페이스${isUp ? " (업링크)" : ""}`;
        return (
          <Section key={p.name} title={title}>
            <IfaceFields
              value={v}
              onChange={(patch) => setIface(i, patch)}
              gatewayLabel={isUp ? "기본 경로" : "게이트웨이"}
              dhcpNote={isUp ? "위쪽에 연결된 장치(인터넷 또는 다른 라우터)에서 주소와 기본 경로를 받습니다." : "이 인터페이스가 DHCP 로 주소를 받습니다. 보통 안쪽 인터페이스는 수동으로 고정합니다."}
            />
            {subnetClash(l3, names, i) && <p class="note error-note">{subnetClash(l3, names, i)} 인터페이스와 서브넷이 겹칩니다. 라우터는 인터페이스마다 다른 서브넷이어야 합니다.</p>}
            {!isUp && v.ipMode === "static" && <p class="note">이 서브넷의 호스트들은 게이트웨이를 {v.ip || "이 주소"} 로 두어야 다른 네트워크로 나갈 수 있습니다.</p>}
          </Section>
        );
      })}
      <Section title="정적 경로">
        {l3.routes.length === 0 && <p class="note">연결된 서브넷과 기본 경로 외에 알아야 할 경로가 있으면 추가합니다. {isNat ? "안쪽에 라우터가 또 있으면 그 뒤 서브넷(예: 192.168.0.0/16)을 안쪽 라우터로 보내는 경로가 필요합니다." : ""}</p>}
        {l3.routes.map((r, i) => (
          <div key={i} class="route-row">
            <span class="muted">목적지</span>
            <input class="input mono" value={r.dest} placeholder="192.168.0.0" title="목적지 네트워크" onInput={(e) => setRoutes(l3.routes.map((x, k) => (k === i ? { ...x, dest: e.currentTarget.value } : x)))} />
            <span class="mono">/</span>
            <input class="input mono prefix-in" type="number" min={0} max={32} value={r.prefix} onInput={(e) => setRoutes(l3.routes.map((x, k) => (k === i ? { ...x, prefix: Math.min(32, Math.max(0, Number(e.currentTarget.value) || 0)) } : x)))} />
            <span class="muted">다음 홉</span>
            <input class="input mono via" value={r.via} placeholder="연결된 서브넷 안의 주소" title="다음 홉 주소 (연결된 서브넷 안)" onInput={(e) => setRoutes(l3.routes.map((x, k) => (k === i ? { ...x, via: e.currentTarget.value } : x)))} />
            <button class="icon-btn" title="경로 삭제" onClick={() => setRoutes(l3.routes.filter((_, k) => k !== i))}>
              <Icon name="trash" size={15} />
            </button>
            {routeError(l3, r) && <div class="error route-error">{routeError(l3, r)}</div>}
          </div>
        ))}
        <button class="btn wide" onClick={() => setRoutes([...l3.routes, { dest: "", prefix: 24, via: "" }])}>
          <Icon name="plus" size={14} />
          경로 추가
        </button>
      </Section>
    </>
  );
}

function ServiceSection({ d, h }: { d: Device; h: HostSettings }) {
  const on = (h.services ?? []).includes(80);
  const toggle = () => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, services: on ? (x.host!.services ?? []).filter((p) => p !== 80) : [...(x.host!.services ?? []), 80] } }));
  const ds = h.dhcpServer ?? DEFAULT_DHCP_SERVER;
  const setDs = (patch: Partial<typeof ds>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, dhcpServer: { ...(x.host!.dhcpServer ?? DEFAULT_DHCP_SERVER), ...patch } } }));
  const staticIp = h.ipMode === "static" && validIp(h.ip) ? h.ip : undefined;
  const rangeErr = (v: string) => {
    const base = ipError(v, true);
    if (base) return base;
    if (staticIp && !sameSubnet(v, staticIp, h.prefix)) return `내 서브넷(${staticIp}/${h.prefix}) 밖입니다`;
    return undefined;
  };
  return (
    <Section title="서비스">
      <label class="toggle-row">
        <span>
          웹 서버 <span class="mono muted">TCP 80</span>
        </span>
        <Toggle on={on} onToggle={toggle} />
      </label>
      <p class="note">{on ? "포트 80 으로 오는 연결 요청(SYN)에 응답합니다. 다른 호스트에서 이 장치로 연결해 보세요." : "꺼져 있으면 연결 요청에 RST 로 거부합니다."}</p>
      <label class="toggle-row">
        <span>
          DHCP 서버 <span class="mono muted">UDP 67</span>
        </span>
        <Toggle on={ds.enabled} onToggle={() => setDs({ enabled: !ds.enabled })} />
      </label>
      {ds.enabled && (
        <>
          {!staticIp && <p class="note error-note">DHCP 서버는 자기 주소가 고정돼 있어야 합니다. 위의 IP 설정을 수동으로 바꾸세요.</p>}
          <Field label="시작 주소" error={rangeErr(ds.start)}>
            <input class="input mono" value={ds.start} onInput={(e) => setDs({ start: e.currentTarget.value })} />
          </Field>
          <Field label="끝 주소" error={rangeErr(ds.end)}>
            <input class="input mono" value={ds.end} onInput={(e) => setDs({ end: e.currentTarget.value })} />
          </Field>
          <Field label="게이트웨이 안내" error={ipError(ds.router, false)}>
            <input class="input mono" value={ds.router} placeholder="비우면 안내 없음" onInput={(e) => setDs({ router: e.currentTarget.value })} />
          </Field>
          <p class="note">클라이언트에게 이 범위의 주소와 함께 게이트웨이를 알려줍니다. 게이트웨이를 비우면 클라이언트는 같은 서브넷 밖으로 나갈 수 없습니다.</p>
        </>
      )}
    </Section>
  );
}

/** LAN 주소/서브넷이 바뀔 때, 기존 범위가 옛 서브넷 안에 있었다면 호스트 부분을 유지한 채 새 서브넷으로 옮긴다 */
function remapRange(oldIp: string, oldPrefix: number, newIp: string, newPrefix: number, range: { start: string; end: string }): { start: string; end: string } | null {
  if (!validIp(oldIp) || !validIp(newIp) || !validIp(range.start) || !validIp(range.end)) return null;
  if (!sameSubnet(range.start, oldIp, oldPrefix) || !sameSubnet(range.end, oldIp, oldPrefix)) return null;
  const hostMask = ~prefixToMask(newPrefix) >>> 0;
  const net = (ipToInt(newIp) & prefixToMask(newPrefix)) >>> 0;
  const move = (ip: string) => intToIp((net | (ipToInt(ip) & hostMask)) >>> 0);
  return { start: move(range.start), end: move(range.end) };
}

function rangeError(r: RouterSettings, which: "start" | "end"): string | undefined {
  const v = r.dhcp[which];
  const base = ipError(v, true);
  if (base) return base;
  if (validIp(r.lanIp) && !sameSubnet(v, r.lanIp, r.lanPrefix)) return `LAN 서브넷 ${intToIp((ipToInt(r.lanIp) & prefixToMask(r.lanPrefix)) >>> 0)}/${r.lanPrefix} 밖입니다`;
  if (which === "end" && validIp(r.dhcp.start) && ipToInt(r.dhcp.start) > ipToInt(v)) return "시작 주소보다 앞입니다";
  return undefined;
}

function RouterSection({ d, r }: { d: Device; r: RouterSettings }) {
  const set = (patch: Partial<RouterSettings>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, ...patch } }));
  const setDhcp = (patch: Partial<RouterSettings["dhcp"]>) => set({ dhcp: { ...r.dhcp, ...patch } });
  const setLan = (lanIp: string, lanPrefix: number) => {
    const moved = remapRange(r.lanIp, r.lanPrefix, lanIp, lanPrefix, r.dhcp);
    set({ lanIp, lanPrefix, dhcp: moved ? { ...r.dhcp, ...moved } : r.dhcp });
  };
  return (
    <>
      <Section title="LAN 인터페이스">
        <Field label="IP 주소" error={ipError(r.lanIp, true)}>
          <input class="input mono" value={r.lanIp} onInput={(e) => setLan(e.currentTarget.value, r.lanPrefix)} />
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
              onInput={(e) => setLan(r.lanIp, Math.min(32, Math.max(0, Number(e.currentTarget.value) || 0)))}
            />
            <span class="mono muted">{intToIp(prefixToMask(r.lanPrefix))}</span>
          </div>
        </Field>
        <p class="note">주소를 바꾸면 DHCP 범위도 같은 서브넷으로 따라갑니다. 이미 주소를 받은 호스트는 "DHCP 다시 요청" 을 해야 새 주소를 받습니다.</p>
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
            <Field label="시작 주소" error={rangeError(r, "start")}>
              <input class="input mono" value={r.dhcp.start} onInput={(e) => setDhcp({ start: e.currentTarget.value })} />
            </Field>
            <Field label="끝 주소" error={rangeError(r, "end")}>
              <input class="input mono" value={r.dhcp.end} onInput={(e) => setDhcp({ end: e.currentTarget.value })} />
            </Field>
            <p class="note">자동(DHCP) 로 설정된 호스트가 연결되면 이 범위에서 주소를 빌려줍니다. 게이트웨이는 LAN 주소로 안내합니다. 이미 실패한 호스트는 그 호스트의 진단에서 "DHCP 다시 요청" 을 누르세요.</p>
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

/** ping, TCP 연결, DHCP 다시 요청 */
function DiagSection({ d }: { d: Device }) {
  void simVersion.value;
  const node = sim.node(d.id);
  const input = useRef<HTMLInputElement>(null);
  const tcpInput = useRef<HTMLInputElement>(null);
  const portInput = useRef<HTMLInputElement>(null);
  if (!(node instanceof Host)) return null;

  const targets: { ip: string; name: string }[] = [];
  const servers: { ip: string; name: string }[] = [];
  let hasInternet = false;
  for (const other of topology.value.devices) {
    if (other.id === d.id) continue;
    const n = sim.node(other.id);
    if (n instanceof Internet) hasInternet = true;
    const ip = n instanceof Host ? n.ip : n instanceof Router ? n.lan.ip : undefined;
    if (ip) targets.push({ ip, name: other.name });
    if (n instanceof L3Node) n.ifaces.forEach((f, k) => f.ip && targets.push({ ip: f.ip, name: `${other.name} ${n.names[k]}` }));
    if (n instanceof Host && ip && n.tcp.listening.size > 0) servers.push({ ip, name: other.name });
  }
  if (hasInternet) {
    for (const [ip, name] of Object.entries(KNOWN_SERVERS)) {
      targets.push({ ip, name });
      servers.push({ ip, name });
    }
  }
  const send = () => {
    const dst = input.current?.value.trim();
    if (!dst || !validIp(dst)) {
      input.current?.focus();
      return;
    }
    sim.act({ kind: "ping", nodeId: d.id, dst });
  };
  const connect = () => {
    const dst = tcpInput.current?.value.trim();
    const port = Number(portInput.current?.value) || 80;
    if (!dst || !validIp(dst)) {
      tcpInput.current?.focus();
      return;
    }
    sim.act({ kind: "tcp-connect", nodeId: d.id, dst, port });
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
      <div class="ping-row tcp-row">
        <input
          ref={tcpInput}
          class="input mono"
          list={`servers-${d.id}`}
          placeholder="연결할 서버 주소"
          defaultValue={servers[0]?.ip ?? ""}
          onKeyDown={(e) => {
            if (e.key === "Enter") connect();
          }}
        />
        <datalist id={`servers-${d.id}`}>
          {servers.map((t) => (
            <option key={t.ip} value={t.ip}>
              {t.name}
            </option>
          ))}
        </datalist>
        <input ref={portInput} class="input mono port" type="number" min={1} max={65535} defaultValue="80" title="포트" />
        <button class="btn" onClick={connect} title="TCP 연결 (3-way handshake → 요청 → 응답 → 종료)">
          <Icon name="send" size={14} />
          연결
        </button>
      </div>
      <p class="note">TCP 연결은 3-way handshake 뒤 "GET /" 요청을 보내고, 서버 응답 3세그먼트를 받은 다음 FIN 으로 닫습니다. 결과는 아래 TCP 연결 표와 로그에서 봅니다.</p>
      {node.ipMode === "dhcp" && (
        <button class="btn wide" onClick={() => sim.act({ kind: "dhcp-renew", nodeId: d.id })} disabled={!node.linkUp}>
          <Icon name="refresh" size={14} />
          DHCP 다시 요청
        </button>
      )}
    </Section>
  );
}
