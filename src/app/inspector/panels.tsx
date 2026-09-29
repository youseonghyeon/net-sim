// 장치 하나가 아닐 때의 패널: 네트워크 요약(구성 검사), 영역, 케이블, 다중 선택.
import { useRef } from "preact/hooks";
import { Host } from "../../core/nodes/host";
import { sim, simVersion } from "../../model/sim";
import {
  alignSelected,
  duplicateSelected,
  lintIssues,
  moveCableEnd,
  removeCable,
  removeCables,
  removeDevices,
  removeZone,
  selection,
  topology,
  updateCable,
  updateCables,
  updateDevices,
  updateZone,
  zoneAroundSelected,
} from "../../model/store";
import type { LintIssue } from "../../model/lint";
import { portProblem, specOf, type Cable, type HostSettings, devicesInZone, ZONE_TINTS, type Zone } from "../../model/topology";
import { Icon } from "../Icons";
import { Field, Section, ipError } from "./ui";

export function deviceName(id: string): string {
  return topology.value.devices.find((d) => d.id === id)?.name ?? "?";
}

export function portName(id: string, port: number): string {
  const d = topology.value.devices.find((x) => x.id === id);
  return d ? (specOf(d).ports[port]?.name ?? `#${port}`) : `#${port}`;
}

// ---------- 패널 ----------

/** 구성 검사 항목 하나: 무엇이 문제인지 + 고치는 법 */
export function LintItem({ issue, deviceName }: { issue: LintIssue; deviceName?: string }) {
  return (
    <li class={`lint-item ${issue.severity}`}>
      <span class="lint-dot" />
      <div>
        <div class="lint-msg">
          {deviceName && (
            <button class="link" onClick={() => (selection.value = { type: "device", id: issue.deviceId })}>
              {deviceName}
            </button>
          )}
          {deviceName && " · "}
          {issue.message}
        </div>
        <div class="lint-fix">{issue.fix}</div>
      </div>
    </li>
  );
}

export function LintSection({ issues, withNames }: { issues: LintIssue[]; withNames: boolean }) {
  const t = topology.value;
  const name = (id: string) => t.devices.find((d) => d.id === id)?.name ?? id;
  return (
    <Section id={withNames ? "lint" : "lint-device"} title={`구성 검사${issues.length ? ` · ${issues.length}` : ""}`}>
      {issues.length === 0 ? (
        <p class="note">설정에서 빠진 칸이나 어긋난 값이 없습니다. 통신이 안 되면 로그를 보세요.</p>
      ) : (
        <ul class="lint-list">
          {issues.map((i, k) => (
            <LintItem key={`${i.deviceId}:${i.code}:${k}`} issue={i} deviceName={withNames ? name(i.deviceId) : undefined} />
          ))}
        </ul>
      )}
    </Section>
  );
}

export function NetworkPanel() {
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
      {t.devices.length > 0 && <LintSection issues={lintIssues.value} withNames />}
      <Section title="사용법">
        <ul class="hints">
          <li>팔레트의 장치를 캔버스로 끌어다 놓습니다.</li>
          <li>케이블 도구(C)로 장치에서 장치로 끌면 빈 포트끼리 연결됩니다. Shift 를 누른 채 끌어도 됩니다. 포트 칸을 잡고 끌어 상대 포트 칸에 놓으면 그 포트끼리 연결됩니다.</li>
          <li>빈 곳을 끌면 영역 선택, Shift+클릭으로 선택에 더하거나 뺍니다. 선택한 묶음은 함께 옮기고 ⌘C · ⌘V · ⌘D 로 복제합니다.</li>
          <li>케이블도 Shift+클릭으로 여러 개 골라 손실률을 한 번에 바꾸거나 함께 지웁니다.</li>
          <li>⌘Z 되돌리기, ⌘⇧Z 다시 실행. 상단의 화살표 버튼도 같습니다.</li>
          <li>휠로 이동, ⌘ + 휠로 확대·축소, ⌥ 를 누른 채 끌어도 이동합니다.</li>
          <li>상단 "파일" 메뉴에서 예제를 불러오거나 JSON 으로 내려받고 불러옵니다.</li>
        </ul>
      </Section>
    </>
  );
}

/** 영역(주석 네모) 패널: 이름·색·안의 장치 */
export function ZonePanel({ z }: { z: Zone }) {
  const t = topology.value;
  const members = devicesInZone(t, z);
  return (
    <>
      <header class="panel-head">
        <Icon name="zone" />
        <div>
          <h2>{z.label}</h2>
          <p>영역 · 안의 장치 {members.length}개</p>
        </div>
      </header>
      <Section>
        <Field label="이름">
          <input class="input" value={z.label} placeholder="집 안, 사무실, 도커 호스트 …" onInput={(e) => updateZone(z.id, { label: e.currentTarget.value })} />
        </Field>
        <Field label="색">
          <div class="segmented" role="radiogroup">
            {ZONE_TINTS.map((tt) => (
              <button key={tt.id} class={z.tint === tt.id ? "on" : ""} onClick={() => updateZone(z.id, { tint: tt.id })}>
                <i class={`zone-swatch tint-${tt.id}`} />
                {tt.label}
              </button>
            ))}
          </div>
        </Field>
        <p class="note">영역은 그림일 뿐 통신에는 영향이 없습니다. 이름표를 끌면 영역만 옮겨지고(안의 장치는 그대로), 오른쪽 아래 손잡이로 크기를 바꿉니다. 영역을 선택하고 ⌘C·⌘D 하면 안의 장치까지 함께 복사됩니다.</p>
      </Section>
      <Section title="안의 장치">
        {members.length === 0 ? (
          <p class="note">타일 중심이 영역 안에 있는 장치가 여기에 나옵니다.</p>
        ) : (
          <ul class="hints">
            {members.map((id) => {
              const d = t.devices.find((x) => x.id === id)!;
              return (
                <li key={id}>
                  <button class="link" onClick={() => (selection.value = { type: "device", id })}>
                    {d.name}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </Section>
      <Section>
        <button class="btn danger" onClick={() => removeZone(z.id)}>
          <Icon name="trash" size={16} />
          영역 삭제 (장치는 남음)
        </button>
      </Section>
    </>
  );
}

/** 케이블 한쪽 끝: 장치 이름 + 포트 선택 (쓰는 중인 포트는 비활성) */
export function CableEndField({ c, end }: { c: Cable; end: "a" | "b" }) {
  const t = topology.value;
  const ref = c[end];
  const d = t.devices.find((x) => x.id === ref.device);
  if (!d) return null;
  const spec = specOf(d);
  return (
    <Field label={d.name}>
      <select
        class="input mono"
        value={String(ref.port)}
        onChange={(e) => {
          const err = moveCableEnd(c.id, end, Number(e.currentTarget.value));
          if (err) e.currentTarget.value = String(ref.port);
        }}
      >
        {spec.ports.map((p, i) => {
          if (p.radio) return null;
          const busy = i !== ref.port && portProblem(t, { device: d.id, port: i }, c.id) !== undefined;
          return (
            <option key={i} value={String(i)} disabled={busy}>
              {p.name}
              {busy ? " (사용 중)" : ""}
            </option>
          );
        })}
      </select>
    </Field>
  );
}

export function CablePanel({ c }: { c: Cable }) {
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
        <CableEndField c={c} end="a" />
        <CableEndField c={c} end="b" />
        <p class="note">포트를 바꾸면 케이블이 그 포트로 옮겨 꽂힙니다. 이미 다른 케이블이 꽂힌 포트는 고를 수 없습니다. 캔버스에서 포트 칸을 잡고 끌어도 원하는 포트끼리 이을 수 있습니다.</p>
      </Section>
      <Section title="실험: 패킷 손실">
        <Field label="손실률">
          <select class="input" value={String(Math.round((c.loss ?? 0) * 100))} onChange={(e) => updateCable(c.id, (x) => ({ ...x, loss: Number(e.currentTarget.value) / 100 }))}>
            <option value="0">없음</option>
            <option value="10">10%</option>
            <option value="30">30%</option>
            <option value="50">50%</option>
          </select>
        </Field>
        <button class="btn wide" onClick={() => sim.dropNext(c.id)}>
          다음 패킷 1개 손실시키기
        </button>
        <p class="note">손실된 패킷은 케이블 중간에서 사라집니다. TCP 는 ACK 가 안 오면 재전송하고, ping 은 timeout 으로 실패합니다. Shift+클릭으로 케이블을 더 고르면 손실률을 한 번에 바꿀 수 있습니다.</p>
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

/** 여러 값이 섞여 있으면 undefined */
export function common<T>(values: T[]): T | undefined {
  return values.length > 0 && values.every((v) => v === values[0]) ? values[0] : undefined;
}

/** 손실률 선택지 (%) — 단일 케이블 패널과 같은 값 */
const LOSS_CHOICES = [0, 10, 30, 50];
const lossLabel = (p: number) => (p === 0 ? "없음" : `${p}%`);

/** 케이블 다중 선택 패널: 손실률 일괄 설정(한 번 = 되돌리기 한 단계) + 함께 삭제 */
export function CablesPanel({ ids }: { ids: string[] }) {
  const t = topology.value;
  const cables = t.cables.filter((c) => ids.includes(c.id));
  const percents = cables.map((c) => Math.round((c.loss ?? 0) * 100));
  const loss = common(percents);
  // 불러온 파일의 손실률이 선택지에 없는 값이어도 그대로 보이게
  const choices = loss !== undefined && !LOSS_CHOICES.includes(loss) ? [...LOSS_CHOICES, loss].sort((a, b) => a - b) : LOSS_CHOICES;
  const counts = new Map<number, number>();
  for (const p of [...percents].sort((a, b) => a - b)) counts.set(p, (counts.get(p) ?? 0) + 1);
  return (
    <>
      <header class="panel-head">
        <Icon name="cable" />
        <div>
          <h2>케이블 {cables.length}개 선택</h2>
          <p>{[...counts.entries()].map(([p, n]) => `${p === 0 ? "손실 없음" : `손실 ${p}%`} ${n}`).join(" · ")}</p>
        </div>
      </header>
      <Section id="multi-cables" title="선택한 케이블">
        <div class="cable-list">
          {cables.map((c, k) => (
            <button key={c.id} class="cable-item" onClick={() => (selection.value = { type: "cable", id: c.id })} title="이 케이블만 선택">
              <span class="ends">
                {deviceName(c.a.device)} <span class="mono">{portName(c.a.device, c.a.port)}</span> — {deviceName(c.b.device)} <span class="mono">{portName(c.b.device, c.b.port)}</span>
              </span>
              <span class={`loss${percents[k] ? " on" : ""}`}>{lossLabel(percents[k]!)}</span>
            </button>
          ))}
        </div>
      </Section>
      <Section title="실험: 패킷 손실">
        <Field label="손실률">
          <select class="input" value={loss === undefined ? "" : String(loss)} onChange={(e) => updateCables(ids, (x) => ({ ...x, loss: Number(e.currentTarget.value) / 100 }))}>
            {loss === undefined && (
              <option value="" disabled>
                여러 값
              </option>
            )}
            {choices.map((p) => (
              <option key={p} value={String(p)}>
                {lossLabel(p)}
              </option>
            ))}
          </select>
        </Field>
        <p class="note">
          {loss === undefined ? "손실률이 케이블마다 다릅니다. 여기서 고르면 선택한 케이블이 모두 같은 값이 됩니다." : `선택한 케이블 ${cables.length}개에 같은 손실률이 적용됩니다.`} ⌘Z 한 번이면 모두 이전 값으로 돌아갑니다.
        </p>
      </Section>
      <Section>
        <button class="btn danger" onClick={() => removeCables(ids)}>
          <Icon name="trash" size={16} />
          케이블 {cables.length}개 삭제
        </button>
      </Section>
    </>
  );
}

/** 다중 선택 패널: 공통 설정 일괄 변경 + 일괄 동작 */
export function MultiPanel({ ids }: { ids: string[] }) {
  void simVersion.value;
  const t = topology.value;
  const devices = t.devices.filter((d) => ids.includes(d.id));
  const hosts = devices.filter((d) => d.host);
  const phones = devices.filter((d) => d.wifi);
  const dhcpHosts = hosts.filter((d) => d.host!.ipMode === "dhcp" && sim.node(d.id) instanceof Host && (sim.node(d.id) as Host).linkUp);
  const pingInput = useRef<HTMLInputElement>(null);
  const kinds = new Map<string, number>();
  for (const d of devices) kinds.set(specOf(d).label, (kinds.get(specOf(d).label) ?? 0) + 1);
  const setHosts = (patch: Partial<HostSettings>) => updateDevices(hosts.map((d) => d.id), (x) => ({ ...x, host: { ...x.host!, ...patch } }));
  const ipMode = common(hosts.map((d) => d.host!.ipMode));
  const gateway = common(hosts.map((d) => d.host!.gateway));
  const dns = common(hosts.map((d) => d.host!.dns ?? ""));
  const prefix = common(hosts.map((d) => d.host!.prefix));
  const ssid = common(phones.map((d) => d.wifi!.ssid));
  const pingAll = () => {
    const dst = pingInput.current?.value.trim();
    if (!dst) {
      pingInput.current?.focus();
      return;
    }
    for (const d of hosts) sim.act({ kind: "ping", nodeId: d.id, dst });
  };
  const pingRows = hosts.map((d) => ({ d, last: (sim.node(d.id) as Host | undefined)?.pings.at(-1) })).filter((r) => r.last);
  return (
    <>
      <header class="panel-head">
        <Icon name="copy" />
        <div>
          <h2>장치 {devices.length}개 선택</h2>
          <p>{[...kinds.entries()].map(([k, n]) => `${k} ${n}`).join(" · ")}</p>
        </div>
      </header>
      <Section title="정렬">
        <div class="btn-row">
          <button class="btn" onClick={() => alignSelected("left")} title="가장 왼쪽 장치의 x 로 맞춤">
            왼쪽 맞춤
          </button>
          <button class="btn" onClick={() => alignSelected("top")} title="가장 위 장치의 y 로 맞춤">
            위쪽 맞춤
          </button>
          <button class="btn" onClick={() => alignSelected("spread-x")} title="양 끝은 두고 가로 간격을 같게">
            가로 간격
          </button>
          <button class="btn" onClick={() => alignSelected("spread-y")} title="양 끝은 두고 세로 간격을 같게">
            세로 간격
          </button>
        </div>
      </Section>
      {hosts.length > 0 && (
        <Section id="multi-hosts" title={`호스트 ${hosts.length}대 공통 설정`}>
          <div class="segmented" role="radiogroup">
            <button class={ipMode === "dhcp" ? "on" : ""} onClick={() => setHosts({ ipMode: "dhcp" })}>
              자동 (DHCP)
            </button>
            <button class={ipMode === "static" ? "on" : ""} onClick={() => setHosts({ ipMode: "static" })}>
              수동
            </button>
          </div>
          {ipMode === undefined && <p class="note">IP 모드가 섞여 있습니다. 위에서 고르면 전부 같은 모드가 됩니다.</p>}
          {ipMode !== "dhcp" && (
            <>
              <p class="note">IP 주소는 장치마다 달라야 하므로 여기서는 바꾸지 않습니다. 서브넷·게이트웨이·DNS 는 한 번에 적용됩니다.</p>
              <Field label="서브넷">
                <div class="prefix">
                  <span class="mono">/</span>
                  <input
                    class="input mono"
                    type="number"
                    min={0}
                    max={32}
                    value={prefix ?? ""}
                    placeholder="여러 값"
                    onInput={(e) => { if (e.currentTarget.value === "") return; setHosts({ prefix: Math.min(32, Math.max(0, Number(e.currentTarget.value) || 0)) }); }}
                  />
                </div>
              </Field>
              <Field label="게이트웨이" error={gateway ? ipError(gateway, false) : undefined}>
                <input class="input mono" value={gateway ?? ""} placeholder={gateway === undefined ? "여러 값" : "192.168.0.1"} onInput={(e) => setHosts({ gateway: e.currentTarget.value })} />
              </Field>
              <Field label="DNS 서버" error={dns ? ipError(dns, false) : undefined}>
                <input class="input mono" value={dns ?? ""} placeholder={dns === undefined ? "여러 값" : "비우면 이름 해석 불가"} onInput={(e) => setHosts({ dns: e.currentTarget.value })} />
              </Field>
            </>
          )}
        </Section>
      )}
      {phones.length > 0 && (
        <Section id="multi-phones" title={`무선 단말 ${phones.length}대 공통 설정`}>
          <Field label="SSID">
            <input class="input" value={ssid ?? ""} placeholder={ssid === undefined ? "여러 값" : "home"} onInput={(e) => updateDevices(phones.map((d) => d.id), (x) => ({ ...x, wifi: { ...x.wifi!, ssid: e.currentTarget.value } }))} />
          </Field>
        </Section>
      )}
      {hosts.length > 0 && (
        <Section title="일괄 진단">
          <div class="ping-row">
            <input
              ref={pingInput}
              class="input mono"
              placeholder="모두가 ping 보낼 주소 또는 이름"
              onKeyDown={(e) => {
                if (e.key === "Enter") pingAll();
              }}
            />
            <button class="btn" onClick={pingAll}>
              <Icon name="send" size={14} />
              ping {hosts.length}대
            </button>
          </div>
          {pingRows.length > 0 && (
            <table class="table ping-table">
              <thead>
                <tr>
                  <th>호스트</th>
                  <th>대상</th>
                  <th>결과</th>
                </tr>
              </thead>
              <tbody>
                {pingRows.map(({ d, last }) => (
                  <tr key={d.id} class={last!.status}>
                    <td>{d.name}</td>
                    <td class="mono">{last!.dst}</td>
                    <td>{last!.status === "ok" ? `응답 ${last!.rtt}ms` : last!.status === "failed" ? `실패 · ${last!.reason}` : "기다리는 중"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {dhcpHosts.length > 0 && (
            <button class="btn wide" onClick={() => dhcpHosts.forEach((d) => sim.act({ kind: "dhcp-renew", nodeId: d.id }))}>
              <Icon name="refresh" size={14} />
              DHCP 임대 갱신 ({dhcpHosts.length}대)
            </button>
          )}
        </Section>
      )}
      <Section>
        <button class="btn wide" onClick={() => zoneAroundSelected()} title="선택한 장치를 감싸는 영역(주석 네모)을 만듭니다">
          <Icon name="zone" size={16} />
          영역으로 묶기
        </button>
        <div class="btn-row">
          <button class="btn" onClick={() => duplicateSelected()} title="복제 (⌘D)">
            <Icon name="copy" size={16} />
            복제
          </button>
          <button class="btn danger" onClick={() => removeDevices(ids)}>
            <Icon name="trash" size={16} />
            {devices.length}개 삭제
          </button>
        </div>
      </Section>
    </>
  );
}
