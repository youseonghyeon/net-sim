// 공유기의 "앱" 묶음 (GL.iNet 관리 화면의 애플리케이션): AdGuard Home·자녀 보호.
import { Router } from "../../core/nodes/router";
import { sim, simVersion } from "../../model/sim";
import { topology, updateDevice } from "../../model/store";
import { DEFAULT_ADGUARD_SETTINGS, type Device, type ParentalCategorySetting, type RouterAdguardSettings, type RouterSettings } from "../../model/topology";
import { Icon } from "../Icons";
import { Field, Section, Toggle, ipError, validIp } from "./ui";

const CATEGORY_LABEL: Record<ParentalCategorySetting, string> = { sns: "SNS", game: "게임", video: "동영상" };

/** 한 줄에 하나 (쉼표도 됨) → 목록 */
function lines(text: string): string[] {
  return text.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);
}

function ruleError(list: string[]): string | undefined {
  const bad = list.find((x) => !/^(\|\|)?[a-z0-9.-]+\.[a-z0-9-]+\^?$/i.test(x));
  return bad ? `${bad} — 이름만 (예: ads.example.com)` : undefined;
}

export function AdguardSection({ d, r }: { d: Device; r: RouterSettings }) {
  void simVersion.value;
  const a = r.adguard ?? { ...DEFAULT_ADGUARD_SETTINGS, enabled: false };
  const set = (patch: Partial<RouterAdguardSettings>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, adguard: { ...(x.router!.adguard ?? DEFAULT_ADGUARD_SETTINGS), ...patch } } }));
  const node = sim.node(d.id);
  const setKid = (i: number, patch: Partial<RouterAdguardSettings["parental"][0]>) => set({ parental: a.parental.map((p, k) => (k === i ? { ...p, ...patch } : p)) });
  // 자녀 보호에 넣을 수 있는 LAN 기기: 수동 주소가 이 공유기 LAN 대역 안인 단말 (자동(DHCP) 기기는 주소가 바뀔 수 있어 고정이 필요)
  const kids = topology.value.devices.filter((x) => x.host?.ipMode === "static" && validIp(x.host.ip) && a.parental.every((p) => p.ip !== x.host!.ip) && x.host.gateway === r.lanIp);
  return (
    <Section title="AdGuard Home">
      <label class="toggle-row">
        <span>{a.enabled ? "켜짐" : "꺼짐"}</span>
        <Toggle on={a.enabled} onToggle={() => set({ enabled: !a.enabled })} />
      </label>
      {!a.enabled && <p class="note">켜면 이 공유기의 DNS 포워더로 오는 질의를 거릅니다. 광고·추적 서버 이름에 0.0.0.0 으로 답해 기기가 아예 접속하지 않게 하고(앱마다 광고 차단을 깔지 않아도 됨), 기기마다 SNS·게임 같은 카테고리를 막을 수 있습니다(자녀 보호).</p>}
      {a.enabled && (
        <>
          {node instanceof Router && (
            <div class="stat-row">
              <span>통계</span>
              <b class="mono">{node.adguard.summary()}</b>
            </div>
          )}
          <label class="toggle-row">
            <span>
              광고·추적 차단 목록
              <small class="muted">AdGuard DNS filter (doubleclick.net 등)</small>
            </span>
            <Toggle on={a.ads} onToggle={() => set({ ads: !a.ads })} />
          </label>
          <Field label="막은 이름의 답">
            <div class="segmented" role="radiogroup">
              <button class={a.mode === "zero" ? "on" : ""} onClick={() => set({ mode: "zero" })} title="AdGuard 기본 — 기기는 0.0.0.0 으로 접속하려다 바로 실패">
                0.0.0.0
              </button>
              <button class={a.mode === "nxdomain" ? "on" : ""} onClick={() => set({ mode: "nxdomain" })} title="없는 이름이라고 답함">
                NXDOMAIN
              </button>
            </div>
          </Field>
          <label class="toggle-row">
            <span>
              DNS 가로채기
              <small class="muted">DNS 를 직접 적은 기기(8.8.8.8)도 공유기가 받아 거름</small>
            </span>
            <Toggle on={a.forceDns} onToggle={() => set({ forceDns: !a.forceDns })} />
          </label>
          <Field label="차단 규칙" hint="한 줄에 하나" error={ruleError(a.custom)}>
            <textarea class="input mono area" rows={3} value={a.custom.join("\n")} placeholder="ads.example.com" onInput={(e) => set({ custom: lines(e.currentTarget.value) })} />
          </Field>
          <Field label="예외" hint="차단보다 먼저" error={ruleError(a.allow)}>
            <textarea class="input mono area" rows={2} value={a.allow.join("\n")} placeholder="www.example.com" onInput={(e) => set({ allow: lines(e.currentTarget.value) })} />
          </Field>
          <h4 class="sub-head">자녀 보호 (기기마다 막을 카테고리)</h4>
          {a.parental.map((p, i) => {
            const who = topology.value.devices.find((x) => x.host?.ip === p.ip);
            return (
              <div key={i} class="kid-row">
                <input class="input mono" value={p.ip} placeholder="192.168.8.50" title={who ? who.name : "기기의 LAN 주소"} onInput={(e) => setKid(i, { ip: e.currentTarget.value })} />
                <div class="kid-cats">
                  {(Object.keys(CATEGORY_LABEL) as ParentalCategorySetting[]).map((c) => (
                    <button key={c} class={`chip${p.categories.includes(c) ? " on" : ""}`} onClick={() => setKid(i, { categories: p.categories.includes(c) ? p.categories.filter((x) => x !== c) : [...p.categories, c] })}>
                      {CATEGORY_LABEL[c]}
                    </button>
                  ))}
                </div>
                <button class="icon-btn" title="삭제" onClick={() => set({ parental: a.parental.filter((_, k) => k !== i) })}>
                  <Icon name="trash" size={15} />
                </button>
                {who && <div class="muted kid-name">{who.name}</div>}
                {ipError(p.ip, true) && <div class="error route-error">{ipError(p.ip, true)}</div>}
              </div>
            );
          })}
          {kids.length > 0 ? (
            <Field label="기기 추가">
              <select
                class="input"
                value=""
                onChange={(e) => {
                  const k = kids.find((x) => x.id === e.currentTarget.value);
                  if (k) set({ parental: [...a.parental, { ip: k.host!.ip, categories: ["sns", "game"] }] });
                  e.currentTarget.value = "";
                }}
              >
                <option value="">LAN 기기를 고르세요 (수동 주소)</option>
                {kids.map((k) => (
                  <option key={k.id} value={k.id}>
                    {k.name} {k.host!.ip}
                  </option>
                ))}
              </select>
            </Field>
          ) : (
            <button class="btn wide" onClick={() => set({ parental: [...a.parental, { ip: "", categories: ["sns", "game"] }] })}>
              <Icon name="plus" size={14} />
              기기 추가
            </button>
          )}
          <p class="note">자녀 보호는 기기의 주소로 구분하므로 수동 주소(또는 늘 같은 주소)가 필요합니다. 쿼리 로그는 표 탭에 있습니다. DoH(HTTPS 위의 DNS)를 쓰는 앱은 DNS 가로채기로도 막지 못합니다.</p>
        </>
      )}
    </Section>
  );
}
