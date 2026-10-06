// 공유기의 "앱" 묶음 (GL.iNet 관리 화면의 애플리케이션): AdGuard Home·자녀 보호.
import { Router } from "../../core/nodes/router";
import { sim, simVersion } from "../../model/sim";
import { topology, updateDevice } from "../../model/store";
import { DEFAULT_ADGUARD_SETTINGS, type Device, type ParentalCategorySetting, type RouterAdguardSettings, type RouterDpiSettings, type RouterSettings } from "../../model/topology";
import { APPS, type AppId, type DpiCategory } from "../../core/nodes/dpi";
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

const DPI_CATEGORIES: DpiCategory[] = ["VPN", "게임", "SNS", "동영상", "알 수 없음"];

/** DPI: 흐름마다 앱을 알아보고 세고, 고른 카테고리·앱을 막는다 */
export function DpiSection({ d, r }: { d: Device; r: RouterSettings }) {
  void simVersion.value;
  const c: RouterDpiSettings = r.dpi ?? { enabled: false, blockApps: [], blockCategories: [] };
  const set = (patch: Partial<RouterDpiSettings>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, dpi: { ...(x.router!.dpi ?? { enabled: true, blockApps: [], blockCategories: [] }), ...patch } } }));
  const toggle = <T extends string>(list: T[], v: T) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
  const apps = (Object.keys(APPS) as AppId[]).filter((a) => !["unknown", "https", "http", "quic", "dns", "ping"].includes(a));
  return (
    <Section title="DPI (앱 알아보기·차단)">
      <label class="toggle-row">
        <span>{c.enabled ? "켜짐" : "꺼짐"}</span>
        <Toggle on={c.enabled} onToggle={() => set({ enabled: !c.enabled })} />
      </label>
      {!c.enabled && <p class="note">켜면 지나가는 흐름마다 무슨 앱인지 알아봅니다 — 내용은 암호화돼 못 보지만 TLS 의 접속 이름(SNI), DNS 로 배운 주소, 프로토콜의 모양(WireGuard·IPsec), 포트는 보입니다. 앱·기기별 트래픽은 표 탭에 쌓이고, 고른 카테고리·앱은 막습니다(TCP 는 RST 를 넣어 끊음).</p>}
      {c.enabled && (
        <>
          <Field label="막을 카테고리">
            <div class="kid-cats">
              {DPI_CATEGORIES.map((cat) => (
                <button key={cat} class={`chip${c.blockCategories.includes(cat) ? " on" : ""}`} onClick={() => set({ blockCategories: toggle(c.blockCategories, cat) })}>
                  {cat}
                </button>
              ))}
            </div>
          </Field>
          <Field label="막을 앱">
            <div class="kid-cats">
              {apps.map((a) => (
                <button key={a} class={`chip${c.blockApps.includes(a) ? " on" : ""}`} title={APPS[a].category} onClick={() => set({ blockApps: toggle(c.blockApps, a) })}>
                  {APPS[a].label}
                </button>
              ))}
            </div>
          </Field>
          <p class="note">"알 수 없음" 을 막으면 모양을 알아볼 수 없는 흐름(난독화한 VPN 등)까지 막습니다. 이미 지나간 흐름은 설정을 바꾸면 다시 검사합니다.</p>
        </>
      )}
    </Section>
  );
}
