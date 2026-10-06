// 인스펙터 공용 부품: 접히는 섹션, 필드 행, 토글, 인터페이스 주소 입력, 주소 검증.
import type { ComponentChildren } from "preact";
import { ipToInt, prefixToMask, intToIp } from "../../core/addr";
import { isIpv6, isLinkLocal6 } from "../../core/addr6";
import { collapsedSections, configGroups, setConfigGroup, toggleSection } from "../../model/store";
import { type IfaceSettings } from "../../model/topology";
import { Icon } from "../Icons";

/** 제목이 있는 섹션은 접을 수 있다. 접힘 상태는 제목(또는 id)별로 기억한다 */
export function Section({ title, id, children }: { title?: string; id?: string; children: ComponentChildren }) {
  if (!title) return <section class="section">{children}</section>;
  const key = id ?? title;
  const collapsed = collapsedSections.value.includes(key);
  return (
    <section class={`section${collapsed ? " collapsed" : ""}`}>
      <h3
        class="collapsible"
        role="button"
        tabIndex={0}
        aria-expanded={!collapsed}
        onClick={() => toggleSection(key)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            toggleSection(key);
          }
        }}
        title={collapsed ? "펼치기" : "접기"}
      >
        <span>{title}</span>
        <Icon name="chevron" size={14} class="chev" />
      </h3>
      {!collapsed && children}
    </section>
  );
}

export interface ConfigGroup {
  id: string;
  label: string;
  /** 이 묶음에 켜 둔 기능이 있으면 칩에 점 (다른 묶음을 보고 있어도 무엇이 켜져 있는지 보이게) */
  on?: boolean;
  content: ComponentChildren;
}

/**
 * 설정 탭의 묶음: 섹션이 많은 장치(공유기·게이트웨이)는 GL.iNet 관리 화면처럼 묶음 칩으로 나눠 한 번에 한 묶음만 보인다.
 * 고른 묶음은 장치 종류(scope)별로 기억한다
 */
export function ConfigGroups({ scope, groups }: { scope: string; groups: ConfigGroup[] }) {
  const want = configGroups.value[scope];
  const cur = groups.find((g) => g.id === want) ?? groups[0]!;
  return (
    <>
      <nav class="config-groups" role="tablist" aria-label="설정 묶음">
        {groups.map((g) => (
          <button key={g.id} role="tab" aria-selected={g === cur} class={g === cur ? "on" : ""} data-group={g.id} onClick={() => setConfigGroup(scope, g.id)} title={g.on ? `${g.label} — 켜 둔 기능이 있습니다` : g.label}>
            {g.label}
            {g.on && <span class="group-dot" />}
          </button>
        ))}
      </nav>
      {cur.content}
    </>
  );
}

export function Field({ label, hint, children, error }: { label: string; hint?: string; children: ComponentChildren; error?: string }) {
  return (
    <div class={`field${error ? " has-error" : ""}`}>
      <label>
        {label}
        {hint && <small>{hint}</small>}
      </label>
      <div class="control">
        {children}
        {error && <div class="field-error">{error}</div>}
      </div>
    </div>
  );
}

export function validIp(s: string): boolean {
  try {
    ipToInt(s);
    return true;
  } catch {
    return false;
  }
}

export function ipError(s: string, required: boolean): string | undefined {
  if (!s) return required ? "필요한 값입니다" : undefined;
  return validIp(s) ? undefined : "예: 192.168.0.10";
}

/** IPv4 또는 IPv6 주소 칸 (DNS 레코드·업스트림처럼 둘 다 되는 곳) */
export function anyIpError(s: string, required: boolean): string | undefined {
  const v = typeof s === "string" ? s.trim() : "";
  if (!v) return required ? "필요한 값입니다" : undefined;
  return validIp(v) || isIpv6(v) ? undefined : "예: 192.168.0.20 또는 2001:db8::20";
}

/** IPv6 주소 칸 검증. linkLocalOk 가 아니면 fe80:: 는 "자동으로 생긴다" 고 안내 (주소 칸) */
export function ip6Error(s: string, required: boolean, linkLocalOk = false): string | undefined {
  const v = typeof s === "string" ? s.trim() : "";
  if (!v) return required ? "필요한 값입니다" : undefined;
  if (!isIpv6(v)) return "예: 2001:db8:1::10";
  if (!linkLocalOk && isLinkLocal6(v)) return "링크 로컬(fe80::)은 MAC 에서 자동으로 생깁니다. 글로벌 주소(예: 2001:db8:1::10)를 넣으세요";
  return undefined;
}

export function Toggle({ on, onToggle }: { on: boolean; onToggle: () => void }) {
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
/** ipRequired: 수동인데 주소가 비었을 때 오류로 보일지 (IPv6 만 쓰는 인터페이스는 비워 둬도 된다) */
export function IfaceFields({ value, onChange, gatewayLabel = "게이트웨이", dhcpNote, ipRequired = true }: { value: IfaceSettings; onChange: (patch: Partial<IfaceSettings>) => void; gatewayLabel?: string; dhcpNote: string; ipRequired?: boolean }) {
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
          <Field label="IP 주소" error={ipError(value.ip, ipRequired)}>
            <input class="input mono" value={value.ip} placeholder={ipRequired ? "192.168.0.1" : "비우면 IPv6 만"} onInput={(e) => onChange({ ip: e.currentTarget.value })} />
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
                onInput={(e) => { if (e.currentTarget.value === "") return; onChange({ prefix: Math.min(32, Math.max(0, Number(e.currentTarget.value) || 0)) }); }}
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
