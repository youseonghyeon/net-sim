// 인스펙터 공용 부품: 접히는 섹션, 필드 행, 토글, 인터페이스 주소 입력, 주소 검증.
import type { ComponentChildren } from "preact";
import { ipToInt, prefixToMask, intToIp } from "../../core/addr";
import { collapsedSections, toggleSection } from "../../model/store";
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
export function IfaceFields({ value, onChange, gatewayLabel = "게이트웨이", dhcpNote }: { value: IfaceSettings; onChange: (patch: Partial<IfaceSettings>) => void; gatewayLabel?: string; dhcpNote: string }) {
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
