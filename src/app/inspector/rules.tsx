// 규칙 편집기: 방화벽(라우터·게이트웨이·NAT 박스·방화벽 장비 공용)과 포트 포워딩.
import { validCidr } from "../../core/nodes/firewall";
import { type FirewallRuleSettings, type FirewallSettings, type PortForwardSettings } from "../../model/topology";
import { Icon } from "../Icons";
import { Field, Section, Toggle, ipError } from "./ui";

/** 방화벽 규칙 편집기 (라우터 / 게이트웨이 / NAT 박스 공용). 지나가는 패킷만 검사한다 */
export function FirewallSection({ value, onChange, uplinkName }: { value: FirewallSettings; onChange: (v: FirewallSettings) => void; uplinkName: string }) {
  const set = (patch: Partial<FirewallSettings>) => onChange({ ...value, ...patch });
  const setRule = (i: number, patch: Partial<FirewallRuleSettings>) => set({ rules: value.rules.map((r, k) => (k === i ? { ...r, ...patch } : r)) });
  const move = (i: number, d: -1 | 1) => {
    const j = i + d;
    if (j < 0 || j >= value.rules.length) return;
    const rules = [...value.rules];
    [rules[i], rules[j]] = [rules[j]!, rules[i]!];
    set({ rules });
  };
  const err = (r: FirewallRuleSettings) => {
    if (r.src && !validCidr(r.src)) return "출발지: 주소 또는 CIDR (주소/마스크 길이)";
    if (r.dst && !validCidr(r.dst)) return "목적지: 주소 또는 CIDR (주소/마스크 길이)";
    if (r.dstPort && !/^\d+$/.test(r.dstPort)) return "포트는 숫자";
    if (r.dstPort && r.proto === "icmp") return "ICMP 에는 포트가 없습니다";
    return undefined;
  };
  return (
    <Section title="방화벽">
      <label class="toggle-row">
        <span>{value.enabled ? "켜짐" : "꺼짐"}</span>
        <Toggle on={value.enabled} onToggle={() => set({ enabled: !value.enabled })} />
      </label>
      {!value.enabled && <p class="note">이 장치를 지나가는 패킷을 규칙으로 거릅니다. 켜면 "ping 은 되는데 80 은 막힘" 같은 상황을 만들 수 있습니다.</p>}
      {value.enabled && (
        <>
          <Field label="기본 정책">
            <div class="segmented" role="radiogroup">
              <button class={value.defaultPolicy === "allow" ? "on" : ""} onClick={() => set({ defaultPolicy: "allow" })}>
                허용
              </button>
              <button class={value.defaultPolicy === "deny" ? "on" : ""} onClick={() => set({ defaultPolicy: "deny" })}>
                차단
              </button>
            </div>
          </Field>
          <label class="toggle-row">
            <span>
              Stateful 검사
              <small class="muted">안에서 시작한 통신의 응답은 허용</small>
            </span>
            <Toggle on={value.stateful} onToggle={() => set({ stateful: !value.stateful })} />
          </label>
          <p class="note">
            규칙은 위에서부터 첫 일치가 이깁니다. "인바운드" 는 {uplinkName} 에서 들어오는 것, "아웃바운드" 는 {uplinkName} 으로 나가는 것이고, 안쪽 서브넷끼리는 "양방향" 규칙에만 걸립니다. NAT 뒤라면 안쪽 주소로 씁니다.
          </p>
          {value.rules.map((r, i) => (
            <div key={i} class="fw-rule">
              <div class="fw-line">
                <span class="fw-idx mono">{i + 1}</span>
                <select class="input" value={r.action} onChange={(e) => setRule(i, { action: e.currentTarget.value as "allow" | "deny" })}>
                  <option value="deny">차단</option>
                  <option value="allow">허용</option>
                </select>
                <select class="input" value={r.direction} onChange={(e) => setRule(i, { direction: e.currentTarget.value as FirewallRuleSettings["direction"] })}>
                  <option value="in">인바운드</option>
                  <option value="out">아웃바운드</option>
                  <option value="any">양방향</option>
                </select>
                <select class="input" value={r.proto} onChange={(e) => setRule(i, { proto: e.currentTarget.value as FirewallRuleSettings["proto"] })}>
                  <option value="any">모든 프로토콜</option>
                  <option value="icmp">ICMP(ping)</option>
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
              <div class="fw-line fw-addr">
                <span class="muted">출발</span>
                <input class="input mono" value={r.src} placeholder="모두" title="출발지: 주소 또는 CIDR (주소/마스크 길이)" onInput={(e) => setRule(i, { src: e.currentTarget.value })} />
                <span class="muted">목적</span>
                <input class="input mono" value={r.dst} placeholder="모두" title="목적지: 주소 또는 CIDR (주소/마스크 길이)" onInput={(e) => setRule(i, { dst: e.currentTarget.value })} />
                <span class="muted">:</span>
                <input class="input mono port" value={r.dstPort} placeholder="포트" disabled={r.proto === "icmp"} onInput={(e) => setRule(i, { dstPort: e.currentTarget.value })} />
              </div>
              <div class="fw-line fw-actions">
                <button class="icon-btn" title="위로" onClick={() => move(i, -1)} disabled={i === 0}>
                  <Icon name="chevron" size={14} class="up" />
                </button>
                <button class="icon-btn" title="아래로" onClick={() => move(i, 1)} disabled={i === value.rules.length - 1}>
                  <Icon name="chevron" size={14} />
                </button>
                <button class="icon-btn" title="규칙 삭제" onClick={() => set({ rules: value.rules.filter((_, k) => k !== i) })}>
                  <Icon name="trash" size={15} />
                </button>
              </div>
              {err(r) && <div class="field-error">{err(r)}</div>}
            </div>
          ))}
          <button class="btn wide" onClick={() => set({ rules: [...value.rules, { action: "deny", proto: "any", direction: "in", src: "", dst: "", dstPort: "" }] })}>
            <Icon name="plus" size={14} />
            규칙 추가
          </button>
        </>
      )}
    </Section>
  );
}

/** 포트 포워딩 규칙 편집기 (라우터 / NAT 박스 공용) */
export function ForwardSection({ rules, onChange, lanHint }: { rules: PortForwardSettings[]; onChange: (rules: PortForwardSettings[]) => void; lanHint: string }) {
  const setRule = (i: number, patch: Partial<PortForwardSettings>) => onChange(rules.map((r, k) => (k === i ? { ...r, ...patch } : r)));
  const port = (v: string, fallback: number) => Math.min(65535, Math.max(1, Number(v) || fallback));
  return (
    <Section id="forward-edit" title="포트 포워딩">
      {rules.length === 0 && <p class="note">바깥에서 시작한 연결은 NAT 테이블에 없어 드롭됩니다. 규칙을 추가하면 공인 포트로 온 연결을 안쪽 서버로 들여보냅니다(웹은 TCP, DNS 는 UDP 53). {lanHint}</p>}
      {rules.map((r, i) => (
        // 두 줄: [TCP/UDP] 공인 :포트 [삭제] / → 안쪽 주소 : 포트
        <div key={i} class="fwd-row">
          <select class="input proto" value={r.proto ?? "tcp"} title="프로토콜" onChange={(e) => setRule(i, { proto: e.currentTarget.value as "tcp" | "udp" })}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
          <span class="muted fwd-publabel">공인 :</span>
          <input class="input mono port fwd-pub" type="number" min={1} max={65535} value={r.publicPort} onInput={(e) => { if (e.currentTarget.value === "") return; setRule(i, { publicPort: port(e.currentTarget.value, 80) }); }} />
          <button class="icon-btn" title="규칙 삭제" onClick={() => onChange(rules.filter((_, k) => k !== i))}>
            <Icon name="trash" size={15} />
          </button>
          <span class="muted fwd-arrow">→</span>
          <input class="input mono fwd-ip" value={r.lanIp} placeholder="192.168.0.20" onInput={(e) => setRule(i, { lanIp: e.currentTarget.value })} />
          <span class="muted fwd-colon">:</span>
          <input class="input mono port fwd-lan" type="number" min={1} max={65535} value={r.lanPort} onInput={(e) => { if (e.currentTarget.value === "") return; setRule(i, { lanPort: port(e.currentTarget.value, 80) }); }} />
          {ipError(r.lanIp, true) && <div class="error fwd-error">{ipError(r.lanIp, true)}</div>}
        </div>
      ))}
      <button class="btn wide" onClick={() => onChange([...rules, { publicPort: 80, lanIp: "", lanPort: 80 }])}>
        <Icon name="plus" size={14} />
        규칙 추가
      </button>
      {rules.length > 0 && <p class="note">인터넷 노드를 선택해 "외부에서 접속" 으로 실제로 들어오는지 확인해 보세요.</p>}
    </Section>
  );
}
