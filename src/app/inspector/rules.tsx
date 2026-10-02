// 규칙 편집기: 방화벽(라우터·게이트웨이·NAT 박스·방화벽 장비 공용)과 포트 포워딩.
import { validCidr } from "../../core/nodes/firewall";
import { type FirewallRuleSettings, type FirewallSettings, type NatTypeSetting, type PortForwardSettings } from "../../model/topology";
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
    if (r.dstPort && r.proto === "esp") return "ESP 에는 포트가 없습니다 (IPsec 협상은 UDP 500·4500 규칙으로)";
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
                  <option value="esp">ESP(IPsec)</option>
                </select>
              </div>
              <div class="fw-line fw-addr">
                <span class="muted">출발</span>
                <input class="input mono" value={r.src} placeholder="모두" title="출발지: 주소 또는 CIDR (주소/마스크 길이)" onInput={(e) => setRule(i, { src: e.currentTarget.value })} />
                <span class="muted">목적</span>
                <input class="input mono" value={r.dst} placeholder="모두" title="목적지: 주소 또는 CIDR (주소/마스크 길이)" onInput={(e) => setRule(i, { dst: e.currentTarget.value })} />
                <span class="muted">:</span>
                <input class="input mono port" value={r.dstPort} placeholder="포트" disabled={r.proto === "icmp" || r.proto === "esp"} onInput={(e) => setRule(i, { dstPort: e.currentTarget.value })} />
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

const NAT_TYPE_TEXT: Record<NatTypeSetting, { label: string; note: string }> = {
  "full-cone": { label: "Full cone", note: "안쪽 주소:포트마다 바깥 포트 하나. 매핑이 생기면 누가 보내든 들여보냅니다 (endpoint-independent). 홀 펀칭이 가장 쉽습니다." },
  restricted: { label: "Restricted cone", note: "바깥 포트는 같지만, 안에서 먼저 보낸 적 있는 주소에서 온 것만 들여보냅니다 (포트는 상관없음)." },
  "port-restricted": { label: "Port-restricted cone", note: "안에서 먼저 보낸 적 있는 주소:포트에서 온 것만 들여보냅니다. 가정용 공유기에 흔하고, 양쪽이 동시에 보내면(홀 펀칭) 뚫립니다." },
  symmetric: { label: "Symmetric", note: "상대마다 바깥 포트를 새로 고르고, 그 상대에게서 온 것만 들여보냅니다. STUN 이 알려 준 포트가 다른 상대에게는 맞지 않아 홀 펀칭이 실패하고 TURN 릴레이가 필요합니다 (통신사 CGNAT·기업 방화벽)." },
};

/** NAT 종류(RFC 4787 매핑·필터링)와 헤어핀 NAT (라우터 / NAT 박스 공용) */
export function NatTypeSection({ natType, hairpin, onChange }: { natType: NatTypeSetting; hairpin: boolean; onChange: (patch: { natType?: NatTypeSetting; hairpin?: boolean }) => void }) {
  return (
    <Section title="NAT 종류">
      <Field label="매핑·필터링">
        <select class="input" value={natType} onChange={(e) => onChange({ natType: e.currentTarget.value as NatTypeSetting })}>
          {(Object.keys(NAT_TYPE_TEXT) as NatTypeSetting[]).map((k) => (
            <option key={k} value={k}>
              {NAT_TYPE_TEXT[k].label}
              {k === "full-cone" ? " (기본)" : ""}
            </option>
          ))}
        </select>
      </Field>
      <p class="note">{NAT_TYPE_TEXT[natType].note} 바꾸면 지금의 NAT 매핑을 지웁니다.</p>
      <label class="toggle-row">
        <span>헤어핀 NAT {hairpin ? "켜짐" : "꺼짐"}</span>
        <Toggle on={hairpin} onToggle={() => onChange({ hairpin: !hairpin })} />
      </label>
      <p class="note">
        {hairpin
          ? "안쪽 기기가 내 바깥 주소의 포워딩 포트(TCP)로 접속하면 안쪽 서버로 되돌려 줍니다. 서버는 이 장비의 안쪽 주소에서 온 연결로 봅니다 (응답도 이 장비를 거치게)."
          : "켜면 안쪽에서도 바깥 주소:포트(도메인)로 포트 포워딩한 서버에 접속할 수 있습니다. 꺼져 있으면 드롭되니 안에서는 서버의 사설 주소로 접속합니다."}
      </p>
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
