// 인터넷 전화 (SIP): 단말의 전화기 설정·전화 걸기, 공유기의 SIP ALG.
import { useState } from "preact/hooks";
import { Host } from "../../core/nodes/host";
import { meshHostname } from "../../core/nodes/tailscale";
import { sim, simVersion } from "../../model/sim";
import { topology, updateDevice } from "../../model/store";
import type { Device, RouterSettings } from "../../model/topology";
import { Field, Section, Toggle } from "./ui";

export function SipPhoneSection({ d }: { d: Device }) {
  const s = d.host?.sip ?? { enabled: false, user: "" };
  const set = (patch: Partial<typeof s>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, sip: { ...(x.host!.sip ?? { enabled: false, user: "" }), ...patch } } }));
  return (
    <Section title="인터넷 전화 (SIP)">
      <label class="toggle-row">
        <span>
          {s.enabled ? "켜짐" : "꺼짐"} <span class="mono muted">UDP 5060</span>
        </span>
        <Toggle on={s.enabled} onToggle={() => set({ enabled: !s.enabled })} />
      </label>
      {s.enabled && (
        <Field label="사용자" hint="@voip.example">
          <input class="input mono" value={s.user} placeholder={meshHostname(d.name)} onChange={(e) => set({ user: e.currentTarget.value })} />
        </Field>
      )}
      <p class="note">켜면 인터넷의 SIP 서버에 등록합니다. 진단 탭에서 다른 사용자에게 전화하면 신호(SIP)는 서버를 거치고, 음성(RTP)은 상대가 SDP 에 적은 주소로 직접 갑니다.</p>
    </Section>
  );
}

/** 진단: 전화 걸기 + 통화 결과 */
export function SipCallSection({ d }: { d: Device }) {
  void simVersion.value;
  const node = sim.node(d.id);
  const others = topology.value.devices.filter((x) => x !== d && x.host?.sip?.enabled).map((x) => (x.host!.sip!.user.trim() || meshHostname(x.name)).toLowerCase());
  const [to, setTo] = useState(others[0] ?? "");
  if (!(node instanceof Host) || !node.sip.config.enabled) return null;
  const last = node.sip.calls.at(-1);
  return (
    <Section title="전화 걸기">
      <Field label="받는 사람">
        <input class="input mono" value={to} list={`sip-users-${d.id}`} placeholder={others[0] ?? "junho"} onInput={(e) => setTo(e.currentTarget.value)} />
        <datalist id={`sip-users-${d.id}`}>
          {others.map((u) => (
            <option key={u} value={u} />
          ))}
        </datalist>
      </Field>
      <button class="btn wide" disabled={!to.trim()} onClick={() => sim.act({ kind: "sip-call", nodeId: d.id, to: to.trim().toLowerCase() })}>
        전화
      </button>
      {last && (
        <p class={`note${last.reason ? " error-note" : ""}`}>
          {last.peer} · {last.state === "ended" ? `받은 음성 ${last.received}/5` : last.state}
          {last.reason ? ` — ${last.reason}` : ""}
        </p>
      )}
    </Section>
  );
}

export function SipAlgSection({ d, r }: { d: Device; r: RouterSettings }) {
  return (
    <Section title="SIP ALG">
      <label class="toggle-row">
        <span>{r.sipAlg ? "켜짐" : "꺼짐"}</span>
        <Toggle on={r.sipAlg === true} onToggle={() => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, sipAlg: !x.router!.sipAlg } }))} />
      </label>
      <p class="note">켜면 LAN 의 인터넷 전화가 보내는 SIP 안의 사설 주소(SDP 음성 주소·Contact)를 공인 주소로 고치고, 음성 포트로 들어올 길을 NAT 에 미리 엽니다. 요즘 전화기·서버는 STUN 이나 서버 중계로 스스로 해결해, ALG 가 오히려 SIP 를 망가뜨려 끄라는 안내도 많습니다.</p>
    </Section>
  );
}
