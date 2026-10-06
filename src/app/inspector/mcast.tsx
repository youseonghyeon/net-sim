// 멀티캐스트 (IPTV 흉내): 스위치·공유기의 IGMP 스누핑 토글, 호스트 진단 탭의 그룹 가입·탈퇴·송출.
import { useState } from "preact/hooks";
import { Host } from "../../core/nodes/host";
import { isMcastIp } from "../../core/packet";
import { sim, simVersion } from "../../model/sim";
import { updateDevice } from "../../model/store";
import type { Device } from "../../model/topology";
import { Field, Section, Toggle } from "./ui";

export function IgmpSection({ d }: { d: Device }) {
  const on = d.switch ? d.switch.igmpSnooping === true : d.router?.igmpSnooping === true;
  const toggle = () =>
    updateDevice(d.id, (x) => (x.switch || x.kind === "switch" ? { ...x, switch: { ...(x.switch ?? { vlans: {} }), igmpSnooping: !on } } : { ...x, router: { ...x.router!, igmpSnooping: !on } }));
  return (
    <Section title="IGMP 스누핑">
      <label class="toggle-row">
        <span>{on ? "켜짐" : "꺼짐"}</span>
        <Toggle on={on} onToggle={toggle} />
      </label>
      <p class="note">
        켜면 기기의 IGMP 가입·탈퇴를 엿들어 멀티캐스트(IPTV)를 가입한 포트로만 보내고, 가입한 포트가 없는 그룹은 보내지 않습니다. 끄면 멀티캐스트는 브로드캐스트처럼 모든 포트로 가서 보지 않는 기기의 링크까지 채웁니다.
        {on ? " 켤 때 쿼리를 보내 이미 가입한 기기들이 다시 알리게 합니다." : ""}
      </p>
    </Section>
  );
}

/** 호스트 진단: 멀티캐스트 그룹 가입·탈퇴·스트림 송출 */
export function McastSection({ d }: { d: Device }) {
  void simVersion.value;
  const [group, setGroup] = useState("239.1.1.1");
  const node = sim.node(d.id);
  const joined = node instanceof Host ? [...node.groups] : [];
  const ok = isMcastIp(group.trim()) && /^\d+\.\d+\.\d+\.\d+$/.test(group.trim());
  const g = group.trim();
  return (
    <Section title="멀티캐스트 (IPTV)">
      <Field label="그룹" error={ok ? undefined : "224.0.0.0 ~ 239.255.255.255 (예: 239.1.1.1)"}>
        <input class="input mono" value={group} onInput={(e) => setGroup(e.currentTarget.value)} />
      </Field>
      <div class="btn-row">
        <button class="btn" disabled={!ok} onClick={() => sim.act({ kind: "mcast-join", nodeId: d.id, group: g })} title={joined.includes(g) ? "이미 가입한 그룹 — 가입 알림(IGMP Report)을 다시 보냅니다" : "그룹에 가입합니다"}>
          {joined.includes(g) ? "다시 알리기" : "가입"}
        </button>
        <button class="btn" disabled={!ok || !joined.includes(g)} onClick={() => sim.act({ kind: "mcast-leave", nodeId: d.id, group: g })}>
          탈퇴
        </button>
        <button class="btn" disabled={!ok} onClick={() => sim.act({ kind: "mcast-send", nodeId: d.id, group: g })} title="그룹 주소로 영상 조각 5개를 보냅니다">
          송출
        </button>
      </div>
      {joined.length > 0 && <p class="note">가입한 그룹: {joined.map((x) => `${x} (받음 ${node instanceof Host ? (node.streamRx.get(x) ?? 0) : 0})`).join(", ")}</p>}
      <p class="note">가입하면 IGMP 가입 알림을 보내고 그 그룹의 MAC 을 받기 시작합니다. 송출은 그룹 주소로 보낼 뿐 누가 받을지는 스위치가 정합니다.</p>
    </Section>
  );
}
