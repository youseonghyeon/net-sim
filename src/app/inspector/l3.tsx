// 게이트웨이·NAT 박스 설정: 인터페이스, 스태틱 라우팅, 동적 라우팅(RIP), VPN, VLAN 서브 인터페이스. 스위치 포트 VLAN 도 여기.
import { sameSubnet } from "../../core/addr";
import { updateDevice } from "../../model/store";
import {
  DEFAULT_FIREWALL_SETTINGS,
  defaultL3,
  specOf,
  type Device,
  type IfaceSettings,
  type L3Settings,
  type SubIfaceSettings,
  vlanColor,
} from "../../model/topology";
import { Icon } from "../Icons";
import { FirewallSection, ForwardSection } from "./rules";
import { Field, IfaceFields, Section, Toggle, ipError, validIp } from "./ui";

/** 다른 수동 인터페이스와 서브넷이 겹치면 그 인터페이스 이름 */
export function subnetClash(l3: L3Settings, names: string[], i: number): string | undefined {
  const me = l3.interfaces[i];
  if (!me || me.ipMode !== "static" || !validIp(me.ip)) return undefined;
  for (let k = 0; k < l3.interfaces.length; k++) {
    const o = l3.interfaces[k];
    if (k === i || !o || o.ipMode !== "static" || !validIp(o.ip)) continue;
    if (sameSubnet(me.ip, o.ip, Math.min(me.prefix, o.prefix))) return names[k];
  }
  return undefined;
}

export function routeError(l3: L3Settings, r: L3Settings["routes"][number]): string | undefined {
  if (!validIp(r.dest) || !validIp(r.via)) return "목적지와 넥스트 홉 주소가 필요합니다";
  if (r.prefix < 1) return "마스크 길이는 1 이상 (디폴트 라우트는 업링크의 디폴트 라우트 칸에)";
  const statics = l3.interfaces.filter((f) => f.ipMode === "static" && validIp(f.ip));
  if (statics.some((f) => f.ip === r.via)) return "넥스트 홉이 내 주소입니다";
  if (statics.length > 0 && !statics.some((f) => sameSubnet(r.via, f.ip, f.prefix))) return "넥스트 홉이 연결된 서브넷 안에 없습니다";
  return undefined;
}

export function L3Section({ d, l3 }: { d: Device; l3: L3Settings }) {
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
              gatewayLabel={isUp ? "디폴트 라우트" : "게이트웨이"}
              dhcpNote={isUp ? "위쪽에 연결된 장치(인터넷 또는 다른 라우터)에서 주소와 디폴트 라우트를 받습니다." : "이 인터페이스가 DHCP 로 주소를 받습니다. 보통 안쪽 인터페이스는 수동으로 고정합니다."}
            />
            {subnetClash(l3, names, i) && <p class="note error-note">{subnetClash(l3, names, i)} 인터페이스와 서브넷이 겹칩니다. 라우터는 인터페이스마다 다른 서브넷이어야 합니다.</p>}
            {!isUp && v.ipMode === "static" && <p class="note">이 서브넷의 호스트들은 게이트웨이를 {v.ip || "이 주소"} 로 두어야 다른 네트워크로 나갈 수 있습니다.</p>}
            {!isUp && !isNat && (
              <Field label="DHCP 릴레이" error={ipError(v.relay ?? "", false)}>
                <input class="input mono" value={v.relay ?? ""} placeholder="서버 주소 (비우면 없음)" onInput={(e) => setIface(i, { relay: e.currentTarget.value })} />
              </Field>
            )}
            {!isUp && !isNat && v.relay && validIp(v.relay) && (
              <p class="note">이 인터페이스로 오는 DHCP 브로드캐스트에 릴레이 에이전트 주소(giaddr)={v.ip || "?"} 를 붙여 {v.relay} 로 유니캐스트 전달합니다. 서버 쪽 "다른 서브넷 풀" 에 이 서브넷 범위가 있어야 합니다.</p>
            )}
          </Section>
        );
      })}
      {!isNat && <SubIfaceSection d={d} l3={l3} />}
      <Section title="스태틱 라우팅">
        {l3.routes.length === 0 && <p class="note">연결된 서브넷과 디폴트 라우트 외에 알아야 할 경로가 있으면 추가합니다. {isNat ? "안쪽에 라우터가 또 있으면 그 뒤 서브넷(예: 192.168.0.0/16)을 안쪽 라우터로 보내는 경로가 필요합니다." : ""}</p>}
        {l3.routes.map((r, i) => (
          <div key={i} class="route-row">
            <span class="muted">목적지</span>
            <input class="input mono" value={r.dest} placeholder="192.168.0.0" title="목적지 네트워크" onInput={(e) => setRoutes(l3.routes.map((x, k) => (k === i ? { ...x, dest: e.currentTarget.value } : x)))} />
            <span class="mono">/</span>
            <input class="input mono prefix-in" type="number" min={0} max={32} value={r.prefix} onInput={(e) => { if (e.currentTarget.value === "") return; setRoutes(l3.routes.map((x, k) => (k === i ? { ...x, prefix: Math.min(32, Math.max(0, Number(e.currentTarget.value) || 0)) } : x))); }} />
            <span class="muted">넥스트 홉</span>
            <input class="input mono via" value={r.via} placeholder="연결된 서브넷 안의 주소" title="넥스트 홉 주소 (연결된 서브넷 안)" onInput={(e) => setRoutes(l3.routes.map((x, k) => (k === i ? { ...x, via: e.currentTarget.value } : x)))} />
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
      <RipSection d={d} l3={l3} />
      <VpnSection d={d} l3={l3} />
      {isNat && (
        <ForwardSection
          rules={l3.forwards ?? []}
          onChange={(forwards) => updateDevice(d.id, (x) => ({ ...x, l3: { ...(x.l3 ?? defaultL3(x.kind)), forwards } }))}
          lanHint="안쪽 서버 주소가 다른 라우터 뒤에 있으면 그쪽 스태틱 라우팅도 있어야 합니다."
        />
      )}
      <FirewallSection
        value={l3.firewall ?? DEFAULT_FIREWALL_SETTINGS}
        onChange={(firewall) => updateDevice(d.id, (x) => ({ ...x, l3: { ...(x.l3 ?? defaultL3(x.kind)), firewall } }))}
        uplinkName={isNat ? "outside" : "if0"}
      />
    </>
  );
}

/** 사이트 간 VPN: 켜기 + 방식(WireGuard 식 / IPsec) + 상대 공인 주소 + (IPsec 이면 사전 공유 키) + 상대 쪽 사설 대역 */
export function VpnSection({ d, l3 }: { d: Device; l3: L3Settings }) {
  const vpn = l3.vpn ?? { enabled: false, peer: "", remote: [] };
  const set = (patch: Partial<NonNullable<L3Settings["vpn"]>>) =>
    updateDevice(d.id, (x) => {
      const cur = x.l3 ?? defaultL3(x.kind);
      return { ...x, l3: { ...cur, vpn: { ...(cur.vpn ?? { enabled: false, peer: "", remote: [] }), ...patch } } };
    });
  const setRemote = (i: number, patch: Partial<{ dest: string; prefix: number }>) => set({ remote: vpn.remote.map((r, k) => (k === i ? { ...r, ...patch } : r)) });
  const ipsec = vpn.mode === "ipsec";
  return (
    <Section title="VPN (사이트 간)">
      <label class="toggle-row">
        <span>
          {vpn.enabled ? "켜짐" : "꺼짐"} <span class="mono muted">{ipsec ? "IKE UDP 500 · ESP" : "UDP 51820"}</span>
        </span>
        <Toggle on={vpn.enabled} onToggle={() => set({ enabled: !vpn.enabled })} />
      </label>
      {!vpn.enabled && (
        <p class="note">
          켜면 상대 사무실의 사설 대역으로 가는 패킷을 암호화해 상대 공인 주소로 보냅니다(WireGuard 식 또는 IPsec). 사설 주소끼리 NAT 없이 이어지고, 인터넷 위에서는 공인 주소끼리의 암호화된 패킷으로만 보입니다. 상대 장비에도 이쪽 주소·대역으로 짝을 맞춰 켜야 합니다.
        </p>
      )}
      {vpn.enabled && (
        <>
          <Field label="방식">
            <div class="segmented" role="radiogroup">
              <button class={!ipsec ? "on" : ""} onClick={() => set({ mode: undefined, psk: undefined })}>
                WireGuard
              </button>
              <button class={ipsec ? "on" : ""} onClick={() => set({ mode: "ipsec", psk: vpn.psk ?? "" })}>
                IPsec
              </button>
            </div>
          </Field>
          <Field label="상대 공인 주소" error={ipError(vpn.peer, true)}>
            <input class="input mono" value={vpn.peer} placeholder="203.0.113.22" onInput={(e) => set({ peer: e.currentTarget.value })} />
          </Field>
          {ipsec && (
            <Field label="사전 공유 키 (PSK)" error={vpn.psk ? undefined : "비어 있습니다. 양쪽에 같은 키를 넣으세요."}>
              <input class="input mono" value={vpn.psk ?? ""} placeholder="양쪽이 같은 문자열" onInput={(e) => set({ psk: e.currentTarget.value })} />
            </Field>
          )}
          <h3 class="sub">상대 쪽 사설 대역</h3>
          {vpn.remote.length === 0 && <p class="note error-note">상대 사무실의 사설 대역(예: 192.168.2.0/24)을 넣어야 그쪽으로 가는 패킷이 터널을 탑니다.</p>}
          {vpn.remote.map((r, i) => (
            <div key={i} class="lb-row">
              <input class="input mono" value={r.dest} placeholder="192.168.2.0" onInput={(e) => setRemote(i, { dest: e.currentTarget.value })} />
              <span class="mono muted">/</span>
              <input class="input mono" type="number" min={1} max={32} value={r.prefix} onInput={(e) => { if (e.currentTarget.value !== "") setRemote(i, { prefix: Math.min(32, Math.max(1, Number(e.currentTarget.value) || 24)) }); }} />
              <button class="icon-btn" title="대역 삭제" onClick={() => set({ remote: vpn.remote.filter((_, k) => k !== i) })}>
                <Icon name="trash" size={15} />
              </button>
              {ipError(r.dest, true) && <div class="error lb-error">{ipError(r.dest, true)}</div>}
            </div>
          ))}
          <button class="btn wide" onClick={() => set({ remote: [...vpn.remote, { dest: "", prefix: 24 }] })}>
            <Icon name="plus" size={14} />
            대역 추가
          </button>
          <p class="note">
            {ipsec
              ? "이 대역으로 가는 첫 패킷이 오면 IKE 로 터널을 맺고(IKE_SA_INIT → IKE_AUTH), 그다음부터 ESP 로 암호화해 보냅니다(NAT 하지 않음). 사이에 NAT 가 있으면 알아채고 UDP 4500 에 싣습니다(NAT-T). 터널로 온 패킷은 이 대역에서 온 것만 받습니다. 상대가 NAT 뒤라면 그 NAT 에 UDP 500·4500 포트 포워딩이 필요합니다."
              : "이 대역으로 가는 패킷은 터널로 가고(NAT 하지 않음), 터널로 온 패킷은 이 대역에서 온 것만 받습니다(WireGuard 의 AllowedIPs). 상대가 NAT 뒤에 있으면 상대가 먼저 보낸 뒤 그 출발지로 답합니다."}{" "}
            양쪽 사설 대역이 겹치면 안 됩니다.
          </p>
        </>
      )}
    </Section>
  );
}

/** 동적 라우팅 (RIP): 켜기 + 디폴트 라우트 광고 */
export function RipSection({ d, l3 }: { d: Device; l3: L3Settings }) {
  const rip = l3.rip ?? { enabled: false };
  const set = (patch: Partial<NonNullable<L3Settings["rip"]>>) =>
    updateDevice(d.id, (x) => {
      const cur = x.l3 ?? defaultL3(x.kind);
      return { ...x, l3: { ...cur, rip: { ...(cur.rip ?? { enabled: false }), ...patch } } };
    });
  const isNat = d.kind === "nat";
  return (
    <Section title="동적 라우팅 (RIP)">
      <label class="toggle-row">
        <span>{rip.enabled ? "켜짐" : "꺼짐"}</span>
        <Toggle on={rip.enabled} onToggle={() => set({ enabled: !rip.enabled })} />
      </label>
      {!rip.enabled && (
        <p class="note">
          켜면 이웃 라우터와 "내가 아는 네트워크와 홉 수" 를 주고받아 라우팅 테이블을 자동으로 채웁니다. 이웃 라우터도 RIP 를 켜야 합니다. 스태틱 라우팅을 하나하나 넣는 대신 쓸 수 있습니다.
        </p>
      )}
      {rip.enabled && (
        <>
          <label class="toggle-row">
            <span>
              디폴트 라우트 광고
              <small class="muted">내 디폴트 라우트를 이웃에게 0.0.0.0/0 으로 알림</small>
            </span>
            <Toggle on={rip.defaultRoute === true} onToggle={() => set({ defaultRoute: !rip.defaultRoute })} />
          </label>
          <p class="note">
            {isNat ? "outside 쪽으로는 광고하지 않습니다(사설 경로를 바깥에 알리지 않음). " : ""}
            배운 경로는 "표" 탭의 라우팅 테이블에 "RIP n홉" 으로 보입니다. 같은 목적지에 스태틱 라우팅이 있으면 스태틱이 우선합니다. 실제 RIP 의 30초 주기 광고 대신 변화가 있을 때만 광고하므로, 스위치 너머 이웃이 사라진 것(내 링크는 살아 있음)은 알아채지 못합니다.
          </p>
        </>
      )}
    </Section>
  );
}

/** 스위치 포트별 VLAN (액세스 번호 또는 트렁크) */
export function VlanSection({ d }: { d: Device }) {
  const spec = specOf(d);
  const vlans = d.switch?.vlans ?? {};
  const setPort = (port: number, v: number | "trunk" | undefined) =>
    updateDevice(d.id, (x) => {
      const next = { ...(x.switch?.vlans ?? {}) };
      if (v === undefined || v === 1) delete next[port];
      else next[port] = v;
      return { ...x, switch: { vlans: next } };
    });
  const used = new Set<number>();
  for (const v of Object.values(vlans)) if (v !== "trunk") used.add(v);
  const any = Object.keys(vlans).length > 0;
  return (
    <Section title="VLAN">
      {!any && <p class="note">모든 포트가 VLAN 1 (하나의 브로드캐스트 도메인). 포트에 다른 번호를 주면 그 포트들끼리만 통신하고, 트렁크 포트는 태그를 붙여 여러 VLAN 을 다른 스위치나 게이트웨이로 실어 나릅니다.</p>}
      <div class="vlan-grid">
        {spec.ports.map((p, i) => {
          const v = vlans[i] ?? 1;
          const isTrunk = v === "trunk";
          return (
            <div key={p.name} class="vlan-row">
              <span class="mono">{p.name}</span>
              <span class="vlan-swatch" style={isTrunk ? undefined : { background: v === 1 ? "var(--line-strong)" : vlanColor(v) }} title={isTrunk ? "트렁크" : `VLAN ${v}`}>
                {isTrunk ? "T" : ""}
              </span>
              <select class="input" value={isTrunk ? "trunk" : "access"} onChange={(e) => setPort(i, e.currentTarget.value === "trunk" ? "trunk" : 1)}>
                <option value="access">액세스</option>
                <option value="trunk">트렁크</option>
              </select>
              <input
                class="input mono port"
                type="number"
                min={1}
                max={4094}
                value={isTrunk ? "" : v}
                disabled={isTrunk}
                placeholder={isTrunk ? "모두" : "1"}
                onInput={(e) => {
                  const n = Number(e.currentTarget.value);
                  if (Number.isInteger(n) && n >= 1 && n <= 4094) setPort(i, n);
                }}
              />
            </div>
          );
        })}
      </div>
      {any && (
        <p class="note">
          VLAN 사이를 잇고 싶으면 트렁크 포트를 게이트웨이에 연결하고, 게이트웨이의 그 인터페이스에 VLAN 마다 서브 인터페이스(주소)를 만드세요 (router-on-a-stick).
          {used.size > 0 && ` 사용 중: VLAN ${[...used].sort((a, b) => a - b).join(", ")}`}
        </p>
      )}
    </Section>
  );
}

/** 게이트웨이 VLAN 서브 인터페이스 편집기 */
export function SubIfaceSection({ d, l3 }: { d: Device; l3: L3Settings }) {
  const spec = specOf(d);
  const subs = l3.subinterfaces ?? [];
  const setSubs = (subinterfaces: SubIfaceSettings[]) => updateDevice(d.id, (x) => ({ ...x, l3: { ...(x.l3 ?? defaultL3(x.kind)), subinterfaces } }));
  const setSub = (i: number, patch: Partial<SubIfaceSettings>) => setSubs(subs.map((s, k) => (k === i ? { ...s, ...patch } : s)));
  const ports = spec.ports.map((p, i) => ({ i, name: p.name })).filter(({ i }) => i > 0 && !spec.ports[i]!.radio);
  const err = (s: SubIfaceSettings) => {
    if (!Number.isInteger(s.vlan) || s.vlan < 1 || s.vlan > 4094) return "VLAN 은 1~4094";
    if (subs.some((o) => o !== s && o.port === s.port && o.vlan === s.vlan)) return "같은 포트에 같은 VLAN 이 두 번";
    if (!validIp(s.ip)) return "IP 주소가 필요합니다";
    if (s.relay && !validIp(s.relay)) return "릴레이 주소 형식";
    return undefined;
  };
  return (
    <Section title="VLAN 서브 인터페이스">
      {subs.length === 0 && <p class="note">트렁크로 들어오는 VLAN 마다 주소를 하나씩 둡니다 (예: if1.10 = 192.168.10.1). 그 VLAN 의 호스트는 이 주소를 게이트웨이로 씁니다.</p>}
      {subs.map((sIf, i) => (
        <div key={i} class="subif-row">
          <div class="fw-line subif-line">
            <select class="input" value={sIf.port} onChange={(e) => setSub(i, { port: Number(e.currentTarget.value) })}>
              {ports.map((p) => (
                <option key={p.i} value={p.i}>
                  {p.name}
                </option>
              ))}
            </select>
            <span class="muted">. VLAN</span>
            <input class="input mono port" type="number" min={1} max={4094} value={sIf.vlan} onInput={(e) => { if (e.currentTarget.value === "") return; setSub(i, { vlan: Number(e.currentTarget.value) || 0 }); }} />
            <button class="icon-btn" title="삭제" onClick={() => setSubs(subs.filter((_, k) => k !== i))}>
              <Icon name="trash" size={15} />
            </button>
          </div>
          <div class="fw-line subif-addr">
            <input class="input mono" value={sIf.ip} placeholder="192.168.10.1" onInput={(e) => setSub(i, { ip: e.currentTarget.value })} />
            <span class="mono">/</span>
            <input class="input mono port" type="number" min={1} max={32} value={sIf.prefix} onInput={(e) => setSub(i, { prefix: Math.min(32, Math.max(1, Number(e.currentTarget.value) || 24)) })} />
          </div>
          <Field label="DHCP 릴레이" error={undefined}>
            <input class="input mono" value={sIf.relay} placeholder="서버 주소 (비우면 없음)" onInput={(e) => setSub(i, { relay: e.currentTarget.value })} />
          </Field>
          {err(sIf) && <div class="field-error">{err(sIf)}</div>}
        </div>
      ))}
      <button class="btn wide" onClick={() => setSubs([...subs, { port: ports[0]?.i ?? 1, vlan: subs.length ? Math.max(...subs.map((x) => x.vlan)) + 10 : 10, ip: "", prefix: 24, relay: "" }])}>
        <Icon name="plus" size={14} />
        서브 인터페이스 추가
      </button>
    </Section>
  );
}
