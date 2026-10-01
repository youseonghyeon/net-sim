// 게이트웨이·NAT 박스 설정: 인터페이스, 스태틱 라우팅, 동적 라우팅(RIP), VPN, 이중화(HA), VLAN 서브 인터페이스. 스위치 포트 VLAN 도 여기.
import { sameSubnet } from "../../core/addr";
import { canonIp6, isIpv6, isLinkLocal6, sameSubnet6 } from "../../core/addr6";
import { linkLocalLabel } from "./host";
import { l3MacOf } from "../../model/netSync";
import { L3Node } from "../../core/nodes/l3";
import { sim, simVersion } from "../../model/sim";
import { updateDevice } from "../../model/store";
import {
  DEFAULT_FIREWALL_SETTINGS,
  defaultL3,
  specOf,
  type Device,
  type IfaceSettings,
  type Ipv6L3Settings,
  type L3Settings,
  type SubIfaceSettings,
  vlanColor,
} from "../../model/topology";
import { Icon } from "../Icons";
import { FirewallSection, ForwardSection } from "./rules";
import { Field, IfaceFields, Section, Toggle, ip6Error, ipError, validIp } from "./ui";

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
              ipRequired={!l3.ipv6?.enabled}
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
      <Ipv6L3Section d={d} l3={l3} />
      <RipSection d={d} l3={l3} />
      <VpnSection d={d} l3={l3} />
      <RaServerSection d={d} l3={l3} />
      <HaSection d={d} l3={l3} />
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

/** IPv6 스태틱 라우팅 한 줄의 문제 (넥스트 홉은 연결된 프리픽스 안의 글로벌 주소) */
export function route6Error(v6: Ipv6L3Settings, r: Ipv6L3Settings["routes"][number]): string | undefined {
  if (!isIpv6(r.dest) || !isIpv6(r.via)) return "목적지와 넥스트 홉 IPv6 주소가 필요합니다 (디폴트 라우트는 :: / 0)";
  if (isLinkLocal6(r.via)) return "넥스트 홉은 링크 로컬 말고 연결된 프리픽스 안의 글로벌 주소로 넣으세요 (링크 로컬은 어느 인터페이스인지 정할 수 없음)";
  const mine = v6.interfaces.filter((f) => isIpv6(f.ip));
  if (mine.some((f) => canonIp6(f.ip) === canonIp6(r.via))) return "넥스트 홉이 내 주소입니다";
  if (mine.length > 0 && !mine.some((f) => sameSubnet6(r.via, f.ip, f.prefix))) return "넥스트 홉이 연결된 프리픽스 안에 없습니다";
  return undefined;
}

/** 게이트웨이·NAT 박스의 IPv6: 켜기 + 인터페이스별 주소 + IPv6 스태틱 라우팅 (::/0 = 디폴트 라우트) */
export function Ipv6L3Section({ d, l3 }: { d: Device; l3: L3Settings }) {
  const spec = specOf(d);
  const names = spec.ports.map((p) => p.name);
  const v6: Ipv6L3Settings = l3.ipv6 ?? { enabled: false, interfaces: [], routes: [] };
  const set = (patch: Partial<Ipv6L3Settings>) =>
    updateDevice(d.id, (x) => {
      const cur = x.l3 ?? defaultL3(x.kind);
      return { ...x, l3: { ...cur, ipv6: { ...(cur.ipv6 ?? { enabled: false, interfaces: [], routes: [] }), ...patch } } };
    });
  const iface = (i: number) => v6.interfaces[i] ?? { ip: "", prefix: 64 };
  const setIface = (i: number, patch: Partial<{ ip: string; prefix: number; ra: boolean }>) => set({ interfaces: names.map((_, k) => (k === i ? { ...iface(k), ...patch } : iface(k))) });
  const anyRa = names.some((_, i) => iface(i).ra === true);
  const setRoutes = (routes: Ipv6L3Settings["routes"]) => set({ routes });
  const isNat = d.kind === "nat";
  return (
    <Section title="IPv6">
      <label class="toggle-row">
        <span>{v6.enabled ? "켜짐" : "꺼짐"}</span>
        <Toggle on={v6.enabled} onToggle={() => set({ enabled: !v6.enabled })} />
      </label>
      {!v6.enabled ? (
        <p class="note">켜면 모든 인터페이스에 링크 로컬 주소가 생기고, IPv6 패킷을 주소 그대로 넘깁니다(Hop Limit 만 줄임). {isNat ? "NAT 박스라도 IPv6 는 변환하지 않습니다 — 바깥에서 안쪽 주소로 바로 들어오므로 막으려면 방화벽 인바운드 규칙이 필요합니다." : ""}</p>
      ) : (
        <>
          {names.map((name, i) => (
            <Field key={name} label={name} hint={linkLocalLabel(l3MacOf(d.mac, i))} error={ip6Error(iface(i).ip, false)}>
              <div class="prefix addr6">
                <input class="input mono" value={iface(i).ip} placeholder="비우면 링크 로컬만" onInput={(e) => setIface(i, { ip: e.currentTarget.value })} />
                <span class="mono">/</span>
                <input
                  class="input mono"
                  type="number"
                  min={1}
                  max={128}
                  value={iface(i).prefix}
                  onInput={(e) => { if (e.currentTarget.value === "") return; setIface(i, { prefix: Math.min(128, Math.max(1, Math.round(Number(e.currentTarget.value)) || 64)) }); }}
                />
              </div>
              <label class="toggle-row ra-row">
                <span>
                  RA 광고 <span class="muted">SLAAC</span>
                </span>
                <Toggle on={iface(i).ra === true} onToggle={() => setIface(i, { ra: !iface(i).ra })} />
              </label>
            </Field>
          ))}
          <p class="note">
            인터페이스 이름 옆의 fe80:: 는 MAC 에서 자동으로 만든 링크 로컬 주소입니다. RA 광고를 켜면 그 링크의 자동(SLAAC) 호스트가 이 인터페이스의 프리픽스(/64 여야 함)로 주소를 만들고 이 링크 로컬 주소를 기본 게이트웨이로 씁니다. 수동 호스트는 게이트웨이를 이 링크 로컬이나 글로벌 주소로 둡니다.
          </p>
          {anyRa && (
            <Field label="RA 의 DNS" hint="RDNSS" error={ip6Error(v6.raDns ?? "", false)}>
              <input class="input mono" value={v6.raDns ?? ""} placeholder="비우면 알리지 않음" onInput={(e) => set({ raDns: e.currentTarget.value })} />
            </Field>
          )}
          {anyRa && (
            <label class="toggle-row">
              <span>
                주기 RA <span class="mono muted">10초 · 라우터 수명 30초</span>
                <small class="muted">이 라우터가 말없이 사라지면 호스트가 뺌</small>
              </span>
              <Toggle on={v6.raPeriodic === true} onToggle={() => set({ raPeriodic: !v6.raPeriodic })} />
            </label>
          )}
          {anyRa && v6.raPeriodic === true && <p class="note">10초마다 RA 를 보내고 라우터 수명을 30초로 알립니다(radvd: 수명 = 간격 × 3). RA 가 30초 동안 오지 않으면 호스트가 이 라우터를 기본 게이트웨이에서 빼고, 같은 링크의 다른 라우터로 넘어갑니다. 끄면 변화가 있을 때만 RA(수명 1800초)라, 말없이 사라진 라우터를 호스트가 30분 동안 모릅니다. RA 는 시간이 흐를 때만 돕니다(위의 "+10초").</p>}
          <h3 class="sub">IPv6 스태틱 라우팅</h3>
          {v6.routes.length === 0 && <p class="note">연결된 프리픽스 밖으로 보낼 경로를 추가합니다. 디폴트 라우트는 목적지 :: / 0 입니다.</p>}
          {v6.routes.map((r, i) => (
            <div key={i} class="route-row">
              <span class="muted">목적지</span>
              <input class="input mono" value={r.dest} placeholder="2001:db8:3::" title="목적지 프리픽스" onInput={(e) => setRoutes(v6.routes.map((x, k) => (k === i ? { ...x, dest: e.currentTarget.value } : x)))} />
              <span class="mono">/</span>
              <input class="input mono prefix-in" type="number" min={0} max={128} value={r.prefix} onInput={(e) => { if (e.currentTarget.value === "") return; setRoutes(v6.routes.map((x, k) => (k === i ? { ...x, prefix: Math.min(128, Math.max(0, Math.round(Number(e.currentTarget.value)) || 0)) } : x))); }} />
              <span class="muted">넥스트 홉</span>
              <input class="input mono via" value={r.via} placeholder="연결된 프리픽스 안의 주소" title="넥스트 홉 주소 (연결된 프리픽스 안의 글로벌 주소)" onInput={(e) => setRoutes(v6.routes.map((x, k) => (k === i ? { ...x, via: e.currentTarget.value } : x)))} />
              <button class="icon-btn" title="경로 삭제" onClick={() => setRoutes(v6.routes.filter((_, k) => k !== i))}>
                <Icon name="trash" size={15} />
              </button>
              {route6Error(v6, r) && <div class="error route-error">{route6Error(v6, r)}</div>}
            </div>
          ))}
          <button class="btn wide" onClick={() => setRoutes([...v6.routes, { dest: "", prefix: 64, via: "" }])}>
            <Icon name="plus" size={14} />
            IPv6 경로 추가
          </button>
        </>
      )}
    </Section>
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
          {ipsec && (
            <label class="toggle-row">
              <span>
                주기 DPD <span class="mono muted">10초 · 조용할 때</span>
                <small class="muted">말없이 사라진 상대를 알아채 터널을 지움</small>
              </span>
              <Toggle on={vpn.dpd === true} onToggle={() => set({ dpd: !vpn.dpd })} />
            </label>
          )}
          {ipsec && <DpdControl d={d} />}
        </>
      )}
    </Section>
  );
}

/** IPsec 터널 상태 + "상대 확인 (DPD)" 버튼 (터널이 맺어져 있을 때만 누를 수 있다) */
function DpdControl({ d }: { d: Device }) {
  void simVersion.value;
  const node = sim.node(d.id);
  if (!(node instanceof L3Node) || node.vpn.mode !== "ipsec") return null;
  const up = node.vpn.ipsecUp;
  return (
    <>
      <p class="note">{node.vpn.saSummary()}</p>
      <button class="btn wide" disabled={!up || node.vpn.dpdWaiting} onClick={() => sim.act({ kind: "vpn-dpd", nodeId: d.id })} title="빈 INFORMATIONAL 을 보내 상대가 살아 있고 이 터널을 아는지 확인합니다">
        <Icon name="send" size={14} />
        상대 확인 (DPD)
      </button>
      <p class="note">
        {up
          ? "조용한 터널은 상대가 꺼지거나 경로가 끊겨도 모릅니다. 누르면 빈 INFORMATIONAL 을 보내고, 1초씩 두 번 다시 보내도 응답이 없으면 터널(SA)을 지웁니다(다음 패킷에 다시 협상). 주기 DPD 를 켜면 상대에게서 10초 동안 받은 것이 없을 때 저절로 보냅니다 — 시간이 흐를 때만(패킷이 오가거나 위의 \"+10초\")."
          : "터널(SA)이 맺어진 뒤에 누를 수 있습니다. 상대 대역으로 ping 을 한 번 보내면 IKE 로 터널을 맺습니다."}
      </p>
    </>
  );
}

/** 원격 접속 VPN 서버: 켜기 + PSK + 가상 주소 풀 + 알려 줄 사내 대역 */
export function RaServerSection({ d, l3 }: { d: Device; l3: L3Settings }) {
  const empty: NonNullable<L3Settings["ra"]> = { enabled: false, psk: "", poolStart: "10.99.0.10", poolEnd: "10.99.0.50", routes: [] };
  const ra = l3.ra ?? empty;
  const set = (patch: Partial<NonNullable<L3Settings["ra"]>>) =>
    updateDevice(d.id, (x) => {
      const cur = x.l3 ?? defaultL3(x.kind);
      return { ...x, l3: { ...cur, ra: { ...(cur.ra ?? empty), ...patch } } };
    });
  const setRoute = (i: number, patch: Partial<{ dest: string; prefix: number }>) => set({ routes: ra.routes.map((r, k) => (k === i ? { ...r, ...patch } : r)) });
  const users = ra.users ?? [];
  const setUser = (i: number, patch: Partial<{ name: string; password: string }>) => set({ users: users.map((u, k) => (k === i ? { ...u, ...patch } : u)) });
  const userError = (i: number): string | undefined => {
    const name = users[i]!.name.trim();
    if (name === "") return "사용자 이름이 필요합니다. 비워 두면 이 줄은 쓰지 않습니다.";
    if (users.findIndex((u) => u.name.trim() === name) !== i) return `${name} 가 이미 위에 있습니다. 같은 이름은 첫 줄만 씁니다.`;
    return undefined;
  };
  return (
    <Section title="원격 접속 VPN 서버">
      <label class="toggle-row">
        <span>
          {ra.enabled ? "켜짐" : "꺼짐"} <span class="mono muted">IPsec · IKE UDP 500</span>
        </span>
        <Toggle on={ra.enabled} onToggle={() => set({ enabled: !ra.enabled })} />
      </label>
      {!ra.enabled && <p class="note">켜면 재택 노트북 같은 클라이언트가 인터넷 너머에서 붙을 수 있습니다. 붙은 클라이언트마다 가상 주소를 하나씩 주고, 아래 사내 대역으로 가는 것만 터널로 보내라고 알려 줍니다.</p>}
      {ra.enabled && (
        <>
          <Field label="사전 공유 키 (PSK)" error={ra.psk ? undefined : "비어 있습니다. 클라이언트와 같은 키를 넣으세요."}>
            <input class="input mono" value={ra.psk} placeholder="클라이언트와 같은 문자열" onInput={(e) => set({ psk: e.currentTarget.value })} />
          </Field>
          <Field label="가상 주소 풀 시작" error={ipError(ra.poolStart, true)}>
            <input class="input mono" value={ra.poolStart} placeholder="10.99.0.10" onInput={(e) => set({ poolStart: e.currentTarget.value })} />
          </Field>
          <Field label="가상 주소 풀 끝" error={ipError(ra.poolEnd, true)}>
            <input class="input mono" value={ra.poolEnd} placeholder="10.99.0.50" onInput={(e) => set({ poolEnd: e.currentTarget.value })} />
          </Field>
          <h3 class="sub">알려 줄 사내 대역</h3>
          {ra.routes.length === 0 && <p class="note error-note">클라이언트가 터널로 보낼 사내 대역(예: 안쪽 LAN)을 넣어야 합니다.</p>}
          {ra.routes.map((r, i) => (
            <div key={i} class="lb-row">
              <input class="input mono" value={r.dest} placeholder="10.50.10.0" onInput={(e) => setRoute(i, { dest: e.currentTarget.value })} />
              <span class="mono muted">/</span>
              <input class="input mono" type="number" min={1} max={32} value={r.prefix} onInput={(e) => { if (e.currentTarget.value !== "") setRoute(i, { prefix: Math.min(32, Math.max(1, Number(e.currentTarget.value) || 24)) }); }} />
              <button class="icon-btn" title="대역 삭제" onClick={() => set({ routes: ra.routes.filter((_, k) => k !== i) })}>
                <Icon name="trash" size={15} />
              </button>
              {ipError(r.dest, true) && <div class="error lb-error">{ipError(r.dest, true)}</div>}
            </div>
          ))}
          <button class="btn wide" onClick={() => set({ routes: [...ra.routes, { dest: "", prefix: 24 }] })}>
            <Icon name="plus" size={14} />
            대역 추가
          </button>
          <h3 class="sub">사용자 계정 (EAP)</h3>
          {users.length === 0 && <p class="note">비어 있으면 PSK 만 맞으면 접속합니다. 계정을 넣으면 PSK 확인 뒤 사용자 이름·비밀번호까지 확인하고(EAP-MSCHAPv2) 가상 주소를 줍니다.</p>}
          {users.map((u, i) => (
            <div key={i} class="record-row">
              <input class="input mono" value={u.name} placeholder="사용자 이름" onInput={(e) => setUser(i, { name: e.currentTarget.value })} />
              <span class="muted">:</span>
              <input class="input mono" value={u.password} placeholder="비밀번호" onInput={(e) => setUser(i, { password: e.currentTarget.value })} />
              <button class="icon-btn" title="계정 삭제" onClick={() => set({ users: users.filter((_, k) => k !== i) })}>
                <Icon name="trash" size={15} />
              </button>
              {userError(i) && <div class="error record-error">{userError(i)}</div>}
            </div>
          ))}
          <button class="btn wide" onClick={() => set({ users: [...users, { name: "", password: "" }] })}>
            <Icon name="plus" size={14} />
            계정 추가
          </button>
          {users.length > 0 && <p class="note">PSK 는 모두가 같이 쓰는 키라 한 명을 막으려면 모두의 키를 바꿔야 하지만, 계정은 그 사람 것만 지우면 됩니다. 이미 접속한 세션은 끊기지 않고 다시 접속할 때 막힙니다.</p>}
          <p class="note">방화벽이 인바운드를 막고 있으면 가상 주소 풀에서 사내 대역으로 들어오는 것을 허용하세요. 안쪽 라우터가 따로 있으면 그 라우터에 풀 대역을 이 장비로 보내는 경로가 필요합니다. 접속한 클라이언트는 "표" 탭에 보입니다.</p>
        </>
      )}
    </Section>
  );
}

/** 이중화 (VRRP 식): 켜기 + 그룹 번호 + 우선순위 + 인터페이스별 가상 주소 */
export function HaSection({ d, l3 }: { d: Device; l3: L3Settings }) {
  const empty: NonNullable<L3Settings["ha"]> = { enabled: false, vrid: 1, priority: 100, vips: [] };
  const ha = l3.ha ?? empty;
  const names = specOf(d).ports.map((p) => p.name);
  const set = (patch: Partial<NonNullable<L3Settings["ha"]>>) =>
    updateDevice(d.id, (x) => {
      const cur = x.l3 ?? defaultL3(x.kind);
      return { ...x, l3: { ...cur, ha: { ...(cur.ha ?? empty), ...patch } } };
    });
  const clamp = (v: string, lo: number, hi: number, dflt: number) => Math.min(hi, Math.max(lo, Math.round(Number(v)) || dflt));
  const vipError = (i: number): string | undefined => {
    const v = ha.vips[i] ?? "";
    const base = ipError(v, false);
    if (base) return base;
    const c = l3.interfaces[i];
    if (!v || !c || c.ipMode !== "static" || !validIp(c.ip)) return undefined;
    if (v === c.ip) return "인터페이스 자신의 주소와 달라야 합니다 (가상 주소는 쌍이 함께 쓰는 별도 주소)";
    if (!sameSubnet(v, c.ip, c.prefix)) return `${names[i]} 의 서브넷(${c.ip}/${c.prefix}) 밖입니다`;
    return undefined;
  };
  return (
    <Section title="이중화 (HA)">
      <label class="toggle-row">
        <span>
          {ha.enabled ? "켜짐" : "꺼짐"} <span class="mono muted">VRRP</span>
        </span>
        <Toggle on={ha.enabled} onToggle={() => set({ enabled: !ha.enabled })} />
      </label>
      {!ha.enabled && (
        <p class="note">
          켜면 같은 설정의 장비 두 대가 가상 주소를 함께 두고, 우선순위가 높은 한 대(master)만 그 주소로 일합니다. master 의 링크가 죽거나 장비가 사라지면 다른 한 대(backup)가 가상 주소를 이어받습니다. 호스트의 게이트웨이는 가상 주소로 둡니다.
        </p>
      )}
      {ha.enabled && (
        <>
          <Field label="그룹 번호 (VRID)">
            <input class="input mono" type="number" min={1} max={255} value={ha.vrid} onInput={(e) => { if (e.currentTarget.value !== "") set({ vrid: clamp(e.currentTarget.value, 1, 255, 1) }); }} />
          </Field>
          <Field label="우선순위">
            <input class="input mono" type="number" min={1} max={254} value={ha.priority} onInput={(e) => { if (e.currentTarget.value !== "") set({ priority: clamp(e.currentTarget.value, 1, 254, 100) }); }} />
          </Field>
          <label class="toggle-row">
            <span>
              세션 동기화 <span class="mono muted">pfsync</span>
              <small class="muted">master 의 NAT 매핑·방화벽 흐름을 backup 에 복사</small>
            </span>
            <Toggle on={ha.sync === true} onToggle={() => set({ sync: !ha.sync })} />
          </label>
          <label class="toggle-row">
            <span>
              주기 광고 <span class="mono muted">1초 · Master_Down 3초</span>
              <small class="muted">말없이 죽은 master 를 backup 이 알아챔</small>
            </span>
            <Toggle on={ha.advert === true} onToggle={() => set({ advert: !ha.advert })} />
          </label>
          {ha.advert === true && <p class="note">master 가 1초마다 광고하고, backup 은 3초(+skew) 동안 못 들으면 이어받습니다. 광고·감시는 시간이 흐를 때만 돕니다 — 시계는 패킷이 오갈 때만 가므로 ping 을 이어 보내거나 위의 "+10초" 로 시간을 흘려보내세요. 짝 장비도 같게 켭니다.</p>}
          <h3 class="sub">가상 주소</h3>
          {names.map((n, i) => (
            <Field key={n} label={n} error={vipError(i)}>
              <input
                class="input mono"
                value={ha.vips[i] ?? ""}
                placeholder="비우면 이 인터페이스는 참여 안 함"
                onInput={(e) => set({ vips: names.map((_, k) => (k === i ? e.currentTarget.value : (ha.vips[k] ?? ""))) })}
              />
            </Field>
          ))}
          <p class="note">
            짝 장비에도 같은 그룹 번호·가상 주소로 켜고, 우선순위만 다르게 둡니다(높은 쪽이 master, 돌아오면 다시 가져감). 가상 MAC 은 00:00:5e:00:01:{ha.vrid.toString(16).padStart(2, "0")} 입니다. {ha.sync ? "세션 동기화를 켜 두면 NAT 매핑·방화벽 흐름이 backup 에도 있어 넘어가도 진행 중인 연결(SSH 세션 등)이 이어집니다. IPsec 터널은 복사되지 않아 다시 협상합니다." : "세션 동기화가 꺼져 있으면 NAT 매핑·방화벽 흐름이 넘어가지 않아, 진행 중이던 연결은 끊기고 새 연결부터 됩니다."}
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
/** 스위치 STP: 켜기 + 브리지 우선순위 */
export function StpSection({ d }: { d: Device }) {
  const stp = d.switch?.stp ?? { enabled: false, priority: 32768 };
  const set = (patch: Partial<typeof stp>) => updateDevice(d.id, (x) => ({ ...x, switch: { ...(x.switch ?? { vlans: {} }), stp: { ...(x.switch?.stp ?? { enabled: false, priority: 32768 }), ...patch } } }));
  return (
    <Section title="스패닝 트리 (STP)">
      <label class="toggle-row">
        <span>{stp.enabled ? "켜짐" : "꺼짐"}</span>
        <Toggle on={stp.enabled} onToggle={() => set({ enabled: !stp.enabled })} />
      </label>
      {!stp.enabled && <p class="note">스위치끼리 여러 경로로 이으면(고리) 브로드캐스트가 끝없이 돕니다. 켜면 스위치끼리 BPDU 를 주고받아 루트를 정하고, 포트 하나를 막아 고리를 끊습니다. 실제 스위치는 기본으로 켜져 있습니다.</p>}
      {stp.enabled && (
        <>
          <Field label="브리지 우선순위">
            <select class="input" value={stp.priority} onChange={(e) => set({ priority: Number(e.currentTarget.value) })}>
              {Array.from({ length: 16 }, (_, k) => k * 4096).map((p) => (
                <option key={p} value={p}>
                  {p}
                  {p === 32768 ? " (기본)" : ""}
                </option>
              ))}
            </select>
          </Field>
          <p class="note">작을수록 루트 브리지가 되기 쉽습니다(같으면 MAC 이 작은 쪽). 가운데(코어) 스위치를 작게 두어 루트로 정하는 게 보통입니다. 막힌 포트는 캔버스에서 점선과 ⊘ 로 보이고, "표" 탭에 포트 역할이 나옵니다.</p>
        </>
      )}
    </Section>
  );
}

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
