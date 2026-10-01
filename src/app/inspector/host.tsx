// 호스트 설정: IP 설정, 서비스(웹·DHCP 서버·DNS 서버·로드밸런서·프록시), HTTP 프록시 설정, 무선 단말·AP.
import { prefixToMask, intToIp, sameSubnet } from "../../core/addr";
import { topology, updateDevice } from "../../model/store";
import {
  DEFAULT_DHCP_SERVER,
  DEFAULT_DNS_SERVER,
  DEFAULT_IPV6_HOST,
  type Ipv6HostSettings,
  DEFAULT_LB_SETTINGS,
  DEFAULT_PROXY_SETTINGS,
  DEFAULT_ROUTER_WIFI,
  DEFAULT_WIFI_BASE,
  type Device,
  type HostSettings,
  WIFI_RANGE,
  wirelessLinks,
  wirelessStatus,
} from "../../model/topology";
import { Icon } from "../Icons";
import { Field, Section, Toggle, anyIpError, ip6Error, ipError, validIp } from "./ui";
import { linkLocalOf } from "../../core/addr6";
import { sim, simVersion } from "../../model/sim";
import { Host } from "../../core/nodes/host";

export function HostSection({ d, h }: { d: Device; h: HostSettings }) {
  const set = (patch: Partial<HostSettings>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, ...patch } }));
  const isStatic = h.ipMode === "static";
  return (
    <Section title="IP 설정">
      <div class="segmented" role="radiogroup">
        <button class={h.ipMode === "dhcp" ? "on" : ""} onClick={() => set({ ipMode: "dhcp" })}>
          자동 (DHCP)
        </button>
        <button class={isStatic ? "on" : ""} onClick={() => set({ ipMode: "static" })}>
          수동
        </button>
      </div>
      {isStatic ? (
        <>
          <Field label="IP 주소" error={ipError(h.ip, !h.ipv6?.enabled)}>
            <input class="input mono" value={h.ip} placeholder={h.ipv6?.enabled ? "비우면 IPv6 만" : "192.168.0.10"} onInput={(e) => set({ ip: e.currentTarget.value })} />
          </Field>
          <Field label="서브넷">
            <div class="prefix">
              <span class="mono">/</span>
              <input
                class="input mono"
                type="number"
                min={0}
                max={32}
                value={h.prefix}
                onInput={(e) => { if (e.currentTarget.value === "") return; set({ prefix: Math.min(32, Math.max(0, Number(e.currentTarget.value) || 0)) }); }}
              />
              <span class="mono muted">{intToIp(prefixToMask(h.prefix))}</span>
            </div>
          </Field>
          <Field label="게이트웨이" error={ipError(h.gateway, false)}>
            <input class="input mono" value={h.gateway} placeholder="192.168.0.1" onInput={(e) => set({ gateway: e.currentTarget.value })} />
          </Field>
          <Field label="DNS 서버" error={ipError(h.dns ?? "", false)}>
            <input class="input mono" value={h.dns ?? ""} placeholder="비우면 이름 해석 불가" onInput={(e) => set({ dns: e.currentTarget.value })} />
          </Field>
        </>
      ) : (
        <p class="note">연결된 네트워크의 DHCP 서버에서 IP 주소, 서브넷, 게이트웨이, DNS 를 받습니다. DHCP 가 없으면 주소 없이 남습니다.</p>
      )}
    </Section>
  );
}

/** MAC 에서 만든 링크 로컬 주소 (MAC 이 이상하면 빈 문자열) */
export function linkLocalLabel(mac: string): string {
  try {
    return linkLocalOf(mac);
  } catch {
    return "";
  }
}

/** 호스트의 IPv6: 켜기 + 수동 주소·프리픽스·기본 게이트웨이. 링크 로컬은 MAC 에서 자동 */
export function Ipv6Section({ d, h }: { d: Device; h: HostSettings }) {
  const v = h.ipv6 ?? { ...DEFAULT_IPV6_HOST, enabled: false };
  const set = (patch: Partial<Ipv6HostSettings>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, ipv6: { ...(x.host!.ipv6 ?? DEFAULT_IPV6_HOST), ...patch } } }));
  const ll = linkLocalLabel(d.mac);
  return (
    <Section title="IPv6">
      <label class="toggle-row">
        <span>{v.enabled ? "켜짐" : "꺼짐"}</span>
        <Toggle on={v.enabled} onToggle={() => set({ enabled: !v.enabled })} />
      </label>
      {!v.enabled ? (
        <p class="note">켜면 MAC 에서 만든 링크 로컬 주소({ll})가 생기고, ARP 대신 NDP 로 이웃을 찾습니다. 실제 OS 는 IPv6 가 기본으로 켜져 있지만, 여기서는 켜야 IPv6 패킷이 오갑니다.</p>
      ) : v.mode === "slaac" ? (
        <>
          <Ipv6ModeSwitch mode={v.mode} onChange={(mode) => set({ mode })} />
          <p class="note">
            라우터 광고(RA)가 알린 /64 프리픽스에 MAC 에서 만든 인터페이스 ID 를 붙여 주소를 스스로 만들고(SLAAC), RA 를 보낸 라우터의 링크 로컬 주소를 기본 게이트웨이로 씁니다. DNS 는 RA 의 RDNSS 옵션으로 받습니다. 링크 로컬 <span class="mono">{ll}</span>
          </p>
          <NudToggle on={v.nud === true} onToggle={() => set({ nud: !v.nud })} />
        </>
      ) : (
        <>
          <Ipv6ModeSwitch mode={v.mode} onChange={(mode) => set({ mode })} />
          <Field label="IPv6 주소" error={ip6Error(v.ip, false)}>
            <div class="prefix addr6">
              <input class="input mono" value={v.ip} placeholder="2001:db8:1::10" onInput={(e) => set({ ip: e.currentTarget.value })} />
              <span class="mono">/</span>
              <input
                class="input mono"
                type="number"
                min={1}
                max={128}
                value={v.prefix}
                title="프리픽스 길이 (보통 64)"
                onInput={(e) => { if (e.currentTarget.value === "") return; set({ prefix: Math.min(128, Math.max(1, Math.round(Number(e.currentTarget.value)) || 64)) }); }}
              />
            </div>
          </Field>
          <Field label="기본 게이트웨이" error={ip6Error(v.gateway, false, true)}>
            <input class="input mono" value={v.gateway} placeholder="라우터 주소 (fe80:: 도 됨)" onInput={(e) => set({ gateway: e.currentTarget.value })} />
          </Field>
          <Field label="IPv6 DNS 서버" error={ip6Error(v.dns ?? "", false, true)}>
            <input class="input mono" value={v.dns ?? ""} placeholder="IPv4 DNS 가 있으면 그쪽을 먼저 씀" onInput={(e) => set({ dns: e.currentTarget.value })} />
          </Field>
          <p class="note">
            링크 로컬 <span class="mono">{ll}</span> 은 MAC 에서 자동으로 생깁니다(fe80::/64 + EUI-64). 주소를 비우면 링크 로컬만으로 같은 링크의 이웃과 통신합니다. 기본 게이트웨이는 라우터의 글로벌 주소나 링크 로컬 주소 어느 쪽이든 됩니다.
          </p>
          <NudToggle on={v.nud === true} onToggle={() => set({ nud: !v.nud })} />
        </>
      )}
    </Section>
  );
}

/** NUD (이웃 도달 확인) 켜기 */
function NudToggle({ on, onToggle }: { on: boolean; onToggle: () => void }) {
  return (
    <>
      <label class="toggle-row">
        <span>
          NUD <span class="mono muted">REACHABLE 30초 · DELAY 5초 · PROBE 3번</span>
          <small class="muted">말없이 사라진 이웃·라우터를 알아챔</small>
        </span>
        <Toggle on={on} onToggle={onToggle} />
      </label>
      {on && <p class="note">이웃을 확인(요청한 NA)한 지 30초가 지나면 STALE, 그 이웃에게 보낼 때 5초 기다렸다 유니캐스트 NS 로 직접 확인합니다(<span class="mono">ip -6 neigh</span> 의 DELAY·PROBE). 3번에 답이 없으면 지우고, 라우터였다면 기본 게이트웨이 후보에서 뒤로 미뤄 다음 라우터로 넘어갑니다. 끄면 60초 지난 항목을 다시 물을 때(NS)만 알아챕니다.</p>}
    </>
  );
}

function Ipv6ModeSwitch({ mode, onChange }: { mode: Ipv6HostSettings["mode"]; onChange: (m: Ipv6HostSettings["mode"]) => void }) {
  return (
    <div class="segmented" role="radiogroup">
      <button class={mode === "slaac" ? "on" : ""} onClick={() => onChange("slaac")}>
        자동 (SLAAC)
      </button>
      <button class={mode === "static" ? "on" : ""} onClick={() => onChange("static")}>
        수동
      </button>
    </div>
  );
}

/** 무선 단말: 어느 SSID 에 붙을지 + 현재 상태. 노트북은 Wi-Fi 켜기/끄기와 지금 쓰는 NIC(유선 우선)도 */
export function WifiClientSection({ d }: { d: Device }) {
  void simVersion.value;
  const t = topology.value;
  const laptop = d.kind === "laptop";
  const on = !!d.wifi && d.wifi.enabled !== false;
  const st = on ? wirelessStatus(t, d) : undefined;
  const baseName = st?.linked ? (t.devices.find((x) => x.id === st.linked!.base)?.name ?? st.linked.base) : undefined;
  const node = sim.node(d.id);
  const active = laptop && node instanceof Host && node.nics.length > 1 ? node.activeNic : undefined;
  const setWifi = (patch: { ssid?: string; enabled?: boolean }) =>
    updateDevice(d.id, (x) => {
      const next = { ssid: x.wifi?.ssid ?? "home", ...(x.wifi?.enabled === false ? { enabled: false } : {}), ...patch };
      if (next.enabled !== false) delete next.enabled;
      return { ...x, wifi: next };
    });
  return (
    <Section title={laptop ? "Wi-Fi" : "무선"}>
      {laptop && (
        <label class="toggle-row">
          <span>
            {on ? "켜짐" : "꺼짐"} <span class="mono muted">wlan0</span>
          </span>
          <Toggle on={on} onToggle={() => setWifi({ enabled: !on })} />
        </label>
      )}
      {laptop && (
        <p class="note">
          {active === 0 ? "지금 유선(eth0)으로 통신합니다." : active === 1 ? "지금 Wi-Fi(wlan0)로 통신합니다." : "연결된 NIC 가 없습니다."} 유선 케이블이 꽂혀 있으면 유선을 쓰고(유선 우선), 빼면 Wi-Fi 로 넘어갑니다. NIC 마다 MAC 이 달라 넘어갈 때마다 주소를 새로 받습니다.
        </p>
      )}
      {on && (
        <Field label="SSID">
          <input class="input mono" value={d.wifi?.ssid ?? ""} placeholder="연결할 네트워크 이름" onInput={(e) => setWifi({ ssid: e.currentTarget.value })} />
        </Field>
      )}
      {st?.linked ? (
        <p class="note ok-note">
          {baseName} 에 연결됨 · 거리 {st.linked.distance}px (범위 {WIFI_RANGE}px){st.linked.standby ? " · 유선을 쓰는 동안 대기" : ""}. 단말을 끌어서 멀어지면 끊깁니다.
        </p>
      ) : st ? (
        <p class="note error-note">{st.reason}</p>
      ) : null}
    </Section>
  );
}

/** 무선 기지(AP·공유기): 켜기/끄기, SSID, 붙은 단말 */
export function WifiBaseSection({ d }: { d: Device }) {
  const t = topology.value;
  const isRouter = !!d.router;
  const cfg = isRouter ? (d.router!.wifi ?? DEFAULT_ROUTER_WIFI) : (d.ap ?? DEFAULT_WIFI_BASE);
  const set = (patch: Partial<typeof cfg>) =>
    updateDevice(d.id, (x) =>
      isRouter ? { ...x, router: { ...x.router!, wifi: { ...(x.router!.wifi ?? DEFAULT_ROUTER_WIFI), ...patch } } } : { ...x, ap: { ...(x.ap ?? DEFAULT_WIFI_BASE), ...patch } },
    );
  const clients = wirelessLinks(t).filter((l) => l.base === d.id);
  return (
    <Section title={isRouter ? "무선 (Wi-Fi)" : "무선 설정"}>
      <label class="toggle-row">
        <span>{cfg.enabled ? "켜짐" : "꺼짐"}</span>
        <Toggle on={cfg.enabled} onToggle={() => set({ enabled: !cfg.enabled })} />
      </label>
      {cfg.enabled && (
        <>
          <Field label="SSID">
            <input class="input mono" value={cfg.ssid} placeholder="home" onInput={(e) => set({ ssid: e.currentTarget.value })} />
          </Field>
          <p class="note">
            전파 범위 {WIFI_RANGE}px 안에서 같은 SSID 를 가진 단말이 붙습니다. {isRouter ? "붙은 단말은 LAN 포트의 유선 호스트와 같은 네트워크입니다." : "AP 는 eth0 으로 스위치/라우터에 꽂아야 단말이 주소를 받습니다."}
          </p>
          {clients.length > 0 && (
            <div class="stat-rows">
              {clients.map((l) => (
                <div key={l.id} class="port-row">
                  <span class="dot up" />
                  <span class="mono">슬롯 {l.slot}</span>
                  <span class="peer">
                    {t.devices.find((x) => x.id === l.client)?.name ?? l.client} <span class="muted">{l.distance}px</span>
                  </span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
      {!cfg.enabled && <p class="note">꺼져 있으면 단말이 붙지 않습니다.</p>}
    </Section>
  );
}

export function ServiceSection({ d, h }: { d: Device; h: HostSettings }) {
  const has = (port: number) => (h.services ?? []).includes(port);
  const toggle = (port: number) =>
    updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, services: has(port) ? (x.host!.services ?? []).filter((p) => p !== port) : [...(x.host!.services ?? []), port] } }));
  const on = has(80);
  const ds = h.dhcpServer ?? DEFAULT_DHCP_SERVER;
  const setDs = (patch: Partial<typeof ds>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, dhcpServer: { ...(x.host!.dhcpServer ?? DEFAULT_DHCP_SERVER), ...patch } } }));
  const staticIp = h.ipMode === "static" && validIp(h.ip) ? h.ip : undefined;
  const rangeErr = (v: string) => {
    const base = ipError(v, true);
    if (base) return base;
    if (staticIp && !sameSubnet(v, staticIp, h.prefix)) return `내 서브넷(${staticIp}/${h.prefix}) 밖입니다`;
    return undefined;
  };
  return (
    <Section title="서비스">
      <label class="toggle-row">
        <span>
          웹 서버 <span class="mono muted">TCP 80</span>
        </span>
        <Toggle on={on} onToggle={() => toggle(80)} />
      </label>
      <p class="note">{on ? "포트 80 으로 오는 연결 요청(SYN)에 응답합니다. 다른 호스트에서 이 장치로 연결해 보세요." : "꺼져 있으면 연결 요청에 RST 로 거부합니다."}</p>
      <label class="toggle-row">
        <span>
          SSH 서버 <span class="mono muted">TCP 22</span>
        </span>
        <Toggle on={has(22)} onToggle={() => toggle(22)} />
      </label>
      {has(22) && <p class="note">포트 22 로 연결을 받습니다. 진단에서 TCP 22 로 연결해 보세요(연결 과정만 보여 주고, 암호화된 SSH 대화 내용은 다루지 않습니다).</p>}
      <label class="toggle-row">
        <span>
          HTTPS 서버 <span class="mono muted">TCP 443</span>
        </span>
        <Toggle on={has(443)} onToggle={() => toggle(443)} />
      </label>
      {has(443) && <p class="note">포트 443 으로 TLS 핸드셰이크(ClientHello → 인증서) 뒤 암호화된 요청에 응답합니다. 중간 장비는 SNI(접속할 이름)와 길이만 봅니다.</p>}
      <label class="toggle-row">
        <span>
          DHCP 서버 <span class="mono muted">UDP 67</span>
        </span>
        <Toggle on={ds.enabled} onToggle={() => setDs({ enabled: !ds.enabled })} />
      </label>
      {ds.enabled && (
        <>
          {!staticIp && <p class="note error-note">DHCP 서버는 자기 주소가 고정돼 있어야 합니다. 위의 IP 설정을 수동으로 바꾸세요.</p>}
          <Field label="시작 주소" error={rangeErr(ds.start)}>
            <input class="input mono" value={ds.start} onInput={(e) => setDs({ start: e.currentTarget.value })} />
          </Field>
          <Field label="끝 주소" error={rangeErr(ds.end)}>
            <input class="input mono" value={ds.end} onInput={(e) => setDs({ end: e.currentTarget.value })} />
          </Field>
          <Field label="기본 게이트웨이" hint="옵션 3" error={ipError(ds.router, false)}>
            <input class="input mono" value={ds.router} placeholder="비우면 옵션 없음" onInput={(e) => setDs({ router: e.currentTarget.value })} />
          </Field>
          <Field label="DNS 서버" hint="옵션 6" error={ipError(ds.dns ?? "", false)}>
            <input class="input mono" value={ds.dns ?? ""} placeholder="비우면 옵션 없음" onInput={(e) => setDs({ dns: e.currentTarget.value })} />
          </Field>
          <p class="note">클라이언트에게 이 범위의 주소와 함께 게이트웨이·DNS 를 알려줍니다. 게이트웨이를 비우면 서브넷 밖으로 못 나가고, DNS 를 비우면 이름을 못 씁니다.</p>
          <h3 class="sub">다른 서브넷 풀 (릴레이용)</h3>
          {(ds.extraPools ?? []).length === 0 && <p class="note">게이트웨이가 DHCP 릴레이로 보내오는 다른 서브넷의 요청에 줄 범위입니다. giaddr 가 속한 서브넷의 풀을 골라 응답합니다.</p>}
          {(ds.extraPools ?? []).map((p, i) => {
            const setPool = (patch: Partial<typeof p>) => setDs({ extraPools: (ds.extraPools ?? []).map((x, k) => (k === i ? { ...x, ...patch } : x)) });
            const bad = !validIp(p.start) || !validIp(p.end) ? "시작·끝 주소가 필요합니다" : !sameSubnet(p.start, p.end, p.prefix) ? "시작과 끝이 같은 서브넷이 아닙니다" : validIp(p.router) && !sameSubnet(p.router, p.start, p.prefix) ? "게이트웨이가 그 서브넷 밖입니다" : undefined;
            return (
              <div key={i} class="pool-row">
                <span class="muted">범위</span>
                <input class="input mono" value={p.start} placeholder="192.168.2.100" onInput={(e) => setPool({ start: e.currentTarget.value })} />
                <span class="muted">~</span>
                <input class="input mono" value={p.end} placeholder="192.168.2.199" onInput={(e) => setPool({ end: e.currentTarget.value })} />
                <button class="icon-btn" title="풀 삭제" onClick={() => setDs({ extraPools: (ds.extraPools ?? []).filter((_, k) => k !== i) })}>
                  <Icon name="trash" size={15} />
                </button>
                <span class="muted">/ 마스크 길이</span>
                <input class="input mono prefix-in" type="number" min={1} max={32} value={p.prefix} onInput={(e) => setPool({ prefix: Math.min(32, Math.max(1, Number(e.currentTarget.value) || 24)) })} />
                <span class="muted">게이트웨이</span>
                <input class="input mono" value={p.router} placeholder="192.168.2.1" onInput={(e) => setPool({ router: e.currentTarget.value })} />
                {bad && <div class="error pool-error">{bad}</div>}
              </div>
            );
          })}
          <button class="btn wide" onClick={() => setDs({ extraPools: [...(ds.extraPools ?? []), { start: "", end: "", prefix: 24, router: "" }] })}>
            <Icon name="plus" size={14} />
            서브넷 풀 추가
          </button>
        </>
      )}
      <DnsServiceSection d={d} h={h} staticIp={staticIp} />
      <LbFields d={d} h={h} />
      <ProxyFields d={d} h={h} />
    </Section>
  );
}

/** 포워드 프록시(Squid 식) 켜기 + 포트·차단 목록 */
function ProxyFields({ d, h }: { d: Device; h: HostSettings }) {
  const px = h.proxy ?? DEFAULT_PROXY_SETTINGS;
  const set = (patch: Partial<typeof px>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, proxy: { ...(x.host!.proxy ?? DEFAULT_PROXY_SETTINGS), ...patch } } }));
  const lbClash = px.enabled && h.lb?.enabled === true && h.lb.port === px.port;
  const serviceClash = px.enabled && !lbClash && (h.services ?? []).includes(px.port);
  return (
    <>
      <label class="toggle-row">
        <span>
          프록시 <span class="mono muted">TCP {px.port}</span>
        </span>
        <Toggle on={px.enabled} onToggle={() => set({ enabled: !px.enabled })} />
      </label>
      {!px.enabled && <p class="note">켜면 다른 장치가 부탁한 웹 요청을 대신 받아 옵니다(Squid 같은 포워드 프록시). 로드밸런서가 서버들을 대신한다면, 프록시는 클라이언트들을 대신합니다.</p>}
      {px.enabled && (
        <>
          <Field label="받는 포트">
            <input class="input mono" type="number" min={1} max={65535} value={px.port} onInput={(e) => { if (e.currentTarget.value !== "") set({ port: Math.min(65535, Math.max(1, Number(e.currentTarget.value) || 3128)) }); }} />
          </Field>
          {lbClash && <p class="note error-note">포트 {px.port} 는 이 장치의 로드밸런서가 먼저 받아 프록시로 동작하지 않습니다. 프록시 포트를 바꾸세요(보통 3128).</p>}
          {serviceClash && <p class="note">포트 {px.port} 로 온 연결은 프록시가 받아, 같은 포트의 다른 서비스는 쓸 수 없습니다.</p>}
          <h3 class="sub">차단 목록</h3>
          {px.deny.length === 0 && <p class="note">비어 있으면 모든 사이트를 대신 받아 옵니다.</p>}
          {px.deny.map((v, i) => (
            <div key={i} class="lb-row proxy-row">
              <input class="input mono" value={v} placeholder="example.com 또는 93.184.216.34" onInput={(e) => set({ deny: px.deny.map((x, k) => (k === i ? e.currentTarget.value : x)) })} />
              <button class="icon-btn" title="차단 항목 삭제" onClick={() => set({ deny: px.deny.filter((_, k) => k !== i) })}>
                <Icon name="trash" size={15} />
              </button>
            </div>
          ))}
          <button class="btn wide" onClick={() => set({ deny: [...px.deny, ""] })}>
            <Icon name="plus" size={14} />
            차단 추가
          </button>
          <p class="note">
            PC 가 <b>대상 주소를 적어</b> 부탁하면(요청 줄이 <span class="mono">GET http://대상/</span>) 이 장치가 대상에 직접 연결해 받은 응답을 돌려줍니다. 이름도 이 장치가 찾습니다. 대상 서버에게는 요청이 이 장치 주소에서 온 것으로 보입니다. 차단 목록의 이름(하위 이름 포함)이나 주소는 403, 이름을 못 찾거나 연결하지 못하면 503 입니다. 방화벽에서 이 장치만 인터넷으로 내보내면 사내 PC 는 프록시로만 나갑니다.
          </p>
        </>
      )}
    </>
  );
}

/** HTTP 프록시 설정 (http_proxy): 웹 요청을 프록시에게 부탁 */
export function HttpProxySection({ d, h }: { d: Device; h: HostSettings }) {
  const hp = h.httpProxy ?? { enabled: false, server: "", port: 3128 };
  const set = (patch: Partial<typeof hp>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, httpProxy: { ...(x.host!.httpProxy ?? { enabled: false, server: "", port: 3128 }), ...patch } } }));
  return (
    <Section title="HTTP 프록시">
      <label class="toggle-row">
        <span>
          {hp.enabled ? "켜짐" : "꺼짐"} <span class="mono muted">http_proxy · https_proxy</span>
        </span>
        <Toggle on={hp.enabled} onToggle={() => set({ enabled: !hp.enabled })} />
      </label>
      {!hp.enabled && <p class="note">켜면 웹(포트 80·443) 요청을 대상에 직접 보내지 않고 프록시 서버에게 부탁합니다. 사내에서 인터넷을 프록시로만 내보낼 때 PC 에 넣는 설정입니다(브라우저 프록시 설정·http_proxy·https_proxy 환경 변수).</p>}
      {hp.enabled && (
        <>
          <Field label="프록시 서버" error={ipError(hp.server, true)}>
            <input class="input mono" value={hp.server} placeholder="192.168.0.10" onInput={(e) => set({ server: e.currentTarget.value })} />
          </Field>
          <Field label="포트">
            <input class="input mono" type="number" min={1} max={65535} value={hp.port} onInput={(e) => { if (e.currentTarget.value !== "") set({ port: Math.min(65535, Math.max(1, Number(e.currentTarget.value) || 3128)) }); }} />
          </Field>
          <p class="note">HTTP(80)는 프록시가 대신 받아 오고, HTTPS(443)는 CONNECT 로 대상까지 터널만 열어 달라고 한 뒤 TLS 는 대상과 직접 합니다(프록시는 이름만 알고 내용은 모름). 웹 요청은 대상이 같은 사무실 서버여도 프록시를 거치고, 이름은 프록시가 찾습니다. SSH 등 웹이 아닌 연결과 ping 은 직접 나갑니다.</p>
        </>
      )}
    </Section>
  );
}

/** 로드밸런서 전용 장비의 설정 (서버의 서비스 섹션과 같은 칸, 섹션 하나로) */
export function LbSection({ d, h }: { d: Device; h: HostSettings }) {
  return (
    <Section title="로드밸런서">
      <LbFields d={d} h={h} />
    </Section>
  );
}

/** 로드밸런서(리버스 프록시) 켜기 + 포트·분배 방식·백엔드 */
function LbFields({ d, h }: { d: Device; h: HostSettings }) {
  const lb = h.lb ?? DEFAULT_LB_SETTINGS;
  const set = (patch: Partial<typeof lb>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, lb: { ...(x.host!.lb ?? DEFAULT_LB_SETTINGS), ...patch } } }));
  const setBackend = (i: number, patch: Partial<{ ip: string; port: number }>) => set({ backends: lb.backends.map((b, k) => (k === i ? { ...b, ...patch } : b)) });
  const shadowsWeb = lb.enabled && (h.services ?? []).includes(lb.port);
  return (
    <>
      <label class="toggle-row">
        <span>
          로드밸런서 <span class="mono muted">TCP {lb.port}</span>
        </span>
        <Toggle on={lb.enabled} onToggle={() => set({ enabled: !lb.enabled })} />
      </label>
      {!lb.enabled && <p class="note">켜면 이 주소로 온 연결을 뒤 서버(백엔드)들에 나눕니다. 서버에 nginx·HAProxy 를 띄운 것과 같고, 로드밸런서 장비도 같은 방식으로 동작합니다.</p>}
      {lb.enabled && (
        <>
          <Field label="받는 포트">
            <input class="input mono" type="number" min={1} max={65535} value={lb.port} onInput={(e) => { if (e.currentTarget.value !== "") set({ port: Math.min(65535, Math.max(1, Number(e.currentTarget.value) || 80)) }); }} />
          </Field>
          <Field label="방식">
            <div class="segmented" role="radiogroup">
              <button class={lb.mode !== "l4" ? "on" : ""} onClick={() => set({ mode: undefined })} title="연결을 받아 대신 요청 (HTTP 를 봄)">
                L7 프록시
              </button>
              <button class={lb.mode === "l4" ? "on" : ""} onClick={() => set({ mode: "l4" })} title="주소·포트만 바꿔 넘김 (연결 하나)">
                L4 주소 변환
              </button>
            </div>
          </Field>
          <Field label="분배 방식">
            <div class="segmented" role="radiogroup">
              <button class={lb.algorithm === "round-robin" ? "on" : ""} onClick={() => set({ algorithm: "round-robin" })}>
                라운드 로빈
              </button>
              <button class={lb.algorithm === "least-conn" ? "on" : ""} onClick={() => set({ algorithm: "least-conn" })}>
                최소 연결
              </button>
            </div>
          </Field>
          <Field label="세션 고정">
            <div class="segmented" role="radiogroup">
              <button class={!lb.sticky ? "on" : ""} onClick={() => set({ sticky: undefined })} title="요청마다 분배 방식대로 고름">
                없음
              </button>
              <button class={lb.sticky === "ip" ? "on" : ""} onClick={() => set({ sticky: "ip" })} title="같은 출발지 IP 는 계속 같은 백엔드로 (소스 IP 어피니티)">
                출발지 IP
              </button>
              <button class={lb.sticky === "cookie" ? "on" : ""} disabled={lb.mode === "l4"} onClick={() => set({ sticky: "cookie" })} title={lb.mode === "l4" ? "L4 는 HTTP 를 보지 않아 쿠키를 넣을 수 없습니다" : "첫 응답에 Set-Cookie 로 백엔드를 적어 두고, 브라우저가 보내는 쿠키로 같은 백엔드를 고름"}>
                쿠키
              </button>
            </div>
          </Field>
          {lb.sticky === "ip" && <p class="note">NAT·프록시 뒤의 여러 사람은 한 주소로 보여 모두 같은 백엔드로 몰립니다. 사람마다 나누려면 쿠키를 쓰세요.</p>}
          {lb.sticky === "cookie" && lb.mode !== "l4" && <p class="note">첫 응답에 <span class="mono">Set-Cookie: SERVERID=백엔드</span> 를 넣고, 브라우저가 다음 요청에 실어 보내는 쿠키로 같은 백엔드를 고릅니다. 주소가 아니라 브라우저마다라 NAT 뒤에서도 사람별로 나뉩니다.</p>}
          {lb.sticky === "cookie" && lb.mode === "l4" && <p class="note error-note">L4 는 HTTP 를 보지 않아 쿠키 세션 고정이 동작하지 않습니다. 출발지 IP 로 바꾸거나 L7 프록시로 바꾸세요.</p>}
          <label class="toggle-row">
            <span>
              액티브 헬스 체크 <span class="mono muted">2초 · 실패 3 · 복귀 2</span>
              <small class="muted">요청이 오기 전에 죽은 백엔드를 뺌</small>
            </span>
            <Toggle on={lb.healthCheck === true} onToggle={() => set({ healthCheck: !lb.healthCheck })} />
          </label>
          {lb.healthCheck === true && <p class="note">2초마다 백엔드에 TCP 로 연결해 보고, 3번 연속 실패면 DOWN(요청을 보내지 않음), 2번 연속 응답하면 UP 입니다(HAProxy check 기본값). 끄면 패시브만 — 누군가의 요청이 실패해야 알고 그 요청을 다음 백엔드로 다시 보냅니다. 체크는 시간이 흐를 때만 돕니다(요청이 오가거나 위의 "+10초").</p>}
          {shadowsWeb && <p class="note">웹 서버도 포트 {lb.port} 인데, 이 포트로 온 연결은 로드밸런서가 받습니다.</p>}
          <h3 class="sub">백엔드</h3>
          {lb.backends.length === 0 && <p class="note error-note">백엔드가 없으면 모든 요청에 502 Bad Gateway 를 돌려줍니다. 뒤 서버의 주소와 포트를 추가하세요.</p>}
          {lb.backends.map((b, i) => (
            <div key={i} class="lb-row">
              <input class="input mono" value={b.ip} placeholder="192.168.0.11" onInput={(e) => setBackend(i, { ip: e.currentTarget.value })} />
              <span class="mono muted">:</span>
              <input class="input mono" type="number" min={1} max={65535} value={b.port} onInput={(e) => { if (e.currentTarget.value !== "") setBackend(i, { port: Math.min(65535, Math.max(1, Number(e.currentTarget.value) || 80)) }); }} />
              <button class="icon-btn" title="백엔드 삭제" onClick={() => set({ backends: lb.backends.filter((_, k) => k !== i) })}>
                <Icon name="trash" size={15} />
              </button>
              {ipError(b.ip, true) && <div class="error lb-error">{ipError(b.ip, true)}</div>}
            </div>
          ))}
          <button class="btn wide" onClick={() => set({ backends: [...lb.backends, { ip: "", port: 80 }] })}>
            <Icon name="plus" size={14} />
            백엔드 추가
          </button>
          <p class="note">
            {lb.mode === "l4" ? (
              <>
                클라이언트의 패킷을 <b>주소·포트만 바꿔</b> 백엔드로 넘기고, 돌아오는 패킷도 바꿔 돌려줍니다(L4, LVS·NLB 식). TCP 연결은 클라이언트와 백엔드 사이 하나뿐이고 로드밸런서는 내용을 보지 않아 SSH·HTTPS(TLS 를 풀지 않고 그대로) 등 무엇이든 나눕니다. 대신 이미 시작한 연결은 다른 백엔드로 옮기지 못해, 백엔드가 거부(RST)하면 10초 빼 두고 클라이언트가 다시 연결해야 합니다.
              </>
            ) : (
              <>
                클라이언트는 이 장치 주소로 접속하고, 로드밸런서가 백엔드 하나를 골라 <b>자기가 대신</b> 연결해 요청한 뒤 응답을 돌려줍니다(리버스 프록시, L7). 그래서 백엔드에게는 클라이언트가 로드밸런서로 보입니다. 백엔드가 거부하거나 응답이 없으면 10초 동안 빼고 곧바로 다음 백엔드로 다시 보냅니다(패시브 헬스 체크).
                {lb.port === 443 && " 포트 443 이면 로드밸런서가 TLS 를 풀어(TLS 종료) 요청을 보고, 백엔드에는 백엔드 포트대로 다시 연결합니다 — 80 이면 평문, 443 이면 다시 암호화."}
              </>
            )}
          </p>
        </>
      )}
    </>
  );
}

export function DnsServiceSection({ d, h, staticIp }: { d: Device; h: HostSettings; staticIp: string | undefined }) {
  const ns = h.dnsServer ?? DEFAULT_DNS_SERVER;
  const setNs = (patch: Partial<typeof ns>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, dnsServer: { ...(x.host!.dnsServer ?? DEFAULT_DNS_SERVER), ...patch } } }));
  const setRecord = (i: number, patch: Partial<{ name: string; ip: string }>) => setNs({ records: ns.records.map((r, k) => (k === i ? { ...r, ...patch } : r)) });
  return (
    <>
      <label class="toggle-row">
        <span>
          DNS 서버 <span class="mono muted">UDP 53</span>
        </span>
        <Toggle on={ns.enabled} onToggle={() => setNs({ enabled: !ns.enabled })} />
      </label>
      {ns.enabled && (
        <>
          {!staticIp && <p class="note error-note">DNS 서버도 자기 주소가 고정돼 있어야 클라이언트가 찾아옵니다. IP 설정을 수동으로 바꾸세요.</p>}
          <h3 class="sub">레코드 (이름 → 주소)</h3>
          {ns.records.length === 0 && <p class="note">이 서버가 직접 답할 이름들입니다. 예: web.home → 192.168.0.20. IPv6 주소를 넣으면 AAAA 레코드가 됩니다(같은 이름에 A·AAAA 를 둘 다 두면 듀얼 스택).</p>}
          {ns.records.map((r, i) => (
            <div key={i} class="record-row">
              <input class="input mono" value={r.name} placeholder="web.home" onInput={(e) => setRecord(i, { name: e.currentTarget.value })} />
              <span class="muted">→</span>
              <input class="input mono" value={r.ip} placeholder="192.168.0.20 또는 2001:db8::20" title="IPv4 면 A 레코드, IPv6 면 AAAA 레코드" onInput={(e) => setRecord(i, { ip: e.currentTarget.value })} />
              <button class="icon-btn" title="레코드 삭제" onClick={() => setNs({ records: ns.records.filter((_, k) => k !== i) })}>
                <Icon name="trash" size={15} />
              </button>
              {(r.name.trim() === "" || anyIpError(r.ip, true)) && <div class="error record-error">{r.name.trim() === "" ? "이름이 필요합니다" : anyIpError(r.ip, true)}</div>}
            </div>
          ))}
          <button class="btn wide" onClick={() => setNs({ records: [...ns.records, { name: "", ip: "" }] })}>
            <Icon name="plus" size={14} />
            레코드 추가
          </button>
          <Field label="업스트림 DNS" error={anyIpError(ns.upstream, false)}>
            <input class="input mono" value={ns.upstream} placeholder="예: 8.8.8.8 (비우면 NXDOMAIN)" onInput={(e) => setNs({ upstream: e.currentTarget.value })} />
          </Field>
          <p class="note">레코드에 없는 이름은 업스트림 DNS 에 대신 물어보고(재귀 질의) 답을 캐시합니다. 인터넷의 8.8.8.8 이나 1.1.1.1 은 google.com, example.com 같은 공개 이름을 압니다.</p>
        </>
      )}
    </>
  );
}

/** 원격 접속 VPN 클라이언트: 켜기 + 종류(회사 IKEv2 / 공유기 L2TP/IPsec) + 서버 공인 주소 + PSK + 계정 + 연결 상태 */
export function RemoteVpnSection({ d, h }: { d: Device; h: HostSettings }) {
  void simVersion.value;
  const ra = h.ra ?? { enabled: false, server: "", psk: "" };
  const set = (patch: Partial<typeof ra>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, ra: { ...(x.host!.ra ?? { enabled: false, server: "", psk: "" }), ...patch } } }));
  const node = sim.node(d.id);
  const status = node instanceof Host ? node.ra.summary() : undefined;
  const l2tp = ra.type === "l2tp";
  return (
    <Section title="원격 접속 VPN">
      <label class="toggle-row">
        <span>
          {ra.enabled ? "켜짐" : "꺼짐"} <span class="mono muted">{l2tp ? "공유기 VPN" : "회사 VPN"}</span>
        </span>
        <Toggle on={ra.enabled} onToggle={() => set({ enabled: !ra.enabled })} />
      </label>
      <Field label="종류">
        <div class="segmented" role="radiogroup">
          <button class={!l2tp ? "on" : ""} onClick={() => set({ type: undefined })} title="회사 VPN 장비에 IKEv2 로 — 사내 대역만 터널로 (split tunnel)">
            IKEv2
          </button>
          <button class={l2tp ? "on" : ""} onClick={() => set({ type: "l2tp", dpd: undefined })} title="집 공유기(ipTIME 등)의 VPN 서버에 L2TP/IPsec 으로 — 모든 트래픽을 집으로 (full tunnel)">
            L2TP/IPsec
          </button>
        </div>
      </Field>
      {!ra.enabled && (
        <p class="note">
          {l2tp
            ? "켜면 집 공유기의 VPN 서버에 붙어 집 LAN 주소를 하나 받고, 모든 트래픽을 집으로 보냅니다(full tunnel). Windows 의 \"L2TP/IPsec 및 미리 공유한 키\" 와 같습니다."
            : "켜면 회사 VPN 장비에 IPsec 으로 붙어 가상 주소를 받고, 회사가 알려 준 사내 대역으로 가는 패킷만 터널로 보냅니다(나머지는 평소처럼). 재택근무 노트북이 회사 내부 서버에 접속하는 방식입니다."}
        </p>
      )}
      {ra.enabled && (
        <>
          <Field label="VPN 서버 (공인 주소)" error={ipError(ra.server, true)}>
            <input class="input mono" value={ra.server} placeholder={l2tp ? "203.0.113.20" : "203.0.113.11"} onInput={(e) => set({ server: e.currentTarget.value })} />
          </Field>
          <Field label="사전 공유 키 (PSK)" error={ra.psk ? undefined : "비어 있습니다. 서버와 같은 키를 넣으세요."}>
            <input class="input mono" value={ra.psk} placeholder="서버와 같은 문자열" onInput={(e) => set({ psk: e.currentTarget.value })} />
          </Field>
          <Field label={l2tp ? "사용자 이름" : "사용자 이름 (EAP)"} error={l2tp && !ra.user?.trim() ? "L2TP/IPsec 은 계정이 꼭 필요합니다. 공유기 VPN 서버에 등록한 이름을 넣으세요." : undefined}>
            <input class="input mono" value={ra.user ?? ""} placeholder={l2tp ? "공유기 VPN 서버의 계정 (예: me)" : "서버가 계정을 요구할 때 (예: kim)"} onInput={(e) => set({ user: e.currentTarget.value })} />
          </Field>
          <Field label="비밀번호">
            <input class="input mono" value={ra.password ?? ""} placeholder="서버 계정과 같은 문자열" onInput={(e) => set({ password: e.currentTarget.value })} />
          </Field>
          {status && <p class={`note${status.startsWith("실패") || status.startsWith("끊김") ? " error-note" : ""}`}>{status}</p>}
          {node instanceof Host && (node.ra.state === "failed" || node.ra.state === "up") && (
            <button class="btn wide" onClick={() => sim.act({ kind: "ra-reconnect", nodeId: d.id })}>
              <Icon name="refresh" size={14} />
              다시 연결
            </button>
          )}
          {!l2tp && node instanceof Host && (
            <button class="btn wide" disabled={node.ra.state !== "up" || node.ra.dpdWaiting} onClick={() => sim.act({ kind: "vpn-dpd", nodeId: d.id })} title="빈 INFORMATIONAL 을 보내 서버가 살아 있고 이 터널을 아는지 확인합니다">
              <Icon name="send" size={14} />
              상대 확인 (DPD)
            </button>
          )}
          {!l2tp && (
            <label class="toggle-row">
              <span>
                주기 DPD <span class="mono muted">10초 · 조용할 때</span>
                <small class="muted">서버가 말없이 사라지면 끊김으로 알림</small>
              </span>
              <Toggle on={ra.dpd === true} onToggle={() => set({ dpd: !ra.dpd })} />
            </label>
          )}
          <p class="note">
            {l2tp
              ? "IPsec(사전 공유 키)으로 통로를 맺고(공유기 NAT 뒤면 UDP 4500), 그 안에서 L2TP·PPP 로 계정을 확인받아 집 LAN 주소를 받습니다. 연결되면 집 공유기가 알려 준 DNS 로 묻고, 인터넷도 집을 거쳐 나갑니다. 출장지 LAN 과 집 LAN 대역이 같으면 집 장치가 \"같은 서브넷\" 으로 보여 터널로 가지 않습니다."
              : "계정이 없는 서버면 사용자 이름은 비워 두세요. \"상대 확인 (DPD)\" 은 연결된 동안 누를 수 있고, 서버가 응답하지 않으면 1초씩 두 번 다시 보낸 뒤 터널을 지우고 끊김으로 바뀝니다. 주기 DPD 를 켜면 서버에게서 10초 동안 받은 것이 없을 때 저절로 보냅니다(시간이 흐를 때만)."}
          </p>
        </>
      )}
    </Section>
  );
}
