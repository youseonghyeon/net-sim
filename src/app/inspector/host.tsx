// 호스트 설정: IP 설정, 서비스(웹·DHCP 서버·DNS 서버·로드밸런서), 무선 단말·AP.
import { prefixToMask, intToIp, sameSubnet } from "../../core/addr";
import { topology, updateDevice } from "../../model/store";
import {
  DEFAULT_DHCP_SERVER,
  DEFAULT_DNS_SERVER,
  DEFAULT_LB_SETTINGS,
  DEFAULT_ROUTER_WIFI,
  DEFAULT_WIFI_BASE,
  type Device,
  type HostSettings,
  WIFI_RANGE,
  wirelessLinks,
  wirelessStatus,
} from "../../model/topology";
import { Icon } from "../Icons";
import { Field, Section, Toggle, ipError, validIp } from "./ui";

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
          <Field label="IP 주소" error={ipError(h.ip, true)}>
            <input class="input mono" value={h.ip} placeholder="192.168.0.10" onInput={(e) => set({ ip: e.currentTarget.value })} />
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

/** 무선 단말: 어느 SSID 에 붙을지 + 현재 상태 */
export function WifiClientSection({ d }: { d: Device }) {
  const t = topology.value;
  const st = wirelessStatus(t, d);
  const baseName = st.linked ? (t.devices.find((x) => x.id === st.linked!.base)?.name ?? st.linked.base) : undefined;
  return (
    <Section title="무선">
      <Field label="SSID">
        <input class="input mono" value={d.wifi?.ssid ?? ""} placeholder="연결할 네트워크 이름" onInput={(e) => updateDevice(d.id, (x) => ({ ...x, wifi: { ssid: e.currentTarget.value } }))} />
      </Field>
      {st.linked ? (
        <p class="note ok-note">
          {baseName} 에 연결됨 · 거리 {st.linked.distance}px (범위 {WIFI_RANGE}px). 단말을 끌어서 멀어지면 끊깁니다.
        </p>
      ) : (
        <p class="note error-note">{st.reason}</p>
      )}
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
            클라이언트는 이 장치 주소로 접속하고, 로드밸런서가 백엔드 하나를 골라 <b>자기가 대신</b> 연결해 요청한 뒤 응답을 돌려줍니다(리버스 프록시, L7). 그래서 백엔드에게는 클라이언트가 로드밸런서로 보입니다. 백엔드가 거부하거나 응답이 없으면 10초 동안 빼고 곧바로 다음 백엔드로 다시 보냅니다(패시브 헬스 체크).
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
          {ns.records.length === 0 && <p class="note">이 서버가 직접 답할 이름들입니다. 예: web.home → 192.168.0.20</p>}
          {ns.records.map((r, i) => (
            <div key={i} class="record-row">
              <input class="input mono" value={r.name} placeholder="web.home" onInput={(e) => setRecord(i, { name: e.currentTarget.value })} />
              <span class="muted">→</span>
              <input class="input mono" value={r.ip} placeholder="192.168.0.20" onInput={(e) => setRecord(i, { ip: e.currentTarget.value })} />
              <button class="icon-btn" title="레코드 삭제" onClick={() => setNs({ records: ns.records.filter((_, k) => k !== i) })}>
                <Icon name="trash" size={15} />
              </button>
              {(r.name.trim() === "" || ipError(r.ip, true)) && <div class="error record-error">{r.name.trim() === "" ? "이름이 필요합니다" : ipError(r.ip, true)}</div>}
            </div>
          ))}
          <button class="btn wide" onClick={() => setNs({ records: [...ns.records, { name: "", ip: "" }] })}>
            <Icon name="plus" size={14} />
            레코드 추가
          </button>
          <Field label="업스트림 DNS" error={ipError(ns.upstream, false)}>
            <input class="input mono" value={ns.upstream} placeholder="예: 8.8.8.8 (비우면 NXDOMAIN)" onInput={(e) => setNs({ upstream: e.currentTarget.value })} />
          </Field>
          <p class="note">레코드에 없는 이름은 업스트림 DNS 에 대신 물어보고(재귀 질의) 답을 캐시합니다. 인터넷의 8.8.8.8 이나 1.1.1.1 은 google.com, example.com 같은 공개 이름을 압니다.</p>
        </>
      )}
    </>
  );
}
