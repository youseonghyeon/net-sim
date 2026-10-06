// WireGuard 설정 (GL.iNet 식): 공유기 서버·클라이언트, 노트북·폰 앱의 설정 파일 칸, 공개 키 표시·다시 만들기·서버 가져오기.
import { Host } from "../../core/nodes/host";
import { Router, WG_POLICY_LABEL } from "../../core/nodes/router";
import { WgClient, wgPrivateKey, validWgKey } from "../../core/nodes/wg";
import { sim, simVersion } from "../../model/sim";
import { topology, updateDevice, updateDevices } from "../../model/store";
import {
  DEFAULT_ROUTER_WG_CLIENT,
  DEFAULT_WG_CLIENT_FIELDS,
  DEFAULT_WG_SERVER,
  DDNS_ZONE_NAME,
  ddnsHostname,
  wgPublicKeyOf,
  type Device,
  type RouterSettings,
  type RouterWgClientSettings,
  type RouterWgServerSettings,
  type WgClientSettings,
} from "../../model/topology";
import { Icon } from "../Icons";
import { Field, Section, Toggle, ipError, validIp } from "./ui";

type Role = "server" | "client" | "host";

/** "10.0.0.2/32" 칸 검증 */
function cidrError(s: string, required: boolean): string | undefined {
  const v = s.trim();
  if (!v) return required ? "필요한 값입니다" : undefined;
  const [ip, p] = v.split("/");
  if (!validIp(ip!.trim()) || (p !== undefined && !(/^\d{1,2}$/.test(p.trim()) && Number(p) <= 32))) return "예: 10.0.0.2/32";
  return undefined;
}

/** AllowedIPs 칸 검증 (쉼표로 여럿) */
function allowedError(s: string): string | undefined {
  const parts = s.split(/[,\s]+/).filter(Boolean);
  if (parts.length === 0) return "터널로 보낼 목적지가 없습니다. 전부면 0.0.0.0/0";
  const bad = parts.find((x) => cidrError(x, true));
  return bad ? `${bad} — 예: 0.0.0.0/0 또는 10.0.0.0/24, 192.168.8.0/24` : undefined;
}

/** 서버 칸: 주소 또는 이름(DDNS) */
function hostError(s: string): string | undefined {
  const v = s.trim();
  if (!v) return "필요한 값입니다";
  if (validIp(v)) return undefined;
  if (/[a-z]/i.test(v)) return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$/i.test(v) ? undefined : "예: myhome.glddns.com";
  return "예: 203.0.113.30 또는 myhome.glddns.com";
}

function keyError(s: string): string | undefined {
  if (!s.trim()) return "상대의 공개 키를 넣으세요 (base64 44자)";
  return validWgKey(s.trim()) ? undefined : "공개 키 모양이 아닙니다 (base64 44자, = 로 끝남)";
}

/** 내 공개 키 한 줄 + 복사 + 키 다시 만들기 (개인 키는 보여 주지 않는다 — 실제 GL.iNet 화면처럼) */
function MyKey({ d, role, onRegenerate }: { d: Device; role: Role; onRegenerate: (privateKey: string) => void }) {
  const pub = wgPublicKeyOf(d, role);
  return (
    <>
      <Field label="내 공개 키" hint="상대에게 알림">
        <div class="key-row">
          <input class="input mono" value={pub} readOnly onFocus={(e) => e.currentTarget.select()} />
          <button class="icon-btn" title="공개 키 복사" onClick={() => void navigator.clipboard?.writeText(pub).catch(() => {})}>
            <Icon name="copy" size={14} />
          </button>
          <button
            class="icon-btn"
            title="키 다시 만들기 (개인 키를 바꾸면 공개 키도 바뀌어 상대에 등록한 키를 다시 적어야 합니다)"
            onClick={() => onRegenerate(wgPrivateKey(`${d.id}:${role}:${Math.random().toString(36).slice(2)}`))}
          >
            <Icon name="refresh" size={14} />
          </button>
        </div>
      </Field>
    </>
  );
}

/** 클라이언트 설정 파일 칸: 서버 주소·포트·서버 공개 키·내 터널 주소·AllowedIPs·DNS */
function ClientFields({ server, w, setServer, setW }: { server: string; w: WgClientSettings; setServer: (v: string) => void; setW: (p: Partial<WgClientSettings>) => void }) {
  return (
    <>
      <Field label="서버 주소" hint="Endpoint · 주소 또는 이름" error={hostError(server)}>
        <input class="input mono" value={server} placeholder="203.0.113.30 또는 myhome.glddns.com" onInput={(e) => setServer(e.currentTarget.value)} />
      </Field>
      <Field label="서버 포트" hint="UDP">
        <input class="input mono" type="number" min={1} max={65535} value={w.port} onInput={(e) => { if (e.currentTarget.value === "") return; setW({ port: Math.min(65535, Math.max(1, Number(e.currentTarget.value) || 51820)) }); }} />
      </Field>
      <Field label="서버 공개 키" hint="[Peer] PublicKey" error={keyError(w.serverKey)}>
        <input class="input mono" value={w.serverKey} placeholder="서버 화면의 공개 키" onInput={(e) => setW({ serverKey: e.currentTarget.value })} />
      </Field>
      <Field label="내 터널 주소" hint="[Interface] Address" error={cidrError(w.address, true)}>
        <input class="input mono" value={w.address} placeholder="10.0.0.2/32" onInput={(e) => setW({ address: e.currentTarget.value })} />
      </Field>
      <Field label="AllowedIPs" hint="터널로 보낼 목적지" error={allowedError(w.allowedIps)}>
        <input class="input mono" value={w.allowedIps} placeholder="0.0.0.0/0" onInput={(e) => setW({ allowedIps: e.currentTarget.value })} />
      </Field>
      <Field label="DNS" error={ipError(w.dns, false)}>
        <input class="input mono" value={w.dns} placeholder="비우면 그대로 (예: 10.0.0.1)" onInput={(e) => setW({ dns: e.currentTarget.value })} />
      </Field>
      <label class="toggle-row">
        <span>
          난독화
          <small class="muted">VPN 을 막는 DPI 를 지나가게 (서버도 켜야 함)</small>
        </span>
        <Toggle on={w.obfuscate === true} onToggle={() => setW({ obfuscate: !w.obfuscate })} />
      </label>
    </>
  );
}

/** WireGuard 서버를 켠 공유기들 (클라이언트의 "서버 가져오기" 목록) */
function serverRouters(self: Device): Device[] {
  return topology.value.devices.filter((x) => x !== self && x.router?.wgServer?.enabled);
}

/** 서버의 터널 대역에서 아직 피어가 쓰지 않는 다음 주소 */
function nextPeerIp(s: RouterWgServerSettings): string {
  const base = s.address.split("/")[0]!.trim();
  const parts = base.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n))) return "";
  const used = new Set([base, ...s.peers.map((p) => p.ip.trim())]);
  for (let h = 2; h < 255; h++) {
    const ip = `${parts[0]}.${parts[1]}.${parts[2]}.${h}`;
    if (!used.has(ip)) return ip;
  }
  return "";
}

/**
 * "서버 가져오기": GL.iNet 서버 화면에서 프로필을 만들어 클라이언트에 넣는 일을 한 번에 — 서버 피어에 내 공개 키를 등록(이미 있으면 그 주소)하고,
 * 클라이언트에 서버 주소·포트·공개 키·터널 주소를 채운다. 되돌리기 한 단계
 */
function importFrom(self: Device, role: "client" | "host", srv: Device): void {
  const s = srv.router!.wgServer!;
  const myKey = wgPublicKeyOf(self, role);
  const existing = s.peers.find((p) => p.publicKey.trim() === myKey);
  const ip = existing?.ip.trim() || nextPeerIp(s);
  if (!ip) return; // 터널 대역이 가득 찼거나 서버 터널 주소가 올바르지 않음 — 서버 칸의 오류가 알려 준다
  const serverAddr = s.address.split("/")[0]!.trim();
  const fields: Partial<WgClientSettings> = { port: s.port, serverKey: wgPublicKeyOf(srv, "server"), address: `${ip}/32`, dns: validIp(serverAddr) ? serverAddr : "" };
  // 서버 공유기에 DDNS 가 켜져 있으면 이름(주소가 바뀌어도 따라감), 아니면 수동 WAN 주소
  const wan = srv.router!.ddns?.enabled && ddnsHostname(srv.router!.ddns.name) ? ddnsHostname(srv.router!.ddns.name)! : srv.router!.wan?.ipMode === "static" ? srv.router!.wan.ip : "";
  updateDevices([self.id, srv.id], (x) => {
    if (x.id === srv.id && !existing) return { ...x, router: { ...x.router!, wgServer: { ...x.router!.wgServer!, peers: [...x.router!.wgServer!.peers, { name: self.name, publicKey: myKey, ip }] } } };
    if (x.id !== self.id) return x;
    if (role === "client") return { ...x, router: { ...x.router!, wgClient: { ...(x.router!.wgClient ?? DEFAULT_ROUTER_WG_CLIENT), ...fields, ...(wan ? { server: wan } : {}) } } };
    const ra = x.host!.ra ?? { enabled: true, server: "", psk: "", type: "wireguard" as const };
    return { ...x, host: { ...x.host!, ra: { ...ra, type: "wireguard", ...(wan ? { server: wan } : {}), wg: { ...(ra.wg ?? DEFAULT_WG_CLIENT_FIELDS), ...fields } } } };
  });
}

function ImportServer({ d, role }: { d: Device; role: "client" | "host" }) {
  const servers = serverRouters(d);
  if (servers.length === 0) return null;
  return (
    <Field label="서버 가져오기" hint="프로필">
      <select
        class="input"
        value=""
        onChange={(e) => {
          const srv = servers.find((x) => x.id === e.currentTarget.value);
          if (srv) importFrom(d, role, srv);
          e.currentTarget.value = "";
        }}
      >
        <option value="">WireGuard 서버를 고르세요</option>
        {servers.map((x) => (
          <option key={x.id} value={x.id}>
            {x.name}
          </option>
        ))}
      </select>
    </Field>
  );
}

// ---------- 공유기 서버 ----------

export function WgServerSection({ d, r }: { d: Device; r: RouterSettings }) {
  void simVersion.value;
  const s = r.wgServer ?? { ...DEFAULT_WG_SERVER, enabled: false };
  const set = (patch: Partial<RouterWgServerSettings>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, wgServer: { ...(x.router!.wgServer ?? DEFAULT_WG_SERVER), ...patch } } }));
  const setPeer = (i: number, patch: Partial<RouterWgServerSettings["peers"][0]>) => set({ peers: s.peers.map((p, k) => (k === i ? { ...p, ...patch } : p)) });
  const node = sim.node(d.id);
  const connected = node instanceof Router ? node.wgs.connected : 0;
  // 피어로 넣을 수 있는 장치: WireGuard 클라이언트를 켠 공유기·WireGuard 앱을 쓰는 단말 중 아직 없는 것
  const registered = new Set(s.peers.map((p) => p.publicKey.trim()));
  const candidates = topology.value.devices
    .filter((x) => x !== d)
    .flatMap((x): { x: Device; role: "client" | "host" }[] => (x.router?.wgClient?.enabled ? [{ x, role: "client" }] : x.host?.ra?.type === "wireguard" ? [{ x, role: "host" }] : []))
    .filter((c) => !registered.has(wgPublicKeyOf(c.x, c.role)));
  return (
    <Section title="WireGuard 서버">
      <label class="toggle-row">
        <span>
          {s.enabled ? "켜짐" : "꺼짐"} <span class="mono muted">UDP {s.port}</span>
        </span>
        <Toggle on={s.enabled} onToggle={() => set({ enabled: !s.enabled })} />
      </label>
      {!s.enabled && (
        <p class="note">켜면 밖에 있는 노트북·폰·다른 공유기가 WireGuard 로 집에 붙습니다. 등록한 공개 키에만 답하므로(모르는 키에는 아무 답도 하지 않음) 포트를 열어 두어도 스캔에 보이지 않습니다. WAN 주소가 바뀌는 집이면 DDNS 이름으로 접속합니다.</p>
      )}
      {s.enabled && (
        <>
          <MyKey d={d} role="server" onRegenerate={(privateKey) => set({ privateKey })} />
          <Field label="터널 주소" hint="서버" error={cidrError(s.address, true)}>
            <input class="input mono" value={s.address} placeholder="10.0.0.1/24" onInput={(e) => set({ address: e.currentTarget.value })} />
          </Field>
          <Field label="포트" hint="UDP">
            <input class="input mono" type="number" min={1} max={65535} value={s.port} onInput={(e) => { if (e.currentTarget.value === "") return; set({ port: Math.min(65535, Math.max(1, Number(e.currentTarget.value) || 51820)) }); }} />
          </Field>
          <label class="toggle-row">
            <span>
              난독화
              <small class="muted">AmneziaWG 식 — 클라이언트도 켜야 함</small>
            </span>
            <Toggle on={s.obfuscate === true} onToggle={() => set({ obfuscate: !s.obfuscate })} />
          </label>
          <label class="toggle-row">
            <span>
              LAN 접근 허용
              <small class="muted">끄면 클라이언트는 인터넷만 이 공유기로</small>
            </span>
            <Toggle on={s.lanAccess} onToggle={() => set({ lanAccess: !s.lanAccess })} />
          </label>
          <h4 class="sub-head">피어 (등록한 클라이언트) · 연결 {connected}</h4>
          {s.peers.map((p, i) => (
            <div key={i} class="wg-peer">
              <input class="input" value={p.name} placeholder="이름" title="피어 이름" onInput={(e) => setPeer(i, { name: e.currentTarget.value })} />
              <input class="input mono" value={p.ip} placeholder="10.0.0.2" title="이 피어의 터널 주소 (AllowedIPs /32)" onInput={(e) => setPeer(i, { ip: e.currentTarget.value })} />
              <button class="icon-btn" title="피어 삭제" onClick={() => set({ peers: s.peers.filter((_, k) => k !== i) })}>
                <Icon name="trash" size={15} />
              </button>
              <input class="input mono key" value={p.publicKey} placeholder="클라이언트의 공개 키" title="클라이언트의 공개 키" onInput={(e) => setPeer(i, { publicKey: e.currentTarget.value })} />
              {(keyError(p.publicKey) || ipError(p.ip, true)) && <div class="error route-error">{keyError(p.publicKey) ?? ipError(p.ip, true)}</div>}
            </div>
          ))}
          <button class="btn wide" onClick={() => set({ peers: [...s.peers, { name: "", publicKey: "", ip: nextPeerIp(s) }] })}>
            <Icon name="plus" size={14} />
            피어 추가
          </button>
          {candidates.length > 0 && (
            <Field label="장치에서 추가">
              <select
                class="input"
                value=""
                onChange={(e) => {
                  const c = candidates.find((k) => k.x.id === e.currentTarget.value);
                  if (c) set({ peers: [...s.peers, { name: c.x.name, publicKey: wgPublicKeyOf(c.x, c.role), ip: nextPeerIp(s) }] });
                  e.currentTarget.value = "";
                }}
              >
                <option value="">WireGuard 를 쓰는 장치를 고르세요</option>
                {candidates.map((c) => (
                  <option key={c.x.id} value={c.x.id}>
                    {c.x.name}
                  </option>
                ))}
              </select>
            </Field>
          )}
          <p class="note">클라이언트 쪽 "내 터널 주소" 는 여기 적은 주소와 같아야 합니다 — 다르면 핸드셰이크는 되지만 서버가 데이터를 버립니다(피어마다 쓸 수 있는 출발지가 정해져 있음). 피어 상태는 표 탭의 "WireGuard 서버 피어" 에 있습니다.</p>
        </>
      )}
    </Section>
  );
}

// ---------- 공유기 클라이언트 ----------

export function WgClientSection({ d, r }: { d: Device; r: RouterSettings }) {
  void simVersion.value;
  const c = r.wgClient ?? { ...DEFAULT_ROUTER_WG_CLIENT, enabled: false };
  const set = (patch: Partial<RouterWgClientSettings>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, wgClient: { ...(x.router!.wgClient ?? DEFAULT_ROUTER_WG_CLIENT), ...patch } } }));
  const node = sim.node(d.id);
  const status = node instanceof Router ? node.wgClientSummary() : undefined;
  const mode = c.policy.mode;
  return (
    <Section title="WireGuard 클라이언트">
      <label class="toggle-row">
        <span>{c.enabled ? "켜짐" : "꺼짐"}</span>
        <Toggle on={c.enabled} onToggle={() => set({ enabled: !c.enabled })} />
      </label>
      {!c.enabled && (
        <p class="note">켜면 이 공유기에 꽂은 기기들의 트래픽을 VPN 서버로 보냅니다 — 기기마다 VPN 앱을 깔지 않아도 됩니다(여행용 공유기·사무실 게이트웨이). 서버는 이 공유기를 터널 주소 하나로만 보므로 LAN 기기 주소는 그 주소로 바뀝니다(NAT).</p>
      )}
      {c.enabled && (
        <>
          <MyKey d={d} role="client" onRegenerate={(privateKey) => set({ privateKey })} />
          <ImportServer d={d} role="client" />
          <ClientFields server={c.server} w={c} setServer={(server) => set({ server })} setW={(p) => set(p)} />
          <label class="toggle-row">
            <span>
              킬 스위치
              <small class="muted">VPN 이 끊기면 인터넷 차단 (실제 주소가 새지 않게)</small>
            </span>
            <Toggle on={c.killSwitch} onToggle={() => set({ killSwitch: !c.killSwitch })} />
          </label>
          <Field label="VPN 정책">
            <div class="segmented" role="radiogroup">
              {(["all", "exclude", "only"] as const).map((m) => (
                <button key={m} class={mode === m ? "on" : ""} title={WG_POLICY_LABEL[m]} onClick={() => set({ policy: { ...c.policy, mode: m } })}>
                  {m === "all" ? "모든 기기" : m === "exclude" ? "목록 제외" : "목록만"}
                </button>
              ))}
            </div>
          </Field>
          {mode !== "all" && (
            <Field label="기기 목록" hint="LAN 주소, 쉼표로" error={c.policy.devices.find((x) => x.trim() && !validIp(x.trim())) ? "예: 192.168.9.100, 192.168.9.101" : undefined}>
              <input
                class="input mono"
                value={c.policy.devices.join(", ")}
                placeholder="192.168.9.100"
                onInput={(e) => set({ policy: { ...c.policy, devices: e.currentTarget.value.split(/[,\s]+/).filter(Boolean) } })}
              />
            </Field>
          )}
          {status && <p class={`note${status.startsWith("끊김") ? " error-note" : ""}`}>{status}</p>}
          {node instanceof Router && (
            <button class="btn wide" onClick={() => sim.act({ kind: "ra-reconnect", nodeId: d.id })}>
              <Icon name="refresh" size={14} />
              다시 연결
            </button>
          )}
          <p class="note">AllowedIPs 를 0.0.0.0/0 으로 두면 모든 트래픽이 터널로 갑니다(full tunnel). DNS 를 적으면 공유기의 DNS 포워더가 그 주소에 터널로 묻습니다 — 호텔·통신사 DNS 가 내가 찾는 이름을 보지 못합니다(DNS 유출 방지).</p>
        </>
      )}
    </Section>
  );
}

// ---------- 노트북·폰 앱 ----------

/** 원격 접속 VPN 섹션의 WireGuard 칸 (종류가 WireGuard 일 때) */
export function HostWgFields({ d }: { d: Device }) {
  void simVersion.value;
  const ra = d.host!.ra!;
  const w = ra.wg ?? DEFAULT_WG_CLIENT_FIELDS;
  const setRa = (patch: Partial<NonNullable<typeof d.host>["ra"] & object>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, ra: { ...x.host!.ra!, ...patch } } }));
  const setW = (p: Partial<WgClientSettings>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, ra: { ...x.host!.ra!, wg: { ...(x.host!.ra!.wg ?? DEFAULT_WG_CLIENT_FIELDS), ...p } } } }));
  const node = sim.node(d.id);
  const status = node instanceof Host && node.ra instanceof WgClient ? node.ra.summary() : undefined;
  return (
    <>
      <MyKey d={d} role="host" onRegenerate={(privateKey) => setW({ privateKey })} />
      <ImportServer d={d} role="host" />
      <ClientFields server={ra.server} w={w} setServer={(server) => setRa({ server })} setW={setW} />
      {status && <p class={`note${status.startsWith("실패") ? " error-note" : ""}`}>{status}</p>}
      {node instanceof Host && (node.ra.state === "failed" || node.ra.state === "up") && (
        <button class="btn wide" onClick={() => sim.act({ kind: "ra-reconnect", nodeId: d.id })}>
          <Icon name="refresh" size={14} />
          다시 연결
        </button>
      )}
      <p class="note">WireGuard 는 주소를 받아 오지 않습니다 — 서버 관리자가 정해 준 터널 주소를 적어 둡니다. 켜 두면 AllowedIPs 로 가는 패킷은 늘 터널로 가서, 핸드셰이크가 안 돼도 밖으로 새지 않습니다. Wi-Fi 를 바꿔도 세션이 이어집니다(엔드포인트 로밍).</p>
    </>
  );
}

// ---------- DDNS ----------

export function DdnsSection({ d, r }: { d: Device; r: RouterSettings }) {
  void simVersion.value;
  const c = r.ddns ?? { enabled: false, name: "" };
  const set = (patch: Partial<NonNullable<RouterSettings["ddns"]>>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, ddns: { ...(x.router!.ddns ?? { enabled: false, name: "" }), ...patch } } }));
  const node = sim.node(d.id);
  const status = node instanceof Router ? node.ddns.summary() : undefined;
  const full = ddnsHostname(c.name);
  return (
    <Section title="DDNS">
      <label class="toggle-row">
        <span>
          {c.enabled ? "켜짐" : "꺼짐"} <span class="mono muted">{full ?? DDNS_ZONE_NAME}</span>
        </span>
        <Toggle on={c.enabled} onToggle={() => set({ enabled: !c.enabled })} />
      </label>
      {!c.enabled && <p class="note">켜면 WAN 의 공인 주소가 바뀔 때마다 이름(예: myhome.{DDNS_ZONE_NAME})을 그 주소로 갱신합니다. 밖에서 VPN 서버 주소를 이름으로 적어 두면 집 주소가 바뀌어도 따라갑니다.</p>}
      {c.enabled && (
        <>
          <Field label="이름" error={c.name.trim() && !full ? "영문 소문자·숫자·- 만 (예: myhome)" : !c.name.trim() ? "이름을 넣으세요" : undefined}>
            <div class="suffix-row">
              <input class="input mono" value={c.name} placeholder="myhome" onInput={(e) => set({ name: e.currentTarget.value })} />
              <span class="mono muted">.{DDNS_ZONE_NAME}</span>
            </div>
          </Field>
          {status && <p class={`note${status.startsWith("실패") ? " error-note" : ""}`}>{status}</p>}
          <p class="note">DDNS 서버는 갱신 요청의 출발지를 등록합니다 — 이 공유기 앞에 다른 NAT 가 있으면 그 공인 주소가 등록됩니다. 앞쪽 주소가 바뀐 것은 공유기가 모르므로 10분마다도 확인합니다. 이름의 TTL 이 30초라 DNS 캐시가 옛 주소를 오래 들고 있지 않습니다.</p>
        </>
      )}
    </Section>
  );
}
