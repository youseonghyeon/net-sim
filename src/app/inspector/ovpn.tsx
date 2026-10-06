// OpenVPN 설정 (GL.iNet 식): 공유기 서버(전송·포트·터널 대역·PUSH·tls-crypt·계정·인증서 폐기)와 노트북·폰 앱의 설정 파일 칸·설정 파일 가져오기.
import { Host } from "../../core/nodes/host";
import { Router } from "../../core/nodes/router";
import { OvpnClient, shortFp } from "../../core/nodes/openvpn";
import { sim, simVersion } from "../../model/sim";
import { topology, updateDevice, updateDevices } from "../../model/store";
import { DEFAULT_OVPN_SERVER_SETTINGS, ddnsHostname, ovpnCaOfDevice, ovpnTlsCryptOfDevice, type Device, type OvpnClientSettings, type RouterOvpnServerSettings, type RouterSettings } from "../../model/topology";
import { Icon } from "../Icons";
import { Field, Section, Toggle, validIp } from "./ui";

const DEFAULT_CLIENT: OvpnClientSettings = { proto: "udp", port: 1194, ca: "", cn: "", certCa: "", tlsCrypt: "" };

function subnetError(s: string): string | undefined {
  const m = /^\s*([0-9.]+)\s*\/\s*(\d{1,2})\s*$/.exec(s);
  if (!m || !validIp(m[1]!) || Number(m[2]) > 30) return "예: 10.8.0.0/24 (/30 보다 작은 대역)";
  return undefined;
}

function hostError(s: string): string | undefined {
  const v = s.trim();
  if (!v) return "필요한 값입니다";
  if (validIp(v)) return undefined;
  if (/[a-z]/i.test(v)) return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$/i.test(v) ? undefined : "예: myhome.glddns.com";
  return "예: 203.0.113.40 또는 myhome.glddns.com";
}

function PortInput({ value, onChange }: { value: number; onChange: (n: number) => void }) {
  return (
    <input
      class="input mono"
      type="number"
      min={1}
      max={65535}
      value={value}
      onInput={(e) => {
        if (e.currentTarget.value === "") return;
        onChange(Math.min(65535, Math.max(1, Number(e.currentTarget.value) || 1194)));
      }}
    />
  );
}

function ProtoPick({ value, onChange }: { value: "udp" | "tcp"; onChange: (p: "udp" | "tcp") => void }) {
  return (
    <div class="segmented" role="radiogroup">
      <button class={value === "udp" ? "on" : ""} onClick={() => onChange("udp")} title="기본 — 빠르고 TCP 위 TCP 의 재전송 겹침이 없음">
        UDP
      </button>
      <button class={value === "tcp" ? "on" : ""} onClick={() => onChange("tcp")} title="웹(TCP 443)만 열어 둔 방화벽을 지나갈 때">
        TCP
      </button>
    </div>
  );
}

// ---------- 공유기 서버 ----------

export function OvpnServerSection({ d, r }: { d: Device; r: RouterSettings }) {
  void simVersion.value;
  const s = r.ovpnServer ?? { ...DEFAULT_OVPN_SERVER_SETTINGS, enabled: false };
  const set = (patch: Partial<RouterOvpnServerSettings>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, ovpnServer: { ...(x.router!.ovpnServer ?? DEFAULT_OVPN_SERVER_SETTINGS), ...patch } } }));
  const setUser = (i: number, patch: Partial<{ name: string; password: string }>) => set({ users: s.users.map((u, k) => (k === i ? { ...u, ...patch } : u)) });
  const node = sim.node(d.id);
  const connected = node instanceof Router ? node.ovpn.connected : 0;
  const ca = ovpnCaOfDevice(d);
  // 이 서버의 CA 가 발급한 인증서를 가진 기기 (설정 파일을 가져간 기기) — 폐기 목록을 고르는 곳
  const issued = topology.value.devices.filter((x) => x.host?.ra?.type === "openvpn" && x.host.ra.ovpn?.certCa === ca && x.host.ra.ovpn.cn.trim());
  const cns = [...new Set([...issued.map((x) => x.host!.ra!.ovpn!.cn.trim()), ...s.revoked])];
  return (
    <Section title="OpenVPN 서버">
      <label class="toggle-row">
        <span>
          {s.enabled ? "켜짐" : "꺼짐"} <span class="mono muted">{s.proto.toUpperCase()} {s.port}</span>
        </span>
        <Toggle on={s.enabled} onToggle={() => set({ enabled: !s.enabled })} />
      </label>
      {!s.enabled && (
        <p class="note">켜면 이 공유기가 CA 가 되어 서버 인증서와 기기마다의 인증서를 발급합니다. 클라이언트는 설정 파일(.ovpn)을 받아 서로 인증서를 확인하고, 서버가 가상 주소·집 LAN 경로·DNS 를 내려 줍니다(PUSH). WireGuard 보다 무겁지만 TCP 443 으로도 열 수 있어 웹만 열어 둔 방화벽을 지나갑니다.</p>
      )}
      {s.enabled && (
        <>
          <div class="stat-row">
            <span>CA 지문</span>
            <b class="mono" title={ca}>
              {shortFp(ca)}
            </b>
          </div>
          <Field label="전송">
            <ProtoPick value={s.proto} onChange={(proto) => set({ proto })} />
          </Field>
          <Field label="포트" hint={s.proto.toUpperCase()}>
            <PortInput value={s.port} onChange={(port) => set({ port })} />
          </Field>
          <Field label="터널 대역" hint="서버는 첫 주소" error={subnetError(s.subnet)}>
            <input class="input mono" value={s.subnet} placeholder="10.8.0.0/24" onInput={(e) => set({ subnet: e.currentTarget.value })} />
          </Field>
          <label class="toggle-row">
            <span>
              LAN 접근 허용
              <small class="muted">push route — 집 LAN 경로를 내려 줌</small>
            </span>
            <Toggle on={s.lanAccess} onToggle={() => set({ lanAccess: !s.lanAccess })} />
          </label>
          <label class="toggle-row">
            <span>
              모든 트래픽을 VPN 으로
              <small class="muted">push redirect-gateway — 인터넷도 집을 거침</small>
            </span>
            <Toggle on={s.redirectGateway} onToggle={() => set({ redirectGateway: !s.redirectGateway })} />
          </label>
          <label class="toggle-row">
            <span>
              DNS 알려 주기
              <small class="muted">push dhcp-option DNS — 이 공유기 DNS 포워더</small>
            </span>
            <Toggle on={s.pushDns} onToggle={() => set({ pushDns: !s.pushDns })} />
          </label>
          <label class="toggle-row">
            <span>
              tls-crypt
              <small class="muted">키가 없는 패킷에는 답하지 않음 (스캔에 안 보임)</small>
            </span>
            <Toggle on={s.tlsCrypt} onToggle={() => set({ tlsCrypt: !s.tlsCrypt })} />
          </label>
          <h4 class="sub-head">계정 (비우면 인증서만) · 연결 {connected}</h4>
          {s.users.map((u, i) => (
            <div key={i} class="record-row">
              <input class="input mono" value={u.name} placeholder="사용자 이름" onInput={(e) => setUser(i, { name: e.currentTarget.value })} />
              <span class="muted">:</span>
              <input class="input mono" value={u.password} placeholder="비밀번호" onInput={(e) => setUser(i, { password: e.currentTarget.value })} />
              <button class="icon-btn" title="계정 삭제" onClick={() => set({ users: s.users.filter((_, k) => k !== i) })}>
                <Icon name="trash" size={15} />
              </button>
            </div>
          ))}
          <button class="btn wide" onClick={() => set({ users: [...s.users, { name: "", password: "" }] })}>
            <Icon name="plus" size={14} />
            계정 추가
          </button>
          {cns.length > 0 && (
            <>
              <h4 class="sub-head">발급한 인증서 · 폐기 (CRL)</h4>
              {cns.map((cn) => {
                const revoked = s.revoked.includes(cn);
                return (
                  <label key={cn} class="toggle-row">
                    <span>
                      {cn}
                      <small class="muted">{revoked ? "폐기됨 — 이 인증서로는 붙지 못함" : "유효"}</small>
                    </span>
                    <Toggle on={revoked} onToggle={() => set({ revoked: revoked ? s.revoked.filter((x) => x !== cn) : [...s.revoked, cn] })} />
                  </label>
                );
              })}
            </>
          )}
          <p class="note">한 사람을 막으려면 그 인증서만 폐기합니다 — CA 와 다른 사람의 인증서는 그대로입니다. 같은 인증서로 두 기기가 붙으면 나중에 붙은 쪽이 앞 기기를 밀어냅니다. 붙은 클라이언트는 표 탭의 "OpenVPN 클라이언트" 에 있습니다.</p>
        </>
      )}
    </Section>
  );
}

// ---------- 노트북·폰 앱 ----------

/** OpenVPN 서버를 켠 공유기들 */
function serverRouters(self: Device): Device[] {
  return topology.value.devices.filter((x) => x !== self && x.router?.ovpnServer?.enabled);
}

/** 공유기 화면에서 이 기기 이름으로 인증서를 발급해 설정 파일(.ovpn)을 내려받아 앱에 넣는 일을 한 번에. 폐기된 이름이면 폐기를 풀지 않는다 */
function importFrom(self: Device, srv: Device): void {
  const s = srv.router!.ovpnServer!;
  const ca = ovpnCaOfDevice(srv);
  const wan = srv.router!.ddns?.enabled && ddnsHostname(srv.router!.ddns.name) ? ddnsHostname(srv.router!.ddns.name)! : srv.router!.wan?.ipMode === "static" ? srv.router!.wan.ip : "";
  const fields: OvpnClientSettings = { proto: s.proto, port: s.port, ca, cn: self.name, certCa: ca, tlsCrypt: s.tlsCrypt ? ovpnTlsCryptOfDevice(srv) : "" };
  updateDevices([self.id], (x) => {
    const ra = x.host!.ra ?? { enabled: true, server: "", psk: "", type: "openvpn" as const };
    return { ...x, host: { ...x.host!, ra: { ...ra, type: "openvpn", ...(wan ? { server: wan } : {}), ovpn: fields } } };
  });
}

export function HostOvpnFields({ d }: { d: Device }) {
  void simVersion.value;
  const ra = d.host!.ra!;
  const o = ra.ovpn ?? DEFAULT_CLIENT;
  const setRa = (patch: Partial<NonNullable<typeof d.host>["ra"] & object>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, ra: { ...x.host!.ra!, ...patch } } }));
  const setO = (p: Partial<OvpnClientSettings>) => updateDevice(d.id, (x) => ({ ...x, host: { ...x.host!, ra: { ...x.host!.ra!, ovpn: { ...(x.host!.ra!.ovpn ?? DEFAULT_CLIENT), ...p } } } }));
  const node = sim.node(d.id);
  const status = node instanceof Host && node.ra instanceof OvpnClient ? node.ra.summary() : undefined;
  const servers = serverRouters(d);
  return (
    <>
      {servers.length > 0 && (
        <Field label="설정 파일 가져오기" hint=".ovpn">
          <select
            class="input"
            value=""
            onChange={(e) => {
              const srv = servers.find((x) => x.id === e.currentTarget.value);
              if (srv) importFrom(d, srv);
              e.currentTarget.value = "";
            }}
          >
            <option value="">OpenVPN 서버를 고르세요</option>
            {servers.map((x) => (
              <option key={x.id} value={x.id}>
                {x.name}
              </option>
            ))}
          </select>
        </Field>
      )}
      <Field label="서버 주소" hint="remote · 주소 또는 이름" error={hostError(ra.server)}>
        <input class="input mono" value={ra.server} placeholder="203.0.113.40 또는 myhome.glddns.com" onInput={(e) => setRa({ server: e.currentTarget.value })} />
      </Field>
      <Field label="전송">
        <ProtoPick value={o.proto} onChange={(proto) => setO({ proto })} />
      </Field>
      <Field label="포트" hint={o.proto.toUpperCase()}>
        <PortInput value={o.port} onChange={(port) => setO({ port })} />
      </Field>
      <Field label="CA" hint="<ca> 지문" error={o.ca.trim() ? undefined : "서버의 CA 지문이 필요합니다 — 설정 파일을 가져오세요"}>
        <input class="input mono" value={o.ca} placeholder="AB:CD:…" onInput={(e) => setO({ ca: e.currentTarget.value })} />
      </Field>
      <Field label="내 인증서" hint="<cert> CN" error={o.cn.trim() ? undefined : "인증서가 없습니다 — 설정 파일을 가져오세요"}>
        <input class="input mono" value={o.cn} placeholder={d.name} onInput={(e) => setO({ cn: e.currentTarget.value })} />
      </Field>
      {o.certCa && o.certCa !== o.ca && <p class="note error-note">내 인증서를 발급한 CA({shortFp(o.certCa)})가 위 CA 와 다릅니다. 서버가 거절합니다.</p>}
      <Field label="tls-crypt 키" hint="비우면 안 씀">
        <input class="input mono" value={o.tlsCrypt} placeholder="(없음)" onInput={(e) => setO({ tlsCrypt: e.currentTarget.value })} />
      </Field>
      <Field label="사용자 이름" hint="auth-user-pass">
        <input class="input mono" value={ra.user ?? ""} placeholder="서버가 계정을 요구할 때" onInput={(e) => setRa({ user: e.currentTarget.value })} />
      </Field>
      <Field label="비밀번호">
        <input class="input mono" value={ra.password ?? ""} placeholder="서버 계정과 같은 문자열" onInput={(e) => setRa({ password: e.currentTarget.value })} />
      </Field>
      {status && <p class={`note${status.startsWith("실패") ? " error-note" : ""}`}>{status}</p>}
      {node instanceof Host && (node.ra.state === "failed" || node.ra.state === "up") && (
        <button class="btn wide" onClick={() => sim.act({ kind: "ra-reconnect", nodeId: d.id })}>
          <Icon name="refresh" size={14} />
          다시 연결
        </button>
      )}
      <p class="note">서버 인증서가 위 CA 의 서명인지 확인하고, 서버도 내 인증서를 확인합니다. 연결되면 서버가 가상 주소·경로·DNS 를 내려 주고(PUSH), 10초마다 keepalive 를 주고받다가 60초 동안 아무것도 받지 못하면 다시 붙습니다(시간이 흐를 때만).</p>
    </>
  );
}
