// 공유기 관리 (GL.iNet 시스템 메뉴): 관리 접근 제어, 기기 차단, GoodCloud, 드롭인 게이트웨이.
import { Router } from "../../core/nodes/router";
import { sim, simVersion } from "../../model/sim";
import { topology, updateDevice } from "../../model/store";
import { DEFAULT_ADMIN_SETTINGS, type Device, type RouterAdminSettings, type RouterSettings } from "../../model/topology";
import { Field, Section, Toggle, validIp } from "./ui";

function cidrListError(s: string): string | undefined {
  const bad = s
    .split(/[,\s]+/)
    .filter(Boolean)
    .find((x) => {
      const [ip, p] = x.split("/");
      return !validIp(ip ?? "") || (p !== undefined && !(/^\d{1,2}$/.test(p) && Number(p) <= 32));
    });
  return bad ? `${bad} — 예: 192.168.8.50 또는 192.168.8.0/24` : undefined;
}

export function AdminSection({ d, r }: { d: Device; r: RouterSettings }) {
  void simVersion.value;
  const a = r.admin ?? { ...DEFAULT_ADMIN_SETTINGS, enabled: false };
  const set = (patch: Partial<RouterAdminSettings>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, admin: { ...(x.router!.admin ?? DEFAULT_ADMIN_SETTINGS), ...patch } } }));
  return (
    <Section title="관리 접근">
      <label class="toggle-row">
        <span>
          관리 화면 {a.enabled ? "켜짐" : "꺼짐"} <span class="mono muted">HTTP 80·HTTPS 443{a.ssh ? "·SSH 22" : ""}</span>
        </span>
        <Toggle on={a.enabled} onToggle={() => set({ enabled: !a.enabled })} />
      </label>
      {!a.enabled && <p class="note">켜면 이 공유기의 관리 화면(웹)과 SSH 가 응답합니다. 누가 열 수 있는지(LAN 만·허용 목록·인터넷)를 정해 보세요.</p>}
      {a.enabled && (
        <>
          <label class="toggle-row">
            <span>
              SSH
              <small class="muted">TCP 22</small>
            </span>
            <Toggle on={a.ssh} onToggle={() => set({ ssh: !a.ssh })} />
          </label>
          <Field label="허용 목록" hint="비우면 LAN 전부" error={cidrListError(a.allow)}>
            <input class="input mono" value={a.allow} placeholder="192.168.8.50, 192.168.8.0/28" onChange={(e) => set({ allow: e.currentTarget.value })} />
          </Field>
          <label class="toggle-row">
            <span>
              WAN 에서도 접근 허용
              <small class="muted">인터넷에서 공인 주소로 관리 화면 — 위험</small>
            </span>
            <Toggle on={a.remote} onToggle={() => set({ remote: !a.remote })} />
          </label>
          <p class="note">WAN 접근을 켜면 누구나 로그인 화면에 닿습니다. 밖에서 관리하려면 VPN 으로 집에 붙거나 GoodCloud(공유기가 먼저 연 연결)를 씁니다. 같은 포트를 포트 포워딩하면 포워딩이 먼저입니다.</p>
        </>
      )}
    </Section>
  );
}

/** 기기 차단: LAN 기기(MAC)의 인터넷을 막는다 */
export function BlockSection({ d, r }: { d: Device; r: RouterSettings }) {
  void simVersion.value;
  const blocked = new Set((r.blocked ?? []).map((m) => m.toLowerCase()));
  const node = sim.node(d.id);
  // LAN 기기: 이 공유기의 DHCP 임대 + 이 공유기 LAN 대역에 수동 주소를 둔 기기
  const leaseMacs = new Set(node instanceof Router ? node.dhcpServer.rows().map((row) => row[1]!.toLowerCase()) : []);
  // 드롭인 게이트웨이면 이 공유기의 WAN 주소를 게이트웨이로 적은 기기도
  const dropInGw = r.dropIn && r.wan?.ipMode === "static" ? r.wan.ip : undefined;
  const wlan = (mac: string) => mac.toLowerCase().replace(/^02:00:00:00/, "02:00:00:02");
  const lanDevices = topology.value.devices.filter((x) => x.host && (leaseMacs.has(x.mac.toLowerCase()) || leaseMacs.has(wlan(x.mac)) || (x.host.ipMode === "static" && (x.host.gateway === r.lanIp || (!!dropInGw && x.host.gateway === dropInGw)))));
  const toggle = (mac: string) => {
    const m = mac.toLowerCase();
    updateDevice(d.id, (x) => {
      const cur = new Set((x.router!.blocked ?? []).map((v) => v.toLowerCase()));
      if (cur.has(m)) cur.delete(m);
      else cur.add(m);
      return { ...x, router: { ...x.router!, blocked: [...cur] } };
    });
  };
  return (
    <Section title="기기 차단">
      {lanDevices.length === 0 && <p class="note">이 공유기에서 주소를 받았거나 이 LAN 에 수동 주소를 둔 기기가 없습니다.</p>}
      {lanDevices.map((x) => (
        <label key={x.id} class="toggle-row">
          <span>
            {x.name} <span class="mono muted">{x.mac}</span>
          </span>
          <Toggle on={blocked.has(x.mac.toLowerCase())} onToggle={() => toggle(x.mac)} />
        </label>
      ))}
      <p class="note">켠 기기는 인터넷으로 나가지 못합니다(LAN 안·공유기와는 통신). MAC 으로 막기 때문에 기기가 MAC 을 바꾸면(스마트폰의 "비공개 Wi-Fi 주소") 빠져나갑니다.</p>
    </Section>
  );
}

export function CloudSection({ d, r }: { d: Device; r: RouterSettings }) {
  void simVersion.value;
  const node = sim.node(d.id);
  const status = node instanceof Router ? node.cloud.summary() : undefined;
  return (
    <Section title="GoodCloud">
      <label class="toggle-row">
        <span>{r.cloud ? "켜짐" : "꺼짐"}</span>
        <Toggle on={r.cloud === true} onToggle={() => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, cloud: !x.router!.cloud } }))} />
      </label>
      {status && <p class="note">{status}</p>}
      <p class="note">켜면 공유기가 클라우드에 먼저 연결해 두고 25초마다 그 연결을 유지합니다. 관리자가 클라우드 화면(internet-1 의 "GoodCloud 원격 관리")에서 이 공유기를 열면 요청이 그 연결로 들어와 — 포트 포워딩도, 공인 주소도 필요 없습니다.</p>
    </Section>
  );
}

export function SambaSection({ d, r }: { d: Device; r: RouterSettings }) {
  const s = r.samba ?? { enabled: false, wan: false };
  const set = (patch: Partial<typeof s>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, samba: { ...(x.router!.samba ?? { enabled: false, wan: false }), ...patch } } }));
  return (
    <Section title="네트워크 저장소">
      <label class="toggle-row">
        <span>
          {s.enabled ? "켜짐" : "꺼짐"} <span class="mono muted">SMB · TCP 445</span>
        </span>
        <Toggle on={s.enabled} onToggle={() => set({ enabled: !s.enabled })} />
      </label>
      {s.enabled && (
        <label class="toggle-row">
          <span>
            WAN 에서도 접근 허용
            <small class="muted">인터넷에 SMB — 매우 위험</small>
          </span>
          <Toggle on={s.wan} onToggle={() => set({ wan: !s.wan })} />
        </label>
      )}
      <p class="note">공유기에 꽂은 USB 디스크를 SMB(Windows 파일 공유)로 나눕니다. LAN 기기에서 이 공유기 주소의 TCP 445 로 접속해 보세요. 인터넷에는 열지 않습니다 — 밖에서는 VPN 으로 집에 붙어 씁니다.</p>
    </Section>
  );
}

export function DropInSection({ d, r }: { d: Device; r: RouterSettings }) {
  return (
    <Section title="드롭인 게이트웨이">
      <label class="toggle-row">
        <span>{r.dropIn ? "켜짐" : "꺼짐"}</span>
        <Toggle on={r.dropIn === true} onToggle={() => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, dropIn: !x.router!.dropIn } }))} />
      </label>
      <p class="note">
        기존 공유기는 그대로 두고 이 공유기의 WAN 만 기존 LAN 에 꽂습니다. 그 LAN 의 기기가 게이트웨이를 이 공유기의 WAN 주소({r.wan?.ipMode === "static" ? r.wan.ip : "수동 주소 필요"})로 적으면, 이 공유기가 받아 VPN·DPI·방화벽을 거쳐 기존 공유기로 내보냅니다(같은 WAN 으로 들어오고 나가는 한 팔 라우터, 응답이 돌아오게 NAT). DNS 가로채기·AdGuard 는 LAN 쪽 기기에만 적용됩니다.
      </p>
    </Section>
  );
}
