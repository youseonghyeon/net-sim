// 공유기 설정: LAN·DHCP 서비스, DNS 포워더, WAN.
import { ipToInt, prefixToMask, intToIp, sameSubnet } from "../../core/addr";
import { updateDevice } from "../../model/store";
import {
  DEFAULT_FIREWALL_SETTINGS,
  DEFAULT_ROUTER_DNS,
  DEFAULT_ROUTER_IPV6,
  DEFAULT_WAN,
  type Device,
  type RouterIpv6Settings,
  type RouterSettings,
  type WanSettings,
} from "../../model/topology";
import { Router } from "../../core/nodes/router";
import { DHCP6_STATE_LABEL } from "../../core/nodes/dhcp6";
import { sim, simVersion } from "../../model/sim";
import { WifiBaseSection } from "./host";
import { FirewallSection, ForwardSection } from "./rules";
import { Field, Section, Toggle, ipError, validIp } from "./ui";

/** LAN 주소/서브넷이 바뀔 때, 기존 범위가 옛 서브넷 안에 있었다면 호스트 부분을 유지한 채 새 서브넷으로 옮긴다 */
export function remapRange(oldIp: string, oldPrefix: number, newIp: string, newPrefix: number, range: { start: string; end: string }): { start: string; end: string } | null {
  if (!validIp(oldIp) || !validIp(newIp) || !validIp(range.start) || !validIp(range.end)) return null;
  if (!sameSubnet(range.start, oldIp, oldPrefix) || !sameSubnet(range.end, oldIp, oldPrefix)) return null;
  const hostMask = ~prefixToMask(newPrefix) >>> 0;
  const net = (ipToInt(newIp) & prefixToMask(newPrefix)) >>> 0;
  const move = (ip: string) => intToIp((net | (ipToInt(ip) & hostMask)) >>> 0);
  return { start: move(range.start), end: move(range.end) };
}

export function rangeError(r: RouterSettings, which: "start" | "end"): string | undefined {
  const v = r.dhcp[which];
  const base = ipError(v, true);
  if (base) return base;
  if (validIp(r.lanIp) && !sameSubnet(v, r.lanIp, r.lanPrefix)) return `LAN 서브넷 ${intToIp((ipToInt(r.lanIp) & prefixToMask(r.lanPrefix)) >>> 0)}/${r.lanPrefix} 밖입니다`;
  if (which === "end" && validIp(r.dhcp.start) && ipToInt(r.dhcp.start) > ipToInt(v)) return "시작 주소보다 앞입니다";
  return undefined;
}

export function RouterSection({ d, r }: { d: Device; r: RouterSettings }) {
  const set = (patch: Partial<RouterSettings>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, ...patch } }));
  const setDhcp = (patch: Partial<RouterSettings["dhcp"]>) => set({ dhcp: { ...r.dhcp, ...patch } });
  const setLan = (lanIp: string, lanPrefix: number) => {
    const moved = remapRange(r.lanIp, r.lanPrefix, lanIp, lanPrefix, r.dhcp);
    set({ lanIp, lanPrefix, dhcp: moved ? { ...r.dhcp, ...moved } : r.dhcp });
  };
  return (
    <>
      <Section title="LAN 인터페이스">
        <Field label="IP 주소" error={ipError(r.lanIp, true)}>
          <input class="input mono" value={r.lanIp} onInput={(e) => setLan(e.currentTarget.value, r.lanPrefix)} />
        </Field>
        <Field label="서브넷">
          <div class="prefix">
            <span class="mono">/</span>
            <input
              class="input mono"
              type="number"
              min={0}
              max={32}
              value={r.lanPrefix}
              onInput={(e) => { if (e.currentTarget.value === "") return; setLan(r.lanIp, Math.min(32, Math.max(0, Number(e.currentTarget.value) || 0))); }}
            />
            <span class="mono muted">{intToIp(prefixToMask(r.lanPrefix))}</span>
          </div>
        </Field>
        <p class="note">주소를 바꾸면 DHCP 범위도 같은 서브넷으로 따라갑니다. 이미 주소를 받은 호스트는 "DHCP 임대 갱신" 을 해야 새 주소를 받습니다.</p>
      </Section>
      <Section title="DHCP 서비스">
        <label class="toggle-row">
          <span>{r.dhcp.enabled ? "켜짐" : "꺼짐"}</span>
          <span class={`toggle${r.dhcp.enabled ? " on" : ""}`} role="switch" aria-checked={r.dhcp.enabled} tabIndex={0}
            onClick={() => setDhcp({ enabled: !r.dhcp.enabled })}
            onKeyDown={(e) => { if (e.key === " " || e.key === "Enter") { e.preventDefault(); setDhcp({ enabled: !r.dhcp.enabled }); } }}
          />
        </label>
        {r.dhcp.enabled ? (
          <>
            <Field label="시작 주소" error={rangeError(r, "start")}>
              <input class="input mono" value={r.dhcp.start} onInput={(e) => setDhcp({ start: e.currentTarget.value })} />
            </Field>
            <Field label="끝 주소" error={rangeError(r, "end")}>
              <input class="input mono" value={r.dhcp.end} onInput={(e) => setDhcp({ end: e.currentTarget.value })} />
            </Field>
            <Field label="DNS 서버" hint="옵션 6" error={ipError(r.dhcp.dns ?? "", false)}>
              <input class="input mono" value={r.dhcp.dns ?? ""} placeholder="비우면 공유기 자신 (DNS 포워더)" onInput={(e) => setDhcp({ dns: e.currentTarget.value })} />
            </Field>
            <p class="note">자동(DHCP) 로 설정된 호스트가 연결되면 이 범위에서 주소를 빌려줍니다. 기본 게이트웨이 옵션은 LAN 주소로 나갑니다. 이미 실패한 호스트는 그 호스트의 진단에서 "DHCP 임대 갱신" 을 누르세요.</p>
          </>
        ) : (
          <p class="note">꺼져 있으면 호스트는 주소를 받지 못합니다. 각 호스트에서 IP 를 수동으로 설정해야 통신할 수 있습니다.</p>
        )}
      </Section>
      <WanSection d={d} w={r.wan ?? DEFAULT_WAN} />
      <WifiBaseSection d={d} />
      <RouterDnsSection d={d} r={r} />
      <RouterIpv6Section d={d} r={r} />
      <ForwardSection rules={r.forwards ?? []} onChange={(forwards) => set({ forwards })} lanHint="예: 공인 :80 → 192.168.0.20:80 (LAN 의 웹 서버)." />
      <FirewallSection value={r.firewall ?? DEFAULT_FIREWALL_SETTINGS} onChange={(firewall) => set({ firewall })} uplinkName="WAN" />
    </>
  );
}

/** 공유기 IPv6: 켜면 WAN 이 ISP 의 RA 로 주소를, DHCPv6-PD 로 프리픽스를 받아 LAN 에 RA 로 알린다. NAT 없이 라우팅하고 인바운드 기본 차단으로 지킨다 */
export function RouterIpv6Section({ d, r }: { d: Device; r: RouterSettings }) {
  void simVersion.value;
  const v6 = r.ipv6 ?? { ...DEFAULT_ROUTER_IPV6, enabled: false };
  const set = (patch: Partial<RouterIpv6Settings>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, ipv6: { ...(x.router!.ipv6 ?? DEFAULT_ROUTER_IPV6), ...patch } } }));
  const node = sim.node(d.id);
  const rt = node instanceof Router ? node : undefined;
  return (
    <Section title="IPv6">
      <label class="toggle-row">
        <span>{v6.enabled ? "켜짐" : "꺼짐"}</span>
        <Toggle on={v6.enabled} onToggle={() => set({ enabled: !v6.enabled })} />
      </label>
      {!v6.enabled ? (
        <p class="note">켜면 WAN 이 ISP 에게 IPv6 프리픽스를 위임받아(DHCPv6-PD) LAN 에 /64 를 RA 로 알립니다. 집 안 장치는 SLAAC 로 공인 IPv6 주소를 만들고, 공유기는 NAT 없이 주소 그대로 넘깁니다.</p>
      ) : (
        <>
          {rt && (
            <div class="stat-rows">
              <div class="stat-row">
                <span>프리픽스 위임</span>
                <b class="mono">{rt.pd.delegated ? `${rt.pd.delegated.prefix}/${rt.pd.delegated.length}` : DHCP6_STATE_LABEL[rt.pd.state]}</b>
              </div>
              <div class="stat-row">
                <span>LAN 프리픽스</span>
                <b class="mono">{rt.lan6.addrs.find((a) => a.origin === "manual") ? `${rt.lan6.summary()} · RA` : "위임 대기"}</b>
              </div>
            </div>
          )}
          <label class="toggle-row">
            <span>IPv6 인바운드 기본 차단 <span class="muted">Stateful</span></span>
            <Toggle on={v6.inboundBlock} onToggle={() => set({ inboundBlock: !v6.inboundBlock })} />
          </label>
          <p class="note">
            {v6.inboundBlock
              ? "바깥에서 먼저 시작한 IPv6 연결은 막고, 안에서 시작한 통신의 응답만 들입니다. IPv4 는 NAT 가 바깥에서의 접속을 가로막지만 IPv6 는 주소가 공인이라 이 방화벽이 그 역할을 합니다."
              : "꺼져 있으면 NAT 가 없으니 바깥에서 집 안 장치의 IPv6 주소로 바로 들어옵니다 (포트 포워딩 없이). 위의 방화벽 규칙은 IPv6 에도 걸립니다."}
          </p>
        </>
      )}
    </Section>
  );
}

export function RouterDnsSection({ d, r }: { d: Device; r: RouterSettings }) {
  const dns = r.dns ?? DEFAULT_ROUTER_DNS;
  const set = (patch: Partial<typeof dns>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, dns: { ...(x.router!.dns ?? DEFAULT_ROUTER_DNS), ...patch } } }));
  return (
    <Section title="DNS 포워더">
      <label class="toggle-row">
        <span>{dns.enabled ? "켜짐" : "꺼짐"}</span>
        <Toggle on={dns.enabled} onToggle={() => set({ enabled: !dns.enabled })} />
      </label>
      {dns.enabled ? (
        <>
          <Field label="업스트림 DNS" error={ipError(dns.upstream, true)}>
            <input class="input mono" value={dns.upstream} placeholder="8.8.8.8" onInput={(e) => set({ upstream: e.currentTarget.value })} />
          </Field>
          <p class="note">DHCP 로 주소를 받는 호스트에게 이 라우터를 DNS 로 안내하고, 호스트의 질의를 업스트림 DNS 에 대신 물어본 뒤 답을 캐시합니다 (공유기 안의 dnsmasq).</p>
        </>
      ) : (
        <p class="note">꺼져 있으면 호스트가 이름을 못 씁니다. 호스트에 8.8.8.8 같은 DNS 를 직접 주거나 다시 켜세요.</p>
      )}
    </Section>
  );
}

export function WanSection({ d, w }: { d: Device; w: WanSettings }) {
  const set = (patch: Partial<WanSettings>) => updateDevice(d.id, (x) => ({ ...x, router: { ...x.router!, wan: { ...(x.router!.wan ?? DEFAULT_WAN), ...patch } } }));
  const isStatic = w.ipMode === "static";
  return (
    <Section title="WAN 인터페이스">
      <div class="segmented" role="radiogroup">
        <button class={!isStatic ? "on" : ""} onClick={() => set({ ipMode: "dhcp" })}>
          자동 (DHCP)
        </button>
        <button class={isStatic ? "on" : ""} onClick={() => set({ ipMode: "static" })}>
          수동
        </button>
      </div>
      {isStatic ? (
        <>
          <Field label="공인 IP" error={ipError(w.ip, true)}>
            <input class="input mono" value={w.ip} placeholder="203.0.113.50" onInput={(e) => set({ ip: e.currentTarget.value })} />
          </Field>
          <Field label="서브넷">
            <div class="prefix">
              <span class="mono">/</span>
              <input
                class="input mono"
                type="number"
                min={0}
                max={32}
                value={w.prefix}
                onInput={(e) => { if (e.currentTarget.value === "") return; set({ prefix: Math.min(32, Math.max(0, Number(e.currentTarget.value) || 0)) }); }}
              />
              <span class="mono muted">{intToIp(prefixToMask(w.prefix))}</span>
            </div>
          </Field>
          <Field label="게이트웨이" error={ipError(w.gateway, true)}>
            <input class="input mono" value={w.gateway} placeholder="203.0.113.1" onInput={(e) => set({ gateway: e.currentTarget.value })} />
          </Field>
        </>
      ) : (
        <p class="note">wan 포트에 인터넷을 연결하면 ISP 에서 공인 주소와 게이트웨이를 받습니다. LAN 의 사설 주소는 이 공인 주소로 NAT 됩니다.</p>
      )}
    </Section>
  );
}
