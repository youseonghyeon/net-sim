// 메시 VPN (Tailscale·ZeroTier 앱): 노트북·폰·서버와 공유기 공통. 공유기는 서브넷 라우터·exit node, 단말은 exit node 고르기.
import { Host } from "../../core/nodes/host";
import { Router } from "../../core/nodes/router";
import { meshHostname } from "../../core/nodes/tailscale";
import { sim, simVersion } from "../../model/sim";
import { topology, updateDevice } from "../../model/store";
import { DEFAULT_MESH_SETTINGS, type Device, type MeshSettings } from "../../model/topology";
import { Field, Section, Toggle } from "./ui";

export function MeshSection({ d }: { d: Device }) {
  void simVersion.value;
  const m = d.host?.mesh ?? d.router?.mesh ?? { ...DEFAULT_MESH_SETTINGS, enabled: false };
  const set = (patch: Partial<MeshSettings>) =>
    updateDevice(d.id, (x) => (x.host ? { ...x, host: { ...x.host, mesh: { ...(x.host.mesh ?? DEFAULT_MESH_SETTINGS), ...patch } } } : { ...x, router: { ...x.router!, mesh: { ...(x.router!.mesh ?? DEFAULT_MESH_SETTINGS), ...patch } } }));
  const node = sim.node(d.id);
  const agent = node instanceof Host || node instanceof Router ? node.mesh : undefined;
  const status = agent?.summary();
  const zt = m.net === "zerotier";
  const myName = meshHostname(m.name.trim() || d.name);
  // exit node 후보: 같은 tailnet 에서 exit node 를 내주는 공유기
  const exits = topology.value.devices.filter((x) => x !== d && x.router?.mesh?.enabled && x.router.mesh.exitNode && x.router.mesh.net === m.net && x.router.mesh.network.trim().toLowerCase() === m.network.trim().toLowerCase());
  return (
    <Section title="메시 VPN (Tailscale·ZeroTier)">
      <label class="toggle-row">
        <span>
          {m.enabled ? "켜짐" : "꺼짐"} <span class="mono muted">{zt ? "ZeroTier · UDP 9993" : "Tailscale · UDP 41641"}</span>
        </span>
        <Toggle on={m.enabled} onToggle={() => set({ enabled: !m.enabled })} />
      </label>
      <Field label="종류">
        <div class="segmented" role="radiogroup">
          <button class={!zt ? "on" : ""} onClick={() => set({ net: "tailscale" })} title="계정(tailnet)으로 로그인 — WireGuard 위의 메시, MagicDNS">
            Tailscale
          </button>
          <button class={zt ? "on" : ""} onClick={() => set({ net: "zerotier" })} title="네트워크 ID 로 참여 — 컨트롤러가 주소를 줌, DNS 없음">
            ZeroTier
          </button>
        </div>
      </Field>
      {!m.enabled && (
        <p class="note">
          켜면 {zt ? "ZeroTier 네트워크 컨트롤러" : "Tailscale 조정 서버"}에 로그인해 메시 주소({zt ? "10.147.17.x" : "100.64.x.y"})를 받고, 같은 {zt ? "네트워크" : "tailnet"} 의 기기들과 직접(홀 펀칭) 또는 릴레이를 거쳐 통신합니다. 서버를 열거나 포트 포워딩을 하지 않아도 NAT 뒤의 기기끼리 이어집니다.
        </p>
      )}
      {m.enabled && (
        <>
          <Field label={zt ? "네트워크 ID" : "tailnet"} hint={zt ? "16자리 16진수" : "계정 — 같아야 서로 봄"} error={!m.network.trim() ? "비어 있으면 로그인이 거절됩니다" : zt && !/^[0-9a-f]{16}$/i.test(m.network.trim()) ? "예: 8056c2e21c000001" : undefined}>
            <input class="input mono" value={m.network} placeholder={zt ? "8056c2e21c000001" : "family"} onChange={(e) => set({ network: e.currentTarget.value })} />
          </Field>
          <Field label="기기 이름" hint={zt ? "" : `MagicDNS: ${myName || "?"}`}>
            <input class="input mono" value={m.name} placeholder={myName} onChange={(e) => set({ name: e.currentTarget.value })} />
          </Field>
          {d.router && (
            <>
              <label class="toggle-row">
                <span>
                  서브넷 라우터
                  <small class="muted">LAN {d.router.lanIp}/{d.router.lanPrefix} 를 알려 앱 없는 LAN 기기에도 닿게</small>
                </span>
                <Toggle on={m.advertiseLan === true} onToggle={() => set({ advertiseLan: !m.advertiseLan })} />
              </label>
              <label class="toggle-row">
                <span>
                  exit node 내주기
                  <small class="muted">다른 기기의 인터넷을 이 공유기로 내보냄</small>
                </span>
                <Toggle on={m.exitNode === true} onToggle={() => set({ exitNode: !m.exitNode })} />
              </label>
            </>
          )}
          {d.host && (
            <Field label="exit node" hint="인터넷을 그 기기로">
              <select class="input" value={m.useExitNode ?? ""} onChange={(e) => set({ useExitNode: e.currentTarget.value || undefined })}>
                <option value="">쓰지 않음</option>
                {exits.map((x) => {
                  const n = meshHostname(x.router!.mesh!.name.trim() || x.name);
                  return (
                    <option key={x.id} value={n}>
                      {n} ({x.name})
                    </option>
                  );
                })}
                {m.useExitNode && !exits.some((x) => meshHostname(x.router!.mesh!.name.trim() || x.name) === m.useExitNode) && <option value={m.useExitNode}>{m.useExitNode} (없음)</option>}
              </select>
            </Field>
          )}
          {status && <p class={`note${status.startsWith("거절") ? " error-note" : ""}`}>{status}</p>}
          <p class="note">
            피어마다 직접 경로가 있는지는 표 탭에 있습니다. 직접 경로는 처음 보낼 때 홀 펀칭(disco ping)으로 찾고, 양쪽 NAT 가 받아 주지 않으면(대개 symmetric NAT) {zt ? "root 릴레이" : "DERP 릴레이"}로 계속 보냅니다. {zt ? "ZeroTier 는 이름을 풀어 주지 않아 주소로 접속합니다." : "피어는 기기 이름으로 찾습니다(MagicDNS)."}
          </p>
        </>
      )}
    </Section>
  );
}
