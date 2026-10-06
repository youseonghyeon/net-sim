// 메시 VPN (Tailscale·ZeroTier) 규칙: 같은 tailnet·네트워크에 참여한 기기들의 설정 — 이름이 다르면 서로 못 보고, exit node·서브넷이 엇갈리면 경로가 없다.
// 조정 서버는 시뮬레이션 밖(인터넷 노드)이라 tailnet 이름 오타는 "혼자인 기기" 로만 드러난다 — 구성 검사가 짚어 준다
import { meshHostname } from "../../core/nodes/tailscale";
import type { Device, MeshSettings } from "../topology";
import { fmtSubnet, overlaps, subnetOf, validIp } from "./addr";
import type { LintContext } from "./context";

const meshOf = (d: Device): MeshSettings | undefined => (d.host?.mesh?.enabled ? d.host.mesh : d.router?.mesh?.enabled ? d.router.mesh : undefined);
const nameOf = (d: Device, m: MeshSettings) => meshHostname(m.name.trim() || d.name) || `${d.kind}-${d.id.slice(-4)}`;
const brand = (m: MeshSettings) => (m.net === "zerotier" ? "ZeroTier" : "Tailscale");
const where = (m: MeshSettings) => (m.net === "zerotier" ? "네트워크" : "tailnet");

// 규칙 20f: 메시 VPN
export function meshRules({ t, add }: LintContext): void {
  const members = t.devices.map((d) => ({ d, m: meshOf(d) })).filter((x): x is { d: Device; m: MeshSettings } => !!x.m);
  const key = (m: MeshSettings) => `${m.net}:${m.network.trim().toLowerCase()}`;
  for (const { d, m } of members) {
    const net = m.network.trim();
    const section = d.router ? "VPN → 메시 VPN" : "메시 VPN";
    if (!net) {
      add({ deviceId: d.id, severity: "error", code: "mesh.no-network", message: `${brand(m)} 를 켰지만 ${m.net === "zerotier" ? "네트워크 ID" : "tailnet(계정)"} 이 비어 있음 → 조정 서버가 로그인을 거절`, fix: `${d.name} → ${section} → ${m.net === "zerotier" ? "네트워크 ID (16자리)" : "tailnet 이름"}` });
      continue;
    }
    if (m.net === "zerotier" && !/^[0-9a-f]{16}$/i.test(net)) {
      add({ deviceId: d.id, severity: "error", code: "mesh.zt-id-invalid", message: `ZeroTier 네트워크 ID "${net}" 가 16자리 16진수가 아님 → 그런 네트워크가 없어 거절됨`, fix: `${d.name} → ${section} → 네트워크 ID (예: 8056c2e21c000001)` });
      continue;
    }
    const same = members.filter((x) => x.d !== d && key(x.m) === key(m));
    if (same.length === 0) {
      add({ deviceId: d.id, severity: "warn", code: "mesh.alone", message: `${where(m)} "${net}" 에 이 기기 하나뿐 → 연결할 피어가 없음 (다른 기기의 ${where(m)} 이름이 다르면 서로 못 본다)`, fix: `다른 기기의 ${brand(m)} 설정에서 ${where(m)} 을(를) "${net}" 로 같게` });
      continue;
    }
    const dup = same.find((x) => nameOf(x.d, x.m) === nameOf(d, m));
    if (dup && t.devices.indexOf(dup.d) < t.devices.indexOf(d))
      add({ deviceId: d.id, severity: "warn", code: "mesh.name-duplicate", message: `${dup.d.name} 와 기기 이름이 ${nameOf(d, m)} 로 같음 → 나중에 로그인한 쪽은 ${nameOf(d, m)}-1 이 되어 이름으로 찾기(MagicDNS)가 엇갈림`, fix: `${d.name} → ${section} → 기기 이름을 다르게`, related: [dup.d.id] });
    if (m.useExitNode?.trim()) {
      const want = meshHostname(m.useExitNode);
      const exit = same.find((x) => nameOf(x.d, x.m) === want);
      if (!exit || !exit.m.exitNode)
        add({ deviceId: d.id, severity: "warn", code: "mesh.exit-unknown", message: exit ? `exit node 로 고른 ${exit.d.name} 가 exit node 를 내주지 않음 → 인터넷은 평소처럼 나감` : `exit node "${m.useExitNode}" 가 이 ${where(m)} 에 없음 → 인터넷은 평소처럼 나감`, fix: exit ? `${exit.d.name} → VPN → 메시 VPN → exit node 켜기` : `${d.name} → 메시 VPN → exit node 를 있는 기기로`, ...(exit ? { related: [exit.d.id] } : {}) });
    }
  }
  // 서브넷 라우터 두 대가 겹치는 대역을 알림 → 더 긴 쪽(같으면 하나)만 쓰여 다른 쪽 LAN 에는 닿지 않음
  const routers = members.filter((x) => x.d.router && x.m.advertiseLan);
  for (let i = 0; i < routers.length; i++)
    for (let j = 0; j < i; j++) {
      const a = routers[i]!;
      const b = routers[j]!;
      if (key(a.m) !== key(b.m)) continue;
      const sa = subnetOf(validIp(a.d.router!.lanIp), a.d.router!.lanPrefix);
      const sb = subnetOf(validIp(b.d.router!.lanIp), b.d.router!.lanPrefix);
      if (sa && sb && overlaps(sa, sb))
        add({ deviceId: a.d.id, severity: "warn", code: "mesh.route-conflict", message: `${b.d.name} 도 같은 대역(${fmtSubnet(sb)})을 서브넷 라우터로 알림 → 한쪽 LAN 에만 닿고, 각 공유기는 그 대역을 자기 LAN 으로 봐 상대 LAN 에 가지 못함`, fix: `한쪽 공유기의 LAN 대역을 바꾸기 (예: 192.168.9.0/24)`, related: [b.d.id] });
    }
}
