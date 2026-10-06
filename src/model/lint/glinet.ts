// 공유기 관리 규칙: 관리 화면을 인터넷에 연 것, 드롭인 게이트웨이의 WAN 주소
import type { LintContext } from "./context";

// 규칙 20g: 공유기 관리
export function glinetRules({ t, add }: LintContext): void {
  for (const d of t.devices) {
    const r = d.router;
    if (!r) continue;
    if (r.admin?.enabled && r.admin.remote)
      add({ deviceId: d.id, severity: "warn", code: "admin.remote-open", message: `관리 화면(HTTP·HTTPS${r.admin.ssh ? "·SSH" : ""})을 WAN(인터넷)에도 열었음 → 누구나 로그인 화면에 닿아 비밀번호 대입 공격을 받는다`, fix: `${d.name} → 보안 → 관리 접근 → WAN 접근 끄기 (원격 관리는 GoodCloud 나 VPN 으로)` });
    if (r.dropIn && r.wan?.ipMode !== "static")
      add({ deviceId: d.id, severity: "warn", code: "dropin.wan-dhcp", message: `드롭인 게이트웨이인데 WAN 주소가 자동(DHCP)임 → 주소가 바뀌면 이 공유기를 게이트웨이로 적은 기기들이 나가지 못함`, fix: `${d.name} → 인터넷 → WAN 을 수동 주소로 (기존 공유기 LAN 안의 쓰지 않는 주소)` });
  }
}
