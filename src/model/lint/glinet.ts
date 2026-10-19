// 공유기 관리 규칙: 관리 화면을 인터넷에 연 것, 드롭인 게이트웨이의 WAN 주소, 멀티 WAN 정책 규칙의 출발지, 스태틱 라우트
import type { LintContext } from "./context";
import { natOn, type RouterRouteSetting, type RouterSettings } from "../topology";
import { parseCidr } from "../netSync";
import { networkOf, sameSubnet } from "../../core/addr";
import { validIp } from "./addr";

/**
 * 스태틱 라우트 한 줄이 main 테이블에 들어가지 못하는 이유 (리눅스가 거절하거나 쓸 수 없는 경로). 들어가면 undefined.
 * 그 인터페이스가 자동(DHCP)이면 대역을 몰라 넥스트 홉은 보지 않는다
 */
export function staticRouteProblem(r: RouterSettings, x: RouterRouteSetting): string | undefined {
  if (!x.dest.trim()) return "대상이 비어 있음";
  const c = parseCidr(x.dest, 32);
  if (!c) return `대상 "${x.dest.trim()}" 이 대역이 아님`;
  if (c.prefix === 0) return "대상이 0.0.0.0/0(디폴트 라우트) — 인터넷으로 나갈 회선은 WAN 설정·멀티 WAN 이 정함";
  if (x.via.trim() && !validIp(x.via.trim())) return `넥스트 홉 "${x.via.trim()}" 이 주소가 아님`;
  const label = x.iface === "wan2" ? "WAN2" : "WAN1";
  if (x.iface === "wan2" && !r.wan2?.enabled) return "멀티 WAN 이 꺼져 WAN2 가 없음";
  const i = x.iface === "wan2" ? r.wan2 : r.wan;
  const ip = i?.ipMode === "static" ? validIp(i.ip) : undefined;
  const via = x.via.trim();
  if (!i || !ip || !via) return undefined;
  if (via === ip) return `넥스트 홉 ${via} 가 공유기 자신의 ${label} 주소`;
  if (!sameSubnet(via, ip, i.prefix)) return `넥스트 홉 ${via} 가 ${label} 대역(${networkOf(ip, i.prefix)}/${i.prefix}) 밖`;
  return undefined;
}

// 규칙 20g: 공유기 관리
export function glinetRules({ t, add }: LintContext): void {
  for (const d of t.devices) {
    // 포트 포워딩으로 SMB(안쪽 445·139)를 인터넷에 — 공유기와 NAT 장비 (바깥 포트를 바꿔도 안쪽 포트로 본다)
    const fwds = d.router?.forwards ?? (natOn(d) ? d.l3?.forwards : undefined) ?? [];
    const smbFwd = fwds.find((f) => (f.proto ?? "tcp") === "tcp" && [445, 139].includes(f.lanPort ?? f.publicPort));
    if (smbFwd)
      add({ deviceId: d.id, severity: "warn", code: "nat.forward-smb", message: `포트 포워딩으로 SMB(TCP ${smbFwd.lanPort})를 ${smbFwd.lanIp} 에 열었음 (공인 포트 ${smbFwd.publicPort}) → 파일 공유를 인터넷에 내놓으면 랜섬웨어가 노린다`, fix: `${d.name} → 포트 포워딩에서 공인 ${smbFwd.publicPort} 규칙 지우기 (밖에서는 VPN 으로)` });
    const r = d.router;
    if (!r) continue;
    const badAllow = (r.admin?.allow ?? "").split(/[,\s]+/).filter(Boolean).filter((x) => {
      const [ip, p] = x.split("/");
      return !/^\d+\.\d+\.\d+\.\d+$/.test(ip ?? "") || (ip ?? "").split(".").some((n) => Number(n) > 255) || (p !== undefined && !(/^\d{1,2}$/.test(p) && Number(p) <= 32));
    });
    if (r.admin?.enabled && badAllow.length)
      add({ deviceId: d.id, severity: "error", code: "admin.allow-invalid", message: `관리 화면 허용 목록의 ${badAllow.join(", ")} 은(는) 주소가 아님 → 그 항목은 쓰지 않음${badAllow.length === (r.admin.allow.split(/[,\s]+/).filter(Boolean).length) ? " (쓸 수 있는 항목이 없어 아무도 열 수 없음)" : ""}`, fix: `${d.name} → 보안 → 관리 접근 → 허용 목록 (예: 192.168.8.50, 192.168.8.0/24)` });
    if (r.admin?.enabled && r.admin.remote)
      add({ deviceId: d.id, severity: "warn", code: "admin.remote-open", message: `관리 화면(HTTP·HTTPS${r.admin.ssh ? "·SSH" : ""})을 WAN(인터넷)에도 열었음 → 누구나 로그인 화면에 닿아 비밀번호 대입 공격을 받는다`, fix: `${d.name} → 보안 → 관리 접근 → WAN 접근 끄기 (원격 관리는 GoodCloud 나 VPN 으로)` });
    if (r.samba?.enabled && r.samba.wan)
      add({ deviceId: d.id, severity: "error", code: "samba.wan-open", message: `네트워크 저장소(SMB, TCP 445)를 WAN(인터넷)에 열었음 → 랜섬웨어(WannaCry 등)·비밀번호 대입이 노리는 포트`, fix: `${d.name} → 앱 → 네트워크 저장소 → WAN 접근 끄기 (밖에서는 VPN 으로 집에 붙어 쓰기)` });

    if (r.dropIn && r.wan?.ipMode !== "static")
      add({ deviceId: d.id, severity: "warn", code: "dropin.wan-dhcp", message: `드롭인 게이트웨이인데 WAN 주소가 자동(DHCP)임 → 주소가 바뀌면 이 공유기를 게이트웨이로 적은 기기들이 나가지 못함`, fix: `${d.name} → 인터넷 → WAN 을 수동 주소로 (기존 공유기 LAN 안의 쓰지 않는 주소)` });

    // 멀티 WAN 정책 규칙: 출발지를 대역으로 읽을 수 없으면 그 규칙은 쓰지 않는다 (그 출발지는 페일오버대로 지금 회선으로)
    const badRules = r.wan2?.enabled ? (r.wan2.rules ?? []).flatMap((x, i) => (parseCidr(x.src, 32) ? [] : [`${i + 1}번(${x.src.trim() ? `"${x.src.trim()}"` : "비어 있음"})`])) : [];
    if (badRules.length)
      add({ deviceId: d.id, severity: "error", code: "mwan.rule-invalid", message: `멀티 WAN 정책 규칙 ${badRules.join(", ")} 의 출발지는 대역이 아님 → 그 규칙은 쓰지 않아 그 출발지도 지금 회선으로 나감`, fix: `${d.name} → 인터넷 → 멀티 WAN → 정책 규칙의 출발지 (예: 10.0.0.0/24, 주소 하나면 192.168.8.50)` });
    // WAN2 를 디폴트 라우트로 쓰지 않는데 정책 규칙이 WAN2 로 보냄: mwan3 policy 에 WAN2 가 없어 WAN1 로 나간다
    const noDefault = r.wan2?.enabled && r.wan2.defaultRoute === false ? (r.wan2.rules ?? []).flatMap((x, i) => (x.line === "wan2" && parseCidr(x.src, 32) ? [`${i + 1}번(${x.src.trim()})`] : [])) : [];
    if (noDefault.length)
      add({ deviceId: d.id, severity: "warn", code: "mwan.rule-no-default", message: `멀티 WAN 정책 규칙 ${noDefault.join(", ")} 은 WAN2 로 보내지만 WAN2 를 디폴트 라우트로 쓰지 않음(mwan3 에서 뺌) → 그 출발지는 WAN1 으로 나감`, fix: `${d.name} → 인터넷 → 멀티 WAN 에서 "디폴트 라우트로 사용" 을 켜거나, 그 규칙을 지우고 필요한 대역만 스태틱 라우트로` });
    // 스태틱 라우트: 들어가지 못하는 줄은 없는 것과 같다 (그 대역은 디폴트 라우트로 나감)
    const badRoutes = (r.routes ?? []).flatMap((x, i) => {
      const why = staticRouteProblem(r, x);
      return why ? [`${i + 1}번(${why})`] : [];
    });
    if (badRoutes.length)
      add({ deviceId: d.id, severity: "error", code: "router.route-invalid", message: `스태틱 라우트 ${badRoutes.join(", ")} → 그 경로는 쓰이지 않아 그 대역도 디폴트 라우트(지금 회선)로 나감`, fix: `${d.name} → 인터넷 → 스태틱 라우트 (넥스트 홉은 고른 인터페이스 대역 안의 라우터 주소, 예: 10.50.10.254)` });
  }
}
