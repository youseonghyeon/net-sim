// AdGuard Home·자녀 보호 규칙: DNS 필터는 공유기 DNS 포워더로 오는 질의만 거른다 — 그 길을 벗어난 기기·설정을 짚는다

import { validIp } from "./addr";
import type { LintContext } from "./context";
import { routerLanKey } from "./segments";

// 규칙 21c: AdGuard — DNS 포워더 꺼짐, DHCP 가 다른 DNS 를 안내, DNS 를 직접 적은 기기(가로채기가 꺼져 있으면)
export function adguardRules({ t, m, add }: LintContext): void {
  for (const d of t.devices) {
    const a = d.router?.adguard;
    if (!a?.enabled) continue;
    const r = d.router!;
    const lanIp = validIp(r.lanIp);
    if (r.dns && !r.dns.enabled) {
      add({ deviceId: d.id, severity: "error", code: "adguard.dns-off", message: "AdGuard Home 은 DNS 포워더로 오는 질의를 거르는데 DNS 포워더가 꺼져 있음 → 아무것도 걸러지지 않음", fix: `${d.name} → 네트워크 → DNS 포워더 켜기` });
      continue;
    }
    const dhcpDns = validIp(r.dhcp.dns?.trim());
    if (r.dhcp.enabled && dhcpDns && dhcpDns !== lanIp && !a.forceDns) {
      add({ deviceId: d.id, severity: "warn", code: "adguard.dhcp-dns", message: `DHCP 가 DNS 서버로 ${dhcpDns} 를 안내해 자동(DHCP) 기기들은 공유기를 거치지 않음 → AdGuard 가 거르지 못함`, fix: `${d.name} → 네트워크 → DHCP 의 DNS 서버를 비우기(공유기 자신), 또는 AdGuard 의 DNS 가로채기 켜기` });
    }
    if (a.forceDns) continue;
    const seg = m.membersOf(routerLanKey(d));
    for (const h of seg?.hosts ?? []) {
      const dns = h.device.host?.ipMode === "static" ? validIp(h.device.host.dns?.trim()) : undefined;
      if (!dns || dns === lanIp) continue;
      add({ deviceId: h.device.id, severity: "warn", code: "adguard.bypass", message: `DNS 를 ${dns} 로 직접 적어 ${d.name} 의 AdGuard Home 을 거치지 않음 → 광고 차단·자녀 보호가 이 기기에 걸리지 않음`, fix: `${d.name} → 앱 → AdGuard → DNS 가로채기 켜기, 또는 ${h.device.name} 의 DNS 를 ${lanIp ?? "공유기 LAN 주소"} 로`, related: [d.id] });
    }
  }
}

