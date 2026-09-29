// 서비스 규칙: 포트 포워딩 대상이 그 포트를 열지 않음, 공유기 DNS 포워더 꺼짐.
import type { Device } from "../topology";
import { validIp, validPort } from "./addr";
import type { LintContext } from "./context";

// 규칙 15: 포트 포워딩 대상 서버가 그 포트를 열지 않음 (예: 공인 443 → 안쪽 :443 인데 웹 서버는 80 만)
export function forwardClosedRule({ t, add }: LintContext): void {
  const listens = (x: Device, proto: "tcp" | "udp", port: number) => {
    const h = x.host!;
    if (proto === "tcp") return (h.services ?? []).includes(port) || (h.lb?.enabled === true && h.lb.port === port);
    return port === 53 && h.dnsServer?.enabled === true;
  };
  for (const d of t.devices) {
    const rules = d.router?.forwards ?? (d.kind === "nat" ? d.l3?.forwards : undefined) ?? [];
    for (const r of rules) {
      const lanIp = validIp(r.lanIp);
      if (!lanIp || !validPort(r.lanPort)) continue;
      const owners = t.devices.filter((x) => x.host?.ipMode === "static" && x.host.ip === lanIp);
      if (owners.length !== 1) continue; // 주소가 여러 사설망에 겹치면 어느 장비인지 알 수 없어 침묵
      const target = owners[0]!;
      const proto = r.proto ?? "tcp";
      if (listens(target, proto, r.lanPort)) continue;
      const what = proto === "udp" ? (r.lanPort === 53 ? "DNS 서버" : `UDP ${r.lanPort}`) : r.lanPort === 80 ? "웹 서버(TCP 80)" : `TCP ${r.lanPort}`;
      const open = (target.host!.services ?? []).map((p) => `TCP ${p}`).concat(target.host!.dnsServer?.enabled ? ["UDP 53(DNS)"] : []);
      add({
        deviceId: d.id,
        severity: "warn",
        code: "nat.forward-closed",
        message: `포트 포워딩 ${proto.toUpperCase()} :${r.publicPort} → ${lanIp}:${r.lanPort} 인데 ${target.name} 가 ${what} 를 열지 않음 → 바깥에서 들어오면 ${proto === "tcp" ? "거부(RST)" : "Port Unreachable"}${open.length ? ` (열린 것: ${open.join(", ")})` : ""}`,
        fix: `${d.name} → 포트 포워딩의 안쪽 포트를 ${target.name} 가 여는 포트로 맞추거나, ${target.name} 의 서비스에서 ${what} 를 켜기`,
        related: [target.id],
      });
    }
  }
}

// 규칙 16: 공유기가 DHCP 로 자기 자신을 DNS 로 안내하는데 DNS 포워더가 꺼져 있음 → 이름 풀이가 모두 실패
export function routerDnsRule({ t, add }: LintContext): void {
  for (const d of t.devices) {
    const r = d.router;
    if (!r?.dhcp.enabled || validIp(r.dhcp.dns)) continue;
    if ((r.dns ?? { enabled: true }).enabled) continue;
    add({
      deviceId: d.id,
      severity: "warn",
      code: "router.dns-off",
      message: `DHCP 가 DNS 서버로 공유기 자신(${r.lanIp})을 안내하는데 DNS 포워더가 꺼져 있음 → 호스트들의 이름 풀이가 실패`,
      fix: `${d.name} → DNS 포워더를 켜거나, DHCP 서비스의 DNS 서버 칸에 8.8.8.8 같은 DNS 서버 주소를 넣고 호스트에서 DHCP 임대 갱신`,
    });
  }
}
