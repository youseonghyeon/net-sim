// IPv6 규칙: 주소 중복, 호스트 기본 게이트웨이(프리픽스 밖·이 링크의 라우터가 아님·라우터 IPv6 꺼짐), 라우터 프리픽스 밖 주소.
// IPv4 규칙과 따로 돈다 — IPv6 를 켠 장치만 본다. 주소 칸은 netSync 의 effective* 와 같은 기준(표준 표기, 링크 로컬 주소 칸은 없음)
import { isLinkLocal6, linkLocalOf, network6, sameSubnet6 } from "../../core/addr6";
import { effectiveHost6, effectiveL3v6, l3MacOf } from "../netSync";
import { DEVICE_SPECS, type Device } from "../topology";
import type { LintContext } from "./context";
import { portName } from "./segments";

interface V6Router {
  device: Device;
  port: number;
  label: string;
  ip?: string;
  prefix: number;
  linkLocal: string;
  seg: number | undefined;
}

function safeLinkLocal(mac: string): string {
  try {
    return linkLocalOf(mac);
  } catch {
    return "";
  }
}

export function ipv6Rules({ t, m, add }: LintContext): void {
  // IPv6 를 켠 라우터 인터페이스 (게이트웨이·NAT 박스). IPv6 를 끈 L3 도 모아 "꺼짐" 안내에 쓴다
  const routers: V6Router[] = [];
  const off: { device: Device; port: number; seg: number | undefined }[] = [];
  for (const d of t.devices) {
    if (DEVICE_SPECS[d.kind].role !== "l3") continue;
    const ports = DEVICE_SPECS[d.kind].ports;
    const v6 = effectiveL3v6(d, ports.length);
    ports.forEach((_, i) => {
      const seg = m.ids.get(`${d.id}:${i}`);
      if (!v6.enabled) {
        off.push({ device: d, port: i, seg });
        return;
      }
      const c = v6.interfaces[i] as { ip?: string; prefix?: number };
      routers.push({ device: d, port: i, label: `${d.name} ${portName(d, i)}`, ip: c.ip, prefix: c.prefix ?? 64, linkLocal: safeLinkLocal(l3MacOf(d.mac, i)), seg });
    });
  }
  const hosts = t.devices.filter((d) => d.host).map((d) => ({ device: d, v6: effectiveHost6(d), seg: m.ids.get(`${d.id}:0`) })).filter((h) => h.v6.enabled);

  // 주소 중복: 전역 주소는 어디서든 하나여야 한다 (같은 링크면 나중에 켠 쪽이 DAD 로 포기)
  const owners = new Map<string, { device: Device; label: string }[]>();
  const own = (ip: string | undefined, device: Device, label: string) => {
    if (!ip) return;
    const list = owners.get(ip) ?? [];
    list.push({ device, label });
    owners.set(ip, list);
  };
  for (const h of hosts) for (const a of h.v6.addrs) own(a.ip, h.device, h.device.name);
  for (const r of routers) own(r.ip, r.device, r.label);
  for (const [ip, list] of owners) {
    if (list.length < 2) continue;
    for (const o of list) {
      const others = list.filter((x) => x !== o);
      add({
        deviceId: o.device.id,
        severity: "error",
        code: "ipv6.duplicate",
        message: `IPv6 주소 ${ip} 를 ${others.map((x) => x.label).join(", ")} 도 씁니다 — 같은 링크면 나중에 켠 쪽이 DAD 로 그 주소를 포기합니다`,
        fix: `${o.label} 의 IPv6 주소를 다른 값으로 바꾸기`,
        related: others.map((x) => x.device.id),
      });
    }
  }

  for (const h of hosts) {
    const d = h.device;
    const gw = h.v6.gateway;
    const addr = h.v6.addrs[0];
    const segRouters = routers.filter((r) => r.seg !== undefined && r.seg === h.seg);
    // 기본 게이트웨이가 내 프리픽스 밖 (글로벌 게이트웨이인데)
    if (gw && addr && !isLinkLocal6(gw) && !sameSubnet6(gw, addr.ip, addr.prefix)) {
      add({
        deviceId: d.id,
        severity: "error",
        code: "ipv6.gateway-off-link",
        message: `IPv6 기본 게이트웨이 ${gw} 가 내 프리픽스 ${network6(addr.ip, addr.prefix)}/${addr.prefix} 밖입니다 — 게이트웨이는 같은 링크에 있어야 NDP 로 찾을 수 있습니다`,
        fix: `${d.name} → IPv6 → 기본 게이트웨이를 같은 프리픽스의 라우터 주소나 라우터의 링크 로컬(fe80::) 주소로`,
      });
      continue;
    }
    if (h.seg === undefined || !m.linked.has(`${d.id}:0`)) continue;
    if (gw && segRouters.length > 0 && !segRouters.some((r) => r.ip === gw || r.linkLocal === gw)) {
      const hint = segRouters.find((r) => r.ip) ?? segRouters[0]!;
      add({
        deviceId: d.id,
        severity: "error",
        code: "ipv6.gateway-unknown",
        message: `IPv6 기본 게이트웨이 ${gw} 는 이 링크의 라우터 주소가 아닙니다 — 그 주소가 NS 에 답하지 않아 다른 네트워크로 못 나갑니다`,
        fix: `${d.name} → IPv6 → 기본 게이트웨이를 ${hint.label} 의 ${hint.ip ?? hint.linkLocal}${hint.ip ? ` (또는 링크 로컬 ${hint.linkLocal})` : ""} 로`,
        related: [hint.device.id],
      });
      continue;
    }
    if (gw && segRouters.length === 0) {
      const r = off.find((o) => o.seg !== undefined && o.seg === h.seg);
      if (r) {
        add({
          deviceId: d.id,
          severity: "error",
          code: "ipv6.router-off",
          message: `이 링크의 라우터 ${r.device.name} 는 IPv6 가 꺼져 있어 IPv6 기본 게이트웨이 ${gw} 로 보낸 패킷을 받지 않습니다`,
          fix: `${r.device.name} → IPv6 를 켜고 ${portName(r.device, r.port)} 에 이 링크의 주소(예: ${addr ? `${network6(addr.ip, addr.prefix)}1` : "2001:db8:1::1"})를 넣기`,
          related: [r.device.id],
        });
      }
      continue;
    }
    // 라우터가 이 링크에 알리는 프리픽스 밖의 주소: 나가기는 해도 라우터가 돌아오는 경로를 모른다
    const withPrefix = segRouters.filter((r) => r.ip);
    if (gw && addr && withPrefix.length > 0 && !withPrefix.some((r) => sameSubnet6(addr.ip, r.ip!, r.prefix))) {
      const r = withPrefix[0]!;
      add({
        deviceId: d.id,
        severity: "error",
        code: "ipv6.prefix-mismatch",
        message: `IPv6 주소 ${addr.ip} 가 이 링크의 라우터 프리픽스 ${network6(r.ip!, r.prefix)}/${r.prefix} 밖입니다 — 라우터가 돌아오는 패킷을 이 링크로 보내지 않습니다`,
        fix: `${d.name} → IPv6 주소를 ${network6(r.ip!, r.prefix)}/${r.prefix} 안의 주소로`,
        related: [r.device.id],
      });
    }
  }
}
