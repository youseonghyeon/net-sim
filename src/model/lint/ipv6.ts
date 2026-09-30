// IPv6 규칙: 주소 중복, 호스트 기본 게이트웨이(프리픽스 밖·이 링크의 라우터가 아님·라우터 IPv6 꺼짐), 라우터 프리픽스 밖 주소,
// SLAAC(자동 호스트가 있는데 이 링크에 RA 가 없음·RA 로 알릴 /64 프리픽스가 없음).
// IPv4 규칙과 따로 돈다 — IPv6 를 켠 장치만 본다. 주소 칸은 netSync 의 effective* 와 같은 기준(표준 표기, 링크 로컬 주소 칸은 없음)
import { isLinkLocal6, linkLocalOf, network6, sameSubnet6 } from "../../core/addr6";
import { effectiveHost6, effectiveL3v6, l3MacOf } from "../netSync";
import { DEVICE_SPECS, wirelessLinks, type Device, type Topology } from "../topology";
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
  /** 이 인터페이스로 RA 를 보냄 */
  ra: boolean;
}

/** 케이블·무선으로 이어진 장치 묶음 번호 (따로 떨어진 두 실습은 주소가 겹쳐도 서로 닿지 않는다) */
function components(t: Topology): Map<string, number> {
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    let r = x;
    while (parent.get(r) !== undefined && parent.get(r) !== r) r = parent.get(r)!;
    parent.set(x, r);
    return r;
  };
  const union = (a: string, b: string) => parent.set(find(a), find(b));
  for (const d of t.devices) parent.set(d.id, d.id);
  for (const c of t.cables) union(c.a.device, c.b.device);
  for (const l of wirelessLinks(t)) union(l.client, l.base);
  const ids = new Map<string, number>();
  const out = new Map<string, number>();
  for (const d of t.devices) {
    const r = find(d.id);
    if (!ids.has(r)) ids.set(r, ids.size);
    out.set(d.id, ids.get(r)!);
  }
  return out;
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
      const c = v6.interfaces[i] as { ip?: string; prefix?: number; ra?: boolean };
      routers.push({ device: d, port: i, label: `${d.name} ${portName(d, i)}`, ip: c.ip, prefix: c.prefix ?? 64, linkLocal: safeLinkLocal(l3MacOf(d.mac, i)), seg, ra: c.ra === true });
    });
  }
  const hosts = t.devices.filter((d) => d.host).map((d) => ({ device: d, v6: effectiveHost6(d), seg: m.ids.get(`${d.id}:0`) })).filter((h) => h.v6.enabled);

  // 주소 중복: 이어진 망 안에서 전역 주소는 하나여야 한다 (같은 링크면 나중에 켠 쪽이 DAD 로 포기, 동시에 켜면 둘 다 포기)
  const comp = components(t);
  const owners = new Map<string, { device: Device; label: string }[]>();
  const own = (ip: string | undefined, device: Device, label: string) => {
    if (!ip) return;
    const key = `${comp.get(device.id)}|${ip}`;
    const list = owners.get(key) ?? [];
    list.push({ device, label });
    owners.set(key, list);
  };
  for (const h of hosts) for (const a of h.v6.addrs) own(a.ip, h.device, h.device.name);
  for (const r of routers) own(r.ip, r.device, r.label);
  for (const [key, list] of owners) {
    if (list.length < 2) continue;
    const ip = key.slice(key.indexOf("|") + 1);
    for (const o of list) {
      const others = list.filter((x) => x !== o);
      add({
        deviceId: o.device.id,
        severity: "error",
        code: "ipv6.duplicate",
        message: `IPv6 주소 ${ip} 를 ${others.map((x) => x.label).join(", ")} 도 씁니다 — 같은 링크면 나중에 켠 쪽이 DAD 로 그 주소를 포기합니다 (동시에 켜면 둘 다 포기)`,
        fix: `${o.label} 의 IPv6 주소를 다른 값으로 바꾸기`,
        related: others.map((x) => x.device.id),
      });
    }
  }

  // SLAAC: RA 를 보내는 라우터 인터페이스가 알릴 /64 프리픽스가 없으면 그 링크의 자동 호스트가 주소를 못 만든다
  const slaacHosts = hosts.filter((h) => h.v6.slaac && h.seg !== undefined && m.linked.has(`${h.device.id}:0`));
  for (const r of routers) {
    if (!r.ra || r.seg === undefined) continue;
    const waiting = slaacHosts.filter((h) => h.seg === r.seg);
    if (waiting.length === 0) continue;
    if (!r.ip || r.prefix !== 64) {
      add({
        deviceId: r.device.id,
        severity: "error",
        code: "ipv6.ra-prefix",
        message: r.ip
          ? `${r.label} 가 RA 로 알리는 프리픽스가 /${r.prefix} 입니다 — SLAAC 는 /64 에서만 주소를 만들어 ${waiting.map((h) => h.device.name).join(", ")} 가 주소를 못 받습니다`
          : `${r.label} 는 RA 를 보내지만 IPv6 주소가 없어 알릴 프리픽스가 없습니다 — ${waiting.map((h) => h.device.name).join(", ")} 가 SLAAC 주소를 못 만듭니다`,
        fix: `${r.device.name} → IPv6 → ${portName(r.device, r.port)} 에 /64 주소(예: 2001:db8:1::1/64)`,
        related: waiting.map((h) => h.device.id),
      });
    }
  }

  for (const h of hosts) {
    const d = h.device;
    const gw = h.v6.gateway;
    if (h.v6.slaac) {
      // 자동 호스트: 이 링크에 IPv6 라우터는 있는데 RA 를 보내는 인터페이스가 없음, 또는 라우터가 IPv6 를 끔
      if (h.seg === undefined || !m.linked.has(`${d.id}:0`)) continue;
      const segRouters = routers.filter((r) => r.seg === h.seg);
      if (segRouters.length > 0 && !segRouters.some((r) => r.ra)) {
        const r = segRouters.find((x) => x.ip) ?? segRouters[0]!;
        add({
          deviceId: d.id,
          severity: "error",
          code: "ipv6.slaac-no-ra",
          message: `IPv6 가 자동(SLAAC)인데 이 링크의 라우터 ${segRouters.map((x) => x.label).join(", ")} 가 RA 를 보내지 않아 주소·기본 게이트웨이를 못 받습니다 (링크 로컬만)`,
          fix: `${r.device.name} → IPv6 → ${portName(r.device, r.port)} 의 RA 광고 켜기, 또는 ${d.name} 의 IPv6 를 수동으로`,
          related: [r.device.id],
        });
      } else if (segRouters.length === 0) {
        const r = off.find((o) => o.seg !== undefined && o.seg === h.seg);
        if (r) {
          add({
            deviceId: d.id,
            severity: "error",
            code: "ipv6.router-off",
            message: `IPv6 가 자동(SLAAC)인데 이 링크의 라우터 ${r.device.name} 는 IPv6 가 꺼져 있어 RA 가 오지 않습니다`,
            fix: `${r.device.name} → IPv6 를 켜고 ${portName(r.device, r.port)} 에 /64 주소를 넣은 뒤 RA 광고 켜기`,
            related: [r.device.id],
          });
        }
      }
      continue;
    }
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
