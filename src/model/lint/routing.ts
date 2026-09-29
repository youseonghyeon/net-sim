// 라우팅 규칙: 업링크 디폴트 라우트, 안쪽 게이트웨이 뒤로 돌아가는 스태틱 라우팅, DHCP 릴레이 대상 경로. 양쪽 다 RIP 면 침묵.
import { DEVICE_SPECS, type Device } from "../topology";
import { contains, covers, fmtSubnet, subnetOf, validIp, type Subnet } from "./addr";
import { names, pickGw, ripOn, subnetsBehind, uniqueDevices, type LintContext } from "./context";
import { portName, validSubifs } from "./segments";

// 규칙 6: 게이트웨이/NAT 업링크(if0/outside)가 수동인데 디폴트 라우트 없음
export function uplinkDefaultRule({ t, m, add }: LintContext): void {
  for (const d of t.devices) {
    if (DEVICE_SPECS[d.kind].role !== "l3" || !d.l3) continue;
    const c = d.l3.interfaces[0];
    if (!c || c.ipMode !== "static") continue;
    const ip = validIp(c.ip);
    if (!ip || validIp(c.gateway)) continue;
    const key = `${d.id}:0`;
    // 위쪽에 "안쪽 인터페이스"(다른 라우터의 LAN 쪽·인터넷)가 있을 때만: 게이트웨이끼리 if0 을 맞댄 백본은 디폴트 라우트가 필요 없다
    const ups = m.gwsOf(key).filter((g) => g.device !== d && g.inside);
    if (ups.length === 0) continue;
    // 위쪽 라우터들도 RIP 를 켰으면 경로(필요하면 디폴트 라우트까지)를 광고로 배운다 — 토폴로지만으로는 판단할 수 없어 침묵
    if (ripOn(d) && ups.every((g) => ripOn(g.device))) continue;
    const pick = pickGw(ups, ip);
    const name = portName(d, 0);
    add({
      deviceId: d.id,
      severity: "error",
      code: "l3.uplink-no-default",
      message: `${name} 에 주소 ${ip} 는 있지만 디폴트 라우트(게이트웨이)가 없음 → 바깥으로 나가는 패킷을 보낼 곳이 없어 드롭`,
      fix: `${d.name} → ${name} → 게이트웨이 칸에 ${pick?.ip ?? `위쪽 라우터(${pick?.label ?? "?"}) 의 주소`} 입력`,
      related: pick ? [pick.device.id] : undefined,
    });
  }
}

// 규칙 7: 안쪽에 또 다른 게이트웨이가 있는데 그 뒤 서브넷으로 돌아가는 스태틱 라우팅 없음
export function returnRouteRule({ t, m, add }: LintContext): void {
  for (const x of t.devices) {
    const role = DEVICE_SPECS[x.kind].role;
    if (role !== "l3" && role !== "router") continue;
    const routes = (x.l3?.routes ?? []).map((r) => ({ subnet: subnetOf(validIp(r.dest), r.prefix), via: validIp(r.via) })).filter((r) => r.subnet && r.via) as { subnet: Subnet; via: string }[];
    const missing: { subnet: Subnet; y: Device; owner: Device }[] = [];
    const seenSeg = new Set<number>();
    for (const g of m.allGws) {
      if (g.device !== x || !g.inside) continue;
      const seg = m.ids.get(g.key)!;
      if (seenSeg.has(seg)) continue;
      seenSeg.add(seg);
      for (const y of m.gwsOf(g.key)) {
        if (y.device === x || !y.uplink || y.device.kind !== "gateway") continue;
        if (ripOn(x) && ripOn(y.device)) continue; // 둘 다 RIP 를 켜면 y 뒤의 서브넷은 광고로 배운다
        for (const s of subnetsBehind(y.device, m, new Set([x.id]))) {
          if (routes.some((r) => covers(r.subnet, s.subnet))) continue;
          if (!missing.some((q) => q.subnet.net === s.subnet.net && q.subnet.prefix === s.subnet.prefix)) missing.push({ subnet: s.subnet, y: y.device, owner: s.owner });
        }
      }
    }
    if (missing.length === 0) continue;
    const ys = uniqueDevices(missing.map((q) => ({ device: q.y })));
    const list = missing.map((q) => fmtSubnet(q.subnet)).join(", ");
    const hop = (y: Device) => {
      const c = y.l3?.interfaces[0];
      const ip = c?.ipMode === "static" ? validIp(c.ip) : undefined;
      return ip ?? `${y.name} 의 ${portName(y, 0)} 주소 (DHCP 로 받는 주소라 수동으로 고정하는 편이 안전)`;
    };
    // 같은 넥스트 홉끼리 묶어 "A, B (넥스트 홉 X)" 로
    const byHop = new Map<string, Subnet[]>();
    for (const q of missing) byHop.set(hop(q.y), [...(byHop.get(hop(q.y)) ?? []), q.subnet]);
    const entries = [...byHop].map(([h, subs]) => `${subs.map(fmtSubnet).join(", ")} → 넥스트 홉 ${h}`).join("; ");
    add({
      deviceId: x.id,
      severity: "error",
      code: "l3.no-return-route",
      message: `${names(ys)} 뒤 ${list} 로 돌아가는 경로가 없어 그쪽에서 나온 통신의 응답이 ${x.name} 에서 드롭됨`,
      fix:
        role === "router"
          ? `공유기는 스태틱 라우팅이 없음 → ${x.name} 자리에 게이트웨이나 NAT 박스를 쓰거나, ${names(ys)} 를 없애고 스위치로 바꾸기`
          : `${x.name} → 스태틱 라우팅에 ${entries} 추가`,
      related: ys.map((y) => y.id),
    });
  }
}

// 규칙 12: DHCP 릴레이 대상에 닿을 경로 없음
export function relayRouteRule({ t, m, add }: LintContext): void {
  for (const d of t.devices) {
    if (DEVICE_SPECS[d.kind].role !== "l3" || !d.l3) continue;
    const ifs = d.l3.interfaces;
    // DHCP 로 받는 인터페이스나 수동 게이트웨이가 있으면 디폴트 라우트가 생기므로 통과로 본다
    const hasDefault = ifs.some((c) => c && (c.ipMode === "dhcp" || validIp(c.gateway)));
    if (hasDefault || ripOn(d)) continue; // RIP 로 배울 경로는 토폴로지만 보고 알 수 없어 침묵
    const connected = m.allGws.filter((g) => g.device === d && g.subnet).map((g) => g.subnet!);
    const routes = (d.l3.routes ?? []).map((r) => subnetOf(validIp(r.dest), r.prefix)).filter((s): s is Subnet => !!s);
    const targets: { ifName: string; relay: string }[] = [];
    ifs.forEach((c, i) => {
      const relay = validIp(c?.relay);
      if (relay) targets.push({ ifName: portName(d, i), relay });
    });
    for (const s of validSubifs(d)) if (s.relay) targets.push({ ifName: s.label, relay: s.relay });
    for (const tgt of targets) {
      if (connected.some((s) => contains(s, tgt.relay)) || routes.some((s) => contains(s, tgt.relay))) continue;
      add({
        deviceId: d.id,
        severity: "warn",
        code: "relay.unreachable",
        message: `${tgt.ifName} 의 DHCP 릴레이 대상 ${tgt.relay} 로 가는 경로가 없음 (어느 인터페이스 서브넷에도 없고 스태틱 라우팅·디폴트 라우트도 없음)`,
        fix: `${d.name} → 스태틱 라우팅에 ${tgt.relay}/32 를 추가하거나, ${tgt.ifName} 의 릴레이 칸을 이 장치 인터페이스 서브넷 안의 DHCP 서버 주소로`,
      });
    }
  }
}
