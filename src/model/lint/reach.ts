// 구성 검사의 "그 주소·포트는 누가 받나": 공유기의 수동 WAN 주소, 포트 포워딩을 따라 안쪽 공유기까지(공유기 뒤 공유기),
// DDNS 이름의 주인, 앞 공유기. VPN 규칙들(WireGuard·OpenVPN·L2TP)이 같은 따라가기를 쓴다 — 한 벌씩 따로 두면 서로 어긋난다
import { ddnsHostname, type Device } from "../topology";
import { validIp } from "./addr";
import type { LintContext } from "./context";

/** 공유기의 수동 WAN 주소 (자동이면 모름 — 판단하지 않는다) */
export function routerWanIp(x: Device): string | undefined {
  return x.router?.wan?.ipMode === "static" ? validIp(x.router.wan.ip) : undefined;
}

/** 그 장비가 서버(isServer)가 아니고 그 포트(proto)를 안쪽으로 포워딩하면 대상(수동 WAN 주소의 공유기)으로 따라간다 */
export function followTarget(devices: Device[], self: Device, start: Device | undefined, port: number, proto: "udp" | "tcp", isServer: (x: Device, port: number) => boolean): { srv: Device; port: number; via?: Device } | undefined {
  let srv = start;
  let p = port;
  let via: Device | undefined;
  for (let hop = 0; srv && !isServer(srv, p) && hop < 4; hop++) {
    const fwd = srv.router?.forwards?.find((f) => (f.proto ?? "tcp") === proto && f.publicPort === p);
    if (!fwd) break;
    const lan = validIp(fwd.lanIp);
    via = srv;
    p = fwd.lanPort;
    srv = lan ? devices.find((x) => x !== self && routerWanIp(x) === lan) : undefined;
  }
  return srv ? { srv, port: p, ...(via ? { via } : {}) } : undefined;
}

/** 이 DDNS 이름을 켜 둔 공유기 */
export function ddnsOwner(devices: Device[], name: string): Device | undefined {
  return devices.find((x) => x.router?.ddns?.enabled && ddnsHostname(x.router.ddns.name) === name);
}

/** 공유기 WAN 이 다른 공유기의 LAN 에 붙어 있으면 그 앞 공유기 (밖에서는 앞 공유기의 공인 주소로 보인다) */
export function frontRouter(m: LintContext["m"], d: Device): Device | undefined {
  const seg = m.ids.get(`${d.id}:0`);
  if (seg === undefined) return undefined;
  return m.allGws.find((g) => g.device !== d && g.gwKind === "router" && m.ids.get(g.key) === seg)?.device;
}
