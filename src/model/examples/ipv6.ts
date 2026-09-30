// 예제 묶음 "IPv6". 등록(메뉴 순서·설명)은 ../examples.ts 의 EXAMPLES.
import { linkLocalOf } from "../../core/addr6";
import { l3MacOf } from "../netSync";
import { DEFAULT_DHCP_SERVER, type Device, type Topology } from "../topology";
import { builder, cable } from "./build";

/** IPv4 없이 IPv6 만: 같은 링크는 NDP, 다른 링크는 게이트웨이가 Hop Limit 만 줄여 넘긴다. 호스트 게이트웨이는 글로벌·링크 로컬 두 방식 */
export function exampleIpv6BasicsTopology(): Topology {
  const { devices, add } = builder();
  const pc1 = add("pc", 40, 440);
  const pc2 = add("pc", 200, 440);
  const sw1 = add("switch", 120, 280);
  const gw = add("gateway", 336, 96);
  const sw2 = add("switch", 552, 280);
  const srv = add("server", 552, 440);
  // 게이트웨이: IPv4 주소 없이 IPv6 만 (if0 은 쓰지 않음)
  const none = { ipMode: "static" as const, ip: "", prefix: 24, gateway: "" };
  gw.l3 = {
    interfaces: [none, none, none],
    routes: [],
    ipv6: { enabled: true, interfaces: [{ ip: "", prefix: 64 }, { ip: "2001:db8:1::1", prefix: 64 }, { ip: "2001:db8:2::1", prefix: 64 }], routes: [] },
  };
  const gwIf1LinkLocal = linkLocalOf(l3MacOf(gw.mac, 1));
  const v6Host = (d: Device, ip: string, gateway: string, services: number[] = []) => {
    d.host = { ipMode: "static", ip: "", prefix: 24, gateway: "", services, dhcpServer: { ...DEFAULT_DHCP_SERVER }, ipv6: { enabled: true, mode: "static", ip, prefix: 64, gateway } };
  };
  v6Host(pc1, "2001:db8:1::10", "2001:db8:1::1");
  // pc-2 는 기본 게이트웨이를 라우터의 링크 로컬로 (IPv6 에서 흔한 방식 — 라우터 광고(RA)로 받을 때도 이 주소다)
  v6Host(pc2, "2001:db8:1::11", gwIf1LinkLocal);
  v6Host(srv, "2001:db8:2::10", "2001:db8:2::1", [80]);
  return {
    devices,
    cables: [cable(pc1, 0, sw1, 0), cable(pc2, 0, sw1, 5), cable(sw1, 3, gw, 1), cable(gw, 2, sw2, 3), cable(sw2, 0, srv, 0)],
  };
}

/** SLAAC: 게이트웨이가 RA 로 프리픽스를 알리고, 자동 호스트는 DHCP 서버 없이 주소·기본 게이트웨이를 스스로 만든다. 서버는 수동 */
export function exampleSlaacTopology(): Topology {
  const { devices, add } = builder();
  const pc1 = add("pc", 8, 440);
  const laptop = add("laptop", 232, 440);
  const sw1 = add("switch", 120, 280);
  const gw = add("gateway", 336, 96);
  const sw2 = add("switch", 552, 280);
  const srv = add("server", 552, 440);
  const none = { ipMode: "static" as const, ip: "", prefix: 24, gateway: "" };
  gw.l3 = {
    interfaces: [none, none, none],
    routes: [],
    ipv6: {
      enabled: true,
      interfaces: [
        { ip: "", prefix: 64 },
        { ip: "2001:db8:1::1", prefix: 64, ra: true },
        { ip: "2001:db8:2::1", prefix: 64, ra: true },
      ],
      routes: [],
    },
  };
  const slaacHost = (d: Device) => {
    d.host = { ipMode: "static", ip: "", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER }, ipv6: { enabled: true, mode: "slaac", ip: "", prefix: 64, gateway: "" } };
  };
  slaacHost(pc1);
  slaacHost(laptop);
  // 서버는 주소가 바뀌면 안 되니 수동 (같은 링크의 RA 는 받지만 무시한다)
  srv.host = { ipMode: "static", ip: "", prefix: 24, gateway: "", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER }, ipv6: { enabled: true, mode: "static", ip: "2001:db8:2::10", prefix: 64, gateway: linkLocalOf(l3MacOf(gw.mac, 2)) } };
  return {
    devices,
    cables: [cable(pc1, 0, sw1, 0), cable(laptop, 0, sw1, 5), cable(sw1, 3, gw, 1), cable(gw, 2, sw2, 3), cable(sw2, 0, srv, 0)],
  };
}
