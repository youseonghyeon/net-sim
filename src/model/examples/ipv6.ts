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

/** 듀얼 스택 사무실: 같은 이름에 A·AAAA, AAAA 우선, AAAA 없는 이름은 A 로, IPv6 가 막히면 IPv4 로 (Happy Eyeballs 축소판) */
export function exampleDualStackTopology(): Topology {
  const { devices, add } = builder();
  const pc1 = add("pc", 8, 440);
  const laptop = add("laptop", 232, 440);
  const sw1 = add("switch", 120, 280);
  const gw = add("gateway", 400, 96);
  const sw2 = add("switch", 680, 280);
  const dns = add("server", 488, 440, "dns-1");
  const web = add("server", 680, 440, "web-1");
  const old = add("server", 872, 440, "old-1");
  gw.l3 = {
    interfaces: [
      { ipMode: "static", ip: "", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "192.168.1.1", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "192.168.2.1", prefix: 24, gateway: "" },
    ],
    routes: [],
    ipv6: {
      enabled: true,
      interfaces: [
        { ip: "", prefix: 64 },
        { ip: "2001:db8:1::1", prefix: 64, ra: true },
        { ip: "2001:db8:2::1", prefix: 64, ra: true },
      ],
      routes: [],
      raDns: "2001:db8:2::53",
    },
    // 켜면 IPv6 웹만 막힌다 → 이름으로 연 연결이 IPv6 로 먼저 시도했다가 IPv4 로 다시 붙는다
    firewall: { enabled: false, defaultPolicy: "allow", stateful: true, rules: [{ action: "deny", proto: "tcp", direction: "any", src: "", dst: "2001:db8:2::10", dstPort: "80" }] },
  };
  const base = { prefix: 24, services: [] as number[], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  // pc-1: IPv4 수동 + IPv6 자동(SLAAC). DNS 는 IPv4 서버를 먼저 쓴다 (AAAA 도 IPv4 로 묻는다)
  pc1.host = { ...base, ipMode: "static", ip: "192.168.1.10", gateway: "192.168.1.1", dns: "192.168.2.53", ipv6: { enabled: true, mode: "slaac", ip: "", prefix: 64, gateway: "" } };
  // 노트북: IPv4 없이 IPv6 만 — DNS 는 RA 의 RDNSS(2001:db8:2::53)로 받아 IPv6 로 묻는다
  laptop.host = { ...base, ipMode: "static", ip: "", gateway: "", ipv6: { enabled: true, mode: "slaac", ip: "", prefix: 64, gateway: "" } };
  const gwIf2 = linkLocalOf(l3MacOf(gw.mac, 2));
  dns.host = {
    ...base,
    ipMode: "static",
    ip: "192.168.2.53",
    gateway: "192.168.2.1",
    ipv6: { enabled: true, mode: "static", ip: "2001:db8:2::53", prefix: 64, gateway: gwIf2 },
    dnsServer: {
      enabled: true,
      records: [
        { name: "web.corp", ip: "192.168.2.10" },
        { name: "web.corp", ip: "2001:db8:2::10" },
        { name: "old.corp", ip: "192.168.2.20" },
      ],
      upstream: "",
    },
  };
  web.host = { ...base, ipMode: "static", ip: "192.168.2.10", gateway: "192.168.2.1", services: [80], ipv6: { enabled: true, mode: "static", ip: "2001:db8:2::10", prefix: 64, gateway: gwIf2 } };
  // old-1: IPv4 만 (IPv6 꺼짐) — AAAA 레코드도 없다
  old.host = { ...base, ipMode: "static", ip: "192.168.2.20", gateway: "192.168.2.1", services: [80] };
  return {
    devices,
    cables: [cable(pc1, 0, sw1, 0), cable(laptop, 0, sw1, 5), cable(sw1, 3, gw, 1), cable(gw, 2, sw2, 3), cable(sw2, 0, dns, 0), cable(sw2, 4, web, 0), cable(sw2, 7, old, 0)],
  };
}

/** 듀얼 스택 집: 공유기가 ISP 에게 /56 을 위임받아(DHCPv6-PD) LAN 에 /64 를 RA 로 알리고, IPv6 는 NAT 없이 나간다. 들어오는 것은 인바운드 기본 차단이 막는다 */
export function exampleDualStackHomeTopology(): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 344, -40);
  const rt = add("router", 344, 96);
  const sw = add("switch", 344, 272);
  const pc = add("pc", 136, 440);
  const laptop = add("laptop", 360, 440);
  const srv = add("server", 584, 440);
  rt.router = { ...rt.router!, ipv6: { enabled: true, inboundBlock: true } };
  // 세 장치 모두 IPv4 는 공유기 DHCP, IPv6 는 공유기 RA 로 SLAAC
  const slaac = { enabled: true, mode: "slaac" as const, ip: "", prefix: 64, gateway: "" };
  for (const d of [pc, laptop, srv]) d.host = { ...d.host!, ipv6: { ...slaac } };
  srv.host = { ...srv.host!, services: [80] };
  return {
    devices,
    cables: [cable(inet, 0, rt, 0), cable(rt, 1, sw, 0), cable(sw, 2, pc, 0), cable(sw, 4, laptop, 0), cable(sw, 6, srv, 0)],
  };
}
