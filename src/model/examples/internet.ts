// 예제 묶음 "인터넷". 등록(메뉴 순서·설명)은 ../examples.ts 의 EXAMPLES.
import { type Cable, DEFAULT_DHCP_SERVER, type Device, type Topology, newId, zoneAround } from "../topology";
import { builder, cable, iface } from "./build";

/**
 * 인터넷의 뼈대: 가장자리는 트리, 중심은 그물.
 * - 가장자리: 집 공유기·회사 NAT 는 디폴트 라우트 한 줄로 동네 국사에, 국사는 다시 통신사 백본에 붙는다 ("모르면 위로").
 * - 중심: KT 백본·SK 백본·구글 망이 삼각형으로 서로 잇고 RIP 로 경로를 주고받는다 (실제 인터넷에서는 BGP 가 하는 일).
 * - 공인 DNS 8.8.8.8 은 구글 망 안에 있고, 집 공유기의 DNS 포워더가 여기로 묻는다. 인터넷 노드 없이 직접 조립한다.
 */
export function exampleInternetTopology(): Topology {
  const { devices, add } = builder();
  const rip = { enabled: true };
  const staticHost = (d: Device, ip: string, gw: string, services: number[] = []) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway: gw, services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };

  // 중심: 구글 망 (공인 DNS 8.8.8.8 이 사는 곳)
  const gSw = add("switch", 520, -216, "구글 망 스위치");
  const dns = add("server", 400, -72, "공인 DNS");
  staticHost(dns, "8.8.8.8", "8.8.8.1");
  dns.host!.dnsServer = { enabled: true, records: [{ name: "nexus.com", ip: "198.51.100.2" }], upstream: "" };
  const google = add("gateway", 592, 24, "구글 라우터");
  google.l3 = { interfaces: [iface("8.8.8.1"), iface("198.18.11.1"), iface("198.18.12.1")], routes: [], rip };
  // 중심: 통신사 백본 둘. 셋이 삼각형(그물)이라 한 줄이 끊겨도 돌아갈 길이 있다. 백본에는 디폴트 라우트가 없다 — 위가 없으므로
  const kt = add("gateway", 240, 200, "KT 백본");
  kt.l3 = { interfaces: [iface("198.18.11.2"), iface("198.18.1.1"), iface("198.18.10.1")], routes: [], rip };
  const sk = add("gateway", 944, 200, "SK 백본");
  sk.l3 = { interfaces: [iface("198.18.12.2"), iface("198.18.10.2"), iface("198.18.2.1")], routes: [], rip };

  // 가장자리: 동네 국사 → 고객. 국사는 백본으로 디폴트 라우트 + 자기 고객 대역을 RIP 로 알린다
  const ktLocal = add("gateway", 240, 376, "KT 국사");
  ktLocal.l3 = { interfaces: [iface("198.18.1.2", "198.18.1.1"), iface("203.0.113.1"), iface("")], routes: [], rip };
  const skLocal = add("gateway", 944, 376, "SK 국사");
  skLocal.l3 = { interfaces: [iface("198.18.2.2", "198.18.2.1"), iface("198.51.100.1"), iface("")], routes: [], rip };

  // 집(KT 가입): 공유기 WAN 은 고정 공인 주소 + 디폴트 라우트 = KT 국사. DNS 포워더는 8.8.8.8 로
  const home = add("router", 240, 536, "집 공유기");
  home.router = { ...home.router!, wan: { ipMode: "static", ip: "203.0.113.2", prefix: 24, gateway: "203.0.113.1" }, dns: { enabled: true, upstream: "8.8.8.8" } };
  const pc = add("pc", 184, 712, "pc-1");
  const laptop = add("laptop", 344, 712, "laptop-1");
  // 회사(SK 가입): NAT 박스 outside = 고정 공인 주소, 웹 서버는 포트 포워딩 80 으로 공개 (nexus.com)
  const coNat = add("nat", 944, 536, "회사 NAT");
  coNat.l3 = { interfaces: [iface("198.51.100.2", "198.51.100.1"), iface("10.0.0.1")], routes: [], forwards: [{ publicPort: 80, lanIp: "10.0.0.10", lanPort: 80 }] };
  const web = add("server", 988, 712, "회사 웹 서버");
  staticHost(web, "10.0.0.10", "10.0.0.1", [80]);

  const cables: Cable[] = [
    cable(gSw, 1, dns, 0),
    cable(gSw, 6, google, 0),
    cable(google, 1, kt, 0),
    cable(google, 2, sk, 0),
    cable(kt, 2, sk, 1),
    cable(kt, 1, ktLocal, 0),
    cable(sk, 2, skLocal, 0),
    cable(ktLocal, 1, home, 0),
    cable(skLocal, 1, coNat, 0),
    cable(home, 1, pc, 0),
    cable(home, 4, laptop, 0),
    cable(coNat, 1, web, 0),
  ];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "중심: 백본 그물 (RIP, 실제로는 BGP)", tint: "amber", ...zoneAround(t, [gSw.id, dns.id, google.id, kt.id, sk.id], 32)! },
    { id: newId("zone"), label: "가장자리: KT 쪽 (디폴트 라우트로 위로)", tint: "blue", ...zoneAround(t, [ktLocal.id, home.id, pc.id, laptop.id], 24)! },
    { id: newId("zone"), label: "가장자리: SK 쪽", tint: "green", ...zoneAround(t, [skLocal.id, coNat.id, web.id], 24)! },
  ];
  return t;
}

/**
 * 도메인으로 회사 웹 서버 접속: 집(DHCP 서버를 따로 둔 기능 단위 공유기)과 회사(NAT → 투명 방화벽 → 게이트웨이 → 서버 서브넷 2개)가
 * 공인 구간(203.0.113.0/24)으로 이어지고, 공인 DNS(8.8.8.8)는 ISP 라우터 너머 다른 네트워크에 있다. 인터넷 노드 없이 직접 조립한 인터넷.
 * 맥북 → nexus.com:80 = 8.8.8.8 에 질의(집 NAT → ISP 라우터) → 회사 공인 주소 → 집 NAT(출발지 변환) → 회사 NAT 포트 포워딩(목적지 변환) → 방화벽(80 만 허용) → 웹 서버
 */
export function examplePublishTopology(): Topology {
  const { devices, add } = builder();
  const staticHost = (d: Device, ip: string, gw: string, services: number[] = []) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway: gw, services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };

  // 공인 구간: 통신사 장비 두 대 (집 NAT·회사 NAT·ISP 라우터가 같은 203.0.113.0/24)
  const ispHome = add("switch", 160, -128, "통신사 (집 쪽)");
  const ispCo = add("switch", 928, -128, "통신사 (회사 쪽)");
  // ISP 라우터: 공인 구간과 공인 DNS 네트워크(8.8.8.0/24)를 잇는다. 두 NAT 의 디폴트 라우트가 여기
  const ispRt = add("gateway", 520, -24, "ISP 라우터");
  ispRt.l3 = { interfaces: [iface("203.0.113.1"), iface("8.8.8.1"), iface("")], routes: [] };
  const pubDns = add("server", 488, 168, "공인 DNS");
  staticHost(pubDns, "8.8.8.8", "8.8.8.1");
  pubDns.host!.dnsServer = { enabled: true, records: [{ name: "nexus.com", ip: "203.0.113.109" }], upstream: "" };

  // 집: NAT → 게이트웨이 → 스위치 → 맥북 · DHCP 서버 · 홈 서버. DNS 는 DHCP 가 8.8.8.8 로 안내
  const homeNat = add("nat", 160, 32, "집 NAT");
  homeNat.l3 = { interfaces: [iface("203.0.113.108", "203.0.113.1"), iface("10.0.0.1")], routes: [{ dest: "192.168.0.0", prefix: 24, via: "10.0.0.2" }] };
  const homeGw = add("gateway", 160, 176, "집 게이트웨이");
  homeGw.l3 = { interfaces: [iface("10.0.0.2", "10.0.0.1"), iface("192.168.0.1"), iface("")], routes: [] };
  const homeSw = add("switch", 160, 320, "집 스위치");
  const macbook = add("laptop", 56, 464, "맥북"); // DHCP
  const dhcp = add("server", 200, 464, "DHCP 서버");
  staticHost(dhcp, "192.168.0.2", "192.168.0.1");
  dhcp.host!.dhcpServer = { enabled: true, start: "192.168.0.100", end: "192.168.0.199", router: "192.168.0.1", dns: "8.8.8.8" };
  const homeSrv = add("server", 344, 464, "홈 서버");
  staticHost(homeSrv, "192.168.0.20", "192.168.0.1", [80]);

  // 회사: NAT(포트 포워딩 80 → 웹 서버) → 투명 방화벽 → 게이트웨이 → 서브넷 두 개
  const coNat = add("nat", 928, 32, "회사 NAT");
  coNat.l3 = {
    interfaces: [iface("203.0.113.109", "203.0.113.1"), iface("10.10.0.1")],
    routes: [
      { dest: "192.168.1.0", prefix: 24, via: "10.10.0.2" },
      { dest: "192.168.2.0", prefix: 24, via: "10.10.0.2" },
    ],
    forwards: [{ publicPort: 80, lanIp: "192.168.1.2", lanPort: 80 }],
  };
  const fw = add("firewall", 928, 144, "회사 방화벽");
  // NAT 안쪽이라 규칙은 변환된 뒤의 사설 주소로 쓴다. 바깥에서 들어오는 건 웹 서버 80 만, 안에서 시작한 통신의 응답은 Stateful 로 통과
  fw.firewall = {
    enabled: true,
    defaultPolicy: "allow",
    stateful: true,
    rules: [
      { action: "allow", proto: "tcp", direction: "in", src: "", dst: "192.168.1.2", dstPort: "80" },
      { action: "deny", proto: "any", direction: "in", src: "", dst: "", dstPort: "" },
    ],
  };
  const coGw = add("gateway", 928, 256, "회사 게이트웨이");
  coGw.l3 = { interfaces: [iface("10.10.0.2", "10.10.0.1"), iface("192.168.1.1"), iface("192.168.2.1")], routes: [] };
  const sw1 = add("switch", 792, 400, "sw-1");
  const sw2 = add("switch", 1064, 400, "sw-2");
  const web = add("server", 760, 544, "웹 서버");
  staticHost(web, "192.168.1.2", "192.168.1.1", [80]);
  const srv1 = add("server", 888, 544, "srv-1");
  staticHost(srv1, "192.168.1.3", "192.168.1.1", [80]);
  const srv2 = add("server", 1040, 544, "srv-2");
  staticHost(srv2, "192.168.2.2", "192.168.2.1", [80]);
  const srv3 = add("server", 1168, 544, "srv-3");
  staticHost(srv3, "192.168.2.3", "192.168.2.1", [80]);

  const cables: Cable[] = [
    cable(ispHome, 7, ispCo, 0),
    cable(ispHome, 1, homeNat, 0),
    cable(ispHome, 5, ispRt, 0),
    cable(ispRt, 1, pubDns, 0),
    cable(homeNat, 1, homeGw, 0),
    cable(homeGw, 1, homeSw, 3),
    cable(homeSw, 0, macbook, 0),
    cable(homeSw, 2, dhcp, 0),
    cable(homeSw, 6, homeSrv, 0),
    cable(ispCo, 6, coNat, 0),
    cable(coNat, 1, fw, 0),
    cable(fw, 1, coGw, 0),
    cable(coGw, 1, sw1, 4),
    cable(coGw, 2, sw2, 3),
    cable(sw1, 0, web, 0),
    cable(sw1, 6, srv1, 0),
    cable(sw2, 1, srv2, 0),
    cable(sw2, 7, srv3, 0),
  ];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "집 192.168.0.0/24", tint: "blue", ...zoneAround(t, [homeNat.id, homeGw.id, homeSw.id, macbook.id, dhcp.id, homeSrv.id], 24)! },
    { id: newId("zone"), label: "공인 DNS 8.8.8.0/24", tint: "amber", ...zoneAround(t, [pubDns.id], 24)! },
    { id: newId("zone"), label: "회사 (nexus.com = 203.0.113.109)", tint: "green", ...zoneAround(t, [coNat.id, fw.id, coGw.id, sw1.id, sw2.id, web.id, srv1.id, srv2.id, srv3.id], 24)! },
  ];
  return t;
}

/**
 * VPN 으로 두 사무실 잇기: 두 NAT 박스가 통신사 구간(공인 203.0.113.0/24)으로 이어지고, 서로의 사설 대역을
 * WireGuard 식 터널(UDP 51820)로 보낸다. 사설 주소끼리 NAT 없이 그대로 닿고, 인터넷 위에서는 공인 주소끼리의 UDP 만 보인다.
 * 두 사무실의 사설 대역은 달라야 한다(겹치면 어느 쪽인지 구분할 수 없다)
 */
export function exampleVpnTopology(): Topology {
  const { devices, add } = builder();
  const staticHost = (d: Device, ip: string, gw: string, services: number[] = []) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway: gw, services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  const isp = add("switch", 400, -104, "통신사 구간");
  const natA = add("nat", 160, 48, "사무실 A NAT");
  natA.l3 = { interfaces: [iface("203.0.113.11"), iface("192.168.1.1")], routes: [], vpn: { enabled: true, peer: "203.0.113.22", remote: [{ dest: "192.168.2.0", prefix: 24 }] } };
  const natB = add("nat", 640, 48, "사무실 B NAT");
  natB.l3 = { interfaces: [iface("203.0.113.22"), iface("192.168.2.1")], routes: [], vpn: { enabled: true, peer: "203.0.113.11", remote: [{ dest: "192.168.1.0", prefix: 24 }] } };
  const swA = add("switch", 160, 208, "sw-a");
  const swB = add("switch", 640, 208, "sw-b");
  const pcA = add("pc", 128, 368, "pc-a");
  const srvA = add("server", 256, 368, "srv-a");
  const pcB = add("pc", 608, 368, "pc-b");
  const srvB = add("server", 736, 368, "srv-b");
  staticHost(pcA, "192.168.1.10", "192.168.1.1");
  staticHost(srvA, "192.168.1.20", "192.168.1.1", [80]);
  staticHost(pcB, "192.168.2.10", "192.168.2.1");
  staticHost(srvB, "192.168.2.20", "192.168.2.1", [80]);
  const cables: Cable[] = [
    cable(isp, 1, natA, 0),
    cable(isp, 6, natB, 0),
    cable(natA, 1, swA, 3),
    cable(natB, 1, swB, 3),
    cable(swA, 1, pcA, 0),
    cable(swA, 6, srvA, 0),
    cable(swB, 1, pcB, 0),
    cable(swB, 6, srvB, 0),
  ];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "사무실 A 192.168.1.0/24", tint: "blue", ...zoneAround(t, [natA.id, swA.id, pcA.id, srvA.id], 24)! },
    { id: newId("zone"), label: "사무실 B 192.168.2.0/24", tint: "green", ...zoneAround(t, [natB.id, swB.id, pcB.id, srvB.id], 24)! },
  ];
  return t;
}

/**
 * 망분리 사무실 + NCP(네이버 클라우드) IPsec VPN.
 * - 사무실: 내부망(업무망)·외부망(인터넷망)이 회선·방화벽·게이트웨이·스위치까지 따로. 실물은 망마다 방화벽 한 대가
 *   NAT·방화벽·라우팅을 다 하지만, 여기서는 역할별로 나누고 사이를 /30 연결 구간(10.255.0.0/30, 10.255.0.4/30)으로 잇는다.
 * - 내부망 방화벽 NAT 가 NCP VPN Gateway 와 IPsec 터널(IKE → ESP)을 맺어, 내부망 PC 가 NCP 서버에 사설 주소로 SSH(22) 한다.
 *   외부망에서는 NCP 서버에 닿지 않는다 (터널 대역이 아님).
 * - NCP: VPN Gateway(방화벽 = ACG 역할: 사무실 내부망에서 오는 SSH·ping 만 허용) 뒤에 Dev VPC(서브넷 3개)와 Prod VPC.
 * 공인 주소는 예시 대역(203.0.113.0/24).
 */
export function exampleNcpVpnTopology(): Topology {
  const { devices, add } = builder();
  const staticHost = (d: Device, ip: string, gw: string, services: number[] = [], prefix = 24) => {
    d.host = { ipMode: "static", ip, prefix, gateway: gw, dns: "8.8.8.8", services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  const dhcpHost = (d: Device) => {
    d.host = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  const denyIn = { enabled: true, defaultPolicy: "deny" as const, stateful: true, rules: [{ action: "allow" as const, proto: "any" as const, direction: "out" as const, src: "", dst: "", dstPort: "" }] };
  const PSK = "office-ncp-psk";

  // 인터넷: 통신사 구간(203.0.113.0/24) — 사무실 회선 두 개와 NCP 가 여기로 나간다
  const inet = add("internet", 728, -600, "internet-1");
  const isp = add("switch", 720, -480, "통신사 구간");
  const modemA = add("switch", 400, -200, "KT 모뎀 (내부망 회선)");
  const modemB = add("switch", 672, -200, "KT 모뎀 (외부망 회선)");
  const meeting = add("switch", 944, -160, "회의실 스위치");
  const printer = add("pc", 1256, -168, "프린터");
  dhcpHost(printer);

  // 내부망(업무망): 방화벽 NAT(IPsec) → 방화벽 → 게이트웨이 → 스위치 두 대(적층) → 고정 주소 PC·맥북
  const natIn = add("nat", 680, 24, "내부망 방화벽 NAT");
  natIn.l3 = {
    interfaces: [iface("203.0.113.11", "203.0.113.1"), { ipMode: "static", ip: "10.255.0.1", prefix: 30, gateway: "" }],
    routes: [{ dest: "10.50.10.0", prefix: 24, via: "10.255.0.2" }],
    vpn: {
      enabled: true,
      mode: "ipsec",
      psk: PSK,
      peer: "203.0.113.50",
      remote: [
        { dest: "192.168.111.0", prefix: 24 },
        { dest: "192.168.112.0", prefix: 24 },
        { dest: "192.168.113.0", prefix: 24 },
        { dest: "172.21.4.0", prefix: 24 },
      ],
    },
  };
  const fwIn = add("firewall", 680, 104, "내부망 방화벽");
  fwIn.firewall = denyIn;
  const gwIn = add("gateway", 680, 184, "내부망 게이트웨이");
  gwIn.l3 = { interfaces: [{ ipMode: "static", ip: "10.255.0.2", prefix: 30, gateway: "10.255.0.1" }, iface("10.50.10.254"), iface("")], routes: [] };
  const swIn1 = add("switch", 552, 288, "내부망 스위치 1");
  const swIn2 = add("switch", 712, 288, "내부망 스위치 2");
  const macbook2 = add("laptop", 344, 520, "맥북 2");
  const macbook1 = add("laptop", 456, 520, "맥북 1");
  const pcIn1 = add("pc", 568, 520, "내부망 PC 1");
  const pcIn2 = add("pc", 680, 520, "내부망 PC 2");
  const pcIn3 = add("pc", 792, 520, "내부망 PC 3");
  staticHost(pcIn1, "10.50.10.1", "10.50.10.254");
  staticHost(pcIn2, "10.50.10.2", "10.50.10.254");
  staticHost(pcIn3, "10.50.10.3", "10.50.10.254");
  staticHost(macbook1, "10.50.10.16", "10.50.10.254");
  staticHost(macbook2, "10.50.10.17", "10.50.10.254");

  // 외부망(인터넷망): 방화벽 NAT(유동 IP, DHCP) → 방화벽 → 게이트웨이 → 스위치 두 대 → DHCP 서버·PC·Wi-Fi
  const natOut = add("nat", 936, 24, "외부망 방화벽 NAT");
  natOut.l3 = {
    interfaces: [{ ipMode: "dhcp", ip: "", prefix: 24, gateway: "" }, { ipMode: "static", ip: "10.255.0.5", prefix: 30, gateway: "" }],
    routes: [{ dest: "192.168.100.0", prefix: 24, via: "10.255.0.6" }],
  };
  const fwOut = add("firewall", 936, 104, "외부망 방화벽");
  fwOut.firewall = { ...denyIn, rules: [...denyIn.rules] };
  const gwOut = add("gateway", 936, 184, "외부망 게이트웨이");
  gwOut.l3 = { interfaces: [{ ipMode: "static", ip: "10.255.0.6", prefix: 30, gateway: "10.255.0.5" }, iface("192.168.100.254"), iface("")], routes: [] };
  const swOut1 = add("switch", 888, 288, "외부망 스위치 1");
  const swOut2 = add("switch", 1048, 288, "외부망 스위치 2");
  const dhcpSrv = add("server", 1224, 280, "외부망 DHCP 서버");
  staticHost(dhcpSrv, "192.168.100.1", "192.168.100.254");
  dhcpSrv.host!.dhcpServer = { enabled: true, start: "192.168.100.2", end: "192.168.100.253", router: "192.168.100.254", dns: "8.8.8.8" };
  const ap = add("ap", 1200, 200, "wifi");
  ap.ap = { enabled: true, ssid: "office_5G" };
  const pcOut1 = add("pc", 904, 520, "외부망 PC 1");
  const pcOut2 = add("pc", 1016, 520, "외부망 PC 2");
  const pcOut3 = add("pc", 1128, 520, "외부망 PC 3");
  const phone1 = add("phone", 1472, 208, "phone-1");
  const phone2 = add("phone", 1432, 336, "phone-2");
  for (const d of [pcOut1, pcOut2, pcOut3, phone1, phone2]) dhcpHost(d);
  phone1.wifi = { ssid: "office_5G" };
  phone2.wifi = { ssid: "office_5G" };

  // NCP: VPN Gateway(IPsec, ACG 역할 방화벽) → VPC 연결 → Dev VPC 라우터(서브넷 3개, VLAN 으로 나눔) / Prod VPC 라우터
  const ncpInet = add("switch", 1840, -480, "인터넷 (NCP 쪽)");
  const ncpGw = add("nat", 1840, -360, "NCP VPN Gateway");
  ncpGw.l3 = {
    interfaces: [iface("203.0.113.50", "203.0.113.1"), iface("10.250.0.1")],
    routes: [
      { dest: "192.168.0.0", prefix: 16, via: "10.250.0.2" },
      { dest: "172.21.0.0", prefix: 16, via: "10.250.0.3" },
    ],
    vpn: { enabled: true, mode: "ipsec", psk: PSK, peer: "203.0.113.11", remote: [{ dest: "10.50.10.0", prefix: 24 }] },
    // ACG 역할: 사무실 내부망에서 터널로 들어오는 SSH·ping 만 허용, 서버가 나가는 것은 허용 (응답은 Stateful 검사로)
    firewall: {
      enabled: true,
      defaultPolicy: "deny",
      stateful: true,
      rules: [
        { action: "allow", proto: "tcp", direction: "in", src: "10.50.10.0/24", dst: "", dstPort: "22" },
        { action: "allow", proto: "icmp", direction: "in", src: "10.50.10.0/24", dst: "", dstPort: "" },
        { action: "allow", proto: "any", direction: "out", src: "", dst: "", dstPort: "" },
      ],
    },
  };
  const ncpSw = add("switch", 1840, -240, "NCP VPC 연결");
  const devRt = add("gateway", 1720, -120, "Dev VPC 라우터");
  devRt.l3 = {
    interfaces: [iface("10.250.0.2", "10.250.0.1"), iface(""), iface("")],
    routes: [],
    subinterfaces: [
      { port: 1, vlan: 111, ip: "192.168.111.1", prefix: 24, relay: "" },
      { port: 1, vlan: 112, ip: "192.168.112.1", prefix: 24, relay: "" },
      { port: 1, vlan: 113, ip: "192.168.113.1", prefix: 24, relay: "" },
    ],
  };
  const prodRt = add("gateway", 2000, -120, "Prod VPC 라우터");
  prodRt.l3 = { interfaces: [iface("10.250.0.3", "10.250.0.1"), iface("172.21.4.1"), iface("")], routes: [] };
  const devSw = add("switch", 1720, 0, "Dev 서브넷 스위치");
  devSw.switch = { vlans: { 0: "trunk", 1: 111, 3: 112, 5: 113 } };
  const dev1 = add("server", 1592, 144, "dev-1");
  const dev2 = add("server", 1720, 144, "dev-2");
  const dev3 = add("server", 1848, 144, "dev-3");
  const prod = add("server", 2000, 40, "prod");
  staticHost(dev1, "192.168.111.11", "192.168.111.1", [22]);
  staticHost(dev2, "192.168.112.11", "192.168.112.1", [22]);
  staticHost(dev3, "192.168.113.11", "192.168.113.1", [22]);
  staticHost(prod, "172.21.4.11", "172.21.4.1", [22]);

  const cables: Cable[] = [
    cable(isp, 4, inet, 0),
    cable(isp, 0, modemA, 1),
    cable(isp, 7, modemB, 1),
    cable(isp, 6, ncpInet, 0),
    cable(modemA, 3, natIn, 0),
    cable(modemB, 0, meeting, 0),
    cable(meeting, 7, printer, 0),
    cable(meeting, 1, natOut, 0),
    cable(natIn, 1, fwIn, 0),
    cable(fwIn, 1, gwIn, 0),
    cable(gwIn, 1, swIn2, 1),
    cable(swIn1, 7, swIn2, 0),
    cable(swIn2, 6, macbook2, 0),
    cable(swIn2, 7, macbook1, 0),
    cable(swIn1, 4, pcIn1, 0),
    cable(swIn2, 4, pcIn2, 0),
    cable(swIn2, 5, pcIn3, 0),
    cable(natOut, 1, fwOut, 0),
    cable(fwOut, 1, gwOut, 0),
    cable(gwOut, 1, swOut1, 6),
    cable(swOut1, 7, swOut2, 0),
    cable(swOut1, 0, pcOut1, 0),
    cable(swOut1, 1, pcOut2, 0),
    cable(swOut2, 1, pcOut3, 0),
    cable(swOut2, 7, dhcpSrv, 0),
    cable(swOut2, 6, ap, 0),
    cable(ncpInet, 4, ncpGw, 0),
    cable(ncpGw, 1, ncpSw, 3),
    cable(ncpSw, 1, devRt, 0),
    cable(ncpSw, 6, prodRt, 0),
    cable(devRt, 1, devSw, 0), // 트렁크 (VLAN 111·112·113)
    cable(devSw, 1, dev1, 0),
    cable(devSw, 3, dev2, 0),
    cable(devSw, 5, dev3, 0),
    cable(prodRt, 1, prod, 0),
  ];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "인터넷", tint: "amber", ...zoneAround(t, [inet.id, isp.id], 24)! },
    { id: newId("zone"), label: "사무실 네트워크 랙", tint: "blue", ...zoneAround(t, [natIn.id, fwIn.id, gwIn.id, natOut.id, fwOut.id, gwOut.id, swIn1.id, swIn2.id, swOut1.id, swOut2.id], 24)! },
    { id: newId("zone"), label: "내부망 방화벽 장비", tint: "amber", ...zoneAround(t, [natIn.id, fwIn.id, gwIn.id], 12)! },
    { id: newId("zone"), label: "외부망 방화벽 장비", tint: "amber", ...zoneAround(t, [natOut.id, fwOut.id, gwOut.id], 12)! },
    { id: newId("zone"), label: "NCP (네이버 클라우드)", tint: "green", ...zoneAround(t, [ncpInet.id, ncpGw.id, ncpSw.id, devRt.id, prodRt.id, devSw.id, dev1.id, dev2.id, dev3.id, prod.id], 32)! },
    { id: newId("zone"), label: "Dev VPC", tint: "blue", ...zoneAround(t, [devRt.id, devSw.id, dev1.id, dev2.id, dev3.id], 16)! },
    { id: newId("zone"), label: "Prod VPC", tint: "amber", ...zoneAround(t, [prodRt.id, prod.id], 16)! },
  ];
  return t;
}

/**
 * 재택근무 원격 접속 VPN: 집 공유기 뒤의 노트북이 인터넷 너머 회사 VPN 방화벽에 붙어 가상 주소(10.99.0.x)를 받고,
 * 사내 대역(10.50.10.0/24)으로 가는 것만 터널로 보낸다(split tunnel). 공유기 NAT 뒤라 UDP 4500 (NAT-T) 로 간다.
 * 서버는 PSK 확인 뒤 사용자 계정(kim·lee)을 EAP 로 확인한다 — 노트북은 kim 으로 접속.
 * 회사 방화벽은 인바운드 기본 차단이지만 VPN 가상 주소 대역에서 들어오는 것은 허용한다.
 */
export function exampleRemoteVpnTopology(): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 344, -296, "internet-1");
  const isp = add("switch", 344, -168, "통신사 구간");
  // 집: 공유기(WAN 은 통신사 DHCP, LAN 은 DHCP 로 노트북에 주소) + 재택 노트북
  const home = add("router", 120, -24, "집 공유기");
  const laptop = add("laptop", 120, 152, "재택 노트북");
  laptop.host = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER }, ra: { enabled: true, server: "203.0.113.11", psk: "remote-psk", user: "kim", password: "kim-pass" } };
  // 회사: VPN 방화벽(NAT 박스, 원격 접속 VPN 서버) → 사내 스위치 → 사내 서버·PC
  const fw = add("nat", 568, -24, "회사 VPN 방화벽");
  fw.l3 = {
    interfaces: [iface("203.0.113.11", "203.0.113.1"), iface("10.50.10.1")],
    routes: [],
    firewall: {
      enabled: true,
      defaultPolicy: "deny",
      stateful: true,
      rules: [
        { action: "allow", proto: "any", direction: "out", src: "", dst: "", dstPort: "" },
        { action: "allow", proto: "any", direction: "in", src: "10.99.0.0/24", dst: "10.50.10.0/24", dstPort: "" },
      ],
    },
    // PSK 는 회사 공통, 계정은 사람마다 (퇴사자는 그 계정만 지우면 된다)
    ra: {
      enabled: true,
      psk: "remote-psk",
      poolStart: "10.99.0.10",
      poolEnd: "10.99.0.50",
      routes: [{ dest: "10.50.10.0", prefix: 24 }],
      users: [
        { name: "kim", password: "kim-pass" },
        { name: "lee", password: "lee-pass" },
      ],
    },
  };
  const sw = add("switch", 568, 136, "사내 스위치");
  const srv = add("server", 480, 296, "사내 서버");
  srv.host = { ipMode: "static", ip: "10.50.10.20", prefix: 24, gateway: "10.50.10.1", services: [22, 80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const pc = add("pc", 656, 296, "사내 PC");
  pc.host = { ipMode: "static", ip: "10.50.10.30", prefix: 24, gateway: "10.50.10.1", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const cables: Cable[] = [
    cable(isp, 3, inet, 0),
    cable(isp, 1, home, 0),
    cable(isp, 6, fw, 0),
    cable(home, 1, laptop, 0),
    cable(fw, 1, sw, 3),
    cable(sw, 1, srv, 0),
    cable(sw, 6, pc, 0),
  ];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "집", tint: "green", ...zoneAround(t, [home.id, laptop.id], 24)! },
    { id: newId("zone"), label: "회사 10.50.10.0/24 (VPN 가상 주소 10.99.0.x)", tint: "blue", ...zoneAround(t, [fw.id, sw.id, srv.id, pc.id], 24)! },
  ];
  return t;
}

/**
 * ipTIME 공유기 VPN (L2TP/IPsec): 출장지 호텔의 노트북이 집 공유기의 VPN 서버에 붙어 집 LAN 의 한 기기가 된다.
 * - 회사 VPN(재택근무 예제)은 전용 장비가 사내 대역만 터널로 받지만(split tunnel), 집 공유기 VPN 은 공유기에 내장돼 있고
 *   노트북이 집 LAN 주소(할당 IP 192.168.0.50~)를 받아 모든 트래픽이 집으로 간다(full tunnel) — 해외에서도 집 공인 주소(한국 IP)로 인터넷에 나간다
 * - IPsec(사전 공유 키)이 바깥 통로를 암호화하고, 그 안의 L2TP·PPP 가 계정 확인·주소 할당을 한다. 호텔 공유기 NAT 뒤라 UDP 4500 (NAT-T)
 * - 집 공유기 WAN 은 수동 공인 주소 (실제 가정은 주소가 바뀌어 DDNS 이름 xxx.iptime.org 로 접속한다)
 */
export function exampleIptimeVpnTopology(): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 344, -296, "internet-1");
  const isp = add("switch", 344, -168, "통신사 구간");
  // 출장지: 호텔 공유기(WAN 은 통신사 DHCP, 손님 LAN 10.10.0.0/24) + 출장 노트북
  const hotel = add("router", 120, -24, "호텔 공유기");
  hotel.router = { ...hotel.router!, lanIp: "10.10.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "10.10.0.100", end: "10.10.0.199" } };
  const laptop = add("laptop", 120, 152, "출장 노트북");
  // Windows 의 "L2TP/IPsec 및 미리 공유한 키" — 서버 주소·사전 공유 키·계정
  laptop.host = {
    ipMode: "dhcp",
    ip: "",
    prefix: 24,
    gateway: "",
    services: [],
    dhcpServer: { ...DEFAULT_DHCP_SERVER },
    ra: { enabled: true, type: "l2tp", server: "203.0.113.20", psk: "home-psk", user: "me", password: "my-pass" },
  };
  // 집: ipTIME 공유기(VPN 서버 켬) + NAS
  const home = add("router", 568, -24, "집 ipTIME");
  home.router = {
    ...home.router!,
    wan: { ipMode: "static", ip: "203.0.113.20", prefix: 24, gateway: "203.0.113.1" },
    // 할당 IP 는 DHCP 범위(100~199) 밖의 LAN 주소
    vpnServer: { enabled: true, psk: "home-psk", poolStart: "192.168.0.50", poolEnd: "192.168.0.59", users: [{ name: "me", password: "my-pass" }] },
  };
  const nas = add("server", 568, 152, "집 NAS");
  nas.host = { ipMode: "static", ip: "192.168.0.20", prefix: 24, gateway: "192.168.0.1", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const cables: Cable[] = [cable(isp, 3, inet, 0), cable(isp, 1, hotel, 0), cable(isp, 6, home, 0), cable(hotel, 1, laptop, 0), cable(home, 1, nas, 0)];
  const t: Topology = { devices, cables };
  t.zones = [
    // 공유기 위로 서비스 배지가 세 줄 쌓이므로 위쪽 여백을 넉넉히 (이름표가 배지에 겹치지 않게)
    { id: newId("zone"), label: "출장지 호텔 10.10.0.0/24", tint: "green", ...zoneAround(t, [hotel.id, laptop.id], 56)! },
    { id: newId("zone"), label: "집 192.168.0.0/24 · VPN 할당 .50~.59", tint: "blue", ...zoneAround(t, [home.id, nas.id], 56)! },
  ];
  return t;
}

/**
 * NAT 종류와 홀 펀칭 (P2P): 화상 통화·게임처럼 NAT 뒤끼리 직접 잇는 방법.
 * - 집 A·집 B 공유기는 port-restricted cone (가정용 공유기에 흔함): 두 쪽이 동시에 보내면(홀 펀칭) 직접 연결된다
 * - 지영 노트북은 통신사 CGNAT(symmetric, 100.64.0.0/10) 뒤 — 상대마다 바깥 포트가 바뀌어 STUN 이 알려 준 주소가 맞지 않는다 → TURN 릴레이
 * - 인터넷 노드가 STUN 서버 두 곳(198.51.100.30·31), 시그널링 서버(198.51.100.40), TURN 릴레이(198.51.100.50)를 흉내 낸다
 */
export function exampleNatTraversalTopology(): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 520, -456);
  const isp = add("switch", 520, -320, "통신사 구간");
  const homeA = add("router", 104, -64, "집 A 공유기");
  // 집 NAS: 바깥에서 공인 주소:8080 으로 들어오게 포트 포워딩. 안에서 같은 주소로 접속하려면 헤어핀 NAT 가 필요하다
  homeA.router = { ...homeA.router!, natType: "port-restricted", forwards: [{ publicPort: 8080, lanIp: "192.168.0.20", lanPort: 80 }] };
  const minsu = add("pc", 40, 120, "민수 PC");
  minsu.host = { ...minsu.host!, p2p: { enabled: true, name: "minsu" } };
  const nas = add("server", 248, 120, "집 NAS");
  nas.host = { ipMode: "static", ip: "192.168.0.20", prefix: 24, gateway: "192.168.0.1", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const homeB = add("router", 600, -64, "집 B 공유기");
  homeB.router = { ...homeB.router!, natType: "port-restricted" };
  const hyunwoo = add("pc", 504, 120, "현우 PC");
  hyunwoo.host = { ...hyunwoo.host!, p2p: { enabled: true, name: "hyunwoo" } };
  // 통신사 CGNAT: 고객에게 100.64.x(공유 주소)를 주고 공인 주소 하나로 여러 고객을 내보낸다 — 대개 symmetric
  const cgnat = add("nat", 1104, -64, "통신사 CGNAT");
  cgnat.l3 = {
    interfaces: [iface("203.0.113.30", "203.0.113.1"), { ipMode: "static", ip: "100.64.0.1", prefix: 24, gateway: "" }],
    routes: [],
    natType: "symmetric",
  };
  const jiyoung = add("laptop", 936, 120, "지영 노트북");
  jiyoung.host = { ipMode: "static", ip: "100.64.0.10", prefix: 24, gateway: "100.64.0.1", dns: "8.8.8.8", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER }, p2p: { enabled: true, name: "jiyoung" } };
  const cables: Cable[] = [cable(isp, 3, inet, 0), cable(isp, 0, homeA, 0), cable(isp, 4, homeB, 0), cable(isp, 7, cgnat, 0), cable(homeA, 1, minsu, 0), cable(homeA, 2, nas, 0), cable(homeB, 1, hyunwoo, 0), cable(cgnat, 1, jiyoung, 0)];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "집 A · port-restricted cone", tint: "green", ...zoneAround(t, [homeA.id, minsu.id, nas.id], 40)! },
    { id: newId("zone"), label: "집 B · port-restricted cone", tint: "blue", ...zoneAround(t, [homeB.id, hyunwoo.id], 40)! },
    { id: newId("zone"), label: "모바일 · CGNAT symmetric", tint: "gray", ...zoneAround(t, [cgnat.id, jiyoung.id], 40)! },
  ];
  return t;
}
