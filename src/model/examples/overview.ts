// 예제 묶음 "종합". 등록(메뉴 순서·설명)은 ../examples.ts 의 EXAMPLES.
import { type Cable, DEFAULT_DHCP_SERVER, type Device, type Topology, newId, zoneAround } from "../topology";
import { builder, cable } from "./build";

/**
 * 중소기업 전체: 앞의 예제들이 한 그림에 모인다.
 * - 본사: 경계 방화벽(NAT 박스 — 포트 포워딩·Stateful 방화벽·지사와 사이트 간 IPsec·재택 원격 접속 VPN 서버)
 *   → 코어 게이트웨이(서버망 + 트렁크 위 VLAN 10 사무실 · VLAN 30 손님 Wi-Fi, DHCP 릴레이, 손님 → 사내 차단)
 *   → 서버망(웹 로드밸런서 + 웹 2대, 사내 위키, 사내 DNS·DHCP 서버)
 * - 지사: NAT 박스가 본사와 IPsec 으로 이어져 사내 DNS·위키를 사설 주소로 쓴다
 * - 재택: 집 공유기 뒤 노트북이 원격 접속 VPN(IKEv2, 계정 kim)으로 붙는다
 * - 카페: 고객 폰이 카페 Wi-Fi 에서 회사 공인 주소:80 으로 들어온다 (포트 포워딩 → 로드밸런서)
 */
export function exampleCompanyTopology(): Topology {
  const { devices, add } = builder();
  const host = (d: Device, ip: string, gateway: string, dns: string, services: number[] = []) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway, dns, services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  const inet = add("internet", 936, -656);
  const isp = add("switch", 936, -516, "통신사 구간");

  // ---------- 카페 (고객) ----------
  const cafe = add("router", 40, -300, "카페 공유기");
  cafe.router = { ...cafe.router!, wifi: { enabled: true, ssid: "cafe" } };
  const guestPhone = add("phone", 100, -96, "고객 폰");
  guestPhone.wifi = { ssid: "cafe" };

  // ---------- 재택 ----------
  const home = add("router", 320, -300, "재택 집 공유기");
  const laptop = add("laptop", 364, -112, "재택 노트북");
  laptop.host = { ...laptop.host!, ra: { enabled: true, server: "203.0.113.10", psk: "remote-psk", user: "kim", password: "kim-pass" } };

  // ---------- 본사 ----------
  const edge = add("nat", 936, -220, "본사 방화벽");
  edge.l3 = {
    interfaces: [
      { ipMode: "static", ip: "203.0.113.10", prefix: 24, gateway: "203.0.113.1" },
      { ipMode: "static", ip: "10.1.0.1", prefix: 24, gateway: "" },
    ],
    // 안쪽 대역은 코어 게이트웨이 뒤
    routes: [{ dest: "10.1.0.0", prefix: 16, via: "10.1.0.2" }],
    // 회사 웹: 공인 :80 → 로드밸런서
    forwards: [{ publicPort: 80, lanIp: "10.1.20.10", lanPort: 80 }],
    firewall: {
      enabled: true,
      defaultPolicy: "deny",
      stateful: true,
      rules: [
        { action: "allow", proto: "any", direction: "out", src: "", dst: "", dstPort: "" },
        { action: "allow", proto: "tcp", direction: "in", src: "", dst: "10.1.20.10", dstPort: "80" },
        { action: "allow", proto: "any", direction: "in", src: "10.2.0.0/24", dst: "10.1.0.0/16", dstPort: "" },
        { action: "allow", proto: "any", direction: "in", src: "10.99.0.0/24", dst: "10.1.0.0/16", dstPort: "" },
      ],
    },
    vpn: { enabled: true, mode: "ipsec", psk: "branch-psk", peer: "203.0.113.20", remote: [{ dest: "10.2.0.0", prefix: 24 }] },
    ra: { enabled: true, psk: "remote-psk", poolStart: "10.99.0.10", poolEnd: "10.99.0.30", routes: [{ dest: "10.1.0.0", prefix: 16 }], users: [{ name: "kim", password: "kim-pass" }] },
  };
  const core = add("gateway", 936, -60, "본사 코어");
  core.l3 = {
    interfaces: [
      { ipMode: "static", ip: "10.1.0.2", prefix: 24, gateway: "10.1.0.1" },
      { ipMode: "static", ip: "10.1.20.1", prefix: 24, gateway: "" }, // if1: 서버망
      { ipMode: "static", ip: "", prefix: 24, gateway: "" }, // if2: 사무실 스위치로 가는 트렁크 (서브 인터페이스만)
    ],
    routes: [],
    subinterfaces: [
      { port: 2, vlan: 10, ip: "10.1.10.1", prefix: 24, relay: "10.1.20.53" }, // 사무실
      { port: 2, vlan: 30, ip: "10.1.30.1", prefix: 24, relay: "10.1.20.53" }, // 손님 Wi-Fi
    ],
    // 손님 Wi-Fi 는 인터넷만: 사내 대역으로는 막는다
    firewall: {
      enabled: true,
      defaultPolicy: "allow",
      stateful: true,
      rules: [{ action: "deny", proto: "any", direction: "any", src: "10.1.30.0/24", dst: "10.1.0.0/16", dstPort: "" }],
    },
  };
  const srvSw = add("switch", 712, 112, "서버 스위치");
  const lb = add("lb", 584, 280, "웹 LB");
  host(lb, "10.1.20.10", "10.1.20.1", "10.1.20.53");
  lb.host!.lb = { enabled: true, port: 80, algorithm: "round-robin", backends: [{ ip: "10.1.20.11", port: 80 }, { ip: "10.1.20.12", port: 80 }] };
  const web1 = add("server", 680, 280, "web-1");
  const web2 = add("server", 776, 280, "web-2");
  host(web1, "10.1.20.11", "10.1.20.1", "10.1.20.53", [80]);
  host(web2, "10.1.20.12", "10.1.20.1", "10.1.20.53", [80]);
  const wiki = add("server", 872, 280, "사내 위키");
  host(wiki, "10.1.20.20", "10.1.20.1", "10.1.20.53", [80, 22]);
  const infra = add("server", 968, 280, "사내 DNS·DHCP");
  host(infra, "10.1.20.53", "10.1.20.1", "8.8.8.8");
  infra.host!.dhcpServer = {
    enabled: true,
    start: "10.1.20.200",
    end: "10.1.20.220",
    router: "10.1.20.1",
    dns: "10.1.20.53",
    // 릴레이(코어 게이트웨이)를 거쳐 오는 사무실·손님 Wi-Fi 풀. 손님에게는 사내 DNS 대신 공인 DNS
    extraPools: [
      { start: "10.1.10.100", end: "10.1.10.199", prefix: 24, router: "10.1.10.1", dns: "10.1.20.53" },
      { start: "10.1.30.100", end: "10.1.30.199", prefix: 24, router: "10.1.30.1", dns: "8.8.8.8" },
    ],
  };
  infra.host!.dnsServer = {
    enabled: true,
    records: [
      { name: "intranet.corp", ip: "10.1.20.20" },
      { name: "www.corp", ip: "10.1.20.10" },
    ],
    upstream: "8.8.8.8",
  };
  const officeSw = add("switch", 1160, 112, "사무실 스위치");
  officeSw.switch = { vlans: { 0: "trunk", 1: 10, 2: 10, 6: 30 } };
  const pc1 = add("pc", 1128, 280, "사무 PC-1");
  const pc2 = add("pc", 1224, 280, "사무 PC-2");
  const ap = add("ap", 1336, 296, "손님 Wi-Fi AP");
  ap.ap = { enabled: true, ssid: "corp-guest" };
  const visitor = add("phone", 1376, 464, "손님 폰");
  visitor.wifi = { ssid: "corp-guest" };

  // ---------- 지사 ----------
  const branch = add("nat", 1624, -300, "지사 NAT");
  branch.l3 = {
    interfaces: [
      { ipMode: "static", ip: "203.0.113.20", prefix: 24, gateway: "203.0.113.1" },
      { ipMode: "static", ip: "10.2.0.1", prefix: 24, gateway: "" },
    ],
    routes: [],
    vpn: { enabled: true, mode: "ipsec", psk: "branch-psk", peer: "203.0.113.10", remote: [{ dest: "10.1.0.0", prefix: 16 }] },
  };
  const brSw = add("switch", 1624, -140, "지사 스위치");
  const bpc1 = add("pc", 1608, 32, "지사 PC-1");
  const bpc2 = add("pc", 1728, 32, "지사 PC-2");
  // 지사도 사내 DNS 를 쓴다 (터널 너머 10.1.20.53)
  host(bpc1, "10.2.0.10", "10.2.0.1", "10.1.20.53");
  host(bpc2, "10.2.0.11", "10.2.0.1", "10.1.20.53");

  const cables: Cable[] = [
    cable(isp, 3, inet, 0),
    cable(isp, 0, cafe, 0),
    cable(isp, 1, home, 0),
    cable(isp, 4, edge, 0),
    cable(isp, 7, branch, 0),
    cable(home, 1, laptop, 0),
    cable(edge, 1, core, 0),
    cable(core, 1, srvSw, 3),
    cable(srvSw, 0, lb, 0),
    cable(srvSw, 1, web1, 0),
    cable(srvSw, 5, web2, 0),
    cable(srvSw, 6, wiki, 0),
    cable(srvSw, 7, infra, 0),
    cable(core, 2, officeSw, 0),
    cable(officeSw, 1, pc1, 0),
    cable(officeSw, 2, pc2, 0),
    cable(officeSw, 6, ap, 0),
    cable(branch, 1, brSw, 3),
    cable(brSw, 1, bpc1, 0),
    cable(brSw, 6, bpc2, 0),
  ];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "카페 (고객)", tint: "gray", ...zoneAround(t, [cafe.id, guestPhone.id], 24)! },
    { id: newId("zone"), label: "재택 (집)", tint: "green", ...zoneAround(t, [home.id, laptop.id], 24)! },
    { id: newId("zone"), label: "본사 10.1.0.0/16", tint: "blue", ...zoneAround(t, [edge.id, core.id, srvSw.id, lb.id, web1.id, web2.id, wiki.id, infra.id, officeSw.id, pc1.id, pc2.id, ap.id, visitor.id], 40)! },
    { id: newId("zone"), label: "서버망 10.1.20.0/24", tint: "blue", ...zoneAround(t, [srvSw.id, lb.id, web1.id, web2.id, wiki.id, infra.id], 16)! },
    { id: newId("zone"), label: "사무실 VLAN 10 · 손님 Wi-Fi VLAN 30", tint: "green", ...zoneAround(t, [officeSw.id, pc1.id, pc2.id, ap.id, visitor.id], 16)! },
    { id: newId("zone"), label: "지사 10.2.0.0/24", tint: "gray", ...zoneAround(t, [branch.id, brSw.id, bpc1.id, bpc2.id], 24)! },
  ];
  return t;
}
