// 테스트용 고정 토폴로지 (예제 메뉴에서는 빠졌지만 테스트가 기대는 구성)
import { type Cable, DEFAULT_DHCP_SERVER, type Device, type L3Settings, type Topology, newId, zoneAround } from "../src/model/topology";
import { builder, cable, iface } from "../src/model/examples/build";
import { exampleNcpVpnTopology } from "../src/model/examples/internet";

/** 집 두 곳 잇기: 인터넷 없이 게이트웨이 둘을 if0 끼리 직접 잇고, 서로의 서브넷을 스태틱 라우팅으로 안다 */
export function twoHomesTopology(): Topology {
  const { devices, add } = builder();
  const gw1 = add("gateway", 96, 200);
  const gw2 = add("gateway", 592, 200);
  const gwCfg = (linkIp: string, lanIp: string, otherDest: string, otherVia: string): L3Settings => ({
    interfaces: [
      { ipMode: "static", ip: linkIp, prefix: 24, gateway: "" }, // if0: 두 집 사이 링크(10.0.0.0/24). 인터넷이 없으니 디폴트 라우트도 없다
      { ipMode: "static", ip: lanIp, prefix: 24, gateway: "" },
      { ipMode: "static", ip: "", prefix: 24, gateway: "" },
    ],
    routes: [{ dest: otherDest, prefix: 24, via: otherVia }], // 상대 집 서브넷은 상대 게이트웨이로
  });
  gw1.l3 = gwCfg("10.0.0.1", "192.168.1.1", "192.168.2.0", "10.0.0.2");
  gw2.l3 = gwCfg("10.0.0.2", "192.168.2.1", "192.168.1.0", "10.0.0.1");
  const sw1 = add("switch", 96, 376);
  const sw2 = add("switch", 592, 376);
  const pc1 = add("pc", 24, 544);
  const pc2 = add("pc", 184, 544);
  const pc3 = add("pc", 520, 544);
  const pc4 = add("pc", 680, 544);
  const staticHost = (d: Device, ip: string, gw: string) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway: gw, services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  staticHost(pc1, "192.168.1.10", "192.168.1.1");
  staticHost(pc2, "192.168.1.11", "192.168.1.1");
  staticHost(pc3, "192.168.2.10", "192.168.2.1");
  staticHost(pc4, "192.168.2.11", "192.168.2.1");
  const cables: Cable[] = [
    cable(gw1, 0, gw2, 0), // if0 ↔ if0
    cable(gw1, 1, sw1, 3),
    cable(gw2, 1, sw2, 3),
    cable(sw1, 0, pc1, 0),
    cable(sw1, 5, pc2, 0),
    cable(sw2, 1, pc3, 0),
    cable(sw2, 6, pc4, 0),
  ];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "집 A 192.168.1.0/24", tint: "blue", ...zoneAround(t, [gw1.id, sw1.id, pc1.id, pc2.id], 24)! },
    { id: newId("zone"), label: "집 B 192.168.2.0/24", tint: "green", ...zoneAround(t, [gw2.id, sw2.id, pc3.id, pc4.id], 24)! },
  ];
  return t;
}

/**
 * 망분리 사무실의 재택 접속 (원격 접속 VPN + 점프 서버): NCP 예제의 사무실에 재택 노트북과 DMZ 를 더한다.
 * (2026-10-19 까지 예제 "망분리 사무실 재택 접속" — 예제는 WireGuard 공유기 구성으로 바뀌고, SSH 점프 시나리오 테스트가 이 구성을 쓴다)
 * - 외부망 방화벽 NAT 가 원격 접속 VPN 서버 (고정 공인 주소 203.0.113.12, IPsec + EAP 계정). VPN 이 노트북에 내려 주는 경로는 DMZ(10.255.1.0/24) 뿐
 * - 두 망 사이에 경로를 열지 않는다: 외부망 게이트웨이 → DMZ 방화벽 → 망간 게이트웨이 → 점프 서버(10.255.1.10), 망간 게이트웨이 → 내부망 접근통제 방화벽 → 내부망 게이트웨이.
 *   DMZ 방화벽은 VPN 대역 → 점프 서버 SSH 만, 내부망 접근통제 방화벽은 점프 서버 → 내부망 SSH 만 들인다 (반대 방향 시작은 모두 막음)
 * - 재택 노트북은 ssh -J 10.255.1.10 10.50.10.1 로 내부망 PC 1 에 닿는다. 내부망 PC 에게는 점프 서버가 접속한 것으로 보인다.
 *   점프 없이 10.50.10.1 로 바로 가면 VPN 경로가 아니라 집 인터넷으로 나가 사설 주소라 드롭된다
 */
export function separatedJumpTopology(): Topology {
  const t = exampleNcpVpnTopology();
  const byName = (n: string) => t.devices.find((d) => d.name === n)!;
  // 가운데에 DMZ 통로를 내려고 내부망은 왼쪽, 외부망·NCP 는 오른쪽으로 옮긴다
  const left = ["KT 모뎀 (내부망 회선)", "내부망 방화벽 NAT", "내부망 방화벽", "내부망 게이트웨이", "내부망 스위치 1", "내부망 스위치 2", "맥북 2", "맥북 1", "내부망 PC 1", "내부망 PC 2", "내부망 PC 3"];
  for (const d of t.devices) {
    if (left.includes(d.name)) d.x -= 260;
    else if (d.name !== "internet-1" && d.name !== "통신사 구간") d.x += 260;
  }
  const natOut = byName("외부망 방화벽 NAT");
  // VPN 서버는 고정 공인 주소, 원격 접속 VPN (내려 주는 경로는 DMZ 뿐), VPN 대역이 DMZ 로 가는 경로
  natOut.l3 = {
    ...natOut.l3!,
    interfaces: [iface("203.0.113.12", "203.0.113.1"), natOut.l3!.interfaces[1]!],
    // DMZ·망간 연결 구간으로 가는 경로 (VPN 사용자 → 점프 서버, 그 응답)
    routes: [...natOut.l3!.routes, { dest: "10.255.1.0", prefix: 24, via: "10.255.0.6" }, { dest: "10.255.0.8", prefix: 29, via: "10.255.0.6" }],
    ra: { enabled: true, psk: "office-ra-psk", poolStart: "10.99.0.10", poolEnd: "10.99.0.50", routes: [{ dest: "10.255.1.0", prefix: 24 }], users: [{ name: "kim", password: "kim-pass" }] },
  };
  // 외부망 방화벽: VPN 대역이 점프 서버 SSH 로 들어가는 것만 더 들인다 (나머지 인바운드는 그대로 차단)
  const fwOut = byName("외부망 방화벽");
  fwOut.firewall = { ...fwOut.firewall!, rules: [...fwOut.firewall!.rules, { action: "allow", proto: "tcp", direction: "in", src: "10.99.0.0/24", dst: "10.255.1.10", dstPort: "22" }] };
  const gwOut = byName("외부망 게이트웨이");
  gwOut.l3 = { ...gwOut.l3!, interfaces: [gwOut.l3!.interfaces[0]!, gwOut.l3!.interfaces[1]!, { ipMode: "static", ip: "10.255.0.9", prefix: 30, gateway: "" }], routes: [...gwOut.l3!.routes, { dest: "10.255.1.0", prefix: 24, via: "10.255.0.10" }, { dest: "10.255.0.12", prefix: 30, via: "10.255.0.10" }] };
  const gwIn = byName("내부망 게이트웨이");
  gwIn.l3 = { ...gwIn.l3!, interfaces: [gwIn.l3!.interfaces[0]!, gwIn.l3!.interfaces[1]!, { ipMode: "static", ip: "10.255.0.14", prefix: 30, gateway: "" }], routes: [...gwIn.l3!.routes, { dest: "10.255.1.0", prefix: 24, via: "10.255.0.13" }] };
  // 내부망 방화벽 NAT 가 망간 연결 구간을 알게 (내부망 게이트웨이 뒤의 구간 — 응답이 길을 잃지 않게)
  const natIn = byName("내부망 방화벽 NAT");
  natIn.l3 = { ...natIn.l3!, routes: [...natIn.l3!.routes, { dest: "10.255.0.12", prefix: 30, via: "10.255.0.2" }] };
  const pcIn1 = byName("내부망 PC 1");
  pcIn1.host = { ...pcIn1.host!, services: [22] };

  const { devices, add } = builder();
  devices.push(...t.devices);
  // DMZ: 외부망 쪽 방화벽 → 망간 게이트웨이 → 점프 서버 / 내부망 접근통제 방화벽 → 내부망.
  // 망간 게이트웨이의 디폴트 라우트는 외부망 쪽이지만 DMZ 방화벽이 DMZ 에서 나가는 새 연결을 모두 막는다 (점프 서버도 인터넷에 못 나감)
  const fwDmz = add("firewall", 936, 300, "DMZ 방화벽");
  fwDmz.firewall = { enabled: true, defaultPolicy: "deny", stateful: true, rules: [{ action: "allow", proto: "tcp", direction: "in", src: "10.99.0.0/24", dst: "10.255.1.10", dstPort: "22" }] };
  const gwDmz = add("gateway", 808, 420, "망간 게이트웨이");
  gwDmz.l3 = {
    interfaces: [{ ipMode: "static", ip: "10.255.0.10", prefix: 30, gateway: "10.255.0.9" }, iface("10.255.1.1"), { ipMode: "static", ip: "10.255.0.13", prefix: 30, gateway: "" }],
    routes: [{ dest: "10.50.10.0", prefix: 24, via: "10.255.0.14" }],
  };
  const jump = add("server", 936, 580, "점프 서버");
  jump.host = { ipMode: "static", ip: "10.255.1.10", prefix: 24, gateway: "10.255.1.1", services: [22], sshJump: true, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const fwIn2 = add("firewall", 680, 580, "내부망 접근통제 방화벽");
  fwIn2.firewall = { enabled: true, defaultPolicy: "deny", stateful: true, rules: [{ action: "allow", proto: "tcp", direction: "in", src: "10.255.1.10", dst: "10.50.10.0/24", dstPort: "22" }] };
  // 재택: 집 공유기 뒤 노트북 (원격 접속 VPN 계정 kim)
  const home = add("router", -120, -440, "집 공유기");
  const laptop = add("laptop", -120, -280, "재택 노트북");
  laptop.host = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER }, ra: { enabled: true, server: "203.0.113.12", psk: "office-ra-psk", user: "kim", password: "kim-pass" } };
  const isp = byName("통신사 구간");
  t.devices = devices;
  t.cables = [
    ...t.cables,
    cable(isp, 2, home, 0),
    cable(home, 1, laptop, 0),
    cable(gwOut, 2, fwDmz, 0),
    cable(fwDmz, 1, gwDmz, 0),
    cable(gwDmz, 1, jump, 0),
    cable(gwDmz, 2, fwIn2, 0),
    cable(fwIn2, 1, gwIn, 2),
  ];
  const ids = (names: string[]) => names.map((n) => byName(n).id);
  t.zones = [
    { id: newId("zone"), label: "인터넷", tint: "amber", ...zoneAround(t, ids(["internet-1", "통신사 구간"]), 24)! },
    { id: newId("zone"), label: "재택", tint: "green", ...zoneAround(t, [home.id, laptop.id], 32)! },
    { id: newId("zone"), label: "내부망 10.50.10.0/24", tint: "blue", ...zoneAround(t, ids(["내부망 방화벽 NAT", "내부망 방화벽", "내부망 게이트웨이", "내부망 스위치 1", "내부망 스위치 2", "맥북 2", "맥북 1", "내부망 PC 1", "내부망 PC 2", "내부망 PC 3"]), 24)! },
    { id: newId("zone"), label: "외부망 192.168.100.0/24 · VPN 10.99.0.0/24", tint: "amber", ...zoneAround(t, ids(["외부망 방화벽 NAT", "외부망 방화벽", "외부망 게이트웨이", "외부망 스위치 1", "외부망 스위치 2", "외부망 DHCP 서버", "wifi", "외부망 PC 1", "외부망 PC 2", "외부망 PC 3", "phone-1", "phone-2"]), 24)! },
    { id: newId("zone"), label: "DMZ 10.255.1.0/24 (점프 서버)", tint: "green", ...zoneAround(t, [fwDmz.id, gwDmz.id, jump.id, fwIn2.id], 20)! },
    { id: newId("zone"), label: "NCP (네이버 클라우드)", tint: "green", ...zoneAround(t, ids(["인터넷 (NCP 쪽)", "NCP VPN Gateway", "NCP VPC 연결", "Dev VPC 라우터", "Prod VPC 라우터", "Dev 서브넷 스위치", "dev-1", "dev-2", "dev-3", "prod"]), 32)! },
  ];
  return t;
}
