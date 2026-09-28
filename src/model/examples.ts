// 예제 토폴로지 13종과 레지스트리. 파일 메뉴의 "예제" 와 테스트가 쓴다.
// 새 예제는 여기에 함수를 추가하고 EXAMPLES 에 등록한다 (구성 검사 이슈 0 은 tests/topology.test.ts 가 확인).
import {
  type Cable,
  DEFAULT_DHCP_SERVER,
  type Device,
  type DeviceKind,
  type L3Settings,
  type Topology,
  type Zone,
  type ZoneTint,
  createDevice,
  newId,
  zoneAround,
} from "./topology";

/** 기능 단위 구성 예제: 인터넷 → NAT 박스 → 게이트웨이 → 스위치 2대(서브넷 2개) + DHCP 서버 호스트 */
export function examplePartsTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const inet = add("internet", 344, -232);
  const nat = add("nat", 344, -80);
  nat.l3 = {
    interfaces: [
      { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "10.0.0.1", prefix: 24, gateway: "" },
    ],
    routes: [{ dest: "192.168.0.0", prefix: 16, via: "10.0.0.2" }],
    // 바깥에서 공인 :80 으로 오면 오른쪽 서브넷의 웹 서버로
    forwards: [{ publicPort: 80, lanIp: "192.168.2.20", lanPort: 80 }],
  };
  const gw = add("gateway", 344, 80);
  gw.l3 = {
    interfaces: [
      { ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" },
      { ipMode: "static", ip: "192.168.1.1", prefix: 24, gateway: "" },
      // 오른쪽 서브넷엔 DHCP 서버가 없어 왼쪽의 dhcp-srv 로 릴레이한다
      { ipMode: "static", ip: "192.168.2.1", prefix: 24, gateway: "", relay: "192.168.1.2" },
    ],
    routes: [],
  };
  const sw1 = add("switch", 120, 256);
  const sw2 = add("switch", 568, 256);
  const dhcp = add("server", 24, 424);
  dhcp.name = "dhcp-srv";
  dhcp.host = {
    ipMode: "static",
    ip: "192.168.1.2",
    prefix: 24,
    gateway: "192.168.1.1",
    dns: "192.168.1.2",
    services: [],
    dhcpServer: {
      enabled: true,
      start: "192.168.1.100",
      end: "192.168.1.199",
      router: "192.168.1.1",
      dns: "192.168.1.2",
      extraPools: [{ start: "192.168.2.100", end: "192.168.2.199", prefix: 24, router: "192.168.2.1", dns: "192.168.1.2" }],
    },
    // 같은 서버가 DNS 도 맡는다: 내부 이름은 레코드로, 공개 이름은 8.8.8.8 에 재귀 질의
    dnsServer: { enabled: true, records: [{ name: "web.home", ip: "192.168.2.20" }], upstream: "8.8.8.8" },
  };
  const pc1 = add("pc", 200, 424);
  const laptop = add("laptop", 520, 424); // 릴레이를 거쳐 dhcp-srv 에서 주소를 받는다
  const web = add("server", 700, 424);
  web.host = { ipMode: "static", ip: "192.168.2.20", prefix: 24, gateway: "192.168.2.1", dns: "192.168.1.2", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: nat.id, port: 0 } },
    { id: newId("cable"), a: { device: nat.id, port: 1 }, b: { device: gw.id, port: 0 } },
    { id: newId("cable"), a: { device: gw.id, port: 1 }, b: { device: sw1.id, port: 0 } },
    { id: newId("cable"), a: { device: gw.id, port: 2 }, b: { device: sw2.id, port: 0 } },
    { id: newId("cable"), a: { device: sw1.id, port: 2 }, b: { device: dhcp.id, port: 0 } },
    { id: newId("cable"), a: { device: sw1.id, port: 5 }, b: { device: pc1.id, port: 0 } },
    { id: newId("cable"), a: { device: sw2.id, port: 3 }, b: { device: laptop.id, port: 0 } },
    { id: newId("cable"), a: { device: sw2.id, port: 6 }, b: { device: web.id, port: 0 } },
  ];
  return { devices, cables };
}

/** VLAN 예제: 인터넷 → NAT → 게이트웨이(if1 트렁크) → 스위치(VLAN 10: pc 2대, VLAN 20: 웹 서버 + 노트북) */
export function exampleVlanTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const inet = add("internet", 344, -232);
  const nat = add("nat", 344, -80);
  nat.l3 = {
    interfaces: [
      { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "10.0.0.1", prefix: 24, gateway: "" },
    ],
    routes: [{ dest: "192.168.0.0", prefix: 16, via: "10.0.0.2" }],
  };
  const gw = add("gateway", 344, 80);
  gw.l3 = {
    interfaces: [
      { ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" },
      { ipMode: "static", ip: "", prefix: 24, gateway: "" }, // if1 은 트렁크: 주소 없이 서브 인터페이스만
      { ipMode: "static", ip: "", prefix: 24, gateway: "" },
    ],
    routes: [],
    // router-on-a-stick: 트렁크 하나 위에 VLAN 마다 게이트웨이 주소
    subinterfaces: [
      { port: 1, vlan: 10, ip: "192.168.10.1", prefix: 24, relay: "" },
      { port: 1, vlan: 20, ip: "192.168.20.1", prefix: 24, relay: "" },
    ],
  };
  const sw = add("switch", 344, 256);
  sw.switch = { vlans: { 0: "trunk", 1: 10, 2: 10, 5: 20, 6: 20 } };
  const pc1 = add("pc", 120, 424);
  const pc2 = add("pc", 260, 424);
  const laptop = add("laptop", 460, 424);
  const web = add("server", 600, 424);
  const staticHost = (d: Device, ip: string, gw: string, services: number[] = []) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway: gw, dns: "8.8.8.8", services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  staticHost(pc1, "192.168.10.10", "192.168.10.1");
  staticHost(pc2, "192.168.10.11", "192.168.10.1");
  staticHost(laptop, "192.168.20.10", "192.168.20.1");
  staticHost(web, "192.168.20.20", "192.168.20.1", [80]);
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: nat.id, port: 0 } },
    { id: newId("cable"), a: { device: nat.id, port: 1 }, b: { device: gw.id, port: 0 } },
    { id: newId("cable"), a: { device: gw.id, port: 1 }, b: { device: sw.id, port: 0 } }, // 트렁크
    { id: newId("cable"), a: { device: sw.id, port: 1 }, b: { device: pc1.id, port: 0 } }, // VLAN 10
    { id: newId("cable"), a: { device: sw.id, port: 2 }, b: { device: pc2.id, port: 0 } }, // VLAN 10
    { id: newId("cable"), a: { device: sw.id, port: 5 }, b: { device: laptop.id, port: 0 } }, // VLAN 20
    { id: newId("cable"), a: { device: sw.id, port: 6 }, b: { device: web.id, port: 0 } }, // VLAN 20
  ];
  return { devices, cables };
}

/** 인터넷 + 공유기(라우터) + 스위치 + 호스트 3대 예제 */
export function exampleTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const inet = add("internet", 344, -40);
  const rt = add("router", 344, 96);
  const sw = add("switch", 344, 272);
  const pc = add("pc", 200, 440);
  const laptop = add("laptop", 388, 440);
  const srv = add("server", 576, 440);
  // 웹 서버는 고정 주소로 두고 라우터가 공인 :80 을 여기로 포워딩한다
  srv.host = { ipMode: "static", ip: "192.168.0.20", prefix: 24, gateway: "192.168.0.1", dns: "192.168.0.1", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  rt.router = { ...rt.router!, forwards: [{ publicPort: 80, lanIp: "192.168.0.20", lanPort: 80 }], wifi: { enabled: true, ssid: "home" } };
  // 공유기의 Wi-Fi 에 붙는 스마트폰 (링크 다운, 전파 범위 안)
  add("phone", 600, 120);
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: rt.id, port: 0 } }, // isp ↔ wan
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 0 } }, // lan1 ↔ eth1
    { id: newId("cable"), a: { device: sw.id, port: 2 }, b: { device: pc.id, port: 0 } }, // eth2
    { id: newId("cable"), a: { device: sw.id, port: 4 }, b: { device: laptop.id, port: 0 } }, // eth4
    { id: newId("cable"), a: { device: sw.id, port: 6 }, b: { device: srv.id, port: 0 } }, // eth6
  ];
  return { devices, cables };
}

/** 가장 단순한 예제: PC 2대 + 스위치, 수동 IP. ARP 와 ping 만 본다 */
export function exampleStarterTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const sw = add("switch", 344, 96);
  const pc1 = add("pc", 232, 280);
  const pc2 = add("pc", 544, 280);
  pc1.host = { ipMode: "static", ip: "192.168.0.10", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  pc2.host = { ipMode: "static", ip: "192.168.0.11", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: sw.id, port: 1 }, b: { device: pc1.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 6 }, b: { device: pc2.id, port: 0 } },
  ];
  return { devices, cables };
}

/** 게이트웨이 2단: NAT 아래에 라우터 전용 서브넷(10.0.0.0/24)을 두고 게이트웨이 둘이 각자 서브넷을 맡는다 */
export function exampleTwoGatewaysTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const inet = add("internet", 344, -232);
  const nat = add("nat", 344, -80);
  nat.l3 = {
    interfaces: [
      { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "10.0.0.1", prefix: 24, gateway: "" },
    ],
    // 게이트웨이마다 그 뒤 서브넷으로 돌아가는 경로. 이게 없으면 응답이 여기서 드롭된다
    routes: [
      { dest: "192.168.1.0", prefix: 24, via: "10.0.0.2" },
      { dest: "192.168.5.0", prefix: 24, via: "10.0.0.3" },
    ],
  };
  const sw0 = add("switch", 344, 80); // 라우터들만 사는 서브넷
  const gw1 = add("gateway", 96, 248);
  const gw2 = add("gateway", 592, 248);
  const gwCfg = (ifIp: string, lanIp: string, otherDest: string, otherVia: string): L3Settings => ({
    interfaces: [
      { ipMode: "static", ip: ifIp, prefix: 24, gateway: "10.0.0.1" },
      { ipMode: "static", ip: lanIp, prefix: 24, gateway: "" },
      { ipMode: "static", ip: "", prefix: 24, gateway: "" },
    ],
    // 옆 게이트웨이 뒤 서브넷은 NAT 를 거치지 않고 같은 스위치에서 바로 넘긴다
    routes: [{ dest: otherDest, prefix: 24, via: otherVia }],
  });
  gw1.l3 = gwCfg("10.0.0.2", "192.168.1.1", "192.168.5.0", "10.0.0.3");
  gw2.l3 = gwCfg("10.0.0.3", "192.168.5.1", "192.168.1.0", "10.0.0.2");
  const sw1 = add("switch", 96, 424);
  const sw2 = add("switch", 592, 424);
  const pc1 = add("pc", 24, 592);
  const pc2 = add("pc", 184, 592);
  const pc3 = add("pc", 520, 592);
  const srv = add("server", 680, 592);
  const staticHost = (d: Device, ip: string, gw: string, services: number[] = []) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway: gw, dns: "8.8.8.8", services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  staticHost(pc1, "192.168.1.10", "192.168.1.1");
  staticHost(pc2, "192.168.1.11", "192.168.1.1");
  staticHost(pc3, "192.168.5.10", "192.168.5.1");
  staticHost(srv, "192.168.5.20", "192.168.5.1", [80]);
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: nat.id, port: 0 } },
    { id: newId("cable"), a: { device: nat.id, port: 1 }, b: { device: sw0.id, port: 3 } },
    { id: newId("cable"), a: { device: sw0.id, port: 0 }, b: { device: gw1.id, port: 0 } },
    { id: newId("cable"), a: { device: sw0.id, port: 7 }, b: { device: gw2.id, port: 0 } },
    { id: newId("cable"), a: { device: gw1.id, port: 1 }, b: { device: sw1.id, port: 3 } },
    { id: newId("cable"), a: { device: gw2.id, port: 1 }, b: { device: sw2.id, port: 3 } },
    { id: newId("cable"), a: { device: sw1.id, port: 0 }, b: { device: pc1.id, port: 0 } },
    { id: newId("cable"), a: { device: sw1.id, port: 5 }, b: { device: pc2.id, port: 0 } },
    { id: newId("cable"), a: { device: sw2.id, port: 1 }, b: { device: pc3.id, port: 0 } },
    { id: newId("cable"), a: { device: sw2.id, port: 6 }, b: { device: srv.id, port: 0 } },
  ];
  return { devices, cables };
}

/** 집 두 곳 잇기: 인터넷 없이 게이트웨이 둘을 if0 끼리 직접 잇고, 서로의 서브넷을 스태틱 라우팅으로 안다 */
export function exampleTwoHomesTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
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
    { id: newId("cable"), a: { device: gw1.id, port: 0 }, b: { device: gw2.id, port: 0 } }, // if0 ↔ if0
    { id: newId("cable"), a: { device: gw1.id, port: 1 }, b: { device: sw1.id, port: 3 } },
    { id: newId("cable"), a: { device: gw2.id, port: 1 }, b: { device: sw2.id, port: 3 } },
    { id: newId("cable"), a: { device: sw1.id, port: 0 }, b: { device: pc1.id, port: 0 } },
    { id: newId("cable"), a: { device: sw1.id, port: 5 }, b: { device: pc2.id, port: 0 } },
    { id: newId("cable"), a: { device: sw2.id, port: 1 }, b: { device: pc3.id, port: 0 } },
    { id: newId("cable"), a: { device: sw2.id, port: 6 }, b: { device: pc4.id, port: 0 } },
  ];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "집 A 192.168.1.0/24", tint: "blue", ...zoneAround(t, [gw1.id, sw1.id, pc1.id, pc2.id], 24)! },
    { id: newId("zone"), label: "집 B 192.168.2.0/24", tint: "green", ...zoneAround(t, [gw2.id, sw2.id, pc3.id, pc4.id], 24)! },
  ];
  return t;
}

/**
 * 동적 라우팅: 게이트웨이 3대가 삼각형으로 직결되고 각자 LAN 을 하나씩 가진다. 스태틱 라우팅 없이 RIP 로 서로의 LAN 을 배운다.
 * 링크 하나를 끊으면 RIP 가 경로를 철회하고 남은 길(다른 게이트웨이 경유)로 다시 수렴한다
 */
export function exampleRipTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const iface = (ip: string) => ({ ipMode: "static" as const, ip, prefix: 24, gateway: "" });
  const rip = { enabled: true };
  const swA = add("switch", 320, 40);
  const gwA = add("gateway", 320, 208);
  const gwB = add("gateway", 64, 400);
  const gwC = add("gateway", 576, 400);
  gwA.name = "gw-a";
  gwB.name = "gw-b";
  gwC.name = "gw-c";
  // gw-a: if0 = LAN(위 스위치), if1 → gw-b, if2 → gw-c
  gwA.l3 = { interfaces: [iface("192.168.1.1"), iface("10.0.12.1"), iface("10.0.13.1")], routes: [], rip };
  // gw-b: if0 → gw-a, if1 = LAN, if2 → gw-c
  gwB.l3 = { interfaces: [iface("10.0.12.2"), iface("192.168.2.1"), iface("10.0.23.2")], routes: [], rip };
  // gw-c: if0 → gw-a, if1 → gw-b, if2 = LAN
  gwC.l3 = { interfaces: [iface("10.0.13.3"), iface("10.0.23.3"), iface("192.168.3.1")], routes: [], rip };
  const swB = add("switch", 8, 592);
  const swC = add("switch", 632, 592);
  const pcA = add("pc", 160, 208);
  const pcB = add("pc", 40, 752);
  const pcC = add("pc", 744, 752);
  pcA.name = "pc-a";
  pcB.name = "pc-b";
  pcC.name = "pc-c";
  const staticHost = (d: Device, ip: string, gw: string) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway: gw, services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  staticHost(pcA, "192.168.1.10", "192.168.1.1");
  staticHost(pcB, "192.168.2.10", "192.168.2.1");
  staticHost(pcC, "192.168.3.10", "192.168.3.1");
  const cable = (a: Device, ap: number, b: Device, bp: number): Cable => ({ id: newId("cable"), a: { device: a.id, port: ap }, b: { device: b.id, port: bp } });
  const cables: Cable[] = [
    cable(swA, 4, gwA, 0),
    cable(swA, 1, pcA, 0),
    cable(gwA, 1, gwB, 0),
    cable(gwA, 2, gwC, 0),
    cable(gwB, 2, gwC, 1),
    cable(gwB, 1, swB, 3),
    cable(gwC, 2, swC, 5),
    cable(swB, 1, pcB, 0),
    cable(swC, 7, pcC, 0),
  ];
  return { devices, cables };
}

/** 백본: 집 세 곳의 게이트웨이 if0 을 스위치 하나(10.0.0.0/24, 라우터만 사는 서브넷)에 모은다. 인터넷 없음 */
export function exampleBackboneTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const bb = add("switch", 368, 40);
  bb.name = "sw-backbone";
  const homes = [
    { x: 48, link: "10.0.0.1", lan: "192.168.1", bbPort: 0 },
    { x: 368, link: "10.0.0.2", lan: "192.168.2", bbPort: 3 },
    { x: 688, link: "10.0.0.3", lan: "192.168.3", bbPort: 7 },
  ];
  const cables: Cable[] = [];
  const zones: Zone[] = [];
  const tints: ZoneTint[] = ["blue", "green", "amber"];
  homes.forEach((h, i) => {
    const gw = add("gateway", h.x, 216);
    gw.l3 = {
      interfaces: [
        { ipMode: "static", ip: h.link, prefix: 24, gateway: "" }, // if0: 백본 쪽. 인터넷이 없으니 디폴트 라우트 없음
        { ipMode: "static", ip: `${h.lan}.1`, prefix: 24, gateway: "" },
        { ipMode: "static", ip: "", prefix: 24, gateway: "" },
      ],
      // 다른 집 서브넷마다 그 집 게이트웨이의 백본 주소로
      routes: homes.filter((o) => o !== h).map((o) => ({ dest: `${o.lan}.0`, prefix: 24, via: o.link })),
    };
    const sw = add("switch", h.x, 392);
    const a = add(i === 2 ? "server" : "pc", h.x - 40, 560);
    const b = add("pc", h.x + 120, 560);
    a.host = { ipMode: "static", ip: `${h.lan}.10`, prefix: 24, gateway: `${h.lan}.1`, services: i === 2 ? [80] : [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
    b.host = { ipMode: "static", ip: `${h.lan}.11`, prefix: 24, gateway: `${h.lan}.1`, services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
    cables.push(
      { id: newId("cable"), a: { device: gw.id, port: 0 }, b: { device: bb.id, port: h.bbPort } },
      { id: newId("cable"), a: { device: gw.id, port: 1 }, b: { device: sw.id, port: 3 } },
      { id: newId("cable"), a: { device: sw.id, port: 0 }, b: { device: a.id, port: 0 } },
      { id: newId("cable"), a: { device: sw.id, port: 6 }, b: { device: b.id, port: 0 } },
    );
    zones.push({ id: newId("zone"), label: `집 ${i + 1} ${h.lan}.0/24`, tint: tints[i]!, ...zoneAround({ devices, cables: [] }, [gw.id, sw.id, a.id, b.id], 20)! });
  });
  zones.push({ id: newId("zone"), label: "백본 10.0.0.0/24 (라우터만)", tint: "gray", ...zoneAround({ devices, cables: [] }, [bb.id], 20)! });
  return { devices, cables, zones };
}

/**
 * 도커 호스트를 부품으로: 집 LAN 의 PC 한 대(docker-host) 안에 브리지 네트워크(172.18.0.0/16)와 컨테이너 3개.
 * NAT 박스 = 호스트의 iptables(MASQUERADE + -p DNAT), 스위치 = 브리지(veth 가 꽂히는 곳), 서버 = 컨테이너, DNS 서버 = embedded DNS(실제로는 127.0.0.11).
 */
export function exampleDockerTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const inet = add("internet", 344, -232);
  const rt = add("router", 344, -80);
  const sw = add("switch", 344, 96);
  const pc = add("pc", 120, 264); // 같은 집 LAN 의 다른 PC
  const host = add("nat", 568, 264); // 도커가 돌아가는 컴퓨터. outside = 그 컴퓨터의 LAN NIC, inside = 브리지 게이트웨이
  host.name = "docker-host";
  host.l3 = {
    interfaces: [
      { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" }, // 공유기에서 주소를 받는다 (컴퓨터 한 대일 뿐)
      { ipMode: "static", ip: "172.18.0.1", prefix: 16, gateway: "" }, // 사용자 정의 브리지 "app" 의 게이트웨이
    ],
    routes: [],
    // docker run -p 8080:80 web
    forwards: [{ publicPort: 8080, lanIp: "172.18.0.2", lanPort: 80 }],
  };
  const br = add("switch", 568, 440);
  br.name = "bridge (app)";
  const web = add("server", 456, 608);
  const db = add("server", 616, 608);
  const dns = add("server", 776, 608);
  web.name = "web";
  db.name = "db";
  dns.name = "embedded-dns";
  const container = (d: Device, ip: string, services: number[]) => {
    d.host = { ipMode: "static", ip, prefix: 16, gateway: "172.18.0.1", dns: "172.18.0.53", services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  container(web, "172.18.0.2", [80]);
  container(db, "172.18.0.3", [5432]);
  container(dns, "172.18.0.53", []);
  // 같은 사용자 정의 네트워크의 컨테이너는 이름으로 찾는다. 모르는 이름은 호스트가 쓰는 DNS 로 넘긴다
  dns.host!.dnsServer = {
    enabled: true,
    records: [
      { name: "web", ip: "172.18.0.2" },
      { name: "db", ip: "172.18.0.3" },
    ],
    upstream: "8.8.8.8",
  };
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: rt.id, port: 0 } },
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 3 } },
    { id: newId("cable"), a: { device: sw.id, port: 0 }, b: { device: pc.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 7 }, b: { device: host.id, port: 0 } }, // 호스트 NIC
    { id: newId("cable"), a: { device: host.id, port: 1 }, b: { device: br.id, port: 3 } }, // 브리지 게이트웨이
    { id: newId("cable"), a: { device: br.id, port: 0 }, b: { device: web.id, port: 0 } }, // veth
    { id: newId("cable"), a: { device: br.id, port: 4 }, b: { device: db.id, port: 0 } },
    { id: newId("cable"), a: { device: br.id, port: 7 }, b: { device: dns.id, port: 0 } },
  ];
  const t: Topology = { devices, cables };
  // 영역: 점선 네모 안은 전부 "컴퓨터 한 대(docker-host) 안" 이라는 뜻
  t.zones = [
    { id: newId("zone"), label: "docker-host 한 대 안 (브리지 네트워크 app)", tint: "blue", ...zoneAround(t, [host.id, br.id, web.id, db.id, dns.id])! },
    { id: newId("zone"), label: "집 LAN 192.168.0.0/24", tint: "gray", ...zoneAround(t, [rt.id, sw.id, pc.id], 24)! },
  ];
  return t;
}

/** 허브 vs 스위치: 같은 공유기 아래 한쪽은 허브, 한쪽은 스위치. ping 이 어디까지 퍼지는지 비교 */
export function exampleHubTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const rt = add("router", 344, 0);
  const hub = add("hub", 112, 200);
  const sw = add("switch", 560, 200);
  const pc1 = add("pc", 40, 376);
  const pc2 = add("pc", 200, 376);
  const pc3 = add("pc", 504, 376);
  const pc4 = add("pc", 664, 376);
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: hub.id, port: 1 } },
    { id: newId("cable"), a: { device: rt.id, port: 4 }, b: { device: sw.id, port: 3 } },
    { id: newId("cable"), a: { device: hub.id, port: 0 }, b: { device: pc1.id, port: 0 } },
    { id: newId("cable"), a: { device: hub.id, port: 3 }, b: { device: pc2.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 0 }, b: { device: pc3.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 7 }, b: { device: pc4.id, port: 0 } },
  ];
  return { devices, cables };
}

/** 방화벽: 공유기가 나가는 TCP 80 만 막는다. ping 은 되고 웹 연결만 차단되는 걸 본다 */
export function exampleFirewallTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const inet = add("internet", 344, -40);
  const rt = add("router", 344, 96);
  rt.router = {
    ...rt.router!,
    firewall: {
      enabled: true,
      defaultPolicy: "allow",
      stateful: true,
      rules: [
        { action: "deny", proto: "tcp", direction: "out", src: "", dst: "", dstPort: "80" },
        { action: "deny", proto: "icmp", direction: "in", src: "", dst: "", dstPort: "" },
      ],
    },
  };
  const sw = add("switch", 344, 272);
  const pc = add("pc", 232, 440);
  const laptop = add("laptop", 456, 440);
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: inet.id, port: 0 }, b: { device: rt.id, port: 0 } },
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 2 }, b: { device: pc.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 5 }, b: { device: laptop.id, port: 0 } },
  ];
  return { devices, cables };
}

/** 방화벽 장비: 스위치와 서버 사이에 투명 방화벽을 끼워 서버로 오는 ping 만 막는다. 주소는 하나도 안 바꾼다 */
export function exampleFirewallApplianceTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const rt = add("router", 344, -40);
  const sw = add("switch", 344, 136);
  const pc = add("pc", 120, 320);
  const laptop = add("laptop", 264, 320);
  const fw = add("firewall", 520, 304);
  fw.firewall = {
    enabled: true,
    defaultPolicy: "allow",
    stateful: true,
    // outside(스위치 쪽)에서 서버로 들어오는 ping 만 차단. TCP 80 은 열려 있고, 서버가 먼저 시작한 통신의 응답은 Stateful 로 통과
    rules: [{ action: "deny", proto: "icmp", direction: "in", src: "", dst: "", dstPort: "" }],
  };
  const srv = add("server", 564, 488);
  srv.host = { ipMode: "static", ip: "192.168.0.20", prefix: 24, gateway: "192.168.0.1", dns: "192.168.0.1", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 3 } },
    { id: newId("cable"), a: { device: sw.id, port: 0 }, b: { device: pc.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 2 }, b: { device: laptop.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 7 }, b: { device: fw.id, port: 0 } }, // outside ← 스위치
    { id: newId("cable"), a: { device: fw.id, port: 1 }, b: { device: srv.id, port: 0 } }, // inside → 서버
  ];
  const t: Topology = { devices, cables };
  t.zones = [{ id: newId("zone"), label: "방화벽 뒤 (보호 구역)", tint: "amber", ...zoneAround(t, [fw.id, srv.id], 20)! }];
  return t;
}

/** 무선 로밍: 같은 SSID 의 AP 두 대. 스마트폰을 끌어 옮기면 가까운 AP 로 갈아탄다 */
export function exampleRoamingTopology(): Topology {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const rt = add("router", 344, 0);
  const sw = add("switch", 344, 176);
  const ap1 = add("ap", 16, 352);
  const ap2 = add("ap", 704, 352);
  ap1.ap = { enabled: true, ssid: "office" };
  ap2.ap = { enabled: true, ssid: "office" };
  const phone = add("phone", 56, 544);
  phone.wifi = { ssid: "office" };
  const cables: Cable[] = [
    { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 3 } },
    { id: newId("cable"), a: { device: sw.id, port: 0 }, b: { device: ap1.id, port: 0 } },
    { id: newId("cable"), a: { device: sw.id, port: 7 }, b: { device: ap2.id, port: 0 } },
  ];
  return { devices, cables };
}

export type ExampleId = "starter" | "router" | "parts" | "homes" | "backbone" | "rip" | "gateways" | "hub" | "vlan" | "firewall" | "fwbox" | "roaming" | "docker";

export interface ExampleSpec {
  id: ExampleId;
  /** 메뉴 묶음 */
  group: string;
  label: string;
  /** 불러온 뒤 무엇을 해 보면 되는지 한 줄 */
  blurb: string;
  build: () => Topology;
}

export const EXAMPLES: Record<ExampleId, ExampleSpec> = {
  starter: { id: "starter", group: "기본", label: "PC 2대 + 스위치 (수동 IP)", blurb: "pc-1 에서 pc-2 로 ping 하면 ARP 로 MAC 을 찾은 뒤 ICMP 가 오갑니다.", build: exampleStarterTopology },
  router: { id: "router", group: "기본", label: "공유기 하나로 (DHCP + NAT + 포트 포워딩 + Wi-Fi)", blurb: "케이블만 꽂으면 DHCP 로 주소를 받고, google.com 으로 ping 하면 DNS → NAT 를 거칩니다.", build: exampleTopology },
  parts: { id: "parts", group: "기능 단위", label: "기능 단위로 (NAT 박스 + 게이트웨이 + DHCP/DNS 서버)", blurb: "공유기를 상자별로 뜯은 구성. 노트북은 게이트웨이 릴레이로 다른 서브넷의 DHCP 서버에서 주소를 받습니다.", build: examplePartsTopology },
  homes: {
    id: "homes",
    group: "기능 단위",
    label: "집 두 곳 잇기 (게이트웨이 ↔ 게이트웨이, 인터넷 없음)",
    blurb: "pc-1 → 192.168.2.10 은 gw-1 → gw-2 두 홉을 지납니다. \"경로\" 로 홉을 확인하고, gw-1 의 스태틱 라우팅을 지우면 No route 로 실패합니다.",
    build: exampleTwoHomesTopology,
  },
  backbone: {
    id: "backbone",
    group: "기능 단위",
    label: "백본 스위치로 집 세 곳 잇기 (라우터 전용 서브넷)",
    blurb: "게이트웨이 셋의 if0 이 sw-backbone(10.0.0.0/24) 에서 만납니다. 게이트웨이마다 다른 두 집으로 가는 스태틱 라우팅이 있고, 하나를 지우면 그 집만 못 갑니다.",
    build: exampleBackboneTopology,
  },
  rip: {
    id: "rip",
    group: "기능 단위",
    label: "동적 라우팅 RIP (게이트웨이 3대 삼각형)",
    blurb: "스태틱 라우팅 없이 RIP 로 서로의 LAN 을 배웁니다(게이트웨이 → 표 탭의 라우팅 테이블). pc-a 에서 192.168.3.10 으로 \"경로\" 를 본 뒤 gw-a ↔ gw-c 케이블을 지우면, RIP 가 경로를 철회하고 gw-b 를 거치는 길로 다시 수렴합니다.",
    build: exampleRipTopology,
  },
  gateways: { id: "gateways", group: "기능 단위", label: "게이트웨이 2단 (라우터 전용 서브넷 + 스태틱 라우팅)", blurb: "pc-1 → 192.168.5.10 은 gw-1 이 스태틱 라우팅으로 gw-2 에 바로 넘기고, 인터넷은 NAT 로 올라갑니다. NAT 의 스태틱 라우팅을 지우면 응답이 돌아오지 못합니다.", build: exampleTwoGatewaysTopology },
  hub: { id: "hub", group: "L2", label: "허브 vs 스위치", blurb: "pc-1 → pc-2 ping 이 허브의 모든 포트(공유기까지)로 복제되는 것과, pc-3 → pc-4 가 스위치에서 그 포트로만 가는 것을 비교하세요.", build: exampleHubTopology },
  vlan: { id: "vlan", group: "L2", label: "VLAN 으로 나눈 사무실 (트렁크 + 서브 인터페이스)", blurb: "같은 스위치인데 VLAN 10 과 20 은 게이트웨이 서브 인터페이스를 거쳐야 통신됩니다.", build: exampleVlanTopology },
  firewall: { id: "firewall", group: "서비스", label: "방화벽 (ping 은 되고 웹은 막힘)", blurb: "pc-1 에서 example.com 으로 ping 은 되지만 TCP 80 연결은 공유기 방화벽 규칙 1 에서 차단됩니다. 규칙 2(인바운드 ICMP 차단)는 바깥에서 먼저 시작한 ping 을 막는 규칙이고, 안에서 시작한 ping 의 응답은 Stateful 검사로 통과합니다.", build: exampleFirewallTopology },
  fwbox: {
    id: "fwbox",
    group: "서비스",
    label: "방화벽 장비 (서버 앞에 끼운 투명 방화벽)",
    blurb: "pc-1 → srv-1 ping 은 fw-1 에서 차단되지만 TCP 80 연결은 됩니다. srv-1 → pc-1 ping 은 응답이 Stateful 검사로 돌아오고, srv-1 → pc-1 traceroute 는 1홉 — fw-1 은 IP 가 없어 홉에 안 보입니다.",
    build: exampleFirewallApplianceTopology,
  },
  docker: {
    id: "docker",
    group: "서비스",
    label: "도커 호스트를 부품으로 (브리지 + MASQUERADE + -p + embedded DNS)",
    blurb: "pc-1 에서 172.18.0.2 로 ping 은 실패하지만(호스트 뒤 사설망), docker-host 의 LAN 주소:8080 으로 TCP 연결은 -p 포워딩으로 web 에 닿습니다. web 에서 db 는 이름으로, google.com 은 MASQUERADE 로 나갑니다.",
    build: exampleDockerTopology,
  },
  roaming: { id: "roaming", group: "무선", label: "무선 로밍 (같은 SSID 의 AP 두 대)", blurb: "phone-1 을 오른쪽 AP 쪽으로 끌면 가까운 AP 로 갈아타고 DHCP 로 새로 임대받습니다.", build: exampleRoamingTopology },
};

export const EXAMPLE_LIST: ExampleSpec[] = Object.values(EXAMPLES);
