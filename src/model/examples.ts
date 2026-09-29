// 예제 토폴로지와 레지스트리. 파일 메뉴의 "예제" 와 테스트가 쓴다.
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

// ---------- 조립 도우미 (예제마다 반복하던 것) ----------

/** 장치를 차례로 만든다. 이름·MAC 은 앞서 만든 장치 기준으로 정해지므로 만드는 순서가 곧 번호 순서다 */
function builder() {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number, name?: string): Device => {
    const d = createDevice(kind, x, y, devices);
    if (name) d.name = name;
    devices.push(d);
    return d;
  };
  return { devices, add };
}

/** 케이블 하나: a 장치의 ap 번 포트 ↔ b 장치의 bp 번 포트 */
function cable(a: Device, ap: number, b: Device, bp: number): Cable {
  return { id: newId("cable"), a: { device: a.id, port: ap }, b: { device: b.id, port: bp } };
}

/** 게이트웨이·NAT 박스의 수동 주소 인터페이스 (/24) */
function iface(ip: string, gateway = "") {
  return { ipMode: "static" as const, ip, prefix: 24, gateway };
}

/** 기능 단위 구성 예제: 인터넷 → NAT 박스 → 게이트웨이 → 스위치 2대(서브넷 2개) + DHCP 서버 호스트 */
export function examplePartsTopology(): Topology {
  const { devices, add } = builder();
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
    cable(inet, 0, nat, 0),
    cable(nat, 1, gw, 0),
    cable(gw, 1, sw1, 0),
    cable(gw, 2, sw2, 0),
    cable(sw1, 2, dhcp, 0),
    cable(sw1, 5, pc1, 0),
    cable(sw2, 3, laptop, 0),
    cable(sw2, 6, web, 0),
  ];
  return { devices, cables };
}

/** VLAN 예제: 인터넷 → NAT → 게이트웨이(if1 트렁크) → 스위치(VLAN 10: pc 2대, VLAN 20: 웹 서버 + 노트북) */
export function exampleVlanTopology(): Topology {
  const { devices, add } = builder();
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
    cable(inet, 0, nat, 0),
    cable(nat, 1, gw, 0),
    cable(gw, 1, sw, 0), // 트렁크
    cable(sw, 1, pc1, 0), // VLAN 10
    cable(sw, 2, pc2, 0), // VLAN 10
    cable(sw, 5, laptop, 0), // VLAN 20
    cable(sw, 6, web, 0), // VLAN 20
  ];
  return { devices, cables };
}

/** 인터넷 + 공유기(라우터) + 스위치 + 호스트 3대 예제 */
export function exampleTopology(): Topology {
  const { devices, add } = builder();
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
    cable(inet, 0, rt, 0), // isp ↔ wan
    cable(rt, 1, sw, 0), // lan1 ↔ eth1
    cable(sw, 2, pc, 0), // eth2
    cable(sw, 4, laptop, 0), // eth4
    cable(sw, 6, srv, 0), // eth6
  ];
  return { devices, cables };
}

/** 가장 단순한 예제: PC 2대 + 스위치, 수동 IP. ARP 와 ping 만 본다 */
export function exampleStarterTopology(): Topology {
  const { devices, add } = builder();
  const sw = add("switch", 344, 96);
  const pc1 = add("pc", 232, 280);
  const pc2 = add("pc", 544, 280);
  pc1.host = { ipMode: "static", ip: "192.168.0.10", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  pc2.host = { ipMode: "static", ip: "192.168.0.11", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const cables: Cable[] = [
    cable(sw, 1, pc1, 0),
    cable(sw, 6, pc2, 0),
  ];
  return { devices, cables };
}

/** 게이트웨이 2단: NAT 아래에 라우터 전용 서브넷(10.0.0.0/24)을 두고 게이트웨이 둘이 각자 서브넷을 맡는다 */
export function exampleTwoGatewaysTopology(): Topology {
  const { devices, add } = builder();
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
    cable(inet, 0, nat, 0),
    cable(nat, 1, sw0, 3),
    cable(sw0, 0, gw1, 0),
    cable(sw0, 7, gw2, 0),
    cable(gw1, 1, sw1, 3),
    cable(gw2, 1, sw2, 3),
    cable(sw1, 0, pc1, 0),
    cable(sw1, 5, pc2, 0),
    cable(sw2, 1, pc3, 0),
    cable(sw2, 6, srv, 0),
  ];
  return { devices, cables };
}

/** 집 두 곳 잇기: 인터넷 없이 게이트웨이 둘을 if0 끼리 직접 잇고, 서로의 서브넷을 스태틱 라우팅으로 안다 */
export function exampleTwoHomesTopology(): Topology {
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
 * 동적 라우팅: 게이트웨이 3대가 삼각형으로 직결되고 각자 LAN 을 하나씩 가진다. 스태틱 라우팅 없이 RIP 로 서로의 LAN 을 배운다.
 * 링크 하나를 끊으면 RIP 가 경로를 철회하고 남은 길(다른 게이트웨이 경유)로 다시 수렴한다
 */
export function exampleRipTopology(): Topology {
  const { devices, add } = builder();
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
  const { devices, add } = builder();
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
      cable(gw, 0, bb, h.bbPort),
      cable(gw, 1, sw, 3),
      cable(sw, 0, a, 0),
      cable(sw, 6, b, 0),
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
  const { devices, add } = builder();
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
    cable(inet, 0, rt, 0),
    cable(rt, 1, sw, 3),
    cable(sw, 0, pc, 0),
    cable(sw, 7, host, 0), // 호스트 NIC
    cable(host, 1, br, 3), // 브리지 게이트웨이
    cable(br, 0, web, 0), // veth
    cable(br, 4, db, 0),
    cable(br, 7, dns, 0),
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
  const { devices, add } = builder();
  const rt = add("router", 344, 0);
  const hub = add("hub", 112, 200);
  const sw = add("switch", 560, 200);
  const pc1 = add("pc", 40, 376);
  const pc2 = add("pc", 200, 376);
  const pc3 = add("pc", 504, 376);
  const pc4 = add("pc", 664, 376);
  const cables: Cable[] = [
    cable(rt, 1, hub, 1),
    cable(rt, 4, sw, 3),
    cable(hub, 0, pc1, 0),
    cable(hub, 3, pc2, 0),
    cable(sw, 0, pc3, 0),
    cable(sw, 7, pc4, 0),
  ];
  return { devices, cables };
}

/** 방화벽: 공유기가 나가는 TCP 80 만 막는다. ping 은 되고 웹 연결만 차단되는 걸 본다 */
export function exampleFirewallTopology(): Topology {
  const { devices, add } = builder();
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
    cable(inet, 0, rt, 0),
    cable(rt, 1, sw, 0),
    cable(sw, 2, pc, 0),
    cable(sw, 5, laptop, 0),
  ];
  return { devices, cables };
}

/**
 * 방화벽 이중화 (VRRP 식): NAT 박스 두 대가 가상 주소(바깥 203.0.113.10, 안쪽 192.168.0.1)를 함께 두고 한 대만 일한다.
 * 호스트의 기본 게이트웨이는 가상 주소라, master(방화벽 A)의 케이블을 뽑거나 지워도 backup(방화벽 B)이 이어받아 설정 변경 없이 계속 나간다.
 * 두 대의 규칙은 같게 둔다 (실제 HA 쌍은 설정을 자동으로 맞추지만 여기서는 손으로).
 */
export function exampleHaTopology(): Topology {
  const { devices, add } = builder();
  const staticHost = (d: Device, ip: string, services: number[] = []) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway: "192.168.0.1", dns: "8.8.8.8", services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  const firewall = () => ({
    enabled: true,
    defaultPolicy: "deny" as const,
    stateful: true,
    rules: [{ action: "allow" as const, proto: "any" as const, direction: "out" as const, src: "", dst: "", dstPort: "" }],
  });
  const inet = add("internet", 344, -296, "internet-1");
  const swOut = add("switch", 344, -168, "outside 스위치");
  const fwA = add("nat", 200, -24, "방화벽 A");
  fwA.l3 = {
    interfaces: [iface("203.0.113.11", "203.0.113.1"), iface("192.168.0.2")],
    routes: [],
    firewall: firewall(),
    ha: { enabled: true, vrid: 10, priority: 200, vips: ["203.0.113.10", "192.168.0.1"] },
  };
  const fwB = add("nat", 488, -24, "방화벽 B");
  fwB.l3 = {
    interfaces: [iface("203.0.113.12", "203.0.113.1"), iface("192.168.0.3")],
    routes: [],
    firewall: firewall(),
    ha: { enabled: true, vrid: 10, priority: 100, vips: ["203.0.113.10", "192.168.0.1"] },
  };
  const swIn = add("switch", 344, 136, "inside 스위치");
  const pc1 = add("pc", 216, 296, "pc-1");
  const pc2 = add("pc", 344, 296, "pc-2");
  const laptop = add("laptop", 472, 296, "laptop-1");
  staticHost(pc1, "192.168.0.10");
  staticHost(pc2, "192.168.0.11");
  staticHost(laptop, "192.168.0.12");
  const cables: Cable[] = [
    cable(swOut, 3, inet, 0),
    cable(swOut, 1, fwA, 0),
    cable(swOut, 6, fwB, 0),
    cable(fwA, 1, swIn, 1),
    cable(fwB, 1, swIn, 6),
    cable(swIn, 2, pc1, 0),
    cable(swIn, 4, pc2, 0),
    cable(swIn, 5, laptop, 0),
  ];
  const t: Topology = { devices, cables };
  t.zones = [{ id: newId("zone"), label: "HA 쌍 · 가상 주소 203.0.113.10 / 192.168.0.1", tint: "amber", ...zoneAround(t, [fwA.id, fwB.id], 24)! }];
  return t;
}

/** 방화벽 장비: 스위치와 서버 사이에 투명 방화벽을 끼워 서버로 오는 ping 만 막는다. 주소는 하나도 안 바꾼다 */
export function exampleFirewallApplianceTopology(): Topology {
  const { devices, add } = builder();
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
    cable(rt, 1, sw, 3),
    cable(sw, 0, pc, 0),
    cable(sw, 2, laptop, 0),
    cable(sw, 7, fw, 0), // outside ← 스위치
    cable(fw, 1, srv, 0), // inside → 서버
  ];
  const t: Topology = { devices, cables };
  t.zones = [{ id: newId("zone"), label: "방화벽 뒤 (보호 구역)", tint: "amber", ...zoneAround(t, [fw.id, srv.id], 20)! }];
  return t;
}

/** 무선 로밍: 같은 SSID 의 AP 두 대. 스마트폰을 끌어 옮기면 가까운 AP 로 갈아탄다 */
export function exampleRoamingTopology(): Topology {
  const { devices, add } = builder();
  const rt = add("router", 344, 0);
  const sw = add("switch", 344, 176);
  const ap1 = add("ap", 16, 352);
  const ap2 = add("ap", 704, 352);
  ap1.ap = { enabled: true, ssid: "office" };
  ap2.ap = { enabled: true, ssid: "office" };
  const phone = add("phone", 56, 544);
  phone.wifi = { ssid: "office" };
  const cables: Cable[] = [
    cable(rt, 1, sw, 3),
    cable(sw, 0, ap1, 0),
    cable(sw, 7, ap2, 0),
  ];
  return { devices, cables };
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
 * 로드밸런서 두 형태 비교: 서버에 LB 서비스를 켠 "nginx 서버" 와 로드밸런서 전용 장비가 같은 웹 서버들 앞에 선다.
 * 공유기의 포트 포워딩(공인 :80 → 로드밸런서 장비)으로 바깥 요청도 NAT → 로드밸런서 → 웹 서버로 간다.
 */
export function exampleLoadBalancerTopology(): Topology {
  const { devices, add } = builder();
  const staticHost = (d: Device, ip: string, services: number[] = []) => {
    d.host = { ...d.host!, ipMode: "static", ip, prefix: 24, gateway: "192.168.0.1", dns: "192.168.0.1", services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  const inet = add("internet", 344, -40, "internet-1");
  const rt = add("router", 344, 96, "공유기");
  rt.router = { ...rt.router!, forwards: [{ publicPort: 80, lanIp: "192.168.0.20", lanPort: 80 }] };
  const sw = add("switch", 344, 272, "sw-1");
  const pc1 = add("pc", -96, 448, "pc-1");
  const pc2 = add("laptop", 32, 448, "laptop-1");
  // 형태 1: 서버에 로드밸런서 서비스(nginx 같은 소프트웨어)를 켠다
  const nginx = add("server", 200, 448, "nginx 서버");
  staticHost(nginx, "192.168.0.10");
  nginx.host!.lb = { enabled: true, port: 80, algorithm: "round-robin", backends: [{ ip: "192.168.0.11", port: 80 }, { ip: "192.168.0.12", port: 80 }] };
  // 형태 2: 로드밸런서 전용 장비 (같은 모듈, 최소 연결)
  const lbDev = add("lb", 328, 448, "lb-1");
  staticHost(lbDev, "192.168.0.20");
  lbDev.host!.lb = { enabled: true, port: 80, algorithm: "least-conn", backends: [{ ip: "192.168.0.11", port: 80 }, { ip: "192.168.0.12", port: 80 }, { ip: "192.168.0.13", port: 80 }] };
  const webs = [
    add("server", 496, 448, "web-1"),
    add("server", 624, 448, "web-2"),
    add("server", 752, 448, "web-3"),
  ];
  webs.forEach((w, i) => staticHost(w, `192.168.0.1${i + 1}`, [80]));

  const cables: Cable[] = [
    cable(inet, 0, rt, 0),
    cable(rt, 1, sw, 3),
    cable(sw, 0, pc1, 0),
    cable(sw, 1, pc2, 0),
    cable(sw, 2, nginx, 0),
    cable(sw, 4, lbDev, 0),
    cable(sw, 5, webs[0]!, 0),
    cable(sw, 6, webs[1]!, 0),
    cable(sw, 7, webs[2]!, 0),
  ];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "앞단: 로드밸런서 (서버 토글 · 전용 장비)", tint: "amber", ...zoneAround(t, [nginx.id, lbDev.id], 24)! },
    { id: newId("zone"), label: "백엔드: 웹 서버", tint: "green", ...zoneAround(t, webs.map((w) => w.id), 24)! },
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

export type ExampleId = "starter" | "router" | "parts" | "homes" | "backbone" | "rip" | "gateways" | "hub" | "vlan" | "firewall" | "fwbox" | "ha" | "publish" | "internet" | "vpn" | "ncp" | "lb" | "roaming" | "docker";

export interface ExampleSpec {
  id: ExampleId;
  /** 메뉴 묶음 */
  group: string;
  label: string;
  /** 불러온 뒤 무엇을 해 보면 되는지 한 줄 */
  blurb: string;
  build: () => Topology;
}

// 메뉴 순서 = 학습 순서: 기본 → 기능 단위 → 라우팅 → L2 → 보안 → 인터넷 → 무선. 이름은 짧게, 괄호에는 배우는 것만
export const EXAMPLES: Record<ExampleId, ExampleSpec> = {
  starter: {
    id: "starter",
    group: "기본",
    label: "PC 두 대 잇기 (ARP·ping)",
    blurb: "pc-1 에서 pc-2 로 ping 하면 ARP 로 MAC 을 찾은 뒤 ICMP 가 오갑니다.",
    build: exampleStarterTopology,
  },
  router: {
    id: "router",
    group: "기본",
    label: "집 공유기 (DHCP·NAT·Wi-Fi)",
    blurb: "케이블만 꽂으면 DHCP 로 주소를 받고, google.com 으로 ping 하면 DNS → NAT 를 거칩니다.",
    build: exampleTopology,
  },
  parts: {
    id: "parts",
    group: "기능 단위",
    label: "공유기를 부품으로 (NAT·게이트웨이·DHCP/DNS 서버)",
    blurb: "공유기를 상자별로 뜯은 구성. 노트북은 게이트웨이 릴레이로 다른 서브넷의 DHCP 서버에서 주소를 받습니다.",
    build: examplePartsTopology,
  },
  docker: {
    id: "docker",
    group: "기능 단위",
    label: "도커 호스트를 부품으로 (브리지·MASQUERADE·포트 공개)",
    blurb: "pc-1 에서 172.18.0.2 로 ping 은 실패하지만(호스트 뒤 사설망), docker-host 의 LAN 주소:8080 으로 TCP 연결은 -p 포워딩으로 web 에 닿습니다. web 에서 db 는 이름으로, google.com 은 MASQUERADE 로 나갑니다.",
    build: exampleDockerTopology,
  },
  gateways: {
    id: "gateways",
    group: "라우팅",
    label: "게이트웨이 2단 (스태틱 라우팅)",
    blurb: "pc-1 → 192.168.5.10 은 gw-1 이 스태틱 라우팅으로 gw-2 에 바로 넘기고, 인터넷은 NAT 로 올라갑니다. NAT 의 스태틱 라우팅을 지우면 응답이 돌아오지 못합니다.",
    build: exampleTwoGatewaysTopology,
  },
  homes: {
    id: "homes",
    group: "라우팅",
    label: "두 집 직접 잇기 (인터넷 없음)",
    blurb: "pc-1 → 192.168.2.10 은 gw-1 → gw-2 두 홉을 지납니다. \"경로\" 로 홉을 확인하고, gw-1 의 스태틱 라우팅을 지우면 No route 로 실패합니다.",
    build: exampleTwoHomesTopology,
  },
  backbone: {
    id: "backbone",
    group: "라우팅",
    label: "백본 스위치로 세 집 잇기",
    blurb: "게이트웨이 셋의 if0 이 sw-backbone(10.0.0.0/24) 에서 만납니다. 게이트웨이마다 다른 두 집으로 가는 스태틱 라우팅이 있고, 하나를 지우면 그 집만 못 갑니다.",
    build: exampleBackboneTopology,
  },
  rip: {
    id: "rip",
    group: "라우팅",
    label: "동적 라우팅 RIP (끊기면 우회)",
    blurb: "스태틱 라우팅 없이 RIP 로 서로의 LAN 을 배웁니다(게이트웨이 → 표 탭의 라우팅 테이블). pc-a 에서 192.168.3.10 으로 \"경로\" 를 본 뒤 gw-a ↔ gw-c 케이블을 지우면, RIP 가 경로를 철회하고 gw-b 를 거치는 길로 다시 수렴합니다.",
    build: exampleRipTopology,
  },
  hub: {
    id: "hub",
    group: "L2",
    label: "허브 vs 스위치",
    blurb: "pc-1 → pc-2 ping 이 허브의 모든 포트(공유기까지)로 복제되는 것과, pc-3 → pc-4 가 스위치에서 그 포트로만 가는 것을 비교하세요.",
    build: exampleHubTopology,
  },
  vlan: {
    id: "vlan",
    group: "L2",
    label: "VLAN 으로 나눈 사무실 (트렁크)",
    blurb: "같은 스위치인데 VLAN 10 과 20 은 게이트웨이 서브 인터페이스를 거쳐야 통신됩니다.",
    build: exampleVlanTopology,
  },
  firewall: {
    id: "firewall",
    group: "보안",
    label: "공유기 방화벽 (ping 은 되고 웹은 막힘)",
    blurb: "pc-1 에서 example.com 으로 ping 은 되지만 TCP 80 연결은 공유기 방화벽 규칙 1 에서 차단됩니다. 규칙 2(인바운드 ICMP 차단)는 바깥에서 먼저 시작한 ping 을 막는 규칙이고, 안에서 시작한 ping 의 응답은 Stateful 검사로 통과합니다.",
    build: exampleFirewallTopology,
  },
  fwbox: {
    id: "fwbox",
    group: "보안",
    label: "투명 방화벽 장비 (서버 앞)",
    blurb: "pc-1 → srv-1 ping 은 fw-1 에서 차단되지만 TCP 80 연결은 됩니다. srv-1 → pc-1 ping 은 응답이 Stateful 검사로 돌아오고, srv-1 → pc-1 traceroute 는 1홉 — fw-1 은 IP 가 없어 홉에 안 보입니다.",
    build: exampleFirewallApplianceTopology,
  },
  ha: {
    id: "ha",
    group: "보안",
    label: "방화벽 이중화 (VRRP)",
    blurb: "pc-1 에서 8.8.8.8 로 ping 하면 master 인 방화벽 A 가 NAT 합니다. 방화벽 A 의 케이블을 지우고(또는 장치를 지우고) 다시 ping 하면 방화벽 B 가 가상 주소를 이어받아 그대로 나갑니다. 케이블을 되돌리면 우선순위가 높은 A 가 다시 가져갑니다. pc-1 에서 93.184.216.34 로 SSH(22) 세션을 열어 둔 채 A 를 지우고 '연결 해제' 하면 끊기지만, 두 방화벽의 이중화 설정에서 세션 동기화를 켜면 이어집니다.",
    build: exampleHaTopology,
  },
  lb: {
    id: "lb",
    group: "서비스",
    label: "로드밸런서 (서버 토글 vs 전용 장비)",
    blurb: "pc-1 에서 192.168.0.10(nginx 서버) 이나 192.168.0.20(lb-1) 으로 TCP 연결을 여러 번 보내 보세요. 진단 목록의 \"응답\" 이 web-1 → web-2 로 바뀝니다. web-2 의 웹 서버를 끄면 그 차례 요청은 거부되고 곧바로 다른 서버로 넘어가며 10초 동안 빠집니다. 인터넷 노드의 외부 접속으로 공인 주소:80 에 들어오면 포트 포워딩 → lb-1 → 웹 서버로 갑니다.",
    build: exampleLoadBalancerTopology,
  },
  internet: {
    id: "internet",
    group: "인터넷",
    label: "인터넷의 뼈대 (가장자리 트리 · 중심 그물)",
    blurb: "pc-1 에서 nexus.com 으로 \"경로\" 와 TCP 연결을 보내 보세요. 집 공유기 → KT 국사 → KT 백본 → SK 백본 → SK 국사 → 회사 NAT. 가장자리는 디폴트 라우트로 위로만 올라가고(트리), 백본 셋은 RIP 로 경로를 주고받습니다(그물, 실제로는 BGP). KT 백본 ↔ SK 백본 케이블을 지우면 구글 망을 돌아가는 길로 다시 수렴합니다.",
    build: exampleInternetTopology,
  },
  publish: {
    id: "publish",
    group: "인터넷",
    label: "도메인으로 회사 웹 서버 접속 (DNS·NAT·포트 포워딩)",
    blurb: "맥북에서 nexus.com:80 으로 TCP 연결을 보내 보세요. 공인 DNS 8.8.8.8(ISP 라우터 너머)이 회사 공인 주소를 알려 주고, 집 NAT(출발지 변환) → 회사 NAT 포트 포워딩(목적지 변환) → 방화벽(웹 서버 80 만 허용) → 웹 서버로 갑니다. srv-1(192.168.1.3)은 사설 주소라 밖에서 직접 닿지 않습니다.",
    build: examplePublishTopology,
  },
  vpn: {
    id: "vpn",
    group: "인터넷",
    label: "VPN 으로 두 사무실 잇기 (터널·캡슐화)",
    blurb: "pc-a 에서 192.168.2.10 으로 ping 하면 사설 주소끼리 바로 닿습니다. 통신사 구간을 지나는 패킷을 눌러 보면 바깥은 공인 주소끼리의 UDP 51820 뿐이고, 원래 패킷은 \"터널 안\" 에 암호화돼 있습니다. NAT 박스 한쪽의 VPN 을 끄면 사설 주소는 인터넷으로 나갈 수 없어 실패합니다.",
    build: exampleVpnTopology,
  },
  ncp: {
    id: "ncp",
    group: "인터넷",
    label: "망분리 사무실 + NCP (IPsec VPN)",
    blurb: "내부망 PC 1 에서 dev-2(192.168.112.11)로 TCP 22 연결하면, 첫 패킷에 IKE 로 IPsec 터널을 맺은 뒤 ESP 로 NCP 서버에 닿습니다. 외부망 PC 에서는 닿지 않습니다. prod 는 172.21.4.11 입니다.",
    build: exampleNcpVpnTopology,
  },
  roaming: {
    id: "roaming",
    group: "무선",
    label: "무선 로밍 (AP 두 대)",
    blurb: "phone-1 을 오른쪽 AP 쪽으로 끌면 가까운 AP 로 갈아탑니다. 주소는 새로 받지 않고, 쓰던 주소를 DHCP Request 로 확인만 하고 그대로 씁니다(INIT-REBOOT).",
    build: exampleRoamingTopology,
  },
};

export const EXAMPLE_LIST: ExampleSpec[] = Object.values(EXAMPLES);
