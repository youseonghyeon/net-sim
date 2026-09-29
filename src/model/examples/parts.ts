// 예제 묶음 "기능 단위". 등록(메뉴 순서·설명)은 ../examples.ts 의 EXAMPLES.
import { type Cable, DEFAULT_DHCP_SERVER, type Device, type Topology, newId, zoneAround } from "../topology";
import { builder, cable } from "./build";

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
