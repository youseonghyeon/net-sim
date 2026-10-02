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
