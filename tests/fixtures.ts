// 테스트용 고정 토폴로지 (예제 메뉴에서는 빠졌지만 테스트가 기대는 구성)
import { type Cable, DEFAULT_DHCP_SERVER, type Device, type L3Settings, type Topology, newId, zoneAround } from "../src/model/topology";
import { builder, cable } from "../src/model/examples/build";

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
