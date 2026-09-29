// 예제 묶음 "라우팅". 등록(메뉴 순서·설명)은 ../examples.ts 의 EXAMPLES.
import { type Cable, DEFAULT_DHCP_SERVER, type Device, type L3Settings, type Topology, type Zone, type ZoneTint, newId, zoneAround } from "../topology";
import { builder, cable, iface } from "./build";

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
