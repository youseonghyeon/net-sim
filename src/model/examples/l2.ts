// 예제 묶음 "L2". 등록(메뉴 순서·설명)은 ../examples.ts 의 EXAMPLES.
import { type Cable, DEFAULT_DHCP_SERVER, type Device, type Topology, newId, zoneAround } from "../topology";
import { builder, cable } from "./build";

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

/**
 * 스위치 이중화 (STP): 스위치 세 대를 삼각형으로 이어 경로를 두 개로 만든다. STP 가 한 포트를 막아(대체 포트) 루프를 끊고,
 * 쓰던 링크가 끊기면 막았던 포트를 열어 다른 경로로 돌아간다. core-1 의 우선순위를 가장 낮게(4096) 두어 루트로 정한다.
 */
export function exampleStpTopology(): Topology {
  const { devices, add } = builder();
  const staticHost = (d: Device, ip: string) => {
    d.host = { ipMode: "static", ip, prefix: 24, gateway: "", services: d.kind === "server" ? [80, 22] : [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  const core1 = add("switch", 200, 0, "core-1");
  core1.switch = { vlans: {}, stp: { enabled: true, priority: 4096 } };
  const core2 = add("switch", 520, 0, "core-2");
  core2.switch = { vlans: {}, stp: { enabled: true, priority: 8192 } };
  const access = add("switch", 360, 200, "access-1");
  access.switch = { vlans: {}, stp: { enabled: true, priority: 32768 } };
  const pc1 = add("pc", 296, 360, "pc-1");
  const pc2 = add("pc", 424, 360, "pc-2");
  const srv = add("server", 648, 160, "srv-1");
  const srv2 = add("server", 72, 160, "srv-2");
  staticHost(pc1, "192.168.0.11");
  staticHost(pc2, "192.168.0.12");
  staticHost(srv, "192.168.0.21");
  staticHost(srv2, "192.168.0.22");
  const cables: Cable[] = [
    cable(core1, 7, core2, 0),
    cable(core1, 5, access, 1),
    cable(core2, 2, access, 6),
    cable(access, 3, pc1, 0),
    cable(access, 4, pc2, 0),
    cable(core2, 7, srv, 0),
    cable(core1, 0, srv2, 0),
  ];
  const t: Topology = { devices, cables };
  t.zones = [{ id: newId("zone"), label: "스위치 삼각형 (경로 두 개) — STP 가 한 포트를 막음", tint: "blue", ...zoneAround(t, [core1.id, core2.id, access.id], 24)! }];
  return t;
}

/**
 * IPTV 멀티캐스트와 IGMP 스누핑: IPTV 서버가 그룹 239.1.1.1 로 영상 조각을 보내면, 스누핑이 없는 스위치는 모든 포트로 뿌린다.
 * 거실 TV 만 그룹에 가입(IGMP Report)했는데 안방 PC·노트북 링크까지 채운다 — 스누핑을 켜면 TV 포트로만
 */
export function exampleIgmpTopology(): Topology {
  const { devices, add } = builder();
  const rt = add("router", 344, -120, "공유기");
  const sw = add("switch", 344, 40, "거실 스위치");
  const srv = add("server", 96, 200, "IPTV 서버");
  srv.host = { ipMode: "static", ip: "192.168.0.10", prefix: 24, gateway: "192.168.0.1", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const tv = add("pc", 272, 200, "거실 TV");
  const pc = add("pc", 448, 200, "안방 PC");
  const lap = add("laptop", 616, 200, "노트북");
  const cables: Cable[] = [cable(rt, 1, sw, 0), cable(sw, 1, srv, 0), cable(sw, 3, tv, 0), cable(sw, 5, pc, 0), cable(sw, 7, lap, 0)];
  const t: Topology = { devices, cables };
  t.zones = [{ id: newId("zone"), label: "거실 LAN · 그룹 239.1.1.1", tint: "blue", ...zoneAround(t, [sw.id, srv.id, tv.id, pc.id, lap.id], 48)! }];
  return t;
}
