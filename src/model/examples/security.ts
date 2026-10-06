// 예제 묶음 "보안". 등록(메뉴 순서·설명)은 ../examples.ts 의 EXAMPLES.
import { type Cable, DEFAULT_DHCP_SERVER, type Device, type Topology, newId, zoneAround } from "../topology";
import { builder, cable, iface } from "./build";

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

/**
 * 드롭인 게이트웨이 (GL.iNet Drop-in Gateway): 기존 공유기는 그대로 두고 Brume 의 WAN 만 기존 LAN 에 꽂는다.
 * 아이 PC 는 게이트웨이를 Brume(192.168.0.2)으로 적어 Brume 의 DPI(게임 차단)를 거치고, 아빠 PC 는 기존 공유기로 바로 나간다
 */
export function exampleDropInTopology(): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 344, -296, "internet-1");
  const isp = add("router", 344, -152, "기존 공유기");
  isp.router = { ...isp.router!, lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.199" } };
  const sw = add("switch", 344, -8, "거실 스위치");
  const brume = add("router", 600, 120, "Brume 3 (드롭인)");
  brume.router = {
    ...brume.router!,
    lanIp: "192.168.8.1",
    lanPrefix: 24,
    dhcp: { enabled: true, start: "192.168.8.100", end: "192.168.8.199" },
    wan: { ipMode: "static", ip: "192.168.0.2", prefix: 24, gateway: "192.168.0.1" },
    dropIn: true,
    dpi: { enabled: true, blockApps: [], blockCategories: ["게임"] },
  };
  const kid = add("pc", 216, 168, "아이 PC");
  kid.host = { ...kid.host!, ipMode: "static", ip: "192.168.0.50", prefix: 24, gateway: "192.168.0.2", dns: "8.8.8.8" };
  const dad = add("pc", 440, 168, "아빠 PC");
  const cables: Cable[] = [cable(isp, 0, inet, 0), cable(isp, 1, sw, 1), cable(sw, 2, kid, 0), cable(sw, 4, dad, 0), cable(sw, 6, brume, 0)];
  const t: Topology = { devices, cables };
  t.zones = [{ id: newId("zone"), label: "기존 LAN 192.168.0.0/24", tint: "blue", ...zoneAround(t, [sw.id, kid.id, dad.id, brume.id], 48)! }];
  return t;
}
