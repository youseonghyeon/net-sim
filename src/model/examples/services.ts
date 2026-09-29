// 예제 묶음 "서비스". 등록(메뉴 순서·설명)은 ../examples.ts 의 EXAMPLES.
import { type Cable, DEFAULT_DHCP_SERVER, type Device, type Topology, newId, zoneAround } from "../topology";
import { builder, cable } from "./build";

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
