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

/**
 * 포워드 프록시: 사무실 PC 는 방화벽 때문에 인터넷에 직접 못 나가고, 프록시 서버(Squid 식)만 나갈 수 있다.
 * pc-1 은 HTTP 프록시 설정(http_proxy)이 있어 웹 요청을 프록시에게 부탁하고, laptop-1 은 설정이 없어 막힌다.
 * 프록시는 이름도 대신 찾고(PC 는 외부 DNS 가 필요 없음), 차단 목록의 사이트는 403 으로 돌려준다.
 */
export function exampleProxyTopology(): Topology {
  const { devices, add } = builder();
  const PROXY = "192.168.0.10";
  const inet = add("internet", 344, -40, "internet-1");
  const rt = add("router", 344, 96, "공유기");
  rt.router = {
    ...rt.router!,
    firewall: {
      enabled: true,
      defaultPolicy: "allow",
      stateful: true,
      rules: [
        // 프록시 서버만 인터넷으로 나간다. 나머지 사무실 장비의 아웃바운드는 모두 차단
        { action: "allow", proto: "any", direction: "out", src: PROXY, dst: "", dstPort: "" },
        { action: "deny", proto: "any", direction: "out", src: "", dst: "", dstPort: "" },
      ],
    },
  };
  const sw = add("switch", 344, 272, "sw-1");
  const pc = add("pc", 120, 448, "pc-1");
  pc.host = { ...pc.host!, httpProxy: { enabled: true, server: PROXY, port: 3128 } };
  const laptop = add("laptop", 264, 448, "laptop-1");
  const proxy = add("server", 520, 448, "proxy-1");
  proxy.host = {
    ...proxy.host!,
    ipMode: "static",
    ip: PROXY,
    prefix: 24,
    gateway: "192.168.0.1",
    dns: "8.8.8.8",
    services: [],
    dhcpServer: { ...DEFAULT_DHCP_SERVER },
    proxy: { enabled: true, port: 3128, deny: ["naver.com"] },
  };
  const cables: Cable[] = [
    cable(inet, 0, rt, 0),
    cable(rt, 1, sw, 3),
    cable(sw, 0, pc, 0),
    cable(sw, 1, laptop, 0),
    cable(sw, 5, proxy, 0),
  ];
  const t: Topology = { devices, cables };
  t.zones = [{ id: newId("zone"), label: "인터넷으로 나갈 수 있는 유일한 장비", tint: "amber", ...zoneAround(t, [proxy.id], 24)! }];
  return t;
}
