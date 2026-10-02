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

/**
 * 도커 네트워크 (맥의 Docker Desktop 구조): 컨테이너는 맥 안의 Linux VM 에 있고, 맥과 VM 은 가상 링크(vmnet)로 이어진다.
 * - macOS = 게이트웨이(if0 집 LAN · if1 lo 127.0.0.1 · if2 vmnet) + NAT, 맥 터미널 = lo 에 붙은 맥 안의 앱 (localhost 로 접속하는 쪽)
 * - Docker VM = 게이트웨이(if0 vmnet · if1 docker0 · if2 br-app) + NAT(MASQUERADE) + 방화벽(DOCKER-ISOLATION: 브리지끼리 막음)
 * - 포트 공개는 두 번: macOS 가 맥의 포트를 VM 으로(Docker Desktop 포트 포워딩), VM 이 컨테이너로(docker -p). 둘 다 docker-proxy 식이라 대상은 바로 앞 장비가 연 연결로 본다
 * - 내장 DNS 는 실제로는 컨테이너마다 127.0.0.11 — 여기서는 br-app 의 서버 하나(172.18.0.11)로 그린다. 기본 브리지(docker0)에는 없다
 * 리눅스에서 도커를 바로 돌리면 VM 이 없고 macOS 자리의 컴퓨터가 곧 Docker VM 이다 (그래서 리눅스 호스트는 172.18.0.2 로 바로 닿는다)
 */
export function exampleDockerTopology(): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 552, -336);
  const rt = add("router", 552, -192, "집 공유기");
  const pc = add("pc", 96, -24, "집 PC");
  const mac = add("gateway", 552, 8, "macOS");
  mac.l3 = {
    interfaces: [
      { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" }, // if0: Wi-Fi(집 LAN) — 공유기에서 주소를 받는다
      { ipMode: "static", ip: "127.0.0.1", prefix: 8, gateway: "" }, // if1: lo — 맥 안의 앱이 localhost 로 오는 곳
      { ipMode: "static", ip: "192.168.64.1", prefix: 24, gateway: "" }, // if2: vmnet — Docker VM 과 잇는 가상 링크
    ],
    routes: [],
    nat: { enabled: true }, // VM 의 바깥 통신을 맥 주소로 (macOS vmnet 공유 모드)
    // Docker Desktop 포트 포워딩: 맥의 포트를 VM 의 같은 포트로. -p 127.0.0.1:5432:5432 는 맥의 127.0.0.1 에만
    publish: [
      { port: 8080, bind: "0.0.0.0", to: "192.168.64.2", toPort: 8080 },
      { port: 5432, bind: "127.0.0.1", to: "192.168.64.2", toPort: 5432 },
    ],
  };
  const app = add("pc", 328, 192, "맥 터미널");
  app.host = { ipMode: "static", ip: "127.0.0.2", prefix: 8, gateway: "127.0.0.1", dns: "192.168.0.1", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const vm = add("gateway", 664, 192, "Docker VM");
  vm.l3 = {
    interfaces: [
      { ipMode: "static", ip: "192.168.64.2", prefix: 24, gateway: "192.168.64.1" }, // if0: eth0 (vmnet 쪽)
      { ipMode: "static", ip: "172.17.0.1", prefix: 16, gateway: "" }, // if1: docker0 (기본 브리지)
      { ipMode: "static", ip: "172.18.0.1", prefix: 16, gateway: "" }, // if2: br-app (docker network create app)
    ],
    routes: [],
    nat: { enabled: true }, // 컨테이너 → 바깥은 MASQUERADE
    // docker run -p 8080:80 web / -p 5432:5432 db
    publish: [
      { port: 8080, bind: "0.0.0.0", to: "172.18.0.2", toPort: 80 },
      { port: 5432, bind: "0.0.0.0", to: "172.18.0.3", toPort: 5432 },
    ],
    // DOCKER-ISOLATION: 서로 다른 브리지 네트워크끼리는 같은 호스트여도 막는다
    firewall: {
      enabled: true,
      defaultPolicy: "allow",
      stateful: true,
      rules: [
        { action: "deny", proto: "any", direction: "any", src: "172.17.0.0/16", dst: "172.18.0.0/16", dstPort: "" },
        { action: "deny", proto: "any", direction: "any", src: "172.18.0.0/16", dst: "172.17.0.0/16", dstPort: "" },
      ],
    },
  };
  const docker0 = add("switch", 488, 368, "docker0");
  const brApp = add("switch", 816, 368, "br-app");
  const container = (d: Device, ip: string, gw: string, dns: string, services: number[]) => {
    d.host = { ipMode: "static", ip, prefix: 16, gateway: gw, dns, services, dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  };
  const old = add("server", 536, 536, "old-app");
  container(old, "172.17.0.2", "172.17.0.1", "8.8.8.8", [80]); // 기본 브리지: 호스트의 DNS 설정을 그대로 받아 이름으로 다른 컨테이너를 못 찾는다
  const web = add("server", 768, 536, "web");
  const db = add("server", 864, 536, "db");
  const dns = add("server", 960, 536, "내장 DNS");
  container(web, "172.18.0.2", "172.18.0.1", "172.18.0.11", [80]);
  container(db, "172.18.0.3", "172.18.0.1", "172.18.0.11", [5432]);
  container(dns, "172.18.0.11", "172.18.0.1", "8.8.8.8", []);
  // 같은 사용자 정의 네트워크의 컨테이너 이름. 모르는 이름은 호스트가 쓰는 DNS 로 넘긴다
  dns.host!.dnsServer = { enabled: true, records: [{ name: "web", ip: "172.18.0.2" }, { name: "db", ip: "172.18.0.3" }], upstream: "8.8.8.8" };
  const cables: Cable[] = [
    cable(inet, 0, rt, 0),
    cable(rt, 1, pc, 0),
    cable(rt, 2, mac, 0),
    cable(mac, 1, app, 0),
    cable(mac, 2, vm, 0),
    cable(vm, 1, docker0, 3),
    cable(vm, 2, brApp, 3),
    cable(docker0, 4, old, 0),
    cable(brApp, 1, web, 0),
    cable(brApp, 4, db, 0),
    cable(brApp, 7, dns, 0),
  ];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "맥북 한 대 안 (if0 Wi-Fi · if1 lo · if2 vmnet)", tint: "blue", ...zoneAround(t, [mac.id, app.id, vm.id, docker0.id, brApp.id, old.id, web.id, db.id, dns.id], 40)! },
    { id: newId("zone"), label: "Docker VM 안 (Linux)", tint: "green", ...zoneAround(t, [vm.id, docker0.id, brApp.id, old.id, web.id, db.id, dns.id], 16)! },
  ];
  return t;
}
