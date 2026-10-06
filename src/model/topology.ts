// 편집 가능한 토폴로지 모델. 시뮬레이션 코어(src/core)와 분리되어 있고, 실행 시 코어 Network 로 변환된다.
import { wgPrivateKey, wgPublicKey } from "../core/nodes/wg";
import { ovpnCaOf, ovpnTlsCryptOf } from "../core/nodes/openvpn";

export type DeviceKind = "pc" | "laptop" | "phone" | "server" | "lb" | "switch" | "hub" | "ap" | "router" | "gateway" | "nat" | "firewall" | "internet";
export type Role = "host" | "switch" | "hub" | "ap" | "router" | "l3" | "internet" | "firewall";
export type PortSide = "top" | "bottom";

export interface PortSpec {
  name: string;
  side: PortSide;
  /** 무선 슬롯: 케이블을 꽂을 수 없고 화면에 포트로 그리지 않는다 */
  radio?: boolean;
}

/** 무선 전파가 닿는 거리 (캔버스 픽셀). 이 안에 있고 SSID 가 같으면 붙는다 */
export const WIFI_RANGE = 300;
const radioSlots = (n: number): PortSpec[] => Array.from({ length: n }, (_, i) => ({ name: `무선 ${i + 1}`, side: "top" as const, radio: true }));

export interface DeviceSpec {
  kind: DeviceKind;
  label: string;
  role: Role;
  width: number;
  height: number;
  ports: PortSpec[];
  namePrefix: string;
}

const lanPorts = (n: number, side: PortSide, prefix = "eth", from = 0): PortSpec[] =>
  Array.from({ length: n }, (_, i) => ({ name: `${prefix}${from + i}`, side }));

export const DEVICE_SPECS: Record<DeviceKind, DeviceSpec> = {
  pc: { kind: "pc", label: "PC", role: "host", width: 64, height: 64, ports: [{ name: "eth0", side: "top" }], namePrefix: "pc" },
  // 노트북: 유선 eth0 + 무선 wlan0 (무선은 Wi-Fi 를 켰을 때만). 둘 다 붙어 있으면 유선을 쓴다
  laptop: { kind: "laptop", label: "노트북", role: "host", width: 64, height: 64, ports: [{ name: "eth0", side: "top" }, { name: "wlan0", side: "top", radio: true }], namePrefix: "laptop" },
  phone: { kind: "phone", label: "스마트폰", role: "host", width: 44, height: 64, ports: [{ name: "wlan0", side: "top", radio: true }], namePrefix: "phone" },
  server: { kind: "server", label: "서버", role: "host", width: 64, height: 64, ports: [{ name: "eth0", side: "top" }], namePrefix: "srv" },
  // 로드밸런서 전용 장비: 호스트처럼 주소 하나를 갖고(VIP) 뒤 서버들에 요청을 나눈다. 서버의 LB 서비스 토글과 같은 모듈(core/nodes/lb.ts)
  lb: { kind: "lb", label: "로드밸런서", role: "host", width: 64, height: 64, ports: [{ name: "eth0", side: "top" }], namePrefix: "lb" },
  switch: {
    kind: "switch",
    label: "스위치",
    role: "switch",
    width: 152,
    height: 44,
    // 실물처럼 포트는 아래쪽 한 줄. 라우터/게이트웨이도 이 줄에 꽂는다
    ports: lanPorts(8, "bottom", "eth", 1),
    namePrefix: "sw",
  },
  hub: {
    kind: "hub",
    label: "허브",
    role: "hub",
    width: 120,
    height: 44,
    ports: lanPorts(4, "bottom", "port", 1),
    namePrefix: "hub",
  },
  ap: {
    kind: "ap",
    label: "무선 AP",
    role: "ap",
    width: 120,
    height: 44,
    // eth0 하나 + 무선 슬롯 8개 (코어 AccessPoint 의 포트 배치와 같다)
    ports: [{ name: "eth0", side: "top" }, ...radioSlots(8)],
    namePrefix: "ap",
  },
  router: {
    kind: "router",
    label: "라우터",
    role: "router",
    width: 152,
    height: 62,
    // wan, lan1~4, 무선 슬롯 8개 (코어 Router.RADIO_PORTS = 5..12)
    ports: [{ name: "wan", side: "top" }, ...lanPorts(4, "bottom", "lan", 1), ...radioSlots(8)],
    namePrefix: "rt",
  },
  gateway: {
    kind: "gateway",
    label: "게이트웨이",
    role: "l3",
    width: 152,
    height: 62,
    ports: [
      { name: "if0", side: "top" },
      { name: "if1", side: "bottom" },
      { name: "if2", side: "bottom" },
    ],
    namePrefix: "gw",
  },
  nat: {
    kind: "nat",
    label: "NAT",
    role: "l3",
    width: 152,
    height: 62,
    ports: [
      { name: "outside", side: "top" },
      { name: "inside", side: "bottom" },
    ],
    namePrefix: "nat",
  },
  firewall: {
    kind: "firewall",
    label: "방화벽",
    role: "firewall",
    width: 152,
    height: 62,
    // 투명(브리지) 방화벽: 위 = outside(인터넷 방향), 아래 = inside(보호할 쪽). IP 없음
    ports: [
      { name: "outside", side: "top" },
      { name: "inside", side: "bottom" },
    ],
    namePrefix: "fw",
  },
  internet: {
    kind: "internet",
    label: "인터넷",
    role: "internet",
    width: 152,
    height: 48,
    ports: [{ name: "isp", side: "bottom" }],
    namePrefix: "internet",
  },
};

/** 팔레트 묶음: 패킷이 나가는 순서(단말 → 스위칭 → 라우팅·경계 → 인터넷) */
export const PALETTE_GROUPS: { label: string; kinds: DeviceKind[] }[] = [
  { label: "단말", kinds: ["pc", "laptop", "phone", "server"] },
  { label: "스위칭", kinds: ["hub", "switch", "ap"] },
  { label: "라우팅·경계", kinds: ["router", "gateway", "nat", "firewall", "lb", "internet"] },
];
export const PALETTE_ORDER: DeviceKind[] = PALETTE_GROUPS.flatMap((g) => g.kinds);

export interface DhcpPoolSettings {
  start: string;
  end: string;
  prefix: number;
  router: string;
  dns?: string;
}

export interface DhcpServerSettings {
  enabled: boolean;
  start: string;
  end: string;
  /** 클라이언트에게 안내할 게이트웨이 (비우면 안내 없음) */
  router: string;
  /** 클라이언트에게 안내할 DNS (비우면 안내 없음) */
  dns?: string;
  /** 릴레이를 거쳐 오는 다른 서브넷용 풀 */
  extraPools?: DhcpPoolSettings[];
}

export interface DnsRecordSettings {
  name: string;
  ip: string;
}

export interface DnsServerSettings {
  enabled: boolean;
  records: DnsRecordSettings[];
  /** 모르는 이름을 물어볼 업스트림 DNS */
  upstream: string;
}

export const DEFAULT_DNS_SERVER: DnsServerSettings = { enabled: false, records: [], upstream: "" };

export interface HostSettings {
  ipMode: "dhcp" | "static";
  ip: string;
  prefix: number;
  gateway: string;
  /** 수동 설정일 때 DNS 서버 */
  dns?: string;
  /** 듣는 TCP 포트 (웹 서버 = 80) */
  services: number[];
  /** 이 호스트가 DHCP 서버 역할을 할 때 */
  dhcpServer: DhcpServerSettings;
  /** 이 호스트가 DNS 서버 역할을 할 때 */
  dnsServer?: DnsServerSettings;
  /** 이 호스트가 로드밸런서(리버스 프록시) 역할을 할 때. 로드밸런서 장비는 켜진 채로 만들어진다 */
  lb?: LbSettings;
  /** 이 호스트가 포워드 프록시(Squid 식) 역할을 할 때 */
  proxy?: ProxySettings;
  /** 이 호스트의 HTTP 프록시 설정 (http_proxy). 없으면 직접 */
  httpProxy?: HttpProxySettings;
  /** 원격 접속 VPN 클라이언트. 없으면 꺼짐 */
  ra?: RaClientSettings;
  /** IPv6. 없으면 꺼짐 (실제 OS 는 기본으로 켜져 있지만, 여기서는 켜야 링크 로컬·NDP 가 오간다) */
  ipv6?: Ipv6HostSettings;
  /** P2P 앱 (화상 통화·게임처럼 NAT 너머 상대와 직접 잇기). 이름이 비면 장치 이름 */
  p2p?: { enabled: boolean; name?: string };
  /** 메시 VPN 앱 (Tailscale·ZeroTier). 없으면 꺼짐 */
  mesh?: MeshSettings;
}

/** 호스트의 IPv6 설정 */
export interface Ipv6HostSettings {
  enabled: boolean;
  /** slaac = 라우터 광고(RA)로 주소·게이트웨이·DNS 를 받음, static = 아래 칸 */
  mode: "slaac" | "static";
  ip: string;
  prefix: number;
  /** IPv6 기본 게이트웨이 (라우터의 글로벌 또는 링크 로컬 주소) */
  gateway: string;
  dns?: string;
  /** NUD (이웃 도달 확인, 없으면 꺼짐 — 60초 지나면 다시 묻기만) */
  nud?: boolean;
}

export const DEFAULT_IPV6_HOST: Ipv6HostSettings = { enabled: true, mode: "slaac", ip: "", prefix: 64, gateway: "" };

/** 게이트웨이·NAT 박스의 IPv6 설정 */
export interface Ipv6L3Settings {
  enabled: boolean;
  /** 물리 인터페이스별 주소 (인덱스 = 인터페이스, 빈 칸 = 링크 로컬만). ra = 이 인터페이스로 라우터 광고(RA)를 보냄 */
  interfaces: { ip: string; prefix: number; ra?: boolean }[];
  /** IPv6 스태틱 라우팅. ::/0 이 디폴트 라우트 */
  routes: StaticRouteSettings[];
  /** RA 의 RDNSS 옵션으로 알릴 DNS 서버 (비우면 없음) */
  raDns?: string;
  /** 주기 RA (10초, 라우터 수명 30초. 없으면 꺼짐) */
  raPeriodic?: boolean;
}

export interface LbSettings {
  enabled: boolean;
  /** 클라이언트가 접속하는 포트 */
  port: number;
  algorithm: "round-robin" | "least-conn";
  backends: { ip: string; port: number }[];
  /** 없으면 L7 (리버스 프록시) */
  mode?: "l7" | "l4";
  /** 세션 고정: "ip" 같은 출발지 IP → 같은 백엔드, "cookie" 응답에 넣은 쿠키로 (L7 만). 예전 저장본의 true 는 "ip" */
  sticky?: "ip" | "cookie";
  /** 액티브 헬스 체크 (없으면 꺼짐 — 패시브만) */
  healthCheck?: boolean;
}

export interface ProxySettings {
  enabled: boolean;
  /** 듣는 포트 (Squid 기본 3128) */
  port: number;
  /** 차단 목록: 이름(하위 이름 포함) 또는 주소 */
  deny: string[];
}

export const DEFAULT_PROXY_SETTINGS: ProxySettings = { enabled: false, port: 3128, deny: [] };

export interface HttpProxySettings {
  enabled: boolean;
  server: string;
  port: number;
}

export const DEFAULT_LB_SETTINGS: LbSettings = { enabled: false, port: 80, algorithm: "round-robin", backends: [] };

export const DEFAULT_DHCP_SERVER: DhcpServerSettings = { enabled: false, start: "192.168.0.100", end: "192.168.0.199", router: "192.168.0.1" };

/** 게이트웨이/NAT 의 인터페이스 하나 */
export interface IfaceSettings {
  ipMode: "dhcp" | "static";
  ip: string;
  prefix: number;
  gateway: string;
  /** DHCP 릴레이 대상 서버 주소 (비우면 릴레이 없음) */
  relay?: string;
}

export interface StaticRouteSettings {
  dest: string;
  prefix: number;
  via: string;
}

export interface SubIfaceSettings {
  /** 물리 인터페이스 인덱스 (if1 = 1, if2 = 2) */
  port: number;
  vlan: number;
  ip: string;
  prefix: number;
  relay: string;
}

export interface L3Settings {
  interfaces: IfaceSettings[];
  routes: StaticRouteSettings[];
  /** NAT 박스의 포트 포워딩 규칙 */
  forwards?: PortForwardSettings[];
  firewall?: FirewallSettings;
  /** 게이트웨이의 VLAN 서브 인터페이스 (router-on-a-stick) */
  subinterfaces?: SubIfaceSettings[];
  /** 동적 라우팅 (RIP). 없으면 꺼짐 */
  rip?: RipSettings;
  /** 사이트 간 VPN (WireGuard 식). 없으면 꺼짐 */
  vpn?: VpnSettings;
  /** 이중화 (VRRP 식). 없으면 꺼짐 */
  ha?: HaSettings;
  /** 원격 접속 VPN 서버. 없으면 꺼짐 */
  ra?: RaServerSettings;
  /** IPv6 라우팅. 없으면 꺼짐 */
  ipv6?: Ipv6L3Settings;
  /** 게이트웨이의 NAT (MASQUERADE, if0 이 바깥). 없으면 꺼짐. NAT 박스는 늘 켜짐 */
  nat?: { enabled: boolean };
  /** 포트 공개 (docker run -p 식): 장비 자신의 주소(bind, 0.0.0.0 = 모두)의 port 로 온 TCP 를 to:toPort 로 */
  publish?: PublishSettings[];
  /** NAT 종류 (NAT 박스·NAT 를 켠 게이트웨이). 없으면 full cone */
  natType?: NatTypeSetting;
  /** 헤어핀 NAT (안에서 바깥 주소의 포워딩 포트로 접속). 없으면 꺼짐 */
  hairpin?: boolean;
}

export interface PublishSettings {
  port: number;
  /** "0.0.0.0" = 이 장비의 모든 주소, "127.0.0.1" 처럼 하나로 좁힐 수 있다 */
  bind: string;
  to: string;
  toPort: number;
}

/** 게이트웨이·NAT 박스가 NAT 를 하는지 (NAT 박스, 또는 NAT 를 켠 게이트웨이) */
export function natOn(d: Device): boolean {
  return d.kind === "nat" || (d.kind === "gateway" && d.l3?.nat?.enabled === true);
}

export interface RaServerSettings {
  enabled: boolean;
  psk: string;
  poolStart: string;
  poolEnd: string;
  /** 클라이언트에게 알려 줄 사내 대역 */
  routes: { dest: string; prefix: number }[];
  /** 사용자 계정 (EAP). 없거나 비면 PSK 만으로 접속 */
  users?: { name: string; password: string }[];
}

export interface RaClientSettings {
  enabled: boolean;
  /** 회사 VPN 장비의 공인 주소 */
  server: string;
  psk: string;
  /** 사용자 계정 (서버가 계정 인증을 요구할 때) */
  user?: string;
  password?: string;
  /** 주기 DPD (없으면 꺼짐) */
  dpd?: boolean;
  /** VPN 종류: 없으면 회사 VPN 장비(IKEv2), "l2tp" 면 공유기 VPN 서버(L2TP/IPsec), "wireguard" 면 WireGuard 앱 (server = 엔드포인트) */
  type?: "l2tp" | "wireguard" | "openvpn";
  /** WireGuard 설정 파일 (type 이 wireguard 일 때) */
  wg?: WgClientSettings;
  /** OpenVPN 설정 파일 (type 이 openvpn 일 때 — server = remote) */
  ovpn?: OvpnClientSettings;
}

/** OpenVPN 설정 파일 (.ovpn) 의 클라이언트 쪽: remote 의 포트·proto, <ca>, <cert>(CN·발급 CA), <tls-crypt> */
export interface OvpnClientSettings {
  proto: "udp" | "tcp";
  port: number;
  /** <ca> — 믿는 CA 의 지문 */
  ca: string;
  /** <cert> 의 CN */
  cn: string;
  /** <cert> 를 발급한 CA 의 지문 */
  certCa: string;
  /** <tls-crypt> 키 지문 (비우면 안 씀) */
  tlsCrypt: string;
}

export interface HaSettings {
  enabled: boolean;
  /** 가상 라우터 번호 1~255 (쌍은 같은 번호) */
  vrid: number;
  /** 우선순위 1~254 (높은 쪽이 master) */
  priority: number;
  /** 인터페이스별 가상 주소 (인덱스 = 인터페이스, "" = 참여 안 함) */
  vips: string[];
  /** 세션 동기화 (없으면 꺼짐) */
  sync?: boolean;
  /** 주기 광고 + Master_Down 감시 (없으면 꺼짐 — 변화가 있을 때만 광고) */
  advert?: boolean;
}

const prefix6 = (v: unknown, dflt: number, min = 1) => (typeof v === "number" && Number.isInteger(v) && v >= min && v <= 128 ? v : dflt);
const text = (v: unknown) => (typeof v === "string" ? v : "");

/** 불러온 JSON 의 호스트 IPv6 설정 정리 */
function normalizeIpv6Host(v: Partial<Ipv6HostSettings>): Ipv6HostSettings {
  return { enabled: v.enabled === true, mode: v.mode === "slaac" ? "slaac" : "static", ip: text(v.ip), prefix: prefix6(v.prefix, 64), gateway: text(v.gateway), ...(typeof v.dns === "string" ? { dns: v.dns } : {}), ...(v.nud === true ? { nud: true } : {}) };
}

/** 불러온 JSON 의 게이트웨이 IPv6 설정 정리 */
function normalizeIpv6L3(v: Partial<Ipv6L3Settings>): Ipv6L3Settings {
  const ifs = Array.isArray(v.interfaces) ? (v.interfaces as unknown[]) : [];
  const routes = Array.isArray(v.routes) ? (v.routes as unknown[]) : [];
  return {
    enabled: v.enabled === true,
    interfaces: ifs.map((x) => {
      const o = (x && typeof x === "object" ? x : {}) as Partial<{ ip: unknown; prefix: unknown; ra: unknown }>;
      return { ip: text(o.ip), prefix: prefix6(o.prefix, 64), ...(o.ra === true ? { ra: true } : {}) };
    }),
    ...(typeof v.raDns === "string" ? { raDns: v.raDns } : {}),
    ...(v.raPeriodic === true ? { raPeriodic: true } : {}),
    routes: routes
      .filter((r): r is { dest: string; prefix: number; via: string } => !!r && typeof r === "object" && typeof (r as { dest?: unknown }).dest === "string")
      .map((r) => ({ dest: r.dest, prefix: prefix6(r.prefix, 64, 0), via: text(r.via) })),
  };
}

/** 불러온 JSON 의 원격 접속 VPN 서버 설정 정리 */
/** 로드밸런서 세션 고정·프록시·HTTP 프록시 설정을 타입대로 정리 (JSON 은 믿을 수 없다) */
function normalizeHostExtras(h: HostSettings): HostSettings {
  const port = (v: unknown, fallback: number) => {
    const n = typeof v === "string" && v.trim() !== "" ? Number(v) : v;
    return typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= 65535 ? n : fallback;
  };
  const out: HostSettings = { ...h };
  if (h.lb) {
    // 예전 저장본: 세션 고정이 켜기/끄기(true)였다 → 출발지 IP. 모르는 값은 버린다
    const st = h.lb.sticky as unknown;
    const { sticky: _drop, healthCheck: hc, ...rest } = h.lb;
    void _drop;
    out.lb = { ...rest, ...(st === true || st === "ip" ? { sticky: "ip" as const } : st === "cookie" ? { sticky: "cookie" as const } : {}), ...(hc === true ? { healthCheck: true } : {}) };
  }
  if (h.proxy) {
    const p = h.proxy as Partial<ProxySettings>;
    const deny = typeof p.deny === "string" ? [p.deny] : Array.isArray(p.deny) ? p.deny.filter((x): x is string => typeof x === "string") : [];
    out.proxy = { enabled: p.enabled === true, port: port(p.port, 3128), deny };
  }
  if (h.httpProxy) {
    const p = h.httpProxy as Partial<HttpProxySettings>;
    out.httpProxy = { enabled: p.enabled === true, server: typeof p.server === "string" ? p.server : typeof p.server === "number" ? String(p.server) : "", port: port(p.port, 3128) };
  }
  if (h.ipv6) out.ipv6 = normalizeIpv6Host(h.ipv6 as Partial<Ipv6HostSettings>);
  if (h.p2p) {
    const p = h.p2p as { enabled?: unknown; name?: unknown };
    out.p2p = { enabled: p.enabled === true, ...(typeof p.name === "string" ? { name: p.name } : {}) };
  }
  if (h.mesh && typeof h.mesh === "object") out.mesh = normalizeMesh(h.mesh as Partial<MeshSettings>);
  return out;
}

function normalizeRaServer(r: Partial<RaServerSettings>): RaServerSettings {
  const str = (v: unknown, d: string) => (typeof v === "string" ? v : d);
  // 계정: 손으로 고친 JSON 의 숫자 이름·비밀번호(1234)는 문자열로 살리고, 객체 하나면 배열로 감싼다. 그 밖(문자열·null 등)은 [] — 계정이 없으면 PSK 만으로 접속
  const users = r.users === undefined ? undefined : Array.isArray(r.users) ? (r.users as unknown[]) : r.users !== null && typeof r.users === "object" ? [r.users as unknown] : [];
  return {
    enabled: r.enabled === true,
    psk: str(r.psk, ""),
    poolStart: str(r.poolStart, "10.99.0.10"),
    poolEnd: str(r.poolEnd, "10.99.0.50"),
    routes: (Array.isArray(r.routes) ? r.routes : [])
      .filter((x): x is { dest: string; prefix: number } => !!x && typeof x === "object" && typeof x.dest === "string")
      .map((x) => ({ dest: x.dest, prefix: Number.isInteger(x.prefix) && x.prefix >= 0 && x.prefix <= 32 ? x.prefix : 24 })),
    // 예전 저장본에는 없다 (없으면 PSK 만)
    ...(users
      ? {
          users: users
            .filter((u): u is { name: unknown; password?: unknown } => !!u && typeof u === "object" && accountText((u as { name?: unknown }).name) !== undefined)
            .map((u) => ({ name: accountText(u.name)!, password: accountText(u.password) ?? "" })),
        }
      : {}),
  };
}

/** 계정 칸(사용자 이름·비밀번호): 문자열은 그대로, 손으로 고친 JSON 의 숫자(1234)는 문자열로. 그 밖은 undefined */
function accountText(v: unknown): string | undefined {
  return typeof v === "string" ? v : typeof v === "number" && Number.isFinite(v) ? String(v) : undefined;
}

/** 불러온 JSON 의 원격 접속 VPN 클라이언트 설정 정리 (계정은 예전 저장본에 없다) */
function normalizeRaClient(r: Partial<RaClientSettings>): RaClientSettings {
  const str = (v: unknown, d: string) => (typeof v === "string" ? v : d);
  const user = accountText(r.user);
  return {
    enabled: r.enabled === true,
    server: str(r.server, ""),
    psk: str(r.psk, ""),
    ...(user !== undefined ? { user, password: accountText(r.password) ?? "" } : {}),
    ...(r.dpd === true ? { dpd: true } : {}),
    ...(r.type === "l2tp" ? { type: "l2tp" as const } : r.type === "wireguard" ? { type: "wireguard" as const } : r.type === "openvpn" ? { type: "openvpn" as const } : {}),
    ...(r.wg && typeof r.wg === "object" ? { wg: normalizeWgFields(r.wg) } : {}),
    ...(r.ovpn && typeof r.ovpn === "object" ? { ovpn: normalizeOvpnClient(r.ovpn) } : {}),
  };
}

/** 불러온 JSON 의 공유기 VPN 서버 설정 정리 (계정 칸은 원격 접속 서버와 같은 규칙) */
function normalizeRouterVpn(r: Partial<RouterVpnServerSettings>): RouterVpnServerSettings {
  const str = (v: unknown, d: string) => (typeof v === "string" ? v : d);
  const users = Array.isArray(r.users) ? (r.users as unknown[]) : r.users !== null && typeof r.users === "object" ? [r.users as unknown] : [];
  return {
    enabled: r.enabled === true,
    psk: str(r.psk, ""),
    poolStart: str(r.poolStart, DEFAULT_ROUTER_VPN_SERVER.poolStart),
    poolEnd: str(r.poolEnd, DEFAULT_ROUTER_VPN_SERVER.poolEnd),
    users: users
      .filter((u): u is { name: unknown; password?: unknown } => !!u && typeof u === "object" && accountText((u as { name?: unknown }).name) !== undefined)
      .map((u) => ({ name: accountText(u.name)!, password: accountText(u.password) ?? "" })),
  };
}

/** 불러온 JSON 의 포트 공개 규칙 정리 (배열이 아니면 [], 숫자·문자열은 타입대로) */
function normalizePublish(v: unknown): PublishSettings[] {
  if (!Array.isArray(v)) return [];
  const num = (x: unknown, d: number) => (typeof x === "number" && Number.isInteger(x) ? x : typeof x === "string" && /^\d+$/.test(x) ? Number(x) : d);
  return v
    // bind 가 문자열이 아니면 버린다 — 0.0.0.0 으로 채우면 손으로 좁혀 둔 공개 범위가 넓어진다
    .filter((r): r is Record<string, unknown> => !!r && typeof r === "object" && typeof r.bind === "string")
    .map((r) => ({ port: num(r.port, 0), bind: r.bind as string, to: typeof r.to === "string" ? r.to : "", toPort: num(r.toPort, 0) }));
}

/** 불러온 JSON 의 이중화 설정 정리 */
function normalizeHa(h: Partial<HaSettings>): HaSettings {
  const int = (v: unknown, lo: number, hi: number, dflt: number) => (typeof v === "number" && Number.isInteger(v) && v >= lo && v <= hi ? v : dflt);
  return {
    enabled: h.enabled === true,
    vrid: int(h.vrid, 1, 255, 1),
    priority: int(h.priority, 1, 254, 100),
    vips: Array.isArray(h.vips) ? h.vips.map((v) => (typeof v === "string" ? v : "")) : [],
    ...(h.sync === true ? { sync: true } : {}),
    ...(h.advert === true ? { advert: true } : {}),
  };
}

/** 불러온 JSON 의 VPN 설정 정리: 빠지거나 잘못된 칸은 기본값으로 (remote 가 없으면 구성 검사·동기화가 멈춘다) */
function normalizeVpn(v: Partial<VpnSettings>): VpnSettings {
  const remote = Array.isArray(v.remote) ? v.remote : [];
  return {
    enabled: v.enabled === true,
    ...(v.mode === "ipsec" ? { mode: "ipsec" as const, psk: typeof v.psk === "string" ? v.psk : "" } : {}),
    peer: typeof v.peer === "string" ? v.peer : "",
    remote: remote
      .filter((r): r is { dest: string; prefix: number } => !!r && typeof r === "object" && typeof r.dest === "string")
      .map((r) => ({ dest: r.dest, prefix: Number.isInteger(r.prefix) && r.prefix >= 0 && r.prefix <= 32 ? r.prefix : 24 })),
    ...(v.dpd === true ? { dpd: true } : {}),
  };
}

export interface VpnSettings {
  enabled: boolean;
  /** 없으면 WireGuard 식 */
  mode?: "wireguard" | "ipsec";
  /** IPsec 사전 공유 키 */
  psk?: string;
  /** 상대 터널 끝의 공인 주소 */
  peer: string;
  /** 상대 쪽 사설 대역 */
  remote: { dest: string; prefix: number }[];
  /** 주기 DPD (IPsec, 없으면 꺼짐) */
  dpd?: boolean;
}

export interface RipSettings {
  enabled: boolean;
  /** 내 디폴트 라우트를 이웃에게 0.0.0.0/0 으로 광고 (default-information originate) */
  defaultRoute?: boolean;
}

/** 스위치 포트별 VLAN: 숫자(액세스) 또는 "trunk". 없으면 VLAN 1 */
export interface SwitchSettings {
  vlans: Record<number, number | "trunk">;
  /** 스패닝 트리. 없으면 꺼짐 (실제 스위치는 기본으로 켜져 있지만, 여기서는 켜야 BPDU 가 오간다) */
  stp?: { enabled: boolean; priority: number };
  /** IGMP 스누핑. 없으면 꺼짐 (멀티캐스트를 모든 포트로) */
  igmpSnooping?: boolean;
}

export interface WanSettings {
  ipMode: "dhcp" | "static";
  ip: string;
  prefix: number;
  gateway: string;
}

export interface PortForwardSettings {
  publicPort: number;
  lanIp: string;
  lanPort: number;
  /** 없으면 TCP */
  proto?: "tcp" | "udp";
}

export interface FirewallRuleSettings {
  action: "allow" | "deny";
  proto: "any" | "icmp" | "tcp" | "udp" | "esp";
  direction: "in" | "out" | "any";
  src: string;
  dst: string;
  /** 비우면 모든 포트 */
  dstPort: string;
}

export interface FirewallSettings {
  enabled: boolean;
  defaultPolicy: "allow" | "deny";
  stateful: boolean;
  rules: FirewallRuleSettings[];
}

export const DEFAULT_FIREWALL_SETTINGS: FirewallSettings = { enabled: false, defaultPolicy: "allow", stateful: true, rules: [] };

export interface RouterSettings {
  lanIp: string;
  lanPrefix: number;
  /** dns: DHCP 가 안내할 DNS 서버(옵션 6). 비우면 공유기 자신(DNS 포워더) */
  dhcp: { enabled: boolean; start: string; end: string; dns?: string };
  wan: WanSettings;
  /** DNS 포워더 (공유기 안의 dnsmasq) */
  dns?: { enabled: boolean; upstream: string };
  /** 포트 포워딩 규칙 */
  forwards?: PortForwardSettings[];
  firewall?: FirewallSettings;
  wifi?: WifiBaseSettings;
  /** IPv6. 없으면 꺼짐. 켜면 ISP 에게 DHCPv6-PD 로 프리픽스를 받아 LAN 에 RA 로 알린다 */
  ipv6?: RouterIpv6Settings;
  /** VPN 서버 (ipTIME 식 L2TP/IPsec). 없으면 꺼짐 */
  vpnServer?: RouterVpnServerSettings;
  /** NAT 종류. 없으면 full cone */
  natType?: NatTypeSetting;
  /** 헤어핀 NAT (NAT 루프백). 없으면 꺼짐 */
  hairpin?: boolean;
  /** WireGuard 서버 (GL.iNet 식). 없으면 꺼짐 */
  wgServer?: RouterWgServerSettings;
  /** WireGuard 클라이언트 (LAN 전체를 VPN 으로 — 킬 스위치·VPN 정책). 없으면 꺼짐 */
  wgClient?: RouterWgClientSettings;
  /** DDNS (glddns.com). 없으면 꺼짐 */
  ddns?: RouterDdnsSettings;
  /** 멀티 WAN 페일오버: lan4 를 WAN2(예비 회선)로. 없으면 꺼짐 */
  wan2?: RouterWan2Settings;
  /** AdGuard Home·자녀 보호 (DNS 필터). 없으면 꺼짐 */
  adguard?: RouterAdguardSettings;
  /** DPI (앱 알아보기·차단). 없으면 꺼짐 */
  dpi?: RouterDpiSettings;
  /** OpenVPN 서버. 없으면 꺼짐 */
  ovpnServer?: RouterOvpnServerSettings;
  /** 메시 VPN (Tailscale·ZeroTier — 서브넷 라우터·exit node). 없으면 꺼짐 */
  mesh?: MeshSettings;
  /** 관리 화면 (HTTP·HTTPS·SSH) 접근 제어. 없으면 관리 화면 흉내 꺼짐 */
  admin?: RouterAdminSettings;
  /** GoodCloud 원격 관리. 없으면 꺼짐 */
  cloud?: boolean;
  /** 인터넷을 막은 LAN 기기 (MAC) */
  blocked?: string[];
  /** 드롭인 게이트웨이: WAN 쪽 LAN 기기의 게이트웨이가 되어 준다 (한 팔 라우터). 없으면 꺼짐 */
  dropIn?: boolean;
  /** 네트워크 저장소 (Samba — SMB TCP 445). 없으면 꺼짐 */
  samba?: { enabled: boolean; wan: boolean };
  /** 내부 스위치의 IGMP 스누핑. 없으면 꺼짐 */
  igmpSnooping?: boolean;
}

export interface RouterAdminSettings {
  enabled: boolean;
  /** WAN(인터넷)에서도 접근 허용 */
  remote: boolean;
  /** LAN 에서 열 수 있는 주소·대역, 쉼표로 (비우면 LAN 전부) */
  allow: string;
  ssh: boolean;
}

export const DEFAULT_ADMIN_SETTINGS: RouterAdminSettings = { enabled: true, remote: false, allow: "", ssh: true };

/**
 * 메시 VPN (Tailscale·ZeroTier) 앱 설정. 노트북·폰·공유기 공통 — advertiseLan·exitNode 는 공유기만, useExitNode 는 단말만
 */
export interface MeshSettings {
  enabled: boolean;
  net: "tailscale" | "zerotier";
  /** tailnet 이름(계정) 또는 ZeroTier 네트워크 ID (16자리 16진수) */
  network: string;
  /** 기기 이름 (비우면 장치 이름에서 — MagicDNS 이름) */
  name: string;
  /** 서브넷 라우터: LAN 대역을 알림 (공유기) */
  advertiseLan?: boolean;
  /** exit node 를 내줌 (공유기) */
  exitNode?: boolean;
  /** 쓸 exit node 의 이름 (단말) */
  useExitNode?: string;
}

export const DEFAULT_MESH_SETTINGS: MeshSettings = { enabled: true, net: "tailscale", network: "", name: "" };

function normalizeMesh(v: Partial<MeshSettings>): MeshSettings {
  return {
    enabled: v.enabled === true,
    net: v.net === "zerotier" ? "zerotier" : "tailscale",
    network: typeof v.network === "string" ? v.network : "",
    name: typeof v.name === "string" ? v.name : "",
    ...(v.advertiseLan === true ? { advertiseLan: true } : {}),
    ...(v.exitNode === true ? { exitNode: true } : {}),
    ...(typeof v.useExitNode === "string" && v.useExitNode ? { useExitNode: v.useExitNode } : {}),
  };
}

/** 공유기 OpenVPN 서버: CA·서버 인증서·tls-crypt 키는 장치마다 정해진 것 (ovpnCaOfDevice) */
export interface RouterOvpnServerSettings {
  enabled: boolean;
  proto: "udp" | "tcp";
  port: number;
  /** 터널 대역 (예: 10.8.0.0/24 — 서버는 첫 주소) */
  subnet: string;
  /** 집 LAN 접근 허용 (push route) */
  lanAccess: boolean;
  /** 클라이언트의 모든 트래픽을 터널로 (push redirect-gateway) */
  redirectGateway: boolean;
  /** 서버 터널 주소를 DNS 로 알려 줌 (push dhcp-option DNS) */
  pushDns: boolean;
  tlsCrypt: boolean;
  /** 계정 (비우면 인증서만) */
  users: { name: string; password: string }[];
  /** 폐기한 인증서의 CN (CRL) */
  revoked: string[];
}

export const DEFAULT_OVPN_SERVER_SETTINGS: RouterOvpnServerSettings = { enabled: true, proto: "udp", port: 1194, subnet: "10.8.0.0/24", lanAccess: true, redirectGateway: false, pushDns: true, tlsCrypt: true, users: [], revoked: [] };

/** 그 공유기의 OpenVPN CA 지문 (장치 id 에서 — 복사한 공유기는 새 CA) */
export function ovpnCaOfDevice(d: Device): string {
  return ovpnCaOf(d.id);
}

/** 그 공유기의 tls-crypt 키 지문 */
export function ovpnTlsCryptOfDevice(d: Device): string {
  return ovpnTlsCryptOf(d.id);
}

function normalizeOvpnServer(v: Partial<RouterOvpnServerSettings>): RouterOvpnServerSettings {
  const users = Array.isArray(v.users) ? (v.users as unknown[]) : [];
  return {
    enabled: v.enabled === true,
    proto: v.proto === "tcp" ? "tcp" : "udp",
    port: typeof v.port === "number" && Number.isInteger(v.port) && v.port >= 1 && v.port <= 65535 ? v.port : 1194,
    subnet: typeof v.subnet === "string" ? v.subnet : "10.8.0.0/24",
    lanAccess: v.lanAccess !== false,
    redirectGateway: v.redirectGateway === true,
    pushDns: v.pushDns !== false,
    tlsCrypt: v.tlsCrypt !== false,
    users: users.filter((u): u is Record<string, unknown> => !!u && typeof u === "object").map((u) => ({ name: accountText(u.name) ?? "", password: accountText(u.password) ?? "" })),
    revoked: Array.isArray(v.revoked) ? v.revoked.filter((x): x is string => typeof x === "string") : [],
  };
}

function normalizeOvpnClient(v: Partial<OvpnClientSettings>): OvpnClientSettings {
  const str = (x: unknown) => (typeof x === "string" ? x : "");
  return {
    proto: v.proto === "tcp" ? "tcp" : "udp",
    port: typeof v.port === "number" && Number.isInteger(v.port) && v.port >= 1 && v.port <= 65535 ? v.port : 1194,
    ca: str(v.ca),
    cn: str(v.cn),
    certCa: str(v.certCa),
    tlsCrypt: str(v.tlsCrypt),
  };
}

/** DPI: 막을 앱(core/nodes/dpi.ts AppId)·카테고리 */
export interface RouterDpiSettings {
  enabled: boolean;
  blockApps: string[];
  blockCategories: string[];
}

export type ParentalCategorySetting = "sns" | "game" | "video";

export interface RouterAdguardSettings {
  enabled: boolean;
  /** 광고·추적 차단 목록 */
  ads: boolean;
  /** 막은 이름에 0.0.0.0 으로(기본) 또는 NXDOMAIN 으로 */
  mode: "zero" | "nxdomain";
  /** 사용자 차단 규칙 (이름 — 하위 이름도) */
  custom: string[];
  /** 예외 */
  allow: string[];
  /** DNS 가로채기: 다른 DNS 로 가는 질의도 공유기가 받아 거른다 */
  forceDns: boolean;
  /** 자녀 보호: 기기(LAN 주소)마다 막을 카테고리 */
  parental: { ip: string; categories: ParentalCategorySetting[] }[];
}

export const DEFAULT_ADGUARD_SETTINGS: RouterAdguardSettings = { enabled: true, ads: true, mode: "zero", custom: [], allow: [], forceDns: false, parental: [] };

const PARENTAL_CATS: ParentalCategorySetting[] = ["sns", "game", "video"];

function normalizeAdguard(v: Partial<RouterAdguardSettings>): RouterAdguardSettings {
  const list = (x: unknown) => (Array.isArray(x) ? x.filter((y): y is string => typeof y === "string") : []);
  const parental = Array.isArray(v.parental) ? (v.parental as unknown[]) : [];
  return {
    enabled: v.enabled === true,
    ads: v.ads !== false,
    mode: v.mode === "nxdomain" ? "nxdomain" : "zero",
    custom: list(v.custom),
    allow: list(v.allow),
    forceDns: v.forceDns === true,
    parental: parental
      .filter((p): p is Record<string, unknown> => !!p && typeof p === "object")
      .map((p) => ({ ip: typeof p.ip === "string" ? p.ip : "", categories: list(p.categories).filter((c): c is ParentalCategorySetting => PARENTAL_CATS.includes(c as ParentalCategorySetting)) })),
  };
}

export interface RouterWan2Settings extends WanSettings {
  enabled: boolean;
  /** 회선이 살았는지 ping 할 주소 (비우면 링크·주소만 본다) */
  track: string;
}

export const DEFAULT_ROUTER_WAN2: RouterWan2Settings = { enabled: true, ipMode: "dhcp", ip: "", prefix: 24, gateway: "", track: "8.8.8.8" };

/** 멀티 WAN 을 켠 공유기는 lan4 가 WAN2 */
export const ROUTER_WAN2_PORT = 4;

/** DDNS: 이름 앞부분 (myhome → myhome.glddns.com) */
export interface RouterDdnsSettings {
  enabled: boolean;
  name: string;
}

/** DDNS 이름의 영역 (core/nodes/ddns.ts DDNS_ZONE 과 같은 값) */
export const DDNS_ZONE_NAME = "glddns.com";

/** DDNS 이름 칸 → 전체 이름 (앞부분만 적으면 영역을 붙이고, 영역까지 적었으면 그대로). 쓸 수 없는 이름이면 undefined */
export function ddnsHostname(name: string | undefined): string | undefined {
  const n = (name ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (!n) return undefined;
  const full = n.endsWith(`.${DDNS_ZONE_NAME}`) ? n : `${n}.${DDNS_ZONE_NAME}`;
  const label = full.slice(0, -(DDNS_ZONE_NAME.length + 1));
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label) ? full : undefined;
}

/** WireGuard 설정 파일 한 장의 클라이언트 쪽 ([Interface] Address·DNS + [Peer] PublicKey·Endpoint 포트·AllowedIPs) */
export interface WgClientSettings {
  /** 개인 키. 비우면 장치마다 정해진 키 */
  privateKey?: string;
  /** 내 터널 주소 (서버 관리자가 정해 준 것, 예: 10.0.0.2/32) */
  address: string;
  /** 서버 포트 (Endpoint 의 포트) */
  port: number;
  /** 서버의 공개 키 */
  serverKey: string;
  /** 터널로 보낼 목적지, 쉼표로 (0.0.0.0/0 = 전부) */
  allowedIps: string;
  /** 연결된 동안 쓸 DNS (비우면 그대로) */
  dns: string;
  /** 난독화 (AmneziaWG 식 — 서버도 켜야 한다) */
  obfuscate?: boolean;
}

export interface RouterWgServerSettings {
  enabled: boolean;
  /** 개인 키. 비우면 장치마다 정해진 키 */
  privateKey?: string;
  /** 서버의 터널 주소 (예: 10.0.0.1/24) */
  address: string;
  port: number;
  /** 등록한 클라이언트: 이름·공개 키·터널 주소 */
  peers: { name: string; publicKey: string; ip: string }[];
  /** 클라이언트가 집 LAN 에 접근해도 되는지 */
  lanAccess: boolean;
  /** 난독화 (AmneziaWG 식 — 클라이언트도 켜야 한다) */
  obfuscate?: boolean;
}

export interface RouterWgClientSettings extends WgClientSettings {
  enabled: boolean;
  /** 서버 주소 (Endpoint) */
  server: string;
  /** 킬 스위치: VPN 이 끊기면 인터넷 차단 */
  killSwitch: boolean;
  /** VPN 정책: 모든 기기 / 목록의 기기만 빼고 / 목록의 기기만 (목록은 LAN 주소) */
  policy: { mode: "all" | "exclude" | "only"; devices: string[] };
}

export const DEFAULT_WG_SERVER: RouterWgServerSettings = { enabled: true, address: "10.0.0.1/24", port: 51820, peers: [], lanAccess: true };
export const DEFAULT_WG_CLIENT_FIELDS: WgClientSettings = { address: "", port: 51820, serverKey: "", allowedIps: "0.0.0.0/0", dns: "" };
export const DEFAULT_ROUTER_WG_CLIENT: RouterWgClientSettings = { enabled: true, server: "", ...DEFAULT_WG_CLIENT_FIELDS, killSwitch: false, policy: { mode: "all", devices: [] } };

/** 장치의 WireGuard 개인 키: 설정에 있으면 그것, 없으면 장치 id 에서 (역할마다 다른 키) */
export function wgKeyOf(d: Device, role: "server" | "client" | "host"): string {
  const set = role === "server" ? d.router?.wgServer?.privateKey : role === "client" ? d.router?.wgClient?.privateKey : d.host?.ra?.wg?.privateKey;
  return set?.trim() || wgPrivateKey(`${d.id}:${role}`);
}

/** 그 장치(역할)의 WireGuard 공개 키 */
export function wgPublicKeyOf(d: Device, role: "server" | "client" | "host"): string {
  return wgPublicKey(wgKeyOf(d, role));
}

function normalizeWan2(v: Partial<RouterWan2Settings>): RouterWan2Settings {
  const str = (x: unknown) => (typeof x === "string" ? x : "");
  return {
    enabled: v.enabled === true,
    ipMode: v.ipMode === "static" ? "static" : "dhcp",
    ip: str(v.ip),
    prefix: typeof v.prefix === "number" && Number.isInteger(v.prefix) && v.prefix >= 1 && v.prefix <= 32 ? v.prefix : 24,
    gateway: str(v.gateway),
    track: typeof v.track === "string" ? v.track : "8.8.8.8",
  };
}

function normalizeWgFields(v: Partial<WgClientSettings>): WgClientSettings {
  const str = (x: unknown, dflt = "") => (typeof x === "string" ? x : dflt);
  return {
    ...(typeof v.privateKey === "string" && v.privateKey ? { privateKey: v.privateKey } : {}),
    address: str(v.address),
    port: typeof v.port === "number" && Number.isInteger(v.port) && v.port >= 1 && v.port <= 65535 ? v.port : 51820,
    serverKey: str(v.serverKey),
    allowedIps: str(v.allowedIps, "0.0.0.0/0"),
    dns: str(v.dns),
    ...(v.obfuscate === true ? { obfuscate: true } : {}),
  };
}

function normalizeWgServer(v: Partial<RouterWgServerSettings>): RouterWgServerSettings {
  const peers = Array.isArray(v.peers) ? (v.peers as unknown[]) : [];
  return {
    enabled: v.enabled === true,
    ...(typeof v.privateKey === "string" && v.privateKey ? { privateKey: v.privateKey } : {}),
    address: typeof v.address === "string" ? v.address : "10.0.0.1/24",
    port: typeof v.port === "number" && Number.isInteger(v.port) && v.port >= 1 && v.port <= 65535 ? v.port : 51820,
    peers: peers
      .filter((p): p is Record<string, unknown> => !!p && typeof p === "object")
      .map((p) => ({ name: typeof p.name === "string" ? p.name : "", publicKey: typeof p.publicKey === "string" ? p.publicKey : "", ip: typeof p.ip === "string" ? p.ip : "" })),
    lanAccess: v.lanAccess !== false,
    ...(v.obfuscate === true ? { obfuscate: true } : {}),
  };
}

function normalizeWgClient(v: Partial<RouterWgClientSettings>): RouterWgClientSettings {
  const pol = (v.policy && typeof v.policy === "object" ? v.policy : {}) as Partial<RouterWgClientSettings["policy"]>;
  return {
    enabled: v.enabled === true,
    server: typeof v.server === "string" ? v.server : "",
    ...normalizeWgFields(v),
    killSwitch: v.killSwitch === true,
    policy: {
      mode: pol.mode === "exclude" || pol.mode === "only" ? pol.mode : "all",
      devices: Array.isArray(pol.devices) ? pol.devices.filter((x): x is string => typeof x === "string") : [],
    },
  };
}

/** NAT 종류 (core/nodes/nat.ts NatType 과 같은 값) */
export type NatTypeSetting = "full-cone" | "restricted" | "port-restricted" | "symmetric";
const NAT_TYPES: NatTypeSetting[] = ["full-cone", "restricted", "port-restricted", "symmetric"];
export function natTypeOf(v: unknown): NatTypeSetting | undefined {
  return NAT_TYPES.includes(v as NatTypeSetting) ? (v as NatTypeSetting) : undefined;
}

/** 공유기 VPN 서버 (L2TP/IPsec): ipTIME 설정 화면의 세 칸 — 사전 공유 키, 계정, 할당 IP */
export interface RouterVpnServerSettings {
  enabled: boolean;
  psk: string;
  /** 할당 IP 범위: 공유기 LAN 대역에서 DHCP 가 쓰지 않는 주소 */
  poolStart: string;
  poolEnd: string;
  users: { name: string; password: string }[];
}

export const DEFAULT_ROUTER_VPN_SERVER: RouterVpnServerSettings = { enabled: true, psk: "", poolStart: "192.168.0.50", poolEnd: "192.168.0.59", users: [] };

export interface RouterIpv6Settings {
  enabled: boolean;
  /** IPv6 인바운드 기본 차단 (Stateful) */
  inboundBlock: boolean;
}

export const DEFAULT_ROUTER_IPV6: RouterIpv6Settings = { enabled: true, inboundBlock: true };

export const DEFAULT_ROUTER_DNS = { enabled: true, upstream: "8.8.8.8" };

/** 무선 기지(AP·공유기)의 설정 */
export interface WifiBaseSettings {
  enabled: boolean;
  ssid: string;
}
/** 무선 단말의 설정 */
export interface WifiClientSettings {
  ssid: string;
  /** false = Wi-Fi 꺼짐 (노트북의 Wi-Fi 토글, SSID 는 기억). 스마트폰은 늘 켜짐 */
  enabled?: boolean;
}
export const DEFAULT_WIFI_BASE: WifiBaseSettings = { enabled: true, ssid: "home" };
export const DEFAULT_ROUTER_WIFI: WifiBaseSettings = { enabled: false, ssid: "home" };

export const DEFAULT_WAN: WanSettings = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" };

export interface Device {
  id: string;
  kind: DeviceKind;
  name: string;
  /** 장치의 MAC (스위치는 사용하지 않지만 일관되게 부여) */
  mac: string;
  x: number;
  y: number;
  host?: HostSettings;
  router?: RouterSettings;
  l3?: L3Settings;
  /** 무선 AP 장치 */
  ap?: WifiBaseSettings;
  /** 스위치 VLAN */
  switch?: SwitchSettings;
  /** 무선 단말 (스마트폰) */
  wifi?: WifiClientSettings;
  /** 투명 방화벽 장비의 규칙 */
  firewall?: FirewallSettings;
}

export interface PortRef {
  device: string;
  port: number;
}

export interface Cable {
  id: string;
  a: PortRef;
  b: PortRef;
  /** 0~1 프레임 손실률 (실험용) */
  loss?: number;
}

/** 영역: 장치 뒤에 그리는 라벨 붙은 네모. "집 안", "도커 호스트" 처럼 묶음을 표시하는 주석이라 시뮬레이션에는 영향이 없다 */
export interface Zone {
  id: string;
  label: string;
  x: number;
  y: number;
  w: number;
  h: number;
  tint: ZoneTint;
}
export type ZoneTint = "gray" | "blue" | "green" | "amber";
export const ZONE_TINTS: { id: ZoneTint; label: string }[] = [
  { id: "gray", label: "회색" },
  { id: "blue", label: "파랑" },
  { id: "green", label: "초록" },
  { id: "amber", label: "노랑" },
];
export const ZONE_MIN = 96;

export interface Topology {
  devices: Device[];
  cables: Cable[];
  /** 없으면 [] 로 본다 (예전 저장본 호환) */
  zones?: Zone[];
}

export const EMPTY_TOPOLOGY: Topology = { devices: [], cables: [] };

/** 장치 타일 중심이 영역 안에 있으면 "영역 안" */
export function zoneContains(z: Zone, d: Device): boolean {
  const s = DEVICE_SPECS[d.kind];
  const cx = d.x + s.width / 2;
  const cy = d.y + s.height / 2;
  return cx >= z.x && cx <= z.x + z.w && cy >= z.y && cy <= z.y + z.h;
}

/** 영역 안의 장치 id */
export function devicesInZone(t: Topology, z: Zone): string[] {
  return t.devices.filter((d) => zoneContains(z, d)).map((d) => d.id);
}

/** 장치 묶음을 감싸는 영역 사각형 (호스트는 아래 이름 줄까지 포함, 여백 pad) */
export function zoneAround(t: Topology, ids: string[], pad = 32): { x: number; y: number; w: number; h: number } | null {
  const picked = t.devices.filter((d) => ids.includes(d.id));
  if (picked.length === 0) return null;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const d of picked) {
    const s = DEVICE_SPECS[d.kind];
    const host = s.role === "host";
    // 호스트는 타일 아래 이름·주소 줄이 타일보다 넓다
    minX = Math.min(minX, d.x - (host ? 20 : 0));
    minY = Math.min(minY, d.y - 12);
    maxX = Math.max(maxX, d.x + s.width + (host ? 20 : 0));
    maxY = Math.max(maxY, d.y + s.height + (host ? 44 : 12));
  }
  return { x: snap(minX - pad), y: snap(minY - pad - 12), w: snap(maxX - minX + pad * 2), h: snap(maxY - minY + pad * 2 + 12) };
}

/** 멀티 WAN 을 켠 공유기의 스펙: lan4 의 이름이 wan2 (위치는 그대로) */
let routerWan2Spec: DeviceSpec | undefined;

export function specOf(device: Device): DeviceSpec {
  if (device.kind === "router" && device.router?.wan2?.enabled) {
    const base = DEVICE_SPECS.router;
    routerWan2Spec ??= { ...base, ports: base.ports.map((p, i) => (i === ROUTER_WAN2_PORT ? { ...p, name: "wan2" } : p)) };
    return routerWan2Spec;
  }
  return DEVICE_SPECS[device.kind];
}

let idSeq = 0;
export function newId(prefix: string): string {
  idSeq += 1;
  return `${prefix}_${Date.now().toString(36)}${idSeq.toString(36)}`;
}

/** 같은 종류 중 비어 있는 가장 작은 번호로 이름을 만든다 (pc-1, pc-2 …) */
export function nextName(kind: DeviceKind, devices: Device[]): string {
  const prefix = DEVICE_SPECS[kind].namePrefix;
  const used = new Set(devices.map((d) => d.name));
  for (let i = 1; ; i++) {
    const name = `${prefix}-${i}`;
    if (!used.has(name)) return name;
  }
}

/** 02:00:00:00:XX:YY 형식으로, 기존 장치와 겹치지 않는 다음 MAC */
export function nextMac(devices: Device[]): string {
  let max = 0;
  for (const d of devices) {
    const m = /^02:00:00:00:([0-9a-f]{2}):([0-9a-f]{2})$/i.exec(d.mac ?? "");
    if (m) max = Math.max(max, parseInt(m[1]! + m[2]!, 16));
  }
  const n = max + 1;
  const hex = n.toString(16).padStart(4, "0");
  return `02:00:00:00:${hex.slice(0, 2)}:${hex.slice(2)}`;
}

export function createDevice(kind: DeviceKind, x: number, y: number, devices: Device[]): Device {
  const spec = DEVICE_SPECS[kind];
  const device: Device = { id: newId(kind), kind, name: nextName(kind, devices), mac: nextMac(devices), x, y };
  if (spec.role === "host") device.host = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "", services: kind === "server" ? [80] : [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  if (spec.role === "router") {
    device.router = { lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.199" }, wan: { ...DEFAULT_WAN } };
  }
  if (spec.role === "l3") device.l3 = defaultL3(kind);
  if (spec.role === "switch") device.switch = { vlans: {} };
  if (spec.role === "ap") device.ap = { ...DEFAULT_WIFI_BASE };
  if (spec.role === "firewall") device.firewall = { ...DEFAULT_FIREWALL_SETTINGS, enabled: true, rules: [] };
  if (kind === "phone") device.wifi = { ssid: "home" };
  if (kind === "lb") device.host!.lb = { ...DEFAULT_LB_SETTINGS, enabled: true, backends: [] };
  return device;
}

// ---------- 무선 연결 (파생 상태) ----------

export interface WirelessLink {
  /** 케이블처럼 쓰이는 id: wl_<단말 id>_<기지 id>_<슬롯>. 기지나 슬롯이 바뀌면 다른 링크로 취급된다 */
  id: string;
  client: string;
  base: string;
  /** 기지의 무선 슬롯 포트 번호 */
  slot: number;
  distance: number;
  /** 단말의 무선 포트 번호 (스마트폰 0, 노트북 1 — 노트북의 0 은 유선 eth0) */
  clientPort: number;
  /** 노트북의 유선에 케이블이 꽂혀 있어 이 무선 연결은 대기 중 (유선 우선 — 케이블을 빼면 이쪽으로 넘어감) */
  standby?: boolean;
}

/** 기지별 슬롯 할당. 단말이 떨어졌다 다시 붙어도 같은 슬롯을 주어 다른 단말이 흔들리지 않게 한다 */
const slotTable = new Map<string, Map<string, number>>();

function radioSlotPorts(d: Device): number[] {
  return specOf(d).ports.map((p, i) => (p.radio ? i : -1)).filter((i) => i >= 0);
}

export function baseSsid(d: Device): WifiBaseSettings | undefined {
  if (d.kind === "ap") return d.ap ?? DEFAULT_WIFI_BASE;
  if (d.router) return d.router.wifi ?? DEFAULT_ROUTER_WIFI;
  return undefined;
}

function center(d: Device): { x: number; y: number } {
  const s = specOf(d);
  return { x: d.x + s.width / 2, y: d.y + s.height / 2 };
}

/** 무선 단말마다 SSID 가 같고 범위 안인 가장 가까운 기지에 붙인다 */
export function wirelessLinks(t: Topology): WirelessLink[] {
  const bases = t.devices.filter((d) => {
    const b = baseSsid(d);
    return b !== undefined && b.enabled && b.ssid.trim() !== "";
  });
  const taken = new Map<string, Set<number>>();
  for (const b of bases) taken.set(b.id, new Set());
  // 단말마다 가장 가까운 기지부터 정한다
  const cands: { c: Device; order: number; base: Device; distance: number; clientPort: number; standby: boolean }[] = [];
  t.devices.forEach((c, order) => {
    if (!c.wifi || c.wifi.enabled === false) return;
    const ssid = c.wifi.ssid.trim();
    if (!ssid) return;
    const clientPort = specOf(c).ports.findIndex((p) => p.radio);
    if (clientPort < 0) return;
    const cc = center(c);
    let best: { base: Device; distance: number } | undefined;
    for (const b of bases) {
      if (baseSsid(b)!.ssid.trim() !== ssid) continue;
      const bc = center(b);
      const distance = Math.hypot(bc.x - cc.x, bc.y - cc.y);
      if (distance > WIFI_RANGE) continue;
      if (!best || distance < best.distance) best = { base: b, distance };
    }
    if (!best) return;
    // 노트북 유선에 케이블이 꽂혀 있으면 이 무선 연결은 대기 (유선 우선)
    const standby = clientPort > 0 && t.cables.some((k) => (k.a.device === c.id && k.a.port !== clientPort) || (k.b.device === c.id && k.b.port !== clientPort));
    cands.push({ c, order, base: best.base, distance: best.distance, clientPort, standby });
  });
  // 슬롯: 먼저 각자 쓰던 슬롯을 지켜 주고(새 단말이 끼어들어도 붙어 있던 단말이 흔들리지 않게), 남은 단말은 빈 슬롯을 받는다 —
  // 이때 쓰는 연결이 대기 연결(노트북 유선 사용 중)보다 먼저
  const slotOf = new Map<Device, number>();
  for (const k of cands) {
    const slot = slotTable.get(k.base.id)?.get(k.c.id);
    const used = taken.get(k.base.id)!;
    if (slot === undefined || used.has(slot) || !radioSlotPorts(k.base).includes(slot)) continue;
    used.add(slot);
    slotOf.set(k.c, slot);
  }
  for (const k of [...cands].sort((a, b) => Number(a.standby) - Number(b.standby) || a.order - b.order)) {
    if (slotOf.has(k.c)) continue;
    const used = taken.get(k.base.id)!;
    const slot = radioSlotPorts(k.base).find((p) => !used.has(p));
    if (slot === undefined) continue; // 슬롯 부족
    used.add(slot);
    slotOf.set(k.c, slot);
    const table = slotTable.get(k.base.id) ?? new Map<string, number>();
    slotTable.set(k.base.id, table);
    table.set(k.c.id, slot);
  }
  const out: WirelessLink[] = [];
  for (const k of cands) {
    const slot = slotOf.get(k.c);
    if (slot === undefined) continue;
    out.push({ id: `wl_${k.c.id}_${k.base.id}_${slot}`, client: k.c.id, base: k.base.id, slot, distance: Math.round(k.distance), clientPort: k.clientPort, ...(k.standby ? { standby: true } : {}) });
  }
  return out;
}

/** 단말이 왜 안 붙는지 (인스펙터 안내용) */
export function wirelessStatus(t: Topology, client: Device): { linked?: WirelessLink; reason?: string } {
  const link = wirelessLinks(t).find((l) => l.client === client.id);
  if (link) return { linked: link };
  if (client.wifi?.enabled === false) return { reason: "Wi-Fi 가 꺼져 있습니다" };
  const ssid = client.wifi?.ssid.trim() ?? "";
  if (!ssid) return { reason: "연결할 SSID 를 입력하세요" };
  const same = t.devices.filter((d) => baseSsid(d)?.ssid.trim() === ssid);
  if (same.length === 0) return { reason: `SSID "${ssid}" 를 송출하는 AP 나 공유기가 없습니다` };
  const on = same.filter((d) => baseSsid(d)!.enabled);
  if (on.length === 0) return { reason: `SSID "${ssid}" 의 무선이 꺼져 있습니다` };
  const cc = center(client);
  const inRange = on.filter((d) => Math.hypot(center(d).x - cc.x, center(d).y - cc.y) <= WIFI_RANGE);
  if (inRange.length === 0) return { reason: `SSID "${ssid}" 는 있지만 전파 범위(${WIFI_RANGE}px) 밖입니다. 단말을 AP 쪽으로 옮기세요` };
  return { reason: `범위 안의 기지 ${inRange.map((d) => d.name).join(", ")} 에 빈 무선 슬롯이 없습니다 (기지당 ${radioSlotPorts(inRange[0]!).length}대)` };
}

export function defaultL3(kind: DeviceKind): L3Settings {
  if (kind === "nat") {
    return {
      interfaces: [
        { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" },
        { ipMode: "static", ip: "192.168.0.1", prefix: 24, gateway: "" },
      ],
      routes: [],
    };
  }
  return {
    interfaces: [
      { ipMode: "dhcp", ip: "", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "192.168.1.1", prefix: 24, gateway: "" },
      { ipMode: "static", ip: "192.168.2.1", prefix: 24, gateway: "" },
    ],
    routes: [],
  };
}

/** 포트가 타일 가장자리에서 튀어나온 위치 (케이블이 붙는 점) */
export function portAnchor(device: Device, port: number): { x: number; y: number; side: PortSide } {
  const spec = specOf(device);
  const p = spec.ports[port];
  if (!p) throw new Error(`${device.name} has no port ${port}`);
  if (p.radio) {
    // 무선 슬롯: 타일 위쪽 가운데 (전파 링크가 여기서 나간다)
    return { x: device.x + spec.width / 2, y: device.y - PORT_DEPTH, side: "top" };
  }
  const siblings = spec.ports.filter((q) => q.side === p.side && !q.radio);
  const index = siblings.indexOf(p);
  const gap = 14;
  const x = device.x + spec.width / 2 + (index - (siblings.length - 1) / 2) * gap;
  const y = p.side === "top" ? device.y - PORT_DEPTH : device.y + spec.height + PORT_DEPTH;
  return { x, y, side: p.side };
}

export const PORT_DEPTH = 6;
export const PORT_WIDTH = 8;

export function usedPorts(topology: Topology, deviceId: string): Set<number> {
  const used = new Set<number>();
  for (const c of topology.cables) {
    if (c.a.device === deviceId) used.add(c.a.port);
    if (c.b.device === deviceId) used.add(c.b.port);
  }
  return used;
}

/**
 * 비어 있는 포트 중 상대 장치를 향한 쪽(상대가 위에 있으면 top)을 우선 고른다.
 * 케이블이 포트에서 수직으로 나가므로, 이렇게 해야 선이 자연스럽게 상대를 향한다.
 */
/**
 * 장치 묶음을 복제한다: 새 id·이름·MAC, 설정은 깊은 복사, 묶음 안에서 서로 잇는 케이블만 따라온다.
 * @returns 붙여 넣을 장치·케이블 (원본 토폴로지에는 아직 없음)
 */
export function cloneDevices(t: Topology, ids: string[], offset: { x: number; y: number }, existing: Device[] = t.devices): { devices: Device[]; cables: Cable[] } {
  const picked = t.devices.filter((d) => ids.includes(d.id));
  const pool = [...existing];
  const idMap = new Map<string, string>();
  const devices: Device[] = [];
  for (const d of picked) {
    const copy: Device = { ...structuredClone(d), id: newId(d.kind), name: nextName(d.kind, pool), mac: nextMac(pool), x: snap(d.x + offset.x), y: snap(d.y + offset.y) };
    // WireGuard 개인 키는 장치의 신원이라 복사하지 않는다 (MAC 처럼 새로 — 새 id 에서 만든 키)
    if (copy.router?.wgServer?.privateKey) delete copy.router.wgServer.privateKey;
    if (copy.router?.wgClient?.privateKey) delete copy.router.wgClient.privateKey;
    if (copy.host?.ra?.wg?.privateKey) delete copy.host.ra.wg.privateKey;
    idMap.set(d.id, copy.id);
    devices.push(copy);
    pool.push(copy);
  }
  const cables: Cable[] = t.cables
    .filter((c) => idMap.has(c.a.device) && idMap.has(c.b.device))
    .map((c) => ({ ...c, id: newId("cable"), a: { device: idMap.get(c.a.device)!, port: c.a.port }, b: { device: idMap.get(c.b.device)!, port: c.b.port } }));
  return { devices, cables };
}

export type AlignMode = "left" | "top" | "spread-x" | "spread-y";

/** 여러 장치를 정렬한다. spread 는 양 끝은 두고 사이 간격을 같게 */
export function alignDevices(t: Topology, ids: string[], mode: AlignMode): Topology {
  const picked = t.devices.filter((d) => ids.includes(d.id));
  if (picked.length < 2) return t;
  const pos = new Map<string, { x: number; y: number }>();
  if (mode === "left") {
    const x = Math.min(...picked.map((d) => d.x));
    for (const d of picked) pos.set(d.id, { x, y: d.y });
  } else if (mode === "top") {
    const y = Math.min(...picked.map((d) => d.y));
    for (const d of picked) pos.set(d.id, { x: d.x, y });
  } else {
    const key = mode === "spread-x" ? "x" : "y";
    const size = (d: Device) => (mode === "spread-x" ? specOf(d).width : specOf(d).height);
    const sorted = [...picked].sort((a, b) => a[key] - b[key]);
    const first = sorted[0]!;
    const last = sorted[sorted.length - 1]!;
    const span = last[key] - first[key] - sorted.slice(0, -1).reduce((acc, d) => acc + size(d), 0);
    const gap = span / (sorted.length - 1);
    let cursor = first[key];
    for (const d of sorted) {
      pos.set(d.id, { x: mode === "spread-x" ? snap(cursor) : d.x, y: mode === "spread-y" ? snap(cursor) : d.y });
      cursor += size(d) + gap;
    }
  }
  return { ...t, devices: t.devices.map((d) => (pos.has(d.id) ? { ...d, ...pos.get(d.id)! } : d)) };
}

/** 저장·공유용 JSON 문서 */
export interface TopologyFile {
  app: "net-sim";
  version: 1;
  devices: Device[];
  cables: Cable[];
  zones?: Zone[];
}

export function serializeTopology(t: Topology): string {
  const doc: TopologyFile = { app: "net-sim", version: 1, devices: t.devices, cables: t.cables, ...(t.zones?.length ? { zones: t.zones } : {}) };
  return JSON.stringify(doc, null, 2);
}

/** JSON 문자열 → 토폴로지. 형식이 틀리면 사용자에게 보일 이유를 돌려준다 */
export function parseTopology(text: string): { topology?: Topology; error?: string } {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { error: "JSON 으로 읽을 수 없습니다. net-sim 에서 내려받은 .json 파일인지 확인하세요" };
  }
  if (!raw || typeof raw !== "object") return { error: "JSON 최상위가 객체가 아닙니다" };
  const doc = raw as Partial<TopologyFile>;
  if (!Array.isArray(doc.devices) || !Array.isArray(doc.cables)) return { error: "devices 와 cables 배열이 있어야 합니다. net-sim 에서 내려받은 파일인지 확인하세요" };
  const ids = new Set<string>();
  for (const d of doc.devices as unknown[]) {
    if (!d || typeof d !== "object") return { error: "devices 항목이 객체가 아닙니다" };
    const dev = d as Partial<Device>;
    if (typeof dev.id !== "string" || !dev.id) return { error: "id 가 없는 장치가 있습니다" };
    if (ids.has(dev.id)) return { error: `장치 id 가 겹칩니다: ${dev.id}` };
    ids.add(dev.id);
    if (typeof dev.kind !== "string" || !(dev.kind in DEVICE_SPECS)) return { error: `모르는 장치 종류입니다: ${String(dev.kind)} (${dev.id}). 이 버전에서 지원하는 종류: ${Object.keys(DEVICE_SPECS).join(", ")}` };
    if (typeof dev.x !== "number" || typeof dev.y !== "number" || !Number.isFinite(dev.x) || !Number.isFinite(dev.y)) return { error: `좌표가 숫자가 아닙니다: ${dev.id}` };
    if (typeof dev.name !== "string") return { error: `이름이 없는 장치가 있습니다: ${dev.id}` };
  }
  for (const c of doc.cables as unknown[]) {
    const cab = c as Partial<Cable>;
    if (!cab || typeof cab.id !== "string" || !cab.a || !cab.b || typeof cab.a.device !== "string" || typeof cab.b.device !== "string" || !Number.isInteger(cab.a.port) || !Number.isInteger(cab.b.port)) {
      return { error: "케이블 항목 형식이 틀립니다 (id, a{device,port}, b{device,port})" };
    }
  }
  // 나머지(없는 설정, 사라진 장치를 가리키는 케이블, 겹치는 포트)는 normalizeTopology 가 기본값으로 채우거나 버린다
  return { topology: normalizeTopology({ devices: doc.devices as Device[], cables: doc.cables as Cable[], zones: Array.isArray(doc.zones) ? (doc.zones as Zone[]) : [] }) };
}

/** 두 장치를 잇는 케이블의 양 끝 포트를 정한다. 못 잇는 이유는 사용자에게 보일 문장으로 돌려준다 */
/** 이 포트에 케이블을 꽂을 수 있는지. 안 되면 이유 (except: 옮기는 중인 케이블은 자기 자리를 비운 것으로 본다) */
export function portProblem(t: Topology, ref: PortRef, except?: string): string | undefined {
  const d = t.devices.find((x) => x.id === ref.device);
  if (!d) return "장치를 찾을 수 없습니다";
  const p = specOf(d).ports[ref.port];
  if (!p) return `${d.name} 에는 ${ref.port + 1}번째 포트가 없습니다`;
  if (p.radio) return `${d.name} ${p.name} 은(는) 무선 슬롯이라 케이블을 꽂을 수 없습니다`;
  const busy = t.cables.find((c) => c.id !== except && ((c.a.device === ref.device && c.a.port === ref.port) || (c.b.device === ref.device && c.b.port === ref.port)));
  if (busy) return `${d.name} ${p.name} 에는 이미 케이블이 꽂혀 있습니다. 다른 포트를 고르거나 그 케이블을 먼저 빼세요`;
  return undefined;
}

/**
 * 두 장치를 잇는 케이블의 양 끝 포트를 정한다. aPort/bPort 를 주면 그 포트를 쓰고(포트 칸 위에 놓은 경우), 없으면 상대를 향한 빈 포트를 고른다.
 * 못 잇는 이유는 사용자에게 보일 문장으로 돌려준다
 */
export function planCable(t: Topology, aId: string, bId: string, aPort?: number, bPort?: number): { a: PortRef; b: PortRef } | { error: string } {
  if (aId === bId) return { error: "같은 장치끼리는 연결할 수 없습니다" };
  const a = t.devices.find((d) => d.id === aId);
  const b = t.devices.find((d) => d.id === bId);
  if (!a || !b) return { error: "장치를 찾을 수 없습니다" };
  for (const d of [a, b]) {
    if (DEVICE_SPECS[d.kind].ports.every((p) => p.radio)) return { error: `${d.name} 은(는) 무선 전용이라 케이블을 꽂을 수 없습니다. SSID 를 맞추고 AP 근처로 옮기세요` };
  }
  if (t.cables.some((c) => (c.a.device === aId && c.b.device === bId) || (c.a.device === bId && c.b.device === aId))) {
    return { error: `${a.name} 와 ${b.name} 는 이미 연결되어 있습니다. 두 번째 케이블은 L2 루프(브로드캐스트 폭주)를 만듭니다` };
  }
  const pa = aPort ?? freePort(t, aId, b.y);
  const pb = bPort ?? freePort(t, bId, a.y);
  if (pa === undefined) return { error: `${a.name} 에 빈 포트가 없습니다` };
  if (pb === undefined) return { error: `${b.name} 에 빈 포트가 없습니다` };
  const ra = { device: aId, port: pa };
  const rb = { device: bId, port: pb };
  const why = portProblem(t, ra) ?? portProblem(t, rb);
  if (why) return { error: why };
  return { a: ra, b: rb };
}

export function freePort(topology: Topology, deviceId: string, peerY?: number): number | undefined {
  const device = topology.devices.find((d) => d.id === deviceId);
  if (!device) return undefined;
  const used = usedPorts(topology, deviceId);
  const spec = specOf(device);
  const preferred: PortSide = peerY !== undefined && peerY < device.y ? "top" : "bottom";
  const order = spec.ports
    .map((_, i) => i)
    .filter((i) => !spec.ports[i]!.radio)
    .sort((a, b) => Number(spec.ports[b]!.side === preferred) - Number(spec.ports[a]!.side === preferred));
  return order.find((i) => !used.has(i));
}

export function cableAt(topology: Topology, ref: PortRef): Cable | undefined {
  return topology.cables.find((c) => samePort(c.a, ref) || samePort(c.b, ref));
}

export function samePort(a: PortRef, b: PortRef): boolean {
  return a.device === b.device && a.port === b.port;
}

export function peerOf(cable: Cable, deviceId: string): PortRef {
  return cable.a.device === deviceId ? cable.b : cable.a;
}

export function snap(v: number, grid = 8): number {
  return Math.round(v / grid) * grid;
}

/** 저장된 토폴로지의 누락 필드 보정 (이전 버전에서 저장한 데이터) */
export function normalizeTopology(t: Topology): Topology {
  const devices: Device[] = [];
  // 모르는 장치 종류(다른 버전의 저장본)는 버린다
  const known = t.devices.filter((d) => d && typeof d.kind === "string" && d.kind in DEVICE_SPECS);
  for (const d of known) {
    const fixed: Device = { ...d };
    // MAC 이 비어 있으면 입력 전체(뒤 장치 포함)와 겹치지 않게
    if (!fixed.mac) fixed.mac = nextMac([...known, ...devices]);
    const spec = DEVICE_SPECS[fixed.kind];
    if (spec.role === "host") {
      if (!fixed.host) fixed.host = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "", services: fixed.kind === "server" ? [80] : [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
      else {
        fixed.host = {
          ...fixed.host,
          services: fixed.host.services ?? (fixed.kind === "server" ? [80] : []),
          dhcpServer: fixed.host.dhcpServer ?? { ...DEFAULT_DHCP_SERVER },
          ...(fixed.host.ra ? { ra: normalizeRaClient(fixed.host.ra) } : {}),
        };
      }
    }
    if (fixed.host) fixed.host = normalizeHostExtras(fixed.host);
    if (spec.role === "ap" && !fixed.ap) fixed.ap = { ...DEFAULT_WIFI_BASE };
    if (spec.role === "firewall") fixed.firewall = fixed.firewall ? { ...DEFAULT_FIREWALL_SETTINGS, ...fixed.firewall, rules: fixed.firewall.rules ?? [] } : { ...DEFAULT_FIREWALL_SETTINGS, enabled: true, rules: [] };
    if (spec.role === "switch" && !fixed.switch) fixed.switch = { vlans: {} };
    if (fixed.switch && fixed.switch.igmpSnooping !== undefined) fixed.switch = { ...fixed.switch, igmpSnooping: fixed.switch.igmpSnooping === true };
    if (fixed.switch?.stp) {
      const st = fixed.switch.stp as Partial<{ enabled: boolean; priority: number }>;
      const prio = typeof st.priority === "number" && Number.isInteger(st.priority) && st.priority >= 0 && st.priority <= 61440 ? st.priority - (st.priority % 4096) : 32768;
      fixed.switch = { ...fixed.switch, stp: { enabled: st.enabled === true, priority: prio } };
    }
    if (fixed.kind === "phone" && !fixed.wifi) fixed.wifi = { ssid: "home" };
    // 무선 단말 설정은 스마트폰·노트북만 (손으로 고친 JSON 의 ssid·enabled 를 타입대로)
    if (fixed.wifi) {
      const w = fixed.wifi as Partial<WifiClientSettings>;
      fixed.wifi = fixed.kind === "phone" || fixed.kind === "laptop" ? { ssid: typeof w.ssid === "string" ? w.ssid : "", ...(w.enabled === false && fixed.kind === "laptop" ? { enabled: false } : {}) } : undefined;
      if (!fixed.wifi) delete fixed.wifi;
    }
    if (spec.role === "l3") {
      const def = defaultL3(fixed.kind);
      if (!fixed.l3) fixed.l3 = def;
      else {
        const ifs = fixed.l3.interfaces ?? [];
        fixed.l3 = {
          ...fixed.l3,
          interfaces: def.interfaces.map((d, i) => (ifs[i] ? { ...d, ...ifs[i] } : d)),
          routes: fixed.l3.routes ?? [],
          ...(fixed.l3.firewall ? { firewall: { ...DEFAULT_FIREWALL_SETTINGS, ...fixed.l3.firewall, rules: fixed.l3.firewall.rules ?? [] } } : {}),
          ...(fixed.l3.vpn ? { vpn: normalizeVpn(fixed.l3.vpn) } : {}),
          ...(fixed.l3.ha ? { ha: normalizeHa(fixed.l3.ha) } : {}),
          ...(fixed.l3.ra ? { ra: normalizeRaServer(fixed.l3.ra) } : {}),
          ...(fixed.l3.ipv6 ? { ipv6: normalizeIpv6L3(fixed.l3.ipv6) } : {}),
          ...(fixed.l3.nat ? { nat: { enabled: (fixed.l3.nat as { enabled?: unknown }).enabled === true } } : {}),
          ...(fixed.l3.publish ? { publish: normalizePublish(fixed.l3.publish) } : {}),
          natType: natTypeOf(fixed.l3.natType),
          hairpin: fixed.l3.hairpin === true ? true : undefined,
        };
      }
    }
    if (spec.role === "router") {
      if (!fixed.router) fixed.router = { lanIp: "192.168.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "192.168.0.100", end: "192.168.0.199" }, wan: { ...DEFAULT_WAN } };
      else {
        const r = fixed.router;
        fixed.router = {
          ...r,
          lanIp: r.lanIp ?? "192.168.0.1",
          lanPrefix: r.lanPrefix ?? 24,
          // 예전/손상 저장본에는 dhcp 가 없을 수 있다 (타입상 필수지만 JSON 은 믿을 수 없다)
          dhcp: (r.dhcp as RouterSettings["dhcp"] | undefined) ?? { enabled: true, start: "192.168.0.100", end: "192.168.0.199" },
          wan: r.wan ?? { ...DEFAULT_WAN },
          ...(r.firewall ? { firewall: { ...DEFAULT_FIREWALL_SETTINGS, ...r.firewall, rules: r.firewall.rules ?? [] } } : {}),
          ...(r.ipv6 ? { ipv6: { enabled: (r.ipv6 as Partial<RouterIpv6Settings>).enabled === true, inboundBlock: (r.ipv6 as Partial<RouterIpv6Settings>).inboundBlock !== false } } : {}),
          ...(r.vpnServer ? { vpnServer: normalizeRouterVpn(r.vpnServer) } : {}),
          ...(r.wgServer ? { wgServer: normalizeWgServer(r.wgServer) } : {}),
          ...(r.wgClient ? { wgClient: normalizeWgClient(r.wgClient) } : {}),
          ...(r.ovpnServer ? { ovpnServer: normalizeOvpnServer(r.ovpnServer) } : {}),
          ...(r.mesh && typeof r.mesh === "object" ? { mesh: normalizeMesh(r.mesh) } : {}),
          ...(r.admin && typeof r.admin === "object"
            ? { admin: { enabled: r.admin.enabled === true, remote: r.admin.remote === true, allow: typeof r.admin.allow === "string" ? r.admin.allow : "", ssh: r.admin.ssh !== false } }
            : {}),
          ...(r.cloud === true ? { cloud: true } : {}),
          ...(r.dropIn === true ? { dropIn: true } : {}),
          ...(r.igmpSnooping === true ? { igmpSnooping: true } : {}),
          ...(r.samba && typeof r.samba === "object" ? { samba: { enabled: r.samba.enabled === true, wan: r.samba.wan === true } } : {}),
          ...(Array.isArray(r.blocked) ? { blocked: r.blocked.filter((x): x is string => typeof x === "string") } : {}),
          ...(r.wan2 ? { wan2: normalizeWan2(r.wan2) } : {}),
          ...(r.adguard ? { adguard: normalizeAdguard(r.adguard) } : {}),
          ...(r.dpi ? { dpi: { enabled: (r.dpi as Partial<RouterDpiSettings>).enabled === true, blockApps: Array.isArray(r.dpi.blockApps) ? r.dpi.blockApps.filter((x): x is string => typeof x === "string") : [], blockCategories: Array.isArray(r.dpi.blockCategories) ? r.dpi.blockCategories.filter((x): x is string => typeof x === "string") : [] } } : {}),
          ...(r.ddns ? { ddns: { enabled: (r.ddns as Partial<RouterDdnsSettings>).enabled === true, name: typeof (r.ddns as Partial<RouterDdnsSettings>).name === "string" ? r.ddns.name : "" } } : {}),
          natType: natTypeOf(r.natType),
          hairpin: r.hairpin === true ? true : undefined,
        };
      }
    }
    devices.push(fixed);
  }
  const ids = new Set(devices.map((d) => d.id));
  const usedPort = new Set<string>();
  const cables: Cable[] = [];
  for (const c of t.cables) {
    if (!ids.has(c.a.device) || !ids.has(c.b.device)) continue;
    const da = devices.find((d) => d.id === c.a.device)!;
    const db = devices.find((d) => d.id === c.b.device)!;
    // 없는 포트(예전 스펙·음수)와 무선 포트(케이블 금지)는 버린다
    const portOk = (d: Device, port: number) => Number.isInteger(port) && port >= 0 && port < DEVICE_SPECS[d.kind].ports.length && !DEVICE_SPECS[d.kind].ports[port]!.radio;
    if (!portOk(da, c.a.port) || !portOk(db, c.b.port) || c.a.device === c.b.device) continue;
    const ka = `${c.a.device}:${c.a.port}`;
    const kb = `${c.b.device}:${c.b.port}`;
    if (usedPort.has(ka) || usedPort.has(kb) || ka === kb) continue; // 같은 포트에 두 케이블: 앞의 것만 남긴다
    usedPort.add(ka);
    usedPort.add(kb);
    cables.push(c);
  }
  const zones: Zone[] = (t.zones ?? [])
    .filter((z) => z && typeof z.id === "string" && [z.x, z.y, z.w, z.h].every((n) => typeof n === "number" && Number.isFinite(n)))
    .map((z) => ({
      id: z.id,
      label: typeof z.label === "string" ? z.label : "영역",
      x: z.x,
      y: z.y,
      w: Math.max(ZONE_MIN, z.w),
      h: Math.max(ZONE_MIN, z.h),
      tint: ZONE_TINTS.some((tt) => tt.id === z.tint) ? z.tint : "gray",
    }));
  return zones.length > 0 ? { devices, cables, zones } : { devices, cables };
}


/** 장치 포트의 VLAN 모드 (스위치가 아니면 undefined) */
export function portVlanOf(d: Device, port: number): number | "trunk" | undefined {
  if (d.kind !== "switch") return undefined;
  return d.switch?.vlans[port] ?? 1;
}

/** VLAN 번호 → 캔버스 색 인덱스 (1 은 기본색). 같은 번호는 항상 같은 색 */
export const VLAN_COLORS = ["#e0a526", "#2ba84a", "#2b8fd6", "#8b5cf6", "#e05a8a", "#14b8a6", "#f97316"];
export function vlanColor(vlan: number): string {
  return VLAN_COLORS[(vlan - 1) % VLAN_COLORS.length]!;
}
