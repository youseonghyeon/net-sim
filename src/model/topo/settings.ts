// 장치 설정의 모양(…Settings)·기본값·불러온 JSON 정리: 기능마다 타입·기본값·정리를 한곳에
import { wgPrivateKey, wgPublicKey } from "../../core/nodes/wg";
import { ovpnCaOf, ovpnTlsCryptOf } from "../../core/nodes/openvpn";
import { normalizeDnsServer, normalizeLbBase, type Obj } from "../normalize";
import { type Device } from "./device";
import { type DeviceKind } from "./specs";

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
  /** SSH 점프 서버 (sshd AllowTcpForwarding): SSH 로 로그인한 사용자가 이 서버를 거쳐 다른 서버로 (ssh -J). 없으면 꺼짐 */
  sshJump?: boolean;
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
  /** 인터넷 전화 (SIP). 없으면 꺼짐. user 가 비면 장치 이름에서 */
  sip?: { enabled: boolean; user: string };
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
export function normalizeIpv6Host(v: Partial<Ipv6HostSettings>): Ipv6HostSettings {
  return { enabled: v.enabled === true, mode: v.mode === "slaac" ? "slaac" : "static", ip: text(v.ip), prefix: prefix6(v.prefix, 64), gateway: text(v.gateway), ...(typeof v.dns === "string" ? { dns: v.dns } : {}), ...(v.nud === true ? { nud: true } : {}) };
}

/** 불러온 JSON 의 게이트웨이 IPv6 설정 정리 */
export function normalizeIpv6L3(v: Partial<Ipv6L3Settings>): Ipv6L3Settings {
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
export function normalizeHostExtras(h: HostSettings): HostSettings {
  const port = (v: unknown, fallback: number) => {
    const n = typeof v === "string" && v.trim() !== "" ? Number(v) : v;
    return typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= 65535 ? n : fallback;
  };
  const out: HostSettings = { ...h };
  if (h.lb) {
    // 예전 저장본: 세션 고정이 켜기/끄기(true)였다 → 출발지 IP. 모르는 값은 버린다
    const st = h.lb.sticky as unknown;
    const hc = h.lb.healthCheck;
    out.lb = { ...normalizeLbBase(h.lb as unknown as Obj), ...(st === true || st === "ip" ? { sticky: "ip" as const } : st === "cookie" ? { sticky: "cookie" as const } : {}), ...(hc === true ? { healthCheck: true } : {}) };
  }
  if (h.dnsServer) out.dnsServer = normalizeDnsServer(h.dnsServer);
  if (h.proxy) {
    const p = h.proxy as Partial<ProxySettings>;
    const deny = typeof p.deny === "string" ? [p.deny] : Array.isArray(p.deny) ? p.deny.filter((x): x is string => typeof x === "string") : [];
    out.proxy = { enabled: p.enabled === true, port: port(p.port, 3128), deny };
  }
  if (h.httpProxy) {
    const p = h.httpProxy as Partial<HttpProxySettings>;
    out.httpProxy = { enabled: p.enabled === true, server: typeof p.server === "string" ? p.server : typeof p.server === "number" ? String(p.server) : "", port: port(p.port, 3128) };
  }
  if (h.sshJump !== undefined) {
    if (h.sshJump === true) out.sshJump = true;
    else delete out.sshJump;
  }
  if (h.ipv6) out.ipv6 = normalizeIpv6Host(h.ipv6 as Partial<Ipv6HostSettings>);
  if (h.p2p) {
    const p = h.p2p as { enabled?: unknown; name?: unknown };
    out.p2p = { enabled: p.enabled === true, ...(typeof p.name === "string" ? { name: p.name } : {}) };
  }
  if (h.mesh && typeof h.mesh === "object") out.mesh = normalizeMesh(h.mesh as Partial<MeshSettings>);
  if (h.sip && typeof h.sip === "object") {
    const p = h.sip as { enabled?: unknown; user?: unknown };
    out.sip = { enabled: p.enabled === true, user: typeof p.user === "string" ? p.user : "" };
  }
  return out;
}

export function normalizeRaServer(r: Partial<RaServerSettings>): RaServerSettings {
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
export function normalizeRaClient(r: Partial<RaClientSettings>): RaClientSettings {
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
export function normalizeRouterVpn(r: Partial<RouterVpnServerSettings>): RouterVpnServerSettings {
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
export function normalizePublish(v: unknown): PublishSettings[] {
  if (!Array.isArray(v)) return [];
  const num = (x: unknown, d: number) => (typeof x === "number" && Number.isInteger(x) ? x : typeof x === "string" && /^\d+$/.test(x) ? Number(x) : d);
  return v
    // bind 가 문자열이 아니면 버린다 — 0.0.0.0 으로 채우면 손으로 좁혀 둔 공개 범위가 넓어진다
    .filter((r): r is Record<string, unknown> => !!r && typeof r === "object" && typeof r.bind === "string")
    .map((r) => ({ port: num(r.port, 0), bind: r.bind as string, to: typeof r.to === "string" ? r.to : "", toPort: num(r.toPort, 0) }));
}

/** 불러온 JSON 의 이중화 설정 정리 */
export function normalizeHa(h: Partial<HaSettings>): HaSettings {
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
export function normalizeVpn(v: Partial<VpnSettings>): VpnSettings {
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
  /** SIP ALG. 없으면 꺼짐 */
  sipAlg?: boolean;
  /** Tor (LAN 의 TCP·DNS 를 Tor 로). 없으면 꺼짐 */
  tor?: boolean;
  /** 스태틱 라우트 (LuCI Network → Static Routes). 없으면 없음 */
  routes?: RouterRouteSetting[];
}

/** 스태틱 라우트: dest = 대상 대역 (CIDR, 주소 하나면 /32), via = 넥스트 홉 (그 인터페이스 대역 안) */
export interface RouterRouteSetting {
  iface: "wan" | "wan2";
  dest: string;
  via: string;
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

export function normalizeMesh(v: Partial<MeshSettings>): MeshSettings {
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

export function normalizeOvpnServer(v: Partial<RouterOvpnServerSettings>): RouterOvpnServerSettings {
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

export function normalizeOvpnClient(v: Partial<OvpnClientSettings>): OvpnClientSettings {
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

export function normalizeAdguard(v: Partial<RouterAdguardSettings>): RouterAdguardSettings {
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
  /** 정책 규칙 (mwan3 rule): 출발지 대역 → 회선, 위에서부터 처음 맞는 것. 없으면 페일오버만 */
  rules?: MwanRuleSetting[];
  /** false = 디폴트 라우트로 쓰지 않음 (LuCI "Use default gateway" 끔 + mwan3 에서 뺌 — 직접 연결된 대역·스태틱 라우트로만). 없으면 씀 */
  defaultRoute?: boolean;
}

/** 멀티 WAN 정책 규칙: src = 출발지 대역 (CIDR, 주소 하나면 /32) */
export interface MwanRuleSetting {
  src: string;
  line: "wan" | "wan2";
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

export function normalizeWan2(v: Partial<RouterWan2Settings>): RouterWan2Settings {
  const str = (x: unknown) => (typeof x === "string" ? x : "");
  return {
    enabled: v.enabled === true,
    ipMode: v.ipMode === "static" ? "static" : "dhcp",
    ip: str(v.ip),
    prefix: typeof v.prefix === "number" && Number.isInteger(v.prefix) && v.prefix >= 1 && v.prefix <= 32 ? v.prefix : 24,
    gateway: str(v.gateway),
    track: typeof v.track === "string" ? v.track : "8.8.8.8",
    ...(Array.isArray(v.rules)
      ? {
          rules: (v.rules as unknown[])
            .filter((x): x is Record<string, unknown> => !!x && typeof x === "object")
            .map((x) => ({ src: str(x.src), line: x.line === "wan" ? ("wan" as const) : ("wan2" as const) })),
        }
      : {}),
    ...(v.defaultRoute === false ? { defaultRoute: false } : {}),
  };
}

export function normalizeRoutes(v: unknown[]): RouterRouteSetting[] {
  const str = (x: unknown) => (typeof x === "string" ? x : "");
  return v
    .filter((x): x is Record<string, unknown> => !!x && typeof x === "object")
    .map((x) => ({ iface: x.iface === "wan2" ? ("wan2" as const) : ("wan" as const), dest: str(x.dest), via: str(x.via) }));
}

export function normalizeWgFields(v: Partial<WgClientSettings>): WgClientSettings {
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

export function normalizeWgServer(v: Partial<RouterWgServerSettings>): RouterWgServerSettings {
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

export function normalizeWgClient(v: Partial<RouterWgClientSettings>): RouterWgClientSettings {
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
