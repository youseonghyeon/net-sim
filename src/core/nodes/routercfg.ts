// 공유기 설정의 모양 (RouterSettings 를 netSync 가 정리해 넘기는 값): 회선·멀티 WAN·스태틱 라우트·WireGuard·IPv6.
// 기능 모듈의 설정(DHCP·DNS·방화벽·L2TP·DDNS·AdGuard·DPI·OpenVPN·메시·관리 화면)은 각 모듈에 있다
import type { Ip, Mac } from "../addr";
import type { AdguardConfig } from "./adguard";
import type { DdnsConfig } from "./ddns";
import type { DhcpServerConfig } from "./dhcp";
import type { DnsServerConfig } from "./dns";
import type { DpiConfig } from "./dpi";
import type { FirewallConfig } from "./firewall";
import type { AdminConfig } from "./glinet";
import type { L2tpServerConfig } from "./l2tp";
import { WAN_LABEL, type MwanRule, type WanName } from "./mwan";
import type { NatType, PortForward } from "./nat";
import type { OvpnServerConfig } from "./openvpn";
import type { MeshConfig } from "./tailscale";
import type { WgPrefix } from "./wg";

export interface WanConfig {
  mode: "dhcp" | "static";
  ip?: Ip;
  prefix?: number;
  gateway?: Ip;
}

export interface RouterConfig {
  id: string;
  mac: Mac;
  wanMac: Mac;
  lanIp: Ip;
  lanPrefix?: number;
  dhcp: DhcpServerConfig;
  wan?: WanConfig;
  /** DNS 포워더 (공유기 안의 dnsmasq): LAN 의 질의를 업스트림 DNS 로 대신 물어봄 */
  dns?: DnsServerConfig;
  firewall?: FirewallConfig;
  wifi?: { enabled: boolean; ssid: string };
  /** 포트 포워딩 규칙 (TCP): 공인 포트로 들어온 연결을 LAN 호스트로 */
  forwards?: PortForward[];
  /** IPv6 (없으면 꺼짐): WAN 은 ISP 의 RA·DHCPv6-PD 로, LAN 에는 위임받은 /64 를 RA 로 */
  ipv6?: RouterIpv6Config;
  /** VPN 서버 (ipTIME 식 L2TP/IPsec, 없으면 꺼짐) */
  vpnServer?: L2tpServerConfig;
  /** NAT 종류 (없으면 full cone) */
  natType?: NatType;
  /** 헤어핀 NAT (NAT 루프백): 안에서 내 공인 주소의 포워딩 포트로 접속하면 안쪽 서버로 되돌려 준다. 없으면 꺼짐 */
  hairpin?: boolean;
  /** WireGuard 서버 (GL.iNet 식, 없으면 꺼짐) */
  wgServer?: RouterWgServerConfig;
  /** WireGuard 클라이언트 (LAN 전체를 VPN 으로, 없으면 꺼짐) */
  wgClient?: RouterWgClientConfig;
  /** DDNS (없으면 꺼짐) */
  ddns?: DdnsConfig;
  /** 멀티 WAN (없으면 꺼짐): lan4 포트를 WAN2 로 */
  wan2?: Wan2Config;
  /** WAN2 인터페이스 MAC (없으면 WAN MAC 의 4번째 옥텟을 03 으로) */
  wan2Mac?: Mac;
  /** AdGuard Home·자녀 보호 (없으면 꺼짐) */
  adguard?: AdguardConfig;
  /** DPI (없으면 꺼짐) */
  dpi?: DpiConfig;
  /** OpenVPN 서버 (없으면 꺼짐) */
  ovpnServer?: OvpnServerConfig;
  /** 메시 VPN (없으면 꺼짐) */
  mesh?: MeshConfig;
  /** 관리 화면 접근 제어 (없으면 관리 화면 흉내 꺼짐) */
  admin?: AdminConfig;
  /** GoodCloud 원격 관리 (없으면 꺼짐) */
  cloud?: boolean;
  /** 인터넷을 막은 LAN 기기 (MAC) */
  blocked?: string[];
  /** 스태틱 라우트 (LuCI Static Routes) */
  routes?: RouterStaticRoute[];
}

/** 멀티 WAN 페일오버: lan4 = WAN2 (예비 회선), 추적 주소 */
export interface Wan2Config extends WanConfig {
  enabled: boolean;
  /** 회선이 살았는지 ping 할 주소 (비우면 링크·주소만 본다) */
  track?: Ip;
  /** 정책 규칙 (출발지 대역 → 회선) */
  rules?: MwanRule[];
  /** false = 디폴트 라우트로 쓰지 않음 (LuCI "Use default gateway" 끔 + mwan3 에서 뺌). 없으면 씀 */
  defaultRoute?: boolean;
}

/** 스태틱 라우트 (LuCI Network → Static Routes, main 테이블): 이 대역은 그 인터페이스의 넥스트 홉으로 */
export interface RouterStaticRoute {
  iface: WanName;
  dest: { ip: Ip; prefix: number };
  /** 넥스트 홉. 없으면 그 인터페이스로 바로 (on-link — 대상에게 직접 ARP) */
  via?: Ip;
}

export function staticRouteLabel(r: RouterStaticRoute): string {
  return `${r.dest.ip}/${r.dest.prefix} ${r.via ? `via ${r.via}` : "on-link"} (${WAN_LABEL[r.iface]})`;
}

/** 공유기 WireGuard 서버: 밖의 노트북·폰·다른 공유기가 공개 키로 붙는다 */
export interface RouterWgServerConfig {
  enabled: boolean;
  privateKey: string;
  /** 서버의 터널 주소 (예: 10.0.0.1/24) */
  address?: { ip: Ip; prefix: number };
  listenPort: number;
  /** 피어 = 등록한 클라이언트 (공개 키 + 그 클라이언트의 터널 주소) */
  peers: { name: string; publicKey: string; ip: Ip }[];
  /** 클라이언트가 집 LAN 에 접근해도 되는지 (GL.iNet "Remote Access LAN") */
  lanAccess: boolean;
  /** 난독화 (AmneziaWG 식 — 클라이언트도 켜야 한다) */
  obfuscate?: boolean;
}

/** 공유기 WireGuard 클라이언트: LAN 기기들의 트래픽을 VPN 서버로 */
export interface RouterWgClientConfig {
  enabled: boolean;
  privateKey: string;
  /** 서버가 정해 준 내 터널 주소 */
  address?: { ip: Ip; prefix: number };
  /** 서버 주소·포트 (엔드포인트) */
  server?: { ip: Ip; port: number };
  /** 서버를 이름으로 적었으면 그 이름 (DDNS — 연결할 때 풀고, 핸드셰이크가 실패하면 다시 푼다) */
  serverName?: { name: string; port: number };
  serverKey: string;
  /** 터널로 보낼 목적지 (0.0.0.0/0 = 전부) */
  allowedIps: WgPrefix[];
  /** VPN 이 알려 준 DNS: 연결되면 DNS 포워더가 이쪽으로 터널을 통해 묻는다 (DNS 유출 방지) */
  dns?: Ip;
  /** 킬 스위치: VPN 이 끊기면 WAN 으로 바로 내보내지 않는다 (GL.iNet "Block Non-VPN Traffic") */
  killSwitch: boolean;
  /** 난독화 (AmneziaWG 식 — 서버도 켜야 한다) */
  obfuscate?: boolean;
  /** VPN 정책: 모든 기기 / 목록의 기기만 빼고 / 목록의 기기만 */
  policy: { mode: "all" | "exclude" | "only"; devices: Ip[] };
}

export const WG_POLICY_LABEL: Record<RouterWgClientConfig["policy"]["mode"], string> = { all: "모든 기기", exclude: "목록의 기기는 VPN 을 쓰지 않음", only: "목록의 기기만 VPN" };

export interface RouterIpv6Config {
  enabled: boolean;
  /** IPv6 인바운드 기본 차단 (Stateful): 안에서 시작한 통신의 응답만 들어온다. NAT 가 없으니 이것이 IPv4 의 NAT 가 하던 보호를 대신한다 */
  inboundBlock: boolean;
}
