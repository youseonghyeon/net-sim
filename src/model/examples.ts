// 예제 레지스트리. 파일 메뉴의 "예제" 와 테스트가 쓴다.
// 예제 함수는 메뉴 묶음별로 examples/ 에 있다(basic·parts·routing·l2·security·services·internet·wireless, 조립 도우미는 build.ts).
// 새 예제는 알맞은 묶음 파일에 함수를 추가하고 EXAMPLES 에 등록한다 (구성 검사 이슈 0 은 tests/topology.test.ts 가 확인).
import type { Topology } from "./topology";
import { exampleStarterTopology, exampleTopology } from "./examples/basic";
import { examplePartsTopology } from "./examples/parts";
import { exampleTwoGatewaysTopology, exampleBackboneTopology, exampleRipTopology } from "./examples/routing";
import { exampleIgmpTopology, exampleHubTopology, exampleVlanTopology, exampleStpTopology } from "./examples/l2";
import { exampleDropInTopology, exampleFirewallTopology, exampleFirewallApplianceTopology, exampleHaTopology } from "./examples/security";
import { exampleLoadBalancerTopology, exampleProxyTopology, exampleDockerTopology, exampleAdguardTopology } from "./examples/services";
import { exampleInternetTopology, examplePublishTopology, exampleNatTraversalTopology, exampleVpnTopology, exampleNcpVpnTopology, exampleRemoteVpnTopology, exampleIptimeVpnTopology, exampleMultiWanTopology } from "./examples/internet";
import { exampleDdnsTopology, exampleDpiTopology, exampleOpenVpnTopology, exampleTailscaleTopology, exampleWireguardTopology } from "./examples/vpn";
import { exampleRoamingTopology } from "./examples/wireless";
import { exampleCompanyTopology } from "./examples/overview";
import { exampleDualStackHomeTopology, exampleDualStackTopology, exampleIpv6BasicsTopology, exampleSlaacTopology } from "./examples/ipv6";

export * from "./examples/basic";
export * from "./examples/parts";
export * from "./examples/routing";
export * from "./examples/l2";
export * from "./examples/security";
export * from "./examples/services";
export * from "./examples/internet";
export * from "./examples/vpn";
export * from "./examples/wireless";
export * from "./examples/ipv6";
export * from "./examples/overview";

export type ExampleId = "starter" | "router" | "parts" | "backbone" | "rip" | "gateways" | "hub" | "vlan" | "stp" | "igmp" | "firewall" | "fwbox" | "dropin" | "ha" | "publish" | "p2p" | "mwan" | "internet" | "vpn" | "ncp" | "remote" | "iptime" | "wireguard" | "ddns" | "openvpn" | "tailscale" | "dpi" | "lb" | "proxy" | "adguard" | "roaming" | "docker" | "ipv6" | "slaac" | "dualstack" | "home6" | "company";

export interface ExampleSpec {
  id: ExampleId;
  /** 메뉴 묶음 */
  group: string;
  label: string;
  /** 불러온 뒤 무엇을 해 보면 되는지 한 줄 */
  blurb: string;
  build: () => Topology;
}

// 메뉴 순서 = 학습 순서: 기본 → 기능 단위 → 라우팅 → L2 → 보안 → 서비스 → 인터넷 → VPN → 무선 → IPv6 → 종합. 이름은 짧게, 괄호에는 배우는 것만
export const EXAMPLES: Record<ExampleId, ExampleSpec> = {
  starter: {
    id: "starter",
    group: "기본",
    label: "PC 두 대 잇기 (ARP·ping)",
    blurb: "pc-1 에서 pc-2 로 ping 하면 ARP 로 MAC 을 찾은 뒤 ICMP 가 오갑니다.",
    build: exampleStarterTopology,
  },
  router: {
    id: "router",
    group: "기본",
    label: "집 공유기 (DHCP·NAT·Wi-Fi)",
    blurb: "케이블만 꽂으면 DHCP 로 주소를 받고, google.com 으로 ping 하면 DNS → NAT 를 거칩니다.",
    build: exampleTopology,
  },
  parts: {
    id: "parts",
    group: "기능 단위",
    label: "공유기를 부품으로 (NAT·게이트웨이·DHCP/DNS 서버)",
    blurb: "공유기를 상자별로 뜯은 구성. 노트북은 게이트웨이 릴레이로 다른 서브넷의 DHCP 서버에서 주소를 받습니다.",
    build: examplePartsTopology,
  },
  gateways: {
    id: "gateways",
    group: "라우팅",
    label: "게이트웨이 2단 (스태틱 라우팅)",
    blurb: "pc-1 → 192.168.5.10 은 gw-1 이 스태틱 라우팅으로 gw-2 에 바로 넘기고, 인터넷은 NAT 로 올라갑니다. NAT 의 스태틱 라우팅을 지우면 응답이 돌아오지 못합니다.",
    build: exampleTwoGatewaysTopology,
  },
  backbone: {
    id: "backbone",
    group: "라우팅",
    label: "백본 스위치로 세 집 잇기",
    blurb: "게이트웨이 셋의 if0 이 sw-backbone(10.0.0.0/24) 에서 만납니다. 게이트웨이마다 다른 두 집으로 가는 스태틱 라우팅이 있고, 하나를 지우면 그 집만 못 갑니다.",
    build: exampleBackboneTopology,
  },
  rip: {
    id: "rip",
    group: "라우팅",
    label: "동적 라우팅 RIP (끊기면 우회)",
    blurb: "스태틱 라우팅 없이 RIP 로 서로의 LAN 을 배웁니다(게이트웨이 → 표 탭의 라우팅 테이블). pc-a 에서 192.168.3.10 으로 \"경로\" 를 본 뒤 gw-a ↔ gw-c 케이블을 지우면, RIP 가 경로를 철회하고 gw-b 를 거치는 길로 다시 수렴합니다.",
    build: exampleRipTopology,
  },
  hub: {
    id: "hub",
    group: "L2",
    label: "허브 vs 스위치",
    blurb: "pc-1 → pc-2 ping 이 허브의 모든 포트(공유기까지)로 복제되는 것과, pc-3 → pc-4 가 스위치에서 그 포트로만 가는 것을 비교하세요.",
    build: exampleHubTopology,
  },
  vlan: {
    id: "vlan",
    group: "L2",
    label: "VLAN 으로 나눈 사무실 (트렁크)",
    blurb: "같은 스위치인데 VLAN 10 과 20 은 게이트웨이 서브 인터페이스를 거쳐야 통신됩니다.",
    build: exampleVlanTopology,
  },
  stp: {
    id: "stp",
    group: "L2",
    label: "스위치 이중화 (STP)",
    blurb: "스위치 셋을 삼각형으로 이어 경로가 둘입니다. STP 가 access-1 의 한 포트를 막아(점선) 루프를 끊습니다. pc-1 에서 srv-1 로 ping 한 뒤 core-1 ↔ access-1 케이블을 지우면 막혔던 포트가 열려 다른 길로 갑니다.",
    build: exampleStpTopology,
  },
  igmp: {
    id: "igmp",
    group: "L2",
    label: "IPTV 멀티캐스트와 IGMP 스누핑",
    blurb: "거실 TV 의 진단 탭에서 그룹 239.1.1.1 에 가입하고(IGMP Report), IPTV 서버에서 그 그룹으로 송출해 보세요. 스누핑이 없는 거실 스위치는 영상 조각을 안방 PC·노트북 포트까지 뿌립니다(그 기기들의 NIC 가 버릴 뿐). 거실 스위치 설정에서 IGMP 스누핑을 켜고 TV 가 다시 가입한 뒤 송출하면 TV 포트로만 갑니다. TV 가 탈퇴하면 아무 데도 보내지 않습니다.",
    build: exampleIgmpTopology,
  },
  firewall: {
    id: "firewall",
    group: "보안",
    label: "공유기 방화벽 (ping 은 되고 웹은 막힘)",
    blurb: "pc-1 에서 example.com 으로 ping 은 되지만 TCP 80 연결은 공유기 방화벽 규칙 1 에서 차단됩니다. 규칙 2(인바운드 ICMP 차단)는 바깥에서 먼저 시작한 ping 을 막는 규칙이고, 안에서 시작한 ping 의 응답은 Stateful 검사로 통과합니다.",
    build: exampleFirewallTopology,
  },
  fwbox: {
    id: "fwbox",
    group: "보안",
    label: "투명 방화벽 장비 (서버 앞)",
    blurb: "pc-1 → srv-1 ping 은 fw-1 에서 차단되지만 TCP 80 연결은 됩니다. srv-1 → pc-1 ping 은 응답이 Stateful 검사로 돌아오고, srv-1 → pc-1 traceroute 는 1홉 — fw-1 은 IP 가 없어 홉에 안 보입니다.",
    build: exampleFirewallApplianceTopology,
  },
  dropin: {
    id: "dropin",
    group: "보안",
    label: "드롭인 게이트웨이 (기존 공유기 옆에 꽂기)",
    blurb: "기존 공유기는 그대로 두고 Brume 3 의 WAN 만 거실 스위치에 꽂았습니다. 아이 PC 는 게이트웨이를 Brume(192.168.0.2)으로 적어 Brume 을 거쳐 나가고(Brume 의 DPI 가 게임을 막음), 아빠 PC 는 기존 공유기로 바로 나갑니다. 두 PC 에서 roblox.com:443 으로 TCP 연결해 보세요 — 아이 PC 만 RST 로 끊깁니다. Brume 은 WAN 하나로 받고 같은 WAN 으로 내보내며(한 팔 라우터), 응답이 Brume 으로 돌아오게 NAT 합니다.",
    build: exampleDropInTopology,
  },
  ha: {
    id: "ha",
    group: "보안",
    label: "방화벽 이중화 (VRRP)",
    blurb: "pc-1 에서 8.8.8.8 로 ping 하면 master 인 방화벽 A 가 NAT 합니다. 방화벽 A 의 케이블을 지우고(또는 장치를 지우고) 다시 ping 하면 방화벽 B 가 가상 주소를 이어받아 그대로 나갑니다. 케이블을 되돌리면 우선순위가 높은 A 가 다시 가져갑니다. pc-1 에서 93.184.216.34 로 SSH(22) 세션을 열어 둔 채 A 를 지우고 '연결 해제' 하면 끊기지만, 두 방화벽의 이중화 설정에서 세션 동기화를 켜면 이어집니다.",
    build: exampleHaTopology,
  },
  lb: {
    id: "lb",
    group: "서비스",
    label: "로드밸런서 (서버 토글 vs 전용 장비)",
    blurb: "pc-1 에서 192.168.0.10(nginx 서버) 이나 192.168.0.20(lb-1) 으로 TCP 연결을 여러 번 보내 보세요. 진단 목록의 \"응답\" 이 web-1 → web-2 로 바뀝니다. web-2 의 웹 서버를 끄면 그 차례 요청은 거부되고 곧바로 다른 서버로 넘어가며 10초 동안 빠집니다. 인터넷 노드의 외부 접속으로 공인 주소:80 에 들어오면 포트 포워딩 → lb-1 → 웹 서버로 갑니다. lb-1 설정에서 방식을 L4 주소 변환으로 바꾸면 연결이 하나로 이어지고(LB 는 주소만 바꿈), 세션 고정을 켜면 같은 PC 는 늘 같은 서버로 갑니다.",
    build: exampleLoadBalancerTopology,
  },
  proxy: {
    id: "proxy",
    group: "서비스",
    label: "포워드 프록시 (프록시로만 나가는 사무실)",
    blurb: "공유기 방화벽은 proxy-1 만 인터넷으로 내보냅니다. pc-1 에서 example.com 으로 TCP 연결(80)을 보내면 프록시 설정(http_proxy)에 따라 proxy-1 에게 부탁하고, proxy-1 이 이름을 찾아 대신 받아 옵니다. 같은 요청을 laptop-1 에서 보내면 설정이 없어 직접 나가다 방화벽에 막혀 timeout 입니다. pc-1 에서 8.8.8.8 로 ping 해 보세요 — 프록시는 웹만 대신하므로 막힙니다. naver.com 은 proxy-1 의 차단 목록에 있어 403 을 받습니다. 포트를 443 으로 바꿔 github.com 에 HTTPS 연결을 보내면 CONNECT 로 터널만 열고 TLS 는 github.com 과 직접 합니다 — proxy-1 의 기록에는 이름(CONNECT github.com:443)만 남고 요청·응답 내용은 없습니다. proxy-1 의 표 탭에서 요청 기록(access.log)을 봅니다.",
    build: exampleProxyTopology,
  },
  adguard: {
    id: "adguard",
    group: "서비스",
    label: "광고 차단·자녀 보호 (AdGuard Home)",
    blurb: "집 Brume 3 의 AdGuard Home 이 DNS 포워더 앞에서 이름을 거릅니다. 아빠 PC 에서 doubleclick.net 으로 ping 하면 0.0.0.0 답을 받아 접속하지 않습니다(표 탭의 AdGuard 쿼리 로그). 아이 태블릿은 자녀 보호로 instagram.com·roblox.com 이 막히고 youtube.com 은 됩니다. 스마트 TV 는 DNS 를 8.8.8.8 로 직접 적었지만 \"DNS 가로채기\" 가 켜져 있어 공유기가 그 질의를 대신 받아 막습니다(TV 는 8.8.8.8 이 답한 줄 압니다). 공유기 설정 → 앱 → AdGuard Home 에서 DNS 가로채기를 끄면 TV 의 doubleclick.net 이 그대로 되고, 구성 검사가 TV 를 짚습니다.",
    build: exampleAdguardTopology,
  },
  docker: {
    id: "docker",
    group: "서비스",
    label: "도커 네트워크 (브리지·내장 DNS·포트 공개)",
    blurb: "맥에서 Docker Desktop 을 쓸 때의 구조입니다. 컨테이너는 맥 안의 Linux VM(Docker VM)에 있고 맥(macOS)과는 가상 링크(vmnet)로 이어집니다. 맥 터미널에서 127.0.0.1:8080(localhost)으로 TCP 연결을 보내면 macOS 의 포트 공개 → Docker VM 의 포트 공개(docker -p 8080:80) → web 으로 가고, web 은 브리지 게이트웨이(172.18.0.1)가 연 연결로 봅니다. 맥 터미널에서 172.18.0.2 로 ping 하면 실패합니다 — 컨테이너 대역은 VM 안에 있어 맥에는 경로가 없습니다(리눅스에서 도커를 바로 돌리면 됩니다). 집 PC 에서 맥 주소:8080 은 되지만 :5432 는 맥의 127.0.0.1 에만 공개돼 막힙니다. 사용자 정의 브리지(br-app)의 web 은 db 를 이름으로 찾지만(내장 DNS), 기본 브리지(docker0)의 old-app 은 이름으로 못 찾고 다른 브리지로는 아예 못 갑니다(DOCKER-ISOLATION). 컨테이너의 인터넷은 VM → 맥 → 공유기 NAT 를 차례로 거칩니다.",
    build: exampleDockerTopology,
  },
  internet: {
    id: "internet",
    group: "인터넷",
    label: "인터넷의 뼈대 (가장자리 트리 · 중심 그물)",
    blurb: "pc-1 에서 nexus.com 으로 \"경로\" 와 TCP 연결을 보내 보세요. 집 공유기 → KT 국사 → KT 백본 → SK 백본 → SK 국사 → 회사 NAT. 가장자리는 디폴트 라우트로 위로만 올라가고(트리), 백본 셋은 RIP 로 경로를 주고받습니다(그물, 실제로는 BGP). KT 백본 ↔ SK 백본 케이블을 지우면 구글 망을 돌아가는 길로 다시 수렴합니다.",
    build: exampleInternetTopology,
  },
  publish: {
    id: "publish",
    group: "인터넷",
    label: "도메인으로 회사 웹 서버 접속 (DNS·NAT·포트 포워딩)",
    blurb: "맥북에서 nexus.com:80 으로 TCP 연결을 보내 보세요. 공인 DNS 8.8.8.8(ISP 라우터 너머)이 회사 공인 주소를 알려 주고, 집 NAT(출발지 변환) → 회사 NAT 포트 포워딩(목적지 변환) → 방화벽(웹 서버 80 만 허용) → 웹 서버로 갑니다. srv-1(192.168.1.3)은 사설 주소라 밖에서 직접 닿지 않습니다.",
    build: examplePublishTopology,
  },
  p2p: {
    id: "p2p",
    group: "인터넷",
    label: "NAT 종류와 홀 펀칭 (P2P·STUN·TURN·헤어핀)",
    blurb: "민수 PC 의 진단 탭에서 hyunwoo 에게 P2P 연결을 보내 보세요. 두 PC 가 STUN 으로 자기 공인 주소:포트를 알아내고 시그널링 서버로 후보를 주고받은 뒤, 서로에게 동시에 보내(홀 펀칭) 두 공유기의 port-restricted NAT 를 뚫고 직접 연결됩니다. jiyoung 에게 보내면 통신사 CGNAT 가 symmetric(상대마다 바깥 포트가 바뀜)이라 홀 펀칭이 실패하고 TURN 릴레이로 이어집니다. 집 A 공유기의 NAT 종류를 full cone 으로 바꾸면 jiyoung 과도 직접 연결됩니다. 민수 PC 에서 집 A 공유기의 WAN 주소:8080 으로 TCP 연결하면 헤어핀 NAT 가 꺼져 있어 드롭되고, 공유기 설정에서 헤어핀 NAT 를 켜면 집 NAS 로 되돌아갑니다.",
    build: exampleNatTraversalTopology,
  },
  mwan: {
    id: "mwan",
    group: "인터넷",
    label: "멀티 WAN 페일오버 (유선 + 휴대폰 핫스팟)",
    blurb: "사무실 Brume 3 은 lan4 를 WAN2 로 바꿔 휴대폰 핫스팟을 예비 회선으로 꽂았습니다(표 탭의 멀티 WAN). 사무실 PC 에서 8.8.8.8 로 ping 하면 유선(WAN1)으로 나갑니다. Brume 3 ↔ 통신사 구간 케이블의 손실을 100% 로 바꾸고(링크는 살아 있는데 인터넷이 안 되는 장애) \"+10초\" 를 두어 번 누르면, 5초마다 보내던 추적 ping 이 3번 실패한 뒤 WAN2 로 넘어갑니다. 다시 ping 하면 핫스팟을 거쳐 다른 공인 주소로 나갑니다. 손실을 0% 로 되돌리면 추적 ping 이 2번 답한 뒤 WAN1 으로 돌아옵니다. 케이블을 지우면 기다리지 않고 바로 넘어갑니다.",
    build: exampleMultiWanTopology,
  },
  vpn: {
    id: "vpn",
    group: "VPN",
    label: "VPN 으로 두 사무실 잇기 (터널·캡슐화)",
    blurb: "pc-a 에서 192.168.2.10 으로 ping 하면 사설 주소끼리 바로 닿습니다. 통신사 구간을 지나는 패킷을 눌러 보면 바깥은 공인 주소끼리의 UDP 51820 뿐이고, 원래 패킷은 \"터널 안\" 에 암호화돼 있습니다. NAT 박스 한쪽의 VPN 을 끄면 사설 주소는 인터넷으로 나갈 수 없어 실패합니다.",
    build: exampleVpnTopology,
  },
  ncp: {
    id: "ncp",
    group: "VPN",
    label: "망분리 사무실 + NCP (IPsec VPN)",
    blurb: "내부망 PC 1 에서 dev-2(192.168.112.11)로 TCP 22 연결하면, 첫 패킷에 IKE 로 IPsec 터널을 맺은 뒤 ESP 로 NCP 서버에 닿습니다. 외부망 PC 에서는 닿지 않습니다. prod 는 172.21.4.11 입니다.",
    build: exampleNcpVpnTopology,
  },
  remote: {
    id: "remote",
    group: "VPN",
    label: "재택근무 원격 접속 VPN",
    blurb: "재택 노트북이 켜지면서 회사 VPN 방화벽에 IPsec 으로 붙어 PSK 와 사용자 계정(kim, EAP)을 확인받고 가상 주소 10.99.0.x 를 받습니다(표 탭). 노트북에서 사내 서버 10.50.10.20 으로 SSH(22) 접속해 보세요 — 사내 대역만 터널로 가고, 8.8.8.8 은 평소처럼 집 공유기로 나갑니다.",
    build: exampleRemoteVpnTopology,
  },
  iptime: {
    id: "iptime",
    group: "VPN",
    label: "ipTIME 공유기 VPN (L2TP/IPsec)",
    blurb: "출장 노트북이 켜지면서 집 ipTIME 의 VPN 서버에 붙습니다: IPsec(사전 공유 키)으로 바깥 통로를 암호화하고(호텔 NAT 뒤라 UDP 4500), 그 안에서 L2TP·PPP 로 계정(me)을 확인받아 집 LAN 주소 192.168.0.50 을 받습니다. 노트북에서 집 NAS 192.168.0.20 으로 TCP 80 을 보내 보세요 — 공유기가 그 주소의 ARP 에 대신 답해 NAS 는 LAN 기기로 봅니다. 8.8.8.8 로 ping 하면 재택근무 예제(사내 대역만 터널)와 달리 모든 트래픽이 집을 거쳐 집 공인 주소로 나갑니다(해외에서도 한국 IP).",
    build: exampleIptimeVpnTopology,
  },
  wireguard: {
    id: "wireguard",
    group: "VPN",
    label: "GL.iNet 식 VPN 게이트웨이 (WireGuard·킬 스위치)",
    blurb: "집 Brume 3 은 WireGuard 서버, 호텔 뒤 여행용 공유기는 WireGuard 클라이언트입니다. 여행 노트북은 아무 설정 없이 모든 트래픽이 집을 거칩니다 — 여행용 공유기에 \"VPN 연결됨\" 이 뜨면(첫 핸드셰이크는 호텔 공유기가 아직 인터넷에 붙기 전이라 사라지고 5초 뒤 다시 시도) 노트북에서 집 NAS 192.168.8.20 으로 TCP 80, 8.8.8.8 로 ping 해 보세요(집 공인 주소로 나감). 출장 폰은 WireGuard 앱으로 집 대역만 터널로 보냅니다(split tunnel). 집 Brume 3 의 피어에서 폰의 공개 키를 한 글자 바꾸면 핸드셰이크에 아무 답도 없이 timeout 이 납니다 — WireGuard 는 모르는 키에 답하지 않습니다. 집 Brume 3 의 WireGuard 서버를 끄면 여행용 공유기의 킬 스위치가 노트북의 인터넷을 막습니다(끄면 호텔로 바로 새어 나감).",
    build: exampleWireguardTopology,
  },
  ddns: {
    id: "ddns",
    group: "VPN",
    label: "주소가 바뀌는 집 (DDNS·WireGuard)",
    blurb: "집 Brume 3 의 WAN 은 자동(DHCP)이라 공인 주소가 바뀔 수 있습니다. 공유기가 DDNS 로 myhome.glddns.com 을 지금 주소로 갱신하고, 카페 폰의 WireGuard 앱은 서버를 이름으로 적어 둡니다. 폰에서 집 NAS 192.168.8.20 으로 ping 한 뒤, internet-1 의 진단 탭에서 \"공인 주소 바꾸기\" 로 집 주소를 바꿔 보세요 — 공유기가 새 주소를 받아 DDNS 를 갱신합니다. 폰은 옛 주소로 보낸 것에 답이 없으니 \"+10초\" 를 몇 번 눌러 시간을 흘리면 새 핸드셰이크가 실패한 뒤 이름을 다시 풀어 새 주소로 붙습니다.",
    build: exampleDdnsTopology,
  },
  openvpn: {
    id: "openvpn",
    group: "VPN",
    label: "OpenVPN (인증서·tls-crypt·TCP 443)",
    blurb: "집 Brume 3 은 OpenVPN 서버를 TCP 443 으로 엽니다. 카페 공유기의 방화벽은 웹(TCP 80·443)만 내보내 보통의 UDP 1194 는 막히기 때문입니다. 카페 노트북은 서버 인증서가 설정 파일의 CA 가 발급한 것인지 확인하고, 서버도 노트북 인증서를 확인한 뒤 가상 주소 10.8.0.2·집 LAN 경로·DNS 를 내려 줍니다(PUSH). 노트북에서 집 NAS 192.168.8.20 으로 TCP 80 을 보내 보세요. 서버와 노트북의 전송을 UDP 1194 로 바꾸면 카페 방화벽에서 막힙니다. 집 Brume 3 에서 노트북 인증서를 폐기하면(CRL) 다시 붙지 못하고, 노트북의 tls-crypt 키를 한 글자 바꾸면 서버는 아무 답도 하지 않습니다.",
    build: exampleOpenVpnTopology,
  },
  tailscale: {
    id: "tailscale",
    group: "VPN",
    label: "Tailscale (메시 VPN·홀 펀칭·DERP·서브넷 라우터)",
    blurb: "세 곳의 기기가 tailnet \"family\" 에 로그인해 100.64.x.y 주소를 받고, 조정 서버가 서로의 후보 주소를 나눠 줍니다(netmap). 카페 노트북에서 work-pc 로 ping 해 보세요 — 이름은 MagicDNS 가 풀고, 카페(port-restricted)와 회사(symmetric) NAT 사이는 홀 펀칭이 안 돼 DERP 릴레이를 거칩니다. home-brume 으로는 홀 펀칭이 성공해 직접 갑니다(표 탭의 경로). 집 Brume 3 은 서브넷 라우터라 노트북에서 집 NAS 192.168.8.20 에도 닿고, 노트북의 exit node 를 home-brume 으로 하면 인터넷도 집을 거칩니다.",
    build: exampleTailscaleTopology,
  },
  dpi: {
    id: "dpi",
    group: "VPN",
    label: "DPI 와 VPN 난독화 (앱 알아보기·차단)",
    blurb: "회사 공유기의 DPI 가 흐름마다 앱을 알아보고(TLS SNI·DNS 로 배운 주소·프로토콜 모양) VPN·게임을 막습니다(표 탭의 DPI 앱별 트래픽). 직원 노트북의 WireGuard 는 첫 패킷의 모양으로 들켜 막힙니다 — 노트북의 VPN 과 집 Brume 3 의 WireGuard 서버 양쪽에서 \"난독화\" 를 켜고 노트북에서 \"다시 연결\" 하면 알아볼 수 없는 UDP 가 되어 지나갑니다(한쪽만 켜면 서로 못 알아봐 침묵합니다). 직원 PC 에서 roblox.com:443 으로 TCP 연결하면 SNI 로 게임이라 RST 로 끊기고, youtube.com:443 은 됩니다.",
    build: exampleDpiTopology,
  },
  roaming: {
    id: "roaming",
    group: "무선",
    label: "무선 로밍·노트북 유선/Wi-Fi 전환",
    blurb: "phone-1 을 오른쪽 AP 쪽으로 끌면 가까운 AP 로 갈아탑니다. 주소는 새로 받지 않고, 쓰던 주소를 DHCP Request 로 확인만 하고 그대로 씁니다(INIT-REBOOT). laptop-1 은 케이블과 Wi-Fi 가 둘 다 있어 유선을 쓰고 Wi-Fi 는 대기(회색 점선)입니다. 케이블을 지우면 Wi-Fi 로 넘어가는데, 무선 NIC 는 MAC 이 달라 공유기가 다른 기기로 보고 다른 주소를 줍니다. 케이블을 되돌리면 유선이 쓰던 주소를 되찾습니다.",
    build: exampleRoamingTopology,
  },
  ipv6: {
    id: "ipv6",
    group: "IPv6",
    label: "IPv6 기초 (링크 로컬·NDP·라우팅)",
    blurb: "IPv4 없이 IPv6 만 씁니다. pc-1 에서 2001:db8:1::11(pc-2) 로 ping 하면 ARP 대신 NDP — NS 가 solicited-node 멀티캐스트로 가고 NA 가 유니캐스트로 돌아옵니다. 2001:db8:2::10(srv-1) 으로 \"경로\" 를 보면 gw-1 이 NAT 없이 Hop Limit 만 줄여 넘기고, TCP 80 으로 연결도 됩니다. pc-2 의 기본 게이트웨이는 gw-1 의 링크 로컬(fe80::) 주소입니다. srv-1 의 링크 로컬(fe80::ff:fe00:6)로 ping 하면 라우터를 넘지 못해 실패합니다.",
    build: exampleIpv6BasicsTopology,
  },
  slaac: {
    id: "slaac",
    group: "IPv6",
    label: "IPv6 자동 주소 (SLAAC·RA)",
    blurb: "pc-1·노트북은 IPv6 가 자동(SLAAC)입니다. 링크가 올라가면 RS 를 보내고, gw-1 의 RA 가 알린 2001:db8:1::/64 에 MAC 에서 만든 인터페이스 ID 를 붙여 주소를 스스로 만듭니다 — DHCP 서버가 없습니다. 기본 게이트웨이는 RA 를 보낸 gw-1 의 링크 로컬 주소입니다(표 탭). pc-1 에서 2001:db8:2::10(srv-1)로 ping·TCP 80 을 보내 보세요. gw-1 의 if1 RA 광고를 끄면 거둠 RA(라우터 수명 0)로 주소와 게이트웨이가 사라집니다.",
    build: exampleSlaacTopology,
  },
  dualstack: {
    id: "dualstack",
    group: "IPv6",
    label: "듀얼 스택 사무실 (A·AAAA·Happy Eyeballs)",
    blurb: "pc-1 에서 web.corp 로 TCP 80 연결을 보내 보세요. IPv6 주소가 있어 AAAA 부터 묻고(IPv4 DNS 서버에 — 질의 종류와 운반 버전은 따로) [2001:db8:2::10]:80 으로 붙습니다. old.corp 는 AAAA 가 없어(NODATA) A 로 다시 물어 IPv4 로 갑니다. 노트북은 IPv4 없이 RA 가 알린 DNS(RDNSS)에 IPv6 로 묻습니다. gw-1 의 방화벽을 켜면(IPv6 웹 차단 규칙) web.corp 연결이 IPv6 로 먼저 시도했다가 timeout 뒤 IPv4 로 다시 붙습니다(Happy Eyeballs 축소판).",
    build: exampleDualStackTopology,
  },
  home6: {
    id: "home6",
    group: "IPv6",
    label: "듀얼 스택 집 (NAT 없는 IPv6·프리픽스 위임)",
    blurb: "공유기는 ISP 에게 DHCPv6-PD 로 /56 을 위임받아 LAN 에 첫 /64 를 RA 로 알립니다(공유기 → 표 탭). pc-1 에서 google.com 으로 ping 하면 AAAA 로 IPv6 주소를 받아 NAT 없이 나갑니다 — 공유기를 지나는 패킷을 눌러 출발지가 pc-1 의 주소 그대로인지 보세요(IPv4 는 WAN 주소로 바뀝니다). github.com 은 IPv6 가 없어(NODATA) IPv4·NAT 로 갑니다. 인터넷 노드의 '외부에서 접속' 으로 srv-1 의 IPv6 주소:80 에 접속하면 공유기의 IPv6 인바운드 기본 차단에 막히고, 끄면 포트 포워딩 없이 바로 들어옵니다 — IPv6 에서는 NAT 가 아니라 방화벽이 지킵니다.",
    build: exampleDualStackHomeTopology,
  },
  company: {
    id: "company",
    group: "종합",
    label: "중소기업 전체 (본사·지사·재택·고객)",
    blurb: "앞의 예제들이 한 그림에 모입니다. 지사 PC-1 에서 intranet.corp 로 TCP 80 을 보내면 사내 DNS 에 물어(지사 → 본사 IPsec 터널) 사내 위키에 닿습니다. 재택 노트북은 켜지면서 원격 접속 VPN(계정 kim)으로 붙어 있어 10.1.20.20 으로 SSH(22) 가 됩니다. 사무 PC 는 VLAN 10 에서 코어 게이트웨이의 DHCP 릴레이로 주소를 받고 www.corp 로 연결하면 웹 LB 가 web-1·web-2 로 나눕니다. 카페의 고객 폰에서 회사 공인 주소 203.0.113.10:80 으로 연결하면 본사 방화벽의 포트 포워딩 → 웹 LB 로 들어옵니다. 손님 폰(VLAN 30 손님 Wi-Fi)은 8.8.8.8 은 되지만 사내 위키(10.1.20.20)는 코어 방화벽에 막힙니다.",
    build: exampleCompanyTopology,
  },
};

export const EXAMPLE_LIST: ExampleSpec[] = Object.values(EXAMPLES);
