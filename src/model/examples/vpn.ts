// 예제 묶음 "VPN" 중 GL.iNet(Brume 3) 식 공유기 VPN. 다른 VPN 예제는 internet.ts. 등록(메뉴 순서·설명)은 ../examples.ts 의 EXAMPLES.
import { type Cable, DEFAULT_DHCP_SERVER, DEFAULT_OVPN_SERVER_SETTINGS, type Topology, newId, ovpnCaOfDevice, ovpnTlsCryptOfDevice, wgPublicKeyOf, zoneAround } from "../topology";
import { builder, cable } from "./build";

/**
 * GL.iNet 식 VPN 게이트웨이 (WireGuard):
 * - 집 Brume 3 = WireGuard 서버 (WAN 수동 공인 주소 203.0.113.30, 터널 10.0.0.1/24). 피어 = 여행용 공유기(10.0.0.2)·출장 폰(10.0.0.3)의 공개 키
 * - 출장지 호텔 공유기 뒤의 여행용 공유기 = WireGuard 클라이언트: 뒤에 꽂은 노트북은 아무 설정 없이 모든 트래픽이 집을 거친다 (full tunnel, 킬 스위치)
 * - 출장 폰 = WireGuard 앱으로 호텔 Wi-Fi 에서 직접. AllowedIPs 를 집 대역만 적어 split tunnel (인터넷은 호텔로 바로)
 * 공개 키는 장치마다 정해진 키라 예제를 만들 때 서로의 공개 키를 적어 둔다 (실제로는 GL.iNet 관리 화면이 설정 파일·QR 을 만든다)
 */
export function exampleWireguardTopology(): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 344, -296, "internet-1");
  const isp = add("switch", 344, -168, "통신사 구간");
  const hotel = add("router", 120, -24, "호텔 공유기");
  hotel.router = { ...hotel.router!, lanIp: "10.10.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "10.10.0.100", end: "10.10.0.199" }, wifi: { enabled: true, ssid: "hotel" } };
  const travel = add("router", 120, 152, "여행용 공유기");
  const laptop = add("laptop", 120, 328, "여행 노트북");
  const phone = add("phone", -80, 96, "출장 폰");
  const home = add("router", 568, -24, "집 Brume 3");
  const nas = add("server", 568, 152, "집 NAS");
  // 집: GL.iNet 기본 LAN 192.168.8.0/24, WireGuard 서버
  home.router = {
    ...home.router!,
    lanIp: "192.168.8.1",
    lanPrefix: 24,
    dhcp: { enabled: true, start: "192.168.8.100", end: "192.168.8.199" },
    wan: { ipMode: "static", ip: "203.0.113.30", prefix: 24, gateway: "203.0.113.1" },
    wgServer: {
      enabled: true,
      address: "10.0.0.1/24",
      port: 51820,
      peers: [
        { name: "여행용 공유기", publicKey: wgPublicKeyOf(travel, "client"), ip: "10.0.0.2" },
        { name: "출장 폰", publicKey: wgPublicKeyOf(phone, "host"), ip: "10.0.0.3" },
      ],
      lanAccess: true,
    },
  };
  nas.host = { ipMode: "static", ip: "192.168.8.20", prefix: 24, gateway: "192.168.8.1", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const serverKey = wgPublicKeyOf(home, "server");
  // 여행용 공유기: WAN 은 호텔 LAN 에서 DHCP, 자기 LAN 192.168.9.0/24. 모든 LAN 트래픽을 집으로 (킬 스위치 켬, DNS 는 집 공유기의 터널 주소)
  travel.router = {
    ...travel.router!,
    lanIp: "192.168.9.1",
    lanPrefix: 24,
    dhcp: { enabled: true, start: "192.168.9.100", end: "192.168.9.199" },
    wgClient: { enabled: true, server: "203.0.113.30", port: 51820, serverKey, address: "10.0.0.2/32", allowedIps: "0.0.0.0/0", dns: "10.0.0.1", killSwitch: true, policy: { mode: "all", devices: [] } },
  };
  // 폰: 호텔 Wi-Fi + WireGuard 앱 (집 대역만 터널로)
  phone.wifi = { ssid: "hotel" };
  phone.host = {
    ...phone.host!,
    ra: { enabled: true, type: "wireguard", server: "203.0.113.30", psk: "", wg: { address: "10.0.0.3/32", port: 51820, serverKey, allowedIps: "10.0.0.0/24, 192.168.8.0/24", dns: "" } },
  };
  const cables: Cable[] = [cable(isp, 3, inet, 0), cable(isp, 1, hotel, 0), cable(isp, 6, home, 0), cable(hotel, 1, travel, 0), cable(travel, 1, laptop, 0), cable(home, 1, nas, 0)];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "출장지 호텔 10.10.0.0/24", tint: "green", ...zoneAround(t, [hotel.id, travel.id, laptop.id, phone.id], 56)! },
    { id: newId("zone"), label: "집 192.168.8.0/24 · WireGuard 10.0.0.0/24", tint: "blue", ...zoneAround(t, [home.id, nas.id], 56)! },
  ];
  return t;
}

/**
 * 주소가 바뀌는 집 (DDNS·WireGuard):
 * - 집 Brume 3 의 WAN 은 자동(DHCP) — 가정용 회선은 공인 주소가 바뀐다. DDNS 로 myhome.glddns.com 을 지금 주소로 갱신한다
 * - 카페 폰의 WireGuard 앱은 서버를 주소가 아니라 이름(myhome.glddns.com)으로 적는다
 * - 인터넷 노드의 진단 탭 "공인 주소 바꾸기" 로 ISP 가 집 주소를 바꾸면(FORCERENEW) 공유기가 새 주소를 받아 DDNS 를 갱신하고,
 *   폰은 옛 주소로 보낸 것에 답이 없어 새 핸드셰이크 → 실패 → 이름을 다시 풀어 새 주소로 잇는다
 */
export function exampleDdnsTopology(): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 344, -296, "internet-1");
  const isp = add("switch", 344, -168, "통신사 구간");
  const cafe = add("router", 120, -24, "카페 공유기");
  // 카페 공유기는 가정·매장용에 흔한 port-restricted NAT: 집 서버가 새 주소에서 먼저 다시 잇는 것은 막혀(폰이 보낸 적 없는 주소) 폰이 이름을 다시 풀어야 한다
  cafe.router = { ...cafe.router!, lanIp: "10.20.0.1", lanPrefix: 24, dhcp: { enabled: true, start: "10.20.0.100", end: "10.20.0.199" }, wifi: { enabled: true, ssid: "cafe" }, natType: "port-restricted" };
  const phone = add("phone", 40, 152, "카페 폰");
  const home = add("router", 568, -24, "집 Brume 3");
  const nas = add("server", 568, 152, "집 NAS");
  home.router = {
    ...home.router!,
    lanIp: "192.168.8.1",
    lanPrefix: 24,
    dhcp: { enabled: true, start: "192.168.8.100", end: "192.168.8.199" },
    ddns: { enabled: true, name: "myhome" },
    wgServer: { enabled: true, address: "10.0.0.1/24", port: 51820, peers: [{ name: "카페 폰", publicKey: wgPublicKeyOf(phone, "host"), ip: "10.0.0.2" }], lanAccess: true },
  };
  nas.host = { ipMode: "static", ip: "192.168.8.20", prefix: 24, gateway: "192.168.8.1", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  phone.wifi = { ssid: "cafe" };
  phone.host = {
    ...phone.host!,
    ra: { enabled: true, type: "wireguard", server: "myhome.glddns.com", psk: "", wg: { address: "10.0.0.2/32", port: 51820, serverKey: wgPublicKeyOf(home, "server"), allowedIps: "10.0.0.0/24, 192.168.8.0/24", dns: "" } },
  };
  const cables: Cable[] = [cable(isp, 3, inet, 0), cable(isp, 1, cafe, 0), cable(isp, 6, home, 0), cable(home, 1, nas, 0)];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "카페 10.20.0.0/24", tint: "green", ...zoneAround(t, [cafe.id, phone.id], 56)! },
    { id: newId("zone"), label: "집 · WAN 자동 · myhome.glddns.com", tint: "blue", ...zoneAround(t, [home.id, nas.id], 56)! },
  ];
  return t;
}

/**
 * DPI 와 VPN 난독화:
 * - 회사 공유기의 DPI 가 지나가는 흐름의 앱을 알아보고 VPN·게임 카테고리를 막는다 (TLS SNI·DNS 로 배운 주소·프로토콜 모양)
 * - 직원 노트북의 WireGuard 는 첫 패킷(148바이트 Initiation)의 모양으로 들켜 막힌다 → 노트북과 집 Brume 3 양쪽에서 난독화를 켜면
 *   모양을 알아볼 수 없는 UDP 가 되어 지나간다 (한쪽만 켜면 서로 못 알아봐 침묵 — 구성 검사가 짚음)
 * - 직원 PC 의 roblox.com(HTTPS)은 SNI 로 게임이라 RST 로 끊기고, youtube.com 은 된다
 */
export function exampleDpiTopology(): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 344, -296, "internet-1");
  const isp = add("switch", 344, -168, "통신사 구간");
  const office = add("router", 120, -24, "회사 공유기");
  office.router = {
    ...office.router!,
    lanIp: "10.30.0.1",
    lanPrefix: 24,
    dhcp: { enabled: true, start: "10.30.0.100", end: "10.30.0.199" },
    dpi: { enabled: true, blockApps: [], blockCategories: ["VPN", "게임"] },
  };
  const sw = add("switch", 120, 136, "사무실 스위치");
  const laptop = add("laptop", 8, 288, "직원 노트북");
  const pc = add("pc", 232, 288, "직원 PC");
  const home = add("router", 568, -24, "집 Brume 3");
  const nas = add("server", 568, 152, "집 NAS");
  home.router = {
    ...home.router!,
    lanIp: "192.168.8.1",
    lanPrefix: 24,
    dhcp: { enabled: true, start: "192.168.8.100", end: "192.168.8.199" },
    wan: { ipMode: "static", ip: "203.0.113.30", prefix: 24, gateway: "203.0.113.1" },
    wgServer: { enabled: true, address: "10.0.0.1/24", port: 51820, peers: [{ name: "직원 노트북", publicKey: wgPublicKeyOf(laptop, "host"), ip: "10.0.0.2" }], lanAccess: true },
  };
  nas.host = { ipMode: "static", ip: "192.168.8.20", prefix: 24, gateway: "192.168.8.1", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  laptop.host = {
    ...laptop.host!,
    ra: { enabled: true, type: "wireguard", server: "203.0.113.30", psk: "", wg: { address: "10.0.0.2/32", port: 51820, serverKey: wgPublicKeyOf(home, "server"), allowedIps: "10.0.0.0/24, 192.168.8.0/24", dns: "" } },
  };
  const cables: Cable[] = [cable(isp, 3, inet, 0), cable(isp, 1, office, 0), cable(isp, 6, home, 0), cable(office, 1, sw, 0), cable(sw, 1, laptop, 0), cable(sw, 2, pc, 0), cable(home, 1, nas, 0)];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "회사 10.30.0.0/24 · DPI (VPN·게임 차단)", tint: "gray", ...zoneAround(t, [office.id, sw.id, laptop.id, pc.id], 56)! },
    { id: newId("zone"), label: "집 192.168.8.0/24 · WireGuard", tint: "blue", ...zoneAround(t, [home.id, nas.id], 56)! },
  ];
  return t;
}

/**
 * OpenVPN (인증서·tls-crypt·TCP 443):
 * - 집 Brume 3 은 OpenVPN 서버를 TCP 443 으로 연다 — 카페 공유기의 방화벽이 웹(TCP 80·443)만 내보내기 때문
 * - 카페 노트북의 OpenVPN 앱은 공유기에서 내보낸 설정 파일(CA 지문·내 인증서·tls-crypt 키)을 가진다
 * - 연결되면 서버가 가상 주소(10.8.0.x)·집 LAN 경로·DNS 를 PUSH 로 내려 준다
 */
export function exampleOpenVpnTopology(): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 344, -296, "internet-1");
  const isp = add("switch", 344, -168, "통신사 구간");
  const cafe = add("router", 120, -24, "카페 공유기");
  // 카페: 손님에게 웹만 허용 (나가는 TCP 80·443 만, 나머지는 드롭 — 응답은 Stateful 검사로)
  cafe.router = {
    ...cafe.router!,
    lanIp: "10.20.0.1",
    lanPrefix: 24,
    dhcp: { enabled: true, start: "10.20.0.100", end: "10.20.0.199" },
    firewall: {
      enabled: true,
      defaultPolicy: "deny",
      stateful: true,
      rules: [
        { action: "allow", proto: "tcp", direction: "out", src: "", dst: "", dstPort: "80" },
        { action: "allow", proto: "tcp", direction: "out", src: "", dst: "", dstPort: "443" },
      ],
    },
  };
  const laptop = add("laptop", 120, 152, "카페 노트북");
  const home = add("router", 568, -24, "집 Brume 3");
  const nas = add("server", 568, 152, "집 NAS");
  home.router = {
    ...home.router!,
    lanIp: "192.168.8.1",
    lanPrefix: 24,
    dhcp: { enabled: true, start: "192.168.8.100", end: "192.168.8.199" },
    wan: { ipMode: "static", ip: "203.0.113.40", prefix: 24, gateway: "203.0.113.1" },
    ovpnServer: { ...DEFAULT_OVPN_SERVER_SETTINGS, proto: "tcp", port: 443 },
  };
  nas.host = { ipMode: "static", ip: "192.168.8.20", prefix: 24, gateway: "192.168.8.1", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const ca = ovpnCaOfDevice(home);
  laptop.host = {
    ...laptop.host!,
    ra: { enabled: true, type: "openvpn", server: "203.0.113.40", psk: "", ovpn: { proto: "tcp", port: 443, ca, cn: "카페 노트북", certCa: ca, tlsCrypt: ovpnTlsCryptOfDevice(home) } },
  };
  const cables: Cable[] = [cable(isp, 3, inet, 0), cable(isp, 1, cafe, 0), cable(isp, 6, home, 0), cable(cafe, 1, laptop, 0), cable(home, 1, nas, 0)];
  const t: Topology = { devices, cables };
  t.zones = [
    { id: newId("zone"), label: "카페 10.20.0.0/24 · 웹만 허용", tint: "green", ...zoneAround(t, [cafe.id, laptop.id], 56)! },
    { id: newId("zone"), label: "집 192.168.8.0/24 · OpenVPN 10.8.0.0/24", tint: "blue", ...zoneAround(t, [home.id, nas.id], 56)! },
  ];
  return t;
}
