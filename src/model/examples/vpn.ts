// 예제 묶음 "VPN" 중 GL.iNet(Brume 3) 식 공유기 VPN. 다른 VPN 예제는 internet.ts. 등록(메뉴 순서·설명)은 ../examples.ts 의 EXAMPLES.
import { type Cable, DEFAULT_DHCP_SERVER, type Topology, newId, wgPublicKeyOf, zoneAround } from "../topology";
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
