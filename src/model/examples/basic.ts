// 예제 묶음 "기본". 등록(메뉴 순서·설명)은 ../examples.ts 의 EXAMPLES.
import { type Cable, DEFAULT_DHCP_SERVER, type Topology } from "../topology";
import { builder, cable } from "./build";

/** 가장 단순한 예제: PC 2대 + 스위치, 수동 IP. ARP 와 ping 만 본다 */
export function exampleStarterTopology(): Topology {
  const { devices, add } = builder();
  const sw = add("switch", 344, 96);
  const pc1 = add("pc", 232, 280);
  const pc2 = add("pc", 544, 280);
  pc1.host = { ipMode: "static", ip: "192.168.0.10", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  pc2.host = { ipMode: "static", ip: "192.168.0.11", prefix: 24, gateway: "", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  const cables: Cable[] = [
    cable(sw, 1, pc1, 0),
    cable(sw, 6, pc2, 0),
  ];
  return { devices, cables };
}

/** 인터넷 + 공유기(라우터) + 스위치 + 호스트 3대 예제 */
export function exampleTopology(): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 344, -40);
  const rt = add("router", 344, 96);
  const sw = add("switch", 344, 272);
  const pc = add("pc", 200, 440);
  const laptop = add("laptop", 388, 440);
  const srv = add("server", 576, 440);
  // 웹 서버는 고정 주소로 두고 라우터가 공인 :80 을 여기로 포워딩한다
  srv.host = { ipMode: "static", ip: "192.168.0.20", prefix: 24, gateway: "192.168.0.1", dns: "192.168.0.1", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  rt.router = { ...rt.router!, forwards: [{ publicPort: 80, lanIp: "192.168.0.20", lanPort: 80 }], wifi: { enabled: true, ssid: "home" } };
  // 공유기의 Wi-Fi 에 붙는 스마트폰 (링크 다운, 전파 범위 안)
  add("phone", 600, 120);
  const cables: Cable[] = [
    cable(inet, 0, rt, 0), // isp ↔ wan
    cable(rt, 1, sw, 0), // lan1 ↔ eth1
    cable(sw, 2, pc, 0), // eth2
    cable(sw, 4, laptop, 0), // eth4
    cable(sw, 6, srv, 0), // eth6
  ];
  return { devices, cables };
}
