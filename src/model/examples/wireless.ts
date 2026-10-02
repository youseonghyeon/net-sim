// 예제 묶음 "무선". 등록(메뉴 순서·설명)은 ../examples.ts 의 EXAMPLES.
import { type Cable, type Topology } from "../topology";
import { builder, cable } from "./build";

/**
 * 무선 로밍: 같은 SSID 의 AP 두 대. 스마트폰을 끌어 옮기면 가까운 AP 로 갈아탄다.
 * 노트북은 유선 케이블 + Wi-Fi: 케이블이 있으면 유선, 케이블을 지우면 Wi-Fi 로 넘어간다 (NIC 마다 MAC 이 달라 주소를 새로 받음)
 */
export function exampleRoamingTopology(): Topology {
  const { devices, add } = builder();
  const rt = add("router", 344, 0);
  const sw = add("switch", 344, 176);
  const ap1 = add("ap", 16, 352);
  const ap2 = add("ap", 704, 352);
  ap1.ap = { enabled: true, ssid: "office" };
  ap2.ap = { enabled: true, ssid: "office" };
  const phone = add("phone", 56, 544);
  phone.wifi = { ssid: "office" };
  const laptop = add("laptop", 216, 544);
  laptop.wifi = { ssid: "office" };
  const cables: Cable[] = [
    cable(rt, 1, sw, 3),
    cable(sw, 0, ap1, 0),
    cable(sw, 7, ap2, 0),
    cable(sw, 2, laptop, 0),
  ];
  return { devices, cables };
}
