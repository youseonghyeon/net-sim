import { Network } from "../network";
import { Host } from "../nodes/host";
import { Router } from "../nodes/router";
import { Switch } from "../nodes/switch";

/** 테스트용: 라우터(DHCP) + 스위치 + DHCP 호스트 2대. 케이블은 호출자가 꽂는다 */
export function buildHomeLan(dhcpEnabled = true): Network {
  const net = new Network();
  net.addNode(
    new Router({
      id: "rt",
      mac: "02:00:00:00:ff:01",
      lanIp: "192.168.0.1",
      lanPrefix: 24,
      dhcp: { enabled: dhcpEnabled, start: "192.168.0.100", end: "192.168.0.101" },
    }),
  );
  net.addNode(new Switch("sw", 9));
  net.addNode(new Host({ id: "pc1", mac: "02:00:00:00:00:01", ipMode: "dhcp" }));
  net.addNode(new Host({ id: "pc2", mac: "02:00:00:00:00:02", ipMode: "dhcp" }));
  net.addNode(new Host({ id: "pc3", mac: "02:00:00:00:00:03", ipMode: "dhcp" }));
  net.connect("rt", 1, "sw", 0, 10, "rt-sw");
  return net;
}
