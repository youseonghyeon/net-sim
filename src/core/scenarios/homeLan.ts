import { Network } from "../network";
import { Host } from "../nodes/host";
import { Internet } from "../nodes/internet";
import { Router } from "../nodes/router";
import { Switch } from "../nodes/switch";

/** 테스트용: 라우터(DHCP) + 스위치 + DHCP 호스트 3대 + 웹 서버(수동 IP, 포트 80) + 인터넷. 호스트 케이블은 호출자가 꽂는다 */
export function buildHomeLan(dhcpEnabled = true, withInternet = false): Network {
  const net = new Network();
  net.addNode(
    new Router({
      id: "rt",
      mac: "02:00:00:00:ff:01",
      wanMac: "02:00:00:01:ff:01",
      lanIp: "192.168.0.1",
      lanPrefix: 24,
      dhcp: { enabled: dhcpEnabled, start: "192.168.0.100", end: "192.168.0.101" },
    }),
  );
  if (withInternet) {
    net.addNode(new Internet({ id: "inet", mac: "02:00:00:ff:00:01" }));
    net.connect("inet", 0, "rt", 0, 10, "inet-rt");
  }
  net.addNode(new Switch("sw", 9));
  net.addNode(new Host({ id: "pc1", mac: "02:00:00:00:00:01", ipMode: "dhcp" }));
  net.addNode(new Host({ id: "pc2", mac: "02:00:00:00:00:02", ipMode: "dhcp" }));
  net.addNode(new Host({ id: "pc3", mac: "02:00:00:00:00:03", ipMode: "dhcp" }));
  net.addNode(new Host({ id: "srv", mac: "02:00:00:00:00:04", ipMode: "static", ip: "192.168.0.50", prefix: 24, gateway: "192.168.0.1", services: [80] }));
  net.connect("rt", 1, "sw", 0, 10, "rt-sw");
  return net;
}
