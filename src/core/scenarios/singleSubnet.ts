import { Network } from "../network";
import { Host } from "../nodes/host";
import { Switch } from "../nodes/switch";
import type { Scenario } from "./index";

/** 1단계: 서브넷 하나. 호스트 3대가 스위치 하나에 연결. ARP + ICMP ping */
export const singleSubnet: Scenario = {
  id: "single-subnet",
  title: "1. 단일 서브넷 (ARP + ping)",
  description:
    "호스트 3대가 스위치 하나에 물려 있는 10.0.0.0/24 서브넷입니다. " +
    "ping 을 보내면 목적지 MAC 을 모르므로 먼저 ARP 요청을 브로드캐스트하고, 스위치가 MAC 테이블을 학습하는 과정을 볼 수 있습니다.",
  build() {
    const net = new Network();
    net.addNode(new Switch("sw1", 4));
    net.addNode(new Host({ id: "h1", mac: "02:00:00:00:00:01", ipMode: "static", ip: "10.0.0.1", prefix: 24 }));
    net.addNode(new Host({ id: "h2", mac: "02:00:00:00:00:02", ipMode: "static", ip: "10.0.0.2", prefix: 24 }));
    net.addNode(new Host({ id: "h3", mac: "02:00:00:00:00:03", ipMode: "static", ip: "10.0.0.3", prefix: 24 }));
    net.connect("h1", 0, "sw1", 0);
    net.connect("h2", 0, "sw1", 1);
    net.connect("h3", 0, "sw1", 2);
    return net;
  },
  layout: {
    sw1: { x: 400, y: 120 },
    h1: { x: 160, y: 340 },
    h2: { x: 400, y: 340 },
    h3: { x: 640, y: 340 },
  },
  quickActions: [
    { label: "h1 → ping h2", action: { kind: "ping", nodeId: "h1", dst: "10.0.0.2" } },
    { label: "h1 → ping h3", action: { kind: "ping", nodeId: "h1", dst: "10.0.0.3" } },
    { label: "h3 → ping h1", action: { kind: "ping", nodeId: "h3", dst: "10.0.0.1" } },
    { label: "h2 → ping 10.0.0.99 (없는 호스트)", action: { kind: "ping", nodeId: "h2", dst: "10.0.0.99" } },
    { label: "h1 → ping 8.8.8.8 (게이트웨이 없음)", action: { kind: "ping", nodeId: "h1", dst: "8.8.8.8" } },
  ],
};

export const scenarios: Scenario[] = [singleSubnet];
