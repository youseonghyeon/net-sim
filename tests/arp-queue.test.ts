// IPv4 ARP: 서로 동시에 ARP 요청을 보낼 때 응답 하나를 잃어도 대기열이 남지 않는다 (IPv6 NDP 에서 먼저 찾은 결함과 같은 자리)
import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { Host } from "../src/core/nodes/host";
import { Switch } from "../src/core/nodes/switch";

describe("ARP 대기열", () => {
  it("동시에 서로 ping, B 의 ARP 응답만 손실 → A 는 B 의 요청으로 배워 보내고, 61초 뒤 ping 도 ARP 로 다시 찾는다", () => {
    const net = new Network();
    net.addNode(new Switch("sw", 4));
    net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "192.168.0.10", prefix: 24 }));
    net.addNode(new Host({ id: "b", mac: "02:00:00:00:00:0b", ipMode: "static", ip: "192.168.0.20", prefix: 24 }));
    const la = net.connect("a", 0, "sw", 0);
    net.connect("b", 0, "sw", 1);
    net.runToIdle();
    const a = net.getHost("a");
    const t0 = net.now;
    net.scheduleAction(t0, { kind: "ping", nodeId: "a", dst: "192.168.0.20" });
    net.scheduleAction(t0, { kind: "ping", nodeId: "b", dst: "192.168.0.10" });
    // a─sw 링크: a 의 요청(t0) → b 의 요청(+10) → a 의 응답(+20) → b 의 응답(+30). 마지막 것만 잃게 한다
    net.runUntil(t0 + 25);
    net.dropNextOn(la.id);
    net.runToIdle();
    const leaked = a.pending.has("192.168.0.20");
    const first = a.pings.at(-1)!.status;
    net.runUntil(net.now + 61_000); // ARP 캐시 만료
    const from = net.trace.length;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "192.168.0.20" });
    net.runToIdle();
    const asked = net.trace.slice(from).filter((e) => e.nodeId === "a" && e.kind === "arp.request.sent").length;
    expect({ leaked, first, asked, second: a.pings.at(-1)!.status }).toEqual({ leaked: false, first: "ok", asked: 1, second: "ok" });
  });
});
