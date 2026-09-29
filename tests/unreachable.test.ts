// ICMP Destination Unreachable: 라우터는 경로 없음(!N)·ARP 무응답(!H), 호스트는 닫힌 UDP 포트(!P) 를 보낸 이에게 알린다.
// 받은 쪽은 timeout 을 기다리지 않고 바로 실패를 안다. 방화벽 차단은 여전히 조용한 드롭.
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { Internet } from "../src/core/nodes/internet";
import { Router } from "../src/core/nodes/router";
import { NetworkSync } from "../src/model/netSync";
import { EXAMPLES, exampleTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";

function load(t: Topology) {
  const s = new NetworkSync();
  s.sync(t);
  s.net.runToIdle();
  const id = (name: string) => t.devices.find((d) => d.name === name)!.id;
  const host = (name: string) => s.net.nodes.get(id(name)) as Host;
  const act = (a: Parameters<typeof s.net.scheduleAction>[1]) => {
    const start = s.net.now;
    s.net.scheduleAction(s.net.now, a);
    s.net.runToIdle();
    return s.net.now - start;
  };
  return { s, id, host, act };
}

describe("ICMP Destination Unreachable", () => {
  it("경로 없음: 게이트웨이가 Net Unreachable 을 돌려 ping 은 timeout 전에 실패, traceroute 는 !N 으로 끝난다", () => {
    const base = EXAMPLES.homes.build();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "gw-1" ? { ...d, l3: { ...d.l3!, routes: [] } } : d)) };
    const { act, id, host } = load(t);
    act({ kind: "ping", nodeId: id("pc-1"), dst: "192.168.2.10" });
    const ping = host("pc-1").pings.at(-1)!;
    expect(ping).toMatchObject({ status: "failed", reason: "Destination Net Unreachable (192.168.1.1)" });
    expect(ping.sentAt).toBeGreaterThan(0);
    act({ kind: "traceroute", nodeId: id("pc-1"), dst: "192.168.2.10" });
    const tr = host("pc-1").traceroutes.at(-1)!;
    // 실제 traceroute 와 같다: 1 번째 프로브는 게이트웨이에서 TTL 초과, 2 번째는 같은 게이트웨이가 경로 없음(!N)
    expect(tr.hops.map((h) => `${h.ip}${h.flag ?? ""}`)).toEqual(["192.168.1.1", "192.168.1.1!N"]);
    expect(tr.status).toBe("failed");
  });

  it("없는 주소: 게이트웨이의 ARP 가 실패하면 Host Unreachable", () => {
    const { act, id, host } = load(EXAMPLES.homes.build());
    act({ kind: "ping", nodeId: id("pc-1"), dst: "192.168.2.99" });
    expect(host("pc-1").pings.at(-1)).toMatchObject({ status: "failed", reason: "Destination Host Unreachable (10.0.0.2)" });
  });

  it("TCP 연결도 SYN 재전송을 기다리지 않고 바로 실패", () => {
    const base = EXAMPLES.homes.build();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "gw-1" ? { ...d, l3: { ...d.l3!, routes: [] } } : d)) };
    const { act, id, host } = load(t);
    const took = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.2.10", port: 80 });
    const c = [...host("pc-1").tcp.conns.values()].at(-1)!;
    expect(c).toMatchObject({ state: "FAILED", reason: "Destination Net Unreachable (192.168.1.1)", retransmits: 0 });
    expect(took).toBeLessThan(400); // 첫 재전송(RTO 400ms)보다 먼저
  });

  it("닫힌 UDP 포트: DNS 서비스가 꺼진 서버에 물으면 Port Unreachable 로 DNS 조회가 바로 실패", () => {
    const base = exampleTopology();
    const srv = base.devices.find((d) => d.name === "srv-1")!;
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "pc-1" ? { ...d, host: { ...d.host!, ipMode: "static", ip: "192.168.0.50", prefix: 24, gateway: "192.168.0.1", dns: srv.host!.ip } } : d)) };
    const { act, id, host } = load(t);
    const took = act({ kind: "ping", nodeId: id("pc-1"), dst: "google.com" });
    const p = host("pc-1").pings.at(-1)!;
    expect(p.status).toBe("failed");
    expect(p.reason).toContain("Destination Port Unreachable");
    expect(took).toBeLessThan(1000); // DNS timeout 보다 먼저
  });

  it("포트 포워딩 대상이 없으면 바깥 클라이언트는 NAT 를 거쳐 Host Unreachable 을 받는다 (원래 패킷은 공인 주소로 되돌려짐)", () => {
    const base = exampleTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.kind === "router" ? { ...d, router: { ...d.router!, forwards: [{ publicPort: 80, lanIp: "192.168.0.99", lanPort: 80 }] } } : d)) };
    const { act, id, s } = load(t);
    const wan = (s.net.nodes.get(id("rt-1")) as Router).wan.ip!;
    act({ kind: "inet-connect", nodeId: id("internet-1"), dst: wan, port: 80 });
    const c = [...(s.net.nodes.get(id("internet-1")) as Internet).tcp.conns.values()].at(-1)!;
    expect(c.state).toBe("FAILED");
    expect(c.reason).toContain("Destination Host Unreachable");
  });

  it("방화벽 차단은 알리지 않는다 (조용한 드롭 — 실무의 기본 DROP)", () => {
    const { act, id, host, s } = load(EXAMPLES.fwbox.build());
    const srvIp = host("srv-1").ip!;
    act({ kind: "ping", nodeId: id("pc-1"), dst: srvIp });
    expect(host("pc-1").pings.at(-1)).toMatchObject({ status: "failed", reason: "timeout · 응답 없음" });
    expect(s.net.trace.some((e) => e.kind === "icmp.unreachable.sent")).toBe(false);
  });
});
