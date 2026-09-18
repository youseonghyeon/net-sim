import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { Host } from "../src/core/nodes/host";
import { Router } from "../src/core/nodes/router";
import { Switch } from "../src/core/nodes/switch";
import { buildHomeLan } from "../src/core/scenarios/homeLan";

describe("리뷰에서 나온 엣지케이스", () => {
  it("L2 루프(스위치 사이 케이블 2개)가 있어도 브로드캐스트가 폭주하지 않는다", () => {
    const net = new Network();
    net.addNode(new Switch("s1", 4));
    net.addNode(new Switch("s2", 4));
    net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "10.0.0.1" }));
    net.addNode(new Host({ id: "b", mac: "02:00:00:00:00:0b", ipMode: "static", ip: "10.0.0.2" }));
    net.connect("s1", 0, "s2", 0);
    net.connect("s1", 1, "s2", 1); // 루프
    net.connect("a", 0, "s1", 2);
    net.connect("b", 0, "s2", 2);
    net.runToIdle(20_000);
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "10.0.0.2" });
    const events = net.runToIdle(20_000);
    expect(events).toBeLessThan(2000);
    expect(net.trace.some((e) => e.kind === "switch.loop")).toBe(true);
    expect(net.pendingEvents).toBe(0);
  });

  it("마지막 ACK 이 유실돼도 재전송된 FIN 을 다시 ACK 해 양쪽 모두 정상 종료한다", () => {
    const net = buildHomeLan();
    const pc1Link = net.connect("pc1", 0, "sw", 1);
    net.connect("srv", 0, "sw", 2);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1", dst: "192.168.0.50", port: 80 });
    // 서버의 마지막 ACK(pc1 의 FIN 에 대한 응답)이 pc1 링크에서 유실되도록: 서버 FIN 이 오간 뒤 시점을 찾아 다음 프레임 유실
    for (let guard = 0; guard < 200; guard++) {
      const before = net.trace.length;
      net.step();
      if (net.trace.slice(before).some((e) => e.nodeId === "pc1" && e.kind === "tcp.fin.sent")) break;
    }
    net.dropNextOn(pc1Link.id); // sw→pc1 로 오는 다음 프레임 = 서버의 마지막 ACK … 또는 pc1→sw 의 FIN 자체
    net.runToIdle();
    const client = [...net.getHost("pc1").tcp.conns.values()][0]!;
    const server = [...net.getHost("srv").tcp.conns.values()][0]!;
    expect(client.state).toBe("CLOSED");
    expect(server.state).toBe("CLOSED");
    expect(net.trace.some((e) => e.kind === "link.loss")).toBe(true);
  });

  it("같은 IP 로 장치를 갈아끼우면 Gratuitous ARP 로 이웃의 ARP 캐시가 갱신된다", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1);
    net.addNode(new Host({ id: "x1", mac: "02:00:00:00:00:e1", ipMode: "static", ip: "192.168.0.60", prefix: 24 }));
    net.connect("x1", 0, "sw", 2);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "192.168.0.60" });
    net.runToIdle();
    expect(net.getHost("pc1").arpCache.get("192.168.0.60")?.mac).toBe("02:00:00:00:00:e1");

    net.removeNode("x1");
    net.addNode(new Host({ id: "x2", mac: "02:00:00:00:00:e2", ipMode: "static", ip: "192.168.0.60", prefix: 24 }));
    net.connect("x2", 0, "sw", 2);
    net.runToIdle();
    expect(net.getHost("pc1").arpCache.get("192.168.0.60")?.mac).toBe("02:00:00:00:00:e2");
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "192.168.0.60" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)?.status).toBe("ok");
  });

  it("호스트를 제거하면 DHCP Release 로 임대가 돌아와 다음 호스트가 쓸 수 있다", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1);
    net.connect("pc2", 0, "sw", 2);
    net.runToIdle();
    const rt = net.nodes.get("rt") as Router;
    expect(rt.leases.size).toBe(2); // 풀 .100~.101 이 모두 찼다
    net.removeNode("pc1");
    net.runToIdle();
    expect(rt.leases.size).toBe(1);
    expect(net.trace.some((e) => e.nodeId === "rt" && e.kind === "dhcp.lease" && e.summary.includes("Release"))).toBe(true);
    net.connect("pc3", 0, "sw", 3);
    net.runToIdle();
    expect(net.getHost("pc3").ip).toBe("192.168.0.100");
  });

  it("장치를 제거하면 그 장치의 타이머가 남아 시계를 끌고 가지 않는다", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "192.168.0.99" });
    net.runUntil(net.now + 5);
    const t = net.now;
    net.removeNode("pc1");
    net.runToIdle();
    // 남은 건 제거 직전 보낸 DHCP Release 배달뿐. ARP(1000ms)/ping(2000ms) 타이머는 따라오지 않는다
    expect(net.now).toBeLessThan(t + 100);
    expect(net.pendingEvents).toBe(0);
  });

  it("LAN 에서 라우터의 WAN 주소로 ping 하면 라우터가 직접 응답한다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    const rt = net.nodes.get("rt") as Router;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: rt.wan.ip! });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)?.status).toBe("ok");
    expect(rt.nat.size).toBe(0);
  });

  it("자기 IP 로 ping 하면 즉시 성공하고, 브로드캐스트 주소는 인터넷으로 나가지 않는다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "192.168.0.100" });
    net.runToIdle();
    expect(net.getHost("pc1").pings.at(-1)).toMatchObject({ status: "ok", rtt: 0 });
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc1", dst: "255.255.255.255" });
    net.runToIdle();
    expect(net.trace.some((e) => e.nodeId === "inet" && e.kind === "inet.forward")).toBe(false);
  });

  it("전송 중에 IP 모드를 바꾸면 연결이 정리되고 옛 주소로 재전송하지 않는다", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1);
    net.connect("srv", 0, "sw", 2);
    net.runToIdle();
    const pc1 = net.getHost("pc1");
    pc1.configure({ ipMode: "static", ip: "192.168.0.60", prefix: 24, gateway: "192.168.0.1" }, net.contextFor("pc1"));
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1", dst: "192.168.0.50", port: 80 });
    net.runUntil(net.now + 5); // SYN(또는 그 ARP)이 링크 위
    const switchedAt = net.now;
    pc1.configure({ ipMode: "dhcp" }, net.contextFor("pc1"));
    net.runToIdle();
    const conn = [...pc1.tcp.conns.values()][0]!;
    expect(conn.state).toBe("FAILED");
    expect(conn.reason).toBe("주소 변경");
    const stale = net.transmissions.filter(
      (t) => t.departAt > switchedAt && t.from.node === "pc1" && t.frame.payload.kind === "ipv4" && t.frame.payload.payload.kind === "tcp" && t.frame.payload.src === "192.168.0.60",
    );
    expect(stale).toHaveLength(0); // 모드 변경 뒤에는 옛 주소로 아무것도 나가지 않는다
  });

  it("끝난 연결과 같은 포트로 새 SYN 이 오면 새 연결로 받는다", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1);
    net.connect("srv", 0, "sw", 2);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1", dst: "192.168.0.50", port: 80 });
    net.runToIdle();
    // 같은 IP 의 새 호스트(새 스택은 49152 부터 다시 시작)
    const ip = net.getHost("pc1").ip!;
    net.removeNode("pc1");
    net.addNode(new Host({ id: "pc1b", mac: "02:00:00:00:00:1b", ipMode: "static", ip, prefix: 24 }));
    net.connect("pc1b", 0, "sw", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1b", dst: "192.168.0.50", port: 80 });
    net.runToIdle();
    expect([...net.getHost("pc1b").tcp.conns.values()][0]?.state).toBe("CLOSED");
  });
});
