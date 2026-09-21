import { describe, expect, it } from "vitest";
import { Internet } from "../src/core/nodes/internet";
import { Router } from "../src/core/nodes/router";
import { TCP_MAX_RETRIES } from "../src/core/nodes/tcp";
import { buildHomeLan } from "../src/core/scenarios/homeLan";

function tcpKinds(net: ReturnType<typeof buildHomeLan>, node?: string): string[] {
  return net.trace.filter((e) => e.kind.startsWith("tcp.") && e.kind !== "tcp.received" && (!node || e.nodeId === node)).map((e) => `${e.nodeId}:${e.kind}`);
}

describe("TCP", () => {
  it("3-way handshake → 요청 → 응답 3세그먼트 → FIN 종료", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1);
    net.connect("srv", 0, "sw", 2);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1", dst: "192.168.0.50", port: 80 });
    net.runToIdle();

    const client = [...net.getHost("pc1").tcp.conns.values()][0]!;
    const server = [...net.getHost("srv").tcp.conns.values()][0]!;
    expect(client.state).toBe("CLOSED");
    expect(server.state).toBe("CLOSED");
    expect(client.bytesSent).toBe(100);
    expect(client.bytesReceived).toBe(3000);
    expect(server.bytesReceived).toBe(100);
    expect(client.retransmits).toBe(0);
    expect(server.retransmits).toBe(0);
    // seq 번호: 클라이언트 1000 + SYN 1 + 100B + FIN 1 = 1102, 서버 3000 + 1 + 3000 + 1 = 6002
    expect(client.sndNxt).toBe(1102);
    expect(server.sndNxt).toBe(6002);
    expect(client.rcvNxt).toBe(6002);
    expect(server.rcvNxt).toBe(1102);

    expect(tcpKinds(net).slice(0, 11)).toEqual([
      "pc1:tcp.connect",
      "pc1:tcp.syn.sent",
      "srv:tcp.syn.received",
      "srv:tcp.synack.sent",
      "pc1:tcp.ack.received", // SYN 이 확인됨
      "pc1:tcp.synack.received",
      "pc1:tcp.ack.sent",
      "pc1:tcp.established",
      "pc1:tcp.data.sent",
      "srv:tcp.ack.received", // SYN·ACK 이 확인됨
      "srv:tcp.established",
    ]);
    expect(tcpKinds(net).filter((k) => k.endsWith("tcp.closed"))).toEqual(["srv:tcp.closed", "pc1:tcp.closed"]);
    expect(net.pendingEvents).toBe(0);
  });

  it("듣는 서비스가 없는 포트로 연결하면 RST 로 거부된다", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1);
    net.connect("srv", 0, "sw", 2);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1", dst: "192.168.0.50", port: 22 });
    net.runToIdle();
    const client = [...net.getHost("pc1").tcp.conns.values()][0]!;
    expect(client.state).toBe("FAILED");
    expect(client.reason).toContain("거부");
    expect(net.trace.some((e) => e.nodeId === "srv" && e.kind === "tcp.rst.sent")).toBe(true);
    expect(net.trace.some((e) => e.nodeId === "pc1" && e.kind === "tcp.refused")).toBe(true);
    expect(net.pendingEvents).toBe(0);
  });

  it("데이터 세그먼트가 손실되면 중복 ACK 후 타임아웃 재전송으로 복구된다", () => {
    const net = buildHomeLan();
    net.connect("pc1", 0, "sw", 1);
    const srvLink = net.connect("srv", 0, "sw", 2);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1", dst: "192.168.0.50", port: 80 });
    // handshake 가 끝나고 서버가 응답을 보내기 직전(요청 도착 전)에 서버 링크의 다음 프레임 1개를 손실시킨다
    net.runUntil(net.now + 55);
    net.dropNextOn(srvLink.id);
    net.runToIdle();

    const client = [...net.getHost("pc1").tcp.conns.values()][0]!;
    const server = [...net.getHost("srv").tcp.conns.values()][0]!;
    expect(net.trace.some((e) => e.kind === "link.loss")).toBe(true);
    expect(net.trace.some((e) => e.kind === "tcp.retransmit")).toBe(true);
    expect(client.state).toBe("CLOSED");
    expect(server.state).toBe("CLOSED");
    expect(client.bytesReceived).toBe(3000);
    expect(server.retransmits).toBeGreaterThanOrEqual(1);
    expect(net.pendingEvents).toBe(0);
  });

  it("SYN 이 계속 손실되면 재전송 3회 후 실패한다", () => {
    const net = buildHomeLan();
    const link = net.connect("pc1", 0, "sw", 1);
    net.connect("srv", 0, "sw", 2);
    net.runToIdle();
    net.setLinkLoss(link.id, 1);
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1", dst: "192.168.0.50", port: 80 });
    net.runToIdle();
    const client = [...net.getHost("pc1").tcp.conns.values()][0]!;
    expect(client.state).toBe("FAILED");
    expect(client.retransmits).toBe(TCP_MAX_RETRIES);
    expect(net.trace.filter((e) => e.kind === "tcp.retransmit")).toHaveLength(TCP_MAX_RETRIES);
    expect(net.trace.some((e) => e.kind === "tcp.failed")).toBe(true);
  });

  it("NAT 를 거쳐 인터넷의 웹 서버와 연결하고 종료한다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc1", dst: "93.184.216.34", port: 80 });
    net.runToIdle();

    const client = [...net.getHost("pc1").tcp.conns.values()][0]!;
    expect(client.state).toBe("CLOSED");
    expect(client.bytesReceived).toBe(3000);
    const rt = net.nodes.get("rt") as Router;
    const entries = [...rt.nat.values()];
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ proto: "tcp", lanIp: "192.168.0.100", innerId: 49152 });
    const inet = net.nodes.get("inet") as Internet;
    const server = [...inet.tcp.conns.values()][0]!;
    expect(server.remoteIp).toBe("203.0.113.100"); // 서버가 보는 상대는 공인 주소
    expect(server.remotePort).toBe(entries[0]!.publicId);
    expect(server.state).toBe("CLOSED");
    expect(net.pendingEvents).toBe(0);
  });
});
