// 예제 "도메인으로 회사 웹 서버 접속": 집 DNS → 집 NAT → 공인 구간 → 회사 NAT 포트 포워딩 → 방화벽 → 웹 서버
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import { loadTopology } from "./helpers";
import { examplePublishTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";

function setup() {
  const x = loadTopology(examplePublishTopology());
  /** 역할을 가리지 않고 마지막 연결 + 그동안의 트레이스 */
  const connect = (from: string, dst: string, port = 80) => {
    const trace = x.act({ kind: "tcp-connect", nodeId: x.id(from), dst, port });
    return { conn: [...x.host(from).tcp.conns.values()].at(-1)!, trace };
  };
  return { ...x, connect };
}

describe("예제: 도메인으로 회사 웹 서버 접속", () => {
  it("구성 검사 이슈가 없고, 맥북은 DHCP 로 주소와 DNS 서버를 받는다", () => {
    const { t, host } = setup();
    expect(lintTopology(t as Topology)).toEqual([]);
    expect(host("맥북").ip).toMatch(/^192\.168\.0\.1\d\d$/);
    expect(host("맥북").iface.dns).toBe("8.8.8.8");
  });

  it("맥북 → nexus.com:80 은 DNS → 집 NAT → 회사 NAT 포트 포워딩 → 방화벽 허용 → 웹 서버로 성공한다", () => {
    const { connect, id } = setup();
    const { conn, trace } = connect("맥북", "nexus.com");
    expect(conn).toMatchObject({ state: "CLOSED", remoteIp: "203.0.113.109", bytesReceived: 3000 });
    const at = (name: string, kind: string) => trace.some((e) => e.nodeId === id(name) && e.kind === kind);
    expect(at("맥북", "dns.resolved")).toBe(true);
    expect(at("집 NAT", "nat.translate")).toBe(true);
    expect(at("회사 NAT", "nat.forward.rule")).toBe(true);
    expect(at("회사 방화벽", "fw.allow")).toBe(true);
    expect(at("웹 서버", "tcp.established")).toBe(true);
  });

  it("DNS 질의는 NAT 밖 공인 DNS 8.8.8.8 로 간다 (집 NAT 변환 → ISP 라우터 → 공인 DNS)", () => {
    const { connect, id, host } = setup();
    expect(host("맥북").iface.dns).toBe("8.8.8.8");
    const { trace } = connect("맥북", "nexus.com");
    const q = trace.findIndex((e) => e.nodeId === id("공인 DNS") && e.kind === "dns.query.received");
    expect(q).toBeGreaterThan(-1);
    expect(trace[q]!.summary).toContain("203.0.113.108"); // 집 NAT 의 공인 주소로 변환되어 도착
    expect(trace.some((e) => e.nodeId === id("ISP 라우터") && e.kind === "ip.forward")).toBe(true);
  });

  it("회사 서버의 사설 주소로는 직접 닿지 않고, 포워딩이 없는 포트는 회사 NAT 에서 드롭된다", () => {
    const { connect, id } = setup();
    expect(connect("맥북", "192.168.1.3").conn.state).toBe("FAILED");
    const other = connect("맥북", "203.0.113.109", 22);
    expect(other.conn.state).toBe("FAILED");
    expect(other.trace.some((e) => e.nodeId === id("회사 NAT") && e.kind === "nat.miss")).toBe(true);
  });

  it("회사 안에서 시작한 통신의 응답은 방화벽 Stateful 검사로 통과한다 (srv-2 → 홈 NAT 공인 주소 ping)", () => {
    const { s, id, host } = setup();
    s.net.scheduleAction(s.net.now, { kind: "ping", nodeId: id("srv-2"), dst: "203.0.113.108" });
    s.net.runToIdle();
    expect(host("srv-2").pings.at(-1)!.status).toBe("ok");
  });
});
