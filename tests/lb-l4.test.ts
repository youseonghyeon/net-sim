// 로드밸런서 L4 모드(주소 변환, 연결 하나)와 세션 고정(같은 출발지 IP → 같은 백엔드)
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import { loadTopology } from "./helpers";
import { exampleLoadBalancerTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";

type LbPatch = Partial<NonNullable<NonNullable<Topology["devices"][number]["host"]>["lb"]>>;
function withLb(patch: LbPatch, name = "lb-1", t: Topology = exampleLoadBalancerTopology()): Topology {
  return { ...t, devices: t.devices.map((d) => (d.name === name ? { ...d, host: { ...d.host!, lb: { ...d.host!.lb!, ...patch } } } : d)) };
}

const load = (t: Topology) => loadTopology(t);

describe("로드밸런서 L4 모드", () => {
  it("주소만 바꿔 넘긴다: LB 에는 TCP 연결이 없고, 연결 두 개가 라운드 로빈으로 백엔드 둘에 간다", () => {
    const t = withLb({ mode: "l4", algorithm: "round-robin" });
    expect(lintTopology(t)).toEqual([]);
    const { id, host, act, lastConn, serverConns } = load(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    expect(tr.some((e) => e.kind === "lb.forward")).toBe(true);
    expect([...host("lb-1").tcp.conns.values()]).toHaveLength(0); // LB 는 연결을 끊어 잇지 않는다
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    const used = ["web-1", "web-2", "web-3"].filter((n) => serverConns(n).length > 0);
    expect(used).toEqual(["web-1", "web-2"]);
    // 백엔드가 본 상대는 LB 주소 (FULLNAT)
    expect(serverConns("web-1")[0]!.remoteIp).toBe("192.168.0.20");
  });

  it("백엔드가 RST 로 거부하면 클라이언트 연결은 거부되고 그 백엔드를 빼 두어, 다시 연결하면 다른 백엔드로 간다", () => {
    const base = withLb({ mode: "l4", algorithm: "round-robin" });
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "web-1" ? { ...d, host: { ...d.host!, services: [] } } : d)) };
    const { id, act, lastConn, serverConns } = load(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(tr.some((e) => e.kind === "lb.down")).toBe(true);
    expect(lastConn("pc-1").state).toBe("FAILED");
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    expect(serverConns("web-2").length).toBe(1);
  });

  it("L4 는 HTTP 가 아니어도 나눈다: 포트 22 로 받으면 백엔드와 SSH 세션이 열린다 (구성 검사도 조용)", () => {
    const base = withLb({ mode: "l4", port: 22, backends: [{ ip: "192.168.0.11", port: 22 }] });
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "web-1" ? { ...d, host: { ...d.host!, services: [80, 22] } } : d)) };
    expect(lintTopology(t).map((i) => i.code)).not.toContain("lb.ssh-port");
    const { id, act, lastConn } = load(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 22 });
    expect(lastConn("pc-1")).toMatchObject({ state: "ESTABLISHED", ssh: { open: true } });
    act({ kind: "tcp-close", nodeId: id("pc-1"), conn: lastConn("pc-1").id });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", reason: "정상 종료" });
  });
});

describe("세션 고정", () => {
  for (const mode of ["l7", "l4"] as const) {
    it(`${mode.toUpperCase()}: 같은 클라이언트는 계속 같은 백엔드, 다른 클라이언트는 다음 차례`, () => {
      const t = withLb({ mode: mode === "l4" ? "l4" : undefined, algorithm: "round-robin", sticky: true });
      const { id, act, serverConns } = load(t);
      for (let k = 0; k < 3; k++) act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
      expect(["web-1", "web-2", "web-3"].map((n) => serverConns(n).length)).toEqual([3, 0, 0]);
      act({ kind: "tcp-connect", nodeId: id("laptop-1"), dst: "192.168.0.20", port: 80 });
      expect(["web-1", "web-2", "web-3"].map((n) => serverConns(n).length)).toEqual([3, 1, 0]);
    });
  }

  it("세션 고정이어도 그 백엔드가 빠지면 다른 백엔드로 가고, 그쪽에 다시 고정된다 (L7)", () => {
    const base = withLb({ algorithm: "round-robin", sticky: true });
    const { s, id, act, serverConns, lastConn } = load(base);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(serverConns("web-1").length).toBe(1);
    // web-1 이 웹 서비스를 멈춤 → 다음 요청은 거부(RST)로 빠지고 web-2 로
    s.sync({ ...base, devices: base.devices.map((d) => (d.name === "web-1" ? { ...d, host: { ...d.host!, services: [] } } : d)) });
    s.net.runToIdle();
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(serverConns("web-2").length).toBe(2);
    expect(serverConns("web-3").length).toBe(0);
  });
});

describe("L4 리뷰에서 나온 경우들", () => {
  const l4 = (patch: LbPatch = {}) => withLb({ mode: "l4", algorithm: "round-robin", ...patch });

  it("리뷰: 정상 종료된 HTTP 연결의 흐름은 진행 중 목록에서 빠지고, 최소 연결이 새어 남은 흐름을 세지 않는다", () => {
    const { id, host, act, serverConns } = load(withLb({ mode: "l4", algorithm: "least-conn" }));
    for (let k = 0; k < 4; k++) act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(host("lb-1").lb.openFlows).toBe(0);
    expect(["web-1", "web-2", "web-3"].map((n) => serverConns(n).length)).toEqual([4, 0, 0]);
  });

  it("리뷰: 백엔드가 자기 자신이면 스택이 넘치지 않고 RST 로 거절한다", () => {
    const t = l4({ backends: [{ ip: "192.168.0.20", port: 80 }] });
    const { id, act, lastConn } = load(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(tr.some((e) => e.kind === "lb.fail" && e.summary.includes("자신"))).toBe(true);
    expect(lastConn("pc-1").state).toBe("FAILED");
  });

  it("리뷰: SYN 에 응답하지 않는 백엔드는 SYN 재전송 때 빼고 다른 백엔드로 옮겨, 연결이 성공한다 (세션 고정이어도)", () => {
    const t = l4({ backends: [{ ip: "192.168.0.99", port: 80 }, { ip: "192.168.0.11", port: 80 }], sticky: true });
    const { id, act, lastConn } = load(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(tr.some((e) => e.kind === "lb.down" && e.summary.includes("192.168.0.99"))).toBe(true);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
  });

  it("리뷰: 세션 고정만 켜도 열려 있던 L4 SSH 세션은 유지된다", () => {
    const base = l4({ port: 22, backends: [{ ip: "192.168.0.11", port: 22 }] });
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "web-1" ? { ...d, host: { ...d.host!, services: [80, 22] } } : d)) };
    const { s, id, act, lastConn } = load(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 22 });
    s.sync(withLb({ sticky: true }, "lb-1", t));
    s.net.runToIdle();
    act({ kind: "tcp-close", nodeId: id("pc-1"), conn: lastConn("pc-1").id });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", reason: "정상 종료" });
  });

  it("리뷰: L4 로드밸런서끼리 서로를 백엔드로 두어도 TTL 이 다해 끝난다 (이벤트 폭주 없음)", () => {
    let t = l4({ backends: [{ ip: "192.168.0.10", port: 80 }] });
    t = withLb({ mode: "l4", backends: [{ ip: "192.168.0.20", port: 80 }] }, "nginx 서버", t);
    const { id, act, lastConn } = load(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(lastConn("pc-1").state).toBe("FAILED");
  });

  it("리뷰: 흐름 상한에서 진행 중인 흐름보다 끝난 흐름을 먼저 내보낸다", () => {
    const { id, host, act } = load(l4());
    for (let k = 0; k < 3; k++) act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(host("lb-1").lb.openFlows).toBe(0);
    expect(host("lb-1").lb.flowRows()).toEqual([]);
  });
});

