// SSH 흉내 (포트 22): 버전 교환 → 키 교환 → 인증 뒤 세션이 열린 채 유지, "연결 해제" 로 FIN 종료.
// 오래 열린 연결이 망 변화에 어떻게 반응하는지: 조용한 동안 경로가 끊겨도 모르고, 닫을 때 알게 된다
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import type { TcpConn } from "../src/core/nodes/tcp";
import { NetworkSync } from "../src/model/netSync";
import { exampleHaTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";

/** HA 예제에 인터넷 쪽 대신 안쪽 서버를 하나 두고 SSH 22 를 연다 */
function load(t: Topology = exampleHaTopology()) {
  const s = new NetworkSync();
  s.sync(t);
  s.net.runToIdle();
  const id = (name: string) => t.devices.find((d) => d.name === name)!.id;
  const host = (name: string) => s.net.nodes.get(id(name)) as Host;
  const act = (a: Parameters<typeof s.net.scheduleAction>[1]) => {
    const from = s.net.trace.length;
    s.net.scheduleAction(s.net.now, a);
    s.net.runToIdle();
    return s.net.trace.slice(from);
  };
  const apply = (next: Topology) => {
    s.sync(next);
    s.net.runToIdle();
  };
  const lastConn = (name: string): TcpConn => [...host(name).tcp.conns.values()].filter((c) => c.role === "client").at(-1)!;
  return { s, id, host, act, apply, lastConn };
}

/** laptop-1 에 SSH 서버를 켠 HA 예제 (같은 LAN 안) */
function withSshServer(): Topology {
  const t = exampleHaTopology();
  return { ...t, devices: t.devices.map((d) => (d.name === "laptop-1" ? { ...d, kind: "server" as const, host: { ...d.host!, services: [22] } } : d)) };
}

describe("SSH 세션", () => {
  it("버전 교환 → 키 교환 → 인증 뒤 열린 채 유지, 연결 해제하면 FIN 으로 정상 종료", () => {
    const { id, act, lastConn, host } = load(withSshServer());
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.12", port: 22 });
    const c = lastConn("pc-1");
    expect(c).toMatchObject({ state: "ESTABLISHED", ssh: { open: true, step: 6 } });
    expect(tr.filter((e) => e.kind === "ssh.open").map((e) => e.nodeId)).toEqual([id("laptop-1"), id("pc-1")]);
    expect(tr.some((e) => e.kind === "tcp.fin.sent")).toBe(false);
    const server = [...host("laptop-1").tcp.conns.values()].find((x) => x.role === "server")!;
    expect(server.state).toBe("ESTABLISHED");
    const bye = act({ kind: "tcp-close", nodeId: id("pc-1"), conn: c.id });
    expect(bye.some((e) => e.kind === "tcp.fin.sent" && e.nodeId === id("pc-1"))).toBe(true);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", reason: "정상 종료" });
    expect(server.state).toBe("CLOSED");
  });

  it("SSH 서버가 없으면 RST 로 거부 (Connection refused)", () => {
    const { id, act, lastConn } = load();
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.12", port: 22 });
    expect(lastConn("pc-1")).toMatchObject({ state: "FAILED", reason: "연결 거부 (RST)" });
  });

  it("세션이 열린 채 서버 케이블이 빠지면 조용한 동안은 모르고, 연결 해제 때 FIN 재전송 끝에 timeout", () => {
    const t = withSshServer();
    const { id, act, apply, lastConn } = load(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.12", port: 22 });
    const lap = id("laptop-1");
    apply({ ...t, cables: t.cables.filter((c) => c.a.device !== lap && c.b.device !== lap) });
    expect(lastConn("pc-1").state).toBe("ESTABLISHED"); // 아무것도 안 보냈으니 모른다
    act({ kind: "tcp-close", nodeId: id("pc-1"), conn: lastConn("pc-1").id });
    expect(lastConn("pc-1")).toMatchObject({ state: "FAILED" });
    expect(lastConn("pc-1").reason).toContain("timeout");
  });

  it("인터넷 서버와 연 세션 도중 이중화가 넘어가면(세션 동기화 없음) 새 master 의 Stateful 검사가 그 흐름을 몰라 응답을 막고, 닫기가 timeout", () => {
    const t = exampleHaTopology();
    const { id, act, apply, lastConn } = load(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "93.184.216.34", port: 22 });
    expect(lastConn("pc-1")).toMatchObject({ state: "ESTABLISHED", ssh: { open: true } });
    const a = id("방화벽 A");
    apply({ ...t, devices: t.devices.filter((d) => d.id !== a), cables: t.cables.filter((c) => c.a.device !== a && c.b.device !== a) });
    const tr = act({ kind: "tcp-close", nodeId: id("pc-1"), conn: lastConn("pc-1").id });
    // FIN 은 방화벽 B 가 새 NAT 매핑으로 내보내지만, 돌아오는 응답은 B 가 모르는 흐름이라 인바운드 차단
    expect(tr.some((e) => e.kind === "nat.translate" && e.nodeId === id("방화벽 B"))).toBe(true);
    expect(tr.some((e) => e.kind === "fw.deny" && e.nodeId === id("방화벽 B"))).toBe(true);
    expect(lastConn("pc-1").state).toBe("FAILED");
    expect(lastConn("pc-1").reason).toContain("timeout");
  });
});
