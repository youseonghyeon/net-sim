// SSH 흉내 (포트 22): 버전 교환 → 키 교환 → 인증 뒤 세션이 열린 채 유지, "연결 해제" 로 FIN 종료.
// 오래 열린 연결이 망 변화에 어떻게 반응하는지: 조용한 동안 경로가 끊겨도 모르고, 닫을 때 알게 된다
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import type { TcpConn } from "../src/core/nodes/tcp";
import { NetworkSync } from "../src/model/netSync";
import { exampleHaTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";
import { L3Node } from "../src/core/nodes/l3";
import { Internet } from "../src/core/nodes/internet";
import { lintTopology } from "../src/model/lint";

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

  it("세션 동기화를 켜면 master 가 NAT 매핑·흐름을 backup 에 복사해 두어, 넘어가도 SSH 세션을 정상으로 닫는다", () => {
    const base = exampleHaTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.l3?.ha ? { ...d, l3: { ...d.l3, ha: { ...d.l3.ha, sync: true } } } : d)) };
    const { id, act, apply, lastConn } = load(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "93.184.216.34", port: 22 });
    expect(tr.some((e) => e.kind === "ha.sync" && e.nodeId === id("방화벽 A"))).toBe(true);
    expect(tr.some((e) => e.kind === "ha.sync" && e.nodeId === id("방화벽 B"))).toBe(true);
    expect(lastConn("pc-1")).toMatchObject({ state: "ESTABLISHED", ssh: { open: true } });
    const a = id("방화벽 A");
    apply({ ...t, devices: t.devices.filter((d) => d.id !== a), cables: t.cables.filter((c) => c.a.device !== a && c.b.device !== a) });
    const bye = act({ kind: "tcp-close", nodeId: id("pc-1"), conn: lastConn("pc-1").id });
    expect(bye.some((e) => e.kind === "fw.deny")).toBe(false);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", reason: "정상 종료" });
  });

  it("세션 동기화: 나중에 켜진 backup 도 master 가 전체 복사(bulk)를 보내 따라잡는다", () => {
    const base = exampleHaTopology();
    const synced: Topology = { ...base, devices: base.devices.map((d) => (d.l3?.ha ? { ...d, l3: { ...d.l3, ha: { ...d.l3.ha, sync: true } } } : d)) };
    const bId = base.devices.find((d) => d.name === "방화벽 B")!.id;
    const noB: Topology = { ...synced, devices: synced.devices.filter((d) => d.id !== bId), cables: synced.cables.filter((c) => c.a.device !== bId && c.b.device !== bId) };
    const { id, act, apply, lastConn } = load(noB);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "93.184.216.34", port: 22 });
    apply(synced); // B 합류 → 후보 알림 → A 가 전체 복사
    const a = id("방화벽 A");
    apply({ ...synced, devices: synced.devices.filter((d) => d.id !== a), cables: synced.cables.filter((c) => c.a.device !== a && c.b.device !== a) });
    act({ kind: "tcp-close", nodeId: id("pc-1"), conn: lastConn("pc-1").id });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", reason: "정상 종료" });
  });

  // ---------- 리뷰에서 나온 경우들 ----------
  const synced = (): Topology => {
    const base = exampleHaTopology();
    return { ...base, devices: base.devices.map((d) => (d.l3?.ha ? { ...d, l3: { ...d.l3, ha: { ...d.l3.ha, sync: true } } } : d)) };
  };
  const without = (t: Topology, name: string): Topology => {
    const id = t.devices.find((d) => d.name === name)!.id;
    return { ...t, devices: t.devices.filter((d) => d.id !== id), cables: t.cables.filter((c) => c.a.device !== id && c.b.device !== id) };
  };

  it("리뷰: B 가 master 인 동안 연 세션도, 우선순위 높은 A 가 돌아와 가져갈 때(preempt) 전체 복사로 이어진다", () => {
    const t = synced();
    const { id, act, apply, lastConn } = load(t);
    apply(without(t, "방화벽 A"));
    act({ kind: "tcp-connect", nodeId: id("pc-2"), dst: "93.184.216.34", port: 22 });
    expect(lastConn("pc-2")).toMatchObject({ state: "ESTABLISHED", ssh: { open: true } });
    apply(t); // A 복귀 → preempt
    act({ kind: "tcp-close", nodeId: id("pc-2"), conn: lastConn("pc-2").id });
    expect(lastConn("pc-2")).toMatchObject({ state: "CLOSED", reason: "정상 종료" });
  });

  it("리뷰: 갈라졌던 동안 양쪽이 같은 공인 id 를 따로 할당해도, 동기화로 덮어쓸 때 옛 연결을 지워 응답이 엉뚱한 호스트로 가지 않는다", () => {
    const t = synced();
    const { s, id, host, act, apply } = load(t);
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    const cutA = { ...t, cables: t.cables.filter((c) => !([c.a.device, c.b.device].includes(id("방화벽 A")) && [c.a.device, c.b.device].includes(id("inside 스위치")))) };
    apply(cutA);
    act({ kind: "ping", nodeId: id("pc-2"), dst: "8.8.8.8" });
    apply(t);
    act({ kind: "ping", nodeId: id("laptop-1"), dst: "8.8.8.8" });
    apply(without(t, "방화벽 A"));
    act({ kind: "ping", nodeId: id("pc-2"), dst: "8.8.8.8" });
    expect(host("pc-2").pings.at(-1)!.status).toBe("ok");
    expect((s.net.nodes.get(id("방화벽 B")) as L3Node).nat).toBeDefined();
  });

  it("리뷰: 자기 주소로 SSH 접속(루프백)도 세션이 열린다", () => {
    const { id, act, lastConn } = load(withSshServer());
    act({ kind: "tcp-connect", nodeId: id("laptop-1"), dst: "192.168.0.12", port: 22 });
    expect(lastConn("laptop-1")).toMatchObject({ state: "ESTABLISHED", ssh: { open: true, step: 6 } });
  });

  it("리뷰: 전체 복사는 같은 순간 한 번만 (VIP 인터페이스마다 후보 알림이 와도)", () => {
    const t = synced();
    const { id, act, apply, s } = load(without(t, "방화벽 B"));
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    const from = s.net.trace.length;
    apply(t);
    const bulks = s.net.trace.slice(from).filter((e) => e.kind === "ha.sync" && e.nodeId === id("방화벽 A") && e.summary.includes("전체 복사"));
    expect(bulks.length).toBe(1);
  });

  it("리뷰: 인터넷에서 포트 포워딩으로 들어온 SSH 세션도 인터넷 쪽에서 연결 해제할 수 있다", () => {
    const base = withSshServer();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.l3?.ha ? { ...d, l3: { ...d.l3, forwards: [{ publicPort: 22, lanIp: "192.168.0.12", lanPort: 22, proto: "tcp" as const }], firewall: { ...d.l3.firewall!, rules: [...d.l3.firewall!.rules, { action: "allow" as const, proto: "tcp" as const, direction: "in" as const, src: "", dst: "192.168.0.12", dstPort: "22" }] } } } : d)) };
    const { s, id, act } = load(t);
    act({ kind: "inet-connect", nodeId: id("internet-1"), dst: "203.0.113.10", port: 22 });
    const inet = s.net.nodes.get(id("internet-1")) as Internet;
    const c = [...inet.tcp.conns.values()].filter((x) => x.localIp === Internet.REMOTE_CLIENT).at(-1)!;
    expect(c).toMatchObject({ state: "ESTABLISHED", ssh: { open: true } });
    act({ kind: "tcp-close", nodeId: id("internet-1"), conn: c.id });
    expect(c.state).toBe("CLOSED");
  });

  it("리뷰: 로드밸런서 포트를 22 로 두면 구성 검사가 경고한다", () => {
    const base = withSshServer();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "laptop-1" ? { ...d, host: { ...d.host!, lb: { enabled: true, port: 22, algorithm: "round-robin" as const, backends: [{ ip: "192.168.0.11", port: 22 }] } } } : d)) };
    expect(lintTopology(t).map((i) => i.code)).toContain("lb.ssh-port");
  });
});
