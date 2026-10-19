// SSH 점프 (ssh -J): 점프 서버에 로그인 → 채널 열기(direct-tcpip) → 점프 서버가 대상에 연결해 중계 → 채널 위에서 대상과 SSH
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { builder, cable } from "../src/model/examples/build";
import { DEFAULT_DHCP_SERVER, type Device, type Topology } from "../src/model/topology";
import type { Host } from "../src/core/nodes/host";
import { practitionerLines } from "../src/model/packetView";
import { lintTopology } from "../src/model/lint";
import { EXAMPLES } from "../src/model/examples";
import { separatedJumpTopology as exampleSeparatedRemoteTopology } from "./fixtures";

const patchDev = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });

/** 같은 스위치의 클라이언트(10.0.0.1)·점프 서버(10.0.0.2, SSH + 점프 허용)·대상(10.0.0.3, SSH) */
function lan(opts: { jump?: boolean; targetSsh?: boolean } = {}): Topology {
  const { devices, add } = builder();
  const sw = add("switch", 0, 0, "sw");
  const cli = add("pc", 0, 100, "cli");
  const jmp = add("server", 100, 100, "jump");
  const tgt = add("server", 200, 100, "tgt");
  const h = (ip: string, services: number[] = []) => ({ ipMode: "static" as const, ip, prefix: 24, gateway: "", services, dhcpServer: { ...DEFAULT_DHCP_SERVER } });
  cli.host = h("10.0.0.1");
  jmp.host = { ...h("10.0.0.2", [22]), ...(opts.jump !== false ? { sshJump: true } : {}) };
  tgt.host = h("10.0.0.3", opts.targetSsh === false ? [] : [22]);
  return { devices, cables: [cable(sw, 0, cli, 0), cable(sw, 1, jmp, 0), cable(sw, 2, tgt, 0)] };
}
const appSeq = (tr: { nodeId: string; kind: string }[], L: ReturnType<typeof loadTopology>) =>
  tr.filter((e) => e.kind.startsWith("ssh.")).map((e) => `${L.t.devices.find((d) => d.id === e.nodeId)!.name}:${e.kind}`);

describe("SSH 점프 (ssh -J)", () => {
  it("점프 서버에 로그인 → 채널 열기 → 대상과 SSH. 대상에게 클라이언트는 점프 서버 주소", () => {
    const L = loadTopology(lan());
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "10.0.0.3", port: 22, jump: "10.0.0.2" });
    expect(appSeq(tr, L)).toEqual([
      "cli:ssh.jump", // ssh -J 시작
      "jump:ssh.open", // 점프 서버 로그인
      "cli:ssh.open",
      "jump:ssh.jump", // 채널 요청 수신
      "jump:ssh.jump", // 대상에 연결
      "jump:ssh.jump", // 채널 열림
      "cli:ssh.jump",
      "tgt:ssh.open", // 대상과 SSH
      "cli:ssh.open",
    ]);
    const c = L.lastConn("cli");
    expect(c.state).toBe("ESTABLISHED");
    expect(c.jump).toEqual({ target: "10.0.0.3:22", state: "up" });
    expect(c.ssh?.open).toBe(true);
    const srv = L.serverConns("tgt").at(-1)!;
    expect(srv.remoteIp).toBe("10.0.0.2");
    expect(srv.ssh?.open).toBe(true);
    expect(L.host("jump").jump.rows()[0]!.slice(1)).toEqual(["10.0.0.1", "10.0.0.3:22", "열림"]);
    // 클라이언트 ↔ 점프 서버 구간의 대상 SSH 는 바깥 SSH 로 감싸져 있다
    expect(tr.some((e) => e.nodeId === L.id("jump") && e.kind === "tcp.data.received" && e.summary.includes("바깥 SSH 로 암호화됨 · 안: 키 교환 요청"))).toBe(true);
  });

  it("연결 해제: 클라이언트 FIN → 점프 서버가 대상 연결도 닫고 기록은 닫힘", () => {
    const L = loadTopology(lan());
    L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "10.0.0.3", port: 22, jump: "10.0.0.2" });
    const c = L.lastConn("cli");
    L.act({ kind: "tcp-close", nodeId: L.id("cli"), conn: c.id });
    expect(c.state).toBe("CLOSED");
    expect(L.serverConns("tgt").at(-1)!.state).toBe("CLOSED");
    expect([...L.host("jump").tcp.conns.values()].every((x) => x.state === "CLOSED")).toBe(true);
    expect(L.host("jump").jump.rows()[0]![3]).toBe("닫힘");
  });

  it("점프 서버가 TCP 포워딩을 허용하지 않으면 administratively prohibited", () => {
    const L = loadTopology(lan({ jump: false }));
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "10.0.0.3", port: 22, jump: "10.0.0.2" });
    const c = L.lastConn("cli");
    expect(c.state).toBe("FAILED");
    expect(c.reason).toBe("점프 실패 · administratively prohibited: open failed");
    expect(tr.some((e) => e.nodeId === L.id("tgt") && e.kind.startsWith("tcp."))).toBe(false);
    expect(L.host("jump").jump.rows()[0]![3]).toBe("거절 · administratively prohibited");
    expect([...L.host("jump").tcp.conns.values()].every((x) => x.state === "CLOSED" || x.state === "FAILED")).toBe(true);
  });

  it("대상이 SSH 를 듣지 않으면 connect failed: Connection refused", () => {
    const L = loadTopology(lan({ targetSsh: false }));
    L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "10.0.0.3", port: 22, jump: "10.0.0.2" });
    expect(L.lastConn("cli").reason).toBe("점프 실패 · connect failed: Connection refused");
  });

  it("대상이 답하지 않으면(없는 주소) connect failed: Connection timed out — 클라이언트 timeout 보다 먼저", () => {
    const L = loadTopology(lan());
    L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "10.0.0.9", port: 22, jump: "10.0.0.2" });
    expect(L.lastConn("cli").reason).toBe("점프 실패 · connect failed: Connection timed out");
  });

  it("점프 서버가 SSH(22)를 듣지 않으면 보통 SSH 처럼 연결 거부", () => {
    const t = patchDev(lan(), "jump", (d) => ({ ...d, host: { ...d.host!, services: [] } }));
    const L = loadTopology(t);
    L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "10.0.0.3", port: 22, jump: "10.0.0.2" });
    expect(L.lastConn("cli").reason).toBe("연결 거부 (RST)");
  });

  it("루프백: 대상 = 점프 서버 자신이어도 끝까지 열린다", () => {
    const L = loadTopology(lan());
    L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "10.0.0.2", port: 22, jump: "10.0.0.2" });
    const c = L.lastConn("cli");
    expect(c.state).toBe("ESTABLISHED");
    expect(c.ssh?.open).toBe(true);
    expect(c.jump?.state).toBe("up");
    const self = [...L.host("jump").tcp.conns.values()].filter((x) => x.localIp === "10.0.0.2" && x.remoteIp === "10.0.0.2");
    expect(self.length).toBe(2); // 점프 서버 → 자기 22 (클라이언트 쪽·서버 쪽)
    expect(self.find((x) => x.role === "server")!.ssh?.open).toBe(true);
    L.act({ kind: "tcp-close", nodeId: L.id("cli"), conn: c.id });
    expect([...L.host("jump").tcp.conns.values()].every((x) => x.state === "CLOSED")).toBe(true);
  });

  it("클라이언트가 점프 서버 자신이어도 (ssh -J 자기 자신)", () => {
    const L = loadTopology(lan());
    L.act({ kind: "tcp-connect", nodeId: L.id("jump"), dst: "10.0.0.3", port: 22, jump: "10.0.0.2" });
    const c = [...L.host("jump").tcp.conns.values()].find((x) => x.role === "client" && x.jump)!;
    expect(c.state).toBe("ESTABLISHED");
    expect(c.ssh?.open).toBe(true);
    expect(L.serverConns("tgt").at(-1)!.ssh?.open).toBe(true);
  });

  it("점프 서버 이름을 못 풀면 실패를 남긴다", () => {
    const L = loadTopology(lan());
    L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "10.0.0.3", port: 22, jump: "bastion.corp" });
    const c = L.lastConn("cli");
    expect(c.state).toBe("FAILED");
    expect(c.remoteIp).toBe("bastion.corp");
    void (L.host("cli") as Host);
  });
});

describe("SSH 점프: 실무 출력", () => {
  const lines = (L: ReturnType<typeof loadTopology>, tr: import("../src/core/trace").TraceEvent[]) => tr.filter((e) => e.kind.startsWith("ssh.")).flatMap((e) => practitionerLines(e, {}).map((l) => `${l.tool} | ${l.line}`));
  it("성공: ProxyJump debug, sshd 의 direct-tcpip, 대상 인증은 (via proxy)", () => {
    const L = loadTopology(lan());
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "10.0.0.3", port: 22, jump: "10.0.0.2" });
    expect(lines(L, tr)).toEqual([
      "ssh -v | debug1: Setting implicit ProxyCommand from ProxyJump: ssh -v -W '[%h]:%p' 10.0.0.2",
      "ssh -v | debug1: Executing proxy command: exec ssh -v -W '[10.0.0.3]:22' 10.0.0.2",
      "sshd (auth.log) | Accepted publickey for user from 10.0.0.1 port 49152 ssh2",
      `ssh -v | debug1: Authenticated to 10.0.0.2 ([10.0.0.2]:22) using "publickey".`,
      "sshd -d | debug1: server_input_channel_open: ctype direct-tcpip rchan 2 win 2097152 max 32768",
      "sshd -d | debug1: server_request_direct_tcpip: originator 10.0.0.1 port 49152, target 10.0.0.3 port 22",
      "sshd (auth.log) | Accepted publickey for user from 10.0.0.2 port 49152 ssh2",
      `ssh -v | debug1: Authenticated to 10.0.0.3 (via proxy) using "publickey".`,
    ]);
  });
  it("실패: 점프 서버는 refused local port forward / connect_to failed, 클라이언트는 channel 0: open failed", () => {
    const L = loadTopology(lan({ jump: false }));
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "10.0.0.3", port: 22, jump: "10.0.0.2" });
    const out = lines(L, tr);
    expect(out).toContain("sshd (auth.log) | refused local port forward: originator 10.0.0.1 port 49152, target 10.0.0.3 port 22");
    expect(out).toContain("ssh | channel 0: open failed: administratively prohibited: open failed\nstdio forwarding failed\nkex_exchange_identification: Connection closed by remote host");
    const L2 = loadTopology(lan({ targetSsh: false }));
    const tr2 = L2.act({ kind: "tcp-connect", nodeId: L2.id("cli"), dst: "10.0.0.3", port: 22, jump: "10.0.0.2" });
    expect(lines(L2, tr2)).toContain("sshd (auth.log) | error: connect_to 10.0.0.3 port 22: failed.");
  });
});

describe("SSH 점프: 구성 검사", () => {
  it("ssh.jump-no-sshd: 점프 허용인데 SSH 서버 꺼짐 (켜져 있으면 침묵)", () => {
    expect(lintTopology(lan()).filter((i) => i.code === "ssh.jump-no-sshd")).toEqual([]);
    const off = patchDev(lan(), "jump", (d) => ({ ...d, host: { ...d.host!, services: [] } }));
    expect(lintTopology(off).filter((i) => i.code === "ssh.jump-no-sshd").map((i) => i.message)).toEqual([expect.stringContaining("SSH 점프를 허용했는데 SSH 서버(TCP 22)가 꺼져 있음")]);
  });
});

describe("망분리 사무실 재택 접속 (VPN + 점프 서버, tests/fixtures)", () => {
  const conn = (L: ReturnType<typeof loadTopology>, name: string) => [...L.host(name).tcp.conns.values()].filter((c) => c.role === "client").at(-1)!;
  it("구성 검사 0, 재택 노트북은 VPN 으로 DMZ 경로만 받는다", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    expect(lintTopology(L.t)).toEqual([]);
    expect(L.host("재택 노트북").ra.state).toBe("up");
  });
  it("ssh -J 점프 서버 → 내부망 PC 1: 열린다. 내부망 PC 에게는 점프 서버가 접속, 방화벽 두 개가 각 구간만 들인다", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("재택 노트북"), dst: "10.50.10.1", port: 22, jump: "10.255.1.10" });
    const c = conn(L, "재택 노트북");
    expect(c.state).toBe("ESTABLISHED");
    expect(c.ssh?.open).toBe(true);
    expect(L.serverConns("내부망 PC 1").at(-1)!.remoteIp).toBe("10.255.1.10");
    expect(tr.some((e) => e.nodeId === L.id("DMZ 방화벽") && e.kind === "fw.allow")).toBe(true);
    expect(tr.some((e) => e.nodeId === L.id("내부망 접근통제 방화벽") && e.kind === "fw.allow")).toBe(true);
    expect(tr.some((e) => e.kind === "fw.deny")).toBe(false);
  });
  it("점프 없이 바로: VPN 경로가 아니라 집 인터넷으로 나가 사설 주소라 드롭 (두 망 사이에 길이 없다)", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("재택 노트북"), dst: "10.50.10.1", port: 22 });
    expect(conn(L, "재택 노트북").state).toBe("FAILED");
    expect(tr.some((e) => e.nodeId === L.id("internet-1") && e.kind === "ip.drop")).toBe(true);
  });
  it("외부망 PC 는 DMZ 방화벽이 막고, 바로 가면 인터넷으로 나가 드롭", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("외부망 PC 1"), dst: "10.50.10.1", port: 22, jump: "10.255.1.10" });
    expect(conn(L, "외부망 PC 1").state).toBe("FAILED");
    expect(tr.some((e) => e.nodeId === L.id("DMZ 방화벽") && e.kind === "fw.deny")).toBe(true);
    const tr2 = L.act({ kind: "tcp-connect", nodeId: L.id("외부망 PC 1"), dst: "10.50.10.1", port: 22 });
    expect(tr2.some((e) => e.nodeId === L.id("internet-1") && e.kind === "ip.drop")).toBe(true);
  });
  it("점프 서버에서도 내부망으로는 SSH 만 (ping 은 내부망 접근통제 방화벽이 드롭)", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    const tr = L.act({ kind: "ping", nodeId: L.id("점프 서버"), dst: "10.50.10.1" });
    expect(L.host("점프 서버").pings.at(-1)!.status).not.toBe("ok");
    expect(tr.some((e) => e.nodeId === L.id("내부망 접근통제 방화벽") && e.kind === "fw.deny")).toBe(true);
  });
  it("점프 서버의 SSH 점프 허용을 끄면 administratively prohibited", () => {
    const t = patchDev(exampleSeparatedRemoteTopology(), "점프 서버", (d) => ({ ...d, host: { ...d.host!, sshJump: false } }));
    const L = loadTopology(t);
    L.act({ kind: "tcp-connect", nodeId: L.id("재택 노트북"), dst: "10.50.10.1", port: 22, jump: "10.255.1.10" });
    expect(conn(L, "재택 노트북").reason).toBe("점프 실패 · administratively prohibited: open failed");
  });
  it("내부망 PC 의 NCP 접속은 그대로 (NCP 예제의 IPsec)", () => {
    const L = loadTopology(exampleSeparatedRemoteTopology());
    L.act({ kind: "tcp-connect", nodeId: L.id("내부망 PC 1"), dst: "192.168.112.11", port: 22 });
    expect(conn(L, "내부망 PC 1").ssh?.open).toBe(true);
  });
});

// 리뷰(2026-10-19) 회귀
describe("review: SSH 점프", () => {
  it("이미 만든 서버에서 \"SSH 점프 허용\" 을 켜면 바로 반영된다 (동기화 키에 sshJump)", () => {
    const off = patchDev(lan(), "jump", (d) => ({ ...d, host: { ...d.host!, sshJump: false } }));
    const L = loadTopology(off);
    L.apply(patchDev(L.t, "jump", (d) => ({ ...d, host: { ...d.host!, sshJump: true } })));
    L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "10.0.0.3", port: 22, jump: "10.0.0.2" });
    expect(L.lastConn("cli").ssh?.open).toBe(true);
    expect(L.lastConn("cli").jump?.state).toBe("up");
  });

  it("듀얼 스택 클라이언트가 점프 서버를 이름으로 적어도 A 로 푼다 (AAAA 가 먼저 와도 실패하지 않음)", () => {
    let t = EXAMPLES.dualstack.build();
    t = patchDev(t, "web-1", (d) => ({ ...d, host: { ...d.host!, services: [...new Set([...(d.host!.services ?? []), 22])], sshJump: true } }));
    const L = loadTopology(t);
    const web = L.host("web-1");
    const tgt = L.t.devices.find((d) => d.name !== "web-1" && d.name !== "pc-1" && d.host?.ipMode === "static" && d.host.ip && d.host.ip !== web.ip)!;
    L.act({ kind: "tcp-connect", nodeId: L.id("pc-1"), dst: tgt.host!.ip, port: 22, jump: "web.corp" });
    const c = [...L.host("pc-1").tcp.conns.values()].filter((x) => x.role === "client").at(-1)!;
    expect(c.remoteIp).toBe(web.ip);
    expect(c.jump?.state).not.toBe("login");
  });

  it("IPv6 대상은 점프하지 않고 바로 이유를 남긴다", () => {
    const L = loadTopology(lan());
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "2001:db8::3", port: 22, jump: "10.0.0.2" });
    expect(L.lastConn("cli").reason).toBe("점프 대상은 IPv4 만");
    expect(tr.some((e) => e.kind === "tcp.syn.sent")).toBe(false);
  });

  it("점프 서버 쪽에 대상으로 가는 경로가 없으면(ICMP Net Unreachable) connect failed: No route to host", () => {
    const { devices, add } = builder();
    const sw = add("switch", 0, 0, "sw");
    const cli = add("pc", 0, 100, "cli");
    const jmp = add("server", 100, 100, "jump");
    const gw = add("gateway", 200, 0, "gw");
    const h = (ip: string, services: number[] = []) => ({ ipMode: "static" as const, ip, prefix: 24, gateway: "10.0.0.254", services, dhcpServer: { ...DEFAULT_DHCP_SERVER } });
    cli.host = h("10.0.0.1");
    jmp.host = { ...h("10.0.0.2", [22]), sshJump: true };
    gw.l3 = { interfaces: [{ ipMode: "static", ip: "10.0.0.254", prefix: 24, gateway: "" }, { ipMode: "static", ip: "", prefix: 24, gateway: "" }, { ipMode: "static", ip: "", prefix: 24, gateway: "" }], routes: [] };
    const L = loadTopology({ devices, cables: [cable(sw, 0, cli, 0), cable(sw, 1, jmp, 0), cable(sw, 2, gw, 0)] });
    L.act({ kind: "tcp-connect", nodeId: L.id("cli"), dst: "10.9.9.9", port: 22, jump: "10.0.0.2" });
    expect(L.lastConn("cli").reason).toBe("점프 실패 · connect failed: No route to host");
  });
});
