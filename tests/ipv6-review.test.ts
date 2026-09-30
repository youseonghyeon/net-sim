// IPv6 1단계 리뷰(clean context)가 찾은 결함의 회귀 테스트. "F*" 는 고친 결함, "OK*" 는 확인했더니 괜찮았던 것.
import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { Host } from "../src/core/nodes/host";
import { L3Node } from "../src/core/nodes/l3";
import { Switch } from "../src/core/nodes/switch";
import { exampleIpv6BasicsTopology, exampleRipTopology, exampleTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import { probeTargets } from "../src/model/reach";
import { cloneDevices, type Device, type Topology } from "../src/model/topology";
import { loadTopology } from "./helpers";

const PC = "02:00:00:00:00:0a";
const SRV = "02:00:00:00:00:0b";

function host(id: string, mac: string, ip6?: string, gw?: string, extra: Partial<ConstructorParameters<typeof Host>[0]> = {}) {
  return new Host({ id, mac, ipMode: "static", ipv6: { enabled: true, addrs: ip6 ? [{ ip: ip6, prefix: 64 }] : [], gateway: gw }, ...extra });
}

/** 듀얼 스택: pc(10.0.1.10 / 2001:db8:1::10) ─ sw1 ─ gw ─ sw2 ─ srv(10.0.2.10 / 2001:db8:2::10) */
function twoLans() {
  const net = new Network();
  net.addNode(new Switch("sw1", 4));
  net.addNode(new Switch("sw2", 4));
  net.addNode(
    new L3Node({
      id: "gw",
      kind: "gateway",
      interfaces: [
        { name: "if0", mac: "02:00:00:10:00:01", mode: "static" },
        { name: "if1", mac: "02:00:00:11:00:01", mode: "static", ip: "10.0.1.1", prefix: 24 },
        { name: "if2", mac: "02:00:00:12:00:01", mode: "static", ip: "10.0.2.1", prefix: 24 },
      ],
      ipv6: { enabled: true, interfaces: [{}, { ip: "2001:db8:1::1", prefix: 64 }, { ip: "2001:db8:2::1", prefix: 64 }], routes: [] },
    }),
  );
  net.addNode(host("pc", PC, "2001:db8:1::10", "2001:db8:1::1", { ip: "10.0.1.10", prefix: 24, gateway: "10.0.1.1" }));
  net.addNode(host("srv", SRV, "2001:db8:2::10", "2001:db8:2::1", { ip: "10.0.2.10", prefix: 24, gateway: "10.0.2.1" }));
  const pcLink = net.connect("pc", 0, "sw1", 0);
  net.connect("gw", 1, "sw1", 1);
  net.connect("gw", 2, "sw2", 1);
  net.connect("srv", 0, "sw2", 0);
  net.runToIdle();
  return { net, pcLink };
}

const upd = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(structuredClone(d)) : d)) });

describe("F1 게이트웨이 IPv6 프리픽스에 소수 (number 입력에 64.5) — 화면이 죽지 않는다", () => {
  const withFrac = (t: Topology) =>
    upd(t, "gw-1", (d) => ({ ...d, l3: { ...d.l3!, ipv6: { ...d.l3!.ipv6!, interfaces: d.l3!.ipv6!.interfaces.map((f, i) => (i === 1 ? { ...f, prefix: 64.5 } : f)) } } }));
  it("구성 검사(lintIssues computed)가 던지지 않는다", () => {
    expect(() => lintTopology(withFrac(exampleIpv6BasicsTopology()))).not.toThrow();
  });
  it("동기화(setIpv6)가 던지지 않는다", () => {
    const t = exampleIpv6BasicsTopology();
    const env = loadTopology(t);
    expect(() => env.apply(withFrac(t))).not.toThrow();
  });
});

describe("F2 서로 동시에 NS 를 보낼 때 NA 하나를 잃어도 대기열이 남지 않는다", () => {
  it("B 의 NA 만 손실 → A 는 B 의 NS 로 배워 보내고, 61초 뒤 ping 도 NS 로 다시 찾는다", () => {
    const net = new Network();
    net.addNode(new Switch("sw", 4));
    net.addNode(host("a", PC, "2001:db8:1::10"));
    net.addNode(host("b", SRV, "2001:db8:1::20"));
    const la = net.connect("a", 0, "sw", 0);
    net.connect("b", 0, "sw", 1);
    net.runToIdle();
    const a = net.getHost("a");
    const t0 = net.now;
    net.scheduleAction(t0, { kind: "ping", nodeId: "a", dst: "2001:db8:1::20" });
    net.scheduleAction(t0, { kind: "ping", nodeId: "b", dst: "2001:db8:1::10" });
    // a─sw 링크: a 의 NS(t0) → b 의 NS(+10) → a 의 NA(+20) → b 의 NA(+30). 마지막 것만 잃게 한다
    net.runUntil(t0 + 25);
    net.dropNextOn(la.id);
    net.runToIdle();
    const leaked = a.v6.pending.has("2001:db8:1::20");
    net.runUntil(net.now + 61_000); // 이웃 캐시 만료
    const from = net.trace.length;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "a", dst: "2001:db8:1::20" });
    net.runToIdle();
    const nsSent = net.trace.slice(from).filter((e) => e.nodeId === "a" && e.kind === "ndp.ns.sent").length;
    expect({ leaked, nsSent, second: a.pings.at(-1)!.status }).toEqual({ leaked: false, nsSent: 1, second: "ok" });
  });
});

describe("F3 IPv4 주소 변경은 IPv6 traceroute 를 끊지 않는다", () => {
  it("IPv4 만 바꾸면 진행 중인 traceroute6 는 그대로", () => {
    const { net } = twoLans();
    net.scheduleAction(net.now, { kind: "traceroute", nodeId: "pc", dst: "2001:db8:2::99" });
    net.runUntil(net.now + 50);
    const pc = net.getHost("pc");
    pc.configure({ ipMode: "static", ip: "10.0.1.11", prefix: 24, gateway: "10.0.1.1" }, net.contextFor("pc"));
    const tr = pc.traceroutes.at(-1)!;
    expect({ status: tr.status, reason: tr.reason }).toEqual({ status: "running", reason: undefined });
  });
});

describe("F4 케이블을 뺀 호스트의 IPv6 실패 문구", () => {
  it("'DAD 로 확인하는 중' 이 아니라 링크 다운을 알린다", () => {
    const { net, pcLink } = twoLans();
    net.disconnect(pcLink.id);
    net.runToIdle();
    const from = net.trace.length;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc", dst: "2001:db8:2::10" });
    net.runToIdle();
    const why = net.trace.slice(from).find((e) => e.nodeId === "pc" && e.kind === "ip.no-address")!.summary;
    expect(why).toContain("링크 다운");
    expect(why).not.toContain("확인하는 중");
  });
});

describe("F5 같은 주소로 서버 교체 (새 MAC): 요청하지 않은 NA 로 알린다", () => {
  it("IPv4 는 Gratuitous ARP, IPv6 는 DAD 뒤 NA 로 게이트웨이 이웃 캐시가 바로 고쳐진다", () => {
    const { net } = twoLans();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc", dst: "2001:db8:2::10" });
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc", dst: "10.0.2.10" });
    net.runToIdle();
    net.removeNode("srv");
    net.runToIdle();
    net.addNode(host("srv2", "02:00:00:00:00:0d", "2001:db8:2::10", "2001:db8:2::1", { ip: "10.0.2.10", prefix: 24, gateway: "10.0.2.1" }));
    net.connect("srv2", 0, "sw2", 0);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc", dst: "10.0.2.10" });
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc", dst: "2001:db8:2::10" });
    net.runToIdle();
    const [v4, v6] = net.getHost("pc").pings.slice(-2);
    expect({ v4: v4!.status, v6: v6!.status }).toEqual({ v4: "ok", v6: "ok" });
  });
});

describe("F6 TCP 를 멀티캐스트(ff02::1)로", () => {
  it("연결을 시작하지 않고, 멀티캐스트로 온 SYN 은 버린다 (RFC 1122)", () => {
    const { net } = twoLans();
    net.addNode(host("c", "02:00:00:00:00:0c", "2001:db8:1::30", undefined, { services: [80] }));
    net.connect("c", 0, "sw1", 2);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "pc", dst: "ff02::1", port: 80 });
    net.runToIdle();
    const serverConns = [...net.getHost("c").tcp.conns.values()].filter((x) => x.role === "server");
    const client = [...net.getHost("pc").tcp.conns.values()].at(-1)!;
    expect({ serverConns: serverConns.length, client: client.state }).toEqual({ serverConns: 0, client: "FAILED" });
  });
});

describe("F7 동시 DAD (예제·JSON 을 불러와 같은 주소 두 장치가 동시에 링크 업)", () => {
  it("둘 다 포기하고, 로그는 '이미 쓰는 주소' 가 아니라 '동시에 확인 중' 이라고 한다", () => {
    const net = new Network();
    net.addNode(new Switch("sw", 4));
    net.addNode(host("a", PC, "2001:db8:1::10"));
    net.addNode(host("b", SRV, "2001:db8:1::10"));
    net.connect("a", 0, "sw", 0);
    net.connect("b", 0, "sw", 1);
    net.runToIdle();
    const states = ["a", "b"].map((id) => net.getHost(id).v6.addrs.find((x) => x.ip === "2001:db8:1::10")!.state);
    expect(states).toEqual(["duplicate", "duplicate"]); // RFC 4862 대로 둘 다 포기 — 이건 맞다
    const fails = net.trace.filter((e) => e.kind === "ndp.dad.fail").map((e) => e.summary);
    expect(fails.filter((s) => s.includes("이미"))).toEqual([]); // 아무도 쓰고 있지 않았다
  });
});

describe("F8 구성 검사 ipv6.duplicate 는 이어진 망 안에서만 본다", () => {
  it("IPv6 예제를 통째로 복사해 옆에 둔 두 실습은 IPv4 처럼 조용", () => {
    const run = (t: Topology) => {
      const c = cloneDevices(t, t.devices.map((d) => d.id), { x: 1000, y: 0 });
      return lintTopology({ ...t, devices: [...t.devices, ...c.devices], cables: [...t.cables, ...c.cables] }).map((i) => i.code);
    };
    expect(run(exampleTopology())).toEqual([]);
    expect(run(exampleIpv6BasicsTopology()).filter((c) => c === "ipv6.duplicate")).toEqual([]);
  });
});

describe("F9 ff02::1 로 ping: 두 번째 응답부터는 추가 응답(DUP)", () => {
  it("보낸 적 있는 seq 의 추가 응답(DUP)을 '보낸 적 없음' 이라 하지 않는다", () => {
    const { net } = twoLans();
    net.addNode(host("c", "02:00:00:00:00:0c", "2001:db8:1::30"));
    net.connect("c", 0, "sw1", 2);
    net.runToIdle();
    const from = net.trace.length;
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc", dst: "ff02::1" });
    net.runToIdle();
    const wrong = net.trace.slice(from).filter((e) => e.nodeId === "pc" && e.summary.includes("내가 보낸 적 없는"));
    expect(wrong.map((e) => e.summary)).toEqual([]);
  });
});

describe("F10 IPv6 ping 실패 이유는 Hop Limit 초과", () => {
  it("::/0 이 서로를 가리키는 두 게이트웨이 → 이유는 Hop Limit", () => {
    const net = new Network();
    for (const s of ["sw1", "sw3"]) net.addNode(new Switch(s, 4));
    const mk = (id: string, n: number, a0: string, a1: string, via: string) =>
      new L3Node({
        id,
        kind: "gateway",
        interfaces: [
          { name: "if0", mac: `02:00:00:10:00:0${n}`, mode: "static" },
          { name: "if1", mac: `02:00:00:11:00:0${n}`, mode: "static" },
        ],
        ipv6: { enabled: true, interfaces: [{ ip: a0, prefix: 64 }, { ip: a1, prefix: 64 }], routes: [{ dest: "::", prefix: 0, via }] },
      });
    net.addNode(mk("g1", 1, "2001:db8:12::1", "2001:db8:1::1", "2001:db8:12::2"));
    net.addNode(mk("g2", 2, "2001:db8:12::2", "2001:db8:2::1", "2001:db8:12::1"));
    net.addNode(host("pc", PC, "2001:db8:1::10", "2001:db8:1::1"));
    net.connect("pc", 0, "sw1", 0);
    net.connect("g1", 1, "sw1", 1);
    net.connect("g1", 0, "sw3", 0);
    net.connect("g2", 0, "sw3", 1);
    net.runToIdle();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pc", dst: "2001:db8:99::1" });
    net.runToIdle(100_000);
    expect(net.getHost("pc").pings.at(-1)!.reason).toContain("Hop Limit");
  });
});

// ---------- 확인했더니 괜찮았던 것 ----------

describe("OK 확인한 것", () => {
  it("TCP 루프백: 내 글로벌·링크 로컬 주소로 연결 (LESSONS 4h·4k 점검 항목)", () => {
    for (const which of ["global", "ll"] as const) {
      const { net } = twoLans();
      const srv = net.getHost("srv");
      srv.setServices([80], net.contextFor("srv"));
      net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: "srv", dst: which === "global" ? "2001:db8:2::10" : srv.v6.linkLocal, port: 80 });
      net.runToIdle();
      const c = [...srv.tcp.conns.values()].filter((x) => x.role === "client").at(-1)!;
      expect({ state: c.state, got: c.bytesReceived > 0 }).toEqual({ state: "CLOSED", got: true });
    }
  });

  it("DAD 중 링크 다운 → 다시 업: 옛 DAD 타이머가 새 DAD 를 일찍 끝내지 않음", () => {
    const net = new Network();
    net.addNode(new Switch("sw", 4));
    net.addNode(host("a", PC, "2001:db8:1::10"));
    const l = net.connect("a", 0, "sw", 0);
    net.runUntil(net.now + 500);
    net.disconnect(l.id);
    net.runUntil(net.now + 100);
    net.connect("a", 0, "sw", 0);
    const upAt = net.now;
    net.runToIdle();
    const pass = net.trace.filter((e) => e.nodeId === "a" && e.kind === "ndp.dad" && e.details?.ok === true);
    expect(pass.map((e) => e.time - upAt)).toEqual([1000, 1000]);
  });

  it("호스트: IPv6 만 바꾸면 IPv4 로그 없음, IPv4 만 바꾸면 DAD 다시 안 함", () => {
    const t = exampleTopology();
    const env = loadTopology(t);
    const h = t.devices.find((d) => d.host && d.host.ipMode === "static")!;
    const t2 = upd(t, h.name, (d) => ({ ...d, host: { ...d.host!, ipv6: { enabled: true, mode: "static", ip: "2001:db8:1::99", prefix: 64, gateway: "" } } }));
    const tr2 = env.apply(t2).filter((e) => e.nodeId === h.id && e.kind === "ip.config");
    expect(tr2.every((e) => e.summary.includes("IPv6"))).toBe(true);
    const t3 = upd(t2, h.name, (d) => ({ ...d, host: { ...d.host!, ip: "192.168.0.123" } }));
    const tr3 = env.apply(t3).filter((e) => e.nodeId === h.id && e.kind.startsWith("ndp"));
    expect(tr3).toEqual([]);
  });

  it("게이트웨이의 IPv6 만 바꿀 때 나오는 HA·VPN·RIP 로그는 기존 동작 (방화벽만 바꿔도 같음)", () => {
    const t = exampleRipTopology();
    const gwName = t.devices.find((d) => d.kind === "gateway")!.name;
    const keep = (e: { kind: string }) => ["ha.config", "vpn.config", "rip.response"].includes(e.kind);
    const a = loadTopology(t).apply(upd(t, gwName, (d) => ({ ...d, l3: { ...d.l3!, ipv6: { enabled: true, interfaces: [], routes: [] } } }))).filter(keep).length;
    const b = loadTopology(t).apply(upd(t, gwName, (d) => ({ ...d, l3: { ...d.l3!, firewall: { enabled: false, defaultPolicy: "deny", stateful: true, rules: [] } } }))).filter(keep).length;
    expect(a).toBe(b);
  });

  it("진단 자동완성: IPv6 만 쓰는 pc-1 도 후보를 받는다", () => {
    const t = exampleIpv6BasicsTopology();
    const r = probeTargets(t, t.devices.find((d) => d.name === "pc-1")!.id, "ping");
    expect(r.candidates.every((c) => c.ok && c.group === "ipv6")).toBe(true);
    expect(r.candidates.length).toBe(4);
  });
});
