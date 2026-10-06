// Tor(7acbb0b) 리뷰(clean context)가 찾은 결함의 재현 테스트. 각 it 은 고친 뒤의 기대 동작을 단언한다 (지금은 실패).
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleDualStackHomeTopology, exampleTorTopology } from "../src/model/examples";
import { TorClient } from "../src/core/nodes/tor";
import { builder, cable } from "../src/model/examples/build";
import { hashCode } from "../src/core/nodes/host";
import { TorNetwork } from "../src/core/nodes/tor";
import type { Router } from "../src/core/nodes/router";
import type { Internet } from "../src/core/nodes/internet";
import type { NodeContext } from "../src/core/nodes/node";
import type { Ipv4Packet, TorCell } from "../src/core/packet";
import { createDevice, type Device, type Topology } from "../src/model/topology";

const BRUME = "Brume 3 (Tor)";
const FRIEND = "친구네 공유기";

function patchRouter(t: Topology, name: string, patch: object): Topology {
  return { ...t, devices: t.devices.map((d) => (d.name === name ? { ...d, router: { ...d.router!, ...patch } } : d)) };
}

describe("Tor 리뷰", () => {
  it("Tor 를 켜면 LAN 의 IPv6 도 밖으로 바로 나가지 않는다 (실제 IPv6 주소가 새지 않게)", () => {
    const base = exampleDualStackHomeTopology();
    const rt = base.devices.find((d) => d.kind === "router")!;
    const L = loadTopology(patchRouter(base, rt.name, { tor: true }));
    const pc = base.devices.find((d) => d.kind === "pc")!;
    expect(L.node<Router>(rt.name).tor.up).toBe(true);
    // 공인 IPv6 의 웹 서버 (인터넷 노드가 TCP 80 에 답함)
    const tr = L.act({ kind: "tcp-connect", nodeId: pc.id, dst: "2606:4700:4700::1111", port: 80 });
    // 실제: handleLan6 이 Tor 를 보지 않고 "라우팅(IPv6) … NAT 없이 출발지 … 가 그대로 인터넷에 보인다" 로 WAN 에 내보냄 → 연결 성공
    expect(tr.some((e) => e.nodeId === rt.id && e.kind === "ip.forward" && e.summary.includes("라우팅(IPv6)") && e.summary.includes("wan"))).toBe(false);
    // 이름으로 접속해도: DNS 는 Tor 로 가지만 AAAA 답을 받아 IPv6 로 직접 접속 (실제: remoteIp 2606:2800:…, 응답 3000B)
    L.act({ kind: "tcp-connect", nodeId: pc.id, dst: "example.com", port: 80 });
    const c = [...L.host(pc.name).tcp.conns.values()].at(-1)!;
    expect(c.remoteIp.includes(":") && c.state === "CLOSED").toBe(false);
  });

  it("Tor 를 켜도 포트 포워딩으로 들어온 연결의 응답은 공유기 공인 주소로 돌아간다 (Tor 로 새지 않음)", () => {
    // 친구네 공유기(포트 포워딩 80 → 친구 웹 서버)에 Tor 를 켬
    const L = loadTopology(patchRouter(exampleTorTopology(), FRIEND, { tor: true }));
    expect(L.node<Router>(FRIEND).tor.up).toBe(true);
    const tr = L.act({ kind: "inet-connect", nodeId: L.id("internet-1"), dst: "203.0.113.50", port: 80 });
    // 실제: 웹 서버의 SYN·ACK 가 lanToWan → forwardToWan → Tor 회로로 → 출구 198.51.100.133 에서 나가 인터넷 클라이언트가 모르는 연결
    expect(tr.some((e) => e.nodeId === L.id(FRIEND) && e.kind === "tor.relay" && e.summary.includes("세 겹 감싸"))).toBe(false);
    const inet = L.node<Internet>("internet-1");
    const client = [...inet.tcp.conns.values()].filter((c) => c.role === "client").at(-1)!;
    expect(client.state).toBe("CLOSED");
    expect(client.bytesReceived).toBeGreaterThan(0);
  });

  it("두 공유기가 같은 회로 번호를 골라도 서로의 회로를 지우지 않는다 (가드는 회로를 보낸 곳마다 따로 기억)", () => {
    // 회로 번호 = abs(hash(`${id}:tor`)) % 0x7fff + 1 — 같은 번호가 나오는 두 id 를 찾는다
    const circOf = (id: string) => (Math.abs(hashCode(`${id}:tor`)) % 0x7fff) + 1;
    const seen = new Map<number, string>();
    let pair: [string, string] | undefined;
    for (let i = 0; !pair; i++) {
      const id = `rt-${i}`;
      const c = circOf(id);
      if (seen.has(c)) pair = [seen.get(c)!, id];
      else seen.set(c, id);
    }
    const { devices, add } = builder();
    const inet = add("internet", 344, -296, "internet-1");
    const isp = add("switch", 344, -168, "통신사 구간");
    const mk = (id: string, name: string, x: number): [Device, Device] => {
      const r = add("router", x, -24, name);
      r.id = id;
      r.router = { ...r.router!, tor: true };
      const lap = add("laptop", x, 152, `${name} 노트북`);
      return [r, lap];
    };
    const [ra, la] = mk(pair[0], "A", 120);
    const [rb, lb] = mk(pair[1], "B", 568);
    const t: Topology = { devices, cables: [cable(isp, 3, inet, 0), cable(isp, 1, ra, 0), cable(isp, 6, rb, 0), cable(ra, 1, la, 0), cable(rb, 1, lb, 0)] };
    const L = loadTopology(t);
    expect(L.node<Router>("A").tor.circ).toBe(L.node<Router>("B").tor.circ);
    // A 가 Tor 를 끔 → DESTROY(circ) → 가드는 그 번호의 회로를 지운다 (B 의 회로이기도 함)
    L.apply(patchRouter(t, "A", { tor: false }));
    const tr = L.act({ kind: "tcp-connect", nodeId: lb.id, dst: "example.com", port: 80 });
    expect(L.lastConn("B 노트북").state).toBe("CLOSED");
    // 실제: "Tor 가드: 모르는 회로 … → DESTROY" — B 의 첫 질의·SYN 이 버려지고 회로를 다시 만든다
    expect(tr.some((e) => e.summary.includes("모르는 회로"))).toBe(false);
  });

  it("출구 포트가 한 바퀴 돌아도 열려 있는 흐름의 응답이 다른 흐름의 공유기로 가지 않는다", () => {
    const sent: { to: string; m: TorCell }[] = [];
    const net = new TorNetwork({ toClient: (to, m) => sent.push({ to: to.ip, m }), deliver: () => {} });
    const ctx = { now: 0, trace: () => {} } as unknown as NodeContext;
    const cell = (src: string, sport: number): TorCell => ({
      kind: "tor",
      op: "data",
      circ: 7,
      layers: 3,
      inner: { kind: "ipv4", src, dst: "93.184.216.34", ttl: 63, payload: { kind: "tcp", srcPort: sport, dstPort: 80 } } as unknown as Ipv4Packet,
    });
    const outer = { kind: "ipv4", src: "203.0.113.100", dst: "198.51.100.131", ttl: 64 } as unknown as Ipv4Packet;
    net.handle(outer, 50000, { kind: "tor", op: "create", circ: 7, layers: 0 }, ctx, 0);
    // 첫 흐름 (계속 열려 있음 — 예: SSH 세션)
    net.handle(outer, 50000, cell("192.168.8.100", 40000), ctx, 0);
    // 다른 흐름 30001개가 지나가 출구 포트가 30000 으로 돌아옴
    // (고친 방식) 끝난 흐름은 출구 포트를 돌려준다 — 다른 흐름 30001개가 열렸다가 RST 로 끝난다
    for (let i = 0; i < 30001; i++) {
      const c = cell("192.168.8.101", 1 + i);
      net.handle(outer, 50000, c, ctx, 0);
      net.handle(outer, 50000, { ...c, inner: { ...c.inner!, payload: { ...(c.inner!.payload as object), rst: true } } as Ipv4Packet }, ctx, 0);
    }
    // 첫 흐름의 상대가 답함 (출구 포트 30000)
    sent.length = 0;
    net.back({ kind: "ipv4", src: "93.184.216.34", dst: "198.51.100.133", ttl: 60, payload: { kind: "tcp", srcPort: 80, dstPort: 30000, seq: 0, ack: 0, len: 0 } } as unknown as Ipv4Packet, ctx);
    // 실제: flows["tcp:30000"] 가 마지막 흐름으로 덮어써져 응답이 192.168.8.101:30001 로 감 (byInner·flows 는 지우지 않아 끝없이 쌓임)
    expect(sent.at(-1)!.m.inner!.dst).toBe("192.168.8.100");
  });

  it("가드가 3번 응답하지 않아 회로를 못 만들면 상태가 '만드는 중' 이 아니라 실패로 보인다", () => {
    // 인터넷 노드 없이 수동 WAN (가드에 닿지 않음)
    const { devices, add } = builder();
    const sw = add("switch", 344, -168, "통신사 구간");
    const r = add("router", 120, -24, "R");
    r.router = { ...r.router!, wan: { ipMode: "static", ip: "203.0.113.20", prefix: 24, gateway: "203.0.113.1" }, tor: true };
    const lap = add("laptop", 120, 152, "노트북");
    const L = loadTopology({ devices, cables: [cable(sw, 1, r, 0), cable(r, 1, lap, 0)] });
    const tr = L.s.net.trace;
    expect(tr.some((e) => e.kind === "tor.drop" && e.summary.includes("회로를 만들지 못함"))).toBe(true);
    // 실제: summary() 는 circ 가 없으면 늘 "회로 만드는 중" (UI 문구·배지 "Tor 대기") — 실패를 숨김
    expect(L.node<Router>("R").tor.summary()).not.toBe("회로 만드는 중");
  });

  it("Tor 를 켜도 공유기 방화벽의 아웃바운드 거부 규칙은 지켜진다", () => {
    const t = patchRouter(exampleTorTopology(), BRUME, {
      firewall: { enabled: true, defaultPolicy: "allow", stateful: true, rules: [{ action: "deny", proto: "tcp", direction: "out", src: "", dst: "203.0.113.50", dstPort: "80" }] },
    });
    const L = loadTopology(t);
    L.act({ kind: "tcp-connect", nodeId: L.id("노트북"), dst: "203.0.113.50", port: 80 });
    // 실제: forwardToWan 이 방화벽 검사 전에 Tor 로 넘겨 거부 규칙을 건너뜀 → 연결 성공
    expect(L.serverConns("친구 웹 서버").length).toBe(0);
  });

  it("인터넷 노드를 바꿔 가드가 회로를 잊어도 첫 이름 해석이 실패하지 않는다 (DESTROY 를 받으면 버린 패킷을 새 회로로)", () => {
    const t = exampleTorTopology();
    const L = loadTopology(t);
    const inet = t.devices.find((d) => d.name === "internet-1")!;
    L.apply({ ...t, devices: t.devices.filter((d) => d !== inet), cables: t.cables.filter((c) => c.a.device !== inet.id && c.b.device !== inet.id) });
    L.apply(t);
    expect(L.node<Router>(BRUME).tor.up).toBe(true);
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("노트북"), dst: "example.com", port: 80 });
    // 실제: 가드 "모르는 회로 → DESTROY", 그 DNS 질의는 버려져 포워더 timeout → SERVFAIL → 연결 실패 (다음 시도부터 됨)
    expect(tr.some((e) => e.summary.includes("모르는 회로"))).toBe(true);
    expect(L.lastConn("노트북").state).toBe("CLOSED");
  });

  it("UDP 53 이라도 DNS 가 아니면 Tor 가 나르지 않는다 (Tor 는 UDP 를 못 나름 — DNS 는 이름 질의만)", () => {
    const io = { wanIp: () => "203.0.113.20", send: () => {} };
    const tor = new TorClient(io, 1, 50000);
    const traces: string[] = [];
    const ctx = { now: 0, trace: (k: string) => traces.push(k), timer: () => {} } as unknown as NodeContext;
    tor.setEnabled(true, ctx);
    tor.handle({ kind: "ipv4", src: "198.51.100.131", dst: "203.0.113.20", ttl: 54 } as unknown as Ipv4Packet, { kind: "tor", op: "created", circ: 2, layers: 0 }, ctx, 0);
    expect(tor.up).toBe(true);
    traces.length = 0;
    // UDP 53 으로 서버를 둔 WireGuard (포털 우회 흔한 수법)
    const wg = { kind: "ipv4", src: "192.168.8.100", dst: "203.0.113.50", ttl: 63, payload: { kind: "udp", srcPort: 40000, dstPort: 53, payload: { kind: "wg", type: "initiation" } } } as unknown as Ipv4Packet;
    tor.sendInner(wg, ctx);
    // 실제: dstPort 53 만 보고 DNS 로 여겨 세 겹 감싸 가드로 (tor.relay) — 출구가 그 UDP 를 목적지에 그대로 내보냄
    expect(traces).toContain("tor.drop");
  });
});
