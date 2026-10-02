// NAT 종류(RFC 4787 매핑·필터링)와 NAT 통과(STUN·시그널링·홀 펀칭·TURN), 헤어핀 NAT
import { describe, expect, it } from "vitest";
import { NatTable, type NatType } from "../src/core/nodes/nat";
import type { NodeContext } from "../src/core/nodes/node";
import type { Router } from "../src/core/nodes/router";
import type { Ipv4Packet } from "../src/core/packet";
import { exampleNatTraversalTopology, examplePublishTopology } from "../src/model/examples/internet";
import { lintTopology } from "../src/model/lint";
import type { Topology } from "../src/model/topology";
import { loadTopology } from "./helpers";

const ctx = { now: 0, trace: () => {} } as unknown as NodeContext;
const PUB = "203.0.113.9";
const udp = (src: string, srcPort: number, dst: string, dstPort: number): Ipv4Packet => ({
  kind: "ipv4",
  src,
  dst,
  ttl: 64,
  payload: { kind: "udp", srcPort, dstPort, payload: { kind: "stun", op: "binding-request", txid: 1 } },
});

/** 안쪽 192.168.0.10:5000 이 1.1.1.1:3478 로 보낸 뒤, 바깥 세 곳에서 같은 공인 포트로 들어오는 것을 받는지 */
function matrix(type: NatType) {
  const nat = new NatTable();
  nat.type = type;
  const out = nat.translate(udp("192.168.0.10", 5000, "1.1.1.1", 3478), PUB, ctx)!;
  const port = (out.payload as { srcPort: number }).srcPort;
  const inbound = (ip: string, p: number) => nat.restore(udp(ip, p, PUB, port), PUB, ctx) !== undefined;
  const other = nat.translate(udp("192.168.0.10", 5000, "2.2.2.2", 3478), PUB, ctx)!;
  return {
    sameEndpoint: inbound("1.1.1.1", 3478),
    sameIpOtherPort: inbound("1.1.1.1", 9999),
    otherIp: inbound("3.3.3.3", 3478),
    portKeptForNewPeer: (other.payload as { srcPort: number }).srcPort === port,
  };
}

describe("NAT 종류 (매핑·필터링)", () => {
  it("full cone: 매핑이 있으면 누구에게서 오든 들여보낸다", () => {
    expect(matrix("full-cone")).toEqual({ sameEndpoint: true, sameIpOtherPort: true, otherIp: true, portKeptForNewPeer: true });
  });
  it("restricted: 안에서 보낸 적 있는 주소에서만 (포트는 상관없음)", () => {
    expect(matrix("restricted")).toEqual({ sameEndpoint: true, sameIpOtherPort: true, otherIp: false, portKeptForNewPeer: true });
  });
  it("port-restricted: 안에서 보낸 적 있는 주소:포트에서만", () => {
    expect(matrix("port-restricted")).toEqual({ sameEndpoint: true, sameIpOtherPort: false, otherIp: false, portKeptForNewPeer: true });
  });
  it("symmetric: 상대마다 바깥 포트가 바뀌고, 그 상대에게서만 들어온다", () => {
    expect(matrix("symmetric")).toEqual({ sameEndpoint: true, sameIpOtherPort: false, otherIp: false, portKeptForNewPeer: false });
  });
  it("NAT 종류를 바꾸면 동적 매핑을 지운다 (매핑 방식이 달라짐)", () => {
    const nat = new NatTable();
    nat.translate(udp("192.168.0.10", 5000, "1.1.1.1", 3478), PUB, ctx);
    expect(nat.size).toBe(1);
    expect(nat.setType("symmetric")).toBe(1);
    expect(nat.size).toBe(0);
  });
});

const peerSummary = (x: ReturnType<typeof loadTopology>, name: string) => x.host(name).p2p.summary() ?? "";
const setRouter = (t: Topology, name: string, patch: object): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.name === name ? { ...d, router: { ...d.router!, ...patch } } : d)),
});

describe("P2P (STUN·시그널링·홀 펀칭·TURN)", () => {
  it("예제는 구성 검사 이슈가 없고, 세 사람 모두 시그널링 서버에 등록된다", () => {
    const t = exampleNatTraversalTopology();
    expect(lintTopology(t)).toEqual([]);
    const x = loadTopology(t);
    for (const n of ["민수 PC", "현우 PC", "지영 노트북"]) expect(peerSummary(x, n)).toContain("등록됨");
  });

  it("port-restricted 두 집은 홀 펀칭으로 직접 연결된다 (TURN 없음)", () => {
    const x = loadTopology(exampleNatTraversalTopology());
    const tr = x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "hyunwoo" });
    expect(peerSummary(x, "민수 PC")).toContain("hyunwoo 와 연결됨 (직접");
    expect(peerSummary(x, "현우 PC")).toContain("minsu 와 연결됨 (직접");
    expect(tr.some((e) => e.kind === "p2p.relay")).toBe(false);
    // 두 STUN 답의 포트가 같아 cone 으로 짐작
    expect(tr.find((e) => e.nodeId === x.id("민수 PC") && e.kind === "p2p.stun" && (e.details as { nat?: string }).nat)?.details).toMatchObject({ nat: "cone" });
  });

  it("symmetric CGNAT 뒤 상대는 홀 펀칭이 실패하고 TURN 릴레이로 이어진다", () => {
    const x = loadTopology(exampleNatTraversalTopology());
    const tr = x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "jiyoung" });
    expect(tr.find((e) => e.nodeId === x.id("지영 노트북") && e.kind === "p2p.stun" && (e.details as { nat?: string }).nat)?.details).toMatchObject({ nat: "symmetric" });
    expect(tr.some((e) => e.nodeId === x.id("민수 PC") && e.kind === "p2p.relay")).toBe(true);
    // 민수가 STUN 이 알려 준 지영의 바깥 포트로 보낸 펀칭은 CGNAT 가 막는다 (그 포트는 STUN 서버 전용 매핑)
    expect(tr.some((e) => e.nodeId === x.id("통신사 CGNAT") && e.kind === "nat.miss" && (e.details as { filtered?: boolean }).filtered)).toBe(true);
    expect(peerSummary(x, "민수 PC")).toContain("jiyoung 와 연결됨 (TURN 릴레이");
    expect(peerSummary(x, "지영 노트북")).toContain("minsu 와 연결됨 (TURN 릴레이");
  });

  it("집 A 를 full cone 으로 바꾸면 symmetric 상대와도 직접 연결된다", () => {
    const t = exampleNatTraversalTopology();
    const x = loadTopology(t);
    x.apply(setRouter(t, "집 A 공유기", { natType: "full-cone" }));
    x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "jiyoung" });
    expect(peerSummary(x, "민수 PC")).toContain("jiyoung 와 연결됨 (직접");
  });

  it("등록되지 않은 상대에게 연결하면 시그널링 서버가 오류로 답한다", () => {
    const x = loadTopology(exampleNatTraversalTopology());
    const tr = x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "nobody" });
    expect(tr.some((e) => e.kind === "p2p.failed")).toBe(true);
    expect(peerSummary(x, "민수 PC")).toContain("nobody 연결 실패");
  });

  it("P2P 앱이 꺼진 장치에서 연결하면 바로 실패를 기록한다", () => {
    const x = loadTopology(exampleNatTraversalTopology());
    const tr = x.act({ kind: "p2p-connect", nodeId: x.id("집 NAS"), peer: "minsu" });
    expect(tr.map((e) => e.kind).filter((k) => k !== "action")).toEqual(["p2p.failed"]);
  });
});

describe("헤어핀 NAT", () => {
  const wanOf = (x: ReturnType<typeof loadTopology>) => x.node<Router>("집 A 공유기").wan.ip!;

  it("꺼져 있으면 안에서 자기 공인 주소의 포워딩 포트로 접속하면 드롭된다", () => {
    const x = loadTopology(exampleNatTraversalTopology());
    const tr = x.act({ kind: "tcp-connect", nodeId: x.id("민수 PC"), dst: wanOf(x), port: 8080 });
    expect(tr.some((e) => e.kind === "ip.drop" && e.summary.includes("헤어핀 NAT 꺼짐"))).toBe(true);
    expect(x.lastConn("민수 PC").bytesReceived).toBe(0);
    expect(x.serverConns("집 NAS")).toHaveLength(0);
  });

  it("켜면 안쪽 서버로 되돌려 주고, 서버는 공유기 LAN 주소에서 온 연결로 본다 (응답도 공유기를 거침)", () => {
    const t = exampleNatTraversalTopology();
    const x = loadTopology(t);
    x.apply(setRouter(t, "집 A 공유기", { hairpin: true }));
    x.act({ kind: "tcp-connect", nodeId: x.id("민수 PC"), dst: wanOf(x), port: 8080 });
    const c = x.lastConn("민수 PC");
    expect(c.bytesReceived).toBeGreaterThan(0);
    const srv = x.serverConns("집 NAS");
    expect(srv).toHaveLength(1);
    expect(srv[0]!.remoteIp).toBe("192.168.0.1");
  });

  it("바깥에서 오는 포트 포워딩은 헤어핀 설정과 상관없이 그대로 된다", () => {
    const x = loadTopology(exampleNatTraversalTopology());
    x.act({ kind: "tcp-connect", nodeId: x.id("현우 PC"), dst: wanOf(x), port: 8080 });
    expect(x.lastConn("현우 PC").bytesReceived).toBeGreaterThan(0);
  });
});

describe("헤어핀 NAT (NAT 박스)", () => {
  const setL3 = (t: Topology, name: string, patch: object): Topology => ({
    ...t,
    devices: t.devices.map((d) => (d.name === name ? { ...d, l3: { ...d.l3!, ...patch } } : d)),
  });

  it("회사 안 srv-2 가 회사 공인 주소:80 으로 접속: 꺼져 있으면 드롭, 켜면 웹 서버로 (출발지는 NAT 안쪽 주소)", () => {
    const t = examplePublishTopology();
    const x = loadTopology(t);
    const off = x.act({ kind: "tcp-connect", nodeId: x.id("srv-2"), dst: "203.0.113.109", port: 80 });
    expect(off.some((e) => e.nodeId === x.id("회사 NAT") && e.kind === "ip.drop" && e.summary.includes("헤어핀 NAT 꺼짐"))).toBe(true);
    expect(x.serverConns("웹 서버")).toHaveLength(0);

    x.apply(setL3(t, "회사 NAT", { hairpin: true }));
    x.act({ kind: "tcp-connect", nodeId: x.id("srv-2"), dst: "203.0.113.109", port: 80 });
    expect(x.lastConn("srv-2").bytesReceived).toBeGreaterThan(0);
    const srv = x.serverConns("웹 서버");
    expect(srv).toHaveLength(1);
    expect(srv[0]!.remoteIp).toBe("10.10.0.1");
  });
});
