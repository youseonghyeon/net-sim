// 리뷰 재현 테스트 (커밋 72016d5: NAT 종류·P2P·헤어핀 NAT).
// "결함" 묶음의 it 는 지금 코드에서 실패하고 고치면 통과해야 한다. "지켜야 할 것" 묶음은 지금도 통과하는 불변식.
import { describe, expect, it } from "vitest";
import { NatTable } from "../src/core/nodes/nat";
import type { NodeContext } from "../src/core/nodes/node";
import type { Router } from "../src/core/nodes/router";
import type { Ipv4Packet } from "../src/core/packet";
import { exampleNatTraversalTopology, examplePublishTopology } from "../src/model/examples/internet";
import { createDevice, newId, normalizeTopology, type Device, type Topology } from "../src/model/topology";
import { loadTopology } from "./helpers";

const ctx = { now: 0, trace: () => {} } as unknown as NodeContext;
const PUB = "203.0.113.9";
const tcp = (src: string, srcPort: number, dst: string, dstPort: number, syn = false): Ipv4Packet => ({
  kind: "ipv4",
  src,
  dst,
  ttl: 64,
  payload: { kind: "tcp", srcPort, dstPort, seq: 1, ack: 0, len: 0, ...(syn ? { syn: true } : { ackFlag: true }) },
});
const portOf = (p: Ipv4Packet) => (p.payload as { srcPort: number }).srcPort;

type X = ReturnType<typeof loadTopology>;
const summary = (x: X, name: string) => x.host(name).p2p.summary() ?? "";
const patch = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });
const setRouter = (t: Topology, name: string, p: object) => patch(t, name, (d) => ({ ...d, router: { ...d.router!, ...p } }));
const setL3 = (t: Topology, name: string, p: object) => patch(t, name, (d) => ({ ...d, l3: { ...d.l3!, ...p } }));
const setP2p = (t: Topology, name: string, p: { enabled: boolean; name?: string }) => patch(t, name, (d) => ({ ...d, host: { ...d.host!, p2p: p } }));
const cableId = (t: Topology, a: string, b: string) => {
  const ia = t.devices.find((d) => d.name === a)!.id;
  const ib = t.devices.find((d) => d.name === b)!.id;
  return t.cables.find((c) => (c.a.device === ia && c.b.device === ib) || (c.a.device === ib && c.b.device === ia))!.id;
};
/** 예제에 장치 하나를 더하고 케이블로 잇는다 */
function addHost(t: Topology, kind: "pc" | "server", name: string, host: Partial<NonNullable<Device["host"]>>, to: string, toPort: number): Topology {
  const d = createDevice(kind, 0, 300, t.devices);
  d.name = name;
  d.host = { ...d.host!, ...host };
  const target = t.devices.find((x) => x.name === to)!;
  return { ...t, devices: [...t.devices, d], cables: [...t.cables, { id: newId("cable"), a: { device: target.id, port: toPort }, b: { device: d.id, port: 0 } }] };
}
const at = (x: X, dt: number, a: Parameters<X["act"]>[0]) => x.s.net.scheduleAction(x.s.net.now + dt, a);

// ---------------------------------------------------------------------------------------------
describe("결함: symmetric NAT 와 이중화 세션 동기화", () => {
  /** master 에서 만든 매핑을 HA 동기화(bulk 와 같은 필드 — symmetric 이면 상대 dest 까지)로 backup 에 넘긴다 */
  const sync = (master: NatTable, backup: NatTable) => {
    for (const e of master.values()) backup.importEntry({ proto: e.proto, lanIp: e.lanIp, innerId: e.innerId, publicId: e.publicId, dest: e.dest }, 0);
  };

  it("F1 넘겨받은 symmetric 매핑으로 같은 흐름이 같은 공인 포트로 나간다 (안 그러면 넘어간 순간 진행 중인 연결이 끊김)", () => {
    const master = new NatTable();
    const backup = new NatTable();
    master.type = backup.type = "symmetric";
    const out = master.translate(tcp("192.168.0.10", 50000, "8.8.8.8", 443, true), PUB, ctx)!;
    sync(master, backup);
    const after = backup.translate(tcp("192.168.0.10", 50000, "8.8.8.8", 443), PUB, ctx)!;
    expect(portOf(after)).toBe(portOf(out));
  });

  it("F2 같은 안쪽 포트의 symmetric 매핑 두 개(상대가 다름)를 넘겨받으면 둘 다 남는다", () => {
    const master = new NatTable();
    const backup = new NatTable();
    master.type = backup.type = "symmetric";
    master.translate(tcp("192.168.0.10", 50000, "8.8.8.8", 443, true), PUB, ctx);
    master.translate(tcp("192.168.0.10", 50000, "1.1.1.1", 443, true), PUB, ctx);
    expect(master.size).toBe(2);
    sync(master, backup);
    expect(backup.size).toBe(2);
  });
});

// ---------------------------------------------------------------------------------------------
describe("결함: P2P 시그널링·상태", () => {
  it("F3 양쪽이 동시에 연결(glare)해도 symmetric 상대와 TURN 으로 이어진다", () => {
    const x = loadTopology(exampleNatTraversalTopology());
    at(x, 0, { kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "jiyoung" });
    at(x, 0, { kind: "p2p-connect", nodeId: x.id("지영 노트북"), peer: "minsu" });
    x.s.net.runToIdle();
    expect(summary(x, "민수 PC")).toContain("jiyoung 와 연결됨");
    expect(summary(x, "지영 노트북")).toContain("minsu 와 연결됨");
  });

  it("F4 상대 집 공유기의 NAT 종류를 바꾼 뒤에도(매핑이 지워짐) 그 상대에게 연결된다 — 시그널링 등록이 낡음", () => {
    const t = exampleNatTraversalTopology();
    const x = loadTopology(t);
    x.apply(setRouter(t, "집 B 공유기", { natType: "full-cone" }));
    x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "hyunwoo" });
    expect(summary(x, "민수 PC")).toContain("hyunwoo 와 연결됨");
  });

  it("F5 공유기 WAN 이 호스트보다 늦게 인터넷에 닿아도(등록 재시도 3번이 끝난 뒤) 결국 등록된다", () => {
    const full = exampleNatTraversalTopology();
    const cut = { ...full, cables: full.cables.filter((c) => c.id !== cableId(full, "통신사 구간", "집 A 공유기")) };
    const x = loadTopology(cut);
    expect(summary(x, "민수 PC")).toContain("등록 전");
    x.apply(full);
    expect(x.node<Router>("집 A 공유기").wan.ip).toBeTruthy();
    // 앱은 10초마다 배경으로 다시 등록을 시도한다 (시간이 흐를 때 — 화면의 "+10초" 와 같은 흐름)
    x.s.net.runUntil(x.s.net.now + 12_000);
    expect(summary(x, "민수 PC")).toContain("등록됨");
  });

  it("F6 NAT 없이 공인 주소를 쓰는 상대(host 후보만 있음)와 홀 펀칭으로 직접 연결된다 (TURN 불필요)", () => {
    let t = exampleNatTraversalTopology();
    t = addHost(t, "pc", "공인 PC", { ipMode: "static", ip: "203.0.113.77", prefix: 24, gateway: "203.0.113.1", dns: "8.8.8.8", p2p: { enabled: true, name: "pub" } }, "통신사 구간", 5);
    const x = loadTopology(t);
    expect(summary(x, "공인 PC")).toContain("등록됨");
    const tr = x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "pub" });
    expect(tr.some((e) => e.kind === "p2p.relay")).toBe(false);
    expect(summary(x, "민수 PC")).toContain("pub 와 연결됨 (직접");
  });

  it("F7 이름을 바꾼 기기는 옛 이름으로 온 연결 제안에 응하지 않는다 (옛 이름이 시그널링 서버에 남음)", () => {
    const t = exampleNatTraversalTopology();
    const x = loadTopology(t);
    x.apply(setP2p(t, "현우 PC", { enabled: true, name: "hw2" }));
    x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "hyunwoo" });
    expect(x.host("현우 PC").p2p.session).toBeUndefined();
    expect(summary(x, "민수 PC")).toContain("등록돼 있지 않음");
  });

  it("F8 P2P 를 끈 기기는 시그널링 서버에서 빠져, 연결하면 '등록돼 있지 않음' 으로 바로 실패한다", () => {
    const t = exampleNatTraversalTopology();
    const x = loadTopology(t);
    x.apply(setP2p(t, "현우 PC", { enabled: false, name: "hyunwoo" }));
    x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "hyunwoo" });
    expect(summary(x, "민수 PC")).toContain("등록돼 있지 않음");
  });

  it("F9 다른 상대(이미 끝난 시도)에 대한 시그널링 오류가 지금 연결을 실패시키지 않는다", () => {
    const x = loadTopology(exampleNatTraversalTopology());
    // nobody 에게 offer 를 보낸 뒤, 오류가 돌아오기 전에 hyunwoo 로 새로 연결
    const start = x.s.net.now;
    x.s.net.scheduleAction(start, { kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "nobody" });
    let sentOffer = -1;
    for (let i = 0; i < 2000 && sentOffer < 0; i++) {
      x.s.net.step();
      if (x.s.net.trace.some((e) => e.kind === "p2p.signal" && e.summary.includes("nobody") && e.summary.includes("offer"))) sentOffer = x.s.net.now;
    }
    expect(sentOffer).toBeGreaterThan(0);
    x.s.net.scheduleAction(x.s.net.now, { kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "hyunwoo" });
    x.s.net.runToIdle();
    expect(summary(x, "민수 PC")).toContain("hyunwoo 와 연결됨");
  });

  it("F10 이미 연결된 기기에 세 번째 사람이 연결하면, 원래 상대가 끊긴 것을 모른 채 '연결됨' 으로 남지 않는다", () => {
    const x = loadTopology(exampleNatTraversalTopology());
    x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "hyunwoo" });
    expect(summary(x, "민수 PC")).toContain("hyunwoo 와 연결됨");
    x.act({ kind: "p2p-connect", nodeId: x.id("지영 노트북"), peer: "hyunwoo" });
    const hwPeer = x.host("현우 PC").p2p.session?.peer;
    // 현우가 지영과의 세션으로 갈아탔다면, 민수는 여전히 현우와 연결됐다고 보이면 안 된다 (또는 현우가 거절해야 함)
    if (hwPeer !== "minsu") expect(summary(x, "민수 PC")).not.toContain("hyunwoo 와 연결됨");
  });

  it("F11 STUN 요청 하나가 손실돼도 (재전송) 연결된다", () => {
    const t = exampleNatTraversalTopology();
    const x = loadTopology(t);
    x.s.net.dropNextOn(cableId(t, "통신사 구간", "집 A 공유기"));
    const tr = x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "hyunwoo" });
    expect(tr.some((e) => e.kind === "link.loss" || e.summary.includes("손실"))).toBe(true);
    expect(summary(x, "민수 PC")).toContain("hyunwoo 와 연결됨");
  });
});

// ---------------------------------------------------------------------------------------------
describe("결함: 헤어핀 NAT", () => {
  it("F12 NAT 박스: 포트 공개와 헤어핀이 같은 프록시 포트(61000)를 써서 동시 연결 둘이 섞이지 않는다", () => {
    let t = examplePublishTopology();
    t = setL3(t, "회사 NAT", { hairpin: true, publish: [{ port: 8000, bind: "0.0.0.0", to: "192.168.1.2", toPort: 80 }] });
    const x = loadTopology(t);
    at(x, 0, { kind: "tcp-connect", nodeId: x.id("srv-2"), dst: "203.0.113.109", port: 80 }); // 헤어핀
    at(x, 0, { kind: "tcp-connect", nodeId: x.id("srv-3"), dst: "10.10.0.1", port: 8000 }); // 포트 공개
    x.s.net.runToIdle();
    expect(x.lastConn("srv-2").bytesReceived).toBe(3000);
    expect(x.lastConn("srv-3").bytesReceived).toBe(3000);
  });

  it("F13 공유기: 진행 중인 헤어핀 연결은 헤어핀 NAT 를 꺼도 끝까지 이어진다 (포트 공개·conntrack 과 같은 원칙)", () => {
    const t = exampleNatTraversalTopology();
    const on = setRouter(t, "집 A 공유기", { hairpin: true });
    const x = loadTopology(on);
    const wan = x.node<Router>("집 A 공유기").wan.ip!;
    at(x, 0, { kind: "tcp-connect", nodeId: x.id("민수 PC"), dst: wan, port: 8080 });
    // 맺어지고 요청이 오가는 중에 끈다
    x.s.net.runUntil(x.s.net.now + 45);
    expect(x.serverConns("집 NAS").length).toBe(1);
    x.s.sync(setRouter(t, "집 A 공유기", { hairpin: false }));
    x.s.net.runToIdle();
    expect(x.lastConn("민수 PC").bytesReceived).toBe(3000);
  });
});

describe("결함: 헤어핀 NAT 와 방화벽", () => {
  /** NAT 를 켠 게이트웨이: if0 바깥, if1 사무실(10.1.0.0/24), if2 서버(10.2.0.0/24). 방화벽이 사무실 → 서버:80 을 막는다 */
  function office(hairpin: boolean): Topology {
    const devices: Device[] = [];
    const add = (kind: Device["kind"], name: string) => {
      const d = createDevice(kind, 0, 0, devices);
      d.name = name;
      devices.push(d);
      return d;
    };
    const gw = add("gateway", "사내 게이트웨이");
    gw.l3 = {
      interfaces: [
        { ipMode: "static", ip: "203.0.113.50", prefix: 24, gateway: "" },
        { ipMode: "static", ip: "10.1.0.1", prefix: 24, gateway: "" },
        { ipMode: "static", ip: "10.2.0.1", prefix: 24, gateway: "" },
      ],
      routes: [],
      nat: { enabled: true },
      hairpin,
      forwards: [{ publicPort: 80, lanIp: "10.2.0.10", lanPort: 80 }],
      firewall: { enabled: true, defaultPolicy: "allow", stateful: true, rules: [{ action: "deny", proto: "tcp", direction: "any", src: "10.1.0.0/24", dst: "10.2.0.10", dstPort: "80" }] },
    } as unknown as Device["l3"];
    const pc = add("pc", "사무실 PC");
    pc.host = { ...pc.host!, ipMode: "static", ip: "10.1.0.10", prefix: 24, gateway: "10.1.0.1" };
    const srv = add("server", "웹 서버");
    srv.host = { ...srv.host!, ipMode: "static", ip: "10.2.0.10", prefix: 24, gateway: "10.2.0.1", services: [80] };
    const cables = [
      { id: newId("cable"), a: { device: gw.id, port: 1 }, b: { device: pc.id, port: 0 } },
      { id: newId("cable"), a: { device: gw.id, port: 2 }, b: { device: srv.id, port: 0 } },
    ];
    return { devices, cables };
  }

  it("(대조) 사설 주소로 바로 가면 방화벽이 막는다", () => {
    const x = loadTopology(office(true));
    const tr = x.act({ kind: "tcp-connect", nodeId: x.id("사무실 PC"), dst: "10.2.0.10", port: 80 });
    expect(tr.some((e) => e.kind === "fw.deny" && e.nodeId === x.id("사내 게이트웨이"))).toBe(true);
    expect(x.serverConns("웹 서버")).toHaveLength(0);
  });

  it("F14 헤어핀으로 돌아가도(바깥 주소:80) 같은 방화벽 규칙에 막힌다 — 지금은 방화벽을 건너뜀", () => {
    const x = loadTopology(office(true));
    x.act({ kind: "tcp-connect", nodeId: x.id("사무실 PC"), dst: "203.0.113.50", port: 80 });
    expect(x.serverConns("웹 서버")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------------------------
describe("지켜야 할 것 (지금 통과)", () => {
  it("port-restricted 두 집이 동시에 서로 연결(glare)해도 직접 연결된다", () => {
    const x = loadTopology(exampleNatTraversalTopology());
    at(x, 0, { kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "hyunwoo" });
    at(x, 0, { kind: "p2p-connect", nodeId: x.id("현우 PC"), peer: "minsu" });
    x.s.net.runToIdle();
    expect(summary(x, "민수 PC")).toContain("hyunwoo 와 연결됨 (직접");
    expect(summary(x, "현우 PC")).toContain("minsu 와 연결됨 (직접");
  });

  it("헤어핀 자기 자신: 집 NAS 가 공인 주소:8080 (= 자기 80) 으로 접속", () => {
    const t = setRouter(exampleNatTraversalTopology(), "집 A 공유기", { hairpin: true });
    const x = loadTopology(t);
    x.act({ kind: "tcp-connect", nodeId: x.id("집 NAS"), dst: x.node<Router>("집 A 공유기").wan.ip!, port: 8080 });
    expect(x.lastConn("집 NAS").bytesReceived).toBe(3000);
  });

  it("헤어핀 NAT 박스 자기 자신: 웹 서버가 회사 공인 주소:80 (= 자기 80) 으로 접속", () => {
    const x = loadTopology(setL3(examplePublishTopology(), "회사 NAT", { hairpin: true }));
    x.act({ kind: "tcp-connect", nodeId: x.id("웹 서버"), dst: "203.0.113.109", port: 80 });
    expect(x.lastConn("웹 서버").bytesReceived).toBe(3000);
  });

  it("symmetric ↔ symmetric (집 A 도 symmetric) 은 TURN 으로 잇고 runToIdle 이 끝난다", () => {
    const x = loadTopology(setRouter(exampleNatTraversalTopology(), "집 A 공유기", { natType: "symmetric" }));
    x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "jiyoung" });
    expect(summary(x, "민수 PC")).toContain("TURN 릴레이");
  });

  it("symmetric 쪽이 제안해도 TURN 으로 잇는다", () => {
    const x = loadTopology(exampleNatTraversalTopology());
    x.act({ kind: "p2p-connect", nodeId: x.id("지영 노트북"), peer: "minsu" });
    expect(summary(x, "지영 노트북")).toContain("minsu 와 연결됨 (TURN");
  });

  it("같은 공유기 뒤 두 기기는 host 후보로 직접 잇는다", () => {
    let t = exampleNatTraversalTopology();
    t = addHost(t, "pc", "민수 동생 PC", { p2p: { enabled: true, name: "sis" } }, "집 A 공유기", 3);
    const x = loadTopology(t);
    x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "sis" });
    expect(summary(x, "민수 PC")).toContain("sis 와 연결됨 (직접, 192.168.0.");
  });

  it("두 번 연달아 연결해도(앞 시도 진행 중) 마지막 시도로 연결되고 지난 STUN 응답은 무시된다", () => {
    const x = loadTopology(exampleNatTraversalTopology());
    at(x, 0, { kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "jiyoung" });
    at(x, 5, { kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "hyunwoo" });
    x.s.net.runToIdle();
    expect(summary(x, "민수 PC")).toContain("hyunwoo 와 연결됨 (직접");
  });

  it("인터넷이 없으면 등록 3번 뒤 멈추고, 연결하면 바로 실패를 남긴다", () => {
    const full = exampleNatTraversalTopology();
    const inet = full.devices.find((d) => d.kind === "internet")!.id;
    const t = { ...full, devices: full.devices.filter((d) => d.id !== inet), cables: full.cables.filter((c) => c.a.device !== inet && c.b.device !== inet) };
    const x = loadTopology(t);
    const tr = x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: "hyunwoo" });
    expect(tr.some((e) => e.kind === "p2p.failed")).toBe(true);
  });

  it("손실 30% 링크에서도 runToIdle 이 끝난다 (끝없는 타이머 없음)", () => {
    const t = exampleNatTraversalTopology();
    const x = loadTopology(t);
    x.s.net.setLinkLoss(cableId(t, "통신사 구간", "집 A 공유기"), 0.3);
    x.s.net.setLinkLoss(cableId(t, "통신사 구간", "통신사 CGNAT"), 0.3);
    for (const p of ["hyunwoo", "jiyoung", "hyunwoo"]) x.act({ kind: "p2p-connect", nodeId: x.id("민수 PC"), peer: p });
    expect(summary(x, "민수 PC")).toMatch(/연결됨|실패/);
  });

  it("restricted NAT 뒤에서 traceroute 의 중간 홉(다른 출발지) Time Exceeded 가 들어온다", () => {
    const x = loadTopology(setL3(examplePublishTopology(), "집 NAT", { natType: "port-restricted" }));
    x.act({ kind: "traceroute", nodeId: x.id("맥북"), dst: "8.8.8.8" });
    const rec = [...x.host("맥북").traceroutes.values()].at(-1) as unknown as { hops: { ip?: string }[] };
    expect(rec.hops.filter((h) => h.ip).length).toBeGreaterThanOrEqual(3);
  });

  it("normalize: 이상한 natType·hairpin·p2p 는 정리된다", () => {
    const t = exampleNatTraversalTopology();
    const bad = setP2p(setRouter(t, "집 A 공유기", { natType: 5, hairpin: "yes" }), "민수 PC", null as unknown as { enabled: boolean });
    const n = normalizeTopology(JSON.parse(JSON.stringify(bad)) as Topology);
    const r = n.devices.find((d) => d.name === "집 A 공유기")!.router!;
    expect(r.natType).toBeUndefined();
    expect(r.hairpin).toBeUndefined();
    expect(() => loadTopology(n)).not.toThrow();
  });
});
