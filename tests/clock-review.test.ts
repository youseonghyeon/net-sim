// 리뷰(8c4fd6c 배경 타이머 + 이중화 주기 광고) 재현 테스트. 실패하는 테스트 = 결함
import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import type { EthernetFrame } from "../src/core/packet";
import type { L3Node } from "../src/core/nodes/l3";
import type { NodeContext, NodeSnapshot, SimNode } from "../src/core/nodes/node";
import { exampleHaTopology } from "../src/model/examples";
import { advanceClock } from "../src/model/simClock";
import type { Device, Topology } from "../src/model/topology";
import { loadTopology } from "./helpers";

const edit = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });
const haSet = (t: Topology, extra: Record<string, unknown>, names = ["방화벽 A", "방화벽 B"]) =>
  names.reduce((x, n) => edit(x, n, (d) => ({ ...d, l3: { ...d.l3!, ha: { ...d.l3!.ha!, ...extra } } })), t);
const advert = (t: Topology, names = ["방화벽 A", "방화벽 B"]) => haSet(t, { advert: true }, names);
const silence = (l: ReturnType<typeof loadTopology>, name: string, loss = 1) => {
  const a = l.id(name);
  for (const c of l.t.cables) if (c.a.device === a || c.b.device === a) l.s.net.setLinkLoss(c.id, loss);
};

describe("리뷰: 이중화 주기 광고", () => {
  it("[1] 말없이 죽었던 master 가 돌아와 되찾으면(backup 이 물러남) 트래픽이 다시 흐른다 — 스위치가 가상 MAC 을 물러난 B 쪽으로 기억하면 블랙홀", () => {
    const l = loadTopology(advert(exampleHaTopology()));
    const { s, act, l3, host, id } = l;
    // 먼저 한 번 통신: pc-1 은 게이트웨이(VIP) ARP 를 기억한다 (60초)
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("ok");
    silence(l, "방화벽 A");
    s.net.runUntil(s.net.now + 10_000);
    expect(l3("방화벽 B").ha.state).toBe("master"); // B 가 Gratuitous ARP → 스위치는 가상 MAC 을 B 쪽 포트로 배움
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("ok");
    // A 복구: A 의 주기 광고를 들은 B 가 물러난다. A 는 자신이 계속 master 였다고 보므로 Gratuitous ARP 를 다시 보내지 않는다
    silence(l, "방화벽 A", 0);
    s.net.runUntil(s.net.now + 5_000);
    expect(l3("방화벽 A").ha.state).toBe("master");
    expect(l3("방화벽 B").ha.state).toBe("backup");
    // 결함: inside 스위치가 가상 MAC 을 여전히 B 쪽 포트로 보내고, B 는 "목적지 MAC 이 내 MAC 아님 → 드롭" (pc-1 의 ARP 캐시가 만료될 60초까지)
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("[1b] 같은 뿌리: 주기 광고를 backup 만 켜면(ha.advert-mismatch) 한 번 넘어갔다 물러난 뒤 A 가 master 인데도 LAN 이 끊긴다 (문구는 '오감' 만 경고)", () => {
    const l = loadTopology(advert(exampleHaTopology(), ["방화벽 B"]));
    const { s, act, l3, host, id } = l;
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("ok");
    const from = s.net.trace.length;
    s.net.runUntil(s.net.now + 5_000);
    expect(s.net.trace.slice(from).some((e) => e.kind === "ha.master" && e.nodeId === id("방화벽 B"))).toBe(true);
    expect(l3("방화벽 A").ha.state).toBe("master");
    expect(l3("방화벽 B").ha.state).toBe("backup");
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("[2] 세션 동기화 + 주기 광고: B 가 이어받은 동안 연 세션도, 말없이 죽었던 A 가 돌아와 되찾을 때 A 에 복사돼 있어야 한다 (preempt 때 전체 복사와 같은 기대)", () => {
    const l = loadTopology(haSet(exampleHaTopology(), { advert: true, sync: true }));
    const { s, act, l3, id, lastConn } = l;
    silence(l, "방화벽 A");
    s.net.runUntil(s.net.now + 10_000);
    expect(l3("방화벽 B").ha.state).toBe("master");
    act({ kind: "tcp-connect", nodeId: id("pc-2"), dst: "93.184.216.34", port: 22 });
    expect(lastConn("pc-2")).toMatchObject({ state: "ESTABLISHED", ssh: { open: true } });
    const onB = l3("방화벽 B").nat!.values().filter((e) => e.lanIp === "192.168.0.11" && e.proto === "tcp");
    expect(onB).toHaveLength(1);
    silence(l, "방화벽 A", 0);
    s.net.runUntil(s.net.now + 5_000);
    expect(l3("방화벽 A").ha.state).toBe("master");
    const onA = l3("방화벽 A").nat!.values().filter((e) => e.lanIp === "192.168.0.11" && e.proto === "tcp");
    expect(onA.map((e) => e.publicId)).toEqual(onB.map((e) => e.publicId));
  });

  it("[3] 물러난 backup 은 새 master 의 첫 광고 전에도 Master_Down 감시가 돈다 — 되찾으러 온 A 가 master 가 된 직후 말없이 죽어도 B 가 다시 이어받음", () => {
    const base = advert(exampleHaTopology());
    const aId = base.devices.find((d) => d.name === "방화벽 A")!.id;
    const noA: Topology = { ...base, devices: base.devices.filter((d) => d.id !== aId), cables: base.cables.filter((c) => c.a.device !== aId && c.b.device !== aId) };
    const l = loadTopology(noA);
    const { s, l3 } = l;
    expect(l3("방화벽 B").ha.state).toBe("master");
    // A 복귀(되돌리기): 후보 알림 → B 가 물러남(preempt)
    s.sync(base);
    let guard = 0;
    while (l3("방화벽 B").ha.state === "master" && guard++ < 10_000) s.net.step();
    expect(l3("방화벽 B").ha.state).toBe("backup");
    // B 가 물러난 바로 그때 A 가 말없이 죽는다 (A 는 곧 skew 뒤 master 가 되지만 광고는 닿지 않는다)
    const lA = { ...l, t: base, id: (n: string) => base.devices.find((d) => d.name === n)!.id };
    silence(lA, "방화벽 A");
    s.net.runUntil(s.net.now + 20_000);
    expect((s.net.nodes.get(aId) as L3Node).ha.state).toBe("master"); // 말없이 죽은 master
    expect(l3("방화벽 B").ha.state).toBe("master"); // 주기 광고를 켰으니 B 가 알아채야 한다
  });
});

/** 배경 타이머로 프레임을 보내는 장치 (주기 광고 흉내) */
class Beacon implements SimNode {
  readonly type = "host" as const;
  readonly portCount = 1;
  readonly got: number[] = [];
  readonly ticks: number[] = [];
  constructor(readonly id: string) {}
  receive(_port: number, _frame: EthernetFrame, ctx: NodeContext): void {
    this.got.push(ctx.now);
  }
  onTimer(tag: string, _data: unknown, ctx: NodeContext): void {
    if (tag === "tick") this.ticks.push(ctx.now);
    if (tag === "tick" || tag === "send") {
      ctx.send(0, { kind: "ethernet", id: ctx.nextPacketId(), src: "02:00:00:00:00:01", dst: "ff:ff:ff:ff:ff:ff", payload: { kind: "arp", op: "request", senderMac: "02:00:00:00:00:01", senderIp: "10.0.0.1", targetMac: "00:00:00:00:00:00", targetIp: "10.0.0.2" } });
    }
  }
  snapshot(): NodeSnapshot {
    return { id: this.id, type: this.type, label: this.id, info: [], tables: [] };
  }
}
const ctxOf = (net: Network, id: string) => net.contextFor(id);

describe("리뷰: 애니메이션 시계와 배경 타이머", () => {
  it("[4] 다음 일반 이벤트로 점프할 때 그 사이 배경 타이머가 보낸 프레임은 링크 위를 지나가는 모습이 보여야 한다 (한 프레임 안에서 배달까지 끝나면 안 됨)", () => {
    const net = new Network();
    const a = net.addNode(new Beacon("a"));
    const b = net.addNode(new Beacon("b"));
    net.connect("a", 0, "b", 0);
    ctxOf(net, "a").timer(1000, "tick", undefined, true); // 배경: 1초에 광고
    ctxOf(net, "a").timer(5000, "normal"); // 일반: 5초 뒤 timeout 같은 것
    const r = advanceClock(net, 0, 16, 1)!;
    expect(a.ticks).toEqual([1000]);
    // 광고 프레임(1000 → 1010)이 링크 위에 있는 시각에서 멈춰야 애니메이션이 된다
    expect(b.got).toEqual([]);
    expect(net.inFlight(r.time)).toHaveLength(1);
  });

  it("[4b] 실제 흐름(화면 시계, 1x): 말없이 죽은 A 를 두고 ping 을 이어 보내 B 가 이어받을 때, B 의 Gratuitous ARP 가 화면에 한 번도 보이지 않는다", () => {
    const l = loadTopology(advert(exampleHaTopology()));
    const { s, l3, id } = l;
    const net = s.net;
    silence(l, "방화벽 A");
    const seen = new Set<number>();
    let shown = net.now;
    for (let k = 0; k < 10 && l3("방화벽 B").ha.state !== "master"; k++) {
      net.runUntil(Math.max(net.now, Math.ceil(shown)));
      net.scheduleAction(net.now, { kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
      net.runUntil(net.now);
      for (let f = 0; f < 200_000; f++) {
        const r = advanceClock(net, shown, 16, 1);
        if (!r) break;
        shown = r.time;
        for (const tx of net.inFlight(shown)) seen.add(tx.id);
      }
    }
    expect(l3("방화벽 B").ha.state).toBe("master");
    const garp = net.transmissions.filter((tx) => tx.from.node === id("방화벽 B") && tx.frame.payload.kind === "arp" && tx.frame.src === "00:00:5e:00:01:0a");
    expect(garp.length).toBeGreaterThan(0);
    expect(garp.some((tx) => seen.has(tx.id))).toBe(true);
  });
});
