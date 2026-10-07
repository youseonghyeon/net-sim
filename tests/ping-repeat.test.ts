// 반복 ping (ping -c N): 1초 간격 송신, 이름은 한 번만 해석, 끝나면 통계(손실률·RTT), 실무 출력
import { describe, expect, it } from "vitest";
import { buildHomeLan } from "../src/core/scenarios/homeLan";
import { singleSubnet } from "../src/core/scenarios/singleSubnet";
import { practitionerLines } from "../src/model/packetView";

function settled() {
  const net = singleSubnet.build();
  net.runToIdle();
  return net;
}
type Net = ReturnType<typeof settled>;
const ping = (net: Net, nodeId: string, dst: string, count?: number) => {
  const from = net.trace.length;
  net.scheduleAction(net.now, { kind: "ping", nodeId, dst, ...(count !== undefined ? { count } : {}) });
  net.runToIdle();
  return net.trace.slice(from);
};
const linkOf = (net: Net, node: string) => [...net.links.values()].find((l) => l.a.node === node || l.b.node === node)!.id;

describe("반복 ping (ping -c N)", () => {
  it("1초 간격으로 4번 보내고, 마지막 응답 뒤에 통계를 남긴다", () => {
    const net = settled();
    const t0 = net.now;
    const tr = ping(net, "h1", "10.0.0.2", 4);
    expect(tr[0]!.summary).toBe("[사용자] ping -c 4 10.0.0.2");
    const sent = tr.filter((e) => e.nodeId === "h1" && e.kind === "icmp.echo.sent");
    expect(sent.map((e) => e.time - t0)).toEqual([0, 1000, 2000, 3000]);
    const h1 = net.getHost("h1");
    const run = h1.pingRuns.at(-1)!;
    expect(run).toMatchObject({ dst: "10.0.0.2", count: 4, sent: 4, done: true });
    expect(run.stats).toMatchObject({ transmitted: 4, received: 4, loss: 0, time: 3000 });
    expect(h1.pings.filter((p) => p.run === run.id).map((p) => p.status)).toEqual(["ok", "ok", "ok", "ok"]);
    // 통계는 마지막 응답 줄 뒤에, 한 번만
    const h1Kinds = tr.filter((e) => e.nodeId === "h1").map((e) => e.kind);
    expect(h1Kinds.at(-1)).toBe("icmp.stats");
    expect(h1Kinds.filter((k) => k === "icmp.stats")).toHaveLength(1);
    expect(h1Kinds.lastIndexOf("icmp.reply.received")).toBeLessThan(h1Kinds.indexOf("icmp.stats"));
    expect(tr.at(-1)!.summary).toMatch(/^ping 10\.0\.0\.2 통계: 4개 보냄 → 4개 받음, 패킷 손실 0% · RTT 최소\/평균\/최대 \d+\/[\d.]+\/\d+ms$/);
    expect(net.pendingEvents).toBe(0);
  });

  it("count 가 없거나 1 이면 예전처럼 한 번만, 통계 없음", () => {
    const net = settled();
    const tr = ping(net, "h1", "10.0.0.2");
    expect(tr[0]!.summary).toBe("[사용자] ping 10.0.0.2");
    expect(tr.map((e) => e.kind)).not.toContain("icmp.stats");
    ping(net, "h1", "10.0.0.2", 1);
    expect(net.getHost("h1").pingRuns).toHaveLength(0);
    expect(net.getHost("h1").pings.every((p) => p.run === undefined)).toBe(true);
  });

  it("응답하지 않는 주소는 전부 실패 — 손실 100%, RTT 줄 없음", () => {
    const net = settled();
    const tr = ping(net, "h1", "10.0.0.99", 3);
    const run = net.getHost("h1").pingRuns.at(-1)!;
    expect(run.stats).toMatchObject({ transmitted: 3, received: 0, loss: 100 });
    expect(run.stats!.avg).toBeUndefined();
    expect(tr.at(-1)!.summary).toBe("ping 10.0.0.99 통계: 3개 보냄 → 0개 받음, 패킷 손실 100%");
    expect(net.pendingEvents).toBe(0);
  });

  it("케이블 손실이 있으면 일부만 돌아와 손실률이 보인다", () => {
    const net = settled();
    net.setLinkLoss(linkOf(net, "h2"), 0.3);
    ping(net, "h1", "10.0.0.2", 20);
    const s = net.getHost("h1").pingRuns.at(-1)!.stats!;
    expect(s.transmitted).toBe(20);
    expect(s.received).toBeGreaterThan(0);
    expect(s.received).toBeLessThan(20);
    expect(s.loss).toBeCloseTo(((20 - s.received) / 20) * 100);
  });

  it("도중에 케이블이 빠지면 남은 요청은 실패하고 통계에 손실로 잡힌다", () => {
    const net = settled();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "h1", dst: "10.0.0.2", count: 4 });
    net.runUntil(net.now + 1500); // 2번째까지 보냄
    net.disconnect(linkOf(net, "h2"));
    net.runToIdle();
    const s = net.getHost("h1").pingRuns.at(-1)!.stats!;
    expect(s).toMatchObject({ transmitted: 4, received: 2, loss: 50 });
    expect(net.pendingEvents).toBe(0);
  });

  it("이름은 처음 한 번만 해석하고 그 주소로 반복한다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    const tr = ping(net as Net, "pc1", "google.com", 3);
    expect(tr.filter((e) => e.nodeId === "pc1" && e.kind === "dns.query.sent")).toHaveLength(1);
    const pc1 = net.getHost("pc1");
    expect(pc1.pings.slice(-3).map((p) => [p.status, p.resolved])).toEqual([
      ["ok", "142.250.196.110"],
      ["ok", "142.250.196.110"],
      ["ok", "142.250.196.110"],
    ]);
    expect(tr.at(-1)!.summary).toContain("ping google.com (142.250.196.110) 통계: 3개 보냄 → 3개 받음");
    // 리눅스 ping 은 통계 머리에 입력한 이름을 그대로 쓴다
    expect(practitionerLines(tr.at(-1)!, {})[0]!.line).toMatch(/^--- google\.com ping statistics ---/);
  });

  it("첫 요청도 못 보내면(이름 해석 실패·IP 미설정) 반복하지 않고 통계도 없다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    const tr = ping(net as Net, "pc1", "nope.example", 4);
    const run = net.getHost("pc1").pingRuns.at(-1)!;
    expect(run).toMatchObject({ done: true, stopped: "없는 이름", sent: 1 });
    expect(tr.map((e) => e.kind)).not.toContain("icmp.echo.sent");
    expect(tr.map((e) => e.kind)).not.toContain("icmp.stats");
    // DHCP 전(IP 없음)
    const net2 = buildHomeLan(true, true);
    const tr2 = ping(net2 as Net, "pc1", "8.8.8.8", 4);
    expect(net2.getHost("pc1").pingRuns.at(-1)).toMatchObject({ done: true, stopped: "IP 미설정" });
    expect(tr2.map((e) => e.kind)).not.toContain("icmp.stats");
    expect(net2.pendingEvents).toBe(0);
  });

  it("도중에 주소를 잃으면 그 요청만 실패하고 반복은 끝까지 간다", () => {
    const net = settled();
    const h1 = net.getHost("h1");
    net.scheduleAction(net.now, { kind: "ping", nodeId: "h1", dst: "10.0.0.2", count: 3 });
    net.runUntil(net.now + 500);
    h1.configure({ ipMode: "static", prefix: 24 }, net.contextFor("h1"));
    net.runToIdle();
    const recs = h1.pings.filter((p) => p.run === h1.pingRuns.at(-1)!.id);
    expect(recs).toHaveLength(3);
    expect(recs.slice(1).map((p) => p.reason)).toEqual(["IP 미설정", "IP 미설정"]);
    expect(h1.pingRuns.at(-1)!.stats).toMatchObject({ transmitted: 3, received: 1 });
  });

  it("횟수는 1~100 정수로 자르고, 동작 기록에도 실제 횟수를 적는다", () => {
    const net = settled();
    const tr = ping(net, "h1", "10.0.0.2", 1000);
    expect(tr[0]!.summary).toBe("[사용자] ping -c 100 10.0.0.2");
    expect(net.getHost("h1").pingRuns.at(-1)!.stats!.transmitted).toBe(100);
    expect(ping(net, "h1", "10.0.0.2", 2.5)[0]!.summary).toBe("[사용자] ping -c 2 10.0.0.2");
    expect(ping(net, "h1", "10.0.0.2", 1.5)[0]!.summary).toBe("[사용자] ping 10.0.0.2");
    expect(ping(net, "h1", "10.0.0.2", Number.NaN)[0]!.summary).toBe("[사용자] ping 10.0.0.2");
  });

  it("실행이 보관 수(5)보다 많이 겹쳐도 모두 끝까지 보내고 통계를 남긴다", () => {
    const net = settled();
    const from = net.trace.length;
    for (let i = 0; i < 6; i++) net.scheduleAction(net.now, { kind: "ping", nodeId: "h1", dst: "10.0.0.2", count: 4 });
    net.runToIdle();
    const stats = net.trace.slice(from).filter((e) => e.kind === "icmp.stats");
    expect(stats).toHaveLength(6);
    expect(stats.every((e) => e.details?.transmitted === 4 && e.details?.received === 4)).toBe(true);
    // 끝난 실행은 다음 실행을 시작할 때 정리돼 보관 수로 돌아간다
    expect(net.getHost("h1").pingRuns).toHaveLength(6);
    ping(net, "h1", "10.0.0.2", 2);
    expect(net.getHost("h1").pingRuns).toHaveLength(5);
  });

  it("IPv6 출발지가 없어 첫 요청도 못 보내면 반복하지 않는다", () => {
    const net = settled();
    const tr = ping(net, "h1", "2001:db8::9", 4);
    expect(net.getHost("h1").pingRuns.at(-1)).toMatchObject({ done: true, stopped: "IPv6 꺼짐", sent: 1 });
    expect(tr.map((e) => e.kind)).not.toContain("icmp.stats");
    expect(net.pendingEvents).toBe(0);
  });
});

describe("반복 ping: 실무 출력 (리눅스 ping 통계)", () => {
  const ev = (details: Record<string, string | number | boolean>) => ({ seq: 0, time: 0, nodeId: "h1", kind: "icmp.stats" as const, layer: "app" as const, summary: "", details });
  it("손실·RTT", () => {
    expect(practitionerLines(ev({ dst: "8.8.8.8", transmitted: 4, received: 3, loss: 25, time: 3000, min: 20, avg: 25, max: 30, mdev: 4.08248 }), {})).toEqual([
      { tool: "ping", line: "--- 8.8.8.8 ping statistics ---\n4 packets transmitted, 3 received, 25% packet loss, time 3000ms\nrtt min/avg/max/mdev = 20.000/25.000/30.000/4.082 ms" },
    ]);
  });
  it("전부 손실이면 RTT 줄이 없다", () => {
    expect(practitionerLines(ev({ dst: "10.0.0.99", transmitted: 3, received: 0, loss: 100, time: 2000 }), {})[0]!.line).toBe("--- 10.0.0.99 ping statistics ---\n3 packets transmitted, 0 received, 100% packet loss, time 2000ms");
  });
});
