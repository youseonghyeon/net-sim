// 진단의 DNS 조회 (nslookup): 캐시를 거치지 않고 묻기, 서버 지정, 실패 코드, 실무 출력
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { buildHomeLan } from "../src/core/scenarios/homeLan";
import { exampleAdguardTopology } from "../src/model/examples";
import { practitionerLines } from "../src/model/packetView";
import { loadTopology } from "./helpers";

/** homeLan + DNS 서버 호스트(ns, 192.168.0.53) + 수동 IP 클라이언트(c1) — tests/dns.test.ts 와 같은 구성 */
function build(clientDns = "192.168.0.53") {
  const net = buildHomeLan();
  net.addNode(
    new Host({
      id: "ns",
      mac: "02:00:00:00:00:53",
      ipMode: "static",
      ip: "192.168.0.53",
      prefix: 24,
      gateway: "192.168.0.1",
      dnsServer: { enabled: true, records: [{ name: "srv.local", ip: "192.168.0.50" }] },
    }),
  );
  net.addNode(new Host({ id: "c1", mac: "02:00:00:00:00:c1", ipMode: "static", ip: "192.168.0.60", prefix: 24, gateway: "192.168.0.1", dns: clientDns || undefined }));
  net.connect("ns", 0, "sw", 1);
  net.connect("srv", 0, "sw", 2);
  net.connect("c1", 0, "sw", 3);
  net.runToIdle();
  return net;
}

type Net = ReturnType<typeof build>;
const lookup = (net: Net, nodeId: string, name: string, qtype: "A" | "AAAA" = "A", server?: string) => {
  const from = net.trace.length;
  net.scheduleAction(net.now, { kind: "dns-lookup", nodeId, name, qtype, ...(server !== undefined ? { server } : {}) });
  net.runToIdle();
  return net.trace.slice(from);
};
const seq = (tr: { nodeId: string; kind: string }[]) => tr.map((e) => `${e.nodeId}:${e.kind}`);

describe("DNS 조회 (nslookup)", () => {
  it("설정된 DNS 에 묻고 답을 기록한다 — 캐시에는 넣지 않는다", () => {
    const net = build();
    const tr = lookup(net, "c1", "SRV.local");
    expect(seq(tr).filter((k) => k.includes("dns.") || k.endsWith(":action"))).toEqual(["c1:action", "c1:dns.query.sent", "ns:dns.query.received", "ns:dns.response.sent", "c1:dns.response.received", "c1:dns.lookup"]);
    expect(tr[0]!.summary).toBe("[사용자] nslookup SRV.local");
    const c1 = net.getHost("c1");
    expect(c1.lookups.at(-1)).toMatchObject({ name: "srv.local", qtype: "A", status: "ok", answer: "192.168.0.50", server: "192.168.0.53" });
    expect(c1.resolver.cache.size).toBe(0);
    expect(tr.find((e) => e.kind === "dns.response.received")!.summary).toContain("캐시에 넣지 않음");
    expect(net.pendingEvents).toBe(0);
  });

  it("ping 으로 캐시가 차 있어도 매번 서버에 묻는다", () => {
    const net = build();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: "srv.local" });
    net.runToIdle();
    expect(net.getHost("c1").resolver.cache.get("srv.local")?.ip).toBe("192.168.0.50");
    const tr = lookup(net, "c1", "srv.local");
    expect(tr.map((e) => e.kind)).not.toContain("dns.cache.hit");
    expect(tr.filter((e) => e.nodeId === "c1" && e.kind === "dns.query.sent")).toHaveLength(1);
  });

  it("서버를 지정하면 설정된 DNS 대신 그 서버에만 묻는다", () => {
    const net = build("192.168.0.99"); // 설정된 DNS 는 없는 주소
    const tr = lookup(net, "c1", "srv.local", "A", "192.168.0.53");
    expect(tr[0]!.summary).toBe("[사용자] nslookup srv.local 192.168.0.53");
    expect(tr.find((e) => e.kind === "dns.query.sent")!.summary).toContain("서버 192.168.0.53");
    expect(net.getHost("c1").lookups.at(-1)).toMatchObject({ status: "ok", answer: "192.168.0.50", server: "192.168.0.53" });
    // 비우면 설정된 DNS(192.168.0.99)에 두 번 묻고 timeout
    const tr2 = lookup(net, "c1", "srv.local");
    expect(tr2.filter((e) => e.kind === "dns.query.sent").map((e) => e.details?.server)).toEqual(["192.168.0.99", "192.168.0.99"]);
    expect(net.getHost("c1").lookups.at(-1)).toMatchObject({ status: "failed", reason: "DNS timeout · 응답 없음", server: "192.168.0.99" });
    expect(tr2.at(-1)).toMatchObject({ kind: "dns.lookup.failed", details: { rcode: "timeout" } });
  });

  it("DNS 설정이 없어도 서버를 지정하면 묻는다", () => {
    const net = build("");
    expect(lookup(net, "c1", "srv.local").at(-1)).toMatchObject({ kind: "dns.lookup.failed", details: { reason: "DNS 서버 없음" } });
    lookup(net, "c1", "srv.local", "A", "192.168.0.53");
    expect(net.getHost("c1").lookups.at(-1)).toMatchObject({ status: "ok", answer: "192.168.0.50" });
  });

  it("없는 이름은 NXDOMAIN, 이름은 있지만 그 종류가 없으면 NODATA", () => {
    const net = build();
    expect(lookup(net, "c1", "nope.local").at(-1)).toMatchObject({ kind: "dns.lookup.failed", details: { reason: "없는 이름", rcode: "NXDOMAIN" } });
    const tr = lookup(net, "c1", "srv.local", "AAAA");
    expect(tr[0]!.summary).toBe("[사용자] nslookup -type=AAAA srv.local");
    expect(net.getHost("c1").lookups.at(-1)).toMatchObject({ qtype: "AAAA", status: "failed", reason: "AAAA 레코드 없음" });
    expect(tr.at(-1)!.details?.rcode).toBe("NODATA");
  });

  it("공유기 포워더를 거쳐 공인 이름의 A·AAAA 를 묻는다", () => {
    const net = buildHomeLan(true, true);
    net.connect("pc1", 0, "sw", 1);
    net.runToIdle();
    lookup(net as Net, "pc1", "google.com", "AAAA");
    expect(net.getHost("pc1").lookups.at(-1)).toMatchObject({ status: "ok", answer: "2404:6800:4004:827::200e", server: "192.168.0.1" });
    // 공유기 포워더를 건너뛰고 공인 DNS 에 바로 (UDP NAT 를 거침)
    const tr = lookup(net as Net, "pc1", "example.com", "A", "8.8.8.8");
    expect(seq(tr)).toContain("inet:dns.query.received");
    expect(seq(tr)).not.toContain("rt:dns.forward");
    expect(net.getHost("pc1").lookups.at(-1)).toMatchObject({ status: "ok", answer: "93.184.216.34", server: "8.8.8.8" });
    expect(net.getHost("pc1").resolver.cache.size).toBe(0);
  });

  it("127.0.0.1 은 내 DNS 서버 서비스에 루프백으로 묻는다", () => {
    const net = build();
    const tr = lookup(net, "ns", "srv.local", "A", "127.0.0.1");
    expect(tr.find((e) => e.kind === "dns.query.sent")!.summary).toContain("루프백");
    expect(net.getHost("ns").lookups.at(-1)).toMatchObject({ status: "ok", answer: "192.168.0.50", server: "192.168.0.53" });
  });

  it("잘못된 입력은 묻지 않고 이유를 남긴다", () => {
    const net = build();
    const c1 = net.getHost("c1");
    let tr = lookup(net, "c1", "192.168.0.50");
    expect(c1.lookups.at(-1)!.reason).toContain("역방향 조회(PTR)");
    expect(tr.map((e) => e.kind)).not.toContain("dns.query.sent");
    tr = lookup(net, "c1", "srv local");
    expect(c1.lookups.at(-1)!.reason).toContain("쓸 수 없는 글자");
    tr = lookup(net, "c1", "srv.local", "A", "192.168.0");
    expect(c1.lookups.at(-1)!.reason).toBe("DNS 서버 주소가 올바르지 않음 (192.168.0)");
    expect(tr.map((e) => e.kind)).not.toContain("dns.query.sent");
    // IPv6 서버를 지정했는데 내 IPv6 가 없음
    lookup(net, "c1", "srv.local", "A", "2001:db8::53");
    expect(c1.lookups.at(-1)).toMatchObject({ status: "failed", reason: "IPv6 주소 없음" });
    expect(net.pendingEvents).toBe(0);
  });

  it("기다리는 중 링크가 끊기면 실패로 끝난다", () => {
    const net = build("192.168.0.99");
    net.scheduleAction(net.now, { kind: "dns-lookup", nodeId: "c1", name: "srv.local", qtype: "A" });
    net.runUntil(net.now + 100);
    expect(net.getHost("c1").lookups.at(-1)!.status).toBe("pending");
    const link = [...net.links.values()].find((l) => l.a.node === "c1" || l.b.node === "c1")!;
    net.disconnect(link.id);
    net.runToIdle();
    expect(net.getHost("c1").lookups.at(-1)).toMatchObject({ status: "failed", reason: "링크 다운" });
  });

  it("한 서버의 Unreachable 은 그 서버로 보낸 질의만 끝낸다 (다른 서버를 기다리는 해석은 그대로)", () => {
    const net = build();
    // 10.99.99.99 는 경로가 없어 라우터가 Net Unreachable — 같은 시각에 설정된 DNS 로 가는 ping 이름 해석
    net.scheduleAction(net.now, { kind: "dns-lookup", nodeId: "c1", name: "srv.local", qtype: "A", server: "10.99.99.99" });
    net.scheduleAction(net.now, { kind: "ping", nodeId: "c1", dst: "srv.local" });
    net.runToIdle();
    const c1 = net.getHost("c1");
    expect(c1.pings.at(-1)).toMatchObject({ status: "ok", resolved: "192.168.0.50" });
    expect(c1.lookups.at(-1)!.status).toBe("failed");
    expect(c1.lookups.at(-1)!.reason).toContain("DNS 서버에 닿지 않음");
    expect(net.pendingEvents).toBe(0);
  });

  it("::1 은 내 IPv6 주소의 DNS 서버 서비스에 루프백으로 묻는다", () => {
    const net = buildHomeLan();
    net.addNode(
      new Host({
        id: "ns6",
        mac: "02:00:00:00:00:56",
        ipMode: "static",
        ip: "192.168.0.56",
        prefix: 24,
        ipv6: { enabled: true, addrs: [{ ip: "2001:db8::53", prefix: 64 }] },
        dnsServer: { enabled: true, records: [{ name: "srv.local", ip: "192.168.0.50" }] },
      }),
    );
    net.connect("ns6", 0, "sw", 1);
    net.runToIdle();
    const tr = lookup(net as Net, "ns6", "srv.local", "A", "::1");
    expect(tr.find((e) => e.kind === "dns.query.sent")!.summary).toContain("루프백");
    expect(net.getHost("ns6").lookups.at(-1)).toMatchObject({ status: "ok", answer: "192.168.0.50", server: "2001:db8::53", rtt: 0 });
  });

  it("기록은 최근 5개만 남는다", () => {
    const net = build();
    for (let i = 0; i < 7; i++) lookup(net, "c1", `n${i}.local`);
    expect(net.getHost("c1").lookups.map((r) => r.name)).toEqual(["n2.local", "n3.local", "n4.local", "n5.local", "n6.local"]);
  });
});

describe("DNS 조회: AdGuard 비교", () => {
  it("공유기 DNS 에 물으면 0.0.0.0(막은 이름), 가로채기가 꺼져 있으면 8.8.8.8 에 직접 물어 실제 주소", () => {
    const t = exampleAdguardTopology();
    const L = loadTopology({ ...t, devices: t.devices.map((d) => (d.router?.adguard ? { ...d, router: { ...d.router, adguard: { ...d.router.adguard, forceDns: false } } } : d)) });
    L.act({ kind: "dns-lookup", nodeId: L.id("아빠 PC"), name: "doubleclick.net", qtype: "A" });
    expect(L.host("아빠 PC").lookups.at(-1)).toMatchObject({ status: "ok", answer: "0.0.0.0", blocked: true });
    L.act({ kind: "dns-lookup", nodeId: L.id("아빠 PC"), name: "doubleclick.net", qtype: "A", server: "8.8.8.8" });
    expect(L.host("아빠 PC").lookups.at(-1)).toMatchObject({ status: "ok", answer: "142.250.76.130", server: "8.8.8.8" });
    expect(L.host("아빠 PC").lookups.at(-1)!.blocked).toBeUndefined();
  });

  it("DNS 가로채기가 켜져 있으면 8.8.8.8 에 물어도 공유기가 대신 막는다", () => {
    const L = load();
    const tr = L.act({ kind: "dns-lookup", nodeId: L.id("스마트 TV"), name: "doubleclick.net", qtype: "A", server: "8.8.8.8" });
    expect(L.host("스마트 TV").lookups.at(-1)).toMatchObject({ answer: "0.0.0.0", blocked: true, server: "8.8.8.8" });
    expect(tr.map((e) => e.kind)).toContain("dns.hijack");
  });
});

function load() {
  return loadTopology(exampleAdguardTopology());
}

describe("DNS 조회: 실무 출력 (nslookup)", () => {
  const ev = (kind: "dns.lookup" | "dns.lookup.failed", details: Record<string, string | number | boolean>) => ({ seq: 0, time: 0, nodeId: "c1", kind, layer: "app" as const, summary: "", details });
  it("답", () => {
    expect(practitionerLines(ev("dns.lookup", { name: "example.com", ip: "93.184.216.34", server: "8.8.8.8" }), {})).toEqual([{ tool: "nslookup", line: "Server:\t\t8.8.8.8\nAddress:\t8.8.8.8#53\n\nName:\texample.com\nAddress: 93.184.216.34" }]);
  });
  it("NXDOMAIN·NODATA·timeout", () => {
    expect(practitionerLines(ev("dns.lookup.failed", { name: "nope.example", server: "192.168.0.1", rcode: "NXDOMAIN" }), {})[0]!.line).toBe("Server:\t\t192.168.0.1\nAddress:\t192.168.0.1#53\n\n** server can't find nope.example: NXDOMAIN");
    expect(practitionerLines(ev("dns.lookup.failed", { name: "github.com", server: "192.168.0.1", rcode: "NODATA" }), {})[0]!.line).toContain("*** Can't find github.com: No answer");
    expect(practitionerLines(ev("dns.lookup.failed", { name: "x.local", server: "192.168.0.99", rcode: "timeout" }), {})[0]!.line).toBe(";; connection timed out; no servers could be reached");
    expect(practitionerLines(ev("dns.lookup.failed", { name: "x.local", reason: "DNS 서버 없음" }), {})).toEqual([]);
  });
});
