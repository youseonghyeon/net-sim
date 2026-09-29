// UDP 포트 포워딩 (다른 NAT 뒤 DNS 서버), 공유기 DHCP 의 DNS 서버 옵션, 관련 구성 검사
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { lintTopology } from "../src/model/lint";
import { NetworkSync } from "../src/model/netSync";
import { exampleTopology } from "../src/model/examples";
import { createDevice, DEFAULT_DHCP_SERVER, newId, type Cable, type Device, type Topology } from "../src/model/topology";

/** 공인 구간 스위치에 공유기 A·B. A 뒤에 pc(수동, DNS = B 의 공인 주소), B 뒤에 DNS 서버 (UDP 53 포워딩) */
function twoHomes(forward: boolean, dnsOn = true): Topology {
  const devices: Device[] = [];
  const cables: Cable[] = [];
  const add = (kind: Parameters<typeof createDevice>[0], name: string) => {
    const d = createDevice(kind, 0, 0, devices);
    d.name = name;
    devices.push(d);
    return d;
  };
  const link = (a: Device, ap: number, b: Device, bp: number) => cables.push({ id: newId("cable"), a: { device: a.id, port: ap }, b: { device: b.id, port: bp } });
  const pub = add("switch", "공인");
  const rtA = add("router", "rt-a");
  rtA.router = { ...rtA.router!, wan: { ipMode: "static", ip: "203.0.113.10", prefix: 24, gateway: "" } };
  const rtB = add("router", "rt-b");
  rtB.router = { ...rtB.router!, wan: { ipMode: "static", ip: "203.0.113.20", prefix: 24, gateway: "" }, forwards: forward ? [{ publicPort: 53, lanIp: "192.168.0.53", lanPort: 53, proto: "udp" }] : [] };
  const pc = add("pc", "pc-a");
  pc.host = { ...pc.host!, ipMode: "static", ip: "192.168.0.50", prefix: 24, gateway: "192.168.0.1", dns: "203.0.113.20" };
  const dns = add("server", "dns-b");
  dns.host = { ipMode: "static", ip: "192.168.0.53", prefix: 24, gateway: "192.168.0.1", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER }, dnsServer: { enabled: dnsOn, records: [{ name: "home-b.lan", ip: "203.0.113.20" }], upstream: "" } };
  link(pub, 0, rtA, 0);
  link(pub, 1, rtB, 0);
  link(rtA, 1, pc, 0);
  link(rtB, 1, dns, 0);
  return { devices, cables };
}

function run(t: Topology) {
  const s = new NetworkSync();
  s.sync(t);
  s.net.runToIdle();
  const pc = t.devices.find((d) => d.name === "pc-a")!.id;
  s.net.scheduleAction(s.net.now, { kind: "ping", nodeId: pc, dst: "home-b.lan" });
  s.net.runToIdle();
  return { s, rec: (s.net.nodes.get(pc) as Host).pings.at(-1)! };
}

describe("UDP 포트 포워딩", () => {
  it("다른 공유기 뒤의 DNS 서버를 UDP 53 포워딩으로 쓰면 이름이 풀린다", () => {
    const { rec, s } = run(twoHomes(true));
    expect(rec.resolved).toBe("203.0.113.20");
    expect(s.net.trace.some((e) => e.kind === "nat.forward.rule" && e.summary.includes("UDP :53"))).toBe(true);
  });

  it("규칙이 없으면 공유기가 받지 않아 이름 풀이가 실패한다", () => {
    const { rec } = run(twoHomes(false));
    expect(rec.status).toBe("failed");
    expect(rec.resolved).toBeUndefined();
  });
});

describe("구성 검사", () => {
  it("nat.forward-closed: 포워딩 대상이 그 포트를 열지 않으면 경고, 켜면 사라진다", () => {
    const off = twoHomes(true, false);
    const rtB = off.devices.find((d) => d.name === "rt-b")!;
    const issue = lintTopology(off).find((i) => i.deviceId === rtB.id && i.code === "nat.forward-closed")!;
    expect(issue.message).toContain("UDP :53 → 192.168.0.53:53");
    expect(lintTopology(twoHomes(true, true)).some((i) => i.code === "nat.forward-closed")).toBe(false);
    // TCP 443 → 웹 서버(80 만) 도 잡는다
    const base = exampleTopology();
    const tcp: Topology = { ...base, devices: base.devices.map((d) => (d.kind === "router" ? { ...d, router: { ...d.router!, forwards: [{ publicPort: 443, lanIp: "192.168.0.20", lanPort: 443 }] } } : d)) };
    expect(lintTopology(tcp).find((i) => i.code === "nat.forward-closed")!.message).toContain("열린 것: TCP 80");
  });

  it("router.dns-off: DHCP 가 공유기 자신을 DNS 로 안내하는데 포워더가 꺼지면 경고, DNS 칸을 채우면 사라진다", () => {
    const base = exampleTopology();
    const off: Topology = { ...base, devices: base.devices.map((d) => (d.kind === "router" ? { ...d, router: { ...d.router!, dns: { enabled: false, upstream: "8.8.8.8" } } } : d)) };
    expect(lintTopology(off).map((i) => i.code)).toContain("router.dns-off");
    const fixed: Topology = { ...off, devices: off.devices.map((d) => (d.kind === "router" ? { ...d, router: { ...d.router!, dhcp: { ...d.router!.dhcp, dns: "8.8.8.8" } } } : d)) };
    expect(lintTopology(fixed).map((i) => i.code)).not.toContain("router.dns-off");
  });
});

describe("공유기 DHCP 의 DNS 서버 옵션", () => {
  it("DNS 칸을 8.8.8.8 로 두면 호스트가 공유기를 거치지 않고 8.8.8.8 에 직접 묻는다", () => {
    const base = exampleTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.kind === "router" ? { ...d, router: { ...d.router!, dhcp: { ...d.router!.dhcp, dns: "8.8.8.8" } } } : d)) };
    const s = new NetworkSync();
    s.sync(t);
    s.net.runToIdle();
    const pc = t.devices.find((d) => d.name === "pc-1")!.id;
    const h = s.net.nodes.get(pc) as Host;
    expect(h.iface.dns).toBe("8.8.8.8");
    s.net.scheduleAction(s.net.now, { kind: "ping", nodeId: pc, dst: "google.com" });
    s.net.runToIdle();
    expect(h.pings.at(-1)!.status).toBe("ok");
    expect(s.net.trace.some((e) => e.nodeId === pc && e.kind === "dns.query.sent" && e.summary.includes("8.8.8.8"))).toBe(true);
  });
});
