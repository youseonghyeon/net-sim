// 사이트 간 VPN (WireGuard 식): 캡슐화·복호화, NAT 없이 사설끼리, 인터넷 구간에는 공인 UDP 51820 만, NAT 뒤 상대(엔드포인트 로밍), 끄면 실패
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { L3Node } from "../src/core/nodes/l3";
import { lintTopology } from "../src/model/lint";
import { NetworkSync } from "../src/model/netSync";
import { exampleVpnTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";

function load(t: Topology = exampleVpnTopology()) {
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
  return { t, s, id, host, act };
}

describe("VPN", () => {
  it("구성 검사 이슈 없음, 사설 주소끼리 ping·TCP 가 터널로 닿는다 (NAT 하지 않음)", () => {
    const { t, id, host, act } = load();
    expect(lintTopology(t)).toEqual([]);
    const tr = act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "vpn.encap" && e.nodeId === id("사무실 A NAT"))).toBe(true);
    expect(tr.some((e) => e.kind === "vpn.decap" && e.nodeId === id("사무실 B NAT"))).toBe(true);
    expect(tr.some((e) => e.kind === "nat.translate")).toBe(false);
    act({ kind: "tcp-connect", nodeId: id("pc-b"), dst: "192.168.1.20", port: 80 });
    expect([...host("pc-b").tcp.conns.values()].at(-1)).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
  });

  it("통신사 구간 스위치를 지나는 프레임은 공인 주소끼리의 UDP 51820 이고, 안쪽 원래 패킷은 그 안에 들어 있다", () => {
    const { s, id, act } = load();
    act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    const isp = id("통신사 구간");
    const onWire = [...s.net.frameLog.values()].flat().filter((x) => x.to === isp && x.frame.payload.kind === "ipv4");
    expect(onWire.length).toBeGreaterThan(0);
    for (const x of onWire) {
      const ip = x.frame.payload as import("../src/core/packet").Ipv4Packet;
      expect(ip.src.startsWith("203.0.113.")).toBe(true);
      if (ip.payload.kind === "udp" && ip.payload.payload.kind === "vpn") expect(ip.payload.payload.inner.dst.startsWith("192.168.")).toBe(true);
    }
    expect(onWire.some((x) => x.frame.payload.kind === "ipv4" && x.frame.payload.payload.kind === "udp" && x.frame.payload.payload.dstPort === 51820)).toBe(true);
  });

  it("traceroute: 터널 안에서는 인터넷 구간이 한 홉으로 보인다 (NAT A → NAT B → 목적지)", () => {
    const { id, host, act } = load();
    act({ kind: "traceroute", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").traceroutes.at(-1)!.hops.map((h) => h.ip)).toEqual(["192.168.1.1", "192.168.2.1", "192.168.2.10"]);
  });

  it("한쪽 VPN 을 끄면 사설 주소로는 닿지 않고, 구성 검사가 짝 설정을 경고한다", () => {
    const base = exampleVpnTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "사무실 B NAT" ? { ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, enabled: false } } } : d)) };
    const { id, host, act } = load(t);
    act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").pings.at(-1)!.status).toBe("failed");
    expect(lintTopology(t).map((i) => i.code)).toContain("vpn.peer-off");
  });

  it("상대가 NAT 뒤여도 그쪽이 먼저 보내면 이어진다 (받은 출발지로 답함 — 엔드포인트 로밍)", () => {
    const { s, t, id, host, act } = load();
    // 사무실 B 의 NAT 박스 바깥 주소를 바꿔 A 의 설정(peer .22)과 달라지게 한다 = 중간에 다른 NAT 가 있는 것과 같은 효과
    const moved: Topology = { ...t, devices: t.devices.map((d) => (d.name === "사무실 B NAT" ? { ...d, l3: { ...d.l3!, interfaces: d.l3!.interfaces.map((c, i) => (i === 0 ? { ...c, ip: "203.0.113.99" } : c)) } } : d)) };
    s.sync(moved);
    s.net.runToIdle();
    act({ kind: "ping", nodeId: id("pc-b"), dst: "192.168.1.10" });
    expect(host("pc-b").pings.at(-1)!.status).toBe("ok");
    const a = s.net.nodes.get(id("사무실 A NAT")) as L3Node;
    expect(a.vpn.endpoint?.ip).toBe("203.0.113.99");
    act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").pings.at(-1)!.status).toBe("ok");
  });

  it("상대 대역에서 온 것이 아니면 풀지 않는다 (AllowedIPs)", () => {
    const base = exampleVpnTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "사무실 A NAT" ? { ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, remote: [{ dest: "192.168.9.0", prefix: 24 }] } } } : d)) };
    const { s, id, act } = load(t);
    const tr = act({ kind: "ping", nodeId: id("pc-b"), dst: "192.168.1.10" });
    expect(tr.some((e) => e.kind === "vpn.drop" && e.nodeId === id("사무실 A NAT") && e.summary.includes("허용하지 않은"))).toBe(true);
    expect(s).toBeDefined();
  });
});
