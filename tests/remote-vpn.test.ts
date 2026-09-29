// 원격 접속 VPN: 집 공유기 NAT 뒤 노트북이 회사 VPN 방화벽에 붙어 가상 주소를 받고, 사내 대역만 터널로 (split tunnel)
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { L3Node } from "../src/core/nodes/l3";
import type { TcpConn } from "../src/core/nodes/tcp";
import type { Ipv4Packet } from "../src/core/packet";
import { lintTopology } from "../src/model/lint";
import { NetworkSync } from "../src/model/netSync";
import { exampleRemoteVpnTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";

function load(t: Topology = exampleRemoteVpnTopology()) {
  const s = new NetworkSync();
  s.sync(t);
  s.net.runToIdle();
  const id = (name: string) => t.devices.find((d) => d.name === name)!.id;
  const host = (name: string) => s.net.nodes.get(id(name)) as Host;
  const l3 = (name: string) => s.net.nodes.get(id(name)) as L3Node;
  const act = (a: Parameters<typeof s.net.scheduleAction>[1]) => {
    const from = s.net.trace.length;
    s.net.scheduleAction(s.net.now, a);
    s.net.runToIdle();
    return s.net.trace.slice(from);
  };
  const apply = (next: Topology) => {
    s.sync(next);
    s.net.runToIdle();
  };
  const lastConn = (name: string): TcpConn => [...host(name).tcp.conns.values()].filter((c) => c.role === "client").at(-1)!;
  const wire = (name: string) => [...s.net.frameLog.values()].flat().filter((x) => x.to === id(name) && x.frame.payload.kind === "ipv4").map((x) => x.frame.payload as Ipv4Packet);
  return { s, t, id, host, l3, act, apply, lastConn, wire };
}

describe("원격 접속 VPN", () => {
  it("노트북이 켜지면서 NAT-T 로 접속해 가상 주소를 받고, 사내 서버에 SSH 가 열린다", () => {
    const { t, id, host, l3, act, lastConn, wire } = load();
    expect(lintTopology(t)).toEqual([]);
    const laptop = host("재택 노트북");
    expect(laptop.ra.state).toBe("up");
    expect(laptop.ra.vip).toBe("10.99.0.10");
    expect(l3("회사 VPN 방화벽").ra.clients.get("10.99.0.10")?.natT).toBe(true);
    act({ kind: "tcp-connect", nodeId: id("재택 노트북"), dst: "10.50.10.20", port: 22 });
    expect(lastConn("재택 노트북")).toMatchObject({ state: "ESTABLISHED", ssh: { open: true } });
    // 사내 서버는 가상 주소에서 온 연결로 본다
    const srvConn = [...host("사내 서버").tcp.conns.values()].find((c) => c.role === "server")!;
    expect(srvConn.remoteIp).toBe("10.99.0.10");
    // 인터넷 구간에는 공인 주소끼리의 UDP 4500 만
    const onWire = wire("통신사 구간");
    expect(onWire.some((p) => p.payload.kind === "udp" && p.payload.payload.kind === "esp")).toBe(true);
    expect(onWire.every((p) => !p.src.startsWith("10.") && !p.dst.startsWith("10."))).toBe(true);
  });

  it("split tunnel: 8.8.8.8 은 터널이 아니라 집 공유기 NAT 로 바로 나간다", () => {
    const { id, host, act } = load();
    const tr = act({ kind: "ping", nodeId: id("재택 노트북"), dst: "8.8.8.8" });
    expect(host("재택 노트북").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "vpn.encap")).toBe(false);
  });

  it("사내 PC 에서 노트북의 가상 주소로 ping 하면 회사 방화벽이 그 클라이언트 터널로 돌려보낸다", () => {
    const { id, host, act } = load();
    const tr = act({ kind: "ping", nodeId: id("사내 PC"), dst: "10.99.0.10" });
    expect(host("사내 PC").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "vpn.encap" && e.nodeId === id("회사 VPN 방화벽"))).toBe(true);
  });

  it("PSK 가 다르면 인증 실패로 끝나고 구성 검사가 지적한다", () => {
    const base = exampleRemoteVpnTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "재택 노트북" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, psk: "wrong" } } } : d)) };
    expect(lintTopology(t).map((i) => i.code)).toContain("ra.psk-mismatch");
    const { host } = load(t);
    expect(host("재택 노트북").ra.state).toBe("failed");
    expect(host("재택 노트북").ra.reason).toContain("AUTHENTICATION_FAILED");
  });

  it("VPN 을 끄면 서버에 Delete 를 알려 터널이 내려가고, 다시 켜면 같은 가상 주소를 받는다", () => {
    const x = load();
    const off: Topology = { ...x.t, devices: x.t.devices.map((d) => (d.name === "재택 노트북" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, enabled: false } } } : d)) };
    x.apply(off);
    expect(x.l3("회사 VPN 방화벽").ra.clients.size).toBe(0);
    x.apply(x.t);
    expect(x.host("재택 노트북").ra.vip).toBe("10.99.0.10");
    x.act({ kind: "ping", nodeId: x.id("재택 노트북"), dst: "10.50.10.20" });
    expect(x.host("재택 노트북").pings.at(-1)!.status).toBe("ok");
  });
});
