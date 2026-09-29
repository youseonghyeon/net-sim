// 원격 접속 VPN: 집 공유기 NAT 뒤 노트북이 회사 VPN 방화벽에 붙어 가상 주소를 받고, 사내 대역만 터널로 (split tunnel)
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import { loadTopology } from "./helpers";
import { exampleRemoteVpnTopology } from "../src/model/examples";
import { createDevice, type Device, type Topology } from "../src/model/topology";
import { tcpdumpLine } from "../src/model/packetView";

const load = (t: Topology = exampleRemoteVpnTopology()) => loadTopology(t);

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

  // ---------- 리뷰에서 나온 경우들 ----------
  const patchL3 = (t: Topology, f: (ra: NonNullable<NonNullable<Device["l3"]>["ra"]>) => NonNullable<NonNullable<Device["l3"]>["ra"]>): Topology => ({
    ...t,
    devices: t.devices.map((d) => (d.l3?.ra ? { ...d, l3: { ...d.l3, ra: f(d.l3.ra) } } : d)),
  });
  /** 집 하나를 더 붙인다 (공유기 + 노트북, 노트북은 같은 사설 주소를 받는다) */
  const secondHome = (t: Topology): Topology => {
    const devices = [...t.devices];
    const rt = { ...createDevice("router", 120, 300, devices), name: "집2 공유기" };
    devices.push(rt);
    const lap = { ...createDevice("laptop", 120, 460, devices), name: "재택 노트북 2" };
    lap.host = { ...lap.host!, ra: { enabled: true, server: "203.0.113.11", psk: "remote-psk" } };
    devices.push(lap);
    const isp = t.devices.find((d) => d.name === "통신사 구간")!;
    return { devices, cables: [...t.cables, { id: "h2w", a: { device: isp.id, port: 2 }, b: { device: rt.id, port: 0 } }, { id: "h2l", a: { device: rt.id, port: 1 }, b: { device: lap.id, port: 0 } }] };
  };

  it("리뷰: 사내 대역에 서버 공인 주소가 포함돼도 바깥 패킷을 다시 가로채지 않는다 (무한 재귀 없음)", () => {
    const t = patchL3(exampleRemoteVpnTopology(), (ra) => ({ ...ra, routes: [...ra.routes, { dest: "203.0.113.0", prefix: 24 }] }));
    const { id, host, act } = load(t);
    act({ kind: "ping", nodeId: id("재택 노트북"), dst: "10.50.10.20" });
    expect(host("재택 노트북").pings.at(-1)!.status).toBe("ok");
  });

  it("리뷰: 두 집의 노트북이 같은 사설 주소여도 둘 다 접속한다", () => {
    const { host, l3 } = load(secondHome(exampleRemoteVpnTopology()));
    expect(host("재택 노트북").ra.state).toBe("up");
    expect(host("재택 노트북 2").ra.state).toBe("up");
    expect(host("재택 노트북").iface.ip).toBe(host("재택 노트북 2").iface.ip);
    expect(l3("회사 VPN 방화벽").ra.clients.size).toBe(2);
  });

  it("리뷰: 서버가 터널을 잃으면(설정 변경) 클라이언트가 INVALID_SPI 를 받고 다시 접속해 이어진다", () => {
    const x = load();
    x.apply(patchL3(x.t, (ra) => ({ ...ra, routes: [...ra.routes, { dest: "10.60.0.0", prefix: 24 }] })));
    expect(x.l3("회사 VPN 방화벽").ra.clients.size).toBe(0);
    const tr = x.act({ kind: "ping", nodeId: x.id("재택 노트북"), dst: "10.50.10.20" });
    expect(tr.some((e) => e.summary.includes("INVALID_SPI"))).toBe(true);
    expect(x.host("재택 노트북").ra.state).toBe("up");
    x.act({ kind: "ping", nodeId: x.id("재택 노트북"), dst: "10.50.10.20" });
    expect(x.host("재택 노트북").pings.at(-1)!.status).toBe("ok");
  });

  it("리뷰: 풀이 1개여도 끊은 클라이언트의 주소는 다른 클라이언트가 받을 수 있다", () => {
    const base = patchL3(secondHome(exampleRemoteVpnTopology()), (ra) => ({ ...ra, poolEnd: "10.99.0.10" }));
    const off: Topology = { ...base, devices: base.devices.map((d) => (d.name === "재택 노트북 2" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, enabled: false } } } : d)) };
    const x = load(off);
    expect(x.host("재택 노트북").ra.vip).toBe("10.99.0.10");
    x.apply({ ...off, devices: off.devices.map((d) => (d.name === "재택 노트북" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, enabled: false } } } : d)) });
    x.apply({ ...base, devices: base.devices.map((d) => (d.name === "재택 노트북" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, enabled: false } } } : d)) });
    expect(x.host("재택 노트북 2").ra.vip).toBe("10.99.0.10");
  });

  it("리뷰: 사내 대역이 집 LAN 과 겹쳐도 집 공유기(직접 연결된 서브넷)에는 그대로 닿는다", () => {
    const t = patchL3(exampleRemoteVpnTopology(), (ra) => ({ ...ra, routes: [...ra.routes, { dest: "192.168.0.0", prefix: 16 }] }));
    const { id, host, act } = load(t);
    act({ kind: "ping", nodeId: id("재택 노트북"), dst: "192.168.0.1" });
    expect(host("재택 노트북").pings.at(-1)!.status).toBe("ok");
  });

  it("리뷰: 구성 검사는 잘못된 풀·끝부분만 겹치는 풀을 잡는다", () => {
    const codes = (t: Topology) => lintTopology(t).map((i) => i.code);
    expect(codes(patchL3(exampleRemoteVpnTopology(), (ra) => ({ ...ra, poolStart: "10.99.0.50", poolEnd: "10.99.0.10" })))).toContain("ra.pool-invalid");
    expect(codes(patchL3(exampleRemoteVpnTopology(), (ra) => ({ ...ra, poolStart: "10.49.0.10", poolEnd: "10.50.10.50" })))).toContain("ra.pool-overlap");
  });

  it("리뷰: 연결 해제(INFORMATIONAL)는 tcpdump 에 inf2 로 보인다", () => {
    const f = { kind: "ethernet" as const, id: 1, src: "02:00:00:00:00:01", dst: "02:00:00:00:00:02", payload: { kind: "ipv4" as const, src: "203.0.113.100", dst: "203.0.113.11", ttl: 64, payload: { kind: "udp" as const, srcPort: 4500, dstPort: 4500, payload: { kind: "ike" as const, exchange: "INFORMATIONAL" as const, response: false, spi: 1, ra: true } } } };
    expect(tcpdumpLine(f)).toContain("child_sa  inf2[I]");
  });

  it("리뷰: 실패한 클라이언트는 '다시 연결' 로 붙는다", () => {
    const base = exampleRemoteVpnTopology();
    const off = patchL3(base, (ra) => ({ ...ra, enabled: false }));
    const x = load(off);
    expect(x.host("재택 노트북").ra.state).toBe("failed");
    x.apply(base);
    x.act({ kind: "ra-reconnect", nodeId: x.id("재택 노트북") });
    expect(x.host("재택 노트북").ra.state).toBe("up");
  });
});
