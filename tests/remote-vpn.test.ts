// 원격 접속 VPN: 집 공유기 NAT 뒤 노트북이 회사 VPN 방화벽에 붙어 가상 주소를 받고, 사내 대역만 터널로 (split tunnel)
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import { loadTopology } from "./helpers";
import { exampleRemoteVpnTopology } from "../src/model/examples";
import { createDevice, parseTopology, serializeTopology, type Device, type RaClientSettings, type RaServerSettings, type Topology } from "../src/model/topology";
import { headerLayers, practitionerLines, tcpdumpLine } from "../src/model/packetView";
import type { TraceEvent } from "../src/core/trace";
import type { IkeMessage } from "../src/core/packet";

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
    lap.host = { ...lap.host!, ra: { enabled: true, server: "203.0.113.11", psk: "remote-psk", user: "lee", password: "lee-pass" } };
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

// ---------- 사용자 계정 인증 (EAP) ----------
const VPN_KINDS = ["vpn.ike", "vpn.eap", "vpn.up", "vpn.drop", "vpn.dpd", "action"];
/** 트레이스를 "장치 이름:종류" 로 (VPN 관련과 사용자 동작만) */
const seqOf = (t: Topology, tr: TraceEvent[]) => tr.filter((e) => VPN_KINDS.includes(e.kind)).map((e) => `${t.devices.find((d) => d.id === e.nodeId)!.name}:${e.kind}`);
const withLaptop = (patch: Partial<RaClientSettings>, t: Topology = exampleRemoteVpnTopology()): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.name === "재택 노트북" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, ...patch } } } : d)),
});
const withServer = (patch: Partial<RaServerSettings>, t: Topology = exampleRemoteVpnTopology()): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.l3?.ra ? { ...d, l3: { ...d.l3, ra: { ...d.l3.ra, ...patch } } } : d)),
});
const codes = (t: Topology) => lintTopology(t).map((i) => i.code);
const LAPTOP = "재택 노트북";
const FW = "회사 VPN 방화벽";
/** 노트북이 보낸 IKE 요청 (회사 방화벽에 도착한 것) */
const ikeFrom = (x: ReturnType<typeof load>) =>
  x.wire(FW).flatMap((p) => (p.payload.kind === "udp" && p.payload.payload.kind === "ike" && !p.payload.payload.response ? [p.payload.payload as IkeMessage] : []));
/** 회사 방화벽 ↔ 통신사 구간 케이블 */
const fwWan = (t: Topology) => {
  const fw = t.devices.find((d) => d.name === FW)!.id;
  const isp = t.devices.find((d) => d.name === "통신사 구간")!.id;
  return t.cables.find((c) => [c.a.device, c.b.device].includes(fw) && [c.a.device, c.b.device].includes(isp))!;
};

describe("원격 접속 VPN — 사용자 계정 인증 (EAP)", () => {
  it("예제: PSK 확인 뒤 EAP 요청 → 비밀번호 응답 → EAP 성공 + 가상 주소, 서버 표·요약에 사용자 이름", () => {
    const x = load();
    expect(lintTopology(x.t)).toEqual([]);
    const tr = x.act({ kind: "ra-reconnect", nodeId: x.id(LAPTOP) });
    expect(seqOf(x.t, tr)).toEqual([
      `${LAPTOP}:action`,
      `${LAPTOP}:vpn.drop`, // 다시 연결 → Delete
      `${LAPTOP}:vpn.ike`, // IKE_SA_INIT
      `${FW}:vpn.drop`, // Delete 받음 → 옛 터널 내림
      `${FW}:vpn.ike`, // IKE_SA_INIT 응답 (NAT 감지)
      `${LAPTOP}:vpn.ike`, // IKE_AUTH: PSK + IDi kim
      `${FW}:vpn.eap`, // PSK 맞음 → EAP 요청 (MSCHAPv2 challenge)
      `${LAPTOP}:vpn.eap`, // EAP 응답 (두 번째 IKE_AUTH)
      `${FW}:vpn.up`, // EAP 성공 + 가상 주소
      `${LAPTOP}:vpn.up`,
    ]);
    expect(x.host(LAPTOP).ra.state).toBe("up");
    // 노트북의 IKE_AUTH 두 번: 첫 번째는 PSK + 사용자 이름, 두 번째는 EAP 응답
    const auths = ikeFrom(x).filter((m) => m.exchange === "IKE_AUTH").slice(-2);
    expect(auths.map((m) => [m.user, m.auth !== undefined, m.eap])).toEqual([
      ["kim", true, undefined],
      ["kim", false, "response"],
    ]);
    const srv = x.l3(FW);
    expect(srv.ra.rows()).toEqual([["kim", "10.99.0.10", expect.stringMatching(/^203\.0\.113\.100:\d+$/), "NAT-T"]]);
    expect(srv.snapshot().info.find(([k]) => k === "원격 접속 VPN 서버")![1]).toContain("접속 1명 (kim 10.99.0.10)");
    x.act({ kind: "ping", nodeId: x.id(LAPTOP), dst: "10.50.10.20" });
    expect(x.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
  });

  it("비밀번호가 틀리면 EAP 실패(AUTHENTICATION_FAILED) — 구성 검사 ra.account-mismatch", () => {
    const t = withLaptop({ password: "wrong" });
    expect(lintTopology(t).find((i) => i.code === "ra.account-mismatch")?.message).toContain("kim 의 비밀번호가");
    const x = load(t);
    const tr = x.act({ kind: "ra-reconnect", nodeId: x.id(LAPTOP) });
    expect(seqOf(t, tr)).toEqual([`${LAPTOP}:action`, `${LAPTOP}:vpn.ike`, `${FW}:vpn.ike`, `${LAPTOP}:vpn.ike`, `${FW}:vpn.eap`, `${LAPTOP}:vpn.eap`, `${FW}:vpn.drop`, `${LAPTOP}:vpn.drop`]);
    expect(tr.find((e) => e.kind === "vpn.drop" && e.nodeId === x.id(FW))!.summary).toContain("kim 의 비밀번호가 다름");
    expect(x.host(LAPTOP).ra.state).toBe("failed");
    expect(x.host(LAPTOP).ra.reason).toContain("계정 또는 비밀번호가 틀림");
    expect(x.l3(FW).ra.clients.size).toBe(0);
  });

  it("서버 목록에 없는 사용자는 EAP 실패 — 서버 로그는 '목록에 없음', 클라이언트에는 같은 AUTHENTICATION_FAILED", () => {
    const t = withLaptop({ user: "park", password: "park-pass" });
    expect(lintTopology(t).find((i) => i.code === "ra.account-mismatch")?.message).toContain("park 가 서버 회사 VPN 방화벽 의 계정 목록에 없음");
    const x = load(t);
    expect(x.s.net.trace.some((e) => e.kind === "vpn.drop" && e.nodeId === x.id(FW) && e.summary.includes("park 가 계정 목록에 없음"))).toBe(true);
    expect(x.host(LAPTOP).ra.state).toBe("failed");
    expect(x.host(LAPTOP).ra.reason).toContain("계정 또는 비밀번호가 틀림");
  });

  it("노트북에 계정이 없으면 EAP 요청을 받고 거기서 멈춘다 (재전송 없음) — 구성 검사 ra.no-account", () => {
    const t = withLaptop({ user: undefined, password: undefined });
    expect(codes(t)).toContain("ra.no-account");
    const x = load(t);
    const tr = x.act({ kind: "ra-reconnect", nodeId: x.id(LAPTOP) });
    expect(seqOf(t, tr)).toEqual([`${LAPTOP}:action`, `${LAPTOP}:vpn.ike`, `${FW}:vpn.ike`, `${LAPTOP}:vpn.ike`, `${FW}:vpn.eap`, `${LAPTOP}:vpn.drop`]);
    expect(x.host(LAPTOP).ra.reason).toContain("계정이 없음");
  });

  it("서버 계정 목록이 비면 지금처럼 PSK 만: EAP 없이 IKE_AUTH 한 번 (노트북에 계정이 남아 있어도)", () => {
    const t = withServer({ users: [] });
    expect(lintTopology(t)).toEqual([]);
    const x = load(t);
    const tr = x.act({ kind: "ra-reconnect", nodeId: x.id(LAPTOP) });
    expect(seqOf(t, tr)).toEqual([`${LAPTOP}:action`, `${LAPTOP}:vpn.drop`, `${LAPTOP}:vpn.ike`, `${FW}:vpn.drop`, `${FW}:vpn.ike`, `${LAPTOP}:vpn.ike`, `${FW}:vpn.up`, `${LAPTOP}:vpn.up`]);
    expect(tr.find((e) => e.kind === "vpn.up" && e.nodeId === x.id(FW))!.summary).toContain("인증 성공 →");
    expect(x.l3(FW).ra.rows()[0]![0]).toBe("-");
    expect(ikeFrom(x).some((m) => m.eap)).toBe(false);
  });

  it("접속 중인 사용자를 목록에서 지워도 세션은 유지되고, 다시 붙을 때 막힌다", () => {
    const x = load();
    const tr = x.apply(withServer({ users: [{ name: "lee", password: "lee-pass" }] }, x.t));
    expect(tr.find((e) => e.kind === "vpn.config" && e.nodeId === x.id(FW))!.summary).toContain("kim 의 세션은 끊지 않음");
    expect(x.l3(FW).ra.clients.size).toBe(1);
    x.act({ kind: "ping", nodeId: x.id(LAPTOP), dst: "10.50.10.20" });
    expect(x.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
    x.act({ kind: "ra-reconnect", nodeId: x.id(LAPTOP) });
    expect(x.host(LAPTOP).ra.state).toBe("failed");
    expect(x.host(LAPTOP).ra.reason).toContain("계정 또는 비밀번호가 틀림");
  });

  it("EAP 응답이 사라지면 그 IKE_AUTH 를 1초 뒤 다시 보낸다 — 첫 IKE_AUTH 의 timer 가 끼어들지 않음", () => {
    const x = load();
    const homeWan = x.t.cables.find((c) => [c.a.device, c.b.device].includes(x.id("집 공유기")) && [c.a.device, c.b.device].includes(x.id("통신사 구간")))!;
    const from = x.s.net.trace.length;
    x.s.net.scheduleAction(x.s.net.now, { kind: "ra-reconnect", nodeId: x.id(LAPTOP) });
    // 노트북이 EAP 응답을 보낸 순간, 집 공유기 → 통신사 구간의 다음 프레임(= 그 EAP 응답)을 떨어뜨린다
    while (!x.s.net.trace.slice(from).some((e) => e.kind === "vpn.eap" && e.nodeId === x.id(LAPTOP))) x.s.net.step();
    x.s.net.dropNextOn(homeWan.id);
    x.s.net.runToIdle();
    const tr = x.s.net.trace.slice(from);
    const eapAt = tr.find((e) => e.kind === "vpn.eap" && e.nodeId === x.id(LAPTOP))!.time;
    const retx = tr.filter((e) => e.kind === "vpn.ike" && e.details?.retransmit !== undefined);
    expect(retx.map((e) => [e.time - eapAt, e.details?.step])).toEqual([[1000, "IKE_AUTH"]]);
    expect(x.host(LAPTOP).ra.state).toBe("up");
  });

  it("리뷰: 서버의 EAP 요청이 사라지면 노트북이 다시 보낸 IKE_AUTH 에 EAP 요청을 다시 보내 이어진다", () => {
    const x = load();
    const homeWan = x.t.cables.find((c) => [c.a.device, c.b.device].includes(x.id("집 공유기")) && [c.a.device, c.b.device].includes(x.id("통신사 구간")))!;
    const from = x.s.net.trace.length;
    x.s.net.scheduleAction(x.s.net.now, { kind: "ra-reconnect", nodeId: x.id(LAPTOP) });
    // 서버가 EAP 요청을 보낸 순간, 통신사 구간 → 집 공유기의 다음 프레임(= 그 EAP 요청)을 떨어뜨린다
    while (!x.s.net.trace.slice(from).some((e) => e.kind === "vpn.eap" && e.nodeId === x.id(FW))) x.s.net.step();
    x.s.net.dropNextOn(homeWan.id);
    x.s.net.runToIdle();
    const tr = x.s.net.trace.slice(from);
    // EAP 요청(사라짐) → 1초 뒤 노트북의 IKE_AUTH 재전송 → 서버가 EAP 요청을 다시 → EAP 응답 → 성공
    expect(seqOf(x.t, tr).slice(-6)).toEqual([`${FW}:vpn.eap`, `${LAPTOP}:vpn.ike`, `${FW}:vpn.eap`, `${LAPTOP}:vpn.eap`, `${FW}:vpn.up`, `${LAPTOP}:vpn.up`]);
    expect(tr.filter((e) => e.nodeId === x.id(FW) && e.kind === "vpn.eap").map((e) => e.details?.resent === true)).toEqual([false, true]);
    expect(x.host(LAPTOP).ra.state).toBe("up");
  });

  it("리뷰: EAP 도중 서버 계정 목록이 비면 PSK 만으로 받아 준다 (PSK 는 이미 확인)", () => {
    const x = load();
    const from = x.s.net.trace.length;
    x.s.net.scheduleAction(x.s.net.now, { kind: "ra-reconnect", nodeId: x.id(LAPTOP) });
    while (!x.s.net.trace.slice(from).some((e) => e.kind === "vpn.eap" && e.nodeId === x.id(FW))) x.s.net.step();
    x.s.sync(withServer({ users: [] }, x.t));
    x.s.net.runToIdle();
    expect(x.host(LAPTOP).ra.state).toBe("up");
    expect(x.l3(FW).ra.rows()[0]![0]).toBe("-");
  });

  it("EAP 응답에 서버가 끝내 답하지 않으면 재전송 2번 뒤 포기", () => {
    const x = load();
    const from = x.s.net.trace.length;
    x.s.net.scheduleAction(x.s.net.now, { kind: "ra-reconnect", nodeId: x.id(LAPTOP) });
    while (!x.s.net.trace.slice(from).some((e) => e.kind === "vpn.eap" && e.nodeId === x.id(LAPTOP))) x.s.net.step();
    x.s.net.setLinkLoss(fwWan(x.t).id, 1);
    x.s.net.runToIdle();
    const tr = x.s.net.trace.slice(from);
    expect(tr.filter((e) => e.nodeId === x.id(LAPTOP) && e.details?.retransmit !== undefined).map((e) => e.details?.step)).toEqual(["IKE_AUTH", "IKE_AUTH"]);
    expect(x.host(LAPTOP).ra.reason).toContain("IKE_AUTH 응답 없음");
  });

  it("구성 검사: 이중화 쌍이면 두 서버의 계정을 모두 본다, 같으면 침묵", () => {
    const base = exampleRemoteVpnTopology();
    const fw = base.devices.find((d) => d.name === FW)!;
    const pair = (bUsers: RaServerSettings["users"]): Topology => {
      const a: Device = { ...fw, l3: { ...fw.l3!, interfaces: fw.l3!.interfaces.map((c, i) => (i === 0 ? { ...c, ip: "203.0.113.12" } : c)), ha: { enabled: true, vrid: 1, priority: 200, vips: ["203.0.113.11", "10.50.10.1"] } } };
      const b: Device = { ...createDevice("nat", 700, -24, base.devices), name: "회사 VPN 방화벽 B" };
      b.l3 = { ...a.l3!, interfaces: a.l3!.interfaces.map((c, i) => (i === 0 ? { ...c, ip: "203.0.113.13" } : c)), ha: { ...a.l3!.ha!, priority: 100 }, ra: { ...a.l3!.ra!, users: bUsers } };
      return { ...base, devices: [...base.devices.map((d) => (d.id === fw.id ? a : d)), b] };
    };
    const acct = (t: Topology) => lintTopology(t).filter((i) => i.code === "ra.account-mismatch" || i.code === "ra.no-account");
    const bad = pair([{ name: "kim", password: "old" }, { name: "lee", password: "lee-pass" }]);
    expect(acct(bad).map((i) => [i.code, i.related])).toEqual([["ra.account-mismatch", [bad.devices.find((d) => d.name === "회사 VPN 방화벽 B")!.id]]]);
    expect(acct(pair([{ name: "kim", password: "kim-pass" }]))).toEqual([]);
  });

  it("불러오기 정규화: 예전 저장본(계정 없음)은 그대로 PSK 만, 계정은 보존", () => {
    const t = exampleRemoteVpnTopology();
    const back = parseTopology(serializeTopology(t)).topology!;
    expect(back.devices.find((d) => d.name === FW)!.l3!.ra!.users).toEqual([
      { name: "kim", password: "kim-pass" },
      { name: "lee", password: "lee-pass" },
    ]);
    expect(back.devices.find((d) => d.name === LAPTOP)!.host!.ra).toEqual({ enabled: true, server: "203.0.113.11", psk: "remote-psk", user: "kim", password: "kim-pass" });
    const old = JSON.parse(serializeTopology(t)) as Topology;
    for (const d of old.devices) {
      if (d.l3?.ra) delete d.l3.ra.users;
      if (d.host?.ra) {
        delete d.host.ra.user;
        delete d.host.ra.password;
      }
    }
    const oldBack = parseTopology(JSON.stringify(old)).topology!;
    expect(oldBack.devices.find((d) => d.name === FW)!.l3!.ra!.users).toBeUndefined();
    expect(oldBack.devices.find((d) => d.name === LAPTOP)!.host!.ra).toEqual({ enabled: true, server: "203.0.113.11", psk: "remote-psk" });
    expect(loadTopology(oldBack).host(LAPTOP).ra.state).toBe("up");
  });

  it("패킷 상세: IKE_AUTH 헤더에 IDi·EAP 단계, strongSwan 줄", () => {
    const x = load();
    const tr = x.act({ kind: "ra-reconnect", nodeId: x.id(LAPTOP) });
    const frames = [...x.s.net.frameLog.values()].flat().map((f) => f.frame);
    const ike = (pred: (m: IkeMessage) => boolean) => frames.find((f) => f.payload.kind === "ipv4" && f.payload.payload.kind === "udp" && f.payload.payload.payload.kind === "ike" && pred(f.payload.payload.payload))!;
    const rows = (f: ReturnType<typeof ike>) => headerLayers(f).find((l) => l.title.startsWith("IKEv2"))!.rows;
    expect(rows(ike((m) => m.eap === "request"))).toContainEqual(["EAP (SK 페이로드 안)", expect.stringContaining("코드 1 (Request)")]);
    expect(rows(ike((m) => m.eap === "response"))).toContainEqual(["IDi (사용자 이름)", "kim"]);
    expect(rows(ike((m) => m.eap === "success"))).toContainEqual(["EAP (SK 페이로드 안)", expect.stringContaining("코드 3 (Success)")]);
    // tcpdump 는 IKE_AUTH 의 SK 페이로드(암호화)를 못 풀어 ikev2_auth 로만 본다
    expect(tcpdumpLine(ike((m) => m.eap === "response"))).toContain("NONESP-encap: isakmp: child_sa  ikev2_auth[I]");
    const lines = (kind: string, node: string) => practitionerLines(tr.find((e) => e.kind === kind && e.nodeId === x.id(node))!, {}).map((l) => l.line);
    expect(lines("vpn.eap", FW)).toEqual(["13[IKE] initiating EAP_MSCHAPV2 method (id 0x01)"]);
    expect(lines("vpn.eap", LAPTOP)).toEqual(["13[IKE] server requested EAP_MSCHAPV2 authentication (id 0x01)"]);
    expect(lines("vpn.up", FW).slice(0, 2)).toEqual(["09[IKE] authentication of 'kim' with EAP successful", "09[IKE] EAP method EAP_MSCHAPV2 succeeded, MSK established"]);
    const bad = load(withLaptop({ password: "wrong" }));
    const fail = bad.s.net.trace.find((e) => e.kind === "vpn.drop" && e.nodeId === bad.id(FW) && e.details?.eap === "failure")!;
    expect(practitionerLines(fail, {}).map((l) => l.line)).toEqual(["12[IKE] EAP-MS-CHAPv2 verification failed for 'kim'", "12[IKE] EAP method EAP_MSCHAPV2 failed for peer 203.0.113.100"]);
    const cli = bad.s.net.trace.find((e) => e.kind === "vpn.drop" && e.nodeId === bad.id(LAPTOP))!;
    expect(practitionerLines(cli, {}).map((l) => l.line)).toEqual(["12[IKE] received EAP_FAILURE, EAP authentication failed"]);
  });
});

// ---------- DPD (Dead Peer Detection) ----------
describe("원격 접속 VPN — DPD", () => {
  it("서버가 살아 있으면 빈 INFORMATIONAL 에 빈 응답 → 터널 유지 (NAT-T 라 UDP 4500)", () => {
    const x = load();
    const tr = x.act({ kind: "vpn-dpd", nodeId: x.id(LAPTOP) });
    expect(seqOf(x.t, tr)).toEqual([`${LAPTOP}:action`, `${LAPTOP}:vpn.dpd`, `${FW}:vpn.dpd`, `${LAPTOP}:vpn.dpd`]);
    expect(x.host(LAPTOP).ra.state).toBe("up");
    const dpd = x.wire(FW).find((p) => p.payload.kind === "udp" && p.payload.payload.kind === "ike" && p.payload.payload.dpd)!;
    expect(dpd.payload).toMatchObject({ kind: "udp", dstPort: 4500, payload: { exchange: "INFORMATIONAL", response: false } });
    const lines = (e: TraceEvent) => practitionerLines(e, {}).map((l) => l.line);
    const [, req, reply, alive] = tr.filter((e) => VPN_KINDS.includes(e.kind));
    expect(lines(req!)).toEqual(["15[IKE] sending DPD request", "15[ENC] generating INFORMATIONAL request 2 [ ]"]);
    expect(lines(reply!)).toEqual(["16[ENC] parsed INFORMATIONAL request 2 [ ]", "16[ENC] generating INFORMATIONAL response 2 [ ]"]);
    expect(lines(alive!)).toEqual(["16[ENC] parsed INFORMATIONAL response 2 [ ]"]);
  });

  it("경로가 끊기면(회사 쪽 케이블 뽑음) 1초씩 두 번 다시 보낸 뒤 SA 삭제 → 끊김, 케이블을 꽂고 '다시 연결' 로 복구", () => {
    const x = load();
    x.apply({ ...x.t, cables: x.t.cables.filter((c) => c.id !== fwWan(x.t).id) });
    const tr = x.act({ kind: "vpn-dpd", nodeId: x.id(LAPTOP) });
    expect(seqOf(x.t, tr)).toEqual([`${LAPTOP}:action`, `${LAPTOP}:vpn.dpd`, `${LAPTOP}:vpn.dpd`, `${LAPTOP}:vpn.dpd`, `${LAPTOP}:vpn.drop`]);
    const t0 = tr[0]!.time;
    expect(tr.filter((e) => e.kind === "vpn.dpd" || e.kind === "vpn.drop").map((e) => e.time - t0)).toEqual([0, 1000, 2000, 3000]);
    const ra = x.host(LAPTOP).ra;
    expect(ra.state).toBe("failed");
    expect(ra.vip).toBeUndefined();
    expect(ra.summary()).toMatch(/^끊김 · DPD 에 서버 응답 없음/);
    expect(practitionerLines(tr.at(-1)!, {}).map((l) => l.line)).toEqual(["11[IKE] giving up after 2 retransmits"]);
    x.apply(x.t);
    x.act({ kind: "ra-reconnect", nodeId: x.id(LAPTOP) });
    expect(x.host(LAPTOP).ra.state).toBe("up");
    x.act({ kind: "ping", nodeId: x.id(LAPTOP), dst: "10.50.10.20" });
    expect(x.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
  });

  it("서버가 그 SA 를 모르면(설정 변경) INVALID_SPI 로 답하고, 노트북은 옛 SA 를 버리고 다시 접속한다", () => {
    const x = load();
    x.apply(withServer({ routes: [{ dest: "10.50.10.0", prefix: 24 }, { dest: "10.60.0.0", prefix: 24 }] }, x.t));
    expect(x.l3(FW).ra.clients.size).toBe(0);
    const tr = x.act({ kind: "vpn-dpd", nodeId: x.id(LAPTOP) });
    expect(seqOf(x.t, tr).slice(0, 5)).toEqual([`${LAPTOP}:action`, `${LAPTOP}:vpn.dpd`, `${FW}:vpn.drop`, `${LAPTOP}:vpn.ike`, `${LAPTOP}:vpn.ike`]);
    expect(tr.find((e) => e.kind === "vpn.drop")!.summary).toContain("INVALID_SPI");
    expect(tr.filter((e) => e.nodeId === x.id(LAPTOP) && e.kind === "vpn.ike")[0]!.summary).toContain("DPD 에 서버가 이 터널을 모른다고 알림");
    expect(x.host(LAPTOP).ra.state).toBe("up");
    expect(x.host(LAPTOP).ra.routes).toHaveLength(2);
  });

  it("연결된 터널이 없으면 DPD 를 보내지 않고 기록만 한다", () => {
    const x = load(withLaptop({ password: "wrong" }));
    const before = x.wire(FW).length;
    const tr = x.act({ kind: "vpn-dpd", nodeId: x.id(LAPTOP) });
    expect(seqOf(x.t, tr)).toEqual([`${LAPTOP}:action`, `${LAPTOP}:vpn.dpd`]);
    expect(tr[1]!.summary).toContain("연결된 터널 없음");
    expect(x.wire(FW).length).toBe(before);
  });
});
