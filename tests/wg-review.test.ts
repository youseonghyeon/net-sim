// WireGuard 리뷰(2026-10-07) 회귀 테스트: 리뷰어가 재현한 결함과 문제없음을 확인한 경우
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleWireguardTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import { WgClient } from "../src/core/nodes/wg";
import { createDevice, wgPublicKeyOf, type Topology, type Device, type RouterWgClientSettings, type RouterWgServerSettings } from "../src/model/topology";
import type { TraceEvent } from "../src/core/trace";
const log = (..._a: unknown[]) => {};

const patchServer = (t: Topology, patch: Partial<RouterWgServerSettings>): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.router?.wgServer ? { ...d, router: { ...d.router, wgServer: { ...d.router.wgServer, ...patch } } } : d)),
});
const patchClient = (t: Topology, patch: Partial<RouterWgClientSettings>): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.router?.wgClient ? { ...d, router: { ...d.router, wgClient: { ...d.router.wgClient, ...patch } } } : d)),
});
const patchDev = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });
const show = (tr: TraceEvent[], L: ReturnType<typeof loadTopology>, kinds = /vpn|wg|killswitch|leak|nat\.|dns\.(forward|timeout)|icmp\.(failed|reply)/) =>
  tr.filter((e) => kinds.test(e.kind)).map((e) => `${e.time} ${L.t.devices.find((d) => d.id === e.nodeId)?.name}:${e.kind} ${e.summary.slice(0, 160)}`);

/** 조건에 맞는 첫 프레임이 링크에 오르는 순간 잃게 한다 (한 이벤트씩 돌리며) */
function loseFirst(L: ReturnType<typeof loadTopology>, pred: (f: any) => boolean, max = 20000): boolean {
  const net = L.s.net;
  let seen = net.transmissions.length;
  for (let i = 0; i < max; i++) {
    for (const tx of net.transmissions.slice(seen)) {
      if (pred(tx.frame)) {
        tx.lost = true;
        tx.lostAt = tx.departAt;
        return true;
      }
    }
    seen = net.transmissions.length;
    if (!net.step()) return false;
  }
  return false;
}
const isWg = (type: string) => (f: any) => f.payload?.kind === "ipv4" && f.payload.payload?.kind === "udp" && f.payload.payload.payload?.kind === "wg" && f.payload.payload.payload.type === type;

describe("WireGuard 리뷰: VPN 점검 항목", () => {
  it("1a Response 가 사라져도 폰은 재시도로 붙는다", () => {
    const base = patchDev(exampleWireguardTopology(), "출장 폰", (d) => ({ ...d, host: { ...d.host!, ra: { ...d.host!.ra!, enabled: false } } }));
    const L = loadTopology(base);
    L.s.sync(patchDev(base, "출장 폰", (d) => ({ ...d, host: { ...d.host!, ra: { ...d.host!.ra!, enabled: true } } })));
    expect(loseFirst(L, isWg("response"))).toBe(true);
    L.s.net.runToIdle();
    log("1a", L.host("출장 폰").ra.state);
    expect(L.host("출장 폰").ra.state).toBe("up");
  });

  it("1a' 여행용 공유기의 Response 가 사라져도 붙는다", () => {
    const base = patchClient(exampleWireguardTopology(), { enabled: false });
    const L = loadTopology(base);
    L.s.sync(patchClient(base, { enabled: true }));
    expect(loseFirst(L, isWg("response"))).toBe(true);
    L.s.net.runToIdle();
    expect(L.node<Router>("여행용 공유기").wgClientSummary()).toContain("연결됨");
  });

  it("1b 서버 공유기를 지웠다 다시 넣으면 (같은 id) 여행용 공유기는 15초 뒤 다시 잇는다", () => {
    const t = exampleWireguardTopology();
    const L = loadTopology(t);
    const homeId = L.id("집 Brume 3");
    L.apply({ ...t, devices: t.devices.filter((d) => d.id !== homeId), cables: t.cables.filter((c) => c.a.device !== homeId && c.b.device !== homeId) });
    L.apply(t);
    let tr = L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "8.8.8.8" });
    log("1b first", L.host("여행 노트북").pings.at(-1)!.status);
    L.s.net.runUntil(L.s.net.now + 20_000);
    tr = L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "8.8.8.8" });
    log("1b", L.host("여행 노트북").pings.at(-1)!.status, show(tr, L).slice(0, 6));
    expect(L.host("여행 노트북").pings.at(-1)!.status).toBe("ok");
  });

  it("1c WireGuard 를 끈 폰에 늦게 온 WireGuard 는 Port Unreachable 로 새지 않는다", () => {
    const t = exampleWireguardTopology();
    const L = loadTopology(t);
    // 폰 끄기
    L.apply(patchDev(t, "출장 폰", (d) => ({ ...d, host: { ...d.host!, ra: { ...d.host!.ra!, enabled: false } } })));
    // NAS → 10.0.0.3 ping: 서버는 여전히 세션을 들고 있어 폰으로 보낸다
    const tr = L.act({ kind: "ping", nodeId: L.id("집 NAS"), dst: "10.0.0.3" });
    const leak = tr.some((e) => e.kind === "icmp.unreachable.sent" || (e.summary.includes("Port Unreachable") && e.nodeId === L.id("출장 폰")));
    log("1c", show(tr, L, /./).filter((s) => s.includes("출장 폰")).slice(0, 5));
    expect(leak).toBe(false);
  });
});

describe("WireGuard 리뷰: 핸드셰이크 교차", () => {
  it("2 양쪽이 동시에 새 핸드셰이크를 시작하면 (교차) 세션이 어긋난다", () => {
    const t = exampleWireguardTopology();
    const L = loadTopology(t);
    const hotelIsp = t.cables.find((c) => [c.a.device, c.b.device].includes(L.id("호텔 공유기")) && [c.a.device, c.b.device].includes(L.id("통신사 구간")))!;
    // 폰 ↔ 서버 경로를 끊고 양쪽이 같은 순간 데이터를 보낸다 → 둘 다 15초 뒤 새 핸드셰이크
    L.s.net.setLinkLoss(hotelIsp.id, 1);
    const now = L.s.net.now;
    L.s.net.scheduleAction(now, { kind: "ping", nodeId: L.id("출장 폰"), dst: "192.168.8.20" });
    L.s.net.scheduleAction(now, { kind: "ping", nodeId: L.id("집 NAS"), dst: "10.0.0.3" });
    L.s.net.runToIdle();
    L.s.net.setLinkLoss(hotelIsp.id, 0);
    const from = L.s.net.trace.length;
    L.s.net.runUntil(now + 16_000);
    L.s.net.runToIdle();
    const tr = L.s.net.trace.slice(from);
    log("2 handshake", show(tr, L, /vpn\.(handshake|up|drop)/));
    const tr2 = L.act({ kind: "ping", nodeId: L.id("출장 폰"), dst: "192.168.8.20" });
    log("2 after", L.host("출장 폰").pings.at(-1)!.status, show(tr2, L, /vpn\.(drop|encap|decap)/));
    // 교차 직후 두 쪽 모두 세션이 있다고 믿지만 서로의 세션 번호가 어긋나 데이터가 버려진다
    expect(tr2.some((e) => e.kind === "vpn.drop" && e.details?.reason === "unknown-session")).toBe(false);
    const f2 = L.s.net.trace.length;
    L.s.net.runUntil(L.s.net.now + 20_000);
    log("2 later", show(L.s.net.trace.slice(f2), L, /vpn\.(handshake|up|drop)/));
    L.act({ kind: "ping", nodeId: L.id("출장 폰"), dst: "192.168.8.20" });
    log("2 after 20s more", L.host("출장 폰").pings.at(-1)!.status);
    expect(L.host("출장 폰").pings.at(-1)!.status).toBe("ok");
  });
});

describe("WireGuard 리뷰: 킬 스위치", () => {
  it("3a 킬 스위치를 켰는데 내 터널 주소가 비어 있으면 그대로 호텔로 샌다", () => {
    const L = loadTopology(patchClient(exampleWireguardTopology(), { address: "" }));
    const tr = L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "8.8.8.8" });
    const leaked = tr.some((e) => e.nodeId === L.id("호텔 공유기") && e.kind === "nat.translate" && e.summary.includes("ICMP"));
    log("3a leaked", leaked, L.host("여행 노트북").pings.at(-1)!.status, lintTopology(L.t).map((i) => i.code));
    expect(leaked).toBe(false);
    expect(lintTopology(L.t).map((i) => i.code)).toContain("wg.no-address");
  });

  it("3b VPN 정책에서 뺀 기기도 킬 스위치에 이름 해석이 막힌다 (DNS 포워더가 VPN 쪽)", () => {
    const L0 = loadTopology(exampleWireguardTopology());
    const lap = L0.host("여행 노트북").iface.ip!;
    const t = patchClient(L0.t, { policy: { mode: "exclude", devices: [lap] } });
    const L = loadTopology(patchServer(t, { enabled: false }));
    L.s.net.runUntil(L.s.net.now + 40_000);
    // 빠진 기기의 IP ping 은 호텔로 바로 됨
    L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "8.8.8.8" });
    const ipOk = L.host("여행 노트북").pings.at(-1)!.status;
    const tr = L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "naver.com" });
    log("3b", ipOk, L.host("여행 노트북").pings.at(-1), show(tr, L).slice(0, 6));
    expect(ipOk).toBe("ok");
    expect(L.host("여행 노트북").pings.at(-1)!.status).toBe("ok");
  });

  it("3c 정책·킬 스위치만 바꾸면 로그가 없다", () => {
    const L = loadTopology(exampleWireguardTopology());
    const tr = L.apply(patchClient(L.t, { killSwitch: false }));
    log("3c", show(tr, L, /./));
    expect(tr.some((e) => e.kind === "vpn.config" && e.summary.includes("킬 스위치 꺼짐"))).toBe(true);
  });
});

describe("WireGuard 리뷰: 노트북 NIC 전환 (로밍)", () => {
  it("5 WireGuard 앱 노트북이 유선 → Wi-Fi 로 넘어가도 터널이 이어진다", () => {
    const t = exampleWireguardTopology();
    const hotel = t.devices.find((d) => d.name === "호텔 공유기")!;
    const phone = t.devices.find((d) => d.name === "출장 폰")!;
    const lap = createDevice("laptop", hotel.x - 120, hotel.y + 40, t.devices);
    lap.name = "출장 노트북";
    lap.wifi = { ssid: "hotel" };
    lap.host = { ...lap.host!, ra: { ...phone.host!.ra!, wg: { ...phone.host!.ra!.wg!, address: "10.0.0.4/32" } } };
    const home = t.devices.find((d) => d.name === "집 Brume 3")!;
    home.router!.wgServer!.peers.push({ name: "출장 노트북", publicKey: wgPublicKeyOf(lap, "host"), ip: "10.0.0.4" });
    const wired = { id: "c-lap", a: { device: hotel.id, port: 2 }, b: { device: lap.id, port: 0 } };
    const t2: Topology = { ...t, devices: [...t.devices, lap], cables: [...t.cables, wired] };
    const L = loadTopology(t2);
    expect(L.host("출장 노트북").ra.state).toBe("up");
    L.act({ kind: "ping", nodeId: L.id("출장 노트북"), dst: "192.168.8.20" });
    expect(L.host("출장 노트북").pings.at(-1)!.status).toBe("ok");
    const trA = L.apply({ ...t2, cables: t2.cables.filter((c) => c.id !== "c-lap") });
    log("5 apply", show(trA, L, /./).filter((x) => x.includes("출장 노트북")).slice(0, 40));
    const tr = L.act({ kind: "ping", nodeId: L.id("출장 노트북"), dst: "192.168.8.20" });
    log("5", L.host("출장 노트북").iface.ip, L.host("출장 노트북").pings.at(-1)!.status, show(tr, L, /vpn/).slice(0, 6));
    expect(L.host("출장 노트북").pings.at(-1)!.status).toBe("ok");
  });
});

describe("WireGuard 리뷰: 서버 쪽", () => {
  it("4 집 LAN 의 NAS 가 서버 자신의 터널 주소 10.0.0.1 로 ping", () => {
    const L = loadTopology(exampleWireguardTopology());
    const tr = L.act({ kind: "ping", nodeId: L.id("집 NAS"), dst: "10.0.0.1" });
    log("4", L.host("집 NAS").pings.at(-1)!.status, show(tr, L, /ip\.|nat\.|icmp\.|drop/).slice(0, 12));
    expect(L.host("집 NAS").pings.at(-1)!.status).toBe("ok");
  });

  it("6 피어 터널 주소를 집 LAN 안(192.168.8.50)으로 적으면 구성 검사는 조용하지만 NAS → 폰이 안 된다", () => {
    let t = exampleWireguardTopology();
    const server = t.devices.find((d) => d.router?.wgServer)!.router!.wgServer!;
    t = patchServer(t, { peers: server.peers.map((p) => (p.name === "출장 폰" ? { ...p, ip: "192.168.8.50" } : p)) });
    t = patchDev(t, "출장 폰", (d) => ({ ...d, host: { ...d.host!, ra: { ...d.host!.ra!, wg: { ...d.host!.ra!.wg!, address: "192.168.8.50/32" } } } }));
    const L = loadTopology(t);
    const codes = lintTopology(t).map((i) => i.code);
    L.act({ kind: "ping", nodeId: L.id("집 NAS"), dst: "192.168.8.50" });
    log("6", codes, L.host("집 NAS").pings.at(-1)!.status);
    expect(codes).toContain("wg.peer-in-lan");
  });

  it("7 여행용 공유기를 집 Brume LAN 뒤에 두면 (공인 주소로 헤어핀) 붙는가", () => {
    const t = exampleWireguardTopology();
    const home = t.devices.find((d) => d.name === "집 Brume 3")!;
    const travel = t.devices.find((d) => d.name === "여행용 공유기")!;
    const cables = t.cables.map((c) => (c.b.device === travel.id && c.b.port === 0 ? { ...c, a: { device: home.id, port: 2 } } : c));
    const L = loadTopology({ ...t, cables });
    log("7", L.node<Router>("여행용 공유기").wgClientSummary(), lintTopology({ ...t, cables }).map((i) => i.code));
    const tr = L.s.net.trace.filter((e) => e.nodeId === L.id("집 Brume 3") && /vpn|nat|drop/.test(e.kind)).slice(0, 6);
    log(show(tr, L, /./));
    expect(L.node<Router>("여행용 공유기").wgClientSummary()).toContain("연결됨");
  });
});

describe("WireGuard 리뷰: 서버·클라이언트를 한 공유기에", () => {
  it("8 집 Brume 이 서버이면서 클라이언트(다른 VPN)도 켬: 서버 피어의 인터넷은?", () => {
    const L = loadTopology(exampleWireguardTopology());
    // 기존 동작 확인만: 폰 full tunnel 로 바꿔 인터넷 ping
    const t = patchDev(L.t, "출장 폰", (d) => ({ ...d, host: { ...d.host!, ra: { ...d.host!.ra!, wg: { ...d.host!.ra!.wg!, allowedIps: "0.0.0.0/0" } } } }));
    const L2 = loadTopology(t);
    L2.act({ kind: "ping", nodeId: L2.id("출장 폰"), dst: "8.8.8.8" });
    expect(L2.host("출장 폰").pings.at(-1)!.status).toBe("ok");
    expect(L2.host("출장 폰").ra).toBeInstanceOf(WgClient);
  });
});

describe("WireGuard 리뷰: 수동 WAN·주소 변경", () => {
  const staticTravel = (t: Topology) => patchDev(t, "여행용 공유기", (d) => ({ ...d, router: { ...d.router!, wan: { ipMode: "static", ip: "10.10.0.50", prefix: 24, gateway: "10.10.0.1" } } }));
  it("9 수동 WAN 여행용 공유기: 케이블을 나중에 꽂으면 VPN 이 스스로 붙는가", () => {
    const t = staticTravel(exampleWireguardTopology());
    const travel = t.devices.find((d) => d.name === "여행용 공유기")!;
    const wanCable = t.cables.find((c) => c.b.device === travel.id && c.b.port === 0)!;
    const L = loadTopology({ ...t, cables: t.cables.filter((c) => c !== wanCable) });
    const tr0 = L.s.net.trace.filter((e) => e.nodeId === travel.id && /vpn/.test(e.kind));
    log("9 before cable", L.node<Router>("여행용 공유기").wgClientSummary(), show(tr0, L).slice(-2));
    const tr = L.apply(t);
    log("9 after cable", L.node<Router>("여행용 공유기").wgClientSummary(), show(tr, L, /vpn/));
    expect(L.node<Router>("여행용 공유기").wgClientSummary()).toContain("연결됨");
  });

  it("9b 수동 WAN 여행용 공유기를 케이블째 불러오면 첫 Initiation 이 링크 전에 나가는가", () => {
    const L = loadTopology(staticTravel(exampleWireguardTopology()));
    const tr = L.s.net.trace.filter((e) => e.nodeId === L.id("여행용 공유기") && /vpn\.(handshake|up)|link\.(up|transmit)/.test(e.kind));
    log("9b", show(tr, L, /./).slice(0, 8));
    // 첫 Initiation 은 WAN 링크가 올라온 뒤에 (앞의 호텔 공유기가 아직 인터넷 주소를 받기 전이면 사라지고 5초 뒤 재시도 — 1단계와 같음)
    const linkUp = L.s.net.trace.findIndex((e) => e.nodeId === L.id("여행용 공유기") && e.kind === "link.up" && e.summary.startsWith("wan"));
    const firstInit = L.s.net.trace.findIndex((e) => e.nodeId === L.id("여행용 공유기") && e.kind === "vpn.handshake");
    expect(linkUp).toBeGreaterThanOrEqual(0);
    expect(firstInit).toBeGreaterThan(linkUp);
    expect(L.node<Router>("여행용 공유기").wgClientSummary()).toContain("연결됨");
  });

  it("12 배경 재시도(P2P 등록) + 킬 스위치 + 서버 꺼짐: 시계가 멈추는가 (runToIdle 종료)", () => {
    let t = patchServer(exampleWireguardTopology(), { enabled: false });
    t = patchDev(t, "여행 노트북", (d) => ({ ...d, host: { ...d.host!, p2p: { enabled: true } } }));
    const L = loadTopology(t, { maxEvents: 200_000 });
    L.s.net.runUntil(L.s.net.now + 30_000);
    let err: unknown;
    let n = 0;
    try {
      n = L.s.net.runToIdle(50_000);
    } catch (e) {
      err = e;
    }
    log("12", String(err), n, L.s.net.now);
    expect(err).toBeUndefined();
  });

  it("12b 대조군: 킬 스위치 끔 (VPN 없이 나감) 이면", () => {
    let t = patchClient(patchServer(exampleWireguardTopology(), { enabled: false }), { enabled: false });
    t = patchDev(t, "여행 노트북", (d) => ({ ...d, host: { ...d.host!, p2p: { enabled: true } } }));
    const t2 = patchDev(t, "internet-1", (d) => d);
    const L = loadTopology(t2, { maxEvents: 200_000 });
    L.s.net.runUntil(L.s.net.now + 30_000);
    let err: unknown;
    try {
      L.s.net.runToIdle(50_000);
    } catch (e) {
      err = e;
    }
    log("12b", String(err), L.s.net.now);
    expect(err).toBeUndefined();
  });

  it("10 여행용 공유기 WAN 주소가 바뀌어도 (DHCP 새 주소) 터널이 이어진다", () => {
    const t = exampleWireguardTopology();
    const L = loadTopology(t);
    const travel = t.devices.find((d) => d.name === "여행용 공유기")!;
    const wanCable = t.cables.find((c) => c.b.device === travel.id && c.b.port === 0)!;
    const before = L.node<Router>("여행용 공유기").wan.ip;
    const t2 = patchDev(t, "호텔 공유기", (d) => ({ ...d, router: { ...d.router!, dhcp: { ...d.router!.dhcp, start: "10.10.0.150", end: "10.10.0.199" } } }));
    L.apply({ ...t2, cables: t2.cables.filter((c) => c !== wanCable) });
    L.apply(t2);
    const after = L.node<Router>("여행용 공유기").wan.ip;
    const tr = L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "192.168.8.20" });
    log("10", before, after, L.host("여행 노트북").pings.at(-1)!.status, show(tr, L, /vpn/).slice(0, 4));
    expect(after).not.toBe(before);
    expect(L.host("여행 노트북").pings.at(-1)!.status).toBe("ok");
  });

  it("11 클라이언트를 끄면 남은 VPN NAT 매핑·늦은 패킷", () => {
    const t = exampleWireguardTopology();
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "8.8.8.8" });
    const tr = L.apply(patchClient(t, { enabled: false }));
    log("11 off", show(tr, L, /./).slice(0, 5));
    const tr2 = L.act({ kind: "ping", nodeId: L.id("집 NAS"), dst: "10.0.0.2" });
    log("11 late", show(tr2, L, /./).filter((x) => x.includes("여행용")).slice(0, 8));
    expect(tr2.some((e) => e.nodeId === L.id("여행용 공유기") && e.summary.includes("클라이언트가 꺼진 뒤 늦게 온 패킷"))).toBe(true);
  });
});
