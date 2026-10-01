// 리뷰 (공유기 VPN 서버, L2TP/IPsec — 20cff8a): 결함 재현 테스트. 각 테스트의 "지금:" 주석은 고치기 전의 동작
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleIptimeVpnTopology, exampleRemoteVpnTopology } from "../src/model/examples";
import { createDevice, type Device, type RouterVpnServerSettings, type Topology } from "../src/model/topology";
import type { Router } from "../src/core/nodes/router";
import { NetworkSync } from "../src/model/netSync";
import { lintTopology } from "../src/model/lint";
import { headerLayers, practitionerLines } from "../src/model/packetView";

const LAP = "출장 노트북";
const HOME = "집 ipTIME";
const ISP = "통신사 구간";

const patchLaptop = (t: Topology, patch: Partial<NonNullable<NonNullable<Device["host"]>["ra"]>>, name = LAP): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.name === name ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, ...patch } } } : d)),
});
const patchServer = (t: Topology, patch: Partial<RouterVpnServerSettings>): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.router?.vpnServer ? { ...d, router: { ...d.router, vpnServer: { ...d.router.vpnServer, ...patch } } } : d)),
});
const linkBetween = (t: Topology, a: string, b: string) => {
  const ia = t.devices.find((d) => d.name === a)!.id;
  const ib = t.devices.find((d) => d.name === b)!.id;
  return t.cables.find((c) => [c.a.device, c.b.device].includes(ia) && [c.a.device, c.b.device].includes(ib))!;
};
const secondLaptop = (t: Topology): Topology => {
  const devices = [...t.devices];
  const lap = { ...createDevice("laptop", 240, 152, devices), name: "출장 노트북 2" };
  lap.host = { ...lap.host!, ra: { ...t.devices.find((d) => d.name === LAP)!.host!.ra! } };
  devices.push(lap);
  const hotel = t.devices.find((d) => d.name === "호텔 공유기")!;
  return { ...t, devices, cables: [...t.cables, { id: "lap2", a: { device: hotel.id, port: 2 }, b: { device: lap.id, port: 0 } }] };
};

/** 공유기 뒤 공유기: 통신사 모뎀 공유기(203.0.113.20)가 UDP 500·4500 을 안쪽 ipTIME(WAN 192.168.1.2)으로 포워딩 */
const doubleNat = (): Topology => {
  const t = exampleIptimeVpnTopology();
  const devices = [...t.devices];
  const modem = { ...createDevice("router", 568, -100, devices), name: "모뎀 공유기" };
  modem.router = {
    ...modem.router!,
    lanIp: "192.168.1.1",
    lanPrefix: 24,
    wan: { ipMode: "static", ip: "203.0.113.20", prefix: 24, gateway: "203.0.113.1" },
    forwards: [
      { publicPort: 500, lanIp: "192.168.1.2", lanPort: 500, proto: "udp" },
      { publicPort: 4500, lanIp: "192.168.1.2", lanPort: 4500, proto: "udp" },
    ],
  };
  devices.push(modem);
  const home = devices.find((d) => d.name === HOME)!;
  const isp = devices.find((d) => d.name === ISP)!;
  const home2: Device = { ...home, router: { ...home.router!, wan: { ipMode: "static", ip: "192.168.1.2", prefix: 24, gateway: "192.168.1.1" } } };
  const cables = t.cables.filter((c) => !([c.a.device, c.b.device].includes(home.id) && [c.a.device, c.b.device].includes(isp.id)));
  cables.push({ id: "c-modem-isp", a: { device: isp.id, port: 6 }, b: { device: modem.id, port: 0 } }, { id: "c-modem-home", a: { device: modem.id, port: 1 }, b: { device: home.id, port: 0 } });
  return { ...t, devices: devices.map((d) => (d.id === home.id ? home2 : d)), cables };
};

/** 노트북을 호텔 NAT 없이 공인 주소 203.0.113.100 으로 통신사 구간에 바로 */
const publicLaptop = (t: Topology): Topology => {
  const lapDev = t.devices.find((d) => d.name === LAP)!;
  const hotel = t.devices.find((d) => d.name === "호텔 공유기")!;
  const isp = t.devices.find((d) => d.name === ISP)!;
  const lap2: Device = { ...lapDev, host: { ...lapDev.host!, ipMode: "static", ip: "203.0.113.100", prefix: 24, gateway: "203.0.113.1" } };
  return {
    ...t,
    devices: t.devices.filter((d) => d.id !== hotel.id).map((d) => (d.id === lapDev.id ? lap2 : d)),
    cables: [...t.cables.filter((c) => ![c.a.device, c.b.device].includes(hotel.id)), { id: "c-lap-isp", a: { device: isp.id, port: 1 }, b: { device: lapDev.id, port: 0 } }],
  };
};

/** 재택근무 예제의 회사 VPN 장비(IKEv2)를 회사 공유기(공인 203.0.113.11, VPN 서버 켬) 뒤로: 공유기가 UDP 500·4500 을 안쪽으로 포워딩 */
const ikev2BehindRouterWithVpnServer = (): Topology => {
  const t = exampleRemoteVpnTopology();
  const devices = [...t.devices];
  const fw = devices.find((d) => d.name === "회사 VPN 방화벽")!;
  const isp = devices.find((d) => d.name === ISP)!;
  const edge = { ...createDevice("router", 568, -100, devices), name: "회사 공유기" };
  edge.router = {
    ...edge.router!,
    lanIp: "192.168.1.1",
    lanPrefix: 24,
    dhcp: { enabled: false, start: "192.168.1.100", end: "192.168.1.199" },
    wan: { ipMode: "static", ip: "203.0.113.11", prefix: 24, gateway: "203.0.113.1" },
    forwards: [
      { publicPort: 500, lanIp: "192.168.1.2", lanPort: 500, proto: "udp" },
      { publicPort: 4500, lanIp: "192.168.1.2", lanPort: 4500, proto: "udp" },
    ],
    vpnServer: { enabled: true, psk: "office-l2tp", poolStart: "192.168.1.50", poolEnd: "192.168.1.59", users: [{ name: "boss", password: "pw" }] },
  };
  devices.push(edge);
  const fw2: Device = { ...fw, l3: { ...fw.l3!, interfaces: fw.l3!.interfaces.map((c, i) => (i === 0 ? { ...c, ip: "192.168.1.2", gateway: "192.168.1.1" } : c)) } };
  const cables = t.cables.filter((c) => !([c.a.device, c.b.device].includes(fw.id) && [c.a.device, c.b.device].includes(isp.id)));
  cables.push({ id: "c-edge-isp", a: { device: isp.id, port: 6 }, b: { device: edge.id, port: 0 } }, { id: "c-edge-fw", a: { device: edge.id, port: 1 }, b: { device: fw.id, port: 0 } });
  return { ...t, devices: devices.map((d) => (d.id === fw.id ? fw2 : d)), cables };
};

describe("리뷰: 공유기 VPN 서버 (L2TP/IPsec)", () => {
  it("1. PSK 거절(AUTHENTICATION-FAILED) 응답이 사라지면 노트북 이유가 'UDP 500·4500 막힘' 으로 바뀐다 — 다시 온 인증에도 같은 거절을 보내야", () => {
    const t = patchLaptop(exampleIptimeVpnTopology(), { psk: "wrong" });
    const s = new NetworkSync();
    s.sync(t);
    const id = (n: string) => t.devices.find((d) => d.name === n)!.id;
    const homeWan = linkBetween(t, HOME, ISP);
    // 노트북의 Main Mode 2 (PSK) 가 통신사 구간 → 집 ipTIME 링크에 실린 뒤, 그 링크의 다음 프레임(= 거절 응답)을 떨어뜨린다
    while (!s.net.trace.some((e) => e.nodeId === id(LAP) && e.summary.includes("인증 값을 보냄"))) s.net.step();
    const from = s.net.trace.length;
    while (!s.net.trace.slice(from).some((e) => e.kind === "link.transmit" && e.details?.linkId === homeWan.id)) s.net.step();
    s.net.dropNextOn(homeWan.id);
    s.net.runToIdle();
    const tr = s.net.trace.slice(from);
    expect(tr.some((e) => e.kind === "link.loss" && e.summary.includes("AUTHENTICATION_FAILED"))).toBe(true);
    const lap = (s.net.nodes.get(id(LAP)) as unknown as { ra: { state: string; reason?: string } }).ra;
    expect(lap.state).toBe("failed");
    // 지금: "IKE Main Mode 응답 없음 (재전송 2번 뒤 timeout) — 서버 주소, 공유기의 VPN 서버, UDP 500·4500 이 막히지 않았는지 확인"
    expect(lap.reason).toContain("사전 공유 키가 다름");
    // 지금: 서버는 다시 온 인증을 "Main Mode 첫 교환 없이 온 인증 → 무시"
    expect(tr.some((e) => e.nodeId === id(HOME) && e.summary.includes("첫 교환 없이 온 인증"))).toBe(false);
  });

  it("2a. CHAP 실패 뒤 서버 'VPN 접속' 표에 유령 줄이 남는다 (AGENTS: CHAP 실패면 서버가 그 SA 를 지움)", () => {
    const x = loadTopology(patchLaptop(exampleIptimeVpnTopology(), { password: "nope" }));
    expect(x.host(LAP).ra.state).toBe("failed");
    // 지금: [["-","인증 대기","203.0.113.100:40001","NAT-T"]]
    expect(x.node<Router>(HOME).vpnServer.rows()).toEqual([]);
  });

  it("2b. IPCP Nak 뒤 서버 'VPN 접속' 표에 유령 줄('주소 대기')이 남는다 (AGENTS: IPCP Nak 이면 서버가 그 SA 를 지움)", () => {
    const one = loadTopology(patchServer(secondLaptop(exampleIptimeVpnTopology()), { poolEnd: "192.168.0.50" }));
    const rows = one.node<Router>(HOME).vpnServer.rows();
    // 지금: [["me","192.168.0.50",…], ["me","주소 대기",…]]
    expect(rows.map((r) => r[1])).toEqual(["192.168.0.50"]);
  });

  it("3a. 서버가 할당 IP 를 바꾸면 세션을 말없이 지워 노트북은 '연결됨' 인 채 모든 트래픽이 사라진다", () => {
    const x = loadTopology(exampleIptimeVpnTopology());
    x.apply(patchServer(x.t, { poolEnd: "192.168.0.58" }));
    expect(x.node<Router>(HOME).vpnServer.connected).toEqual([]);
    x.act({ kind: "ping", nodeId: x.id(LAP), dst: "192.168.0.20" });
    expect(x.host(LAP).pings.at(-1)!.status).toBe("failed");
    // 지금: "up" (요약 "연결됨 (L2TP/IPsec) · 집 LAN 주소 192.168.0.50"). 서버가 StopCCN/Delete 를 보내거나(실제 xl2tpd·charon 재시작), 모르는 SPI 에 알려야
    expect(x.host(LAP).ra.state).not.toBe("up");
  });

  it("3b. 서버를 껐다 켜도 노트북은 '연결됨' 그대로 (클라이언트의 서버 StopCCN 처리 코드는 쓰이지 않는다)", () => {
    const x = loadTopology(exampleIptimeVpnTopology());
    x.apply(patchServer(x.t, { enabled: false }));
    x.apply(x.t);
    expect(x.node<Router>(HOME).vpnServer.connected).toEqual([]);
    expect(x.host(LAP).ra.state).not.toBe("up");
  });

  it("3c. 공유기 WAN 링크가 끊겼다 이어지면 서버는 세션을 비우는데 노트북은 '연결됨' 그대로 → 수동 WAN 은 주소가 그대로라 양쪽 모두 유지 (결정)", () => {
    const x = loadTopology(exampleIptimeVpnTopology());
    const wan = linkBetween(x.t, HOME, ISP);
    x.apply({ ...x.t, cables: x.t.cables.filter((c) => c.id !== wan.id) });
    x.apply(x.t);
    expect(x.node<Router>(HOME).vpnServer.connected.map((c) => c.vip)).toEqual(["192.168.0.50"]);
    expect(x.host(LAP).ra.state).toBe("up");
    x.act({ kind: "ping", nodeId: x.id(LAP), dst: "192.168.0.20" });
    expect(x.host(LAP).pings.at(-1)!.status).toBe("ok");
  });

  it("3e. 공유기가 연결을 말없이 잊으면(자동 WAN 이 주소를 잃음 등) 노트북의 다음 패킷에 INVALID-SPI → 노트북이 다시 접속", () => {
    const x = loadTopology(exampleIptimeVpnTopology());
    x.node<Router>(HOME).vpnServer.clear();
    const tr = x.act({ kind: "ping", nodeId: x.id(LAP), dst: "192.168.0.20" });
    expect(tr.some((e) => e.nodeId === x.id(HOME) && e.summary.includes("INVALID-SPI 로 알림"))).toBe(true);
    expect(tr.filter((e) => e.nodeId === x.id(HOME) && e.kind === "nat.miss")).toEqual([]);
    expect(x.host(LAP).ra.state).toBe("up");
    x.act({ kind: "ping", nodeId: x.id(LAP), dst: "192.168.0.20" });
    expect(x.host(LAP).pings.at(-1)!.status).toBe("ok");
  });

  it("3f. 서버를 끄면 노트북은 '끊김 · 공유기가 연결을 끊음 (StopCCN)' 으로 바뀌고, 켠 뒤 '다시 연결' 로 붙는다", () => {
    const x = loadTopology(exampleIptimeVpnTopology());
    x.apply(patchServer(x.t, { enabled: false }));
    expect(x.host(LAP).ra.state).toBe("failed");
    expect(x.host(LAP).ra.summary()).toContain("끊김 · 공유기가 연결을 끊음");
    x.apply(x.t);
    x.act({ kind: "ra-reconnect", nodeId: x.id(LAP) });
    expect(x.host(LAP).ra.state).toBe("up");
  });

  it("3g. 서버가 꺼진 공유기에 온 L2TP/IPsec 협상은 '포트 포워딩 규칙을 추가' 가 아니라 'VPN 서버가 꺼져 있음' 으로 기록", () => {
    const x = loadTopology(patchServer(exampleIptimeVpnTopology(), { enabled: false }));
    expect(x.s.net.trace.some((e) => e.nodeId === x.id(HOME) && e.summary.includes("VPN 서버가 꺼져 있어 받지 않음"))).toBe(true);
    expect(x.s.net.trace.filter((e) => e.nodeId === x.id(HOME) && e.kind === "nat.miss")).toEqual([]);
  });

  it("3d. 서버가 모르는 SA 의 ESP(UDP 4500)를 받으면 '포트 포워딩 규칙을 추가하면 열 수 있음' 이라고 엉뚱하게 안내한다", () => {
    const x = loadTopology(exampleIptimeVpnTopology());
    x.apply(patchServer(x.t, { poolEnd: "192.168.0.58" }));
    const tr = x.act({ kind: "ping", nodeId: x.id(LAP), dst: "192.168.0.20" });
    const miss = tr.filter((e) => e.nodeId === x.id(HOME) && e.kind === "nat.miss");
    // 지금: "NAT 테이블에 없는 UDP 포트 4500 → 드롭 … (UDP 포트 포워딩 규칙을 추가하면 열 수 있음)" — VPN 서버가 켜져 있는데 4500 포워딩을 권함
    expect(miss.filter((e) => e.summary.includes("포트 포워딩 규칙을 추가"))).toEqual([]);
  });

  it("4. 노트북 → 집 LAN 의 없는 주소: 공유기가 ARP 실패에 Host Unreachable(!H)을 보내지 않아 timeout 만 (인터넷에서 온 것에는 보냄)", () => {
    const x = loadTopology(exampleIptimeVpnTopology());
    const tr = x.act({ kind: "ping", nodeId: x.id(LAP), dst: "192.168.0.99" });
    expect(tr.some((e) => e.nodeId === x.id(HOME) && e.kind === "arp.timeout")).toBe(true);
    // 지금: Router.onTimer("arp-timeout") 이 출발지(192.168.0.50)가 LAN 대역이라 건너뜀 → 노트북 "timeout · 응답 없음"
    expect(tr.some((e) => e.nodeId === x.id(HOME) && e.kind === "icmp.unreachable.sent")).toBe(true);
    expect(x.host(LAP).pings.at(-1)!.reason).toContain("Host Unreachable");
  });

  it("5. 구성 검사 오탐 ra.server-off: 모뎀 공유기가 UDP 500·4500 을 안쪽 ipTIME 으로 포워딩하면(공유기 뒤 공유기) 실제로는 접속된다", () => {
    const t = doubleNat();
    const x = loadTopology(t);
    expect(x.host(LAP).ra.state).toBe("up");
    x.act({ kind: "ping", nodeId: x.id(LAP), dst: "192.168.0.20" });
    expect(x.host(LAP).pings.at(-1)!.status).toBe("ok");
    // 지금: ra.server-off "모뎀 공유기 (203.0.113.20) 에 VPN 서버(L2TP/IPsec)가 꺼져 있음 → IKE 에 답이 없어 접속 실패"
    expect(lintTopology(t).map((i) => i.code)).not.toContain("ra.server-off");
  });

  it("6. 구성 검사 오탐 ra.type-mismatch: VPN 서버를 켠 공유기가 UDP 500·4500 을 안쪽 IKEv2 서버로 포워딩하면 IKEv2 도 접속된다", () => {
    const t = ikev2BehindRouterWithVpnServer();
    const x = loadTopology(t);
    expect(x.host("재택 노트북").ra.state).toBe("up");
    x.act({ kind: "ping", nodeId: x.id("재택 노트북"), dst: "10.50.10.20" });
    expect(x.host("재택 노트북").pings.at(-1)!.status).toBe("ok");
    // 지금: ra.type-mismatch error "회사 공유기 는 공유기 VPN 서버(L2TP/IPsec)인데 … 공유기가 IKEv2 에 답하지 않아 접속 실패"
    expect(lintTopology(t).map((i) => i.code)).not.toContain("ra.type-mismatch");
  });

  it("7. NAT 가 서버 앞에 있을 때(공유기 뒤 공유기, 노트북은 공인 주소) 서버 로그가 '클라이언트가 공유기 뒤' 라고 탓한다", () => {
    const x = loadTopology(publicLaptop(doubleNat()));
    expect(x.host(LAP).ra.state).toBe("up");
    const srv = x.s.net.trace.find((e) => e.kind === "vpn.ike" && e.nodeId === x.id(HOME) && e.details?.nat !== undefined)!;
    // 지금: "NAT 있음 (클라이언트가 공유기 뒤 — 이후 UDP 4500, NAT-T)" — 노트북은 공인 주소, NAT 는 서버(ipTIME) 앞
    expect(srv.summary).not.toContain("클라이언트가 공유기 뒤");
    // 지금: charon "05[IKE] remote host is behind NAT" (실제는 local host)
    expect(practitionerLines(srv, {}).map((l) => l.line)).not.toContain("05[IKE] remote host is behind NAT");
    // 노트북 쪽 요약은 "NAT 서버 앞에 있음" 으로 맞는데 실무 줄은 "local host is behind NAT"
    const cli = x.s.net.trace.find((e) => e.kind === "vpn.ike" && e.nodeId === x.id(LAP) && e.summary.includes("Main Mode 응답 (NAT"))!;
    expect(cli.summary).toContain("서버 앞");
    expect(practitionerLines(cli, {}).map((l) => l.line).join("\n")).not.toContain("local host is behind NAT");
  });

  it("8. 실무 로그: 서버(공유기)의 vpn.up 이 클라이언트 줄 'local IP address <할당 주소>' 로 나온다 (서버 pppd 는 remote IP address)", () => {
    const x = loadTopology(exampleIptimeVpnTopology());
    const ev = x.s.net.trace.find((e) => e.kind === "vpn.up" && e.nodeId === x.id(HOME))!;
    // l2tpLines 가 서버를 요약 "VPN 서버" 로만 알아보는데 서버의 vpn.up 요약은 "VPN 접속 수립" 으로 시작
    expect(practitionerLines(ev, {}).map((l) => l.line)).toContain("pppd[2345]: remote IP address 192.168.0.50");
  });

  it("9a. VPN 을 끈 직후 터널로 오던 패킷이 도착하면 노트북이 서버에 ICMP Port Unreachable(UDP 4500)을 보낸다", () => {
    const x = loadTopology(exampleIptimeVpnTopology());
    const from = x.s.net.trace.length;
    x.s.net.scheduleAction(x.s.net.now, { kind: "ping", nodeId: x.id("집 NAS"), dst: "192.168.0.50" });
    // 공유기가 노트북으로 가는 패킷을 터널에 실은 순간 노트북 VPN 을 끈다 (그 ESP 는 이미 오는 중)
    while (!x.s.net.trace.slice(from).some((e) => e.kind === "vpn.encap" && e.nodeId === x.id(HOME))) x.s.net.step();
    x.s.sync(patchLaptop(x.t, { enabled: false }));
    x.s.net.runToIdle();
    const tr = x.s.net.trace.slice(from);
    // 지금: "UDP 포트 4500 를 듣는 프로그램 없음 → 드롭" + "203.0.113.20 에게 ICMP Destination Port Unreachable 통지" (IKEv2 원격 접속도 같은 길 — host.handleIp 가 ra.config.enabled 일 때만 VPN 이 받음)
    expect(tr.filter((e) => e.nodeId === x.id(LAP) && e.kind === "icmp.unreachable.sent")).toEqual([]);
  });

  it("9b. 협상 중 VPN 종류를 L2TP → IKEv2 로 바꾸면 늦게 온 Main Mode 응답에 ICMP Port Unreachable(UDP 500)을 보낸다", () => {
    const x = loadTopology(exampleIptimeVpnTopology());
    const from = x.s.net.trace.length;
    x.s.net.scheduleAction(x.s.net.now, { kind: "ra-reconnect", nodeId: x.id(LAP) });
    while (!x.s.net.trace.slice(from).some((e) => e.kind === "vpn.ike" && e.nodeId === x.id(LAP) && e.summary.includes("Main Mode 요청"))) x.s.net.step();
    x.s.sync(patchLaptop(x.t, { type: undefined }));
    x.s.net.runToIdle();
    const tr = x.s.net.trace.slice(from);
    // 지금: RaClient.handleIke 가 m.ra 가 아닌 응답을 false 로 돌려 호스트가 "UDP 포트 500 를 듣는 프로그램 없음" + Port Unreachable
    expect(tr.filter((e) => e.nodeId === x.id(LAP) && e.kind === "icmp.unreachable.sent")).toEqual([]);
  });

  it("9c. 협상 중 VPN 종류를 IKEv2 → L2TP 로 바꾸면 늦게 온 IKE_SA_INIT 응답에 ICMP Port Unreachable(UDP 500)을 보낸다", () => {
    const L = "재택 노트북";
    const x = loadTopology(exampleRemoteVpnTopology());
    const from = x.s.net.trace.length;
    x.s.net.scheduleAction(x.s.net.now, { kind: "ra-reconnect", nodeId: x.id(L) });
    while (!x.s.net.trace.slice(from).some((e) => e.kind === "vpn.ike" && e.nodeId === x.id(L) && e.summary.includes("IKE_SA_INIT 요청"))) x.s.net.step();
    x.s.sync(patchLaptop(x.t, { type: "l2tp" }, L));
    x.s.net.runToIdle();
    const tr = x.s.net.trace.slice(from);
    // 지금: L2tpClient.handleIke 가 m.l2tp 가 아닌 응답을 false 로 → Port Unreachable
    expect(tr.filter((e) => e.nodeId === x.id(L) && e.kind === "icmp.unreachable.sent")).toEqual([]);
  });

  it("10. 패킷 상세: ESP 전송 모드인데 ESP 아래에 '터널 안 · IPv4' 헤더(10.10.0.100 → 203.0.113.20)를 그린다", () => {
    const x = loadTopology(exampleIptimeVpnTopology());
    x.act({ kind: "ping", nodeId: x.id(LAP), dst: "192.168.0.20" });
    const frame = [...x.s.net.frameLog.values()]
      .flat()
      .map((y) => y.frame)
      .find((f) => f.payload.kind === "ipv4" && f.payload.payload.kind === "udp" && f.payload.payload.payload.kind === "esp" && f.payload.payload.payload.transport === true)!;
    const titles = headerLayers(frame).map((l) => l.title);
    const esp = titles.findIndex((x) => x.startsWith("ESP"));
    expect(esp).toBeGreaterThan(0);
    // 지금: "터널 안 · IPv4 (L3)" — 전송 모드에는 안쪽 IP 헤더가 없다 (ESP 바로 아래가 UDP 1701)
    expect(titles[esp + 1]).toContain("UDP");
  });

  it("11. 할당 IP 시작을 LAN 아래로 잘못 넣으면 주소 하나 고르는 데 범위를 한 칸씩 훑어 멈추고(10.0.0.1 이면 수십억 번), LAN 의 네트워크 주소를 준다", () => {
    const t0 = performance.now();
    const x = loadTopology(patchServer(exampleIptimeVpnTopology(), { poolStart: "192.0.0.50" }));
    const ms = performance.now() - t0;
    expect(lintTopology(x.t).map((i) => i.code)).toContain("router.vpn-pool"); // 구성 검사는 알려 준다
    // 지금: 192.168.0.0 (네트워크 주소)
    expect(x.host(LAP).ra.vip).not.toBe("192.168.0.0");
    // 지금: 수 초 (1,100만 번 반복 — L2tpServer.allocate 의 LAN 밖 continue)
    expect(ms).toBeLessThan(1500);
  }, 120_000);

  it("12. 노트북이 끊긴 뒤 옛 프록시 ARP 로 공유기에 온 패킷을 '호스트끼리 직접 통신' 이라며 드롭한다", () => {
    const x = loadTopology(exampleIptimeVpnTopology());
    x.act({ kind: "ping", nodeId: x.id("집 NAS"), dst: "192.168.0.50" });
    x.apply(patchLaptop(x.t, { enabled: false }));
    const tr = x.act({ kind: "ping", nodeId: x.id("집 NAS"), dst: "192.168.0.50" });
    const drop = tr.find((e) => e.nodeId === x.id(HOME) && e.kind === "ip.drop")!;
    expect(drop).toBeDefined();
    // 지금: "목적지 192.168.0.50 는 LAN 안의 주소 → 라우터를 거칠 필요가 없음 (호스트끼리 직접 통신) → 드롭" — NAS 가 공유기로 보낸 이유는 VPN 기기의 프록시 ARP
    expect(drop.summary).not.toContain("호스트끼리 직접 통신");
  });

  it("13. 할당 IP 안의 주소를 LAN 의 수동 장치가 쓰고 있어도 구성 검사는 침묵하고, 서버는 그 주소를 VPN 기기에 준다", () => {
    const t = exampleIptimeVpnTopology();
    const devices = [...t.devices];
    const pc = { ...createDevice("pc", 700, 152, devices), name: "집 PC" };
    pc.host = { ...pc.host!, ipMode: "static", ip: "192.168.0.50", prefix: 24, gateway: "192.168.0.1" };
    devices.push(pc);
    const home = devices.find((d) => d.name === HOME)!;
    const tt: Topology = { ...t, devices, cables: [...t.cables, { id: "c-pc", a: { device: home.id, port: 2 }, b: { device: pc.id, port: 0 } }] };
    const x = loadTopology(tt);
    expect(x.host(LAP).ra.vip).toBe("192.168.0.50"); // 서버는 쓰는 중인지 보지 않는다 (실제 ipTIME 도 그럴 수 있음)
    x.act({ kind: "ping", nodeId: x.id("집 NAS"), dst: "192.168.0.50" });
    // NAS 의 192.168.0.50 은 노트북이 아니라 집 PC 로 간다
    expect(x.host("집 NAS").iface.arpCache.get("192.168.0.50")?.mac).toBe(x.host("집 PC").iface.mac);
    // 지금: [] — router.vpn-pool 은 DHCP 범위만 본다
    expect(lintTopology(tt).length).toBeGreaterThan(0);
  });
});
