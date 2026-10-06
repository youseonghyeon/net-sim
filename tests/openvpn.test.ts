// OpenVPN: 인증서(CA·CRL)·tls-crypt·PUSH·UDP/TCP 전송·keepalive·재시작 알림
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleOpenVpnTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import type { Host } from "../src/core/nodes/host";
import type { OvpnClient } from "../src/core/nodes/openvpn";
import { NetworkSync } from "../src/model/netSync";
import type { OvpnClientSettings, RouterOvpnServerSettings, Topology } from "../src/model/topology";
import { headerLayers, practitionerLines, tcpdumpLine } from "../src/model/packetView";

const LAPTOP = "카페 노트북";
const HOME = "집 Brume 3";
const server = (t: Topology, p: Partial<RouterOvpnServerSettings>): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === HOME ? { ...d, router: { ...d.router!, ovpnServer: { ...d.router!.ovpnServer!, ...p } } } : d)) });
const client = (t: Topology, p: Partial<OvpnClientSettings>, ra: object = {}): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.name === LAPTOP ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, ...ra, ovpn: { ...d.host!.ra!.ovpn!, ...p } } } } : d)),
});
const reconnect = (L: ReturnType<typeof loadTopology>) => L.act({ kind: "ra-reconnect", nodeId: L.id(LAPTOP) });

describe("OpenVPN", () => {
  it("예제: 카페 노트북이 TCP 443 으로 집 Brume 3 에 붙어 PUSH 를 받고 집 NAS 에 닿는다", () => {
    const L = loadTopology(exampleOpenVpnTopology());
    const lap = L.host(LAPTOP);
    expect(lap.ra.state).toBe("up");
    expect(lap.ra.summary()).toContain("10.8.0.2");
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id(LAPTOP), dst: "192.168.8.20", port: 80 });
    expect(L.lastConn(LAPTOP).state).toBe("CLOSED");
    expect(L.serverConns("집 NAS").at(-1)!.remoteIp).toBe("10.8.0.2");
    expect(tr.some((e) => e.kind === "vpn.encap")).toBe(true);
    expect(L.node<Router>(HOME).ovpn.rows()[0]![0]).toBe(LAPTOP);
    expect(lintTopology(L.t)).toEqual([]);
    // 이름은 PUSH 받은 DNS(서버 터널 주소)로 — 집 공유기 DNS 포워더가 답한다
    const tr2 = L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "naver.com" });
    expect(tr2.some((e) => e.nodeId === L.id(HOME) && e.kind.startsWith("dns.") && e.summary.includes("10.8.0.2"))).toBe(true);
  });

  it("UDP 1194 로 바꾸면 카페 방화벽(웹만 허용)에 막혀 응답 없음으로 실패한다", () => {
    const t = client(server(exampleOpenVpnTopology(), { proto: "udp", port: 1194 }), { proto: "udp", port: 1194 });
    const L = loadTopology(t);
    expect(L.host(LAPTOP).ra.state).toBe("failed");
    expect(L.host(LAPTOP).ra.summary()).toContain("응답 없음");
    expect(L.s.net.trace.some((e) => e.kind === "fw.deny" && e.summary.includes("UDP"))).toBe(true);
    // 방화벽이 없는 곳에서는 UDP 로 붙는다
    const open: Topology = { ...t, devices: t.devices.map((d) => (d.name === "카페 공유기" ? { ...d, router: { ...d.router!, firewall: undefined } } : d)) };
    const L2 = loadTopology(open);
    expect(L2.host(LAPTOP).ra.state).toBe("up");
    L2.act({ kind: "ping", nodeId: L2.id(LAPTOP), dst: "192.168.8.20" });
    expect(L2.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
  });

  it("설정 파일의 CA 가 다르면 노트북이 서버 인증서를 믿지 않는다 (VERIFY ERROR)", () => {
    const L = loadTopology(client(exampleOpenVpnTopology(), { ca: "AA:BB:CC:DD:EE:FF:00:11" }));
    expect(L.host(LAPTOP).ra.state).toBe("failed");
    expect(L.host(LAPTOP).ra.summary()).toContain("VERIFY ERROR");
    expect(L.node<Router>(HOME).ovpn.connected).toBe(0);
  });

  it("다른 CA 가 발급한 내 인증서는 서버가 거절한다", () => {
    const L = loadTopology(client(exampleOpenVpnTopology(), { certCa: "AA:BB:CC:DD:EE:FF:00:11" }));
    expect(L.host(LAPTOP).ra.summary()).toContain("이 서버의 CA 가 발급한 인증서가 아님");
    expect(L.node<Router>(HOME).ovpn.rows()[0]![4]).toContain("VERIFY ERROR");
  });

  it("인증서를 폐기(CRL)하면 붙어 있던 노트북은 끊기고 다시 붙지 못한다", () => {
    const L = loadTopology(exampleOpenVpnTopology());
    expect(L.host(LAPTOP).ra.state).toBe("up");
    const tr = L.apply(server(L.t, { revoked: [LAPTOP] }));
    // 서버가 다시 시작(RST) → 노트북이 2초 뒤 다시 붙으려다 폐기로 거절
    expect(tr.some((e) => e.nodeId === L.id(LAPTOP) && e.summary.includes("RST"))).toBe(true);
    expect(L.host(LAPTOP).ra.state).toBe("failed");
    expect(L.host(LAPTOP).ra.summary()).toContain("폐기");
  });

  it("tls-crypt 키가 다르면 서버는 아무 답도 하지 않는다", () => {
    const L = loadTopology(client(exampleOpenVpnTopology(), { tlsCrypt: "00:00:00:00:00:00" }));
    const srv = L.s.net.trace.filter((e) => e.nodeId === L.id(HOME) && e.kind === "vpn.drop");
    expect(srv.some((e) => e.summary.includes("tls-crypt unwrap error"))).toBe(true);
    // 서버는 HARD_RESET_SERVER 를 보내지 않았다
    expect(L.s.net.trace.some((e) => e.nodeId === L.id(HOME) && e.kind === "vpn.handshake" && e.summary.includes("세션 시작"))).toBe(false);
    expect(L.host(LAPTOP).ra.summary()).toContain("tls-crypt 키가 다르거나");
  });

  it("계정을 요구하는 서버: 맞는 계정이면 붙고, 틀리면 AUTH_FAILED", () => {
    const base = server(exampleOpenVpnTopology(), { users: [{ name: "me", password: "pw1" }] });
    const ok = loadTopology(client(base, {}, { user: "me", password: "pw1" }));
    expect(ok.host(LAPTOP).ra.state).toBe("up");
    expect(ok.node<Router>(HOME).ovpn.rows()[0]![3]).toBe("me");
    const bad = loadTopology(client(base, {}, { user: "me", password: "x" }));
    expect(bad.host(LAPTOP).ra.summary()).toContain("AUTH_FAILED");
  });

  it("redirect-gateway 면 인터넷도 집을 거쳐 집 공인 주소로 나간다", () => {
    const L = loadTopology(server(exampleOpenVpnTopology(), { redirectGateway: true }));
    const tr = L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "8.8.8.8" });
    expect(L.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.nodeId === L.id(HOME) && e.kind === "nat.translate" && e.summary.includes("10.8.0.2"))).toBe(true);
    // 카페 방화벽은 ICMP 를 막지만, 터널 안이라 TCP 443 으로만 보인다
    expect(tr.some((e) => e.kind === "fw.deny")).toBe(false);
  });

  it("집 LAN 기기가 붙은 노트북에 먼저 보낼 수 있고, 터널 대역의 빈 주소는 Unreachable", () => {
    const L = loadTopology(exampleOpenVpnTopology());
    L.act({ kind: "ping", nodeId: L.id("집 NAS"), dst: "10.8.0.2" });
    expect(L.host("집 NAS").pings.at(-1)!.status).toBe("ok");
    L.act({ kind: "ping", nodeId: L.id("집 NAS"), dst: "10.8.0.77" });
    expect(L.host("집 NAS").pings.at(-1)!.status).toBe("failed");
  });

  it("노트북이 VPN 을 끄면 서버에 알리고(TCP FIN), 다시 켜면 같은 가상 주소", () => {
    const L = loadTopology(exampleOpenVpnTopology());
    const off = client(L.t, {}, { enabled: false });
    const tr = L.apply(off);
    expect(tr.some((e) => e.nodeId === L.id(HOME) && e.summary.includes("FIN"))).toBe(true);
    expect(L.node<Router>(HOME).ovpn.connected).toBe(0);
    L.apply(client(off, {}, { enabled: true }));
    expect(L.host(LAPTOP).ra.summary()).toContain("10.8.0.2");
    // 늦게 온 패킷이 Port Unreachable 로 새지 않는다
    expect(L.s.net.trace.some((e) => e.nodeId === L.id(LAPTOP) && e.kind === "icmp.unreachable.sent")).toBe(false);
  });

  it("UDP: 서버 설정이 바뀌면 붙어 있던 노트북에 RESTART 를 알리고 노트북이 다시 붙는다", () => {
    const t = client(server(exampleOpenVpnTopology(), { proto: "udp", port: 1194 }), { proto: "udp", port: 1194 });
    const open: Topology = { ...t, devices: t.devices.map((d) => (d.name === "카페 공유기" ? { ...d, router: { ...d.router!, firewall: undefined } } : d)) };
    const L = loadTopology(open);
    expect(L.host(LAPTOP).ra.state).toBe("up");
    const tr = L.apply(server(L.t, { pushDns: false }));
    expect(tr.some((e) => e.nodeId === L.id(LAPTOP) && e.summary.includes("RESTART"))).toBe(true);
    expect(L.host(LAPTOP).ra.state).toBe("up");
    expect((L.host(LAPTOP).ra as OvpnClient).dns).toBeUndefined();
  });

  it("UDP: 서버 응답이 사라지면 같은 요청을 다시 보내고, 서버는 같은 답을 다시 보낸다", () => {
    const t = client(server(exampleOpenVpnTopology(), { proto: "udp", port: 1194 }), { proto: "udp", port: 1194 });
    const open: Topology = { ...t, devices: t.devices.map((d) => (d.name === "카페 공유기" ? { ...d, router: { ...d.router!, firewall: undefined } } : d)) };
    const s = new NetworkSync();
    s.sync(open);
    const id = (n: string) => open.devices.find((d) => d.name === n)!.id;
    const link = open.cables.find((c) => [c.a.device, c.b.device].includes(id(HOME)) && [c.a.device, c.b.device].includes(id("통신사 구간")))!;
    // 노트북의 TLS 클라이언트 인증서가 집 링크에 실린 뒤, 그 링크의 다음 프레임(= TLS 완료 응답)을 떨어뜨린다
    while (!s.net.trace.some((e) => e.nodeId === id(LAPTOP) && e.summary.includes("VERIFY OK 서버"))) s.net.step();
    const from = s.net.trace.length;
    while (!s.net.trace.slice(from).some((e) => e.kind === "link.transmit" && e.details?.linkId === link.id)) s.net.step();
    s.net.dropNextOn(link.id);
    s.net.runToIdle();
    const tr = s.net.trace.slice(from);
    expect(tr.some((e) => e.kind === "link.loss")).toBe(true);
    expect(tr.some((e) => e.nodeId === id(HOME) && e.summary.includes("그대로 다시 보냄"))).toBe(true);
    expect((s.net.nodes.get(id(LAPTOP)) as Host).ra.state).toBe("up");
  });

  it("같은 인증서를 두 기기가 쓰면 나중에 붙은 쪽이 앞 기기를 밀어낸다 (duplicate-cn 꺼짐)", () => {
    const base = exampleOpenVpnTopology();
    const lap = base.devices.find((d) => d.name === LAPTOP)!;
    const cafe = base.devices.find((d) => d.name === "카페 공유기")!;
    const twin = { ...structuredClone(lap), id: "laptop-twin", name: "복제 노트북", mac: "02:00:00:00:00:99", y: lap.y + 120 };
    const t: Topology = { ...base, devices: [...base.devices, twin], cables: [...base.cables, { id: "c-twin", a: { device: cafe.id, port: 2 }, b: { device: twin.id, port: 0 } }] };
    const L = loadTopology(t);
    expect(L.node<Router>(HOME).ovpn.connected).toBe(1);
    expect(L.s.net.trace.some((e) => e.kind === "vpn.drop" && e.summary.includes("duplicate-cn"))).toBe(true);
    expect(lintTopology(t).map((i) => i.code)).toContain("ovpn.duplicate-cn");
  });

  it("DPI 는 TCP 443 이어도 모양으로 OpenVPN 을 알아보고 막는다", () => {
    const base = exampleOpenVpnTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "카페 공유기" ? { ...d, router: { ...d.router!, dpi: { enabled: true, blockApps: [], blockCategories: ["VPN"] } } } : d)) };
    const L = loadTopology(t);
    expect(L.host(LAPTOP).ra.state).not.toBe("up");
    expect(L.s.net.trace.some((e) => e.kind === "dpi.block" && e.summary.includes("OpenVPN"))).toBe(true);
  });

  it("패킷 상세: 바깥 TCP 443 위의 OpenVPN 층과 tls-crypt, 데이터는 터널 안 원래 패킷", () => {
    const L = loadTopology(exampleOpenVpnTopology());
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "192.168.8.20" });
    const frames = [...L.s.net.frameLog.values()].flat().map((x) => x.frame);
    const reset = frames.find((f) => f.payload.kind === "ipv4" && f.payload.payload.kind === "tcp" && f.payload.payload.ovpn?.op === "reset-client")!;
    const layers = headerLayers(reset);
    expect(layers.find((l) => l.title === "OpenVPN")!.rows.some(([k]) => k === "tls-crypt")).toBe(true);
    const data = frames.find((f) => f.payload.kind === "ipv4" && f.payload.payload.kind === "tcp" && f.payload.payload.ovpn?.op === "data")!;
    expect(headerLayers(data).some((l) => l.title.startsWith("터널 안"))).toBe(true);
    expect(tcpdumpLine(reset)).toContain("443");
  });

  it("실무 로그: openvpn 의 VERIFY OK·PUSH_REPLY·Initialization Sequence Completed·tls-crypt unwrap error", () => {
    const L = loadTopology(exampleOpenVpnTopology());
    const lines = L.s.net.trace.flatMap((e) => practitionerLines(e, {}).filter((l) => l.tool.startsWith("openvpn")).map((l) => l.line));
    expect(lines).toContain("Initialization Sequence Completed");
    expect(lines.some((l) => l.includes("VERIFY OK: depth=0, CN=카페 노트북"))).toBe(true);
    expect(lines.some((l) => l.startsWith("PUSH: Received control message: 'PUSH_REPLY,") && l.includes("route 192.168.8.0 255.255.255.0") && l.includes("ifconfig 10.8.0.2 255.255.255.0"))).toBe(true);
    const bad = loadTopology(client(exampleOpenVpnTopology(), { tlsCrypt: "00:00:00:00:00:00" }));
    const badLines = bad.s.net.trace.flatMap((e) => practitionerLines(e, {}).map((l) => l.line));
    expect(badLines).toContain("tls-crypt unwrap error: packet authentication failed");
  });
});
