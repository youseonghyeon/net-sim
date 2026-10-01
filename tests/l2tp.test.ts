// 공유기 VPN (ipTIME 식 L2TP/IPsec): 출장지 호텔 NAT 뒤 노트북이 집 공유기의 VPN 서버에 붙어 집 LAN 주소를 받고, 모든 트래픽이 집으로 간다 (full tunnel)
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import { loadTopology } from "./helpers";
import { exampleIptimeVpnTopology } from "../src/model/examples";
import { createDevice, type Device, type RouterVpnServerSettings, type Topology } from "../src/model/topology";
import { L2tpClient } from "../src/core/nodes/l2tp";
import { RaClient } from "../src/core/nodes/ravpn";
import type { Router } from "../src/core/nodes/router";
import { headerLayers, practitionerLines, tcpdumpLine } from "../src/model/packetView";

const load = (t: Topology = exampleIptimeVpnTopology()) => loadTopology(t);
const patchLaptop = (t: Topology, patch: Partial<NonNullable<NonNullable<Device["host"]>["ra"]>>, name = "출장 노트북"): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.name === name ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, ...patch } } } : d)),
});
const patchServer = (t: Topology, patch: Partial<RouterVpnServerSettings>): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.router?.vpnServer ? { ...d, router: { ...d.router, vpnServer: { ...d.router.vpnServer, ...patch } } } : d)),
});
/** 같은 호텔에 노트북을 하나 더 (계정 me 를 같이 쓴다) */
const secondLaptop = (t: Topology): Topology => {
  const devices = [...t.devices];
  const lap = { ...createDevice("laptop", 240, 152, devices), name: "출장 노트북 2" };
  lap.host = { ...lap.host!, ra: { ...t.devices.find((d) => d.name === "출장 노트북")!.host!.ra! } };
  devices.push(lap);
  const hotel = t.devices.find((d) => d.name === "호텔 공유기")!;
  return { ...t, devices, cables: [...t.cables, { id: "lap2", a: { device: hotel.id, port: 2 }, b: { device: lap.id, port: 0 } }] };
};

describe("공유기 VPN (L2TP/IPsec)", () => {
  it("노트북이 켜지면서 IPsec(NAT-T) → L2TP → PPP 로 붙어 집 LAN 주소를 받는다", () => {
    const { t, s, host, node, wire } = load();
    expect(lintTopology(t)).toEqual([]);
    const lap = host("출장 노트북");
    expect(lap.ra).toBeInstanceOf(L2tpClient);
    expect(lap.ra.state).toBe("up");
    expect(lap.ra.vip).toBe("192.168.0.50");
    expect((lap.ra as L2tpClient).dns).toBe("192.168.0.1");
    expect(node<Router>("집 ipTIME").vpnServer.connected).toEqual([{ user: "me", vip: "192.168.0.50", peer: "203.0.113.100", natT: true }]);
    // 순서: Main Mode(NAT 감지) → Main Mode(PSK) → Quick Mode → SCCRQ → ICRQ → LCP → CHAP → IPCP
    const steps = s.net.trace.filter((e) => e.nodeId === t.devices.find((d) => d.name === "출장 노트북")!.id && /^vpn\.(ike|eap|up)$/.test(e.kind) && !e.summary.includes("다시 보냄")).map((e) => e.summary.split(":")[1]!.trim().slice(0, 12));
    expect(steps.length).toBe(9);
    // 통신사 구간에는 공인 주소끼리의 UDP 500·4500 만 (집 LAN 주소는 ESP 안)
    const onWire = wire("통신사 구간").filter((p) => p.payload.kind === "udp" && (p.payload.dstPort === 4500 || p.payload.srcPort === 4500));
    expect(onWire.length).toBeGreaterThan(0);
    expect(wire("통신사 구간").every((p) => !p.src.startsWith("192.168.") && !p.dst.startsWith("192.168.") && !p.src.startsWith("10.") && !p.dst.startsWith("10."))).toBe(true);
  });

  it("집 NAS 에 TCP 80 — NAS 는 집 LAN 주소 192.168.0.50 에서 온 연결로 본다", () => {
    const { id, act, lastConn, serverConns } = load();
    act({ kind: "tcp-connect", nodeId: id("출장 노트북"), dst: "192.168.0.20", port: 80 });
    expect(lastConn("출장 노트북")).toMatchObject({ state: "CLOSED", finReceived: true, bytesReceived: 3000 });
    expect(serverConns("집 NAS").at(-1)!.remoteIp).toBe("192.168.0.50");
  });

  it("NAS 에서 노트북의 VPN 주소로 ping: 공유기가 그 주소의 ARP 에 대신 답하고(프록시 ARP) 터널로 넘긴다", () => {
    const { id, host, node, act } = load();
    const tr = act({ kind: "ping", nodeId: id("집 NAS"), dst: "192.168.0.50" });
    expect(host("집 NAS").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "arp.reply.sent" && e.nodeId === id("집 ipTIME") && e.summary.includes("프록시 ARP"))).toBe(true);
    expect(host("집 NAS").iface.arpCache.get("192.168.0.50")?.mac).toBe(node<Router>("집 ipTIME").lan.mac);
  });

  it("full tunnel: 8.8.8.8 도 집을 거쳐 집 공인 주소로 나간다 (호텔 공유기는 UDP 4500 만 변환)", () => {
    const { id, host, act } = load();
    const tr = act({ kind: "ping", nodeId: id("출장 노트북"), dst: "8.8.8.8" });
    expect(host("출장 노트북").pings.at(-1)!.status).toBe("ok");
    const homeNat = tr.find((e) => e.kind === "nat.translate" && e.nodeId === id("집 ipTIME"));
    expect(homeNat?.summary).toContain("192.168.0.50 (ICMP");
    expect(homeNat?.summary).toContain("203.0.113.20");
    expect(tr.filter((e) => e.kind === "nat.translate" && e.nodeId === id("호텔 공유기")).every((e) => e.summary.includes("UDP 포트 4500"))).toBe(true);
  });

  it("이름은 집 공유기가 알려 준 DNS(IPCP, 공유기 DNS 포워더)로 터널 안에서 묻는다", () => {
    const { id, host, act } = load();
    const tr = act({ kind: "ping", nodeId: id("출장 노트북"), dst: "naver.com" });
    expect(host("출장 노트북").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "vpn.encap" && e.nodeId === id("출장 노트북") && e.summary.includes("192.168.0.1 로 가는"))).toBe(true);
    expect(tr.some((e) => e.nodeId === id("호텔 공유기") && e.kind.startsWith("dns."))).toBe(false);
  });

  it("traceroute 8.8.8.8: 첫 홉이 집 공유기 LAN 주소 (호텔 공유기는 터널 바깥이라 보이지 않는다)", () => {
    const { id, host, act } = load();
    act({ kind: "traceroute", nodeId: id("출장 노트북"), dst: "8.8.8.8" });
    const rec = host("출장 노트북").traceroutes.at(-1)!;
    expect(rec.status).toBe("done");
    expect(rec.hops[0]!.ip).toBe("192.168.0.1");
  });

  it("사전 공유 키가 다르면 IPsec 단계에서 실패하고 구성 검사가 지적한다", () => {
    const t = patchLaptop(exampleIptimeVpnTopology(), { psk: "wrong" });
    expect(lintTopology(t).map((i) => i.code)).toContain("ra.psk-mismatch");
    const lap = load(t).host("출장 노트북");
    expect(lap.ra.state).toBe("failed");
    expect(lap.ra.reason).toContain("사전 공유 키가 다름");
  });

  it("비밀번호가 다르면 PPP 계정 인증(CHAP)에서 실패 — 서버 로그만 이유를 구분한다", () => {
    const t = patchLaptop(exampleIptimeVpnTopology(), { password: "nope" });
    expect(lintTopology(t).map((i) => i.code)).toContain("ra.account-mismatch");
    const x = load(t);
    expect(x.host("출장 노트북").ra.state).toBe("failed");
    expect(x.host("출장 노트북").ra.reason).toContain("계정 또는 비밀번호가 틀림");
    expect(x.s.net.trace.some((e) => e.nodeId === x.id("집 ipTIME") && e.summary.includes("me 의 비밀번호가 다름"))).toBe(true);
    expect(x.node<Router>("집 ipTIME").vpnServer.connected).toEqual([]);
  });

  it("노트북에 계정이 없으면 CHAP 요청을 받고 실패한다", () => {
    const t = patchLaptop(exampleIptimeVpnTopology(), { user: undefined, password: undefined });
    expect(lintTopology(t).map((i) => i.code)).toContain("ra.no-account");
    const lap = load(t).host("출장 노트북");
    expect(lap.ra.state).toBe("failed");
    expect(lap.ra.reason).toContain("계정이 없음");
  });

  it("공유기 VPN 서버가 꺼져 있으면 Main Mode 재전송 뒤 timeout", () => {
    const t = patchServer(exampleIptimeVpnTopology(), { enabled: false });
    expect(lintTopology(t).map((i) => i.code)).toContain("ra.server-off");
    const lap = load(t).host("출장 노트북");
    expect(lap.ra.state).toBe("failed");
    expect(lap.ra.reason).toContain("Main Mode 응답 없음");
  });

  it("VPN 을 끄면 L2TP(StopCCN)·IPsec(Delete)를 알려 주소를 돌려주고, 다시 켜면 같은 주소를 받는다", () => {
    const x = load();
    const tr = x.apply(patchLaptop(x.t, { enabled: false }));
    expect(tr.some((e) => e.nodeId === x.id("집 ipTIME") && e.summary.includes("StopCCN"))).toBe(true);
    expect(x.node<Router>("집 ipTIME").vpnServer.connected).toEqual([]);
    x.apply(x.t);
    expect(x.host("출장 노트북").ra.vip).toBe("192.168.0.50");
    x.act({ kind: "ping", nodeId: x.id("출장 노트북"), dst: "192.168.0.20" });
    expect(x.host("출장 노트북").pings.at(-1)!.status).toBe("ok");
  });

  it("두 대가 같은 계정으로 붙으면 주소를 따로 받는다. 할당 IP 가 하나뿐이면 두 번째는 IPCP Nak 로 실패", () => {
    const two = load(secondLaptop(exampleIptimeVpnTopology()));
    expect([two.host("출장 노트북").ra.vip, two.host("출장 노트북 2").ra.vip].sort()).toEqual(["192.168.0.50", "192.168.0.51"]);
    const one = load(patchServer(secondLaptop(exampleIptimeVpnTopology()), { poolEnd: "192.168.0.50" }));
    const states = [one.host("출장 노트북").ra.state, one.host("출장 노트북 2").ra.state].sort();
    expect(states).toEqual(["failed", "up"]);
    const failed = [one.host("출장 노트북"), one.host("출장 노트북 2")].find((h) => h.ra.state === "failed")!;
    expect(failed.ra.reason).toContain("할당 IP");
  });

  it("계정 목록만 바뀌면 붙어 있는 세션은 유지된다 (인증은 접속할 때 한 번)", () => {
    const x = load();
    x.apply(patchServer(x.t, { users: [{ name: "other", password: "x" }] }));
    expect(x.host("출장 노트북").ra.state).toBe("up");
    x.act({ kind: "ping", nodeId: x.id("출장 노트북"), dst: "192.168.0.20" });
    expect(x.host("출장 노트북").pings.at(-1)!.status).toBe("ok");
  });

  it("실무 로그: 서버는 charon(IKEv1)·xl2tpd·pppd, 클라이언트는 pppd 주소 줄. tcpdump 는 Main Mode 를 ident 로", () => {
    const { s: sync, id } = load();
    const lines = (node: string, kind: string, pick: (e: (typeof sync.net.trace)[number]) => boolean = () => true) =>
      practitionerLines(sync.net.trace.find((e) => e.nodeId === id(node) && e.kind === kind && pick(e))!, {}).map((l) => l.line);
    expect(lines("집 ipTIME", "vpn.ike", (e) => e.details?.l2tp === "SCCRQ")[0]).toContain("xl2tpd[1234]: Connection established to 203.0.113.100, 1701");
    expect(lines("집 ipTIME", "vpn.eap", (e) => e.details?.ppp === "success")).toEqual(["pppd[2345]: MSCHAP-v2 peer authentication succeeded for me"]);
    expect(lines("출장 노트북", "vpn.up")).toEqual(["pppd[2345]: local  IP address 192.168.0.50"]);
    expect(lines("집 ipTIME", "vpn.ike", (e) => e.details?.nat === true).join("\n")).toContain("remote host is behind NAT");
    const mm = [...sync.net.frameLog.values()].flat().map((x) => x.frame).find((f) => f.payload.kind === "ipv4" && f.payload.payload.kind === "udp" && f.payload.payload.payload.kind === "ike" && f.payload.payload.payload.exchange === "MAIN_MODE")!;
    expect(tcpdumpLine(mm)).toContain("isakmp: phase 1 I ident");
    const ppp = [...sync.net.frameLog.values()].flat().map((x) => x.frame).find((f) => f.payload.kind === "ipv4" && f.payload.payload.kind === "udp" && f.payload.payload.payload.kind === "esp" && f.payload.payload.payload.inner.payload.kind === "udp")!;
    expect(headerLayers(ppp).map((l) => l.title).join(" / ")).toContain("L2TP");
  });

  it("VPN 종류를 IKEv2 로 바꾸면 L2TP 를 끊고 IKEv2 클라이언트로 바꿔 낀다 (공유기는 IKEv2 를 받지 않는다)", () => {
    const x = load();
    const tr = x.apply(patchLaptop(x.t, { type: undefined }));
    expect(x.host("출장 노트북").ra).toBeInstanceOf(RaClient);
    expect(tr.some((e) => e.summary.includes("VPN 종류가 바뀜"))).toBe(true);
    expect(x.node<Router>("집 ipTIME").vpnServer.connected).toEqual([]);
    expect(x.host("출장 노트북").ra.state).toBe("failed");
  });
});
