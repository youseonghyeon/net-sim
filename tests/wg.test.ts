// WireGuard (GL.iNet 식 공유기 서버·클라이언트, 폰 앱): 핸드셰이크·cryptokey routing·킬 스위치·VPN 정책·모르는 키에 침묵
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleWireguardTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import { WgClient, wgPrivateKey, wgPublicKey, validWgKey } from "../src/core/nodes/wg";
import { headerLayers, practitionerLines, tcpdumpLine } from "../src/model/packetView";
import type { RouterWgClientSettings, RouterWgServerSettings, Topology } from "../src/model/topology";

const load = (t: Topology = exampleWireguardTopology()) => loadTopology(t);
const patchServer = (t: Topology, patch: Partial<RouterWgServerSettings>): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.router?.wgServer ? { ...d, router: { ...d.router, wgServer: { ...d.router.wgServer, ...patch } } } : d)),
});
const patchClient = (t: Topology, patch: Partial<RouterWgClientSettings>): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.router?.wgClient ? { ...d, router: { ...d.router, wgClient: { ...d.router.wgClient, ...patch } } } : d)),
});

describe("WireGuard 키", () => {
  it("개인 키에서 공개 키가 정해지고, 실제 키와 같은 모양(base64 44자)이다", () => {
    const priv = wgPrivateKey("dev-1");
    expect(validWgKey(priv)).toBe(true);
    expect(validWgKey(wgPublicKey(priv))).toBe(true);
    expect(wgPublicKey(priv)).toBe(wgPublicKey(wgPrivateKey("dev-1")));
    expect(wgPublicKey(priv)).not.toBe(wgPublicKey(wgPrivateKey("dev-2")));
  });
});

describe("GL.iNet 식 WireGuard", () => {
  it("켜지면 여행용 공유기·폰이 집 Brume 에 핸드셰이크(Initiation → Response → keepalive)로 붙는다", () => {
    const { t, node, host, id, s } = load();
    expect(lintTopology(t)).toEqual([]);
    const home = node<Router>("집 Brume 3");
    expect(home.wgs.connected).toBe(2);
    expect(node<Router>("여행용 공유기").wgClientSummary()).toContain("연결됨");
    expect(host("출장 폰").ra).toBeInstanceOf(WgClient);
    expect(host("출장 폰").ra.state).toBe("up");
    // 폰: Initiation → Response → keepalive
    const phone = s.net.trace.filter((e) => e.nodeId === id("출장 폰") && /^vpn\.(handshake|up|keepalive)$/.test(e.kind)).map((e) => e.kind);
    expect(phone).toEqual(["vpn.handshake", "vpn.up", "vpn.keepalive"]);
  });

  it("여행 노트북(설정 없음)의 집 NAS 접속: 여행용 공유기가 터널 주소 10.0.0.2 로 바꿔 터널로 보낸다", () => {
    const { id, act, lastConn, serverConns, wire } = load();
    act({ kind: "tcp-connect", nodeId: id("여행 노트북"), dst: "192.168.8.20", port: 80 });
    expect(lastConn("여행 노트북")).toMatchObject({ state: "CLOSED", finReceived: true, bytesReceived: 3000 });
    expect(serverConns("집 NAS").at(-1)!.remoteIp).toBe("10.0.0.2");
    // 통신사 구간에는 공인 주소끼리의 UDP 51820 만 — 사설 주소는 터널 안
    const isp = wire("통신사 구간");
    expect(isp.some((p) => p.payload.kind === "udp" && p.payload.payload.kind === "wg" && p.payload.payload.inner?.dst === "192.168.8.20")).toBe(true);
    expect(isp.every((p) => !p.dst.startsWith("192.168.") && !p.src.startsWith("192.168.") && !p.dst.startsWith("10.0.0."))).toBe(true);
  });

  it("full tunnel: 노트북의 8.8.8.8 ping 은 집 공인 주소로 나가고, 이름은 집 공유기의 터널 주소(10.0.0.1) DNS 로 묻는다", () => {
    const { id, host, act } = load();
    const tr = act({ kind: "ping", nodeId: id("여행 노트북"), dst: "naver.com" });
    expect(host("여행 노트북").pings.at(-1)!.status).toBe("ok");
    // 여행용 공유기의 DNS 포워더가 VPN DNS 10.0.0.1 에 터널로 묻는다 (호텔·통신사 DNS 로 새지 않음)
    expect(tr.some((e) => e.nodeId === id("여행용 공유기") && e.kind === "dns.forward" && e.summary.includes("10.0.0.1"))).toBe(true);
    expect(tr.some((e) => e.nodeId === id("집 Brume 3") && e.kind === "dns.query.received" && e.summary.includes("10.0.0.2"))).toBe(true);
    // ping 은 집 Brume 의 NAT 로 공인 주소 203.0.113.30 이 되어 나간다
    const homeNat = tr.find((e) => e.kind === "nat.translate" && e.nodeId === id("집 Brume 3") && e.summary.includes("ICMP"));
    expect(homeNat?.summary).toContain("203.0.113.30");
    // 호텔 공유기가 변환한 것은 WireGuard UDP 뿐
    expect(tr.filter((e) => e.kind === "nat.translate" && e.nodeId === id("호텔 공유기")).every((e) => e.summary.includes("UDP"))).toBe(true);
  });

  it("폰은 split tunnel: 집 대역은 터널로, 8.8.8.8 은 호텔로 바로", () => {
    const { id, host, act } = load();
    let tr = act({ kind: "ping", nodeId: id("출장 폰"), dst: "192.168.8.20" });
    expect(host("출장 폰").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.nodeId === id("출장 폰") && e.kind === "vpn.encap")).toBe(true);
    tr = act({ kind: "ping", nodeId: id("출장 폰"), dst: "8.8.8.8" });
    expect(host("출장 폰").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.nodeId === id("출장 폰") && e.kind === "vpn.encap")).toBe(false);
  });

  it("NAS 에서 WireGuard 로 붙은 폰(10.0.0.3)으로 ping: 공유기가 그 터널로 넘긴다", () => {
    const { id, host, act } = load();
    act({ kind: "ping", nodeId: id("집 NAS"), dst: "10.0.0.3" });
    expect(host("집 NAS").pings.at(-1)!.status).toBe("ok");
  });

  it("서버에 등록된 공개 키가 다르면 서버는 아무 답도 하지 않고, 폰은 세 번 시도한 뒤 timeout", () => {
    const base = exampleWireguardTopology();
    const server = base.devices.find((d) => d.router?.wgServer)!.router!.wgServer!;
    const t = patchServer(base, { peers: server.peers.map((p) => (p.name === "출장 폰" ? { ...p, publicKey: wgPublicKey(wgPrivateKey("다른 폰")) } : p)) });
    const { id, host, s } = load(t);
    expect(host("출장 폰").ra.state).toBe("failed");
    const srv = s.net.trace.filter((e) => e.nodeId === id("집 Brume 3") && e.summary.includes("출장 폰") === false && e.kind === "vpn.drop");
    expect(srv.length).toBe(3);
    expect(srv[0]!.summary).toContain("피어 목록에 없음");
    // 서버는 Response 를 한 번도 보내지 않았다
    expect(s.net.trace.some((e) => e.nodeId === id("집 Brume 3") && e.kind === "vpn.handshake" && e.summary.includes("203.0.113.100:4000") && e.summary.includes("폰"))).toBe(false);
    expect(host("출장 폰").ra.summary()).toContain("응답하지 않음");
  });

  it("폰이 서버의 공개 키를 잘못 알면 mac1 에서 버려진다 (역시 침묵)", () => {
    const base = exampleWireguardTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "출장 폰" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, wg: { ...d.host!.ra!.wg!, serverKey: wgPublicKey(wgPrivateKey("엉뚱한 서버")) } } } } : d)) };
    const { id, host, s } = load(t);
    expect(host("출장 폰").ra.state).toBe("failed");
    expect(s.net.trace.some((e) => e.nodeId === id("집 Brume 3") && e.kind === "vpn.drop" && e.summary.includes("mac1"))).toBe(true);
  });

  it("cryptokey routing: 폰이 등록된 주소(10.0.0.3)가 아닌 10.0.0.9 를 쓰면 핸드셰이크는 되지만 데이터는 버려진다", () => {
    const base = exampleWireguardTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "출장 폰" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, wg: { ...d.host!.ra!.wg!, address: "10.0.0.9/32" } } } } : d)) };
    const { id, host, act } = load(t);
    expect(host("출장 폰").ra.state).toBe("up");
    const tr = act({ kind: "ping", nodeId: id("출장 폰"), dst: "192.168.8.20" });
    expect(host("출장 폰").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.nodeId === id("집 Brume 3") && e.kind === "vpn.drop" && e.summary.includes("AllowedIPs"))).toBe(true);
  });

  it("LAN 접근을 끄면 폰은 집 NAS 에 못 가고(fw.deny), 공유기 자신(10.0.0.1)에는 ping 이 된다", () => {
    const { id, host, act } = load(patchServer(exampleWireguardTopology(), { lanAccess: false }));
    let tr = act({ kind: "ping", nodeId: id("출장 폰"), dst: "192.168.8.20" });
    expect(host("출장 폰").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.nodeId === id("집 Brume 3") && e.kind === "fw.deny")).toBe(true);
    tr = act({ kind: "ping", nodeId: id("출장 폰"), dst: "10.0.0.1" });
    expect(host("출장 폰").pings.at(-1)!.status).toBe("ok");
  });

  it("킬 스위치: 서버가 꺼져 VPN 이 끊기면 노트북의 인터넷을 막는다 (호텔로 새지 않음)", () => {
    const L = load();
    const { id, host, act, apply, s } = L;
    apply(patchServer(L.t, { enabled: false }));
    // 세션이 남은 채 보낸 것이 버려진다 → 15초 뒤 새 핸드셰이크 → 3번 실패 (시간이 흘러야 알아챈다)
    act({ kind: "ping", nodeId: id("여행 노트북"), dst: "8.8.8.8" });
    expect(host("여행 노트북").pings.at(-1)!.status).toBe("failed");
    s.net.runUntil(s.net.now + 40_000);
    expect(L.node<Router>("여행용 공유기").wgClientSummary()).toContain("킬 스위치로 인터넷 차단");
    const tr = act({ kind: "ping", nodeId: id("여행 노트북"), dst: "8.8.8.8" });
    expect(host("여행 노트북").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.nodeId === id("여행용 공유기") && e.kind === "vpn.killswitch")).toBe(true);
    expect(tr.some((e) => e.nodeId === id("호텔 공유기") && e.kind === "nat.translate" && e.summary.includes("ICMP"))).toBe(false);
  });

  it("킬 스위치를 끄면 VPN 이 끊긴 동안 노트북 트래픽이 호텔로 바로 나간다 (vpn.leak)", () => {
    const L = load(patchClient(exampleWireguardTopology(), { killSwitch: false }));
    const { id, host, act, apply, s } = L;
    apply(patchServer(L.t, { enabled: false }));
    act({ kind: "ping", nodeId: id("여행 노트북"), dst: "8.8.8.8" });
    s.net.runUntil(s.net.now + 40_000);
    const tr = act({ kind: "ping", nodeId: id("여행 노트북"), dst: "8.8.8.8" });
    expect(host("여행 노트북").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.nodeId === id("여행용 공유기") && e.kind === "vpn.leak")).toBe(true);
    expect(tr.some((e) => e.nodeId === id("호텔 공유기") && e.kind === "nat.translate" && e.summary.includes("ICMP"))).toBe(true);
  });

  it("서버가 설정 변경으로 세션을 잊으면, 클라이언트는 15초 동안 답이 없을 때 새 핸드셰이크로 다시 잇는다", () => {
    const L = load();
    const { id, host, act, apply, s } = L;
    const server = L.t.devices.find((d) => d.router?.wgServer)!.router!.wgServer!;
    // 피어 이름만 바꿔도 그 피어의 세션은 새로 (설정이 바뀐 피어)
    const tr0 = apply(patchServer(L.t, { peers: server.peers.map((p) => (p.name === "출장 폰" ? { ...p, name: "출장 폰 (새 이름)" } : p)) }));
    expect(tr0.some((e) => e.kind === "vpn.config" && e.summary.includes("세션 1개는 버리고"))).toBe(true);
    let tr = act({ kind: "ping", nodeId: id("출장 폰"), dst: "192.168.8.20" });
    expect(host("출장 폰").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.nodeId === id("집 Brume 3") && e.kind === "vpn.drop" && e.summary.includes("모르는 세션"))).toBe(true);
    s.net.runUntil(s.net.now + 20_000);
    tr = act({ kind: "ping", nodeId: id("출장 폰"), dst: "192.168.8.20" });
    expect(host("출장 폰").pings.at(-1)!.status).toBe("ok");
  });

  it("VPN 정책 '목록의 기기는 VPN 을 쓰지 않음' 이면 그 노트북은 호텔로 바로 나간다", () => {
    const L = load();
    const lapIp = L.host("여행 노트북").iface.ip!;
    const { id, act, apply } = L;
    apply(patchClient(L.t, { policy: { mode: "exclude", devices: [lapIp] } }));
    const tr = act({ kind: "ping", nodeId: id("여행 노트북"), dst: "8.8.8.8" });
    expect(L.host("여행 노트북").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.nodeId === id("여행용 공유기") && e.kind === "vpn.encap")).toBe(false);
  });

  it("패킷 상세: Initiation 은 UDP 148바이트, WireGuard 층에 공개 키·mac1", () => {
    const { s } = load();
    const init = [...s.net.frameLog.values()].flat().map((x) => x.frame).find((f) => f.payload.kind === "ipv4" && f.payload.payload.kind === "udp" && f.payload.payload.payload.kind === "wg" && f.payload.payload.payload.type === "initiation")!;
    expect(tcpdumpLine(init)).toContain("UDP, length 148");
    const wg = headerLayers(init).find((l) => l.title === "WireGuard")!;
    expect(wg.rows.map((r) => r[0])).toContain("mac1");
  });
});

describe("WireGuard 실무 출력", () => {
  it("커널 dyndbg 줄: 응답자는 Receiving initiation → Sending response → Keypair, 모르는 키는 Invalid handshake initiation", () => {
    const { s, id } = load();
    const resp = s.net.trace.find((e) => e.nodeId === id("집 Brume 3") && e.kind === "vpn.handshake")!;
    expect(practitionerLines(resp, {}).map((l) => l.line)).toEqual(["wireguard: wg0: Receiving handshake initiation from peer 1 (?)", "wireguard: wg0: Sending handshake response to peer 1 (?)", expect.stringMatching(/^wireguard: wg0: Keypair \d+ created for peer 1$/)]);
    const base = exampleWireguardTopology();
    const server = base.devices.find((d) => d.router?.wgServer)!.router!.wgServer!;
    const bad = load(patchServer(base, { peers: server.peers.filter((p) => p.name !== "출장 폰") }));
    const drop = bad.s.net.trace.find((e) => e.kind === "vpn.drop" && e.details?.reason === "unknown-key")!;
    expect(practitionerLines(drop, {})[0]!.line).toBe("wireguard: wg0: Invalid handshake initiation from ?");
  });
});

describe("WireGuard 구성 검사", () => {
  const codes = (t: Topology) => lintTopology(t).map((i) => `${t.devices.find((d) => d.id === i.deviceId)!.name}:${i.code}`);
  const patchPhone = (t: Topology, wg: Partial<NonNullable<NonNullable<NonNullable<Topology["devices"][0]["host"]>["ra"]>["wg"]>>): Topology => ({
    ...t,
    devices: t.devices.map((d) => (d.name === "출장 폰" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, wg: { ...d.host!.ra!.wg!, ...wg } } } } : d)),
  });

  it("예제는 이슈 0", () => {
    expect(codes(exampleWireguardTopology())).toEqual([]);
  });

  it("서버 공개 키가 다르면 wg.server-key, 등록되지 않았으면 wg.not-registered, 주소가 다르면 wg.address-mismatch", () => {
    const t = exampleWireguardTopology();
    expect(codes(patchPhone(t, { serverKey: wgPublicKey(wgPrivateKey("x")) }))).toEqual(["출장 폰:wg.server-key"]);
    expect(codes(patchPhone(t, { privateKey: wgPrivateKey("새 폰") }))).toEqual(["출장 폰:wg.not-registered"]);
    expect(codes(patchPhone(t, { address: "10.0.0.9/32" }))).toEqual(["출장 폰:wg.address-mismatch"]);
    expect(codes(patchPhone(t, { port: 51821 }))).toEqual(["출장 폰:wg.port-mismatch"]);
  });

  it("서버가 꺼져 있으면 두 클라이언트 모두 wg.server-off", () => {
    expect(codes(patchServer(exampleWireguardTopology(), { enabled: false })).sort()).toEqual(["여행용 공유기:wg.server-off", "출장 폰:wg.server-off"]);
  });

  it("DNS 가 AllowedIPs 밖이면 wg.dns-outside, 터널 대역이 LAN 과 겹치면 wg.overlap, 피어 주소가 겹치면 wg.peer-duplicate", () => {
    const t = exampleWireguardTopology();
    expect(codes(patchPhone(t, { dns: "10.0.1.1" }))).toEqual(["출장 폰:wg.dns-outside"]);
    expect(codes(patchServer(t, { address: "192.168.8.254/24" })).includes("집 Brume 3:wg.overlap")).toBe(true);
    const server = t.devices.find((d) => d.router?.wgServer)!.router!.wgServer!;
    expect(codes(patchServer(t, { peers: server.peers.map((p) => ({ ...p, ip: "10.0.0.2" })) })).includes("집 Brume 3:wg.peer-duplicate")).toBe(true);
  });

  it("서버가 다른 공유기 뒤에 있으면 그 공유기의 UDP 포워딩을 따라간다 (포워딩 대상의 키로 판단)", () => {
    const t = exampleWireguardTopology();
    // 집 Brume 의 WAN 을 ISP 모뎀 공유기 뒤 사설 주소로 두고, 모뎀이 51820 을 포워딩하는 구성은 따라가기만 확인 (서버 꺼짐을 대상에서 찾는다)
    const modem = { ...t.devices.find((d) => d.name === "호텔 공유기")!, id: "modem", name: "모뎀", router: { ...t.devices.find((d) => d.name === "호텔 공유기")!.router!, wan: { ipMode: "static" as const, ip: "203.0.113.40", prefix: 24, gateway: "203.0.113.1" }, forwards: [{ publicPort: 51820, lanIp: "203.0.113.30", lanPort: 51820, proto: "udp" as const }] } };
    const moved: Topology = { ...t, devices: [...t.devices.map((d) => (d.name === "출장 폰" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, server: "203.0.113.40" } } } : d)), modem] };
    expect(codes(moved).filter((c) => c.startsWith("출장 폰"))).toEqual([]);
    expect(codes(patchServer(moved, { enabled: false })).filter((c) => c.startsWith("출장 폰"))).toEqual(["출장 폰:wg.server-off"]);
  });
});
