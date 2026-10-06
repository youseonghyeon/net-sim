// 메시 VPN (Tailscale·ZeroTier) 리뷰: 확인된 결함의 재현 (실패하는 테스트 = 결함)
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleTailscaleTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import type { MeshSettings, Topology } from "../src/model/topology";
import { DEFAULT_OVPN_SERVER_SETTINGS } from "../src/model/topology";
import { ovpnCaOfDevice, ovpnTlsCryptOfDevice } from "../src/model/topology";

const LAPTOP = "카페 노트북";
const PC = "회사 PC";
const HOME = "집 Brume 3";
const NAS = "집 NAS";
const CAFE = "카페 공유기";
const mesh = (t: Topology, name: string, p: Partial<MeshSettings>): Topology => ({
  ...t,
  devices: t.devices.map((d) =>
    d.name !== name
      ? d
      : d.host
        ? { ...d, host: { ...d.host, mesh: { ...(d.host.mesh ?? { enabled: true, net: "tailscale", network: "family", name: "" }), ...p } } }
        : { ...d, router: { ...d.router!, mesh: { ...(d.router!.mesh ?? { enabled: true, net: "tailscale", network: "family", name: "" }), ...p } } },
  ),
});
const edit = (t: Topology, name: string, f: (d: Topology["devices"][number]) => Topology["devices"][number]): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });

describe("메시 VPN 리뷰", () => {
  it("1. 이름을 바꾸면 조정 서버의 기기 이름(MagicDNS)도 바뀐다", () => {
    const L = loadTopology(exampleTailscaleTopology());
    L.apply(mesh(L.t, LAPTOP, { name: "mylaptop" }));
    expect(L.host(LAPTOP).mesh.self?.name).toBe("mylaptop");
    L.act({ kind: "ping", nodeId: L.id(PC), dst: "mylaptop" });
    expect(L.host(PC).pings.at(-1)!.status).toBe("ok");
  });

  it("2. 같은 이름 셋: 세 번째도 laptop-1 이 되면 안 된다 (laptop-2)", () => {
    let t = mesh(exampleTailscaleTopology(), PC, { name: "laptop" });
    t = mesh(t, HOME, { name: "laptop" });
    const L = loadTopology(t);
    const names = [L.host(LAPTOP).mesh.self!.name, L.host(PC).mesh.self!.name, L.node<Router>(HOME).mesh.self!.name];
    expect(new Set(names).size).toBe(3);
  });

  it("3. 이름이 laptop-1 로 바뀐 기기에서 'laptop' 은 상대(원래 laptop)로 풀려야 한다 (자기 자신 X)", () => {
    const L = loadTopology(mesh(exampleTailscaleTopology(), PC, { name: "laptop" }));
    expect(L.host(PC).mesh.self!.name).toBe("laptop-1");
    expect(L.host(PC).mesh.resolve("laptop")).toBe(L.host(LAPTOP).mesh.self!.ip);
  });

  it("4. 자기 MagicDNS 이름으로 ping 하면 자기 자신에게 닿는다", () => {
    const L = loadTopology(exampleTailscaleTopology());
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "laptop" });
    expect(L.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
  });

  it("5. 서브넷 라우터 LAN 의 기기가 그 공유기 자신의 메시 주소로 ping 하면 공유기가 답한다", () => {
    const L = loadTopology(exampleTailscaleTopology());
    const own = L.node<Router>(HOME).mesh.self!.ip;
    const tr = L.act({ kind: "ping", nodeId: L.id(NAS), dst: own });
    expect(tr.some((e) => e.kind === "ip.no-route" && e.summary.includes("온라인 피어가 없음"))).toBe(false);
    expect(L.host(NAS).pings.at(-1)!.status).toBe("ok");
  });

  it("6. 카페 공유기의 공인 주소가 바뀐(isp-renumber) 뒤 주기 확인(25초)이 지나면 집 쪽에서 노트북으로 먼저 보내도 닿고, 새 netmap 도 받는다", () => {
    const L = loadTopology(exampleTailscaleTopology());
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "192.168.8.20" });
    expect(L.node<Router>(HOME).mesh.rows().find((r) => r[0] === "laptop")![2]).toMatch(/^직접/);
    const old = L.node<Router>(CAFE).wan.ip!;
    L.act({ kind: "isp-renumber", nodeId: L.id("internet-1"), ip: old });
    expect(L.node<Router>(CAFE).wan.ip).not.toBe(old);
    // 노트북은 바깥 주소가 바뀐 것을 주기 확인(25초 — STUN·조정 서버·릴레이 연결 유지)으로 알아챈다 (시간이 흐를 때만)
    L.s.net.runUntil(L.s.net.now + 30_000);
    // 집 NAS → 노트북 메시 주소 (서브넷 라우터 경유, 노트북이 먼저 보내지 않음)
    L.act({ kind: "ping", nodeId: L.id(NAS), dst: L.host(LAPTOP).mesh.self!.ip });
    expect(L.host(NAS).pings.at(-1)!.status).toBe("ok");
  });

  it("6b. 카페 공유기 공인 주소가 바뀐 뒤 주기 확인이 지나면 노트북은 조정 서버의 netmap 갱신(회사 PC 로그아웃)을 받는다", () => {
    const L = loadTopology(exampleTailscaleTopology());
    const old = L.node<Router>(CAFE).wan.ip!;
    L.act({ kind: "isp-renumber", nodeId: L.id("internet-1"), ip: old });
    L.s.net.runUntil(L.s.net.now + 30_000);
    L.apply(mesh(L.t, PC, { enabled: false }));
    expect(L.host(LAPTOP).mesh.rows().find((r) => r[0] === "work-pc")![2]).toBe("오프라인");
  });

  it("7. 직접 경로를 막던 방화벽을 치운 뒤 시간이 지나면 다시 홀 펀칭해 직접 경로가 된다 (relayOnly 가 영원하지 않음)", () => {
    const fw = edit(exampleTailscaleTopology(), CAFE, (d) => ({
      ...d,
      router: { ...d.router!, firewall: { enabled: true, defaultPolicy: "allow", stateful: true, rules: [{ action: "deny", proto: "udp", direction: "out", src: "", dst: "", dstPort: "41641" }] } },
    }));
    const L = loadTopology(fw);
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "192.168.8.20" });
    expect(L.host(LAPTOP).mesh.rows().find((r) => r[0] === "home-brume")![2]).toContain("직접 실패");
    L.apply(edit(L.t, CAFE, (d) => ({ ...d, router: { ...d.router!, firewall: undefined } })));
    L.s.net.runUntil(L.s.net.now + 30_000);
    for (let i = 0; i < 3; i++) L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "192.168.8.20" });
    expect(L.host(LAPTOP).mesh.rows().find((r) => r[0] === "home-brume")![2]).toMatch(/^직접/);
  });

  it("8b. 공유기가 UDP 41641 을 LAN 의 Tailscale 기기로 포트 포워딩하면 그 기기가 로그인된다 (공유기 자신의 메시 앱이 netmap 을 가로채지 않음)", () => {
    let t = edit(exampleTailscaleTopology(), HOME, (d) => ({ ...d, router: { ...d.router!, forwards: [{ publicPort: 41641, lanIp: "192.168.8.20", lanPort: 41641, proto: "udp" }] } }));
    t = mesh(t, NAS, { enabled: true, net: "tailscale", network: "family", name: "nas" });
    const L = loadTopology(t);
    expect(L.host(NAS).mesh.up).toBe(true);
    expect(L.node<Router>(HOME).mesh.self!.name).toBe("home-brume");
  });

  it("8. 공유기 NAT 가 LAN 기기의 흐름에 공인 포트 41641 을 줘도 공유기 자신의 메시 앱이 가로채지 않는다", () => {
    const base = exampleTailscaleTopology();
    const L = loadTopology(base);
    const home = L.node<Router>(HOME);
    const homeIp = home.mesh.self!.ip;
    // NAT 할당 순번을 41641 앞에 두고 NAS 가 Tailscale 에 로그인 (실제로는 흐름 1641 개 뒤)
    (home.nat as unknown as { seq: number }).seq = 41641;
    L.apply(mesh(L.t, NAS, { enabled: true, net: "tailscale", network: "family", name: "nas" }));
    expect(home.mesh.self!.ip).toBe(homeIp);
    expect(L.host(NAS).mesh.up).toBe(true);
  });

  it("9. exit node 이름: UI 가 주는 MagicDNS 이름(home-brume)으로 고르면 기기 이름을 'Home Brume' 으로 적은 공유기도 exit node 로 쓰인다", () => {
    let t = mesh(exampleTailscaleTopology(), HOME, { name: "Home Brume" });
    t = mesh(t, LAPTOP, { useExitNode: "home-brume" });
    expect(lintTopology(t).filter((i) => i.code.startsWith("mesh."))).toEqual([]);
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "8.8.8.8" });
    expect(tr.some((e) => e.nodeId === L.id(HOME) && e.kind === "nat.translate" && e.summary.includes("100.64.0."))).toBe(true);
  });

  it("10. OpenVPN(redirect-gateway)이 연결된 노트북도 메시 피어(100.64.x.y)에는 메시로 닿는다 (더 긴 경로가 이김)", () => {
    let t = exampleTailscaleTopology();
    t = mesh(t, HOME, { enabled: false });
    t = edit(t, HOME, (d) => ({
      ...d,
      router: { ...d.router!, wan: { ipMode: "static", ip: "203.0.113.40", prefix: 24, gateway: "203.0.113.1" }, ovpnServer: { ...DEFAULT_OVPN_SERVER_SETTINGS, redirectGateway: true } },
    }));
    const home = t.devices.find((d) => d.name === HOME)!;
    const ca = ovpnCaOfDevice(home);
    t = edit(t, LAPTOP, (d) => ({ ...d, host: { ...d.host!, ra: { enabled: true, type: "openvpn", server: "203.0.113.40", psk: "", ovpn: { proto: "udp", port: 1194, ca, cn: LAPTOP, certCa: ca, tlsCrypt: ovpnTlsCryptOfDevice(home) } } } }));
    const L = loadTopology(t);
    expect(L.host(LAPTOP).ra.summary()).toMatch(/연결/);
    expect(L.host(LAPTOP).mesh.up).toBe(true);
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "work-pc" });
    expect(L.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
  });

  // ---- 확인용 (통과하면 결함 아님) ----
  it("ok-a. 인터넷 노드가 없어도 runToIdle 이 끝난다 (로그인 재시도는 배경 타이머)", () => {
    const base = exampleTailscaleTopology();
    const inet = base.devices.find((d) => d.name === "internet-1")!.id;
    const t: Topology = { ...base, devices: base.devices.filter((d) => d.id !== inet), cables: base.cables.filter((c) => c.a.device !== inet && c.b.device !== inet) };
    const L = loadTopology(t, { maxEvents: 200_000 });
    expect(L.host(LAPTOP).mesh.up).toBe(false);
  });

  it("ok-b. 공유기를 치우면 다른 기기의 netmap 에서 오프라인", () => {
    const L = loadTopology(exampleTailscaleTopology());
    const homeId = L.id(HOME);
    L.apply({ ...L.t, devices: L.t.devices.filter((d) => d.id !== homeId), cables: L.t.cables.filter((c) => c.a.device !== homeId && c.b.device !== homeId) });
    expect(L.host(LAPTOP).mesh.rows().find((r) => r[0] === "home-brume")![2]).toBe("오프라인");
  });

  it("ok-c. 같은 카페 LAN 의 두 노트북은 LAN 후보로 직접", () => {
    const base = exampleTailscaleTopology();
    const lap = base.devices.find((d) => d.name === LAPTOP)!;
    const cafe = base.devices.find((d) => d.name === CAFE)!;
    const lap2 = { ...structuredClone(lap), id: "laptop-two", name: "노트북2", mac: "02:00:00:00:00:99", x: lap.x + 120 };
    lap2.host = { ...lap2.host!, mesh: { enabled: true, net: "tailscale", network: "family", name: "laptop2" } };
    const t: Topology = { ...base, devices: [...base.devices, lap2], cables: [...base.cables, { id: "c-two", a: { device: cafe.id, port: 2 }, b: { device: lap2.id, port: 0 } }] };
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "laptop2" });
    expect(L.host(LAPTOP).pings.at(-1)!.status).toBe("ok");
    expect(L.host(LAPTOP).mesh.rows().find((r) => r[0] === "laptop2")![2]).toMatch(/^직접 10\.20\.0\./);
  });

  it("ok-d. 같은 호스트에서 P2P 앱(UDP 41641)과 Tailscale 을 함께 켜도 P2P 연결이 된다", () => {
    let t = exampleTailscaleTopology();
    t = edit(t, LAPTOP, (d) => ({ ...d, host: { ...d.host!, p2p: { enabled: true, name: "lap" } } }));
    t = edit(t, PC, (d) => ({ ...d, host: { ...d.host!, p2p: { enabled: true, name: "pc" } } }));
    const L = loadTopology(t);
    const tr = L.act({ kind: "p2p-connect", nodeId: L.id(LAPTOP), peer: "pc" });
    expect(tr.some((e) => e.kind.startsWith("p2p.") && /연결됨|connected|릴레이|relay/.test(e.summary))).toBe(true);
    expect(L.host(LAPTOP).mesh.up).toBe(true);
  });
});
