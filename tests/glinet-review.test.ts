// 리뷰 (1e4891b 공유기 관리): 관리 접근·기기 차단·GoodCloud·드롭인 게이트웨이. 여기의 테스트는 모두 확인된 결함의 재현 — 고치기 전에는 실패한다
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleDropInTopology, exampleDualStackHomeTopology, exampleMultiWanTopology, exampleWireguardTopology } from "../src/model/examples";
import type { Router } from "../src/core/nodes/router";
import type { RouterSettings, Topology } from "../src/model/topology";
import { lintTopology } from "../src/model/lint";

const HOME = "집 Brume 3";
const NAS = "집 NAS";
const BRUME = "Brume 3 (드롭인)";
const KID = "아이 PC";
const OFFICE = "사무실 Brume 3";
const router = (t: Topology, name: string, p: Partial<RouterSettings>): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? { ...d, router: { ...d.router!, ...p } } : d)) });
const admin = (t: Topology, name: string, p: Partial<NonNullable<RouterSettings["admin"]>> = {}) => router(t, name, { admin: { enabled: true, remote: false, allow: "", ssh: true, ...p } });

describe("드롭인 게이트웨이", () => {
  it("드롭인으로 온 기기도 VPN 클라이언트 정책·킬 스위치를 따른다 (터널이 끊겼으면 WAN 으로 새지 않음)", () => {
    // 서버가 없는 주소라 핸드셰이크가 실패 → 킬 스위치가 붙잡아야 한다
    const t = router(exampleDropInTopology(), BRUME, {
      wgClient: { enabled: true, server: "203.0.113.99", port: 51820, serverKey: `${"x".repeat(43)}=`, address: "10.0.0.2/32", allowedIps: "0.0.0.0/0", dns: "", killSwitch: true, policy: { mode: "all", devices: [] } },
    });
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id(KID), dst: "8.8.8.8" });
    // 실제: policyApplies() 가 LAN 대역 출발지만 보므로 드롭인 기기는 VPN·킬 스위치를 건너뛰고 WAN 으로 NAT 되어 나간다 (ping ok)
    expect(tr.some((e) => e.nodeId === L.id(BRUME) && e.kind === "vpn.killswitch")).toBe(true);
    expect(L.host(KID).pings.at(-1)!.status).toBe("failed");
  });

  it("DPI 가 드롭인 기기의 TCP 를 막으면 RST 가 그 기기(WAN 쪽)로 간다 — LAN 인터페이스로 보내 No route 가 되면 안 된다", () => {
    const L = loadTopology(exampleDropInTopology());
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id(KID), dst: "roblox.com", port: 443 });
    // 실제: dpiCheck 가 rstToClient 를 this.lan.sendIp 로 보내 "192.168.0.50 는 다른 서브넷인데 게이트웨이 설정 없음 → 드롭", 아이 PC 는 5.8초 timeout
    expect(tr.some((e) => e.nodeId === L.id(BRUME) && e.kind === "ip.no-route")).toBe(false);
    expect(tr.some((e) => e.nodeId === L.id(KID) && (e.kind === "tcp.rst.received" || e.kind === "tcp.refused"))).toBe(true);
  });

  it("드롭인 모드에서 WAN 쪽 LAN 기기는 관리 화면(WAN 주소)에 닿는다 — '인터넷의' 기기로 보고 막지 않는다", () => {
    const L = loadTopology(admin(exampleDropInTopology(), BRUME));
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("아빠 PC"), dst: "192.168.0.2", port: 80 });
    // 실제: fw.deny "관리 접근 제어: 인터넷의 192.168.0.100 가 … WAN 에서의 관리 접근이 꺼져 있어 드롭"
    expect(tr.some((e) => e.kind === "fw.deny" && e.summary.includes("인터넷의 192.168.0."))).toBe(false);
    expect(L.lastConn("아빠 PC").state).toBe("CLOSED");
  });

  it("드롭인 기기가 Brume(WAN 주소)을 DNS 로 쓰면 답이 WAN 쪽으로 돌아간다 (AGENTS 에 생략으로 적혀 있지만 No route 로 조용히 실패)", () => {
    const base = exampleDropInTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === KID ? { ...d, host: { ...d.host!, dns: "192.168.0.2" } } : d)) };
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id(KID), dst: "google.com" });
    // 실제: 포워더가 답을 LAN 인터페이스로 보내 "192.168.0.50 는 다른 서브넷인데 게이트웨이 설정 없음 → 드롭", 아이 PC 는 DNS timeout
    expect(tr.some((e) => e.nodeId === L.id(BRUME) && e.kind === "ip.no-route")).toBe(false);
    expect(L.host(KID).pings.at(-1)!.status).toBe("ok");
  });
});

describe("관리 접근", () => {
  it("VPN(WireGuard 서버의 피어)으로 붙은 폰이 192.168.8.1 관리 화면을 연다 (원격 접근 허용 시) — routeFromWg 가 관리 화면을 거치지 않음", () => {
    const L = loadTopology(admin(exampleWireguardTopology(), HOME, { remote: true }));
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("출장 폰"), dst: "192.168.8.1", port: 80 });
    // 실제: "공유기 자신에게 온 TCP 80 → 듣는 서비스 없음, 드롭" ×4, 폰은 SYN timeout
    expect(tr.some((e) => e.nodeId === L.id(HOME) && e.summary.includes("듣는 서비스 없음"))).toBe(false);
    expect(L.lastConn("출장 폰").state).toBe("CLOSED");
  });

  it("원격 접근을 켜면 WAN2 공인 주소로 온 관리 접속도 받는다 — receiveWan2 에 관리 화면이 없음", () => {
    let t = admin(exampleMultiWanTopology(), OFFICE, { remote: true });
    const w2 = loadTopology(t).node<Router>(OFFICE).wan2.ip!;
    // 핫스팟이 443 을 Brume WAN2 로 포워딩 (WAN2 가 핫스팟 NAT 뒤라서)
    t = router(t, "휴대폰 핫스팟", { forwards: [{ publicPort: 443, lanIp: w2, lanPort: 443 }] });
    const L = loadTopology(t);
    const tr = L.act({ kind: "inet-connect", nodeId: L.id("internet-1"), dst: L.node<Router>("휴대폰 핫스팟").wan.ip!, port: 443 });
    // 실제: Brume 에서 nat.miss "NAT 테이블에 없는 TCP 포트 443 → 드롭"
    expect(tr.some((e) => e.nodeId === L.id(OFFICE) && e.kind === "nat.miss")).toBe(false);
    expect(tr.some((e) => e.nodeId === L.id(OFFICE) && e.kind === "fw.allow" && e.summary.includes("관리 접근 제어"))).toBe(true);
  });

  it("허용 목록에 잘못된 항목만 있으면 모두에게 열리지 않는다 (fail-open 금지)", () => {
    const L = loadTopology(admin(exampleWireguardTopology(), HOME, { allow: "192.168.8.500" }));
    L.act({ kind: "tcp-connect", nodeId: L.id(NAS), dst: "192.168.8.1", port: 80 });
    // 실제: parseCidrList 가 잘못된 항목을 버려 allow = [] → "LAN 전부" 로 허용 (CLOSED, 응답 받음)
    expect(L.node<Router>(HOME).admin.config.allow.length > 0 || L.lastConn(NAS).state !== "CLOSED").toBe(true);
  });

  it("관리 설정을 바꿔도 여전히 허용되는 SSH 세션은 그대로 — 닫을 때 FIN 이 timeout 되지 않는다", () => {
    const t = admin(exampleWireguardTopology(), HOME);
    const L = loadTopology(t);
    L.act({ kind: "tcp-connect", nodeId: L.id(NAS), dst: "192.168.8.1", port: 22 });
    expect(L.lastConn(NAS).state).toBe("ESTABLISHED");
    // NAS 는 여전히 허용되는 변경 (허용 목록에 NAS 대역)
    L.apply(admin(t, HOME, { allow: "192.168.8.0/24" }));
    const tr = L.act({ kind: "tcp-close", nodeId: L.id(NAS), conn: L.lastConn(NAS).id });
    // 실제: 공유기는 abortAll 로 FAILED 만 표시(통지 없음), NAS 의 FIN 을 "실패 상태에서 FIN·ACK → 무시" ×4 → NAS 는 FIN timeout
    // 고친 방식: 규칙은 새 연결부터 — 여전히 허용되는 세션은 그대로 두어 깔끔히 닫힌다 (FIN 이 timeout 되지 않음)
    expect(tr.some((e) => e.nodeId === L.id(HOME) && e.summary.includes("실패 상태"))).toBe(false);
    expect(L.lastConn(NAS).state).toBe("CLOSED");
    expect(L.lastConn(NAS).reason ?? "").not.toContain("timeout");
  });

  it("관리 화면은 공유기의 IPv6 LAN 주소로도 응답한다 — local6 는 여전히 '듣는 서비스 없음'", () => {
    const base = exampleDualStackHomeTopology();
    const rt = base.devices.find((d) => d.kind === "router")!;
    const pc = base.devices.find((d) => d.kind === "pc")!;
    const L = loadTopology(admin(base, rt.name));
    const a6 = L.node<Router>(rt.name).lan6.addrs.find((x) => x.origin === "manual")!.ip;
    const tr = L.act({ kind: "tcp-connect", nodeId: pc.id, dst: a6, port: 80 });
    expect(tr.some((e) => e.nodeId === rt.id && e.summary.includes("듣는 서비스 없음"))).toBe(false);
    expect(L.lastConn(pc.name).state).toBe("CLOSED");
  });

  it("헤어핀이 꺼져 있어도 관리 화면을 켠 공유기는 LAN 에서 자기 공인 주소:443 에 관리 화면으로 답한다 (OpenWrt: DNAT 는 wan 인터페이스에만)", () => {
    const t = router(admin(exampleWireguardTopology(), HOME), HOME, { forwards: [{ publicPort: 443, lanIp: "192.168.8.20", lanPort: 80 }] });
    const L = loadTopology(t);
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id(NAS), dst: "203.0.113.30", port: 443 });
    // 실제: "헤어핀 NAT 꺼짐 … 드롭" — 관리 화면이 켜진 뒤로는 사실이 아님 (실무의 "공유기 로그인 화면이 뜬다" 증상)
    expect(tr.some((e) => e.nodeId === L.id(HOME) && e.kind === "fw.allow" && e.summary.includes("관리 접근 제어"))).toBe(true);
  });
});

describe("기기 차단", () => {
  it("Wi-Fi 로 붙은 노트북도 막힌다 — 장치 MAC(유선)만 막아 wlan0(02:00:00:02:…)은 빠져나감, UI 목록에도 안 나옴", () => {
    const base = exampleWireguardTopology();
    const laptop = base.devices.find((d) => d.name === "여행 노트북")!;
    let t: Topology = {
      ...base,
      cables: base.cables.filter((c) => c.a.device !== laptop.id && c.b.device !== laptop.id),
      devices: base.devices.map((d) => (d.id === laptop.id ? { ...d, wifi: { ssid: "travel" } } : d)),
    };
    // BlockSection 의 토글이 저장하는 값 = x.mac (유선 MAC)
    t = router(t, "여행용 공유기", { wifi: { enabled: true, ssid: "travel" }, blocked: [laptop.mac] });
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id("여행 노트북"), dst: "8.8.8.8" });
    // 실제: blockedFrame 은 frame.src(= wlan0 MAC) 를 보므로 통과 → ping ok
    expect(L.host("여행 노트북").pings.at(-1)!.status).toBe("failed");
    // 임대 MAC 은 wlan0 → BlockSection 의 leaseMacs.has(x.mac) 에 걸리지 않아 목록에서도 빠진다
    // 임대 MAC 은 wlan0 (유선 MAC 의 4번째 옥텟 02) — 기기 차단 목록(BlockSection)은 이 MAC 으로도 노트북을 찾는다
    expect(L.node<Router>("여행용 공유기").dhcpServer.rows().map((r) => r[1]!.toLowerCase())).toContain(laptop.mac.toLowerCase().replace(/^02:00:00:00/, "02:00:00:02"));
  });
});

describe("GoodCloud", () => {
  it("멀티 WAN 이 WAN2 로 넘어가면 바로 다시 등록해 원격 관리가 끊기지 않는다", () => {
    const L = loadTopology(router(exampleMultiWanTopology(), OFFICE, { cloud: true }));
    const r = L.node<Router>(OFFICE);
    const wan1 = L.t.cables.find((c) => c.b.device === L.id(OFFICE) && c.b.port === 0)!;
    L.apply({ ...L.t, cables: L.t.cables.filter((c) => c !== wan1) });
    expect(r.mwan.active).toBe("wan2");
    const tr = L.act({ kind: "cloud-manage", nodeId: L.id("internet-1"), device: r.cloud.device });
    // 실제: onSwitch 는 DDNS 만 갱신 → 클라우드는 옛 WAN1 주소로 보내 3초 뒤 "응답 없음 (timeout)"
    expect(tr.some((e) => e.nodeId === L.id(OFFICE) && e.kind === "cloud.manage")).toBe(true);
  });

  it("WAN2 로 연결 유지를 보낸 뒤에는 WAN2 로 온 관리 요청을 받는다 — receiveWan2 에 GoodCloud 가 없음", () => {
    const L = loadTopology(router(exampleMultiWanTopology(), OFFICE, { cloud: true }));
    const r = L.node<Router>(OFFICE);
    const wan1 = L.t.cables.find((c) => c.b.device === L.id(OFFICE) && c.b.port === 0)!;
    L.apply({ ...L.t, cables: L.t.cables.filter((c) => c !== wan1) });
    L.s.net.runUntil(L.s.net.now + 30_000); // 25초 연결 유지가 WAN2 로 나가 클라우드가 새 연락 주소를 배움
    const tr = L.act({ kind: "cloud-manage", nodeId: L.id("internet-1"), device: r.cloud.device });
    // 실제: Brume 에서 nat.miss "NAT 테이블에 없는 UDP 포트 … → 드롭" 후 timeout
    expect(tr.some((e) => e.nodeId === L.id(OFFICE) && e.kind === "nat.miss")).toBe(false);
    expect(tr.some((e) => e.nodeId === L.id(OFFICE) && e.kind === "cloud.manage")).toBe(true);
  });

  it("상태의 VPN 칸은 WireGuard 서버를 켜 둔 공유기를 'VPN 없음' 으로 보고하지 않는다", () => {
    const L = loadTopology(router(exampleWireguardTopology(), HOME, { cloud: true }));
    const tr = L.act({ kind: "cloud-manage", nodeId: L.id("internet-1"), device: L.node<Router>(HOME).cloud.device });
    const m = tr.find((e) => e.nodeId === L.id(HOME) && e.kind === "cloud.manage")!;
    expect(m).toBeDefined();
    // 실제: status.vpn 은 WireGuard 클라이언트·OpenVPN 서버·메시만 본다 → "VPN 없음"
    expect(m.summary).not.toContain("VPN 없음");
  });
});

describe("구성 검사", () => {
  it("DHCP 서비스의 기본 게이트웨이 옵션(3)이 드롭인 공유기 WAN 주소면 dhcp.gateway-mismatch 가 아니다", () => {
    const base = exampleDropInTopology();
    const t: Topology = {
      ...base,
      devices: base.devices.map((d) =>
        d.name === "기존 공유기"
          ? { ...d, router: { ...d.router!, dhcp: { ...d.router!.dhcp, enabled: false } } }
          : d.name === "아빠 PC"
            ? { ...d, kind: "server" as const, host: { ...d.host!, ipMode: "static" as const, ip: "192.168.0.10", prefix: 24, gateway: "192.168.0.1", dns: "8.8.8.8", dhcpServer: { enabled: true, start: "192.168.0.100", end: "192.168.0.199", router: "192.168.0.2", dns: "8.8.8.8" } } }
            : d,
      ),
    };
    // 실제: "기본 게이트웨이 옵션(3) 192.168.0.2 가 … 다름 → … (Brume 3 (드롭인) WAN 가 ARP 에 응답하지만 자기 주소로 온 패킷이 아니라 드롭)" — 드롭인이면 거짓
    expect(lintTopology(t).map((i) => i.code)).not.toContain("dhcp.gateway-mismatch");
  });
});
