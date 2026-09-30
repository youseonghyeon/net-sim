// IPv6 4단계(공유기·인터넷) 리뷰(clean context)가 찾은 결함의 회귀 테스트. 각 it 은 고친 뒤의 기대 동작을 단언한다.
import { describe, expect, it } from "vitest";
import { exampleDualStackHomeTopology } from "../src/model/examples";
import { builder, cable } from "../src/model/examples/build";
import { Internet } from "../src/core/nodes/internet";
import { Router } from "../src/core/nodes/router";
import type { EthernetFrame } from "../src/core/packet";
import { lintTopology } from "../src/model/lint";
import { headerLayers } from "../src/model/packetView";
import type { Topology } from "../src/model/topology";
import { loadTopology } from "./helpers";

const byName = (t: Topology, n: string) => t.devices.find((d) => d.name === n)!;
const slaac = { enabled: true, mode: "slaac" as const, ip: "", prefix: 64, gateway: "" };

/** internet ─ sw-isp ─ rt-1 (공유기 IPv6 켬) ─ pc-1 (SLAAC) */
function ispSwitch(): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 344, -200);
  const swIsp = add("switch", 344, -60, "sw-isp");
  const rt = add("router", 200, 96, "rt-1");
  const pc = add("pc", 200, 300, "pc-1");
  rt.router = { ...rt.router!, ipv6: { enabled: true, inboundBlock: true } };
  pc.host = { ...pc.host!, ipv6: { ...slaac } };
  return { devices, cables: [cable(inet, 0, swIsp, 0), cable(swIsp, 1, rt, 0), cable(rt, 1, pc, 0)] };
}

/** internet ─ sw-isp ─ (gw-1 IPv6 켬·RA 끔 | nat-1 IPv6 끔) + pc-1 이 ISP 링크에 바로 */
function ispLinkHost(neighbor: "gateway" | "nat", pcV6: { mode: "slaac" | "static"; ip: string; gateway: string }): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 0, 0);
  const sw = add("switch", 0, 100, "sw-isp");
  const r = add(neighbor, 200, 200, "r-1");
  const pc = add("pc", 0, 300, "pc-1");
  if (neighbor === "gateway") {
    const none = { ipMode: "static" as const, ip: "", prefix: 24, gateway: "" };
    r.l3 = { interfaces: [none, none, none], routes: [], ipv6: { enabled: true, interfaces: [{ ip: "2001:db8:ffff::2", prefix: 64 }, { ip: "2001:db8:1::1", prefix: 64 }, { ip: "", prefix: 64 }], routes: [] } };
  }
  pc.host = { ...pc.host!, ipv6: { enabled: true, prefix: 64, ...pcV6 } };
  return { devices, cables: [cable(inet, 0, sw, 0), cable(sw, 1, r, 0), cable(sw, 2, pc, 0)] };
}

describe("고친 결함 1: ISP 회선이 끊겨도 위임을 지우지 않는다 (스위치 너머 공유기는 끊긴 줄 모른다)", () => {
  it("ISP 쪽 케이블(스위치와 인터넷 사이)을 뺐다 꽂은 뒤 IPv6 ping", () => {
    const t = ispSwitch();
    const L = loadTopology(t);
    const rt = L.node<Router>("rt-1");
    const inet = L.node<Internet>("internet-1");
    const pc = L.host("pc-1");
    L.act({ kind: "ping", nodeId: pc.id, dst: "2001:4860:4860::8888" });
    expect(pc.pings.at(-1)!.status).toBe("ok");
    const inetId = L.id("internet-1");
    L.apply({ ...structuredClone(t), cables: t.cables.filter((c) => c.a.device !== inetId && c.b.device !== inetId) });
    L.apply(t);
    const tr = L.act({ kind: "ping", nodeId: pc.id, dst: "2001:4860:4860::8888" });
    // 관찰: { state: "bound", delegations: 0, ping: "failed" } — ISP 가 "출발지 … 는 ISP 가 위임한 프리픽스·ISP 링크의 주소가 아님 → 드롭"
    expect({ state: rt.pd.state, delegations: inet.delegations.size, ping: pc.pings.at(-1)!.status }).toEqual({ state: "bound", delegations: 1, ping: "ok" });
    void tr;
  });

  it("한계: 스위치 너머 인터넷 노드를 지웠다 되돌리면 공유기는 모른다 — ISP 드롭 로그가 원인과 해결(WAN 다시 꽂기)을 알려 주고, 다시 꽂으면 복구", () => {
    const t = ispSwitch();
    const L = loadTopology(t);
    const inetId = L.id("internet-1");
    L.apply({ devices: t.devices.filter((d) => d.id !== inetId), cables: t.cables.filter((c) => c.a.device !== inetId && c.b.device !== inetId) });
    L.apply(t);
    const tr = L.act({ kind: "ping", nodeId: L.id("pc-1"), dst: "2001:4860:4860::8888" });
    expect(tr.find((e) => e.kind === "ip.drop" && e.nodeId === inetId)?.summary).toContain("공유기 WAN 케이블을 다시 꽂으면");
    // 공유기 WAN 을 뺐다 꽂으면 다시 위임받는다
    const rtId = L.id("rt-1");
    L.apply({ ...structuredClone(t), cables: t.cables.filter((c) => !((c.a.device === rtId && c.a.port === 0) || (c.b.device === rtId && c.b.port === 0))) });
    L.apply(t);
    const inet = L.node<Internet>("internet-1");
    L.act({ kind: "ping", nodeId: L.id("pc-1"), dst: "2001:4860:4860::8888" });
    expect({ delegations: inet.delegations.size, ping: L.host("pc-1").pings.at(-1)!.status }).toEqual({ delegations: 1, ping: "ok" });
  });
});

describe("고친 결함 2: 이름 해석 콜백이 동작 시점의 ctx(now 스냅숏)를 써서 타이머가 과거 기준으로 걸린다 (뿌리는 기존 코드, AAAA→A 두 번 조회로 드러남)", () => {
  it("예제 '듀얼 스택 집' pc-1 → github.com:80 (AAAA NODATA → A): SYN 을 보내고 100ms 만에 '400ms 안에 ACK 없음' 재전송", () => {
    const t = exampleDualStackHomeTopology();
    const L = loadTopology(t);
    const pc = L.host("pc-1");
    const tr = L.act({ kind: "tcp-connect", nodeId: pc.id, dst: "github.com", port: 80 });
    const syn = tr.find((e) => e.nodeId === pc.id && e.kind === "tcp.syn.sent")!;
    const rtx = tr.find((e) => e.nodeId === pc.id && e.kind === "tcp.retransmit");
    // 관찰: syn 2360ms, retransmit 2460ms ("400ms 안에 ACK 없음"), 닫힐 때 "재전송 1회"
    expect(rtx ? rtx.time - syn.time : "none").toBe("none");
  });

  it("첫 DNS 질의가 손실되면(재시도 2000ms) ping 타이머가 과거에 걸려 시뮬레이션 시각이 거꾸로 가고 ping 이 곧바로 timeout", () => {
    const t = exampleDualStackHomeTopology();
    const L = loadTopology(t);
    const pc = L.host("pc-1");
    const pcCable = t.cables.find((c) => c.a.device === pc.id || c.b.device === pc.id)!;
    const from = L.s.net.trace.length;
    L.s.net.scheduleAction(L.s.net.now, { kind: "ping", nodeId: pc.id, dst: "github.com" });
    L.s.net.dropNextOn(pcCable.id);
    L.s.net.runToIdle();
    const tr = L.s.net.trace.slice(from);
    let back = 0;
    for (let i = 1; i < tr.length; i++) if (tr[i]!.time < tr[i - 1]!.time) back++;
    // 관찰: back = 2 (4240 → 4060 "DNS timeout … 재시도", 4180 → 4060 "ping github.com timeout"), ping failed, 그 뒤 "내가 보낸 적 없는 Echo 응답"
    expect({ back, ping: pc.pings.at(-1)!.status }).toEqual({ back: 0, ping: "ok" });
  });
});

describe("고친 결함 3: 구성 검사 오탐: ISP 링크(인터넷 노드가 RA 를 보냄)와 PD 공유기 LAN 의 글로벌 게이트웨이", () => {
  it("ISP 링크의 SLAAC 호스트 옆에 IPv6 게이트웨이(RA 끔): ipv6.slaac-no-ra — 실제로는 ISP RA 로 주소를 받아 ping 된다", () => {
    const t = ispLinkHost("gateway", { mode: "slaac", ip: "", gateway: "" });
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id("pc-1"), dst: "2001:4860:4860::8888" });
    expect(L.host("pc-1").pings.at(-1)!.status).toBe("ok");
    expect(lintTopology(t).map((i) => i.code)).toEqual([]); // 관찰: ["ipv6.slaac-no-ra"]
  });

  it("ISP 링크의 SLAAC 호스트 옆에 IPv6 끈 NAT 박스: ipv6.router-off — 실제로는 ISP RA 로 주소를 받는다", () => {
    const t = ispLinkHost("nat", { mode: "slaac", ip: "", gateway: "" });
    const L = loadTopology(t);
    expect(L.host("pc-1").v6.globals.length).toBe(1);
    expect(lintTopology(t).map((i) => i.code)).toEqual([]); // 관찰: ["ipv6.router-off"]
  });

  it("ISP 링크의 수동 호스트, 게이트웨이 = ISP 2001:db8:ffff::1: ipv6.gateway-unknown — 실제로는 ping 된다", () => {
    const t = ispLinkHost("gateway", { mode: "static", ip: "2001:db8:ffff::10", gateway: "2001:db8:ffff::1" });
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id("pc-1"), dst: "2001:4860:4860::8888" });
    expect(L.host("pc-1").pings.at(-1)!.status).toBe("ok");
    expect(lintTopology(t).map((i) => i.code)).toEqual([]); // 관찰: ["ipv6.gateway-unknown"]
  });

  it("공유기(IPv6 켬) 뒤 수동 호스트, 게이트웨이 = 공유기 LAN 글로벌 2001:db8:1000:100::1: ipv6.gateway-unknown — 실제로는 ping 된다", () => {
    const t = exampleDualStackHomeTopology();
    const srv = byName(t, "srv-1");
    srv.host = { ...srv.host!, ipv6: { enabled: true, mode: "static", ip: "2001:db8:1000:100::50", prefix: 64, gateway: "2001:db8:1000:100::1" } };
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id("srv-1"), dst: "2001:4860:4860::8888" });
    expect(L.host("srv-1").pings.at(-1)!.status).toBe("ok");
    expect(lintTopology(t).map((i) => i.code)).toEqual([]); // 관찰: ["ipv6.gateway-unknown"] ("… 는 이 링크의 라우터 주소가 아닙니다")
  });
});

describe("고친 결함 4: '외부에서 접속' 에 표준 표기가 아닌 IPv6(대문자·0 채움)를 넣으면 연결 실패", () => {
  it("UI 검증(isIpv6)은 통과하지만 Internet.connectFrom 이 canonIp6 를 하지 않아 공유기 NS 대상이 호스트 주소와 문자열로 안 맞음", () => {
    const t = exampleDualStackHomeTopology();
    byName(t, "rt-1").router!.ipv6!.inboundBlock = false;
    const L = loadTopology(t);
    const inet = L.node<Internet>("internet-1");
    const ip = L.host("srv-1").v6.globals[0]!.ip; // 2001:db8:1000:100:0:ff:fe00:6
    L.act({ kind: "inet-connect", nodeId: inet.id, dst: ip, port: 80 });
    expect([...inet.tcp.conns.values()].at(-1)!.state).toBe("CLOSED");
    L.act({ kind: "inet-connect", nodeId: inet.id, dst: ip.toUpperCase(), port: 80 });
    // 관찰: FAILED "Destination Unreachable (address unreachable)"
    expect([...inet.tcp.conns.values()].at(-1)!.state).toBe("CLOSED");
  });
});

describe("고친 결함 5: IPv4 만 쓰는 구성의 로그가 바뀜: 공유기 LAN 의 멀티캐스트 플러딩 문구", () => {
  it("STP 스위치의 BPDU 가 공유기 LAN 포트 사이로 플러딩될 때 (부모 커밋: '01:80:c2:00:00:00 는 MAC 테이블에 없음 → …')", () => {
    const { devices, add } = builder();
    const inet = add("internet", 0, 0);
    const rt = add("router", 0, 100, "rt-1");
    const sw = add("switch", 0, 200, "sw-1");
    const pc = add("pc", 0, 300, "pc-1");
    const pc2 = add("pc", 100, 300, "pc-2");
    sw.switch = { vlans: {}, stp: { enabled: true, priority: 4096 } };
    const t: Topology = { devices, cables: [cable(inet, 0, rt, 0), cable(rt, 1, sw, 0), cable(sw, 1, pc, 0), cable(rt, 2, pc2, 0)] };
    const L = loadTopology(t);
    const flood = L.s.net.trace.find((e) => e.nodeId === L.id("rt-1") && e.kind === "switch.flood" && e.summary.includes("01:80:c2"))!;
    // 관찰: "멀티캐스트 01:80:c2:00:00:00 → 다른 LAN 포트로 플러딩 [lan2]"
    expect(flood.summary).toBe("01:80:c2:00:00:00 는 MAC 테이블에 없음 → 다른 LAN 포트로 플러딩 [lan2]");
  });
});

describe("고친 결함 6: 공유기 방화벽의 인바운드 허용 규칙은 IPv6 핀홀 (기본 차단과 모순되지 않게)", () => {
  it("인바운드 TCP 80 허용 규칙이 있으면 기본 차단을 건너뛰어 바깥에서 srv-1 의 IPv6 :80 으로 들어온다", () => {
    const t = exampleDualStackHomeTopology();
    const rt = byName(t, "rt-1");
    rt.router = { ...rt.router!, firewall: { enabled: true, defaultPolicy: "allow", stateful: true, rules: [{ action: "allow", proto: "tcp", direction: "in", src: "", dst: "", dstPort: "80" }] } };
    const L = loadTopology(t);
    const inet = L.node<Internet>("internet-1");
    const tr = L.act({ kind: "inet-connect", nodeId: inet.id, dst: L.host("srv-1").v6.globals[0]!.ip, port: 80 });
    expect(tr.some((e) => e.kind === "fw.allow")).toBe(true);
    expect(tr.some((e) => e.kind === "fw.deny")).toBe(false);
    expect([...inet.tcp.conns.values()].at(-1)).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    // 규칙이 없으면 기본 차단의 안내가 "어떻게 여는지" 를 알려 준다
    const t2 = exampleDualStackHomeTopology();
    const L2 = loadTopology(t2);
    const inet2 = L2.node<Internet>("internet-1");
    const tr2 = L2.act({ kind: "inet-connect", nodeId: inet2.id, dst: L2.host("srv-1").v6.globals[0]!.ip, port: 80 });
    expect(tr2.find((e) => e.kind === "fw.deny")!.summary).toContain("인바운드 규칙(핀홀)");
  });
});

describe("고친 결함 7: 위임받은 /56 안이지만 LAN /64 가 아닌 목적지: 공유기가 알림 없이 드롭 (RFC 7084 WPD-5 는 Unreachable)", () => {
  it("바깥에서 [2001:db8:1000:1ab::99]:80 → 공유기 '위임받은 LAN 프리픽스가 아님 → 드롭', 바깥 클라이언트는 SYN 3번 timeout", () => {
    const t = exampleDualStackHomeTopology();
    byName(t, "rt-1").router!.ipv6!.inboundBlock = false;
    const L = loadTopology(t);
    const inet = L.node<Internet>("internet-1");
    L.act({ kind: "inet-connect", nodeId: inet.id, dst: "2001:db8:1000:1ab::99", port: 80 });
    // 관찰: "timeout · SYN 에 응답 없음 (재전송 3회)"
    expect([...inet.tcp.conns.values()].at(-1)!.reason).toContain("Unreachable");
  });

  it("LAN 에서 위임 /56 의 다른 /64 로 ping: 공유기 → ISP → 공유기로 되돌아온 뒤 조용히 드롭 (timeout)", () => {
    const L = loadTopology(exampleDualStackHomeTopology());
    const pc = L.host("pc-1");
    L.act({ kind: "ping", nodeId: pc.id, dst: "2001:db8:1000:1ab::1" });
    expect(pc.pings.at(-1)!.reason ?? "").toContain("Unreachable"); // 관찰: "timeout · 응답 없음"
  });
});

describe("고친 결함 8: '외부 클라이언트' 2001:db8:beef::7 에 LAN 에서 ping 하면 ISP 가 '인터넷에 없는 주소'", () => {
  it("IPv4 짝 198.51.100.7 은 ping 되는데 IPv6 는 no route (TCP 는 됨)", () => {
    const L = loadTopology(exampleDualStackHomeTopology());
    const pc = L.host("pc-1");
    L.act({ kind: "ping", nodeId: pc.id, dst: "198.51.100.7" });
    expect(pc.pings.at(-1)!.status).toBe("ok");
    L.act({ kind: "ping", nodeId: pc.id, dst: "2001:db8:beef::7" });
    expect(pc.pings.at(-1)!.status).toBe("ok"); // 관찰: failed "Destination Unreachable (no route) (2001:db8:ffff::1)"
  });
});

describe("고친 결함 9: 패킷 상세: Request·Release 에도 '이 프리픽스를 통째로 맡긴다' (서버가 위임할 때의 말)", () => {
  it("Release 의 IA_PD 행", () => {
    const f: EthernetFrame = {
      kind: "ethernet",
      id: 1,
      src: "02:00:00:01:00:02",
      dst: "33:33:00:01:00:02",
      payload: { kind: "ipv6", src: "fe80::ff:fe01:2", dst: "ff02::1:2", hopLimit: 1, payload: { kind: "udp", srcPort: 546, dstPort: 547, payload: { kind: "dhcp6", type: "release", xid: 1, clientId: "02:00:00:01:00:02", serverId: "02:00:00:00:00:01", prefix: { prefix: "2001:db8:1000:100::", length: 56 } } } },
    };
    const rows = Object.fromEntries(headerLayers(f).at(-1)!.rows);
    expect(rows["옵션 25 IA_PD"]).not.toContain("맡긴다"); // 관찰: "옵션 26 IAPREFIX 2001:db8:1000:100::/56 — 이 프리픽스를 통째로 맡긴다"
  });
});
