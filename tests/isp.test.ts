// 인터넷 노드(ISP): 가입자마다 /29 (첫 주소 = ISP 게이트웨이), 가입자끼리는 ISP 라우터를 거친다, 손으로 적은 공인 주소는 받지 않는다(IP Source Guard),
// ISP 대역 직접 입력·무작위 (사설·특수 대역·흉내 서버와 겹치면 안 됨)
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { builder, cable } from "../src/model/examples/build";
import { EXAMPLES, exampleRemoteVpnTopology } from "../src/model/examples";
import { leaseHints } from "../src/model/netSync";
import { lintTopology } from "../src/model/lint";
import { effectiveIspNet, ispNetProblem, randomIspNet } from "../src/model/isp";
import { Internet } from "../src/core/nodes/internet";
import type { Router } from "../src/core/nodes/router";
import { DEFAULT_DHCP_SERVER, parseTopology, serializeTopology, type Topology } from "../src/model/topology";

/** 인터넷 ─ 통신사 구간 ─ 공유기 두 대(자동 WAN), 각 공유기 뒤 PC 하나 */
function twoHomes(net?: string): Topology {
  const { devices, add } = builder();
  const inet = add("internet", 0, 0, "internet-1");
  if (net !== undefined) inet.internet = { net };
  const isp = add("switch", 0, 100, "통신사 구간");
  const a = add("router", -200, 200, "집 A");
  const b = add("router", 200, 200, "집 B");
  const pa = add("pc", -200, 350, "PC A");
  const pb = add("pc", 200, 350, "PC B");
  for (const p of [pa, pb]) p.host = { ipMode: "dhcp", ip: "", prefix: 24, gateway: "", services: [80], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
  return { devices, cables: [cable(isp, 0, inet, 0), cable(isp, 1, a, 0), cable(isp, 2, b, 0), cable(a, 1, pa, 0), cable(b, 1, pb, 0)] };
}

describe("ISP: 가입자마다 /29", () => {
  it("공유기마다 다른 대역을 받는다 (첫 주소가 ISP 게이트웨이, 둘째가 가입자)", () => {
    const L = loadTopology(twoHomes());
    const a = L.node<Router>("집 A");
    const b = L.node<Router>("집 B");
    expect([a.wan.ip, a.wan.prefix, a.wan.gateway]).toEqual(["203.0.113.2", 29, "203.0.113.1"]);
    expect([b.wan.ip, b.wan.prefix, b.wan.gateway]).toEqual(["203.0.113.10", 29, "203.0.113.9"]);
    expect(L.lint()).toEqual([]);
  });

  it("가입자끼리는 같은 서브넷이 아니라 ISP 라우터를 거친다 (TTL 하나 줄고, ARP 는 그 대역의 게이트웨이 주소로 묻는다)", () => {
    const L = loadTopology(twoHomes());
    const tr = L.act({ kind: "ping", nodeId: L.id("PC A"), dst: "203.0.113.10" });
    expect(L.host("PC A").pings.at(-1)!.status).toBe("ok");
    const fwd = tr.find((e) => e.nodeId === L.id("internet-1") && e.kind === "ip.forward")!;
    expect(fwd.summary).toContain("ISP 라우터: 203.0.113.10 는 가입자 대역 203.0.113.8/29 (게이트웨이 203.0.113.9) → 그 가입자에게 전달");
    // 집 A 는 상대를 직접 ARP 하지 않고 자기 게이트웨이(203.0.113.1)로 보낸다
    expect(tr.some((e) => e.nodeId === L.id("집 A") && e.kind === "arp.request.sent" && e.details?.targetIp === "203.0.113.10")).toBe(false);
    // ISP 가 집 B 에게 묻는 ARP 의 보낸이는 그 대역의 게이트웨이
    const arp = L.s.net.transmissions.find((t) => t.from.node === L.id("internet-1") && t.frame.payload.kind === "arp" && t.frame.payload.targetIp === "203.0.113.10");
    expect(arp?.frame.payload.kind === "arp" && arp.frame.payload.senderIp).toBe("203.0.113.9");
  });

  it("traceroute: ISP 홉은 보낸 가입자 대역의 게이트웨이 주소로 보인다", () => {
    const L = loadTopology(twoHomes());
    const tr = L.act({ kind: "traceroute", nodeId: L.id("PC A"), dst: "203.0.113.10" });
    const hops = tr.filter((e) => e.kind === "icmp.ttl-exceeded").map((e) => e.details?.from);
    expect(hops).toEqual(["192.168.0.1", "203.0.113.1"]);
  });

  it("같은 기기는 케이블을 다시 꽂아도 같은 대역을 받는다", () => {
    const L = loadTopology(twoHomes());
    const b = L.id("집 B");
    const t = L.t;
    L.apply({ ...t, cables: t.cables.filter((c) => !(c.a.device === b || c.b.device === b) || c.a.port !== 0 && c.b.port !== 0) });
    L.apply(t);
    expect(L.node<Router>("집 B").wan.ip).toBe("203.0.113.10");
  });

  it("손으로 적은 공인 주소: ISP 는 받지도 보내지도 않는다 (IP Source Guard) + 구성 검사 isp.static-address", () => {
    const base = twoHomes();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "집 B" ? { ...d, router: { ...d.router!, wan: { ipMode: "static", ip: "203.0.113.50", prefix: 24, gateway: "203.0.113.1" } } } : d)) };
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id("PC B"), dst: "8.8.8.8" });
    expect(L.host("PC B").pings.at(-1)!.status).not.toBe("ok");
    expect(tr.some((e) => e.nodeId === L.id("internet-1") && e.kind === "ip.drop" && e.summary.includes("IP Source Guard"))).toBe(true);
    // 그 주소로 가는 것도 길이 없다 (Net Unreachable)
    const tr2 = L.act({ kind: "ping", nodeId: L.id("PC A"), dst: "203.0.113.50" });
    expect(tr2.some((e) => e.nodeId === L.id("internet-1") && e.kind === "ip.no-route" && e.summary.includes("임대한 가입자 주소가 아님"))).toBe(true);
    expect(L.host("PC A").pings.at(-1)!.reason).toContain("Unreachable");
    expect(lintTopology(t).filter((i) => i.code === "isp.static-address").map((i) => i.message)).toEqual([expect.stringContaining("집 B WAN 203.0.113.50 를 ISP 구간(internet-1)에 손으로 적었음")]);
    // 자동(DHCP) WAN 은 임대 주소를 알아도 "손으로 적음" 이 아니다
    expect(loadTopology(twoHomes()).lint()).toEqual([]);
  });
});

describe("ISP 대역", () => {
  it("직접 입력: 가입자는 새 대역을 /29 로 받는다", () => {
    const L = loadTopology(twoHomes("198.18.0.0/24"));
    expect(L.node<Router>("집 A").wan.ip).toBe("203.0.113.2"); // 벤치마크 대역은 쓸 수 없어 기본 대역
    expect(L.lint().map((i) => i.code)).toEqual(["isp.net-invalid"]);
    const M = loadTopology(twoHomes("211.48.20.0/24"));
    expect(M.node<Router>("집 A").wan.ip).toBe("211.48.20.2");
    expect(M.node<Router>("집 B").wan.gateway).toBe("211.48.20.9");
    expect(M.lint()).toEqual([]);
  });

  it("실행 중에 바꾸면 가입자에게 FORCERENEW → 새 대역에서 다시 받는다", () => {
    const L = loadTopology(twoHomes());
    const t = L.t;
    const tr = L.apply({ ...t, devices: t.devices.map((d) => (d.kind === "internet" ? { ...d, internet: { net: "211.48.20.0/24" } } : d)) });
    expect(tr.some((e) => e.summary.includes("FORCERENEW"))).toBe(true);
    expect(L.node<Router>("집 A").wan.ip).toMatch(/^211\.48\.20\./);
    expect(L.node<Router>("집 B").wan.ip).toMatch(/^211\.48\.20\./);
    L.act({ kind: "ping", nodeId: L.id("PC A"), dst: L.node<Router>("집 B").wan.ip! });
    expect(L.host("PC A").pings.at(-1)!.status).toBe("ok");
  });

  it("쓸 수 없는 대역: 형식·길이·사설·특수·흉내 서버와 겹침", () => {
    expect(ispNetProblem("203.0.113.0/24")).toBeUndefined();
    expect(ispNetProblem("203.0.113")).toContain("대역이 아님");
    expect(ispNetProblem("203.0.113.0/29")).toContain("/16 ~ /28");
    expect(ispNetProblem("203.0.0.0/8")).toContain("/16 ~ /28");
    expect(ispNetProblem("192.168.10.0/24")).toContain("사설 대역 192.168.0.0/16");
    expect(ispNetProblem("100.64.5.0/24")).toContain("CGNAT");
    expect(ispNetProblem("172.20.0.0/16")).toContain("사설");
    expect(ispNetProblem("198.51.100.0/24")).toContain("인터넷 노드가 흉내 내는 공인 서버");
    expect(ispNetProblem("8.8.8.0/24")).toContain("8.8.8.8 (Google DNS)");
    expect(effectiveIspNet("10.0.0.0/24")).toEqual({ ip: "203.0.113.0", prefix: 24 });
    expect(effectiveIspNet("211.48.20.77/24")).toEqual({ ip: "211.48.20.0", prefix: 24 });
  });

  it("무작위: 늘 쓸 수 있는 공인 /24", () => {
    let seed = 1;
    const rand = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    for (let i = 0; i < 200; i++) {
      const net = randomIspNet(rand);
      expect(net).toMatch(/\/24$/);
      expect(ispNetProblem(net)).toBeUndefined();
    }
  });

  it("저장·불러오기에 ISP 대역이 남는다", () => {
    const t = twoHomes("211.48.20.0/24");
    const back = parseTopology(serializeTopology(t)).topology!;
    expect(back.devices.find((d) => d.kind === "internet")!.internet).toEqual({ net: "211.48.20.0/24" });
  });
});

describe("구성 검사: ISP 가 나눠 준 주소를 알면 VPN 서버를 주소로 찾는다", () => {
  it("모르면 침묵, 알면 PSK 가 다른 것을 짚는다", () => {
    const base = exampleRemoteVpnTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "재택 노트북" ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, psk: "wrong" } } } : d)) };
    expect(lintTopology(t).map((i) => i.code)).not.toContain("ra.psk-mismatch");
    expect(loadTopology(t).lint().map((i) => i.code)).toContain("ra.psk-mismatch");
  });

  it("인터넷 노드의 임대 표", () => {
    const L = loadTopology(twoHomes());
    const inet = L.node<Internet>("internet-1");
    expect([...inet.dhcpServer.leases.keys()].sort()).toEqual(["203.0.113.10", "203.0.113.2"]);
  });
});

// 리뷰(2026-10-19) 회귀
describe("review: ISP", () => {
  const staticWan = (t: Topology, name: string, ip: string, prefix = 24, gateway = "203.0.113.1"): Topology => ({
    ...t,
    devices: t.devices.map((d) => (d.name === name ? { ...d, router: { ...d.router!, wan: { ipMode: "static", ip, prefix, gateway } } } : d)),
  });
  /** 통신사 구간에 손으로 적은 주소의 PC 하나 */
  const withStaticPc = (t: Topology, ip: string, prefix: number, gateway: string): Topology => {
    const { devices, add } = builder();
    devices.push(...t.devices);
    const pc = add("pc", 0, 300, "손 주소 PC");
    pc.host = { ipMode: "static", ip, prefix, gateway, dns: "8.8.8.8", services: [], dhcpServer: { ...DEFAULT_DHCP_SERVER } };
    const isp = t.devices.find((d) => d.name === "통신사 구간")!;
    return { ...t, devices, cables: [...t.cables, cable(isp, 5, pc, 0)] };
  };

  it("Tor 를 거쳐도 손으로 적은 공인 주소와는 통신하지 못한다 (출구 → ISP 대역은 임대한 주소만, 받는 쪽은 Source Guard)", () => {
    const t = staticWan(EXAMPLES.tor.build(), "친구네 공유기", "203.0.113.50");
    const L = loadTopology(t);
    L.act({ kind: "tcp-connect", nodeId: L.id("노트북"), dst: "203.0.113.50", port: 80 });
    expect(L.lastConn("노트북").state).not.toBe("CLOSED");
    expect(L.serverConns("친구 웹 서버")).toEqual([]);
  });

  it("Source Guard 는 IP 와 MAC 을 함께 본다: 남의 임대 주소를 손으로 적은 기기는 막는다", () => {
    const base = twoHomes();
    const L = loadTopology(base);
    const b = L.id("집 B");
    const spoof = withStaticPc({ ...base, cables: base.cables.filter((c) => !((c.a.device === b && c.a.port === 0) || (c.b.device === b && c.b.port === 0))) }, "203.0.113.10", 29, "203.0.113.9");
    const tr = L.apply(spoof);
    const pc = spoof.devices.find((d) => d.name === "손 주소 PC")!.id;
    tr.push(...L.act({ kind: "ping", nodeId: pc, dst: "8.8.8.8" }));
    expect(L.s.net.getHost(pc).pings.at(-1)!.status).not.toBe("ok");
    expect(tr.some((e) => e.kind === "ip.drop" && e.summary.includes("다른 기기") && e.summary.includes("IP Source Guard"))).toBe(true);
  });

  it("ISP 대역 밖의 손 주소도 Source Guard 가 막는다", () => {
    // ISP 대역 밖 주소지만 /23 으로 적어 ISP 게이트웨이(203.0.113.1)로 나간다
    const L = loadTopology(withStaticPc(twoHomes(), "203.0.112.5", 23, "203.0.113.1"));
    const tr = L.act({ kind: "ping", nodeId: L.id("손 주소 PC"), dst: "8.8.8.8" });
    expect(tr.some((e) => e.nodeId === L.id("internet-1") && e.kind === "ip.drop" && e.summary.includes("ISP 대역 203.0.113.0/24 밖"))).toBe(true);
    expect(L.host("손 주소 PC").pings.at(-1)!.status).not.toBe("ok");
  });

  it("ISP 가 만든 연결도 임대하지 않은 ISP 대역 주소로는 내보내지 않는다", () => {
    const L = loadTopology(staticWan(twoHomes(), "집 B", "203.0.113.50"));
    const tr = L.act({ kind: "inet-connect", nodeId: L.id("internet-1"), dst: "203.0.113.50", port: 80 });
    expect(tr.some((e) => e.nodeId === L.id("internet-1") && e.kind === "ip.no-route" && e.summary.includes("임대한 가입자 주소가 아님"))).toBe(true);
    expect(L.wire("집 B").some((p) => p.payload.kind === "tcp")).toBe(false);
  });

  it("ISP 게이트웨이의 ARP 응답은 'ISP 게이트웨이' 로 적는다 (VPN 프록시 ARP 문구가 아님)", () => {
    const L = loadTopology(twoHomes());
    L.act({ kind: "ping", nodeId: L.id("PC B"), dst: "8.8.8.8" });
    const ev = L.s.net.trace.find((e) => e.nodeId === L.id("internet-1") && e.kind === "arp.reply.sent" && e.summary.includes("203.0.113.9"))!;
    expect(ev.summary).toContain("ISP 게이트웨이 — 가입자 대역 203.0.113.8/29");
    expect(ev.summary).not.toContain("VPN");
  });

  it("ISP 대역을 바꾸면 옛 서버 주소로 온 Request 에 바로 Nak → Discover (다른 서버로 보지 않음)", () => {
    const L = loadTopology(twoHomes());
    const tr = L.apply({ ...L.t, devices: L.t.devices.map((d) => (d.kind === "internet" ? { ...d, internet: { net: "211.48.20.0/24" } } : d)) });
    expect(tr.some((e) => e.kind === "dhcp.nak.sent" && e.summary.includes("내 예전 주소"))).toBe(true);
    expect(tr.some((e) => e.kind === "dhcp.ignore" && e.summary.includes("다른 서버"))).toBe(false);
    expect(tr.some((e) => e.kind === "dhcp.timeout")).toBe(false);
  });

  it("실행 중에 자동 WAN 을 손 주소로 바꾸면 (옛 임대가 남아 있어도) 구성 검사 isp.static-address", () => {
    const L = loadTopology(twoHomes());
    const t = staticWan(L.t, "집 B", "203.0.113.50");
    L.apply(t);
    expect(L.lint(t).map((i) => i.code)).toContain("isp.static-address");
  });

  it("/28 ISP 에서 주소를 바꿔도 빈 대역이 옛 것뿐이면 그것을 다시 준다 (주소를 영영 못 받지 않음)", () => {
    const L = loadTopology(twoHomes("211.48.20.0/28"));
    const a = L.node<Router>("집 A");
    expect(a.wan.ip).toBe("211.48.20.2");
    L.act({ kind: "isp-renumber", nodeId: L.id("internet-1"), ip: "211.48.20.2" });
    expect(a.wan.ip).toBe("211.48.20.2");
  });

  it("AdGuard 용 흉내 주소(광고·SNS) 대역도 ISP 대역으로 쓸 수 없다", () => {
    expect(ispNetProblem("157.240.215.0/24")).toContain("인터넷 노드가 흉내 내는 공인 서버");
  });

  it("케이블을 뺀 자동 WAN 은 임대가 남아 있어도 구성 검사에 주소를 넘기지 않는다", () => {
    const L = loadTopology(twoHomes());
    const b = L.id("집 B");
    L.apply({ ...L.t, cables: L.t.cables.filter((c) => !((c.a.device === b && c.a.port === 0) || (c.b.device === b && c.b.port === 0))) });
    expect(Object.keys(leaseHints(L.s.net))).not.toContain(`${b}:0`);
  });
});
