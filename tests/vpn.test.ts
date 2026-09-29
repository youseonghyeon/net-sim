// 사이트 간 VPN (WireGuard 식): 캡슐화·복호화, NAT 없이 사설끼리, 인터넷 구간에는 공인 UDP 51820 만, NAT 뒤 상대(엔드포인트 로밍), 끄면 실패
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { L3Node } from "../src/core/nodes/l3";
import { lintTopology } from "../src/model/lint";
import { NetworkSync } from "../src/model/netSync";
import { loadTopology } from "./helpers";
import { probeTargets } from "../src/model/reach";
import { exampleVpnTopology } from "../src/model/examples";
import { createDevice, parseTopology, serializeTopology, type Device, type Topology } from "../src/model/topology";

const load = (t: Topology = exampleVpnTopology()) => loadTopology(t);

describe("VPN", () => {
  it("구성 검사 이슈 없음, 사설 주소끼리 ping·TCP 가 터널로 닿는다 (NAT 하지 않음)", () => {
    const { t, id, host, act } = load();
    expect(lintTopology(t)).toEqual([]);
    const tr = act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "vpn.encap" && e.nodeId === id("사무실 A NAT"))).toBe(true);
    expect(tr.some((e) => e.kind === "vpn.decap" && e.nodeId === id("사무실 B NAT"))).toBe(true);
    expect(tr.some((e) => e.kind === "nat.translate")).toBe(false);
    act({ kind: "tcp-connect", nodeId: id("pc-b"), dst: "192.168.1.20", port: 80 });
    expect([...host("pc-b").tcp.conns.values()].at(-1)).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
  });

  it("통신사 구간 스위치를 지나는 프레임은 공인 주소끼리의 UDP 51820 이고, 안쪽 원래 패킷은 그 안에 들어 있다", () => {
    const { s, id, act } = load();
    act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    const isp = id("통신사 구간");
    const onWire = [...s.net.frameLog.values()].flat().filter((x) => x.to === isp && x.frame.payload.kind === "ipv4");
    expect(onWire.length).toBeGreaterThan(0);
    for (const x of onWire) {
      const ip = x.frame.payload as import("../src/core/packet").Ipv4Packet;
      expect(ip.src.startsWith("203.0.113.")).toBe(true);
      if (ip.payload.kind === "udp" && ip.payload.payload.kind === "vpn") expect(ip.payload.payload.inner.dst.startsWith("192.168.")).toBe(true);
    }
    expect(onWire.some((x) => x.frame.payload.kind === "ipv4" && x.frame.payload.payload.kind === "udp" && x.frame.payload.payload.dstPort === 51820)).toBe(true);
  });

  it("traceroute: 터널 안에서는 인터넷 구간이 한 홉으로 보인다 (NAT A → NAT B → 목적지)", () => {
    const { id, host, act } = load();
    act({ kind: "traceroute", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").traceroutes.at(-1)!.hops.map((h) => h.ip)).toEqual(["192.168.1.1", "192.168.2.1", "192.168.2.10"]);
  });

  it("한쪽 VPN 을 끄면 사설 주소로는 닿지 않고, 구성 검사가 짝 설정을 경고한다", () => {
    const base = exampleVpnTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "사무실 B NAT" ? { ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, enabled: false } } } : d)) };
    const { id, host, act } = load(t);
    act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").pings.at(-1)!.status).toBe("failed");
    expect(lintTopology(t).map((i) => i.code)).toContain("vpn.peer-off");
  });

  it("상대가 NAT 뒤여도 그쪽이 먼저 보내면 이어진다 (받은 출발지로 답함 — 엔드포인트 로밍)", () => {
    const { s, t, id, host, act } = load();
    // 사무실 B 의 NAT 박스 바깥 주소를 바꿔 A 의 설정(peer .22)과 달라지게 한다 = 중간에 다른 NAT 가 있는 것과 같은 효과
    const moved: Topology = { ...t, devices: t.devices.map((d) => (d.name === "사무실 B NAT" ? { ...d, l3: { ...d.l3!, interfaces: d.l3!.interfaces.map((c, i) => (i === 0 ? { ...c, ip: "203.0.113.99" } : c)) } } : d)) };
    s.sync(moved);
    s.net.runToIdle();
    act({ kind: "ping", nodeId: id("pc-b"), dst: "192.168.1.10" });
    expect(host("pc-b").pings.at(-1)!.status).toBe("ok");
    const a = s.net.nodes.get(id("사무실 A NAT")) as L3Node;
    expect(a.vpn.endpoint?.ip).toBe("203.0.113.99");
    act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").pings.at(-1)!.status).toBe("ok");
  });

  it("상대 대역에서 온 것이 아니면 풀지 않는다 (AllowedIPs)", () => {
    const base = exampleVpnTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "사무실 A NAT" ? { ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, remote: [{ dest: "192.168.9.0", prefix: 24 }] } } } : d)) };
    const { s, id, act } = load(t);
    const tr = act({ kind: "ping", nodeId: id("pc-b"), dst: "192.168.1.10" });
    expect(tr.some((e) => e.kind === "vpn.drop" && e.nodeId === id("사무실 A NAT") && e.summary.includes("허용하지 않은"))).toBe(true);
    expect(s).toBeDefined();
  });

  it("VPN 게이트웨이가 VPN 을 안 켠 NAT 박스 뒤에 있어도 UDP 51820 포워딩으로 터널이 이어진다 (구성 검사도 포워딩 너머를 상대로 본다)", () => {
    const base = exampleVpnTopology();
    const devices: Device[] = base.devices.map((d) =>
      d.name === "사무실 B NAT"
        ? { ...d, l3: { interfaces: [d.l3!.interfaces[0]!, { ipMode: "static", ip: "10.0.0.1", prefix: 24, gateway: "" }], routes: [{ dest: "192.168.2.0", prefix: 24, via: "10.0.0.2" }], forwards: [{ publicPort: 51820, lanIp: "10.0.0.2", lanPort: 51820, proto: "udp" }] } }
        : d,
    );
    const gw = createDevice("gateway", 640, 128, devices);
    gw.name = "vpn-gw-b";
    gw.l3 = {
      interfaces: [
        { ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" },
        { ipMode: "static", ip: "192.168.2.1", prefix: 24, gateway: "" },
        { ipMode: "static", ip: "", prefix: 24, gateway: "" },
      ],
      routes: [],
      vpn: { enabled: true, peer: "203.0.113.11", remote: [{ dest: "192.168.1.0", prefix: 24 }] },
    };
    devices.push(gw);
    const natB = devices.find((d) => d.name === "사무실 B NAT")!;
    const swB = devices.find((d) => d.name === "sw-b")!;
    const cables = base.cables.filter((c) => !(c.a.device === natB.id && c.b.device === swB.id));
    cables.push({ id: "c-nat-gw", a: { device: natB.id, port: 1 }, b: { device: gw.id, port: 0 } }, { id: "c-gw-sw", a: { device: gw.id, port: 1 }, b: { device: swB.id, port: 3 } });
    const t: Topology = { devices, cables };
    expect(lintTopology(t).filter((i) => i.code.startsWith("vpn."))).toEqual([]);
    const { id, host, act } = load(t);
    const tr = act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "vpn.decap" && e.nodeId === gw.id)).toBe(true);
    expect(tr.some((e) => e.kind === "vpn.drop")).toBe(false);
    act({ kind: "ping", nodeId: id("pc-b"), dst: "192.168.1.10" });
    expect(host("pc-b").pings.at(-1)!.status).toBe("ok");
  });

  it("터널 너머의 없는 주소로 보내면 상대 NAT 가 보낸 Host Unreachable 이 터널로 돌아온다", () => {
    const { id, act } = load();
    const tr = act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.99" });
    expect(tr.some((e) => e.kind === "icmp.unreachable.sent" && e.nodeId === id("사무실 B NAT"))).toBe(true);
    expect(tr.some((e) => e.kind === "icmp.unreachable.received" && e.nodeId === id("pc-a"))).toBe(true);
    expect(tr.some((e) => e.kind === "vpn.drop")).toBe(false);
  });

  it("방화벽: 터널로 나가는 것은 아웃바운드, 풀려서 들어오는 것은 인바운드 (Stateful 이면 응답은 통과)", () => {
    const base = exampleVpnTopology();
    const t: Topology = {
      ...base,
      devices: base.devices.map((d) =>
        d.name === "사무실 A NAT" ? { ...d, l3: { ...d.l3!, firewall: { enabled: true, defaultPolicy: "deny", stateful: true, rules: [{ action: "allow", proto: "any", direction: "out", src: "", dst: "", dstPort: "" }] } } } : d,
      ),
    };
    const { id, host, act } = load(t);
    act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").pings.at(-1)!.status).toBe("ok");
    const tr = act({ kind: "ping", nodeId: id("pc-b"), dst: "192.168.1.10" });
    expect(host("pc-b").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.kind === "fw.deny" && e.nodeId === id("사무실 A NAT"))).toBe(true);
  });

  it("불러온 JSON 의 VPN 설정이 깨져 있어도(대역 목록 없음) 정리해서 연다", () => {
    const doc = JSON.parse(serializeTopology(exampleVpnTopology()));
    const a = doc.devices.find((d: Device) => d.name === "사무실 A NAT");
    a.l3.vpn = { enabled: true, peer: 5, remote: null };
    const b = doc.devices.find((d: Device) => d.name === "사무실 B NAT");
    b.l3.vpn = { enabled: true, peer: "203.0.113.11", remote: [null, { dest: "192.168.1.0", prefix: 99 }] };
    const { topology, error } = parseTopology(JSON.stringify(doc));
    expect(error).toBeUndefined();
    const vpnOf = (n: string) => topology!.devices.find((d) => d.name === n)!.l3!.vpn;
    expect(vpnOf("사무실 A NAT")).toEqual({ enabled: true, peer: "", remote: [] });
    expect(vpnOf("사무실 B NAT")).toEqual({ enabled: true, peer: "203.0.113.11", remote: [{ dest: "192.168.1.0", prefix: 24 }] });
    expect(() => lintTopology(topology!)).not.toThrow();
    expect(() => new NetworkSync().sync(topology!)).not.toThrow();
  });

  it("두 사이트가 같은 상대에 VPN 을 연결하면 구성 검사가 경고한다 (상대는 터널 하나라 응답을 빼앗음)", () => {
    const base = exampleVpnTopology();
    const devices = [...base.devices];
    const c = createDevice("nat", 400, 48, devices);
    c.name = "사무실 C NAT";
    c.l3 = { interfaces: [{ ipMode: "static", ip: "203.0.113.33", prefix: 24, gateway: "" }, { ipMode: "static", ip: "192.168.3.1", prefix: 24, gateway: "" }], routes: [], vpn: { enabled: true, peer: "203.0.113.22", remote: [{ dest: "192.168.2.0", prefix: 24 }] } };
    devices.push(c);
    const issues = lintTopology({ devices, cables: base.cables }).filter((i) => i.code === "vpn.shared-peer");
    expect(issues.map((i) => i.deviceId).sort()).toEqual([devices.find((d) => d.name === "사무실 A NAT")!.id, c.id].sort());
  });

  it("진단 자동완성: 상대가 AllowedIPs 로 버리면 실패 이유가 VPN 드롭", () => {
    const base = exampleVpnTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "사무실 B NAT" ? { ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, remote: [{ dest: "192.168.9.0", prefix: 24 }] } } } : d)) };
    const pcA = t.devices.find((d) => d.name === "pc-a")!.id;
    const c = probeTargets(t, pcA, "ping").candidates.find((x) => x.value === "192.168.2.10");
    expect(c?.reason).toBe("VPN 드롭 (사무실 B NAT)");
  });
});
