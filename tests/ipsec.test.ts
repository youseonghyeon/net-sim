// IPsec 모드: IKE_SA_INIT·IKE_AUTH 로 터널을 맺고 ESP 로 보낸다. NAT 가 끼면 UDP 4500 (NAT-T), PSK 가 다르면 인증 실패, 상대가 없으면 timeout
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import type { Ipv4Packet } from "../src/core/packet";
import { lintTopology } from "../src/model/lint";
import { NetworkSync } from "../src/model/netSync";
import { exampleNcpVpnTopology, exampleVpnTopology } from "../src/model/examples";
import { createDevice, type Device, type Topology, type VpnSettings } from "../src/model/topology";
import { L3Node } from "../src/core/nodes/l3";
import { tcpdumpLine } from "../src/model/packetView";

/** VPN 예제의 두 NAT 를 IPsec 으로 (patch 로 한쪽씩 바꿀 수 있음) */
function ipsec(a: Partial<VpnSettings> = {}, b: Partial<VpnSettings> = {}): Topology {
  const base = exampleVpnTopology();
  return {
    ...base,
    devices: base.devices.map((d) =>
      d.name === "사무실 A NAT" ? { ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, mode: "ipsec", psk: "s3cret", ...a } } }
      : d.name === "사무실 B NAT" ? { ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, mode: "ipsec", psk: "s3cret", ...b } } }
      : d,
    ),
  };
}

function load(t: Topology) {
  const s = new NetworkSync();
  s.sync(t);
  s.net.runToIdle();
  const id = (name: string) => t.devices.find((d) => d.name === name)!.id;
  const host = (name: string) => s.net.nodes.get(id(name)) as Host;
  const act = (a: Parameters<typeof s.net.scheduleAction>[1]) => {
    const from = s.net.trace.length;
    s.net.scheduleAction(s.net.now, a);
    s.net.runToIdle();
    return s.net.trace.slice(from);
  };
  const wire = (nodeName: string) => [...s.net.frameLog.values()].flat().filter((x) => x.to === id(nodeName) && x.frame.payload.kind === "ipv4").map((x) => x.frame.payload as Ipv4Packet);
  return { s, id, host, act, wire };
}

describe("IPsec", () => {
  it("첫 패킷에 IKE_SA_INIT → IKE_AUTH 로 터널을 맺고, 기다리던 ping 을 ESP 로 보낸다 (NAT 없음 → ESP 그대로)", () => {
    const t = ipsec();
    expect(lintTopology(t)).toEqual([]);
    const { id, host, act, wire } = load(t);
    const tr = act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").pings.at(-1)!.status).toBe("ok");
    const seq = tr.filter((e) => e.kind.startsWith("vpn.") && e.kind !== "vpn.encap" && e.kind !== "vpn.decap").map((e) => `${t.devices.find((d) => d.id === e.nodeId)!.name}:${e.kind}`);
    expect(seq).toEqual(["사무실 A NAT:vpn.ike", "사무실 B NAT:vpn.ike", "사무실 A NAT:vpn.ike", "사무실 B NAT:vpn.up", "사무실 A NAT:vpn.up"]);
    const onWire = wire("통신사 구간");
    expect(onWire.some((p) => p.payload.kind === "esp")).toBe(true);
    expect(onWire.some((p) => p.payload.kind === "udp" && (p.payload.dstPort === 4500 || p.payload.dstPort === 51820))).toBe(false);
    // 한번 맺은 터널은 다시 협상하지 않는다
    const again = act({ kind: "tcp-connect", nodeId: id("pc-b"), dst: "192.168.1.20", port: 80 });
    expect(again.some((e) => e.kind === "vpn.ike")).toBe(false);
    expect([...host("pc-b").tcp.conns.values()].at(-1)).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
  });

  it("traceroute: 터널 안에서는 인터넷 구간이 한 홉", () => {
    const t = ipsec();
    const { id, host, act } = load(t);
    act({ kind: "traceroute", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").traceroutes.at(-1)!.hops.map((h) => h.ip)).toEqual(["192.168.1.1", "192.168.2.1", "192.168.2.10"]);
  });

  it("PSK 가 다르면 IKE_AUTH 가 AUTHENTICATION_FAILED 로 거절되고 기다리던 패킷은 드롭 (구성 검사도 지적)", () => {
    const t = ipsec({}, { psk: "other" });
    expect(lintTopology(t).map((i) => i.code)).toContain("vpn.psk-mismatch");
    const { id, host, act } = load(t);
    const tr = act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.kind === "vpn.drop" && e.nodeId === id("사무실 B NAT") && e.summary.includes("PSK"))).toBe(true);
    expect(tr.some((e) => e.kind === "vpn.drop" && e.nodeId === id("사무실 A NAT") && e.summary.includes("AUTHENTICATION_FAILED"))).toBe(true);
    expect(tr.some((e) => e.kind === "vpn.up")).toBe(false);
  });

  it("상대가 IPsec 을 안 켜면 IKE 응답이 없어 timeout 후 드롭, 다음 패킷에 다시 협상", () => {
    const t = ipsec({}, { enabled: false });
    const { id, act } = load(t);
    const tr = act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(tr.some((e) => e.kind === "vpn.drop" && e.summary.includes("timeout"))).toBe(true);
    const tr2 = act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    // 새 협상 1번 + 재전송 2번 뒤 포기
    expect(tr2.filter((e) => e.kind === "vpn.ike").map((e) => e.summary.includes("재전송"))).toEqual([false, true, true]);
  });

  it("방식이 다르면(한쪽 WireGuard) 구성 검사가 지적한다", () => {
    const t = ipsec({}, { mode: "wireguard" });
    expect(lintTopology(t).map((i) => i.code)).toContain("vpn.mode-mismatch");
  });

  it("상대 VPN 게이트웨이가 NAT 박스 뒤(UDP 500·4500 포워딩)면 NAT 를 감지해 UDP 4500 (NAT-T) 으로 보낸다", () => {
    const base = ipsec();
    const devices: Device[] = base.devices.map((d) =>
      d.name === "사무실 B NAT"
        ? {
            ...d,
            l3: {
              interfaces: [d.l3!.interfaces[0]!, { ipMode: "static", ip: "10.0.0.1", prefix: 24, gateway: "" }],
              routes: [{ dest: "192.168.2.0", prefix: 24, via: "10.0.0.2" }],
              forwards: [
                { publicPort: 500, lanIp: "10.0.0.2", lanPort: 500, proto: "udp" },
                { publicPort: 4500, lanIp: "10.0.0.2", lanPort: 4500, proto: "udp" },
              ],
            },
          }
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
      vpn: { enabled: true, mode: "ipsec", psk: "s3cret", peer: "203.0.113.11", remote: [{ dest: "192.168.1.0", prefix: 24 }] },
    };
    devices.push(gw);
    const natB = devices.find((d) => d.name === "사무실 B NAT")!;
    const swB = devices.find((d) => d.name === "sw-b")!;
    const cables = base.cables.filter((c) => !(c.a.device === natB.id && c.b.device === swB.id));
    cables.push({ id: "c1", a: { device: natB.id, port: 1 }, b: { device: gw.id, port: 0 } }, { id: "c2", a: { device: gw.id, port: 1 }, b: { device: swB.id, port: 3 } });
    const t: Topology = { devices, cables };
    expect(lintTopology(t).filter((i) => i.code.startsWith("vpn."))).toEqual([]);
    const { id, host, act, wire } = load(t);
    const tr = act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.kind === "vpn.up" && e.nodeId === gw.id && e.summary.includes("NAT-T"))).toBe(true);
    const onWire = wire("통신사 구간");
    expect(onWire.some((p) => p.payload.kind === "esp")).toBe(false); // ESP 는 NAT 를 못 지나므로 쓰지 않음
    expect(onWire.some((p) => p.payload.kind === "udp" && p.payload.payload.kind === "esp" && p.payload.dstPort === 4500)).toBe(true);
    act({ kind: "ping", nodeId: id("pc-b"), dst: "192.168.1.10" });
    expect(host("pc-b").pings.at(-1)!.status).toBe("ok");
  });

  it("예제 망분리 + NCP: 내부망 PC 는 dev 3대·prod 에 SSH(22)로 닿고, 80 은 NCP 방화벽(ACG)이 막고, 외부망은 터널을 못 탄다", () => {
    const t = exampleNcpVpnTopology();
    expect(lintTopology(t)).toEqual([]);
    const { s, id, host, act } = load(t);
    const conn = () => [...host("내부망 PC 1").tcp.conns.values()].at(-1)!;
    const first = act({ kind: "tcp-connect", nodeId: id("내부망 PC 1"), dst: "192.168.111.11", port: 22 });
    expect(first.some((e) => e.kind === "vpn.up" && e.nodeId === id("내부망 방화벽 NAT"))).toBe(true);
    expect(conn()).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    for (const dst of ["192.168.112.11", "192.168.113.11", "172.21.4.11"]) {
      act({ kind: "tcp-connect", nodeId: id("내부망 PC 1"), dst, port: 22 });
      expect(conn()).toMatchObject({ remoteIp: dst, state: "CLOSED", bytesReceived: 3000 });
    }
    const web = act({ kind: "tcp-connect", nodeId: id("내부망 PC 1"), dst: "192.168.112.11", port: 80 });
    expect(web.some((e) => e.kind === "fw.deny" && e.nodeId === id("NCP VPN Gateway"))).toBe(true);
    act({ kind: "ping", nodeId: id("외부망 PC 1"), dst: "192.168.112.11" });
    expect(host("외부망 PC 1").pings.at(-1)!.status).toBe("failed");
    act({ kind: "ping", nodeId: id("외부망 PC 1"), dst: "8.8.8.8" });
    expect(host("외부망 PC 1").pings.at(-1)!.status).toBe("ok");
    expect(s).toBeDefined();
  });

  it("리뷰: 한쪽만 설정이 바뀌어 터널이 내려가도, 옛 터널로 온 ESP 를 받은 쪽이 새로 협상해 복구한다", () => {
    const t = ipsec();
    const { s, id, host, act } = load(t);
    act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    // B 만 설정 변경 (대역 추가) → B 의 SA 가 내려감, A 는 여전히 up
    const changed: Topology = { ...t, devices: t.devices.map((d) => (d.name === "사무실 B NAT" ? { ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, remote: [...d.l3!.vpn!.remote, { dest: "192.168.9.0", prefix: 24 }] } } } : d)) };
    s.sync(changed);
    s.net.runToIdle();
    const first = act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(first.some((e) => e.kind === "vpn.up")).toBe(true); // B 가 알아채고 새로 맺음
    act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    expect(host("pc-a").pings.at(-1)!.status).toBe("ok");
  });

  it("리뷰: 상대 공인 주소가 바뀌면 인증된 ESP 의 출발지를 따라가 그쪽으로 답한다", () => {
    const t = ipsec();
    const { s, id, host, act } = load(t);
    act({ kind: "ping", nodeId: id("pc-a"), dst: "192.168.2.10" });
    const moved: Topology = { ...t, devices: t.devices.map((d) => (d.name === "사무실 B NAT" ? { ...d, l3: { ...d.l3!, interfaces: d.l3!.interfaces.map((c, i) => (i === 0 ? { ...c, ip: "203.0.113.99" } : c)) } } : d)) };
    s.sync(moved);
    s.net.runToIdle();
    act({ kind: "ping", nodeId: id("pc-b"), dst: "192.168.1.10" });
    act({ kind: "ping", nodeId: id("pc-b"), dst: "192.168.1.10" });
    expect(host("pc-b").pings.at(-1)!.status).toBe("ok");
    expect((s.net.nodes.get(id("사무실 A NAT")) as L3Node).vpn.target()?.ip).toBe("203.0.113.99");
  });

  it("리뷰: NAT 뒤 상대가 UDP 500 만 포워딩하면 구성 검사가 4500 을 지적한다, PSK 가 양쪽 다 비면 경고", () => {
    const base = ipsec();
    const natB = (forwards: { publicPort: number; lanIp: string; lanPort: number; proto: "udp" }[]): Topology => ({
      ...base,
      devices: [
        ...base.devices.map((d) => (d.name === "사무실 B NAT" ? { ...d, l3: { interfaces: [d.l3!.interfaces[0]!, { ipMode: "static" as const, ip: "10.0.0.1", prefix: 24, gateway: "" }], routes: [], forwards } } : d)),
        { ...createDevice("gateway", 0, 0, base.devices), name: "gw-b", l3: { interfaces: [{ ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" }, { ipMode: "static", ip: "", prefix: 24, gateway: "" }, { ipMode: "static", ip: "", prefix: 24, gateway: "" }], routes: [], vpn: { enabled: true, mode: "ipsec", psk: "s3cret", peer: "203.0.113.11", remote: [] } } },
      ],
    });
    const codes = (t: Topology) => lintTopology(t).map((i) => i.code);
    expect(codes(natB([{ publicPort: 500, lanIp: "10.0.0.2", lanPort: 500, proto: "udp" }]))).toContain("vpn.natt-closed");
    expect(codes(natB([{ publicPort: 500, lanIp: "10.0.0.2", lanPort: 500, proto: "udp" }, { publicPort: 4500, lanIp: "10.0.0.2", lanPort: 4500, proto: "udp" }]))).not.toContain("vpn.natt-closed");
    expect(codes(ipsec({ psk: "" }, { psk: "" }))).toContain("vpn.psk-empty");
  });

  it("리뷰: 방화벽 규칙에 ESP 를 고를 수 있고, 인바운드 기본 차단이어도 ESP·IKE 를 허용하면 상대가 먼저 연 터널이 지난다", () => {
    const base = ipsec();
    const isp = base.devices.find((d) => d.name === "통신사 구간")!;
    const natA = base.devices.find((d) => d.name === "사무실 A NAT")!;
    const fw = { ...createDevice("firewall", 160, -30, base.devices), name: "fw-a" };
    fw.firewall = {
      enabled: true,
      defaultPolicy: "deny",
      stateful: true,
      rules: [
        { action: "allow", proto: "any", direction: "out", src: "", dst: "", dstPort: "" },
        { action: "allow", proto: "udp", direction: "in", src: "203.0.113.22", dst: "", dstPort: "500" },
        { action: "allow", proto: "esp", direction: "in", src: "203.0.113.22", dst: "", dstPort: "" },
      ],
    };
    const cables = base.cables.filter((c) => !([c.a.device, c.b.device].includes(isp.id) && [c.a.device, c.b.device].includes(natA.id)));
    cables.push({ id: "f0", a: { device: isp.id, port: 1 }, b: { device: fw.id, port: 0 } }, { id: "f1", a: { device: fw.id, port: 1 }, b: { device: natA.id, port: 0 } });
    const t: Topology = { devices: [...base.devices, fw], cables };
    const { id, host, act } = load(t);
    act({ kind: "ping", nodeId: id("pc-b"), dst: "192.168.1.10" });
    expect(host("pc-b").pings.at(-1)!.status).toBe("ok");
  });

  it("리뷰: tcpdump 는 4500 에서 나가는 IKE 응답에도 NONESP-encap 을 붙인다", () => {
    const f = { kind: "ethernet" as const, id: 1, src: "02:00:00:00:00:01", dst: "02:00:00:00:00:02", payload: { kind: "ipv4" as const, src: "203.0.113.22", dst: "203.0.113.11", ttl: 64, payload: { kind: "udp" as const, srcPort: 4500, dstPort: 40001, payload: { kind: "ike" as const, exchange: "IKE_AUTH" as const, response: true, spi: 1 } } } };
    expect(tcpdumpLine(f)).toContain("NONESP-encap: isakmp: child_sa  ikev2_auth[R]");
  });
});
