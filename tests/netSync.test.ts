import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { L3Node } from "../src/core/nodes/l3";
import { Router } from "../src/core/nodes/router";
import { NetworkSync } from "../src/model/netSync";
import { createDevice, EXAMPLES, exampleTopology, examplePartsTopology, exampleVlanTopology, newId, type Device, type Topology } from "../src/model/topology";

function byName(t: Topology, name: string): Device {
  const d = t.devices.find((x) => x.name === name);
  if (!d) throw new Error(`no device named ${name}`);
  return d;
}
function host(s: NetworkSync, t: Topology, name: string): Host {
  const n = s.net.nodes.get(byName(t, name).id);
  if (!(n instanceof Host)) throw new Error(`${name} is not a Host`);
  return n;
}
function ping(s: NetworkSync, t: Topology, from: string, dst: string) {
  const net = s.net;
  net.scheduleAction(net.now, { kind: "ping", nodeId: byName(t, from).id, dst });
  net.runToIdle();
  return host(s, t, from).pings.at(-1)!;
}
/** 토폴로지를 불변으로 고치는 도우미 */
function patch(t: Topology, name: string, f: (d: Device) => Device): Topology {
  return { ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) };
}

describe("NetworkSync: 예제 토폴로지가 그대로 동작한다", () => {
  it("공유기 예제: 동기화만으로 DHCP 가 돌아 유선·무선 호스트가 주소를 받고, 위치 이동은 변경으로 치지 않는다", () => {
    const s = new NetworkSync();
    const t = exampleTopology();
    expect(s.sync(t)).toBe(true);
    s.net.runToIdle();
    for (const n of ["pc-1", "laptop-1", "phone-1"]) expect(host(s, t, n).ip, n).toMatch(/^192\.168\.0\.1\d\d$/);
    expect(host(s, t, "srv-1").ip).toBe("192.168.0.20");
    expect((s.net.nodes.get(byName(t, "rt-1").id) as Router).wan.ip).toMatch(/^203\.0\.113\./);
    // 무선 링크가 케이블처럼 들어갔다
    expect([...s.net.links.keys()].some((id) => id.startsWith("wl_"))).toBe(true);
    // 위치만 바꾸면 시뮬레이션은 건드리지 않는다
    const moved = { ...t, devices: t.devices.map((d) => ({ ...d, x: d.x + 40 })) };
    const before = s.net.trace.length;
    expect(s.sync(moved)).toBe(false);
    expect(s.net.trace.length).toBe(before);
    // 이름 해석 + NAT 를 거쳐 인터넷 ping
    expect(ping(s, moved, "pc-1", "google.com")).toMatchObject({ status: "ok" });
  });

  it("부품 예제: 게이트웨이 릴레이로 다른 서브넷 풀에서 주소를 받고, NAT 박스로 인터넷·LAN DNS 레코드가 된다", () => {
    const s = new NetworkSync();
    const t = examplePartsTopology();
    s.sync(t);
    s.net.runToIdle();
    expect(host(s, t, "pc-1").ip).toMatch(/^192\.168\.1\.1\d\d$/);
    expect(host(s, t, "laptop-1").ip).toMatch(/^192\.168\.2\.1\d\d$/);
    expect(ping(s, t, "pc-1", host(s, t, "laptop-1").ip!)).toMatchObject({ status: "ok" });
    expect(ping(s, t, "pc-1", "8.8.8.8")).toMatchObject({ status: "ok" });
    expect(ping(s, t, "pc-1", "web.home")).toMatchObject({ status: "ok", resolved: "192.168.2.20" });
  });

  it("VLAN 예제: 같은 VLAN 은 직접, 다른 VLAN 은 서브 인터페이스를 거쳐, 인터넷은 NAT 를 거쳐 닿는다", () => {
    const s = new NetworkSync();
    const t = exampleVlanTopology();
    s.sync(t);
    s.net.runToIdle();
    const gw = s.net.nodes.get(byName(t, "gw-1").id) as L3Node;
    expect(gw.names).toEqual(["if0", "if1", "if2", "if1.10", "if1.20"]);
    expect(ping(s, t, "pc-1", "192.168.10.11")).toMatchObject({ status: "ok" });
    expect(ping(s, t, "pc-1", "192.168.20.20")).toMatchObject({ status: "ok" });
    expect(ping(s, t, "pc-1", "google.com")).toMatchObject({ status: "ok" });
  });
});

describe("NetworkSync: 나머지 예제도 불러오자마자 학습 포인트가 재현된다", () => {
  function load(id: keyof typeof EXAMPLES) {
    const s = new NetworkSync();
    const t = EXAMPLES[id].build();
    s.sync(t);
    s.net.runToIdle();
    return { s, t };
  }

  it("PC 2대 + 스위치: ARP 뒤 ping", () => {
    const { s, t } = load("starter");
    expect(ping(s, t, "pc-1", "192.168.0.11")).toMatchObject({ status: "ok" });
    expect(s.net.trace.some((e) => e.kind === "arp.request.sent")).toBe(true);
  });

  it("집 두 곳: 게이트웨이 둘이 if0 로 직접 이어져 정적 경로로 오가고, 경로를 지우면 '경로 없음'", () => {
    const { s, t } = load("homes");
    expect(ping(s, t, "pc-1", "192.168.1.11")).toMatchObject({ status: "ok" }); // 같은 집
    expect(ping(s, t, "pc-1", "192.168.2.10")).toMatchObject({ status: "ok" }); // 다른 집
    expect(ping(s, t, "pc-4", "192.168.1.10")).toMatchObject({ status: "ok" }); // 반대 방향
    const pc1 = byName(t, "pc-1").id;
    s.net.scheduleAction(s.net.now, { kind: "traceroute", nodeId: pc1, dst: "192.168.2.10" });
    s.net.runToIdle();
    expect(host(s, t, "pc-1").traceroutes.at(-1)).toMatchObject({ status: "done", hops: [{ ip: "192.168.1.1" }, { ip: "10.0.0.2" }, { ip: "192.168.2.10" }] });
    const broken = patch(t, "gw-1", (d) => ({ ...d, l3: { ...d.l3!, routes: [] } }));
    s.sync(broken);
    expect(ping(s, broken, "pc-1", "192.168.2.10")).toMatchObject({ status: "failed" });
    expect(s.net.trace.some((e) => e.nodeId === byName(t, "gw-1").id && e.kind === "ip.no-route")).toBe(true);
  });

  it("백본: 집 세 곳이 스위치 하나에서 만나고, 경로 하나를 지우면 그 집만 못 간다", () => {
    const { s, t } = load("backbone");
    expect(ping(s, t, "pc-1", "192.168.2.10")).toMatchObject({ status: "ok" });
    expect(ping(s, t, "pc-1", "192.168.3.10")).toMatchObject({ status: "ok" });
    expect(ping(s, t, "pc-4", "192.168.1.11")).toMatchObject({ status: "ok" });
    const pc1 = byName(t, "pc-1").id;
    s.net.scheduleAction(s.net.now, { kind: "traceroute", nodeId: pc1, dst: "192.168.3.10" });
    s.net.runToIdle();
    expect(host(s, t, "pc-1").traceroutes.at(-1)).toMatchObject({ status: "done", hops: [{ ip: "192.168.1.1" }, { ip: "10.0.0.3" }, { ip: "192.168.3.10" }] });
    // gw-1 에서 3번 집 경로만 지우면 2번 집은 되고 3번 집은 경로 없음
    const broken = patch(t, "gw-1", (d) => ({ ...d, l3: { ...d.l3!, routes: d.l3!.routes.filter((r) => r.dest !== "192.168.3.0") } }));
    s.sync(broken);
    expect(ping(s, broken, "pc-1", "192.168.2.10")).toMatchObject({ status: "ok" });
    expect(ping(s, broken, "pc-1", "192.168.3.10")).toMatchObject({ status: "failed" });
  });

  it("게이트웨이 2단: 옆 서브넷은 정적 경로로 바로, 인터넷은 NAT 로. NAT 의 되돌아오는 경로를 지우면 응답이 끊긴다", () => {
    const { s, t } = load("gateways");
    expect(ping(s, t, "pc-1", "192.168.5.10")).toMatchObject({ status: "ok" });
    // gw-1 이 NAT 를 거치지 않고 gw-2 로 넘겼다
    expect(s.net.transmissions.some((x) => x.from.node === byName(t, "gw-1").id && x.to.node === byName(t, "sw-1").id)).toBe(true);
    expect(ping(s, t, "pc-3", "8.8.8.8")).toMatchObject({ status: "ok" });
    const broken = patch(t, "nat-1", (d) => ({ ...d, l3: { ...d.l3!, routes: [] } }));
    s.sync(broken);
    expect(ping(s, broken, "pc-3", "8.8.8.8")).toMatchObject({ status: "failed" });
  });

  it("허브 vs 스위치: 허브 쪽 ping 은 공유기까지 복제되고 스위치 쪽은 안 간다", () => {
    const { s, t } = load("hub");
    const rt = byName(t, "rt-1").id;
    const ip = (n: string) => host(s, t, n).ip!;
    const before = s.net.transmissions.length;
    ping(s, t, "pc-1", ip("pc-2"));
    const hubSide = s.net.transmissions.slice(before);
    expect(hubSide.some((x) => x.to.node === rt && x.frame.payload.kind === "ipv4" && x.frame.payload.payload.kind === "icmp")).toBe(true);
    const mid = s.net.transmissions.length;
    ping(s, t, "pc-3", ip("pc-4"));
    const swSide = s.net.transmissions.slice(mid);
    expect(swSide.some((x) => x.to.node === rt && x.frame.payload.kind === "ipv4" && x.frame.payload.payload.kind === "icmp")).toBe(false);
  });

  it("방화벽: ping 은 되고 TCP 80 은 공유기에서 차단", () => {
    const { s, t } = load("firewall");
    expect(ping(s, t, "pc-1", "example.com")).toMatchObject({ status: "ok" });
    const pc = byName(t, "pc-1").id;
    s.net.scheduleAction(s.net.now, { kind: "tcp-connect", nodeId: pc, dst: "example.com", port: 80 });
    s.net.runToIdle();
    expect(s.net.trace.some((e) => e.nodeId === byName(t, "rt-1").id && e.kind === "fw.deny")).toBe(true);
    expect([...host(s, t, "pc-1").tcp.conns.values()].at(-1)?.state).toBe("FAILED");
  });

  it("무선 로밍: 왼쪽 AP 에 붙었다가 오른쪽으로 옮기면 갈아탄다", () => {
    const { s, t } = load("roaming");
    const ap1 = byName(t, "ap-1").id;
    const ap2 = byName(t, "ap-2").id;
    const link = () => [...s.net.links.values()].find((l) => l.id.startsWith("wl_"));
    expect(host(s, t, "phone-1").ip).toMatch(/^192\.168\.0\./);
    expect([link()!.a.node, link()!.b.node]).toContain(ap1);
    const moved = patch(t, "phone-1", (d) => ({ ...d, x: 740 }));
    s.sync(moved);
    s.net.runToIdle();
    expect([link()!.a.node, link()!.b.node]).toContain(ap2);
    expect(host(s, t, "phone-1").ip).toMatch(/^192\.168\.0\./);
  });
});

describe("NetworkSync: diff 동기화", () => {
  function lan() {
    const devices: Device[] = [];
    const add = (kind: Parameters<typeof createDevice>[0], x: number, y: number) => {
      const d = createDevice(kind, x, y, devices);
      devices.push(d);
      return d;
    };
    const rt = add("router", 300, 0);
    const sw = add("switch", 300, 200);
    const pc = add("pc", 100, 400);
    const t: Topology = {
      devices,
      cables: [
        { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 0 } },
        { id: newId("cable"), a: { device: sw.id, port: 1 }, b: { device: pc.id, port: 0 } },
      ],
    };
    const s = new NetworkSync();
    s.sync(t);
    s.net.runToIdle();
    return { s, t, rt, sw, pc };
  }

  it("장치를 지우면 케이블이 빠지기 전에 DHCP Release 가 나가 라우터 임대가 사라진다", () => {
    const { s, t, rt, pc } = lan();
    const router = s.net.nodes.get(rt.id) as Router;
    expect(router.dhcpServer.leases.size).toBe(1);
    const next: Topology = { devices: t.devices.filter((d) => d.id !== pc.id), cables: t.cables.filter((c) => c.b.device !== pc.id) };
    expect(s.sync(next)).toBe(true);
    s.net.runToIdle();
    expect(s.net.trace.some((e) => e.nodeId === pc.id && e.kind === "dhcp.release")).toBe(true);
    expect(router.dhcpServer.leases.size).toBe(0);
    expect(s.net.hasNode(pc.id)).toBe(false);
  });

  it("케이블만 빼면 호스트는 링크 다운으로 주소를 잃고, 다시 꽂으면 DHCP 를 다시 한다", () => {
    const { s, t, pc } = lan();
    const unplugged: Topology = { ...t, cables: t.cables.filter((c) => c.b.device !== pc.id) };
    s.sync(unplugged);
    s.net.runToIdle();
    const h = s.net.nodes.get(pc.id) as Host;
    expect(h.linkUp).toBe(false);
    expect(h.ip).toBeUndefined();
    s.sync(t);
    s.net.runToIdle();
    expect(h.ip).toMatch(/^192\.168\.0\.1\d\d$/);
  });

  it("호스트를 고정 주소로 바꾸면 configure 가 불리고, 입력 중인 불완전한 주소는 '없음' 으로 넘어간다", () => {
    const { s, t, pc } = lan();
    const h = s.net.nodes.get(pc.id) as Host;
    const typing = patch(t, "pc-1", (d) => ({ ...d, host: { ...d.host!, ipMode: "static", ip: "192.168.0." } }));
    expect(s.sync(typing)).toBe(true);
    expect(h.ipMode).toBe("static");
    expect(h.ip).toBeUndefined();
    // 같은 불완전 입력을 한 글자 더 쳐도 유효 주소가 아니면 변경 아님
    const typing2 = patch(typing, "pc-1", (d) => ({ ...d, host: { ...d.host!, ip: "192.168.0.5" } }));
    expect(s.sync(typing2)).toBe(true);
    expect(h.ip).toBe("192.168.0.5");
    const typing3 = patch(typing2, "pc-1", (d) => ({ ...d, host: { ...d.host!, gateway: "192.168." } }));
    expect(s.sync(typing3)).toBe(false);
  });

  it("서비스(웹 포트) 토글은 노드를 새로 만들지 않고 setServices 로 반영된다", () => {
    const { s, t, pc } = lan();
    const h = s.net.nodes.get(pc.id) as Host;
    const ip = h.ip;
    s.sync(patch(t, "pc-1", (d) => ({ ...d, host: { ...d.host!, services: [80] } })));
    expect(s.net.nodes.get(pc.id)).toBe(h); // 같은 객체
    expect(h.tcp.listening.has(80)).toBe(true);
    expect(h.ip).toBe(ip); // 주소 유지
  });

  it("케이블 손실률 변경은 setLinkLoss 로만 반영된다", () => {
    const { s, t } = lan();
    const cable = t.cables[1]!;
    s.sync({ ...t, cables: t.cables.map((c) => (c.id === cable.id ? { ...c, loss: 0.5 } : c)) });
    expect(s.net.links.get(cable.id)?.lossRate).toBe(0.5);
    s.sync(t);
    expect(s.net.links.get(cable.id)?.lossRate).toBe(0);
  });

  it("reset 은 새 네트워크로 시작하고 다시 sync 하면 전부 다시 만든다", () => {
    const { s, t, pc } = lan();
    const before = s.net;
    s.reset();
    expect(s.net).not.toBe(before);
    expect(s.net.nodes.size).toBe(0);
    s.sync(t);
    s.net.runToIdle();
    expect((s.net.nodes.get(pc.id) as Host).ip).toMatch(/^192\.168\.0\./);
  });
});

describe("NetworkSync: 무선", () => {
  function wifi() {
    const devices: Device[] = [];
    const add = (kind: Parameters<typeof createDevice>[0], x: number, y: number) => {
      const d = createDevice(kind, x, y, devices);
      devices.push(d);
      return d;
    };
    const rt = add("router", 0, 0);
    rt.router = { ...rt.router!, wifi: { enabled: true, ssid: "home" } };
    const ap = add("ap", 800, 0); // 공유기와 같은 SSID, 유선으로 공유기에 연결
    const phone = add("phone", 60, 150);
    const t: Topology = { devices, cables: [{ id: newId("cable"), a: { device: rt.id, port: 2 }, b: { device: ap.id, port: 0 } }] };
    const s = new NetworkSync();
    s.sync(t);
    s.net.runToIdle();
    return { s, t, rt, ap, phone };
  }

  it("범위 안이면 붙어서 주소를 받고, 범위 밖으로 끌면 끊겨 주소를 잃는다", () => {
    const { s, t, phone } = wifi();
    const h = s.net.nodes.get(phone.id) as Host;
    expect(h.ip).toMatch(/^192\.168\.0\./);
    const far = patch(t, "phone-1", (d) => ({ ...d, y: 2000 }));
    expect(s.sync(far)).toBe(true);
    s.net.runToIdle();
    expect(h.linkUp).toBe(false);
    expect(h.ip).toBeUndefined();
    expect(s.net.trace.some((e) => e.nodeId === phone.id && e.kind === "wifi.disassociate" && e.summary.includes("끊김"))).toBe(true);
  });

  it("다른 기지로 로밍하면 옛 링크를 끊고 새 기지에 붙어 주소를 다시 받는다", () => {
    const { s, t, rt, ap, phone } = wifi();
    const h = s.net.nodes.get(phone.id) as Host;
    const linkTo = (base: string) => [...s.net.links.values()].find((l) => l.id.startsWith("wl_") && (l.a.node === base || l.b.node === base));
    expect(linkTo(rt.id)).toBeDefined();
    const roamed = patch(t, "phone-1", (d) => ({ ...d, x: 760, y: 150 }));
    expect(s.sync(roamed)).toBe(true);
    s.net.runToIdle();
    expect(linkTo(rt.id)).toBeUndefined();
    expect(linkTo(ap.id)).toBeDefined();
    expect(s.net.trace.some((e) => e.nodeId === phone.id && e.kind === "wifi.disassociate" && e.summary.includes("옮겨"))).toBe(true);
    expect(h.ip).toMatch(/^192\.168\.0\./); // AP 는 브리지라 공유기가 다시 임대
  });

  it("SSID 가 달라지면 끊기고, 맞추면 다시 붙는다", () => {
    const { s, t, phone } = wifi();
    const h = s.net.nodes.get(phone.id) as Host;
    s.sync(patch(t, "phone-1", (d) => ({ ...d, wifi: { ssid: "office" } })));
    s.net.runToIdle();
    expect(h.ip).toBeUndefined();
    s.sync(t);
    s.net.runToIdle();
    expect(h.ip).toMatch(/^192\.168\.0\./);
  });
});
