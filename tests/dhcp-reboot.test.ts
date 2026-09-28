// DHCP INIT-REBOOT (RFC 2131 4.3.2): 링크가 다시 연결되면 Discover 대신 쓰던 주소를 Request 로 확인한다
import { describe, expect, it } from "vitest";
import { Host } from "../src/core/nodes/host";
import { NetworkSync } from "../src/model/netSync";
import { createDevice, newId, type Device, type Topology } from "../src/model/topology";

/** 공유기 두 대(각자 LAN), pc 는 rt-1 에 꽂혀 있다 */
function twoRouters(rt2Lan: string) {
  const devices: Device[] = [];
  const add = (kind: Parameters<typeof createDevice>[0], x: number, y: number) => {
    const d = createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const rt1 = add("router", 0, 0);
  const rt2 = add("router", 400, 0);
  const base = rt2Lan.split(".").slice(0, 3).join(".");
  rt2.router = { ...rt2.router!, lanIp: rt2Lan, dhcp: { enabled: true, start: `${base}.100`, end: `${base}.199` } };
  const pc = add("pc", 0, 200);
  const plug = (rt: Device): Topology => ({ devices, cables: [{ id: `c-${rt.id}`, a: { device: rt.id, port: 1 }, b: { device: pc.id, port: 0 } }] });
  return { rt1, rt2, pc, plug };
}

function kindsSince(s: NetworkSync, from: number, id: string) {
  return s.net.trace.slice(from).filter((e) => e.nodeId === id).map((e) => e.kind);
}

describe("DHCP INIT-REBOOT", () => {
  it("같은 네트워크에 다시 꽂으면 Request → Ack 로 쓰던 주소를 그대로 쓴다", () => {
    const { rt1, pc, plug } = twoRouters("192.168.5.1");
    const s = new NetworkSync();
    s.sync(plug(rt1));
    s.net.runToIdle();
    const h = s.net.nodes.get(pc.id) as Host;
    const ip = h.ip;
    expect(ip).toMatch(/^192\.168\.0\.1\d\d$/);
    s.sync({ devices: plug(rt1).devices, cables: [] });
    s.net.runToIdle();
    expect(h.ip).toBeUndefined();
    const from = s.net.trace.length;
    s.sync(plug(rt1));
    s.net.runToIdle();
    expect(h.ip).toBe(ip);
    expect(kindsSince(s, from, pc.id)).toEqual(expect.arrayContaining(["dhcp.request.sent", "dhcp.ack.received"]));
    expect(kindsSince(s, from, pc.id)).not.toContain("dhcp.discover.sent");
  });

  it("다른 네트워크에 꽂으면 서버가 Nak → 잊고 Discover 로 새 주소를 받는다", () => {
    const { rt1, rt2, pc, plug } = twoRouters("192.168.5.1");
    const s = new NetworkSync();
    s.sync(plug(rt1));
    s.net.runToIdle();
    const from = s.net.trace.length;
    s.sync(plug(rt2));
    s.net.runToIdle();
    const h = s.net.nodes.get(pc.id) as Host;
    expect(h.ip).toMatch(/^192\.168\.5\.1\d\d$/);
    const kinds = kindsSince(s, from, pc.id);
    expect(kinds.indexOf("dhcp.nak.received")).toBeGreaterThan(-1);
    expect(kinds.indexOf("dhcp.discover.sent")).toBeGreaterThan(kinds.indexOf("dhcp.nak.received"));
    expect(s.net.trace.some((e) => e.nodeId === rt2.id && e.kind === "dhcp.nak.sent" && e.summary.includes("INIT-REBOOT"))).toBe(true);
  });

  it("같은 서브넷이지만 임대 기록이 없는 서버는 응답하지 않고, 클라이언트는 timeout 후 Discover", () => {
    const { rt1, rt2, pc, plug } = twoRouters("192.168.0.1"); // rt-2 도 192.168.0.0/24 지만 이 pc 를 모른다
    const s = new NetworkSync();
    s.sync(plug(rt1));
    s.net.runToIdle();
    const from = s.net.trace.length;
    s.sync(plug(rt2));
    s.net.runToIdle();
    const h = s.net.nodes.get(pc.id) as Host;
    expect(h.ip).toMatch(/^192\.168\.0\.1\d\d$/);
    const kinds = kindsSince(s, from, pc.id);
    expect(kinds).toContain("dhcp.timeout");
    expect(kinds.indexOf("dhcp.discover.sent")).toBeGreaterThan(kinds.indexOf("dhcp.timeout"));
    expect(s.net.trace.some((e) => e.nodeId === rt2.id && e.kind === "dhcp.ignore" && e.summary.includes("INIT-REBOOT"))).toBe(true);
  });

  it("같은 세그먼트에 범위가 다른 DHCP 서버가 둘이어도, 다시 연결할 때 주소가 끊기지 않는다 (늦은 Nak 무시·범위 밖은 침묵)", () => {
    const devices: Device[] = [];
    const add = (kind: Parameters<typeof createDevice>[0], x: number) => {
      const d = createDevice(kind, x, 0, devices);
      devices.push(d);
      return d;
    };
    const rt = add("router", 0);
    const sw = add("switch", 200);
    const srv = add("server", 400);
    srv.host = { ipMode: "static", ip: "192.168.0.10", prefix: 24, gateway: "192.168.0.1", services: [], dhcpServer: { enabled: true, start: "192.168.0.200", end: "192.168.0.250", router: "192.168.0.1" } };
    const pc = add("pc", 600);
    const base = [
      { id: newId("cable"), a: { device: rt.id, port: 1 }, b: { device: sw.id, port: 0 } },
      { id: newId("cable"), a: { device: sw.id, port: 2 }, b: { device: srv.id, port: 0 } },
    ];
    const withPc: Topology = { devices, cables: [...base, { id: "pc-cable", a: { device: sw.id, port: 5 }, b: { device: pc.id, port: 0 } }] };
    const s = new NetworkSync();
    s.sync(withPc);
    s.net.runToIdle();
    const h = s.net.nodes.get(pc.id) as Host;
    const ip = h.ip;
    expect(ip).toBeDefined();
    s.sync({ devices, cables: base });
    s.net.runToIdle();
    const from = s.net.trace.length;
    s.sync(withPc);
    s.net.runToIdle();
    expect(h.ip).toBe(ip);
    const kinds = kindsSince(s, from, pc.id);
    expect(kinds).not.toContain("dhcp.discover.sent");
    expect(s.net.trace.slice(from).some((e) => e.kind === "dhcp.nak.sent")).toBe(false);
  });
});
