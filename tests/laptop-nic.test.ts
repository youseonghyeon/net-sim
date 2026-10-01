// 노트북 NIC 두 개 (유선 eth0 + 무선 wlan0): 유선이 살아 있으면 유선, 빼면 Wi-Fi 로 넘어간다. NIC 마다 MAC 이 달라 넘어갈 때마다 주소를 새로 받는다
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import { loadTopology } from "./helpers";
import { exampleIptimeVpnTopology } from "../src/model/examples";
import { createDevice, normalizeTopology, parseTopology, serializeTopology, wirelessLinks, type Device, type Topology } from "../src/model/topology";
import { serviceBadgesOf } from "../src/model/status";
import { wlanMacOf } from "../src/model/netSync";
import type { Router } from "../src/core/nodes/router";

/** 공유기(Wi-Fi "home" 켬) + 서버(고정 192.168.0.20, SSH) + 노트북(유선 케이블 + Wi-Fi "home") */
function home(opts: { cable?: boolean; wifi?: Device["wifi"] } = {}): Topology {
  const devices: Device[] = [];
  const add = (kind: Device["kind"], x: number, y: number, name: string) => {
    const d = { ...createDevice(kind, x, y, devices), name };
    devices.push(d);
    return d;
  };
  const rt = add("router", 200, 0, "공유기");
  rt.router = { ...rt.router!, wifi: { enabled: true, ssid: "home" } };
  const srv = add("server", 360, 160, "서버");
  srv.host = { ...srv.host!, ipMode: "static", ip: "192.168.0.20", prefix: 24, gateway: "192.168.0.1", services: [22, 80] };
  const lap = add("laptop", 200, 160, "노트북");
  if (opts.wifi !== undefined) lap.wifi = opts.wifi;
  const cables = [{ id: "c-srv", a: { device: rt.id, port: 2 }, b: { device: srv.id, port: 0 } }];
  if (opts.cable !== false) cables.push({ id: "c-lap", a: { device: rt.id, port: 1 }, b: { device: lap.id, port: 0 } });
  return { devices, cables };
}
const unplug = (t: Topology): Topology => ({ ...t, cables: t.cables.filter((c) => c.id !== "c-lap") });

describe("노트북 유선·무선 NIC (유선 우선 자동 전환)", () => {
  it("케이블과 Wi-Fi 가 둘 다 있으면 유선을 쓰고, Wi-Fi 는 붙어만 있다 (대기)", () => {
    const t = home({ wifi: { ssid: "home" } });
    expect(lintTopology(t)).toEqual([]);
    expect(wirelessLinks(t)).toMatchObject([{ clientPort: 1, standby: true }]);
    const x = loadTopology(t);
    const lap = x.host("노트북");
    expect(lap.activeNic).toBe(0);
    expect(lap.mac).toBe(t.devices.find((d) => d.name === "노트북")!.mac);
    expect(lap.ip).toBe("192.168.0.100");
    expect(x.s.net.trace.some((e) => e.nodeId === x.id("노트북") && e.summary.includes("wlan0 연결됨 → 지금 쓰는 유선(eth0) 가 우선이라 대기"))).toBe(true);
    expect(serviceBadgesOf(lap)).not.toContain("Wi-Fi");
  });

  it("케이블을 빼면 Wi-Fi 로 넘어간다: MAC 이 바뀌어 공유기는 다른 기기로 보고 다른 주소를 준다", () => {
    const x = loadTopology(home({ wifi: { ssid: "home" } }));
    const eth = x.host("노트북").mac;
    const tr = x.apply(unplug(x.t));
    const lap = x.host("노트북");
    expect(lap.activeNic).toBe(1);
    expect(lap.mac).toBe(wlanMacOf(eth));
    expect(lap.ip).toBe("192.168.0.101");
    expect(serviceBadgesOf(lap)).toContain("Wi-Fi");
    expect(tr.some((e) => e.nodeId === x.id("노트북") && e.kind === "link.down" && e.summary === "eth0 링크 다운")).toBe(true);
    expect(tr.some((e) => e.nodeId === x.id("노트북") && e.summary.includes(`Wi-Fi(wlan0) 로 전환: 다른 NIC 라 MAC 이 ${eth} → ${wlanMacOf(eth)} 로 바뀜 → DHCP 로 주소를 새로 받는다`))).toBe(true);
    // 공유기의 DHCP 임대는 MAC 둘
    expect(x.node<Router>("공유기").dhcpServer.rows().map((r) => r[0]).sort()).toEqual(["192.168.0.100", "192.168.0.101"]);
    x.act({ kind: "ping", nodeId: x.id("노트북"), dst: "192.168.0.20" });
    expect(lap.pings.at(-1)!.status).toBe("ok");
  });

  it("케이블을 다시 꽂으면 유선으로 돌아오고, 유선 NIC 가 쓰던 주소를 INIT-REBOOT 로 되찾는다", () => {
    const x = loadTopology(home({ wifi: { ssid: "home" } }));
    x.apply(unplug(x.t));
    const tr = x.apply(x.t);
    const lap = x.host("노트북");
    expect(lap.activeNic).toBe(0);
    expect(lap.ip).toBe("192.168.0.100");
    expect(tr.some((e) => e.nodeId === x.id("노트북") && e.summary.includes("eth0 링크 연결됨 → 유선이 우선이라 Wi-Fi(wlan0) 를 내려놓음"))).toBe(true);
    expect(tr.some((e) => e.nodeId === x.id("노트북") && e.summary.includes("유선(eth0) 로 전환"))).toBe(true);
    expect(tr.some((e) => e.nodeId === x.id("노트북") && e.kind === "dhcp.request.sent" && e.summary.includes("INIT-REBOOT") && e.summary.includes("192.168.0.100"))).toBe(true);
  });

  it("넘어가면 열려 있던 SSH 세션은 끊긴다 (출발지 주소가 바뀜)", () => {
    const x = loadTopology(home({ wifi: { ssid: "home" } }));
    x.act({ kind: "tcp-connect", nodeId: x.id("노트북"), dst: "192.168.0.20", port: 22 });
    expect(x.lastConn("노트북")).toMatchObject({ state: "ESTABLISHED", ssh: { open: true } });
    x.apply(unplug(x.t));
    expect(x.lastConn("노트북").state).toBe("FAILED");
    expect(x.lastConn("노트북").reason).toContain("링크 다운");
  });

  it("Wi-Fi 만 (케이블 없음): 처음부터 Wi-Fi 로 붙고 구성 검사도 조용하다", () => {
    const t = home({ cable: false, wifi: { ssid: "home" } });
    expect(lintTopology(t)).toEqual([]);
    const x = loadTopology(t);
    expect(x.host("노트북").activeNic).toBe(1);
    expect(x.host("노트북").ip).toBe("192.168.0.100");
  });

  it("Wi-Fi 를 끄면(SSID 는 기억) 케이블을 빼는 순간 연결이 없다. 다시 켜면 붙는다", () => {
    const off = unplug(home({ wifi: { ssid: "home", enabled: false } }));
    expect(wirelessLinks(off)).toEqual([]);
    const x = loadTopology(off);
    expect(x.host("노트북").activeNic).toBeUndefined();
    expect(x.host("노트북").linkUp).toBe(false);
    x.apply({ ...off, devices: off.devices.map((d) => (d.name === "노트북" ? { ...d, wifi: { ssid: "home" } } : d)) });
    expect(x.host("노트북").activeNic).toBe(1);
    expect(x.host("노트북").ip).toBeDefined();
  });

  it("Wi-Fi 를 켜지 않은 노트북은 예전처럼 유선 하나 (Wi-Fi 기지 근처여도 붙지 않음)", () => {
    const t = home();
    expect(wirelessLinks(t)).toEqual([]);
    const x = loadTopology(t);
    expect(x.host("노트북").activeNic).toBe(0);
    expect(x.s.net.trace.filter((e) => e.nodeId === x.id("노트북") && e.kind === "link.up").map((e) => e.summary)).toEqual(["eth0 링크 연결됨 → 유선(eth0) 로 통신 (MAC " + x.host("노트북").mac + ")"]);
  });

  it("저장·불러오기: Wi-Fi 꺼짐은 노트북만 남고, 다른 장치의 wifi 는 버린다", () => {
    const t = home({ wifi: { ssid: "cafe", enabled: false } });
    const back = parseTopology(serializeTopology(t)).topology!;
    expect(back.devices.find((d) => d.name === "노트북")!.wifi).toEqual({ ssid: "cafe", enabled: false });
    const pc = { ...createDevice("pc", 0, 0, []), wifi: { ssid: "x" } };
    expect(normalizeTopology({ devices: [pc], cables: [] }).devices[0]!.wifi).toBeUndefined();
  });

  it("호텔에서 케이블을 빼면 호텔 Wi-Fi 로 넘어가 L2TP/IPsec VPN 이 다시 붙고, 집 LAN 주소는 그대로", () => {
    const base = exampleIptimeVpnTopology();
    const t: Topology = {
      ...base,
      devices: base.devices.map((d) =>
        d.name === "호텔 공유기" ? { ...d, router: { ...d.router!, wifi: { enabled: true, ssid: "hotel" } } } : d.name === "출장 노트북" ? { ...d, wifi: { ssid: "hotel" } } : d,
      ),
    };
    expect(lintTopology(t)).toEqual([]);
    const x = loadTopology(t);
    expect(x.host("출장 노트북").ra.vip).toBe("192.168.0.50");
    const lapId = x.id("출장 노트북");
    x.apply({ ...t, cables: t.cables.filter((c) => c.a.device !== lapId && c.b.device !== lapId) });
    const lap = x.host("출장 노트북");
    expect(lap.activeNic).toBe(1);
    expect(lap.ip).toBe("10.10.0.101");
    expect(lap.ra.state).toBe("up");
    expect(lap.ra.vip).toBe("192.168.0.50");
    x.act({ kind: "ping", nodeId: lapId, dst: "192.168.0.20" });
    expect(lap.pings.at(-1)!.status).toBe("ok");
  });
});
