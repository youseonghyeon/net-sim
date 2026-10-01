// 리뷰: 노트북 유선·무선 NIC (75fae70) 결함 재현 테스트. "실제:" 주석은 고치기 전의 동작. 5·7 은 고친 구조(원인 줄 → 정리 → 0ms 뒤 전환 줄)에 맞춰 단언을 옮겼다
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { lintTopology } from "../src/model/lint";
import { createDevice, wirelessLinks, type Device, type Topology } from "../src/model/topology";

/** 공유기(Wi-Fi "home") + 서버(고정 192.168.0.20) + 노트북(유선 케이블 c-lap + 선택적 Wi-Fi) — tests/laptop-nic.test.ts 의 home() 과 같은 꼴 */
function home(opts: { cable?: boolean; wifi?: Device["wifi"]; static?: boolean } = {}): Topology {
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
  if (opts.static) lap.host = { ...lap.host!, ipMode: "static", ip: "192.168.0.50", prefix: 24, gateway: "192.168.0.1" };
  if (opts.wifi !== undefined) lap.wifi = opts.wifi;
  const cables = [{ id: "c-srv", a: { device: rt.id, port: 2 }, b: { device: srv.id, port: 0 } }];
  if (opts.cable !== false) cables.push({ id: "c-lap", a: { device: rt.id, port: 1 }, b: { device: lap.id, port: 0 } });
  return { devices, cables };
}
const unplug = (t: Topology): Topology => ({ ...t, cables: t.cables.filter((c) => c.id !== "c-lap") });
const plug = (t: Topology): Topology => {
  const rt = t.devices.find((d) => d.name === "공유기")!;
  const lap = t.devices.find((d) => d.name === "노트북")!;
  return { ...t, cables: [...t.cables.filter((c) => c.id !== "c-lap"), { id: "c-lap", a: { device: rt.id, port: 1 }, b: { device: lap.id, port: 0 } }] };
};
const setLap = (t: Topology, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === "노트북" ? f(d) : d)) });

describe("노트북 NIC 리뷰 결함", () => {
  it("1. 둘 다 끊긴 상태를 거쳐 Wi-Fi 로 넘어가도 유선 NIC 의 DHCP 기억이 남아, 케이블을 다시 꽂으면 INIT-REBOOT 로 확인한다", () => {
    // 유선만(Wi-Fi 꺼짐) .100 → 케이블 뺌(연결 없음) → Wi-Fi 켬(.101) → 케이블 다시 꽂음
    const t0 = home({ wifi: { ssid: "home", enabled: false } });
    const x = loadTopology(t0);
    const lapId = x.id("노트북");
    expect(x.host("노트북").ip).toBe("192.168.0.100");
    let t = unplug(t0);
    x.apply(t);
    expect(x.host("노트북").activeNic).toBeUndefined();
    t = setLap(t, (d) => ({ ...d, wifi: { ssid: "home" } }));
    x.apply(t);
    expect(x.host("노트북").activeNic).toBe(1);
    const tr = x.apply(plug(t));
    expect(x.host("노트북").activeNic).toBe(0);
    // 실제: useNic 이 prev === undefined 라 nics[0].lease 를 저장하지 않아 기억을 잃고 Discover 부터
    expect(tr.some((e) => e.nodeId === lapId && e.kind === "dhcp.request.sent" && e.summary.includes("INIT-REBOOT") && e.summary.includes("192.168.0.100"))).toBe(true);
    expect(tr.some((e) => e.nodeId === lapId && e.kind === "dhcp.discover.sent")).toBe(false);
  });

  it("2a. 유선 + Wi-Fi 대기인 노트북을 지우면 Wi-Fi 로 넘어가 DHCP Discover 를 보내지 않는다 (공유기에 유령 Offer 가 남아 다음 장치가 주소를 건너뜀)", () => {
    const t = home({ wifi: { ssid: "home" } });
    const x = loadTopology(t);
    const lapId = x.id("노트북");
    const rtId = x.id("공유기");
    const t1: Topology = { devices: t.devices.filter((d) => d.id !== lapId), cables: t.cables.filter((c) => c.id !== "c-lap") };
    const tr = x.apply(t1);
    // 실제: removeNode 가 케이블 → 무선 순으로 끊는 동안 노트북이 "eth0 링크 다운 → Wi-Fi 로 전환" 하고 Discover 를 보낸다 (graceful 이라 배달됨)
    expect(tr.filter((e) => e.nodeId === lapId && e.summary.includes("로 전환"))).toEqual([]);
    expect(tr.filter((e) => e.nodeId === rtId && e.kind === "dhcp.discover.received")).toEqual([]);
    // 그 Offer(192.168.0.100 → 지운 노트북의 wlan MAC)는 만료가 없어 돌려받은 .100 을 막는다
    const pc = { ...createDevice("pc", 100, 160, t1.devices), name: "새 PC" };
    x.apply({ devices: [...t1.devices, pc], cables: [...t1.cables, { id: "c-pc", a: { device: rtId, port: 1 }, b: { device: pc.id, port: 0 } }] });
    expect(x.s.net.getHost(pc.id).ip).toBe("192.168.0.100");
  });

  it("2b. 노트북의 케이블·Wi-Fi 가 모두 같은 공유기에 붙어 있을 때 공유기를 지우면 Wi-Fi 로 전환했다가 끊기는 가짜 전환이 없다", () => {
    const t = home({ wifi: { ssid: "home" } });
    const x = loadTopology(t);
    const lapId = x.id("노트북");
    const rtId = x.id("공유기");
    const tr = x.apply({ devices: t.devices.filter((d) => d.id !== rtId), cables: [] });
    // 실제: "eth0 링크 다운 → 연결돼 있던 Wi-Fi(wlan0) 로 전환 … 주소를 새로 받는다" + wlan0 로 DHCP Discover, 곧바로 "wlan0 링크 다운"
    expect(tr.filter((e) => e.nodeId === lapId && e.summary.includes("로 전환"))).toEqual([]);
    expect(tr.filter((e) => e.nodeId === lapId && e.kind === "dhcp.discover.sent")).toEqual([]);
  });

  it("3. 유선을 쓰는 노트북의 Wi-Fi 를 켜도(대기) 이미 붙어 있던 스마트폰들의 무선 슬롯·연결은 그대로다", () => {
    const devices: Device[] = [];
    const add = (kind: Device["kind"], x: number, y: number, name: string) => {
      const d = { ...createDevice(kind, x, y, devices), name };
      devices.push(d);
      return d;
    };
    const rt = add("router", 200, 0, "공유기");
    rt.router = { ...rt.router!, wifi: { enabled: true, ssid: "home" } };
    const lap = add("laptop", 100, 160, "노트북"); // 스마트폰보다 먼저 만든 노트북
    const p1 = add("phone", 250, 160, "폰1");
    const p2 = add("phone", 300, 160, "폰2");
    const t: Topology = { devices, cables: [{ id: "c-lap", a: { device: rt.id, port: 1 }, b: { device: lap.id, port: 0 } }] };
    const x = loadTopology(t);
    const before = wirelessLinks(t).map((l) => l.id);
    expect(x.host("폰1").ip).toBeDefined();
    const t2 = { ...t, devices: t.devices.map((d) => (d.id === lap.id ? { ...d, wifi: { ssid: "home" } } : d)) };
    const after = wirelessLinks(t2);
    expect(after.find((l) => l.client === lap.id)?.standby).toBe(true);
    // 실제: 장치 순서대로 슬롯을 다시 고르며 노트북이 폰1 의 슬롯을 차지 → 폰1·폰2 슬롯이 밀려 링크 id 가 바뀐다
    expect(after.filter((l) => l.client !== lap.id).map((l) => l.id)).toEqual(before);
    const tr = x.apply(t2);
    // 실제: 두 폰 모두 "무선 연결 변경 … 다시 연결" → 링크 다운 → 임대 주소 해제 → INIT-REBOOT
    expect(tr.filter((e) => (e.nodeId === p1.id || e.nodeId === p2.id) && (e.kind === "wifi.disassociate" || e.kind === "link.down"))).toEqual([]);
  });

  it("4. 구성 검사 ipv6.duplicate: 대기 중인 Wi-Fi(쓰지 않는 링크)로 떨어진 두 실습을 한 묶음으로 보지 않는다", () => {
    const devices: Device[] = [];
    const add = (kind: Device["kind"], x: number, y: number, name: string) => {
      const d = { ...createDevice(kind, x, y, devices), name };
      devices.push(d);
      return d;
    };
    // 섬 A: 스위치 + PC(IPv6 수동 2001:db8:1::10) + 노트북(유선, Wi-Fi 켬 → 대기)
    const sw = add("switch", 0, 0, "스위치");
    const pc = add("pc", 0, 200, "PC");
    pc.host = { ...pc.host!, ipv6: { enabled: true, mode: "static", ip: "2001:db8:1::10", prefix: 64, gateway: "" } };
    const lap = add("laptop", 400, 200, "노트북");
    lap.wifi = { ssid: "lab" };
    // 섬 B: AP + 스마트폰(같은 IPv6 주소) — 어디에도 케이블로 이어지지 않음
    const ap = add("ap", 400, 0, "AP");
    ap.ap = { enabled: true, ssid: "lab" };
    const ph = add("phone", 500, 100, "폰");
    ph.wifi = { ssid: "lab" };
    ph.host = { ...ph.host!, ipv6: { enabled: true, mode: "static", ip: "2001:db8:1::10", prefix: 64, gateway: "" } };
    const t: Topology = {
      devices,
      cables: [
        { id: "c1", a: { device: sw.id, port: 0 }, b: { device: pc.id, port: 0 } },
        { id: "c2", a: { device: sw.id, port: 1 }, b: { device: lap.id, port: 0 } },
      ],
    };
    expect(wirelessLinks(t).find((l) => l.client === lap.id)?.standby).toBe(true);
    // Wi-Fi 를 끈 노트북이면 조용하다 — 대기 링크도 같아야 한다 (노트북은 포워딩하지 않고, 대기 Wi-Fi 는 쓰지도 않는다)
    const off = { ...t, devices: t.devices.map((d) => (d.id === lap.id ? { ...d, wifi: { ssid: "lab", enabled: false } } : d)) };
    expect(lintTopology(off).filter((i) => i.code === "ipv6.duplicate")).toEqual([]);
    // 실제: lint/ipv6.ts components() 가 대기 링크까지 union 해 PC·폰 둘 다 error
    expect(lintTopology(t).filter((i) => i.code === "ipv6.duplicate")).toEqual([]);
  });

  it("5. NIC 전환 로그는 원인(링크 다운·전환) 줄이 결과(임대 해제·VPN 끊김) 줄보다 먼저 나온다 — 단일 NIC 의 링크 다운과 같은 순서", () => {
    const x = loadTopology(home({ wifi: { ssid: "home" } }));
    const lapId = x.id("노트북");
    const tr = x.apply(unplug(x.t)).filter((e) => e.nodeId === lapId);
    const cause = tr.findIndex((e) => e.kind === "link.down" && e.summary.startsWith("eth0 링크 다운"));
    const effect = tr.findIndex((e) => e.kind === "dhcp.release");
    const sw = tr.findIndex((e) => e.summary.includes("Wi-Fi(wlan0) 로 전환"));
    expect(cause).toBeGreaterThanOrEqual(0);
    expect(effect).toBeGreaterThanOrEqual(0);
    // 실제: stackDown(…, null) 이 먼저 돌아 "NIC 전환으로 임대 주소 … 해제" 가 "eth0 링크 다운 → … 전환" 보다 앞선다
    expect(cause).toBeLessThan(effect);
    // 전환은 정리 뒤 (같은 순간의 다른 링크 변화까지 본 다음)
    expect(sw).toBeGreaterThan(effect);
  });

  it("6. 유선을 쓰는 동안 붙은 대기 Wi-Fi 의 연결 로그는 'DHCP 시작' 이라고 하지 않는다 (DHCP 는 시작하지 않음)", () => {
    const x = loadTopology(home({ wifi: { ssid: "home" } }));
    const lapId = x.id("노트북");
    expect(x.host("노트북").activeNic).toBe(0);
    const assoc = x.s.net.trace.filter((e) => e.nodeId === lapId && e.kind === "wifi.associate");
    expect(assoc.length).toBe(1);
    // 실제: netSync 가 대기 링크에도 "무선 연결: 공유기 에 붙음 (…) → DHCP 시작"
    expect(assoc[0]!.summary).not.toContain("DHCP 시작");
  });

  it("7. 수동 IP 노트북이 NIC 를 바꿔 끼면 로그가 '주소를 새로 받는다' 고 하지 않는다 (같은 수동 주소를 다시 Probe 해 쓴다)", () => {
    const x = loadTopology(home({ wifi: { ssid: "home" }, static: true }));
    const lapId = x.id("노트북");
    const tr = x.apply(unplug(x.t)).filter((e) => e.nodeId === lapId);
    expect(x.host("노트북").ip).toBe("192.168.0.50");
    const sw = tr.find((e) => e.summary.includes("로 전환"))!;
    expect(sw).toBeDefined();
    expect(sw.summary).not.toContain("주소를 새로 받는다");
    expect(sw.summary).toContain("수동 주소 192.168.0.50 를 새 MAC 으로 다시 확인");
  });
});
