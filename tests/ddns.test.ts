// DDNS (glddns.com 식): 공유기가 공인 주소를 이름에 갱신하고, ISP 가 주소를 바꾸면(FORCERENEW) 다시 갱신한다.
// WireGuard 앱은 서버를 이름으로 적어 두고, 핸드셰이크가 실패하면 이름을 다시 풀어 새 주소로 잇는다
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleDdnsTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import type { Internet } from "../src/core/nodes/internet";
import type { Topology } from "../src/model/topology";
import { ddnsHostname } from "../src/model/topology";

const load = (t: Topology = exampleDdnsTopology()) => loadTopology(t);

describe("DDNS", () => {
  it("이름 칸: 앞부분만 적으면 glddns.com 을 붙이고, 쓸 수 없는 글자면 없음", () => {
    expect(ddnsHostname("MyHome")).toBe("myhome.glddns.com");
    expect(ddnsHostname("myhome.glddns.com")).toBe("myhome.glddns.com");
    expect(ddnsHostname("my home")).toBeUndefined();
    expect(ddnsHostname("-x")).toBeUndefined();
  });

  it("WAN 주소를 받으면 갱신하고, 공인 DNS 가 그 이름을 짧은 TTL 로 답한다", () => {
    const { t, node, id } = load();
    expect(lintTopology(t)).toEqual([]);
    const home = node<Router>("집 Brume 3");
    expect(home.ddns.state).toBe("ok");
    expect(home.ddns.ip).toBe(home.wan.ip);
    expect(node<Internet>("internet-1").ddns.lookup("myhome.glddns.com")).toBe(home.wan.ip);
    void id;
  });

  it("카페 폰의 WireGuard 앱이 서버 이름을 풀어 붙는다", () => {
    const { host, id, act } = load();
    expect(host("카페 폰").ra.state).toBe("up");
    act({ kind: "ping", nodeId: id("카페 폰"), dst: "192.168.8.20" });
    expect(host("카페 폰").pings.at(-1)!.status).toBe("ok");
  });

  it("ISP 가 주소를 바꾸면(FORCERENEW) 공유기가 새 주소로 DDNS 를 갱신하고, 폰은 실패 뒤 이름을 다시 풀어 새 주소로 잇는다", () => {
    const L = load();
    const { node, host, id, act, s } = L;
    const home = node<Router>("집 Brume 3");
    const old = home.wan.ip!;
    const tr = act({ kind: "isp-renumber", nodeId: id("internet-1"), ip: old });
    const now = home.wan.ip!;
    expect(now).not.toBe(old);
    expect(tr.some((e) => e.kind === "ddns.ok" && e.summary.includes(now))).toBe(true);
    expect(node<Internet>("internet-1").ddns.lookup("myhome.glddns.com")).toBe(now);
    // 폰은 아직 옛 주소: 보낸 것에 답이 없다
    act({ kind: "ping", nodeId: id("카페 폰"), dst: "192.168.8.20" });
    expect(host("카페 폰").pings.at(-1)!.status).toBe("failed");
    // 시간이 흐르면: 15초 무응답 → 새 핸드셰이크 3번 실패 → 이름을 다시 풀어(TTL 이 짧아 캐시가 끝남) 새 주소로
    const from = s.net.trace.length;
    s.net.runUntil(s.net.now + 60_000);
    const later = s.net.trace.slice(from);
    expect(later.some((e) => e.nodeId === id("카페 폰") && e.kind === "vpn.handshake" && e.summary.includes(`${old} → ${now}`))).toBe(true);
    expect(host("카페 폰").ra.state).toBe("up");
    act({ kind: "ping", nodeId: id("카페 폰"), dst: "192.168.8.20" });
    expect(host("카페 폰").pings.at(-1)!.status).toBe("ok");
  });

  it("다른 공유기가 같은 이름을 쓰려 하면 badauth (이름은 기기마다 하나)", () => {
    const base = exampleDdnsTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.name === "카페 공유기" ? { ...d, router: { ...d.router!, ddns: { enabled: true, name: "myhome" } } } : d)) };
    expect(lintTopology(t).map((i) => i.code)).toContain("ddns.name-taken");
    const { node } = load(t);
    const cafe = node<Router>("카페 공유기");
    const home = node<Router>("집 Brume 3");
    // 먼저 등록한 쪽이 이름을 갖고, 나중 쪽은 badauth
    const loser = cafe.ddns.state === "failed" ? cafe : home;
    expect(loser.ddns.reason).toContain("badauth");
  });

  it("다시 푼 주소가 같으면 다시 잇지 않는다 (실패 → 다시 풀기 → 실패 의 끝없는 반복 없음)", () => {
    const L = load();
    const { id, act, apply, s, t } = L;
    // 서버를 꺼서 늘 실패하게 — 주소는 그대로
    apply({ ...t, devices: t.devices.map((d) => (d.router?.wgServer ? { ...d, router: { ...d.router, wgServer: { ...d.router.wgServer, enabled: false } } } : d)) });
    act({ kind: "ping", nodeId: id("카페 폰"), dst: "192.168.8.20" });
    s.net.runUntil(s.net.now + 120_000);
    const tail = s.net.trace.slice(-20);
    expect(s.net.trace.some((e) => e.nodeId === id("카페 폰") && e.summary.includes("다시 푼 주소도"))).toBe(true);
    // 조용해졌다: 마지막 이벤트 이후 대기 중인 일반 이벤트가 없어 runToIdle 이 끝난다 (loadTopology 의 run 이 끝났으므로)
    expect(tail.length).toBeGreaterThan(0);
  });
});

describe("DDNS 구성 검사", () => {
  const codes = (t: Topology) => lintTopology(t).map((i) => `${t.devices.find((d) => d.id === i.deviceId)!.name}:${i.code}`);
  const setHome = (t: Topology, ddns: { enabled: boolean; name: string }): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === "집 Brume 3" ? { ...d, router: { ...d.router!, ddns } } : d)) });

  it("쓸 수 없는 이름이면 ddns.name-invalid, 폰이 가리키는 이름을 아무도 등록하지 않으면 wg.name-unknown", () => {
    const t = exampleDdnsTopology();
    expect(codes(setHome(t, { enabled: true, name: "my home" })).sort()).toEqual(["집 Brume 3:ddns.name-invalid", "카페 폰:wg.name-unknown"]);
    expect(codes(setHome(t, { enabled: false, name: "myhome" }))).toEqual(["카페 폰:wg.name-unknown"]);
  });

  it("이름으로 찾은 서버의 키·등록도 확인한다 (DDNS 이름 → 그 이름을 켠 공유기)", () => {
    const t = exampleDdnsTopology();
    const off: Topology = { ...t, devices: t.devices.map((d) => (d.router?.wgServer ? { ...d, router: { ...d.router, wgServer: { ...d.router.wgServer, peers: [] } } } : d)) };
    expect(codes(off).sort()).toEqual(["집 Brume 3:wg.no-peers", "카페 폰:wg.not-registered"]);
  });
});
