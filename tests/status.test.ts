import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { AccessPoint } from "../src/core/nodes/ap";
import { Host } from "../src/core/nodes/host";
import { L3Node } from "../src/core/nodes/l3";
import { Router } from "../src/core/nodes/router";
import { Switch } from "../src/core/nodes/switch";
import { buildHomeLan } from "../src/core/scenarios/homeLan";
import { hostStatusOf, serviceBadgesOf, wanStatusOf } from "../src/model/status";

describe("타일 상태 문구", () => {
  it("호스트: 케이블 없음 → DHCP 요청 중 → 주소, 무선 단말은 '무선 연결 없음'", () => {
    const net = new Network();
    const h = net.addNode(new Host({ id: "a", mac: "02:00:00:00:00:0a" }));
    expect(hostStatusOf(h, false)).toMatchObject({ text: "케이블 없음", tone: "muted" });
    expect(hostStatusOf(h, true)).toMatchObject({ text: "무선 연결 없음", tone: "muted" });
    net.addNode(new Switch("sw", 2));
    net.connect("a", 0, "sw", 0);
    net.runUntil(0);
    expect(hostStatusOf(h, false)).toMatchObject({ text: "DHCP 요청 중 (1/3)", tone: "warn" });
    net.runToIdle();
    expect(hostStatusOf(h, false)).toMatchObject({ text: "DHCP 실패 · IP 없음", tone: "warn" });
    h.configure({ ipMode: "static", ip: "10.0.0.5", prefix: 24 }, net.contextFor("a"));
    expect(hostStatusOf(h, false)).toMatchObject({ text: "10.0.0.5/24", tone: "ok", mono: true });
    h.configure({ ipMode: "static" }, net.contextFor("a"));
    expect(hostStatusOf(h, false)).toMatchObject({ text: "IP 없음 · 수동 입력 필요", tone: "warn" });
    expect(hostStatusOf(undefined, false)).toBeNull();
  });

  it("공유기·인터넷·AP·게이트웨이 요약과 WAN 줄", () => {
    const net = buildHomeLan(true, true);
    net.runToIdle();
    const rt = net.nodes.get("rt") as Router;
    expect(hostStatusOf(rt, false)).toMatchObject({ text: "192.168.0.1/24", tone: "ok" });
    expect(wanStatusOf(rt)?.text).toMatch(/^WAN 203\.0\.113\./);
    expect(hostStatusOf(net.nodes.get("inet"), false)?.text).toMatch(/^ISP /);
    const ap = new AccessPoint("ap", "home");
    expect(hostStatusOf(ap, false)).toMatchObject({ text: "SSID home · 단말 0대" });

    const gw = new L3Node({
      id: "gw",
      kind: "gateway",
      interfaces: [
        { name: "if0", mac: "02:00:00:10:00:01", mode: "dhcp" },
        { name: "if1", mac: "02:00:00:11:00:01", mode: "static", ip: "192.168.1.1", prefix: 24 },
        { name: "if2", mac: "02:00:00:12:00:01", mode: "static" },
      ],
      subinterfaces: [{ port: 2, vlan: 10 }, { port: 2, vlan: 20 }],
    });
    expect(hostStatusOf(gw, false)).toMatchObject({ text: "192.168.1.1 · if2.10/20", tone: "ok" });
    expect(wanStatusOf(gw)).toMatchObject({ text: "if0 연결 없음", tone: "muted" });
    const bare = new L3Node({ id: "g2", kind: "gateway", interfaces: [{ name: "if0", mac: "02:00:00:10:00:02", mode: "static" }, { name: "if1", mac: "02:00:00:11:00:02", mode: "static" }] });
    expect(hostStatusOf(bare, false)).toMatchObject({ text: "if1 없음", tone: "warn" });
  });

  it("서비스 배지: 상자 안에서 도는 소프트웨어만 보인다", () => {
    const net = buildHomeLan(true, true);
    net.runToIdle();
    const rt = net.nodes.get("rt") as Router;
    expect(serviceBadgesOf(net.nodes.get("srv"))).toEqual(["웹"]);
    expect(serviceBadgesOf(rt)).toEqual(["DHCP", "DNS", "NAT"]);
    rt.configure(
      {
        lanIp: "192.168.0.1",
        lanPrefix: 24,
        dhcp: rt.dhcpServer.config,
        wan: { mode: "dhcp" },
        forwards: [{ publicPort: 80, lanIp: "192.168.0.50", lanPort: 80 }],
        firewall: { enabled: true, defaultPolicy: "allow", stateful: true, rules: [] },
        wifi: { enabled: true, ssid: "home" },
      },
      net.contextFor("rt"),
    );
    expect(serviceBadgesOf(rt)).toEqual(["DHCP", "DNS", "NAT+포워딩", "방화벽", "Wi-Fi home"]);
    expect(serviceBadgesOf(net.nodes.get("inet"))).toEqual(["ISP DHCP", "DNS", "웹"]);
    const sw = new Switch("sw", 4);
    expect(serviceBadgesOf(sw)).toEqual([]);
    sw.setVlans(new Map([[0, "trunk"]]), net.contextFor("sw"));
    expect(serviceBadgesOf(sw)).toEqual(["VLAN"]);
    expect(serviceBadgesOf(undefined)).toEqual([]);
  });
});
