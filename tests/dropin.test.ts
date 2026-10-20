// 드롭인 게이트웨이: 기존 LAN 에 WAN 만 꽂은 Brume 이 그 LAN 기기의 게이트웨이가 된다 (한 팔 라우터 + NAT)
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleDropInTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Topology } from "../src/model/topology";

describe("드롭인 게이트웨이", () => {
  it("아이 PC(게이트웨이 = Brume)만 Brume 의 DPI 에 걸리고, 아빠 PC 는 기존 공유기로 바로", () => {
    const L = loadTopology(exampleDropInTopology());
    expect(L.lint()).toEqual([]);
    let tr = L.act({ kind: "tcp-connect", nodeId: L.id("아이 PC"), dst: "roblox.com", port: 443 });
    expect(L.lastConn("아이 PC").state).toBe("FAILED");
    expect(tr.some((e) => e.kind === "dpi.block" && e.summary.includes("Roblox"))).toBe(true);
    expect(tr.some((e) => e.kind === "ip.forward" && e.summary.includes("드롭인 게이트웨이"))).toBe(true);
    tr = L.act({ kind: "tcp-connect", nodeId: L.id("아빠 PC"), dst: "roblox.com", port: 443 });
    expect(L.lastConn("아빠 PC").state).toBe("CLOSED");
    expect(tr.some((e) => e.nodeId === L.id("Brume 3 (드롭인)") && e.kind === "ip.forward")).toBe(false);
  });

  it("막지 않는 곳은 Brume 을 거쳐 NAT 되어 돌아온다 (ping 8.8.8.8 — 응답이 WAN 쪽 기기로 되돌아감)", () => {
    const L = loadTopology(exampleDropInTopology());
    const tr = L.act({ kind: "ping", nodeId: L.id("아이 PC"), dst: "8.8.8.8" });
    expect(L.host("아이 PC").pings.at(-1)!.status).toBe("ok");
    expect(tr.some((e) => e.nodeId === L.id("Brume 3 (드롭인)") && e.kind === "nat.translate")).toBe(true);
    expect(tr.some((e) => e.summary.includes("WAN 인터페이스로 되돌려 전달"))).toBe(true);
  });

  it("드롭인을 끄면 Brume 은 자기 주소가 아닌 패킷을 버린다 (아이 PC 는 인터넷에 못 나감)", () => {
    const base = exampleDropInTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.router?.dropIn ? { ...d, router: { ...d.router, dropIn: false } } : d)) };
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id("아이 PC"), dst: "8.8.8.8" });
    expect(L.host("아이 PC").pings.at(-1)!.status).toBe("failed");
  });

  it("드롭인으로 오는 기기도 기기 차단(MAC)이 걸린다", () => {
    const base = exampleDropInTopology();
    const kid = base.devices.find((d) => d.name === "아이 PC")!;
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.router?.dropIn ? { ...d, router: { ...d.router, blocked: [kid.mac] } } : d)) };
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: L.id("아이 PC"), dst: "8.8.8.8" });
    expect(L.host("아이 PC").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.kind === "fw.deny" && e.summary.includes("기기 차단"))).toBe(true);
  });

  it("드롭인 기기가 공유기의 LAN 주소(192.168.8.1)로 보낸 관리 화면·DNS·ping 도 공유기 자신이 받고, 답은 그 주소에서 WAN 으로", () => {
    const base = exampleDropInTopology();
    const t: Topology = { ...base, devices: base.devices.map((d) => (d.router?.dropIn ? { ...d, router: { ...d.router, admin: { enabled: true, remote: false, allow: "", ssh: true } } } : d)) };
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id("아이 PC"), dst: "192.168.8.1" });
    expect(L.host("아이 PC").pings.at(-1)!.status).toBe("ok");
    L.act({ kind: "tcp-connect", nodeId: L.id("아이 PC"), dst: "192.168.8.1", port: 443 });
    expect(L.lastConn("아이 PC").state).toBe("CLOSED");
    const tr = L.act({ kind: "dns-lookup", nodeId: L.id("아이 PC"), name: "example.com", qtype: "A", server: "192.168.8.1" });
    expect(L.host("아이 PC").lookups.at(-1)!.status).toBe("ok");
    // 답의 출발지는 물어본 주소 (WAN 주소로 바꾸지 않음)
    expect(tr.find((e) => e.nodeId === L.id("아이 PC") && e.kind === "dns.response.received")!.summary).toContain("서버 192.168.8.1");
    // 듣는 서비스가 없는 포트는 NAT 역변환으로 넘기지 않고 드롭
    const tr2 = L.act({ kind: "tcp-connect", nodeId: L.id("아이 PC"), dst: "192.168.8.1", port: 8080 });
    expect(tr2.some((e) => e.kind === "ip.drop" && e.summary.includes("LAN 주소 192.168.8.1") && e.summary.includes("듣는 서비스 없음"))).toBe(true);
    expect(tr2.some((e) => e.kind === "nat.miss")).toBe(false);
  });

  it("WAN 주소로 물은 DNS 의 답은 WAN 주소에서", () => {
    const L = loadTopology(exampleDropInTopology());
    const tr = L.act({ kind: "dns-lookup", nodeId: L.id("아이 PC"), name: "example.com", qtype: "A", server: "192.168.0.2" });
    expect(tr.find((e) => e.nodeId === L.id("아이 PC") && e.kind === "dns.response.received")!.summary).toContain("서버 192.168.0.2");
  });
});
