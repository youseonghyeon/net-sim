// Tor: 회로(가드·중간·출구), 목적지는 출구 주소를 본다, TCP·DNS 만
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleTorTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import type { Topology } from "../src/model/topology";

describe("Tor", () => {
  it("회로가 서고, 친구 웹 서버는 출구 주소에서 온 연결로 본다", () => {
    const L = loadTopology(exampleTorTopology());
    expect(lintTopology(L.t)).toEqual([]);
    expect(L.node<Router>("Brume 3 (Tor)").tor.up).toBe(true);
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("노트북"), dst: "203.0.113.50", port: 80 });
    expect(L.lastConn("노트북").state).toBe("CLOSED");
    expect(L.serverConns("친구 웹 서버").at(-1)!.remoteIp).toBe("198.51.100.133");
    expect(tr.some((e) => e.kind === "tor.relay" && e.summary.includes("세 겹"))).toBe(true);
  });

  it("이름(DNS)도 Tor 로, 인터넷이 흉내 내는 서버(example.com)에도 닿는다", () => {
    const L = loadTopology(exampleTorTopology());
    const tr = L.act({ kind: "tcp-connect", nodeId: L.id("노트북"), dst: "example.com", port: 80 });
    expect(L.lastConn("노트북").state).toBe("CLOSED");
    expect(tr.some((e) => e.summary.includes("업스트림") && e.summary.includes("Tor"))).toBe(true);
  });

  it("ping 은 Tor 가 나르지 못해 버려진다, Tor 를 끄면 된다", () => {
    const L = loadTopology(exampleTorTopology());
    const tr = L.act({ kind: "ping", nodeId: L.id("노트북"), dst: "8.8.8.8" });
    expect(L.host("노트북").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.kind === "tor.drop" && e.summary.includes("ICMP"))).toBe(true);
    const off: Topology = { ...L.t, devices: L.t.devices.map((d) => (d.router?.tor ? { ...d, router: { ...d.router, tor: false } } : d)) };
    L.apply(off);
    L.act({ kind: "ping", nodeId: L.id("노트북"), dst: "8.8.8.8" });
    expect(L.host("노트북").pings.at(-1)!.status).toBe("ok");
    L.act({ kind: "tcp-connect", nodeId: L.id("노트북"), dst: "203.0.113.50", port: 80 });
    expect(L.serverConns("친구 웹 서버").at(-1)!.remoteIp).not.toBe("198.51.100.133");
  });
});
