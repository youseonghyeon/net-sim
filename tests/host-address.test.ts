// 호스트 주소 수명주기: 주소를 잃거나 얻으면 주소에 묶인 앱(원격 접속 VPN·P2P·메시·SIP) 전부에 한 곳에서 알린다.
// 경로(고정 주소 변경·고정 → DHCP·링크 다운·DHCP 임대·ARP Probe 끝)마다 목록이 달라 SIP 가 빠졌던 결함의 회귀
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleSipTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";

const MINJI = "민지 전화기";
const withHost = (t: Topology, name: string, patch: Record<string, unknown>): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? { ...d, host: { ...d.host!, ...patch } } : d)) });

describe("호스트 주소 수명주기", () => {
  it("고정 주소를 바꾸면 SIP 전화기가 새 주소로 다시 등록해 걸려 오는 전화를 받는다", () => {
    const L = loadTopology(exampleSipTopology());
    const tr = L.apply(withHost(L.t, MINJI, { ipMode: "static", ip: "192.168.0.77", prefix: 24, gateway: "192.168.0.1", dns: "192.168.0.1" }));
    expect(tr.some((e) => e.nodeId === L.id(MINJI) && e.kind.startsWith("sip"))).toBe(true);
    L.act({ kind: "sip-call", nodeId: L.id("준호 전화기"), to: "minji" });
    expect(L.host("준호 전화기").sip.calls.at(-1)!.state).not.toBe("failed");
    expect(L.host(MINJI).sip.calls.length).toBeGreaterThan(0);
  });

  it("고정 → 자동(DHCP) 으로 바꿔도 새 주소를 받은 뒤 다시 등록한다", () => {
    const base = withHost(exampleSipTopology(), MINJI, { ipMode: "static", ip: "192.168.0.77", prefix: 24, gateway: "192.168.0.1", dns: "192.168.0.1" });
    const L = loadTopology(base);
    L.apply(withHost(L.t, MINJI, { ipMode: "dhcp", ip: "" }));
    expect(L.host(MINJI).ip).not.toBe("192.168.0.77");
    L.act({ kind: "sip-call", nodeId: L.id("준호 전화기"), to: "minji" });
    expect(L.host("준호 전화기").sip.calls.at(-1)!.state).not.toBe("failed");
    expect(L.host(MINJI).sip.calls.length).toBeGreaterThan(0);
  });
});
