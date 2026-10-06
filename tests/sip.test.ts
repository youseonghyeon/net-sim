// 인터넷 전화(SIP·RTP)와 SIP ALG
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleSipTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Topology } from "../src/model/topology";
import type { Internet } from "../src/core/nodes/internet";

const alg = (t: Topology, names: string[]): Topology => ({ ...t, devices: t.devices.map((d) => (names.includes(d.name) ? { ...d, router: { ...d.router!, sipAlg: true } } : d)) });
const call = (L: ReturnType<typeof loadTopology>) => L.act({ kind: "sip-call", nodeId: L.id("민지 전화기"), to: "junho" });

describe("인터넷 전화와 SIP ALG", () => {
  it("둘 다 등록되고, 서버는 Contact 의 사설 주소 대신 실제로 온 곳을 기억한다", () => {
    const L = loadTopology(exampleSipTopology());
    expect(lintTopology(L.t)).toEqual([]);
    expect(L.host("민지 전화기").sip.registered).toBe(true);
    const rows = L.node<Internet>("internet-1").sip.rows();
    expect(rows.find((r) => r[0] === "minji")![1]).toMatch(/^192\.168\.0\./);
    expect(rows.find((r) => r[0] === "minji")![2]).toMatch(/^203\.0\.113\./);
  });

  it("ALG 가 없으면 통화는 연결되지만 양쪽 다 소리가 안 들린다 (SDP 가 사설 주소)", () => {
    const L = loadTopology(exampleSipTopology());
    call(L);
    const a = L.host("민지 전화기").sip.calls.at(-1)!;
    const b = L.host("준호 전화기").sip.calls.at(-1)!;
    expect(a.state).toBe("ended");
    expect(a.sent).toBe(5);
    expect(a.received).toBe(0);
    expect(b.received).toBe(0);
    expect(a.reason).toContain("사설 주소");
  });

  it("한쪽만 ALG 면 한쪽 통화, 둘 다 켜면 양쪽 다 들린다", () => {
    const L1 = loadTopology(alg(exampleSipTopology(), ["준호네 공유기"]));
    const tr = call(L1);
    expect(tr.some((e) => e.kind === "sip.alg")).toBe(true);
    // 준호의 SDP 만 공인 주소로 고쳐짐 → 민지의 음성은 준호에게 가고, 준호의 음성은 민지의 사설 주소로 가서 사라진다 (한쪽 통화)
    expect(L1.host("준호 전화기").sip.calls.at(-1)!.received).toBe(5);
    expect(L1.host("민지 전화기").sip.calls.at(-1)!.received).toBe(0);
    const both = loadTopology(alg(exampleSipTopology(), ["민지네 공유기", "준호네 공유기"]));
    call(both);
    expect(both.host("민지 전화기").sip.calls.at(-1)!.received).toBe(5);
    expect(both.host("준호 전화기").sip.calls.at(-1)!.received).toBe(5);
  });

  it("등록되지 않은 사람에게 걸면 404", () => {
    const L = loadTopology(exampleSipTopology());
    L.act({ kind: "sip-call", nodeId: L.id("민지 전화기"), to: "nobody" });
    expect(L.host("민지 전화기").sip.calls.at(-1)!.reason).toContain("404");
  });
});
