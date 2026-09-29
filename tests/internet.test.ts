// 예제 "인터넷의 뼈대": 가장자리는 디폴트 라우트(트리), 중심은 RIP 그물. 공인 DNS 8.8.8.8, 백본 링크 절단 후 우회
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import type { ActionSpec } from "../src/core/network";
import { loadTopology } from "./helpers";
import { exampleInternetTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";

function setup(t: Topology = exampleInternetTopology()) {
  const x = loadTopology(t);
  return { ...x, run: (action: ActionSpec) => void x.act(action) };
}

describe("예제: 인터넷의 뼈대", () => {
  it("구성 검사 이슈가 없고, pc-1 은 공유기에서 주소를 받는다", () => {
    const { t, host } = setup();
    expect(lintTopology(t)).toEqual([]);
    expect(host("pc-1").ip).toMatch(/^192\.168\.0\./);
  });

  it("nexus.com: 8.8.8.8 로 이름을 풀고, KT → SK 백본을 지나 회사 웹 서버까지 TCP 가 성공한다", () => {
    const { run, id, host } = setup();
    run({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "nexus.com", port: 80 });
    expect([...host("pc-1").tcp.conns.values()].at(-1)).toMatchObject({ state: "CLOSED", remoteIp: "198.51.100.2", bytesReceived: 3000 });
    run({ kind: "traceroute", nodeId: id("pc-1"), dst: "198.51.100.2" });
    expect(host("pc-1").traceroutes.at(-1)!.hops.map((h) => h.ip)).toEqual(["192.168.0.1", "203.0.113.1", "198.18.1.1", "198.18.10.2", "198.18.2.2", "198.51.100.2"]);
  });

  it("KT 백본 ↔ SK 백본 케이블을 지우면 구글 망을 돌아가는 길로 다시 수렴한다", () => {
    const base = exampleInternetTopology();
    const kt = base.devices.find((d) => d.name === "KT 백본")!.id;
    const sk = base.devices.find((d) => d.name === "SK 백본")!.id;
    const { s, run, id, host } = setup(base);
    const cut: Topology = { ...base, cables: base.cables.filter((c) => !([c.a.device, c.b.device].includes(kt) && [c.a.device, c.b.device].includes(sk))) };
    s.sync(cut);
    s.net.runToIdle();
    run({ kind: "traceroute", nodeId: id("pc-1"), dst: "198.51.100.2" });
    expect(host("pc-1").traceroutes.at(-1)!.hops.map((h) => h.ip)).toEqual(["192.168.0.1", "203.0.113.1", "198.18.1.1", "198.18.11.1", "198.18.12.2", "198.18.2.2", "198.51.100.2"]);
  });
});
