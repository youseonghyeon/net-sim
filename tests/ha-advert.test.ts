// 이중화 주기 광고 (배경 타이머): master 는 1초마다 광고, backup 은 3초 + skew 동안 못 들으면 "말없이 죽은 master" 로 보고 이어받는다.
// 광고·감시는 시계를 스스로 움직이지 않는다 — 패킷이 오가거나 시간을 흘려보낼 때만 돈다
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import { exampleHaTopology } from "../src/model/examples";
import type { Device, Topology } from "../src/model/topology";
import { loadTopology } from "./helpers";

const edit = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });
const advert = (t: Topology, names = ["방화벽 A", "방화벽 B"]) => names.reduce((x, n) => edit(x, n, (d) => ({ ...d, l3: { ...d.l3!, ha: { ...d.l3!.ha!, advert: true } } })), t);
/**
 * 방화벽 A 의 케이블 두 개에 손실률 100%: 링크는 살아 있어 A 는 모르고(물러나지 않음), 광고도 닿지 않는다 — 말없이 죽은 master.
 * (케이블을 뽑으면 A 가 링크 다운을 알아채 물러남 광고를 남은 케이블로 보내므로 말없이 죽지 않는다)
 */
const silenceA = (l: ReturnType<typeof loadTopology>, loss = 1) => {
  const a = l.id("방화벽 A");
  for (const c of l.t.cables) if (c.a.device === a || c.b.device === a) l.s.net.setLinkLoss(c.id, loss);
};

describe("이중화 주기 광고 (Master_Down)", () => {
  it("광고는 시계를 움직이지 않는다: 조용하면 멈추고, 시간을 흘려보내면 1초마다 광고", () => {
    const t = advert(exampleHaTopology());
    expect(lintTopology(t)).toEqual([]);
    const { s, l3, id } = loadTopology(t);
    expect(l3("방화벽 A").ha.state).toBe("master");
    expect(s.net.runToIdle()).toBe(0);
    expect(s.net.peekNextTime()).toBeUndefined();
    expect(s.net.peekBackgroundTime()).toBeDefined();
    const from = s.net.trace.length;
    s.net.runUntil(s.net.now + 5000);
    const heard = s.net.trace.slice(from).filter((e) => e.kind === "ha.advert" && e.nodeId === id("방화벽 B"));
    // 1초마다, VIP 인터페이스 두 곳(outside·inside)에서 듣는다
    expect(heard.length).toBe(10);
    expect(heard[0]!.summary).toContain("Master_Down 감시 다시 시작");
    expect(l3("방화벽 B").ha.state).toBe("backup");
  });

  it("주기 광고가 꺼져 있으면: A 가 말없이 죽으면(케이블 손실 100%) B 는 영영 backup (지금까지의 한계)", () => {
    const l = loadTopology(exampleHaTopology());
    const { s, act, l3, host, id } = l;
    silenceA(l);
    s.net.runUntil(s.net.now + 30_000);
    expect(l3("방화벽 B").ha.state).toBe("backup");
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("failed");
  });

  it("주기 광고를 켜면: ping 이 몇 번 실패하며 시간이 흐르는 동안 B 가 알아채 이어받고, 그 뒤 ping 은 된다", () => {
    const l = loadTopology(advert(exampleHaTopology()));
    const { act, l3, host, id } = l;
    silenceA(l);
    let failed = 0;
    while (l3("방화벽 B").ha.state !== "master" && failed < 10) {
      act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
      expect(host("pc-1").pings.at(-1)!.status).toBe("failed");
      failed++;
    }
    expect(l3("방화벽 B").ha.state).toBe("master");
    expect(failed).toBeGreaterThanOrEqual(2);
    expect(failed).toBeLessThanOrEqual(4);
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("시간 흘려보내기(runUntil)로도 이어받고, A 를 다시 꽂으면 A 가 되찾는다 (preempt)", () => {
    const l = loadTopology(advert(exampleHaTopology()));
    const { s, act, l3, host, id } = l;
    const t0 = s.net.now;
    silenceA(l);
    const from = s.net.trace.length;
    s.net.runUntil(s.net.now + 10_000);
    const took = s.net.trace.slice(from).find((e) => e.kind === "ha.state" && e.nodeId === id("방화벽 B"))!;
    expect(took.summary).toContain("말없이 죽은 것으로 보고 이어받음");
    // Master_Down = 3초 + skew((256 − 100)/256 초 ≈ 609ms): 마지막으로 들은 광고(손실 전) 뒤 3.6초 안쪽
    expect(took.time - t0).toBeLessThanOrEqual(3610);
    expect(took.time - t0).toBeGreaterThan(2500);
    expect(l3("방화벽 B").ha.state).toBe("master");
    silenceA(l, 0);
    s.net.runUntil(s.net.now + 10_000);
    expect(l3("방화벽 A").ha.state).toBe("master");
    expect(l3("방화벽 B").ha.state).toBe("backup");
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("ok");
  });

  it("살아 있는 master 가 광고하는 동안은 아무리 시간이 흘러도 backup 이 가져가지 않는다 (둘 다 master 가 되지 않음)", () => {
    const { s, l3 } = loadTopology(advert(exampleHaTopology()));
    s.net.runUntil(s.net.now + 60_000);
    expect(l3("방화벽 A").ha.state).toBe("master");
    expect(l3("방화벽 B").ha.state).toBe("backup");
  });

  it("주기 광고를 켜고 끄는 것만으로는 넘어가지 않는다 (선출을 다시 하지 않음)", () => {
    const t = exampleHaTopology();
    const { apply, l3, id } = loadTopology(t);
    const on = apply(advert(t, ["방화벽 A"]));
    expect(on.some((e) => e.kind === "ha.master" || e.kind === "ha.backup")).toBe(false);
    expect(on.find((e) => e.kind === "ha.config" && e.nodeId === id("방화벽 A"))!.summary).toContain("주기 광고 켜짐");
    apply(advert(t));
    apply(t);
    expect(l3("방화벽 A").ha.state).toBe("master");
    expect(l3("방화벽 B").ha.state).toBe("backup");
  });

  it("구성 검사 ha.advert-mismatch: 한쪽만 켜면 두 장비 모두 경고", () => {
    const t = advert(exampleHaTopology(), ["방화벽 B"]);
    const issues = lintTopology(t).filter((i) => i.code === "ha.advert-mismatch");
    expect(issues.map((i) => t.devices.find((d) => d.id === i.deviceId)!.name).sort()).toEqual(["방화벽 A", "방화벽 B"]);
  });
});
