// 골든 트레이스 (LESSONS 4j): 예제마다 불러오기 → 배경 타이머 30초 → 단말 몇 대의 ping 까지의 트레이스 전체(시각·장치·종류·문구)와
// 실무 출력 줄을 파일로 고정한다. 동작을 바꾸지 않는 리팩터링은 이 파일이 그대로여야 하고, 바뀌면 diff 를 건별로 보고 의도한 것만
// `npx vitest run tests/golden.test.ts -u` 로 갱신한다.
// 장치 id 는 Date.now 와 순번에서 나오고 키·포트·xid 가 그 해시에서 나오므로, 예제마다 시계를 0 에 고정하고 순번을 처음부터 센다.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { EXAMPLE_LIST } from "../src/model/examples";
import { NetworkSync } from "../src/model/netSync";
import { practitionerLines } from "../src/model/packetView";
import { resetIdSequence, type Topology } from "../src/model/topology";

/** 예제마다 ping 을 보낼 단말 수 (이름 순으로 앞에서부터) */
const PINGERS = 3;

beforeAll(() => {
  vi.spyOn(Date, "now").mockReturnValue(0);
});
afterAll(() => {
  vi.restoreAllMocks();
});

function build(make: () => Topology): Topology {
  resetIdSequence();
  return make();
}

function golden(t: Topology): string {
  const s = new NetworkSync();
  const name = new Map(t.devices.map((d) => [d.id, d.name]));
  const lines: string[] = [];
  let seen = 0;
  const flush = (label: string) => {
    lines.push(`## ${label}`);
    const tr = s.net.trace;
    for (; seen < tr.length; seen++) {
      const e = tr[seen]!;
      lines.push(`${e.time} ${name.get(e.nodeId) ?? e.nodeId} ${e.kind} | ${e.summary}`);
      const frames = e.packetId !== undefined ? s.net.framesAt(e.packetId, e.nodeId, e.time) : {};
      for (const p of practitionerLines(e, frames, (id) => name.get(id) ?? id)) lines.push(`    > ${p.tool}: ${p.line.replace(/\n/g, "\n      ")}`);
    }
  };
  s.sync(t);
  s.net.runToIdle(200_000);
  flush("불러오기");
  s.net.runUntil(s.net.now + 30_000, 200_000);
  flush("30초 뒤");
  const pingers = t.devices.filter((d) => d.host && ["pc", "laptop", "phone", "server"].includes(d.kind)).sort((a, b) => (a.name < b.name ? -1 : 1)).slice(0, PINGERS);
  for (const d of pingers) {
    s.net.scheduleAction(s.net.now, { kind: "ping", nodeId: d.id, dst: "8.8.8.8" });
    s.net.runToIdle(200_000);
    flush(`${d.name} → 8.8.8.8`);
  }
  return lines.join("\n") + "\n";
}

describe("골든 트레이스 (예제 전부)", () => {
  for (const ex of EXAMPLE_LIST) {
    it(ex.id, async () => {
      await expect(golden(build(ex.build))).toMatchFileSnapshot(`./__golden__/${ex.id}.txt`);
    });
  }

  it("같은 코드를 두 번 돌리면 같다 (결정론)", () => {
    const ex = EXAMPLE_LIST.find((e) => e.id === "company")!;
    expect(golden(build(ex.build))).toBe(golden(build(ex.build)));
  });
});
