// 답을 받은 뒤에도 남은 재전송·대기 timer 가 할 일 없이 울리면, 조용해진 네트워크의 시계가 그 시각까지 간다
// (불러온 뒤 시계가 마지막 일보다 수 초 앞서 있었다 — IKE·HA·P2P·SIP·Tor·메시·DDNS·OpenVPN·L2TP·WireGuard).
// 예제마다 불러오기를 조용해질 때까지 돌리고, 마지막 기록 뒤에 아무 기록도 남기지 않은 일반 timer 가 없어야 한다
import { describe, expect, it } from "vitest";
import { EXAMPLE_LIST } from "../src/model/examples";
import { NetworkSync } from "../src/model/netSync";
import type { NodeContext } from "../src/core/nodes/node";

describe("불러온 뒤 할 일 없는 timer 가 시계를 밀지 않는다", () => {
  for (const ex of EXAMPLE_LIST) {
    it(ex.id, () => {
      const t = ex.build();
      const s = new NetworkSync();
      const name = new Map(t.devices.map((d) => [d.id, d.name]));
      const idle: { at: number; what: string }[] = [];
      s.sync(t);
      for (const [id, n] of s.net.nodes) {
        const orig = n.onTimer?.bind(n);
        if (!orig) continue;
        n.onTimer = (tag: string, data: unknown, ctx: NodeContext) => {
          const before = s.net.trace.length;
          orig(tag, data, ctx);
          if (s.net.trace.length === before) idle.push({ at: s.net.now, what: `${name.get(id)} ${tag} ${JSON.stringify(data)}` });
        };
      }
      s.net.runToIdle(200_000);
      const last = s.net.trace.at(-1)!.time;
      expect(idle.filter((x) => x.at > last).map((x) => x.what)).toEqual([]);
    });
  }
});
