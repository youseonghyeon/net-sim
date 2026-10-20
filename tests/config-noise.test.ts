// 설정 칸 하나를 바꿨을 때 켠 적 없는 기능이 "꺼짐" 으로 기록되지 않는다 (게이트웨이 헤어핀만 켰는데 "이중화 꺼짐 · 원격 접속 VPN 서버 꺼짐" 이 찍히던 결함 —
// 처음 넣은 설정과 정리한 설정의 모양이 달라 꺼짐 → 꺼짐을 변경으로 봤다)
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { EXAMPLE_LIST } from "../src/model/examples";

describe("칸 하나를 바꿔도 꺼져 있던 기능은 조용하다", () => {
  for (const ex of EXAMPLE_LIST) {
    const t = ex.build();
    const gws = t.devices.filter((d) => d.l3);
    if (!gws.length) continue;
    it(ex.id, () => {
      const L = loadTopology(t);
      // 불러오기: 처음 설정이 들어갈 때도
      const ids = new Set(gws.map((g) => g.id));
      expect(L.s.net.trace.filter((e) => ids.has(e.nodeId) && /꺼짐$/.test(e.summary)).map((e) => e.summary)).toEqual([]);
      for (const gw of gws) {
        const next = { ...L.t, devices: L.t.devices.map((d) => (d.id === gw.id ? { ...d, l3: { ...d.l3!, hairpin: !d.l3!.hairpin } } : d)) };
        const noise = L.apply(next).filter((e) => e.nodeId === gw.id && /꺼짐/.test(e.summary) && !/헤어핀/.test(e.summary));
        expect(noise.map((e) => `${gw.name}: ${e.summary}`)).toEqual([]);
        L.apply(L.t);
      }
    });
  }
});
