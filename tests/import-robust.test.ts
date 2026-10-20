// 불러오기 견고성: 저장본의 설정 칸 하나가 빠져도(손으로 고친 JSON·예전 저장본) parse → 동기화 → 구성 검사가 예외 없이 돈다.
// 예제의 장치 설정에서 칸을 하나씩 지운 JSON 으로 확인한다 (칸 하나 = 경로 하나, 배열은 첫 항목만)
import { describe, expect, it } from "vitest";
import { EXAMPLE_LIST } from "../src/model/examples";
import { NetworkSync } from "../src/model/netSync";
import { lintTopology } from "../src/model/lint";
import { parseTopology, serializeTopology } from "../src/model/topology";

const SETTINGS = ["host", "router", "l3", "switch", "ap", "firewall", "wifi", "internet"] as const;

/** 설정 객체의 모든 칸 경로 (배열은 첫 항목만) */
function paths(o: unknown, base: (string | number)[]): (string | number)[][] {
  if (!o || typeof o !== "object") return [];
  if (Array.isArray(o)) return o.length ? [[...base, 0], ...paths(o[0], [...base, 0])] : [];
  return Object.entries(o as Record<string, unknown>).flatMap(([k, v]) => [[...base, k], ...paths(v, [...base, k])]);
}

describe("불러오기 견고성 (칸 하나 빠진 저장본)", () => {
  it("예제의 설정 칸을 하나씩 지워도 parse → 동기화 → 구성 검사가 예외 없이 돈다", () => {
    const failures: string[] = [];
    const seen = new Set<string>();
    for (const ex of EXAMPLE_LIST) {
      const json = JSON.parse(serializeTopology(ex.build()));
      json.devices.forEach((d: Record<string, unknown>, di: number) => {
        for (const key of SETTINGS) {
          for (const path of paths(d[key], [key])) {
            const sig = `${d.kind}:${path.map((x) => (typeof x === "number" ? "N" : x)).join(".")}`;
            if (seen.has(sig)) continue;
            seen.add(sig);
            const copy = structuredClone(json);
            let o = copy.devices[di];
            for (const k of path.slice(0, -1)) o = o[k];
            const last = path.at(-1)!;
            if (Array.isArray(o)) o.splice(last as number, 1);
            else delete o[last];
            try {
              const r = parseTopology(JSON.stringify(copy));
              if (!r.topology) continue; // 읽을 수 없다고 알린 것은 괜찮다
              const s = new NetworkSync();
              s.sync(r.topology);
              s.net.runToIdle(50_000);
              lintTopology(r.topology);
            } catch (e) {
              failures.push(`${ex.id} ${sig}: ${(e as Error).message.split("\n")[0]}`);
            }
          }
        }
      });
    }
    expect(failures).toEqual([]);
  }, 120_000);
});
