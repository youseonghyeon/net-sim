// 설정 반영 불변식 (LESSONS 4zl): 장치를 처음부터 그 설정으로 불러온 노드와, 기본 장치로 만든 뒤 설정을 바꿔 넣은 노드의
// 설정 상태가 같아야 한다. 새 설정 칸을 makeNode·applyConfig 에는 넣고 변경 감지 키(netSync)에서 빠뜨리면 여기서 걸린다.
import { describe, expect, it } from "vitest";
import { EXAMPLE_LIST } from "../src/model/examples";
import { NetworkSync } from "../src/model/netSync";
import { createDevice, type Device, type Topology } from "../src/model/topology";
import { separatedJumpTopology } from "./fixtures";

/** 노드에서 설정으로 보이는 것: 이름이 config·…Cfg·enabled·…On 등인 속성 (깊이 2). 꺼진 기능은 뺀다 (기본값과 같은지 볼 필요 없음) */
function settingsOf(o: unknown, depth = 0, seen = new Set<unknown>()): Record<string, unknown> | undefined {
  if (!o || typeof o !== "object" || seen.has(o) || depth > 2) return undefined;
  seen.add(o);
  const r: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
    if (/(^config$|Cfg$|^enabled$|On$|^hairpin$|^dropIn$|^routes$|^wifi$|^httpProxy$)/.test(k) && typeof v !== "function") {
      if (k === "config" && v && (v as { enabled?: unknown }).enabled !== true) continue;
      if (k === "routes" && v instanceof Map) continue;
      r[k] = JSON.parse(JSON.stringify(v instanceof Map ? [...v] : v) ?? "null");
    } else if (v && typeof v === "object" && !(v instanceof Map) && !(v instanceof Set) && !Array.isArray(v)) {
      // 꺼진 구성요소(config.enabled === false)는 설정이 아니다 — 끈 VPN 클라이언트는 늦게 온 패킷을 조용히 버리려고 객체를 남겨 둔다 (AGENTS 점검 ③)
      if ((v as { config?: { enabled?: unknown } }).config?.enabled === false) continue;
      const s = settingsOf(v, depth + 1, seen);
      if (s && Object.keys(s).length) r[k] = s;
    }
  }
  return r;
}

function load(t: Topology): NetworkSync {
  const s = new NetworkSync();
  s.sync(t);
  s.net.runToIdle(200_000);
  return s;
}

/** 설정 객체에서 불리언 칸의 경로 (배열은 첫 항목만) */
function boolPaths(o: unknown, base: string[] = []): string[][] {
  if (!o || typeof o !== "object") return [];
  if (Array.isArray(o)) return o.length ? boolPaths(o[0], [...base, "0"]) : [];
  return Object.entries(o as Record<string, unknown>).flatMap(([k, v]) => (typeof v === "boolean" ? [[...base, k]] : boolPaths(v, [...base, k])));
}

function flip(d: Device, path: string[]): Device {
  const copy = structuredClone(d) as unknown as Record<string, unknown>;
  let o = copy;
  for (const k of path.slice(0, -1)) o = o[k] as Record<string, unknown>;
  const last = path.at(-1)!;
  o[last] = !o[last];
  return copy as unknown as Device;
}

const SETTINGS = ["host", "router", "l3", "switch", "ap", "firewall", "wifi", "internet"] as const;

/**
 * 장치 종류·설정 칸마다 처음 나오는 장치에서 그 불리언 칸 하나만 뒤집어: 처음부터 그 값으로 불러온 노드와, 불러온 뒤 실행 중에 바꾼 노드의
 * 설정 상태가 같은가. 다른 것 목록 ("예제 장치 경로")
 */
function toggleMismatches(cases: { id: string; t: Topology }[]): string[] {
  const seen = new Set<string>();
  const bad: string[] = [];
  for (const { id, t } of cases) {
    for (const d of t.devices) {
      for (const key of SETTINGS) {
        for (const path of boolPaths(d[key], [key])) {
          const sig = `${d.kind}:${path.join(".").replace(/\.\d+\./g, ".N.")}`;
          if (seen.has(sig)) continue;
          seen.add(sig);
          const t2: Topology = { ...t, devices: t.devices.map((x) => (x.id === d.id ? flip(d, path) : x)) };
          const live = load(t);
          live.sync(t2);
          live.net.runToIdle(200_000);
          const fresh = load(t2);
          if (JSON.stringify(settingsOf(fresh.net.nodes.get(d.id))) !== JSON.stringify(settingsOf(live.net.nodes.get(d.id)))) bad.push(`${id} ${d.name} ${path.join(".")}`);
        }
      }
    }
  }
  return bad;
}

describe("설정 반영 불변식: 칸 하나를 실행 중에 바꿈 == 처음부터 그 값", () => {
  it("예제 전부 + tests/fixtures 의 망분리 + 점프 서버 (SSH 점프 허용 — 4zl 의 그 설정)", () => {
    const cases = [...EXAMPLE_LIST.map((ex) => ({ id: ex.id, t: ex.build() })), { id: "fixture:separatedJump", t: separatedJumpTopology() }];
    expect(toggleMismatches(cases)).toEqual([]);
  }, 300_000);
});
