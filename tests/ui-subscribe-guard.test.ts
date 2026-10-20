// 화면 컴포넌트가 시뮬레이션 상태(sim.node()·sim.net)를 그릴 때 읽으면 simVersion(또는 simTime)도 읽어야 바뀔 때 다시 그린다.
// 빠뜨리면 그 칸이 처음 값에 멈춘다 (LESSONS 4zi — 진단 탭 P2P 칸). 컴포넌트 함수마다 소스로 확인한다
import { describe, expect, it } from "vitest";

const files = import.meta.glob("../src/app/**/*.tsx", { query: "?raw", import: "default", eager: true }) as Record<string, string>;

/** 허용: 이미 지난 이벤트의 프레임 기록만 읽는 곳 (그 기록은 바뀌지 않는다) */
const ALLOWED = ["src/app/PacketDetail.tsx PacketDetail"];

/** 최상위 함수 단위로 나눈다 (컴포넌트는 최상위 function) */
function functions(src: string): { name: string; body: string }[] {
  return src
    .split(/\n(?=(?:export )?function \w+)/)
    .map((body) => ({ name: /^(?:export )?function (\w+)/.exec(body)?.[1] ?? "", body }))
    .filter((f) => f.name);
}

describe("시뮬레이션 상태를 읽는 컴포넌트는 simVersion 을 읽는다", () => {
  it("sim.node()·sim.net 을 읽는 함수에 simVersion.value·simTime.value 가 있다", () => {
    const missing: string[] = [];
    for (const [path, src] of Object.entries(files)) {
      for (const f of functions(src)) {
        // 시뮬레이션 상태를 읽는 함수: sim.node()·sim.net 을 부르거나, 코어 노드를 props 로 받는다
        const sig = f.body.slice(0, f.body.indexOf("{", f.body.indexOf(")")));
        const readsSim = /\bsim\.(node\(|net\.)/.test(f.body) || /\b\w+\??: (Host|Router|L3Node|SimNode|Switch|Internet|AccessPoint|FirewallBridge)\b/.test(sig);
        if (!readsSim) continue;
        // logTick = 로그 창이 simVersion 을 200ms 로 묶은 신호
        if (/(simVersion|simTime|logTick)\.value/.test(f.body)) continue;
        const where = `${path.replace("../", "")} ${f.name}`;
        if (!ALLOWED.includes(where)) missing.push(where);
      }
    }
    expect(missing).toEqual([]);
  });
});
