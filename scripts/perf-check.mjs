// 성능 측정: 예제 전부 + 큰 스트레스 구성(공유기 아래 PC 52대가 한꺼번에 DHCP)을 실제 브라우저에서 돌리며
// 프레임 간격·긴 프레임·메인 스레드 점유율을 잰다. 부팅 직후 DHCP 브로드캐스트가 몰리는 6초가 가장 무거운 구간이다.
// 실행: npm run perf-check                 (헤드리스, CPU 4배 감속 — 느린 노트북 흉내)
//       npm run perf-check -- --headed      (실제 창·GPU 로 그리기)
//       npm run perf-check -- --throttle 1  (감속 없이)
import { chromium } from "playwright";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build, createServer, preview } from "vite";

const args = process.argv.slice(2);
const headed = args.includes("--headed");
const ti = args.indexOf("--throttle");
const throttle = ti >= 0 ? Number(args[ti + 1]) : 4;
const only = args.find((a) => a.startsWith("--only="))?.slice(7);
const WINDOW_MS = 6000;
/** 이 이상이면 실패로 본다 (감속 적용 기준). 60fps 한 프레임 16.7ms, 두 프레임 33ms */
const BUDGET = { p95: 34, longFrames: 3 };

// 토폴로지는 Node 에서 만든다 (vite 로 TS 모듈만 불러옴). 페이지는 배포본과 같은 프로덕션 빌드로 띄운다 —
// 개발 서버는 preact 디버그 훅이 붙어 렌더가 눈에 띄게 느려 사용자 체감과 다르다
const dev = await createServer({ server: { middlewareMode: true }, appType: "custom", logLevel: "silent" });
const topo = await dev.ssrLoadModule("/src/model/topology.ts");
await dev.close();

/** 인터넷 ─ 공유기 ─ LAN 포트 4개마다 스위치 ─ (자식 스위치 + PC 6대), 자식 스위치에 노트북 7대 → 단말 52대 */
function stressTopology() {
  const devices = [];
  const cables = [];
  const add = (kind, x, y) => {
    const d = topo.createDevice(kind, x, y, devices);
    devices.push(d);
    return d;
  };
  const link = (a, b) => {
    const plan = topo.planCable({ devices, cables }, a.id, b.id);
    if ("error" in plan) throw new Error(plan.error);
    cables.push({ id: topo.newId("cable"), a: plan.a, b: plan.b });
  };
  const inet = add("internet", 1560, -200);
  const rt = add("router", 1560, 0);
  link(inet, rt);
  for (let g = 0; g < 4; g++) {
    const gx = g * 820;
    const sw = add("switch", gx + 320, 200);
    link(rt, sw);
    for (let i = 0; i < 6; i++) link(sw, add("pc", gx + i * 96, 360));
    const child = add("switch", gx + 320, 520);
    link(sw, child);
    for (let i = 0; i < 7; i++) link(child, add("laptop", gx + i * 96, 680));
  }
  return { devices, cables };
}

const outDir = mkdtempSync(join(tmpdir(), "net-sim-perf-"));
await build({ logLevel: "silent", build: { outDir, emptyOutDir: true } });
const server = await preview({ logLevel: "silent", preview: { port: 5198 }, build: { outDir } });
const URL = server.resolvedUrls.local[0];
const browser = await chromium.launch({ headless: !headed });

async function measure(scenario) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(URL);
  const t = scenario === "stress" ? stressTopology() : topo.EXAMPLES[scenario].build();
  await page.evaluate((json) => {
    localStorage.clear();
    localStorage.setItem("net-sim.theme", JSON.stringify("dark"));
    localStorage.setItem("net-sim.topology.v1", json);
  }, JSON.stringify(t));
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Emulation.setCPUThrottlingRate", { rate: throttle });
  await page.reload();
  await page.waitForSelector("[data-device]");
  await page.keyboard.press("Shift+Digit1"); // 전체 보기 — 모든 장치가 화면 안에서 그려지게
  await cdp.send("Performance.enable");
  const metrics = async () => Object.fromEntries((await cdp.send("Performance.getMetrics")).metrics.map((x) => [x.name, x.value]));
  const m0 = await metrics();
  const r = await page.evaluate(
    (windowMs) =>
      new Promise((res) => {
        const gaps = [];
        let maxPackets = 0;
        let labelFlips = 0;
        const shown = new WeakMap();
        let last = performance.now();
        const t0 = last;
        const f = (t) => {
          gaps.push(t - last);
          last = t;
          const packets = document.querySelectorAll(".packet");
          maxPackets = Math.max(maxPackets, packets.length);
          for (const p of packets) {
            const lab = p.querySelector(".packet-label");
            const v = lab ? `${lab.getAttribute("class")}|${lab.getAttribute("transform")}` : "";
            const was = shown.get(p);
            // 보이던 라벨이 숨거나 자리를 옮기면 깜빡임/튐으로 센다 (처음 숨어 있다가 나타나는 것은 세지 않음)
            if (was !== undefined && was !== v && !was.includes("hidden") && was !== "") labelFlips++;
            shown.set(p, v);
          }
          if (t - t0 < windowMs) requestAnimationFrame(f);
          else res({ gaps, maxPackets, labelFlips, wall: t - t0 });
        };
        requestAnimationFrame(f);
      }),
    WINDOW_MS,
  );
  const m1 = await metrics();
  const devices = await page.locator("[data-device]").count();
  await page.close();
  const s = [...r.gaps].sort((a, b) => a - b);
  const q = (p) => s[Math.min(s.length - 1, Math.floor(s.length * p))];
  return {
    scenario,
    devices,
    fps: (r.gaps.length / (r.wall / 1000)).toFixed(0),
    p50: q(0.5).toFixed(1),
    p95: q(0.95).toFixed(1),
    max: s.at(-1).toFixed(0),
    longFrames: r.gaps.filter((g) => g > 50).length,
    busy: `${Math.round(((m1.TaskDuration - m0.TaskDuration) * 1000 * 100) / r.wall)}%`,
    script: `${Math.round((m1.ScriptDuration - m0.ScriptDuration) * 1000)}ms`,
    layout: `${Math.round((m1.LayoutDuration - m0.LayoutDuration) * 1000)}ms`,
    maxPackets: r.maxPackets,
    labelFlips: r.labelFlips,
    errors: errors.length,
  };
}

const ids = [...Object.keys(topo.EXAMPLES), "stress"].filter((id) => !only || only.split(",").includes(id));

console.log(`perf-check: ${headed ? "headed" : "headless"}, CPU ${throttle}x 감속, 구간 ${WINDOW_MS / 1000}s`);
const rows = [];
for (const id of ids) rows.push(await measure(id));
console.table(rows);
await browser.close();
await new Promise((r) => server.httpServer.close(r));
rmSync(outDir, { recursive: true, force: true });

const bad = rows.filter((r) => r.errors > 0 || (throttle >= 4 && (Number(r.p95) > BUDGET.p95 || r.longFrames > BUDGET.longFrames)));
if (bad.length) {
  console.log(`문제: 예산 초과 — ${bad.map((r) => `${r.scenario}(p95 ${r.p95}ms, 긴 프레임 ${r.longFrames}, 오류 ${r.errors})`).join(", ")}`);
  console.log(`해결: 해당 시나리오를 --only=<id> --headed 로 다시 돌려 보고, 매 프레임 도는 코드(Canvas PacketLayer/ActiveCables, sim.ts tick)부터 확인하세요`);
  console.log(`참조: scripts/perf-check.mjs 의 BUDGET, docs/LESSONS.md`);
  process.exit(1);
}
console.log("OK: 모든 시나리오가 예산 안 (p95 ≤ 34ms, 50ms 넘는 프레임 ≤ 3)");
