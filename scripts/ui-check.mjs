// 브라우저 스모크 테스트: 개발 서버를 직접 띄우고 UI 흐름(동작 → 다음 → 재생 → 이전 → 타임아웃)을 확인한다.
// 실행: npm run ui-check   (스크린샷은 .shots/ 에 저장)
import { mkdirSync } from "node:fs";
import { chromium } from "playwright";
import { createServer } from "vite";

const OUT = ".shots";
mkdirSync(OUT, { recursive: true });
const server = await createServer({ server: { port: 5173, strictPort: true }, logLevel: "silent" });
await server.listen();

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });
const errors = [];
page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
page.on("console", (m) => { if (m.type() === "error") errors.push("console: " + m.text()); });

await page.goto("http://localhost:5173");
await page.waitForLoadState("networkidle");
await page.screenshot({ path: `${OUT}/01-initial.png` });

// 1) h1 → ping h2 클릭: 즉시 action 로그와 ARP 요청이 링크에 올라가야 함
await page.click("text=h1 → ping h2");
await page.waitForTimeout(100);
const logAfterAction = await page.locator("#log li .summary").allInnerTexts();
const packets = await page.locator("#packets .packet").count();
console.log("after action: log rows =", logAfterAction.length, "packets in flight =", packets);
console.log(logAfterAction.slice(0, 5).map((s) => "  " + s).join("\n"));
await page.screenshot({ path: `${OUT}/02-after-action.png` });

// 2) 다음 ▶ 를 한 번 눌러 스위치 플러딩 확인
await page.click("#btn-next");
await page.waitForTimeout(100);
console.log("after next: clock =", await page.locator("#clock").innerText());
console.log("  packets =", await page.locator("#packets .packet").count());
console.log("  active node =", await page.locator("#nodes .node.active").getAttribute("data-id"));
await page.screenshot({ path: `${OUT}/03-after-next.png` });

// 3) 재생 눌러 끝까지
await page.click("#btn-play");
await page.waitForTimeout(400);
await page.screenshot({ path: `${OUT}/04-playing.png` });
await page.waitForFunction(() => document.querySelector("#btn-play").textContent.includes("재생"), null, { timeout: 15000 });
const clock = await page.locator("#clock").innerText();
const last = (await page.locator("#log li .summary").allInnerTexts()).at(-1);
console.log("after play: clock =", clock, "| last log =", last);
const arpRows = await page.locator("#inspector .card").filter({ hasText: "h1" }).locator("table").first().locator("tbody tr").allInnerTexts();
console.log("h1 ARP cache rows:", arpRows);
const macRows = await page.locator("#inspector .card").filter({ hasText: "sw1" }).locator("tbody tr").allInnerTexts();
console.log("sw1 MAC table rows:", macRows);
await page.screenshot({ path: `${OUT}/05-done.png` });

// 4) 이전 ◀ 두 번 → 이벤트 수 감소, 로그 줄어듦
const before = await page.locator("#clock").innerText();
await page.click("#btn-prev"); await page.click("#btn-prev");
await page.waitForTimeout(100);
console.log("prev x2:", before, "→", await page.locator("#clock").innerText(), "| log rows =", await page.locator("#log li").count());
await page.screenshot({ path: `${OUT}/06-prev.png` });

// 5) 없는 호스트 ping → 타임아웃까지 재생
await page.click("#btn-reset");
await page.click("text=없는 호스트");
await page.click("#btn-play");
await page.waitForFunction(() => document.querySelector("#btn-play").textContent.includes("재생"), null, { timeout: 15000 });
console.log("timeout scenario: clock =", await page.locator("#clock").innerText());
console.log("  last =", (await page.locator("#log li .summary").allInnerTexts()).at(-1));
await page.screenshot({ path: `${OUT}/07-timeout.png` });

// 6) 로그 행 클릭 → details 펼침
await page.locator("#log li").nth(1).click();
await page.waitForTimeout(50);
console.log("details pre count:", await page.locator("#log li pre").count());

console.log("ERRORS:", errors.length ? errors : "none");
await browser.close();
await server.close();
process.exit(errors.length ? 1 : 0);
