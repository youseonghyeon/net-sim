// 브라우저 스모크 테스트: 편집 → DHCP 자동 할당 → DHCP 끄고 실패 → 수동 설정 → ping 성공 흐름을 실제 브라우저에서 확인한다.
// 실행: npm run ui-check   (스크린샷은 .shots/ 에 저장)
import { mkdirSync } from "node:fs";
import { chromium } from "playwright";
import { createServer } from "vite";

const OUT = ".shots";
mkdirSync(OUT, { recursive: true });
const server = await createServer({ server: { port: 5199 }, logLevel: "silent" });
await server.listen();
const URL = server.resolvedUrls.local[0];

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
const errors = [];
page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
page.on("console", (m) => { if (m.type() === "error") errors.push("console: " + m.text()); });

const device = (name) => page.locator("[data-device]", { hasText: name });
async function clickDevice(name) {
  const box = await device(name).locator(".tile").boundingBox();
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
}
async function addrOf(name) {
  const el = device(name).locator(".addr, .status");
  return (await el.count()) ? (await el.first().textContent()) : "";
}
async function waitAddr(name, pattern, timeout = 30000) {
  const start = Date.now();
  for (;;) {
    const a = await addrOf(name);
    if (pattern.test(a)) return a;
    if (Date.now() - start > timeout) throw new Error(`waitAddr(${name}, ${pattern}) timed out; last = "${a}"`);
    await page.waitForTimeout(100);
  }
}

await page.goto(URL);
await page.waitForLoadState("networkidle");
await page.evaluate(() => localStorage.clear());
await page.reload();
await page.waitForLoadState("networkidle");
await page.evaluate(() => document.fonts.ready);

// 1) 예제 로드 → DHCP 로 주소를 받는 과정 (4배속)
await page.selectOption(".transport .speed", "4");
await page.click("text=예제 네트워크 불러오기");
await page.waitForTimeout(500);
await page.screenshot({ path: `${OUT}/10-dhcp-in-progress.png` });
console.log("packets visible during DHCP:", await page.locator(".packet").count());
for (const n of ["pc-1", "laptop-1", "srv-1"]) console.log(n, "→", await waitAddr(n, /^192\.168\.0\.\d+\/24$/));
async function wanOf() {
  return (await device("rt-1").locator("text").nth(2).textContent()) ?? "";
}
for (let i = 0; i < 100 && !/WAN 203\.0\.113\./.test(await wanOf()); i++) await page.waitForTimeout(100);
console.log("rt-1 wan →", await wanOf());
await page.screenshot({ path: `${OUT}/11-dhcp-done.png` });

// 1b) 외부 ping (NAT)
await clickDevice("pc-1");
await page.fill(".ping-row .input", "8.8.8.8");
await page.click(".ping-row .btn");
await page.waitForFunction(() => /응답 \d+ms|실패/.test(document.querySelector(".ping-log li")?.textContent ?? ""), null, { timeout: 30000 });
console.log("ping 8.8.8.8 from pc-1:", (await page.locator(".ping-log li").first().innerText()).replace("\n", " "));
const natRows = await page.locator(".inspector").locator("text=NAT 테이블").count();
await clickDevice("rt-1");
await page.waitForTimeout(100);
await page.screenshot({ path: `${OUT}/11b-router-nat.png` });

// 2) 라우터 DHCP 끄기 → 새 PC 연결 → 실패
await clickDevice("rt-1");
await page.click(".toggle");
await page.click(".palette .tool.item:has-text('PC')");
await page.keyboard.press("c");
const a = await device("pc-2").locator(".tile").boundingBox();
const b = await device("sw-1").locator(".tile").boundingBox();
await page.mouse.move(a.x + a.width / 2, a.y + a.height / 2);
await page.mouse.down();
await page.mouse.move(a.x + 40, a.y - 40, { steps: 5 });
await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 10 });
await page.mouse.up();
await page.keyboard.press("v");
console.log("pc-2 →", await waitAddr("pc-2", /DHCP 실패/));
await page.screenshot({ path: `${OUT}/12-dhcp-failed.png` });

// 3) IP 없이 ping → 실패, 수동 설정 → ping 성공
await clickDevice("pc-2");
await page.fill(".ping-row .input", "192.168.0.1");
await page.click(".ping-row .btn");
await page.waitForTimeout(200);
console.log("ping without ip:", await page.locator(".ping-log li").first().innerText());
await page.click(".segmented button:has-text('수동')");
await page.fill(".inspector input[placeholder='192.168.0.10']", "192.168.0.50");
await page.fill(".inspector input[placeholder='192.168.0.1']", "192.168.0.1");
console.log("pc-2 →", await waitAddr("pc-2", /^192\.168\.0\.50\/24$/));
await page.click(".ping-row .btn");
await page.waitForFunction(() => /응답 \d+ms/.test(document.querySelector(".ping-log li")?.textContent ?? ""), null, { timeout: 20000 });
console.log("ping after static:", await page.locator(".ping-log li").first().innerText());

// 4) 로그 열고 스크린샷
await page.click(".log-toggle");
await page.waitForTimeout(200);
console.log("log rows:", await page.locator(".log-list .row").count());
await page.screenshot({ path: `${OUT}/13-static-ping-log.png` });

// 5) 다크
await page.click(".topbar-right .icon-btn[title]");
await page.waitForTimeout(100);
await page.screenshot({ path: `${OUT}/14-dark.png` });

// 6) 케이블 제거 → 주소 해제 (DHCP 호스트)
await clickDevice("pc-1");
await page.waitForTimeout(100);
const cable = page.locator("[data-cable]").first();
await cable.locator(".hit").click({ force: true });
await page.keyboard.press("Delete");
await page.waitForTimeout(200);
console.log("cables after delete:", await page.locator("[data-cable]").count());

console.log("ERRORS:", errors.length ? errors : "none");
await browser.close();
await server.close();
process.exit(errors.length ? 1 : 0);
