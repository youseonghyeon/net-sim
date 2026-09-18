// 브라우저 스모크 테스트: 캔버스 에디터의 핵심 흐름을 실제 브라우저에서 확인하고 스크린샷을 남긴다.
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

await page.goto(URL);
await page.waitForLoadState("networkidle");
await page.evaluate(() => { localStorage.clear(); });
await page.reload();
await page.waitForLoadState("networkidle");
await page.evaluate(() => document.fonts.ready);
await page.screenshot({ path: `${OUT}/01-empty.png` });

// 1) 예제 불러오기
await page.click("text=예제 네트워크 불러오기");
await page.waitForTimeout(100);
const devices = await page.locator("[data-device]").count();
const cables = await page.locator("[data-cable]").count();
console.log("example: devices =", devices, "cables =", cables);
await page.screenshot({ path: `${OUT}/02-example-light.png` });

// 2) 장치 선택 → 인스펙터
async function clickDevice(name) {
  const box = await page.locator("[data-device]", { hasText: name }).locator(".tile").boundingBox();
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
}
await clickDevice("pc-1");
await page.waitForTimeout(100);
console.log("inspector title =", await page.locator(".inspector h2").innerText());
await page.screenshot({ path: `${OUT}/03-select-pc.png` });

// 3) 수동 IP 로 전환하고 입력
await page.click(".segmented button:has-text('수동')");
await page.fill(".inspector input[placeholder='192.168.0.10']", "192.168.0.10");
await page.fill(".inspector input[placeholder='192.168.0.1']", "192.168.0.1");
await page.waitForTimeout(100);
const addr = await page.locator("[data-device]", { hasText: "pc-1" }).locator(".addr").textContent();
console.log("pc-1 addr label =", addr);
await page.screenshot({ path: `${OUT}/04-static-ip.png` });

// 4) 라우터 선택 → DHCP 끄기
await clickDevice("rt-1");
await page.click(".toggle");
await page.waitForTimeout(100);
console.log("dhcp toggle text =", await page.locator(".toggle-row span").first().innerText());
await page.screenshot({ path: `${OUT}/05-router-dhcp-off.png` });

// 5) 팔레트에서 PC 추가(클릭) → 케이블 도구로 스위치와 연결
await page.click(".palette .tool.item:has-text('PC')");
await page.waitForTimeout(50);
await page.keyboard.press("c");
const sw = page.locator("[data-device]", { hasText: "sw-1" });
const pc2 = page.locator("[data-device]", { hasText: "pc-2" });
const a = await pc2.locator(".tile").boundingBox();
const b = await sw.locator(".tile").boundingBox();
await page.mouse.move(a.x + a.width / 2, a.y + a.height / 2);
await page.mouse.down();
await page.mouse.move(a.x + 40, a.y - 40, { steps: 5 });
await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 10 });
await page.screenshot({ path: `${OUT}/06-cable-drag.png` });
await page.mouse.up();
await page.waitForTimeout(100);
console.log("after cable: cables =", await page.locator("[data-cable]").count(), "| inspector =", await page.locator(".inspector h2").innerText());
await page.keyboard.press("v");

// 6) 다크 테마
await page.click(".icon-btn[title]");
await page.waitForTimeout(100);
await clickDevice("sw-1");
await page.waitForTimeout(100);
await page.screenshot({ path: `${OUT}/07-dark.png` });

// 7) 삭제 키
await page.keyboard.press("Delete");
await page.waitForTimeout(50);
console.log("after delete sw-1: devices =", await page.locator("[data-device]").count(), "cables =", await page.locator("[data-cable]").count());

// 8) 새로고침 후 유지되는지
await page.reload();
await page.waitForLoadState("networkidle");
console.log("after reload: devices =", await page.locator("[data-device]").count());

console.log("ERRORS:", errors.length ? errors : "none");
await browser.close();
await server.close();
process.exit(errors.length ? 1 : 0);
