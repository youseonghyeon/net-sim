// 예제 하나를 불러와 캔버스 스크린샷을 찍는다 (배치 확인용): node scripts/shot-example.mjs <예제 id> [출력 경로]
import { chromium } from "playwright";
import { createServer } from "vite";

const id = process.argv[2];
const out = process.argv[3] ?? `.shots/example-${id}.png`;
const server = await createServer({ server: { port: 5198 }, logLevel: "silent" });
await server.listen();
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
await page.goto(server.resolvedUrls.local[0]);
await page.click(".menu-btn");
await page.click(`.menu-item[data-example="${id}"]`);
await page.waitForTimeout(2500);
// 로그를 접어 캔버스를 넓게
if (await page.locator(".log.open").count()) await page.click(".log-toggle");
await page.waitForTimeout(300);
await page.screenshot({ path: out });
await browser.close();
await server.close();
