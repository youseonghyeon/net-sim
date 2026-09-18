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
process.on("unhandledRejection", async (e) => {
  console.log("CRASH:", e?.message?.split("\n")[0]);
  console.log("toast:", await page.locator(".toast").allInnerTexts().catch(() => []));
  console.log("ERRORS:", errors.length ? errors : "none");
  await page.screenshot({ path: `${OUT}/crash.png` }).catch(() => {});
  process.exit(1);
});

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
// 1a) 이름으로 ping: pc-1 → google.com (라우터 DNS 포워더 → 8.8.8.8)
await clickDevice("pc-1");
await page.fill(".ping-row .input", "google.com");
await page.click(".ping-row .btn");
await page.waitForFunction(() => /응답 \d+ms|실패/.test(document.querySelector(".ping-log li")?.textContent ?? ""), null, { timeout: 40000 });
console.log("ping google.com:", (await page.locator(".ping-log li").first().innerText()).replace("\n", " "));
// 1a2) 바깥에서 공인 :80 접속 → 포트 포워딩으로 srv-1 에 닿는다
await clickDevice("internet-1");
await page.click("button:has-text('접속')");
await page.waitForFunction(() => { const sec = [...document.querySelectorAll(".inspector .section")].find((s) => s.textContent.includes("웹 서버 연결")); return /종료됨|실패/.test(sec?.querySelector("tbody tr")?.textContent ?? ""); }, null, { timeout: 40000 });
console.log("inbound via port forward:", await page.locator(".inspector .section", { hasText: "웹 서버 연결" }).locator("tbody tr").first().innerText());
async function wanOf() {
  return (await device("rt-1").locator("text.addr, text.status").nth(1).textContent()) ?? "";
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

// 1c) 장치 삭제 → DHCP Release 로 라우터 임대가 줄어든다
await clickDevice("laptop-1");
await page.click("button:has-text('장치 삭제')");
await page.waitForTimeout(600);
await clickDevice("rt-1");
await page.waitForTimeout(100);
const leaseRows = await page.locator(".inspector .section", { hasText: "DHCP 임대" }).locator("tbody tr").allInnerTexts();
console.log("router leases after deleting laptop-1:", leaseRows.length, leaseRows.some((r) => /비어/.test(r)) ? "(empty)" : "");

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

// 3b) TCP: pc-1 → srv-1 (웹 서버) 연결, 완료까지 대기
await clickDevice("pc-1");
const srvIp = await addrOf("srv-1");
await page.fill(".tcp-row .input:not(.port)", srvIp.split("/")[0]);
await page.click(".tcp-row .btn");
await page.waitForTimeout(600);
await page.screenshot({ path: `${OUT}/12b-tcp-in-flight.png` });
const tcpRows = () => page.locator(".inspector .section", { has: page.locator("h3", { hasText: /^TCP 연결$/ }) }).locator("tbody tr");
await page.waitForFunction(() => { const sec = [...document.querySelectorAll(".inspector .section")].find((s) => s.querySelector("h3")?.textContent === "TCP 연결"); return /종료됨/.test(sec?.querySelector("tbody tr")?.textContent ?? ""); }, null, { timeout: 40000 });
console.log("tcp to srv-1:", await tcpRows().first().innerText());

// 3c) 케이블 손실 실험: srv-1 케이블 다음 패킷 유실 → 재전송으로 복구
const srvCable = page.locator("[data-cable]").nth(4);
await srvCable.locator(".hit").click({ force: true });
await page.waitForTimeout(100);
await page.click("text=다음 패킷 1개 유실시키기");
await clickDevice("pc-1");
await page.click(".tcp-row .btn");
await page.waitForFunction(() => { const sec = [...document.querySelectorAll(".inspector .section")].find((s) => s.querySelector("h3")?.textContent === "TCP 연결"); const rows = sec?.querySelectorAll("tbody tr") ?? []; return rows.length >= 2 && /종료됨/.test(rows[0]?.textContent ?? ""); }, null, { timeout: 60000 });
console.log("tcp after loss:", await tcpRows().first().innerText());
console.log("retransmit logged:", await page.evaluate(() => document.body.textContent.includes("재전송")));

// 3d) NAT 를 거쳐 example.com:80
await page.fill(".tcp-row .input:not(.port)", "93.184.216.34");
await page.click(".tcp-row .btn");
await page.waitForFunction(() => { const sec = [...document.querySelectorAll(".inspector .section")].find((s) => s.querySelector("h3")?.textContent === "TCP 연결"); const t = sec?.querySelector("tbody tr")?.textContent ?? ""; return /93\.184\.216\.34/.test(t) && /종료됨/.test(t); }, null, { timeout: 60000 });
console.log("tcp to example.com:", await tcpRows().first().innerText());

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

// 7) 라우터 LAN 서브넷 변경 → DHCP 범위가 따라가고, 다시 요청하면 새 서브넷 주소를 받는다
{
  // 레이아웃 회귀 확인: 로그가 열려 있어도 캔버스가 푸터를 덮지 않아야 한다
  const body = await page.locator(".body").boundingBox();
  const canvas = await page.locator("#canvas-svg").boundingBox();
  console.log("layout ok:", Math.abs(body.height - canvas.height) < 1 ? "yes" : `NO (body ${Math.round(body.height)} vs canvas ${Math.round(canvas.height)})`);
}
await page.click(".log-toggle"); // 로그를 닫아 캔버스 아래쪽 장치가 보이게
await page.waitForTimeout(100);
await clickDevice("rt-1");
await page.click(".toggle"); // DHCP 다시 켜기
const lanInput = page.locator(".inspector input.mono").first();
await lanInput.fill("192.168.127.1");
await page.waitForTimeout(100);
console.log("dhcp range after LAN change:", await page.locator(".inspector input.mono").evaluateAll((els) => els.map((e) => e.value).slice(2, 4)));
await clickDevice("pc-1");
await page.click("button:has-text('DHCP 다시 요청')");
console.log("pc-1 after subnet change →", await waitAddr("pc-1", /^192\.168\.127\.\d+\/24$/));

// 8) 기능 단위 예제: NAT 박스 + 게이트웨이 + DHCP 서버 호스트
await page.selectOption("select.example", "parts");
await page.waitForTimeout(300);
console.log("parts example devices:", await page.locator("[data-device]").count());
console.log("pc-1 (DHCP from dhcp-srv) →", await waitAddr("pc-1", /^192\.168\.1\.\d+\/24$/));
console.log("laptop-1 (DHCP via gateway relay) →", await waitAddr("laptop-1", /^192\.168\.2\.\d+\/24$/));
console.log("badges:", await page.locator(".badge text").allTextContents());
const natLine = () => device("nat-1").locator("text.addr, text.status").nth(1).textContent();
for (let i = 0; i < 100 && !/outside 203\.0\.113\./.test((await natLine()) ?? ""); i++) await page.waitForTimeout(100);
console.log("nat-1 outside →", await natLine());
await clickDevice("pc-1");
await page.fill(".ping-row .input", "192.168.2.100");
await page.click(".ping-row .btn");
await page.waitForFunction(() => /응답 \d+ms|실패/.test(document.querySelector(".ping-log li")?.textContent ?? ""), null, { timeout: 30000 });
console.log("ping across gateway:", (await page.locator(".ping-log li").first().innerText()).replace("\n", " "));
await page.fill(".ping-row .input", "8.8.8.8");
await page.click(".ping-row .btn");
await page.waitForFunction(() => /8\.8\.8\.8/.test(document.querySelector(".ping-log li")?.textContent ?? "") && /응답 \d+ms|실패/.test(document.querySelector(".ping-log li")?.textContent ?? ""), null, { timeout: 30000 });
console.log("ping via NAT box:", (await page.locator(".ping-log li").first().innerText()).replace("\n", " "));
await page.fill(".ping-row .input", "web.home");
await page.click(".ping-row .btn");
await page.waitForFunction(() => /web\.home/.test(document.querySelector(".ping-log li")?.textContent ?? "") && /응답 \d+ms|실패/.test(document.querySelector(".ping-log li")?.textContent ?? ""), null, { timeout: 30000 });
console.log("ping web.home (LAN DNS record):", (await page.locator(".ping-log li").first().innerText()).replace("\n", " "));
await clickDevice("nat-1");
await page.waitForTimeout(100);
await page.screenshot({ path: `${OUT}/15-parts-nat.png` });
await clickDevice("gw-1");
await page.waitForTimeout(100);
await page.screenshot({ path: `${OUT}/16-parts-gateway.png` });

console.log("ERRORS:", errors.length ? errors : "none");
await browser.close();
await server.close();
process.exit(errors.length ? 1 : 0);
