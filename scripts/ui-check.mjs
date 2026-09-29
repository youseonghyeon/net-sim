// 브라우저 스모크 테스트: 편집 → DHCP 자동 할당 → DHCP 끄고 실패 → 수동 설정 → ping 성공 흐름을 실제 브라우저에서 확인한다.
// 실행: npm run ui-check   (스크린샷은 .shots/ 에 저장)
import { mkdirSync, writeFileSync } from "node:fs";
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
/** 인스펙터 탭 이동 (없으면 무시) */
async function goTab(name) {
  const b = page.locator(".inspector .tabs button", { hasText: name });
  if (await b.count()) await b.first().click();
}
/** 장치 클릭 → 진단 탭이 있으면 진단, 없으면 설정 탭 */
async function clickDevice(name) {
  const box = await device(name).locator(".tile").boundingBox();
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
  await page.waitForTimeout(30);
  if (await page.locator(".inspector .tabs button", { hasText: "진단" }).count()) await goTab("진단");
  else await goTab("설정");
}
/** 상단 파일 메뉴에서 예제 불러오기 / 비우기 */
async function loadEx(id) {
  await page.click(".menu-btn");
  await page.click(`.menu-item[data-example="${id}"]`);
}
async function clearUi() {
  await page.click(".menu-btn");
  await page.click(".menu-item.danger");
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
console.log("start cards:", await page.locator(".start-card").count());
await page.screenshot({ path: `${OUT}/00-start.png` });
await page.locator(".start-card", { hasText: "집 공유기" }).click();
await page.waitForTimeout(500);
await page.screenshot({ path: `${OUT}/10-dhcp-in-progress.png` });
console.log("packets visible during DHCP:", await page.locator(".packet").count());
for (const n of ["pc-1", "laptop-1", "srv-1"]) console.log(n, "→", await waitAddr(n, /^192\.168\.0\.\d+\/24$/));
// 1w) 스마트폰이 공유기 Wi-Fi 로 주소를 받는다 → 멀리 끌면 끊긴다
console.log("phone-1 (Wi-Fi) →", await waitAddr("phone-1", /^192\.168\.0\.\d+\/24$/));
console.log("wifi links:", await page.locator(".wifi-link").count(), "| coverage:", await page.locator(".wifi-range").count());
{
  const ph = await device("phone-1").locator(".tile").boundingBox();
  await page.mouse.move(ph.x + ph.width / 2, ph.y + ph.height / 2);
  await page.mouse.down();
  await page.mouse.move(ph.x + ph.width / 2, ph.y + ph.height / 2 + 420, { steps: 12 });
  await page.mouse.up();
  await page.waitForTimeout(300);
  console.log("phone-1 far →", await addrOf("phone-1"), "| links:", await page.locator(".wifi-link").count());
  const ph2 = await device("phone-1").locator(".tile").boundingBox();
  await page.mouse.move(ph2.x + ph2.width / 2, ph2.y + ph2.height / 2);
  await page.mouse.down();
  await page.mouse.move(ph.x + ph.width / 2, ph.y + ph.height / 2, { steps: 12 });
  await page.mouse.up();
  console.log("phone-1 back →", await waitAddr("phone-1", /^192\.168\.0\.\d+\/24$/));
}
await page.screenshot({ path: `${OUT}/19-wifi.png` });

// 1t) traceroute: pc-1 → 8.8.8.8 은 공유기 → ISP → 목적지 3홉
await clickDevice("pc-1");
await page.fill(".ping-row .input", "8.8.8.8");
await page.locator(".ping-row .btn", { hasText: "경로" }).click();
await page.waitForFunction(() => /홉|실패/.test(document.querySelector(".trace-head")?.textContent ?? ""), null, { timeout: 40000 });
console.log("traceroute 8.8.8.8:", (await page.locator(".trace-head").innerText()).replace("\n", " "), "|", (await page.locator(".trace-hops li").allInnerTexts()).map((x) => x.replace(/\s+/g, " ").trim()).join(" → "));

// 1a) 이름으로 ping: pc-1 → google.com (라우터 DNS 포워더 → 8.8.8.8)
await clickDevice("pc-1");
await page.fill(".ping-row .input", "google.com");
await page.click(".ping-row .btn");
await page.waitForFunction(() => /응답 \d+ms|실패/.test(document.querySelector(".ping-log li")?.textContent ?? ""), null, { timeout: 40000 });
console.log("ping google.com:", (await page.locator(".ping-log li").first().innerText()).replace("\n", " "));
// 1a2) 바깥에서 공인 :80 접속 → 포트 포워딩으로 srv-1 에 닿는다
await clickDevice("internet-1");
await page.click("button:has-text('접속')");
await page.waitForFunction(() => /종료됨|실패/.test(document.querySelector(".inspector .tcp-log li")?.textContent ?? ""), null, { timeout: 40000 });
console.log("inbound via port forward:", (await page.locator(".inspector .tcp-log li").first().innerText()).replace(/\s+/g, " "));

// 1a3) 방화벽: 라우터에서 "나가는 ICMP 차단" 규칙 → pc-1 의 외부 ping 이 막힌다
await clickDevice("rt-1");
const fwSection = page.locator(".inspector .section", { has: page.locator("h3", { hasText: /^방화벽$/ }) });
await fwSection.locator(".toggle").first().click();
await fwSection.locator("button:has-text('규칙 추가')").click();
await fwSection.locator(".fw-line select").nth(1).selectOption("out");
await fwSection.locator(".fw-line select").nth(2).selectOption("icmp");
await page.waitForTimeout(100);
await clickDevice("pc-1");
await page.fill(".ping-row .input", "8.8.8.8");
await page.click(".ping-row .btn");
await page.waitForFunction(() => /8\.8\.8\.8/.test(document.querySelector(".ping-log li")?.textContent ?? "") && /응답 \d+ms|실패/.test(document.querySelector(".ping-log li")?.textContent ?? ""), null, { timeout: 30000 });
console.log("ping 8.8.8.8 with firewall:", (await page.locator(".ping-log li").first().innerText()).replace("\n", " "));
console.log("fw badge:", (await page.locator(".badge text").allTextContents()).includes("방화벽"));
await clickDevice("rt-1");
await page.waitForTimeout(100);
await page.screenshot({ path: `${OUT}/18-firewall.png` });
await fwSection.locator(".toggle").first().click(); // 다시 끔 (첫 토글 = 켜짐/꺼짐)
await page.waitForTimeout(100);
async function wanOf() {
  return (await device("rt-1").locator("text.uplink").textContent()) ?? "";
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
await goTab("개요");
await page.click("button:has-text('장치 삭제')");
await page.waitForTimeout(600);
await clickDevice("rt-1");
await goTab("표");
await page.waitForTimeout(100);
const leaseRows = await page.locator(".inspector .section", { hasText: "DHCP 임대" }).locator("tbody tr").allInnerTexts();
console.log("router leases after deleting laptop-1:", leaseRows.length, leaseRows.some((r) => /비어/.test(r)) ? "(empty)" : "");

// 2) 라우터 DHCP 끄기 → 새 PC 연결 → 실패
await clickDevice("rt-1");
await goTab("설정");
const dhcpToggle = () => page.locator(".inspector .section", { has: page.locator("h3", { hasText: /^DHCP 서비스$/ }) }).locator(".toggle");
await dhcpToggle().click();
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
await goTab("설정");
await page.click(".segmented button:has-text('수동')");
await page.fill(".inspector input[placeholder='192.168.0.10']", "192.168.0.50");
await page.fill(".inspector input[placeholder='192.168.0.1']", "192.168.0.1");
console.log("pc-2 →", await waitAddr("pc-2", /^192\.168\.0\.50\/24$/));
await goTab("진단");
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
const tcpRows = () => page.locator(".inspector .tcp-log li");
await page.waitForFunction(() => /종료됨/.test(document.querySelector(".inspector .tcp-log li")?.textContent ?? ""), null, { timeout: 40000 });
console.log("tcp to srv-1:", await tcpRows().first().innerText());

// 3c) 케이블 손실 실험: srv-1 케이블 다음 패킷 손실 → 재전송으로 복구
const srvCable = page.locator("[data-cable]").nth(4);
await srvCable.locator(".hit").click({ force: true });
await page.waitForTimeout(100);
await page.click("text=다음 패킷 1개 손실시키기");
await clickDevice("pc-1");
await page.click(".tcp-row .btn");
await page.waitForFunction(() => { const rows = document.querySelectorAll(".inspector .tcp-log li"); return rows.length >= 2 && /종료됨/.test(rows[0]?.textContent ?? ""); }, null, { timeout: 60000 });
console.log("tcp after loss:", await tcpRows().first().innerText());
console.log("retransmit logged:", await page.evaluate(() => document.body.textContent.includes("재전송")));

// 3d) NAT 를 거쳐 example.com:80
await page.fill(".tcp-row .input:not(.port)", "93.184.216.34");
await page.click(".tcp-row .btn");
await page.waitForFunction(() => { const t = document.querySelector(".inspector .tcp-log li")?.textContent ?? ""; return /93\.184\.216\.34/.test(t) && /종료됨/.test(t); }, null, { timeout: 60000 });
console.log("tcp to example.com:", await tcpRows().first().innerText());

// 4) 로그 열고 스크린샷
await page.click(".log-toggle");
await page.waitForTimeout(200);
console.log("log rows:", await page.locator(".log-list .row").count());
await page.screenshot({ path: `${OUT}/13-static-ping-log.png` });

// 5) 다크
await page.click('.topbar-right .icon-btn[title*="테마"]');
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
await goTab("설정");
await dhcpToggle().click(); // DHCP 다시 켜기
const lanInput = page.locator(".inspector input.mono").first();
await lanInput.fill("192.168.127.1");
await page.waitForTimeout(100);
console.log("dhcp range after LAN change:", await page.locator(".inspector input.mono").evaluateAll((els) => els.map((e) => e.value).slice(2, 4)));
await clickDevice("pc-1");
await page.click("button:has-text('DHCP 임대 갱신')");
console.log("pc-1 after subnet change →", await waitAddr("pc-1", /^192\.168\.127\.\d+\/24$/));

// 8) 기능 단위 예제: NAT 박스 + 게이트웨이 + DHCP 서버 호스트
await loadEx("parts");
await page.waitForTimeout(300);
console.log("parts lint badges:", await page.locator(".lint-badge").count());
console.log("parts example devices:", await page.locator("[data-device]").count());
console.log("pc-1 (DHCP from dhcp-srv) →", await waitAddr("pc-1", /^192\.168\.1\.\d+\/24$/));
console.log("laptop-1 (DHCP via gateway relay) →", await waitAddr("laptop-1", /^192\.168\.2\.\d+\/24$/));
console.log("badges:", await page.locator(".badge text").allTextContents());
const natLine = () => device("nat-1").locator("text.uplink").textContent();
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

// 9) VLAN 예제: 같은 VLAN 은 직접, 다른 VLAN 은 게이트웨이 서브 인터페이스를 거쳐 통신
await loadEx("vlan");
await page.waitForTimeout(400);
console.log("vlan example devices:", await page.locator("[data-device]").count(), "| trunk ports:", await page.locator(".port.trunk").count(), "| VLAN badge:", (await page.locator(".badge text").allTextContents()).includes("VLAN"));
await clickDevice("pc-1");
await page.fill(".ping-row .input", "192.168.10.11");
await page.click(".ping-row .btn");
await page.waitForFunction(() => /응답 \d+ms|실패/.test(document.querySelector(".ping-log li")?.textContent ?? ""), null, { timeout: 30000 });
console.log("ping same VLAN:", (await page.locator(".ping-log li").first().innerText()).replace("\n", " "));
await page.fill(".ping-row .input", "192.168.20.20");
await page.click(".ping-row .btn");
await page.waitForFunction(() => /192\.168\.20\.20/.test(document.querySelector(".ping-log li")?.textContent ?? "") && /응답 \d+ms|실패/.test(document.querySelector(".ping-log li")?.textContent ?? ""), null, { timeout: 30000 });
console.log("ping across VLAN via gateway:", (await page.locator(".ping-log li").first().innerText()).replace("\n", " "));
await page.fill(".ping-row .input", "google.com");
await page.click(".ping-row .btn");
await page.waitForFunction(() => /google/.test(document.querySelector(".ping-log li")?.textContent ?? "") && /응답 \d+ms|실패/.test(document.querySelector(".ping-log li")?.textContent ?? ""), null, { timeout: 40000 });
console.log("ping internet from VLAN 10:", (await page.locator(".ping-log li").first().innerText()).replace("\n", " "));
await clickDevice("sw-1");
await page.waitForTimeout(100);
await page.screenshot({ path: `${OUT}/20-vlan.png` });

// 10) 편집 도구: 영역 선택 → 함께 이동 → 복제 → 일괄 설정 → 되돌리기 → JSON 저장/불러오기
await loadEx("gateways");
await page.waitForTimeout(400);
console.log("gateways example devices:", await page.locator("[data-device]").count(), "| blurb toast:", (await page.locator(".toast").textContent().catch(() => "")).slice(0, 30));
await page.locator(".toast").waitFor({ state: "detached", timeout: 5000 }); // 안내 토스트가 아래쪽 장치를 가린다
{
  // pc-1·pc-2 를 영역으로 잡는다 (빈 곳에서 드래그)
  const a = await device("pc-1").locator(".tile").boundingBox();
  const b = await device("pc-2").locator(".tile").boundingBox();
  await page.mouse.move(a.x - 30, a.y - 30);
  await page.mouse.down();
  await page.mouse.move(b.x + b.width + 30, b.y + b.height + 30, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(100);
  console.log("marquee selected:", await page.locator(".device.selected").count(), "| multi panel:", (await page.locator(".inspector h2").textContent()));
  await page.screenshot({ path: `${OUT}/21-multi-select.png` });
  // 함께 이동: 둘 다 같은 양만큼 내려간다
  const a1 = await device("pc-1").locator(".tile").boundingBox();
  await page.mouse.move(a1.x + a1.width / 2, a1.y + a1.height / 2);
  await page.mouse.down();
  await page.mouse.move(a1.x + a1.width / 2, a1.y + a1.height / 2 + 80, { steps: 6 });
  await page.mouse.up();
  const a2 = await device("pc-1").locator(".tile").boundingBox();
  const b2 = await device("pc-2").locator(".tile").boundingBox();
  console.log("group move dy:", Math.round(a2.y - a1.y), Math.round(b2.y - b.y));
  // 일괄 설정: 게이트웨이를 한 번에. 틀린 값이면 구성 검사 배지가 뜨고, 고치면 사라진다
  const sec = page.locator(".inspector .section").filter({ has: page.locator("h3", { hasText: "공통 설정" }) });
  console.log("lint badges before:", await page.locator(".lint-badge").count());
  await sec.locator("input.mono").nth(1).fill("10.9.9.9");
  await page.waitForTimeout(100);
  console.log("lint badges after bad gateway:", await page.locator(".lint-badge").count(), "| error:", await page.locator(".lint-badge.error").count());
  await sec.locator("input.mono").nth(1).fill("192.168.1.1");
  await page.waitForTimeout(100);
  console.log("lint badges after fix:", await page.locator(".lint-badge").count());
  // 복제 → 장치 수 +2, 되돌리기 → 원래대로 (입력 칸에 포커스가 있으면 단축키가 무시되므로 먼저 뺀다)
  await page.evaluate(() => document.activeElement?.blur());
  const n0 = await page.locator("[data-device]").count();
  await page.keyboard.press("Meta+d");
  await page.waitForTimeout(150);
  const n1 = await page.locator("[data-device]").count();
  await page.keyboard.press("Meta+z");
  await page.waitForTimeout(150);
  const n2 = await page.locator("[data-device]").count();
  console.log("duplicate:", n0, "→", n1, "| undo →", n2);
  await page.keyboard.press("Meta+Shift+z");
  await page.waitForTimeout(150);
  console.log("redo →", await page.locator("[data-device]").count());
  await page.screenshot({ path: `${OUT}/22-after-redo.png` });
  // 되돌리기로 복제본이 사라지면 선택도 비므로, 클릭 + Shift+클릭으로 다시 두 대를 고른다
  await clickDevice("pc-1");
  await page.waitForTimeout(100);
  console.log("click pc-1 selected:", await page.locator(".device.selected").count(), "|", await page.locator(".inspector h2").textContent(), "| toast:", await page.locator(".toast").textContent().catch(() => ""));
  await page.keyboard.down("Shift");
  await clickDevice("pc-2");
  await page.keyboard.up("Shift");
  await page.waitForTimeout(100);
  console.log("shift-click selected:", await page.locator(".device.selected").count());
  // 일괄 ping
  await page.fill(".inspector .ping-row .input", "8.8.8.8");
  await page.click(".inspector .ping-row .btn");
  await page.waitForFunction(() => { const rows = [...document.querySelectorAll(".ping-table tbody tr")]; return rows.length >= 2 && rows.every((r) => /응답|실패/.test(r.textContent)); }, null, { timeout: 30000 });
  console.log("batch ping rows:", (await page.locator(".ping-table tbody tr").allInnerTexts()).map((r) => r.replace(/\t/g, " ")).join(" / "));
}
// JSON: 저장된 토폴로지를 파일로 쓰고, 비운 뒤 올려서 복원
{
  const json = await page.evaluate(() => localStorage.getItem("net-sim.topology.v1"));
  const saved = JSON.parse(json);
  writeFileSync(`${OUT}/export.json`, JSON.stringify({ app: "net-sim", version: 1, ...saved }, null, 2));
  await clearUi();
  await page.waitForTimeout(150);
  console.log("after clear:", await page.locator("[data-device]").count());
  await page.locator('input[type="file"]').setInputFiles(`${OUT}/export.json`);
  await page.waitForTimeout(400);
  console.log("after import:", await page.locator("[data-device]").count(), "| toast:", await page.locator(".toast").textContent().catch(() => ""));
  await page.locator('input[type="file"]').setInputFiles({ name: "bad.json", mimeType: "application/json", buffer: Buffer.from("{oops") });
  await page.waitForTimeout(300);
  console.log("bad import toast:", await page.locator(".toast").textContent().catch(() => ""));
}
// 11) 인스펙터: 섹션 접기 → 넓게 → 접기(레일) → 펼치기, 끌어서 폭 조절
{
  await clickDevice("gw-1");
  await page.waitForTimeout(150);
  const sec = page.locator(".inspector .section").filter({ has: page.locator("h3", { hasText: /^스태틱 라우팅$/ }) });
  await sec.locator("h3").click();
  console.log("section collapsed:", await sec.evaluate((el) => el.classList.contains("collapsed")), "| fields hidden:", (await sec.locator(".btn").count()) === 0);
  await sec.locator("h3").click();
  const w0 = (await page.locator(".inspector").boundingBox()).width;
  await page.click('.inspector-tools .icon-btn[title="넓게"]');
  await page.waitForTimeout(150);
  const w1 = (await page.locator(".inspector").boundingBox()).width;
  await page.screenshot({ path: `${OUT}/26-inspector-wide.png` });
  await page.click('.inspector-tools .icon-btn[title="보통 폭"]');
  await page.waitForTimeout(150);
  await page.keyboard.press("Meta+\\");
  await page.waitForTimeout(150);
  const w2 = (await page.locator(".inspector").boundingBox()).width;
  const canvasW = (await page.locator(".canvas-wrap").boundingBox()).width;
  console.log("no horizontal scroll when collapsed:", await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth && document.body.scrollWidth <= window.innerWidth));
  await page.click('.inspector .icon-btn[title*="펼치기"]');
  await page.waitForTimeout(150);
  const w3 = (await page.locator(".inspector").boundingBox()).width;
  console.log("inspector width: normal", w0, "→ wide", w1, "→ collapsed", w2, "(canvas", Math.round(canvasW), ") → open", w3);
  // 끌어서 400px
  const h = await page.locator(".inspector-resize").boundingBox();
  await page.mouse.move(h.x + 3, h.y + 200);
  await page.mouse.down();
  await page.mouse.move(1440 - 400, h.y + 200, { steps: 6 });
  await page.mouse.up();
  await page.waitForTimeout(150);
  console.log("dragged width:", (await page.locator(".inspector").boundingBox()).width);
  // 오른쪽으로 계속 끌면 접힘 → 레일 버튼으로 다시 펼침
  const h2 = await page.locator(".inspector-resize").boundingBox();
  await page.mouse.move(h2.x + 3, h2.y + 200);
  await page.mouse.down();
  await page.mouse.move(1440 - 120, h2.y + 200, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(150);
  console.log("drag past min → collapsed:", (await page.locator(".inspector").boundingBox()).width);
  await page.click('.inspector .icon-btn[title*="펼치기"]');
  await page.waitForTimeout(150);
  console.log("reopened width:", (await page.locator(".inspector").boundingBox()).width);
  await page.click('.inspector-tools .icon-btn[title="보통 폭"]').catch(() => {});
  // 화면에 맞추기: 뷰포트를 멀리 옮긴 뒤 버튼 → 장치들이 다시 캔버스 안에
  await page.mouse.move(700, 450);
  await page.keyboard.down("Alt");
  await page.mouse.down();
  await page.mouse.move(1100, 700, { steps: 6 });
  await page.mouse.up();
  await page.keyboard.up("Alt");
  await page.click(".zoom .icon-btn");
  await page.waitForTimeout(150);
  const cw = await page.locator(".canvas-wrap").boundingBox();
  const boxes = await page.locator("[data-device] .tile").evaluateAll((els) => els.map((e) => e.getBoundingClientRect()));
  console.log("fit: all tiles inside canvas:", boxes.every((b) => b.left >= cw.x && b.right <= cw.x + cw.width && b.top >= cw.y && b.bottom <= cw.y + cw.height));
}
// 12) 영역: 선택 → 영역으로 묶기 → 이름 바꾸기 → 이름표 끌어서 안의 장치와 함께 이동 → 영역 도구로 그리기 → 삭제
{
  await loadEx("docker");
  await page.locator(".toast").waitFor({ state: "detached", timeout: 5000 });
  const a = await device("web").locator(".tile").boundingBox();
  const b = await device("embedded-dns").locator(".tile").boundingBox();
  await page.mouse.move(a.x - 30, a.y - 30);
  await page.mouse.down();
  await page.mouse.move(b.x + b.width + 30, b.y + b.height + 30, { steps: 6 });
  await page.mouse.up();
  await page.waitForTimeout(100);
  await page.click("text=영역으로 묶기");
  await page.waitForTimeout(150);
  const zonesBefore = await page.locator("[data-zone]").count();
  console.log("zones (예제 2 + 새로 1):", zonesBefore, "| panel:", await page.locator(".inspector h2").textContent(), "| members:", (await page.locator(".inspector p").first().textContent()));
  await page.fill(".inspector .input", "컨테이너들");
  await page.waitForTimeout(100);
  const zone = page.locator("[data-zone].selected");
  console.log("zone label:", await zone.locator(".zone-label text").textContent());
  const before = await device("web").locator(".tile").boundingBox();
  const lab = await zone.locator(".zone-label rect").boundingBox();
  await page.mouse.move(lab.x + lab.width / 2, lab.y + lab.height / 2);
  await page.mouse.down();
  await page.mouse.move(lab.x + lab.width / 2 - 120, lab.y + lab.height / 2, { steps: 6 });
  await page.mouse.up();
  await page.waitForTimeout(100);
  const after = await device("web").locator(".tile").boundingBox();
  console.log("zone drag moved web by (영역만 이동이라 0):", Math.round(after.x - before.x));
  await page.screenshot({ path: `${OUT}/29-zone.png` });
  // 영역 도구로 빈 곳에 그리기
  await page.click(".palette .tool:has-text('영역')");
  await page.mouse.move(150, 150);
  await page.mouse.down();
  await page.mouse.move(400, 320, { steps: 6 });
  await page.mouse.up();
  await page.waitForTimeout(100);
  console.log("zones after draw:", await page.locator("[data-zone]").count(), "| tool back to select:", await page.locator(".palette .tool.on").textContent());
  await page.keyboard.press("Delete");
  await page.waitForTimeout(100);
  console.log("zones after delete:", await page.locator("[data-zone]").count(), "| devices intact:", await page.locator("[data-device]").count());
  // 영역 복제(⌘D) 후 붙여 넣은 장치를 끌면 붙여 넣은 영역도 같이 움직인다
  const src = page.locator("[data-zone]", { hasText: "컨테이너들" }).locator(".zone-label rect");
  const sb = await src.boundingBox();
  await page.mouse.click(sb.x + sb.width / 2, sb.y + sb.height / 2);
  await page.keyboard.press("Meta+KeyD");
  await page.waitForTimeout(150);
  const pz = page.locator("[data-zone].selected");
  const pzCount = await pz.count();
  const z0 = await pz.locator(".zone-edge").boundingBox();
  const tile = await page.locator("[data-device].selected .tile").first().boundingBox();
  await page.mouse.move(tile.x + tile.width / 2, tile.y + tile.height / 2);
  await page.mouse.down();
  await page.mouse.move(tile.x + tile.width / 2 + 96, tile.y + tile.height / 2 + 48, { steps: 6 });
  await page.mouse.up();
  await page.waitForTimeout(100);
  const z1 = await pz.locator(".zone-edge").boundingBox();
  console.log("pasted zone selected:", pzCount, "| moved with devices:", Math.round(z1.x - z0.x) > 0 && Math.round(z1.y - z0.y) > 0 ? "yes" : "NO");
  // 속성 패널 접기 → 레일 여백 → 장치 더블클릭으로 다시 열기
  await page.keyboard.press("Meta+Backslash");
  await page.waitForTimeout(100);
  const rail = await page.locator(".inspector.collapsed").boundingBox();
  const btn = await page.locator(".inspector.collapsed .icon-btn").boundingBox();
  console.log("rail width:", Math.round(rail.width), "| button gap right:", Math.round(rail.x + rail.width - (btn.x + btn.width)));
  await page.screenshot({ path: `${OUT}/29b-rail.png`, clip: { x: rail.x - 200, y: 0, width: rail.width + 200, height: 120 } });
  const web = await device("web").locator(".tile").boundingBox();
  await page.mouse.dblclick(web.x + web.width / 2, web.y + web.height / 2);
  await page.waitForTimeout(100);
  console.log("dblclick opens inspector:", (await page.locator(".inspector.collapsed").count()) === 0 ? "yes" : "NO", "|", await page.locator(".inspector .device-head").first().textContent().catch(() => "?"));
}
// 13) 방화벽 장비 예제: ping 차단, TCP 80 통과, 장치 패널에 규칙 편집기
{
  await loadEx("fwbox");
  await page.locator(".toast").waitFor({ state: "detached", timeout: 5000 });
  console.log("fw device:", await device("fw-1").count(), "| status:", await addrOf("fw-1"));
  await clickDevice("fw-1");
  await page.waitForTimeout(150);
  console.log("fw panel sections:", (await page.locator(".inspector h3").allTextContents()).slice(0, 5).join(" / "));
  await clickDevice("pc-1");
  await waitAddr("pc-1", /^192\.168\.0\.\d+\/24$/);
  await page.fill(".ping-row .input", "192.168.0.20");
  await page.click(".ping-row .btn");
  await page.waitForFunction(() => /응답 \d+ms|실패/.test(document.querySelector(".ping-log li")?.textContent ?? ""), null, { timeout: 30000 });
  console.log("ping srv through fw:", (await page.locator(".ping-log li").first().innerText()).replace("\n", " "));
  await page.fill(".tcp-row .input", "192.168.0.20");
  await page.click(".tcp-row .btn");
  await page.waitForFunction(() => /종료됨|실패/.test(document.querySelector(".inspector .tcp-log li")?.textContent ?? ""), null, { timeout: 40000 });
  console.log("tcp srv through fw:", await tcpRows().first().innerText());
  await page.screenshot({ path: `${OUT}/31-firewall-box.png` });
}
// 14) 케이블 포트 지정: 스위치의 6번째 포트 칸을 잡고 PC 로 끌기 → 패널에서 포트 바꾸기
{
  await clearUi();
  await page.click(".palette .tool.item:has-text('스위치')");
  await page.click(".palette .tool.item:has-text('PC')");
  await page.waitForTimeout(150);
  const slot = page.locator("[data-device]", { hasText: "sw-1" }).locator("[data-port='5'] .port-hit");
  const sb = await slot.boundingBox();
  const pcTile = await device("pc-1").locator(".tile").boundingBox();
  await page.mouse.move(sb.x + sb.width / 2, sb.y + sb.height / 2);
  await page.mouse.down();
  await page.mouse.move(pcTile.x + pcTile.width / 2, pcTile.y + pcTile.height / 2, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(150);
  const cab = await page.evaluate(() => JSON.parse(localStorage.getItem("net-sim.topology.v1")).cables);
  console.log("cable ports:", cab.map((c) => `${c.a.port}-${c.b.port}`).join(","), "| selected:", await page.locator(".inspector h2").textContent());
  const sel = page.locator(".inspector select.mono").first();
  const opts = await sel.locator("option").allTextContents();
  // 스위치 쪽 select 를 찾아 eth3 로 바꾼다
  const selects = page.locator(".inspector select.mono");
  for (let i = 0; i < (await selects.count()); i++) {
    const s = selects.nth(i);
    if ((await s.locator("option").count()) > 2) await s.selectOption({ label: "eth3" });
  }
  await page.waitForTimeout(150);
  const cab2 = await page.evaluate(() => JSON.parse(localStorage.getItem("net-sim.topology.v1")).cables);
  console.log("after panel change:", cab2.map((c) => `${c.a.port}-${c.b.port}`).join(","), "| options:", opts.length);
  await page.screenshot({ path: `${OUT}/36-cable-port.png` });
}
// 15) 진단 자동완성 + 장치별 기억: 도커 예제의 pc-1 에서 목록 열기 → 그룹·닿지 않는 후보 → 다른 장치 갔다 와도 값 유지
{
  await loadEx("docker");
  await page.locator(".toast").waitFor({ state: "detached", timeout: 5000 });
  await clickDevice("pc-1");
  await waitAddr("pc-1", /^192\.168\.0\.\d+\/24$/);
  await page.locator(".ping-row .picker .input").first().click();
  await page.waitForTimeout(150);
  const groups = await page.locator(".picker-list h5").allTextContents();
  console.log("picker groups:", groups.join(" / "), "| bad toggle:", await page.locator(".picker-toggle").textContent().catch(() => "none"));
  await page.locator(".picker-toggle").dispatchEvent("mousedown");
  await page.waitForTimeout(100);
  console.log("bad rows:", (await page.locator(".picker-item.bad").allInnerTexts()).slice(0, 2).map((x) => x.replace(/\s+/g, " ")).join(" | "));
  await page.screenshot({ path: `${OUT}/37-picker.png` });
  await page.keyboard.press("Escape");
  await page.locator(".ping-row .picker .input").first().fill("google.com");
  await clickDevice("web");
  await page.waitForTimeout(100);
  await clickDevice("pc-1");
  await page.waitForTimeout(100);
  console.log("remembered ping target:", await page.locator(".ping-row .picker .input").first().inputValue());
}
// 동적 라우팅(RIP) 예제: 게이트웨이가 광고로 경로를 배우고, 그 경로로 ping 이 된다
{
  await loadEx("rip");
  await page.locator(".toast").waitFor({ state: "detached", timeout: 5000 }).catch(() => {});
  const ripRows = async () => {
    await clickDevice("gw-a");
    await goTab("표");
    return page.locator(".inspector .table td", { hasText: /^RIP \d홉$/ }).count();
  };
  let rows = 0;
  for (let i = 0; i < 60 && rows < 3; i++) {
    rows = await ripRows();
    if (rows < 3) await page.waitForTimeout(250);
  }
  console.log("gw-a RIP routes:", rows, "| badge:", await device("gw-a").locator(".badge, .pill", { hasText: "RIP" }).count());
  await page.screenshot({ path: `${OUT}/40-rip-table.png` });
  await clickDevice("pc-a");
  await page.locator(".ping-row .picker .input").first().fill("192.168.3.10");
  await page.keyboard.press("Escape");
  await page.click(".ping-row .btn:has-text('ping')");
  await page.locator(".inspector .ping-log li.ok, .inspector .ping-log li.failed").first().waitFor({ timeout: 30000 });
  console.log("pc-a → 192.168.3.10 via RIP:", (await page.locator(".inspector .ping-log li").first().textContent())?.replace(/\s+/g, " "));
}
// 로드밸런서 예제: nginx 서버(LB 서비스 토글)로 연결을 두 번 → 응답 서버가 바뀐다, lb-1 장비의 설정 섹션
{
  await loadEx("lb");
  await page.locator(".toast").waitFor({ state: "detached", timeout: 5000 }).catch(() => {});
  await waitAddr("pc-1", /^192\.168\.0\.1\d\d/);
  await clickDevice("pc-1");
  await page.locator(".inspector .picker .input").nth(1).fill("192.168.0.10");
  await page.keyboard.press("Escape");
  for (let k = 0; k < 2; k++) {
    const before = await page.locator(".inspector .tcp-log li.ok").count();
    await page.click(".inspector .btn:has-text('연결')");
    for (let i = 0; i < 120 && (await page.locator(".inspector .tcp-log li.ok").count()) <= before; i++) await page.waitForTimeout(250);
  }
  const served = (await page.locator(".inspector .tcp-log li.ok").allTextContents()).map((x) => x.match(/응답 ([\d.]+)/)?.[1]);
  console.log("lb served:", served.join(" , "));
  await page.screenshot({ path: `${OUT}/42-lb.png` });
  await clickDevice("lb-1");
  await goTab("설정");
  console.log("lb-1 section:", await page.locator(".inspector h3", { hasText: "로드밸런서" }).count(), "| backends:", await page.locator(".inspector .lb-row").count(), "| badge:", await device("lb-1").locator(".badge", { hasText: "LB" }).count());
  await page.screenshot({ path: `${OUT}/43-lb-config.png` });
}
// 패킷 상세 보기: 로그 줄을 펼치면 도구 출력(tcpdump·시스코 debug)과 계층별 헤더
{
  await loadEx("router");
  await page.locator(".toast").waitFor({ state: "detached", timeout: 5000 }).catch(() => {});
  await waitAddr("pc-1", /^192\.168\.0\.1\d\d/);
  await clickDevice("pc-1");
  await page.locator(".ping-row .picker .input").first().fill("8.8.8.8");
  await page.keyboard.press("Escape");
  for (let k = 0; k < 2; k++) {
    await page.click(".ping-row .btn:has-text('ping')");
    await page.locator(".inspector .ping-log li.ok").nth(k).waitFor({ timeout: 30000 });
  }
  if (!(await page.locator(".log.open").count())) await page.click(".log-toggle");
  const natRow = page.locator(".log-list .row", { hasText: "NAT 변환" }).last();
  await natRow.scrollIntoViewIfNeeded();
  await natRow.click();
  const detail = natRow.locator(".pkt-detail");
  await detail.waitFor({ timeout: 5000 });
  console.log("pkt detail:", (await detail.locator(".pkt-tool").allTextContents()).join(" | "), "| layers:", (await detail.locator(".pkt-layer-title").allTextContents()).join(","));
  console.log("nat debug line:", await detail.locator(".pkt-line", { hasText: "debug ip nat" }).locator("code").textContent().catch(() => "?"));
  await detail.screenshot({ path: `${OUT}/44-pkt-detail.png` });
}
// 캔버스의 패킷을 누르면 일시정지 + 상세 카드, 재생하면 닫힘
{
  await loadEx("starter");
  await page.locator(".toast").waitFor({ state: "detached", timeout: 5000 }).catch(() => {});
  await clickDevice("pc-1");
  await page.locator(".ping-row .picker .input").first().fill("192.168.0.11");
  await page.keyboard.press("Escape");
  await page.click(".ping-row .btn:has-text('ping')");
  const pk = page.locator("g.packet[data-tx]").first();
  await pk.waitFor({ timeout: 10000 });
  // 누르기용 히트 원(r=13)은 투명해야 한다 — 종류별 색 규칙(.packet.arp circle)이 덮어써 패킷이 커 보인 적이 있다
  const hitFills = await page.evaluate(() => [...document.querySelectorAll("g.packet .packet-hit")].map((c) => getComputedStyle(c).fill));
  const painted = hitFills.filter((f) => f !== "transparent" && f !== "rgba(0, 0, 0, 0)" && f !== "none");
  console.log("packet hit circles transparent:", painted.length === 0 ? `yes (${hitFills.length})` : "NO " + painted.join(","));
  if (painted.length) errors.push(`packet-hit painted: ${painted[0]} — 히트 원이 칠해짐 / 종류별 색 규칙에 :not(.packet-hit) / src/app/styles.css .packet.* circle`);
  const box = await pk.boundingBox();
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
  const card = page.locator(".packet-card");
  await card.waitFor({ timeout: 3000 });
  const paused = await page.evaluate(() => document.querySelector(".topbar")?.textContent ?? "");
  console.log("packet card:", (await card.locator(".packet-card-head b").textContent())?.slice(0, 40), "| layers:", (await card.locator(".pkt-layer-title").allTextContents()).join(","), "| route:", (await card.locator(".packet-card-route").textContent())?.split(" · ")[0]);
  await page.screenshot({ path: `${OUT}/45-packet-card.png` });
  await page.keyboard.press("Space");
  await page.waitForTimeout(200);
  console.log("card closed on play:", (await card.count()) === 0 ? "yes" : "NO", paused ? "" : "");
}
// 공유기 설정: DHCP 의 DNS 서버 칸, 포트 포워딩 두 줄 편집기(TCP/UDP)
{
  await loadEx("router");
  await page.locator(".toast").waitFor({ state: "detached", timeout: 5000 }).catch(() => {});
  await clickDevice("rt-1");
  await goTab("설정");
  const dnsField = page.locator(".inspector .field", { hasText: "DNS 서버" }).first();
  console.log("router dhcp dns field:", await dnsField.count(), "| placeholder:", await dnsField.locator("input").getAttribute("placeholder"));
  const fwd = page.locator(".inspector .fwd-row").first();
  await fwd.scrollIntoViewIfNeeded();
  await fwd.locator("select.proto").selectOption("udp");
  await page.waitForTimeout(100);
  const b = await fwd.boundingBox();
  const ip = await fwd.locator(".fwd-ip").boundingBox();
  console.log("fwd row: two lines", b.height > 50 ? "yes" : "NO", "| ip width", Math.round(ip.width), "| proto", await fwd.locator("select.proto").inputValue());
  await fwd.screenshot({ path: `${OUT}/46-fwd-row.png` });
}
// VPN 예제: 사설끼리 ping, 통신사 구간을 지나는 패킷 카드에 "터널 안" 층, NAT 박스 설정에 VPN 섹션
{
  await loadEx("vpn");
  await page.locator(".toast").waitFor({ state: "detached", timeout: 5000 }).catch(() => {});
  await clickDevice("pc-a");
  await page.locator(".ping-row .picker .input").first().fill("192.168.2.10");
  await page.keyboard.press("Escape");
  await page.click(".ping-row .btn:has-text('ping')");
  await page.locator(".inspector .ping-log li.ok, .inspector .ping-log li.failed").first().waitFor({ timeout: 30000 });
  console.log("vpn ping:", (await page.locator(".inspector .ping-log li").first().textContent())?.replace(/\s+/g, " "));
  await clickDevice("사무실 A NAT");
  await goTab("설정");
  console.log("vpn section:", await page.locator(".inspector h3", { hasText: "VPN" }).count(), "| remote rows:", await page.locator(".inspector .lb-row").count(), "| badge:", await device("사무실 A NAT").locator(".badge", { hasText: "VPN" }).count());
  // 다시 ping 을 보내고 통신사 구간 위의 터널 패킷을 눌러 본다
  await clickDevice("pc-a");
  await page.click(".ping-row .btn:has-text('ping')");
  const isp = await device("통신사 구간").locator(".tile").boundingBox();
  let clicked = false;
  for (let i = 0; i < 80 && !clicked; i++) {
    for (const el of await page.locator("g.packet.vpn[data-tx]").all()) {
      const b = await el.boundingBox();
      if (b && b.y < isp.y + isp.height + 80) {
        await page.mouse.click(b.x + b.width / 2, b.y + b.height / 2);
        clicked = (await page.locator(".packet-card").count()) > 0;
        if (clicked) break;
      }
    }
    if (!clicked) await page.waitForTimeout(50);
  }
  if (clicked) {
    console.log("vpn packet card:", (await page.locator(".packet-card .pkt-layer-title").allTextContents()).join(" > "));
    await page.screenshot({ path: `${OUT}/47-vpn-card.png` });
    await page.keyboard.press("Escape");
    await page.keyboard.press("Space");
  } else console.log("vpn packet card: (터널 패킷을 누르지 못함)");
}
// 망분리 + NCP 예제: 내부망 PC 1 → dev-2 TCP 22 (IPsec 터널을 맺고 연결), VPN 설정에 IPsec·PSK, 서버에 SSH 토글
{
  await loadEx("ncp");
  await page.locator(".toast").waitFor({ state: "detached", timeout: 5000 }).catch(() => {});
  await page.screenshot({ path: `${OUT}/48-ncp-overview.png` });
  await clickDevice("내부망 PC 1");
  await goTab("진단");
  await page.fill(".tcp-row .input:not(.port)", "192.168.112.11");
  await page.keyboard.press("Escape");
  await page.fill(".tcp-row .input.port", "22");
  await page.click(".tcp-row .btn");
  await page.waitForFunction(() => { const t = document.querySelector(".inspector .tcp-log li")?.textContent ?? ""; return /192\.168\.112\.11:22/.test(t) && /종료됨|실패/.test(t); }, null, { timeout: 60000 });
  console.log("ncp ssh:", (await page.locator(".inspector .tcp-log li").first().innerText()).replace(/\s+/g, " "));
  console.log("ncp ipsec up logged:", await page.evaluate(() => document.body.textContent.includes("IPsec 터널 수립")) ? "yes" : "NO (로그 창이 접혀 있으면 확인 불가)");
  await clickDevice("NCP VPN Gateway");
  await goTab("설정");
  const vpnSec = page.locator(".inspector section", { has: page.locator("h3", { hasText: "VPN" }) }).first();
  console.log("ncp vpn mode:", await vpnSec.locator(".segmented button.on").textContent(), "| psk field:", await vpnSec.locator(".field", { hasText: "사전 공유 키" }).count());
  await vpnSec.screenshot({ path: `${OUT}/49-ncp-vpn-section.png` });
  await clickDevice("dev-2");
  await goTab("설정");
  console.log("ssh toggle:", await page.locator(".inspector .toggle-row", { hasText: "SSH 서버" }).count(), "| badge:", await device("dev-2").locator(".badge", { hasText: "SSH" }).count());
}
// 방화벽 이중화: A 가 master → ping, A 를 지우면 B 가 master 가 되어 ping 이 계속된다
{
  await loadEx("ha");
  await page.locator(".toast").waitFor({ state: "detached", timeout: 5000 }).catch(() => {});
  await page.waitForFunction(() => [...document.querySelectorAll("[data-device]")].some((el) => /방화벽 A/.test(el.textContent ?? "") && /HA master/.test(el.textContent ?? "")), null, { timeout: 20000 });
  console.log("ha initial: A master", "| B:", await device("방화벽 B").locator(".badge", { hasText: "HA" }).textContent());
  const pingOnce = async () => {
    await clickDevice("pc-1");
    await goTab("진단");
    await page.locator(".ping-row .picker .input").first().fill("8.8.8.8");
    await page.keyboard.press("Escape");
    const before = await page.locator(".inspector .ping-log li").count();
    await page.click(".ping-row .btn:has-text('ping')");
    await page.waitForFunction((n) => document.querySelectorAll(".inspector .ping-log li").length > n || n >= 3, before, { timeout: 30000 });
    await page.waitForFunction(() => /응답 \d+ms|실패/.test(document.querySelector(".inspector .ping-log li")?.textContent ?? ""), null, { timeout: 30000 });
    return (await page.locator(".inspector .ping-log li").first().innerText()).replace(/\s+/g, " ");
  };
  console.log("ha ping via A:", await pingOnce());
  await clickDevice("방화벽 A");
  await goTab("설정");
  console.log("ha section:", await page.locator(".inspector h3", { hasText: "이중화" }).count());
  await page.locator(".inspector section", { has: page.locator("h3", { hasText: "이중화" }) }).first().screenshot({ path: `${OUT}/50-ha-section.png` });
  await page.keyboard.press("Delete");
  await page.waitForFunction(() => [...document.querySelectorAll("[data-device]")].some((el) => /방화벽 B/.test(el.textContent ?? "") && /HA master/.test(el.textContent ?? "")), null, { timeout: 20000 });
  console.log("ha failover: B master");
  console.log("ha ping via B:", await pingOnce());
  await page.screenshot({ path: `${OUT}/51-ha-failover.png` });
}
// 이벤트 로그 높이 조절: 끝까지 올리면 상단바 바로 아래, 새로고침해도 유지, 아래로 한참 끌면 접힘
{
  if (!(await page.locator(".log.open").count())) await page.click(".log-toggle");
  const handle = page.locator(".log-resize");
  const hb = await handle.boundingBox();
  await page.mouse.move(hb.x + hb.width / 2, hb.y + hb.height / 2);
  await page.mouse.down();
  await page.mouse.move(hb.x + hb.width / 2, 0, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(100);
  const top = (await page.locator(".log").boundingBox()).y;
  const bar = await page.locator(".topbar").boundingBox();
  console.log("log max: top", Math.round(top), "| topbar bottom", Math.round(bar.y + bar.height), "| layout ok:", await page.evaluate(() => (document.body.scrollHeight <= window.innerHeight ? "yes" : "no")));
  await page.screenshot({ path: `${OUT}/41-log-max.png` });
  // 중간 높이로 내려 두고 새로고침 → 유지
  const hb2 = await handle.boundingBox();
  await page.mouse.move(hb2.x + 200, hb2.y + 3);
  await page.mouse.down();
  await page.mouse.move(hb2.x + 200, 500, { steps: 8 });
  await page.mouse.up();
  const before = Math.round((await page.locator(".log-list").boundingBox()).height);
  await page.reload();
  await page.waitForSelector("[data-device]");
  if (!(await page.locator(".log.open").count())) await page.click(".log-toggle");
  const after = Math.round((await page.locator(".log-list").boundingBox()).height);
  console.log("log height persisted:", before, "→", after);
  // 아래로 한참 끌면 접힌다
  const hb3 = await page.locator(".log-resize").boundingBox();
  await page.mouse.move(hb3.x + 200, hb3.y + 3);
  await page.mouse.down();
  await page.mouse.move(hb3.x + 200, 895, { steps: 10 });
  await page.mouse.up();
  console.log("log collapsed by drag:", (await page.locator(".log.open").count()) === 0 ? "yes" : "NO");
  // 로그 "이전 기록 더 보기": 처음엔 최근 500줄, 누르면 더 많이 (이벤트가 많은 예제로)
  await loadEx("publish");
  await waitAddr("맥북", /^192\.168\.0\.1\d\d/);
  await clickDevice("맥북");
  await page.locator(".inspector .picker .input").nth(1).fill("nexus.com");
  await page.keyboard.press("Escape");
  for (let k = 0; k < 3; k++) {
    await page.click(".inspector .btn:has-text('연결')");
    await page.waitForTimeout(1500);
  }
  for (let i = 0; i < 120; i++) {
    const n = Number(((await page.locator(".log-toggle .count").textContent()) ?? "0").replace(/,/g, ""));
    if (n > 1500) break;
    await page.waitForTimeout(250);
  }
  await page.click(".log-toggle");
  await page.click(".layer-filters .chip:has-text('L1')"); // 링크 전송까지 보이게 (기본은 꺼짐)
  await page.waitForTimeout(400);
  const rowsBefore = await page.locator(".log-list .row").count();
  const more = page.locator(".log-more button");
  if (await more.count()) {
    await more.click();
    await page.waitForTimeout(300);
    console.log("log more:", rowsBefore, "→", await page.locator(".log-list .row").count(), "| total:", await page.locator(".log-toggle .count").textContent());
  } else console.log("log more: (500줄 이하라 버튼 없음)", rowsBefore);
}
console.log("layout ok (end):", await page.evaluate(() => document.body.scrollHeight <= window.innerHeight ? "yes" : "no"));

console.log("ERRORS:", errors.length ? errors : "none");
await browser.close();
await server.close();
process.exit(errors.length ? 1 : 0);
