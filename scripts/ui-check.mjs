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
await page.waitForFunction(() => { const sec = [...document.querySelectorAll(".inspector .section")].find((s) => s.textContent.includes("웹 서버 연결")); return /종료됨|실패/.test(sec?.querySelector("tbody tr")?.textContent ?? ""); }, null, { timeout: 40000 });
console.log("inbound via port forward:", await page.locator(".inspector .section", { hasText: "웹 서버 연결" }).locator("tbody tr").first().innerText());

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

// 3c) 케이블 손실 실험: srv-1 케이블 다음 패킷 손실 → 재전송으로 복구
const srvCable = page.locator("[data-cable]").nth(4);
await srvCable.locator(".hit").click({ force: true });
await page.waitForTimeout(100);
await page.click("text=다음 패킷 1개 손실시키기");
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
await dhcpToggle().click(); // DHCP 다시 켜기
const lanInput = page.locator(".inspector input.mono").first();
await lanInput.fill("192.168.127.1");
await page.waitForTimeout(100);
console.log("dhcp range after LAN change:", await page.locator(".inspector input.mono").evaluateAll((els) => els.map((e) => e.value).slice(2, 4)));
await clickDevice("pc-1");
await page.click("button:has-text('DHCP 임대 갱신')");
console.log("pc-1 after subnet change →", await waitAddr("pc-1", /^192\.168\.127\.\d+\/24$/));

// 8) 기능 단위 예제: NAT 박스 + 게이트웨이 + DHCP 서버 호스트
await page.selectOption("select.example", "parts");
await page.waitForTimeout(300);
console.log("parts lint badges:", await page.locator(".lint-badge").count());
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

// 9) VLAN 예제: 같은 VLAN 은 직접, 다른 VLAN 은 게이트웨이 서브 인터페이스를 거쳐 통신
await page.selectOption("select.example", "vlan");
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
await page.selectOption("select.example", "gateways");
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
  await page.click("text=비우기");
  await page.waitForTimeout(150);
  console.log("after clear:", await page.locator("[data-device]").count());
  await page.locator('input[type="file"]').setInputFiles(`${OUT}/export.json`);
  await page.waitForTimeout(400);
  console.log("after import:", await page.locator("[data-device]").count(), "| toast:", await page.locator(".toast").textContent().catch(() => ""));
  await page.locator('input[type="file"]').setInputFiles({ name: "bad.json", mimeType: "application/json", buffer: Buffer.from("{oops") });
  await page.waitForTimeout(300);
  console.log("bad import toast:", await page.locator(".toast").textContent().catch(() => ""));
}
console.log("layout ok (end):", await page.evaluate(() => document.body.scrollHeight <= window.innerHeight ? "yes" : "no"));

console.log("ERRORS:", errors.length ? errors : "none");
await browser.close();
await server.close();
process.exit(errors.length ? 1 : 0);
