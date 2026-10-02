// 종합 예제 "중소기업 전체": 앞의 예제들의 기능이 한 구성에서 함께 동작한다
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import { loadTopology } from "./helpers";
import { exampleCompanyTopology } from "../src/model/examples";

describe("중소기업 전체 (본사·지사·재택·고객)", () => {
  const x = loadTopology(exampleCompanyTopology());

  it("구성 검사 이슈가 없고, 사무실·손님 Wi-Fi 는 코어 게이트웨이의 DHCP 릴레이로 VLAN 별 주소를 받는다", () => {
    expect(lintTopology(x.t)).toEqual([]);
    expect(x.host("사무 PC-1").ip).toMatch(/^10\.1\.10\./);
    expect(x.host("손님 폰").ip).toMatch(/^10\.1\.30\./);
    expect(x.host("손님 폰").iface.dns).toBe("8.8.8.8");
    expect(x.host("재택 노트북").ra.state).toBe("up");
  });

  it("지사 PC → intranet.corp: 사내 DNS 에 묻고 위키에 닿는다 (지사 ↔ 본사 IPsec 터널)", () => {
    const tr = x.act({ kind: "tcp-connect", nodeId: x.id("지사 PC-1"), dst: "intranet.corp", port: 80 });
    expect(x.lastConn("지사 PC-1")).toMatchObject({ state: "CLOSED", bytesReceived: 3000, remoteIp: "10.1.20.20" });
    expect(tr.some((e) => e.nodeId === x.id("지사 NAT") && e.kind === "vpn.encap")).toBe(true);
  });

  it("재택 노트북 → 사내 위키 SSH: 원격 접속 VPN 으로", () => {
    x.act({ kind: "tcp-connect", nodeId: x.id("재택 노트북"), dst: "10.1.20.20", port: 22 });
    expect(x.lastConn("재택 노트북")).toMatchObject({ state: "ESTABLISHED", ssh: { open: true } });
  });

  it("사무 PC → www.corp: 웹 LB 가 web-1·web-2 로 번갈아 나눈다", () => {
    const served: string[] = [];
    for (let i = 0; i < 2; i++) {
      x.act({ kind: "tcp-connect", nodeId: x.id("사무 PC-1"), dst: "www.corp", port: 80 });
      served.push(x.lastConn("사무 PC-1").servedBy ?? "");
    }
    expect(served.sort()).toEqual(["10.1.20.11", "10.1.20.12"]);
  });

  it("카페 고객 폰 → 회사 공인 주소:80 은 포트 포워딩으로 웹 LB 에", () => {
    x.act({ kind: "tcp-connect", nodeId: x.id("고객 폰"), dst: "203.0.113.10", port: 80 });
    expect(x.lastConn("고객 폰")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
  });

  it("손님 폰: 인터넷은 되고 사내 위키는 코어 방화벽에 막힌다", () => {
    const tr = x.act({ kind: "ping", nodeId: x.id("손님 폰"), dst: "10.1.20.20" });
    expect(x.host("손님 폰").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.nodeId === x.id("본사 코어") && e.kind === "fw.deny")).toBe(true);
    x.act({ kind: "ping", nodeId: x.id("손님 폰"), dst: "8.8.8.8" });
    expect(x.host("손님 폰").pings.at(-1)!.status).toBe("ok");
  });
});
