// IPv6 3단계(듀얼 스택) 리뷰(clean context)가 찾은 결함의 회귀 테스트. 각 it 은 고친 뒤의 기대 동작을 단언한다.
import { describe, expect, it } from "vitest";
import { exampleDualStackTopology, exampleTopology } from "../src/model/examples";
import { loadTopology } from "./helpers";
import { probeTargets } from "../src/model/reach";
import { NetworkSync, effectiveDnsServer } from "../src/model/netSync";
import { parseTopology, serializeTopology, type Topology } from "../src/model/topology";
import { anyIpError } from "../src/app/inspector/ui";

const byName = (t: Topology, n: string) => t.devices.find((d) => d.name === n)!;
const unplug = (t: Topology, id: string): Topology => ({ ...structuredClone(t), cables: t.cables.filter((c) => c.a.device !== id && c.b.device !== id) });

describe("고친 결함 1: resolveName 이 취소(resolver.clear)를 'AAAA 실패' 로 보고 A 를 다시 묻는다", () => {
  it("링크 다운 중에 A 질의를 보내 ARP 대기열에 남기고, 케이블을 다시 꽂은 뒤의 IPv4 ping 이 ARP timeout 으로 실패", () => {
    const t = exampleDualStackTopology();
    const L = loadTopology(t);
    const pc = L.host("pc-1");
    const from = L.s.net.trace.length;
    L.s.net.scheduleAction(L.s.net.now, { kind: "tcp-connect", nodeId: pc.id, dst: "web.corp", port: 80 });
    L.s.net.runUntil(L.s.net.now + 5); // AAAA 질의가 나간 직후
    L.s.sync(unplug(t, pc.id));
    const downAt = L.s.net.now;
    L.s.net.runUntil(L.s.net.now + 50);
    L.s.sync(t); // 50ms 뒤 다시 연결
    L.s.net.runUntil(L.s.net.now + 300);
    L.s.net.scheduleAction(L.s.net.now, { kind: "ping", nodeId: pc.id, dst: "192.168.2.20" });
    L.s.net.runToIdle();
    const tr = L.s.net.trace.slice(from).filter((e) => e.nodeId === pc.id);
    // 관찰: ping 192.168.2.20 → failed "ARP timeout · 응답 없음" (링크 다운 때 대기열에 들어간 A 질의의 ARP 타이머가 새 ping 까지 드롭)
    // 같은 절차에서 AAAA 대기가 없으면 ok (RTT 160ms)
    expect(pc.pings.at(-1)).toMatchObject({ status: "ok" });
    // 링크 다운 뒤에 DNS 질의를 새로 보내면 안 된다 (관찰: "web.corp 의 주소는?" → 서버 192.168.2.53 이 링크 다운 직후에 나감)
    expect(tr.filter((e) => e.kind === "dns.query.sent" && e.time >= downAt).map((e) => e.summary)).toEqual([]);
  });

  it("수동 DNS 를 바꾸면 A 질의가 옛 DNS 서버로 나갔다가 곧바로 취소된다", () => {
    const t = exampleDualStackTopology();
    const L = loadTopology(t);
    const pc = L.host("pc-1");
    const from = L.s.net.trace.length;
    L.s.net.scheduleAction(L.s.net.now, { kind: "tcp-connect", nodeId: pc.id, dst: "web.corp", port: 80 });
    L.s.net.runUntil(L.s.net.now + 5);
    const next = structuredClone(t);
    byName(next, "pc-1").host!.dns = "192.168.2.99";
    L.s.sync(next);
    L.s.net.runToIdle();
    const q = L.s.net.trace.slice(from).filter((e) => e.nodeId === pc.id && e.kind === "dns.query.sent");
    // 관찰: [AAAA → 192.168.2.53, A → 192.168.2.53(옛 서버, 설정 변경 뒤)] + 나중에 "요청한 적 없는 DNS 응답" 2줄
    expect(q.length).toBe(1);
  });

  it("취소된 traceroute 도 AAAA NODATA 뒤 A 를 다시 묻는다", () => {
    const L = loadTopology(exampleDualStackTopology());
    const pc = L.host("pc-1");
    const from = L.s.net.trace.length;
    L.s.net.scheduleAction(L.s.net.now, { kind: "traceroute", nodeId: pc.id, dst: "old.corp" });
    L.s.net.scheduleAction(L.s.net.now + 5, { kind: "traceroute", nodeId: pc.id, dst: "192.168.2.20" }); // 앞의 것을 취소
    L.s.net.runToIdle();
    const q = L.s.net.trace.slice(from).filter((e) => e.nodeId === pc.id && e.kind === "dns.query.sent");
    expect(q.length).toBe(1); // 관찰: 2 (취소 뒤 "AAAA 레코드가 없음 → IPv4 주소(A)로 다시 묻는다" + A 질의)
  });
});

describe("고친 결함 2: 이름 TCP 연결: AAAA 답이 온 뒤 IPv6 출발지가 없으면 조용히 사라진다 (host.ts `if (!src) return;`)", () => {
  it("AAAA 를 기다리는 동안 IPv6 를 끄면 연결 기록도 실패 로그도 없다 (IPv4 가 있는데도)", () => {
    const t = exampleDualStackTopology();
    const L = loadTopology(t);
    const pc = L.host("pc-1");
    L.s.net.scheduleAction(L.s.net.now, { kind: "tcp-connect", nodeId: pc.id, dst: "web.corp", port: 80 });
    L.s.net.runUntil(L.s.net.now + 5);
    const next = structuredClone(t);
    byName(next, "pc-1").host!.ipv6!.enabled = false;
    L.s.sync(next);
    L.s.net.runToIdle();
    // 기대: IPv4 로 연결(또는 최소한 실패 기록). 관찰: conns 비어 있음, 마지막 로그는 "web.corp = 2001:db8:2::10 → 이 주소의 80 포트로 연결"
    expect([...pc.tcp.conns.values()].length).toBeGreaterThan(0);
  });

  it("같은 일이 RA 거둠(SLAAC 주소 삭제)으로도 생긴다", () => {
    const t = exampleDualStackTopology();
    const L = loadTopology(t);
    const pc = L.host("pc-1");
    L.s.net.scheduleAction(L.s.net.now, { kind: "tcp-connect", nodeId: pc.id, dst: "web.corp", port: 80 });
    L.s.net.runUntil(L.s.net.now + 5);
    const next = structuredClone(t);
    byName(next, "gw-1").l3!.ipv6!.interfaces[1]!.ra = false;
    L.s.sync(next);
    L.s.net.runToIdle();
    expect([...pc.tcp.conns.values()].length).toBeGreaterThan(0);
  });
});

describe("고친 결함 3: 진단 자동완성(reach.ts): 이름 후보가 첫 레코드 하나로만 판정된다", () => {
  it("IPv6 만 쓰는 노트북의 TCP 후보에 web.corp(AAAA 로 닿음)가 없다", () => {
    const t = exampleDualStackTopology();
    const r = probeTargets(t, byName(t, "laptop-1").id, "tcp", 80);
    // 관찰: ["2001:db8:2::10"] 만
    expect(r.candidates.map((c) => c.value)).toContain("web.corp");
  });

  it("AAAA 레코드가 먼저 적힌 경우 IPv4 전용 호스트의 TCP 후보에서 web.corp 가 빠진다", () => {
    const t = exampleDualStackTopology();
    const recs = byName(t, "dns-1").host!.dnsServer!.records;
    [recs[0], recs[1]] = [recs[1]!, recs[0]!];
    byName(t, "pc-1").host!.ipv6!.enabled = false;
    const r = probeTargets(t, byName(t, "pc-1").id, "tcp", 80);
    // 관찰: ["192.168.2.10", "192.168.2.20", "old.corp"]
    expect(r.candidates.map((c) => c.value)).toContain("web.corp");
  });
});

describe("고친 결함 4: 손으로 고친 JSON: DNS 레코드 ip·업스트림이 숫자면 동기화가 예외로 죽는다 (예전에는 무시)", () => {
  it("effectiveDnsServer / NetworkSync.sync 가 TypeError: s?.trim is not a function", () => {
    const raw = JSON.parse(serializeTopology(exampleDualStackTopology()));
    raw.devices.find((d: { name: string }) => d.name === "dns-1").host.dnsServer.records[2].ip = 1234;
    const { topology, error } = parseTopology(JSON.stringify(raw));
    expect(error).toBeUndefined(); // 불러오기는 통과
    expect(() => effectiveDnsServer(byName(topology!, "dns-1"))).not.toThrow();
    expect(() => new NetworkSync().sync(topology!)).not.toThrow();
  });

  it("인스펙터 칸 검증도 숫자에서 예외 (anyIpError → s.trim)", () => {
    expect(() => anyIpError(1234 as unknown as string, true)).not.toThrow();
  });
});

describe("고친 결함 5: UI 검증과 모델 정리가 공백에서 어긋난다", () => {
  it("' 192.168.2.20' 은 칸 오류가 없는데 레코드는 조용히 버려진다 (예전 ipError 는 오류를 보였다)", () => {
    const t = exampleDualStackTopology();
    byName(t, "dns-1").host!.dnsServer!.records[2]!.ip = " 192.168.2.20";
    const uiOk = anyIpError(" 192.168.2.20", true) === undefined;
    const kept = effectiveDnsServer(byName(t, "dns-1"))!.records.some((r) => r.name === "old.corp");
    expect(uiOk).toBe(kept); // 관찰: uiOk=true, kept=false
  });
});

describe("고친 결함 6: Happy Eyeballs 축소판이 실제와 다른 곳 (학습 오해)", () => {
  it("IPv6 가 RST(Connection refused)면 IPv4 로 다시 가지 않는다 — curl·브라우저는 다음 주소로 간다", () => {
    const t = exampleDualStackTopology();
    byName(t, "dns-1").host!.dnsServer!.records[1]!.ip = "2001:db8:2::53"; // 낡은 AAAA: 80 을 안 여는 장비
    const L = loadTopology(t);
    const pc = L.host("pc-1");
    L.act({ kind: "tcp-connect", nodeId: pc.id, dst: "web.corp", port: 80 });
    // 관찰: 마지막 연결 = [2001:db8:2::53]:80 FAILED "연결 거부 (RST)", IPv4 시도 없음
    expect(L.lastConn("pc-1")).toMatchObject({ remoteIp: "192.168.2.10", state: "CLOSED" });
  });

  it("IPv6 글로벌은 있지만 IPv6 경로가 없는 호스트도 AAAA 를 먼저 골라 ping 이 실패 (RFC 6724 규칙 1: 못 쓰는 목적지는 뒤로)", () => {
    const t = exampleDualStackTopology();
    byName(t, "pc-1").host!.ipv6 = { enabled: true, mode: "static", ip: "2001:db8:1::10", prefix: 64, gateway: "" };
    const L = loadTopology(t);
    const pc = L.host("pc-1");
    L.act({ kind: "ping", nodeId: pc.id, dst: "web.corp" });
    // 관찰: resolved 2001:db8:2::10, failed "timeout · 응답 없음" (호스트가 ip.no-route 로 스스로 드롭). TCP 는 SYN 4번(≈7초) 뒤에야 IPv4 로
    expect(pc.pings.at(-1)).toMatchObject({ status: "ok", resolved: "192.168.2.10" });
  });
});

describe("고친 결함 7: 로그 문구", () => {
  it("인터넷 공인 DNS 의 질의 수신 줄에 AAAA 가 빠져 있다 (답은 'AAAA 레코드 없음')", () => {
    const t = exampleTopology();
    const pcDev = t.devices.find((d) => d.kind === "pc")!;
    pcDev.host!.ipv6 = { enabled: true, mode: "static", ip: "2001:db8:1::10", prefix: 64, gateway: "" };
    const L = loadTopology(t);
    const tr = L.act({ kind: "ping", nodeId: pcDev.id, dst: "example.com" });
    const inetId = t.devices.find((d) => d.kind === "internet")!.id;
    const recv = tr.filter((e) => e.nodeId === inetId && e.kind === "dns.query.received").map((e) => e.summary);
    // 관찰: 두 줄 모두 '질의 수신 "example.com?"'
    expect(recv[0]).toContain("AAAA");
  });

  it("DNS 가 하나도 없는 듀얼 스택 호스트: 'AAAA 를 받지 못함 (DNS 서버 없음) → A 로 다시 묻는다' 뒤 같은 실패를 한 번 더", () => {
    const t = exampleDualStackTopology();
    delete byName(t, "pc-1").host!.dns;
    byName(t, "gw-1").l3!.ipv6!.raDns = undefined;
    const L = loadTopology(t);
    const pc = L.host("pc-1");
    const tr = L.act({ kind: "ping", nodeId: pc.id, dst: "web.corp" });
    expect(tr.filter((e) => e.nodeId === pc.id && e.kind === "dns.no-server").length).toBe(1); // 관찰: 2
  });
});
