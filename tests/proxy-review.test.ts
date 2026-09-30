// 포워드 프록시·쿠키 고정 리뷰 회귀: 응답 중간 멈춤, 자동완성, 불러오기 견고성, LB 앞 프록시 팜, 쿠키 사이트 키, 주소 차단, 실무 줄, 루프백 ACK, 포트 겹침
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import { exampleLoadBalancerTopology, exampleProxyTopology } from "../src/model/examples";
import { probeTargets } from "../src/model/reach";
import { NetworkSync } from "../src/model/netSync";
import { normalizeTopology, type Device, type Topology } from "../src/model/topology";
import { practitionerLines } from "../src/model/packetView";
import { loadTopology } from "./helpers";

const edit = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });
const host = (d: Device, patch: Partial<NonNullable<Device["host"]>>): Device => ({ ...d, host: { ...d.host!, ...patch } });

/** LB 예제의 nginx 서버(192.168.0.10)를 프록시로 바꾸고 pc-1 이 그 프록시를 쓰게 한다 */
function lbWithProxy(): Topology {
  let t = exampleLoadBalancerTopology();
  t = edit(t, "nginx 서버", (d) => host(d, { lb: { ...d.host!.lb!, enabled: false }, proxy: { enabled: true, port: 3128, deny: [] } }));
  return edit(t, "pc-1", (d) => host(d, { httpProxy: { enabled: true, server: "192.168.0.10", port: 3128 } }));
}

describe("리뷰 회귀: 포워드 프록시", () => {
  it("대상이 응답 도중 멈추면 프록시의 대상 연결도 마지막 수신 10초 뒤 timeout 으로 끝난다 (영원히 열려 있지 않음)", () => {
    const t = lbWithProxy();
    const { s, id, host: h, apply } = loadTopology(t);
    s.net.scheduleAction(s.net.now, { kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.11", port: 80 });
    const from = s.net.trace.length;
    const web1Cable = t.cables.find((c) => c.a.device === id("web-1") || c.b.device === id("web-1"))!;
    const proxyCable = t.cables.find((c) => c.a.device === id("nginx 서버") || c.b.device === id("nginx 서버"))!;
    // 스위치가 응답 1/3(seq 3001)을 프록시 쪽으로 내보낸 직후 다음 세그먼트(2/3)를 잃게 하고,
    // 프록시가 1/3 을 받으면 web-1 이 2/3 을 재전송하기 전에 web-1 케이블을 뺀다
    const until = (pred: (e: { nodeId: string; kind: string; summary: string }) => boolean) => {
      while (!s.net.trace.slice(from).some(pred)) if (!s.net.step()) throw new Error("기다린 이벤트가 오지 않음");
    };
    until((e) => e.nodeId === id("sw-1") && e.kind === "link.transmit" && e.summary.includes("seq=3001") && e.summary.includes(id("nginx 서버")));
    s.net.dropNextOn(proxyCable.id);
    until((e) => e.nodeId === id("nginx 서버") && e.kind === "tcp.data.received" && e.summary.includes("HTTP 200 (1/3)"));
    apply({ ...t, cables: t.cables.filter((c) => c !== web1Cable) });
    const up = [...h("nginx 서버").tcp.conns.values()].find((c) => c.role === "client" && c.remoteIp === "192.168.0.11")!;
    expect(up.state).toBe("FAILED");
    expect(up.reason).toContain("timeout · 응답이 중간에 멈춤");
    expect(h("nginx 서버").proxy.rows()[0]![2]).toMatch(/^TCP_MISS/);
  });

  it("진단 자동완성: 프록시 경유 연결은 이름이 프록시 주소로 풀린 것처럼 보이지 않는다", () => {
    const t = exampleProxyTopology();
    const pc = t.devices.find((d) => d.name === "pc-1")!.id;
    const r = probeTargets(t, pc, "tcp", 80).candidates.find((c) => c.value === "example.com")!;
    expect(r.ok).toBe(true);
    expect(r.resolved).toBe("93.184.216.34");
  });

  it("JSON 불러오기: 깨진 프록시 설정 값에도 구성 검사·동기화가 멈추지 않고 알맞게 정리된다", () => {
    let t = exampleProxyTopology();
    t = edit(t, "pc-1", (d) => host(d, { httpProxy: { enabled: true, server: 123 as unknown as string, port: "3128" as unknown as number } }));
    t = edit(t, "proxy-1", (d) => host(d, { proxy: { enabled: true, port: "3128" as unknown as number, deny: "naver.com" as unknown as string[] } }));
    t = edit(t, "laptop-1", (d) => host(d, { lb: { enabled: false, port: 80, algorithm: "round-robin", backends: [], sticky: "foo" as unknown as "ip" } }));
    const n = normalizeTopology(t);
    const get = (name: string) => n.devices.find((d) => d.name === name)!.host!;
    expect(get("pc-1").httpProxy).toEqual({ enabled: true, server: "123", port: 3128 });
    expect(get("proxy-1").proxy).toEqual({ enabled: true, port: 3128, deny: ["naver.com"] });
    expect(get("laptop-1").lb!.sticky).toBeUndefined();
    expect(() => lintTopology(n)).not.toThrow();
    expect(() => new NetworkSync().sync(n)).not.toThrow();
    // 포트가 문자열로 저장돼 있어도 프록시 설정은 살아 있다
    const fixed = normalizeTopology(edit(exampleProxyTopology(), "pc-1", (d) => host(d, { httpProxy: { enabled: true, server: "192.168.0.10", port: "3128" as unknown as number } })));
    const { id, act } = loadTopology(fixed);
    expect(act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "example.com", port: 80 }).some((e) => e.kind === "proxy.use")).toBe(true);
  });

  it("L7 로드밸런서 뒤의 프록시 팜: LB 가 요청 대상(절대 URI)을 그대로 넘겨 프록시가 대신 받아 오고, 구성 검사는 HTTPS(CONNECT) 경고만", () => {
    let t = exampleLoadBalancerTopology();
    t = edit(t, "nginx 서버", (d) => host(d, { lb: { enabled: true, port: 3128, algorithm: "round-robin", backends: [{ ip: "192.168.0.13", port: 3128 }] } }));
    t = edit(t, "web-3", (d) => host(d, { proxy: { enabled: true, port: 3128, deny: [] } }));
    t = edit(t, "pc-1", (d) => host(d, { httpProxy: { enabled: true, server: "192.168.0.10", port: 3128 } }));
    // proxy.not-running 오탐은 없다. L7 은 CONNECT 를 중계하지 않아 HTTPS 만 경고 (L4 로 바꾸면 사라진다)
    expect(lintTopology(t).map((i) => i.code)).toEqual(["proxy.l7-connect"]);
    expect(lintTopology(edit(t, "nginx 서버", (d) => host(d, { lb: { ...d.host!.lb!, mode: "l4" } }))).map((i) => i.code)).toEqual([]);
    const { id, act, lastConn } = loadTopology(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.11", port: 80 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", bytesReceived: 3000, servedBy: "192.168.0.11" });
    expect(lastConn("pc-1").status).toBe("HTTP 200");
  });

  it("구성 검사: HTTP 프록시가 일반 웹 서버를 가리키면 그 서버 자신의 응답이 온다고 알린다 (시뮬레이션과 같게)", () => {
    const t = edit(exampleLoadBalancerTopology(), "pc-1", (d) => host(d, { httpProxy: { enabled: true, server: "192.168.0.11", port: 80 } }));
    const issue = lintTopology(t).find((i) => i.code === "proxy.not-running")!;
    expect(issue.message).toContain("그 서버 자신의 응답");
    const { id, act, lastConn } = loadTopology(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "example.com", port: 80 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
  });

  it("차단 목록의 주소는 이름으로 접속해도 막힌다 (Squid dst ACL 처럼 풀어서 비교)", () => {
    const t = edit(exampleProxyTopology(), "proxy-1", (d) => host(d, { proxy: { enabled: true, port: 3128, deny: ["93.184.216.34"] } }));
    const { id, act, lastConn } = loadTopology(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "example.com", port: 80 });
    expect(tr.find((e) => e.kind === "proxy.deny")!.summary).toContain("93.184.216.34");
    expect(lastConn("pc-1").status).toBe("HTTP 403 Forbidden");
  });

  it("Squid access.log: 이름 해석 실패는 TCP_MISS/503, 대상 없는 요청은 TAG_NONE/400 과 요청 줄 그대로", () => {
    const { id, act } = loadTopology(exampleProxyTopology());
    const fail = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "err400.example", port: 80 }).find((e) => e.kind === "proxy.fail")!;
    expect(practitionerLines(fail, {}).find((l) => l.tool === "Squid access.log")!.line).toContain("TCP_MISS/503 200 GET http://err400.example/");
    const bad = act({ kind: "tcp-connect", nodeId: id("laptop-1"), dst: "192.168.0.10", port: 3128 }).find((e) => e.kind === "proxy.fail")!;
    const line = practitionerLines(bad, {}).find((l) => l.tool === "Squid access.log")!.line;
    expect(line).toContain("TAG_NONE/400 200 GET / - HIER_NONE/-");
  });

  it("루프백: 프록시가 자기 웹 서버를 대상으로 하면 응답 뒤에 '받아 오는 대로 보냄' ACK 를 또 보내지 않는다", () => {
    const t = edit(exampleProxyTopology(), "proxy-1", (d) => host(d, { services: [80] }));
    const { id, act, lastConn } = loadTopology(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.10", port: 80 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    expect(tr.filter((e) => e.summary.includes("응답은 뒤 서버에서 받아 오는 대로 보냄"))).toHaveLength(0);
  });

  it("구성 검사 proxy.port-clash: 같은 장비의 로드밸런서가 프록시 포트를 먼저 받음", () => {
    const t = edit(exampleProxyTopology(), "proxy-1", (d) => host(d, { lb: { enabled: true, port: 3128, algorithm: "round-robin", backends: [{ ip: "192.168.0.10", port: 80 }] } }));
    expect(lintTopology(t).map((i) => i.code)).toContain("proxy.port-clash");
  });
});

describe("리뷰 회귀: 쿠키 사이트 키", () => {
  it("쿠키는 브라우저처럼 호스트 이름으로 저장해, 직접 접속과 프록시 경유가 같은 쿠키를 쓴다", () => {
    let t = exampleLoadBalancerTopology();
    // web-3 을 이 사무실 DNS 서버로: shop.local → lb-1
    t = edit(t, "web-3", (d) => host(d, { dnsServer: { enabled: true, records: [{ name: "shop.local", ip: "192.168.0.20" }], upstream: "" } }));
    t = edit(t, "pc-1", (d) => host(d, { ipMode: "static", ip: "192.168.0.50", prefix: 24, gateway: "192.168.0.1", dns: "192.168.0.13" }));
    t = edit(t, "nginx 서버", (d) => host(d, { dns: "192.168.0.13", lb: { ...d.host!.lb!, enabled: false }, proxy: { enabled: true, port: 3128, deny: [] } }));
    t = edit(t, "lb-1", (d) => host(d, { lb: { ...d.host!.lb!, algorithm: "round-robin", sticky: "cookie" } }));
    const { id, act, apply, host: h, lastConn } = loadTopology(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "shop.local", port: 80 });
    const cookie = h("pc-1").tcp.cookies.get("shop.local");
    expect(cookie).toMatch(/^SERVERID=/);
    apply(edit(t, "pc-1", (d) => host(d, { httpProxy: { enabled: true, server: "192.168.0.10", port: 3128 } })));
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "shop.local", port: 80 });
    expect(lastConn("pc-1")).toMatchObject({ target: "shop.local:80", cookie, state: "CLOSED" });
    expect(lastConn("pc-1").setCookie).toBeUndefined();
  });
});
