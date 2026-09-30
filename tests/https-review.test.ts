// 리뷰 재현: 6ea2401 "HTTPS(TLS 1.3 축소판) + 포워드 프록시 CONNECT 터널" 의 결함. 모두 지금 코드에서 실패해야 한다 (고치면 통과)
import { describe, expect, it } from "vitest";
import { exampleLoadBalancerTopology, exampleProxyTopology } from "../src/model/examples";
import type { Device, Topology } from "../src/model/topology";
import type { NodeContext } from "../src/core/nodes/node";
import { ForwardProxy } from "../src/core/nodes/proxy";
import { TcpStack, type TcpConn } from "../src/core/nodes/tcp";
import type { TraceEvent } from "../src/core/trace";
import { practitionerLines } from "../src/model/packetView";
import { loadTopology } from "./helpers";

const PROXY = "192.168.0.10";
const edit = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });
const services = (t: Topology, name: string, ports: number[]) => edit(t, name, (d) => ({ ...d, host: { ...d.host!, services: ports } }));
const lb = (t: Topology, patch: object) => edit(t, "lb-1", (d) => ({ ...d, host: { ...d.host!, lb: { ...d.host!.lb!, ...patch } } }));

describe("리뷰 결함: HTTPS·CONNECT (6ea2401)", () => {
  it("1. L7 로드밸런서 443(TLS 종료): 백엔드가 느려도 받은 요청을 곧바로 ACK 해 클라이언트가 요청을 재전송하지 않는다 (HTTP 80 과 같게)", () => {
    // 첫 백엔드는 없는 주소 → LB 가 SYN timeout(5초 남짓)을 기다리는 동안 클라이언트 요청은 ACK 를 받아야 한다
    const mk = (port: number) => lb(exampleLoadBalancerTopology(), { port, algorithm: "round-robin", backends: [{ ip: "192.168.0.99", port: 80 }, { ip: "192.168.0.11", port: 80 }] });
    const http = loadTopology(mk(80));
    http.act({ kind: "tcp-connect", nodeId: http.id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect(http.lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 200", retransmits: 0 });

    const https = loadTopology(mk(443));
    const tr = https.act({ kind: "tcp-connect", nodeId: https.id("pc-1"), dst: "192.168.0.20", port: 443 });
    expect(https.lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 200" });
    // 지금: receiveData 의 `conn.bytesSent === 0` 조건이 TLS(핸드셰이크로 1400B 보냄)에서 늘 거짓 → ACK 가 없어 400ms 뒤 요청 재전송
    expect.soft(tr.some((e) => e.nodeId === https.id("lb-1") && e.kind === "tcp.ack.sent" && e.summary.includes("요청을 받았고"))).toBe(true);
    expect(https.lastConn("pc-1").retransmits).toBe(0);
  });

  it("2. L7 로드밸런서 → 백엔드 443: 백엔드의 TLS 핸드셰이크(ServerHello 1400B)를 응답 크기로 세지 않는다", () => {
    const t = services(lb(exampleLoadBalancerTopology(), { port: 443, backends: [{ ip: "192.168.0.11", port: 443 }] }), "web-1", [443]);
    const { id, act, lastConn } = loadTopology(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 443 });
    // 백엔드 응답 본문은 3000B → LB 도 3000B 를 전달해야 한다 (지금은 4400B, 클라이언트는 LB 의 ServerHello 1400 + 4400 = 5800B)
    expect.soft(tr.find((e) => e.kind === "lb.relay")?.details?.bytes).toBe(3000);
    expect(lastConn("pc-1").bytesReceived).toBe(1400 + 3000);
  });

  it("3. CONNECT 터널은 TLS 안의 Cookie·Set-Cookie·X-Served-By 를 그대로 넘긴다 — 프록시를 거쳐도 쿠키 세션 고정이 된다", () => {
    let t = lb(exampleLoadBalancerTopology(), { port: 443, algorithm: "round-robin", sticky: "cookie", backends: [{ ip: "192.168.0.11", port: 80 }, { ip: "192.168.0.12", port: 80 }] });
    t = edit(t, "web-3", (d) => ({ ...d, host: { ...d.host!, proxy: { enabled: true, port: 3128, deny: [] } } }));
    t = edit(t, "pc-1", (d) => ({ ...d, host: { ...d.host!, httpProxy: { enabled: true, server: "192.168.0.13", port: 3128 } } }));
    const { id, act, lastConn, host, serverConns } = loadTopology(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 443 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 200", tunnel: "up" });
    // 지금: proxy.onRelay 가 len·data·tls·sni 만 복사 → Set-Cookie·origin 이 사라진다
    expect.soft(lastConn("pc-1").servedBy).toBe("192.168.0.11");
    expect.soft(host("pc-1").tcp.cookies.get("192.168.0.20")).toBe("SERVERID=192.168.0.11:80");
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 443 });
    expect(["web-1", "web-2"].map((n) => serverConns(n).length)).toEqual([2, 0]);
  });

  it("4. 터널 반대편 실패로 프록시가 RST 를 보내면, 클라이언트 연결이 성공(초록 '종료됨')으로 보이지 않는다", () => {
    const t = exampleProxyTopology();
    const { id, s, lastConn } = loadTopology(t);
    const wan = t.cables.find((c) => c.a.device === id("internet-1") || c.b.device === id("internet-1"))!;
    s.net.scheduleAction(s.net.now, { kind: "tcp-connect", nodeId: id("pc-1"), dst: "93.184.216.34", port: 443 });
    while (!s.net.trace.some((e) => e.kind === "proxy.tunnel" && e.nodeId === id("proxy-1"))) s.net.step();
    s.net.setLinkLoss(wan.id, 1);
    s.net.runToIdle();
    const c = lastConn("pc-1");
    expect(c.status).toBeUndefined(); // 응답은 한 바이트도 못 받았다 (받은 것은 CONNECT 200 40B 뿐)
    // diag.tsx 의 "ok" 색(CLOSED && 받음 > 0 && 4xx·5xx 아님)과 reach.ts probeTargets 의 ok 판정이 같은 조건이다.
    // 지금: RST 수신 → state CLOSED("상대가 RST 로 끊음"), bytesReceived 40 → 초록 "종료됨 · 받음 40B", 자동완성은 닿음으로 판정
    const looksOk = c.state === "CLOSED" && c.bytesReceived > 0 && !/^HTTP [45]/.test(c.status ?? "");
    expect(looksOk).toBe(false);
  });

  it("5. (회귀) http_proxy 가 포트 443 에서 듣는 프록시를 가리켜도 HTTP(80) 요청은 평문 절대 URI 로 보낸다 — 이전 커밋에서는 됐다", () => {
    let t = edit(exampleProxyTopology(), "proxy-1", (d) => ({ ...d, host: { ...d.host!, proxy: { ...d.host!.proxy!, port: 443 } } }));
    t = edit(t, "pc-1", (d) => ({ ...d, host: { ...d.host!, httpProxy: { enabled: true, server: PROXY, port: 443 } } }));
    const { id, act, lastConn } = loadTopology(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "example.com", port: 80 });
    // 지금: SYN_SENT 에서 remotePort === 443 이면 무조건 ClientHello → 프록시가 400 → 클라이언트 tls.fail
    expect(tr.some((e) => e.kind === "tls.fail")).toBe(false);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 200", target: "example.com:80" });
  });

  it("6. 평문 HTTP 서버(포트 80)는 TLS ClientHello 를 GET 으로 받아 HTTP 200 으로 답하지 않는다 (L4 443 → 백엔드 80, 포트 포워딩 443 → 80 등)", () => {
    const t = lb(exampleLoadBalancerTopology(), { mode: "l4", port: 443, backends: [{ ip: "192.168.0.11", port: 80 }] });
    const { id, act, lastConn } = loadTopology(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 443 });
    expect(lastConn("pc-1").state).toBe("FAILED"); // 클라이언트는 TLS 실패로 끝난다 (이건 맞다)
    // 지금: web-1 은 "데이터 수신: TLS ClientHello" 뒤 "응답 데이터 전송 HTTP 200 (1/3)…" — 서버 로그·표가 정상 처리로 보인다 (nginx 는 400)
    expect(tr.some((e) => e.nodeId === id("web-1") && e.kind === "tcp.data.sent" && e.summary.includes("HTTP 200"))).toBe(false);
  });

  it("7. 터널 반대편이 닫혀 넘기지 못한 데이터: 요약은 '드롭'(용어 목록), Squid access.log 줄을 지어내지 않는다", () => {
    const events: TraceEvent[] = [];
    const ctx = {
      now: 1000,
      send() {},
      isPortConnected: () => true,
      timer: () => ({ cancel() {} }),
      trace: (kind, layer, summary, details) => void events.push({ seq: events.length, time: 1000, nodeId: "proxy", kind, layer, summary, details }),
      nextPacketId: () => 1,
    } as NodeContext;
    const tcp = new TcpStack({ send() {} });
    const proxy = new ForwardProxy(tcp, () => PROXY, () => {});
    proxy.config = { enabled: true, port: 3128, deny: [] };
    const down = { id: "down", role: "server", localIp: PROXY, localPort: 3128, remoteIp: "192.168.0.100", remotePort: 49152, state: "ESTABLISHED", iss: 3000, sndNxt: 3001, sndUna: 3001, rcvNxt: 1101, unacked: [], retransmits: 0, bytesSent: 0, bytesReceived: 100, responseSegments: 3, finReceived: false, createdAt: 0, target: "93.184.216.34:443", method: "CONNECT" } as TcpConn;
    expect(proxy.onRequest(down, ctx)).toBe(true);
    const up = [...tcp.conns.values()].find((c) => c.relay)!;
    up.state = "ESTABLISHED";
    proxy.onEstablished(up, ctx);
    // 대상이 먼저 닫음 (LAST_ACK) → 뒤늦게 클라이언트 데이터가 옴
    up.state = "LAST_ACK";
    proxy.onRelay(down, { kind: "tcp", srcPort: 49152, dstPort: 3128, seq: 1101, ack: 3041, ackFlag: true, len: 100, data: "GET /", tls: "app" }, ctx);
    const ev = events.find((e) => e.kind === "proxy.fail")!;
    expect(ev).toBeDefined();
    expect.soft(ev.summary).toContain("드롭");
    // 지금: result·method 가 없어 "… - 200 GET http://93.184.216.34:443/ - HIER_NONE/- text/html" 같은 가짜 access.log 줄이 나온다
    expect(practitionerLines(ev, {}).filter((l) => l.tool === "Squid access.log")).toEqual([]);
  });
});
