// HTTPS (TLS 1.3 축소판) + 포워드 프록시 CONNECT 터널
// - 직접: ClientHello(SNI) → ServerHello·인증서·Finished → Finished → 암호화된 요청·응답
// - 프록시: CONNECT 호스트:443 → 200 Connection established → 같은 연결로 대상과 TLS, 프록시는 바이트만 넘긴다
import { describe, expect, it } from "vitest";
import { exampleLoadBalancerTopology, exampleProxyTopology } from "../src/model/examples";
import type { Device, Topology } from "../src/model/topology";
import type { TcpConn } from "../src/core/nodes/tcp";
import { loadTopology } from "./helpers";

const PROXY = "192.168.0.10";
const kinds = (tr: { kind: string }[], prefix: string) => tr.filter((e) => e.kind.startsWith(prefix)).map((e) => e.kind);
const edit = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });
const services = (t: Topology, name: string, ports: number[]) => edit(t, name, (d) => ({ ...d, host: { ...d.host!, services: ports } }));
const settled = (c: TcpConn) => c.state === "CLOSED" || c.state === "FAILED";

describe("HTTPS 직접 연결", () => {
  it("주소로 접속: ClientHello(SNI 없음) → ServerHello·인증서 → Finished → 암호화된 요청·응답 → FIN", () => {
    const t = services(exampleLoadBalancerTopology(), "web-1", [80, 443]);
    const { id, act, lastConn, serverConns } = loadTopology(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.11", port: 443 });
    expect(kinds(tr.filter((e) => e.nodeId === id("pc-1")), "tls.")).toEqual(["tls.hello", "tls.established"]);
    expect(kinds(tr.filter((e) => e.nodeId === id("web-1")), "tls.")).toEqual(["tls.hello", "tls.established"]);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 200", bytesReceived: 1400 + 3000, tls: { done: true, sent: 0 } });
    expect(lastConn("pc-1").tls!.sni).toBeUndefined();
    expect(serverConns("web-1").at(-1)).toMatchObject({ state: "CLOSED", localPort: 443, tls: { done: true, sent: 1400 } });
    // 요청은 TLS 안: 받은 쪽에서 "복호화" 로 보인다
    expect(tr.some((e) => e.nodeId === id("web-1") && e.kind === "tcp.data.received" && e.summary.includes("복호화: GET /"))).toBe(true);
  });

  it("이름으로 접속하면 SNI 를 싣고, 인터넷 서버도 443 을 받는다", () => {
    const { id, act, lastConn, s } = loadTopology(exampleLoadBalancerTopology());
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "github.com", port: 443 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 200", tls: { done: true, sni: "github.com" } });
    const inet = [...s.net.nodes.values()].find((n) => n.constructor.name === "Internet") as unknown as { tcp: { conns: Map<string, TcpConn> } };
    expect([...inet.tcp.conns.values()].at(-1)!.tls).toMatchObject({ done: true, sni: "github.com" });
  });

  it("443 을 열지 않은 서버는 RST 로 거부한다", () => {
    const { id, act, lastConn } = loadTopology(exampleLoadBalancerTopology());
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.11", port: 443 });
    expect(lastConn("pc-1")).toMatchObject({ state: "FAILED", reason: "연결 거부 (RST)" });
  });

  it("443 에서 TLS 가 아닌 답이 오면 핸드셰이크 실패 (프록시가 443 을 듣는 등)", () => {
    const t = edit(exampleProxyTopology(), "proxy-1", (d) => ({ ...d, host: { ...d.host!, proxy: { ...d.host!.proxy!, port: 443 } } }));
    const { id, act, lastConn } = loadTopology(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("laptop-1"), dst: PROXY, port: 443 });
    expect(tr.some((e) => e.nodeId === id("laptop-1") && e.kind === "tls.fail")).toBe(true);
    expect(lastConn("laptop-1")).toMatchObject({ state: "FAILED", reason: "TLS 핸드셰이크 실패 · 상대가 TLS 로 답하지 않음", status: "HTTP 400 Bad Request" });
  });

  it("루프백: 내 주소의 443 으로 HTTPS", () => {
    const t = services(exampleLoadBalancerTopology(), "web-1", [80, 443]);
    const { id, act, host } = loadTopology(t);
    act({ kind: "tcp-connect", nodeId: id("web-1"), dst: "192.168.0.11", port: 443 });
    const conns = [...host("web-1").tcp.conns.values()];
    expect(conns.every(settled)).toBe(true);
    expect(conns.find((c) => c.role === "client")).toMatchObject({ state: "CLOSED", status: "HTTP 200", tls: { done: true } });
  });

  it("케이블 손실이 있어도 재전송으로 핸드셰이크·응답을 끝낸다", () => {
    const t = services(exampleLoadBalancerTopology(), "web-1", [443]);
    const { id, act, lastConn, s, t: topo } = loadTopology(t);
    const cable = topo.cables.find((c) => c.a.device === id("web-1") || c.b.device === id("web-1"))!;
    s.net.setLinkLoss(cable.id, 0.3);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.11", port: 443 });
    const c = lastConn("pc-1");
    expect(c).toMatchObject({ state: "CLOSED", status: "HTTP 200", bytesReceived: 4400 });
    expect(s.net.trace.some((e) => e.kind === "tcp.retransmit")).toBe(true);
  });
});

describe("프록시 CONNECT 터널", () => {
  it("예제: pc-1 의 HTTPS 는 CONNECT 로 터널을 열고, TLS 는 대상과 직접 — 프록시는 내용을 모른다", () => {
    const { id, act, lastConn, host } = loadTopology(exampleProxyTopology());
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "github.com", port: 443 });
    expect(tr.filter((e) => e.nodeId === id("pc-1") && e.kind === "dns.query.sent")).toHaveLength(0);
    expect(kinds(tr.filter((e) => e.nodeId === id("pc-1")), "proxy.")).toEqual(["proxy.use", "proxy.tunnel"]);
    expect(kinds(tr.filter((e) => e.nodeId === id("proxy-1")), "proxy.")).toEqual(["proxy.request", "proxy.tunnel", "proxy.relay"]);
    expect(kinds(tr.filter((e) => e.nodeId === id("pc-1")), "tls.")).toEqual(["tls.hello", "tls.established"]);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", remoteIp: PROXY, remotePort: 3128, target: "github.com:443", method: "CONNECT", tunnel: "up", status: "HTTP 200", tls: { done: true, sni: "github.com" } });
    // 프록시의 대상 쪽 연결은 중계일 뿐 — TLS 를 하지 않는다
    expect(lastConn("proxy-1")).toMatchObject({ state: "CLOSED", remotePort: 443, relay: true });
    expect(lastConn("proxy-1").tls).toBeUndefined();
    expect([...host("proxy-1").tcp.conns.values()].every(settled)).toBe(true);
    // 프록시의 기록에는 요청 줄·응답 내용이 없다 (암호화) — SNI 는 보인다
    const atProxy = tr.filter((e) => e.nodeId === id("proxy-1"));
    expect(atProxy.some((e) => e.summary.includes("GET /") || e.summary.includes("HTTP 200 ("))).toBe(false);
    expect(atProxy.some((e) => e.summary.includes("SNI github.com"))).toBe(true);
    expect(host("proxy-1").proxy.rows()[0]).toEqual([lastConn("pc-1").localIp, "CONNECT github.com:443", "TCP_TUNNEL/200"]);
  });

  it("차단 목록의 도메인은 터널을 열지 않고 403 (HTTPS 도 도메인 단위로 막힌다)", () => {
    const { id, act, lastConn, host } = loadTopology(exampleProxyTopology());
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "www.naver.com", port: 443 });
    expect(kinds(tr, "proxy.")).toEqual(["proxy.use", "proxy.deny"]);
    expect(tr.some((e) => e.kind.startsWith("tls."))).toBe(false);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 403 Forbidden", tunnel: "wait" });
    expect(host("proxy-1").proxy.rows()[0]).toEqual([lastConn("pc-1").localIp, "CONNECT www.naver.com:443", "TCP_DENIED/403"]);
  });

  it("이름을 못 찾거나 대상이 거부하면 503 (NONE/503)", () => {
    const { id, act, lastConn, host } = loadTopology(exampleProxyTopology());
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "nope.example", port: 443 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 503 Service Unavailable" });
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.1", port: 443 });
    expect(kinds(tr, "proxy.")).toEqual(["proxy.use", "proxy.request", "proxy.fail"]);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 503 Service Unavailable" });
    expect(host("proxy-1").proxy.rows().slice(0, 2).map((r) => r[2])).toEqual(["NONE/503", "NONE/503"]);
  });

  it("프록시 설정이 없는 laptop-1 의 HTTPS 는 직접 나가다 방화벽에 막힌다", () => {
    const { id, act, lastConn } = loadTopology(exampleProxyTopology());
    const tr = act({ kind: "tcp-connect", nodeId: id("laptop-1"), dst: "93.184.216.34", port: 443 });
    expect(tr.some((e) => e.kind.startsWith("proxy."))).toBe(false);
    expect(tr.some((e) => e.kind === "fw.deny")).toBe(true);
    expect(lastConn("laptop-1")).toMatchObject({ state: "FAILED" });
  });

  it("프록시가 아닌 곳을 가리키면: 웹 서버는 405, HTTPS 서버는 평문 요청이라 400", () => {
    const base = services(exampleLoadBalancerTopology(), "web-1", [80, 443]);
    const at = (port: number) => edit(base, "pc-1", (d) => ({ ...d, host: { ...d.host!, httpProxy: { enabled: true, server: "192.168.0.11", port } } }));
    const web = loadTopology(at(80));
    web.act({ kind: "tcp-connect", nodeId: web.id("pc-1"), dst: "github.com", port: 443 });
    expect(web.lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 405 Method Not Allowed" });
    const tls = loadTopology(at(443));
    const tr = tls.act({ kind: "tcp-connect", nodeId: tls.id("pc-1"), dst: "github.com", port: 443 });
    expect(tr.some((e) => e.nodeId === tls.id("web-1") && e.kind === "tls.fail")).toBe(true);
    expect(tls.lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 400 Bad Request" });
  });

  it("루프백: 프록시 자신의 443 으로 CONNECT, 프록시 장비가 자기 프록시를 거쳐 HTTPS", () => {
    const t = services(exampleProxyTopology(), "proxy-1", [443]);
    const { id, act, lastConn, host } = loadTopology(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: PROXY, port: 443 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 200", tunnel: "up" });
    expect([...host("proxy-1").tcp.conns.values()].every(settled)).toBe(true);
    expect(host("proxy-1").proxy.rows()[0]![2]).toBe("TCP_TUNNEL/200");

    const self = edit(exampleProxyTopology(), "proxy-1", (d) => ({ ...d, host: { ...d.host!, httpProxy: { enabled: true, server: PROXY, port: 3128 } } }));
    const l = loadTopology(self);
    l.act({ kind: "tcp-connect", nodeId: l.id("proxy-1"), dst: "github.com", port: 443 });
    const mine = [...l.host("proxy-1").tcp.conns.values()].find((c) => c.role === "client" && c.method === "CONNECT")!;
    expect(mine).toMatchObject({ state: "CLOSED", status: "HTTP 200", tls: { done: true, sni: "github.com" } });
    expect([...l.host("proxy-1").tcp.conns.values()].every(settled)).toBe(true);
  });

  it("터널이 열린 뒤 대상 쪽이 끊기면 프록시가 클라이언트 연결도 끊는다 (영원히 기다리지 않음)", () => {
    const t = exampleProxyTopology();
    const { id, s, lastConn, host } = loadTopology(t);
    const wan = t.cables.find((c) => c.a.device === id("internet-1") || c.b.device === id("internet-1"))!;
    s.net.scheduleAction(s.net.now, { kind: "tcp-connect", nodeId: id("pc-1"), dst: "93.184.216.34", port: 443 });
    // 터널이 열릴 때까지 돌린 뒤 인터넷 쪽 링크를 끊는다
    while (!s.net.trace.some((e) => e.kind === "proxy.tunnel" && e.nodeId === id("proxy-1"))) s.net.step();
    s.net.setLinkLoss(wan.id, 1);
    s.net.runToIdle();
    expect(settled(lastConn("pc-1"))).toBe(true);
    expect(lastConn("pc-1").status).toBeUndefined();
    expect([...host("proxy-1").tcp.conns.values()].every(settled)).toBe(true);
    expect(host("proxy-1").proxy.rows()[0]![2]).toBe("TCP_TUNNEL/200");
  });
});

describe("로드밸런서와 HTTPS", () => {
  const lbAt = (patch: object, web: number[]) => {
    let t = edit(exampleLoadBalancerTopology(), "lb-1", (d) => ({ ...d, host: { ...d.host!, lb: { ...d.host!.lb!, ...patch } } }));
    for (const n of ["web-1", "web-2", "web-3"]) t = services(t, n, web);
    return t;
  };

  it("L7 이 443 을 받으면 TLS 를 풀고 백엔드에는 80 평문으로 (TLS 종료), 쿠키 고정도 된다", () => {
    const t = lbAt({ port: 443, algorithm: "round-robin", sticky: "cookie" }, [80]);
    const { id, act, lastConn, serverConns, host } = loadTopology(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 443 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 200", servedBy: "192.168.0.11", tls: { done: true } });
    expect(lastConn("lb-1")).toMatchObject({ remotePort: 80, state: "CLOSED" });
    expect(lastConn("lb-1").tls).toBeUndefined();
    expect(host("pc-1").tcp.cookies.get("192.168.0.20")).toBe("SERVERID=192.168.0.11:80");
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 443 });
    expect(["web-1", "web-2", "web-3"].map((n) => serverConns(n).length)).toEqual([2, 0, 0]);
  });

  it("백엔드도 443 이면 다시 암호화해서 보낸다", () => {
    const t = lbAt({ port: 443, backends: [{ ip: "192.168.0.11", port: 443 }] }, [443]);
    const { id, act, lastConn } = loadTopology(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 443 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 200" });
    expect(lastConn("lb-1")).toMatchObject({ remotePort: 443, state: "CLOSED", tls: { done: true } });
  });

  it("L7 은 CONNECT 를 중계하지 않아 405, L4 는 프록시 팜 앞에서 터널을 그대로 넘긴다", () => {
    const proxyFarm = (mode: "l4" | "l7") => {
      let t = edit(exampleLoadBalancerTopology(), "nginx 서버", (d) => ({ ...d, host: { ...d.host!, lb: { ...d.host!.lb!, enabled: false }, proxy: { enabled: true, port: 3128, deny: [] } } }));
      t = edit(t, "lb-1", (d) => ({ ...d, host: { ...d.host!, lb: { ...d.host!.lb!, mode, port: 3128, backends: [{ ip: PROXY, port: 3128 }] } } }));
      return edit(t, "pc-1", (d) => ({ ...d, host: { ...d.host!, httpProxy: { enabled: true, server: "192.168.0.20", port: 3128 } } }));
    };
    const l7 = loadTopology(proxyFarm("l7"));
    const tr = l7.act({ kind: "tcp-connect", nodeId: l7.id("pc-1"), dst: "github.com", port: 443 });
    expect(tr.some((e) => e.nodeId === l7.id("lb-1") && e.kind === "lb.fail")).toBe(true);
    expect(l7.lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 405 Method Not Allowed" });
    const l4 = loadTopology(proxyFarm("l4"));
    l4.act({ kind: "tcp-connect", nodeId: l4.id("pc-1"), dst: "github.com", port: 443 });
    expect(l4.lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 200", tunnel: "up", tls: { done: true } });
  });
});
