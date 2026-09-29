// 포워드 프록시 (Squid 식): http_proxy 설정 → 프록시가 대신 연결·이름 해석, 차단 목록 403, 실패 503, 대상 없음 400
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import { exampleLoadBalancerTopology, exampleProxyTopology } from "../src/model/examples";
import type { Device, Topology } from "../src/model/topology";
import { denied, splitTarget } from "../src/core/nodes/proxy";
import { loadTopology } from "./helpers";

const PROXY = "192.168.0.10";
const kinds = (tr: { nodeId: string; kind: string }[], prefix: string) => tr.filter((e) => e.kind.startsWith(prefix)).map((e) => e.kind);

describe("포워드 프록시", () => {
  it("예제: pc-1 의 웹 요청은 프록시가 이름을 찾아 대신 받아 온다 (pc-1 은 DNS 질의를 하지 않음)", () => {
    const t = exampleProxyTopology();
    expect(lintTopology(t)).toEqual([]);
    const { id, act, lastConn, host } = loadTopology(t);
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "example.com", port: 80 });
    expect(tr.filter((e) => e.nodeId === id("pc-1") && e.kind === "dns.query.sent")).toHaveLength(0);
    expect(tr.find((e) => e.kind === "proxy.use")!.nodeId).toBe(id("pc-1"));
    expect(kinds(tr.filter((e) => e.nodeId === id("proxy-1")), "proxy.")).toEqual(["proxy.request", "proxy.relay"]);
    expect(tr.some((e) => e.nodeId === id("proxy-1") && e.kind === "dns.query.sent")).toBe(true);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", bytesReceived: 3000, remoteIp: PROXY, remotePort: 3128, target: "example.com:80", servedBy: "93.184.216.34" });
    // 대상 서버에게 연결한 것은 프록시 (인터넷 쪽에서는 공유기 NAT 뒤의 공인 주소)
    expect(lastConn("proxy-1")).toMatchObject({ remoteIp: "93.184.216.34", remotePort: 80, via: 1 });
    expect(host("proxy-1").proxy.rows()[0]).toEqual([lastConn("pc-1").localIp, "example.com:80", "TCP_MISS/200"]);
  });

  it("예제: 프록시 설정이 없는 laptop-1 은 직접 나가다 방화벽에 막히고, pc-1 도 ping 은 막힌다 (프록시는 웹만 대신)", () => {
    const { id, act, lastConn, host } = loadTopology(exampleProxyTopology());
    const tr = act({ kind: "tcp-connect", nodeId: id("laptop-1"), dst: "example.com", port: 80 });
    expect(tr.some((e) => e.kind === "proxy.use")).toBe(false);
    expect(tr.some((e) => e.kind === "fw.deny")).toBe(true);
    expect(lastConn("laptop-1")).toMatchObject({ state: "FAILED" });
    act({ kind: "ping", nodeId: id("pc-1"), dst: "8.8.8.8" });
    expect(host("pc-1").pings.at(-1)!.status).toBe("failed");
  });

  it("차단 목록의 사이트는 대상에 연결하지 않고 403, 이름을 못 찾으면 503", () => {
    const { id, act, lastConn, host } = loadTopology(exampleProxyTopology());
    const before = [...host("proxy-1").tcp.conns.values()].filter((c) => c.role === "client").length;
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "www.naver.com", port: 80 });
    expect(kinds(tr, "proxy.")).toEqual(["proxy.use", "proxy.deny"]);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 403 Forbidden" });
    expect([...host("proxy-1").tcp.conns.values()].filter((c) => c.role === "client").length).toBe(before);

    const nx = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "nope.example", port: 80 });
    expect(kinds(nx, "proxy.")).toEqual(["proxy.use", "proxy.fail"]);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 503 Service Unavailable" });
    expect(host("proxy-1").proxy.rows().slice(0, 2).map((r) => r[2])).toEqual(["TCP_MISS/503", "TCP_DENIED/403"]);
  });

  it("대상이 연결을 거부하면 503, 프록시 설정 없이 프록시 포트로 직접 접속하면 400", () => {
    const { id, act, lastConn } = loadTopology(exampleProxyTopology());
    // 같은 사무실 주소도 웹 요청이면 프록시를 거친다 (http_proxy 는 예외 목록이 없으면 전부)
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.1", port: 80 });
    expect(kinds(tr, "proxy.")).toEqual(["proxy.use", "proxy.request", "proxy.fail"]);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", status: "HTTP 503 Service Unavailable" });
    act({ kind: "tcp-connect", nodeId: id("laptop-1"), dst: PROXY, port: 3128 });
    expect(lastConn("laptop-1")).toMatchObject({ state: "CLOSED", status: "HTTP 400 Bad Request" });
  });

  it("웹(80)이 아닌 포트는 프록시를 거치지 않는다 (SSH 는 직접 나가다 방화벽에 막힘)", () => {
    const { id, act } = loadTopology(exampleProxyTopology());
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "93.184.216.34", port: 22 });
    expect(tr.some((e) => e.kind.startsWith("proxy."))).toBe(false);
    expect(tr.some((e) => e.kind === "fw.deny")).toBe(true);
  });

  it("프록시를 끄면 듣는 포트를 닫고 요청은 거부된다", () => {
    const t = exampleProxyTopology();
    const { id, act, apply, lastConn } = loadTopology(t);
    apply({ ...t, devices: t.devices.map((d) => (d.name === "proxy-1" ? { ...d, host: { ...d.host!, proxy: { ...d.host!.proxy!, enabled: false } } } : d)) });
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "example.com", port: 80 });
    expect(lastConn("pc-1")).toMatchObject({ state: "FAILED", reason: "연결 거부 (RST)" });
  });
});

describe("프록시 뒤의 여러 사람과 로드밸런서 세션 고정", () => {
  // LB 예제의 nginx 서버를 프록시로 바꾸고 두 PC 가 그 프록시를 쓰게 한다: lb-1 에게는 두 PC 가 모두 프록시 주소로 보인다
  function viaProxy(sticky: "ip" | "cookie"): Topology {
    const t = exampleLoadBalancerTopology();
    const patch = (d: Device): Device => {
      if (d.name === "nginx 서버") return { ...d, host: { ...d.host!, lb: { ...d.host!.lb!, enabled: false }, proxy: { enabled: true, port: 3128, deny: [] } } };
      if (d.name === "lb-1") return { ...d, host: { ...d.host!, lb: { ...d.host!.lb!, algorithm: "round-robin", sticky } } };
      if (d.name === "pc-1" || d.name === "laptop-1") return { ...d, host: { ...d.host!, httpProxy: { enabled: true, server: PROXY, port: 3128 } } };
      return d;
    };
    return { ...t, devices: t.devices.map(patch) };
  }
  const used = (serverConns: (n: string) => unknown[]) => ["web-1", "web-2", "web-3"].map((n) => serverConns(n).length);

  it("출발지 IP 고정: 두 PC 가 한 주소(프록시)로 보여 모두 같은 백엔드로 몰린다", () => {
    const { id, act, serverConns } = loadTopology(viaProxy("ip"));
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    act({ kind: "tcp-connect", nodeId: id("laptop-1"), dst: "192.168.0.20", port: 80 });
    expect(used(serverConns)).toEqual([2, 0, 0]);
  });

  it("쿠키 고정: 프록시가 Set-Cookie·Cookie 를 그대로 넘겨 PC 마다 다른 백엔드에 고정된다", () => {
    const { id, act, serverConns, lastConn, host } = loadTopology(viaProxy("cookie"));
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    act({ kind: "tcp-connect", nodeId: id("laptop-1"), dst: "192.168.0.20", port: 80 });
    expect(used(serverConns)).toEqual([1, 1, 0]);
    // 쿠키는 브라우저(PC)가 사이트별로 저장한다. 프록시는 저장하지 않는다
    expect(host("pc-1").tcp.cookies.get("192.168.0.20")).toBe("SERVERID=192.168.0.11:80");
    expect(host("nginx 서버").tcp.cookies.size).toBe(0);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    act({ kind: "tcp-connect", nodeId: id("laptop-1"), dst: "192.168.0.20", port: 80 });
    expect(used(serverConns)).toEqual([2, 2, 0]);
    expect(lastConn("laptop-1").cookie).toBe("SERVERID=192.168.0.12:80");
  });
});

describe("프록시 도우미", () => {
  it("차단 목록: 이름은 하위 이름까지, 주소는 같을 때만", () => {
    expect(denied("naver.com", ["naver.com"])).toBe("naver.com");
    expect(denied("www.NAVER.com", ["naver.com"])).toBe("naver.com");
    expect(denied("notnaver.com", ["naver.com"])).toBeUndefined();
    expect(denied("m.naver.com", ["*.naver.com"])).toBe("*.naver.com");
    expect(denied("93.184.216.34", ["93.184.216.34"])).toBe("93.184.216.34");
    expect(denied("1.93.184.216.34", ["93.184.216.34"])).toBeUndefined();
    expect(denied("example.com", [" ", ""])).toBeUndefined();
  });
  it("대상 나누기", () => {
    expect(splitTarget("example.com:80")).toEqual({ host: "example.com", port: 80 });
    expect(splitTarget("example.com")).toEqual({ host: "example.com", port: 80 });
  });
});

describe("구성 검사: 프록시·쿠키 고정", () => {
  const codes = (t: Topology) => lintTopology(t).map((i) => i.code);
  const edit = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });

  it("proxy.not-running: 가리키는 장비의 프록시가 꺼졌거나 포트가 다를 때만", () => {
    const t = exampleProxyTopology();
    expect(codes(t)).toEqual([]);
    const off = edit(t, "proxy-1", (d) => ({ ...d, host: { ...d.host!, proxy: { ...d.host!.proxy!, enabled: false } } }));
    expect(lintTopology(off).find((i) => i.code === "proxy.not-running")!.message).toContain("모두 거부(RST)");
    const port = edit(t, "pc-1", (d) => ({ ...d, host: { ...d.host!, httpProxy: { enabled: true, server: PROXY, port: 8080 } } }));
    expect(lintTopology(port).find((i) => i.code === "proxy.not-running")!.message).toContain("프록시는 포트 3128 에서 듣는 중");
    // 모르는 주소(어느 장비의 수동 주소도 아님)·설정 꺼짐은 침묵
    expect(codes(edit(t, "pc-1", (d) => ({ ...d, host: { ...d.host!, httpProxy: { enabled: true, server: "10.9.9.9", port: 3128 } } })))).toEqual([]);
    expect(codes(edit(off, "pc-1", (d) => ({ ...d, host: { ...d.host!, httpProxy: { ...d.host!.httpProxy!, enabled: false } } })))).toEqual([]);
  });

  it("lb.cookie-l4: L4 에 쿠키 고정일 때만", () => {
    const t = exampleLoadBalancerTopology();
    const lb = (patch: object) => edit(t, "lb-1", (d) => ({ ...d, host: { ...d.host!, lb: { ...d.host!.lb!, ...patch } } }));
    expect(codes(lb({ mode: "l4", sticky: "cookie" }))).toEqual(["lb.cookie-l4"]);
    expect(codes(lb({ mode: "l4", sticky: "ip" }))).toEqual([]);
    expect(codes(lb({ sticky: "cookie" }))).toEqual([]);
  });

  it("프록시 포트를 포트 포워딩·로드밸런서 백엔드로 가리켜도 닫힌 포트로 보지 않는다", () => {
    const t = edit(exampleProxyTopology(), "공유기", (d) => ({ ...d, router: { ...d.router!, forwards: [{ publicPort: 3128, lanIp: PROXY, lanPort: 3128 }] } }));
    expect(codes(t)).toEqual([]);
  });
});
