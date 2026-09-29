// 로드밸런서 쿠키 세션 고정 (L7): 첫 응답에 Set-Cookie: SERVERID=<백엔드>, 브라우저가 다음 요청에 Cookie 로 실어 보내면 같은 백엔드
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import { exampleLoadBalancerTopology } from "../src/model/examples";
import { normalizeTopology, type Topology } from "../src/model/topology";
import { loadTopology } from "./helpers";

type LbPatch = Partial<NonNullable<NonNullable<Topology["devices"][number]["host"]>["lb"]>>;
function withLb(patch: LbPatch, name = "lb-1", t: Topology = exampleLoadBalancerTopology()): Topology {
  return { ...t, devices: t.devices.map((d) => (d.name === name ? { ...d, host: { ...d.host!, lb: { ...d.host!.lb!, ...patch } } } : d)) };
}
const LB = "192.168.0.20";
const used = (serverConns: (n: string) => unknown[]) => ["web-1", "web-2", "web-3"].map((n) => serverConns(n).length);

describe("쿠키 세션 고정", () => {
  it("첫 응답에 Set-Cookie 를 넣고, 같은 브라우저의 다음 요청은 Cookie 로 같은 백엔드에 간다 (다시 심지 않음)", () => {
    const t = withLb({ algorithm: "round-robin", sticky: "cookie" });
    expect(lintTopology(t)).toEqual([]);
    const { id, act, host, lastConn, serverConns } = loadTopology(t);
    const first = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: LB, port: 80 });
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", bytesReceived: 3000, setCookie: "SERVERID=192.168.0.11:80" });
    expect(lastConn("pc-1").cookie).toBeUndefined();
    expect(first.filter((e) => e.kind === "tcp.cookie").map((e) => e.nodeId)).toEqual([id("pc-1")]);
    expect(host("pc-1").tcp.cookies.get(LB)).toBe("SERVERID=192.168.0.11:80");

    for (let k = 0; k < 2; k++) {
      const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: LB, port: 80 });
      expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", cookie: "SERVERID=192.168.0.11:80" });
      expect(lastConn("pc-1").setCookie).toBeUndefined();
      expect(tr.find((e) => e.kind === "lb.pick")!.summary).toContain("쿠키 고정");
    }
    expect(used(serverConns)).toEqual([3, 0, 0]);
    // 쿠키가 없는 다른 브라우저는 분배 방식대로 다음 차례
    act({ kind: "tcp-connect", nodeId: id("laptop-1"), dst: LB, port: 80 });
    expect(lastConn("laptop-1").setCookie).toBe("SERVERID=192.168.0.12:80");
    expect(used(serverConns)).toEqual([3, 1, 0]);
  });

  it("LB 가 백엔드에 연결할 때는 브라우저 쿠키를 싣지 않고, 백엔드가 본 요청에도 쿠키가 없다", () => {
    const t = withLb({ sticky: "cookie" });
    const { id, act, serverConns } = loadTopology(t);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: LB, port: 80 });
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: LB, port: 80 });
    expect(serverConns("web-1").map((c) => c.cookie)).toEqual([undefined, undefined]);
  });

  it("쿠키가 가리키는 백엔드가 빠지면 다시 골라 새 쿠키를 심는다", () => {
    const base = withLb({ algorithm: "round-robin", sticky: "cookie" });
    const { id, act, apply, lastConn, host } = loadTopology(base);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: LB, port: 80 });
    expect(host("pc-1").tcp.cookies.get(LB)).toBe("SERVERID=192.168.0.11:80");
    apply({ ...base, devices: base.devices.map((d) => (d.name === "web-1" ? { ...d, host: { ...d.host!, services: [] } } : d)) });
    const tr = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: LB, port: 80 });
    expect(tr.some((e) => e.kind === "lb.down")).toBe(true);
    expect(lastConn("pc-1")).toMatchObject({ state: "CLOSED", bytesReceived: 3000, setCookie: "SERVERID=192.168.0.12:80" });
    expect(host("pc-1").tcp.cookies.get(LB)).toBe("SERVERID=192.168.0.12:80");
    // web-1 은 10초 동안 빠져 있다: 쿠키가 web-1 을 가리키던 요청이 와도 다시 고르고 이유를 남긴다
    host("pc-1").tcp.cookies.set(LB, "SERVERID=192.168.0.11:80");
    const again = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: LB, port: 80 });
    expect(again.find((e) => e.kind === "lb.pick")!.summary).toContain("쿠키가 가리키는 192.168.0.11:80 는 빠져 있거나 없어 다시 고름");
  });

  it("L4 는 HTTP 를 보지 않아 쿠키 고정이 동작하지 않는다: 쿠키 없이 연결마다 분배 방식대로", () => {
    const t = withLb({ mode: "l4", algorithm: "round-robin", sticky: "cookie" });
    const { id, act, lastConn, serverConns } = loadTopology(t);
    for (let k = 0; k < 2; k++) act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: LB, port: 80 });
    expect(lastConn("pc-1").setCookie).toBeUndefined();
    expect(used(serverConns)).toEqual([1, 1, 0]);
  });

  it("예전 저장본의 세션 고정 true 는 출발지 IP 로 읽는다", () => {
    const old = withLb({ sticky: true as unknown as "ip" });
    const lb = normalizeTopology(old).devices.find((d) => d.name === "lb-1")!.host!.lb!;
    expect(lb.sticky).toBe("ip");
  });
});
