// 로드밸런서 액티브 헬스 체크 (배경 타이머, HAProxy check inter 2s fall 3 rise 2)
// 요청이 오기 전에 죽은 백엔드를 빼고, 살아나면 다시 넣는다. 체크는 시간이 흐를 때만 돈다
import { describe, expect, it } from "vitest";
import { exampleLoadBalancerTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Device, Topology } from "../src/model/topology";
import { practitionerLines } from "../src/model/packetView";
import { loadTopology } from "./helpers";

const edit = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });
const lb = (t: Topology, patch: object) => edit(t, "lb-1", (d) => ({ ...d, host: { ...d.host!, lb: { ...d.host!.lb!, ...patch } } }));
const withCheck = (patch: object = {}) => lb(exampleLoadBalancerTopology(), { healthCheck: true, algorithm: "round-robin", ...patch });
const services = (t: Topology, name: string, ports: number[]) => edit(t, name, (d) => ({ ...d, host: { ...d.host!, services: ports } }));

describe("로드밸런서 액티브 헬스 체크", () => {
  it("꺼져 있으면(기본) 배경 타이머가 없고, 켜도 시간이 흐르기 전에는 체크하지 않는다", () => {
    const off = loadTopology(exampleLoadBalancerTopology());
    expect(off.s.net.peekBackgroundTime()).toBeUndefined();
    const t = withCheck();
    expect(lintTopology(t)).toEqual([]);
    const { s, id } = loadTopology(t);
    expect(s.net.trace.some((e) => e.nodeId === id("lb-1") && e.summary.includes("헬스 체크 (연결되는지만"))).toBe(false);
    expect(s.net.peekBackgroundTime()).toBeDefined();
    const from = s.net.trace.length;
    s.net.runUntil(s.net.now + 2500);
    const probes = s.net.trace.slice(from).filter((e) => e.nodeId === id("lb-1") && e.kind === "tcp.connect");
    expect(probes).toHaveLength(3);
    // 성공이 이어지는 동안은 헬스 체크 줄이 없다 (연결 패킷만)
    expect(s.net.trace.slice(from).some((e) => e.kind === "lb.check" || e.kind === "lb.down")).toBe(false);
    s.net.runToIdle();
    expect(s.net.peekNextTime()).toBeUndefined(); // 체크가 끝나면 조용해진다
  });

  it("백엔드가 포트를 닫으면 3번 연속 실패 뒤 DOWN — 그 뒤 요청은 처음부터 그 백엔드로 가지 않는다 (패시브는 한 번 실패해야 앎)", () => {
    const t = services(withCheck(), "web-2", []);
    const { s, id, act, host, serverConns } = loadTopology(t);
    const from = s.net.trace.length;
    s.net.runUntil(s.net.now + 6500);
    const tr = s.net.trace.slice(from).filter((e) => e.nodeId === id("lb-1"));
    expect(tr.filter((e) => e.kind === "lb.check").map((e) => e.summary)).toEqual([
      "헬스 체크: 백엔드 192.168.0.12:80 실패 1/3 — 연결 거부 (RST, Layer4 connection problem)",
      "헬스 체크: 백엔드 192.168.0.12:80 실패 2/3 — 연결 거부 (RST, Layer4 connection problem)",
    ]);
    const down = tr.find((e) => e.kind === "lb.down")!;
    expect(down.summary).toContain("3번 연속 실패");
    expect(practitionerLines(down, {})[0]!.line).toBe("Server backend/192.168.0.12:80 is DOWN, reason: Layer4 connection problem. 2 active and 0 backup servers left.");
    expect(host("lb-1").lb.rows(s.net.now)[1]![1]).toBe("DOWN (헬스 체크: 연결 거부 (RST, Layer4 connection problem))");
    // 라운드 로빈 세 번: web-2 는 건너뛰고, 실패한 요청(재시도)도 없다
    for (let k = 0; k < 3; k++) {
      const r = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
      expect(r.some((e) => e.kind === "lb.down" && !e.summary.includes("헬스 체크"))).toBe(false);
    }
    expect(serverConns("web-2").filter((c) => !c.probe && c.bytesReceived > 0)).toHaveLength(0);
  });

  it("말없이 죽은 백엔드(케이블 손실 100%): timeout 3번이면 DOWN, 그동안 runToIdle 은 끝난다 (SYN 재전송 없음)", () => {
    const l = loadTopology(withCheck());
    const { s, id, t, host } = l;
    const web3 = t.cables.find((c) => c.a.device === id("web-3") || c.b.device === id("web-3"))!;
    s.net.setLinkLoss(web3.id, 1);
    s.net.runUntil(s.net.now + 8500);
    expect(host("lb-1").lb.rows(s.net.now)[2]![1]).toContain("DOWN (헬스 체크: 2초 동안 응답 없음 (Layer4 timeout))");
    // 배경 타이머만 남으면 멈춘다 — 체크가 일반 타이머를 남기지 않는다
    expect(s.net.runToIdle(2000)).toBeLessThan(2000);
    expect(s.net.peekNextTime()).toBeUndefined();
  });

  it("살아나면 2번 연속 응답 뒤 UP 으로 돌아온다", () => {
    const t = withCheck();
    const { s, id, apply, host } = loadTopology(services(t, "web-2", []));
    s.net.runUntil(s.net.now + 6500);
    expect(host("lb-1").lb.rows(s.net.now)[1]![1]).toContain("DOWN");
    apply(t);
    const from = s.net.trace.length;
    s.net.runUntil(s.net.now + 4500);
    const up = s.net.trace.slice(from).filter((e) => e.nodeId === id("lb-1") && e.kind === "lb.check");
    expect(up.map((e) => e.summary)).toEqual(["헬스 체크: 백엔드 192.168.0.12:80 응답 1/2 (아직 DOWN)", "헬스 체크: 백엔드 192.168.0.12:80 2번 연속 응답 → UP, 다시 요청을 보냄 (살아 있는 백엔드 3대)"]);
    expect(practitionerLines(up[1]!, {})[0]!.line).toBe("Server backend/192.168.0.12:80 is UP, reason: Layer4 check passed. 3 active and 0 backup servers online.");
    expect(host("lb-1").lb.rows(s.net.now)[1]![1]).toBe("사용 중 · 헬스 체크 정상");
  });

  it("L4 모드에서도 체크하고, 체크 응답은 L4 변환에 걸리지 않는다", () => {
    const t = services(withCheck({ mode: "l4" }), "web-1", []);
    const { s, act, id, host } = loadTopology(t);
    s.net.runUntil(s.net.now + 6500);
    expect(host("lb-1").lb.rows(s.net.now).map((r) => r[1])).toEqual(["DOWN (헬스 체크: 연결 거부 (RST, Layer4 connection problem))", "사용 중 · 헬스 체크 정상", "사용 중 · 헬스 체크 정상"]);
    act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    expect([...host("pc-1").tcp.conns.values()].at(-1)).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    expect(s.net.trace.some((e) => e.kind === "lb.fail" && e.summary.includes("흐름 기록이 없음"))).toBe(false);
  });

  it("루프백: 백엔드가 로드밸런서 자신이어도 체크가 끝나고, 끄면 체크가 멈춘다", () => {
    const t = withCheck({ backends: [{ ip: "192.168.0.20", port: 80 }, { ip: "192.168.0.11", port: 80 }] });
    const { s, id, apply, host } = loadTopology(t);
    s.net.runUntil(s.net.now + 4500);
    s.net.runToIdle();
    expect(host("lb-1").lb.rows(s.net.now).map((r) => r[1])).toEqual(["사용 중 · 헬스 체크 정상", "사용 중 · 헬스 체크 정상"]);
    expect([...host("lb-1").tcp.conns.values()].every((c) => c.state === "CLOSED" || c.state === "FAILED")).toBe(true);
    apply(lb(t, { healthCheck: false }));
    const from = s.net.trace.length;
    s.net.runUntil(s.net.now + 6000);
    expect(s.net.trace.slice(from).some((e) => e.nodeId === id("lb-1") && e.kind === "tcp.connect")).toBe(false);
  });
});
