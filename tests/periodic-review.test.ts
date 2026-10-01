// 리뷰: 액티브 헬스 체크(59943f7)·주기 DPD(2f503f1) — 배경 타이머로 도는 주기 동작의 결함 재현
import { describe, expect, it } from "vitest";
import { exampleLoadBalancerTopology, exampleVpnTopology } from "../src/model/examples";
import { probeTargets } from "../src/model/reach";
import type { Device, Topology } from "../src/model/topology";
import { loadTopology } from "./helpers";

const edit = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });
const lb = (t: Topology, patch: object) => edit(t, "lb-1", (d) => ({ ...d, host: { ...d.host!, lb: { ...d.host!.lb!, ...patch } } }));
const withCheck = (patch: object = {}) => lb(exampleLoadBalancerTopology(), { healthCheck: true, algorithm: "round-robin", ...patch });
const host = (t: Topology, name: string, patch: object) => edit(t, name, (d) => ({ ...d, host: { ...d.host!, ...patch } }));
/** 그 장치에 붙은 케이블의 손실률 (토폴로지에 저장되는 값 — 화면의 "손실 100%") */
const lossOn = (t: Topology, name: string, loss: number): Topology => {
  const id = t.devices.find((d) => d.name === name)!.id;
  return { ...t, cables: t.cables.map((c) => (c.a.device === id || c.b.device === id ? { ...c, loss } : c)) };
};

describe("리뷰: 액티브 헬스 체크", () => {
  it("[1] 돌아오는 길만 끊긴 백엔드(SYN 은 닿고 SYN·ACK 이 못 돌아옴): 배경 타이머 체크가 백엔드의 SYN·ACK 재전송(일반 타이머)을 끝없이 이어 runToIdle 이 끝나지 않는다", () => {
    // web-3 은 /30 에 게이트웨이 없음 → LB(192.168.0.20) 의 SYN 은 받지만 SYN·ACK 은 No route 로 드롭 (구성 검사가 경고하는 흔한 실수)
    const broken = (hc: boolean) => host(lb(exampleLoadBalancerTopology(), { healthCheck: hc }), "web-3", { prefix: 30, gateway: "" });
    // 대조: 체크를 끄면 같은 구성도 조용해진다
    const off = loadTopology(broken(false));
    off.s.net.runUntil(off.s.net.now + 2500);
    expect(() => off.s.net.runToIdle(10_000)).not.toThrow();
    // 체크를 켜면: 라운드마다 web-3 에 새 SYN_RCVD 연결이 생기고 SYN·ACK 재전송(400·800·1600·2400ms, 일반 타이머)이
    // 다음 라운드(2초)를 넘겨 이어진다 → 일반 이벤트가 끊이지 않아 시계가 멈추지 않는다 (화면도 영원히 돈다)
    const on = loadTopology(broken(true));
    on.s.net.runUntil(on.s.net.now + 2500);
    expect(() => on.s.net.runToIdle(10_000)).not.toThrow();
  });

  it("[2] 죽은 백엔드로 체크 연결을 보낸 채 헬스 체크(또는 로드밸런서)를 끄면 그 연결이 SYN_SENT 로 영원히 남는다 (abandon 하지 않음)", () => {
    for (const patch of [{ healthCheck: false }, { enabled: false }]) {
      const t = lossOn(withCheck(), "web-3", 1);
      const { s, apply, host: node } = loadTopology(t);
      s.net.runUntil(s.net.now + 2500); // 첫 라운드: web-3 으로 간 SYN 은 손실 → SYN_SENT (재전송 타이머 없음)
      expect([...node("lb-1").tcp.conns.values()].some((c) => c.probe && c.state === "SYN_SENT")).toBe(true);
      apply(lb(t, patch));
      s.net.runUntil(s.net.now + 30_000);
      // 끈 뒤 30초가 지나도 체크 연결이 "SYN 보냄 (응답 대기)" 로 TCP 표에 남는다 (prune 은 끝난 연결만 치운다)
      const stuck = [...node("lb-1").tcp.conns.values()].filter((c) => c.probe && c.state === "SYN_SENT");
      expect(stuck.map((c) => `${c.remoteIp} ${c.state}`)).toEqual([]);
    }
  });

  it("[3] 진단 자동완성(probeTargets): 헬스 체크를 켠 로드밸런서에서 TCP 후보를 확인하면 체크 연결을 '내가 연 연결' 로 집어 닿는 서버를 '정상 종료' 실패로 보인다", () => {
    const t = lossOn(withCheck(), "web-1", 1);
    const off = lb(t, { healthCheck: false });
    const id = t.devices.find((d) => d.name === "lb-1")!.id;
    const verdict = (x: Topology) => Object.fromEntries(probeTargets(x, id, "tcp", 80).candidates.map((c) => [c.value, c.ok ? "ok" : `X ${c.reason ?? ""}`]));
    // 헬스 체크는 lb-1 에서 나가는 연결과 무관하므로 결과가 같아야 한다
    expect(verdict(t)).toEqual(verdict(off));
  });

  it("[4] 로드밸런서가 NAT 뒤에서 바깥 백엔드를 체크하면 2초마다 NAT 매핑이 하나씩 쌓이고 지워지지 않는다 (공유기 NAT 표가 끝없이 자람)", () => {
    // 백엔드 하나를 공인 웹 서버(example.com)로 — CDN 원본·외부 API 를 뒤에 둔 구성
    const t = lb(withCheck(), { backends: [{ ip: "93.184.216.34", port: 80 }] });
    const { s, node } = loadTopology(t);
    const nat = () => (node("공유기") as unknown as { nat: { size: number } }).nat.size;
    const before = nat();
    s.net.runUntil(s.net.now + 120_000); // 2분
    s.net.runToIdle();
    // 체크 연결은 열고 곧 닫는다 — 닫힌 체크의 매핑이 60개 넘게 남으면 표·공인 포트가 한없이 늘어난다
    expect(nat() - before).toBeLessThan(10);
  });

  it("[5] L4: 체크 연결의 임시 포트가 변환 포트 범위(50000~)에 들어오면, 죽은 백엔드를 기다리는 체크 포트를 새 L4 흐름이 변환 포트로 받아 멀쩡한 백엔드가 패시브로 빠진다", () => {
    const t = lossOn(withCheck({ mode: "l4" }), "web-3", 1);
    const { s, act, id, host: node } = loadTopology(t);
    const lbn = node("lb-1").lb as unknown as { checking: Map<string, { conn: { localPort: number; remoteIp: string } }>; nextNatPort: number };
    // 체크 임시 포트는 49152 부터 라운드마다 백엔드 수만큼 는다 → 약 9분 뒤(282 라운드) web-3 체크가 50000 을 쓴다
    const waiting = () => [...lbn.checking.values()].find((c) => c.conn.remoteIp === "192.168.0.13")?.conn.localPort;
    for (let k = 0; k < 400 && waiting() !== lbn.nextNatPort; k++) s.net.runUntil(s.net.now + 2000);
    expect(waiting()).toBe(50000);
    // 이 2초 안에 들어온 클라이언트의 첫 L4 흐름이 변환 포트 50000 을 받는다 (allocNatPort 는 TCP 스택이 쓰는 포트를 보지 않음)
    const r = act({ kind: "tcp-connect", nodeId: id("pc-1"), dst: "192.168.0.20", port: 80 });
    // web-1 은 멀쩡한데 SYN·ACK 이 체크 연결 몫으로 빠져 TCP 스택이 RST → 클라이언트 SYN 재전송 → "SYN 에 응답 없음" 으로 web-1 을 뺀다
    expect(r.filter((e) => e.kind === "lb.down").map((e) => e.summary)).toEqual([]);
  });
});

describe("리뷰: 주기 DPD", () => {
  const A = "사무실 A NAT";
  const B = "사무실 B NAT";
  const ipsecBoth = (): Topology => {
    const base = exampleVpnTopology();
    const vpn = (d: Device) => ({ ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, mode: "ipsec" as const, psk: "s3cret", dpd: true } } });
    return { ...base, devices: base.devices.map((d) => (d.name === A || d.name === B ? vpn(d) : d)) };
  };

  it("[6] 양쪽 다 주기 DPD: 상대의 DPD 요청을 방금 받고도 '10초 동안 받은 것이 없음' 이라며 자기 DPD 를 또 보낸다 (받은 DPD 요청을 heard 로 세지 않음)", () => {
    const x = loadTopology(ipsecBoth());
    x.act({ kind: "ping", nodeId: x.id("pc-a"), dst: "192.168.2.10" });
    expect(x.l3(A).vpn.ipsecUp).toBe(true);
    const from = x.s.net.trace.length;
    x.s.net.runUntil(x.s.net.now + 25_000);
    const tr = x.s.net.trace.slice(from);
    // 각 주기 DPD 직전에 그 장비가 상대의 DPD 요청을 받아(빈 응답을 보냄) 있었다면, 그 뒤 10초가 지나야 "받은 것이 없음" 이 맞다
    const gaps = tr
      .filter((e) => e.kind === "vpn.dpd" && e.details?.periodic === true)
      .map((p) => {
        const heard = tr.filter((e) => e.nodeId === p.nodeId && e.kind === "vpn.dpd" && e.details?.dpd === "reply" && e.time <= p.time).at(-1);
        return heard ? p.time - heard.time : Infinity;
      });
    expect(gaps.length).toBeGreaterThan(0);
    expect(gaps.filter((g) => g < 10_000)).toEqual([]);
  });
});
