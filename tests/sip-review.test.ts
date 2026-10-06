// 리뷰: 인터넷 전화(SIP·RTP)·SIP ALG 결함 재현 (df71520)
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleSipTopology } from "../src/model/examples";
import { cable } from "../src/model/examples/build";
import { createDevice, type Topology } from "../src/model/topology";
import { effectiveSip } from "../src/model/netSync";
import { meshHostname } from "../src/core/nodes/tailscale";
import type { Router } from "../src/core/nodes/router";
import type { Internet } from "../src/core/nodes/internet";
import type { Ipv4Packet, SipMessage } from "../src/core/packet";

type L = ReturnType<typeof loadTopology>;
const setRouter = (t: Topology, name: string, patch: object): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? { ...d, router: { ...d.router!, ...patch } } : d)) });
const bothAlg = (t: Topology) => setRouter(setRouter(t, "민지네 공유기", { sipAlg: true }), "준호네 공유기", { sipAlg: true });
const call = (x: L, from = "민지 전화기", to = "junho") => x.act({ kind: "sip-call", nodeId: x.id(from), to });
const last = (x: L, name: string) => x.host(name).sip.calls.at(-1)!;

/** 민지네 공유기 Wi-Fi 에 전화기 하나 더 (sujin) */
function withSujin(t: Topology): Topology {
  const pa = t.devices.find((d) => d.name === "민지 전화기")!;
  const p = createDevice("phone", pa.x + 80, pa.y, t.devices);
  p.name = "수진 전화기";
  p.host = { ...p.host!, sip: { enabled: true, user: "sujin" } };
  p.wifi = { ssid: "minji-home" };
  return { ...t, devices: [...t.devices, p] };
}

describe("SIP 리뷰", () => {
  it("1. ISP 가 공유기 공인 주소를 바꿔도 등록 갱신(60초)이 지나면 다시 전화를 받는다", () => {
    const x = loadTopology(bothAlg(exampleSipTopology()));
    const inet = x.node<Internet>("internet-1");
    const old = inet.sip.users.get("junho")!.at.ip;
    x.act({ kind: "isp-renumber", nodeId: x.id("internet-1"), ip: old });
    const now = x.node<Router>("준호네 공유기").wan.ip;
    expect(now).not.toBe(old);
    // 전화기는 등록을 주기적으로 갱신해(60초) 서버가 새 공인 주소를 배운다 (시간이 흐를 때만)
    x.s.net.runUntil(x.s.net.now + 65_000);
    call(x);
    // 서버는 옛 공인 주소로 INVITE 를 넘기고, 준호네 공유기는 "내 공인 주소 아님" 으로 드롭 → 민지는 "응답 없음"
    expect(last(x, "민지 전화기").state).not.toBe("failed");
    expect(inet.sip.users.get("junho")!.at.ip).toBe(now);
  });

  it("2. 공유기 WAN 이 늦게 이어지면 등록 3번 실패 뒤 다시 시도하지 않는다 (요약은 계속 '등록 중')", () => {
    const base = exampleSipTopology();
    const rb = base.devices.find((d) => d.name === "준호네 공유기")!.id;
    const x = loadTopology({ ...base, cables: base.cables.filter((c) => c.b.device !== rb) });
    expect(x.host("준호 전화기").sip.registered).toBe(false);
    x.apply(base);
    x.s.net.runUntil(x.s.net.now + 30_000);
    expect(x.node<Router>("준호네 공유기").wan.ip).toBeTruthy();
    expect(x.host("준호 전화기").sip.registered).toBe(true);
  });

  it("3. BYE 가 사라지면(케이블 손실) 받은 쪽은 영영 '통화 중' — BYE 재전송 없음", () => {
    const t = bothAlg(exampleSipTopology());
    const x = loadTopology(t);
    const wanB = t.cables.find((c) => c.b.device === x.id("준호네 공유기"))!;
    const start = x.s.net.now;
    x.s.net.scheduleAction(start, { kind: "sip-call", nodeId: x.id("민지 전화기"), to: "junho" });
    x.s.net.runUntil(start + 520); // 준호의 음성까지 다 오간 뒤, BYE 전
    x.s.net.setLinkLoss(wanB.id, 1);
    x.s.net.runToIdle();
    x.s.net.setLinkLoss(wanB.id, 0);
    x.s.net.runUntil(x.s.net.now + 60_000);
    expect(last(x, "민지 전화기").state).toBe("ended");
    expect(last(x, "준호 전화기").state).not.toBe("talking");
  });

  it("4. BYE 의 200 OK 를 서버가 건 쪽에 넘기지 않는다 (BYE 때 통화 기록을 지워 뒤에 온 200 을 버림)", () => {
    const x = loadTopology(bothAlg(exampleSipTopology()));
    call(x);
    const okForBye = x.wire("민지 전화기").filter((p: Ipv4Packet) => p.payload.kind === "udp" && p.payload.payload.kind === "sip" && (p.payload.payload as SipMessage).status === 200 && (p.payload.payload as SipMessage).cseq === -1);
    expect(okForBye.length).toBeGreaterThan(0);
  });

  it("5. 자기 자신에게 걸면 '받은 전화' 기록이 영영 ringing 으로 남는다 (같은 Call-ID 를 find 가 건 쪽 기록으로 찾음)", () => {
    const x = loadTopology(bothAlg(exampleSipTopology()));
    call(x, "민지 전화기", "minji");
    const calls = x.host("민지 전화기").sip.calls;
    expect(calls.filter((c) => c.state === "ringing" || c.state === "calling" || c.state === "talking")).toEqual([]);
  });

  it("6. 같은 공유기 뒤 두 전화기: ALG 를 끄면 들리는데, 켜면 SDP 가 공인 주소로 바뀌어 UDP 헤어핀이 없어 양쪽 다 안 들린다", () => {
    const off = loadTopology(withSujin(exampleSipTopology()));
    call(off, "민지 전화기", "sujin");
    expect(last(off, "민지 전화기").received).toBe(5);
    const on = loadTopology(setRouter(withSujin(exampleSipTopology()), "민지네 공유기", { sipAlg: true }));
    call(on, "민지 전화기", "sujin");
    expect(last(on, "민지 전화기").received).toBe(5);
    expect(last(on, "수진 전화기").received).toBe(5);
  });

  it("7. 방화벽(기본 차단 + Stateful)이 있으면 ALG 구멍으로 먼저 온 음성이 방화벽에 막힌다 (방화벽에는 구멍을 안 냄 — conntrack RELATED 없음)", () => {
    const fw = { enabled: true, defaultPolicy: "deny", stateful: true, rules: [{ action: "allow", proto: "any", direction: "out", src: "", dst: "", dstPort: "" }] };
    const x = loadTopology(setRouter(setRouter(bothAlg(exampleSipTopology()), "준호네 공유기", { firewall: fw }), "민지네 공유기", { firewall: fw }));
    expect(x.host("준호 전화기").sip.registered).toBe(true);
    call(x);
    expect(last(x, "준호 전화기").received).toBe(5);
    expect(last(x, "민지 전화기").received).toBe(5);
  });

  it("8. DPI 가 SIP·RTP 를 '알 수 없는 UDP' 로 분류한다 → '알 수 없음' 을 막으면 인터넷 전화가 끊긴다", () => {
    const x = loadTopology(setRouter(bothAlg(exampleSipTopology()), "민지네 공유기", { dpi: { enabled: true, blockApps: [], blockCategories: [] } }));
    call(x);
    const apps = [...(x.node<Router>("민지네 공유기").dpi.stats.get(x.host("민지 전화기").iface.ip!)?.keys() ?? [])];
    expect(apps.length).toBeGreaterThan(0);
    expect(apps).not.toContain("unknown");
  });

  it("9. 통화가 끝나면 ALG 가 연 음성 포트 구멍을 닫는다", () => {
    const t = setRouter(setRouter(bothAlg(exampleSipTopology()), "민지네 공유기", { natType: "port-restricted" }), "준호네 공유기", { natType: "port-restricted" });
    const x = loadTopology(t);
    call(x);
    expect(last(x, "민지 전화기").state).toBe("ended");
    const rtpPort = x.host("민지 전화기").sip.rtpPort;
    const entry = x.node<Router>("민지네 공유기").nat.values().find((e) => e.proto === "udp" && e.innerId === rtpPort && e.pinhole);
    // 고친 방식: 통화가 끝나면 ALG 가 그 구멍을 닫는다 (매핑이 없거나, 남아도 ALG 구멍이 아님)
    expect(entry === undefined || entry.pinhole !== true).toBe(true);
  });

  it("10. 사용자 이름을 바꿔도 옛 이름 등록이 서버에 남아 옛 이름으로 건 전화가 그 전화기에 걸린다 (해제 REGISTER 없음, 받는 쪽은 To 를 안 봄)", () => {
    const t = bothAlg(exampleSipTopology());
    const x = loadTopology(t);
    x.apply({ ...t, devices: t.devices.map((d) => (d.name === "준호 전화기" ? { ...d, host: { ...d.host!, sip: { enabled: true, user: "jun" } } } : d)) });
    call(x, "민지 전화기", "junho");
    expect(last(x, "민지 전화기").reason ?? "").toContain("404");
  });

  it("11. 공인 주소 전화기(NAT 없음) ↔ NAT 뒤 전화기(ALG 켬): 양쪽 다 들린다", () => {
    const t = setRouter(exampleSipTopology(), "준호네 공유기", { sipAlg: true });
    const isp = t.devices.find((d) => d.name === "통신사 구간")!;
    const pc = createDevice("pc", isp.x + 120, isp.y, t.devices);
    pc.name = "공인 PC";
    pc.host = { ...pc.host!, sip: { enabled: true, user: "pub" } };
    const x = loadTopology({ ...t, devices: [...t.devices, pc], cables: [...t.cables, cable(isp, 2, pc, 0)] });
    expect(x.host("공인 PC").sip.registered).toBe(true);
    call(x, "공인 PC", "junho");
    expect(last(x, "공인 PC").received).toBe(5);
    expect(last(x, "준호 전화기").received).toBe(5);
  });

  it("12. symmetric NAT 양쪽 + ALG: 양쪽 다 들린다", () => {
    const t = setRouter(setRouter(bothAlg(exampleSipTopology()), "민지네 공유기", { natType: "symmetric" }), "준호네 공유기", { natType: "symmetric" });
    const x = loadTopology(t);
    call(x);
    expect(last(x, "민지 전화기").received).toBe(5);
    expect(last(x, "준호 전화기").received).toBe(5);
  });

  it("13. 한글 장치 이름 + 빈 사용자: 실제 등록 이름(phone-xxxx)과 UI 가 보여 주는 이름(placeholder·받는 사람 목록 = meshHostname)이 다르다", () => {
    const t = exampleSipTopology();
    const d = t.devices.find((x) => x.name === "준호 전화기")!;
    const blank = { ...d, host: { ...d.host!, sip: { enabled: true, user: "" } } };
    // 고친 방식: UI(sip.tsx)도 effectiveSip 의 이름을 쓴다 — 한글 이름이면 비지 않은 대체 이름
    expect(meshHostname(blank.name)).toBe("");
    expect(effectiveSip(blank).user).toMatch(/^phone-/);
  });
});
