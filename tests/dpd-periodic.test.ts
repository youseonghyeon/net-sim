// 주기 DPD (배경 타이머, strongSwan dpddelay 식): 상대에게서 10초 동안 받은 것이 없으면 DPD, 트래픽이 오가면 보내지 않는다.
// 말없이 사라진 상대(케이블 손실 100%)를 시간이 흐르는 동안 알아채 SA 를 지운다
import { describe, expect, it } from "vitest";
import { exampleRemoteVpnTopology, exampleVpnTopology } from "../src/model/examples";
import type { Topology, VpnSettings } from "../src/model/topology";
import { loadTopology } from "./helpers";

const A = "사무실 A NAT";
const B = "사무실 B NAT";
function ipsec(a: Partial<VpnSettings> = {}): Topology {
  const base = exampleVpnTopology();
  return {
    ...base,
    devices: base.devices.map((d) =>
      d.name === A ? { ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, mode: "ipsec", psk: "s3cret", ...a } } }
      : d.name === B ? { ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, mode: "ipsec", psk: "s3cret" } } }
      : d,
    ),
  };
}
const cableOf = (t: Topology, a: string, b: string) => {
  const ia = t.devices.find((d) => d.name === a)!.id;
  const ib = t.devices.find((d) => d.name === b)!.id;
  return t.cables.find((c) => [c.a.device, c.b.device].includes(ia) && [c.a.device, c.b.device].includes(ib))!;
};
/** 터널을 맺어 둔 상태로 */
const up = (t: Topology) => {
  const x = loadTopology(t);
  x.act({ kind: "ping", nodeId: x.id("pc-a"), dst: "192.168.2.10" });
  expect(x.l3(A).vpn.ipsecUp).toBe(true);
  return x;
};
const periodic = (x: ReturnType<typeof loadTopology>, from: number, name: string) => x.s.net.trace.slice(from).filter((e) => e.nodeId === x.id(name) && e.kind === "vpn.dpd" && e.details?.periodic === true);

describe("사이트 간 IPsec 주기 DPD", () => {
  it("꺼져 있으면(기본) 배경 타이머가 없다", () => {
    const x = up(ipsec());
    expect(x.s.net.peekBackgroundTime()).toBeUndefined();
  });

  it("조용한 터널: 10초마다 DPD, 상대가 답하면 터널 유지", () => {
    const x = up(ipsec({ dpd: true }));
    const from = x.s.net.trace.length;
    x.s.net.runUntil(x.s.net.now + 25_000);
    expect(periodic(x, from, A)).toHaveLength(2);
    expect(x.s.net.trace.slice(from).filter((e) => e.kind === "vpn.dpd" && e.details?.dpd === "alive")).toHaveLength(2);
    expect(x.l3(A).vpn.ipsecUp).toBe(true);
  });

  it("트래픽이 오가면 보내지 않는다 (받은 ESP 가 곧 살아 있다는 증거)", () => {
    const x = up(ipsec({ dpd: true }));
    const from = x.s.net.trace.length;
    for (let k = 0; k < 5; k++) {
      x.s.net.runUntil(x.s.net.now + 5_000);
      x.act({ kind: "ping", nodeId: x.id("pc-a"), dst: "192.168.2.10" });
    }
    expect(periodic(x, from, A)).toHaveLength(0);
  });

  it("상대가 말없이 사라지면(케이블 손실 100%) DPD 가 재전송 뒤 SA 를 지운다 — 다음 패킷에 다시 협상", () => {
    const x = up(ipsec({ dpd: true }));
    x.s.net.setLinkLoss(cableOf(x.t, B, "통신사 구간").id, 1);
    const from = x.s.net.trace.length;
    x.s.net.runUntil(x.s.net.now + 15_000);
    expect(periodic(x, from, A)).toHaveLength(1);
    expect(x.s.net.trace.slice(from).some((e) => e.nodeId === x.id(A) && e.kind === "vpn.drop" && e.details?.dpd === "dead")).toBe(true);
    expect(x.l3(A).vpn.ipsecUp).toBe(false);
    // SA 가 없으면 주기 DPD 도 멈춘다 — 조용해진다
    x.s.net.runToIdle();
    expect(x.s.net.peekNextTime()).toBeUndefined();
  });

  it("주기 DPD 만 켜고 끄면 터널을 다시 맺지 않는다", () => {
    const t = ipsec();
    const x = up(t);
    const on: Topology = { ...t, devices: t.devices.map((d) => (d.name === A ? { ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, dpd: true } } } : d)) };
    const tr = x.apply(on);
    expect(tr.some((e) => e.kind === "vpn.ike" || e.kind === "vpn.up")).toBe(false);
    expect(tr.find((e) => e.kind === "vpn.config")!.summary).toContain("주기 DPD 켜짐");
    expect(x.l3(A).vpn.ipsecUp).toBe(true);
    expect(x.s.net.peekBackgroundTime()).toBeDefined();
  });
});

describe("원격 접속 주기 DPD", () => {
  const LAPTOP = "재택 노트북";
  const FW = "회사 VPN 방화벽";
  const withDpd = (on: boolean): Topology => {
    const t = exampleRemoteVpnTopology();
    return { ...t, devices: t.devices.map((d) => (d.name === LAPTOP ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, dpd: on } } } : d)) };
  };

  it("서버가 말없이 사라지면 시간이 흐르는 동안 알아채 끊김, 꺼져 있으면 연결된 줄 안다", () => {
    for (const on of [true, false]) {
      const x = loadTopology(withDpd(on));
      expect(x.host(LAPTOP).ra.state).toBe("up");
      x.s.net.setLinkLoss(cableOf(x.t, FW, "통신사 구간").id, 1);
      x.s.net.runUntil(x.s.net.now + 15_000);
      expect(x.host(LAPTOP).ra.state).toBe(on ? "failed" : "up");
      if (on) expect(x.host(LAPTOP).ra.reason).toContain("DPD 에 서버 응답 없음");
    }
  });
});
