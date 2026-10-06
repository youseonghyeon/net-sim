// OpenVPN 리뷰: 결함 재현 (고치기 전에는 실패해야 한다)
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleOpenVpnTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { TraceEvent } from "../src/core/trace";
import { practitionerLines } from "../src/model/packetView";
import { ovpnCaOfDevice, ovpnTlsCryptOfDevice, type OvpnClientSettings, type RouterOvpnServerSettings, type Topology } from "../src/model/topology";

const LAPTOP = "카페 노트북";
const HOME = "집 Brume 3";
const CAFE = "카페 공유기";
const server = (t: Topology, p: Partial<RouterOvpnServerSettings>): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === HOME ? { ...d, router: { ...d.router!, ovpnServer: { ...d.router!.ovpnServer!, ...p } } } : d)) });
const client = (t: Topology, p: Partial<OvpnClientSettings>, ra: object = {}): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.name === LAPTOP ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, ...ra, ovpn: { ...d.host!.ra!.ovpn!, ...p } } } } : d)),
});
const noCafeFw = (t: Topology): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === CAFE ? { ...d, router: { ...d.router!, firewall: undefined } } : d)) });
/** 조건에 맞는 트레이스가 새로 생길 때까지 한 단계씩 (상한 2만 단계) */
function stepUntil(L: ReturnType<typeof loadTopology>, pred: (e: TraceEvent) => boolean): void {
  const from = L.s.net.trace.length;
  for (let i = 0; i < 20000; i++) {
    if (L.s.net.trace.slice(from).some(pred)) return;
    L.s.net.step();
  }
  throw new Error("stepUntil: 조건을 만나지 못함");
}
const udp = (t: Topology) => noCafeFw(client(server(t, { proto: "udp", port: 1194 }), { proto: "udp", port: 1194 }));

describe("OpenVPN 리뷰", () => {
  it("TCP 로 붙은 채 VPN 종류를 바꾸면 서버의 FIN·ACK 가 호스트 TCP 로 새어 RST 가 나가지 않는다", () => {
    const L = loadTopology(exampleOpenVpnTopology());
    expect(L.host(LAPTOP).ra.state).toBe("up");
    const tr = L.apply(client(L.t, {}, { type: "wireguard" }));
    expect(tr.filter((e) => e.nodeId === L.id(LAPTOP) && e.kind === "tcp.rst.sent").map((e) => e.summary)).toEqual([]);
  });

  it("TCP: 노트북 케이블을 뺐다 다시 꽂으면 새 연결이 옛 세션을 밀어낼 때 옛 포트로 온 FIN 이 호스트 TCP 로 새어 RST 가 나가지 않는다", () => {
    const L = loadTopology(exampleOpenVpnTopology());
    expect(L.host(LAPTOP).ra.state).toBe("up");
    const lapCable = L.t.cables.find((c) => c.a.device === L.id(LAPTOP) || c.b.device === L.id(LAPTOP))!;
    L.apply({ ...L.t, cables: L.t.cables.filter((c) => c !== lapCable) });
    const tr = L.apply(L.t);
    expect(L.host(LAPTOP).ra.state).toBe("up");
    expect(tr.filter((e) => e.nodeId === L.id(LAPTOP) && e.kind === "tcp.rst.sent").map((e) => e.summary)).toEqual([]);
  });

  it("TCP: 서버 설정을 연달아 바꿔(다시 연결하는 도중에 또 재시작) 도 노트북은 방화벽·DPI 탓으로 포기하지 않고 다시 붙는다", () => {
    const L = loadTopology(exampleOpenVpnTopology());
    const s = L.s;
    const lapId = L.id(LAPTOP);
    s.sync(server(L.t, { pushDns: false }));
    // 2초 뒤 다시 연결이 시작되어 TCP 가 맺어질 때까지
    stepUntil(L, (e) => e.nodeId === lapId && e.summary.includes("다시 연결 (connect-retry)"));
    stepUntil(L, (e) => e.nodeId === lapId && e.summary.includes("TCP 연결됨"));
    s.sync(server(L.t, { pushDns: false, lanAccess: false }));
    s.net.runToIdle();
    const lap = L.host(LAPTOP);
    expect(lap.ra.summary()).not.toContain("방화벽·DPI");
    expect(lap.ra.state).toBe("up");
  });

  it("UDP: 노트북이 협상하는 도중 서버 설정이 바뀌면 노트북은 timeout(키·방화벽 탓)으로 영영 포기하지 않는다", () => {
    const L = loadTopology(udp(exampleOpenVpnTopology()));
    expect(L.host(LAPTOP).ra.state).toBe("up");
    const s = L.s;
    const lapId = L.id(LAPTOP);
    const t1 = server(L.t, { pushDns: false });
    s.sync(t1);
    stepUntil(L, (e) => e.nodeId === lapId && e.summary.includes("다시 연결 (connect-retry)"));
    stepUntil(L, (e) => e.nodeId === lapId && e.summary.includes("HARD_RESET_SERVER 수신"));
    s.sync(server(t1, { lanAccess: false }));
    s.net.runToIdle();
    const lap = L.host(LAPTOP);
    expect(lap.ra.summary()).not.toContain("TLS key negotiation failed");
    expect(lap.ra.state).toBe("up");
  });

  it("DPI 가 붙어 있던 TCP 연결을 끊으면 노트북 로그가 '서버가 다시 시작함' 으로 원인을 잘못 짚지 않는다", () => {
    const L = loadTopology(exampleOpenVpnTopology());
    expect(L.host(LAPTOP).ra.state).toBe("up");
    const dpi: Topology = { ...L.t, devices: L.t.devices.map((d) => (d.name === CAFE ? { ...d, router: { ...d.router!, dpi: { enabled: true, blockApps: [], blockCategories: ["VPN"] } } } : d)) };
    L.apply(dpi);
    const tr = L.act({ kind: "ping", nodeId: L.id(LAPTOP), dst: "192.168.8.20" });
    expect(tr.some((e) => e.kind === "dpi.block")).toBe(true);
    const lapLines = tr.filter((e) => e.nodeId === L.id(LAPTOP) && e.kind === "vpn.drop").map((e) => e.summary);
    expect(lapLines.some((l) => l.includes("서버가 다시 시작함"))).toBe(false);
  });

  it("구성 검사: DDNS 이름의 서버가 앞 공유기 뒤에 있고 TCP 443 → 1194 로 포워딩되면 proto-mismatch 오탐이 없다", () => {
    const t = behindFront();
    const L = loadTopology(t);
    // (시작할 때 이름 풀기 실패는 아래 별도 결함 — 여기서는 다시 연결해 실제로 붙는 것을 확인)
    L.act({ kind: "ra-reconnect", nodeId: L.id(LAPTOP) });
    expect(L.host(LAPTOP).ra.state).toBe("up"); // 실제로는 붙는다
    expect(lintTopology(t).filter((i) => i.code.startsWith("ovpn.")).map((i) => `${i.code}: ${i.message}`)).toEqual([]);
  });
});

describe("OpenVPN 리뷰 (상태 표시)", () => {
  it("서버가 다시 시작해 2초 뒤 다시 연결을 기다리는 동안 상태가 '꺼짐·주소를 받으면 연결' 로 보이지 않는다", () => {
    const L = loadTopology(exampleOpenVpnTopology());
    L.s.sync(server(L.t, { pushDns: false }));
    stepUntil(L, (e) => e.nodeId === L.id(LAPTOP) && e.summary.includes("초 뒤 다시 연결"));
    const lap = L.host(LAPTOP);
    expect(lap.ra.state).not.toBe("off");
    expect(lap.ra.summary()).not.toContain("주소를 받으면 연결");
  });
});

describe("OpenVPN 리뷰 (실무 로그)", () => {
  it("TCP 연결(SYN) timeout 을 'TLS key negotiation failed' 로 옮기지 않는다", () => {
    // 카페 방화벽은 TCP 80·443 만 허용 — 8443 은 조용히 드롭돼 SYN timeout
    const L = loadTopology(client(server(exampleOpenVpnTopology(), { port: 8443 }), { port: 8443 }));
    expect(L.host(LAPTOP).ra.summary()).toContain("SYN timeout");
    const lines = L.s.net.trace.filter((e) => e.nodeId === L.id(LAPTOP)).flatMap((e) => practitionerLines(e, {}).filter((l) => l.tool.startsWith("openvpn")).map((l) => l.line));
    expect(lines.filter((l) => l.includes("TLS key negotiation failed"))).toEqual([]);
  });

  it("서버가 WAN 주소 변경으로 세션을 비운 일을 서버의 'Inactivity timeout (--ping-restart)' 로 옮기지 않는다", () => {
    const L = loadTopology(exampleOpenVpnTopology());
    const tr = L.apply({ ...L.t, devices: L.t.devices.map((d) => (d.name === HOME ? { ...d, router: { ...d.router!, wan: { ...d.router!.wan!, ip: "203.0.113.41" } } } : d)) });
    const ev = tr.filter((e) => e.nodeId === L.id(HOME) && e.kind === "vpn.drop" && e.summary.includes("WAN 주소"));
    expect(ev.length).toBe(1);
    expect(ev.flatMap((e) => practitionerLines(e, {}).map((l) => l.line)).filter((l) => l.includes("Inactivity timeout"))).toEqual([]);
  });
});

describe("OpenVPN 리뷰 (멀티 WAN)", () => {
  it("멀티 WAN: WAN1 을 쓰는 동안 노트북이 WAN2 주소로 TCP 연결하면 서버의 답도 그 주소에서 나간다 (TCP 연결의 로컬 주소는 바뀌지 않는다)", () => {
    const base = exampleOpenVpnTopology();
    const home = base.devices.find((d) => d.name === HOME)!;
    const isp = base.devices.find((d) => d.name === "통신사 구간")!;
    const t: Topology = {
      ...base,
      devices: base.devices.map((d) =>
        d.id === home.id
          ? { ...d, router: { ...d.router!, wan2: { enabled: true, ipMode: "static" as const, ip: "203.0.113.41", prefix: 24, gateway: "203.0.113.1", track: "" } } }
          : d.name === LAPTOP
            ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, server: "203.0.113.41" } } }
            : d,
      ),
      cables: [...base.cables, { id: "c-wan2", a: { device: isp.id, port: 7 }, b: { device: home.id, port: 4 } }],
    };
    const L = loadTopology(t);
    const srv = L.s.net.trace.filter((e) => e.nodeId === L.id(HOME) && e.summary.startsWith("OpenVPN 서버")).map((e) => e.summary);
    expect(srv.some((x) => x.includes("SYN"))).toBe(true); // 서버는 WAN2 로 SYN 을 받았다
    expect(L.host(LAPTOP).ra.state).toBe("up");
  });
});

describe("OpenVPN 리뷰 (이름)", () => {
  it("서버를 DDNS 이름으로 적으면(설정 파일 가져오기의 기본) 시작할 때 카페 공유기 WAN 이 아직 없어 이름 풀기가 한 번 실패해도 다시 풀어 붙는다", () => {
    const base = exampleOpenVpnTopology();
    const t: Topology = {
      ...base,
      devices: base.devices.map((d) =>
        d.name === HOME ? { ...d, router: { ...d.router!, ddns: { enabled: true, name: "myhome" } } } : d.name === LAPTOP ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, server: "myhome.glddns.com" } } } : d,
      ),
    };
    expect(lintTopology(t).filter((i) => i.code.startsWith("ovpn."))).toEqual([]);
    const L = loadTopology(t);
    expect(L.host(LAPTOP).ra.summary()).not.toContain("풀지 못함");
    expect(L.host(LAPTOP).ra.state).toBe("up");
  });
});

/** 집: 앞 공유기(203.0.113.40, OpenVPN 꺼짐, TCP 443 → 안쪽 Brume:1194 포워딩) 뒤에 안쪽 Brume(WAN 192.168.8.2, OpenVPN TCP 1194, DDNS myhome) */
function behindFront(): Topology {
  const base = exampleOpenVpnTopology();
  const front = base.devices.find((d) => d.name === HOME)!;
  const inner = structuredClone(front);
  inner.id = "brume-inner";
  inner.name = "안쪽 Brume";
  inner.x = front.x + 200;
  inner.router = {
    ...inner.router!,
    lanIp: "192.168.9.1",
    dhcp: { enabled: true, start: "192.168.9.100", end: "192.168.9.199" },
    wan: { ipMode: "static", ip: "192.168.8.2", prefix: 24, gateway: "192.168.8.1" },
    ovpnServer: { ...inner.router!.ovpnServer!, proto: "tcp", port: 1194 },
    ddns: { enabled: true, name: "myhome" },
  };
  const outer = { ...front, router: { ...front.router!, ovpnServer: { ...front.router!.ovpnServer!, enabled: false }, forwards: [{ proto: "tcp" as const, publicPort: 443, lanIp: "192.168.8.2", lanPort: 1194 }] } };
  const devices = base.devices.map((d) =>
    d.id === front.id
      ? outer
      : d.name === LAPTOP
        ? { ...d, host: { ...d.host!, ra: { ...d.host!.ra!, server: "myhome.glddns.com", ovpn: { proto: "tcp" as const, port: 443, ca: ovpnCaOfDevice(inner), cn: LAPTOP, certCa: ovpnCaOfDevice(inner), tlsCrypt: ovpnTlsCryptOfDevice(inner) } } } }
        : d,
  );
  return { ...base, devices: [...devices, inner], cables: [...base.cables, { id: "c-inner", a: { device: front.id, port: 2 }, b: { device: inner.id, port: 0 } }] };
}
