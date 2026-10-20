// VPN 협상 교란 표 (AGENTS 점검 "새 VPN 협상" ①~③, LESSONS 4u·4z·4zb·4zg): 프로토콜마다 같은 교란을 걸고 결과를 파일로 고정한다.
// 새 VPN 종류를 넣으면 CASES 에 한 줄 더한다 — 교란 전부가 자동으로 돈다. 바뀐 칸은 보고 의도한 것만 `-u`.
//   ① 응답 손실: 다시 접속하는 동안 서버 쪽 회선이 1.5초 끊김 → 결국 붙는가
//   ② 서버가 상태를 잊음: 서버를 껐다 켬 → 클라이언트가 알고 다시 붙는가 (ping 두 번)
//   ③ 끈 뒤 늦은 패킷: 서버 쪽에서 보낸 ping 이 날아가는 동안 클라이언트를 끔 → Port Unreachable 이 새지 않는가
//   ④ 클라이언트 공인 주소가 바뀜(ISP FORCERENEW) → 이어지는가 (ping 두 번)
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { EXAMPLES, type ExampleId } from "../src/model/examples";
import { NetworkSync } from "../src/model/netSync";
import { resetIdSequence, type Device, type Topology } from "../src/model/topology";
import type { Host } from "../src/core/nodes/host";
import type { Router } from "../src/core/nodes/router";
import type { L3Node } from "../src/core/nodes/l3";

beforeAll(() => {
  vi.spyOn(Date, "now").mockReturnValue(0);
});
afterAll(() => {
  vi.restoreAllMocks();
});

interface Case {
  name: string;
  ex: ExampleId;
  /** 터널을 시작하는 쪽 장치와 그 뒤에서 ping 할 장치 */
  client: string;
  pinger: string;
  /** 터널 너머 ping 대상 */
  target: string;
  /** 서버 장치 (회선 끊김·껐다 켬) */
  server: string;
  /** 클라이언트 쪽 공인 주소를 가진 장치 (ISP 가 주소를 바꿈) */
  clientEdge: string;
  /** 서버 켜기·끄기 */
  serverOn: (d: Device, on: boolean) => Device;
  /** 클라이언트 켜기·끄기 */
  clientOn: (d: Device, on: boolean) => Device;
  /** 서버 쪽에서 클라이언트(터널 너머)로 보낼 ping: 보낼 장치와 주소 (L 이 있어야 아는 주소면 함수) */
  back: { from: string; dst: (L: Loaded) => string };
}

const raOn = (d: Device, on: boolean): Device => ({ ...d, host: { ...d.host!, ra: { ...d.host!.ra!, enabled: on } } });
const CASES: Case[] = [
  {
    name: "IKEv2 원격 접속",
    ex: "remote",
    client: "재택 노트북",
    pinger: "재택 노트북",
    target: "10.50.10.20",
    server: "회사 VPN 방화벽",
    clientEdge: "집 공유기",
    serverOn: (d, on) => ({ ...d, l3: { ...d.l3!, ra: { ...d.l3!.ra!, enabled: on } } }),
    clientOn: raOn,
    back: { from: "사내 서버", dst: (L) => L.host("재택 노트북").ra.vip ?? "10.99.0.10" },
  },
  {
    name: "L2TP/IPsec (공유기 VPN 서버)",
    ex: "iptime",
    client: "출장 노트북",
    pinger: "출장 노트북",
    target: "192.168.0.20",
    server: "집 ipTIME",
    clientEdge: "호텔 공유기",
    serverOn: (d, on) => ({ ...d, router: { ...d.router!, vpnServer: { ...d.router!.vpnServer!, enabled: on } } }),
    clientOn: raOn,
    back: { from: "집 NAS", dst: () => "192.168.0.50" },
  },
  {
    name: "WireGuard (폰 → 공유기 서버)",
    ex: "wireguard",
    client: "출장 폰",
    pinger: "출장 폰",
    target: "192.168.8.20",
    server: "집 Brume 3",
    clientEdge: "호텔 공유기",
    serverOn: (d, on) => ({ ...d, router: { ...d.router!, wgServer: { ...d.router!.wgServer!, enabled: on } } }),
    clientOn: raOn,
    back: { from: "집 NAS", dst: () => "10.0.0.3" },
  },
  {
    name: "OpenVPN (TCP 443)",
    ex: "openvpn",
    client: "카페 노트북",
    pinger: "카페 노트북",
    target: "192.168.8.20",
    server: "집 Brume 3",
    clientEdge: "카페 공유기",
    serverOn: (d, on) => ({ ...d, router: { ...d.router!, ovpnServer: { ...d.router!.ovpnServer!, enabled: on } } }),
    clientOn: raOn,
    back: { from: "집 NAS", dst: (L) => L.host("카페 노트북").ra.vip ?? "10.8.0.2" },
  },
  {
    name: "사이트 간 IPsec (사무실 ↔ NCP)",
    ex: "ncp",
    client: "내부망 방화벽 NAT",
    pinger: "내부망 PC 1",
    target: "192.168.111.11",
    server: "NCP VPN Gateway",
    clientEdge: "내부망 방화벽 NAT",
    serverOn: (d, on) => ({ ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, enabled: on } } }),
    clientOn: (d, on) => ({ ...d, l3: { ...d.l3!, vpn: { ...d.l3!.vpn!, enabled: on } } }),
    back: { from: "dev-1", dst: () => "10.50.10.1" },
  },
];

type Loaded = ReturnType<typeof load>;
function load(t: Topology) {
  const s = new NetworkSync();
  s.sync(t);
  s.net.runToIdle(200_000);
  const id = (n: string) => t.devices.find((d) => d.name === n)!.id;
  const host = (n: string) => s.net.nodes.get(id(n)) as Host;
  let cur = t;
  const apply = (f: (t: Topology) => Topology) => {
    cur = f(cur);
    s.sync(cur);
    s.net.runToIdle(200_000);
  };
  const act = (a: Parameters<typeof s.net.scheduleAction>[1]) => {
    s.net.scheduleAction(s.net.now, a);
    s.net.runToIdle(200_000);
  };
  return { s, t, id, host, apply, act, current: () => cur };
}

const patch = (name: string, f: (d: Device) => Device) => (t: Topology): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });
/** 회복할 때까지: 0·20·40·60·120·180초에 ping — 처음 된 시점, 아니면 마지막 실패 이유 (OpenVPN 의 ping-restart 는 120초) */
const recover = (L: Loaded, from: string, dst: string): string => {
  const start = L.s.net.now;
  let last = "";
  for (const at of [0, 20, 40, 60, 120, 180]) {
    L.s.net.runUntil(Math.max(L.s.net.now, start + at * 1000), 200_000);
    last = ping(L, from, dst);
    if (last === "ok") return at === 0 ? "바로 됨" : `${at}초 뒤 됨`;
  }
  return `180초 안에 회복 안 됨 — ${last}`;
};
const ping = (L: Loaded, from: string, dst: string): string => {
  L.act({ kind: "ping", nodeId: L.id(from), dst });
  const p = L.host(from).pings.at(-1)!;
  return p.status === "ok" ? "ok" : `${p.status}(${p.reason ?? ""})`;
};
const wanOf = (L: Loaded, name: string): string | undefined => {
  const n = L.s.net.nodes.get(L.id(name)) as Router | L3Node;
  return "wan" in n ? (n as Router).wan.ip : (n as L3Node).ifaces[0]?.ip;
};
const serverLink = (L: Loaded, c: Case) => {
  const sid = L.id(c.server);
  return L.t.cables.find((x) => (x.a.device === sid && x.a.port === 0) || (x.b.device === sid && x.b.port === 0))!;
};

function fresh(c: Case): Loaded {
  resetIdSequence();
  return load(EXAMPLES[c.ex].build());
}

function row(c: Case): string[] {
  const out: string[] = [`## ${c.name} (${c.ex} — ${c.client} → ${c.server})`];
  {
    const L = fresh(c);
    out.push(`연결: ping ${ping(L, c.pinger, c.target)}`);
  }
  {
    // ① 다시 접속하는 동안 서버 쪽 회선을 1.5초 끊는다
    const L = fresh(c);
    const link = serverLink(L, c);
    L.apply(patch(c.client, (d) => c.clientOn(d, false)));
    L.s.net.setLinkLoss(link.id, 1);
    // 다시 켜고 1.5초만 끊긴 채로 (조용해질 때까지 돌리면 협상 내내 끊긴다)
    L.s.sync(patch(c.client, (d) => c.clientOn(d, true))(L.current()));
    L.s.net.scheduleAction(L.s.net.now, { kind: "ping", nodeId: L.id(c.pinger), dst: c.target });
    L.s.net.runUntil(L.s.net.now + 1500, 200_000);
    L.s.net.setLinkLoss(link.id, 0);
    L.s.net.runToIdle(200_000);
    out.push(`① 다시 켜는 동안 서버 회선 1.5초 끊김: ${recover(L, c.pinger, c.target)}`);
  }
  {
    const L = fresh(c);
    ping(L, c.pinger, c.target);
    L.apply(patch(c.server, (d) => c.serverOn(d, false)));
    L.apply(patch(c.server, (d) => c.serverOn(d, true)));
    out.push(`② 서버 껐다 켬: ${recover(L, c.pinger, c.target)}`);
  }
  {
    const L = fresh(c);
    ping(L, c.pinger, c.target);
    const dst = c.back.dst(L);
    const from = L.s.net.trace.length;
    L.s.net.scheduleAction(L.s.net.now, { kind: "ping", nodeId: L.id(c.back.from), dst });
    L.s.net.runUntil(L.s.net.now + 30, 200_000); // 요청이 날아가는 중에
    L.apply(patch(c.client, (d) => c.clientOn(d, false)));
    L.s.net.runUntil(L.s.net.now + 5_000, 200_000);
    const leak = L.s.net.trace.slice(from).filter((e) => e.kind === "icmp.unreachable.sent" && e.details?.code === "port").map((e) => L.t.devices.find((d) => d.id === e.nodeId)?.name);
    out.push(`③ 끈 뒤 늦은 패킷 (${c.back.from} → ${dst}): Port Unreachable ${leak.length ? `샘 (${[...new Set(leak)].join(", ")})` : "없음"}`);
  }
  {
    const L = fresh(c);
    ping(L, c.pinger, c.target);
    const before = wanOf(L, c.clientEdge);
    L.act({ kind: "isp-renumber", nodeId: L.id("internet-1"), ip: before! });
    const after = wanOf(L, c.clientEdge);
    out.push(`④ 클라이언트 공인 주소 ${before} → ${after}: ${recover(L, c.pinger, c.target)}`);
  }
  return out;
}

describe("VPN 협상 교란 표", () => {
  it("지금 결과와 같다", async () => {
    await expect(CASES.flatMap(row).join("\n") + "\n").toMatchFileSnapshot("./__golden__/vpn-conformance.txt");
  }, 120_000);
});
