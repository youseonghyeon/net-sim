// 공유기 경로 표 (AGENTS 점검 "새 들어오는 길", LESSONS 4zh·4zk): 들어오는 길 × 기능마다 지금 결과를 파일로 고정한다.
// 새 길·새 기능을 넣거나 공유기 경로 코드를 정리하면 이 표가 바뀐다 — 바뀐 칸을 보고 의도한 것만 `-u` 로 갱신한다.
// 칸 = "결과 · 공유기에서 일어난 일(fw.deny·dpi.block·ip.no-route 등)". 기대와 다른 칸도 지금 동작 그대로 적혀 있다 (그래야 바뀌면 보인다).
import { describe, expect, it, vi, beforeAll, afterAll } from "vitest";
import { EXAMPLES, type ExampleId } from "../src/model/examples";
import { NetworkSync } from "../src/model/netSync";
import { resetIdSequence, type Device, type RouterSettings, type Topology } from "../src/model/topology";
import type { ActionSpec } from "../src/core/network";
import type { Host } from "../src/core/nodes/host";
import type { Internet } from "../src/core/nodes/internet";

beforeAll(() => {
  vi.spyOn(Date, "now").mockReturnValue(0);
});
afterAll(() => {
  vi.restoreAllMocks();
});

/** 인터넷 저편 웹 서버 (example.com) — 이름 해석과 무관하게 */
const WEB = "93.184.216.34";

interface Row {
  name: string;
  ex: ExampleId;
  router: string;
  src: string;
  /** 이 길로 들어오게 만드는 준비 (예: 메시 exit node 쓰기) */
  prep?: (t: Topology) => Topology;
}

const ROWS: Row[] = [
  { name: "LAN", ex: "wireguard", router: "집 Brume 3", src: "집 NAS" },
  { name: "드롭인", ex: "dropin", router: "Brume 3 (드롭인)", src: "아이 PC" },
  { name: "WireGuard 피어 (전체 터널)", ex: "mwanvpn", router: "집 Brume 3", src: "카페 폰" },
  { name: "OpenVPN (redirect-gateway)", ex: "openvpn", router: "집 Brume 3", src: "카페 노트북", prep: (t) => patchRouter(t, "집 Brume 3", (r) => ({ ...r, ovpnServer: { ...r.ovpnServer!, redirectGateway: true } })) },
  { name: "L2TP (전체 터널)", ex: "iptime", router: "집 ipTIME", src: "출장 노트북" },
  { name: "메시 exit node", ex: "tailscale", router: "집 Brume 3", src: "카페 노트북", prep: (t) => patchDev(t, "카페 노트북", (d) => ({ ...d, host: { ...d.host!, mesh: { ...d.host!.mesh!, useExitNode: "home-brume" } } })) },
];

interface Feature {
  name: string;
  patch?: (r: RouterSettings, src: Device) => RouterSettings;
  probe: (L: Loaded, row: Row) => ActionSpec;
}

const tcpWeb = (L: Loaded, row: Row): ActionSpec => ({ kind: "tcp-connect", nodeId: L.id(row.src), dst: WEB, port: 80 });
const FEATURES: Feature[] = [
  { name: "기본", probe: tcpWeb },
  { name: "DPI 가 HTTP 차단", patch: (r) => ({ ...r, dpi: { enabled: true, blockApps: ["http"], blockCategories: [] } }), probe: tcpWeb },
  {
    name: "방화벽 아웃바운드 TCP 80 거부",
    patch: (r) => ({ ...r, firewall: { enabled: true, defaultPolicy: "allow", stateful: true, rules: [{ action: "deny", proto: "tcp", direction: "out", src: "", dst: "", dstPort: "80" }] } }),
    probe: tcpWeb,
  },
  { name: "기기 차단 (보낸 기기 MAC)", patch: (r, src) => ({ ...r, blocked: [src.mac] }), probe: tcpWeb },
  { name: "관리 화면 (LAN 주소 :443)", patch: (r) => ({ ...r, admin: { enabled: true, remote: false, allow: "", ssh: true } }), probe: (L, row) => ({ kind: "tcp-connect", nodeId: L.id(row.src), dst: L.router(row).lanIp, port: 443 }) },
  { name: "DNS (공유기 LAN 주소에 묻기)", probe: (L, row) => ({ kind: "dns-lookup", nodeId: L.id(row.src), name: "example.com", qtype: "A", server: L.router(row).lanIp }) },
  { name: "없는 WireGuard 터널 주소 ping", patch: (r) => ({ ...r, wgServer: r.wgServer ?? { enabled: true, address: "10.0.0.1/24", port: 51820, peers: [], lanAccess: true } }), probe: (L, row) => ({ kind: "ping", nodeId: L.id(row.src), dst: "10.0.0.99" }) },
];

/** 공유기에서 일어난 일 중 표에 적을 것 */
const ROUTER_KINDS = ["fw.deny", "fw.allow", "dpi.block", "ip.no-route", "ip.drop", "vpn.killswitch", "nat.translate", "dns.query.received", "dns.hijack"];

function patchDev(t: Topology, name: string, f: (d: Device) => Device): Topology {
  return { ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) };
}
function patchRouter(t: Topology, name: string, f: (r: RouterSettings) => RouterSettings): Topology {
  return patchDev(t, name, (d) => ({ ...d, router: f(d.router!) }));
}

type Loaded = ReturnType<typeof loadAt>;
function loadAt(t: Topology) {
  const s = new NetworkSync();
  s.sync(t);
  s.net.runToIdle(200_000);
  const id = (n: string) => t.devices.find((d) => d.name === n)!.id;
  return { s, t, id, router: (row: Row) => t.devices.find((d) => d.name === row.router)!.router! };
}

function outcome(L: Loaded, row: Row, a: ActionSpec): string {
  const from = L.s.net.trace.length;
  L.s.net.scheduleAction(L.s.net.now, a);
  L.s.net.runToIdle(200_000);
  const rid = L.id(row.router);
  const events = [...new Set(L.s.net.trace.slice(from).filter((e) => e.nodeId === rid && ROUTER_KINDS.includes(e.kind)).map((e) => e.kind))];
  let result = "";
  if (a.kind === "tcp-connect" || a.kind === "inet-connect") {
    const node = L.s.net.nodes.get(a.nodeId) as Host | Internet;
    const c = [...node.tcp.conns.values()].filter((x) => x.role === "client").at(-1);
    result = c ? `${c.state}${c.reason ? ` (${c.reason})` : ""}` : "연결 없음";
  } else if (a.kind === "ping") {
    const p = (L.s.net.nodes.get(a.nodeId) as Host).pings.at(-1);
    result = p ? `${p.status}${p.reason ? ` (${p.reason})` : ""}` : "ping 없음";
  } else if (a.kind === "dns-lookup") {
    const r = (L.s.net.nodes.get(a.nodeId) as Host).lookups.at(-1);
    result = r ? `${r.status}${r.answer ? ` ${r.answer}` : ""}` : "조회 없음";
  }
  return `${result} · 공유기: ${events.join(" ") || "-"}`;
}

function table(): string {
  const lines: string[] = [];
  for (const row of ROWS) {
    lines.push(`## ${row.name} (${row.ex} — ${row.src} → ${row.router})`);
    for (const f of FEATURES) {
      resetIdSequence();
      let t = EXAMPLES[row.ex].build();
      if (row.prep) t = row.prep(t);
      const src = t.devices.find((d) => d.name === row.src)!;
      if (f.patch) t = patchRouter(t, row.router, (r) => f.patch!(r, src));
      const L = loadAt(t);
      lines.push(`${f.name}: ${outcome(L, row, f.probe(L, row))}`);
    }
  }
  // WAN 으로 들어오는 길: 인터넷 저편 → 공유기 공인 주소 :8080 (포트 포워딩 → 집 NAS :80)
  lines.push(`## WAN 인바운드 (wireguard — internet-1 → 집 Brume 3 :8080 → 집 NAS :80)`);
  const inbound: { name: string; patch?: (r: RouterSettings) => RouterSettings }[] = [
    { name: "기본" },
    { name: "DPI 가 HTTP 차단", patch: (r) => ({ ...r, dpi: { enabled: true, blockApps: ["http"], blockCategories: [] } }) },
    { name: "방화벽 인바운드 TCP 80 거부", patch: (r) => ({ ...r, firewall: { enabled: true, defaultPolicy: "allow", stateful: true, rules: [{ action: "deny", proto: "tcp", direction: "in", src: "", dst: "", dstPort: "80" }] } }) },
  ];
  const row: Row = { name: "WAN", ex: "wireguard", router: "집 Brume 3", src: "internet-1" };
  for (const f of inbound) {
    resetIdSequence();
    let t = patchRouter(EXAMPLES.wireguard.build(), row.router, (r) => ({ ...r, forwards: [{ proto: "tcp", publicPort: 8080, lanIp: "192.168.8.20", lanPort: 80 }] }));
    if (f.patch) t = patchRouter(t, row.router, f.patch);
    const L = loadAt(t);
    const wanIp = (L.s.net.nodes.get(L.id(row.router)) as unknown as { wan: { ip: string } }).wan.ip;
    lines.push(`${f.name}: ${outcome(L, row, { kind: "inet-connect", nodeId: L.id("internet-1"), dst: wanIp, port: 8080 })}`);
  }
  return lines.join("\n") + "\n";
}

describe("공유기 경로 표 (들어오는 길 × 기능)", () => {
  it("지금 결과와 같다", async () => {
    await expect(table()).toMatchFileSnapshot("./__golden__/router-paths.txt");
  }, 120_000);
});
