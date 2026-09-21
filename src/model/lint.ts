// 구성 검사(lint): 시뮬레이션을 돌리기 전에 토폴로지(편집 모델)만 보고 "설정 한 칸 빠짐" 을 찾는다.
// DOM·signal·코어에 의존하지 않는 순수 함수. 입력 중인 불완전한 값(빈 칸, "192.168.0.")은 netSync 의 effective* 와
// 같은 기준으로 "없음" 으로 보되, 빈 칸 자체는 지적하지 않고(타일 상태 문구가 보여줌) 값끼리 안 맞는 것만 지적한다.
// 오탐이 미탐보다 나쁘므로, 확신이 없는 경우(주소를 아직 모르는 DHCP 인터페이스 등)는 조용히 넘어간다.
import { DEVICE_SPECS, portVlanOf, wirelessLinks, type Device, type PortRef, type Topology } from "./topology";

export interface LintIssue {
  /** 배지를 붙일 장치 */
  deviceId: string;
  /** error = 통신이 확실히 안 됨, warn = 될 수도 있지만 의심 */
  severity: "error" | "warn";
  /** 안정적인 식별자 (예: "dhcp.no-router") */
  code: string;
  /** 무엇이 잘못됐는지 (한 문장) */
  message: string;
  /** 어떻게 고치는지 (인스펙터 어느 칸인지 구체적으로) */
  fix: string;
  /** 관련 장치 id */
  related?: string[];
}

// ---------- 주소 도우미 (core/addr 와 같은 기준이지만 예외 대신 undefined) ----------

function ipInt(s: string | undefined): number | undefined {
  if (!s) return undefined;
  const parts = s.split(".");
  if (parts.length !== 4) return undefined;
  let n = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return undefined;
    const v = Number(p);
    if (v > 255) return undefined;
    n = n * 256 + v;
  }
  return n;
}

function validIp(s: string | undefined): string | undefined {
  return ipInt(s) === undefined ? undefined : s;
}

function validPrefix(p: number): boolean {
  return Number.isInteger(p) && p >= 1 && p <= 32;
}

function maskOf(prefix: number): number {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

interface Subnet {
  net: number;
  prefix: number;
}

/** ip 와 prefix 가 모두 유효할 때만 서브넷 */
function subnetOf(ip: string | undefined, prefix: number): Subnet | undefined {
  const n = ipInt(ip);
  if (n === undefined || !validPrefix(prefix)) return undefined;
  return { net: (n & maskOf(prefix)) >>> 0, prefix };
}

function contains(s: Subnet, ip: string): boolean {
  const n = ipInt(ip);
  return n !== undefined && ((n & maskOf(s.prefix)) >>> 0) === s.net;
}

/** outer 가 inner 를 통째로 포함하는가 (같은 서브넷도 포함) */
function covers(outer: Subnet, inner: Subnet): boolean {
  return outer.prefix <= inner.prefix && ((inner.net & maskOf(outer.prefix)) >>> 0) === outer.net;
}

function overlaps(a: Subnet, b: Subnet): boolean {
  return covers(a, b) || covers(b, a);
}

function fmtSubnet(s: Subnet): string {
  return `${intToIp(s.net)}/${s.prefix}`;
}

// ---------- L2 세그먼트 ----------

class Union {
  private parent = new Map<string, string>();
  find(k: string): string {
    let root = k;
    while (true) {
      const p = this.parent.get(root);
      if (p === undefined || p === root) break;
      root = p;
    }
    // 경로 압축
    let cur = k;
    while (cur !== root) {
      const next = this.parent.get(cur)!;
      this.parent.set(cur, root);
      cur = next;
    }
    return root;
  }
  union(a: string, b: string): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.parent.set(ra, rb);
  }
}

/** 케이블 한쪽 끝이 L2 관점에서 무엇에 붙는지 */
type Attach =
  | { kind: "end"; key: string; subifs?: { vlan: number; key: string }[] }
  | { kind: "bridge"; key: string }
  | { kind: "access"; key: string }
  | { kind: "trunk"; sw: Device }
  | { kind: "none" };

interface ValidSubif {
  port: number;
  vlan: number;
  ip?: string;
  prefix: number;
  relay?: string;
  key: string;
  label: string;
}

/** 라우터 역할 인터페이스 (호스트가 게이트웨이로 삼을 수 있는 것) */
interface GwIface {
  device: Device;
  key: string;
  /** 인스펙터·문구용 이름 (예: "gw-1 if1", "rt-1 LAN") */
  label: string;
  /** 인터페이스 칸 이름 (예: "if1", "if1.10", "LAN") */
  ifName: string;
  ip?: string;
  subnet?: Subnet;
  /** 안쪽(호스트가 붙는) 인터페이스인가. L3 의 if0/outside 는 false */
  inside: boolean;
  /** L3 장치의 업링크(포트 0) */
  uplink: boolean;
  gwKind: "l3" | "router" | "internet";
  port: number;
}

interface HostEp {
  device: Device;
  key: string;
  ip?: string;
  subnet?: Subnet;
}

interface Addr {
  device: Device;
  key: string;
  ip: string;
  label: string;
}

interface DhcpSrv {
  device: Device;
  key: string;
}

interface Members {
  gws: GwIface[];
  hosts: HostEp[];
  addrs: Addr[];
  dhcp: DhcpSrv[];
}

interface Model {
  ids: Map<string, number>;
  members: Map<number, Members>;
  /** 어떤 링크에라도 참여한 끝점 */
  linked: Set<string>;
  /** 트렁크 불일치로 고립된 끝점 (세그먼트 규칙에서 제외) */
  stranded: Set<string>;
  /** 규칙 13a: 트렁크 포트에 꽂힌 태그 미지원 장치 */
  onTrunk: { device: Device; sw: Device; swPort: number }[];
  /** 규칙 13b: 서브 인터페이스가 있는 포트의 상대가 트렁크가 아님 */
  subifNotTrunk: { device: Device; port: number; peer: Device; peerPort: number }[];
  /** 모든 라우터 역할 인터페이스 (세그먼트 무관) */
  allGws: GwIface[];
  gwsOf(key: string): GwIface[];
  membersOf(key: string): Members | undefined;
}

const INTERNET_IP = "203.0.113.1";
const INTERNET_PREFIX = 24;

function portName(d: Device, port: number): string {
  return DEVICE_SPECS[d.kind].ports[port]?.name ?? `포트 ${port}`;
}

function routerLanKey(d: Device): string {
  return `${d.id}:1`;
}

function bridgeKey(d: Device): string {
  return `br:${d.id}`;
}

function switchKey(d: Device, vlan: number): string {
  return `sw:${d.id}@${vlan}`;
}

function accessVlanOf(d: Device, port: number): number | "trunk" {
  const v = portVlanOf(d, port);
  if (v === "trunk") return "trunk";
  return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= 4094 ? v : 1;
}

/** effectiveL3 와 같은 기준으로 걸러낸 서브 인터페이스 (같은 포트·VLAN 은 앞의 것만) */
function validSubifs(d: Device): ValidSubif[] {
  const spec = DEVICE_SPECS[d.kind];
  const out: ValidSubif[] = [];
  const seen = new Set<string>();
  for (const s of d.l3?.subinterfaces ?? []) {
    if (!Number.isInteger(s.vlan) || s.vlan < 1 || s.vlan > 4094) continue;
    if (!Number.isInteger(s.port) || s.port < 1 || s.port >= spec.ports.length || spec.ports[s.port]!.radio) continue;
    const dup = `${s.port}:${s.vlan}`;
    if (seen.has(dup)) continue;
    seen.add(dup);
    out.push({ port: s.port, vlan: s.vlan, ip: validIp(s.ip), prefix: s.prefix, relay: validIp(s.relay), key: `${d.id}:${s.port}@${s.vlan}`, label: `${portName(d, s.port)}.${s.vlan}` });
  }
  return out;
}

function attachOf(d: Device, port: number): Attach {
  const spec = DEVICE_SPECS[d.kind];
  if (!spec.ports[port]) return { kind: "none" };
  switch (spec.role) {
    case "host":
    case "internet":
      return { kind: "end", key: `${d.id}:${port}` };
    case "router":
      return port === 0 ? { kind: "end", key: `${d.id}:0` } : { kind: "bridge", key: routerLanKey(d) };
    case "l3":
      return { kind: "end", key: `${d.id}:${port}`, subifs: validSubifs(d).filter((s) => s.port === port).map((s) => ({ vlan: s.vlan, key: s.key })) };
    case "hub":
    case "ap":
      return { kind: "bridge", key: bridgeKey(d) };
    case "firewall":
      // 투명 방화벽은 analyze 에서 케이블 두 개를 하나로 접어 없앤다. 여기 오면 한쪽만 꽂힌 것 → 고립
      return { kind: "none" };
    case "switch": {
      const v = accessVlanOf(d, port);
      return v === "trunk" ? { kind: "trunk", sw: d } : { kind: "access", key: switchKey(d, v) };
    }
  }
}

function analyze(t: Topology): Model {
  const byId = new Map(t.devices.map((d) => [d.id, d]));
  const uf = new Union();
  const linked = new Set<string>();
  const stranded = new Set<string>();
  const onTrunk: Model["onTrunk"] = [];
  const subifNotTrunk: Model["subifNotTrunk"] = [];

  // 트렁크끼리는 "존재하는 모든 VLAN" 을 통과시킨다
  const vlanUniverse = new Set<number>([1]);
  for (const d of t.devices) {
    if (d.kind === "switch") for (const v of Object.values(d.switch?.vlans ?? {})) if (typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= 4094) vlanUniverse.add(v);
    if (DEVICE_SPECS[d.kind].role === "l3") for (const s of validSubifs(d)) vlanUniverse.add(s.vlan);
  }

  // 공유기 LAN 포트와 무선 슬롯은 한 브리지
  for (const d of t.devices) {
    if (d.kind !== "router") continue;
    const spec = DEVICE_SPECS[d.kind];
    for (let p = 1; p < spec.ports.length; p++) uf.union(`${d.id}:${p}`, routerLanKey(d));
  }

  // 투명 방화벽(IP 없는 브리지)은 L2 로는 전선과 같다: 양쪽 케이블을 하나로 접어 방화벽 너머의 장치끼리 직접 잇는다
  const rawLinks = [
    ...t.cables.map((c) => ({ a: c.a, b: c.b })),
    ...wirelessLinks(t).map((l) => ({ a: { device: l.client, port: 0 }, b: { device: l.base, port: l.slot } })),
  ];
  const links: { a: PortRef; b: PortRef }[] = [];
  const fwEnds = new Map<string, PortRef[]>(); // 방화벽 id → 양쪽 끝 (outside 쪽, inside 쪽)
  for (const l of rawLinks) {
    const fa = byId.get(l.a.device)?.kind === "firewall";
    const fb = byId.get(l.b.device)?.kind === "firewall";
    if (fa && fb) continue; // 방화벽끼리 직결: 보수적으로 무시
    if (fa) (fwEnds.get(l.a.device) ?? fwEnds.set(l.a.device, []).get(l.a.device)!)[l.a.port] = l.b;
    else if (fb) (fwEnds.get(l.b.device) ?? fwEnds.set(l.b.device, []).get(l.b.device)!)[l.b.port] = l.a;
    else links.push(l);
  }
  for (const ends of fwEnds.values()) if (ends[0] && ends[1]) links.push({ a: ends[0], b: ends[1] });
  const mark = (a: Attach) => {
    if (a.kind === "end" || a.kind === "bridge" || a.kind === "access") linked.add(a.key);
    if (a.kind === "end") for (const s of a.subifs ?? []) linked.add(s.key);
  };
  for (const { a, b } of links) {
    const da = byId.get(a.device);
    const db = byId.get(b.device);
    if (!da || !db) continue;
    const A = attachOf(da, a.port);
    const B = attachOf(db, b.port);
    if (A.kind === "none" || B.kind === "none") continue;
    mark(A);
    mark(B);
    if (A.kind === "trunk" || B.kind === "trunk") {
      const trunkSide = A.kind === "trunk" ? { sw: da, port: a.port } : { sw: db, port: b.port };
      const other = A.kind === "trunk" ? { attach: B, device: db } : { attach: A, device: da };
      const o = other.attach;
      if (o.kind === "trunk") {
        for (const v of vlanUniverse) uf.union(switchKey(trunkSide.sw, v), switchKey(o.sw, v));
      } else if (o.kind === "end" && o.subifs && o.subifs.length > 0) {
        // 게이트웨이 서브 인터페이스: VLAN 마다 스위치의 그 VLAN 도메인에 붙는다. 물리 인터페이스(태그 없음)는 고립
        for (const s of o.subifs) uf.union(switchKey(trunkSide.sw, s.vlan), s.key);
        stranded.add(o.key);
      } else if (o.kind === "access") {
        // 트렁크 ↔ 액세스: 양쪽 다 상대 프레임을 버린다 → 잇지 않음
      } else if (o.kind === "end" && DEVICE_SPECS[other.device.kind].role === "l3") {
        // 서브 인터페이스 없는 L3 물리 포트가 트렁크에: 태그 없는 프레임은 버려진다 → 고립
        stranded.add(o.key);
      } else {
        // 호스트·공유기·허브·AP·인터넷: 태그 프레임을 이해하지 못함
        stranded.add(o.key);
        onTrunk.push({ device: other.device, sw: trunkSide.sw, swPort: trunkSide.port });
      }
      continue;
    }
    // 여기부터 양쪽 다 트렁크가 아님: 물리 인터페이스끼리 잇는다
    uf.union(A.key, B.key);
    const sides = [
      { attach: A, device: da, port: a.port, peer: db, peerPort: b.port },
      { attach: B, device: db, port: b.port, peer: da, peerPort: a.port },
    ];
    for (const s of sides) {
      if (s.attach.kind === "end" && s.attach.subifs && s.attach.subifs.length > 0) {
        for (const sub of s.attach.subifs) stranded.add(sub.key);
        subifNotTrunk.push({ device: s.device, port: s.port, peer: s.peer, peerPort: s.peerPort });
      }
    }
  }

  // 끝점 인터페이스 → 세그먼트 id (장치 순서대로 번호를 매긴다)
  const ids = new Map<string, number>();
  const rootId = new Map<string, number>();
  const register = (key: string) => {
    const r = uf.find(key);
    let id = rootId.get(r);
    if (id === undefined) {
      id = rootId.size;
      rootId.set(r, id);
    }
    ids.set(key, id);
    return id;
  };
  const members = new Map<number, Members>();
  const memberOf = (id: number): Members => {
    let m = members.get(id);
    if (!m) {
      m = { gws: [], hosts: [], addrs: [], dhcp: [] };
      members.set(id, m);
    }
    return m;
  };
  const allGws: GwIface[] = [];
  const addGw = (g: GwIface) => {
    allGws.push(g);
    memberOf(register(g.key)).gws.push(g);
    if (g.ip) memberOf(ids.get(g.key)!).addrs.push({ device: g.device, key: g.key, ip: g.ip, label: g.label });
  };

  for (const d of t.devices) {
    const spec = DEVICE_SPECS[d.kind];
    if (spec.role === "host" && d.host) {
      const key = `${d.id}:0`;
      const id = register(key);
      const h = d.host;
      const ip = h.ipMode === "static" ? validIp(h.ip) : undefined;
      const m = memberOf(id);
      m.hosts.push({ device: d, key, ip, subnet: ip ? subnetOf(ip, h.prefix) : undefined });
      if (ip) m.addrs.push({ device: d, key, ip, label: `${d.name} IP` });
      // DHCP 모드 호스트의 DHCP 서비스는 동작하지 않는다 ("내 주소가 고정이 아님") → 서버로 세지 않음
      if (h.dhcpServer.enabled && ip) m.dhcp.push({ device: d, key });
    } else if (spec.role === "internet") {
      addGw({ device: d, key: `${d.id}:0`, label: `${d.name} ISP`, ifName: "isp", ip: INTERNET_IP, subnet: subnetOf(INTERNET_IP, INTERNET_PREFIX), inside: true, uplink: false, gwKind: "internet", port: 0 });
    } else if (spec.role === "router" && d.router) {
      const r = d.router;
      const wanKey = `${d.id}:0`;
      register(wanKey);
      const wan = r.wan;
      const wanIp = wan?.ipMode === "static" ? validIp(wan.ip) : undefined;
      if (wanIp) memberOf(ids.get(wanKey)!).addrs.push({ device: d, key: wanKey, ip: wanIp, label: `${d.name} WAN` });
      const lanIp = validIp(r.lanIp);
      addGw({ device: d, key: routerLanKey(d), label: `${d.name} LAN`, ifName: "LAN", ip: lanIp, subnet: subnetOf(lanIp, r.lanPrefix), inside: true, uplink: false, gwKind: "router", port: 1 });
      for (let p = 2; p < spec.ports.length; p++) register(`${d.id}:${p}`);
      if (r.dhcp.enabled) memberOf(ids.get(routerLanKey(d))!).dhcp.push({ device: d, key: routerLanKey(d) });
    } else if (spec.role === "l3" && d.l3) {
      spec.ports.forEach((p, i) => {
        const c = d.l3!.interfaces[i];
        const ip = c && c.ipMode === "static" ? validIp(c.ip) : undefined;
        addGw({ device: d, key: `${d.id}:${i}`, label: `${d.name} ${p.name}`, ifName: p.name, ip, subnet: c ? subnetOf(ip, c.prefix) : undefined, inside: i > 0, uplink: i === 0, gwKind: "l3", port: i });
      });
      for (const s of validSubifs(d)) {
        addGw({ device: d, key: s.key, label: `${d.name} ${s.label}`, ifName: s.label, ip: s.ip, subnet: subnetOf(s.ip, s.prefix), inside: true, uplink: false, gwKind: "l3", port: s.port });
      }
    }
  }

  return {
    ids,
    members,
    linked,
    stranded,
    onTrunk,
    subifNotTrunk,
    allGws,
    gwsOf: (key) => {
      const id = ids.get(key);
      return id === undefined ? [] : (members.get(id)?.gws ?? []);
    },
    membersOf: (key) => {
      const id = ids.get(key);
      return id === undefined ? undefined : members.get(id);
    },
  };
}

/**
 * 장치 인터페이스 단위 L2 세그먼트(브로드캐스트 도메인) id.
 * 키는 `"<장치 id>:<포트>"`. 호스트·인터넷은 포트 0, 공유기는 0 = WAN 이고 1..12(LAN·무선 슬롯)는 모두 같은 id,
 * 게이트웨이/NAT 는 인터페이스마다 다르며 서브 인터페이스는 `"<장치 id>:<포트>@<VLAN>"`.
 * 스위치·허브·AP 는 통과(같은 도메인으로 합침)하므로 키가 없다. 케이블이 없는 인터페이스도 자기만의 id 를 받는다.
 */
export function l2Segments(t: Topology): Map<string, number> {
  return analyze(t).ids;
}

// ---------- 규칙 ----------

const SEVERITY_RANK = { error: 0, warn: 1 } as const;

function names(devices: Device[]): string {
  return devices.map((d) => d.name).join(", ");
}

function uniqueDevices(list: { device: Device }[], exclude?: Device): Device[] {
  const seen = new Set<string>();
  const out: Device[] = [];
  for (const { device } of list) {
    if (device === exclude || seen.has(device.id)) continue;
    seen.add(device.id);
    out.push(device);
  }
  return out;
}

/** 후보 라우터 인터페이스 중 참조 주소와 같은 서브넷인 것을 우선, 없으면 주소를 아는 첫 번째 */
function pickGw(gws: GwIface[], ref: string | undefined): GwIface | undefined {
  const known = gws.filter((g) => g.ip && g.subnet);
  if (ref) {
    const same = known.find((g) => contains(g.subnet!, ref));
    if (same) return same;
  }
  return known[0] ?? gws[0];
}

/** Y(게이트웨이) 뒤에 있는 서브넷들: Y 의 안쪽 인터페이스 + 그 아래 또 다른 게이트웨이 뒤까지 (NAT 박스 뒤는 주소가 바뀌므로 제외) */
function subnetsBehind(y: Device, m: Model, visited: Set<string>): { subnet: Subnet; owner: Device }[] {
  if (visited.has(y.id)) return [];
  visited.add(y.id);
  const out: { subnet: Subnet; owner: Device }[] = [];
  for (const g of m.allGws) {
    if (g.device !== y || !g.inside) continue;
    if (g.subnet) out.push({ subnet: g.subnet, owner: y });
    for (const z of m.gwsOf(g.key)) {
      if (z.device !== y && z.uplink && z.device.kind === "gateway") out.push(...subnetsBehind(z.device, m, visited));
    }
  }
  return out;
}

export function lintTopology(t: Topology): LintIssue[] {
  const m = analyze(t);
  const issues: LintIssue[] = [];
  const add = (i: LintIssue) => issues.push(i);
  /** 규칙 3·4 에 이미 걸린 호스트 (규칙 11 은 같은 원인의 약한 진술이라 생략) */
  const flaggedHosts = new Set<string>();

  // 규칙 1·2·5(DHCP 서버 쪽): 호스트 DHCP 서비스의 게이트웨이/DNS 안내
  for (const d of t.devices) {
    const h = d.host;
    // 주소를 DHCP 로 받는 호스트의 DHCP 서비스는 코어에서 동작하지 않으므로("내 주소가 고정이 아님") 안내 내용을 검사하지 않는다
    if (!h?.dhcpServer.enabled || h.ipMode !== "static") continue;
    const key = `${d.id}:0`;
    const gws = m.gwsOf(key);
    const srv = h.dhcpServer;
    const router = validIp(srv.router);
    const ownIp = h.ipMode === "static" ? validIp(h.ip) : undefined;
    const ownDns = h.dnsServer?.enabled && ownIp ? ownIp : undefined;
    if (!router) {
      if (gws.length > 0 && !m.stranded.has(key)) {
        const pick = pickGw(gws, validIp(srv.start) ?? ownIp);
        add({
          deviceId: d.id,
          severity: "warn",
          code: "dhcp.no-router",
          message: `DHCP 로 주소는 나가지만 게이트웨이를 알려주지 않아 단말이 다른 네트워크로 못 나감`,
          fix: `${d.name} → DHCP 서비스 → 게이트웨이 칸에 ${pick?.ip ?? `${pick?.label ?? "이 세그먼트 라우터 인터페이스"} 의 주소`} 입력`,
          related: pick ? [pick.device.id] : undefined,
        });
      }
    } else {
      if (!validIp(srv.dns)) {
        const fwd = gws.find((g) => g.gwKind === "router" && g.ip);
        add({
          deviceId: d.id,
          severity: "warn",
          code: "dhcp.no-dns",
          message: `DHCP 가 DNS 서버를 알려주지 않아 단말이 이름(google.com 등)을 해석하지 못함`,
          fix: `${d.name} → DHCP 서비스 → DNS 칸에 ${ownDns ?? fwd?.ip ?? "8.8.8.8"} 입력${ownDns ? " (이 서버의 DNS 서비스)" : fwd ? ` (${fwd.device.name} 의 DNS 포워더)` : ""}`,
        });
      }
      if (m.linked.has(key) && !m.stranded.has(key) && gws.length === 0) {
        add({
          deviceId: d.id,
          severity: "warn",
          code: "segment.no-router",
          message: `이 서브넷엔 게이트웨이 장치가 없는데 DHCP 가 게이트웨이 ${router} 를 안내함 → 단말이 존재하지 않는 주소로 보냄`,
          fix: `게이트웨이/NAT 박스나 공유기를 이 스위치에 연결하고 그 인터페이스 주소를 ${router} 로 맞추거나, DHCP 서비스의 게이트웨이 칸을 비우기`,
        });
      }
    }
    (srv.extraPools ?? []).forEach((p, i) => {
      const start = validIp(p.start);
      const poolNet = subnetOf(start, p.prefix);
      if (!start || !poolNet) return;
      const poolRouter = validIp(p.router);
      if (!poolRouter) {
        const cand = m.allGws.find((g) => g.ip && g.inside && contains(poolNet, g.ip));
        if (!cand) return; // 그 서브넷에 라우터 인터페이스가 없으면 릴레이 자체가 안 되므로 추측하지 않음
        add({
          deviceId: d.id,
          severity: "warn",
          code: "dhcp.no-router",
          message: `추가 풀 ${fmtSubnet(poolNet)} 이 게이트웨이를 알려주지 않아 그 서브넷 단말이 다른 네트워크로 못 나감`,
          fix: `${d.name} → DHCP 서비스 → 추가 풀 ${i + 1} → 게이트웨이 칸에 ${cand.ip} (${cand.label}) 입력`,
          related: [cand.device.id],
        });
      } else if (!validIp(p.dns)) {
        add({
          deviceId: d.id,
          severity: "warn",
          code: "dhcp.no-dns",
          message: `추가 풀 ${fmtSubnet(poolNet)} 이 DNS 서버를 알려주지 않아 그 서브넷 단말이 이름을 해석하지 못함`,
          fix: `${d.name} → DHCP 서비스 → 추가 풀 ${i + 1} → DNS 칸에 ${ownDns ?? "8.8.8.8"} 입력`,
        });
      }
    });
  }

  // 규칙 3·4·5·11(호스트 쪽): 수동 호스트의 게이트웨이와 서브넷
  for (const d of t.devices) {
    const h = d.host;
    if (!h || h.ipMode !== "static") continue;
    const key = `${d.id}:0`;
    const ip = validIp(h.ip);
    const gw = validIp(h.gateway);
    const own = subnetOf(ip, h.prefix);
    if (ip && gw && own && !contains(own, gw)) {
      flaggedHosts.add(d.id);
      add({
        deviceId: d.id,
        severity: "error",
        code: "host.gateway-outside-subnet",
        message: `게이트웨이 ${gw} 가 내 서브넷 ${fmtSubnet(own)} 밖 → ARP 로 찾을 수 없어 어디로도 못 나감`,
        fix: `${d.name} → IP 설정 → 게이트웨이를 ${fmtSubnet(own)} 안의 라우터 주소로 바꾸거나, IP/서브넷 마스크를 게이트웨이와 같은 서브넷으로`,
      });
    }
    const inSegment = m.linked.has(key) && !m.stranded.has(key);
    const gws = inSegment ? m.gwsOf(key) : [];
    if (gw && inSegment) {
      if (gws.length === 0) {
        flaggedHosts.add(d.id);
        add({
          deviceId: d.id,
          severity: "warn",
          code: "segment.no-router",
          message: `이 서브넷엔 게이트웨이 장치가 없음 → 게이트웨이 ${gw} 로 보낸 패킷은 응답 없이 사라짐`,
          fix: `게이트웨이/NAT 박스나 공유기를 이 스위치에 연결하고 그 인터페이스 주소를 ${gw} 로 맞추기 (같은 서브넷 안에서만 통신한다면 게이트웨이 칸을 비워도 됨)`,
        });
      } else if (gws.every((g) => g.ip) && !gws.some((g) => g.ip === gw)) {
        const pick = pickGw(gws, ip);
        flaggedHosts.add(d.id);
        add({
          deviceId: d.id,
          severity: "warn",
          code: "host.no-gateway-in-segment",
          message: `게이트웨이 ${gw} 가 같은 세그먼트의 라우터 주소(${gws.map((g) => g.ip).join(", ")})와 다름 → ARP 응답 없음`,
          fix: `${d.name} → IP 설정 → 게이트웨이 칸을 ${pick?.ip ?? gws[0]!.ip} (${pick?.label ?? gws[0]!.label}) 로 바꾸거나, 케이블을 ${gw} 를 가진 라우터 쪽 스위치로 옮기기`,
          related: uniqueDevices(gws).map((x) => x.id),
        });
      }
    }
    if (ip && inSegment && !flaggedHosts.has(d.id)) {
      const refs = gws.filter((g) => g.subnet);
      if (refs.length > 0 && !refs.some((g) => contains(g.subnet!, ip))) {
        const pick = pickGw(refs, undefined)!;
        add({
          deviceId: d.id,
          severity: "warn",
          code: "segment.mixed-subnet",
          message: `IP ${ip}/${h.prefix} 가 이 세그먼트 라우터의 서브넷(${refs.map((g) => fmtSubnet(g.subnet!)).join(", ")}) 밖 → 라우터가 응답을 돌려보내지 못함`,
          fix: `${d.name} → IP 설정 → IP 를 ${fmtSubnet(pick.subnet!)} 안의 주소로 바꾸기 (게이트웨이 ${pick.ip})`,
          related: uniqueDevices(refs).map((x) => x.id),
        });
      }
    }
  }

  // 규칙 6: 게이트웨이/NAT 업링크(if0/outside)가 수동인데 디폴트 라우트 없음
  for (const d of t.devices) {
    if (DEVICE_SPECS[d.kind].role !== "l3" || !d.l3) continue;
    const c = d.l3.interfaces[0];
    if (!c || c.ipMode !== "static") continue;
    const ip = validIp(c.ip);
    if (!ip || validIp(c.gateway)) continue;
    const key = `${d.id}:0`;
    // 위쪽에 "안쪽 인터페이스"(다른 라우터의 LAN 쪽·인터넷)가 있을 때만: 게이트웨이끼리 if0 을 맞댄 백본은 디폴트 라우트가 필요 없다
    const ups = m.gwsOf(key).filter((g) => g.device !== d && g.inside);
    if (ups.length === 0) continue;
    const pick = pickGw(ups, ip);
    const name = portName(d, 0);
    add({
      deviceId: d.id,
      severity: "error",
      code: "l3.uplink-no-default",
      message: `${name} 에 주소 ${ip} 는 있지만 디폴트 라우트(게이트웨이)가 없음 → 바깥으로 나가는 패킷을 보낼 곳이 없어 드롭`,
      fix: `${d.name} → ${name} → 게이트웨이 칸에 ${pick?.ip ?? `위쪽 라우터(${pick?.label ?? "?"}) 의 주소`} 입력`,
      related: pick ? [pick.device.id] : undefined,
    });
  }

  // 규칙 7: 안쪽에 또 다른 게이트웨이가 있는데 그 뒤 서브넷으로 돌아가는 스태틱 라우팅 없음
  for (const x of t.devices) {
    const role = DEVICE_SPECS[x.kind].role;
    if (role !== "l3" && role !== "router") continue;
    const routes = (x.l3?.routes ?? []).map((r) => ({ subnet: subnetOf(validIp(r.dest), r.prefix), via: validIp(r.via) })).filter((r) => r.subnet && r.via) as { subnet: Subnet; via: string }[];
    const missing: { subnet: Subnet; y: Device; owner: Device }[] = [];
    const seenSeg = new Set<number>();
    for (const g of m.allGws) {
      if (g.device !== x || !g.inside) continue;
      const seg = m.ids.get(g.key)!;
      if (seenSeg.has(seg)) continue;
      seenSeg.add(seg);
      for (const y of m.gwsOf(g.key)) {
        if (y.device === x || !y.uplink || y.device.kind !== "gateway") continue;
        for (const s of subnetsBehind(y.device, m, new Set([x.id]))) {
          if (routes.some((r) => covers(r.subnet, s.subnet))) continue;
          if (!missing.some((q) => q.subnet.net === s.subnet.net && q.subnet.prefix === s.subnet.prefix)) missing.push({ subnet: s.subnet, y: y.device, owner: s.owner });
        }
      }
    }
    if (missing.length === 0) continue;
    const ys = uniqueDevices(missing.map((q) => ({ device: q.y })));
    const list = missing.map((q) => fmtSubnet(q.subnet)).join(", ");
    const hop = (y: Device) => {
      const c = y.l3?.interfaces[0];
      const ip = c?.ipMode === "static" ? validIp(c.ip) : undefined;
      return ip ?? `${y.name} 의 ${portName(y, 0)} 주소 (DHCP 로 받는 주소라 수동으로 고정하는 편이 안전)`;
    };
    // 같은 넥스트 홉끼리 묶어 "A, B (넥스트 홉 X)" 로
    const byHop = new Map<string, Subnet[]>();
    for (const q of missing) byHop.set(hop(q.y), [...(byHop.get(hop(q.y)) ?? []), q.subnet]);
    const entries = [...byHop].map(([h, subs]) => `${subs.map(fmtSubnet).join(", ")} → 넥스트 홉 ${h}`).join("; ");
    add({
      deviceId: x.id,
      severity: "error",
      code: "l3.no-return-route",
      message: `${names(ys)} 뒤 ${list} 로 돌아가는 경로가 없어 그쪽에서 나온 통신의 응답이 ${x.name} 에서 버려짐`,
      fix:
        role === "router"
          ? `공유기는 스태틱 라우팅이 없음 → ${x.name} 자리에 게이트웨이나 NAT 박스를 쓰거나, ${names(ys)} 를 없애고 스위치로 바꾸기`
          : `${x.name} → 스태틱 라우팅에 ${entries} 추가`,
      related: ys.map((y) => y.id),
    });
  }

  // 규칙 8: 한 장치의 인터페이스끼리 서브넷 겹침
  for (const d of t.devices) {
    if (DEVICE_SPECS[d.kind].role !== "l3") continue;
    const ifs = m.allGws.filter((g) => g.device === d && g.subnet);
    const pairs: [GwIface, GwIface][] = [];
    for (let i = 0; i < ifs.length; i++) for (let j = i + 1; j < ifs.length; j++) if (overlaps(ifs[i]!.subnet!, ifs[j]!.subnet!)) pairs.push([ifs[i]!, ifs[j]!]);
    if (pairs.length === 0) continue;
    add({
      deviceId: d.id,
      severity: "error",
      code: "l3.subnet-overlap",
      message: `${pairs.map(([a, b]) => `${a.ifName} ${fmtSubnet(a.subnet!)} 와 ${b.ifName} ${fmtSubnet(b.subnet!)}`).join(", ")} 서브넷이 겹침 → 어느 인터페이스로 보낼지 정할 수 없음`,
      fix: `${d.name} → ${pairs[0]![1].ifName} → IP/서브넷 마스크를 다른 서브넷으로 (인터페이스마다 서브넷이 달라야 함)`,
    });
  }

  // 규칙 9·10: 세그먼트 안의 DHCP 서버 중복과 IP 중복
  for (const mem of m.members.values()) {
    if (mem.dhcp.length >= 2) {
      const all = uniqueDevices(mem.dhcp);
      for (const d of all) {
        const others = all.filter((x) => x !== d);
        add({
          deviceId: d.id,
          severity: "warn",
          code: "segment.two-dhcp",
          message: `같은 세그먼트에 DHCP 서버가 ${all.length}개 (${names(all)}) → 단말이 어느 쪽 주소·게이트웨이를 받을지 정해지지 않음`,
          fix: `하나만 남기고 ${names(others)} 의 DHCP 서비스를 끄기`,
          related: others.map((x) => x.id),
        });
      }
    }
    const byIp = new Map<string, Addr[]>();
    for (const a of mem.addrs) byIp.set(a.ip, [...(byIp.get(a.ip) ?? []), a]);
    for (const [ip, list] of byIp) {
      if (list.length < 2) continue;
      for (const a of list) {
        const others = list.filter((x) => x !== a);
        add({
          deviceId: a.device.id,
          severity: "error",
          code: "segment.duplicate-ip",
          message: `IP ${ip} 가 같은 세그먼트의 ${others.map((x) => x.label).join(", ")} 와 겹침 → ARP 응답이 뒤섞여 통신 불안정`,
          fix: `${a.label} 주소를 다른 것으로 바꾸기 (같은 세그먼트에서 같은 IP 는 하나만)`,
          related: uniqueDevices(others, a.device).map((x) => x.id),
        });
      }
    }
  }

  // 규칙 11(업링크 쪽): L3 if0/공유기 WAN 의 수동 주소가 위쪽 라우터 서브넷 밖
  for (const d of t.devices) {
    const role = DEVICE_SPECS[d.kind].role;
    let key: string | undefined;
    let ip: string | undefined;
    let prefix = 0;
    if (role === "l3" && d.l3) {
      const c = d.l3.interfaces[0];
      if (c?.ipMode === "static") {
        key = `${d.id}:0`;
        ip = validIp(c.ip);
        prefix = c.prefix;
      }
    } else if (role === "router" && d.router?.wan?.ipMode === "static") {
      key = `${d.id}:0`;
      ip = validIp(d.router.wan.ip);
      prefix = d.router.wan.prefix;
    }
    if (!key || !ip || !m.linked.has(key) || m.stranded.has(key)) continue;
    const refs = m.gwsOf(key).filter((g) => g.device !== d && g.inside && g.subnet);
    if (refs.length === 0 || refs.some((g) => contains(g.subnet!, ip!))) continue;
    const pick = pickGw(refs, undefined)!;
    const name = portName(d, 0);
    add({
      deviceId: d.id,
      severity: "warn",
      code: "segment.mixed-subnet",
      message: `${name} 주소 ${ip}/${prefix} 가 위쪽 라우터의 서브넷(${refs.map((g) => fmtSubnet(g.subnet!)).join(", ")}) 밖 → 서로 닿지 않음`,
      fix: `${d.name} → ${name} → IP 를 ${fmtSubnet(pick.subnet!)} 안의 주소로, 게이트웨이를 ${pick.ip} 로`,
      related: uniqueDevices(refs).map((x) => x.id),
    });
  }

  // 규칙 12: DHCP 릴레이 대상에 닿을 경로 없음
  for (const d of t.devices) {
    if (DEVICE_SPECS[d.kind].role !== "l3" || !d.l3) continue;
    const ifs = d.l3.interfaces;
    // DHCP 로 받는 인터페이스나 수동 게이트웨이가 있으면 디폴트 라우트가 생기므로 통과로 본다
    const hasDefault = ifs.some((c) => c && (c.ipMode === "dhcp" || validIp(c.gateway)));
    if (hasDefault) continue;
    const connected = m.allGws.filter((g) => g.device === d && g.subnet).map((g) => g.subnet!);
    const routes = (d.l3.routes ?? []).map((r) => subnetOf(validIp(r.dest), r.prefix)).filter((s): s is Subnet => !!s);
    const targets: { ifName: string; relay: string }[] = [];
    ifs.forEach((c, i) => {
      const relay = validIp(c?.relay);
      if (relay) targets.push({ ifName: portName(d, i), relay });
    });
    for (const s of validSubifs(d)) if (s.relay) targets.push({ ifName: s.label, relay: s.relay });
    for (const tgt of targets) {
      if (connected.some((s) => contains(s, tgt.relay)) || routes.some((s) => contains(s, tgt.relay))) continue;
      add({
        deviceId: d.id,
        severity: "warn",
        code: "relay.unreachable",
        message: `${tgt.ifName} 의 DHCP 릴레이 대상 ${tgt.relay} 로 가는 경로가 없음 (어느 인터페이스 서브넷에도 없고 정적·디폴트 라우트도 없음)`,
        fix: `${d.name} → 스태틱 라우팅에 ${tgt.relay}/32 를 추가하거나, ${tgt.ifName} 의 릴레이 칸을 이 장치 인터페이스 서브넷 안의 DHCP 서버 주소로`,
      });
    }
  }

  // 규칙 13a: 트렁크 포트에 태그를 모르는 장치
  for (const { device, sw, swPort } of m.onTrunk) {
    add({
      deviceId: device.id,
      severity: "error",
      code: "vlan.host-on-trunk",
      message: `${sw.name} 의 트렁크 포트 ${portName(sw, swPort)} 에 연결됨 → ${DEVICE_SPECS[device.kind].label} 는 802.1Q 태그를 이해하지 못해 통신 불가`,
      fix: `${sw.name} → VLAN → ${portName(sw, swPort)} 를 액세스(VLAN 번호)로 바꾸기`,
      related: [sw.id],
    });
  }
  // 규칙 13b: 서브 인터페이스가 있는 포트의 상대가 트렁크가 아님
  for (const { device, port, peer, peerPort } of m.subifNotTrunk) {
    const isSwitch = peer.kind === "switch";
    add({
      deviceId: device.id,
      severity: "error",
      code: "vlan.subif-not-trunk",
      message: `${portName(device, port)} 에 VLAN 서브 인터페이스가 있는데 상대 ${peer.name} ${portName(peer, peerPort)} 가 트렁크가 아님 → 태그 프레임이 버려짐`,
      fix: isSwitch ? `${peer.name} → VLAN → ${portName(peer, peerPort)} 를 트렁크로 바꾸기` : `${portName(device, port)} 을 스위치의 트렁크 포트에 연결하거나 서브 인터페이스를 지우기`,
      related: [peer.id],
    });
  }

  return finalize(issues, t);
}

/** 같은 (장치, code) 는 하나로 합치고, error → warn, 그다음 장치 순서로 정렬 */
function finalize(issues: LintIssue[], t: Topology): LintIssue[] {
  const index = new Map(t.devices.map((d, i) => [d.id, i]));
  const seen = new Map<string, LintIssue>();
  const kept: LintIssue[] = [];
  for (const i of issues) {
    const k = `${i.deviceId}\u0000${i.code}`;
    const prev = seen.get(k);
    if (prev) {
      if (i.related) prev.related = [...new Set([...(prev.related ?? []), ...i.related])];
      continue;
    }
    const copy = { ...i, related: i.related?.filter((r) => r !== i.deviceId) };
    if (!copy.related || copy.related.length === 0) delete copy.related;
    seen.set(k, copy);
    kept.push(copy);
  }
  return kept
    .map((i, n) => ({ i, n }))
    .sort((a, b) => SEVERITY_RANK[a.i.severity] - SEVERITY_RANK[b.i.severity] || (index.get(a.i.deviceId) ?? 0) - (index.get(b.i.deviceId) ?? 0) || a.n - b.n)
    .map((x) => x.i);
}
