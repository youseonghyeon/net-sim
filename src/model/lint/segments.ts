// L2 세그먼트 모델: 케이블·무선·VLAN·투명 방화벽을 따라 인터페이스를 브로드캐스트 도메인으로 묶고,
// 세그먼트마다 라우터 인터페이스·호스트·주소·DHCP 서버를 모은다. 규칙들은 이 모델(`analyze`)을 본다.
import { DEVICE_SPECS, ROUTER_WAN2_PORT, portVlanOf, specOf, wirelessLinks, type Device, type PortRef, type Topology } from "../topology";
import { subnetOf, validIp, type Subnet } from "./addr";

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

export interface ValidSubif {
  port: number;
  vlan: number;
  ip?: string;
  prefix: number;
  relay?: string;
  key: string;
  label: string;
}

/** 라우터 역할 인터페이스 (호스트가 게이트웨이로 삼을 수 있는 것) */
export interface GwIface {
  device: Device;
  key: string;
  /** 인스펙터·문구용 이름 (예: "gw-1 if1", "rt-1 LAN") */
  label: string;
  /** 인터페이스 칸 이름 (예: "if1", "if1.10", "LAN") */
  ifName: string;
  ip?: string;
  /** 이중화(HA)를 켠 L3 인터페이스의 가상 주소 — 호스트 게이트웨이로 이 주소를 써도 된다 */
  vip?: string;
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

export interface Addr {
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

export interface Model {
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

export function portName(d: Device, port: number): string {
  return specOf(d).ports[port]?.name ?? `포트 ${port}`;
}

export function routerLanKey(d: Device): string {
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
export function validSubifs(d: Device): ValidSubif[] {
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
      // 멀티 WAN 이면 lan4 는 WAN2 (공유기 LAN 브리지가 아니라 따로 끝점)
      return port === 0 || (port === ROUTER_WAN2_PORT && d.router?.wan2?.enabled) ? { kind: "end", key: `${d.id}:${port}` } : { kind: "bridge", key: routerLanKey(d) };
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

export function analyze(t: Topology): Model {
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
    for (let p = 1; p < spec.ports.length; p++) if (!(p === ROUTER_WAN2_PORT && d.router?.wan2?.enabled)) uf.union(`${d.id}:${p}`, routerLanKey(d));
  }

  // 투명 방화벽(IP 없는 브리지)은 L2 로는 전선과 같다: 양쪽 케이블을 하나로 접어 방화벽 너머의 장치끼리 직접 잇는다
  const rawLinks = [
    ...t.cables.map((c) => ({ a: c.a, b: c.b })),
    // 단말 쪽은 호스트 끝점(포트 0)으로 본다. 노트북의 대기 중 Wi-Fi(유선이 꽂힘)는 쓰지 않으므로 뺀다
    ...wirelessLinks(t)
      .filter((l) => !l.standby)
      .map((l) => ({ a: { device: l.client, port: 0 }, b: { device: l.base, port: l.slot } })),
  ];
  const links: { a: PortRef; b: PortRef }[] = [];
  const isFw = (id: string) => byId.get(id)?.kind === "firewall";
  // 포트 → 케이블 반대편 (방화벽 체인을 따라가기 위해)
  const peerOfPort = new Map<string, PortRef>();
  for (const l of rawLinks) {
    peerOfPort.set(`${l.a.device}:${l.a.port}`, l.b);
    peerOfPort.set(`${l.b.device}:${l.b.port}`, l.a);
  }
  /** 방화벽으로 들어간 끝을 반대 포트로 계속 따라가 방화벽이 아닌 첫 장치를 찾는다. 끊기거나 루프면 undefined */
  const through = (end: PortRef): PortRef | undefined => {
    const seen = new Set<string>();
    let cur: PortRef | undefined = end;
    while (cur && isFw(cur.device)) {
      if (seen.has(cur.device)) return undefined;
      seen.add(cur.device);
      cur = peerOfPort.get(`${cur.device}:${cur.port === 0 ? 1 : 0}`);
    }
    return cur;
  };
  const folded = new Set<string>();
  for (const l of rawLinks) {
    if (!isFw(l.a.device) && !isFw(l.b.device)) {
      links.push(l);
      continue;
    }
    // 방화벽이 낀 케이블: 방화벽 쪽 끝은 반대 포트 너머(체인이면 끝까지)로 바꿔 한 번만 잇는다
    const left = isFw(l.a.device) ? through(peerOfPort.get(`${l.a.device}:${l.a.port === 0 ? 1 : 0}`) ?? { device: "", port: -1 }) : l.a;
    const right = isFw(l.b.device) ? through(peerOfPort.get(`${l.b.device}:${l.b.port === 0 ? 1 : 0}`) ?? { device: "", port: -1 }) : l.b;
    if (!left || !right || !byId.has(left.device) || !byId.has(right.device)) continue;
    const key = [`${left.device}:${left.port}`, `${right.device}:${right.port}`].sort().join("|");
    if (folded.has(key)) continue;
    folded.add(key);
    links.push({ a: left, b: right });
  }
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
        // 서브 인터페이스 없는 L3 물리 포트가 트렁크에: 태그 없는 프레임은 드롭된다 → 고립
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
      if (r.wan2?.enabled) {
        const k2 = `${d.id}:${ROUTER_WAN2_PORT}`;
        register(k2);
        const ip2 = r.wan2.ipMode === "static" ? validIp(r.wan2.ip) : undefined;
        if (ip2) memberOf(ids.get(k2)!).addrs.push({ device: d, key: k2, ip: ip2, label: `${d.name} WAN2` });
      }
      const lanIp = validIp(r.lanIp);
      addGw({ device: d, key: routerLanKey(d), label: `${d.name} LAN`, ifName: "LAN", ip: lanIp, subnet: subnetOf(lanIp, r.lanPrefix), inside: true, uplink: false, gwKind: "router", port: 1 });
      for (let p = 2; p < spec.ports.length; p++) register(`${d.id}:${p}`);
      if (r.dhcp.enabled) memberOf(ids.get(routerLanKey(d))!).dhcp.push({ device: d, key: routerLanKey(d) });
    } else if (spec.role === "l3" && d.l3) {
      spec.ports.forEach((p, i) => {
        const c = d.l3!.interfaces[i];
        const ip = c && c.ipMode === "static" ? validIp(c.ip) : undefined;
        const vip = d.l3!.ha?.enabled ? validIp(d.l3!.ha.vips[i]) : undefined;
        addGw({ device: d, key: `${d.id}:${i}`, label: `${d.name} ${p.name}`, ifName: p.name, ip, ...(vip ? { vip } : {}), subnet: c ? subnetOf(ip, c.prefix) : undefined, inside: i > 0, uplink: i === 0, gwKind: "l3", port: i });
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
