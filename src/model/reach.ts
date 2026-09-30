// 진단 자동완성용 "닿는 후보" 계산. 지금 토폴로지를 복제한 시뮬레이션을 뒤에서 돌려, 후보마다 실제로 ping(또는 TCP 연결)을 보내 본다.
// 화면의 시뮬레이션에는 손대지 않는다. 라우팅·NAT·방화벽·VLAN 이 모두 반영되고, 버튼을 눌렀을 때의 결과와 같다.
import { isPrivateIp, sameSubnet } from "../core/addr";
import { isIpv6 } from "../core/addr6";
import type { Network } from "../core/network";
import { PUBLIC_ZONE } from "../core/nodes/dns";
import { Host } from "../core/nodes/host";
import { Internet, KNOWN_SERVERS, KNOWN_SERVERS6 } from "../core/nodes/internet";
import { L3Node } from "../core/nodes/l3";
import { Router } from "../core/nodes/router";
import { NetworkSync } from "./netSync";
import type { Topology } from "./topology";

/** 출발 호스트에서 본 상대의 위치 */
export type ReachGroup = "same" | "routed" | "internet" | "ipv6" | "name";

export const REACH_GROUP_LABEL: Record<ReachGroup, string> = {
  same: "같은 서브넷 · 바로 (ARP)",
  routed: "다른 서브넷 · 게이트웨이 경유",
  internet: "인터넷 · NAT 경유",
  ipv6: "IPv6 (NDP · NAT 없음)",
  name: "이름 (DNS)",
};

export interface ReachCandidate {
  /** 입력칸에 들어갈 값 (IP 또는 이름) */
  value: string;
  /** 장치 이름 등 설명 */
  label: string;
  /** 이름이면 해석된 주소 */
  resolved?: string;
  group: ReachGroup;
  ok: boolean;
  /** 닿으면 거친 홉 수 (traceroute) */
  hops?: number;
  /** 안 닿으면 이유 */
  reason?: string;
}

export interface ReachResult {
  candidates: ReachCandidate[];
  /** 확인할 수 없을 때 이유 (출발 호스트에 주소가 없음 등) */
  note?: string;
}

/** 이 시간 동안의 트레이스에서 실패 원인을 찾아 사람이 읽을 이유로 */
function failureReason(net: Network, fromIndex: number, fallback: string | undefined, names: Map<string, string>): string {
  const recent = net.trace.slice(fromIndex);
  const at = (id: string) => names.get(id) ?? id;
  const fw = recent.find((e) => e.kind === "fw.deny");
  if (fw) return `방화벽 차단 (${at(fw.nodeId)})`;
  const priv = recent.find((e) => e.kind === "ip.drop" && e.summary.includes("사설"));
  if (priv) return `NAT 뒤 사설 주소 (${at(priv.nodeId)} 에서 드롭)`;
  const vpn = recent.find((e) => e.kind === "vpn.drop");
  if (vpn) return `VPN 드롭 (${at(vpn.nodeId)})`;
  const noRoute = recent.find((e) => e.kind === "ip.no-route");
  if (noRoute) return `경로 없음 (${at(noRoute.nodeId)})`;
  const vlan = recent.find((e) => e.kind === "vlan.drop");
  if (vlan) return "다른 VLAN";
  const conflict = recent.find((e) => e.kind === "ip.conflict");
  if (conflict) return `주소 충돌 (${at(conflict.nodeId)})`;
  return fallback ?? "timeout";
}

/**
 * fromId 호스트에서 닿는 후보를 계산한다.
 * mode "tcp" 면 port 를 열어 둔 서버만 후보로 삼고 TCP 연결로 확인한다
 */
export function probeTargets(t: Topology, fromId: string, mode: "ping" | "tcp", port = 80): ReachResult {
  /** 복제본을 새로 만든다. 한 후보에서 이벤트 한도를 넘으면 큐가 어지러워지므로 다음 후보는 새 복제본에서 */
  const fresh = (): { net: Network; src: Host } | undefined => {
    const sync = new NetworkSync();
    try {
      sync.sync(t);
      sync.net.runToIdle(50_000);
    } catch {
      return undefined;
    }
    const n = sync.net.nodes.get(fromId);
    return n instanceof Host ? { net: sync.net, src: n } : undefined;
  };
  const first = fresh();
  if (!first) return t.devices.some((d) => d.id === fromId && d.host) ? { candidates: [], note: "구성이 커서 확인하지 못했습니다" } : { candidates: [] };
  let { net, src } = first;
  const hasV6 = src.v6.enabled && src.v6.globals.length > 0;
  if (!src.ip && !hasV6) return { candidates: [], note: "이 장치에 IP 가 없어 닿는 곳을 확인할 수 없습니다 (IP 미설정)" };
  const srcIp = src.ip ?? "";
  const srcPrefix = src.iface.prefix;
  const names = new Map(t.devices.map((d) => [d.id, d.name]));

  // 후보 모으기 (값 기준 중복 제거)
  const raw = new Map<string, { value: string; label: string; isName: boolean; deviceId?: string }>();
  const addIp = (ip: string | undefined, label: string, deviceId?: string) => {
    if (!ip || ip === srcIp || raw.has(ip) || (!src.ip && !isIpv6(ip))) return;
    raw.set(ip, { value: ip, label, isName: false, deviceId });
  };
  /** IPv6 글로벌 주소 후보 (출발 호스트가 IPv6 글로벌 주소를 가질 때만) */
  const addIp6 = (ips: string[], label: string, deviceId?: string) => {
    if (!hasV6) return;
    for (const ip of ips) if (!src.v6.owns(ip) && !raw.has(ip)) raw.set(ip, { value: ip, label, isName: false, deviceId });
  };
  let hasInternet = false;
  for (const d of t.devices) {
    if (d.id === fromId) continue;
    const n = net.nodes.get(d.id);
    if (n instanceof Internet) hasInternet = true;
    if (mode === "tcp") {
      if (n instanceof Host && n.tcp.listening.has(port)) {
        addIp(n.ip, d.name, d.id);
        addIp6(n.v6.globals.map((a) => a.ip), d.name, d.id);
      }
      continue;
    }
    if (n instanceof Host) {
      addIp(n.ip, d.name, d.id);
      addIp6(n.v6.globals.map((a) => a.ip), d.name, d.id);
    } else if (n instanceof Router) {
      addIp(n.lan.ip, `${d.name} LAN`, d.id);
      addIp(n.wan.ip, `${d.name} WAN`, d.id);
    } else if (n instanceof L3Node) {
      n.ifaces.forEach((f, i) => addIp(f.ip, `${d.name} ${n.names[i]}`, d.id));
      n.v6.forEach((v, i) => addIp6(v.globals.map((a) => a.ip), `${d.name} ${n.names[i]}`, d.id));
    }
  }
  if (hasInternet && src.ip) {
    for (const [ip, name] of Object.entries(KNOWN_SERVERS)) {
      if (mode === "tcp" && port !== 80 && port !== 443) continue;
      addIp(ip, name);
    }
  }
  if (hasInternet && !(mode === "tcp" && port !== 80 && port !== 443)) for (const [ip, name] of Object.entries(KNOWN_SERVERS6)) addIp6([ip], name);
  // 이름 후보: LAN 의 DNS 서버 레코드 + 인터넷이 있으면 공개 이름. 같은 이름의 A·AAAA 는 하나로 모은다
  const nameList: { name: string; ip: string; ips: string[] }[] = [];
  const addName = (name: string, ip: string) => {
    const e = nameList.find((x) => x.name === name);
    if (e) e.ips.push(ip);
    else nameList.push({ name, ip, ips: [ip] });
  };
  for (const d of t.devices) {
    const n = net.nodes.get(d.id);
    // 이 호스트가 물을 수 있는 DNS 가 있을 때만 (IPv4 DNS, 또는 IPv6 만 있으면 IPv6 DNS). 같은 이름의 A·AAAA 는 하나로
    const canAsk = !!src.ip || (hasV6 && !!src.v6.effectiveDns);
    if (n instanceof Host && n.dnsServer.config.enabled && canAsk) for (const r of n.dnsServer.config.records) addName(r.name, r.ip);
  }
  if (hasInternet && src.ip) for (const r of PUBLIC_ZONE) addName(r.name, r.ip);
  for (const r of nameList) {
    if (raw.has(r.name)) continue;
    if (mode === "tcp") {
      // TCP 는 그 포트를 여는 서버를 가리키는 이름만
      const target = [...raw.values()].find((x) => !x.isName && r.ips.includes(x.value));
      if (!target) continue;
    }
    raw.set(r.name, { value: r.name, label: r.ip, isName: true });
  }

  // 하나씩 실제로 보내 본다 (복제본이라 순서대로 보내도 서로 영향이 거의 없다)
  const candidates: ReachCandidate[] = [];
  for (const c of raw.values()) {
    const start = net.trace.length;
    let ok = false;
    let resolved: string | undefined;
    let reason: string | undefined;
    try {
      if (mode === "ping") {
        net.scheduleAction(net.now, { kind: "ping", nodeId: fromId, dst: c.value });
        net.runToIdle(20_000);
        const rec = src.pings.at(-1);
        ok = rec?.status === "ok";
        resolved = rec?.resolved;
        reason = rec?.reason;
      } else {
        net.scheduleAction(net.now, { kind: "tcp-connect", nodeId: fromId, dst: c.value, port });
        net.runToIdle(20_000);
        // 내가 연 연결 (내가 프록시·로드밸런서이기도 하면 중계 연결이 뒤에 생긴다)
        const conn = [...src.tcp.conns.values()].filter((x) => x.role === "client" && x.via === undefined && !x.relay).at(-1);
        const httpError = /^HTTP [45]/.test(conn?.status ?? "");
        ok = conn?.state === "CLOSED" && conn.bytesReceived > 0 && !httpError;
        reason = httpError ? `${conn!.status} (${conn!.target ? "프록시" : "로드밸런서 뒤 백엔드 문제"})` : conn?.reason;
        // 프록시 경유면 접속한 곳은 프록시다: 이름이 가리킨 주소는 응답을 만든 서버 쪽
        resolved = c.isName ? (conn?.target ? conn.servedBy : conn?.remoteIp) : undefined;
      }
    } catch {
      reason = "확인 중 이벤트가 너무 많음 (순환 구성 의심)";
      const again = fresh();
      if (again) ({ net, src } = again);
    }
    // 같은 사설 주소를 쓰는 장치가 여러 대면(두 집이 모두 192.168.0.x) 실제로 응답한 장치 이름을 붙인다
    let label = c.label;
    if (ok && !c.isName && mode === "ping") {
      const reply = net.trace.slice(start).find((e) => e.kind === "icmp.reply.sent" && e.nodeId !== fromId && names.has(e.nodeId));
      const byInternet = t.devices.find((d) => d.id === reply?.nodeId)?.kind === "internet"; // 공인 서버 응답은 인터넷 노드가 대신 보낸다
      if (reply && !byInternet && reply.nodeId !== c.deviceId) label = names.get(reply.nodeId)!;
    }
    let hops: number | undefined;
    if (ok) {
      try {
        net.scheduleAction(net.now, { kind: "traceroute", nodeId: fromId, dst: resolved ?? c.value });
        net.runToIdle(20_000);
        const tr = src.traceroutes.at(-1);
        if (tr?.status === "done") hops = tr.hops.length;
      } catch {
        /* 홉 수는 없어도 된다 */
      }
    }
    const ip = c.isName ? resolved ?? nameList.find((r) => r.name === c.value)?.ip : c.value;
    const group: ReachGroup = c.isName ? "name" : ip && isIpv6(ip) ? "ipv6" : ip && sameSubnet(ip, srcIp, srcPrefix) ? "same" : ip && isPrivateIp(ip) ? "routed" : "internet";
    candidates.push({
      value: c.value,
      label,
      resolved: c.isName ? ip : undefined,
      group,
      ok,
      hops,
      reason: ok ? undefined : failureReason(net, start, reason, names),
    });
  }
  const order: ReachGroup[] = ["same", "routed", "internet", "ipv6", "name"];
  candidates.sort((a, b) => order.indexOf(a.group) - order.indexOf(b.group) || (a.hops ?? 99) - (b.hops ?? 99));
  return { candidates };
}

// 같은 토폴로지·출발지·모드면 다시 계산하지 않는다 (토폴로지는 불변 객체라 참조로 비교)
let memo: { t: Topology; key: string; result: ReachResult } | undefined;
export function probeTargetsCached(t: Topology, fromId: string, mode: "ping" | "tcp", port = 80): ReachResult {
  const key = `${fromId}|${mode}|${port}`;
  if (memo && memo.t === t && memo.key === key) return memo.result;
  const result = probeTargets(t, fromId, mode, port);
  memo = { t, key, result };
  return result;
}
