// 주소 규칙: 호스트·DHCP 서비스의 게이트웨이/DNS 안내, 세그먼트의 서브넷 섞임·DHCP 서버 중복·IP 중복, 인터페이스끼리 서브넷 겹침.
import { DEVICE_SPECS, type Device, type Topology } from "../topology";
import { contains, fmtSubnet, ipInt, overlaps, subnetOf, validIp, type Subnet } from "./addr";
import { names, pickGw, uniqueDevices, type LintContext, type LintIssue } from "./context";
import { portName, type Addr, type GwIface, type Model } from "./segments";

/**
 * 규칙 23: 코어 `DhcpServer.rangeProblem` 과 같은 기준 — 기본 풀 범위가 거꾸로이거나 서버 자신의 서브넷 밖이면
 * 서버는 Discover 에 전혀 응답하지 않는다(릴레이로 온 추가 풀 요청 포함). 추가 풀은 서버 서브넷 밖이 정상이라 보지 않는다.
 * 주소·범위를 아직 모르면(입력 중 — 코어는 옛 값을 계속 쓴다) 판단하지 않는다
 */
function rangeProblem(ownIp: string, prefix: number, start: string | undefined, end: string | undefined): "reversed" | "outside" | undefined {
  const me = ipInt(ownIp)!;
  const s = ipInt(start);
  const e = ipInt(end);
  if (s === undefined || e === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return undefined;
  if (s > e) return "reversed";
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0; // /0 은 모든 주소가 같은 서브넷
  const net = (n: number) => (n & mask) >>> 0;
  return net(s) !== net(me) || net(e) !== net(me) ? "outside" : undefined;
}

/** 주소가 어느 DHCP 서버(호스트 서비스의 기본·추가 풀, 공유기 DHCP)의 범위 안인가 — 그 주소를 받은 단말이 있을 수 있다 */
function inDhcpRange(t: Topology, addr: string): boolean {
  const n = ipInt(addr)!;
  const within = (s: string | undefined, e: string | undefined) => {
    const a = ipInt(s);
    const b = ipInt(e);
    return a !== undefined && b !== undefined && a <= n && n <= b;
  };
  return t.devices.some((d) => {
    const hs = d.host?.dhcpServer;
    if (hs?.enabled && d.host!.ipMode === "static" && (within(hs.start, hs.end) || (hs.extraPools ?? []).some((p) => within(p.start, p.end)))) return true;
    return d.router?.dhcp.enabled === true && within(d.router.dhcp.start, d.router.dhcp.end);
  });
}

/**
 * 문구용: 세그먼트(keys)의 라우터 인터페이스(실제·가상) 어느 것도 아닌 addr 를 게이트웨이로 쓰면 코어에서 어떻게 되는가.
 * 수동 주소로 그 주소를 가진 장비가 있으면 ARP 는 되지만 그 장비가 드롭, DHCP 범위 안이면 그 주소를 받은 단말일 수 있고, 아니면 ARP timeout
 */
function strayGwFate(t: Topology, m: Model, keys: string[], addr: string, self?: Device): string {
  const owner = keys.flatMap((k) => m.membersOf(k)?.addrs ?? []).find((a) => a.ip === addr && a.device !== self);
  if (owner) {
    return DEVICE_SPECS[owner.device.kind].role === "host"
      ? `${owner.device.name} 가 ARP 에 응답하지만 호스트는 포워딩하지 않아 드롭`
      : `${owner.label} 가 ARP 에 응답하지만 자기 주소로 온 패킷이 아니라 드롭`;
  }
  if (inDhcpRange(t, addr)) return `그 주소를 DHCP 로 받은 단말이 있으면 그 단말이 드롭(호스트는 포워딩 안 함), 없으면 ARP timeout`;
  return `그 주소로 ARP 에 응답하는 장비가 없어 ARP timeout`;
}

/** 같은 code 의 이슈(기본 풀·추가 풀)를 하나로 — finalize 는 (장치, code) 로 합치며 뒤의 문구를 버리므로 여기서 문구를 잇는다 */
function mergeByCode(list: LintIssue[]): LintIssue[] {
  const byCode = new Map<string, LintIssue>();
  for (const i of list) {
    const prev = byCode.get(i.code);
    if (!prev) {
      byCode.set(i.code, { ...i });
      continue;
    }
    prev.message += `. ${i.message}`;
    prev.fix += `. ${i.fix}`;
    if (i.related) prev.related = [...new Set([...(prev.related ?? []), ...i.related])];
  }
  return [...byCode.values()];
}

/**
 * 규칙 21: 기본 게이트웨이 옵션(3)이 세그먼트 라우터 인터페이스 주소(실제·HA 가상) 어느 것과도 다른가.
 * 주소를 모르는(DHCP·입력 중) 라우터 인터페이스가 끼면 그 주소일 수 있으므로 판단하지 않는다
 */
function gatewayMismatch(gws: GwIface[], router: string): boolean {
  return gws.length > 0 && gws.every((g) => g.ip) && !gws.some((g) => g.ip === router || g.vip === router);
}

/** 문구용: 세그먼트 라우터 주소 목록 (가상 주소는 표시) */
function gwAddrList(gws: GwIface[]): string {
  return [...new Set(gws.flatMap((g) => [g.ip!, ...(g.vip ? [`${g.vip}(가상 주소)`] : [])]))].join(", ");
}

/** 문구용: 추천할 게이트웨이 주소 — 이중화 쌍이면 가상 주소 */
function gwSuggest(g: GwIface): string {
  return g.vip ? `${g.vip} (${g.label} 가상 주소)` : `${g.ip} (${g.label})`;
}

// 규칙 1·2·5·21·23(DHCP 서버 쪽): 호스트 DHCP 서비스의 범위, 게이트웨이/DNS 안내
export function dhcpServiceRules({ t, m, add: addNow }: LintContext): void {
  for (const d of t.devices) {
    const h = d.host;
    // 주소를 DHCP 로 받는 호스트의 DHCP 서비스는 코어에서 동작하지 않으므로("내 주소가 고정이 아님") 안내 내용을 검사하지 않는다
    if (!h?.dhcpServer.enabled || h.ipMode !== "static") continue;
    const key = `${d.id}:0`;
    const gws = m.gwsOf(key);
    const srv = h.dhcpServer;
    const router = validIp(srv.router);
    const ownIp = h.ipMode === "static" ? validIp(h.ip) : undefined;
    // 서버 주소가 없으면(입력 중) 코어 서버는 응답하지 않는다("서버 자신의 IP 주소가 없음"). 빈 칸은 타일이 보여주므로 여기선 침묵
    if (!ownIp) continue;
    const problem = rangeProblem(ownIp, h.prefix, validIp(srv.start), validIp(srv.end));
    if (problem) {
      // 서버가 Discover 에 응답하지 않으니 "주소는 나가지만 …" 하는 안내 규칙(기본·추가 풀)은 모두 사실이 아니다 → 이것 하나만
      const relayToo = (srv.extraPools ?? []).some((p) => validIp(p.start) && validIp(p.end)) ? " (릴레이로 오는 추가 풀 요청에도 응답하지 않음)" : "";
      const own = subnetOf(ownIp, h.prefix);
      addNow({
        deviceId: d.id,
        severity: "error",
        code: "dhcp.range-invalid",
        message:
          problem === "reversed"
            ? `DHCP 범위의 시작 주소 ${srv.start} 가 끝 주소 ${srv.end} 보다 큼 → 서버가 Discover 에 응답하지 않아(DHCP 설정 오류) 단말이 주소를 못 받음${relayToo}`
            : `DHCP 범위 ${srv.start} ~ ${srv.end} 가 이 서버의 서브넷 ${own ? fmtSubnet(own) : `${ownIp}/${h.prefix}`} 밖 → 서버가 Discover 에 응답하지 않아(DHCP 설정 오류) 단말이 주소를 못 받음${relayToo}`,
        fix:
          problem === "reversed"
            ? `${d.name} → DHCP 서비스 → 시작·끝 주소를 맞바꾸기 (시작 ≤ 끝)`
            : `${d.name} → DHCP 서비스 → 시작·끝 주소를 ${own ? fmtSubnet(own) : "이 서버의 서브넷"} 안으로 바꾸거나, IP 설정의 IP/서브넷을 범위와 같은 서브넷으로`,
      });
      continue;
    }
    // 기본 풀과 추가 풀의 같은 code 는 장치마다 한 이슈로 합쳐지므로 모았다가 문구를 이어 낸다
    const found: LintIssue[] = [];
    const add = (i: LintIssue) => found.push(i);
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
      if (!m.stranded.has(key) && gatewayMismatch(gws, router)) {
        const pick = pickGw(gws, validIp(srv.start) ?? ownIp)!;
        const own = subnetOf(ownIp, h.prefix);
        add({
          deviceId: d.id,
          severity: "warn",
          code: "dhcp.gateway-mismatch",
          message: `기본 게이트웨이 옵션(3) ${router} 가 이 세그먼트의 라우터 주소(${gwAddrList(gws)})와 다름${own && !contains(own, router) ? `, 풀 서브넷 ${fmtSubnet(own)} 밖이기도 함` : ""} → 단말이 주소는 받지만 다른 네트워크로 못 나감 (${strayGwFate(t, m, [key], router)})`,
          fix: `${d.name} → DHCP 서비스 → 기본 게이트웨이 칸을 ${gwSuggest(pick)} 로 바꾸고, 이미 주소를 받은 호스트에서 DHCP 임대 갱신`,
          related: uniqueDevices(gws).map((x) => x.id),
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
      if (poolRouter) {
        // 이 풀을 받는 단말의 세그먼트 = 주소가 풀 서브넷 안인 라우터 인터페이스(릴레이 giaddr 가 될 곳)가 있는 세그먼트
        const relays = m.allGws.filter((g) => g.ip && contains(poolNet, g.ip) && m.linked.has(g.key) && !m.stranded.has(g.key));
        const segGws = [...new Map(relays.flatMap((g) => m.gwsOf(g.key)).map((g) => [g.key, g])).values()];
        if (relays.length === 0 || !gatewayMismatch(segGws, poolRouter)) return;
        const pick = pickGw(segGws, start)!;
        add({
          deviceId: d.id,
          severity: "warn",
          code: "dhcp.gateway-mismatch",
          message: `추가 풀 ${fmtSubnet(poolNet)} 의 기본 게이트웨이 옵션(3) ${poolRouter} 가 그 세그먼트의 라우터 주소(${gwAddrList(segGws)})와 다름${contains(poolNet, poolRouter) ? "" : ", 풀 서브넷 밖이기도 함"} → 그 서브넷 단말이 주소는 받지만 다른 네트워크로 못 나감 (${strayGwFate(t, m, relays.map((g) => g.key), poolRouter)})`,
          fix: `${d.name} → DHCP 서비스 → 추가 풀 ${i + 1} → 게이트웨이 칸을 ${gwSuggest(pick)} 로 바꾸고, 이미 주소를 받은 호스트에서 DHCP 임대 갱신`,
          related: uniqueDevices(segGws).map((x) => x.id),
        });
      }
    });
    for (const i of mergeByCode(found)) addNow(i);
  }
}

// 규칙 3·4·5·11·22(호스트 쪽): 수동 호스트의 게이트웨이와 서브넷
export function staticHostRules({ t, m, add }: LintContext): void {
  /** 규칙 3·4 에 이미 걸린 호스트 (규칙 11 은 같은 원인의 약한 진술이라 생략) */
  const flaggedHosts = new Set<string>();
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
      } else if (gws.every((g) => g.ip) && !gws.some((g) => g.ip === gw || g.vip === gw) && !dropInGateway(t, m, key, gw)) {
        const pick = pickGw(gws, ip);
        flaggedHosts.add(d.id);
        add({
          deviceId: d.id,
          severity: "warn",
          code: "host.no-gateway-in-segment",
          message: `게이트웨이 ${gw} 가 같은 세그먼트의 라우터 주소(${gws.map((g) => g.ip).join(", ")})와 다름 → ${strayGwFate(t, m, [key], gw, d)}`,
          fix: `${d.name} → IP 설정 → 게이트웨이 칸을 ${pick?.ip ?? gws[0]!.ip} (${pick?.label ?? gws[0]!.label}) 로 바꾸거나, 케이블을 ${gw} 를 가진 라우터 쪽 스위치로 옮기기`,
          related: uniqueDevices(gws).map((x) => x.id),
        });
      } else {
        const real = gws.find((g) => g.ip === gw && g.vip && g.vip !== gw);
        if (real) {
          add({
            deviceId: d.id,
            severity: "warn",
            code: "ha.host-real-gw",
            message: `게이트웨이 ${gw} 는 ${real.device.name} 의 실제 주소 — 이중화 쌍이 넘어가도(그 장비가 죽어도) 따라가지 않음`,
            fix: `${d.name} → IP 설정 → 게이트웨이를 가상 주소 ${real.vip} 로`,
            related: [real.device.id],
          });
        }
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
    // 규칙 22: IP 는 라우터 서브넷 안인데 프리픽스 길이가 다름. 게이트웨이 규칙(3·4·5)에 걸린 호스트는 그쪽이 먼저(규칙 3 은 고치는 법에
    // 서브넷 마스크 포함, 규칙 4 의 게이트웨이는 라우터가 아니라 "게이트웨이로 돌려 보냄" 이 사실이 아님).
    // 서브넷을 모르는(DHCP) 라우터 인터페이스가 끼거나 같은 길이의 라우터가 하나라도 있으면 침묵. /0 도 본다(모든 주소를 같은 네트워크로 봄)
    const ownNet: Subnet | undefined = own ?? (ip && h.prefix === 0 ? { net: 0, prefix: 0 } : undefined);
    if (ip && ownNet && inSegment && !flaggedHosts.has(d.id) && gws.every((g) => g.subnet)) {
      const refs = gws.filter((g) => contains(g.subnet!, ip));
      if (refs.length > 0 && !refs.some((g) => g.subnet!.prefix === h.prefix)) {
        const pick = refs.find((g) => g.ip === gw || g.vip === gw) ?? refs[0]!;
        const rs = pick.subnet!;
        const via = gw ? gws.find((g) => g.ip === gw || g.vip === gw) : undefined;
        const result =
          h.prefix < rs.prefix
            ? `${ownNet.prefix === 0 ? `${fmtSubnet(rs)} 밖의 모든 주소` : `${fmtSubnet(ownNet)} 안이지만 ${fmtSubnet(rs)} 밖인 주소`}도 같은 네트워크로 보고 ARP 로 직접 찾다가 실패(ARP timeout)`
            : `같은 서브넷 ${fmtSubnet(rs)} 인데 ${fmtSubnet(ownNet)} 밖인 주소를 다른 네트워크로 보고 ${
                !gw
                  ? "게이트웨이 설정이 없어 드롭"
                  : via?.gwKind === "router"
                    ? `게이트웨이 ${gw} 로 보냄 → 공유기가 "LAN 안의 주소" 라며 드롭`
                    : via?.gwKind === "l3"
                      ? `게이트웨이 ${gw} 로 돌려 보냄 → 라우터를 거쳐 되돌아오는 우회 경로 (응답은 직접 와서 비대칭)`
                      : `게이트웨이 ${gw} 로 돌려 보냄`
              }`;
        add({
          deviceId: d.id,
          severity: "warn",
          code: "host.prefix-mismatch",
          message: `서브넷 /${h.prefix} 가 이 세그먼트 라우터 ${pick.label} 의 /${rs.prefix} 보다 ${h.prefix < rs.prefix ? "짧음" : "김"} → ${result}`,
          fix: `${d.name} → IP 설정 → 서브넷을 /${rs.prefix} 로 (${pick.label} ${fmtSubnet(rs)} 와 같게)`,
          related: [pick.device.id],
        });
      }
    }
  }
}

// 규칙 8: 한 장치의 인터페이스끼리 서브넷 겹침
export function interfaceOverlapRule({ t, m, add }: LintContext): void {
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
}

// 규칙 9·10: 세그먼트 안의 DHCP 서버 중복과 IP 중복
export function segmentConflictRules({ m, add }: LintContext): void {
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
}

// 규칙 11(업링크 쪽): L3 if0/공유기 WAN 의 수동 주소가 위쪽 라우터 서브넷 밖
export function uplinkSubnetRule({ t, m, add }: LintContext): void {
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
}

/** 게이트웨이가 같은 세그먼트의 드롭인 게이트웨이 공유기(수동 WAN 주소)인가 — 그 공유기는 WAN 쪽 기기의 게이트웨이가 되어 준다 */
function dropInGateway(t: Topology, m: LintContext["m"], key: string, gw: string): boolean {
  const seg = m.ids.get(key);
  return t.devices.some((x) => x.router?.dropIn && x.router.wan?.ipMode === "static" && x.router.wan.ip === gw && seg !== undefined && m.ids.get(`${x.id}:0`) === seg);
}
