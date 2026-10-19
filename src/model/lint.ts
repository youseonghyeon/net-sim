// 구성 검사(lint): 시뮬레이션을 돌리기 전에 토폴로지(편집 모델)만 보고 "설정 한 칸 빠짐" 을 찾는다.
// DOM·signal·코어에 의존하지 않는 순수 함수. 입력 중인 불완전한 값(빈 칸, "192.168.0.")은 netSync 의 effective* 와
// 같은 기준으로 "없음" 으로 보되, 빈 칸 자체는 지적하지 않고(타일 상태 문구가 보여줌) 값끼리 안 맞는 것만 지적한다.
// 오탐이 미탐보다 나쁘므로, 확신이 없는 경우(주소를 아직 모르는 DHCP 인터페이스 등)는 조용히 넘어간다.
// 구현은 `lint/` 폴더: addr(주소 도우미)·segments(L2 세그먼트 모델)·context(이슈 타입·마무리) + 주제별 규칙 파일.
import { ROUTER_WAN2_PORT, type Topology } from "./topology";
import { intToIp, ipToInt, networkOf, sameSubnet } from "../core/addr";
import { effectiveIspNet, ispGatewayOf } from "./isp";
import { SUBSCRIBER_PREFIX } from "../core/nodes/internet";
import { dhcpServiceRules, interfaceOverlapRule, segmentConflictRules, staticHostRules, uplinkSubnetRule } from "./lint/addressing";
import { finalize, type LintContext, type LintIssue } from "./lint/context";
import { haRules } from "./lint/ha";
import { ipv6Rules } from "./lint/ipv6";
import { loopStpRule, vlanTrunkRules } from "./lint/l2";
import { lbRules } from "./lint/lb";
import { relayRouteRule, returnRouteRule, routerWanLanRule, uplinkDefaultRule } from "./lint/routing";
import { analyze } from "./lint/segments";
import { forwardClosedRule, httpProxyRule, proxyPortClashRule, routerDnsRule, sshJumpRule } from "./lint/services";
import { remoteAccessRules, routerVpnRules, siteVpnRules } from "./lint/vpn";
import { ddnsRules, wireguardRules } from "./lint/wg";
import { ovpnRules } from "./lint/ovpn";
import { meshRules } from "./lint/mesh";
import { glinetRules } from "./lint/glinet";
import { adguardRules } from "./lint/adguard";
import { ispRules } from "./lint/isp";

export type { LintIssue } from "./lint/context";

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

/** 규칙 실행 순서 (규칙 번호 순). 결과는 finalize 가 정렬하지만, 같은 (장치, code) 는 먼저 낸 것의 문구가 남으므로 순서를 지킨다 */
const RULES: ((ctx: LintContext) => void)[] = [
  dhcpServiceRules, // 1·2·5·21·23
  staticHostRules, // 3·4·5·11·22
  uplinkDefaultRule, // 6
  ispRules, // 6b
  returnRouteRule, // 7
  interfaceOverlapRule, // 8
  segmentConflictRules, // 9·10
  uplinkSubnetRule, // 11
  relayRouteRule, // 12
  routerWanLanRule, // 12b
  vlanTrunkRules, // 13a·13b
  lbRules, // 14
  forwardClosedRule, // 15
  routerDnsRule, // 16
  siteVpnRules, // 17
  haRules, // 18
  loopStpRule, // 19
  remoteAccessRules, // 20
  routerVpnRules, // 20b
  wireguardRules, // 20c
  ddnsRules, // 20d
  ovpnRules, // 20e
  meshRules, // 20f
  glinetRules, // 20g
  httpProxyRule, // 21
  proxyPortClashRule, // 21b
  sshJumpRule, // 21d
  adguardRules, // 21c
  ipv6Rules, // 22 (IPv6)
];

/**
 * leased: ISP 가 DHCP 로 나눠 준 공인 주소("장치 id:포트" → 주소, 시뮬레이터 상태 — `leaseHints`). 주면 그 자동 인터페이스를
 * 그 주소의 수동 인터페이스처럼 보고 검사한다 (VPN 서버·포트 포워딩을 주소로 찾게). 없으면 자동 인터페이스는 주소를 모르는 것으로 (침묵)
 */
export function lintTopology(t: Topology, opts: { leased?: Record<string, string> } = {}): LintIssue[] {
  const issues: LintIssue[] = [];
  const rewritten = new Set<string>();
  const view = withLeases(t, opts.leased ?? {}, rewritten);
  const ctx: LintContext = { t: view, m: analyze(view), add: (i) => issues.push(i), leased: rewritten };
  for (const rule of RULES) rule(ctx);
  return finalize(issues, t);
}

/**
 * 임대받은 주소를 그 인터페이스의 수동 주소로 둔 토폴로지 (구성 검사용 보기). 프리픽스·게이트웨이는 구성 검사의 세그먼트 모델이 보는 ISP 와 맞춰
 * ISP 대역 전체와 그 첫 게이트웨이로 둔다 (실제로는 가입자 대역 /29 와 그 대역의 게이트웨이 — 세그먼트 규칙은 ISP 를 대역 하나로 본다)
 */
function withLeases(t: Topology, leased: Record<string, string>, rewritten: Set<string>): Topology {
  if (Object.keys(leased).length === 0) return t;
  const nets = t.devices.filter((d) => d.kind === "internet").map((d) => effectiveIspNet(d.internet?.net));
  const iface = (ip: string) => {
    const net = nets.find((n) => sameSubnet(ip, n.ip, n.prefix));
    return net
      ? { ipMode: "static" as const, ip, prefix: net.prefix, gateway: ispGatewayOf(net) }
      : { ipMode: "static" as const, ip, prefix: SUBSCRIBER_PREFIX, gateway: intToIp(ipToInt(networkOf(ip, SUBSCRIBER_PREFIX)) + 1) };
  };
  const devices = t.devices.map((d) => {
    // 바꾼 인터페이스만 "임대받은 것" 으로 기록 (지금 수동으로 바꾼 인터페이스에 옛 임대가 남아 있어도 손으로 적은 주소로 본다)
    const at = (port: number) => {
      const ip = leased[`${d.id}:${port}`];
      if (ip) rewritten.add(`${d.id}:${port}`);
      return ip;
    };
    if (d.router) {
      const w = d.router.wan;
      const w2 = d.router.wan2;
      const wan = (!w || w.ipMode === "dhcp") && at(0) ? { ...(w ?? {}), ...iface(at(0)!) } : w;
      const wan2 = w2?.enabled && w2.ipMode === "dhcp" && at(ROUTER_WAN2_PORT) ? { ...w2, ...iface(at(ROUTER_WAN2_PORT)!) } : w2;
      return wan === w && wan2 === w2 ? d : { ...d, router: { ...d.router, ...(wan ? { wan } : {}), ...(wan2 ? { wan2 } : {}) } };
    }
    if (d.l3 && d.l3.interfaces.some((c, i) => c.ipMode === "dhcp" && at(i))) return { ...d, l3: { ...d.l3, interfaces: d.l3.interfaces.map((c, i) => (c.ipMode === "dhcp" && at(i) ? { ...c, ...iface(at(i)!) } : c)) } };
    if (d.host && d.host.ipMode === "dhcp" && at(0)) return { ...d, host: { ...d.host, ...iface(at(0)!) } };
    return d;
  });
  return { ...t, devices };
}
