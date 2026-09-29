// 구성 검사(lint): 시뮬레이션을 돌리기 전에 토폴로지(편집 모델)만 보고 "설정 한 칸 빠짐" 을 찾는다.
// DOM·signal·코어에 의존하지 않는 순수 함수. 입력 중인 불완전한 값(빈 칸, "192.168.0.")은 netSync 의 effective* 와
// 같은 기준으로 "없음" 으로 보되, 빈 칸 자체는 지적하지 않고(타일 상태 문구가 보여줌) 값끼리 안 맞는 것만 지적한다.
// 오탐이 미탐보다 나쁘므로, 확신이 없는 경우(주소를 아직 모르는 DHCP 인터페이스 등)는 조용히 넘어간다.
// 구현은 `lint/` 폴더: addr(주소 도우미)·segments(L2 세그먼트 모델)·context(이슈 타입·마무리) + 주제별 규칙 파일.
import type { Topology } from "./topology";
import { dhcpServiceRules, interfaceOverlapRule, segmentConflictRules, staticHostRules, uplinkSubnetRule } from "./lint/addressing";
import { finalize, type LintContext, type LintIssue } from "./lint/context";
import { haRules } from "./lint/ha";
import { loopStpRule, vlanTrunkRules } from "./lint/l2";
import { lbRules } from "./lint/lb";
import { relayRouteRule, returnRouteRule, uplinkDefaultRule } from "./lint/routing";
import { analyze } from "./lint/segments";
import { forwardClosedRule, httpProxyRule, proxyPortClashRule, routerDnsRule } from "./lint/services";
import { remoteAccessRules, siteVpnRules } from "./lint/vpn";

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
  dhcpServiceRules, // 1·2·5·21
  staticHostRules, // 3·4·5·11·22
  uplinkDefaultRule, // 6
  returnRouteRule, // 7
  interfaceOverlapRule, // 8
  segmentConflictRules, // 9·10
  uplinkSubnetRule, // 11
  relayRouteRule, // 12
  vlanTrunkRules, // 13a·13b
  lbRules, // 14
  forwardClosedRule, // 15
  routerDnsRule, // 16
  siteVpnRules, // 17
  haRules, // 18
  loopStpRule, // 19
  remoteAccessRules, // 20
  httpProxyRule, // 21
  proxyPortClashRule, // 21b
];

export function lintTopology(t: Topology): LintIssue[] {
  const issues: LintIssue[] = [];
  const ctx: LintContext = { t, m: analyze(t), add: (i) => issues.push(i) };
  for (const rule of RULES) rule(ctx);
  return finalize(issues, t);
}
