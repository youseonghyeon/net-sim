// 타일·패널에 보이는 상태 문구. 노드 객체만 보고 결정하므로 유닛 테스트가 가능하다.
import { AccessPoint } from "../core/nodes/ap";
import { FirewallBridge } from "../core/nodes/fwbridge";
import { DHCP_MAX_ATTEMPTS, DHCP_STATE_LABEL, Host } from "../core/nodes/host";
import { Internet } from "../core/nodes/internet";
import { L3Node } from "../core/nodes/l3";
import type { SimNode } from "../core/nodes/node";
import { Router } from "../core/nodes/router";
import { Switch } from "../core/nodes/switch";

export interface StatusLine {
  text: string;
  tone: "ok" | "warn" | "muted";
  mono: boolean;
}

/** 호스트의 화면 표시용 주소 상태 */
export function hostStatusOf(node: SimNode | undefined, wireless: boolean): StatusLine | null {
  if (node instanceof Host) {
    if (node.ip) return { text: `${node.ip}/${node.iface.prefix}`, tone: "ok", mono: true };
    if (!node.linkUp) return { text: wireless ? "무선 연결 없음" : "링크 다운", tone: "muted", mono: false };
    if (node.ipMode === "static") return { text: "IP 미설정", tone: "warn", mono: false };
    switch (node.dhcp.state) {
      case "discovering":
      case "requesting":
        return { text: `DHCP 요청 중 (${node.dhcp.attempts}/${DHCP_MAX_ATTEMPTS})`, tone: "warn", mono: false };
      case "failed":
        return { text: "DHCP 실패 · IP 미설정", tone: "warn", mono: false };
      default:
        return { text: "IP 미설정", tone: "warn", mono: false };
    }
  }
  if (node instanceof Router) return { text: `${node.lan.ip}/${node.lan.prefix}`, tone: "ok", mono: true };
  if (node instanceof Internet) return { text: `ISP ${node.iface.ip}/${node.iface.prefix}`, tone: "ok", mono: true };
  if (node instanceof AccessPoint) return { text: `SSID ${node.ssid} · 단말 ${node.stations.size}대`, tone: "ok", mono: false };
  if (node instanceof FirewallBridge) {
    const c = node.firewall.config;
    if (!c.enabled) return { text: "꺼짐 · 모두 통과", tone: "muted", mono: false };
    return { text: `규칙 ${c.rules.length}개 · 기본 ${c.defaultPolicy === "allow" ? "허용" : "차단"}`, tone: c.rules.length > 0 || c.defaultPolicy === "deny" ? "ok" : "muted", mono: false };
  }
  if (node instanceof L3Node) {
    // 아래쪽(안쪽) 물리 인터페이스 요약. 서브 인터페이스가 있으면 "if1.10/.20" 처럼 접는다
    const parts: string[] = [];
    let ok = true;
    for (let p = 1; p < node.portCount; p++) {
      const iface = node.ifaces[p]!;
      const subs = node.meta.map((m, i) => ({ m, i })).filter(({ m, i }) => i >= node.portCount && m.port === p);
      if (iface.ip) parts.push(iface.ip);
      else if (subs.length) parts.push(`${node.names[p]}.${subs.map(({ m }) => m.vlan).join("/")}`);
      else {
        parts.push(`${node.names[p]} 없음`);
        ok = false;
      }
    }
    return { text: parts.join(" · "), tone: ok ? "ok" : "warn", mono: true };
  }
  return null;
}

/** 타일에 붙는 서비스 배지: 어느 상자에서 어떤 소프트웨어가 도는지 */
export function serviceBadgesOf(node: SimNode | undefined): string[] {
  const out: string[] = [];
  if (node instanceof Host) {
    if (node.dhcpServer.config.enabled) out.push("DHCP");
    if (node.dnsServer.config.enabled) out.push("DNS");
    if (node.tcp.listening.has(80)) out.push("웹");
  } else if (node instanceof Router) {
    if (node.dhcp.enabled) out.push("DHCP");
    if (node.dnsForwarder.config.enabled) out.push("DNS");
    out.push(node.nat.forwards.length > 0 ? "NAT+포워딩" : "NAT");
    if (node.firewall.config.enabled) out.push("방화벽");
    if (node.wifi.enabled) out.push(`Wi-Fi ${node.wifi.ssid}`);
  } else if (node instanceof L3Node) {
    if (node.relays.some(Boolean)) out.push("DHCP 릴레이");
    if (node.nat) out.push(node.nat.forwards.length > 0 ? "NAT+포워딩" : "NAT");
    if (node.firewall.config.enabled) out.push("방화벽");
  } else if (node instanceof Internet) {
    out.push("ISP DHCP", "DNS", "웹");
  } else if (node instanceof Switch && node.vlanAware) {
    out.push("VLAN");
  } else if (node instanceof FirewallBridge) {
    if (node.firewall.config.enabled && node.firewall.config.stateful) out.push("Stateful");
  }
  return out;
}

/** 라우터 타일의 WAN 줄 */
export function wanStatusOf(node: SimNode | undefined): StatusLine | null {
  if (node instanceof L3Node) {
    const name = node.names[0]!;
    const up = node.ifaces[0]!;
    if (up.ip) return { text: `${name} ${up.ip}`, tone: "ok", mono: true };
    if (!node.linkUp[0]) return { text: `${name} 연결 없음`, tone: "muted", mono: false };
    if (!node.clients[0]) return { text: `${name} 주소 수동 입력 필요`, tone: "warn", mono: false };
    return { text: `${name} ${DHCP_STATE_LABEL[node.clients[0].state]}`, tone: node.clients[0].state === "failed" ? "warn" : "muted", mono: false };
  }
  if (!(node instanceof Router)) return null;
  if (node.wan.ip) return { text: `WAN ${node.wan.ip}`, tone: "ok", mono: true };
  if (!node.wanLinkUp) return { text: "WAN 연결 없음", tone: "muted", mono: false };
  if (node.wanMode === "static") return { text: "WAN 주소 수동 입력 필요", tone: "warn", mono: false };
  return { text: `WAN ${DHCP_STATE_LABEL[node.wanClient.state]}`, tone: node.wanClient.state === "failed" ? "warn" : "muted", mono: false };
}
