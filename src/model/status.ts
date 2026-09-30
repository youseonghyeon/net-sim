// 타일·패널에 보이는 상태 문구. 노드 객체만 보고 결정하므로 유닛 테스트가 가능하다.
import { AccessPoint } from "../core/nodes/ap";
import { FirewallBridge } from "../core/nodes/fwbridge";
import { DHCP_MAX_ATTEMPTS, DHCP_STATE_LABEL, Host } from "../core/nodes/host";
import { Internet } from "../core/nodes/internet";
import { L3Node } from "../core/nodes/l3";
import type { NetInterface } from "../core/nodes/iface";
import type { Ipv6Interface } from "../core/nodes/ipv6";
import { DHCP6_STATE_LABEL } from "../core/nodes/dhcp6";
import type { SimNode } from "../core/nodes/node";
import { Router } from "../core/nodes/router";
import { Switch } from "../core/nodes/switch";

export interface StatusLine {
  text: string;
  tone: "ok" | "warn" | "muted";
  mono: boolean;
}

/** 호스트의 화면 표시용 주소 상태 */
/** 인터페이스가 주소 충돌 중이면 경고 줄 (포기한 주소는 "사용 안 함") */
function conflictLine(label: string, iface: NetInterface): StatusLine | null {
  if (!iface.conflict || !iface.ip) return null;
  return { text: `${label}${iface.ip} 충돌${iface.conflict.refused ? " · 사용 안 함" : ""}`, tone: "warn", mono: false };
}

/** IPv6 인터페이스 한 줄: 글로벌 주소(없으면 링크 로컬), DAD 중·중복이면 그 상태. 타일에는 /64 를 빼 폭을 줄인다 (IPv6 는 거의 늘 /64) */
function v6Line(v: Ipv6Interface, tile = false): StatusLine | null {
  if (!v.enabled) return null;
  const dup = v.addrs.find((a) => a.state === "duplicate");
  if (dup) return { text: `${dup.ip} 중복`, tone: "warn", mono: false };
  const g = v.addrs.find((a) => a.origin !== "link-local");
  if (g) return g.state === "preferred" ? { text: tile && g.prefix === 64 ? g.ip : `${g.ip}/${g.prefix}`, tone: "ok", mono: true } : { text: "IPv6 DAD 중", tone: "muted", mono: false };
  if (!v.owns(v.linkLocal)) return { text: "IPv6 DAD 중", tone: "muted", mono: false };
  // SLAAC 인데 RA 를 못 받음: 기다리는 중이면 흐리게, RS 를 다 보내고도 없으면 경고
  if (v.slaac) {
    if (v.raWaiting) return { text: "RA 기다리는 중", tone: "muted", mono: false };
    return v.routers.size > 0 ? { text: "RA 받음 · /64 프리픽스 없음", tone: "warn", mono: false } : { text: "RA 없음 · 링크 로컬만", tone: "warn", mono: false };
  }
  return { text: v.linkLocal, tone: "ok", mono: true };
}

/** 개요 탭의 IPv6 줄 (꺼져 있으면 null) */
export function ipv6StatusOf(node: SimNode | undefined): StatusLine | null {
  if (node instanceof Host) {
    const l = v6Line(node.v6);
    return l && { ...l, text: `IPv6 ${l.text}` };
  }
  if (node instanceof Router && node.ipv6Enabled) {
    const lan = node.lan6.addrs.find((a) => a.origin === "manual");
    if (lan) return { text: `IPv6 LAN ${lan.ip}/64 · 위임 ${node.pd.delegated?.prefix}/${node.pd.delegated?.length}`, tone: "ok", mono: true };
    return { text: `IPv6 프리픽스 위임 ${DHCP6_STATE_LABEL[node.pd.state]}`, tone: node.pd.state === "failed" ? "warn" : "muted", mono: false };
  }
  if (node instanceof L3Node && node.ipv6Enabled) {
    const parts = node.v6.map((v, i) => ({ v, i })).filter(({ v, i }) => node.linkUp[i] || v.addrs.some((a) => a.origin !== "link-local"));
    if (parts.length === 0) return { text: "IPv6 켜짐 · 연결 없음", tone: "muted", mono: false };
    const lines = parts.map(({ v, i }) => ({ name: node.names[i]!, l: v6Line(v) }));
    return { text: `IPv6 ${lines.map(({ name, l }) => `${name} ${l?.text ?? "-"}`).join(" · ")}`, tone: lines.some(({ l }) => l?.tone === "warn") ? "warn" : "ok", mono: true };
  }
  return null;
}

export function hostStatusOf(node: SimNode | undefined, wireless: boolean): StatusLine | null {
  if (node instanceof Host) {
    const c = conflictLine("IP ", node.iface);
    if (c) return c;
    if (node.ip) return { text: `${node.ip}/${node.iface.prefix}`, tone: "ok", mono: true };
    if (!node.linkUp) return { text: wireless ? "무선 연결 없음" : "링크 다운", tone: "muted", mono: false };
    // IPv4 주소가 없고 IPv6 만 쓰는 호스트는 IPv6 주소를 보인다
    const v6 = node.ipMode === "static" ? v6Line(node.v6, true) : null;
    if (v6) return v6;
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
  if (node instanceof Router) return conflictLine("LAN ", node.lan) ?? { text: `${node.lan.ip}/${node.lan.prefix}`, tone: "ok", mono: true };
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
      const g6 = node.ipv6Enabled ? node.v6[p]?.addrs.find((a) => a.origin !== "link-local" && a.state === "preferred") : undefined;
      if (iface.ip && iface.conflict) {
        parts.push(`${iface.ip} 충돌`);
        ok = false;
      } else if (iface.ip) parts.push(iface.ip);
      else if (g6) parts.push(g6.ip); // IPv4 없이 IPv6 만 쓰는 인터페이스
      else if (subs.length) parts.push(`${node.names[p]}.${subs.map(({ m }) => m.vlan).join("/")}`);
      else if (node.linkUp[p]) {
        // 케이블이 꽂혔는데 주소가 없으면 경고. 케이블 없는 빈 인터페이스는 쓰지 않는 포트라 요약에서 뺀다
        parts.push(`${node.names[p]} 없음`);
        ok = false;
      }
    }
    if (parts.length === 0) return { text: "연결 없음", tone: "muted", mono: false };
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
    if (node.tcp.listening.has(80) && !(node.lb.config.enabled && node.lb.config.port === 80)) out.push("웹");
    if (node.tcp.listening.has(22) && !(node.lb.config.enabled && node.lb.config.port === 22)) out.push("SSH");
    if (node.lb.config.enabled) out.push(`LB ${node.lb.config.backends.length}대`);
    if (node.proxy.config.enabled) out.push("프록시");
    if (node.ra.config.enabled) out.push(node.ra.state === "up" ? "VPN 연결됨" : "VPN");
    if (node.v6.enabled) out.push("IPv6");
  } else if (node instanceof Router) {
    if (node.dhcp.enabled) out.push("DHCP");
    if (node.dnsForwarder.config.enabled) out.push("DNS");
    out.push(node.nat.forwards.length > 0 ? "NAT+포워딩" : "NAT");
    if (node.firewall.config.enabled) out.push("방화벽");
    if (node.wifi.enabled) out.push(`Wi-Fi ${node.wifi.ssid}`);
    if (node.ipv6Enabled) out.push("IPv6");
  } else if (node instanceof L3Node) {
    if (node.relays.some(Boolean)) out.push("DHCP 릴레이");
    if (node.rip.config.enabled) out.push("RIP");
    if (node.vpn.config.enabled) out.push("VPN");
    if (node.ra.config.enabled) out.push(`원격 VPN ${node.ra.clients.size}`);
    if (node.ha.config.enabled) out.push(node.ha.state === "master" ? "HA master" : "HA backup");
    if (node.nat) out.push(node.nat.forwards.length > 0 ? "NAT+포워딩" : "NAT");
    if (node.firewall.config.enabled) out.push("방화벽");
    if (node.ipv6Enabled) out.push("IPv6");
  } else if (node instanceof Internet) {
    out.push("ISP DHCP", "DNS", "웹");
  } else if (node instanceof Switch && (node.vlanAware || node.stp.config.enabled)) {
    if (node.vlanAware) out.push("VLAN");
    if (node.stp.config.enabled) out.push(node.stp.isRoot ? "STP 루트" : "STP");
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
    const c = conflictLine(`${name} `, up);
    if (c) return c;
    if (up.ip) return { text: `${name} ${up.ip}`, tone: "ok", mono: true };
    if (!node.linkUp[0]) return { text: `${name} 연결 없음`, tone: "muted", mono: false };
    if (!node.clients[0]) return { text: `${name} 주소 수동 입력 필요`, tone: "warn", mono: false };
    return { text: `${name} ${DHCP_STATE_LABEL[node.clients[0].state]}`, tone: node.clients[0].state === "failed" ? "warn" : "muted", mono: false };
  }
  if (!(node instanceof Router)) return null;
  const wc = conflictLine("WAN ", node.wan);
  if (wc) return wc;
  if (node.wan.ip) return { text: `WAN ${node.wan.ip}`, tone: "ok", mono: true };
  if (!node.wanLinkUp) return { text: "WAN 연결 없음", tone: "muted", mono: false };
  if (node.wanMode === "static") return { text: "WAN 주소 수동 입력 필요", tone: "warn", mono: false };
  return { text: `WAN ${DHCP_STATE_LABEL[node.wanClient.state]}`, tone: node.wanClient.state === "failed" ? "warn" : "muted", mono: false };
}
