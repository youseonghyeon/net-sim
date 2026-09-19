// 방화벽: 라우터/게이트웨이/NAT 박스를 "지나가는" 패킷을 규칙으로 거른다 (iptables 의 FORWARD 체인에 해당).
// 규칙은 위에서부터 첫 일치가 이긴다. 상태 추적을 켜면 안에서 시작한 통신의 응답은 규칙과 무관하게 통과한다.
import { ipToInt, prefixToMask, type Ip } from "../addr";
import type { Ipv4Packet } from "../packet";
import type { NodeContext } from "./node";

export type FwAction = "allow" | "deny";
export type FwProto = "any" | "icmp" | "tcp" | "udp";
/** in = 업링크(WAN/outside/if0)에서 들어옴, out = 업링크로 나감, lan = 안쪽 서브넷끼리 */
export type FwDirection = "in" | "out" | "any";
export type FlowDirection = "in" | "out" | "lan";

export interface FirewallRule {
  action: FwAction;
  proto: FwProto;
  direction: FwDirection;
  /** 출발지 CIDR (예: 192.168.0.0/24, 192.168.0.20). 비우면 모두 */
  src?: string;
  /** 목적지 CIDR. 비우면 모두 */
  dst?: string;
  /** 목적지 포트 (tcp/udp). 비우면 모두 */
  dstPort?: number;
}

export interface FirewallConfig {
  enabled: boolean;
  /** 어떤 규칙에도 안 걸린 패킷의 처리 */
  defaultPolicy: FwAction;
  /** 안에서 시작한 통신의 응답을 자동 허용 (상태 추적) */
  stateful: boolean;
  rules: FirewallRule[];
}

export const DEFAULT_FIREWALL: FirewallConfig = { enabled: false, defaultPolicy: "allow", stateful: true, rules: [] };

export const PROTO_LABEL: Record<FwProto, string> = { any: "모든 프로토콜", icmp: "ICMP(ping)", tcp: "TCP", udp: "UDP" };
export const DIRECTION_LABEL: Record<FwDirection, string> = { in: "들어오는", out: "나가는", any: "모든 방향" };

/** "a.b.c.d" 또는 "a.b.c.d/n" 이 ip 를 포함하는지. 형식이 틀리면 false */
export function cidrContains(cidr: string, ip: Ip): boolean {
  const [base, prefixStr] = cidr.trim().split("/");
  if (!base) return false;
  const prefix = prefixStr === undefined ? 32 : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  try {
    const mask = prefixToMask(prefix);
    return ((ipToInt(base) & mask) >>> 0) === ((ipToInt(ip) & mask) >>> 0);
  } catch {
    return false;
  }
}

export function validCidr(cidr: string): boolean {
  const [base, prefixStr] = cidr.trim().split("/");
  if (!base) return false;
  if (prefixStr !== undefined) {
    const p = Number(prefixStr);
    if (!Number.isInteger(p) || p < 0 || p > 32) return false;
  }
  try {
    ipToInt(base);
    return true;
  } catch {
    return false;
  }
}

export function describeRule(r: FirewallRule): string {
  const parts = [r.action === "allow" ? "허용" : "차단", DIRECTION_LABEL[r.direction], PROTO_LABEL[r.proto]];
  if (r.src) parts.push(`출발 ${r.src}`);
  if (r.dst) parts.push(`목적 ${r.dst}`);
  if (r.dstPort) parts.push(`포트 ${r.dstPort}`);
  return parts.join(" · ");
}

/** 새 통신을 여는 패킷인가 (conntrack 의 NEW). 응답 패킷은 흐름을 만들지 않는다 */
function isInitiator(pkt: Ipv4Packet): boolean {
  const p = pkt.payload;
  if (p.kind === "icmp") return p.type === "echo-request";
  if (p.kind === "tcp") return !!p.syn && !p.ackFlag;
  return true;
}

function flowKey(pkt: Ipv4Packet, reverse: boolean): string {
  const p = pkt.payload;
  const a = reverse ? pkt.dst : pkt.src;
  const b = reverse ? pkt.src : pkt.dst;
  if (p.kind === "icmp") return `icmp:${a}:${b}:${p.id}`;
  const ap = reverse ? p.dstPort : p.srcPort;
  const bp = reverse ? p.srcPort : p.dstPort;
  return `${p.kind}:${a}:${ap}:${b}:${bp}`;
}

export class Firewall {
  /** 허용되어 지나간 흐름 (정방향 키) */
  private readonly flows = new Set<string>();

  constructor(public config: FirewallConfig = { ...DEFAULT_FIREWALL, rules: [] }) {}

  setConfig(cfg: FirewallConfig, ctx: NodeContext, label: string): void {
    const prev = this.config;
    const changed = prev.enabled !== cfg.enabled || prev.defaultPolicy !== cfg.defaultPolicy || prev.stateful !== cfg.stateful || JSON.stringify(prev.rules) !== JSON.stringify(cfg.rules);
    this.config = { ...cfg, rules: cfg.rules.map((r) => ({ ...r })) };
    if (!changed) return;
    if (!cfg.enabled) {
      ctx.trace("ip.config", "sys", `${label} 방화벽 꺼짐 → 모든 패킷 통과`, {});
      this.flows.clear();
      return;
    }
    ctx.trace(
      "ip.config",
      "sys",
      `${label} 방화벽: 규칙 ${cfg.rules.length}개, 기본 정책 ${cfg.defaultPolicy === "allow" ? "허용" : "차단"}, 상태 추적 ${cfg.stateful ? "켜짐" : "꺼짐"}`,
      { rules: cfg.rules.length, defaultPolicy: cfg.defaultPolicy, stateful: cfg.stateful },
    );
  }

  private matches(r: FirewallRule, pkt: Ipv4Packet, dir: FlowDirection): boolean {
    if (r.direction !== "any" && r.direction !== dir) return false;
    const p = pkt.payload;
    if (r.proto !== "any" && r.proto !== p.kind) return false;
    if (r.src && !cidrContains(r.src, pkt.src)) return false;
    if (r.dst && !cidrContains(r.dst, pkt.dst)) return false;
    if (r.dstPort) {
      if (p.kind === "icmp") return false;
      if (p.dstPort !== r.dstPort) return false;
    }
    return true;
  }

  /** 지나가는 패킷 검사. true 면 통과. 차단이면 이유를 트레이스로 남긴다 */
  check(pkt: Ipv4Packet, dir: FlowDirection, ctx: NodeContext, frameId?: number): boolean {
    if (!this.config.enabled) return true;
    const what = describePacket(pkt);
    const dirLabel = dir === "in" ? "들어오는" : dir === "out" ? "나가는" : "서브넷 간";
    const established = this.config.stateful && this.flows.has(flowKey(pkt, true));
    const idx = this.config.rules.findIndex((r) => this.matches(r, pkt, dir));
    const rule = idx >= 0 ? this.config.rules[idx]! : undefined;
    const verdict: FwAction = rule ? rule.action : this.config.defaultPolicy;

    if (verdict === "deny" && established) {
      ctx.trace(
        "fw.established",
        "L3",
        `방화벽: ${dirLabel} ${what} 은(는) ${rule ? `규칙 ${idx + 1}(${describeRule(rule)})` : "기본 정책"} 상 차단이지만, 안에서 시작한 통신의 응답이라 상태 추적으로 허용`,
        { rule: idx, dir },
        frameId,
      );
      return true;
    }
    if (verdict === "deny") {
      ctx.trace(
        "fw.deny",
        "L3",
        `방화벽 차단: ${dirLabel} ${what} — ${rule ? `규칙 ${idx + 1} (${describeRule(rule)})` : "일치하는 규칙 없음, 기본 정책 차단"} → 폐기`,
        { rule: idx, dir, src: pkt.src, dst: pkt.dst },
        frameId,
      );
      return false;
    }
    if (rule) {
      ctx.trace("fw.allow", "L3", `방화벽 허용: ${dirLabel} ${what} — 규칙 ${idx + 1} (${describeRule(rule)})`, { rule: idx, dir }, frameId);
    }
    if (this.config.stateful && !established && isInitiator(pkt)) {
      this.flows.add(flowKey(pkt, false));
      if (this.flows.size > 512) this.flows.delete(this.flows.values().next().value!);
    }
    return true;
  }

  rows(): string[][] {
    return this.config.rules.map((r, i) => [String(i + 1), describeRule(r)]);
  }
}

function describePacket(pkt: Ipv4Packet): string {
  const p = pkt.payload;
  if (p.kind === "icmp") return `ICMP ${p.type === "echo-request" ? "ping 요청" : "ping 응답"} ${pkt.src} → ${pkt.dst}`;
  return `${p.kind.toUpperCase()} ${pkt.src}:${p.srcPort} → ${pkt.dst}:${p.dstPort}`;
}
