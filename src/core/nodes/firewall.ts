// 방화벽: 라우터/게이트웨이/NAT 박스를 "지나가는" 패킷을 규칙으로 거른다 (iptables 의 FORWARD 체인에 해당).
// 규칙은 위에서부터 첫 일치가 이긴다. Stateful 검사를 켜면 안에서 시작한 통신의 응답은 규칙과 무관하게 통과한다.
import { ipToInt, prefixToMask, type Ip } from "../addr";
import { isIpv6, sameSubnet6 } from "../addr6";
import { describeOriginal, hasPorts, icmpErrorLabel, icmpv6ErrorLabel, isIcmpErrorAny, type IpPacket } from "../packet";
import type { NodeContext } from "./node";

export type FwAction = "allow" | "deny";
export type FwProto = "any" | "icmp" | "tcp" | "udp" | "esp";
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
  /** 안에서 시작한 통신의 응답을 자동 허용 (Stateful 검사) */
  stateful: boolean;
  rules: FirewallRule[];
}

export const DEFAULT_FIREWALL: FirewallConfig = { enabled: false, defaultPolicy: "allow", stateful: true, rules: [] };

export const PROTO_LABEL: Record<FwProto, string> = { any: "모든 프로토콜", icmp: "ICMP(ping)", tcp: "TCP", udp: "UDP", esp: "ESP(IPsec)" };
export const DIRECTION_LABEL: Record<FwDirection, string> = { in: "인바운드", out: "아웃바운드", any: "양방향" };

/** "a.b.c.d" 또는 "a.b.c.d/n" (IPv6 는 "2001:db8::/32") 이 ip 를 포함하는지. 형식이 틀리거나 버전이 다르면 false */
export function cidrContains(cidr: string, ip: Ip): boolean {
  const [base, prefixStr] = cidr.trim().split("/");
  if (!base || prefixStr === "") return false;
  if (isIpv6(base)) {
    const p6 = prefixStr === undefined ? 128 : Number(prefixStr);
    return Number.isInteger(p6) && p6 >= 0 && p6 <= 128 && isIpv6(ip) && sameSubnet6(base, ip, p6);
  }
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
  if (!base || prefixStr === "") return false;
  if (isIpv6(base)) {
    const p = prefixStr === undefined ? 128 : Number(prefixStr);
    return Number.isInteger(p) && p >= 0 && p <= 128;
  }
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
function isInitiator(pkt: IpPacket): boolean {
  const p = pkt.payload;
  if (p.kind === "icmp" || p.kind === "icmp6") return p.type === "echo-request";
  if (p.kind === "tcp") return !!p.syn && !p.ackFlag;
  return true;
}

function flowKey(pkt: IpPacket, reverse: boolean): string {
  const p = pkt.payload;
  if (isIcmpErrorAny(p)) {
    // ICMP 오류는 내장된 원래 패킷에 대한 응답이다: 역방향 키 = 원래 흐름의 정방향 키. 스스로 흐름을 만들지는 않는다
    if (!reverse) return `icmp-error:${pkt.src}:${pkt.dst}`;
    const o = p.original;
    return o.l4.kind === "icmp" ? `icmp:${o.src}:${o.dst}:${o.l4.id}` : `${o.l4.kind}:${o.src}:${o.l4.srcPort}:${o.dst}:${o.l4.dstPort}`;
  }
  const a = reverse ? pkt.dst : pkt.src;
  const b = reverse ? pkt.src : pkt.dst;
  if (p.kind === "icmp" || p.kind === "icmp6") return `icmp:${a}:${b}:${"id" in p ? p.id : 0}`;
  if (!hasPorts(p)) return `${p.kind}:${a}:${b}`; // ESP·제어 멀티캐스트는 포트가 없어 주소 쌍으로 본다
  const ap = reverse ? p.dstPort : p.srcPort;
  const bp = reverse ? p.srcPort : p.dstPort;
  return `${p.kind}:${a}:${ap}:${b}:${bp}`;
}

export class Firewall {
  /** 허용되어 지나간 흐름 (정방향 키) */
  private readonly flows = new Set<string>();
  /** 새 흐름이 생길 때 (이중화 세션 동기화) */
  onFlow?: (key: string, ctx: NodeContext) => void;

  /** 지금 기억하는 흐름 (세션 동기화의 전체 복사용) */
  flowKeys(): string[] {
    return [...this.flows];
  }

  /** 다른 장비(이중화 master)가 알려 준 흐름을 받아 둔다 */
  importFlow(key: string): void {
    this.flows.add(key);
    if (this.flows.size > 512) this.flows.delete(this.flows.values().next().value!);
  }

  constructor(
    public config: FirewallConfig = { ...DEFAULT_FIREWALL, rules: [] },
    /** 로그 앞 이름 (공유기의 "IPv6 기본 방화벽" 처럼 사용자 규칙과 구분할 때) */
    private readonly label = "방화벽",
    /** 기본 정책으로 차단할 때 덧붙일 안내 */
    private readonly denyHint?: string,
  ) {}

  /** 켜져 있고, 이 패킷에 처음 일치하는 규칙이 허용인지 (기본 정책은 보지 않는다) */
  allowsByRule(pkt: IpPacket, dir: FlowDirection): boolean {
    if (!this.config.enabled) return false;
    const rule = this.config.rules.find((r) => this.matches(r, pkt, dir));
    return rule?.action === "allow";
  }

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
      `${label} 방화벽: 규칙 ${cfg.rules.length}개, 기본 정책 ${cfg.defaultPolicy === "allow" ? "허용" : "차단"}, Stateful 검사 ${cfg.stateful ? "켜짐" : "꺼짐"}`,
      { rules: cfg.rules.length, defaultPolicy: cfg.defaultPolicy, stateful: cfg.stateful },
    );
  }

  private matches(r: FirewallRule, pkt: IpPacket, dir: FlowDirection): boolean {
    if (r.direction !== "any" && r.direction !== dir) return false;
    const p = pkt.payload;
    // "ICMP" 규칙은 ICMPv6 에도 걸린다 (ping 을 막거나 여는 규칙이 두 버전에 같이)
    const kind = p.kind === "icmp6" ? "icmp" : p.kind;
    if (r.proto !== "any" && r.proto !== kind) return false;
    if (r.src && !cidrContains(r.src, pkt.src)) return false;
    if (r.dst && !cidrContains(r.dst, pkt.dst)) return false;
    if (r.dstPort) {
      if (!hasPorts(p)) return false;
      if (p.dstPort !== r.dstPort) return false;
    }
    return true;
  }

  /** 검사 없이 흐름만 기억한다 (나가는 것은 모두 통과시키는 기본 방화벽: 돌아오는 응답을 Stateful 로 들이려고) */
  remember(pkt: IpPacket, ctx: NodeContext): void {
    if (!this.config.enabled || !this.config.stateful || !isInitiator(pkt)) return;
    const key = flowKey(pkt, false);
    if (this.flows.has(key)) return;
    this.flows.add(key);
    if (this.flows.size > 512) this.flows.delete(this.flows.values().next().value!);
    this.onFlow?.(key, ctx);
  }

  /** 지나가는 패킷 검사. true 면 통과. 차단이면 이유를 트레이스로 남긴다 */
  check(pkt: IpPacket, dir: FlowDirection, ctx: NodeContext, frameId?: number): boolean {
    if (!this.config.enabled) return true;
    const what = describePacket(pkt);
    const dirLabel = dir === "in" ? "인바운드" : dir === "out" ? "아웃바운드" : "서브넷 간";
    const established = this.config.stateful && this.flows.has(flowKey(pkt, true));
    const idx = this.config.rules.findIndex((r) => this.matches(r, pkt, dir));
    const rule = idx >= 0 ? this.config.rules[idx]! : undefined;
    const verdict: FwAction = rule ? rule.action : this.config.defaultPolicy;

    if (verdict === "deny" && established) {
      ctx.trace(
        "fw.established",
        "L3",
        `${this.label}: ${dirLabel} ${what} 은(는) ${rule ? `규칙 ${idx + 1}(${describeRule(rule)})` : "기본 정책"} 상 차단이지만, 안에서 시작한 통신의 ${isIcmpErrorAny(pkt.payload) ? "오류 통지라" : "응답이라"} Stateful 검사로 허용`,
        { rule: idx, dir },
        frameId,
      );
      return true;
    }
    if (verdict === "deny") {
      ctx.trace(
        "fw.deny",
        "L3",
        `${this.label} 차단: ${dirLabel} ${what} — ${rule ? `규칙 ${idx + 1} (${describeRule(rule)})` : this.denyHint ?? "일치하는 규칙 없음, 기본 정책 차단"} → 드롭`,
        { rule: idx, dir, src: pkt.src, dst: pkt.dst },
        frameId,
      );
      return false;
    }
    if (rule) {
      ctx.trace("fw.allow", "L3", `${this.label} 허용: ${dirLabel} ${what} — 규칙 ${idx + 1} (${describeRule(rule)})`, { rule: idx, dir }, frameId);
    }
    if (this.config.stateful && !established && isInitiator(pkt)) {
      const key = flowKey(pkt, false);
      this.flows.add(key);
      if (this.flows.size > 512) this.flows.delete(this.flows.values().next().value!);
      this.onFlow?.(key, ctx);
    }
    return true;
  }

  rows(): string[][] {
    return this.config.rules.map((r, i) => [String(i + 1), describeRule(r)]);
  }
}

function describePacket(pkt: IpPacket): string {
  const p = pkt.payload;
  if (p.kind === "icmp6") {
    if (p.type === "time-exceeded" || p.type === "unreachable") return `ICMPv6 ${icmpv6ErrorLabel(p)} ${pkt.src} → ${pkt.dst} (원래 ${describeOriginal(p.original)})`;
    return `ICMPv6 ${p.type === "echo-request" ? "ping 요청" : p.type === "echo-reply" ? "ping 응답" : p.type.toUpperCase()} ${pkt.src} → ${pkt.dst}`;
  }
  if (p.kind === "icmp" && (p.type === "time-exceeded" || p.type === "unreachable")) return `ICMP ${icmpErrorLabel(p)} ${pkt.src} → ${pkt.dst} (원래 ${describeOriginal(p.original)})`;
  if (p.kind === "icmp") return `ICMP ${p.type === "echo-request" ? "ping 요청" : "ping 응답"} ${pkt.src} → ${pkt.dst}`;
  if (!hasPorts(p)) return `${p.kind.toUpperCase()} ${pkt.src} → ${pkt.dst}${p.kind === "esp" ? " (IPsec)" : ""}`;
  return pkt.kind === "ipv6" ? `${p.kind.toUpperCase()} [${pkt.src}]:${p.srcPort} → [${pkt.dst}]:${p.dstPort}` : `${p.kind.toUpperCase()} ${pkt.src}:${p.srcPort} → ${pkt.dst}:${p.dstPort}`;
}
