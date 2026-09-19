import { isBroadcastMac, type Mac } from "../addr";
import { describeFrame, MAX_L2_HOPS, type EthernetFrame } from "../packet";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";

interface MacEntry {
  port: number;
  vlan: number;
  learnedAt: number;
}

/** 포트 모드: 액세스(VLAN 번호, 태그 없음) 또는 트렁크(모든 VLAN 을 태그 달아 실어 나름) */
export type PortVlan = number | "trunk";
export const DEFAULT_VLAN = 1;

/**
 * 학습형 L2 스위치: 출발지 MAC 학습, 목적지 MAC 조회, 모르면 플러딩.
 * VLAN: 액세스 포트는 소속 VLAN 하나, 트렁크 포트는 802.1Q 태그로 여러 VLAN. MAC 테이블과 플러딩은 VLAN 마다 따로.
 */
export class Switch implements SimNode {
  readonly type = "switch" as const;
  /** "vlan:mac" → 항목 */
  readonly macTable = new Map<string, MacEntry>();
  readonly id: string;
  readonly portCount: number;
  private readonly portNames: string[];
  /** 포트별 VLAN 설정. 없으면 액세스 VLAN 1 */
  readonly portVlan = new Map<number, PortVlan>();
  /** 최근 본 프레임 id → 수신 포트. 같은 프레임이 다시 오면 L2 루프 */
  private readonly seen = new Map<number, number>();

  /** ports: 포트 개수(이름은 port N) 또는 포트 이름 목록 */
  constructor(id: string, ports: number | string[] = 4) {
    this.id = id;
    this.portNames = typeof ports === "number" ? Array.from({ length: ports }, (_, i) => `port ${i}`) : ports;
    this.portCount = this.portNames.length;
  }

  portName(port: number): string {
    return this.portNames[port] ?? `port ${port}`;
  }

  vlanOf(port: number): PortVlan {
    return this.portVlan.get(port) ?? DEFAULT_VLAN;
  }

  /** VLAN 을 쓰고 있는지 (설정이 하나라도 기본과 다르면) */
  get vlanAware(): boolean {
    for (const v of this.portVlan.values()) if (v !== DEFAULT_VLAN) return true;
    return false;
  }

  setVlans(cfg: Map<number, PortVlan>, ctx: NodeContext): void {
    let changed = false;
    for (let p = 0; p < this.portCount; p++) {
      const next = cfg.get(p) ?? DEFAULT_VLAN;
      if (this.vlanOf(p) !== next) {
        changed = true;
        this.portVlan.set(p, next);
        ctx.trace("ip.config", "sys", `${this.portName(p)}: ${next === "trunk" ? "트렁크 (모든 VLAN, 태그 있음)" : `액세스 VLAN ${next}`}`, { port: p, vlan: next });
      }
    }
    if (changed) {
      this.macTable.clear();
      ctx.trace("ip.config", "sys", `VLAN 설정 변경 → MAC 테이블 비움`, {});
    }
  }

  private key(vlan: number, mac: Mac): string {
    return `${vlan}:${mac}`;
  }

  receive(port: number, frame: EthernetFrame, ctx: NodeContext): void {
    const label = describeFrame(frame);
    const pn = this.portName(port);
    const mode = this.vlanOf(port);
    ctx.trace("frame.receive", "L2", `${pn} 수신: ${label} [${frame.src} → ${frame.dst}]${frame.vlan !== undefined ? ` (VLAN ${frame.vlan} 태그)` : ""}`, { port, src: frame.src, dst: frame.dst, vlan: frame.vlan }, frame.id);
    if (!guardLoop(this.seen, port, frame, ctx, pn)) return;
    frame = { ...frame, hops: (frame.hops ?? 0) + 1 };

    // 이 프레임이 속한 VLAN 결정
    let vlan: number;
    if (mode === "trunk") {
      if (frame.vlan === undefined) {
        ctx.trace("vlan.drop", "L2", `${pn} 는 트렁크인데 태그 없는 프레임 → 폐기 (상대 포트도 트렁크여야 함)`, { port }, frame.id);
        return;
      }
      vlan = frame.vlan;
      frame = { ...frame, vlan: undefined };
    } else {
      if (frame.vlan !== undefined) {
        ctx.trace("vlan.drop", "L2", `${pn} 는 액세스 포트(VLAN ${mode})인데 VLAN ${frame.vlan} 태그 프레임 → 폐기 (트렁크로 바꿔야 함)`, { port }, frame.id);
        return;
      }
      vlan = mode;
    }

    const existing = this.macTable.get(this.key(vlan, frame.src));
    if ((!existing || existing.port !== port) && ctx.isPortConnected(port)) {
      this.macTable.set(this.key(vlan, frame.src), { port, vlan, learnedAt: ctx.now });
      const v = this.vlanAware ? ` (VLAN ${vlan})` : "";
      ctx.trace(
        "switch.learn",
        "L2",
        existing ? `MAC 테이블 갱신: ${frame.src} → ${pn}${v} (이전 ${this.portName(existing.port)})` : `MAC 테이블 학습: ${frame.src} → ${pn}${v}`,
        { mac: frame.src, port, vlan },
        frame.id,
      );
    }

    if (isBroadcastMac(frame.dst)) {
      this.flood(port, vlan, frame, ctx, "브로드캐스트");
      return;
    }
    const entry = this.macTable.get(this.key(vlan, frame.dst));
    if (!entry) {
      this.flood(port, vlan, frame, ctx, `${frame.dst} 는 ${this.vlanAware ? `VLAN ${vlan} 의 ` : ""}MAC 테이블에 없음`);
      return;
    }
    if (entry.port === port) {
      ctx.trace("switch.filter", "L2", `목적지 ${frame.dst} 가 수신 포트(${pn})와 같음 → 필터링(전달 안 함)`, { port }, frame.id);
      return;
    }
    ctx.trace("switch.forward", "L2", `MAC 테이블 조회: ${frame.dst} → ${this.portName(entry.port)} 로 전달${this.vlanAware ? ` (VLAN ${vlan})` : ""}`, { dst: frame.dst, port: entry.port, vlan }, frame.id);
    this.sendOut(entry.port, vlan, frame, ctx);
  }

  /** 포트 모드에 맞춰 태그를 붙이거나 뗀 뒤 송신 */
  private sendOut(port: number, vlan: number, frame: EthernetFrame, ctx: NodeContext): void {
    if (this.vlanOf(port) === "trunk") {
      ctx.trace("vlan.tag", "L2", `${this.portName(port)} 는 트렁크 → 802.1Q 태그 VLAN ${vlan} 를 붙여 송신`, { port, vlan }, frame.id);
      ctx.send(port, { ...frame, vlan });
      return;
    }
    ctx.send(port, frame);
  }

  /** 같은 VLAN 의 액세스 포트 + 모든 트렁크 포트로 */
  private flood(inPort: number, vlan: number, frame: EthernetFrame, ctx: NodeContext, reason: string): void {
    const ports: number[] = [];
    const excluded: number[] = [];
    for (let p = 0; p < this.portCount; p++) {
      if (p === inPort || !ctx.isPortConnected(p)) continue;
      const m = this.vlanOf(p);
      if (m === "trunk" || m === vlan) ports.push(p);
      else excluded.push(p);
    }
    const v = this.vlanAware ? ` (VLAN ${vlan}${excluded.length ? `; 다른 VLAN 포트 ${excluded.map((p) => this.portName(p)).join(", ")} 제외` : ""})` : "";
    ctx.trace(
      "switch.flood",
      "L2",
      `${reason} → ${this.portName(inPort)} 제외 플러딩 [${ports.map((p) => this.portName(p)).join(", ")}]${v}`,
      { inPort, ports, reason, vlan },
      frame.id,
    );
    for (const p of ports) this.sendOut(p, vlan, frame, ctx);
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    if (up) return;
    for (const [k, e] of this.macTable) if (e.port === port) this.macTable.delete(k);
    ctx.trace("link.down", "L1", `${this.portName(port)} 링크 끊김 → 그 포트의 MAC 학습 정보 삭제`, { port });
  }

  onTimer(): void {}

  snapshot(): NodeSnapshot {
    const vlans = new Set<number>();
    for (let p = 0; p < this.portCount; p++) {
      const m = this.vlanOf(p);
      if (m !== "trunk") vlans.add(m);
    }
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [
        ["포트 수", String(this.portCount)],
        ...(this.vlanAware ? [["VLAN", [...vlans].sort((a, b) => a - b).join(", ")] as [string, string]] : []),
      ],
      tables: [
        {
          title: "MAC 테이블",
          columns: this.vlanAware ? ["VLAN", "MAC", "포트", "학습 시각"] : ["MAC", "포트", "학습 시각"],
          rows: [...this.macTable.entries()].map(([k, e]) => {
            const mac = k.slice(k.indexOf(":") + 1);
            return this.vlanAware ? [String(e.vlan), mac, this.portName(e.port), `${e.learnedAt}ms`] : [mac, this.portName(e.port), `${e.learnedAt}ms`];
          }),
        },
      ],
    };
  }
}

/**
 * L2 루프 안전장치. 같은 프레임을 두 번째 보거나 홉 수가 한도를 넘으면 버린다.
 * 실제 이더넷에는 이런 장치가 없어서(TTL 없음) STP 로 루프를 미리 끊어야 한다 — 그 점을 로그로 알려준다.
 */
export function guardLoop(seen: Map<number, number>, port: number, frame: EthernetFrame, ctx: NodeContext, portName: string): boolean {
  if ((frame.hops ?? 0) >= MAX_L2_HOPS) {
    ctx.trace("switch.loop", "L2", `프레임이 스위치 ${MAX_L2_HOPS}개를 넘게 돌았음 → L2 루프로 판단해 폐기. 실제 이더넷엔 TTL 이 없어 STP 가 없으면 브로드캐스트 폭주가 난다`, { port }, frame.id);
    return false;
  }
  const prev = seen.get(frame.id);
  if (prev !== undefined) {
    ctx.trace("switch.loop", "L2", `같은 프레임을 ${portName} 에서 다시 받음 (처음은 다른 포트) → L2 루프 감지, 폐기. 케이블이 두 경로로 이어져 있음`, { port, first: prev }, frame.id);
    return false;
  }
  seen.set(frame.id, port);
  if (seen.size > 512) {
    const oldest = seen.keys().next().value;
    if (oldest !== undefined) seen.delete(oldest);
  }
  return true;
}
