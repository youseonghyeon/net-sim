import { isBroadcastMac, type Mac } from "../addr";
import { describeFrame, MAX_L2_HOPS, type EthernetFrame } from "../packet";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";

interface MacEntry {
  port: number;
  learnedAt: number;
}

/** 학습형 L2 스위치: 출발지 MAC 학습, 목적지 MAC 조회, 모르면 플러딩 */
export class Switch implements SimNode {
  readonly type = "switch" as const;
  readonly macTable = new Map<Mac, MacEntry>();
  readonly id: string;
  readonly portCount: number;
  private readonly portNames: string[];
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

  receive(port: number, frame: EthernetFrame, ctx: NodeContext): void {
    const label = describeFrame(frame);
    const pn = this.portName(port);
    ctx.trace("frame.receive", "L2", `${pn} 수신: ${label} [${frame.src} → ${frame.dst}]`, { port, src: frame.src, dst: frame.dst }, frame.id);
    if (!guardLoop(this.seen, port, frame, ctx, pn)) return;
    frame = { ...frame, hops: (frame.hops ?? 0) + 1 };

    const existing = this.macTable.get(frame.src);
    if (!existing || existing.port !== port) {
      this.macTable.set(frame.src, { port, learnedAt: ctx.now });
      ctx.trace(
        "switch.learn",
        "L2",
        existing ? `MAC 테이블 갱신: ${frame.src} → ${pn} (이전 ${this.portName(existing.port)})` : `MAC 테이블 학습: ${frame.src} → ${pn}`,
        { mac: frame.src, port },
        frame.id,
      );
    }

    if (isBroadcastMac(frame.dst)) {
      this.flood(port, frame, ctx, "브로드캐스트");
      return;
    }
    const entry = this.macTable.get(frame.dst);
    if (!entry) {
      this.flood(port, frame, ctx, `${frame.dst} 는 MAC 테이블에 없음`);
      return;
    }
    if (entry.port === port) {
      ctx.trace("switch.filter", "L2", `목적지 ${frame.dst} 가 수신 포트(${pn})와 같음 → 필터링(전달 안 함)`, { port }, frame.id);
      return;
    }
    ctx.trace("switch.forward", "L2", `MAC 테이블 조회: ${frame.dst} → ${this.portName(entry.port)} 로 전달`, { dst: frame.dst, port: entry.port }, frame.id);
    ctx.send(entry.port, frame);
  }

  private flood(inPort: number, frame: EthernetFrame, ctx: NodeContext, reason: string): void {
    const ports: number[] = [];
    for (let p = 0; p < this.portCount; p++) {
      if (p !== inPort && ctx.isPortConnected(p)) ports.push(p);
    }
    ctx.trace(
      "switch.flood",
      "L2",
      `${reason} → ${this.portName(inPort)} 제외 플러딩 [${ports.map((p) => this.portName(p)).join(", ")}]`,
      { inPort, ports, reason },
      frame.id,
    );
    for (const p of ports) ctx.send(p, frame);
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    if (up) return;
    for (const [mac, e] of this.macTable) if (e.port === port) this.macTable.delete(mac);
    ctx.trace("link.down", "L1", `${this.portName(port)} 링크 끊김 → 그 포트의 MAC 학습 정보 삭제`, { port });
  }

  onTimer(): void {}

  snapshot(): NodeSnapshot {
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [["포트 수", String(this.portCount)]],
      tables: [
        {
          title: "MAC 테이블",
          columns: ["MAC", "포트", "학습 시각"],
          rows: [...this.macTable.entries()].map(([mac, e]) => [mac, this.portName(e.port), `${e.learnedAt}ms`]),
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
