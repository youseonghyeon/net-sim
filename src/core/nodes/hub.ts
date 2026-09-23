import { describeFrame, type EthernetFrame } from "../packet";
import type { NodeContext, NodeSnapshot, NodeType, SimNode } from "./node";
import { guardLoop } from "./switch";

/**
 * 옛날 허브(리피터): MAC 학습도 목적지 조회도 없이, 들어온 프레임을 수신 포트 제외 모든 포트로 그대로 반복한다.
 *
 * 학습 포인트 — 스위치가 허브를 대체한 이유:
 * - 허브에 물린 모든 장치가 모든 프레임을 본다. 유니캐스트라도 "내 MAC 아님" 으로 각자 버릴 뿐, 선에는 다 흐른다(도청 가능).
 * - 포트가 몇 개든 전체가 하나의 충돌 도메인이라 동시에 두 장치가 보내면 충돌한다. 대역폭을 모두가 나눠 쓴다.
 * - 스위치는 출발지 MAC 을 학습해 목적지 포트로만 보내므로 포트마다 충돌 도메인이 분리되고, 남의 프레임이 내 포트로 오지 않는다.
 * 루프 안전장치(`guardLoop`)는 스위치와 같은 것을 쓴다 — 실제 허브에도 TTL 이 없어 케이블 두 개로 이으면 폭주한다.
 */
export class Hub implements SimNode {
  // NodeType 유니온에 "hub" 를 추가하는 것은 통합자 몫(node.ts 미수정). 추가되면 이 캐스트는 그대로 두어도 된다.
  readonly type = "hub" as unknown as NodeType;
  readonly id: string;
  readonly portCount: number;
  private readonly portNames: string[];
  /** 최근 본 프레임 id → 수신 포트. 같은 프레임이 다시 오면 L2 루프 (스위치와 동일한 안전장치) */
  private readonly seen = new Map<number | string, number>();

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

    // 목적지 MAC 은 보지도 않고, 학습도 하지 않는다. 연결된 다른 포트 전부로 반복.
    const ports: number[] = [];
    for (let p = 0; p < this.portCount; p++) {
      if (p !== port && ctx.isPortConnected(p)) ports.push(p);
    }
    if (ports.length === 0) {
      ctx.trace("hub.repeat", "L2", `허브: 학습 없이 ${pn} 제외 모든 포트로 반복 — 반복할 포트 없음 (다른 포트에 케이블이 없음)`, { inPort: port, ports }, frame.id);
      return;
    }
    ctx.trace(
      "hub.repeat",
      "L2",
      `허브: 학습 없이 ${pn} 제외 모든 포트로 반복 [${ports.map((p) => this.portName(p)).join(", ")}] — 목적지가 누구든 모든 장치가 이 프레임을 본다 (충돌 도메인 공유)`,
      { inPort: port, ports },
      frame.id,
    );
    for (const p of ports) ctx.send(p, frame);
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    if (up) return;
    ctx.trace("link.down", "L1", `${this.portName(port)} 링크 다운`, { port });
  }

  onTimer(): void {}

  snapshot(): NodeSnapshot {
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [
        ["포트 수", String(this.portCount)],
        ["MAC 테이블", "없음 (허브는 학습하지 않음)"],
      ],
      tables: [],
    };
  }
}
