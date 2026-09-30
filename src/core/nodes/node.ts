import type { EthernetFrame, Layer } from "../packet";
import type { TraceKind } from "../trace";

export type NodeType = "host" | "switch" | "hub" | "ap" | "router" | "internet" | "gateway" | "nat" | "firewall";

export interface TimerHandle {
  cancel(): void;
}

/** 노드가 시뮬레이터와 상호작용하는 유일한 통로 */
export interface NodeContext {
  readonly now: number;
  /** 지정 포트에 연결된 링크로 프레임 송신 */
  send(port: number, frame: EthernetFrame): void;
  isPortConnected(port: number): boolean;
  /**
   * delay(ms) 후 onTimer(tag, data) 호출. 핸들로 취소 가능.
   * background 면 배경 타이머: 스스로 시계를 움직이지 않고, 다른 일(패킷 이동·timeout·"+N초")로 시간이 그 시각을 지날 때만 발화한다.
   * 주기 동작(광고·헬스 체크·DPD)용 — 조용한 네트워크에서 시계가 끝없이 점프하지 않게
   */
  timer(delay: number, tag: string, data?: unknown, background?: boolean): TimerHandle;
  trace(kind: TraceKind, layer: Layer, summary: string, details?: Record<string, unknown>, packetId?: number): void;
  nextPacketId(): number;
}

export interface SnapshotTable {
  title: string;
  columns: string[];
  rows: string[][];
}

/** UI 인스펙터용 상태 스냅샷 */
export interface NodeSnapshot {
  id: string;
  type: NodeType;
  label: string;
  info: [string, string][];
  tables: SnapshotTable[];
}

export interface SimNode {
  readonly id: string;
  readonly type: NodeType;
  readonly portCount: number;
  receive(port: number, frame: EthernetFrame, ctx: NodeContext): void;
  onTimer(tag: string, data: unknown, ctx: NodeContext): void;
  /** 포트에 케이블이 꽂히거나(up) 빠질 때(down) */
  onLink?(port: number, up: boolean, ctx: NodeContext): void;
  /** 장치가 제거되기 직전 (정상 종료: DHCP Release 등). 이때 보낸 프레임은 케이블이 빠져도 배달된다 */
  onRemove?(ctx: NodeContext): void;
  snapshot(): NodeSnapshot;
}
