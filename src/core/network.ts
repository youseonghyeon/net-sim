import type { Ip } from "./addr";
import { describeFrame, type EthernetFrame, type Layer } from "./packet";
import { Scheduler } from "./scheduler";
import type { TraceEvent, TraceKind } from "./trace";
import { Host } from "./nodes/host";
import type { NodeContext, SimNode, TimerHandle } from "./nodes/node";

export interface Endpoint {
  node: string;
  port: number;
}

export interface Link {
  id: string;
  a: Endpoint;
  b: Endpoint;
  latency: number;
}

/** 링크 위를 이동하는 프레임. UI 애니메이션의 근거 */
export interface Transmission {
  id: number;
  linkId: string;
  from: Endpoint;
  to: Endpoint;
  departAt: number;
  arriveAt: number;
  frame: EthernetFrame;
  /** 도착 전에 링크가 끊겨 유실됨 */
  lost?: boolean;
}

/** 사용자 동작. 직렬화 가능한 형태 */
export type ActionSpec = { kind: "ping"; nodeId: string; dst: Ip } | { kind: "dhcp-renew"; nodeId: string };

export interface RecordedAction {
  time: number;
  action: ActionSpec;
}

type SimEvent =
  | { type: "deliver"; tx: Transmission }
  | { type: "timer"; nodeId: string; tag: string; data?: unknown; cancelled: boolean }
  | { type: "action"; action: ActionSpec };

export class Network {
  readonly nodes = new Map<string, SimNode>();
  readonly links = new Map<string, Link>();
  readonly trace: TraceEvent[] = [];
  readonly transmissions: Transmission[] = [];
  readonly actions: RecordedAction[] = [];

  /** 마지막으로 처리한 이벤트 시각(ms) */
  now = 0;
  /** 처리한 이벤트 개수 */
  eventCount = 0;

  private readonly sched = new Scheduler<SimEvent>();
  private readonly portMap = new Map<string, { link: Link; other: Endpoint }>();
  private packetSeq = 0;
  private traceSeq = 0;
  private txSeq = 0;
  private linkSeq = 0;

  // ---------- 구성 (실행 중에도 변경 가능) ----------

  addNode<T extends SimNode>(node: T): T {
    if (this.nodes.has(node.id)) throw new Error(`duplicate node id: ${node.id}`);
    this.nodes.set(node.id, node);
    return node;
  }

  removeNode(id: string): void {
    const node = this.nodes.get(id);
    if (!node) return;
    for (const link of [...this.links.values()]) {
      if (link.a.node === id || link.b.node === id) this.disconnect(link.id);
    }
    this.nodes.delete(id);
  }

  connect(aNode: string, aPort: number, bNode: string, bPort: number, latency = 10, id?: string): Link {
    const a = { node: aNode, port: aPort };
    const b = { node: bNode, port: bPort };
    for (const ep of [a, b]) {
      const n = this.nodes.get(ep.node);
      if (!n) throw new Error(`unknown node: ${ep.node}`);
      if (ep.port < 0 || ep.port >= n.portCount) throw new Error(`${ep.node} has no port ${ep.port}`);
      if (this.portMap.has(epKey(ep))) throw new Error(`${ep.node}:${ep.port} already connected`);
    }
    const link: Link = { id: id ?? `link${++this.linkSeq}`, a, b, latency };
    this.links.set(link.id, link);
    this.portMap.set(epKey(a), { link, other: b });
    this.portMap.set(epKey(b), { link, other: a });
    for (const ep of [a, b]) this.nodes.get(ep.node)!.onLink?.(ep.port, true, this.ctx(ep.node));
    return link;
  }

  disconnect(linkId: string): void {
    const link = this.links.get(linkId);
    if (!link) return;
    this.links.delete(linkId);
    this.portMap.delete(epKey(link.a));
    this.portMap.delete(epKey(link.b));
    for (const tx of this.transmissions) {
      if (tx.linkId === linkId && !tx.lost && tx.arriveAt > this.now) {
        tx.lost = true;
        this.pushTrace(tx.from.node, "link.lost", "L1", `케이블이 빠져 전송 중이던 ${describeFrame(tx.frame)} 유실`, { linkId }, tx.frame.id);
      }
    }
    for (const ep of [link.a, link.b]) {
      const node = this.nodes.get(ep.node);
      node?.onLink?.(ep.port, false, this.ctx(ep.node));
    }
  }

  hasNode(id: string): boolean {
    return this.nodes.has(id);
  }

  getHost(id: string): Host {
    const n = this.nodes.get(id);
    if (!(n instanceof Host)) throw new Error(`${id} is not a host`);
    return n;
  }

  /** 노드 설정 변경 등 "지금" 일어나는 일을 위해 현재 시각 컨텍스트를 준다 */
  contextFor(nodeId: string): NodeContext {
    return this.ctx(nodeId);
  }

  // ---------- 사용자 동작 ----------

  scheduleAction(time: number, action: ActionSpec): void {
    if (time < this.now) throw new Error(`cannot schedule action in the past (${time} < ${this.now})`);
    this.actions.push({ time, action });
    this.sched.push(time, { type: "action", action }, 1);
  }

  // ---------- 실행 ----------

  /** 취소된 타이머를 건너뛰고 다음 이벤트 시각 */
  peekNextTime(): number | undefined {
    for (;;) {
      const head = this.sched.peek();
      if (!head) return undefined;
      if (head.payload.type === "timer" && head.payload.cancelled) {
        this.sched.pop();
        continue;
      }
      return head.time;
    }
  }

  get pendingEvents(): number {
    this.peekNextTime();
    return this.sched.size;
  }

  /** 이벤트 하나 처리. 처리한 게 없으면 false */
  step(): boolean {
    if (this.peekNextTime() === undefined) return false;
    const item = this.sched.pop()!;
    this.now = item.time;
    this.eventCount++;
    const ev = item.payload;
    switch (ev.type) {
      case "deliver": {
        if (ev.tx.lost) break;
        const node = this.nodes.get(ev.tx.to.node);
        if (!node || !this.links.has(ev.tx.linkId)) {
          ev.tx.lost = true;
          break;
        }
        node.receive(ev.tx.to.port, ev.tx.frame, this.ctx(node.id));
        break;
      }
      case "timer": {
        if (ev.cancelled) break;
        const node = this.nodes.get(ev.nodeId);
        node?.onTimer(ev.tag, ev.data, this.ctx(node.id));
        break;
      }
      case "action":
        this.runAction(ev.action);
        break;
    }
    return true;
  }

  /** time 이하의 이벤트를 모두 처리하고 now 를 time 으로 맞춘다 */
  runUntil(time: number): number {
    let n = 0;
    for (;;) {
      const next = this.peekNextTime();
      if (next === undefined || next > time) break;
      this.step();
      n++;
    }
    if (time > this.now) this.now = time;
    return n;
  }

  runToIdle(maxEvents = 10_000): number {
    let n = 0;
    while (n < maxEvents && this.step()) n++;
    if (n >= maxEvents) throw new Error(`runToIdle: exceeded ${maxEvents} events`);
    return n;
  }

  /** 지정 시각에 링크 위에 있는 프레임 */
  inFlight(at = this.now): Transmission[] {
    return this.transmissions.filter((t) => !t.lost && t.departAt <= at && at < t.arriveAt);
  }

  /** 오래된 전송 기록 정리 (UI 가 길게 돌아도 메모리가 늘지 않도록) */
  pruneTransmissions(before: number): void {
    let i = 0;
    while (i < this.transmissions.length && this.transmissions[i]!.arriveAt < before) i++;
    if (i > 0) this.transmissions.splice(0, i);
  }

  // ---------- 내부 ----------

  private runAction(action: ActionSpec): void {
    const node = this.nodes.get(action.nodeId);
    if (!node) return;
    const ctx = this.ctx(action.nodeId);
    switch (action.kind) {
      case "ping":
        ctx.trace("action", "sys", `[사용자] ping ${action.dst}`, { ...action });
        this.getHost(action.nodeId).ping(action.dst, ctx);
        break;
      case "dhcp-renew":
        ctx.trace("action", "sys", `[사용자] DHCP 다시 요청`, { ...action });
        this.getHost(action.nodeId).renewDhcp(ctx);
        break;
    }
  }

  private ctx(nodeId: string): NodeContext {
    const now = this.now;
    return {
      now,
      send: (port, frame) => this.send(nodeId, port, frame),
      isPortConnected: (port) => this.portMap.has(epKey({ node: nodeId, port })),
      timer: (delay, tag, data): TimerHandle => {
        const ev: SimEvent = { type: "timer", nodeId, tag, data, cancelled: false };
        this.sched.push(now + delay, ev);
        return { cancel: () => void ((ev as { cancelled: boolean }).cancelled = true) };
      },
      trace: (kind, layer, summary, details, packetId) => this.pushTrace(nodeId, kind, layer, summary, details, packetId),
      nextPacketId: () => ++this.packetSeq,
    };
  }

  private send(nodeId: string, port: number, frame: EthernetFrame): void {
    const from = { node: nodeId, port };
    const conn = this.portMap.get(epKey(from));
    if (!conn) {
      this.pushTrace(nodeId, "link.unconnected", "L1", `port ${port} 에 연결된 케이블 없음 → 송신 실패`, { port }, frame.id);
      return;
    }
    const tx: Transmission = {
      id: ++this.txSeq,
      linkId: conn.link.id,
      from,
      to: conn.other,
      departAt: this.now,
      arriveAt: this.now + conn.link.latency,
      frame,
    };
    this.transmissions.push(tx);
    this.pushTrace(
      nodeId,
      "link.transmit",
      "L1",
      `링크 전송: ${describeFrame(frame)} ${nodeId}:${port} → ${conn.other.node}:${conn.other.port} (${conn.link.latency}ms)`,
      { linkId: conn.link.id, arriveAt: tx.arriveAt },
      frame.id,
    );
    this.sched.push(tx.arriveAt, { type: "deliver", tx });
  }

  private pushTrace(nodeId: string, kind: TraceKind, layer: Layer, summary: string, details?: Record<string, unknown>, packetId?: number): void {
    const ev: TraceEvent = { seq: this.traceSeq++, time: this.now, nodeId, kind, layer, summary };
    if (details) ev.details = details;
    if (packetId !== undefined) ev.packetId = packetId;
    this.trace.push(ev);
  }
}

function epKey(ep: Endpoint): string {
  return `${ep.node}:${ep.port}`;
}
