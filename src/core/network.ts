import type { Ip } from "./addr";
import { describeFrame, type EthernetFrame, type Layer } from "./packet";
import { Scheduler } from "./scheduler";
import type { TraceEvent, TraceKind } from "./trace";
import { Host } from "./nodes/host";
import type { NodeContext, SimNode } from "./nodes/node";

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

/** 링크 위를 이동 중인(또는 이동했던) 프레임. UI 애니메이션의 근거 */
export interface Transmission {
  id: number;
  linkId: string;
  from: Endpoint;
  to: Endpoint;
  departAt: number;
  arriveAt: number;
  frame: EthernetFrame;
}

/** 사용자 동작. 재생(rewind)을 위해 직렬화 가능한 형태로 기록한다 */
export type ActionSpec = { kind: "ping"; nodeId: string; dst: Ip };

export interface RecordedAction {
  time: number;
  action: ActionSpec;
}

type SimEvent =
  | { type: "deliver"; tx: Transmission }
  | { type: "timer"; nodeId: string; tag: string; data?: unknown }
  | { type: "action"; action: ActionSpec };

export class Network {
  readonly nodes = new Map<string, SimNode>();
  readonly links: Link[] = [];
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

  // ---------- 구성 ----------

  addNode<T extends SimNode>(node: T): T {
    if (this.nodes.has(node.id)) throw new Error(`duplicate node id: ${node.id}`);
    this.nodes.set(node.id, node);
    return node;
  }

  connect(aNode: string, aPort: number, bNode: string, bPort: number, latency = 10): Link {
    const a = { node: aNode, port: aPort };
    const b = { node: bNode, port: bPort };
    for (const ep of [a, b]) {
      const n = this.nodes.get(ep.node);
      if (!n) throw new Error(`unknown node: ${ep.node}`);
      if (ep.port < 0 || ep.port >= n.portCount) throw new Error(`${ep.node} has no port ${ep.port}`);
      if (this.portMap.has(epKey(ep))) throw new Error(`${ep.node}:${ep.port} already connected`);
    }
    const link: Link = { id: `${aNode}:${aPort}-${bNode}:${bPort}`, a, b, latency };
    this.links.push(link);
    this.portMap.set(epKey(a), { link, other: b });
    this.portMap.set(epKey(b), { link, other: a });
    return link;
  }

  getHost(id: string): Host {
    const n = this.nodes.get(id);
    if (!(n instanceof Host)) throw new Error(`${id} is not a host`);
    return n;
  }

  // ---------- 사용자 동작 ----------

  scheduleAction(time: number, action: ActionSpec): void {
    if (time < this.now) throw new Error(`cannot schedule action in the past (${time} < ${this.now})`);
    this.actions.push({ time, action });
    this.sched.push(time, { type: "action", action }, 1);
  }

  // ---------- 실행 ----------

  peekNextTime(): number | undefined {
    return this.sched.peek()?.time;
  }

  get pendingEvents(): number {
    return this.sched.size;
  }

  /** 이벤트 하나 처리. 처리한 게 없으면 false */
  step(): boolean {
    const item = this.sched.pop();
    if (!item) return false;
    this.now = item.time;
    this.eventCount++;
    const ev = item.payload;
    switch (ev.type) {
      case "deliver": {
        const node = this.nodes.get(ev.tx.to.node)!;
        node.receive(ev.tx.to.port, ev.tx.frame, this.ctx(node.id));
        break;
      }
      case "timer": {
        const node = this.nodes.get(ev.nodeId)!;
        node.onTimer(ev.tag, ev.data, this.ctx(node.id));
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
    while (this.sched.peek() !== undefined && this.sched.peek()!.time <= time) {
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

  /** 현재 시각(또는 지정 시각) 기준으로 링크 위에 있는 프레임 */
  inFlight(at = this.now): Transmission[] {
    return this.transmissions.filter((t) => t.departAt <= at && at < t.arriveAt);
  }

  // ---------- 내부 ----------

  private runAction(action: ActionSpec): void {
    const ctx = this.ctx(action.nodeId);
    switch (action.kind) {
      case "ping": {
        ctx.trace("action", "sys", `[사용자] ${action.nodeId} 에서 ping ${action.dst}`, { ...action });
        this.getHost(action.nodeId).ping(action.dst, ctx);
        break;
      }
    }
  }

  private ctx(nodeId: string): NodeContext {
    const now = this.now;
    return {
      now,
      send: (port, frame) => this.send(nodeId, port, frame),
      isPortConnected: (port) => this.portMap.has(epKey({ node: nodeId, port })),
      timer: (delay, tag, data) => {
        this.sched.push(now + delay, { type: "timer", nodeId, tag, data });
      },
      trace: (kind, layer, summary, details, packetId) => this.pushTrace(nodeId, kind, layer, summary, details, packetId),
      nextPacketId: () => ++this.packetSeq,
    };
  }

  private send(nodeId: string, port: number, frame: EthernetFrame): void {
    const from = { node: nodeId, port };
    const conn = this.portMap.get(epKey(from));
    if (!conn) {
      this.pushTrace(nodeId, "link.unconnected", "L1", `port ${port} 에 연결된 링크 없음 → 송신 실패`, { port }, frame.id);
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
