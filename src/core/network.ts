import type { Ip } from "./addr";
import { describeFrame, type EthernetFrame, type Layer } from "./packet";
import { Scheduler } from "./scheduler";
import type { TraceEvent, TraceKind } from "./trace";
import { Host } from "./nodes/host";
import { Internet } from "./nodes/internet";
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
  /** 0~1. 프레임마다 이 확률로 유실 (결정론적 난수) */
  lossRate: number;
  /** 다음 프레임 1개를 유실시킨다 (사용자 실험용) */
  dropNext: boolean;
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
  /** 도착 전에 링크가 끊기거나 손실로 유실됨 */
  lost?: boolean;
  /** 유실된 경우 화면에서 사라지는 시각 */
  lostAt?: number;
  /** 장치 제거 직전에 보낸 프레임: 케이블이 빠져도 배달 (정상 종료 메시지) */
  graceful?: boolean;
}

/** 사용자 동작. 직렬화 가능한 형태 */
export type ActionSpec =
  | { kind: "ping"; nodeId: string; dst: Ip }
  | { kind: "dhcp-renew"; nodeId: string }
  | { kind: "tcp-connect"; nodeId: string; dst: Ip; port: number }
  /** 인터넷 노드의 "저편 클라이언트" 가 공인 주소 dst:port 로 TCP 연결 (포트 포워딩 시연) */
  | { kind: "inet-connect"; nodeId: string; dst: Ip; port: number };

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
  private rng = 0x2545f491;

  // ---------- 구성 (실행 중에도 변경 가능) ----------

  addNode<T extends SimNode>(node: T): T {
    if (this.nodes.has(node.id)) throw new Error(`duplicate node id: ${node.id}`);
    this.nodes.set(node.id, node);
    return node;
  }

  removeNode(id: string): void {
    const node = this.nodes.get(id);
    if (!node) return;
    const before = this.transmissions.length;
    node.onRemove?.(this.ctx(id));
    for (const tx of this.transmissions.slice(before)) if (tx.from.node === id) tx.graceful = true;
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
    const link: Link = { id: id ?? `link${++this.linkSeq}`, a, b, latency, lossRate: 0, dropNext: false };
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
      if (tx.linkId === linkId && !tx.lost && !tx.graceful && tx.arriveAt > this.now) {
        tx.lost = true;
        tx.lostAt = this.now;
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

  setLinkLoss(linkId: string, lossRate: number): void {
    const link = this.links.get(linkId);
    if (link) link.lossRate = Math.min(1, Math.max(0, lossRate));
  }

  /** 다음에 이 링크를 지나는 프레임 1개를 유실시킨다 */
  dropNextOn(linkId: string): void {
    const link = this.links.get(linkId);
    if (link) link.dropNext = true;
  }

  /** 결정론적 [0,1) 난수 (xorshift) */
  private random(): number {
    let x = this.rng;
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    this.rng = x >>> 0;
    return this.rng / 0x100000000;
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

  /** 취소됐거나 주인이 사라진 타이머를 건너뛰고 다음 이벤트 시각 */
  peekNextTime(): number | undefined {
    for (;;) {
      const head = this.sched.peek();
      if (!head) return undefined;
      const p = head.payload;
      if (p.type === "timer" && (p.cancelled || !this.nodes.has(p.nodeId))) {
        this.sched.pop();
        continue;
      }
      if (p.type === "deliver" && p.tx.lost) {
        this.sched.pop();
        continue;
      }
      return head.time;
    }
  }

  /** 실제로 처리될 이벤트 수 (취소·고아 타이머, 유실 배달 제외) */
  get pendingEvents(): number {
    this.peekNextTime();
    return this.sched.count((p) => {
      if (p.type === "timer") return !p.cancelled && this.nodes.has(p.nodeId);
      if (p.type === "deliver") return !p.tx.lost;
      return true;
    });
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
        if (!node || (!this.links.has(ev.tx.linkId) && !ev.tx.graceful)) {
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

  /** 지정 시각에 링크 위에 있는 프레임 (유실 중인 것은 사라지는 시각까지 포함) */
  inFlight(at = this.now): Transmission[] {
    return this.transmissions.filter((t) => t.departAt <= at && at < (t.lost ? (t.lostAt ?? t.departAt) : t.arriveAt));
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
      case "tcp-connect":
        ctx.trace("action", "sys", `[사용자] ${action.dst}:${action.port} 에 TCP 연결`, { ...action });
        this.getHost(action.nodeId).connect(action.dst, action.port, ctx);
        break;
      case "inet-connect":
        if (!(node instanceof Internet)) throw new Error(`${action.nodeId} is not an internet node`);
        ctx.trace("action", "sys", `[사용자] 인터넷에서 ${action.dst}:${action.port} 로 접속 시도`, { ...action });
        node.connectFrom(action.dst, action.port, ctx);
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
    const link = conn.link;
    if (link.dropNext || (link.lossRate > 0 && this.random() < link.lossRate)) {
      const why = link.dropNext ? "사용자가 유실시킴" : `손실률 ${Math.round(link.lossRate * 100)}%`;
      link.dropNext = false;
      tx.lost = true;
      tx.lostAt = this.now + link.latency * 0.55;
      this.pushTrace(nodeId, "link.loss", "L1", `케이블에서 ${describeFrame(frame)} 유실 (${why}) — 상대는 받지 못한다`, { linkId: link.id }, frame.id);
      return;
    }
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
