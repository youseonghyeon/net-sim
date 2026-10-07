import type { Ip } from "./addr";
import { describeFrame, type EthernetFrame, type Layer } from "./packet";
import { Scheduler } from "./scheduler";
import type { TraceEvent, TraceKind } from "./trace";
import { Host } from "./nodes/host";
import { Internet } from "./nodes/internet";
import { L3Node } from "./nodes/l3";
import { Router } from "./nodes/router";
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
  /** 0~1. 프레임마다 이 확률로 손실 (결정론적 난수) */
  lossRate: number;
  /** 다음 프레임 1개를 손실시킨다 (사용자 실험용) */
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
  /** 도착 전에 링크가 끊기거나 손실로 손실됨 */
  lost?: boolean;
  /** 손실된 경우 화면에서 사라지는 시각 */
  lostAt?: number;
  /** 장치 제거 직전에 보낸 프레임: 케이블이 빠져도 배달 (정상 종료 메시지) */
  graceful?: boolean;
}

/** 사용자 동작. 직렬화 가능한 형태 */
export type ActionSpec =
  /** count > 1 이면 반복 ping (ping -c N: 1초 간격, 끝나면 통계). 없으면 한 번 */
  | { kind: "ping"; nodeId: string; dst: Ip; count?: number }
  /** 경로 추적: TTL 을 1 부터 늘려 가며 각 홉의 Time Exceeded 로 라우터 목록을 얻는다. dst 는 IP 또는 이름 */
  | { kind: "traceroute"; nodeId: string; dst: string }
  /** nslookup: 캐시를 거치지 않고 DNS 서버에 그 이름의 A·AAAA 를 묻는다. server 가 있으면 그 서버에, 없으면 설정된 DNS 에 */
  | { kind: "dns-lookup"; nodeId: string; name: string; qtype: "A" | "AAAA"; server?: Ip }
  | { kind: "dhcp-renew"; nodeId: string }
  | { kind: "tcp-connect"; nodeId: string; dst: Ip; port: number }
  /** 원격 접속 VPN 다시 연결 (실패했거나 서버가 다시 켜졌을 때) */
  | { kind: "ra-reconnect"; nodeId: string }
  /** IPsec 상대 확인 (DPD, 빈 INFORMATIONAL): 게이트웨이·NAT 박스면 사이트 간 VPN 의 상대, 호스트면 원격 접속 서버 */
  | { kind: "vpn-dpd"; nodeId: string }
  /** 열린 TCP 연결을 사용자가 닫는다 (SSH "연결 해제"). conn 은 TcpConn.id */
  | { kind: "tcp-close"; nodeId: string; conn: string }
  /** 멀티캐스트 그룹 가입·탈퇴(IGMP)·스트림 송출 (IPTV 흉내) */
  | { kind: "mcast-join"; nodeId: string; group: Ip }
  | { kind: "mcast-leave"; nodeId: string; group: Ip }
  | { kind: "mcast-send"; nodeId: string; group: Ip }
  /** 인터넷 전화: 그 사용자에게 전화 걸기 */
  | { kind: "sip-call"; nodeId: string; to: string }
  /** 인터넷 노드의 "저편 클라이언트" 가 공인 주소 dst:port 로 TCP 연결 (포트 포워딩 시연) */
  | { kind: "inet-connect"; nodeId: string; dst: Ip; port: number }
  /** GoodCloud: 관리자가 클라우드 화면에서 그 공유기(MAC)를 엶 */
  | { kind: "cloud-manage"; nodeId: string; device: string }
  /** P2P 앱으로 이름이 peer 인 상대와 연결 (STUN → 시그널링 → 홀 펀칭 → 안 되면 TURN) */
  | { kind: "p2p-connect"; nodeId: string; peer: string }
  /** 인터넷 노드: ISP 가 그 공인 주소를 쓰는 고객에게 다른 주소를 주게 한다 (FORCERENEW) */
  | { kind: "isp-renumber"; nodeId: string; ip: Ip };

/** 링크에 실린 프레임 한 번 (로그에서 "그때 그 프레임" 을 찾기 위해 보관) */
export interface FrameSighting {
  from: string;
  to: string;
  departAt: number;
  arriveAt: number;
  frame: EthernetFrame;
  /** 다른 프레임을 처리하다 새로 만든 프레임이면 그 원래 프레임 id (라우터·NAT 는 홉마다 새 L2 프레임을 만든다) */
  cause?: number;
}

/** 보관하는 프레임 id 수 상한 (오래된 것부터 버린다) */
const FRAME_LOG_CAP = 20_000;

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
  /** 배경 타이머: 다음 일반 이벤트(또는 runUntil 의 끝)까지 시간이 지나갈 때만 발화한다. 시계를 스스로 움직이지 않는다 */
  private readonly bg = new Scheduler<SimEvent>();
  /** 장치별 걸려 있는 타이머 (장치를 지울 때 취소) */
  private readonly timersOf = new Map<string, Set<SimEvent>>();
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
    // 남은 타이머는 버린다 (되돌리기로 같은 id 의 새 장치가 생겨도 옛 타이머가 발동하지 않게)
    for (const ev of this.timersOf.get(id) ?? []) (ev as { cancelled: boolean }).cancelled = true;
    this.timersOf.delete(id);
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
        this.pushTrace(tx.from.node, "link.lost", "L1", `케이블이 빠져 전송 중이던 ${describeFrame(tx.frame)} 손실`, { linkId }, tx.frame.id);
      }
    }
    // 링크 다운을 알아챈 장치가 곧바로 다른 포트로 보내는 알림(이중화의 물러남 광고 등)은, 같은 순간 그 케이블까지 빠져도 나간 것으로 본다
    const before = this.transmissions.length;
    for (const ep of [link.a, link.b]) {
      const node = this.nodes.get(ep.node);
      node?.onLink?.(ep.port, false, this.ctx(ep.node));
    }
    for (const tx of this.transmissions.slice(before)) tx.graceful = true;
  }

  hasNode(id: string): boolean {
    return this.nodes.has(id);
  }

  setLinkLoss(linkId: string, lossRate: number): void {
    const link = this.links.get(linkId);
    if (link) link.lossRate = Math.min(1, Math.max(0, lossRate));
  }

  /** 다음에 이 링크를 지나는 프레임 1개를 손실시킨다 */
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

  /** 다음 배경 타이머 시각 (취소·고아 제외) */
  peekBackgroundTime(): number | undefined {
    for (;;) {
      const head = this.bg.peek();
      if (!head) return undefined;
      const p = head.payload;
      if (p.type === "timer" && (p.cancelled || !this.nodes.has(p.nodeId))) {
        this.bg.pop();
        continue;
      }
      return head.time;
    }
  }

  /** 실제로 처리될 이벤트 수 (취소·고아 타이머, 손실 배달 제외) */
  get pendingEvents(): number {
    this.peekNextTime();
    return this.sched.count((p) => {
      if (p.type === "timer") return !p.cancelled && this.nodes.has(p.nodeId);
      if (p.type === "deliver") return !p.tx.lost;
      return true;
    });
  }

  /** 이벤트 하나 처리 (그보다 이른 배경 타이머가 있으면 그것 먼저). 일반 이벤트가 없으면(조용함) false — 배경 타이머만으로는 시계가 가지 않는다 */
  step(): boolean {
    const next = this.peekNextTime();
    if (next === undefined) return false;
    return this.stepUntil(next);
  }

  /**
   * limit 이하에서 가장 이른 이벤트 하나를 처리한다. 배경 타이머와 일반 이벤트가 같은 시각이면 일반 이벤트 먼저
   * (그 순간 도착한 광고가 Master_Down 보다 앞선다). 처리한 게 없으면 false
   */
  stepUntil(limit: number): boolean {
    const next = this.peekNextTime();
    const bg = this.peekBackgroundTime();
    if (bg !== undefined && bg <= limit && (next === undefined || bg < next)) {
      const item = this.bg.pop()!;
      this.now = item.time;
      this.eventCount++;
      const ev = item.payload as Extract<SimEvent, { type: "timer" }>;
      this.timersOf.get(ev.nodeId)?.delete(ev);
      const node = this.nodes.get(ev.nodeId);
      node?.onTimer(ev.tag, ev.data, this.ctx(ev.nodeId));
      return true;
    }
    if (next === undefined || next > limit) return false;
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
        this.receiving = ev.tx.frame.id;
        try {
          node.receive(ev.tx.to.port, ev.tx.frame, this.ctx(node.id));
        } finally {
          this.receiving = undefined;
        }
        break;
      }
      case "timer": {
        this.timersOf.get(ev.nodeId)?.delete(ev);
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

  /** time 이하의 이벤트(배경 타이머 포함 — 그만큼 시간이 지나가므로)를 모두 처리하고 now 를 time 으로 맞춘다 */
  runUntil(time: number, maxEvents = Infinity): number {
    let n = 0;
    while (this.stepUntil(time)) {
      if (++n >= maxEvents) throw new Error(`runUntil: exceeded ${maxEvents} events`);
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

  /** 지정 시각에 링크 위에 있는 프레임 (손실 중인 것은 사라지는 시각까지 포함) */
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
      case "ping": {
        const count = Host.pingCount(action.count);
        ctx.trace("action", "sys", `[사용자] ping ${count > 1 ? `-c ${count} ` : ""}${action.dst}`, { ...action });
        this.getHost(action.nodeId).ping(action.dst, ctx, action.count);
        break;
      }
      case "traceroute":
        ctx.trace("action", "sys", `[사용자] traceroute ${action.dst}`, { ...action });
        this.getHost(action.nodeId).traceroute(action.dst, ctx);
        break;
      case "dns-lookup":
        ctx.trace("action", "sys", `[사용자] nslookup${action.qtype === "AAAA" ? " -type=AAAA" : ""} ${action.name}${action.server ? ` ${action.server}` : ""}`, { ...action });
        this.getHost(action.nodeId).lookup(action.name, action.qtype, action.server, ctx);
        break;
      case "dhcp-renew":
        ctx.trace("action", "sys", `[사용자] DHCP 임대 갱신`, { ...action });
        this.getHost(action.nodeId).renewDhcp(ctx);
        break;
      case "tcp-connect":
        ctx.trace("action", "sys", `[사용자] ${action.dst}:${action.port} 에 TCP 연결`, { ...action });
        this.getHost(action.nodeId).connect(action.dst, action.port, ctx);
        break;
      case "p2p-connect":
        ctx.trace("action", "sys", `[사용자] P2P 연결 → ${action.peer}`, { ...action });
        this.getHost(action.nodeId).p2p.connect(action.peer, ctx);
        break;
      case "ra-reconnect":
        ctx.trace("action", "sys", `[사용자] ${node instanceof Router ? "VPN 클라이언트" : "원격 접속 VPN"} 다시 연결`, { ...action });
        if (node instanceof Router) node.wgReconnect(ctx);
        else this.getHost(action.nodeId).ra.reconnect(ctx);
        break;
      case "vpn-dpd":
        ctx.trace("action", "sys", `[사용자] VPN 상대 확인 (DPD)`, { ...action });
        if (node instanceof L3Node) node.vpn.dpd(ctx);
        else this.getHost(action.nodeId).ra.dpd(ctx);
        break;
      case "sip-call":
        ctx.trace("action", "sys", `[사용자] 인터넷 전화로 ${action.to} 에게 전화`, { ...action });
        this.getHost(action.nodeId).sip.call(action.to, ctx);
        break;
      case "mcast-join":
        ctx.trace("action", "sys", `[사용자] 멀티캐스트 그룹 ${action.group} 가입`, { ...action });
        this.getHost(action.nodeId).joinGroup(action.group, ctx);
        break;
      case "mcast-leave":
        ctx.trace("action", "sys", `[사용자] 멀티캐스트 그룹 ${action.group} 탈퇴`, { ...action });
        this.getHost(action.nodeId).leaveGroup(action.group, ctx);
        break;
      case "mcast-send":
        ctx.trace("action", "sys", `[사용자] 멀티캐스트 그룹 ${action.group} 로 스트림 송출`, { ...action });
        this.getHost(action.nodeId).sendStream(action.group, ctx);
        break;
      case "tcp-close":
        ctx.trace("action", "sys", `[사용자] 연결 해제 ${action.conn.split("-")[1] ?? action.conn}`, { ...action });
        if (!(node instanceof Internet ? node.tcp : this.getHost(action.nodeId).tcp).disconnect(action.conn, ctx)) ctx.trace("tcp.ignore", "L4", `닫을 연결이 없음 (이미 끝났거나 연결 중이 아님)`, { conn: action.conn });
        break;
      case "isp-renumber":
        if (!(node instanceof Internet)) throw new Error(`${action.nodeId} is not an internet node`);
        ctx.trace("action", "sys", `[사용자] ISP 가 ${action.ip} 고객의 공인 주소를 바꿈`, { ...action });
        node.renumber(action.ip, ctx);
        break;
      case "cloud-manage":
        if (!(node instanceof Internet)) throw new Error(`${action.nodeId} is not an internet node`);
        ctx.trace("action", "sys", `[사용자] GoodCloud 관리 화면에서 기기 ${action.device} 를 엶`, { ...action });
        node.cloudManage(action.device, ctx);
        break;
      case "inet-connect":
        if (!(node instanceof Internet)) throw new Error(`${action.nodeId} is not an internet node`);
        ctx.trace("action", "sys", `[사용자] 인터넷에서 ${action.dst}:${action.port} 로 접속 시도`, { ...action });
        node.connectFrom(action.dst, action.port, ctx);
        break;
    }
  }

  private ctx(nodeId: string): NodeContext {
    // now 는 읽을 때의 시각: 콜백(DNS 응답을 기다린 뒤 등)이 앞선 이벤트의 ctx 를 들고 있어도 타이머·RTT 가 과거 기준이 되지 않게
    const net = this;
    return {
      get now() {
        return net.now;
      },
      send: (port, frame) => this.send(nodeId, port, frame),
      isPortConnected: (port) => this.portMap.has(epKey({ node: nodeId, port })),
      timer: (delay, tag, data, background): TimerHandle => {
        const ev: SimEvent = { type: "timer", nodeId, tag, data, cancelled: false };
        (background ? this.bg : this.sched).push(this.now + delay, ev);
        let set = this.timersOf.get(nodeId);
        if (!set) this.timersOf.set(nodeId, (set = new Set()));
        set.add(ev);
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
      this.pushTrace(nodeId, "link.unconnected", "L1", `port ${port} 에 연결된 링크 다운 → 송신 실패`, { port }, frame.id);
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
    this.recordFrame({ from: nodeId, to: conn.other.node, departAt: tx.departAt, arriveAt: tx.arriveAt, frame, ...(this.receiving !== undefined && this.receiving !== frame.id ? { cause: this.receiving } : {}) });
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
      const why = link.dropNext ? "사용자가 손실시킴" : `손실률 ${Math.round(link.lossRate * 100)}%`;
      link.dropNext = false;
      tx.lost = true;
      tx.lostAt = this.now + link.latency * 0.55;
      this.pushTrace(nodeId, "link.loss", "L1", `케이블에서 ${describeFrame(frame)} 손실 (${why}) — 상대는 받지 못한다`, { linkId: link.id }, frame.id);
      return;
    }
    this.sched.push(tx.arriveAt, { type: "deliver", tx });
  }

  /** 프레임 id → 링크에 실린 기록들 (오래된 id 부터 버린다) */
  readonly frameLog = new Map<number, FrameSighting[]>();

  /**
   * 지금 처리 중인(받는 중인) 프레임 id: 이 동안 새로 만든 프레임은 그 "원인" 으로 이어 둔다.
   * ARP 응답을 기다렸다 나중에 보내는 패킷은 이어지지 않는다 (그때는 받은 프레임만 보인다)
   */
  private receiving: number | undefined;

  private recordFrame(s: FrameSighting): void {
    const push = (id: number) => {
      const list = this.frameLog.get(id);
      if (list) list.push(s);
      else {
        this.frameLog.set(id, [s]);
        if (this.frameLog.size > FRAME_LOG_CAP) this.frameLog.delete(this.frameLog.keys().next().value!);
      }
    };
    push(s.frame.id);
    if (s.cause !== undefined) push(s.cause); // 원래 프레임의 기록에도: "이 장치가 이걸 받고 내보낸 것"
  }

  /**
   * 로그 한 줄(장치 nodeId, 시각 time)이 가리키는 프레임: 그 장치가 받은 것(time 이전에 도착한 마지막)과
   * 그 장치가 내보낸 것(time 이후 처음). NAT·TTL 감소·VLAN 태그처럼 장치를 지나며 바뀐 내용을 둘 다 볼 수 있다
   */
  framesAt(packetId: number, nodeId: string, time: number): { received?: EthernetFrame; sent?: EthernetFrame } {
    const list = this.frameLog.get(packetId) ?? [];
    const received = list.filter((s) => s.to === nodeId && s.arriveAt <= time && s.frame.id === packetId).at(-1)?.frame;
    const sent = list.find((s) => s.from === nodeId && s.departAt >= time)?.frame;
    return { received, sent };
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
