// Tor (양파 라우팅 — GL.iNet 의 Tor 앱): 공유기가 LAN 의 TCP·DNS 를 세 릴레이(가드 → 중간 → 출구)를 거치는 회로로 보낸다.
// - 공유기는 패킷을 세 릴레이의 키로 세 겹 감싼다. 릴레이마다 한 겹씩 벗겨, 가드는 "누가 보냈는지" 만, 출구는 "어디로 가는지" 만 안다
// - 목적지는 출구 릴레이의 주소(198.51.100.133)에서 온 연결로 본다 — 내 공인 주소는 숨는다
// - Tor 는 TCP 스트림만 나른다(DNS 는 출구가 대신 풀어 줌). ping(ICMP)·그 밖의 UDP 는 나르지 못해 공유기가 버린다 (새지 않게)
// 줄인 것: TLS·셀 분할·회로 다시 만들기·디렉터리·가드 고르기·.onion 서비스, 여기서는 회로 하나를 계속 쓰고 IP 패킷째 나른다
import type { Ip } from "../addr";
import { TOR_EXIT, TOR_GUARD, TOR_MIDDLE, TOR_PORT, type Endpoint, type Ipv4Packet, type TorCell } from "../packet";
import type { NodeContext } from "./node";

export const TOR_TIMER_TAG = "tor";
const WAIT = 1500;
const QUEUE = 32;

export interface TorIo {
  wanIp(): Ip | undefined;
  /** 공유기 자신의 바깥 패킷 (NAT 하지 않음) */
  send(pkt: Ipv4Packet, ctx: NodeContext): void;
}

export class TorClient {
  enabled = false;
  circ: number | undefined;
  private building = false;
  private tries = 0;
  private tok = 0;
  private queue: Ipv4Packet[] = [];
  private nextCirc: number;
  sent = 0;
  received = 0;

  constructor(
    private readonly io: TorIo,
    seed: number,
    /** 가드로 보낼 때 쓰는 내 포트 */
    readonly port: number,
  ) {
    this.nextCirc = (Math.abs(seed) % 0x7fff) + 1;
  }

  get up(): boolean {
    return this.enabled && this.circ !== undefined;
  }

  setEnabled(on: boolean, ctx: NodeContext): void {
    if (on === this.enabled) return;
    this.enabled = on;
    this.tok++;
    this.queue = [];
    if (!on) {
      if (this.circ !== undefined) this.toGuard({ kind: "tor", op: "destroy", circ: this.circ, layers: 0 }, ctx);
      this.circ = undefined;
      this.building = false;
      ctx.trace("ip.config", "sys", "Tor 꺼짐 — LAN 기기는 평소처럼 공유기 공인 주소로 나간다", { tor: false });
      return;
    }
    ctx.trace("ip.config", "sys", "Tor 켜짐: LAN 의 TCP·DNS 를 Tor 회로(가드 → 중간 → 출구)로 보내고, 나머지(ping·UDP)는 버린다 (Tor 밖으로 새지 않게)", { tor: true });
    this.build(ctx);
  }

  /** WAN 주소를 얻거나 바뀜: 회로를 다시 만든다 */
  onWanAddress(ctx: NodeContext): void {
    if (!this.enabled || !this.io.wanIp()) return;
    this.circ = undefined;
    this.building = false;
    this.build(ctx);
  }

  private toGuard(m: TorCell, ctx: NodeContext): void {
    const me = this.io.wanIp();
    if (!me) return;
    this.io.send({ kind: "ipv4", src: me, dst: TOR_GUARD, ttl: 64, payload: { kind: "udp", srcPort: this.port, dstPort: TOR_PORT, payload: m } }, ctx);
  }

  private build(ctx: NodeContext): void {
    if (this.building || !this.io.wanIp()) return;
    this.building = true;
    this.tries = 1;
    const circ = this.nextCirc++;
    const tok = ++this.tok;
    ctx.trace("tor.circuit", "app", `Tor: 회로 만들기 — 가드 ${TOR_GUARD} 에 CREATE (가드를 거쳐 중간 ${TOR_MIDDLE}, 출구 ${TOR_EXIT} 까지 늘린다 — 릴레이마다 따로 키를 나눈다)`, { tor: true, circ });
    this.toGuard({ kind: "tor", op: "create", circ, layers: 0 }, ctx);
    ctx.timer(WAIT, TOR_TIMER_TAG, { tor: "create", tok, circ });
  }

  /**
   * LAN 에서 인터넷으로 가는 패킷: TCP·DNS 면 회로로 (회로가 아직이면 기다림), 나머지는 버린다. 처리했으면 true (늘 true — Tor 를 켜면 밖으로 바로 나가지 않는다)
   */
  sendInner(pkt: Ipv4Packet, ctx: NodeContext, frameId?: number): boolean {
    const p = pkt.payload;
    const dns = p.kind === "udp" && p.dstPort === 53;
    if (p.kind !== "tcp" && !dns) {
      ctx.trace("tor.drop", "L3", `Tor: ${pkt.src} → ${pkt.dst} 의 ${p.kind === "icmp" ? "ICMP(ping)" : p.kind === "udp" ? `UDP ${p.dstPort}` : p.kind} 는 Tor 가 나르지 못함 (TCP 스트림·DNS 만) → 버림 — Tor 밖으로 내보내면 실제 주소가 드러난다`, { tor: true, dst: pkt.dst }, frameId);
      return true;
    }
    if (this.circ === undefined) {
      if (this.queue.length < QUEUE) this.queue.push(pkt);
      if (this.queue.length === 1) ctx.trace("tor.circuit", "app", `Tor: 회로가 아직 없어 ${pkt.dst} 로 가는 패킷을 기다리게 함 (회로가 서면 보냄)`, { tor: true }, frameId);
      this.build(ctx);
      return true;
    }
    this.sent++;
    ctx.trace("tor.relay", "L3", `Tor: ${pkt.src} → ${pkt.dst}${p.kind === "tcp" ? `:${p.dstPort}` : " (DNS)"} 를 출구·중간·가드 키로 세 겹 감싸 가드 ${TOR_GUARD} 로 (가드는 나를 알지만 목적지는 모른다)`, { tor: true, dst: pkt.dst }, frameId);
    this.toGuard({ kind: "tor", op: "data", circ: this.circ, layers: 3, inner: pkt }, ctx);
    return true;
  }

  /** 가드에게서 온 셀 (내 포트). 풀린 패킷이면 돌려준다 */
  handle(pkt: Ipv4Packet, m: TorCell, ctx: NodeContext, frameId: number): Ipv4Packet | null {
    if (!this.enabled || pkt.src !== TOR_GUARD) return null;
    if (m.op === "created") {
      if (this.circ !== undefined && this.circ === m.circ) return null;
      this.circ = m.circ;
      this.building = false;
      ctx.trace("tor.circuit", "app", `Tor: 회로 ${m.circ} 이 섬 (가드 → 중간 → 출구 ${TOR_EXIT}) — 이제 목적지는 출구 주소에서 온 연결로 본다${this.queue.length ? `, 기다리던 ${this.queue.length}개를 보냄` : ""}`, { tor: true, circ: m.circ }, frameId);
      const q = this.queue;
      this.queue = [];
      for (const x of q) this.sendInner(x, ctx);
      return null;
    }
    if (m.op === "destroy") {
      this.circ = undefined;
      ctx.trace("tor.circuit", "app", `Tor: 회로가 닫힘 → 다음 패킷에 다시 만든다`, { tor: true }, frameId);
      return null;
    }
    if (m.op === "data" && m.inner && m.circ === this.circ) {
      this.received++;
      ctx.trace("tor.relay", "L3", `Tor: 회로로 돌아온 응답 — 세 겹을 벗겨 ${m.inner.src} → ${m.inner.dst}`, { tor: true }, frameId);
      return m.inner;
    }
    return null;
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const d = data as { tor?: string; tok?: number; circ?: number };
    if (d.tok !== this.tok || !this.enabled || this.circ !== undefined) return;
    if (this.tries > 2) {
      this.building = false;
      ctx.trace("tor.drop", "app", `Tor: 가드 ${TOR_GUARD} 응답 없음 (3번) — 회로를 만들지 못함. 기다리던 ${this.queue.length}개를 버림 (Tor 를 막는 망이면 브리지가 필요)`, { tor: true, failed: true });
      this.queue = [];
      return;
    }
    this.tries++;
    this.toGuard({ kind: "tor", op: "create", circ: d.circ!, layers: 0 }, ctx);
    ctx.timer(WAIT, TOR_TIMER_TAG, { tor: "create", tok: d.tok, circ: d.circ });
  }

  summary(): string | undefined {
    if (!this.enabled) return undefined;
    return this.circ !== undefined ? `회로 ${this.circ} · 출구 ${TOR_EXIT} · 보냄 ${this.sent} · 받음 ${this.received}` : "회로 만드는 중";
  }
}

// ---------- Tor 네트워크 (인터넷 노드가 세 릴레이를 흉내) ----------

interface ExitFlow {
  /** 셀을 돌려보낼 공유기 (가드가 본 주소) */
  client: Endpoint;
  circ: number;
  src: Ip;
  sport: number;
}

export class TorNetwork {
  /** 출구가 연 흐름: "proto:출구 포트" → 원래 보낸 곳 */
  private readonly flows = new Map<string, ExitFlow>();
  private readonly byInner = new Map<string, number>();
  private nextPort = 30000;
  private nextCirc = 1;
  readonly circuits = new Map<number, Endpoint>();

  constructor(
    private readonly io: {
      /** 가드가 공유기에게 셀을 보낸다 */
      toClient(to: Endpoint, m: TorCell, ctx: NodeContext): void;
      /** 출구가 목적지로 보낸다 (인터넷 노드가 그 패킷을 받은 것처럼 처리) */
      deliver(pkt: Ipv4Packet, ctx: NodeContext, frameId: number): void;
    },
  ) {}

  handle(pkt: Ipv4Packet, srcPort: number, m: TorCell, ctx: NodeContext, frameId: number): void {
    const from: Endpoint = { ip: pkt.src, port: srcPort };
    if (m.op === "create") {
      const circ = m.circ || this.nextCirc++;
      this.circuits.set(circ, from);
      ctx.trace("tor.relay", "app", `Tor 가드 ${TOR_GUARD}: ${from.ip} 의 CREATE → 중간 ${TOR_MIDDLE} 로 EXTEND → 출구 ${TOR_EXIT} 로 EXTEND → 회로 ${circ} (가드는 보낸 사람 ${from.ip} 를 안다, 중간은 가드·출구만, 출구는 보낸 사람을 모른다)`, { circ }, frameId);
      this.io.toClient(from, { kind: "tor", op: "created", circ, layers: 0 }, ctx);
      return;
    }
    if (m.op === "destroy") {
      this.circuits.delete(m.circ);
      return;
    }
    if (m.op !== "data" || !m.inner) return;
    if (!this.circuits.has(m.circ)) {
      ctx.trace("tor.relay", "app", `Tor 가드: 모르는 회로 ${m.circ} → DESTROY`, { circ: m.circ }, frameId);
      this.io.toClient(from, { kind: "tor", op: "destroy", circ: m.circ, layers: 0 }, ctx);
      return;
    }
    this.circuits.set(m.circ, from);
    const inner = m.inner;
    const p = inner.payload;
    if (p.kind !== "tcp" && p.kind !== "udp") return;
    ctx.trace("tor.relay", "app", `Tor: 가드 ${TOR_GUARD} 가 한 겹 벗김 (보낸 곳 ${from.ip} — 안은 여전히 암호) → 중간 ${TOR_MIDDLE} 가 한 겹 → 출구 ${TOR_EXIT} 가 마지막 겹을 벗겨 목적지 ${inner.dst}:${p.dstPort} 를 봄 (누가 보냈는지는 모름)`, { circ: m.circ }, frameId);
    const innerKey = `${p.kind}:${m.circ}:${inner.src}:${p.srcPort}:${inner.dst}:${p.dstPort}`;
    let port = this.byInner.get(innerKey);
    if (port === undefined) {
      port = this.nextPort++;
      if (this.nextPort > 60000) this.nextPort = 30000;
      this.byInner.set(innerKey, port);
      this.flows.set(`${p.kind}:${port}`, { client: from, circ: m.circ, src: inner.src, sport: p.srcPort });
    }
    const out: Ipv4Packet = { ...inner, src: TOR_EXIT, ttl: 60, payload: { ...p, srcPort: port } } as Ipv4Packet;
    this.io.deliver(out, ctx, frameId);
  }

  /** 출구 주소로 온 응답: 원래 흐름을 찾아 세 겹 감싸 공유기로 돌려보낸다. 처리했으면 true */
  back(pkt: Ipv4Packet, ctx: NodeContext): boolean {
    if (pkt.dst !== TOR_EXIT) return false;
    const p = pkt.payload;
    if (p.kind !== "tcp" && p.kind !== "udp") {
      ctx.trace("tor.relay", "app", `Tor 출구: ${pkt.src} 의 ${p.kind} → 회로로 나르지 않음`, {});
      return true;
    }
    const f = this.flows.get(`${p.kind}:${p.dstPort}`);
    if (!f) {
      ctx.trace("tor.relay", "app", `Tor 출구: 모르는 흐름 (${p.kind.toUpperCase()} ${p.dstPort}) → 버림`, {});
      return true;
    }
    const inner: Ipv4Packet = { ...pkt, dst: f.src, payload: { ...p, dstPort: f.sport } } as Ipv4Packet;
    ctx.trace("tor.relay", "app", `Tor 출구 ${TOR_EXIT}: ${pkt.src} 의 응답을 출구 키로 감쌈 → 중간 → 가드가 한 겹씩 더 감싸 ${f.client.ip} 로`, { circ: f.circ });
    this.io.toClient(f.client, { kind: "tor", op: "data", circ: f.circ, layers: 3, inner }, ctx);
    return true;
  }
}
