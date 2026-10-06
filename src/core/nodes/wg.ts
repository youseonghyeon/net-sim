// WireGuard (GL.iNet·Brume 의 VPN 서버·클라이언트, 노트북·폰의 WireGuard 앱):
//
// 공개 키가 곧 신원이다. 각자 개인 키 하나를 갖고, 상대의 공개 키·주소(엔드포인트)·AllowedIPs 를 "피어" 로 적는다.
// - 핸드셰이크 (1-RTT): 보낼 패킷이 생기면 Initiation → Response 로 세션 키를 만든다 (Noise IK). 시작한 쪽은 곧바로 keepalive 로 확인
// - 침묵: 응답자는 Initiation 을 응답자 공개 키로 확인(mac1)하고 시작한 쪽 공개 키가 피어 목록에 있어야만 답한다 — 아니면 아무 답도 하지 않는다.
//   그래서 키가 틀리면 "거절" 이 아니라 timeout 으로만 보인다 (포트 스캔에도 보이지 않는 이유)
// - cryptokey routing: 보낼 때는 목적지가 AllowedIPs 에 든 피어에게, 받을 때는 안쪽 출발지가 그 피어의 AllowedIPs 안이어야 받는다
// - 엔드포인트 로밍: 인증된 패킷의 바깥 출발지(주소·포트)를 그 피어의 새 주소로 기억한다 — 서버는 고정 주소가 필요 없고,
//   노트북이 Wi-Fi 를 바꾸거나 NAT 매핑이 바뀌어도 세션이 이어진다
// - 연결 상태가 없다: 끊는다는 메시지가 없고, 조용하면 아무것도 보내지 않는다.
//   받은 뒤 10초 동안 보낼 것이 없으면 keepalive 로 받았다고 알리고(passive keepalive), 보낸 뒤 15초 동안 받은 것이 없으면
//   새 핸드셰이크를 한다 (상대가 재시작해 세션을 잊었을 때 다시 잇는 길). 둘 다 배경 타이머라 시간이 흐를 때만 돈다
// 생략: 쿠키(부하 시 DoS 방어), 2분마다 재협상(rekey), 3분 뒤 세션 폐기, PersistentKeepalive 주기(이 시뮬레이터의 NAT 매핑은 만료되지 않는다).
// 핸드셰이크 재시도는 5초 간격 3번(실제는 90초 동안 계속) — 그 뒤 보낼 패킷이 또 생기면 다시 시도한다.
import { sameSubnet, type Ip } from "../addr";
import { VPN_PORT, type Ipv4Packet, type WgMessage } from "../packet";
import type { NodeContext } from "./node";
import { DEFAULT_RA_CLIENT, type RaClientConfig, type RaClientState } from "./ravpn";

export const WG_PORT = VPN_PORT;
export const WG_TIMER_TAG = "wg-timer";
/** 핸드셰이크 응답을 기다리는 시간 (REKEY_TIMEOUT) */
export const WG_REKEY_TIMEOUT = 5000;
/** 핸드셰이크 시도 횟수 (실제는 90초 동안 5초마다) */
export const WG_HANDSHAKE_TRIES = 3;
/** passive keepalive: 받은 뒤 이만큼 보낸 것이 없으면 keepalive (KEEPALIVE_TIMEOUT) */
export const WG_KEEPALIVE = 10_000;
/** 보낸 뒤 이만큼 받은 것이 없으면 새 핸드셰이크 (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) */
export const WG_DEAD = 15_000;
/** 핸드셰이크를 기다리며 쌓아 두는 패킷 수 */
const WG_QUEUE = 32;

// ---------- 키 ----------

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function fnv(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h || 1;
}

/** 씨앗에서 만든 32바이트를 base64 로 (44자, 실제 WireGuard 키와 같은 모양) */
function key32(seed: string): string {
  let x = fnv(seed);
  const bytes: number[] = [];
  for (let i = 0; i < 32; i++) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    bytes.push(x & 0xff);
  }
  let out = "";
  for (let i = 0; i < 30; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]! + B64[n & 63]!;
  }
  const n = (bytes[30]! << 16) | (bytes[31]! << 8);
  return out + B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]! + "=";
}

/** 개인 키 (wg genkey): 씨앗(장치 id 등)에서 결정론적으로 — 시뮬레이터 코어에는 난수가 없다 */
export function wgPrivateKey(seed: string): string {
  return key32(`wg-private:${seed}`);
}

/** 공개 키 (wg pubkey): 개인 키에서 계산된다. 실제는 Curve25519, 여기서는 해시 흉내 — 개인 키 없이는 만들 수 없다는 점만 같다 */
export function wgPublicKey(privateKey: string): string {
  return key32(`wg-public:${privateKey}`);
}

/** WireGuard 키 모양 (base64 44자, = 로 끝남) */
export function validWgKey(k: string | undefined): boolean {
  return !!k && /^[A-Za-z0-9+/]{43}=$/.test(k);
}

/** 로그용 짧은 키 (wg show 는 전체를 보이지만 로그 한 줄에는 앞부분만) */
export function shortKey(k: string): string {
  return k.length > 10 ? `${k.slice(0, 8)}…` : k;
}

// ---------- 설정·상태 ----------

export interface WgPrefix {
  dest: Ip;
  prefix: number;
}

export interface WgPeer {
  /** 화면용 이름 (GL.iNet 의 프로필 이름) */
  name?: string;
  publicKey: string;
  /** 이 피어의 주소:포트. 서버 쪽 피어는 보통 비워 둔다 — 피어가 먼저 접속하면 그 출발지를 배운다 */
  endpoint?: { ip: Ip; port: number };
  /** 이 피어에게 보낼 목적지이자 이 피어에게서 받아도 되는 출발지 (AllowedIPs) */
  allowedIps: WgPrefix[];
}

export interface WgConfig {
  enabled: boolean;
  privateKey: string;
  /** 이 터널 인터페이스(wg0)의 주소 */
  address?: { ip: Ip; prefix: number };
  listenPort: number;
  peers: WgPeer[];
}

interface Session {
  /** 내가 정한 세션 번호 (상대가 data 의 receiver 로 쓴다) */
  local: number;
  /** 상대가 정한 세션 번호 (내가 data 의 receiver 로 쓴다) */
  remote: number;
  since: number;
  counter: number;
}

export interface WgPeerState {
  cfg: WgPeer;
  endpoint?: { ip: Ip; port: number };
  session?: Session;
  /** 직전 세션: 새 세션을 맺은 직후에도 상대가 아직 옛 세션으로 보낸 데이터를 받는다 (실제 WireGuard 의 previous keypair — 양쪽이 동시에 핸드셰이크했을 때 엇갈리지 않게) */
  prevSession?: Session;
  /** 내가 시작해 응답을 기다리는 핸드셰이크 */
  pending?: { local: number; tries: number };
  queue: { inner: Ipv4Packet; frameId?: number }[];
  rxBytes: number;
  txBytes: number;
  lastHandshake?: number;
  /** 마지막으로 받은 데이터(keepalive 아님)의 시각 */
  lastRxData?: number;
  lastTx?: number;
  /** passive keepalive 배경 타이머가 걸려 있는지 */
  keepaliveArmed: boolean;
  /** 보냈는데 아직 아무것도 받지 못한 첫 시각 (받으면 지운다) */
  unansweredSince?: number;
  deadTok: number;
  /** 마지막 핸드셰이크 실패 이유 (다시 맺히면 지운다) */
  failed?: string;
  /** 엔드포인트 이름을 푸는 중 (그동안 보낼 패킷은 쌓아 둔다) */
  resolving?: boolean;
  /** 이름을 다시 풀기 전의 엔드포인트 (같은 주소가 나오면 다시 잇지 않는다 — 실패 → 다시 풀기 → 실패 의 끝없는 반복 방지) */
  prevEndpoint?: { ip: Ip; port: number };
}

/** 바깥(인터넷 쪽) 송신: 장치가 정한다 — 공유기는 WAN, 노트북은 지금 쓰는 NIC */
export interface WgIo {
  /** 상대 엔드포인트로 갈 때 바깥 패킷의 출발지 (없으면 보낼 수 없음) */
  source(dst: Ip): Ip | undefined;
  send(outer: Ipv4Packet, ctx: NodeContext, frameId?: number): void;
}

interface WgTimer {
  wg: string;
  peer: string;
  what: "rekey" | "keepalive" | "dead";
  local?: number;
  tries?: number;
  tok?: number;
}

function inPrefixes(ip: Ip, list: WgPrefix[]): WgPrefix | undefined {
  let best: WgPrefix | undefined;
  for (const r of list) {
    let hit = false;
    try {
      hit = sameSubnet(ip, r.dest, r.prefix);
    } catch {
      hit = false;
    }
    if (hit && (!best || r.prefix > best.prefix)) best = r;
  }
  return best;
}

export function prefixesLabel(list: WgPrefix[]): string {
  return list.map((r) => `${r.dest}/${r.prefix}`).join(", ") || "(없음)";
}

export const DEFAULT_WG: WgConfig = { enabled: false, privateKey: "", listenPort: WG_PORT, peers: [] };

/**
 * WireGuard 인터페이스 하나 (wg0). 피어마다 엔드포인트·세션·대기열을 갖는다.
 * 장치는 보낼 패킷을 send 로, 받은 UDP 를 handle 로 넘기고, 풀린 원래 패킷을 받아 라우팅한다.
 */
export class WgInterface {
  config: WgConfig = { ...DEFAULT_WG, peers: [] };
  readonly peers = new Map<string, WgPeerState>();
  private nextIdx: number;
  private tok = 0;
  /** 핸드셰이크가 끝내 실패했을 때 (엔드포인트가 이름이면 다시 풀어 보게 — GL.iNet 의 reresolve) */
  onFail: ((p: WgPeerState, ctx: NodeContext) => void) | undefined;
  /** 보낼 패킷이 있는데 엔드포인트가 없음 (이름 풀기가 실패했던 피어 — 다시 풀어 보게). 없으면 드롭 */
  needEndpoint: ((p: WgPeerState, ctx: NodeContext) => void) | undefined;

  constructor(
    private readonly io: WgIo,
    /** 로그 앞머리·타이머 구분 (예: "WireGuard 서버") */
    readonly label: string,
    seed: string,
  ) {
    this.nextIdx = (fnv(`wg-idx:${seed}`) % 0xfff) * 0x1000 + 1;
  }

  get publicKey(): string {
    return wgPublicKey(this.config.privateKey);
  }

  get enabled(): boolean {
    return this.config.enabled;
  }

  /** 설정 교체. 키·포트·주소가 바뀌면 모든 세션을 버리고, 피어별로는 바뀐 피어만 새로 (나머지 세션은 유지). 바뀐 것이 있으면 true */
  setConfig(cfg: WgConfig, ctx: NodeContext): boolean {
    const norm = (c: WgConfig) => JSON.stringify(c);
    if (norm(cfg) === norm(this.config)) return false;
    if (!cfg.enabled && !this.config.enabled) {
      // 꺼진 채 칸만 바뀜: 조용히 기억만 (켜져 있던 적이 없으니 버릴 세션도 없다)
      this.config = { ...cfg, peers: cfg.peers.map((p) => ({ ...p, allowedIps: p.allowedIps.map((r) => ({ ...r })) })) };
      this.peers.clear();
      return false;
    }
    const base = (c: WgConfig) => JSON.stringify({ e: c.enabled, k: c.privateKey, a: c.address, p: c.listenPort });
    const resetAll = base(cfg) !== base(this.config);
    const old = new Map(this.peers);
    const kept = new Map<string, WgPeerState>();
    for (const p of cfg.peers) {
      const prev = resetAll ? undefined : old.get(p.publicKey);
      if (prev && JSON.stringify(prev.cfg) === JSON.stringify(p)) kept.set(p.publicKey, prev);
      else kept.set(p.publicKey, { cfg: { ...p, allowedIps: p.allowedIps.map((r) => ({ ...r })) }, ...(p.endpoint ? { endpoint: { ...p.endpoint } } : {}), queue: [], rxBytes: 0, txBytes: 0, keepaliveArmed: false, deadTok: 0 });
    }
    this.config = { ...cfg, ...(cfg.address ? { address: { ...cfg.address } } : {}), peers: cfg.peers.map((p) => ({ ...p, allowedIps: p.allowedIps.map((r) => ({ ...r })) })) };
    this.peers.clear();
    for (const [k, v] of kept) this.peers.set(k, v);
    const dropped = [...old.values()].filter((p) => p.session && this.peers.get(p.cfg.publicKey) !== p).length;
    if (!cfg.enabled) {
      ctx.trace("vpn.config", "sys", `${this.label} 꺼짐${dropped ? ` — 세션 ${dropped}개를 버림 (WireGuard 에는 "끊음" 메시지가 없어 상대는 모른다)` : ""}`, { wg: true, enabled: false });
      return true;
    }
    ctx.trace(
      "vpn.config",
      "sys",
      `${this.label} 설정: 내 공개 키 ${shortKey(this.publicKey)}, 터널 주소 ${cfg.address ? `${cfg.address.ip}/${cfg.address.prefix}` : "없음"}, UDP ${cfg.listenPort}, 피어 ${cfg.peers.length}개${dropped ? ` — 바뀐 피어의 세션 ${dropped}개는 버리고 다음 패킷에 새로 핸드셰이크` : ""}`,
      { wg: true, enabled: true, peers: cfg.peers.length },
    );
    return true;
  }

  /** 이 목적지로 보낼 피어 (AllowedIPs 중 가장 긴 마스크 — cryptokey routing) */
  route(dst: Ip): WgPeerState | undefined {
    if (!this.config.enabled) return undefined;
    let best: { p: WgPeerState; len: number } | undefined;
    for (const p of this.peers.values()) {
      const hit = inPrefixes(dst, p.cfg.allowedIps);
      if (hit && (!best || hit.prefix > best.len)) best = { p, len: hit.prefix };
    }
    return best?.p;
  }

  /** 피어 이름 (로그용): 이름이 없으면 공개 키 앞부분 */
  peerName(p: WgPeerState): string {
    return p.cfg.name?.trim() || `피어 ${shortKey(p.cfg.publicKey)}`;
  }

  /** 원래 패킷을 피어에게: 세션이 있으면 바로, 없으면 쌓아 두고 핸드셰이크를 시작한다 */
  send(p: WgPeerState, inner: Ipv4Packet, ctx: NodeContext, frameId?: number): void {
    if (!this.config.enabled) return;
    if (!p.endpoint && (p.resolving || this.needEndpoint)) {
      if (p.queue.length < WG_QUEUE) p.queue.push({ inner, frameId });
      if (!p.resolving) this.needEndpoint!(p, ctx);
      return;
    }
    if (!p.endpoint) {
      ctx.trace("vpn.drop", "L3", `${this.label}: ${inner.dst} 는 ${this.peerName(p)} 의 AllowedIPs 인데 그 피어의 주소(엔드포인트)를 모름 — 피어가 먼저 핸드셰이크를 해야 주소를 배운다 → 드롭`, { wg: true, dst: inner.dst }, frameId);
      return;
    }
    if (p.session) {
      this.transmit(p, inner, ctx, frameId);
      return;
    }
    if (p.queue.length >= WG_QUEUE) {
      ctx.trace("vpn.drop", "L3", `${this.label}: 핸드셰이크를 기다리는 패킷이 너무 많음 → ${inner.src} → ${inner.dst} 드롭`, { wg: true }, frameId);
      return;
    }
    p.queue.push({ inner, frameId });
    if (!p.pending) this.initiate(p, ctx, frameId, `${inner.src} → ${inner.dst} 를 보낼 세션이 없음`);
  }

  /** 엔드포인트가 정해진 피어 중 세션이 없는 쪽과 핸드셰이크 (클라이언트를 켜면 바로 — GL.iNet·앱의 "연결") */
  connect(ctx: NodeContext): void {
    if (!this.config.enabled) return;
    for (const p of this.peers.values()) if (p.endpoint && !p.session && !p.pending) this.initiate(p, ctx, undefined, "연결");
  }

  /** 핸드셰이크 시작 (Initiation) */
  private initiate(p: WgPeerState, ctx: NodeContext, frameId: number | undefined, why: string, tries = 1, local = this.nextIdx++): void {
    const ep = p.endpoint;
    const src = ep ? this.io.source(ep.ip) : undefined;
    if (!ep || !src) {
      this.fail(p, `${this.peerName(p)} 의 주소 ${ep ? `${ep.ip}` : "(모름)"} 로 갈 바깥 경로가 없음 (WAN·주소 확인)`, ctx, frameId);
      return;
    }
    p.pending = { local, tries };
    ctx.trace(
      "vpn.handshake",
      "L4",
      `${this.label}: ${why} → ${this.peerName(p)}(${ep.ip}:${ep.port}) 에 핸드셰이크 시작 (Initiation, 세션 ${local}${tries > 1 ? `, 재시도 ${tries}/${WG_HANDSHAKE_TRIES}` : ""}) — 내 공개 키는 상대 공개 키 ${shortKey(p.cfg.publicKey)} 로 암호화해 상대만 읽는다`,
      { wg: true, peer: ep.ip, local, tries },
      frameId,
    );
    this.out(src, ep, { kind: "wg", type: "initiation", sender: local, static: this.publicKey, to: p.cfg.publicKey }, ctx, frameId);
    const t: WgTimer = { wg: this.label, peer: p.cfg.publicKey, what: "rekey", local, tries };
    ctx.timer(WG_REKEY_TIMEOUT, WG_TIMER_TAG, t);
  }

  private fail(p: WgPeerState, why: string, ctx: NodeContext, frameId?: number): void {
    const n = p.queue.length;
    p.queue = [];
    p.pending = undefined;
    p.session = undefined;
      p.prevSession = undefined;
    p.failed = why;
    ctx.trace("vpn.drop", "L4", `${this.label}: 핸드셰이크 실패 — ${why}${n ? ` → 기다리던 패킷 ${n}개 드롭` : ""}. 보낼 패킷이 또 생기면 다시 시도`, { wg: true, failed: true, dropped: n }, frameId);
    this.onFail?.(p, ctx);
  }

  /**
   * 엔드포인트를 이름에서 풀어 정함 (처음, 또는 실패 뒤 다시 풀었을 때). 주소가 바뀌었거나 처음이면 세션을 버리고,
   * 기다리던 패킷이 있거나 connect 가 true 면 바로 핸드셰이크
   */
  setEndpoint(p: WgPeerState, ep: { ip: Ip; port: number }, ctx: NodeContext, connect: "always" | "if-changed"): void {
    const before = p.endpoint ?? p.prevEndpoint;
    const changed = !before || before.ip !== ep.ip || before.port !== ep.port;
    p.resolving = false;
    p.prevEndpoint = undefined;
    if (!p.endpoint || p.endpoint.ip !== ep.ip || p.endpoint.port !== ep.port) {
      p.endpoint = { ...ep };
      p.session = undefined;
      p.prevSession = undefined;
      p.pending = undefined;
    }
    if (!this.config.enabled || p.pending || p.session) return;
    if (p.queue.length > 0 || connect === "always" || changed) {
      this.initiate(p, ctx, undefined, changed && before ? `서버 주소가 ${before.ip} → ${ep.ip} 로 바뀜` : `엔드포인트 ${ep.ip}:${ep.port}`);
      return;
    }
    ctx.trace("vpn.config", "sys", `${this.label}: 다시 푼 주소도 ${ep.ip} 그대로 → 다시 잇지 않음 (보낼 패킷이 생기면 시도)`, { wg: true, ip: ep.ip });
  }

  /** 엔드포인트 이름을 푸는 동안: 보낼 패킷은 쌓아 두고(주소를 알면 보낸다), 옛 주소는 쓰지 않는다 */
  markResolving(p: WgPeerState): void {
    p.resolving = true;
    if (p.endpoint) p.prevEndpoint = p.endpoint;
    p.endpoint = undefined;
    p.session = undefined;
      p.prevSession = undefined;
    p.pending = undefined;
  }

  private out(src: Ip, ep: { ip: Ip; port: number }, m: WgMessage, ctx: NodeContext, frameId?: number): void {
    this.io.send({ kind: "ipv4", src, dst: ep.ip, ttl: 64, payload: { kind: "udp", srcPort: this.config.listenPort, dstPort: ep.port, payload: m } }, ctx, frameId);
  }

  /** 데이터(또는 keepalive) 송신 */
  private transmit(p: WgPeerState, inner: Ipv4Packet | undefined, ctx: NodeContext, frameId?: number): void {
    const s = p.session!;
    const ep = p.endpoint!;
    const src = this.io.source(ep.ip);
    if (!src) {
      ctx.trace("vpn.drop", "L3", `${this.label}: ${this.peerName(p)} 의 주소 ${ep.ip} 로 갈 바깥 경로가 없음 → 드롭`, { wg: true }, frameId);
      return;
    }
    const counter = s.counter++;
    p.lastTx = ctx.now;
    if (inner) {
      ctx.trace("vpn.encap", "L3", `${this.label}: ${inner.src} → ${inner.dst} 는 ${this.peerName(p)} 의 AllowedIPs → 세션 ${s.remote} 키로 암호화해 UDP ${src}:${this.config.listenPort} → ${ep.ip}:${ep.port} 로 (counter ${counter})`, { wg: true, inner: `${inner.src}>${inner.dst}`, peer: ep.ip }, frameId);
      p.txBytes += 32 + 20;
      // 보낸 뒤 15초 동안 아무것도 못 받으면 새 핸드셰이크 (상대가 세션을 잊었을 수 있다)
      if (p.unansweredSince === undefined) {
        p.unansweredSince = ctx.now;
        this.armDead(p, ctx, WG_DEAD);
      }
    } else {
      ctx.trace("vpn.keepalive", "L4", `${this.label}: ${this.peerName(p)} 에 keepalive (빈 데이터, 32바이트) — 받았다는 표시`, { wg: true, peer: ep.ip }, frameId);
      p.txBytes += 32;
    }
    this.out(src, ep, { kind: "wg", type: "data", receiver: s.remote, counter, ...(inner ? { inner } : {}) }, ctx, frameId);
  }

  private armDead(p: WgPeerState, ctx: NodeContext, delay: number): void {
    p.deadTok = ++this.tok;
    const t: WgTimer = { wg: this.label, peer: p.cfg.publicKey, what: "dead", tok: p.deadTok };
    ctx.timer(delay, WG_TIMER_TAG, t, true);
  }

  /** 이 인터페이스의 타이머면 처리하고 true */
  onTimer(data: unknown, ctx: NodeContext): boolean {
    const d = data as WgTimer;
    if (!d || d.wg !== this.label) return false;
    const p = this.peers.get(d.peer);
    if (!p || !this.config.enabled) return true;
    if (d.what === "rekey") {
      if (!p.pending || p.pending.local !== d.local || p.pending.tries !== d.tries) return true;
      if ((d.tries ?? 1) < WG_HANDSHAKE_TRIES) {
        this.initiate(p, ctx, undefined, `핸드셰이크 응답 없음 (${WG_REKEY_TIMEOUT / 1000}초)`, (d.tries ?? 1) + 1);
        return true;
      }
      this.fail(
        p,
        p.cfg.endpoint || p.resolving !== undefined
          ? `${this.peerName(p)} 가 ${WG_HANDSHAKE_TRIES}번 모두 응답하지 않음 (timeout) — WireGuard 는 키가 틀리거나 등록되지 않은 상대에게 답하지 않는다. 양쪽 공개 키, 상대 주소·UDP ${p.endpoint?.port ?? WG_PORT} 포트(포트 포워딩)를 확인`
          : `${this.peerName(p)} 가 ${WG_HANDSHAKE_TRIES}번 모두 응답하지 않음 (timeout) — 상대가 먼저 접속해 배운 주소라, 상대 앞 NAT 가 이쪽(바뀐 주소 등)에서 먼저 온 패킷을 막을 수 있다. 상대가 다시 보내면 이어진다`,
        ctx,
      );
      return true;
    }
    if (d.what === "keepalive") {
      p.keepaliveArmed = false;
      if (!p.session || p.lastRxData === undefined) return true;
      if (p.lastTx !== undefined && p.lastTx >= p.lastRxData) return true; // 그사이 무언가 보냈다 — 그것이 받았다는 표시
      const wait = p.lastRxData + WG_KEEPALIVE - ctx.now;
      if (wait > 0) {
        p.keepaliveArmed = true;
        ctx.timer(wait, WG_TIMER_TAG, { wg: this.label, peer: p.cfg.publicKey, what: "keepalive" } satisfies WgTimer, true);
        return true;
      }
      this.transmit(p, undefined, ctx);
      return true;
    }
    // dead: 보낸 뒤 15초 동안 받은 것이 없음
    if (d.tok !== p.deadTok || p.unansweredSince === undefined) return true;
    const idle = ctx.now - p.unansweredSince;
    if (idle < WG_DEAD) {
      this.armDead(p, ctx, WG_DEAD - idle);
      return true;
    }
    p.unansweredSince = undefined;
    if (p.pending || !p.endpoint) return true;
    this.initiate(p, ctx, undefined, `보낸 뒤 ${WG_DEAD / 1000}초 동안 ${this.peerName(p)} 에게서 아무것도 받지 못함 (상대가 재시작해 세션을 잊었을 수 있음)`);
    return true;
  }

  /**
   * 받은 WireGuard 메시지. 풀린 원래 패킷(데이터)이면 돌려주고, 핸드셰이크·keepalive·드롭이면 null.
   * outer 는 바깥 IP, srcPort 는 바깥 UDP 출발지 포트 (엔드포인트 로밍)
   */
  handle(outer: Ipv4Packet, srcPort: number, m: WgMessage, ctx: NodeContext, frameId?: number): Ipv4Packet | null {
    if (!this.config.enabled) return null;
    const from = { ip: outer.src, port: srcPort };
    if (m.type === "initiation") {
      if (m.to !== this.publicKey) {
        ctx.trace("vpn.drop", "L4", `${this.label}: ${from.ip}:${from.port} 의 Initiation 을 내 공개 키로 확인할 수 없음 (mac1 불일치 — 보낸 쪽이 알고 있는 이 장비의 공개 키 ${shortKey(m.to ?? "")} 가 내 키 ${shortKey(this.publicKey)} 와 다름) → 응답 없이 버림`, { wg: true, from: from.ip, reason: "mac1" }, frameId);
        return null;
      }
      const p = m.static ? this.peers.get(m.static) : undefined;
      if (!p) {
        ctx.trace("vpn.drop", "L4", `${this.label}: ${from.ip}:${from.port} 의 Initiation — 보낸 공개 키 ${shortKey(m.static ?? "")} 가 피어 목록에 없음 → 응답 없이 버림 (Invalid handshake initiation. WireGuard 는 모르는 상대에게 답하지 않는다 — 피어에 그 공개 키를 등록하세요)`, { wg: true, from: from.ip, reason: "unknown-key" }, frameId);
        return null;
      }
      this.roam(p, from, ctx, frameId);
      const local = this.nextIdx++;
      // 내가 시작한 핸드셰이크(pending)가 있어도 지우지 않는다: 양쪽이 동시에 시작했으면 그 Response 도 곧 온다 (세션은 두 칸이라 둘 다 받는다)
      this.install(p, { local, remote: m.sender ?? 0, since: ctx.now, counter: 0 });
      p.lastHandshake = ctx.now;
      p.failed = undefined;
      p.unansweredSince = undefined;
      ctx.trace("vpn.handshake", "L4", `${this.label}: ${this.peerName(p)}(${from.ip}:${from.port}) 의 Initiation — 공개 키가 피어 목록에 있음 → Response 로 답하고 세션 ${local} ↔ ${m.sender} 를 만듦`, { wg: true, from: from.ip, local }, frameId);
      const src = outer.dst;
      this.out(src, from, { kind: "wg", type: "response", sender: local, receiver: m.sender }, ctx, frameId);
      this.flush(p, ctx);
      return null;
    }
    if (m.type === "response") {
      const p = [...this.peers.values()].find((x) => x.pending?.local === m.receiver);
      if (!p) {
        ctx.trace("vpn.drop", "L4", `${this.label}: ${from.ip} 의 Response (세션 ${m.receiver}) — 지금 기다리는 핸드셰이크가 아님 (늦게 온 응답) → 무시`, { wg: true, from: from.ip, late: true }, frameId);
        return null;
      }
      this.roam(p, from, ctx, frameId);
      this.install(p, { local: m.receiver!, remote: m.sender ?? 0, since: ctx.now, counter: 0 });
      p.pending = undefined;
      p.lastHandshake = ctx.now;
      p.failed = undefined;
      p.unansweredSince = undefined;
      ctx.trace("vpn.up", "L4", `${this.label}: ${this.peerName(p)} 의 Response → 핸드셰이크 완료, 세션 ${m.receiver} ↔ ${m.sender} (1-RTT). 이제 ${prefixesLabel(p.cfg.allowedIps)} 로 가는 패킷은 이 세션으로 암호화`, { wg: true, from: from.ip }, frameId);
      // 기다리던 패킷이 있으면 그것이, 없으면 keepalive 가 "세션을 받았다" 는 확인이 된다
      if (p.queue.length) this.flush(p, ctx);
      else this.transmit(p, undefined, ctx, frameId);
      return null;
    }
    const p = [...this.peers.values()].find((x) => x.session?.local === m.receiver || x.prevSession?.local === m.receiver);
    if (!p) {
      ctx.trace("vpn.drop", "L4", `${this.label}: ${from.ip}:${from.port} 의 데이터가 모르는 세션 ${m.receiver} 로 옴 (이 장비가 재시작·설정 변경으로 세션을 잊음) → 버림. 상대는 ${WG_DEAD / 1000}초 동안 답이 없으면 새로 핸드셰이크한다`, { wg: true, from: from.ip, reason: "unknown-session" }, frameId);
      return null;
    }
    this.roam(p, from, ctx, frameId);
    p.unansweredSince = undefined;
    const inner = m.inner;
    if (!inner) {
      ctx.trace("vpn.keepalive", "L4", `${this.label}: ${this.peerName(p)} 의 keepalive 수신 (세션 살아 있음)`, { wg: true, from: from.ip }, frameId);
      p.rxBytes += 32;
      return null;
    }
    if (!inPrefixes(inner.src, p.cfg.allowedIps)) {
      ctx.trace("vpn.drop", "L3", `${this.label}: ${this.peerName(p)} 에게서 풀린 패킷의 출발지 ${inner.src} 가 그 피어의 AllowedIPs(${prefixesLabel(p.cfg.allowedIps)}) 밖 → 드롭 (cryptokey routing: 피어마다 쓸 수 있는 출발지가 정해져 있다)`, { wg: true, src: inner.src }, frameId);
      return null;
    }
    p.rxBytes += 32 + 20;
    p.lastRxData = ctx.now;
    if (!p.keepaliveArmed) {
      p.keepaliveArmed = true;
      ctx.timer(WG_KEEPALIVE, WG_TIMER_TAG, { wg: this.label, peer: p.cfg.publicKey, what: "keepalive" } satisfies WgTimer, true);
    }
    ctx.trace("vpn.decap", "L3", `${this.label}: ${this.peerName(p)} 의 데이터(세션 ${m.receiver})를 풀어 ${inner.src} → ${inner.dst} 패킷을 꺼냄 (출발지가 AllowedIPs 안)`, { wg: true, from: from.ip, inner: `${inner.src}>${inner.dst}` }, frameId);
    return inner;
  }

  /** 새 세션을 현재로, 지금 것은 직전으로 */
  private install(p: WgPeerState, s: Session): void {
    if (p.session) p.prevSession = p.session;
    p.session = s;
  }

  /** 인증된 패킷의 바깥 출발지가 바뀌었으면 그 피어의 새 주소로 (엔드포인트 로밍) */
  private roam(p: WgPeerState, from: { ip: Ip; port: number }, ctx: NodeContext, frameId?: number): void {
    const e = p.endpoint;
    if (e && e.ip === from.ip && e.port === from.port) return;
    p.endpoint = { ...from };
    if (e) ctx.trace("vpn.roam", "L4", `${this.label}: ${this.peerName(p)} 의 주소가 ${e.ip}:${e.port} → ${from.ip}:${from.port} 로 바뀜 (엔드포인트 로밍 — NAT 매핑·Wi-Fi 가 바뀌어도 세션이 이어진다)`, { wg: true, from: from.ip }, frameId);
  }

  private flush(p: WgPeerState, ctx: NodeContext): void {
    const q = p.queue;
    p.queue = [];
    for (const x of q) this.transmit(p, x.inner, ctx, x.frameId);
  }

  /** 모든 세션·대기열을 버림 (WAN 이 주소를 잃음 등). 상대에게 알리는 메시지는 없다 */
  reset(): void {
    for (const p of this.peers.values()) {
      p.session = undefined;
      p.prevSession = undefined;
      p.pending = undefined;
      p.queue = [];
      p.unansweredSince = undefined;
      p.failed = undefined;
      if (!p.cfg.endpoint) p.endpoint = undefined;
    }
  }

  /** 표시용: wg show 의 피어 줄 */
  rows(): string[][] {
    return [...this.peers.values()].map((p) => [
      this.peerName(p),
      shortKey(p.cfg.publicKey),
      p.endpoint ? `${p.endpoint.ip}:${p.endpoint.port}` : "(모름)",
      prefixesLabel(p.cfg.allowedIps),
      p.session ? `${p.lastHandshake ?? 0}ms` : p.pending ? "핸드셰이크 중" : p.failed ? "실패" : "없음",
      `받음 ${p.rxBytes}B · 보냄 ${p.txBytes}B`,
    ]);
  }

  /** 세션이 하나라도 맺어진 피어 수 */
  get connected(): number {
    return [...this.peers.values()].filter((p) => p.session).length;
  }
}

// ---------- 노트북·폰의 WireGuard 앱 ----------

/** 앱이 장치에 부탁하는 것: 지금 주소·바깥 송신·직접 연결된 서브넷인지 */
export interface WgClientIo {
  myIp(): Ip | undefined;
  send(outer: Ipv4Packet, ctx: NodeContext): void;
  local(dst: Ip): boolean;
  /** 서버 이름 풀기 (터널 밖 DNS 로 — 캐시를 지우고) */
  resolve(name: string, ctx: NodeContext, done: (ip: Ip | undefined, reason?: string) => void): void;
}

/**
 * 노트북·폰의 WireGuard 앱 (원격 접속 VPN 의 한 종류). 서버 하나를 피어로 둔 WireGuard 인터페이스.
 * IKEv2·L2TP 와 달리 주소를 받아 오지 않는다 — 서버 관리자가 정해 준 터널 주소를 설정 파일에 적어 둔다.
 * 켜 두면 AllowedIPs 로 가는 패킷은 늘 터널로 간다(핸드셰이크가 안 돼도 밖으로 새지 않는다 — 앱 자체가 킬 스위치처럼 동작)
 */
export class WgClient {
  config: RaClientConfig = { ...DEFAULT_RA_CLIENT, type: "wireguard" };
  readonly wg: WgInterface;
  readonly dpdWaiting = false;
  readonly reason: string | undefined = undefined;

  constructor(
    private readonly io: WgClientIo,
    seed: string,
    /** 바깥 UDP 포트 (ListenPort 를 비운 설정 — 장치마다 고정) */
    readonly listenPort: number,
  ) {
    this.wg = new WgInterface({ source: () => this.io.myIp(), send: (outer, ctx) => this.io.send(outer, ctx) }, "WireGuard", seed);
    // 핸드셰이크가 끝내 실패하면 서버 이름을 다시 풀어 본다 (서버의 공인 주소가 바뀌었을 수 있다)
    this.wg.onFail = (_p, ctx) => {
      if (this.serverName) this.resolveServer(ctx, "핸드셰이크 실패 — 서버 주소가 바뀌었을 수 있어 이름을 다시 풂", true);
    };
    // 이름 풀기가 실패해 엔드포인트가 없는데 보낼 패킷이 생김: 다시 풀어 본다
    this.wg.needEndpoint = (_p, ctx) => {
      if (this.serverName) this.resolveServer(ctx, "보낼 패킷이 생겼는데 서버 주소를 모름 — 이름을 다시 풂");
    };
  }

  /** 서버를 이름으로 적었으면 그 이름 */
  private get serverName(): string | undefined {
    const s = this.config.server;
    return s && /[a-z]/i.test(s) ? s : undefined;
  }

  /** 지금 쓰는 서버 주소 (이름이면 푼 주소) */
  private get serverIp(): Ip | undefined {
    return this.serverName ? this.peer?.endpoint?.ip : this.config.server;
  }

  private resolveServer(ctx: NodeContext, why: string, reresolve = false): void {
    const name = this.serverName;
    const p = this.peer;
    const w = this.config.wg;
    if (!name || !p || !w || !this.io.myIp()) return;
    this.wg.markResolving(p);
    ctx.trace("vpn.config", "sys", `WireGuard: ${why} → ${name} 을(를) 터널 밖 DNS 로 물음`, { wg: true, name });
    this.io.resolve(name, ctx, (ip, reason) => {
      if (this.serverName !== name || !this.wg.enabled) return;
      if (!ip) {
        p.resolving = false;
        const n = p.queue.length;
        p.queue = [];
        p.failed = `서버 이름 ${name} 을(를) 풀지 못함 (${reason ?? "?"})`;
        // 전에 쓰던 주소가 있으면 그대로 다시 써 본다 (이름 풀기만 잠깐 안 됐을 수 있다)
        if (p.prevEndpoint) {
          p.endpoint = p.prevEndpoint;
          p.prevEndpoint = undefined;
        }
        ctx.trace("vpn.drop", "L4", `WireGuard: ${p.failed}${n ? ` → 기다리던 패킷 ${n}개 드롭` : ""}${p.endpoint ? ` — 전에 쓰던 ${p.endpoint.ip} 로 계속 시도` : " — 보낼 패킷이 또 생기면 다시 풂"}. 이름(DDNS)과 DNS 설정을 확인`, { wg: true, failed: true });
        return;
      }
      ctx.trace("vpn.config", "sys", `WireGuard: ${name} = ${ip} → 엔드포인트 ${ip}:${w.port}`, { wg: true, name, ip });
      this.wg.setEndpoint(p, { ip, port: w.port }, ctx, reresolve ? "if-changed" : "always");
    });
  }

  private get peer(): WgPeerState | undefined {
    return this.wg.peers.values().next().value;
  }

  get state(): RaClientState {
    const p = this.peer;
    if (!this.config.enabled || !this.wg.enabled || !p) return "off";
    if (p.session) return "up";
    if (p.pending) return "init";
    return p.failed ? "failed" : "off";
  }

  /** 내 터널 주소 (켜져 있으면 핸드셰이크 전에도 — 인터페이스에 붙어 있는 주소) */
  get vip(): Ip | undefined {
    return this.config.enabled ? this.config.wg?.address?.ip : undefined;
  }

  get routes(): WgPrefix[] {
    return this.config.wg?.allowedIps ?? [];
  }

  get dns(): Ip | undefined {
    return this.config.enabled ? this.config.wg?.dns : undefined;
  }

  setConfig(cfg: RaClientConfig, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.config)) return;
    this.config = { ...cfg };
    const w = cfg.wg;
    const ok = cfg.enabled && !!w && !!w.address && !!cfg.server;
    const byName = !!cfg.server && /[a-z]/i.test(cfg.server);
    this.wg.setConfig(
      ok
        ? { enabled: true, privateKey: w!.privateKey, address: w!.address, listenPort: this.listenPort, peers: [{ name: "서버", publicKey: w!.serverKey, ...(byName ? {} : { endpoint: { ip: cfg.server!, port: w!.port } }), allowedIps: w!.allowedIps }] }
        : { ...DEFAULT_WG, peers: [] },
      ctx,
    );
    if (cfg.enabled && !ok) ctx.trace("vpn.config", "sys", `WireGuard: 설정이 비어 있음 (${!cfg.server ? "서버 주소" : !w?.address ? "내 터널 주소" : "설정"}) → 연결하지 않음`, { wg: true });
    if (ok) {
      ctx.trace("vpn.config", "sys", `WireGuard: ${prefixesLabel(w!.allowedIps)} 로 가는 패킷을 출발지 ${w!.address!.ip} 로 바꿔 서버 ${cfg.server}:${w!.port} 로${w!.dns ? `, DNS 는 ${w!.dns}` : ""}`, { wg: true });
      this.connect(ctx);
    }
  }

  connect(ctx: NodeContext): void {
    if (!this.io.myIp()) return;
    const p = this.peer;
    if (this.serverName && p && !p.endpoint) {
      if (!p.resolving) this.resolveServer(ctx, "연결");
      return;
    }
    this.wg.connect(ctx);
  }

  handleIke(): boolean {
    return false;
  }

  unwrap(): undefined {
    return undefined;
  }

  /** 받은 WireGuard 메시지: 풀린 패킷이면 목적지(내 터널 주소)를 실제 주소로 되돌려 돌려준다 */
  handleWg(outer: Ipv4Packet, srcPort: number, m: WgMessage, ctx: NodeContext, frameId: number): Ipv4Packet | null {
    const inner = this.wg.handle(outer, srcPort, m, ctx, frameId);
    if (!inner) return null;
    const me = this.io.myIp();
    if (!me || inner.dst !== this.vip) {
      ctx.trace("vpn.drop", "L3", `WireGuard: 풀린 패킷의 목적지 ${inner.dst} 가 내 터널 주소(${this.vip ?? "없음"})가 아님 → 드롭`, { dst: inner.dst }, frameId);
      return null;
    }
    return { ...inner, dst: me };
  }

  /** 내보낼 패킷: AllowedIPs 로 가는 것이면 출발지를 터널 주소로 바꿔 터널로. 가로챘으면 true */
  intercept(pkt: Ipv4Packet, ctx: NodeContext): boolean {
    const vip = this.vip;
    if (!vip || !this.wg.enabled) return false;
    const p = pkt.payload;
    // 터널 자신(바깥 UDP)·서버로 가는 것·직접 연결된 서브넷·DHCP·브로드캐스트는 그대로 (가로채면 바깥 패킷이 다시 터널로 들어간다)
    if (p.kind === "udp" && (p.payload.kind === "wg" || p.payload.kind === "dhcp")) return false;
    if (pkt.dst === this.serverIp || pkt.dst === "255.255.255.255" || this.io.local(pkt.dst)) return false;
    const peer = this.wg.route(pkt.dst);
    if (!peer) return false;
    // 서버 이름을 푸는 중(엔드포인트 없음)에는 DNS 질의를 터널 밖으로 — 터널이 서기 전에 풀어야 한다 (wg-quick 도 DNS 를 바꾸기 전에 푼다)
    if (!peer.endpoint && p.kind === "udp" && p.payload.kind === "dns") return false;
    this.wg.send(peer, { ...pkt, src: vip }, ctx);
    return true;
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    this.wg.onTimer(data, ctx);
  }

  onDpdTick(): void {}

  /** 주소가 바뀌거나 잃음: WireGuard 는 연결 상태가 없어 세션을 그대로 둔다 — 다음에 보내는 패킷으로 서버가 새 주소를 배운다 (로밍) */
  lost(ctx: NodeContext, why: string): void {
    if (this.state !== "up") return;
    ctx.trace("vpn.roam", "L4", `WireGuard: ${why} — 세션은 그대로 (연결 상태가 없는 VPN). 다음에 보내는 패킷의 새 출발지를 서버가 배운다`, { wg: true });
  }

  disconnect(ctx: NodeContext, why: string): void {
    if (this.state === "up") ctx.trace("vpn.drop", "L4", `WireGuard 끔 (${why}) — 서버에 알리는 메시지는 없다 (서버는 세션을 그대로 들고 있다가 쓰지 않을 뿐)`, { wg: true });
    this.wg.reset();
  }

  reconnect(ctx: NodeContext): void {
    this.wg.reset();
    const p = this.peer;
    if (this.serverName && p) {
      this.resolveServer(ctx, "다시 연결");
      return;
    }
    this.connect(ctx);
  }

  dpd(ctx: NodeContext): void {
    ctx.trace("vpn.dpd", "L4", `WireGuard 에는 DPD 가 없음 — 보낸 뒤 ${WG_DEAD / 1000}초 동안 아무것도 받지 못하면 스스로 새 핸드셰이크를 한다`, { dpd: "none" });
  }

  summary(): string | undefined {
    if (!this.config.enabled) return undefined;
    const s = this.state;
    const w = this.config.wg;
    if (!w?.address || !this.config.server) return "설정 필요 (서버 주소·내 터널 주소)";
    const ep = this.peer?.endpoint;
    const via = this.serverName ? ` · ${this.serverName}${ep ? ` = ${ep.ip}` : ""}` : "";
    if (s === "up") return `연결됨 · 터널 주소 ${w.address.ip} · ${prefixesLabel(w.allowedIps)} 는 터널로${via}`;
    if (s === "init") return `연결 중 (핸드셰이크)${via}`;
    if (s === "failed") return `실패 · ${this.peer?.failed ?? ""}`;
    return "대기 (주소를 받으면 연결)";
  }
}
