// P2P 연결 (NAT 트래버설 축소판 — 화상 통화·게임·Tailscale 같은 앱이 NAT 뒤끼리 직접 잇는 방법):
//   1. STUN: 공인 STUN 서버 두 곳에 "바깥에서 본 내 주소:포트는?" — 두 답의 포트가 다르면 내 NAT 는 symmetric (상대마다 바깥 포트가 바뀜)
//   2. 시그널링: 서로 모르는 두 기기가 시그널링 서버를 거쳐 후보 주소(host·srflx)를 주고받는다 (offer·answer — 실제로는 웹소켓)
//   3. 홀 펀칭: 양쪽이 상대 후보로 동시에 UDP 를 보낸다. 내가 먼저 보내야 내 NAT 가 그 상대의 답을 들여보낸다
//      → 안 되면(대개 한쪽이라도 symmetric) 4. TURN: 공인 릴레이 서버를 거쳐 잇는다 (항상 되지만 느리고 서버 비용이 든다)
// 줄인 것: ICE 의 후보 우선순위·연결 확인(STUN 체크)·TURN 권한(CreatePermission)·keepalive. 한 번에 한 상대만 (다른 상대와 연결 중이면 새 제안은 busy 로 거절).
// 요청(STUN·offer·Allocate·relay 알림)은 응답이 없으면 WAIT 마다 2번까지 다시 보낸다 (RFC 5389 재전송 축소판).
import { sameSubnet, type Ip } from "../addr";
import { P2P_PORT, SIGNAL_PORT, STUN_PORT, type Endpoint, type Ipv4Packet, type P2pCandidate, type P2pMessage, type StunMessage, type UdpPacket } from "../packet";
import type { NodeContext, TimerHandle } from "./node";

/** 인터넷 노드가 흉내 내는 공인 서버들 (TEST-NET-2 대역) */
export const STUN_SERVERS: Ip[] = ["198.51.100.30", "198.51.100.31"];
export const SIGNAL_SERVER: Ip = "198.51.100.40";
export const TURN_SERVER: Ip = "198.51.100.50";
export const P2P_TIMER_TAG = "p2p";
/** 홀 펀칭 재시도 간격·횟수 */
const PUNCH_INTERVAL = 200;
const PUNCH_TRIES = 6;
/** STUN·시그널링·TURN 응답을 기다리는 시간, 다시 보내는 횟수 */
const WAIT = 1500;
const RETRIES = 2;
/** 등록이 3번 실패한 뒤 다시 시도하는 간격 (배경 타이머 — 시간이 흐를 때만, 인터넷이 없어도 시계를 붙잡지 않게) */
const REG_RETRY = 10_000;

export interface P2pConfig {
  enabled: boolean;
  /** 시그널링 서버에 등록할 이름 (상대가 이 이름으로 연결한다) */
  name: string;
}

export interface P2pHost {
  myIp(): Ip | undefined;
  /** 내가 직접 붙은 서브넷인지 (host 후보는 같은 LAN 일 때만 시도) */
  local(dst: Ip): boolean;
  send(pkt: Ipv4Packet, ctx: NodeContext): void;
}

type Phase = "stun" | "signal" | "punch" | "turn" | "connected" | "failed";

interface Session {
  peer: string;
  role: "offer" | "answer";
  phase: Phase;
  /** STUN 요청 번호 → 응답 (서버 순서대로) */
  stunTx: number[];
  stunResults: (Endpoint | undefined)[];
  nat?: "none" | "cone" | "symmetric";
  mine?: P2pCandidate[];
  theirs?: P2pCandidate[];
  /** 상대가 짐작한 자기 NAT (none 이면 host 후보가 곧 공인 주소) */
  theirNat?: "none" | "cone" | "symmetric";
  tries: number;
  /** 지금 단계의 재전송 횟수 */
  retries: number;
  via?: "direct" | "relay";
  /** 연결된 상대 주소 (직접이면 상대 NAT 바깥, 릴레이면 TURN 이 본 상대) */
  path?: Endpoint;
  relay?: Endpoint;
  reason?: string;
  timer?: TimerHandle;
  token: number;
}

export const P2P_PHASE_LABEL: Record<Phase, string> = {
  stun: "STUN 으로 바깥 주소 확인 중",
  signal: "시그널링 서버로 상대를 기다리는 중",
  punch: "홀 펀칭 중",
  turn: "TURN 릴레이로 잇는 중",
  connected: "연결됨",
  failed: "실패",
};

const ep = (e: Endpoint) => `${e.ip}:${e.port}`;

export class P2pAgent {
  config: P2pConfig = { enabled: false, name: "" };
  /** 시그널링 서버가 본 내 바깥 주소 (등록됨) */
  registered: Endpoint | undefined;
  session: Session | undefined;
  /** 등록 전에 사용자가 연결을 눌렀다: 등록되면 이어서 이 상대에게 연결 */
  private pending: string | undefined;
  private txid = 0x5000;
  private token = 0;

  constructor(private readonly host: P2pHost) {}

  setConfig(cfg: P2pConfig, ctx: NodeContext): void {
    if (cfg.enabled === this.config.enabled && cfg.name === this.config.name) return;
    // 끄거나 이름을 바꾸면 옛 이름을 시그널링 서버에서 지운다 (남아 있으면 옛 이름으로 온 제안을 받거나, 상대가 응답 없음으로 실패한다)
    if (this.config.enabled && this.config.name && (this.registered || this.regFor)) this.sendTo({ ip: SIGNAL_SERVER, port: SIGNAL_PORT }, { kind: "p2p", op: "unregister", from: this.config.name }, ctx);
    this.config = { ...cfg };
    this.registered = undefined;
    this.regFor = undefined;
    this.pending = undefined;
    this.end();
    ctx.trace("p2p.signal", "app", cfg.enabled ? `P2P 앱 켜짐: 이름 "${cfg.name}" 으로 시그널링 서버에 등록` : "P2P 앱 꺼짐 → 시그널링 서버에서 등록 해제", { enabled: cfg.enabled, name: cfg.name });
    this.onAddress(ctx);
  }

  /** 등록을 보낸 내 주소 (같은 주소로 다시 보내지 않게), 등록 재시도 */
  private regFor: Ip | undefined;
  private regTries = 0;
  private regToken = 0;

  /** 주소를 얻었을 때(DHCP·고정 주소 확인 끝): 시그널링 서버에 등록 — 이 등록이 만든 NAT 매핑으로 서버가 나중에 연락한다 */
  onAddress(ctx: NodeContext): void {
    const me = this.host.myIp();
    if (!this.config.enabled || !me || this.regFor === me) return;
    this.regFor = me;
    this.registered = undefined;
    this.regTries = 0;
    this.sendRegister(ctx);
  }

  /** 등록 (윗단 공유기가 아직 주소를 못 받았을 수 있어 1.5초마다 3번까지, 그 뒤로는 10초마다 배경으로) */
  private sendRegister(ctx: NodeContext): void {
    this.regTries++;
    this.sendTo({ ip: SIGNAL_SERVER, port: SIGNAL_PORT }, { kind: "p2p", op: "register", from: this.config.name }, ctx);
    ctx.timer(WAIT, P2P_TIMER_TAG, { reg: ++this.regToken });
  }

  /** 주소를 잃음: 진행 중인 연결은 끝 (바깥 주소가 바뀐다) */
  lost(): void {
    this.registered = undefined;
    this.regFor = undefined;
    this.pending = undefined;
    this.end();
  }

  private end(): void {
    this.session?.timer?.cancel();
    this.session = undefined;
  }

  private sendTo(to: Endpoint, payload: StunMessage | P2pMessage, ctx: NodeContext): void {
    const me = this.host.myIp();
    if (!me) return;
    this.host.send({ kind: "ipv4", src: me, dst: to.ip, ttl: 64, payload: { kind: "udp", srcPort: P2P_PORT, dstPort: to.port, payload } }, ctx);
  }

  private toSignal(m: P2pMessage, ctx: NodeContext): void {
    this.sendTo({ ip: SIGNAL_SERVER, port: SIGNAL_PORT }, m, ctx);
  }

  private arm(s: Session, delay: number, step: string, ctx: NodeContext): void {
    s.timer?.cancel();
    s.timer = ctx.timer(delay, P2P_TIMER_TAG, { token: s.token, step });
  }

  private fail(s: Session, why: string, ctx: NodeContext): void {
    s.timer?.cancel();
    s.phase = "failed";
    s.reason = why;
    ctx.trace("p2p.failed", "app", `P2P 연결 실패 (상대 ${s.peer}): ${why}`, { peer: s.peer });
  }

  private newSession(peer: string, role: Session["role"]): Session {
    this.end();
    const s: Session = { peer, role, phase: "stun", stunTx: [], stunResults: [], tries: 0, retries: 0, token: ++this.token };
    this.session = s;
    return s;
  }

  /** 사용자 동작: 이름이 peer 인 상대와 P2P 연결 */
  connect(peer: string, ctx: NodeContext): void {
    const name = peer.trim();
    if (!this.config.enabled) {
      ctx.trace("p2p.failed", "app", `P2P 연결 못 함: 이 장치의 P2P 앱이 꺼져 있음 (서비스에서 켜세요)`, {});
      return;
    }
    if (!name || name === this.config.name) {
      ctx.trace("p2p.failed", "app", `P2P 연결 못 함: 상대 이름이 비었거나 나 자신`, {});
      return;
    }
    if (!this.registered) {
      const me = this.host.myIp();
      if (!me) {
        ctx.trace("p2p.failed", "app", `P2P 연결 못 함: 주소가 없어 시그널링 서버에 등록할 수 없음 (IP 설정·DHCP 를 확인)`, {});
        return;
      }
      // 아직 등록 전 (윗단이 늦게 인터넷에 닿음 등): 지금 다시 등록하고, 되면 이어서 연결한다
      this.end();
      this.pending = name;
      ctx.trace("p2p.connect", "app", `P2P 연결 → ${name}: 아직 시그널링 서버에 등록 전 → 먼저 등록하고, 등록되면 이어서 연결`, { peer: name });
      this.regFor = me;
      this.regTries = 0;
      this.sendRegister(ctx);
      return;
    }
    this.pending = undefined;
    const s = this.newSession(name, "offer");
    ctx.trace("p2p.connect", "app", `P2P 연결 시작 → ${name}: 먼저 STUN 서버 두 곳에 바깥 주소를 묻는다 (두 답의 포트가 다르면 내 NAT 는 symmetric)`, { peer: name });
    this.startStun(s, ctx);
  }

  private startStun(s: Session, ctx: NodeContext): void {
    s.phase = "stun";
    s.retries = 0;
    s.stunTx = STUN_SERVERS.map(() => ++this.txid);
    s.stunResults = STUN_SERVERS.map(() => undefined);
    this.sendStun(s, ctx);
  }

  /** 답이 아직 없는 STUN 서버에 Binding 요청 (재전송은 같은 요청 번호) */
  private sendStun(s: Session, ctx: NodeContext): void {
    STUN_SERVERS.forEach((ip, i) => {
      if (!s.stunResults[i]) this.sendTo({ ip, port: STUN_PORT }, { kind: "stun", op: "binding-request", txid: s.stunTx[i]! }, ctx);
    });
    this.arm(s, WAIT, "stun", ctx);
  }

  /** 받은 UDP (내 P2P 포트로). 처리했으면 true */
  handle(pkt: Ipv4Packet, udp: UdpPacket, ctx: NodeContext, frameId: number): boolean {
    if (!this.config.enabled || udp.dstPort !== P2P_PORT) return false;
    const m = udp.payload;
    const from: Endpoint = { ip: pkt.src, port: udp.srcPort };
    if (m.kind === "stun") return this.onStun(from, m, ctx, frameId);
    if (m.kind !== "p2p") return false;
    if (from.ip === SIGNAL_SERVER && from.port === SIGNAL_PORT) return this.onSignal(m, ctx, frameId);
    return this.onPeer(from, m, false, ctx, frameId);
  }

  private onStun(from: Endpoint, m: StunMessage, ctx: NodeContext, frameId: number): boolean {
    const s = this.session;
    if (m.op === "binding-response") {
      const i = s?.stunTx.indexOf(m.txid) ?? -1;
      if (!s || s.phase !== "stun" || i < 0 || !m.mapped || s.stunResults[i]) {
        ctx.trace("p2p.stun", "app", `지난 STUN 응답 → 무시`, {}, frameId);
        return true;
      }
      s.stunResults[i] = m.mapped;
      ctx.trace("p2p.stun", "app", `STUN ${from.ip}: 바깥에서 본 내 주소는 ${ep(m.mapped)}`, { server: from.ip, mapped: ep(m.mapped) }, frameId);
      if (s.stunResults.every((r) => r)) this.stunDone(s, ctx);
      return true;
    }
    if (m.op === "allocate-response" && s && s.phase === "turn" && !s.relay && m.relayed) {
      s.relay = m.relayed;
      s.retries = 0;
      ctx.trace("p2p.relay", "app", `TURN 서버가 릴레이 주소 ${ep(m.relayed)} 를 줌 → 시그널링 서버로 상대에게 "이 주소로 보내라" 를 알림`, { relay: ep(m.relayed) }, frameId);
      this.sendRelayNotice(s, ctx);
      return true;
    }
    if (m.op === "data" && m.data && m.peer && from.ip === TURN_SERVER) return this.onPeer(m.peer, m.data, true, ctx, frameId);
    return true;
  }

  private sendRelayNotice(s: Session, ctx: NodeContext): void {
    this.toSignal({ kind: "p2p", op: "relay", from: this.config.name, to: s.peer, candidates: [{ type: "relay", ...s.relay! }] }, ctx);
    this.arm(s, WAIT, "turn", ctx);
  }

  /** STUN 두 답이 모임: NAT 종류를 짐작하고 후보를 만든다 */
  private stunDone(s: Session, ctx: NodeContext): void {
    const me = this.host.myIp()!;
    const [a, b] = s.stunResults as Endpoint[];
    s.nat = a!.ip === me && a!.port === P2P_PORT ? "none" : a!.port === b!.port ? "cone" : "symmetric";
    s.mine = [{ type: "host", ip: me, port: P2P_PORT }, ...(s.nat === "none" ? [] : [{ type: "srflx" as const, ...a! }])];
    ctx.trace(
      "p2p.stun",
      "app",
      s.nat === "none"
        ? `STUN 결과: 바깥에서 본 주소가 내 주소 그대로 → NAT 없음`
        : s.nat === "cone"
          ? `STUN 결과: 두 서버가 본 바깥 포트가 같음 (${a!.port}) → 내 NAT 는 cone (상대가 바뀌어도 바깥 포트가 그대로 — 홀 펀칭 가능)`
          : `STUN 결과: 두 서버가 본 바깥 포트가 다름 (${a!.port} ≠ ${b!.port}) → 내 NAT 는 symmetric (상대마다 바깥 포트가 바뀌어 상대에게 알려 준 주소가 맞지 않는다 — 홀 펀칭이 어렵다)`,
      { nat: s.nat },
    );
    ctx.trace("p2p.signal", "app", `시그널링 서버로 ${s.role === "offer" ? "연결 제안(offer)" : "연결 응답(answer)"} → ${s.peer}: 내 후보 ${s.mine.map((c) => `${c.type} ${ep(c)}`).join(", ")}`, { peer: s.peer });
    this.sendCandidates(s, ctx);
    if (s.role === "offer") {
      s.phase = "signal";
      s.retries = 0;
      this.arm(s, WAIT, "signal", ctx);
    } else this.startPunch(s, ctx);
  }

  private sendCandidates(s: Session, ctx: NodeContext): void {
    this.toSignal({ kind: "p2p", op: s.role === "offer" ? "offer" : "answer", from: this.config.name, to: s.peer, candidates: s.mine, nat: s.nat }, ctx);
  }

  private onSignal(m: P2pMessage, ctx: NodeContext, frameId: number): boolean {
    if (m.op === "registered") {
      this.registered = m.candidates?.[0] ? { ip: m.candidates[0].ip, port: m.candidates[0].port } : undefined;
      ctx.trace("p2p.signal", "app", `시그널링 서버에 "${this.config.name}" 등록됨 (서버가 본 내 바깥 주소 ${this.registered ? ep(this.registered) : "?"}) — 상대의 연결 제안은 이 주소로 온다`, { registered: this.registered ? ep(this.registered) : undefined }, frameId);
      const p = this.pending;
      this.pending = undefined;
      if (p && this.registered) this.connect(p, ctx);
      return true;
    }
    const s = this.session;
    if (m.op === "error") {
      // 서버가 알려 준 오류는 그 상대(m.to)에게 보낸 것에 대한 것 — 이미 버린 시도의 오류로 지금 연결을 끊지 않는다
      if (s && s.peer === m.to && s.phase !== "connected" && s.phase !== "failed") this.fail(s, m.error ?? "시그널링 오류", ctx);
      else ctx.trace("p2p.signal", "app", `지금 연결 중이 아닌 상대 ${m.to ?? "?"} 에 대한 시그널링 오류 → 무시`, {}, frameId);
      return true;
    }
    if (m.to && m.to !== this.config.name) {
      ctx.trace("p2p.signal", "app", `${m.from} 의 ${m.op} 는 "${m.to}" 에게 온 것 (내 이름은 "${this.config.name}") → 무시`, {}, frameId);
      return true;
    }
    if (m.op === "busy") {
      if (s && s.peer === m.from && s.role === "offer" && s.phase !== "connected" && s.phase !== "failed") this.fail(s, `${m.from} 가 다른 상대와 연결 중이라 거절함 (busy)`, ctx);
      return true;
    }
    if (m.op === "offer") return this.onOffer(m, ctx, frameId);
    if (!s || s.peer !== m.from) {
      ctx.trace("p2p.signal", "app", `지금 연결 중이 아닌 상대 ${m.from} 의 ${m.op} → 무시`, {}, frameId);
      return true;
    }
    if (m.op === "answer" && s.role === "offer" && s.phase === "signal") {
      s.theirs = m.candidates ?? [];
      s.theirNat = m.nat;
      ctx.trace("p2p.signal", "app", `${m.from} 의 연결 응답(answer) 받음 (상대 후보 ${s.theirs.map((c) => `${c.type} ${ep(c)}`).join(", ")}${m.nat === "symmetric" ? ", 상대 NAT 는 symmetric" : ""}) → 홀 펀칭 시작`, { peer: m.from }, frameId);
      this.startPunch(s, ctx);
      return true;
    }
    if (m.op === "relay" && s.phase !== "connected") {
      // 상대가 TURN 릴레이 주소를 알려 옴: 거기로 보낸다 (내 NAT 는 내가 보낸 릴레이 주소의 답을 들여보낸다)
      s.theirs = m.candidates ?? [];
      s.phase = "turn";
      ctx.trace("p2p.relay", "app", `${m.from} 가 TURN 릴레이 주소 ${s.theirs.map((c) => ep(c)).join(", ")} 를 알려 옴 → 직접은 안 되니 릴레이로 보낸다`, { peer: m.from }, frameId);
      s.tries = 0;
      this.punch(s, ctx);
      return true;
    }
    return true;
  }

  /** 상대의 연결 제안 */
  private onOffer(m: P2pMessage, ctx: NodeContext, frameId: number): boolean {
    const s = this.session;
    const live = s && s.phase !== "failed";
    if (live && s.peer === m.from) {
      // 동시에 서로 제안함(glare): 이름이 앞선 쪽이 제안 역할을 지키고, 다른 쪽이 응답한다 — 둘 다 응답 역할이 되면 아무도 TURN 을 열지 않는다
      if (s.role === "offer" && (s.phase === "stun" || s.phase === "signal")) {
        if (this.config.name < m.from) {
          ctx.trace("p2p.signal", "app", `${m.from} 도 동시에 나에게 제안함 → 이름이 앞선 내가 제안 역할을 지킨다 (상대가 내 제안에 응답)`, { peer: m.from, glare: true }, frameId);
          return true;
        }
        ctx.trace("p2p.signal", "app", `${m.from} 도 동시에 나에게 제안함 → 이름이 앞선 ${m.from} 의 제안에 응답하고 내 제안은 접는다`, { peer: m.from, glare: true }, frameId);
      } else if (s.role === "answer" && s.phase !== "connected") {
        // 같은 제안이 다시 옴 (내 응답이 사라져 상대가 다시 보냄): 응답을 다시 보낸다
        if (s.mine) this.sendCandidates(s, ctx);
        ctx.trace("p2p.signal", "app", `${m.from} 의 연결 제안을 다시 받음 → ${s.mine ? "응답(answer)을 다시 보냄" : "아직 STUN 중 — 끝나면 응답"}`, { peer: m.from }, frameId);
        return true;
      }
    } else if (live) {
      // 다른 상대와 연결 중(또는 연결됨): 한 번에 한 상대만 — 거절해야 지금 상대가 말없이 버려지지 않는다
      ctx.trace("p2p.signal", "app", `${m.from} 의 연결 제안 → 지금 ${s.peer} 와 ${s.phase === "connected" ? "연결돼 있어" : "연결하는 중이라"} 거절 (busy)`, { peer: m.from, busy: s.peer }, frameId);
      this.toSignal({ kind: "p2p", op: "busy", from: this.config.name, to: m.from }, ctx);
      return true;
    }
    // 상대가 먼저 연결을 제안: 내 후보를 만들어 답하고 홀 펀칭 시작
    const ns = this.newSession(m.from, "answer");
    ns.theirs = m.candidates ?? [];
    ns.theirNat = m.nat;
    ctx.trace("p2p.signal", "app", `${m.from} 의 연결 제안(offer) 받음 (상대 후보 ${(m.candidates ?? []).map((c) => `${c.type} ${ep(c)}`).join(", ")}${m.nat === "symmetric" ? ", 상대 NAT 는 symmetric" : ""}) → 내 바깥 주소를 STUN 으로 확인해 답한다`, { peer: m.from }, frameId);
    this.startStun(ns, ctx);
    return true;
  }

  private startPunch(s: Session, ctx: NodeContext): void {
    s.phase = "punch";
    s.tries = 0;
    this.punch(s, ctx);
  }

  /**
   * 상대 후보로 펀칭 한 번 — PUNCH_INTERVAL 마다 다시. host 후보(상대의 사설 주소)는 같은 NAT 뒤일 때만(바깥 주소가 같음):
   * 집집마다 같은 사설 대역(192.168.0.x)을 써서, 다른 집의 사설 주소는 내 LAN 의 엉뚱한 기기(나 자신일 수도)를 가리킨다.
   * 상대가 NAT 없이 공인 주소를 쓰면(theirNat none) host 후보가 곧 바깥 주소다
   */
  private punch(s: Session, ctx: NodeContext): void {
    const me = this.host.myIp();
    const mySrflx = s.mine?.find((c) => c.type === "srflx")?.ip;
    const theirSrflx = s.theirs?.find((c) => c.type === "srflx")?.ip;
    const sameNat = mySrflx !== undefined && mySrflx === theirSrflx;
    const targets = (s.theirs ?? []).filter((c) => c.type !== "host" || (c.ip !== me && (s.theirNat === "none" || (sameNat && this.host.local(c.ip)))));
    if (targets.length === 0) {
      ctx.trace("p2p.punch", "app", `홀 펀칭: 상대 후보 중 닿을 수 있는 주소가 없음 (사설 주소뿐) → 건너뜀`, { peer: s.peer });
      this.punchExhausted(s, ctx);
      return;
    }
    s.tries++;
    if (s.tries === 1)
      ctx.trace(
        "p2p.punch",
        "app",
        `홀 펀칭: ${targets.map((c) => `${c.type} ${ep(c)}`).join(", ")} 로 UDP 를 보낸다 — 내가 먼저 보내야 내 NAT 가 그 상대에게서 오는 답을 들여보낸다 (상대도 동시에 나에게 보낸다)`,
        { peer: s.peer, targets: targets.map(ep) },
      );
    for (const c of targets) this.sendTo(c, { kind: "p2p", op: "punch", from: this.config.name, to: s.peer, seq: s.tries }, ctx);
    this.arm(s, PUNCH_INTERVAL, "punch", ctx);
  }

  /** 펀칭을 다 했는데 상대에게서 아무것도 안 들어옴: 제안한 쪽은 TURN 으로, 응답한 쪽은 릴레이 알림을 기다린다 */
  private punchExhausted(s: Session, ctx: NodeContext): void {
    if (s.phase === "turn") {
      // 릴레이로 보내는 중이었다: 상대가 릴레이로 답할 때까지 기다린다
      this.arm(s, WAIT * 2, "wait-relay", ctx);
      return;
    }
    if (s.role === "offer") {
      s.phase = "turn";
      s.retries = 0;
      ctx.trace("p2p.relay", "app", `홀 펀칭 ${PUNCH_TRIES}번 동안 상대에게서 아무것도 들어오지 않음 (어느 한쪽 NAT 가 막음 — 대개 symmetric) → TURN 서버 ${TURN_SERVER} 에 릴레이 주소를 요청`, { peer: s.peer });
      this.sendAllocate(s, ctx);
    } else {
      // 응답한 쪽은 상대가 릴레이를 알려 오기를 기다린다
      this.arm(s, WAIT * 3, "wait-relay", ctx);
    }
  }

  private sendAllocate(s: Session, ctx: NodeContext): void {
    this.sendTo({ ip: TURN_SERVER, port: STUN_PORT }, { kind: "stun", op: "allocate-request", txid: ++this.txid }, ctx);
    this.arm(s, WAIT, "turn", ctx);
  }

  /** 상대에게서 온 P2P 메시지 (직접, 또는 TURN 이 전해 준 것 — viaTurn) */
  private onPeer(from: Endpoint, m: P2pMessage, viaTurn: boolean, ctx: NodeContext, frameId: number): boolean {
    const s = this.session;
    if (!s || s.peer !== m.from || s.phase === "failed") {
      ctx.trace("p2p.punch", "app", `모르는 상대 ${m.from} (${ep(from)}) 의 ${m.op} → 무시`, {}, frameId);
      return true;
    }
    if (m.op === "punch") {
      const ack: P2pMessage = { kind: "p2p", op: "punch-ack", from: this.config.name, to: s.peer, seq: m.seq };
      if (viaTurn) this.sendTo({ ip: TURN_SERVER, port: STUN_PORT }, { kind: "stun", op: "send", txid: ++this.txid, peer: from, data: ack }, ctx);
      else this.sendTo(from, ack, ctx);
    }
    if (s.phase === "connected") return true;
    const relay = viaTurn || from.ip === TURN_SERVER;
    s.timer?.cancel();
    s.phase = "connected";
    s.via = relay ? "relay" : "direct";
    s.path = from;
    ctx.trace(
      "p2p.connected",
      "app",
      relay
        ? `P2P 연결됨 (TURN 릴레이 경유): ${s.peer} 와 ${TURN_SERVER} 를 거쳐 주고받는다 — 직접 구멍이 안 뚫려(symmetric NAT 등) 공인 릴레이가 중계한다`
        : `P2P 연결됨 (직접, 홀 펀칭 성공): ${s.peer} 의 ${m.op === "punch" ? "펀칭" : "확인"}이 ${ep(from)} 에서 들어옴 — 서버 없이 두 NAT 사이로 바로 주고받는다`,
      { peer: s.peer, via: s.via, path: ep(from) },
      frameId,
    );
    return true;
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const { token, step, reg, regRetry } = data as { token: number; step: string; reg?: number; regRetry?: boolean };
    if (reg !== undefined) {
      if (reg !== this.regToken || this.registered || !this.regFor || this.regFor !== this.host.myIp() || !this.config.enabled) return;
      if (regRetry) {
        // 배경 재시도: 다시 3번
        this.regTries = 0;
        this.sendRegister(ctx);
      } else if (this.regTries < 3) this.sendRegister(ctx);
      else {
        ctx.trace("p2p.failed", "app", `시그널링 서버 ${SIGNAL_SERVER} 에 등록하지 못함 (응답 없음 3번) — 인터넷에 닿는지 확인. ${REG_RETRY / 1000}초마다 다시 시도`, {});
        if (this.pending) {
          ctx.trace("p2p.failed", "app", `P2P 연결 못 함 (상대 ${this.pending}): 시그널링 서버에 등록되지 않음`, { peer: this.pending });
          this.pending = undefined;
        }
        ctx.timer(REG_RETRY, P2P_TIMER_TAG, { reg: ++this.regToken, regRetry: true }, true);
      }
      return;
    }
    const s = this.session;
    if (!s || s.token !== token || s.phase === "connected" || s.phase === "failed") return;
    if (step === "stun") {
      if (s.retries < RETRIES) {
        s.retries++;
        this.sendStun(s, ctx);
        return;
      }
      const got = s.stunResults.filter(Boolean).length;
      this.fail(s, `STUN 서버 응답 없음 (${got}/${STUN_SERVERS.length}, ${RETRIES}번 다시 보냄) — 인터넷에 닿는지 확인`, ctx);
      return;
    }
    if (step === "signal") {
      if (s.retries < RETRIES) {
        s.retries++;
        this.sendCandidates(s, ctx);
        this.arm(s, WAIT, "signal", ctx);
        return;
      }
      this.fail(s, `상대 ${s.peer} 의 응답(answer)이 오지 않음 — 상대의 P2P 앱이 켜져 있고 인터넷에 닿는지 확인`, ctx);
      return;
    }
    if (step === "punch") {
      if (s.tries < PUNCH_TRIES) return this.punch(s, ctx);
      this.punchExhausted(s, ctx);
      return;
    }
    if (step === "turn") {
      if (s.retries < RETRIES) {
        s.retries++;
        if (s.relay) this.sendRelayNotice(s, ctx);
        else this.sendAllocate(s, ctx);
        return;
      }
      this.fail(s, s.relay ? `TURN 릴레이 주소를 알렸지만 상대가 릴레이로 보내오지 않음` : `TURN 서버 응답 없음`, ctx);
      return;
    }
    if (step === "wait-relay") this.fail(s, `홀 펀칭 실패 (상대에게서 아무것도 들어오지 않음) — 상대가 릴레이를 알려 오지도 않음`, ctx);
  }

  summary(): string | undefined {
    if (!this.config.enabled) return undefined;
    const s = this.session;
    const reg = this.registered ? `등록됨 (${ep(this.registered)})` : "등록 전";
    if (this.pending) return `"${this.config.name}" · ${this.pending} — 등록되면 연결 (${reg})`;
    if (!s) return `"${this.config.name}" · ${reg}`;
    if (s.phase === "connected") return `"${this.config.name}" · ${s.peer} 와 연결됨 (${s.via === "relay" ? "TURN 릴레이" : "직접"}, ${s.path ? ep(s.path) : ""})`;
    if (s.phase === "failed") return `"${this.config.name}" · ${s.peer} 연결 실패 — ${s.reason ?? ""}`;
    return `"${this.config.name}" · ${s.peer} — ${P2P_PHASE_LABEL[s.phase]}`;
  }
}

/** 같은 서브넷인지 (host 후보) — 호스트가 넘겨 주는 도우미 */
export function sameLan(ip: Ip, mine: Ip | undefined, prefix: number): boolean {
  return !!mine && sameSubnet(ip, mine, prefix);
}
