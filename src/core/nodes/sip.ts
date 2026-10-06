// 인터넷 전화 (SIP·RTP) 와 SIP ALG:
// - 전화기는 SIP 서버에 등록하고(REGISTER), 걸 때 INVITE 의 SDP 에 "내 음성은 이 주소:포트로" 를 적는다. 서버는 신호만 전해 주고,
//   음성(RTP)은 두 전화기가 SDP 주소로 직접 보낸다
// - NAT 뒤 전화기는 SDP 에 사설 주소(10.x)를 적는다 → 신호(SIP)는 서버가 보낸 곳(NAT 바깥)으로 답해 주니 통화는 연결되는데, 음성은 사설 주소로 가서 사라진다 (소리가 안 들림)
// - SIP ALG(공유기): 나가는 SIP 의 SDP·Contact 를 공인 주소로 고치고, 그 음성 포트를 받을 NAT 구멍을 미리 연다
// 줄인 것: 인증(401)·SIP over TCP/TLS·re-INVITE·코덱 협상·STUN/ICE·서버 쪽 미디어 중계(RTP 프록시), 통화 중 대기음
import type { Ip } from "../addr";
import { SIP_PORT, SIP_SERVER, type Endpoint, type Ipv4Packet, type RtpPacket, type SipMessage, type UdpPacket } from "../packet";
import type { NodeContext } from "./node";

export const SIP_TIMER_TAG = "sip";
const WAIT = 1500;
const RTP_PACKETS = 5;
const RTP_INTERVAL = 20;
/** 음성을 다 보낸 뒤 끊기까지 */
const HANGUP_AFTER = 400;
/** 등록 갱신 (배경 타이머 — 공유기 공인 주소가 바뀌어도 서버가 새 주소를 배우게. 실제 전화기는 등록 만료 전·NAT keepalive 로) */
const REREGISTER = 60_000;
/** 등록이 3번 실패한 뒤 다시 시도 (배경 타이머) */
const REG_RETRY = 10_000;
/** 통화 중 이만큼 아무것도 오지 않으면 끊는다 (RTP timeout — BYE 가 사라진 통화가 영영 남지 않게, 배경 타이머) */
const RTP_TIMEOUT = 30_000;

export const CALL_STATE_LABEL: Record<SipCall["state"], string> = { calling: "거는 중", ringing: "벨 울림", talking: "통화 중", ended: "끝남", failed: "실패" };

export interface SipPhoneConfig {
  enabled: boolean;
  user: string;
}

export interface SipIo {
  myIp(): Ip | undefined;
  send(pkt: Ipv4Packet, ctx: NodeContext): void;
}

export interface SipCall {
  callId: string;
  role: "caller" | "callee";
  peer: string;
  state: "calling" | "ringing" | "talking" | "ended" | "failed";
  /** 상대가 SDP 로 알려 준 음성 주소 */
  remote?: Endpoint;
  sent: number;
  received: number;
  reason?: string;
  startedAt: number;
  /** 보낸 BYE 의 200 을 받았음 */
  byeAcked?: boolean;
  /** 마지막으로 상대에게서 무언가(음성·신호) 받은 시각 */
  lastHeard?: number;
}

const isPrivate = (ip: Ip) => {
  const [a, b] = ip.split(".").map(Number) as [number, number];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
};

export class SipPhone {
  config: SipPhoneConfig = { enabled: false, user: "" };
  registered = false;
  readonly calls: SipCall[] = [];
  private regTok = 0;
  private regTries = 0;
  private regFailed = false;
  private cseq = 1;
  private callSeq = 0;

  constructor(
    private readonly io: SipIo,
    /** 음성(RTP) 포트 (장치마다 고정) */
    readonly rtpPort: number,
  ) {}

  setConfig(cfg: SipPhoneConfig, ctx: NodeContext): void {
    if (cfg.enabled === this.config.enabled && cfg.user === this.config.user) return;
    // 옛 이름의 등록을 해제한다 (Expires: 0) — 아니면 서버가 옛 이름으로 온 전화를 계속 이 기기로 넘긴다
    if (this.registered && this.config.user) {
      ctx.trace("sip.register", "app", `인터넷 전화: ${this.config.user} 등록 해제 (REGISTER Expires: 0)`, { sip: true });
      this.send({ kind: "sip", method: "REGISTER", callId: `reg-${this.config.user}`, from: this.config.user, to: this.config.user, cseq: this.cseq++, expires: 0 }, ctx);
    }
    for (const c of this.calls) if (c.state !== "ended" && c.state !== "failed") this.end(c, ctx, undefined, "전화기 설정 변경");
    this.config = { ...cfg };
    this.registered = false;
    this.regTok++;
    if (cfg.enabled) this.register(ctx);
  }

  private send(m: SipMessage, ctx: NodeContext, to: Endpoint = { ip: SIP_SERVER, port: SIP_PORT }): void {
    const me = this.io.myIp();
    if (!me) return;
    this.io.send({ kind: "ipv4", src: me, dst: to.ip, ttl: 64, payload: { kind: "udp", srcPort: SIP_PORT, dstPort: to.port, payload: m } }, ctx);
  }

  /** 주소를 얻음 */
  onAddress(ctx: NodeContext): void {
    if (this.config.enabled && !this.registered) this.register(ctx);
  }

  /** 주소를 잃음 (링크 다운 등): 등록이 무효가 되고, 진행 중 통화는 끝난다 */
  lost(ctx?: NodeContext): void {
    this.registered = false;
    this.regTok++;
    if (ctx) for (const c of this.calls) if (c.state !== "ended" && c.state !== "failed") this.end(c, ctx, undefined, "연결이 끊김");
  }

  private register(ctx: NodeContext): void {
    const me = this.io.myIp();
    if (!me || !this.config.user) return;
    this.regTries = 1;
    this.regFailed = false;
    const tok = ++this.regTok;
    ctx.trace("sip.register", "app", `인터넷 전화: SIP 서버 ${SIP_SERVER} 에 ${this.config.user} 로 등록 (Contact ${me}:${SIP_PORT} — 나에게 연락할 주소)`, { sip: true });
    this.send({ kind: "sip", method: "REGISTER", callId: `reg-${this.config.user}`, from: this.config.user, to: this.config.user, cseq: this.cseq++, contact: { ip: me, port: SIP_PORT } }, ctx);
    ctx.timer(WAIT, SIP_TIMER_TAG, { sip: "register", tok });
  }

  /** 전화 걸기 */
  call(to: string, ctx: NodeContext): void {
    const me = this.io.myIp();
    if (!this.config.enabled || !me) {
      ctx.trace("sip.call", "app", `인터넷 전화가 꺼져 있거나 주소가 없어 걸 수 없음`, { sip: true });
      return;
    }
    if (!this.registered) {
      ctx.trace("sip.call", "app", `아직 SIP 서버에 등록되지 않아 걸 수 없음 (인터넷 연결 확인) → 지금 다시 등록`, { sip: true });
      this.register(ctx);
      return;
    }
    const callId = `${this.config.user}-${++this.callSeq}`;
    this.calls.push({ callId, role: "caller", peer: to, state: "calling", sent: 0, received: 0, startedAt: ctx.now });
    if (this.calls.length > 10) this.calls.shift();
    ctx.trace("sip.call", "app", `인터넷 전화: ${to} 에게 전화 (INVITE) — SDP 에 "내 음성은 ${me}:${this.rtpPort} 로" 를 적음${isPrivate(me) ? " (사설 주소 — NAT 뒤라 상대는 여기로 보낼 수 없다)" : ""}`, { sip: true, callId });
    this.send({ kind: "sip", method: "INVITE", callId, from: this.config.user, to, cseq: this.cseq++, contact: { ip: me, port: SIP_PORT }, sdp: { ip: me, port: this.rtpPort } }, ctx);
    ctx.timer(WAIT * 2, SIP_TIMER_TAG, { sip: "invite", callId });
  }

  /** 내 SIP 포트로 온 것 (서버가 전해 준 신호) */
  handle(pkt: Ipv4Packet, udp: UdpPacket, m: SipMessage, ctx: NodeContext, frameId: number): void {
    if (!this.config.enabled) return;
    const call = this.calls.find((c) => c.callId === m.callId);
    if (m.status === 200 && m.callId.startsWith("reg-")) {
      if (m.callId !== `reg-${this.config.user}`) return; // 해제한 옛 이름의 답
      if (!this.registered) {
        ctx.trace("sip.register", "app", `인터넷 전화: 등록됨 (${this.config.user}@voip.example) — 서버는 이 등록이 온 주소(NAT 바깥)로 전화를 넘겨 준다. ${REREGISTER / 1000}초마다 갱신`, { sip: true }, frameId);
        ctx.timer(REREGISTER, SIP_TIMER_TAG, { sip: "refresh", tok: this.regTok }, true);
      }
      this.registered = true;
      return;
    }
    if (m.method === "INVITE" && m.to !== this.config.user) {
      ctx.trace("sip.call", "app", `인터넷 전화: ${m.to} 앞으로 온 전화 — 내 이름(${this.config.user})이 아님 → 404`, { sip: true }, frameId);
      this.send({ kind: "sip", status: 404, callId: m.callId, from: m.from, to: m.to, cseq: m.cseq }, ctx, { ip: pkt.src, port: udp.srcPort });
      return;
    }
    if (m.method === "INVITE") {
      const c: SipCall = { callId: m.callId, role: "callee", peer: m.from, state: "ringing", ...(m.sdp ? { remote: { ...m.sdp } } : {}), sent: 0, received: 0, startedAt: ctx.now };
      this.calls.push(c);
      if (this.calls.length > 10) this.calls.shift();
      const me = this.io.myIp()!;
      ctx.trace("sip.call", "app", `인터넷 전화: ${m.from} 에게서 전화 옴 (상대 음성 주소 ${m.sdp ? `${m.sdp.ip}:${m.sdp.port}` : "?"}) → 받음 (180 Ringing → 200 OK, SDP 에 "내 음성은 ${me}:${this.rtpPort} 로")`, { sip: true, callId: m.callId }, frameId);
      const back = { ip: pkt.src, port: udp.srcPort };
      this.send({ kind: "sip", status: 180, callId: m.callId, from: m.from, to: m.to, cseq: m.cseq }, ctx, back);
      this.send({ kind: "sip", status: 200, callId: m.callId, from: m.from, to: m.to, cseq: m.cseq, contact: { ip: me, port: SIP_PORT }, sdp: { ip: me, port: this.rtpPort } }, ctx, back);
      return;
    }
    if (!call) return;
    if (m.status === 180) {
      call.state = "ringing";
      ctx.trace("sip.call", "app", `인터넷 전화: ${call.peer} 쪽에서 벨이 울림 (180 Ringing)`, { sip: true }, frameId);
      return;
    }
    if (m.status === 404 || m.status === 486) {
      call.state = "failed";
      call.reason = m.status === 486 ? `자기 자신에게는 걸 수 없음 (486 Busy Here)` : `${call.peer} 는 등록돼 있지 않음 (404)`;
      ctx.trace("sip.call", "app", `인터넷 전화: ${call.reason}`, { sip: true, failed: true }, frameId);
      return;
    }
    if (m.status === 200 && m.cseq !== -1 && call.state !== "talking" && call.role === "caller" && m.sdp) {
      call.state = "talking";
      call.remote = { ...m.sdp };
      ctx.trace("sip.call", "app", `인터넷 전화: ${call.peer} 가 받음 (200 OK, 상대 음성 주소 ${m.sdp.ip}:${m.sdp.port}) → ACK, 통화 시작 — 음성은 서버를 거치지 않고 그 주소로 직접`, { sip: true, callId: call.callId }, frameId);
      this.send({ kind: "sip", method: "ACK", callId: call.callId, from: this.config.user, to: call.peer, cseq: m.cseq }, ctx);
      this.startRtp(call, ctx);
      return;
    }
    if (m.method === "ACK" && call.role === "callee" && call.state === "ringing") {
      call.state = "talking";
      ctx.trace("sip.call", "app", `인터넷 전화: ACK — 통화 시작, 음성을 ${call.remote ? `${call.remote.ip}:${call.remote.port}` : "?"} 로 보냄`, { sip: true, callId: call.callId }, frameId);
      this.startRtp(call, ctx);
      return;
    }
    if (m.method === "BYE") {
      this.end(call, ctx, frameId, `${call.peer} 가 끊음`);
      this.send({ kind: "sip", status: 200, callId: call.callId, from: m.from, to: m.to, cseq: -1 }, ctx, { ip: pkt.src, port: udp.srcPort });
      return;
    }
    if (m.status === 200 && m.cseq === -1) call.byeAcked = true;
  }

  /** 내 음성 포트로 온 RTP */
  handleRtp(m: RtpPacket, ctx: NodeContext, frameId: number): void {
    const call = this.calls.find((c) => c.callId === m.callId);
    if (!call || call.state === "ended" || call.state === "failed") return;
    call.received++;
    call.lastHeard = ctx.now;
    if (call.received === 1) ctx.trace("sip.rtp", "app", `인터넷 전화: ${call.peer} 의 음성이 들림 (RTP 도착)`, { sip: true, callId: call.callId }, frameId);
  }

  private startRtp(call: SipCall, ctx: NodeContext): void {
    call.lastHeard = ctx.now;
    ctx.timer(RTP_TIMEOUT, SIP_TIMER_TAG, { sip: "idle", callId: call.callId }, true);
    this.rtpStep(call.callId, 1, ctx);
  }

  private rtpStep(callId: string, seq: number, ctx: NodeContext): void {
    const call = this.calls.find((c) => c.callId === callId);
    const me = this.io.myIp();
    if (!call || call.state !== "talking" || !call.remote || !me) return;
    call.sent++;
    const m: RtpPacket = { kind: "rtp", callId, seq, from: this.config.user };
    this.io.send({ kind: "ipv4", src: me, dst: call.remote.ip, ttl: 64, payload: { kind: "udp", srcPort: this.rtpPort, dstPort: call.remote.port, payload: m } }, ctx);
    if (seq < RTP_PACKETS) ctx.timer(RTP_INTERVAL, SIP_TIMER_TAG, { sip: "rtp", callId, seq: seq + 1 });
    else if (call.role === "caller") ctx.timer(HANGUP_AFTER, SIP_TIMER_TAG, { sip: "hangup", callId });
  }

  private end(call: SipCall, ctx: NodeContext, frameId: number | undefined, why: string): void {
    if (call.state === "ended") return;
    call.state = "ended";
    const heard = call.received > 0;
    call.reason = heard ? undefined : `상대 소리가 안 들림 — 상대가 알려 준 음성 주소 ${call.remote ? `${call.remote.ip}:${call.remote.port}` : "?"}${call.remote && isPrivate(call.remote.ip) ? " 는 사설 주소라 상대의 음성이 거기로 가서 사라짐 (SIP ALG·STUN·서버 중계가 필요)" : " 에서 음성이 오지 않음"}`;
    ctx.trace("sip.call", "app", `인터넷 전화: 통화 끝 (${why}) — 보낸 음성 ${call.sent} · 받은 음성 ${call.received}${heard ? "" : ` → ${call.reason}`}`, { sip: true, callId: call.callId, failed: !heard }, frameId);
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const d = data as { sip?: string; tok?: number; callId?: string; seq?: number; tries?: number };
    if (d.sip === "refresh" || d.sip === "retry") {
      if (d.tok !== this.regTok || !this.config.enabled) return;
      if (d.sip === "retry" && this.registered) return;
      const me = this.io.myIp();
      if (me) this.send({ kind: "sip", method: "REGISTER", callId: `reg-${this.config.user}`, from: this.config.user, to: this.config.user, cseq: this.cseq++, contact: { ip: me, port: SIP_PORT } }, ctx);
      ctx.timer(d.sip === "refresh" ? REREGISTER : REG_RETRY, SIP_TIMER_TAG, { sip: d.sip, tok: d.tok }, true);
      return;
    }
    if (d.sip === "register") {
      if (d.tok !== this.regTok || this.registered) return;
      if (this.regTries > 2) {
        this.regFailed = true;
        ctx.trace("sip.register", "app", `인터넷 전화: SIP 서버 응답 없음 (3번) — 인터넷 연결을 확인. ${REG_RETRY / 1000}초마다 다시 시도 (시간이 흐를 때만)`, { sip: true, failed: true });
        ctx.timer(REG_RETRY, SIP_TIMER_TAG, { sip: "retry", tok: d.tok }, true);
        return;
      }
      this.regTries++;
      const me = this.io.myIp();
      if (!me) return;
      this.send({ kind: "sip", method: "REGISTER", callId: `reg-${this.config.user}`, from: this.config.user, to: this.config.user, cseq: this.cseq++, contact: { ip: me, port: SIP_PORT } }, ctx);
      ctx.timer(WAIT, SIP_TIMER_TAG, { sip: "register", tok: d.tok });
      return;
    }
    const call = this.calls.find((c) => c.callId === d.callId);
    if (!call) return;
    if (d.sip === "invite" && call.state === "calling") {
      call.state = "failed";
      call.reason = "응답 없음 (SIP 서버 또는 상대에게 닿지 않음)";
      ctx.trace("sip.call", "app", `인터넷 전화: ${call.peer} 에게 건 전화 ${call.reason}`, { sip: true, failed: true });
      return;
    }
    if (d.sip === "rtp") this.rtpStep(call.callId, d.seq!, ctx);
    if (d.sip === "idle" && call.state === "talking") {
      const quiet = ctx.now - (call.lastHeard ?? call.startedAt);
      if (quiet < RTP_TIMEOUT) ctx.timer(RTP_TIMEOUT - quiet, SIP_TIMER_TAG, { sip: "idle", callId: call.callId }, true);
      else this.end(call, ctx, undefined, `${RTP_TIMEOUT / 1000}초 동안 상대에게서 아무것도 오지 않음 (RTP timeout — BYE 가 사라졌을 수 있음)`);
    }
    if (d.sip === "hangup" && call.state === "talking") {
      this.send({ kind: "sip", method: "BYE", callId: call.callId, from: this.config.user, to: call.peer, cseq: this.cseq++ }, ctx);
      this.end(call, ctx, undefined, "내가 끊음 (BYE)");
      ctx.timer(WAIT, SIP_TIMER_TAG, { sip: "bye", callId: call.callId, tries: 1 });
    }
    // BYE 의 200 이 없으면 다시 보낸다 (2번 — SIP Timer E 축소판)
    if (d.sip === "bye" && !call.byeAcked && (d.tries ?? 1) <= 2) {
      ctx.trace("sip.call", "app", `인터넷 전화: BYE 의 200 OK 가 없음 → 다시 보냄 (${(d.tries ?? 1) + 1}/3)`, { sip: true });
      this.send({ kind: "sip", method: "BYE", callId: call.callId, from: this.config.user, to: call.peer, cseq: this.cseq++ }, ctx);
      ctx.timer(WAIT, SIP_TIMER_TAG, { sip: "bye", callId: call.callId, tries: (d.tries ?? 1) + 1 });
    }
  }

  summary(): string | undefined {
    if (!this.config.enabled) return undefined;
    const last = this.calls.at(-1);
    return `${this.registered ? `등록됨 · ${this.config.user}@voip.example` : this.regFailed ? "등록 실패 (10초마다 다시)" : "등록 중"}${last ? ` · 마지막 통화 ${last.peer}: ${last.state === "ended" ? `받은 음성 ${last.received}/${RTP_PACKETS}` : CALL_STATE_LABEL[last.state]}` : ""}`;
  }
}

// ---------- SIP 서버 (인터넷 노드) ----------

export class SipServer {
  /** 사용자 → 등록 (Contact 헤더, 실제로 온 주소) */
  readonly users = new Map<string, { contact?: Endpoint; at: Endpoint }>();
  /** 통화 → 양쪽의 실제 주소 */
  private readonly calls = new Map<string, { caller: Endpoint; callee: Endpoint }>();

  constructor(private readonly send: (to: Endpoint, m: SipMessage, ctx: NodeContext) => void) {}

  handle(pkt: Ipv4Packet, srcPort: number, m: SipMessage, ctx: NodeContext, frameId: number): void {
    const from: Endpoint = { ip: pkt.src, port: srcPort };
    if (m.method === "REGISTER" && m.expires === 0) {
      this.users.delete(m.from);
      ctx.trace("sip.server", "app", `SIP 서버: ${m.from} 등록 해제`, { user: m.from }, frameId);
      this.send(from, { kind: "sip", status: 200, callId: m.callId, from: m.from, to: m.to, cseq: m.cseq }, ctx);
      return;
    }
    if (m.method === "REGISTER") {
      // 실제로 온 주소(received·rport)를 기억한다 — Contact 의 사설 주소로는 연락할 수 없다
      this.users.set(m.from, { ...(m.contact ? { contact: m.contact } : {}), at: from });
      ctx.trace("sip.server", "app", `SIP 서버: ${m.from} 등록 — Contact 는 ${m.contact ? `${m.contact.ip}:${m.contact.port}` : "?"} 이지만 실제로 온 곳은 ${from.ip}:${from.port}${m.contact && m.contact.ip !== from.ip ? " (NAT 바깥) → 이 주소로 연락한다 (received·rport)" : ""}`, { user: m.from }, frameId);
      this.send(from, { kind: "sip", status: 200, callId: m.callId, from: m.from, to: m.to, cseq: m.cseq }, ctx);
      return;
    }
    if (m.method === "INVITE" && m.to === m.from) {
      ctx.trace("sip.server", "app", `SIP 서버: ${m.from} 가 자기 자신에게 전화 → 486 Busy Here`, { to: m.to }, frameId);
      this.send(from, { kind: "sip", status: 486, callId: m.callId, from: m.from, to: m.to, cseq: m.cseq }, ctx);
      return;
    }
    if (m.method === "INVITE") {
      const callee = this.users.get(m.to);
      if (!callee) {
        ctx.trace("sip.server", "app", `SIP 서버: ${m.to} 는 등록돼 있지 않음 → ${m.from} 에게 404`, { to: m.to }, frameId);
        this.send(from, { kind: "sip", status: 404, callId: m.callId, from: m.from, to: m.to, cseq: m.cseq }, ctx);
        return;
      }
      this.calls.set(m.callId, { caller: from, callee: callee.at });
      ctx.trace("sip.server", "app", `SIP 서버: ${m.from} → ${m.to} INVITE 를 ${callee.at.ip}:${callee.at.port} 로 전해 줌 — SDP(음성 주소 ${m.sdp ? `${m.sdp.ip}:${m.sdp.port}` : "?"})는 건드리지 않는다 (서버는 신호만 나른다)`, { callId: m.callId }, frameId);
      this.send(callee.at, m, ctx);
      return;
    }
    const call = this.calls.get(m.callId);
    if (!call) return;
    // 응답·ACK·BYE 는 반대편으로
    const toCaller = from.ip === call.callee.ip && from.port === call.callee.port;
    const to = toCaller ? call.caller : call.callee;
    ctx.trace("sip.server", "app", `SIP 서버: ${m.status ? `${m.status}` : m.method} 를 ${toCaller ? "건 쪽" : "받는 쪽"} ${to.ip}:${to.port} 로 전해 줌`, { callId: m.callId }, frameId);
    this.send(to, m, ctx);
    // BYE 의 200 까지 넘긴 뒤 통화를 잊는다 (BYE 때 지우면 그 200 을 건 쪽에 넘기지 못한다)
    if (m.status === 200 && m.cseq === -1) this.calls.delete(m.callId);
  }

  rows(): string[][] {
    return [...this.users.entries()].map(([u, r]) => [u, r.contact ? `${r.contact.ip}:${r.contact.port}` : "—", `${r.at.ip}:${r.at.port}`]);
  }
}

// ---------- SIP ALG (공유기) ----------

/**
 * 나가는 SIP 의 SDP·Contact 를 공인 주소로 고치고, 음성 포트를 받을 NAT 구멍을 연다.
 * pinhole(lanIp, port) → 공인 포트. 고친 메시지를 돌려준다 (고칠 게 없으면 그대로)
 */
export function sipAlgRewrite(m: SipMessage, lanIp: Ip, publicIp: Ip, publicSipPort: number, pinhole: (lanIp: Ip, port: number) => number): SipMessage {
  let out: SipMessage = m;
  if (m.contact && m.contact.ip === lanIp) out = { ...out, contact: { ip: publicIp, port: publicSipPort } };
  if (m.sdp && m.sdp.ip === lanIp) {
    const port = pinhole(lanIp, m.sdp.port);
    out = { ...out, sdp: { ip: publicIp, port }, alg: { ...m.sdp } };
  }
  return out;
}
