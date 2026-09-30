// 로드밸런서 (리버스 프록시, L7): nginx·HAProxy·클라우드 ALB 가 흔히 쓰는 방식.
// 클라이언트는 LB 주소로 접속하고, LB 가 백엔드 하나를 골라 "자기가 대신" 연결해 요청한 뒤 받은 응답을 돌려준다.
// 백엔드 입장에서 클라이언트는 LB 다. 서버의 서비스 토글(Host)과 로드밸런서 전용 장비가 이 모듈을 함께 쓴다.
//
// 헬스 체크는 패시브(nginx 의 max_fails/fail_timeout 방식): 백엔드가 거부(RST)하거나 timeout 이면 10초 동안 빼고
// 곧바로 다음 백엔드로 다시 보낸다. 누군가 실패를 겪어야 안다.
// 액티브 헬스 체크(설정 healthCheck, 기본 꺼짐 — HAProxy "check inter 2s fall 3 rise 2"): 2초마다 백엔드에 TCP 로 연결해 보고,
// 3번 연속 실패면 DOWN(요청을 보내지 않음), 2번 연속 성공이면 UP. 요청이 오기 전에 죽은 백엔드를 뺀다.
// 주기는 배경 타이머라 시계를 스스로 움직이지 않는다 — 요청이 오가거나 "+N초" 로 시간이 흐를 때만 돈다.
//
// L4 모드 (LVS FULLNAT·클라우드 NLB 식): 연결을 끊어 잇지 않고 패킷의 주소·포트만 바꿔 넘긴다.
//   클라이언트 → LB:포트  ⇒  LB:변환 포트 → 백엔드:포트   (돌아올 때 반대로)
//   TCP 연결은 클라이언트와 백엔드 사이 하나뿐이고, LB 는 HTTP 내용을 보지 않는다(그래서 SSH 등 무엇이든 나눈다).
//   대신 요청 단위로 다시 고르거나 응답 상태를 볼 수 없다 — 백엔드가 RST 로 거부할 때만 빼 둔다.
// 세션 고정: 출발지 IP (두 모드 공통) — 같은 출발지 IP 는 살아 있는 한 같은 백엔드로 (소스 IP 어피니티).
//   NAT·프록시 뒤의 여러 사람은 한 주소로 보여 모두 한 백엔드로 몰린다.
// 쿠키 (L7 만, HAProxy "cookie SERVERID insert" 식) — 첫 응답에 Set-Cookie: SERVERID=<백엔드> 를 넣고, 브라우저가 다음 요청에
//   실어 보내는 Cookie 로 같은 백엔드를 고른다. 주소가 아니라 브라우저마다라 NAT 뒤에서도 사람별로 나뉜다. L4 는 HTTP 를 보지 않아 못 쓴다.
import type { Ip } from "../addr";
import type { Ipv4Packet, TcpSegment } from "../packet";
import type { NodeContext } from "./node";
import { responseBytes, type TcpConn, type TcpStack } from "./tcp";

export type LbAlgorithm = "round-robin" | "least-conn";
export type LbMode = "l7" | "l4";
export const LB_MODE_LABEL: Record<LbMode, string> = { l7: "L7 프록시", l4: "L4 주소 변환" };

export const LB_ALGORITHM_LABEL: Record<LbAlgorithm, string> = {
  "round-robin": "라운드 로빈",
  "least-conn": "최소 연결",
};

export interface LbBackend {
  ip: Ip;
  port: number;
}

export interface LbConfig {
  enabled: boolean;
  /** 클라이언트가 접속하는 포트 (LB 가 듣는 포트) */
  port: number;
  algorithm: LbAlgorithm;
  backends: LbBackend[];
  /** 없으면 L7 (리버스 프록시) */
  mode?: LbMode;
  /** 세션 고정: "ip" 같은 출발지 IP 는 같은 백엔드로, "cookie" 응답에 넣은 쿠키로 (L7 만) */
  sticky?: LbSticky;
  /** 액티브 헬스 체크: 2초마다 TCP 연결로 확인, 3번 실패면 DOWN, 2번 성공이면 UP (배경 타이머) */
  healthCheck?: boolean;
}

/** 액티브 헬스 체크 간격·판정 (HAProxy 기본값 inter 2s, fall 3, rise 2). 체크의 timeout 은 간격과 같다 */
export const LB_CHECK_INTERVAL = 2000;
export const LB_CHECK_FALL = 3;
export const LB_CHECK_RISE = 2;
export const LB_CHECK_TAG = "lb-check";

/** 백엔드 하나의 액티브 헬스 체크 상태 */
interface CheckState {
  down: boolean;
  /** 지금 방향의 연속 횟수 (UP 이면 실패, DOWN 이면 성공) */
  streak: number;
  /** 마지막 실패 이유 */
  reason?: string;
}

export type LbSticky = "ip" | "cookie";
export const LB_STICKY_LABEL: Record<LbSticky, string> = { ip: "세션 고정 (출발지 IP)", cookie: "세션 고정 (쿠키)" };
/** 쿠키 세션 고정에 쓰는 쿠키 이름 (HAProxy 예제의 관례) */
export const LB_COOKIE = "SERVERID";
/** Cookie 헤더에서 이 LB 의 쿠키가 가리키는 백엔드 "주소:포트" */
function cookieBackend(cookie: string | undefined): string | undefined {
  return cookie ? new RegExp(`(?:^|;\\s*)${LB_COOKIE}=([^;]+)`).exec(cookie)?.[1] : undefined;
}

export const DEFAULT_LB: LbConfig = { enabled: false, port: 80, algorithm: "round-robin", backends: [] };
/** 실패한 백엔드를 빼 두는 시간 (nginx fail_timeout 기본값 10초) */
export const LB_FAIL_TIMEOUT = 10_000;
/** 살아 있는 백엔드가 하나도 없을 때 돌려주는 응답 */
const BAD_GATEWAY = { len: 200, data: "HTTP 502 Bad Gateway" };
/** 요청이 로드밸런서를 이만큼 거쳤으면 순환 구성으로 보고 끊는다 (LB 끼리 서로를 백엔드로 둔 경우) */
export const LB_MAX_HOPS = 5;
const LOOP_DETECTED = { len: 200, data: "HTTP 508 Loop Detected" };
const METHOD_NOT_ALLOWED = { len: 200, data: "HTTP 405 Method Not Allowed" };
const RESPONSE_SEGMENT_BYTES = 1000;

const keyOf = (b: LbBackend) => `${b.ip}:${b.port}`;
/** L4 모드에서 백엔드 쪽으로 쓰는 변환 포트 */
const L4_PORT_START = 50000;

/** L4 모드의 흐름 하나 (클라이언트 연결 ↔ 백엔드 쪽 변환 포트) */
interface L4Flow {
  clientIp: Ip;
  clientPort: number;
  backend: LbBackend;
  natPort: number;
  finFromClient: boolean;
  finFromBackend: boolean;
  createdAt: number;
  /** 백엔드의 SYN·ACK 를 넘겼는지 (못 봤는데 SYN 이 다시 오면 그 백엔드가 응답하지 않는 것) */
  synAckSeen: boolean;
  /** 끝난 시각 (양쪽 FIN 뒤 마지막 ACK, 또는 RST). TIME_WAIT 동안 남겨 두어 늦게 온 재전송도 넘긴다 */
  closedAt?: number;
}

/** 끝난 흐름을 남겨 두는 시간 (늦게 온 FIN·ACK 재전송을 넘기려고, TIME_WAIT 흉내) */
const L4_TIME_WAIT = 2000;
const L4_MAX_FLOWS = 256;

interface Pending {
  /** 클라이언트 쪽 연결 (응답을 기다리는 중) */
  down: TcpConn;
  backend: LbBackend;
  /** 이번 요청에서 이미 시도한 백엔드 */
  tried: Set<string>;
}

export interface LbStats {
  served: number;
  fails: number;
}

export class LoadBalancer {
  config: LbConfig = { ...DEFAULT_LB, backends: [] };
  private rr = 0;
  /** 빼 둔 백엔드 → 다시 넣을 시각 */
  private readonly downUntil = new Map<string, number>();
  readonly stats = new Map<string, LbStats>();
  /** 백엔드로 보낸 연결 id → 기다리는 클라이언트 연결 */
  private readonly pending = new Map<string, Pending>();
  /** 세션 고정: 클라이언트 IP → 백엔드 */
  private readonly affinity = new Map<Ip, string>();
  /** L4: "클라이언트IP:포트" → 흐름, 변환 포트 → 흐름 */
  private readonly flows = new Map<string, L4Flow>();
  private readonly byNatPort = new Map<number, L4Flow>();
  private nextNatPort = L4_PORT_START;
  /** 액티브 헬스 체크: 백엔드 → 상태 */
  private readonly checkState = new Map<string, CheckState>();
  /** 진행 중인 체크 연결 id → 백엔드 */
  private readonly checking = new Map<string, { key: string; conn: TcpConn }>();
  /** 지금 유효한 체크 라운드 타이머 번호 */
  private checkRound: number | undefined;
  private checkToken = 0;

  constructor(
    private readonly tcp: TcpStack,
    /** LB 가 백엔드로 연결할 때 쓸 내 주소 */
    private readonly localIp: () => Ip | undefined,
  ) {}

  setConfig(cfg: LbConfig, ctx: NodeContext): void {
    const same = JSON.stringify(cfg) === JSON.stringify(this.config);
    this.config = { ...cfg, backends: cfg.backends.map((b) => ({ ...b })) };
    if (same) return;
    // 설정에 남은 백엔드의 상태·고정·흐름은 유지한다 (세션 고정만 켰는데 열린 연결이 끊기면 안 된다)
    const kept = new Set(cfg.backends.map(keyOf));
    for (const k of [...this.downUntil.keys()]) if (!kept.has(k)) this.downUntil.delete(k);
    for (const k of [...this.checkState.keys()]) if (!kept.has(k) || !cfg.healthCheck) this.checkState.delete(k);
    if (!cfg.enabled || !cfg.healthCheck) this.checkRound = undefined;
    for (const [ip, k] of [...this.affinity]) if (!kept.has(k) || cfg.sticky !== "ip") this.affinity.delete(ip);
    for (const f of [...this.flows.values()]) if (cfg.mode !== "l4" || !kept.has(keyOf(f.backend))) this.dropFlow(f);
    ctx.trace(
      "lb.config",
      "sys",
      cfg.enabled
        ? `로드밸런서 켜짐 (${LB_MODE_LABEL[cfg.mode ?? "l7"]}${cfg.sticky ? `, ${LB_STICKY_LABEL[cfg.sticky]}` : ""}${cfg.healthCheck ? `, 액티브 헬스 체크 ${LB_CHECK_INTERVAL / 1000}초` : ""}): 포트 ${cfg.port} 로 온 ${cfg.mode === "l4" ? "연결" : "요청"}을 ${LB_ALGORITHM_LABEL[cfg.algorithm]} 로 백엔드 ${cfg.backends.length}대(${cfg.backends.map(keyOf).join(", ") || "없음"})에 나눔`
        : "로드밸런서 꺼짐",
      { ...cfg },
    );
  }

  /** 이 서버 연결을 LB 가 맡는지 (L7: LB 포트로 온 연결) */
  handles(conn: TcpConn): boolean {
    return this.config.enabled && this.config.mode !== "l4" && conn.role === "server" && conn.localPort === this.config.port;
  }

  /** 지금 살아 있는 것으로 보는 백엔드 (패시브로 빼 두지 않았고, 액티브 체크로 DOWN 이 아님) */
  isUp(b: LbBackend, now: number): boolean {
    return (this.downUntil.get(keyOf(b)) ?? -Infinity) <= now && !this.checkState.get(keyOf(b))?.down;
  }

  // ---------- 액티브 헬스 체크 ----------

  /** 체크가 켜져 있는데 돌고 있지 않으면 다음 라운드를 건다 (링크 연결·설정 변경 때) */
  ensureChecks(ctx: NodeContext): void {
    if (!this.config.enabled || !this.config.healthCheck || this.checkRound !== undefined) return;
    this.scheduleRound(ctx);
  }

  private scheduleRound(ctx: NodeContext): void {
    this.checkRound = ++this.checkToken;
    ctx.timer(LB_CHECK_INTERVAL, LB_CHECK_TAG, { round: this.checkRound }, true);
  }

  /** 체크 라운드: 지난 체크 중 답이 없던 것은 timeout, 백엔드마다 새로 연결해 본다 */
  onTimer(data: unknown, ctx: NodeContext): void {
    if ((data as { round: number }).round !== this.checkRound) return;
    this.checkRound = undefined;
    if (!this.config.enabled || !this.config.healthCheck) return;
    for (const [id, c] of [...this.checking]) {
      this.checking.delete(id);
      this.result(c.key, false, `${LB_CHECK_INTERVAL / 1000}초 동안 응답 없음 (Layer4 timeout)`, ctx);
      this.tcp.abandon(c.conn, "헬스 체크 timeout", ctx);
    }
    const me = this.localIp();
    if (me) {
      for (const b of this.config.backends) {
        const key = keyOf(b);
        this.tcp.connect(me, b.ip, b.port, ctx, { probe: true, onCreated: (conn) => this.checking.set(conn.id, { key, conn }) });
      }
    }
    this.scheduleRound(ctx);
  }

  /** 체크 연결이 맺어짐: 성공으로 세고 닫는다. 체크 연결이었으면 true */
  onEstablished(conn: TcpConn, ctx: NodeContext): boolean {
    const c = this.checking.get(conn.id);
    if (!c) return false;
    this.checking.delete(conn.id);
    this.result(c.key, true, "", ctx);
    this.tcp.disconnect(conn.id, ctx);
    return true;
  }

  /** 체크 한 번의 결과를 세어 DOWN·UP 을 정한다. 알리는 것은 실패와 상태가 바뀔 때만 (성공이 이어지는 동안은 조용히) */
  private result(key: string, ok: boolean, reason: string, ctx: NodeContext): void {
    if (!this.config.backends.some((b) => keyOf(b) === key)) return;
    const st = this.checkState.get(key) ?? { down: false, streak: 0 };
    this.checkState.set(key, st);
    const bad = !ok;
    if (bad === st.down) {
      // 지금 상태와 같은 결과: 반대 방향 연속 횟수를 지운다
      st.streak = 0;
      if (bad) st.reason = reason;
      return;
    }
    st.streak++;
    if (bad) st.reason = reason;
    const need = bad ? LB_CHECK_FALL : LB_CHECK_RISE;
    if (st.streak < need) {
      if (bad) ctx.trace("lb.check", "app", `헬스 체크: 백엔드 ${key} 실패 ${st.streak}/${LB_CHECK_FALL} — ${reason}`, { backend: key, reason, streak: st.streak });
      else ctx.trace("lb.check", "app", `헬스 체크: 백엔드 ${key} 응답 ${st.streak}/${LB_CHECK_RISE} (아직 DOWN)`, { backend: key, streak: st.streak });
      return;
    }
    st.down = bad;
    st.streak = 0;
    const alive = this.config.backends.filter((b) => keyOf(b) !== key && !this.checkState.get(keyOf(b))?.down).length + (bad ? 0 : 1);
    if (bad) {
      for (const [ip, k] of [...this.affinity]) if (k === key) this.affinity.delete(ip); // 고정도 풀어 다른 백엔드로
      ctx.trace("lb.down", "app", `헬스 체크: 백엔드 ${key} ${LB_CHECK_FALL}번 연속 실패 (${reason}) → DOWN, 요청을 보내지 않음 (남은 백엔드 ${alive}대) — 요청이 오기 전에 뺀다`, { backend: key, reason, check: true, left: alive });
    } else {
      ctx.trace("lb.check", "app", `헬스 체크: 백엔드 ${key} ${LB_CHECK_RISE}번 연속 응답 → UP, 다시 요청을 보냄 (살아 있는 백엔드 ${alive}대)`, { backend: key, up: true, left: alive });
    }
  }

  private active(b: LbBackend): number {
    let n = 0;
    for (const p of this.pending.values()) if (keyOf(p.backend) === keyOf(b)) n++;
    for (const f of this.flows.values()) if (f.closedAt === undefined && keyOf(f.backend) === keyOf(b)) n++;
    return n;
  }

  /**
   * 분배 규칙대로 백엔드 하나 고르기 (빼 둔 것·이번 요청에서 이미 실패한 것 제외).
   * 세션 고정이면 그 클라이언트가 쓰던 백엔드(출발지 IP) 또는 쿠키가 가리키는 백엔드 먼저 (L4 는 쿠키를 모른다 — cookie 를 넘기지 않음)
   */
  private pick(now: number, tried: Set<string>, client?: Ip, cookie?: string): { backend: LbBackend; sticky: boolean } | undefined {
    const alive = this.config.backends.filter((b) => this.isUp(b, now) && !tried.has(keyOf(b)));
    if (alive.length === 0) return undefined;
    const ipSticky = this.config.sticky === "ip" && client !== undefined;
    const want = ipSticky ? this.affinity.get(client) : this.config.sticky === "cookie" ? cookieBackend(cookie) : undefined;
    const prev = want !== undefined ? alive.find((b) => keyOf(b) === want) : undefined;
    if (prev) return { backend: prev, sticky: true };
    const b = this.pickBy(alive);
    if (b && ipSticky) this.affinity.set(client, keyOf(b));
    return b ? { backend: b, sticky: false } : undefined;
  }

  private pickBy(alive: LbBackend[]): LbBackend | undefined {
    if (this.config.algorithm === "least-conn") {
      // 활성 연결이 가장 적은 것, 같으면 목록 앞쪽
      return alive.reduce((best, b) => (this.active(b) < this.active(best) ? b : best));
    }
    // 라운드 로빈: 목록 순서대로 돌아가며, 빠진 것은 건너뛴다
    const n = this.config.backends.length;
    for (let k = 0; k < n; k++) {
      const b = this.config.backends[(this.rr + k) % n]!;
      if (alive.includes(b)) {
        this.rr = (this.rr + k + 1) % n;
        return b;
      }
    }
    return undefined;
  }

  /** 클라이언트 요청 도착: 맡으면 true (응답은 백엔드에서 받아 온 뒤) */
  onRequest(conn: TcpConn, ctx: NodeContext): boolean {
    if (!this.handles(conn)) return false;
    if (conn.method === "CONNECT") {
      // nginx 식 L7 은 CONNECT 를 받지 않는다 (nginx 는 405). 프록시 팜 앞이면 보통 L4 로 연결째 넘긴다
      ctx.trace("lb.fail", "app", `로드밸런서(L7): ${conn.remoteIp} 의 CONNECT ${conn.target ?? "?"} → 이 L7 로드밸런서(nginx 식)는 CONNECT 터널을 중계하지 않음 → 405 Method Not Allowed (프록시 팜 앞에는 L4 모드를 쓰세요)`, { client: conn.remoteIp });
      this.tcp.respond(conn, [METHOD_NOT_ALLOWED], ctx);
      return true;
    }
    this.forward(conn, new Set(), ctx);
    return true;
  }

  private forward(down: TcpConn, tried: Set<string>, ctx: NodeContext): void {
    const hops = down.via ?? 0;
    if (hops >= LB_MAX_HOPS) {
      ctx.trace("lb.fail", "app", `로드밸런서: 요청이 이미 로드밸런서 ${hops}개를 거침 (Via) → 로드밸런서끼리 서로를 백엔드로 둔 순환으로 보고 508 Loop Detected`, { via: hops });
      this.tcp.respond(down, [LOOP_DETECTED], ctx);
      return;
    }
    const me = this.localIp();
    const chosen = me ? this.pick(ctx.now, tried, down.remoteIp, down.cookie) : undefined;
    const b = chosen?.backend;
    if (!b || !me) {
      const why = !me ? "내 주소가 없음" : this.config.backends.length === 0 ? "백엔드가 하나도 없음" : "살아 있는 백엔드가 없음 (모두 실패로 빠져 있음)";
      ctx.trace("lb.fail", "app", `로드밸런서: ${why} → 클라이언트 ${down.remoteIp} 에게 502 Bad Gateway`, { client: down.remoteIp });
      this.tcp.respond(down, [BAD_GATEWAY], ctx);
      return;
    }
    const alive = this.config.backends.filter((x) => this.isUp(x, ctx.now));
    const stale = this.config.sticky === "cookie" && !chosen!.sticky ? cookieBackend(down.cookie) : undefined;
    const why = chosen!.sticky
      ? this.config.sticky === "cookie"
        ? `쿠키 고정 (Cookie ${LB_COOKIE}=${keyOf(b)})`
        : `세션 고정 (이 클라이언트가 쓰던 백엔드)`
      : (this.config.algorithm === "least-conn" ? `최소 연결 (진행 중 ${this.active(b)}개)` : `라운드 로빈 (살아 있는 ${alive.length}대 중 차례)`) +
        (stale ? ` — 쿠키가 가리키는 ${stale} 는 빠져 있거나 없어 다시 고름` : "");
    ctx.trace("lb.pick", "app", `로드밸런서: 클라이언트 ${down.remoteIp} 의 요청 → 백엔드 ${keyOf(b)} 선택 — ${why}. LB 가 대신 연결해 요청`, { backend: keyOf(b), client: down.remoteIp });
    // 요청 줄은 그대로 넘긴다: 절대 URI(프록시에게 온 요청)면 뒤의 프록시 팜이 대상을 알아야 한다
    this.tcp.connect(me, b.ip, b.port, ctx, { via: hops + 1, ...(down.target ? { target: down.target } : {}), onCreated: (up) => this.pending.set(up.id, { down, backend: b, tried }) });
  }

  /** 백엔드 연결이 끝남: 응답을 받았으면 클라이언트에게 전달, 실패면 빼 두고 다음 백엔드로. LB 가 처리한 연결이면 true */
  onFinish(up: TcpConn, ctx: NodeContext): boolean {
    const c = this.checking.get(up.id);
    if (c) {
      // 맺어지기 전에 끝난 체크 연결: 거부(RST)·닿지 않음(Unreachable)
      this.checking.delete(up.id);
      this.result(c.key, false, up.reason === "연결 거부 (RST)" ? "연결 거부 (RST, Layer4 connection problem)" : (up.reason ?? "연결 실패"), ctx);
      return true;
    }
    if (up.probe) return true; // 성공으로 센 뒤 닫힌 체크 연결
    const p = this.pending.get(up.id);
    if (!p) return false;
    this.pending.delete(up.id);
    const key = keyOf(p.backend);
    const st = this.stats.get(key) ?? { served: 0, fails: 0 };
    this.stats.set(key, st);
    // 응답을 끝까지 받았으면(상대 FIN 까지) 마지막 종료 절차가 timeout 이어도 성공으로 본다. FIN 없이 끊긴(RST·timeout) 일부 응답은 실패
    const body = responseBytes(up); // 백엔드가 443 이면 TLS 핸드셰이크는 응답이 아니다
    if (body > 0 && up.finReceived) {
      st.served++;
      // 받은 응답을 상태 줄 그대로 전달한다 (뒤에서 502·508 이 오면 그대로). 응답을 만든 서버는 뒤 LB 가 알려 준 것을 우선
      const status = up.status ?? "HTTP 200";
      const origin = up.servedBy ?? p.backend.ip;
      const n = Math.max(1, Math.ceil(body / RESPONSE_SEGMENT_BYTES));
      // 쿠키 고정: 클라이언트가 이 백엔드를 가리키는 쿠키를 안 가져왔으면(처음·다시 고름) 응답에 심는다
      const setCookie = this.config.sticky === "cookie" && cookieBackend(p.down.cookie) !== key ? `${LB_COOKIE}=${key}` : undefined;
      ctx.trace(
        "lb.relay",
        "app",
        `로드밸런서: 백엔드 ${key} 의 응답 (${status}, ${body}B) 을 클라이언트 ${p.down.remoteIp} 에게 전달${origin !== p.backend.ip ? ` — 응답을 만든 서버는 그 뒤의 ${origin}` : ""}${setCookie ? ` — Set-Cookie: ${setCookie} 를 넣어 이 브라우저의 다음 요청을 같은 백엔드로` : ""}`,
        { backend: key, bytes: body, status, ...(setCookie ? { setCookie } : {}) },
      );
      this.tcp.respond(
        p.down,
        Array.from({ length: n }, (_, k) => ({ len: Math.min(RESPONSE_SEGMENT_BYTES, body - k * RESPONSE_SEGMENT_BYTES), data: status === "HTTP 200" ? `HTTP 200 (${k + 1}/${n})` : status })),
        ctx,
        { origin, ...(setCookie ? { setCookie } : {}) },
      );
      return true;
    }
    if (p.down.state !== "ESTABLISHED") return true; // 기다리던 클라이언트가 이미 없다
    // 거부(RST)나 timeout 만 백엔드 탓. 내 링크가 끊기는 등으로 중단된 것은 빼지 않고, 기다리는 클라이언트에게 502 로 알린다
    const backendFault = up.reason?.startsWith("timeout") || up.reason === "연결 거부 (RST)";
    if (!backendFault) {
      ctx.trace("lb.fail", "app", `로드밸런서: 백엔드 ${key} 연결이 중단됨 (${up.reason ?? "?"}) → 클라이언트 ${p.down.remoteIp} 에게 502 Bad Gateway`, { backend: key });
      this.tcp.respond(p.down, [BAD_GATEWAY], ctx);
      return true;
    }
    st.fails++;
    this.downUntil.set(key, ctx.now + LB_FAIL_TIMEOUT);
    p.tried.add(key);
    ctx.trace("lb.down", "app", `로드밸런서: 백엔드 ${key} 실패 (${up.reason}) → ${LB_FAIL_TIMEOUT / 1000}초 동안 빼고 다음 백엔드로 다시 시도 (패시브 헬스 체크)`, { backend: key, reason: up.reason });
    this.forward(p.down, p.tried, ctx);
    return true;
  }

  // ---------- L4 (주소 변환) ----------

  /**
   * L4 모드에서 받은 TCP 세그먼트를 처리한다. LB 가 맡을 게 아니면 undefined, 맡았으면 내보낼 패킷들(없을 수도)
   * - LB 포트로 온 클라이언트 세그먼트 → 목적지를 백엔드, 출발지를 LB:변환 포트로
   * - 변환 포트로 온 백엔드 세그먼트 → 목적지를 클라이언트, 출발지를 LB:LB 포트로
   */
  l4(pkt: Ipv4Packet, seg: TcpSegment, ctx: NodeContext, frameId?: number): Ipv4Packet[] | undefined {
    if (!this.config.enabled || this.config.mode !== "l4") return undefined;
    const me = this.localIp();
    if (!me || pkt.dst !== me) return undefined;
    if (seg.dstPort === this.config.port) return this.l4FromClient(pkt, seg, me, ctx, frameId);
    // 내 헬스 체크 연결의 응답은 변환하지 않는다 (임시 포트가 변환 포트 범위와 겹쳐도)
    if ([...this.checking.values()].some((c) => c.conn.localPort === seg.dstPort) || [...this.tcp.conns.values()].some((c) => c.probe && c.localPort === seg.dstPort && c.state !== "CLOSED" && c.state !== "FAILED")) return undefined;
    const flow = this.byNatPort.get(seg.dstPort);
    if (flow && pkt.src === flow.backend.ip && seg.srcPort === flow.backend.port) return this.l4FromBackend(pkt, seg, flow, me, ctx, frameId);
    return undefined;
  }

  private l4FromClient(pkt: Ipv4Packet, seg: TcpSegment, me: Ip, ctx: NodeContext, frameId?: number): Ipv4Packet[] {
    this.expire(ctx.now);
    const key = `${pkt.src}:${seg.srcPort}`;
    let flow = this.flows.get(key);
    const synOnly = seg.syn && !seg.ackFlag;
    if (synOnly && flow) {
      if (flow.closedAt !== undefined || flow.finFromClient || flow.finFromBackend) {
        // 끝난 연결의 포트를 다시 씀: 새 연결로
        this.dropFlow(flow);
        flow = undefined;
      } else if (!flow.synAckSeen && ctx.now > flow.createdAt) {
        // SYN 재전송인데 백엔드의 SYN·ACK 를 한 번도 못 봄: 그 백엔드가 응답하지 않는다 → 빼 두고 다시 고른다 (아직 연결 전이라 옮겨도 된다)
        this.markDown(flow.backend, "SYN 에 응답 없음 (SYN 재전송이 옴)", ctx, frameId);
        this.dropFlow(flow);
        flow = undefined;
      } else if (!this.isUp(flow.backend, ctx.now)) {
        this.dropFlow(flow);
        flow = undefined;
      }
    }
    if (synOnly && !flow) {
      // 자기 자신(같은 주소·포트)을 백엔드로 두면 패킷이 제자리를 돈다 → 후보에서 뺀다
      const self = new Set(this.config.backends.filter((b) => b.ip === me && b.port === this.config.port).map(keyOf));
      const chosen = this.pick(ctx.now, self, pkt.src);
      if (!chosen) {
        const why = self.size && self.size === this.config.backends.length ? "백엔드가 로드밸런서 자신뿐" : "살아 있는 백엔드가 없음";
        ctx.trace("lb.fail", "L4", `로드밸런서(L4): ${pkt.src}:${seg.srcPort} 의 SYN — ${why} → RST 로 거절`, { client: pkt.src }, frameId);
        return [{ kind: "ipv4", src: me, dst: pkt.src, ttl: 64, payload: { kind: "tcp", srcPort: seg.dstPort, dstPort: seg.srcPort, seq: 0, ack: seg.seq + 1, rst: true, ackFlag: true, len: 0 } }];
      }
      this.makeRoom();
      const natPort = this.allocNatPort();
      flow = { clientIp: pkt.src, clientPort: seg.srcPort, backend: chosen.backend, natPort, finFromClient: false, finFromBackend: false, createdAt: ctx.now, synAckSeen: false };
      this.flows.set(key, flow);
      this.byNatPort.set(natPort, flow);
      const why = chosen.sticky ? "세션 고정" : this.config.algorithm === "least-conn" ? "최소 연결" : "라운드 로빈";
      ctx.trace("lb.pick", "L4", `로드밸런서(L4): ${pkt.src}:${seg.srcPort} 의 새 연결(SYN) → 백엔드 ${keyOf(chosen.backend)} (${why}). 연결을 끊지 않고 주소만 바꿔 넘김 — TCP 연결은 클라이언트와 백엔드 사이 하나`, { backend: keyOf(chosen.backend), client: pkt.src }, frameId);
    }
    if (!flow) {
      ctx.trace("lb.fail", "L4", `로드밸런서(L4): ${pkt.src}:${seg.srcPort} 의 세그먼트인데 흐름 기록이 없음 (SYN 없이 옴) → 드롭`, { client: pkt.src }, frameId);
      return [];
    }
    if (pkt.ttl <= 1) {
      ctx.trace("ip.drop", "L3", `로드밸런서(L4): TTL ${pkt.ttl} 로 도착 → 더 넘기면 0 → 드롭 (로드밸런서끼리 서로를 백엔드로 두면 여기서 끝난다)`, {}, frameId);
      return [];
    }
    if (seg.fin) flow.finFromClient = true;
    const out: Ipv4Packet = { ...pkt, src: me, dst: flow.backend.ip, ttl: pkt.ttl - 1, payload: { ...seg, srcPort: flow.natPort, dstPort: flow.backend.port } };
    ctx.trace("lb.forward", "L4", `L4 변환(→ 백엔드): ${pkt.src}:${seg.srcPort} → ${me}:${seg.dstPort} 를 ${me}:${flow.natPort} → ${keyOf(flow.backend)} 로 바꿔 보냄`, { client: `${pkt.src}:${seg.srcPort}`, vip: `${me}:${seg.dstPort}`, backend: keyOf(flow.backend), natPort: flow.natPort, state: ipvsState(seg, flow) }, frameId);
    this.noteClose(flow, seg, ctx.now);
    return [out];
  }

  private l4FromBackend(pkt: Ipv4Packet, seg: TcpSegment, flow: L4Flow, me: Ip, ctx: NodeContext, frameId?: number): Ipv4Packet[] {
    if (seg.rst && !flow.finFromClient && !flow.synAckSeen) {
      // 백엔드가 연결을 거부(듣지 않는 포트): 패시브 헬스 체크로 빼 두고, 클라이언트에게도 RST 를 넘긴다
      this.markDown(flow.backend, "RST 로 거부 — L4 는 이미 시작한 연결을 다른 백엔드로 옮기지 못함, 클라이언트가 다시 연결해야 함", ctx, frameId);
    }
    if (seg.syn && seg.ackFlag) flow.synAckSeen = true;
    if (pkt.ttl <= 1) {
      ctx.trace("ip.drop", "L3", `로드밸런서(L4): TTL ${pkt.ttl} 로 도착 → 드롭`, {}, frameId);
      return [];
    }
    if (seg.fin && !flow.finFromBackend) {
      flow.finFromBackend = true;
      if (!flow.finFromClient) {
        const st = this.stats.get(keyOf(flow.backend)) ?? { served: 0, fails: 0 };
        st.served++;
        this.stats.set(keyOf(flow.backend), st);
      }
    }
    const out: Ipv4Packet = { ...pkt, src: me, dst: flow.clientIp, ttl: pkt.ttl - 1, payload: { ...seg, srcPort: this.config.port, dstPort: flow.clientPort } };
    ctx.trace("lb.forward", "L4", `L4 변환(→ 클라이언트): ${keyOf(flow.backend)} → ${me}:${flow.natPort} 를 ${me}:${this.config.port} → ${flow.clientIp}:${flow.clientPort} 로 바꿔 보냄`, { client: `${flow.clientIp}:${flow.clientPort}`, vip: `${me}:${this.config.port}`, backend: keyOf(flow.backend), natPort: flow.natPort, state: ipvsState(seg, flow) }, frameId);
    this.noteClose(flow, seg, ctx.now);
    return [out];
  }

  /** 양쪽 FIN 뒤 순수 ACK(어느 쪽이든), 또는 RST 면 끝난 것으로 표시 — 바로 지우지 않고 TIME_WAIT 동안 남긴다 */
  private noteClose(flow: L4Flow, seg: TcpSegment, now: number): void {
    if (flow.closedAt !== undefined) return;
    if (seg.rst || (flow.finFromClient && flow.finFromBackend && !seg.fin && seg.len === 0 && seg.ackFlag)) flow.closedAt = now;
  }

  private markDown(b: LbBackend, why: string, ctx: NodeContext, frameId?: number): void {
    const key = keyOf(b);
    this.downUntil.set(key, ctx.now + LB_FAIL_TIMEOUT);
    const st = this.stats.get(key) ?? { served: 0, fails: 0 };
    st.fails++;
    this.stats.set(key, st);
    for (const [ip, k] of [...this.affinity]) if (k === key) this.affinity.delete(ip); // 고정도 풀어 다른 백엔드로
    ctx.trace("lb.down", "L4", `로드밸런서(L4): 백엔드 ${key} 실패 (${why}) → ${LB_FAIL_TIMEOUT / 1000}초 동안 뺌 (패시브 헬스 체크)`, { backend: key, reason: why }, frameId);
  }

  /** TIME_WAIT 이 지난 끝난 흐름을 치운다 */
  private expire(now: number): void {
    for (const f of [...this.flows.values()]) if (f.closedAt !== undefined && now - f.closedAt >= L4_TIME_WAIT) this.dropFlow(f);
  }

  /** 상한에 닿으면 끝난 흐름부터, 없으면 가장 오래된 것을 내보낸다 */
  private makeRoom(): void {
    if (this.flows.size < L4_MAX_FLOWS) return;
    const closed = [...this.flows.values()].find((f) => f.closedAt !== undefined);
    this.dropFlow(closed ?? this.flows.values().next().value!);
  }

  private allocNatPort(): number {
    for (let k = 0; k < 10000; k++) {
      const p = this.nextNatPort++;
      if (this.nextNatPort > 59999) this.nextNatPort = L4_PORT_START;
      if (!this.byNatPort.has(p)) return p;
    }
    return this.nextNatPort;
  }

  private dropFlow(f: L4Flow): void {
    this.flows.delete(`${f.clientIp}:${f.clientPort}`);
    this.byNatPort.delete(f.natPort);
  }

  /** 표시용: L4 흐름 (진행 중인 것만) */
  flowRows(): string[][] {
    return [...this.flows.values()].filter((f) => f.closedAt === undefined).map((f) => [`${f.clientIp}:${f.clientPort}`, `:${f.natPort} → ${keyOf(f.backend)}`]);
  }

  /** 진행 중인 L4 흐름 수 */
  get openFlows(): number {
    return [...this.flows.values()].filter((f) => f.closedAt === undefined).length;
  }

  /** 표시용: 백엔드마다 상태·처리 수 */
  rows(now: number): string[][] {
    return this.config.backends.map((b) => {
      const st = this.stats.get(keyOf(b)) ?? { served: 0, fails: 0 };
      const until = this.downUntil.get(keyOf(b));
      const chk = this.checkState.get(keyOf(b));
      const state = chk?.down
        ? `DOWN (헬스 체크: ${chk.reason ?? "실패"})`
        : until !== undefined && until > now
          ? `빠짐 (${Math.ceil((until - now) / 1000)}초 뒤 다시 시도)`
          : this.config.healthCheck
            ? `사용 중 · 헬스 체크 ${chk?.streak ? `실패 ${chk.streak}/${LB_CHECK_FALL}` : "정상"}`
            : "사용 중";
      return [keyOf(b), state, `${st.served}건`, st.fails ? `실패 ${st.fails}` : "-"];
    });
  }
}

/** ipvsadm -Lnc 의 연결 상태 표기 */
function ipvsState(seg: TcpSegment, f: L4Flow): string {
  if (seg.rst) return "CLOSE";
  if (seg.syn) return "SYN_RECV";
  if (f.finFromClient || f.finFromBackend) return f.finFromClient && f.finFromBackend ? "TIME_WAIT" : "FIN_WAIT";
  return "ESTABLISHED";
}
