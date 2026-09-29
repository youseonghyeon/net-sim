// 로드밸런서 (리버스 프록시, L7): nginx·HAProxy·클라우드 ALB 가 흔히 쓰는 방식.
// 클라이언트는 LB 주소로 접속하고, LB 가 백엔드 하나를 골라 "자기가 대신" 연결해 요청한 뒤 받은 응답을 돌려준다.
// 백엔드 입장에서 클라이언트는 LB 다. 서버의 서비스 토글(Host)과 로드밸런서 전용 장비가 이 모듈을 함께 쓴다.
//
// 헬스 체크는 패시브(nginx 의 max_fails/fail_timeout 방식): 백엔드가 거부(RST)하거나 timeout 이면 10초 동안 빼고
// 곧바로 다음 백엔드로 다시 보낸다. 주기적인 액티브 헬스 체크는 없다 — 시뮬레이터 시계는 조용하면 멈추므로.
import type { Ip } from "../addr";
import type { NodeContext } from "./node";
import type { TcpConn, TcpStack } from "./tcp";

export type LbAlgorithm = "round-robin" | "least-conn";

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
}

export const DEFAULT_LB: LbConfig = { enabled: false, port: 80, algorithm: "round-robin", backends: [] };
/** 실패한 백엔드를 빼 두는 시간 (nginx fail_timeout 기본값 10초) */
export const LB_FAIL_TIMEOUT = 10_000;
/** 살아 있는 백엔드가 하나도 없을 때 돌려주는 응답 */
const BAD_GATEWAY = { len: 200, data: "HTTP 502 Bad Gateway" };
const RESPONSE_SEGMENT_BYTES = 1000;

const keyOf = (b: LbBackend) => `${b.ip}:${b.port}`;

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

  constructor(
    private readonly tcp: TcpStack,
    /** LB 가 백엔드로 연결할 때 쓸 내 주소 */
    private readonly localIp: () => Ip | undefined,
  ) {}

  setConfig(cfg: LbConfig, ctx: NodeContext): void {
    const same = JSON.stringify(cfg) === JSON.stringify(this.config);
    this.config = { ...cfg, backends: cfg.backends.map((b) => ({ ...b })) };
    if (same) return;
    this.downUntil.clear();
    ctx.trace(
      "lb.config",
      "sys",
      cfg.enabled
        ? `로드밸런서 켜짐: 포트 ${cfg.port} 로 온 요청을 ${LB_ALGORITHM_LABEL[cfg.algorithm]} 로 백엔드 ${cfg.backends.length}대(${cfg.backends.map(keyOf).join(", ") || "없음"})에 나눔`
        : "로드밸런서 꺼짐",
      { ...cfg },
    );
  }

  /** 이 서버 연결을 LB 가 맡는지 (LB 포트로 온 연결) */
  handles(conn: TcpConn): boolean {
    return this.config.enabled && conn.role === "server" && conn.localPort === this.config.port;
  }

  /** 지금 살아 있는 것으로 보는 백엔드 */
  isUp(b: LbBackend, now: number): boolean {
    return (this.downUntil.get(keyOf(b)) ?? -Infinity) <= now;
  }

  private active(b: LbBackend): number {
    let n = 0;
    for (const p of this.pending.values()) if (keyOf(p.backend) === keyOf(b)) n++;
    return n;
  }

  /** 분배 규칙대로 백엔드 하나 고르기 (빼 둔 것·이번 요청에서 이미 실패한 것 제외) */
  private pick(now: number, tried: Set<string>): LbBackend | undefined {
    const alive = this.config.backends.filter((b) => this.isUp(b, now) && !tried.has(keyOf(b)));
    if (alive.length === 0) return undefined;
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
    this.forward(conn, new Set(), ctx);
    return true;
  }

  private forward(down: TcpConn, tried: Set<string>, ctx: NodeContext): void {
    const me = this.localIp();
    const b = me ? this.pick(ctx.now, tried) : undefined;
    if (!b || !me) {
      const why = !me ? "내 주소가 없음" : this.config.backends.length === 0 ? "백엔드가 하나도 없음" : "살아 있는 백엔드가 없음 (모두 실패로 빠져 있음)";
      ctx.trace("lb.fail", "app", `로드밸런서: ${why} → 클라이언트 ${down.remoteIp} 에게 502 Bad Gateway`, { client: down.remoteIp });
      this.tcp.respond(down, [BAD_GATEWAY], ctx);
      return;
    }
    const alive = this.config.backends.filter((x) => this.isUp(x, ctx.now));
    const why =
      this.config.algorithm === "least-conn"
        ? `최소 연결 (진행 중 ${this.active(b)}개)`
        : `라운드 로빈 (살아 있는 ${alive.length}대 중 차례)`;
    ctx.trace("lb.pick", "app", `로드밸런서: 클라이언트 ${down.remoteIp} 의 요청 → 백엔드 ${keyOf(b)} 선택 — ${why}. LB 가 대신 연결해 요청`, { backend: keyOf(b), client: down.remoteIp });
    const up = this.tcp.connect(me, b.ip, b.port, ctx);
    this.pending.set(up.id, { down, backend: b, tried });
  }

  /** 백엔드 연결이 끝남: 응답을 받았으면 클라이언트에게 전달, 실패면 빼 두고 다음 백엔드로. LB 가 처리한 연결이면 true */
  onFinish(up: TcpConn, ctx: NodeContext): boolean {
    const p = this.pending.get(up.id);
    if (!p) return false;
    this.pending.delete(up.id);
    const key = keyOf(p.backend);
    const st = this.stats.get(key) ?? { served: 0, fails: 0 };
    this.stats.set(key, st);
    if (up.state === "CLOSED" && up.bytesReceived > 0) {
      st.served++;
      const n = Math.max(1, Math.ceil(up.bytesReceived / RESPONSE_SEGMENT_BYTES));
      ctx.trace("lb.relay", "app", `로드밸런서: 백엔드 ${key} 의 응답 ${up.bytesReceived}B 를 클라이언트 ${p.down.remoteIp} 에게 전달`, { backend: key, bytes: up.bytesReceived });
      this.tcp.respond(
        p.down,
        Array.from({ length: n }, (_, k) => ({ len: Math.min(RESPONSE_SEGMENT_BYTES, up.bytesReceived - k * RESPONSE_SEGMENT_BYTES), data: `HTTP 200 (${k + 1}/${n})` })),
        ctx,
        p.backend.ip,
      );
      return true;
    }
    // 거부(RST)나 timeout 만 백엔드 탓. 내 링크가 끊겨 중단된 것은 빼지 않는다
    const backendFault = up.reason?.startsWith("timeout") || up.reason === "연결 거부 (RST)";
    if (!backendFault || p.down.state !== "ESTABLISHED") return true;
    st.fails++;
    this.downUntil.set(key, ctx.now + LB_FAIL_TIMEOUT);
    p.tried.add(key);
    ctx.trace("lb.down", "app", `로드밸런서: 백엔드 ${key} 실패 (${up.reason}) → ${LB_FAIL_TIMEOUT / 1000}초 동안 빼고 다음 백엔드로 다시 시도 (패시브 헬스 체크)`, { backend: key, reason: up.reason });
    this.forward(p.down, p.tried, ctx);
    return true;
  }

  /** 표시용: 백엔드마다 상태·처리 수 */
  rows(now: number): string[][] {
    return this.config.backends.map((b) => {
      const st = this.stats.get(keyOf(b)) ?? { served: 0, fails: 0 };
      const until = this.downUntil.get(keyOf(b));
      const state = until !== undefined && until > now ? `빠짐 (${Math.ceil((until - now) / 1000)}초 뒤 다시 시도)` : "사용 중";
      return [keyOf(b), state, `${st.served}건`, st.fails ? `실패 ${st.fails}` : "-"];
    });
  }
}
