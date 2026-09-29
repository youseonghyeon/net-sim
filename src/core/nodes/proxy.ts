// 포워드 프록시 (Squid 식 HTTP 프록시): 사내 PC 가 웹 서버에 직접 가지 않고, 프록시에게 "이 주소를 대신 받아 와 달라" 고 부탁한다.
// PC 의 요청 줄은 절대 URI(GET http://example.com/)라 프록시가 대상을 안다. 이름이면 프록시가 DNS 로 찾는다 — PC 에는 외부 DNS 가 없어도 된다.
// 프록시가 대상 서버에 직접 연결해 받은 응답을 돌려준다. 대상 서버에게 클라이언트는 프록시 주소로 보인다.
// 그래서 방화벽은 "프록시만 인터넷으로" 로 좁힐 수 있고, 프록시는 차단 목록(URL 필터링 흉내)으로 대상을 막는다(403).
//
// 로드밸런서(lb.ts, 리버스 프록시)와 모양은 같지만 편이 반대다:
//   리버스 = 서버들을 대신한다 (클라이언트는 LB 주소가 곧 서버인 줄 안다)
//   포워드 = 클라이언트들을 대신한다 (클라이언트가 프록시를 알고 설정해 둔다)
// 실패는 Squid 처럼: 대상 없음(프록시 설정 없이 직접 접속) 400, 차단 403, 이름을 못 찾음·연결 실패 503.
// 차단 목록의 주소는 이름을 푼 뒤에도 비교한다 (Squid dst ACL) — 주소로 막은 사이트를 이름으로 돌아가지 못하게.
// HTTP(포트 80 요청)만 다룬다 — HTTPS 의 CONNECT 터널은 없다.
import { ipToInt, type Ip } from "../addr";
import type { NodeContext } from "./node";
import type { TcpConn, TcpStack } from "./tcp";

export interface ProxyConfig {
  enabled: boolean;
  /** 프록시가 듣는 포트 (Squid 기본 3128) */
  port: number;
  /** 막을 대상: 이름(그 하위 이름도) 또는 주소 */
  deny: string[];
}

export const DEFAULT_PROXY: ProxyConfig = { enabled: false, port: 3128, deny: [] };

const BAD_REQUEST = { len: 200, data: "HTTP 400 Bad Request" };
const FORBIDDEN = { len: 200, data: "HTTP 403 Forbidden" };
const UNAVAILABLE = { len: 200, data: "HTTP 503 Service Unavailable" };
const RESPONSE_SEGMENT_BYTES = 1000;

function isValidIp(s: string): boolean {
  try {
    ipToInt(s);
    return true;
  } catch {
    return false;
  }
}

/** "호스트:포트" → 둘로 (포트가 없으면 80) */
export function splitTarget(target: string): { host: string; port: number } {
  const m = /^(.*):(\d+)$/.exec(target);
  return m ? { host: m[1]!, port: Number(m[2]) } : { host: target, port: 80 };
}

/** 차단 목록에 걸리는지: 주소는 같을 때, 이름은 같거나 그 하위 이름일 때 (example.com 은 www.example.com 도 막음) */
export function denied(host: string, deny: readonly string[]): string | undefined {
  const h = host.toLowerCase();
  return deny.find((raw) => {
    const d = raw.trim().toLowerCase().replace(/^\*?\./, "");
    return d !== "" && (h === d || (!isValidIp(d) && !isValidIp(h) && h.endsWith(`.${d}`)));
  });
}

interface Pending {
  down: TcpConn;
  target: string;
}

/** 프록시가 처리한 요청 기록 (Squid access.log 흉내, 최근 것만) */
export interface ProxyLogEntry {
  at: number;
  client: Ip;
  target: string;
  /** "TCP_MISS/200", "TCP_DENIED/403" 처럼 */
  result: string;
}
const LOG_MAX = 20;

export class ForwardProxy {
  config: ProxyConfig = { ...DEFAULT_PROXY, deny: [] };
  private readonly pending = new Map<string, Pending>();
  readonly log: ProxyLogEntry[] = [];

  constructor(
    private readonly tcp: TcpStack,
    /** 프록시가 대상에 연결할 때 쓸 내 주소 */
    private readonly localIp: () => Ip | undefined,
    /** 이름 → 주소 (프록시 장비의 리졸버) */
    private readonly resolve: (name: string, ctx: NodeContext, done: (ip: Ip | undefined, err?: string) => void) => void,
  ) {}

  setConfig(cfg: ProxyConfig, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.config)) return;
    this.config = { ...cfg, deny: [...cfg.deny] };
    ctx.trace(
      "proxy.config",
      "sys",
      cfg.enabled ? `프록시 켜짐: 포트 ${cfg.port} 로 온 요청의 대상에 대신 연결해 응답을 돌려줌${cfg.deny.length ? ` (차단 목록 ${cfg.deny.join(", ")})` : ""}` : "프록시 꺼짐",
      { ...cfg },
    );
  }

  /** 이 서버 연결을 프록시가 맡는지 (프록시 포트로 온 연결) */
  handles(conn: TcpConn): boolean {
    return this.config.enabled && conn.role === "server" && conn.localPort === this.config.port;
  }

  /** 클라이언트 요청 도착: 맡으면 true (응답은 대상에서 받아 온 뒤) */
  onRequest(down: TcpConn, ctx: NodeContext): boolean {
    if (!this.handles(down)) return false;
    const target = down.target;
    if (!target) {
      ctx.trace("proxy.fail", "app", `프록시: ${down.remoteIp} 의 요청에 대상(절대 URI)이 없음 — 프록시 설정 없이 프록시 주소로 직접 접속한 것 → 400 Bad Request`, { client: down.remoteIp, result: "TAG_NONE/400", url: "/" });
      this.finish(down, "-", "TAG_NONE/400", [BAD_REQUEST], ctx);
      return true;
    }
    const { host, port } = splitTarget(target);
    const rule = denied(host, this.config.deny);
    const deny = (why: string, r: string) => {
      ctx.trace("proxy.deny", "app", `프록시: ${down.remoteIp} 가 부탁한 ${target}${why} 는 차단 목록(${r})에 있음 → 대상에 연결하지 않고 403 Forbidden`, { client: down.remoteIp, target, rule: r, result: "TCP_DENIED/403" });
      this.finish(down, target, "TCP_DENIED/403", [FORBIDDEN], ctx);
    };
    if (rule) {
      deny("", rule);
      return true;
    }
    const go = (ip: Ip) => {
      const me = this.localIp();
      if (!me || down.state !== "ESTABLISHED") return;
      // 이름을 푼 주소도 차단 목록과 비교 (주소로 막은 사이트를 이름으로 우회하지 못하게)
      const byIp = ip !== host ? denied(ip, this.config.deny) : undefined;
      if (byIp) return deny(` (${ip})`, byIp);
      ctx.trace(
        "proxy.request",
        "app",
        `프록시: ${down.remoteIp} 의 부탁으로 ${target}${host !== ip ? ` (${ip})` : ""} 에 내 주소 ${me} 로 대신 연결 — 대상 서버에게는 프록시가 클라이언트로 보인다`,
        { client: down.remoteIp, target, ip },
      );
      this.tcp.connect(me, ip, port, ctx, { via: (down.via ?? 0) + 1, ...(down.cookie ? { cookie: down.cookie } : {}), onCreated: (up) => this.pending.set(up.id, { down, target }) });
    };
    if (isValidIp(host)) {
      go(host);
      return true;
    }
    // 이름은 프록시가 찾는다 (PC 는 대상의 이름을 풀지 않았다)
    this.resolve(host, ctx, (ip, err) => {
      if (ip) return go(ip);
      ctx.trace("proxy.fail", "app", `프록시: ${target} 의 이름을 주소로 바꾸지 못함 (${err ?? "이름 해석 실패"}) → 503 Service Unavailable (프록시의 DNS 설정을 확인)`, { client: down.remoteIp, target, result: "TCP_MISS/503" });
      this.finish(down, target, "TCP_MISS/503", [UNAVAILABLE], ctx);
    });
    return true;
  }

  /** 대상 연결이 끝남: 응답을 받았으면 전달, 아니면 503. 프록시가 처리한 연결이면 true */
  onFinish(up: TcpConn, ctx: NodeContext): boolean {
    const p = this.pending.get(up.id);
    if (!p) return false;
    this.pending.delete(up.id);
    // 응답을 끝까지(대상의 FIN 까지) 받았을 때만 전달. FIN 없이 끊긴(RST·timeout) 일부 응답은 503
    if (up.bytesReceived > 0 && up.finReceived) {
      const status = up.status ?? "HTTP 200";
      const n = Math.max(1, Math.ceil(up.bytesReceived / RESPONSE_SEGMENT_BYTES));
      ctx.trace(
        "proxy.relay",
        "app",
        `프록시: ${p.target} 의 응답 (${status}, ${up.bytesReceived}B) 을 ${p.down.remoteIp} 에게 전달${up.setCookie ? ` — Set-Cookie 도 그대로` : ""}`,
        { client: p.down.remoteIp, target: p.target, ip: up.remoteIp, status, bytes: up.bytesReceived, result: `TCP_MISS/${status.split(" ")[1] ?? "200"}` },
      );
      this.finish(
        p.down,
        p.target,
        `TCP_MISS/${status.split(" ")[1] ?? "200"}`,
        Array.from({ length: n }, (_, k) => ({ len: Math.min(RESPONSE_SEGMENT_BYTES, up.bytesReceived - k * RESPONSE_SEGMENT_BYTES), data: status === "HTTP 200" ? `HTTP 200 (${k + 1}/${n})` : status })),
        ctx,
        { origin: up.servedBy ?? up.remoteIp, ...(up.setCookie ? { setCookie: up.setCookie } : {}) },
      );
      return true;
    }
    if (p.down.state !== "ESTABLISHED") {
      // 기다리던 클라이언트가 이미 끊었다 (Squid 는 TCP_MISS_ABORTED 로 남긴다)
      this.record(p.down, p.target, "TCP_MISS_ABORTED/000", ctx);
      return true;
    }
    ctx.trace(
      "proxy.fail",
      "app",
      `프록시: ${p.target} ${up.bytesReceived > 0 ? `의 응답이 중간에 끊김 (${up.bytesReceived}B 받음, ${up.reason ?? "?"})` : `에 연결하지 못함 (${up.reason ?? "?"})`} → ${p.down.remoteIp} 에게 503 Service Unavailable`,
      { client: p.down.remoteIp, target: p.target, reason: up.reason, result: "TCP_MISS/503" },
    );
    this.finish(p.down, p.target, "TCP_MISS/503", [UNAVAILABLE], ctx);
    return true;
  }

  private finish(down: TcpConn, target: string, result: string, parts: { len: number; data: string }[], ctx: NodeContext, meta: { origin?: string; setCookie?: string } = {}): void {
    this.record(down, target, result, ctx);
    this.tcp.respond(down, parts, ctx, meta);
  }

  private record(down: TcpConn, target: string, result: string, ctx: NodeContext): void {
    this.log.push({ at: ctx.now, client: down.remoteIp, target, result });
    if (this.log.length > LOG_MAX) this.log.shift();
  }

  rows(): string[][] {
    return [...this.log].reverse().map((e) => [e.client, e.target, e.result]);
  }
}
