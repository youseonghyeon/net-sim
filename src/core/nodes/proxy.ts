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
//
// HTTPS(포트 443)는 CONNECT 터널: 내용이 암호화돼 프록시가 대신 받아 올 수 없으므로, PC 가 "CONNECT 호스트:443" 으로
// 대상까지 TCP 통로를 부탁하고 프록시는 연결한 뒤 두 연결 사이로 바이트만 그대로 넘긴다 (TLS 는 PC 와 대상 서버가 직접).
// 프록시가 아는 것은 CONNECT 의 호스트와 ClientHello 의 SNI 뿐이라 차단도 도메인 단위다 (경로·내용은 모른다).
import { ipToInt, type Ip } from "../addr";
import type { TcpSegment } from "../packet";
import type { NodeContext } from "./node";
import { CONNECT_ESTABLISHED, responseBytes, type TcpConn, type TcpStack } from "./tcp";

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
  /** CONNECT 터널을 열려는 연결 */
  connect?: boolean;
}

/** 열린 CONNECT 터널: 클라이언트 쪽(down)과 대상 쪽(up) 연결 */
interface Tunnel {
  down: TcpConn;
  up: TcpConn;
  target: string;
}

/** 프록시가 처리한 요청 기록 (Squid access.log 흉내, 최근 것만) */
export interface ProxyLogEntry {
  at: number;
  client: Ip;
  target: string;
  /** "TCP_MISS/200", "TCP_DENIED/403" 처럼 */
  result: string;
  /** CONNECT 요청이면 (없으면 GET) */
  method?: "CONNECT";
}
const LOG_MAX = 20;

export class ForwardProxy {
  config: ProxyConfig = { ...DEFAULT_PROXY, deny: [] };
  private readonly pending = new Map<string, Pending>();
  /** 연결 id (양쪽 모두) → 터널 */
  private readonly tunnels = new Map<string, Tunnel>();
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
    const connect = down.method === "CONNECT";
    const method = connect ? { method: "CONNECT" as const } : {};
    const rule = denied(host, this.config.deny);
    const deny = (why: string, r: string) => {
      ctx.trace(
        "proxy.deny",
        "app",
        connect
          ? `프록시: ${down.remoteIp} 의 CONNECT ${target}${why} 는 차단 목록(${r})에 있음 → 터널을 열지 않고 403 Forbidden (HTTPS 는 경로를 볼 수 없어 도메인 단위로만 막는다)`
          : `프록시: ${down.remoteIp} 가 부탁한 ${target}${why} 는 차단 목록(${r})에 있음 → 대상에 연결하지 않고 403 Forbidden`,
        { client: down.remoteIp, target, rule: r, result: "TCP_DENIED/403", ...method },
      );
      this.finish(down, target, "TCP_DENIED/403", [FORBIDDEN], ctx, {}, connect);
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
        connect
          ? `프록시: ${down.remoteIp} 의 CONNECT 요청 → ${target}${host !== ip ? ` (${ip})` : ""} 에 내 주소 ${me} 로 TCP 연결 (연결되면 터널을 열고 그 뒤로는 바이트만 전달)`
          : `프록시: ${down.remoteIp} 의 부탁으로 ${target}${host !== ip ? ` (${ip})` : ""} 에 내 주소 ${me} 로 대신 연결 — 대상 서버에게는 프록시가 클라이언트로 보인다`,
        { client: down.remoteIp, target, ip, ...method },
      );
      if (connect) this.tcp.connect(me, ip, port, ctx, { relay: true, onCreated: (up) => this.pending.set(up.id, { down, target, connect }) });
      else this.tcp.connect(me, ip, port, ctx, { via: (down.via ?? 0) + 1, ...(down.cookie ? { cookie: down.cookie } : {}), onCreated: (up) => this.pending.set(up.id, { down, target }) });
    };
    if (isValidIp(host)) {
      go(host);
      return true;
    }
    // 이름은 프록시가 찾는다 (PC 는 대상의 이름을 풀지 않았다)
    this.resolve(host, ctx, (ip, err) => {
      if (ip) return go(ip);
      const result = connect ? "NONE/503" : "TCP_MISS/503";
      ctx.trace("proxy.fail", "app", `프록시: ${target} 의 이름을 주소로 바꾸지 못함 (${err ?? "이름 해석 실패"}) → 503 Service Unavailable (프록시의 DNS 설정을 확인)`, { client: down.remoteIp, target, result, ...method });
      this.finish(down, target, result, [UNAVAILABLE], ctx, {}, connect);
    });
    return true;
  }

  /** CONNECT 대상에 연결됨: 클라이언트에게 200 Connection established 를 보내고 두 연결을 터널로 잇는다 */
  onEstablished(up: TcpConn, ctx: NodeContext): void {
    const p = this.pending.get(up.id);
    if (!p?.connect) return;
    this.pending.delete(up.id);
    const { down, target } = p;
    if (down.state !== "ESTABLISHED") {
      // 기다리던 클라이언트가 먼저 떠났다
      ctx.trace("proxy.fail", "app", `프록시: ${target} 에 연결됐지만 CONNECT 를 부탁한 ${down.remoteIp} 가 이미 끊음 → 대상 연결도 닫음`, { client: down.remoteIp, target, ip: up.remoteIp, result: "NONE/000", method: "CONNECT" });
      this.record(down, target, "NONE/000", ctx, true);
      this.tcp.disconnect(up.id, ctx);
      return;
    }
    const t: Tunnel = { down, up, target };
    this.tunnels.set(up.id, t);
    this.tunnels.set(down.id, t);
    // 상태를 먼저 세운다: 클라이언트가 내 주소(루프백)면 200 을 보내는 순간 ClientHello 가 되돌아온다
    down.relay = true;
    ctx.trace(
      "proxy.tunnel",
      "app",
      `프록시: ${target} (${up.remoteIp}) 에 연결됨 → ${down.remoteIp} 에게 "${CONNECT_ESTABLISHED}". 이제 두 연결 사이로 바이트만 그대로 넘김 — 안은 TLS 로 암호화돼 프록시는 이름(CONNECT·SNI)만 알고 경로·내용은 모른다`,
      { client: down.remoteIp, target, ip: up.remoteIp, method: "CONNECT" },
    );
    this.tcp.sendData(down, { len: 40, data: CONNECT_ESTABLISHED }, ctx, `CONNECT 응답 전송: "${CONNECT_ESTABLISHED}"`, "터널 열림");
  }

  /** 터널로 온 데이터(seg)·FIN(undefined) 을 반대편 연결로 그대로 넘긴다 */
  onRelay(conn: TcpConn, seg: TcpSegment | undefined, ctx: NodeContext): void {
    const t = this.tunnels.get(conn.id);
    if (!t) return;
    const other = conn === t.up ? t.down : t.up;
    const where = other === t.up ? `대상 ${t.target}` : `클라이언트 ${t.down.remoteIp}`;
    if (!seg) {
      // 한쪽이 닫으면 다른 쪽도 닫는다
      if (other.state === "ESTABLISHED") this.tcp.disconnect(other.id, ctx);
      return;
    }
    const what = seg.tls === "client-hello" ? `TLS ClientHello${seg.sni ? ` (SNI ${seg.sni})` : ""}` : seg.tls ? "TLS 레코드 (암호화됨)" : "데이터";
    // 바이트를 그대로 넘긴다: 안쪽(TLS 안의 HTTP 헤더 흉내 — Cookie·Set-Cookie·X-Served-By)도 손대지 않는다
    const { kind: _k, srcPort: _s, dstPort: _d, seq: _q, ack: _a, syn: _y, ackFlag: _f, fin: _n, rst: _r, ...part } = seg;
    if (!this.tcp.sendData(other, part, ctx, `터널 전달 → ${where}: ${what}`, "내용은 보지 않고 그대로")) {
      ctx.trace("proxy.fail", "app", `프록시: 터널 반대편(${where}) 연결이 이미 닫혀 받은 ${seg.len}B 를 넘기지 못함 → 드롭`, { client: t.down.remoteIp, target: t.target });
    }
  }

  /** 대상 연결이 끝남: 응답을 받았으면 전달, 아니면 503. 프록시가 처리한 연결이면 true */
  onFinish(up: TcpConn, ctx: NodeContext): boolean {
    const t = this.tunnels.get(up.id);
    if (t) {
      this.closeTunnel(t, up, ctx);
      return true;
    }
    const p = this.pending.get(up.id);
    if (!p) return false;
    this.pending.delete(up.id);
    if (p.connect) {
      // CONNECT 대상에 연결하지 못함 (거부·timeout·경로 없음)
      if (p.down.state !== "ESTABLISHED") {
        this.record(p.down, p.target, "NONE/000", ctx, true);
        return true;
      }
      ctx.trace("proxy.fail", "app", `프록시: CONNECT ${p.target} 에 연결하지 못함 (${up.reason ?? "?"}) → ${p.down.remoteIp} 에게 503 Service Unavailable`, { client: p.down.remoteIp, target: p.target, ip: up.remoteIp, reason: up.reason, result: "NONE/503", method: "CONNECT" });
      this.finish(p.down, p.target, "NONE/503", [UNAVAILABLE], ctx, {}, true);
      return true;
    }
    // 응답을 끝까지(대상의 FIN 까지) 받았을 때만 전달. FIN 없이 끊긴(RST·timeout) 일부 응답은 503
    const body = responseBytes(up);
    if (body > 0 && up.finReceived) {
      const status = up.status ?? "HTTP 200";
      const n = Math.max(1, Math.ceil(body / RESPONSE_SEGMENT_BYTES));
      ctx.trace(
        "proxy.relay",
        "app",
        `프록시: ${p.target} 의 응답 (${status}, ${body}B) 을 ${p.down.remoteIp} 에게 전달${up.setCookie ? ` — Set-Cookie 도 그대로` : ""}`,
        { client: p.down.remoteIp, target: p.target, ip: up.remoteIp, status, bytes: body, result: `TCP_MISS/${status.split(" ")[1] ?? "200"}` },
      );
      this.finish(
        p.down,
        p.target,
        `TCP_MISS/${status.split(" ")[1] ?? "200"}`,
        Array.from({ length: n }, (_, k) => ({ len: Math.min(RESPONSE_SEGMENT_BYTES, body - k * RESPONSE_SEGMENT_BYTES), data: status === "HTTP 200" ? `HTTP 200 (${k + 1}/${n})` : status })),
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

  /** 터널의 한쪽이 끝남: 다른 쪽이 열려 있으면 닫고 (실패면 RST), 둘 다 끝나면 기록 */
  private closeTunnel(t: Tunnel, conn: TcpConn, ctx: NodeContext): void {
    const other = conn === t.up ? t.down : t.up;
    if (other.state === "ESTABLISHED") {
      if (conn.state === "FAILED") this.tcp.reset(other, `CONNECT ${t.target} 터널 반대편 연결 실패 (${conn.reason ?? "?"})`, ctx);
      else this.tcp.disconnect(other.id, ctx);
    }
    const done = (c: TcpConn) => c.state === "CLOSED" || c.state === "FAILED";
    if (!this.tunnels.has(conn.id) || !done(t.up) || !done(t.down)) return;
    this.tunnels.delete(t.up.id);
    this.tunnels.delete(t.down.id);
    ctx.trace(
      "proxy.relay",
      "app",
      `프록시: CONNECT ${t.target} 터널 닫힘 — 클라이언트 ${t.down.remoteIp} 에게 ${t.down.bytesSent}B, 대상에게 ${t.up.bytesSent}B 를 넘김 (내용은 암호화돼 모름)`,
      { client: t.down.remoteIp, target: t.target, ip: t.up.remoteIp, bytes: t.down.bytesSent, result: "TCP_TUNNEL/200", method: "CONNECT" },
    );
    this.record(t.down, t.target, "TCP_TUNNEL/200", ctx, true);
  }

  private finish(down: TcpConn, target: string, result: string, parts: { len: number; data: string }[], ctx: NodeContext, meta: { origin?: string; setCookie?: string } = {}, connect = false): void {
    this.record(down, target, result, ctx, connect);
    this.tcp.respond(down, parts, ctx, meta);
  }

  private record(down: TcpConn, target: string, result: string, ctx: NodeContext, connect = false): void {
    this.log.push({ at: ctx.now, client: down.remoteIp, target, result, ...(connect ? { method: "CONNECT" as const } : {}) });
    if (this.log.length > LOG_MAX) this.log.shift();
  }

  rows(): string[][] {
    return [...this.log].reverse().map((e) => [e.client, e.method ? `${e.method} ${e.target}` : e.target, e.result]);
  }
}
