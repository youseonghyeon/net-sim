// 학습용 축소 TCP: 3-way handshake, 누적 ACK, 타임아웃 재전송, FIN 종료, RST.
// 슬라이딩 윈도우·혼잡 제어는 없다. 앱 계층은 두 가지:
// - HTTP 흉내 (기본): "요청 1개 → 응답 N 세그먼트" 뒤 서버가 FIN
// - SSH 흉내 (포트 22): 버전 교환 → 키 교환 → 인증 뒤 세션을 열어 둔 채 유지. 사용자가 "연결 해제" 하면 FIN.
//   명령은 주고받지 않는다 (내용은 암호화라 보여 줄 것도 없다). 오래 열린 연결이 NAT·방화벽·이중화 변화에 어떻게 반응하는지 보는 용도
//   (keepalive 없음 — 조용한 세션은 경로가 끊겨도 모르고, 다음에 보낼 때 알게 된다)
// - HTTPS 흉내 (포트 443, TLS 1.3 축소판): ClientHello(SNI) → ServerHello·인증서·Finished → Finished 뒤 HTTP 흉내를 암호화해 주고받는다.
//   중간 장비는 SNI 와 길이만 보고, 요청·응답 내용은 두 끝만 안다
// - 프록시 CONNECT: 끝 클라이언트가 프록시에게 "CONNECT 호스트:443" → 200 Connection established 뒤 같은 연결로 대상과 TLS.
//   프록시의 두 연결(relay)은 앱 흉내 없이 받은 것을 앱(proxy.ts)에게 넘겨 반대편으로 그대로 보낸다
import type { Ip } from "../addr";
import { isIpv6 } from "../addr6";
import { tcpFlags, type IpPacket, type TcpSegment } from "../packet";
import { looksLikeName } from "./dns";
import type { NodeContext, TimerHandle } from "./node";

export type TcpState = "SYN_SENT" | "SYN_RCVD" | "ESTABLISHED" | "FIN_WAIT_1" | "FIN_WAIT_2" | "CLOSE_WAIT" | "LAST_ACK" | "CLOSED" | "FAILED";

export const TCP_STATE_LABEL: Record<TcpState, string> = {
  SYN_SENT: "SYN 보냄 (응답 대기)",
  SYN_RCVD: "SYN 받음 (ACK 대기)",
  ESTABLISHED: "연결됨",
  FIN_WAIT_1: "종료 요청 보냄",
  FIN_WAIT_2: "상대 종료 대기",
  CLOSE_WAIT: "상대가 종료 요청",
  LAST_ACK: "마지막 ACK 대기",
  CLOSED: "종료됨",
  FAILED: "실패",
};

export const TCP_RTO = 400;
export const TCP_MAX_RETRIES = 3;
export const TCP_TIMER_TAG = "tcp-rto";
/** 요청을 보낸 뒤 응답 첫 바이트를 기다리는 시간 (HTTP 클라이언트의 read timeout). 중간 로드밸런서가 끊겨도 영원히 기다리지 않게 */
export const TCP_READ_TIMEOUT = 10_000;
export const CLIENT_ISS = 1000;
export const SERVER_ISS = 3000;
const EPHEMERAL_START = 49152;
const REQUEST_BYTES = 100;
const RESPONSE_SEGMENT_BYTES = 1000;
export const SSH_PORT = 22;
export const HTTPS_PORT = 443;
/** TLS 1.3 축소판의 핸드셰이크 메시지 (한 레코드 = 한 세그먼트) */
const TLS_CLIENT_HELLO = { len: 300, data: "ClientHello" };
const TLS_SERVER_HELLO = { len: 1400, data: "ServerHello·인증서·Finished" };
const TLS_CLIENT_FINISHED = { len: 80, data: "Finished" };
/** 프록시가 CONNECT 터널을 열었다는 응답 */
export const CONNECT_ESTABLISHED = "HTTP 200 Connection established";
/** SSH 세션을 여는 주고받기 (클라이언트 → 서버 → 클라이언트 → …). 마지막 서버 메시지를 받으면 세션이 열린다 */
const SSH_STEPS: { from: "client" | "server"; len: number; data: string }[] = [
  { from: "client", len: 40, data: "SSH-2.0 버전 알림" },
  { from: "server", len: 40, data: "SSH-2.0 버전 알림" },
  { from: "client", len: 600, data: "키 교환 요청 (KEXINIT·ECDH)" },
  { from: "server", len: 700, data: "키 교환 응답 (호스트 키·서명)" },
  { from: "client", len: 200, data: "NEWKEYS·사용자 인증 (암호화됨)" },
  { from: "server", len: 100, data: "인증 성공 (암호화됨)" },
];

interface Unacked {
  seg: TcpSegment;
  retries: number;
  timer: TimerHandle;
}

export interface TcpConn {
  id: string;
  role: "client" | "server";
  localIp: Ip;
  localPort: number;
  remoteIp: Ip;
  remotePort: number;
  state: TcpState;
  iss: number;
  sndNxt: number;
  sndUna: number;
  rcvNxt: number;
  unacked: Unacked[];
  retransmits: number;
  bytesSent: number;
  bytesReceived: number;
  /** 서버가 보낼 응답 세그먼트 수 */
  responseSegments: number;
  /** 상대의 FIN 을 받았는지 */
  finReceived: boolean;
  createdAt: number;
  closedAt?: number;
  reason?: string;
  /** 서버: 앱(로드밸런서)이 요청을 맡아 응답을 미뤘는지 */
  deferred?: boolean;
  /** 클라이언트: 응답을 실제로 만든 서버 (로드밸런서 뒤의 백엔드) */
  servedBy?: string;
  /** 클라이언트: 받은 응답의 상태 줄 (예: "HTTP 200", "HTTP 502 Bad Gateway") */
  status?: string;
  /** 요청이 거친 로드밸런서 수 (클라이언트: 보낼 값, 서버: 받은 값) */
  via?: number;
  /** 요청의 Cookie (클라이언트: 보낸 값, 서버: 받은 값) */
  cookie?: string;
  /** 클라이언트: 응답의 Set-Cookie */
  setCookie?: string;
  /** 프록시 경유 요청의 대상 "호스트:포트" (클라이언트: 프록시에게 부탁한 곳, 서버: 받은 값) */
  target?: string;
  /** 끝 클라이언트: 쿠키를 저장·찾는 사이트 (사용자가 적은 호스트 — 이름 또는 주소) */
  site?: string;
  /** 클라이언트: 응답 대기 timeout 타이머 */
  readTimer?: TimerHandle;
  /** SSH 흉내 (포트 22): 지금까지 주고받은 메시지 수, 세션이 열렸는지 */
  ssh?: { step: number; open: boolean };
  /** 요청 메서드 CONNECT (클라이언트: 프록시에게 보냄, 서버: 받음) */
  method?: "CONNECT";
  /** 끝 클라이언트의 CONNECT 터널: 프록시의 응답을 기다림 → 열림 (그 뒤 이 연결로 대상과 TLS) */
  tunnel?: "wait" | "up";
  /** 중계 연결 (프록시의 CONNECT 터널 양쪽): 앱 흉내 없이 받은 데이터·FIN 을 앱에게 넘긴다 */
  relay?: boolean;
  /** TLS (포트 443): 핸드셰이크가 끝났는지, 핸드셰이크로 보낸 바이트 (서버가 응답을 이미 보냈는지 가를 때 뺀다), SNI */
  tls?: { done: boolean; sent: number; sni?: string };
  /** 클라이언트: 응답이 아니라 연결 준비로 받은 바이트 (CONNECT 응답·TLS 핸드셰이크) — 응답 크기에서 뺀다 */
  setupReceived?: number;
}

/** 받은 응답 본문 크기 (CONNECT 응답·TLS 핸드셰이크 제외) */
export function responseBytes(conn: TcpConn): number {
  return conn.bytesReceived - (conn.setupReceived ?? 0);
}

export interface TcpHost {
  /** 세그먼트를 IP 패킷으로 감싸 내보낸다 */
  send(pkt: IpPacket, ctx: NodeContext): void;
  /** 서버 연결에 요청이 도착: true 를 돌려주면 앱이 맡아 나중에 respond() 로 응답한다 (로드밸런서) */
  onRequest?(conn: TcpConn, ctx: NodeContext): boolean;
  /** 연결이 끝남 (정상 종료·거부·timeout·중단) */
  onFinish?(conn: TcpConn, ctx: NodeContext): void;
  /** 중계 연결(relay)이 맺어짐 (프록시가 CONNECT 대상에 연결됨) */
  onEstablished?(conn: TcpConn, ctx: NodeContext): void;
  /** 중계 연결로 데이터(세그먼트)나 FIN(undefined)이 옴: 앱이 반대편 연결로 넘긴다 */
  onRelay?(conn: TcpConn, seg: TcpSegment | undefined, ctx: NodeContext): void;
}

/** 응답 세그먼트 하나 */
export interface ResponsePart {
  len: number;
  data: string;
}

/** 요청에 붙이는 것 */
export interface ConnectOptions {
  /** 이 요청이 이미 거친 로드밸런서·프록시 수 (그들이 뒤로 보낼 때만). 있으면 쿠키 저장소를 쓰지 않는다 (중계 연결) */
  via?: number;
  /** 프록시에게 부탁할 대상 "호스트:포트" (요청 줄이 절대 URI) */
  target?: string;
  /** 보낼 Cookie. 없으면 끝 클라이언트는 쿠키 저장소에서 찾는다 */
  cookie?: string;
  /** 쿠키의 사이트 (사용자가 적은 이름). 없으면 프록시 대상의 호스트, 그것도 없으면 접속한 주소 */
  site?: string;
  /** SYN 을 보내기 전에 부른다. 내 주소로 가는 루프백은 connect 안에서 연결이 끝까지 진행되므로, 추적할 쪽은 여기서 등록한다 */
  onCreated?: (conn: TcpConn) => void;
  /** CONNECT: 프록시에게 target 까지 터널을 열어 달라고 한다 (HTTPS) */
  method?: "CONNECT";
  /** 중계 연결: 맺어지면 요청을 보내지 않고 host.onEstablished, 받은 것은 host.onRelay 로 */
  relay?: boolean;
}

/** 응답에 붙이는 것 */
export interface ResponseMeta {
  /** 응답을 실제로 만든 서버 (X-Served-By 흉내) */
  origin?: string;
  /** 첫 응답 세그먼트에 싣는 Set-Cookie */
  setCookie?: string;
}

/** 연결에 실어 보낼 데이터 한 덩어리: 길이·내용과 헤더 흉내 필드 (터널 중계는 받은 세그먼트의 이것들을 그대로 넘긴다) */
export type RelayPart = { len: number } & Partial<Pick<TcpSegment, "data" | "tls" | "sni" | "origin" | "via" | "cookie" | "setCookie" | "target" | "method">>;

/** 받은 데이터의 요약: TLS 면 레코드 종류 (중계하는 프록시는 안을 모른다, 끝 장치는 풀어 본다) */
function describeData(seg: TcpSegment, relay: boolean): string {
  switch (seg.tls) {
    case "client-hello":
      return `TLS ClientHello${seg.sni ? ` (SNI ${seg.sni}${relay ? " — 암호화 전이라 보임" : ""})` : ""}`;
    case "server-hello":
      return relay ? "TLS ServerHello (인증서·Finished 는 암호화됨)" : `TLS ${seg.data ?? "ServerHello"}`;
    case "finished":
      return relay ? "TLS 핸드셰이크 (암호화됨)" : "TLS Finished";
    case "app":
      return relay ? "TLS 응용 데이터 (암호화됨 — 내용은 모름)" : `TLS 응용 데이터 (복호화: ${seg.data ?? "?"})`;
    default:
      return seg.data ?? "";
  }
}

function connKey(localIp: Ip, localPort: number, remoteIp: Ip, remotePort: number): string {
  return `${endpoint(localIp, localPort)}-${endpoint(remoteIp, remotePort)}`;
}

/** 주소:포트. IPv6 는 주소에 콜론이 있어 대괄호로 감싼다 ([2001:db8::10]:80) */
export function endpoint(ip: Ip, port: number): string {
  return isIpv6(ip) ? `[${ip}]:${port}` : `${ip}:${port}`;
}

/** 쿠키의 사이트: 사용자가 적은 이름, 프록시 경유면 부탁한 대상의 호스트, 아니면 접속한 주소 (브라우저처럼 호스트 이름 기준, 대소문자 무시) */
function siteOf(remoteIp: Ip, target?: string, name?: string): string {
  return (name ?? (target ? target.replace(/:\d+$/, "") : remoteIp)).toLowerCase();
}

export class TcpStack {
  readonly conns = new Map<string, TcpConn>();
  readonly listening = new Set<number>();
  /** 연결을 TLS 로 받는 포트 (HTTPS 서버·TLS 를 푸는 로드밸런서: 443) */
  readonly tlsPorts = new Set<number>();
  /** 쿠키 저장소 (브라우저): 사이트(사용자가 적은 호스트 — 이름 또는 주소, 포트는 보지 않음) → 받은 Set-Cookie. 끝 클라이언트만 쓴다 */
  readonly cookies = new Map<string, string>();
  private nextPort = EPHEMERAL_START;

  constructor(
    private readonly host: TcpHost,
    /** 서버 응답 세그먼트 수 */
    private readonly responseSegments = 3,
  ) {}

  // ---------- 클라이언트 ----------

  connect(localIp: Ip, remoteIp: Ip, remotePort: number, ctx: NodeContext, opts: ConnectOptions = {}): TcpConn {
    const { via, target, onCreated, method, relay } = opts;
    const localPort = this.nextPort++;
    // 쿠키는 끝 클라이언트(브라우저)만: 중계 연결(via 가 있는 로드밸런서·프록시)은 저장소를 쓰지 않는다
    const site = via === undefined ? siteOf(remoteIp, target, opts.site) : undefined;
    const cookie = opts.cookie ?? (site !== undefined ? this.cookies.get(site) : undefined);
    const conn: TcpConn = {
      id: connKey(localIp, localPort, remoteIp, remotePort),
      role: "client",
      localIp,
      localPort,
      remoteIp,
      remotePort,
      state: "SYN_SENT",
      iss: CLIENT_ISS,
      sndNxt: CLIENT_ISS,
      sndUna: CLIENT_ISS,
      rcvNxt: 0,
      unacked: [],
      retransmits: 0,
      bytesSent: 0,
      bytesReceived: 0,
      responseSegments: this.responseSegments,
      finReceived: false,
      createdAt: ctx.now,
      ...(via !== undefined ? { via } : {}),
      ...(target !== undefined ? { target } : {}),
      ...(cookie !== undefined ? { cookie } : {}),
      ...(site !== undefined ? { site } : {}),
      ...(method ? { method } : {}),
      ...(relay ? { relay } : {}),
    };
    this.conns.set(conn.id, conn);
    this.prune();
    onCreated?.(conn);
    ctx.trace("tcp.connect", "L4", `TCP 연결 시작: ${endpoint(localIp, localPort)} → ${endpoint(remoteIp, remotePort)} (초기 seq ${conn.iss})`, { conn: conn.id });
    this.transmit(conn, { syn: true }, ctx, `SYN 전송: "연결하자" seq=${conn.iss}`, "tcp.syn.sent");
    return conn;
  }

  // ---------- 수신 ----------

  handle(pkt: IpPacket, seg: TcpSegment, ctx: NodeContext): void {
    const key = connKey(pkt.dst, seg.dstPort, pkt.src, seg.srcPort);
    let conn = this.conns.get(key);
    const flags = tcpFlags(seg);
    // 끝난 연결과 같은 4-tuple 로 새 SYN 이 오면 옛 기록을 치우고 새로 받는다
    if (conn && (conn.state === "CLOSED" || conn.state === "FAILED") && seg.syn && !seg.ackFlag) {
      this.conns.delete(key);
      conn = undefined;
    }
    if (!conn) {
      if (seg.syn && !seg.ackFlag) {
        this.accept(pkt, seg, ctx);
        return;
      }
      if (!seg.rst) {
        ctx.trace("tcp.rst.sent", "L4", `연결 없는 세그먼트 (${flags} from ${endpoint(pkt.src, seg.srcPort)}) → RST 로 거절`, { from: pkt.src, port: seg.srcPort });
        this.host.send(this.packet(pkt.dst, pkt.src, { srcPort: seg.dstPort, dstPort: seg.srcPort, seq: seg.ack, ack: seg.seq + seg.len + (seg.syn ? 1 : 0) + (seg.fin ? 1 : 0), rst: true, ackFlag: true, len: 0 }), ctx);
      }
      return;
    }
    ctx.trace("tcp.received", "L4", `${flags} 수신 (seq=${seg.seq} ack=${seg.ack}${seg.len ? ` len=${seg.len}` : ""}) [${TCP_STATE_LABEL[conn.state]}]`, { conn: conn.id, seq: seg.seq, ack: seg.ack, len: seg.len });

    if (seg.rst) {
      // 응답을 끝까지(FIN) 받기 전에 끊긴 요청은 실패다 (SSH 세션은 열려 있던 것이 끊긴 것이라 종료로 본다)
      const cut = conn.role === "client" && !conn.ssh && !conn.finReceived && conn.state !== "SYN_SENT";
      conn.state = conn.state === "SYN_SENT" || cut ? "FAILED" : "CLOSED";
      conn.reason = conn.state === "FAILED" ? (cut ? "상대가 RST 로 끊음 (응답을 다 받기 전)" : "연결 거부 (RST)") : "상대가 RST 로 끊음";
      conn.closedAt = ctx.now;
      this.cancelAll(conn);
      ctx.trace(
        conn.state === "FAILED" && !cut ? "tcp.refused" : "tcp.rst.received",
        "L4",
        cut
          ? `RST 수신: 응답을 다 받기 전에 ${endpoint(conn.remoteIp, conn.remotePort)} 가 연결을 끊음 (Connection reset by peer) → 실패`
          : conn.state === "FAILED"
            ? `RST 수신: ${endpoint(conn.remoteIp, conn.remotePort)} 에 그 포트를 듣는 서비스가 없음 → 연결 거부 (Connection refused)`
            : `RST 수신 → 연결 끊김`,
        { conn: conn.id },
      );
      this.host.onFinish?.(conn, ctx);
      return;
    }

    // ACK 처리: 확인된 만큼 재전송 큐에서 제거
    if (seg.ackFlag && seg.ack > conn.sndUna) {
      const acked = seg.ack - conn.sndUna;
      conn.sndUna = seg.ack;
      const before = conn.unacked.length;
      conn.unacked = conn.unacked.filter((u) => {
        const end = u.seg.seq + u.seg.len + (u.seg.syn ? 1 : 0) + (u.seg.fin ? 1 : 0);
        if (end <= seg.ack) {
          u.timer.cancel();
          return false;
        }
        return true;
      });
      if (before > 0) ctx.trace("tcp.ack.received", "L4", `ACK ${seg.ack} 으로 ${acked} 바이트(또는 SYN/FIN) 확인 → 재전송 큐에서 제거 (남은 ${conn.unacked.length})`, { conn: conn.id, ack: seg.ack });
    }

    switch (conn.state) {
      case "SYN_SENT":
        if (seg.syn && seg.ackFlag && seg.ack === conn.iss + 1) {
          conn.rcvNxt = seg.seq + 1;
          conn.state = "ESTABLISHED";
          ctx.trace("tcp.synack.received", "L4", `SYN·ACK 수신: 서버 초기 seq ${seg.seq}, 내 SYN 확인(ack ${seg.ack})`, { conn: conn.id });
          this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송: 3-way handshake 완료 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
          ctx.trace("tcp.established", "L4", `연결 성립 ${endpoint(conn.localIp, conn.localPort)} ↔ ${endpoint(conn.remoteIp, conn.remotePort)}`, { conn: conn.id });
          if (conn.relay) {
            // 중계 연결 (프록시 → CONNECT 대상): 요청은 끝 클라이언트가 터널 너머로 보낸다
            this.host.onEstablished?.(conn, ctx);
            return;
          }
          if (conn.remotePort === SSH_PORT && conn.via === undefined) {
            conn.ssh = { step: 0, open: false };
            this.sshNext(conn, ctx);
            return;
          }
          if (conn.method === "CONNECT") this.sendConnect(conn, ctx);
          // 프록시에게 하는 평문 요청(target — 프록시가 443 에서 들어도)은 TLS 가 아니다
          else if (conn.remotePort === HTTPS_PORT && conn.target === undefined) this.tlsHello(conn, ctx);
          else this.sendRequest(conn, ctx);
        } else {
          ctx.trace("tcp.ignore", "L4", `SYN_SENT 상태에서 기대하지 않은 ${flags} → 무시`, { conn: conn.id });
        }
        return;

      case "SYN_RCVD":
        if (seg.ackFlag && seg.ack === conn.iss + 1) {
          conn.state = "ESTABLISHED";
          ctx.trace("tcp.established", "L4", `ACK 수신 → 3-way handshake 완료, 연결 성립 ${endpoint(conn.localIp, conn.localPort)} ↔ ${endpoint(conn.remoteIp, conn.remotePort)}`, { conn: conn.id });
          if (seg.len > 0) this.receiveData(conn, seg, ctx);
        } else if (seg.syn && !seg.ackFlag) {
          // 클라이언트가 SYN 을 다시 보냄 (내 SYN·ACK 이 손실됨) → SYN·ACK 재전송
          const u = conn.unacked.find((x) => x.seg.syn);
          ctx.trace("tcp.retransmit", "L4", `SYN 이 다시 옴 → 내 SYN·ACK 이 손실된 것으로 보고 즉시 재전송`, { conn: conn.id });
          if (u) this.host.send(this.packet(conn.localIp, conn.remoteIp, u.seg), ctx);
        } else {
          ctx.trace("tcp.ignore", "L4", `SYN_RCVD 상태에서 기대하지 않은 ${flags} → 무시`, { conn: conn.id });
        }
        return;

      case "ESTABLISHED":
      case "FIN_WAIT_1":
      case "FIN_WAIT_2":
      case "CLOSE_WAIT":
      case "LAST_ACK":
        if (seg.len > 0) this.receiveData(conn, seg, ctx);
        if (seg.fin) this.receiveFin(conn, seg, ctx);
        if (conn.state === "FIN_WAIT_1" && conn.unacked.length === 0) {
          if (conn.finReceived) this.close(conn, ctx, "정상 종료");
          else conn.state = "FIN_WAIT_2";
        }
        if (conn.state === "LAST_ACK" && conn.unacked.length === 0) {
          this.close(conn, ctx, "정상 종료");
        }
        return;

      case "CLOSED":
        // 내 마지막 ACK 이 손실되어 상대가 FIN 을 다시 보낸 경우: 다시 ACK 해 준다 (TIME_WAIT 의 역할)
        if (seg.fin || seg.len > 0) {
          ctx.trace("tcp.ack.sent", "L4", `종료된 연결로 ${flags} 가 다시 옴 → 내 마지막 ACK 이 손실된 듯, ACK 재전송 (ack=${conn.rcvNxt})`, { conn: conn.id });
          this.host.send(this.packet(conn.localIp, conn.remoteIp, { srcPort: conn.localPort, dstPort: conn.remotePort, seq: conn.sndNxt, ack: conn.rcvNxt, ackFlag: true, len: 0 }), ctx);
          return;
        }
        ctx.trace("tcp.ignore", "L4", `종료된 연결로 온 ${flags} → 무시`, { conn: conn.id });
        return;

      default:
        ctx.trace("tcp.ignore", "L4", `${TCP_STATE_LABEL[conn.state]} 상태에서 ${flags} → 무시`, { conn: conn.id });
    }
  }

  /** ICMP Destination Unreachable 이 내 연결 시도(SYN)에 대한 것이면 즉시 실패로 끝낸다. 처리했으면 true */
  onUnreachable(o: { dst: Ip; l4: { kind: string; srcPort?: number; dstPort?: number } }, reason: string, ctx: NodeContext): boolean {
    if (o.l4.kind !== "tcp") return false;
    const conn = [...this.conns.values()].find((c) => c.role === "client" && c.localPort === o.l4.srcPort && c.remoteIp === o.dst && c.remotePort === o.l4.dstPort);
    if (!conn || conn.state !== "SYN_SENT") return false;
    conn.state = "FAILED";
    conn.reason = reason;
    conn.closedAt = ctx.now;
    this.cancelAll(conn);
    ctx.trace("tcp.failed", "L4", `TCP 연결 실패: ${reason} → SYN 재전송을 기다리지 않고 바로 포기 (${endpoint(conn.remoteIp, conn.remotePort)})`, { conn: conn.id });
    this.host.onFinish?.(conn, ctx);
    return true;
  }

  /** IP 가 없는 등 시작조차 못 한 연결을 기록에 남긴다 (인스펙터 표시용) */
  recordFailure(localIp: Ip, remoteIp: Ip, remotePort: number, reason: string, ctx: NodeContext): void {
    const localPort = this.nextPort++;
    this.conns.set(connKey(localIp, localPort, remoteIp, remotePort), {
      id: connKey(localIp, localPort, remoteIp, remotePort),
      role: "client",
      localIp,
      localPort,
      remoteIp,
      remotePort,
      state: "FAILED",
      iss: 0,
      sndNxt: 0,
      sndUna: 0,
      rcvNxt: 0,
      unacked: [],
      retransmits: 0,
      bytesSent: 0,
      bytesReceived: 0,
      responseSegments: 0,
      finReceived: false,
      createdAt: ctx.now,
      closedAt: ctx.now,
      reason,
    });
    this.prune();
  }

  /** 끝난 연결이 너무 많이 쌓이지 않게 오래된 것부터 정리 */
  private prune(): void {
    const done = [...this.conns.values()].filter((c) => c.state === "CLOSED" || c.state === "FAILED");
    for (const c of done.slice(0, Math.max(0, done.length - 12))) this.conns.delete(c.id);
  }

  private accept(pkt: IpPacket, seg: TcpSegment, ctx: NodeContext): void {
    if (!this.listening.has(seg.dstPort)) {
      ctx.trace("tcp.rst.sent", "L4", `SYN 수신 (from ${endpoint(pkt.src, seg.srcPort)}) 그러나 포트 ${seg.dstPort} 를 듣는 서비스 없음 → RST 로 거절`, { port: seg.dstPort, from: pkt.src });
      this.host.send(this.packet(pkt.dst, pkt.src, { srcPort: seg.dstPort, dstPort: seg.srcPort, seq: 0, ack: seg.seq + 1, rst: true, ackFlag: true, len: 0 }), ctx);
      return;
    }
    const conn: TcpConn = {
      id: connKey(pkt.dst, seg.dstPort, pkt.src, seg.srcPort),
      role: "server",
      localIp: pkt.dst,
      localPort: seg.dstPort,
      remoteIp: pkt.src,
      remotePort: seg.srcPort,
      state: "SYN_RCVD",
      iss: SERVER_ISS,
      sndNxt: SERVER_ISS,
      sndUna: SERVER_ISS,
      rcvNxt: seg.seq + 1,
      unacked: [],
      retransmits: 0,
      bytesSent: 0,
      bytesReceived: 0,
      responseSegments: this.responseSegments,
      finReceived: false,
      createdAt: ctx.now,
      ...(this.tlsPorts.has(seg.dstPort) ? { tls: { done: false, sent: 0 } } : {}),
    };
    this.conns.set(conn.id, conn);
    this.prune();
    ctx.trace("tcp.syn.received", "L4", `SYN 수신: ${endpoint(pkt.src, seg.srcPort)} 가 포트 ${seg.dstPort} 로 연결 요청 (seq ${seg.seq}) → 듣는 서비스 있음`, { conn: conn.id });
    this.transmit(conn, { syn: true, ackFlag: true }, ctx, `SYN·ACK 전송: "좋다, 내 초기 seq 는 ${conn.iss}" (ack=${conn.rcvNxt})`, "tcp.synack.sent");
  }

  private receiveData(conn: TcpConn, seg: TcpSegment, ctx: NodeContext): void {
    if (seg.seq < conn.rcvNxt) {
      ctx.trace("tcp.dup", "L4", `이미 받은 데이터 (seq ${seg.seq} < 기대 ${conn.rcvNxt}) → 드롭하고 ACK ${conn.rcvNxt} 다시 보냄`, { conn: conn.id });
      this.transmit(conn, { ackFlag: true }, ctx, `ACK 재전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
      return;
    }
    if (seg.seq > conn.rcvNxt) {
      ctx.trace("tcp.out-of-order", "L4", `순서가 어긋난 데이터 (seq ${seg.seq}, 기대 ${conn.rcvNxt}) → 중간 세그먼트가 손실됨. 드롭하고 중복 ACK ${conn.rcvNxt} 로 재요청`, { conn: conn.id });
      this.transmit(conn, { ackFlag: true }, ctx, `중복 ACK 전송 (ack=${conn.rcvNxt}): "여기부터 다시 보내라"`, "tcp.ack.sent");
      return;
    }
    conn.rcvNxt = seg.seq + seg.len;
    conn.bytesReceived += seg.len;
    ctx.trace("tcp.data.received", "L4", `데이터 수신: ${describeData(seg, conn.relay === true)} ${seg.len}B (seq ${seg.seq}) → 누적 ${conn.bytesReceived}B, 다음 기대 seq ${conn.rcvNxt}`, { conn: conn.id, seq: seg.seq, len: seg.len });
    // 중계 연결 (프록시의 CONNECT 터널): 받은 것을 확인하고 앱이 반대편으로 그대로 넘긴다
    if (conn.relay) {
      this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
      this.host.onRelay?.(conn, seg, ctx);
      return;
    }
    if (conn.role === "client") {
      if (seg.origin) conn.servedBy = seg.origin;
      // 터널이 열렸다는 CONNECT 응답은 요청의 결과가 아니다 (결과는 터널 너머 서버의 응답)
      if (conn.status === undefined && seg.data && !(conn.tunnel === "wait" && seg.data === CONNECT_ESTABLISHED)) conn.status = /^HTTP \d{3}( [A-Za-z ]+)?/.exec(seg.data)?.[0].trim();
      if (seg.setCookie) {
        conn.setCookie = seg.setCookie;
        // 끝 클라이언트(브라우저)만 저장해 다음 요청부터 싣는다. 중계 연결(로드밸런서·프록시)은 받은 것을 앞으로 넘길 뿐
        if (conn.site !== undefined) {
          this.cookies.set(conn.site, seg.setCookie);
          ctx.trace("tcp.cookie", "app", `Set-Cookie 수신: ${seg.setCookie} → 쿠키 저장, 이 사이트로 가는 다음 요청부터 Cookie 헤더로 보냄`, { conn: conn.id, cookie: seg.setCookie });
        }
      }
      // 응답 대기 timeout 은 "마지막으로 받은 뒤 10초" (HTTP read timeout 처럼 받을 때마다 다시 잰다) — 응답이 중간에 멈춰도 끝난다.
      // FIN 을 받으면 끝(receiveFin). SSH 는 단계마다 sshNext 가 따로 건다
      conn.readTimer?.cancel();
      conn.readTimer = !conn.ssh && conn.state === "ESTABLISHED" ? ctx.timer(TCP_READ_TIMEOUT, TCP_TIMER_TAG, { conn: conn.id, read: true }) : undefined;
    }
    if (conn.role === "server") {
      if (seg.via !== undefined) conn.via = seg.via;
      if (seg.cookie !== undefined) conn.cookie = seg.cookie;
      if (seg.target !== undefined) conn.target = seg.target;
      if (seg.method !== undefined) conn.method = seg.method;
    }
    // SSH 흉내: 상대 메시지를 받으면 다음 차례 메시지를 보낸다
    if (conn.ssh && conn.state === "ESTABLISHED") {
      conn.ssh.step++;
      this.sshNext(conn, ctx);
      return;
    }
    // CONNECT 응답·TLS 핸드셰이크 (요청·응답은 그 뒤)
    if (conn.state === "ESTABLISHED" && (conn.tunnel === "wait" || (conn.tls && !conn.tls.done))) {
      this.handshake(conn, seg, ctx);
      return;
    }
    // TLS 가 아닌 포트로 ClientHello (L4·포트 포워딩이 443 을 평문 80 으로 넘김 등): nginx 처럼 400 — 요청으로 받아 답하지 않는다
    if (conn.role === "server" && conn.state === "ESTABLISHED" && seg.tls === "client-hello" && conn.bytesSent === 0 && !conn.deferred) {
      conn.deferred = true;
      ctx.trace("tls.fail", "app", `TLS ClientHello 가 평문 포트 ${conn.localPort} 로 옴 → HTTP 요청이 아니므로 400 Bad Request (HTTPS 를 받으려면 443 을 TLS 로 받는 서버로 보내야 함)`, { conn: conn.id });
      this.respond(conn, [{ len: 200, data: "HTTP 400 Bad Request" }], ctx);
      return;
    }
    // 응답을 아직 안 보낸 서버 연결 (TLS 면 핸드셰이크로 보낸 것은 빼고 센다)
    if (conn.role === "server" && conn.state === "ESTABLISHED" && conn.bytesSent === (conn.tls?.sent ?? 0) && !conn.deferred) {
      // 앱이 요청을 맡으면(로드밸런서·프록시) 받았다는 ACK 만 보내고 응답은 나중에.
      // 상태를 먼저 세운다: 뒤 서버가 내 주소(루프백)면 onRequest 안에서 응답까지 끝날 수 있고, 그때는 응답이 곧 ACK 다
      conn.deferred = true;
      if (this.host.onRequest?.(conn, ctx)) {
        if (conn.state === "ESTABLISHED" && conn.bytesSent === (conn.tls?.sent ?? 0)) this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송 (ack=${conn.rcvNxt}) — 요청을 받았고, 응답은 뒤 서버에서 받아 오는 대로 보냄`, "tcp.ack.sent");
        return;
      }
      delete conn.deferred;
      // 프록시가 아닌 서버가 CONNECT 를 받음 (프록시 설정이 웹 서버를 가리킴): 터널을 열 줄 모른다
      if (conn.method === "CONNECT") {
        ctx.trace("tcp.data.received", "app", `CONNECT ${conn.target ?? "?"} 요청을 받았지만 이 포트(${conn.localPort})는 프록시가 아님 → 405 Method Not Allowed`, { conn: conn.id });
        this.respond(conn, [{ len: 200, data: "HTTP 405 Method Not Allowed" }], ctx);
        return;
      }
      // 로드밸런서가 맡지 않은 포트 22 = SSH 서버: 클라이언트의 첫 메시지(버전 알림)를 받았으니 내 차례
      if (conn.localPort === SSH_PORT && conn.via === undefined) {
        conn.ssh = { step: 1, open: false };
        this.sshNext(conn, ctx);
        return;
      }
      // 앱: 요청을 받았으니 응답 세그먼트를 연달아 보내고 FIN
      const n = conn.responseSegments;
      this.respond(conn, Array.from({ length: n }, (_, k) => ({ len: RESPONSE_SEGMENT_BYTES, data: `HTTP 200 (${k + 1}/${n})` })), ctx);
      return;
    }
    this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
  }

  /** SSH 흉내: 내 차례면 다음 메시지를 보내고, 마지막 메시지까지 오갔으면 세션을 연다 */
  private sshNext(conn: TcpConn, ctx: NodeContext): void {
    const ssh = conn.ssh!;
    conn.readTimer?.cancel();
    conn.readTimer = undefined;
    if (ssh.step >= SSH_STEPS.length) {
      this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
      if (!ssh.open) {
        ssh.open = true;
        ctx.trace(
          "ssh.open",
          "app",
          conn.role === "client"
            ? `SSH 세션 열림: ${endpoint(conn.remoteIp, conn.remotePort)} 와 키 교환·인증 끝 → 연결을 열어 둔 채 유지 (명령은 주고받지 않음. "연결 해제" 로 닫음)`
            : `SSH 세션 열림: ${endpoint(conn.remoteIp, conn.remotePort)} 가 인증함 → 연결을 열어 둔 채 유지`,
          { conn: conn.id },
        );
      }
      return;
    }
    const step = SSH_STEPS[ssh.step]!;
    if (step.from !== conn.role) {
      // 상대 차례: 받은 것만 확인하고 기다린다
      this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
      return;
    }
    // 상태를 먼저 갱신하고 보낸다: 내 주소로 보내는 루프백은 transmit 안에서 상대 응답까지 돌아온다
    const n = ssh.step;
    ssh.step++;
    const opens = ssh.step >= SSH_STEPS.length && conn.role === "server";
    if (opens) ssh.open = true;
    // 클라이언트: 서버의 다음 메시지를 기다린다 (영원히 안 오면 끝나지 않으므로 timeout)
    if (conn.role === "client") conn.readTimer = ctx.timer(TCP_READ_TIMEOUT, TCP_TIMER_TAG, { conn: conn.id, read: true, step: ssh.step });
    this.transmit(conn, { ackFlag: true, len: step.len, data: step.data }, ctx, `SSH ${n + 1}/${SSH_STEPS.length}: ${step.data} ${step.len}B 전송 (seq=${conn.sndNxt})`, "tcp.data.sent");
    if (opens) ctx.trace("ssh.open", "app", `SSH 세션 열림: ${endpoint(conn.remoteIp, conn.remotePort)} 가 인증함 → 연결을 열어 둔 채 유지`, { conn: conn.id });
  }

  /** 앱: 요청 전송 (TLS 가 끝났으면 암호화해서). 응답이 영원히 안 오면 끝나지 않으므로 응답 대기 timeout 을 건다 */
  private sendRequest(conn: TcpConn, ctx: NodeContext): void {
    const tls = conn.tls?.done === true;
    // 프록시에게 대신 받아 달라는 요청만 절대 URI. CONNECT 터널 안의 요청은 대상 서버에게 직접 하는 요청이다
    const absolute = conn.target !== undefined && conn.method !== "CONNECT";
    const line = absolute ? `GET http://${conn.target!.replace(/:80$/, "")}/` : "GET /";
    const notes = [
      absolute ? `프록시에게 ${conn.target} 를 대신 받아 달라고 부탁 (요청 줄이 절대 URI)` : "",
      conn.via ? `로드밸런서·프록시 ${conn.via}개 거침 (Via)` : "",
      conn.cookie ? `Cookie: ${conn.cookie}` : "",
    ].filter(Boolean);
    this.transmit(
      conn,
      {
        ackFlag: true,
        len: REQUEST_BYTES,
        data: line,
        ...(conn.via !== undefined ? { via: conn.via } : {}),
        ...(absolute ? { target: conn.target } : {}),
        ...(conn.cookie ? { cookie: conn.cookie } : {}),
        ...(tls ? { tls: "app" as const } : {}),
      },
      ctx,
      tls
        ? `암호화된 요청 전송: TLS 응용 데이터 ${REQUEST_BYTES}B (안: "${line}") (seq=${conn.sndNxt})${notes.length ? ` — ${notes.join(", ")}` : ""}`
        : `요청 데이터 전송: "${line}" ${REQUEST_BYTES}B (seq=${conn.sndNxt})${notes.length ? ` — ${notes.join(", ")}` : ""}`,
      "tcp.data.sent",
    );
    this.armRead(conn, ctx);
  }

  /** 끝 클라이언트: 프록시에게 CONNECT (HTTPS 는 내용이 암호화돼 프록시가 대신 받아 올 수 없어 통로만 빌린다) */
  private sendConnect(conn: TcpConn, ctx: NodeContext): void {
    conn.tunnel = "wait";
    const line = `CONNECT ${conn.target}`;
    this.transmit(
      conn,
      { ackFlag: true, len: REQUEST_BYTES, data: line, method: "CONNECT", target: conn.target },
      ctx,
      `CONNECT 요청 전송: "${line}" ${REQUEST_BYTES}B (seq=${conn.sndNxt}) — 프록시에게 ${conn.target} 까지 TCP 터널을 열어 달라고 부탁 (HTTPS 는 암호화돼 프록시가 대신 받아 올 수 없어 통로만 빌린다)`,
      "tcp.data.sent",
    );
    this.armRead(conn, ctx);
  }

  /** 클라이언트: TLS 핸드셰이크 시작 (ClientHello). SNI 는 사용자가 적은 이름 (주소로 접속하면 없음) */
  private tlsHello(conn: TcpConn, ctx: NodeContext): void {
    const sni = conn.site !== undefined && looksLikeName(conn.site) ? conn.site : undefined;
    conn.tls = { done: false, sent: 0, ...(sni ? { sni } : {}) };
    ctx.trace(
      "tls.hello",
      "app",
      `TLS 핸드셰이크 시작: ClientHello 전송${sni ? ` (SNI ${sni} — 접속할 이름. 암호화 전이라 중간 장비도 본다)` : " (주소로 접속해 SNI 없음)"}${conn.tunnel ? ` — 프록시 터널을 지나 ${conn.target} 에 직접` : ""}`,
      { conn: conn.id, role: "client", ...(sni ? { sni } : {}) },
    );
    this.transmit(conn, { ackFlag: true, len: TLS_CLIENT_HELLO.len, data: TLS_CLIENT_HELLO.data, tls: "client-hello", ...(sni ? { sni } : {}) }, ctx, `TLS ClientHello ${TLS_CLIENT_HELLO.len}B 전송 (seq=${conn.sndNxt})`, "tcp.data.sent");
    this.armRead(conn, ctx);
  }

  /** CONNECT 응답과 TLS 핸드셰이크 메시지를 받았을 때 */
  private handshake(conn: TcpConn, seg: TcpSegment, ctx: NodeContext): void {
    if (conn.tunnel === "wait") {
      if (seg.data === CONNECT_ESTABLISHED) {
        conn.tunnel = "up";
        conn.setupReceived = (conn.setupReceived ?? 0) + seg.len;
        ctx.trace("proxy.tunnel", "app", `프록시가 ${conn.target} 까지 터널을 열었음 (${CONNECT_ESTABLISHED}) → 이 연결 그대로 대상 서버와 TLS 핸드셰이크. 프록시는 이제 바이트만 전달한다`, { conn: conn.id, target: conn.target, client: true });
        this.tlsHello(conn, ctx);
        return;
      }
      // 거절 (403·503 등): 상태 줄을 남기고(receiveData) 프록시의 FIN 을 기다린다
      this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송 (ack=${conn.rcvNxt}) — 프록시가 터널을 열지 않음 (${conn.status ?? seg.data ?? "?"})`, "tcp.ack.sent");
      return;
    }
    const tls = conn.tls!;
    if (conn.role === "client") {
      if (seg.tls !== "server-hello") {
        // 443 에서 TLS 가 아닌 답 (프록시·평문 서버): curl 의 "wrong version number"
        conn.state = "FAILED";
        conn.reason = "TLS 핸드셰이크 실패 · 상대가 TLS 로 답하지 않음";
        conn.closedAt = ctx.now;
        this.cancelAll(conn);
        ctx.trace("tls.fail", "app", `TLS 핸드셰이크 실패: ServerHello 대신 TLS 가 아닌 데이터(${seg.data ?? "?"})가 옴 → RST 로 끊음. ${endpoint(conn.remoteIp, conn.remotePort)} 가 HTTPS 서버가 맞는지 확인`, { conn: conn.id });
        this.host.send(this.packet(conn.localIp, conn.remoteIp, { srcPort: conn.localPort, dstPort: conn.remotePort, seq: conn.sndNxt, ack: conn.rcvNxt, rst: true, ackFlag: true, len: 0 }), ctx);
        this.host.onFinish?.(conn, ctx);
        return;
      }
      // 상태를 먼저 세우고 보낸다 (루프백이면 transmit 안에서 서버가 곧바로 답한다)
      tls.done = true;
      conn.setupReceived = (conn.setupReceived ?? 0) + seg.len;
      ctx.trace("tls.established", "app", `TLS 핸드셰이크 완료: 서버 인증서${tls.sni ? `(${tls.sni})` : ""}를 확인하고 세션 키를 정함 → Finished 뒤 요청부터 암호화 (중간 장비는 길이만 본다)`, { conn: conn.id, role: "client", ...(tls.sni ? { sni: tls.sni } : {}) });
      this.transmit(conn, { ackFlag: true, len: TLS_CLIENT_FINISHED.len, data: TLS_CLIENT_FINISHED.data, tls: "finished" }, ctx, `TLS Finished ${TLS_CLIENT_FINISHED.len}B 전송 (seq=${conn.sndNxt}, 암호화됨)`, "tcp.data.sent");
      this.sendRequest(conn, ctx);
      return;
    }
    if (seg.tls === "client-hello") {
      if (seg.sni) tls.sni = seg.sni;
      ctx.trace("tls.hello", "app", `TLS ClientHello 수신${seg.sni ? ` (SNI ${seg.sni})` : " (SNI 없음)"} → ServerHello·인증서·Finished 로 답함 (인증서로 내가 누구인지 증명, 이후 내용은 암호화)`, { conn: conn.id, role: "server", ...(seg.sni ? { sni: seg.sni } : {}) });
      tls.sent = conn.bytesSent + TLS_SERVER_HELLO.len;
      this.transmit(conn, { ackFlag: true, len: TLS_SERVER_HELLO.len, data: TLS_SERVER_HELLO.data, tls: "server-hello" }, ctx, `TLS ServerHello·인증서·Finished ${TLS_SERVER_HELLO.len}B 전송 (seq=${conn.sndNxt}, 인증서부터 암호화)`, "tcp.data.sent");
      return;
    }
    if (seg.tls === "finished") {
      tls.done = true;
      ctx.trace("tls.established", "app", `TLS 핸드셰이크 완료: 클라이언트 Finished 확인 → 암호화된 요청을 기다림`, { conn: conn.id, role: "server" });
      this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
      return;
    }
    // 평문 요청이 HTTPS 포트로 (프록시 설정이 이 서버의 443 을 가리키는 등): nginx 의 "The plain HTTP request was sent to HTTPS port"
    ctx.trace("tls.fail", "app", `TLS 가 아닌 평문 요청(${seg.data ?? "?"})이 HTTPS 포트 ${conn.localPort} 로 옴 → 400 Bad Request (평문 HTTP 요청을 HTTPS 포트로 보냄)`, { conn: conn.id });
    conn.tls = undefined;
    this.respond(conn, [{ len: 200, data: "HTTP 400 Bad Request" }], ctx);
  }

  /** 클라이언트의 응답 대기 timeout 을 (다시) 건다 */
  private armRead(conn: TcpConn, ctx: NodeContext): void {
    conn.readTimer?.cancel();
    conn.readTimer = ctx.timer(TCP_READ_TIMEOUT, TCP_TIMER_TAG, { conn: conn.id, read: true });
  }

  /** 연결을 연 채로 데이터 한 덩어리를 보낸다 (프록시의 CONNECT 응답·터널 중계). 보낼 수 없는 상태면 false */
  sendData(conn: TcpConn, part: RelayPart, ctx: NodeContext, summary: string, note?: string): boolean {
    if (conn.state !== "ESTABLISHED") return false;
    this.transmit(conn, { ackFlag: true, ...part }, ctx, `${summary} ${part.len}B (seq=${conn.sndNxt})${note ? ` — ${note}` : ""}`, "tcp.data.sent");
    return true;
  }

  /** 연결을 RST 로 끊는다 (터널 반대편이 실패했을 때) */
  reset(conn: TcpConn, reason: string, ctx: NodeContext): void {
    if (conn.state === "CLOSED" || conn.state === "FAILED") return;
    conn.state = "FAILED";
    conn.reason = reason;
    conn.closedAt = ctx.now;
    this.cancelAll(conn);
    ctx.trace("tcp.rst.sent", "L4", `${reason} → ${endpoint(conn.remoteIp, conn.remotePort)} 연결을 RST 로 끊음`, { conn: conn.id });
    this.host.send(this.packet(conn.localIp, conn.remoteIp, { srcPort: conn.localPort, dstPort: conn.remotePort, seq: conn.sndNxt, ack: conn.rcvNxt, rst: true, ackFlag: true, len: 0 }), ctx);
    this.host.onFinish?.(conn, ctx);
  }

  /** 사용자가 연결을 닫는다 (SSH "연결 해제"): FIN 을 보내 정상 종료를 시작 */
  disconnect(id: string, ctx: NodeContext): boolean {
    const conn = this.conns.get(id);
    if (!conn || conn.state !== "ESTABLISHED") return false;
    conn.readTimer?.cancel();
    conn.readTimer = undefined;
    conn.state = "FIN_WAIT_1";
    this.transmit(conn, { fin: true, ackFlag: true }, ctx, `FIN 전송: 연결 해제 요청 (seq=${conn.sndNxt})`, "tcp.fin.sent");
    return true;
  }

  /** 서버 연결로 응답 세그먼트를 보내고 FIN. origin 을 주면 세그먼트에 "응답을 만든 서버" 를, setCookie 는 첫 세그먼트에 싣는다 */
  respond(conn: TcpConn, parts: ResponsePart[], ctx: NodeContext, meta: ResponseMeta = {}): void {
    if (conn.state !== "ESTABLISHED") return; // 기다리는 동안 클라이언트가 끊었으면 보낼 곳이 없다
    const { origin, setCookie } = meta;
    const tls = conn.tls?.done === true;
    parts.forEach((p, k) => {
      const cookie = k === 0 && setCookie ? setCookie : undefined;
      const notes = `${origin ? ` — 만든 서버 ${origin}` : ""}${cookie ? `, Set-Cookie: ${cookie}` : ""}`;
      this.transmit(
        conn,
        { ackFlag: true, len: p.len, data: p.data, ...(origin ? { origin } : {}), ...(cookie ? { setCookie: cookie } : {}), ...(tls ? { tls: "app" as const } : {}) },
        ctx,
        tls
          ? `암호화된 응답 전송 ${k + 1}/${parts.length}: TLS 응용 데이터 ${p.len}B (안: ${p.data}) (seq=${conn.sndNxt})${notes}`
          : `응답 데이터 전송 ${k + 1}/${parts.length}: ${p.data} ${p.len}B (seq=${conn.sndNxt})${notes}`,
        "tcp.data.sent",
      );
    });
    conn.state = "FIN_WAIT_1";
    this.transmit(conn, { fin: true, ackFlag: true }, ctx, `FIN 전송: 응답을 다 보냈으니 종료 요청 (seq=${conn.sndNxt})`, "tcp.fin.sent");
  }

  private receiveFin(conn: TcpConn, seg: TcpSegment, ctx: NodeContext): void {
    if (seg.seq !== conn.rcvNxt) {
      ctx.trace("tcp.out-of-order", "L4", `FIN 의 seq ${seg.seq} 가 기대 ${conn.rcvNxt} 와 다름 → 앞 데이터가 손실됨. ACK ${conn.rcvNxt} 재요청`, { conn: conn.id });
      this.transmit(conn, { ackFlag: true }, ctx, `중복 ACK 전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
      return;
    }
    conn.rcvNxt = seg.seq + 1;
    conn.finReceived = true;
    conn.readTimer?.cancel(); // 응답이 끝났다
    conn.readTimer = undefined;
    ctx.trace("tcp.fin.received", "L4", `FIN 수신: 상대가 더 보낼 데이터 없음 → ACK 후 나도 종료`, { conn: conn.id });
    if (conn.state === "ESTABLISHED") {
      conn.state = "CLOSE_WAIT";
      this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
      conn.state = "LAST_ACK";
      this.transmit(conn, { fin: true, ackFlag: true }, ctx, `FIN 전송: 나도 종료 (seq=${conn.sndNxt})`, "tcp.fin.sent");
    } else {
      // FIN_WAIT_1/2: 내 FIN 을 보낸 뒤 상대 FIN 도착. 내 FIN 이 아직 확인 안 됐으면 그 ACK 를 기다린다
      this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
      if (conn.unacked.length === 0) this.close(conn, ctx, "정상 종료");
    }
    // 중계 연결: 한쪽이 닫았으면 앱이 반대편도 닫는다
    if (conn.relay) this.host.onRelay?.(conn, undefined, ctx);
  }

  private close(conn: TcpConn, ctx: NodeContext, reason: string): void {
    conn.state = "CLOSED";
    conn.reason = reason;
    conn.closedAt = ctx.now;
    this.cancelAll(conn);
    ctx.trace("tcp.closed", "L4", `연결 종료 ${endpoint(conn.localIp, conn.localPort)} ↔ ${endpoint(conn.remoteIp, conn.remotePort)}: 보냄 ${conn.bytesSent}B, 받음 ${conn.bytesReceived}B, 재전송 ${conn.retransmits}회`, { conn: conn.id });
    this.host.onFinish?.(conn, ctx);
  }

  // ---------- 송신 ----------

  private transmit(conn: TcpConn, part: Partial<TcpSegment>, ctx: NodeContext, summary: string, kind: "tcp.syn.sent" | "tcp.synack.sent" | "tcp.ack.sent" | "tcp.data.sent" | "tcp.fin.sent"): void {
    const seg: TcpSegment = {
      kind: "tcp",
      srcPort: conn.localPort,
      dstPort: conn.remotePort,
      seq: conn.sndNxt,
      ack: conn.rcvNxt,
      len: 0,
      ...part,
    };
    const consumes = seg.len + (seg.syn ? 1 : 0) + (seg.fin ? 1 : 0);
    ctx.trace(kind, "L4", summary, { conn: conn.id, seq: seg.seq, ack: seg.ack, len: seg.len });
    // 상태를 먼저 갱신하고 보낸다: 내 주소로 보내는 루프백은 그 자리에서 처리돼 곧바로 다음 세그먼트를 부르므로
    if (consumes > 0) {
      conn.sndNxt += consumes;
      conn.bytesSent += seg.len;
      const timer = ctx.timer(TCP_RTO, TCP_TIMER_TAG, { conn: conn.id, seq: seg.seq });
      conn.unacked.push({ seg, retries: 0, timer });
    }
    this.host.send(this.packet(conn.localIp, conn.remoteIp, seg), ctx);
  }

  private packet(src: Ip, dst: Ip, seg: Omit<TcpSegment, "kind">): IpPacket {
    if (isIpv6(dst)) return { kind: "ipv6", src, dst, hopLimit: 64, payload: { kind: "tcp", ...seg } };
    return { kind: "ipv4", src, dst, ttl: 64, payload: { kind: "tcp", ...seg } };
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const { conn: id, seq, read, step } = data as { conn: string; seq: number; read?: boolean; step?: number };
    const conn = this.conns.get(id);
    if (!conn) return;
    if (read) {
      conn.readTimer = undefined;
      if (conn.state !== "ESTABLISHED") return;
      // SSH: 기다리던 단계에서 멈춰 있을 때만. HTTP: 마지막으로 받은 뒤 10초 (받을 때마다 다시 건다)
      if (conn.ssh && (conn.ssh.open || conn.ssh.step !== step)) return;
      // 핸드셰이크 단계에서 멈춤 (프록시가 CONNECT 에 답하지 않음·서버가 ClientHello 에 답하지 않음)
      const phase = conn.tunnel === "wait" ? "프록시의 CONNECT 응답" : conn.tls && !conn.tls.done ? "TLS ServerHello" : undefined;
      // 응답 내용을 일부 받았는지 (TLS 면 핸드셰이크 말고 응답 — 상태 줄을 받았는지로)
      const partial = !conn.ssh && !phase && (conn.tls ? conn.status !== undefined : conn.bytesReceived > 0);
      // 요청은 상대가 받았는데(ACK) 응답이 오지 않거나 중간에 멈춤: 중간 로드밸런서가 끊겼거나 백엔드에서 멈춤. RST 로 알리고 포기
      conn.state = "FAILED";
      conn.reason = phase
        ? `timeout · ${phase} 없음 (${TCP_READ_TIMEOUT / 1000}초)`
        : partial
          ? `timeout · 응답이 중간에 멈춤 (${conn.bytesReceived}B 받은 뒤 ${TCP_READ_TIMEOUT / 1000}초)`
          : `timeout · 응답 없음 (요청은 전달됨, ${TCP_READ_TIMEOUT / 1000}초)`;
      conn.closedAt = ctx.now;
      this.cancelAll(conn);
      ctx.trace(
        "tcp.failed",
        "L4",
        phase
          ? `응답 timeout: ${endpoint(conn.remoteIp, conn.remotePort)} 에서 ${phase} 을(를) ${TCP_READ_TIMEOUT / 1000}초 동안 받지 못함 → RST 로 끊음. ${conn.tunnel === "wait" ? "프록시가 대상에 연결 중인지 확인" : "그 포트가 HTTPS 서버인지, 터널 너머 대상이 답하는지 확인"}`
          : partial
            ? `응답 timeout: ${endpoint(conn.remoteIp, conn.remotePort)} 의 응답을 ${conn.bytesReceived}B 받은 뒤 ${TCP_READ_TIMEOUT / 1000}초 동안 더 오지 않음 → RST 로 끊음. 상대(또는 그 뒤의 서버)가 중간에 끊겼는지 확인`
            : `응답 timeout: 요청은 ${endpoint(conn.remoteIp, conn.remotePort)} 가 받았지만(ACK) ${TCP_READ_TIMEOUT / 1000}초 동안 응답이 없음 → RST 로 끊음. 상대 뒤의 서버(로드밸런서의 백엔드 등)를 확인`,
        { conn: conn.id },
      );
      this.host.send(this.packet(conn.localIp, conn.remoteIp, { srcPort: conn.localPort, dstPort: conn.remotePort, seq: conn.sndNxt, ack: conn.rcvNxt, rst: true, ackFlag: true, len: 0 }), ctx);
      this.host.onFinish?.(conn, ctx);
      return;
    }
    const u = conn.unacked.find((x) => x.seg.seq === seq);
    if (!u) return;
    if (u.retries >= TCP_MAX_RETRIES) {
      // 연결 시작(SYN)에 아무 응답이 없으면: 중간에서 조용히 드롭된 것 (방화벽 차단·포워딩 규칙 없음·경로 없음). 거부라면 RST 가 온다
      const handshake = conn.state === "SYN_SENT";
      conn.state = "FAILED";
      conn.reason = handshake ? `timeout · SYN 에 응답 없음 (재전송 ${TCP_MAX_RETRIES}회)` : `timeout · ACK 없음 (재전송 ${TCP_MAX_RETRIES}회)`;
      conn.closedAt = ctx.now;
      this.cancelAll(conn);
      ctx.trace(
        "tcp.failed",
        "L4",
        handshake
          ? `TCP timeout: SYN 을 ${TCP_MAX_RETRIES}번 다시 보냈지만 SYN-ACK 없음 → 연결 포기 (${endpoint(conn.remoteIp, conn.remotePort)}). 거부(RST)가 아니라 무응답이므로 중간에서 드롭된 것 — 방화벽·포트 포워딩·경로를 확인`
          : `TCP timeout: seq ${seq} 를 ${TCP_MAX_RETRIES}번 다시 보냈지만 ACK 없음 → 연결 포기 (${endpoint(conn.remoteIp, conn.remotePort)})`,
        { conn: conn.id, seq },
      );
      this.host.onFinish?.(conn, ctx);
      return;
    }
    u.retries += 1;
    conn.retransmits += 1;
    ctx.trace("tcp.retransmit", "L4", `${TCP_RTO}ms 안에 ACK 없음 → ${tcpFlags(u.seg)} seq=${seq} 재전송 (${u.retries}/${TCP_MAX_RETRIES})`, { conn: conn.id, seq, retry: u.retries });
    this.host.send(this.packet(conn.localIp, conn.remoteIp, u.seg), ctx);
    u.timer = ctx.timer(TCP_RTO * u.retries * 2, TCP_TIMER_TAG, { conn: conn.id, seq });
  }

  private cancelAll(conn: TcpConn): void {
    for (const u of conn.unacked) u.timer.cancel();
    conn.unacked = [];
    conn.readTimer?.cancel();
    conn.readTimer = undefined;
  }

  /** 노드 삭제/링크 끊김 등으로 모든 연결을 정리 */
  /** 열린 연결을 모두 실패로 끝낸다. only 가 있으면 그 조건에 맞는 연결만 (예: 주소가 바뀐 IP 버전) */
  abortAll(reason: string, ctx: NodeContext, only?: (conn: TcpConn) => boolean): void {
    for (const conn of this.conns.values()) {
      if (conn.state === "CLOSED" || conn.state === "FAILED") continue;
      if (only && !only(conn)) continue;
      this.cancelAll(conn);
      conn.state = "FAILED";
      conn.reason = reason;
      conn.closedAt = ctx.now;
      this.host.onFinish?.(conn, ctx);
    }
  }

  rows(): string[][] {
    return [...this.conns.values()]
      .slice(-6)
      .reverse()
      .map((c) => [
        `${c.role === "client" ? "→" : "←"} ${endpoint(c.remoteIp, c.remotePort)}`,
        TCP_STATE_LABEL[c.state] + (c.reason && c.state !== "CLOSED" ? ` · ${c.reason}` : ""),
        `${c.bytesSent}B / ${c.bytesReceived}B${c.retransmits ? ` · 재전송 ${c.retransmits}` : ""}`,
      ]);
  }
}
