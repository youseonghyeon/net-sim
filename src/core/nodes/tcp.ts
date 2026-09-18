// 학습용 축소 TCP: 3-way handshake, 누적 ACK, 타임아웃 재전송, FIN 종료, RST.
// 슬라이딩 윈도우·혼잡 제어는 없다. 앱 계층은 "요청 1개 → 응답 N 세그먼트" 인 HTTP 흉내다.
import type { Ip } from "../addr";
import { tcpFlags, type Ipv4Packet, type TcpSegment } from "../packet";
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
export const CLIENT_ISS = 1000;
export const SERVER_ISS = 3000;
const EPHEMERAL_START = 49152;
const REQUEST_BYTES = 100;
const RESPONSE_SEGMENT_BYTES = 1000;

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
}

export interface TcpHost {
  /** 세그먼트를 IP 패킷으로 감싸 내보낸다 */
  send(pkt: Ipv4Packet, ctx: NodeContext): void;
}

function connKey(localIp: Ip, localPort: number, remoteIp: Ip, remotePort: number): string {
  return `${localIp}:${localPort}-${remoteIp}:${remotePort}`;
}

function endpoint(ip: Ip, port: number): string {
  return `${ip}:${port}`;
}

export class TcpStack {
  readonly conns = new Map<string, TcpConn>();
  readonly listening = new Set<number>();
  private nextPort = EPHEMERAL_START;

  constructor(
    private readonly host: TcpHost,
    /** 서버 응답 세그먼트 수 */
    private readonly responseSegments = 3,
  ) {}

  // ---------- 클라이언트 ----------

  connect(localIp: Ip, remoteIp: Ip, remotePort: number, ctx: NodeContext): TcpConn {
    const localPort = this.nextPort++;
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
    };
    this.conns.set(conn.id, conn);
    ctx.trace("tcp.connect", "L4", `TCP 연결 시작: ${endpoint(localIp, localPort)} → ${endpoint(remoteIp, remotePort)} (초기 seq ${conn.iss})`, { conn: conn.id });
    this.transmit(conn, { syn: true }, ctx, `SYN 전송: "연결하자" seq=${conn.iss}`, "tcp.syn.sent");
    return conn;
  }

  // ---------- 수신 ----------

  handle(pkt: Ipv4Packet, seg: TcpSegment, ctx: NodeContext): void {
    const key = connKey(pkt.dst, seg.dstPort, pkt.src, seg.srcPort);
    const conn = this.conns.get(key);
    const flags = tcpFlags(seg);
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
      conn.state = conn.state === "SYN_SENT" ? "FAILED" : "CLOSED";
      conn.reason = conn.state === "FAILED" ? "연결 거부 (RST)" : "상대가 RST 로 끊음";
      conn.closedAt = ctx.now;
      this.cancelAll(conn);
      ctx.trace(conn.state === "FAILED" ? "tcp.refused" : "tcp.rst.received", "L4", conn.state === "FAILED" ? `RST 수신: ${endpoint(conn.remoteIp, conn.remotePort)} 에 그 포트를 듣는 서비스가 없음 → 연결 거부 (Connection refused)` : `RST 수신 → 연결 끊김`, { conn: conn.id });
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
          // 앱: 요청 전송
          this.transmit(conn, { ackFlag: true, len: REQUEST_BYTES, data: "GET /" }, ctx, `요청 데이터 전송: "GET /" ${REQUEST_BYTES}B (seq=${conn.sndNxt})`, "tcp.data.sent");
        } else {
          ctx.trace("tcp.ignore", "L4", `SYN_SENT 상태에서 기대하지 않은 ${flags} → 무시`, { conn: conn.id });
        }
        return;

      case "SYN_RCVD":
        if (seg.ackFlag && seg.ack === conn.iss + 1) {
          conn.state = "ESTABLISHED";
          ctx.trace("tcp.established", "L4", `ACK 수신 → 3-way handshake 완료, 연결 성립 ${endpoint(conn.localIp, conn.localPort)} ↔ ${endpoint(conn.remoteIp, conn.remotePort)}`, { conn: conn.id });
          if (seg.len > 0) this.receiveData(conn, seg, ctx);
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

      default:
        ctx.trace("tcp.ignore", "L4", `${TCP_STATE_LABEL[conn.state]} 상태에서 ${flags} → 무시`, { conn: conn.id });
    }
  }

  private accept(pkt: Ipv4Packet, seg: TcpSegment, ctx: NodeContext): void {
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
    };
    this.conns.set(conn.id, conn);
    ctx.trace("tcp.syn.received", "L4", `SYN 수신: ${endpoint(pkt.src, seg.srcPort)} 가 포트 ${seg.dstPort} 로 연결 요청 (seq ${seg.seq}) → 듣는 서비스 있음`, { conn: conn.id });
    this.transmit(conn, { syn: true, ackFlag: true }, ctx, `SYN·ACK 전송: "좋다, 내 초기 seq 는 ${conn.iss}" (ack=${conn.rcvNxt})`, "tcp.synack.sent");
  }

  private receiveData(conn: TcpConn, seg: TcpSegment, ctx: NodeContext): void {
    if (seg.seq < conn.rcvNxt) {
      ctx.trace("tcp.dup", "L4", `이미 받은 데이터 (seq ${seg.seq} < 기대 ${conn.rcvNxt}) → 버리고 ACK ${conn.rcvNxt} 다시 보냄`, { conn: conn.id });
      this.transmit(conn, { ackFlag: true }, ctx, `ACK 재전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
      return;
    }
    if (seg.seq > conn.rcvNxt) {
      ctx.trace("tcp.out-of-order", "L4", `순서가 어긋난 데이터 (seq ${seg.seq}, 기대 ${conn.rcvNxt}) → 중간 세그먼트가 유실됨. 버리고 ACK ${conn.rcvNxt} 로 재요청`, { conn: conn.id });
      this.transmit(conn, { ackFlag: true }, ctx, `중복 ACK 전송 (ack=${conn.rcvNxt}): "여기부터 다시 보내라"`, "tcp.ack.sent");
      return;
    }
    conn.rcvNxt = seg.seq + seg.len;
    conn.bytesReceived += seg.len;
    ctx.trace("tcp.data.received", "L4", `데이터 수신: ${seg.data ?? ""} ${seg.len}B (seq ${seg.seq}) → 누적 ${conn.bytesReceived}B, 다음 기대 seq ${conn.rcvNxt}`, { conn: conn.id, seq: seg.seq, len: seg.len });
    if (conn.role === "server" && conn.state === "ESTABLISHED" && conn.bytesSent === 0) {
      // 앱: 요청을 받았으니 응답 세그먼트를 연달아 보내고 FIN
      const n = conn.responseSegments;
      for (let i = 1; i <= n; i++) {
        this.transmit(conn, { ackFlag: true, len: RESPONSE_SEGMENT_BYTES, data: `HTTP 200 (${i}/${n})` }, ctx, `응답 데이터 전송 ${i}/${n}: ${RESPONSE_SEGMENT_BYTES}B (seq=${conn.sndNxt})`, "tcp.data.sent");
      }
      conn.state = "FIN_WAIT_1";
      this.transmit(conn, { fin: true, ackFlag: true }, ctx, `FIN 전송: 응답을 다 보냈으니 종료 요청 (seq=${conn.sndNxt})`, "tcp.fin.sent");
      return;
    }
    this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
  }

  private receiveFin(conn: TcpConn, seg: TcpSegment, ctx: NodeContext): void {
    if (seg.seq !== conn.rcvNxt) {
      ctx.trace("tcp.out-of-order", "L4", `FIN 의 seq ${seg.seq} 가 기대 ${conn.rcvNxt} 와 다름 → 앞 데이터가 유실됨. ACK ${conn.rcvNxt} 재요청`, { conn: conn.id });
      this.transmit(conn, { ackFlag: true }, ctx, `중복 ACK 전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
      return;
    }
    conn.rcvNxt = seg.seq + 1;
    conn.finReceived = true;
    ctx.trace("tcp.fin.received", "L4", `FIN 수신: 상대가 더 보낼 데이터 없음 → ACK 후 나도 종료`, { conn: conn.id });
    if (conn.state === "ESTABLISHED") {
      conn.state = "CLOSE_WAIT";
      this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
      conn.state = "LAST_ACK";
      this.transmit(conn, { fin: true, ackFlag: true }, ctx, `FIN 전송: 나도 종료 (seq=${conn.sndNxt})`, "tcp.fin.sent");
      return;
    }
    // FIN_WAIT_1/2: 내 FIN 을 보낸 뒤 상대 FIN 도착. 내 FIN 이 아직 확인 안 됐으면 그 ACK 를 기다린다
    this.transmit(conn, { ackFlag: true }, ctx, `ACK 전송 (ack=${conn.rcvNxt})`, "tcp.ack.sent");
    if (conn.unacked.length === 0) this.close(conn, ctx, "정상 종료");
  }

  private close(conn: TcpConn, ctx: NodeContext, reason: string): void {
    conn.state = "CLOSED";
    conn.reason = reason;
    conn.closedAt = ctx.now;
    this.cancelAll(conn);
    ctx.trace("tcp.closed", "L4", `연결 종료 ${endpoint(conn.localIp, conn.localPort)} ↔ ${endpoint(conn.remoteIp, conn.remotePort)}: 보냄 ${conn.bytesSent}B, 받음 ${conn.bytesReceived}B, 재전송 ${conn.retransmits}회`, { conn: conn.id });
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
    this.host.send(this.packet(conn.localIp, conn.remoteIp, seg), ctx);
    if (consumes > 0) {
      conn.sndNxt += consumes;
      conn.bytesSent += seg.len;
      const timer = ctx.timer(TCP_RTO, TCP_TIMER_TAG, { conn: conn.id, seq: seg.seq });
      conn.unacked.push({ seg, retries: 0, timer });
    }
  }

  private packet(src: Ip, dst: Ip, seg: Omit<TcpSegment, "kind">): Ipv4Packet {
    return { kind: "ipv4", src, dst, ttl: 64, payload: { kind: "tcp", ...seg } };
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const { conn: id, seq } = data as { conn: string; seq: number };
    const conn = this.conns.get(id);
    if (!conn) return;
    const u = conn.unacked.find((x) => x.seg.seq === seq);
    if (!u) return;
    if (u.retries >= TCP_MAX_RETRIES) {
      conn.state = "FAILED";
      conn.reason = `${TCP_MAX_RETRIES}회 재전송에도 응답 없음`;
      conn.closedAt = ctx.now;
      this.cancelAll(conn);
      ctx.trace("tcp.failed", "L4", `TCP 실패: seq ${seq} 를 ${TCP_MAX_RETRIES}번 다시 보냈지만 ACK 없음 → 연결 포기 (${endpoint(conn.remoteIp, conn.remotePort)})`, { conn: conn.id, seq });
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
  }

  /** 노드 삭제/링크 끊김 등으로 모든 연결을 정리 */
  abortAll(reason: string, ctx: NodeContext): void {
    for (const conn of this.conns.values()) {
      if (conn.state === "CLOSED" || conn.state === "FAILED") continue;
      this.cancelAll(conn);
      conn.state = "FAILED";
      conn.reason = reason;
      conn.closedAt = ctx.now;
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
