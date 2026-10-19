// SSH 점프 서버 (bastion, OpenSSH 의 AllowTcpForwarding): 클라이언트가 "ssh -J 점프서버 대상" 으로 점프 서버에 로그인한 뒤
// 그 세션으로 "대상:포트 로 채널을 열어 달라"(direct-tcpip) 고 부탁하면, 점프 서버가 내 주소로 대상에 TCP 를 열고 두 연결 사이로 바이트를 넘긴다.
// 클라이언트는 그 채널 위에서 대상과 SSH 를 처음부터 다시 맺는다 — 대상과의 키 교환·인증은 두 끝이 직접 하므로 점프 서버도 안을 풀지 못한다.
//
// 학습 포인트: 대상에게 클라이언트는 점프 서버 주소로 보인다. 그래서 망분리처럼 두 망 사이에 경로를 열지 않고도,
// 내부망 방화벽은 "점프 서버에서 오는 22 만" 으로 좁히고 점프 서버에서 접속 기록(누가 어디로)을 한곳에 모은다.
// 프록시의 CONNECT 터널(proxy.ts)과 모양이 같다 — 통로를 부탁하는 말이 HTTP 가 아니라 SSH 채널 요청일 뿐.
// 생략: 사용자별 허용 대상(PermitOpen), 여러 단계 점프(-J a,b), 채널 다중화(한 세션에 채널 여럿), SSH_MSG_DISCONNECT(실패 뒤 클라이언트는 RST 로 끊는다)
import { ipToInt, type Ip } from "../addr";
import type { TcpSegment } from "../packet";
import type { NodeContext } from "./node";
import { splitTarget } from "./proxy";
import { SSH_CHANNEL_CONFIRM, SSH_CHANNEL_DATA, type TcpConn, type TcpStack } from "./tcp";

/** 채널 하나: 클라이언트 쪽(down, 점프 서버의 SSH 세션)과 대상 쪽(up) 연결 */
interface Channel {
  down: TcpConn;
  up: TcpConn;
  target: string;
}

/** 점프 서버의 접속 기록 (sshd 로그 흉내, 최근 것만) */
export interface JumpLogEntry {
  at: number;
  client: Ip;
  target: string;
  /** "열림", "거절 · …", "닫힘" */
  result: string;
}
const LOG_MAX = 20;

function isValidIp(s: string): boolean {
  try {
    ipToInt(s);
    return true;
  } catch {
    return false;
  }
}

export class SshJump {
  /** AllowTcpForwarding (꺼져 있으면 채널 요청을 거절) */
  enabled = false;
  private readonly pending = new Map<string, { down: TcpConn; target: string }>();
  /** 연결 id (양쪽 모두) → 채널 */
  private readonly channels = new Map<string, Channel>();
  readonly log: JumpLogEntry[] = [];

  constructor(
    private readonly tcp: TcpStack,
    /** 대상에 연결할 때 쓸 내 주소 */
    private readonly localIp: () => Ip | undefined,
    /** 이름 → 주소 (점프 서버의 리졸버) */
    private readonly resolve: (name: string, ctx: NodeContext, done: (ip: Ip | undefined, err?: string) => void) => void,
  ) {}

  setEnabled(on: boolean, ctx: NodeContext): void {
    if (on === this.enabled) return;
    this.enabled = on;
    ctx.trace("ip.config", "sys", on ? `SSH 점프 허용 (AllowTcpForwarding yes): 로그인한 사용자가 이 서버를 거쳐 다른 서버로 접속할 수 있음 (ssh -J)` : `SSH 점프 막음 (AllowTcpForwarding no): 채널 요청을 거절함 — 이미 열린 채널은 그대로`, { sshJump: on });
  }

  /** 열린 SSH 세션으로 채널 요청: 맡으면 true (거절도 여기서 알린다). 꺼져 있으면 false (TCP 스택이 거절) */
  onChannelOpen(down: TcpConn, target: string, ctx: NodeContext): boolean {
    if (!this.enabled) {
      this.record(down, target, "거절 · administratively prohibited", ctx);
      return false;
    }
    const { host, port } = splitTarget(target);
    const fail = (why: string, detail: string) => {
      this.record(down, target, `거절 · ${why}`, ctx);
      this.tcp.channelFail(down, target, why, detail, ctx);
    };
    const go = (ip: Ip) => {
      if (down.state !== "ESTABLISHED") return;
      const me = this.localIp();
      // 이름을 푸는 동안 내 주소를 잃음: 채널을 열 수 없다고 바로 알린다 (클라이언트가 10초 기다리지 않게)
      if (!me) return fail("connect failed: Network is unreachable", "점프 서버에 IPv4 주소가 없음");
      ctx.trace("ssh.jump", "app", `점프 서버: ${down.remoteIp} 의 채널 요청 → ${target}${host !== ip ? ` (${ip})` : ""} 에 내 주소 ${me} 로 TCP 연결 (연결되면 채널을 열고 그 뒤로는 바이트만 전달 — 대상에게는 점프 서버가 클라이언트로 보인다)`, { client: down.remoteIp, target, ip, role: "jump" });
      this.tcp.connect(me, ip, port, ctx, { relay: true, onCreated: (up) => this.pending.set(up.id, { down, target }) });
    };
    if (isValidIp(host)) {
      go(host);
      return true;
    }
    this.resolve(host, ctx, (ip, err) => {
      if (ip) return go(ip);
      fail("connect failed: Name or service not known", `${host} 의 이름을 주소로 바꾸지 못함 (${err ?? "이름 해석 실패"}) — 점프 서버의 DNS 설정을 확인`);
    });
    return true;
  }

  /** 대상에 연결됨: 클라이언트에게 채널이 열렸다고 알리고 두 연결을 잇는다. 처리했으면 true */
  onEstablished(up: TcpConn, ctx: NodeContext): boolean {
    const p = this.pending.get(up.id);
    if (!p) return false;
    this.pending.delete(up.id);
    const { down, target } = p;
    if (down.state !== "ESTABLISHED") {
      ctx.trace("ssh.jump.fail", "app", `점프 서버: ${target} 에 연결됐지만 채널을 부탁한 ${down.remoteIp} 가 이미 끊음 → 대상 연결도 닫음`, { client: down.remoteIp, target, role: "jump" });
      this.tcp.disconnect(up.id, ctx);
      return true;
    }
    const ch: Channel = { down, up, target };
    this.channels.set(up.id, ch);
    this.channels.set(down.id, ch);
    // 상태를 먼저 세운다: 클라이언트가 내 주소(루프백)면 채널 응답을 보내는 순간 대상과의 SSH 첫 메시지가 되돌아온다
    down.relay = true;
    this.record(down, target, "열림", ctx);
    ctx.trace("ssh.jump", "app", `점프 서버: ${target} (${up.remoteIp}) 에 연결됨 → ${down.remoteIp} 에게 채널 열림. 이제 두 연결 사이로 바이트만 넘김 (안은 클라이언트 ↔ 대상의 SSH 로 암호화)`, { client: down.remoteIp, target, ip: up.remoteIp, role: "jump" });
    this.tcp.sendData(down, { len: 40, data: SSH_CHANNEL_CONFIRM }, ctx, `SSH 채널 열림 응답 전송`, "암호화됨");
    return true;
  }

  /** 채널로 온 데이터(seg)·FIN(undefined) 을 반대편으로 넘긴다. 클라이언트 쪽은 바깥 SSH 로 한 번 더 감싸고 푼다. 처리했으면 true */
  onRelay(conn: TcpConn, seg: TcpSegment | undefined, ctx: NodeContext): boolean {
    const ch = this.channels.get(conn.id);
    if (!ch) return false;
    const toTarget = conn === ch.down;
    const other = toTarget ? ch.up : ch.down;
    if (!seg) {
      if (other.state === "ESTABLISHED") this.tcp.disconnect(other.id, ctx);
      return true;
    }
    const raw = seg.data ?? "";
    const inner = toTarget && raw.startsWith(SSH_CHANNEL_DATA) ? raw.slice(SSH_CHANNEL_DATA.length, -1) : raw;
    const part = toTarget ? { len: Math.max(1, seg.len - 32), data: inner } : { len: seg.len + 32, data: `${SSH_CHANNEL_DATA}${raw})` };
    const where = toTarget ? `대상 ${ch.target}` : `클라이언트 ${ch.down.remoteIp}`;
    if (!this.tcp.sendData(other, part, ctx, `채널 전달 → ${where}: SSH 메시지`, toTarget ? "바깥 SSH 를 풀고 안의 것을 그대로 (안은 대상과의 SSH)" : "바깥 SSH 로 감싸서")) {
      ctx.trace("ssh.jump.fail", "app", `점프 서버: 채널 반대편(${where}) 연결이 이미 닫혀 받은 ${seg.len}B 를 넘기지 못함 → 드롭`, { client: ch.down.remoteIp, target: ch.target, role: "jump" });
    }
    return true;
  }

  /** 대상 연결·채널이 끝남. 처리했으면 true */
  onFinish(conn: TcpConn, ctx: NodeContext): boolean {
    const ch = this.channels.get(conn.id);
    if (ch) {
      const other = conn === ch.up ? ch.down : ch.up;
      if (other.state === "ESTABLISHED") {
        if (conn.state === "FAILED") this.tcp.reset(other, `점프 채널 반대편 연결 실패 (${conn.reason ?? "?"})`, ctx);
        else this.tcp.disconnect(other.id, ctx);
      }
      const done = (c: TcpConn) => c.state === "CLOSED" || c.state === "FAILED";
      if (done(ch.up) && done(ch.down)) {
        this.channels.delete(ch.up.id);
        this.channels.delete(ch.down.id);
        this.record(ch.down, ch.target, "닫힘", ctx);
      }
      return true;
    }
    const p = this.pending.get(conn.id);
    if (!p) return false;
    this.pending.delete(conn.id);
    if (p.down.state !== "ESTABLISHED") return true;
    // 대상에 연결하지 못함: OpenSSH 의 "connect failed: …" (RST = 거부, ICMP Unreachable·ARP 실패 = 경로 없음, 무응답 = timeout)
    const refused = /RST|거부/.test(conn.reason ?? "");
    const unreachable = !refused && /Unreachable/.test(conn.reason ?? "");
    const why = refused ? "connect failed: Connection refused" : unreachable ? "connect failed: No route to host" : "connect failed: Connection timed out";
    this.record(p.down, p.target, `거절 · ${why}`, ctx);
    this.tcp.channelFail(p.down, p.target, why, refused ? `${p.target} 에 그 포트를 듣는 서비스가 없음 (RST)` : unreachable ? `${p.target} 로 가는 길이 없음 (${conn.reason}) — 점프 서버의 경로·대상 주소를 확인` : `${p.target} 가 SYN 에 답하지 않음 — 점프 서버와 대상 사이의 방화벽·경로를 확인`, ctx);
    return true;
  }

  private record(down: TcpConn, target: string, result: string, ctx: NodeContext): void {
    this.log.push({ at: ctx.now, client: down.remoteIp, target, result });
    if (this.log.length > LOG_MAX) this.log.shift();
  }

  rows(): string[][] {
    return [...this.log].reverse().map((e) => [`${e.at}ms`, e.client, e.target, e.result]);
  }
}
