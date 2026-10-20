// 두 TCP 연결을 잇는 중계 (프록시 CONNECT 터널·SSH 점프 채널): 짝을 양쪽 연결로 찾고, 한쪽이 닫히면 다른 쪽도 닫고(실패면 RST),
// 둘 다 끝나면 짝을 지운다. 바이트를 어떻게 넘길지(그대로·SSH 로 감싸기)는 앱이 정한다
import type { NodeContext } from "./node";
import type { TcpConn, TcpStack } from "./tcp";

export interface SplicePair {
  /** 부탁한 클라이언트 쪽 (내가 받은 연결) */
  down: TcpConn;
  /** 대상 쪽 (내가 건 연결) */
  up: TcpConn;
  target: string;
}

export class TcpSplice<P extends SplicePair> {
  private readonly pairs = new Map<string, P>();

  constructor(
    private readonly tcp: TcpStack,
    /** RST 사유의 이름 ("CONNECT 대상 터널", "점프 채널") */
    private readonly label: (p: P) => string,
  ) {}

  /** 잇는다: 클라이언트 쪽은 이제 요청·응답이 아니라 중계 연결 */
  open(p: P): void {
    this.pairs.set(p.up.id, p);
    this.pairs.set(p.down.id, p);
    p.down.relay = true;
  }

  get(conn: TcpConn): P | undefined {
    return this.pairs.get(conn.id);
  }

  other(p: P, conn: TcpConn): TcpConn {
    return conn === p.up ? p.down : p.up;
  }

  /** 한쪽에서 FIN 이 옴: 반대편도 닫는다 */
  fin(p: P, conn: TcpConn, ctx: NodeContext): void {
    const other = this.other(p, conn);
    if (other.state === "ESTABLISHED") this.tcp.disconnect(other.id, ctx);
  }

  /** 한쪽 연결이 끝남: 반대편을 닫고(실패면 RST), 둘 다 끝났으면 짝을 지우고 true (그때 앱이 기록한다) */
  finish(p: P, conn: TcpConn, ctx: NodeContext): boolean {
    const other = this.other(p, conn);
    if (other.state === "ESTABLISHED") {
      if (conn.state === "FAILED") this.tcp.reset(other, `${this.label(p)} 반대편 연결 실패 (${conn.reason ?? "?"})`, ctx);
      else this.tcp.disconnect(other.id, ctx);
    }
    const done = (c: TcpConn) => c.state === "CLOSED" || c.state === "FAILED";
    if (!this.pairs.has(conn.id) || !done(p.up) || !done(p.down)) return false;
    this.pairs.delete(p.up.id);
    this.pairs.delete(p.down.id);
    return true;
  }
}
