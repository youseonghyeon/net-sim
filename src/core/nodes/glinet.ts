// 공유기 관리 (GL.iNet 의 시스템 메뉴): 관리 화면 접근 제어, GoodCloud 원격 관리.
// - 관리 화면: 공유기 자신이 HTTP 80·HTTPS 443·SSH 22 로 응답한다(TcpStack). 누가 열 수 있는지는 접근 제어가 정한다 —
//   LAN 에서만(기본), 허용 목록의 주소만, WAN(인터넷)에서도(원격 접근 — 비밀번호 대입 공격에 그대로 노출)
// - GoodCloud: 공유기가 먼저 클라우드에 연결해 두면(바깥으로 나가는 연결이라 NAT·방화벽을 지나간다) 관리자의 요청이 그 연결로 들어온다.
//   공유기의 관리 포트를 인터넷에 열지 않고도 원격 관리 — "들어오는 연결" 대신 "먼저 나간 연결" 을 쓴다
// 줄인 것: 로그인·비밀번호(관리 화면은 응답만), 클라우드의 TLS·WebSocket(UDP 로), 원격으로 설정 바꾸기(상태 조회만)
import { sameSubnet, type Ip } from "../addr";
import { CLOUD_PORT, CLOUD_SERVER, type CloudMessage, type Endpoint, type Ipv4Packet, type TcpSegment } from "../packet";
import type { NodeContext } from "./node";
import { TcpStack } from "./tcp";

export const CLOUD_TIMER_TAG = "cloud";
/** 클라우드 연결 유지 간격 (배경 타이머 — 시간이 흐를 때만) */
const CLOUD_KEEPALIVE = 25_000;
const CLOUD_WAIT = 1500;

export interface AdminConfig {
  enabled: boolean;
  /** WAN(인터넷)에서도 관리 화면 접근 허용 */
  remote: boolean;
  /** LAN 에서 관리 화면을 열 수 있는 주소·대역 (비우면 LAN 전부) */
  allow: { dest: Ip; prefix: number }[];
  /** SSH (22) */
  ssh: boolean;
}

export const DEFAULT_ADMIN: AdminConfig = { enabled: false, remote: false, allow: [], ssh: true };

const label = (port: number) => (port === 22 ? "SSH" : port === 443 ? "관리 화면 (HTTPS)" : "관리 화면 (HTTP)");

export class RouterAdmin {
  config: AdminConfig = { ...DEFAULT_ADMIN, allow: [] };
  readonly tcp: TcpStack;

  constructor(send: (pkt: Ipv4Packet, ctx: NodeContext) => void) {
    this.tcp = new TcpStack({ send: (pkt, ctx) => send(pkt as Ipv4Packet, ctx) });
  }

  setConfig(cfg: AdminConfig, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.config)) return;
    this.config = { ...cfg, allow: cfg.allow.map((a) => ({ ...a })) };
    this.tcp.listening.clear();
    this.tcp.tlsPorts.clear();
    if (cfg.enabled) {
      this.tcp.listening.add(80);
      this.tcp.listening.add(443);
      this.tcp.tlsPorts.add(443);
      if (cfg.ssh) this.tcp.listening.add(22);
    }
    // 열려 있던 관리 연결은 새 규칙과 상관없이 정리 (세션은 다시 열면 된다)
    this.tcp.abortAll("관리 접근 설정 변경", ctx);
    ctx.trace(
      "ip.config",
      "sys",
      cfg.enabled
        ? `관리 접근: 관리 화면 HTTP 80·HTTPS 443${cfg.ssh ? "·SSH 22" : ""} — ${cfg.allow.length ? `LAN 의 ${cfg.allow.map((a) => `${a.dest}/${a.prefix}`).join(", ")} 만` : "LAN 전부"}${cfg.remote ? ", WAN(인터넷)에서도 허용 (원격 접근 — 누구나 로그인 화면에 닿는다)" : ", WAN 에서는 막음"}`
        : "관리 화면 흉내 꺼짐",
      { admin: cfg.enabled },
    );
  }

  /** 관리 포트인가 */
  isAdminPort(port: number): boolean {
    return this.config.enabled && this.tcp.listening.has(port);
  }

  /**
   * 관리 포트로 온 TCP: 접근 제어를 보고 받거나 드롭한다. 처리했으면 true (관리 포트가 아니면 false — 호출한 쪽이 이어서 처리)
   * from: lan = LAN 에서 공유기 주소로, wan = 인터넷에서 공인 주소로
   */
  handle(pkt: Ipv4Packet, seg: TcpSegment, from: "lan" | "wan", lan: { ip: Ip; prefix: number } | undefined, ctx: NodeContext, frameId: number): boolean {
    if (!this.isAdminPort(seg.dstPort)) return false;
    const c = this.config;
    // 이미 열린 연결의 세그먼트는 그대로 (SYN 만 검사 — 연결 단위 허용)
    const known = [...this.tcp.conns.values()].some((x) => x.remoteIp === pkt.src && x.remotePort === seg.srcPort && x.localPort === seg.dstPort && x.state !== "CLOSED" && x.state !== "FAILED");
    if (!known && seg.syn) {
      if (from === "wan" && !c.remote) {
        ctx.trace("fw.deny", "L4", `관리 접근 제어: 인터넷의 ${pkt.src} 가 ${label(seg.dstPort)} (TCP ${seg.dstPort}) 에 접속 → WAN 에서의 관리 접근이 꺼져 있어 드롭 (원격 관리는 GoodCloud 처럼 공유기가 먼저 연 연결로)`, { src: pkt.src, port: seg.dstPort }, frameId);
        return true;
      }
      if (from === "lan" && c.allow.length && !c.allow.some((a) => sameSubnet(pkt.src, a.dest, a.prefix))) {
        ctx.trace("fw.deny", "L4", `관리 접근 제어: ${pkt.src} 는 관리 화면 허용 목록(${c.allow.map((a) => `${a.dest}/${a.prefix}`).join(", ")})에 없음 → ${label(seg.dstPort)} 접속 드롭`, { src: pkt.src, port: seg.dstPort }, frameId);
        return true;
      }
      if (from === "lan" && lan && !sameSubnet(pkt.src, lan.ip, lan.prefix) && !c.remote) {
        ctx.trace("fw.deny", "L4", `관리 접근 제어: ${pkt.src} 는 LAN(${lan.ip}/${lan.prefix}) 밖의 주소 (VPN 으로 붙은 기기 등) → ${label(seg.dstPort)} 접속 드롭 (LAN 만 허용)`, { src: pkt.src, port: seg.dstPort }, frameId);
        return true;
      }
      ctx.trace("fw.allow", "L4", `관리 접근 제어: ${pkt.src} → ${label(seg.dstPort)} 허용 (${from === "wan" ? "WAN 원격 접근 켜짐" : c.allow.length ? "허용 목록" : "LAN"})`, { src: pkt.src, port: seg.dstPort }, frameId);
    }
    this.tcp.handle(pkt, seg, ctx);
    return true;
  }

  rows(): string[][] {
    return this.tcp.rows();
  }
}

// ---------- GoodCloud ----------

export interface CloudIo {
  /** 지금 인터넷으로 나가는 회선의 내 주소 */
  wanIp(): Ip | undefined;
  /** 클라우드로 보낸다 (공유기 자신의 패킷 — NAT 하지 않음) */
  send(pkt: Ipv4Packet, ctx: NodeContext): void;
  /** 상태 (관리자에게 보여 줄 것) */
  status(): { wan: Ip; clients: number; vpn: string };
}

export class CloudAgent {
  enabled = false;
  registered = false;
  private tok = 0;
  private tries = 0;
  /** 마지막으로 받은 원격 관리 요청 수 */
  managed = 0;

  constructor(
    private readonly io: CloudIo,
    /** 기기 식별 (MAC) */
    readonly device: string,
    /** 클라우드에서 보일 이름 */
    public name: string,
    /** 클라우드로 보낼 때 쓰는 내 포트 (장치마다 고정) */
    readonly port: number,
  ) {}

  setEnabled(on: boolean, ctx: NodeContext): void {
    if (on === this.enabled) return;
    this.enabled = on;
    this.registered = false;
    this.tok++;
    ctx.trace("ip.config", "sys", on ? `GoodCloud 켜짐: 클라우드(${CLOUD_SERVER})에 먼저 연결해 두고 그 연결로 원격 관리를 받는다 — 관리 포트를 인터넷에 열지 않는다` : "GoodCloud 꺼짐", { cloud: on });
    if (on) this.register(ctx);
  }

  private sendMsg(m: CloudMessage, ctx: NodeContext): void {
    const me = this.io.wanIp();
    if (!me) return;
    this.io.send({ kind: "ipv4", src: me, dst: CLOUD_SERVER, ttl: 64, payload: { kind: "udp", srcPort: this.port, dstPort: CLOUD_PORT, payload: m } }, ctx);
  }

  /** WAN 주소를 얻거나 바뀜: 다시 등록 (클라우드가 새 주소로 연락하게) */
  onWanAddress(ctx: NodeContext): void {
    if (!this.enabled || !this.io.wanIp()) return;
    this.registered = false;
    this.tok++;
    this.register(ctx);
  }

  private register(ctx: NodeContext): void {
    if (!this.io.wanIp()) return;
    this.tries = 1;
    ctx.trace("cloud.register", "app", `GoodCloud: 클라우드 ${CLOUD_SERVER} 에 기기 등록 (${this.name}, ${this.device})`, { cloud: true });
    this.sendMsg({ kind: "cloud", op: "register", device: this.device, name: this.name }, ctx);
    ctx.timer(CLOUD_WAIT, CLOUD_TIMER_TAG, { cloud: "register", tok: this.tok });
  }

  /** 내 포트로 온 클라우드 메시지. 처리했으면 true */
  handle(pkt: Ipv4Packet, m: CloudMessage, ctx: NodeContext, frameId: number): boolean {
    if (!this.enabled || pkt.src !== CLOUD_SERVER) return false;
    if (m.op === "registered") {
      if (!this.registered) {
        this.registered = true;
        ctx.trace("cloud.register", "app", `GoodCloud: 등록됨 — 이 연결(NAT 매핑)을 ${CLOUD_KEEPALIVE / 1000}초마다 유지해 클라우드가 이 길로 연락한다`, { cloud: true }, frameId);
        ctx.timer(CLOUD_KEEPALIVE, CLOUD_TIMER_TAG, { cloud: "keepalive", tok: this.tok }, true);
      }
      return true;
    }
    if (m.op === "manage") {
      this.managed++;
      const st = this.io.status();
      ctx.trace("cloud.manage", "app", `GoodCloud: 클라우드에서 원격 관리 요청 → 상태로 답함 (WAN ${st.wan}, 기기 ${st.clients}대, VPN ${st.vpn}) — 공유기가 먼저 연 연결로 들어와 포트 포워딩이 필요 없다`, { cloud: true }, frameId);
      this.sendMsg({ kind: "cloud", op: "status", device: this.device, name: this.name, txid: m.txid ?? 0, status: st }, ctx);
      return true;
    }
    return true;
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const d = data as { cloud?: string; tok?: number };
    if (d.tok !== this.tok || !this.enabled) return;
    if (d.cloud === "register") {
      if (this.registered) return;
      if (this.tries > 2) {
        ctx.trace("cloud.register", "app", `GoodCloud: 클라우드 응답 없음 (3번) — 인터넷 연결을 확인. ${CLOUD_KEEPALIVE / 1000}초마다 다시 시도`, { cloud: true, failed: true });
        ctx.timer(CLOUD_KEEPALIVE, CLOUD_TIMER_TAG, { cloud: "retry", tok: this.tok }, true);
        return;
      }
      this.tries++;
      this.sendMsg({ kind: "cloud", op: "register", device: this.device, name: this.name }, ctx);
      ctx.timer(CLOUD_WAIT, CLOUD_TIMER_TAG, { cloud: "register", tok: this.tok });
      return;
    }
    if (d.cloud === "retry") {
      if (this.registered) return;
      this.sendMsg({ kind: "cloud", op: "register", device: this.device, name: this.name }, ctx);
      ctx.timer(CLOUD_KEEPALIVE, CLOUD_TIMER_TAG, { cloud: "retry", tok: this.tok }, true);
      return;
    }
    if (d.cloud === "keepalive") {
      this.sendMsg({ kind: "cloud", op: "keepalive", device: this.device, name: this.name }, ctx);
      ctx.timer(CLOUD_KEEPALIVE, CLOUD_TIMER_TAG, { cloud: "keepalive", tok: this.tok }, true);
    }
  }

  summary(): string | undefined {
    if (!this.enabled) return undefined;
    return this.registered ? `연결됨 · 원격 관리 ${this.managed}번` : "연결 중 (클라우드에 등록)";
  }
}

/** 클라우드 서버 (인터넷 노드): 등록한 공유기의 연락 주소를 기억하고, 관리자의 요청을 그 주소로 보낸다 */
export class CloudService {
  readonly devices = new Map<string, { name: string; at: Endpoint; lastStatus?: CloudMessage["status"]; pending?: number }>();
  private nextTx = 1;

  constructor(private readonly send: (to: Endpoint, m: CloudMessage, ctx: NodeContext) => void) {}

  handle(pkt: Ipv4Packet, srcPort: number, m: CloudMessage, ctx: NodeContext, frameId: number): void {
    const from: Endpoint = { ip: pkt.src, port: srcPort };
    if (m.op === "register" || m.op === "keepalive") {
      const had = this.devices.get(m.device);
      const moved = !had || had.at.ip !== from.ip || had.at.port !== from.port;
      this.devices.set(m.device, { ...(had ?? {}), name: m.name ?? had?.name ?? m.device, at: from });
      if (m.op === "register" || moved) ctx.trace("cloud.server", "app", `GoodCloud 서버: ${m.name ?? m.device} ${m.op === "register" ? "등록" : "연결 유지"} — 연락할 주소 ${from.ip}:${from.port} (그 공유기의 NAT 바깥)`, { device: m.device }, frameId);
      if (m.op === "register") this.send(from, { kind: "cloud", op: "registered", device: m.device }, ctx);
      return;
    }
    if (m.op === "status") {
      const d = this.devices.get(m.device);
      if (!d) return;
      d.lastStatus = m.status;
      d.pending = undefined;
      ctx.trace("cloud.server", "app", `GoodCloud 서버: ${d.name} 의 상태 받음 (WAN ${m.status?.wan}, 기기 ${m.status?.clients}대, VPN ${m.status?.vpn}) → 관리자 화면에 표시`, { device: m.device }, frameId);
    }
  }

  /** 관리자가 클라우드 화면에서 그 기기를 엶: 등록된 연락 주소로 요청 (응답이 없으면 timeout) */
  manage(device: string, ctx: NodeContext, timer: (txid: number) => void): void {
    const d = this.devices.get(device);
    if (!d) {
      ctx.trace("cloud.server", "app", `GoodCloud 서버: 기기 ${device} 는 등록돼 있지 않음 (공유기의 GoodCloud 가 꺼져 있거나 인터넷에 닿지 않음)`, { device });
      return;
    }
    const txid = this.nextTx++;
    d.pending = txid;
    ctx.trace("cloud.server", "app", `GoodCloud 서버: 관리자가 ${d.name} 을(를) 엶 → 공유기가 연결해 둔 주소 ${d.at.ip}:${d.at.port} 로 요청 (들어오는 연결이 아니라 그 연결의 응답처럼 — NAT 가 들여보낸다)`, { device });
    this.send(d.at, { kind: "cloud", op: "manage", device, txid }, ctx);
    timer(txid);
  }

  /** 요청 timeout */
  expire(device: string, txid: number, ctx: NodeContext): void {
    const d = this.devices.get(device);
    if (!d || d.pending !== txid) return;
    d.pending = undefined;
    ctx.trace("cloud.server", "app", `GoodCloud 서버: ${d.name} 응답 없음 (timeout) — 공유기가 꺼졌거나 연결(NAT 매핑)이 바뀌었다. 공유기가 다시 연결 유지를 보내면 새 주소로 닿는다`, { device, failed: true });
  }

  rows(): string[][] {
    return [...this.devices.entries()].map(([dev, d]) => [d.name, dev, `${d.at.ip}:${d.at.port}`, d.lastStatus ? `WAN ${d.lastStatus.wan} · 기기 ${d.lastStatus.clients}대 · VPN ${d.lastStatus.vpn}` : "—"]);
  }
}
