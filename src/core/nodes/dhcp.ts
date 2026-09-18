// DHCP 클라이언트/서버. 호스트(클라이언트), 라우터(LAN 서버 + WAN 클라이언트), 인터넷(서버)이 공유한다.
import { intToIp, ipToInt, prefixToMask, type Ip, type Mac } from "../addr";
import { DHCP_CLIENT_PORT, DHCP_SERVER_PORT, LIMITED_BROADCAST_IP, UNSPECIFIED_IP, type DhcpMessage, type Ipv4Packet } from "../packet";
import type { Emit, NetInterface } from "./iface";
import type { NodeContext, TimerHandle } from "./node";

export type DhcpState = "idle" | "discovering" | "requesting" | "bound" | "failed";

export const DHCP_STATE_LABEL: Record<DhcpState, string> = {
  idle: "대기",
  discovering: "서버 찾는 중",
  requesting: "주소 요청 중",
  bound: "주소 받음",
  failed: "실패",
};

export const DHCP_TIMEOUT = 1000;
export const DHCP_MAX_ATTEMPTS = 3;
export const DHCP_TIMER_TAG = "dhcp-timeout";

/** 인터페이스 하나에 붙는 DHCP 클라이언트 (DORA + 재시도) */
export class DhcpClient {
  state: DhcpState = "idle";
  attempts = 0;
  private xid = 0;
  private xidSeq = 0;
  private offered?: { ip: Ip; serverId?: Ip; prefix: number; router?: Ip };
  private timer: TimerHandle | undefined;

  constructor(
    private readonly iface: NetInterface,
    private readonly seed: number,
    /** 로그 문구에 붙는 인터페이스 이름 (예: "wan") — 비우면 생략 */
    private readonly label = "",
  ) {}

  private tag(text: string): string {
    return this.label ? `[${this.label}] ${text}` : text;
  }

  start(ctx: NodeContext, emit: Emit): void {
    this.iface.clearAddress();
    this.timer?.cancel();
    this.xid = 0x1000 + ((this.seed + ++this.xidSeq) & 0xffff);
    this.state = "discovering";
    this.attempts = 1;
    this.offered = undefined;
    this.sendDiscover(ctx, emit);
  }

  stop(): void {
    this.timer?.cancel();
    this.timer = undefined;
    this.state = "idle";
    this.attempts = 0;
    this.offered = undefined;
  }

  private sendDiscover(ctx: NodeContext, emit: Emit): void {
    const msg: DhcpMessage = { kind: "dhcp", op: "discover", xid: this.xid, clientMac: this.iface.mac };
    ctx.trace(
      "dhcp.discover.sent",
      "app",
      this.tag(`DHCP Discover 브로드캐스트 (시도 ${this.attempts}/${DHCP_MAX_ATTEMPTS}): "IP 주소를 줄 서버 있나요?" (아직 IP 없음, 출발지 0.0.0.0)`),
      { xid: this.xid, attempt: this.attempts },
    );
    this.iface.sendBroadcast(clientPacket(msg), ctx, emit);
    this.arm(ctx);
  }

  private arm(ctx: NodeContext): void {
    this.timer?.cancel();
    this.timer = ctx.timer(DHCP_TIMEOUT, DHCP_TIMER_TAG, { xid: this.xid, label: this.label });
  }

  /** 이 클라이언트의 타이머인지 (라우터처럼 클라이언트가 여럿일 때 구분) */
  ownsTimer(data: unknown): boolean {
    return (data as { label?: string })?.label === this.label;
  }

  handle(msg: DhcpMessage, frameId: number, ctx: NodeContext, emit: Emit): void {
    if (msg.xid !== this.xid) {
      ctx.trace("dhcp.ignore", "app", this.tag(`DHCP ${msg.op} 의 xid 가 내 요청과 다름 → 무시`), { xid: msg.xid }, frameId);
      return;
    }
    switch (msg.op) {
      case "offer": {
        if (this.state !== "discovering") {
          ctx.trace("dhcp.ignore", "app", this.tag(`이미 ${DHCP_STATE_LABEL[this.state]} 상태라 Offer 무시`), {}, frameId);
          return;
        }
        const prefix = msg.options?.prefix ?? 24;
        this.state = "requesting";
        this.offered = { ip: msg.yiaddr!, serverId: msg.serverId, prefix, router: msg.options?.router };
        ctx.trace(
          "dhcp.offer.received",
          "app",
          this.tag(`DHCP Offer 수신: 서버 ${msg.serverId} 가 ${msg.yiaddr}/${prefix} 제안 (게이트웨이 ${msg.options?.router ?? "없음"})`),
          { ...msg },
          frameId,
        );
        const req: DhcpMessage = { kind: "dhcp", op: "request", xid: this.xid, clientMac: this.iface.mac, requestedIp: msg.yiaddr, serverId: msg.serverId };
        ctx.trace("dhcp.request.sent", "app", this.tag(`DHCP Request 브로드캐스트: "${msg.yiaddr} 를 서버 ${msg.serverId} 에게서 받겠습니다"`), { ...req });
        this.iface.sendBroadcast(clientPacket(req), ctx, emit);
        this.arm(ctx);
        return;
      }
      case "ack": {
        if (this.state !== "requesting") {
          ctx.trace("dhcp.ignore", "app", this.tag(`요청 중이 아닌데 Ack 수신 → 무시`), {}, frameId);
          return;
        }
        const prefix = msg.options?.prefix ?? this.offered?.prefix ?? 24;
        const router = msg.options?.router ?? this.offered?.router;
        this.iface.configure(msg.yiaddr, prefix, router);
        this.state = "bound";
        this.timer?.cancel();
        this.timer = undefined;
        ctx.trace("dhcp.ack.received", "app", this.tag(`DHCP Ack 수신: 서버 ${msg.serverId} 가 ${msg.yiaddr} 확정`), { ...msg }, frameId);
        ctx.trace(
          "dhcp.bound",
          "app",
          this.tag(`IP 획득: ${msg.yiaddr}/${prefix} (서브넷 마스크 ${intToIp(prefixToMask(prefix))}), 게이트웨이 ${router ?? "없음"}`),
          { ip: msg.yiaddr, prefix, router },
        );
        return;
      }
      case "nak":
        ctx.trace("dhcp.nak.received", "app", this.tag(`DHCP Nak 수신: 서버가 요청을 거부 → 처음부터 다시 시도`), { ...msg }, frameId);
        this.start(ctx, emit);
        return;
      default:
        ctx.trace("dhcp.ignore", "app", this.tag(`클라이언트가 처리하지 않는 DHCP ${msg.op} → 무시`), {}, frameId);
    }
  }

  onTimeout(data: unknown, ctx: NodeContext, emit: Emit): void {
    const { xid } = data as { xid: number };
    this.timer = undefined;
    if (xid !== this.xid || (this.state !== "discovering" && this.state !== "requesting")) return;
    if (this.attempts < DHCP_MAX_ATTEMPTS) {
      this.attempts += 1;
      this.state = "discovering";
      ctx.trace("dhcp.timeout", "app", this.tag(`DHCP 응답 없음 (${DHCP_TIMEOUT}ms) → 재시도 ${this.attempts}/${DHCP_MAX_ATTEMPTS}`), { attempt: this.attempts });
      this.sendDiscover(ctx, emit);
      return;
    }
    this.state = "failed";
    this.iface.clearAddress();
    ctx.trace(
      "dhcp.failed",
      "app",
      this.tag(`DHCP 실패: 서버 응답 없음 (${DHCP_MAX_ATTEMPTS}회 시도) → 주소 없음. DHCP 서비스를 켜거나 IP 를 수동 설정하세요`),
      {},
    );
  }
}

function clientPacket(msg: DhcpMessage): Ipv4Packet {
  return {
    kind: "ipv4",
    src: UNSPECIFIED_IP,
    dst: LIMITED_BROADCAST_IP,
    ttl: 64,
    payload: { kind: "udp", srcPort: DHCP_CLIENT_PORT, dstPort: DHCP_SERVER_PORT, payload: msg },
  };
}

// ---------- 서버 ----------

export interface DhcpServerConfig {
  enabled: boolean;
  start: Ip;
  end: Ip;
}

export interface Lease {
  mac: Mac;
  at: number;
}

export const LEASE_TIME = 86_400;

/** 인터페이스 하나에서 동작하는 DHCP 서버. 게이트웨이로 자기 인터페이스 주소를 안내한다 */
export class DhcpServer {
  readonly leases = new Map<Ip, Lease>();
  private readonly offers = new Map<Mac, Ip>();

  constructor(
    public config: DhcpServerConfig,
    private readonly iface: NetInterface,
  ) {}

  handle(msg: DhcpMessage, frameId: number, ctx: NodeContext, emit: Emit): void {
    const me = this.iface.ip!;
    if (msg.op === "discover") {
      ctx.trace("dhcp.discover.received", "app", `DHCP Discover 수신 (클라이언트 ${msg.clientMac})`, { ...msg }, frameId);
      if (!this.config.enabled) {
        ctx.trace("dhcp.disabled", "app", `DHCP 서비스가 꺼져 있음 → 응답하지 않음 (클라이언트는 타임아웃 후 실패)`, {}, frameId);
        return;
      }
      const ip = this.pickAddress(msg.clientMac);
      if (!ip) {
        ctx.trace("dhcp.pool.exhausted", "app", `빌려줄 주소가 없음 (범위 ${this.config.start} ~ ${this.config.end} 모두 사용 중) → 응답 안 함`, {}, frameId);
        return;
      }
      this.offers.set(msg.clientMac, ip);
      const offer: DhcpMessage = {
        kind: "dhcp",
        op: "offer",
        xid: msg.xid,
        clientMac: msg.clientMac,
        yiaddr: ip,
        serverId: me,
        options: { prefix: this.iface.prefix, router: me, leaseTime: LEASE_TIME },
      };
      ctx.trace("dhcp.offer.sent", "app", `DHCP Offer: ${msg.clientMac} 에게 ${ip}/${this.iface.prefix} 제안 (게이트웨이 ${me}) → 클라이언트 MAC 으로 유니캐스트`, { ...offer });
      this.iface.sendToMac(msg.clientMac, this.packet(offer, ip), ctx, emit);
      return;
    }
    if (msg.op === "request") {
      ctx.trace("dhcp.request.received", "app", `DHCP Request 수신: ${msg.clientMac} 가 ${msg.requestedIp} 요청 (서버 ${msg.serverId})`, { ...msg }, frameId);
      if (!this.config.enabled) {
        ctx.trace("dhcp.disabled", "app", `DHCP 서비스가 꺼져 있음 → 응답하지 않음`, {}, frameId);
        return;
      }
      if (msg.serverId !== me) {
        ctx.trace("dhcp.ignore", "app", `클라이언트가 다른 서버(${msg.serverId})를 선택 → 내 제안 철회`, {}, frameId);
        this.offers.delete(msg.clientMac);
        return;
      }
      const offered = this.offers.get(msg.clientMac);
      const leased = msg.requestedIp ? this.leases.get(msg.requestedIp) : undefined;
      const ok = msg.requestedIp && ((offered && offered === msg.requestedIp) || (leased && leased.mac === msg.clientMac));
      if (!ok) {
        const nak: DhcpMessage = { kind: "dhcp", op: "nak", xid: msg.xid, clientMac: msg.clientMac, serverId: me };
        ctx.trace("dhcp.nak.sent", "app", `DHCP Nak: ${msg.requestedIp} 는 ${msg.clientMac} 에게 제안한 주소가 아님 → 거부`, { ...nak });
        this.iface.sendToMac(msg.clientMac, this.packet(nak, LIMITED_BROADCAST_IP), ctx, emit);
        return;
      }
      const ip = msg.requestedIp!;
      this.offers.delete(msg.clientMac);
      this.leases.set(ip, { mac: msg.clientMac, at: ctx.now });
      const ack: DhcpMessage = {
        kind: "dhcp",
        op: "ack",
        xid: msg.xid,
        clientMac: msg.clientMac,
        yiaddr: ip,
        serverId: me,
        options: { prefix: this.iface.prefix, router: me, leaseTime: LEASE_TIME },
      };
      ctx.trace("dhcp.lease", "app", `임대 등록: ${ip} → ${msg.clientMac}`, { ip, mac: msg.clientMac });
      ctx.trace("dhcp.ack.sent", "app", `DHCP Ack: ${msg.clientMac} 에게 ${ip}/${this.iface.prefix} 확정 (게이트웨이 ${me})`, { ...ack });
      this.iface.sendToMac(msg.clientMac, this.packet(ack, ip), ctx, emit);
      return;
    }
    ctx.trace("dhcp.ignore", "app", `서버가 처리하지 않는 DHCP ${msg.op} → 무시`, {}, frameId);
  }

  private packet(msg: DhcpMessage, dst: Ip): Ipv4Packet {
    return { kind: "ipv4", src: this.iface.ip!, dst, ttl: 64, payload: { kind: "udp", srcPort: DHCP_SERVER_PORT, dstPort: DHCP_CLIENT_PORT, payload: msg } };
  }

  /** 기존 임대 → 기존 제안 → 범위 안의 첫 빈 주소 */
  private pickAddress(mac: Mac): Ip | undefined {
    for (const [ip, lease] of this.leases) if (lease.mac === mac) return ip;
    const offered = this.offers.get(mac);
    if (offered) return offered;
    let start: number, end: number;
    try {
      start = ipToInt(this.config.start);
      end = ipToInt(this.config.end);
    } catch {
      return undefined;
    }
    const taken = new Set([...this.leases.keys(), ...this.offers.values(), this.iface.ip]);
    for (let n = start; n <= end; n++) {
      const ip = intToIp(n);
      if (!taken.has(ip)) return ip;
    }
    return undefined;
  }

  rows(): string[][] {
    return [...this.leases.entries()].map(([ip, l]) => [ip, l.mac, `${l.at}ms`]);
  }
}
