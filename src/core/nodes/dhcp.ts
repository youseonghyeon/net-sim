// DHCP 클라이언트/서버. 호스트(클라이언트), 라우터(LAN 서버 + WAN 클라이언트), 인터넷(서버)이 공유한다.
import { intToIp, ipToInt, prefixToMask, sameSubnet, type Ip, type Mac } from "../addr";
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
  private serverId: Ip | undefined;

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

  /** 정상 종료(장치 제거)에 앞서 서버에게 임대를 돌려준다 */
  release(ctx: NodeContext, emit: Emit): void {
    if (this.state !== "bound" || !this.iface.ip) return;
    const msg: DhcpMessage = { kind: "dhcp", op: "release", xid: this.xid, clientMac: this.iface.mac, requestedIp: this.iface.ip, serverId: this.serverId };
    ctx.trace("dhcp.release", "app", this.tag(`DHCP Release: ${this.iface.ip} 를 서버 ${this.serverId ?? "?"} 에게 반납`), { ...msg });
    const pkt: Ipv4Packet = {
      kind: "ipv4",
      src: this.iface.ip,
      dst: this.serverId ?? LIMITED_BROADCAST_IP,
      ttl: 64,
      payload: { kind: "udp", srcPort: DHCP_CLIENT_PORT, dstPort: DHCP_SERVER_PORT, payload: msg },
    };
    // ARP 를 기다릴 틈이 없는 마지막 메시지라 L2 브로드캐스트로 보낸다
    this.iface.sendBroadcast(pkt, ctx, emit);
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
        this.serverId = msg.serverId;
        this.timer?.cancel();
        this.timer = undefined;
        ctx.trace("dhcp.ack.received", "app", this.tag(`DHCP Ack 수신: 서버 ${msg.serverId} 가 ${msg.yiaddr} 확정`), { ...msg }, frameId);
        ctx.trace(
          "dhcp.bound",
          "app",
          this.tag(`IP 획득: ${msg.yiaddr}/${prefix} (서브넷 마스크 ${intToIp(prefixToMask(prefix))}), 게이트웨이 ${router ?? "없음"}`),
          { ip: msg.yiaddr, prefix, router },
        );
        this.iface.announce(ctx, emit);
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
      this.tag(`DHCP 실패: 서버 응답 없음 (${DHCP_MAX_ATTEMPTS}회 시도) → 주소 없음. DHCP 서비스를 켠 뒤 "DHCP 다시 요청" 을 누르거나, IP 를 수동 설정하세요`),
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
  /** 클라이언트에게 안내할 게이트웨이. 비우면 서버 자신의 주소(라우터) 또는 없음(호스트 서버) */
  router?: Ip;
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
    /** router 옵션이 비었을 때 자기 주소를 안내할지 */
    private readonly selfIsRouter = true,
  ) {}

  /** 안내할 게이트웨이 */
  private advertisedRouter(): Ip | undefined {
    return this.config.router || (this.selfIsRouter ? this.iface.ip : undefined);
  }

  /** 범위 변경: 새 범위 밖의 임대·제안은 버린다 */
  setConfig(cfg: DhcpServerConfig, ctx: NodeContext): void {
    this.config = { ...cfg };
    this.dropInvalid(ctx, "DHCP 범위 변경");
  }

  /** 인터페이스 주소가 바뀌면 그 서브넷 밖의 임대·제안은 무효 */
  onInterfaceChanged(ctx: NodeContext): void {
    this.dropInvalid(ctx, "인터페이스 주소 변경");
  }

  /** 범위가 인터페이스 서브넷 안에 있는지. 아니면 사유를 돌려준다 */
  rangeProblem(): string | undefined {
    const ip = this.iface.ip;
    if (!ip) return "인터페이스에 주소가 없음";
    try {
      const start = ipToInt(this.config.start);
      const end = ipToInt(this.config.end);
      if (start > end) return `시작 주소 ${this.config.start} 가 끝 주소 ${this.config.end} 보다 큼`;
      if (!sameSubnet(this.config.start, ip, this.iface.prefix) || !sameSubnet(this.config.end, ip, this.iface.prefix)) {
        return `범위 ${this.config.start} ~ ${this.config.end} 가 인터페이스 서브넷(${ip}/${this.iface.prefix}) 밖`;
      }
    } catch {
      return "범위 주소 형식이 잘못됨";
    }
    return undefined;
  }

  private inRange(ip: Ip): boolean {
    try {
      const n = ipToInt(ip);
      return n >= ipToInt(this.config.start) && n <= ipToInt(this.config.end) && !!this.iface.ip && sameSubnet(ip, this.iface.ip, this.iface.prefix);
    } catch {
      return false;
    }
  }

  private dropInvalid(ctx: NodeContext, why: string): void {
    const dropped: Ip[] = [];
    for (const ip of [...this.leases.keys()]) {
      if (!this.inRange(ip)) {
        this.leases.delete(ip);
        dropped.push(ip);
      }
    }
    for (const [mac, ip] of [...this.offers]) if (!this.inRange(ip)) this.offers.delete(mac);
    if (dropped.length > 0) {
      ctx.trace(
        "dhcp.lease",
        "app",
        `${why} → 범위 밖 임대 ${dropped.length}개 무효화 (${dropped.join(", ")}). 해당 호스트는 "DHCP 다시 요청" 을 하면 새 주소를 받는다`,
        { dropped },
      );
    }
  }

  handle(msg: DhcpMessage, frameId: number, ctx: NodeContext, emit: Emit): void {
    const me = this.iface.ip!;
    if (msg.op === "discover") {
      ctx.trace("dhcp.discover.received", "app", `DHCP Discover 수신 (클라이언트 ${msg.clientMac})`, { ...msg }, frameId);
      if (!this.config.enabled) {
        ctx.trace("dhcp.disabled", "app", `DHCP 서비스가 꺼져 있음 → 응답하지 않음 (클라이언트는 타임아웃 후 실패)`, {}, frameId);
        return;
      }
      const problem = this.rangeProblem();
      if (problem) {
        ctx.trace("dhcp.misconfigured", "app", `DHCP 설정 오류: ${problem} → 응답하지 않음. 범위를 서브넷 안으로 고치세요`, { problem }, frameId);
        return;
      }
      const ip = this.pickAddress(msg.clientMac);
      if (!ip) {
        ctx.trace("dhcp.pool.exhausted", "app", `빌려줄 주소가 없음 (범위 ${this.config.start} ~ ${this.config.end} 모두 사용 중) → 응답 안 함`, {}, frameId);
        return;
      }
      this.offers.set(msg.clientMac, ip);
      const gw = this.advertisedRouter();
      const offer: DhcpMessage = {
        kind: "dhcp",
        op: "offer",
        xid: msg.xid,
        clientMac: msg.clientMac,
        yiaddr: ip,
        serverId: me,
        options: { prefix: this.iface.prefix, router: gw, leaseTime: LEASE_TIME },
      };
      ctx.trace("dhcp.offer.sent", "app", `DHCP Offer: ${msg.clientMac} 에게 ${ip}/${this.iface.prefix} 제안 (게이트웨이 ${gw ?? "안내 없음"}) → 클라이언트 MAC 으로 유니캐스트`, { ...offer });
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
      const gw = this.advertisedRouter();
      const ack: DhcpMessage = {
        kind: "dhcp",
        op: "ack",
        xid: msg.xid,
        clientMac: msg.clientMac,
        yiaddr: ip,
        serverId: me,
        options: { prefix: this.iface.prefix, router: gw, leaseTime: LEASE_TIME },
      };
      ctx.trace("dhcp.lease", "app", `임대 등록: ${ip} → ${msg.clientMac}`, { ip, mac: msg.clientMac });
      ctx.trace("dhcp.ack.sent", "app", `DHCP Ack: ${msg.clientMac} 에게 ${ip}/${this.iface.prefix} 확정 (게이트웨이 ${gw ?? "안내 없음"})`, { ...ack });
      this.iface.sendToMac(msg.clientMac, this.packet(ack, ip), ctx, emit);
      return;
    }
    if (msg.op === "release") {
      const ip = msg.requestedIp;
      const lease = ip ? this.leases.get(ip) : undefined;
      if (ip && lease && lease.mac === msg.clientMac) {
        this.leases.delete(ip);
        ctx.trace("dhcp.lease", "app", `DHCP Release 수신: ${ip} 임대 해제 (${msg.clientMac}) → 다른 클라이언트에게 줄 수 있음`, { ip, mac: msg.clientMac }, frameId);
      } else {
        ctx.trace("dhcp.ignore", "app", `DHCP Release 수신했지만 ${ip ?? "?"} 는 ${msg.clientMac} 의 임대가 아님 → 무시`, {}, frameId);
      }
      return;
    }
    ctx.trace("dhcp.ignore", "app", `서버가 처리하지 않는 DHCP ${msg.op} → 무시`, {}, frameId);
  }

  private packet(msg: DhcpMessage, dst: Ip): Ipv4Packet {
    return { kind: "ipv4", src: this.iface.ip!, dst, ttl: 64, payload: { kind: "udp", srcPort: DHCP_SERVER_PORT, dstPort: DHCP_CLIENT_PORT, payload: msg } };
  }

  /** 기존 임대 → 기존 제안 → 범위 안의 첫 빈 주소 (기존 것이 현재 범위 밖이면 버린다) */
  private pickAddress(mac: Mac): Ip | undefined {
    for (const [ip, lease] of this.leases) {
      if (lease.mac !== mac) continue;
      if (this.inRange(ip)) return ip;
      this.leases.delete(ip);
    }
    const offered = this.offers.get(mac);
    if (offered && this.inRange(offered)) return offered;
    this.offers.delete(mac);
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
