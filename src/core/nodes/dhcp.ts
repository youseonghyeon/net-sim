// DHCP 클라이언트/서버. 호스트(클라이언트), 라우터(LAN 서버 + WAN 클라이언트), 인터넷(서버)이 공유한다.
import { intToIp, ipToInt, prefixToMask, sameSubnet, type Ip, type Mac } from "../addr";
import { DHCP_CLIENT_PORT, DHCP_SERVER_PORT, LIMITED_BROADCAST_IP, UNSPECIFIED_IP, type DhcpMessage, type Ipv4Packet } from "../packet";
import type { Emit, NetInterface } from "./iface";
import type { NodeContext, TimerHandle } from "./node";

export type DhcpState = "idle" | "rebooting" | "discovering" | "requesting" | "bound" | "failed";

export const DHCP_STATE_LABEL: Record<DhcpState, string> = {
  idle: "대기",
  rebooting: "이전 주소 확인 중",
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
  /** 마지막으로 받은 주소. 링크가 다시 연결되면(로밍·케이블 재연결) Discover 대신 이 주소를 계속 써도 되는지 묻는다 (INIT-REBOOT) */
  private last: Ip | undefined;

  constructor(
    private readonly iface: NetInterface,
    private readonly seed: number,
    /** 로그 문구에 붙는 인터페이스 이름 (예: "wan") — 비우면 생략 */
    private readonly label = "",
  ) {}

  private tag(text: string): string {
    return this.label ? `[${this.label}] ${text}` : text;
  }

  /** 주소 받기 시작. 전에 받은 주소가 있으면 INIT-REBOOT(Request 로 확인), 없으면 Discover 부터 */
  start(ctx: NodeContext, emit: Emit): void {
    this.iface.clearAddress();
    this.timer?.cancel();
    this.xid = 0x1000 + ((this.seed + ++this.xidSeq) & 0xffff);
    this.attempts = 1;
    this.offered = undefined;
    if (this.last) {
      this.state = "rebooting";
      const req: DhcpMessage = { kind: "dhcp", op: "request", xid: this.xid, clientMac: this.iface.mac, requestedIp: this.last };
      ctx.trace(
        "dhcp.request.sent",
        "app",
        this.tag(`DHCP Request 브로드캐스트 (INIT-REBOOT): "전에 쓰던 ${this.last} 를 계속 써도 되나요?" — 다시 연결되면 Discover 대신 쓰던 주소부터 확인 (서버 식별자 없음)`),
        { ...req },
      );
      this.iface.sendBroadcast(clientPacket(req), ctx, emit);
      this.arm(ctx);
      return;
    }
    this.state = "discovering";
    this.sendDiscover(ctx, emit);
  }

  /** 전에 받은 주소 (INIT-REBOOT 로 확인할 것). 노트북은 NIC(유선·무선)마다 따로 기억해 바꿔 낀다 */
  get remembered(): Ip | undefined {
    return this.last;
  }
  set remembered(ip: Ip | undefined) {
    this.last = ip;
  }

  /** 전에 받은 주소를 잊고 Discover 부터 */
  private restart(ctx: NodeContext, emit: Emit): void {
    this.last = undefined;
    this.start(ctx, emit);
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
    this.last = undefined;
    const msg: DhcpMessage = { kind: "dhcp", op: "release", xid: this.xid, clientMac: this.iface.mac, requestedIp: this.iface.ip, serverId: this.serverId };
    ctx.trace("dhcp.release", "app", this.tag(`DHCP Release: ${this.iface.ip} 를 서버 ${this.serverId ?? "?"} 에게 돌려줌 (임대 해제)`), { ...msg });
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
    // FORCERENEW 는 서버가 먼저 보내는 메시지라 xid 가 내 요청과 상관없다
    if (msg.xid !== this.xid && msg.op !== "forcerenew") {
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
        if (this.state !== "requesting" && this.state !== "rebooting") {
          ctx.trace("dhcp.ignore", "app", this.tag(`요청 중이 아닌데 Ack 수신 → 무시`), {}, frameId);
          return;
        }
        const prefix = msg.options?.prefix ?? this.offered?.prefix ?? 24;
        const router = msg.options?.router ?? this.offered?.router;
        this.iface.configure(msg.yiaddr, prefix, router, msg.options?.dns);
        const rebooted = this.state === "rebooting";
        this.state = "bound";
        this.last = msg.yiaddr;
        this.serverId = msg.serverId;
        this.timer?.cancel();
        this.timer = undefined;
        ctx.trace("dhcp.ack.received", "app", this.tag(rebooted ? `DHCP Ack 수신: 서버 ${msg.serverId} 가 쓰던 주소 ${msg.yiaddr} 를 그대로 쓰라고 확인` : `DHCP Ack 수신: 서버 ${msg.serverId} 가 ${msg.yiaddr} 확정`), { ...msg }, frameId);
        ctx.trace(
          "dhcp.bound",
          "app",
          this.tag(`IP 획득: ${msg.yiaddr}/${prefix} (서브넷 마스크 ${intToIp(prefixToMask(prefix))}), 게이트웨이 ${router ?? "없음"}, DNS ${msg.options?.dns ?? "없음"}`),
          { ip: msg.yiaddr, prefix, router, dns: msg.options?.dns },
        );
        this.iface.announce(ctx, emit);
        return;
      }
      case "nak":
        if (this.state !== "requesting" && this.state !== "rebooting") {
          // 이미 주소를 받은 뒤 다른 서버가 늦게 보낸 Nak 은 무시한다 (RFC 2131)
          ctx.trace("dhcp.ignore", "app", this.tag(`${DHCP_STATE_LABEL[this.state]} 상태라 Nak 무시 (다른 서버의 응답)`), {}, frameId);
          return;
        }
        ctx.trace(
          "dhcp.nak.received",
          "app",
          this.tag(this.state === "rebooting" ? `DHCP Nak 수신: 전에 쓰던 ${this.last} 는 이 네트워크에서 쓸 수 없음 → 잊고 Discover 부터` : `DHCP Nak 수신: 서버가 요청을 거부 → 처음부터 다시 시도`),
          { ...msg },
          frameId,
        );
        this.restart(ctx, emit);
        return;
      case "forcerenew": {
        // RFC 3203: 서버가 "지금 임대를 다시 확인하라" 고 알린다 (ISP 가 고객 주소를 바꿀 때). 쓰던 주소로 Request → 서버가 Nak 이면 Discover 부터
        if (this.state !== "bound" || !this.iface.ip) {
          ctx.trace("dhcp.ignore", "app", this.tag(this.iface.ip ? `수동 주소(${this.iface.ip})를 쓰는 중이라 FORCERENEW 무시 — DHCP 로 받은 주소가 아니다 (서버에는 예전 임대가 남아 있었다)` : `주소가 없는 상태라 FORCERENEW 무시`), {}, frameId);
          return;
        }
        const cur = this.iface.ip;
        this.state = "requesting";
        this.attempts = 1;
        ctx.trace("dhcp.request.sent", "app", this.tag(`DHCP FORCERENEW 수신: 서버 ${msg.serverId ?? "?"} 가 임대를 다시 확인하라고 함 → 쓰던 ${cur} 로 Request (RFC 3203)`), { ip: cur, forcerenew: true }, frameId);
        const req: DhcpMessage = { kind: "dhcp", op: "request", xid: this.xid, clientMac: this.iface.mac, requestedIp: cur, serverId: this.serverId ?? msg.serverId };
        this.iface.sendBroadcast(clientPacket(req), ctx, emit);
        this.arm(ctx);
        return;
      }
      default:
        ctx.trace("dhcp.ignore", "app", this.tag(`클라이언트가 처리하지 않는 DHCP ${msg.op} → 무시`), {}, frameId);
    }
  }

  onTimeout(data: unknown, ctx: NodeContext, emit: Emit): void {
    const { xid } = data as { xid: number };
    this.timer = undefined;
    if (xid !== this.xid || (this.state !== "discovering" && this.state !== "requesting" && this.state !== "rebooting")) return;
    if (this.state === "rebooting") {
      ctx.trace("dhcp.timeout", "app", this.tag(`DHCP timeout: 전에 쓰던 ${this.last} 확인에 ${DHCP_TIMEOUT}ms 동안 응답 없음 (서버에 임대 기록이 없거나 다른 네트워크) → Discover 부터`), {});
      this.restart(ctx, emit);
      return;
    }
    if (this.attempts < DHCP_MAX_ATTEMPTS) {
      this.attempts += 1;
      this.state = "discovering";
      ctx.trace("dhcp.timeout", "app", this.tag(`DHCP timeout: ${DHCP_TIMEOUT}ms 동안 응답 없음 → 재시도 ${this.attempts}/${DHCP_MAX_ATTEMPTS}`), { attempt: this.attempts });
      this.sendDiscover(ctx, emit);
      return;
    }
    this.state = "failed";
    this.last = undefined;
    this.iface.clearAddress();
    ctx.trace(
      "dhcp.failed",
      "app",
      this.tag(`DHCP 실패: timeout (${DHCP_MAX_ATTEMPTS}회 시도해도 서버 응답 없음) → 주소 없음. DHCP 서비스를 켠 뒤 "DHCP 임대 갱신" 을 누르거나, IP 를 수동 설정하세요`),
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

export interface DhcpPool {
  start: Ip;
  end: Ip;
  prefix: number;
  /** 이 서브넷 클라이언트에게 안내할 게이트웨이 */
  router?: Ip;
  /** 안내할 DNS 서버 */
  dns?: Ip;
}

export interface DhcpServerConfig {
  enabled: boolean;
  /** 서버 자신이 속한 서브넷의 풀 */
  start: Ip;
  end: Ip;
  /** 클라이언트에게 안내할 게이트웨이. 비우면 서버 자신의 주소(라우터) 또는 없음(호스트 서버) */
  router?: Ip;
  /** 안내할 DNS 서버. 비우면 라우터는 자기 주소(DNS 포워더), 호스트 서버는 없음 */
  dns?: Ip;
  /** 릴레이를 거쳐 오는 다른 서브넷용 풀 */
  extraPools?: DhcpPool[];
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
  /** 같은 장비의 다른 인터페이스 주소 (공유기의 WAN). 풀에 들어 있어도 빌려주지 않는다 — dnsmasq 도 이미 쓰는 주소는 건너뛴다 */
  ownAddresses: () => (Ip | undefined)[] = () => [];

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

  /** 안내할 DNS */
  private advertisedDns(): Ip | undefined {
    return this.config.dns || (this.selfIsRouter ? this.iface.ip : undefined);
  }

  /** 범위 변경: 새 범위 밖의 임대·제안은 버린다 */
  setConfig(cfg: DhcpServerConfig, ctx: NodeContext): void {
    this.config = { ...cfg };
    if (!this.rangeProblem()) this.dropInvalid(ctx, "DHCP 범위 변경");
  }

  /** 인터페이스 주소가 바뀌면 그 서브넷 밖의 임대·제안은 무효 */
  onInterfaceChanged(ctx: NodeContext): void {
    this.dropInvalid(ctx, "인터페이스 주소 변경");
  }

  /** 내 서브넷 풀 + 다른 서브넷 풀 */
  private pools(): DhcpPool[] {
    const local: DhcpPool = { start: this.config.start, end: this.config.end, prefix: this.iface.prefix, router: this.advertisedRouter(), dns: this.advertisedDns() };
    return [local, ...(this.config.extraPools ?? [])];
  }

  /** 요청이 온 서브넷(giaddr 기준)에 맞는 풀. 릴레이 없이 직접 오면 내 서브넷 풀 */
  private poolFor(giaddr: Ip | undefined): DhcpPool | undefined {
    if (!giaddr) return this.pools()[0];
    return (this.config.extraPools ?? []).find((p) => {
      try {
        return sameSubnet(giaddr, p.start, p.prefix);
      } catch {
        return false;
      }
    }) ?? (this.iface.ip && sameSubnet(giaddr, this.iface.ip, this.iface.prefix) ? this.pools()[0] : undefined);
  }

  /** 범위가 인터페이스 서브넷 안에 있는지. 아니면 사유를 돌려준다 */
  rangeProblem(): string | undefined {
    const ip = this.iface.ip;
    if (!ip) return "서버 자신의 IP 주소가 없음 (고정 주소가 필요)";
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

  private inPool(ip: Ip, p: DhcpPool): boolean {
    try {
      const n = ipToInt(ip);
      return n >= ipToInt(p.start) && n <= ipToInt(p.end) && sameSubnet(ip, p.start, p.prefix);
    } catch {
      return false;
    }
  }

  private inRange(ip: Ip): boolean {
    if (!this.iface.ip) return false;
    return this.pools().some((p) => this.inPool(ip, p));
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
        `${why} → 범위 밖 임대 ${dropped.length}개 무효화 (${dropped.join(", ")}). 해당 호스트는 "DHCP 임대 갱신" 을 하면 새 주소를 받는다`,
        { dropped },
      );
    }
  }

  handle(msg: DhcpMessage, frameId: number, ctx: NodeContext, emit: Emit): void {
    const me = this.iface.ip!;
    const via = msg.giaddr ? ` (릴레이 ${msg.giaddr} 경유)` : "";
    if (msg.op === "discover") {
      ctx.trace("dhcp.discover.received", "app", `DHCP Discover 수신 (클라이언트 ${msg.clientMac})${via}`, { ...msg }, frameId);
      if (!this.config.enabled) {
        ctx.trace("dhcp.disabled", "app", `DHCP 서비스가 꺼져 있음 → 응답하지 않음 (클라이언트는 timeout 후 실패)`, {}, frameId);
        return;
      }
      const problem = this.rangeProblem();
      if (problem) {
        ctx.trace("dhcp.misconfigured", "app", `DHCP 설정 오류: ${problem} → 응답하지 않음`, { problem }, frameId);
        return;
      }
      const pool = this.poolFor(msg.giaddr);
      if (!pool) {
        ctx.trace("dhcp.misconfigured", "app", `릴레이 ${msg.giaddr} 의 서브넷에 해당하는 풀이 없음 → 응답하지 않음. "다른 서브넷 풀" 에 그 서브넷 범위를 추가하세요`, { giaddr: msg.giaddr }, frameId);
        return;
      }
      const ip = this.pickAddress(msg.clientMac, pool);
      if (!ip) {
        ctx.trace("dhcp.pool.exhausted", "app", `임대할 주소 없음 (풀 고갈) (범위 ${pool.start} ~ ${pool.end} 모두 사용 중) → 응답 안 함`, {}, frameId);
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
        giaddr: msg.giaddr,
        options: { prefix: pool.prefix, router: pool.router, dns: pool.dns, leaseTime: LEASE_TIME },
      };
      ctx.trace(
        "dhcp.offer.sent",
        "app",
        `DHCP Offer: ${msg.clientMac} 에게 ${ip}/${pool.prefix} 제안 (기본 게이트웨이 옵션 ${pool.router ?? "없음"}) → ${msg.giaddr ? `릴레이 ${msg.giaddr} 로 유니캐스트` : "클라이언트 MAC 으로 유니캐스트"}`,
        { ...offer },
      );
      this.reply(offer, ip, msg, ctx, emit);
      return;
    }
    if (msg.op === "request") {
      ctx.trace("dhcp.request.received", "app", `DHCP Request 수신: ${msg.clientMac} 가 ${msg.requestedIp} 요청 (${msg.serverId ? `서버 ${msg.serverId}` : "서버 식별자 없음 — INIT-REBOOT"})${via}`, { ...msg }, frameId);
      if (!this.config.enabled) {
        ctx.trace("dhcp.disabled", "app", `DHCP 서비스가 꺼져 있음 → 응답하지 않음`, {}, frameId);
        return;
      }
      if (msg.serverId === undefined) {
        // INIT-REBOOT (RFC 2131 4.3.2): 서버 식별자 없이 쓰던 주소를 확인하러 옴
        const ip = msg.requestedIp;
        const pool = this.poolFor(msg.giaddr);
        const lease = ip ? this.leases.get(ip) : undefined;
        // Nak 은 확실히 틀렸을 때만: 다른 서브넷이거나 남이 임대 중. 같은 서브넷인데 내 범위 밖이면 다른 서버의 임대일 수 있어 침묵
        const wrongNet = !ip || !pool || !sameSubnet(ip, pool.start, pool.prefix);
        if (wrongNet || (lease && lease.mac !== msg.clientMac)) {
          const nak: DhcpMessage = { kind: "dhcp", op: "nak", xid: msg.xid, clientMac: msg.clientMac, serverId: me, giaddr: msg.giaddr };
          const why = lease && lease.mac !== msg.clientMac ? `다른 클라이언트(${lease.mac})가 임대 중` : `이 네트워크(${pool ? `${pool.start}/${pool.prefix}` : "풀 없음"})의 주소가 아님`;
          ctx.trace("dhcp.nak.sent", "app", `DHCP Nak (INIT-REBOOT): ${ip ?? "?"} 는 ${why} → 다시 Discover 하라고 거부`, { ...nak });
          this.reply(nak, LIMITED_BROADCAST_IP, msg, ctx, emit);
          return;
        }
        if (!lease || !this.inPool(ip!, pool!)) {
          ctx.trace("dhcp.ignore", "app", `INIT-REBOOT: ${ip} 에 대한 ${msg.clientMac} 의 임대 기록이 없음 → 응답하지 않음 (RFC 2131). 클라이언트는 timeout 후 Discover`, { ip }, frameId);
          return;
        }
        this.offers.delete(msg.clientMac);
        this.leases.set(ip, { mac: msg.clientMac, at: ctx.now });
        const ack: DhcpMessage = {
          kind: "dhcp",
          op: "ack",
          xid: msg.xid,
          clientMac: msg.clientMac,
          yiaddr: ip,
          serverId: me,
          giaddr: msg.giaddr,
          options: { prefix: pool.prefix, router: pool.router, dns: pool.dns, leaseTime: LEASE_TIME },
        };
        ctx.trace("dhcp.ack.sent", "app", `DHCP Ack (INIT-REBOOT): ${msg.clientMac} 의 임대 ${ip} 가 아직 유효 → 그대로 쓰라고 확인${msg.giaddr ? ` → 릴레이 ${msg.giaddr} 로` : ""}`, { ...ack });
        this.reply(ack, ip, msg, ctx, emit);
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
        const nak: DhcpMessage = { kind: "dhcp", op: "nak", xid: msg.xid, clientMac: msg.clientMac, serverId: me, giaddr: msg.giaddr };
        const taken = this.avoid.get(msg.clientMac) === msg.requestedIp;
        ctx.trace("dhcp.nak.sent", "app", taken ? `DHCP Nak: ${msg.requestedIp} 는 서버가 거둬 간 주소 (주소 바꾸기) → 다시 Discover 하라고 거부` : `DHCP Nak: ${msg.requestedIp} 는 ${msg.clientMac} 에게 제안한 주소가 아님 → 거부`, { ...nak });
        this.reply(nak, LIMITED_BROADCAST_IP, msg, ctx, emit);
        return;
      }
      const ip = msg.requestedIp!;
      const pool = this.pools().find((p) => this.inPool(ip, p)) ?? this.pools()[0]!;
      this.offers.delete(msg.clientMac);
      this.leases.set(ip, { mac: msg.clientMac, at: ctx.now });
      const ack: DhcpMessage = {
        kind: "dhcp",
        op: "ack",
        xid: msg.xid,
        clientMac: msg.clientMac,
        yiaddr: ip,
        serverId: me,
        giaddr: msg.giaddr,
        options: { prefix: pool.prefix, router: pool.router, dns: pool.dns, leaseTime: LEASE_TIME },
      };
      ctx.trace("dhcp.lease", "app", `임대 할당: ${ip} → ${msg.clientMac}`, { ip, mac: msg.clientMac });
      ctx.trace("dhcp.ack.sent", "app", `DHCP Ack: ${msg.clientMac} 에게 ${ip}/${pool.prefix} 확정 (게이트웨이 ${pool.router ?? "안내 없음"}, DNS ${pool.dns ?? "안내 없음"})${msg.giaddr ? ` → 릴레이 ${msg.giaddr} 로` : ""}`, { ...ack });
      this.reply(ack, ip, msg, ctx, emit);
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

  /** 응답 전송: 릴레이를 거쳐 왔으면 릴레이 주소(UDP 67)로 라우팅해 보내고, 아니면 클라이언트 MAC 으로 직접 */
  private reply(msg: DhcpMessage, clientDst: Ip, req: DhcpMessage, ctx: NodeContext, emit: Emit): void {
    if (req.giaddr) {
      const pkt: Ipv4Packet = { kind: "ipv4", src: this.iface.ip!, dst: req.giaddr, ttl: 64, payload: { kind: "udp", srcPort: DHCP_SERVER_PORT, dstPort: DHCP_SERVER_PORT, payload: msg } };
      this.iface.sendIp(pkt, ctx, emit);
      return;
    }
    this.iface.sendToMac(req.clientMac, this.packet(msg, clientDst), ctx, emit);
  }

  /** 고객마다 다시 주지 않을 주소 (ISP 가 주소를 바꾼 고객의 옛 주소) */
  private readonly avoid = new Map<Mac, Ip>();

  /**
   * ISP 의 고객 주소 바꾸기: 그 임대를 지우고(옛 주소는 그 고객에게 다시 주지 않음) FORCERENEW 로 알린다 (RFC 3203).
   * 고객 공유기는 쓰던 주소로 Request → Nak → Discover 로 새 주소를 받는다. 지운 임대가 있으면 그 고객 MAC
   */
  renumber(ip: Ip, ctx: NodeContext, emit: Emit): Mac | undefined {
    const lease = this.leases.get(ip);
    if (!lease) {
      ctx.trace("dhcp.ignore", "app", `${ip} 는 임대 중인 주소가 아님 → 바꿀 것이 없음`, { ip });
      return undefined;
    }
    this.leases.delete(ip);
    this.avoid.set(lease.mac, ip);
    ctx.trace("dhcp.lease", "app", `고객 ${lease.mac} 의 공인 주소 ${ip} 임대를 지우고 다른 주소를 주기로 함 → DHCP FORCERENEW 로 알림 (가정용 회선의 공인 주소가 바뀌는 순간 — 그래서 DDNS 가 필요하다)`, { ip, mac: lease.mac, renumber: true });
    const msg: DhcpMessage = { kind: "dhcp", op: "forcerenew", xid: 0, clientMac: lease.mac, serverId: this.iface.ip };
    this.iface.sendToMac(lease.mac, this.packet(msg, ip), ctx, emit);
    return lease.mac;
  }

  /** 기존 임대 → 기존 제안 → 풀 안의 첫 빈 주소 (기존 것이 그 풀 밖이면 버린다) */
  private pickAddress(mac: Mac, pool: DhcpPool): Ip | undefined {
    const own = new Set(this.ownAddresses().filter((ip): ip is Ip => !!ip));
    for (const [ip, lease] of this.leases) {
      if (lease.mac !== mac) continue;
      if (this.inPool(ip, pool) && !own.has(ip)) return ip;
      if (!this.inRange(ip) || own.has(ip)) this.leases.delete(ip);
    }
    const offered = this.offers.get(mac);
    if (offered && this.inPool(offered, pool) && !own.has(offered)) return offered;
    this.offers.delete(mac);
    let start: number, end: number;
    try {
      start = ipToInt(pool.start);
      end = ipToInt(pool.end);
    } catch {
      return undefined;
    }
    const taken = new Set([...this.leases.keys(), ...this.offers.values(), this.iface.ip, ...own]);
    const avoid = this.avoid.get(mac);
    for (let n = start; n <= end; n++) {
      const ip = intToIp(n);
      if (!taken.has(ip) && ip !== avoid) return ip;
    }
    return undefined;
  }

  rows(): string[][] {
    return [...this.leases.entries()].map(([ip, l]) => [ip, l.mac, `${l.at}ms`]);
  }
}
