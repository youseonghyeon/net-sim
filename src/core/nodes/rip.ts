// 동적 라우팅: RIPv2 축소판 (거리 벡터). 게이트웨이·NAT 박스(L3Node)가 켜서 쓴다.
// 학습 포인트: 라우터끼리 "내가 아는 네트워크와 홉 수" 를 이웃에게 알리고, 받은 쪽은 +1 해서 더 짧은 경로를 고른다.
//
// 실제 RIP 와 다른 점 (시뮬레이터 시계는 조용하면 멈추므로):
// - 30초 주기 업데이트·180초 timeout 이 없다. 변화가 있을 때만 보내는 트리거 업데이트로 동작한다.
// - 대신 링크 다운·주소 변경을 즉시 반영하고(경로 철회 = 메트릭 16), 경로를 하나라도 잃으면 모든 이웃에게 Request 를 보내
//   대체 경로를 다시 듣는다(주기 업데이트가 하던 일). 철회가 있을 때만 일어나고 메트릭은 16 에서 멈추므로 끝이 있다.
//   스위치 너머의 이웃이 사라진 것(내 링크는 살아 있음)은 알아채지 못한다.
import { networkOf, sameSubnet, type Ip } from "../addr";
import { RIP_INFINITY, RIP_MULTICAST_IP, RIP_MULTICAST_MAC, RIP_PORT, type Ipv4Packet, type RipEntry, type RipMessage } from "../packet";
import type { NodeContext } from "./node";

export interface RipConfig {
  enabled: boolean;
  /** 디폴트 라우트 광고 (default-information originate): 내 디폴트 라우트를 이웃에게 0.0.0.0/0 으로 알린다 */
  defaultRoute: boolean;
}

export const DEFAULT_RIP: RipConfig = { enabled: false, defaultRoute: false };
/** 트리거 업데이트를 모아 보내는 지연. ARP Probe(200ms)가 끝난 뒤라 새 주소로 보낼 수 있다 */
export const RIP_UPDATE_DELAY = 250;
export const RIP_TIMER_TAG = "rip-update";

/** RIP 로 배운 경로 */
export interface RipRoute {
  dest: Ip;
  prefix: number;
  nextHop: Ip;
  /** 나가는 인터페이스 인덱스 */
  out: number;
  /** 홉 수. 16 = 도달 불가(철회 중) */
  metric: number;
}

/** RIP 가 라우터에게서 알아야 하는 것 */
export interface RipHost {
  readonly ifaceCount: number;
  ifaceName(i: number): string;
  ifaceIp(i: number): Ip | undefined;
  ifacePrefix(i: number): number;
  /** 이 인터페이스로 RIP 를 주고받는지 (주소 있음·링크 업·NAT outside 아님) */
  participates(i: number): boolean;
  /** 쓸 수 있는(링크 업·주소 있음) 스태틱 디폴트 라우트가 나가는 인터페이스. 업링크가 죽으면 undefined → 광고 철회 */
  staticDefaultOut(): number | undefined;
  /** 인터페이스 i 로 L2 멀티캐스트 송신 */
  send(i: number, pkt: Ipv4Packet, ctx: NodeContext): void;
}

const keyOf = (dest: Ip, prefix: number) => `${dest}/${prefix}`;

export class Rip {
  config: RipConfig = { ...DEFAULT_RIP };
  /** 배운 경로 (목적지/프리픽스 → 경로) */
  readonly routes = new Map<string, RipRoute>();
  /** 지난번에 광고한 내 네트워크 (없어지면 철회를 보내야 한다) */
  private advertised = new Map<string, { dest: Ip; prefix: number }>();
  /** 지난번에 RIP 를 보낸 인터페이스 (새로 생기면 Request 도 보낸다) */
  private active = new Set<number>();
  private pending = false;
  /** 지난 업데이트 뒤로 경로를 잃었는지 (그러면 이웃에게 Request 로 대체 경로를 묻는다) */
  private lost = false;

  constructor(private readonly host: RipHost) {}

  setConfig(cfg: RipConfig, ctx: NodeContext): void {
    if (cfg.enabled === this.config.enabled && cfg.defaultRoute === this.config.defaultRoute) return;
    const was = this.config;
    this.config = { ...cfg };
    if (cfg.enabled !== was.enabled) {
      ctx.trace(
        "rip.config",
        "sys",
        cfg.enabled
          ? `RIP 켜짐 → 이웃 라우터에게 Request 로 경로를 묻고, 내 네트워크를 광고`
          : `RIP 꺼짐 → 이웃에게 내 경로를 모두 철회(메트릭 16)하고 배운 경로 삭제`,
        { ...cfg },
      );
    } else {
      ctx.trace("rip.config", "sys", cfg.defaultRoute ? `RIP 디폴트 라우트 광고 켜짐 → 이웃에게 0.0.0.0/0 을 알림` : `RIP 디폴트 라우트 광고 꺼짐 → 0.0.0.0/0 철회`, { ...cfg });
    }
    this.kick(ctx);
  }

  /** 곧 업데이트를 보내도록 예약 (여러 변화를 한 번에 모은다) */
  kick(ctx: NodeContext): void {
    if (this.pending || (!this.config.enabled && this.active.size === 0)) return;
    this.pending = true;
    ctx.timer(RIP_UPDATE_DELAY, RIP_TIMER_TAG, {});
  }

  onTimer(ctx: NodeContext): void {
    this.pending = false;
    this.update(ctx);
  }

  /** 지금 쓸 수 있는 RIP 경로 (링크가 살아 있고 넥스트 홉이 그 인터페이스 서브넷 안) */
  usable(r: RipRoute): boolean {
    if (!this.config.enabled || r.metric >= RIP_INFINITY || !this.host.participates(r.out)) return false;
    const ip = this.host.ifaceIp(r.out);
    return ip !== undefined && sameSubnet(r.nextHop, ip, this.host.ifacePrefix(r.out));
  }

  /** 내가 광고하는 네트워크: 참여 인터페이스의 서브넷 (+ 디폴트 라우트 광고) */
  private ownNetworks(): Map<string, { dest: Ip; prefix: number; iface: number }> {
    const own = new Map<string, { dest: Ip; prefix: number; iface: number }>();
    if (!this.config.enabled) return own;
    for (let i = 0; i < this.host.ifaceCount; i++) {
      const ip = this.host.ifaceIp(i);
      if (!ip || !this.host.participates(i)) continue;
      const prefix = this.host.ifacePrefix(i);
      const dest = networkOf(ip, prefix);
      own.set(keyOf(dest, prefix), { dest, prefix, iface: i });
    }
    if (this.config.defaultRoute) {
      const out = this.host.staticDefaultOut();
      if (out !== undefined) own.set(keyOf("0.0.0.0", 0), { dest: "0.0.0.0", prefix: 0, iface: out });
    }
    return own;
  }

  /** 트리거 업데이트: 못 쓰게 된 경로를 철회로 바꾸고, 인터페이스마다 Response(필요하면 Request 도)를 보낸다 */
  private update(ctx: NodeContext): void {
    const participating: number[] = [];
    if (this.config.enabled) for (let i = 0; i < this.host.ifaceCount; i++) if (this.host.participates(i)) participating.push(i);
    // 나가는 인터페이스가 죽었거나 넥스트 홉이 서브넷 밖이 된 경로는 철회 (RIP 를 끈 경우는 아래에서 한꺼번에)
    if (this.config.enabled) for (const r of this.routes.values()) {
      if (r.metric < RIP_INFINITY && !this.usable(r)) {
        r.metric = RIP_INFINITY;
        this.lost = true;
        ctx.trace("rip.withdraw", "app", `RIP 경로 철회: ${keyOf(r.dest, r.prefix)} (넥스트 홉 ${r.nextHop}) — ${this.host.ifaceName(r.out)} 을 더 쓸 수 없음 → 이웃에게 메트릭 16 으로 알림`, { dest: r.dest, prefix: r.prefix });
      }
    }
    const own = this.ownNetworks();
    const withdrawnOwn = [...this.advertised].filter(([k]) => !own.has(k)).map(([, v]) => v);
    // RIP 를 끈 경우: 지난번에 보내던 인터페이스로 마지막 철회만 보낸다
    const sendOn = this.config.enabled ? participating : [...this.active].filter((i) => this.host.participates(i));
    const askAll = this.lost;
    this.lost = false;
    for (const i of sendOn) {
      // 새로 참여한 인터페이스, 또는 경로를 잃었을 때는 모든 인터페이스로 Request: 이웃이 아는 대체 경로를 다시 듣는다
      if (this.config.enabled && (!this.active.has(i) || askAll)) {
        this.sendMessage(i, { kind: "rip", command: "request", entries: [] }, ctx);
      }
      const entries = this.config.enabled ? this.entriesFor(i, own, withdrawnOwn) : this.withdrawAll();
      if (entries.length > 0) this.sendMessage(i, { kind: "rip", command: "response", entries }, ctx);
    }
    // 철회를 알렸으니 테이블에서 지운다
    for (const [k, r] of this.routes) if (r.metric >= RIP_INFINITY || !this.config.enabled) this.routes.delete(k);
    this.advertised = new Map([...own].map(([k, v]) => [k, { dest: v.dest, prefix: v.prefix }]));
    this.active = new Set(this.config.enabled ? participating : []);
  }

  /** 인터페이스 i 로 보낼 경로 목록 (split horizon + poison reverse: i 에서 배운 경로는 16 으로) */
  private entriesFor(i: number, own: Map<string, { dest: Ip; prefix: number; iface: number }>, withdrawnOwn: { dest: Ip; prefix: number }[]): RipEntry[] {
    const out: RipEntry[] = [];
    for (const n of own.values()) {
      if (n.iface === i && n.prefix > 0) continue; // 보내는 쪽 서브넷은 이웃도 직접 연결이라 알리지 않는다
      out.push({ dest: n.dest, prefix: n.prefix, metric: n.prefix === 0 && n.iface === i ? RIP_INFINITY : 1 });
    }
    for (const w of withdrawnOwn) out.push({ dest: w.dest, prefix: w.prefix, metric: RIP_INFINITY });
    for (const [k, r] of this.routes) {
      if (own.has(k)) continue;
      const metric = r.metric >= RIP_INFINITY || r.out === i ? RIP_INFINITY : Math.min(r.metric + 1, RIP_INFINITY);
      out.push({ dest: r.dest, prefix: r.prefix, metric });
    }
    return out;
  }

  private withdrawAll(): RipEntry[] {
    return [
      ...[...this.advertised.values()].map((n) => ({ dest: n.dest, prefix: n.prefix, metric: RIP_INFINITY })),
      ...[...this.routes.values()].map((r) => ({ dest: r.dest, prefix: r.prefix, metric: RIP_INFINITY })),
    ];
  }

  private sendMessage(i: number, msg: RipMessage, ctx: NodeContext): void {
    const src = this.host.ifaceIp(i)!;
    const pkt: Ipv4Packet = { kind: "ipv4", src, dst: RIP_MULTICAST_IP, ttl: 1, payload: { kind: "udp", srcPort: RIP_PORT, dstPort: RIP_PORT, payload: msg } };
    const name = this.host.ifaceName(i);
    if (msg.command === "request") {
      ctx.trace("rip.request", "app", `[${name}] RIP Request → ${RIP_MULTICAST_IP}: "이웃 라우터는 아는 경로를 전부 알려 주세요"`, { iface: name });
    } else {
      const list = msg.entries.map((e) => `${keyOf(e.dest, e.prefix)}=${e.metric >= RIP_INFINITY ? "16(철회)" : e.metric}`).join(", ");
      ctx.trace("rip.response", "app", `[${name}] RIP Response → ${RIP_MULTICAST_IP}: 경로 ${msg.entries.length}개 광고 (${list}) — 메트릭은 홉 수, 이 인터페이스에서 배운 경로는 16 으로(poison reverse)`, { iface: name, entries: msg.entries.map((e) => ({ ...e })) });
    }
    this.host.send(i, pkt, ctx);
  }

  /** 인터페이스 i 로 들어온 RIP 메시지 */
  handle(i: number, src: Ip, msg: RipMessage, frameId: number, ctx: NodeContext): void {
    const name = this.host.ifaceName(i);
    if (!this.config.enabled || !this.host.participates(i)) {
      ctx.trace("rip.ignore", "app", `[${name}] RIP ${msg.command === "request" ? "Request" : "Response"} 수신 — ${this.config.enabled ? "이 인터페이스는 RIP 에 참여하지 않음" : "RIP 가 꺼져 있음"} → 무시`, {}, frameId);
      return;
    }
    const myIp = this.host.ifaceIp(i)!;
    const prefix = this.host.ifacePrefix(i);
    if (src === myIp || !sameSubnet(src, myIp, prefix)) {
      ctx.trace("rip.ignore", "app", `[${name}] RIP 보낸 곳 ${src} 가 이 인터페이스 서브넷(${networkOf(myIp, prefix)}/${prefix}) 밖 → 무시`, { src }, frameId);
      return;
    }
    if (msg.command === "request") {
      ctx.trace("rip.receive", "app", `[${name}] RIP Request 수신 (from ${src}) → 곧 전체 경로를 광고`, { src }, frameId);
      this.kick(ctx);
      return;
    }
    ctx.trace("rip.receive", "app", `[${name}] RIP Response 수신 (from ${src}): 경로 ${msg.entries.length}개`, { src, count: msg.entries.length }, frameId);
    const own = this.ownNetworks();
    let changed = false;
    for (const e of msg.entries) {
      const k = keyOf(e.dest, e.prefix);
      if (own.has(k)) continue; // 내 직접 연결 네트워크는 배우지 않는다
      const metric = Math.min(e.metric, RIP_INFINITY);
      const cur = this.routes.get(k);
      if (cur && cur.nextHop === src && cur.out === i) {
        if (metric === cur.metric) continue;
        if (metric >= RIP_INFINITY) {
          cur.metric = RIP_INFINITY;
          this.lost = true;
          ctx.trace("rip.withdraw", "app", `RIP 경로 철회 수신: ${k} — ${src} 가 더는 닿지 않는다고 알림(메트릭 16) → 삭제하고 이웃에게도 알림`, { dest: e.dest, prefix: e.prefix, from: src }, frameId);
        } else {
          ctx.trace("rip.learn", "app", `RIP 경로 메트릭 변경: ${k} via ${src} ${cur.metric} → ${metric}홉`, { dest: e.dest, prefix: e.prefix, metric }, frameId);
          cur.metric = metric;
        }
        changed = true;
        continue;
      }
      // 다른 이웃이 보낸 16(철회·poison reverse)은 내 경로와 무관하다. 대답하지 않는다 — 대답하면 poison reverse 끼리 끝없이 주고받는다
      if (metric >= RIP_INFINITY) continue;
      if (!cur || !this.usable(cur) || metric < cur.metric) {
        const why = !cur || !this.usable(cur) ? "새 경로" : `더 짧은 경로 (${cur.metric} → ${metric}홉)`;
        this.routes.set(k, { dest: e.dest, prefix: e.prefix, nextHop: src, out: i, metric });
        ctx.trace("rip.learn", "app", `RIP 경로 학습: ${k} via ${src} (${name}), ${metric}홉 — ${why} → 라우팅 테이블에 추가`, { dest: e.dest, prefix: e.prefix, nextHop: src, metric }, frameId);
        changed = true;
      }
    }
    if (changed) this.kick(ctx);
  }

  /**
   * 인터페이스 i 가 곧 주소를 바꾸거나 사라진다: 아직 옛 주소일 때 그쪽 이웃에게 모든 경로 철회를 보낸다.
   * (보내지 않으면 이웃은 옛 넥스트 홉 경로를 계속 쓴다 — 주기 timeout 이 없으므로)
   */
  retire(i: number, ctx: NodeContext): void {
    if (!this.config.enabled || !this.active.has(i) || !this.host.participates(i)) return;
    const entries = this.withdrawAll();
    if (entries.length > 0) {
      ctx.trace("rip.withdraw", "app", `[${this.host.ifaceName(i)}] 주소가 바뀌거나 인터페이스가 사라짐 → 옛 주소로 이웃에게 모든 경로 철회를 먼저 알림`, { iface: this.host.ifaceName(i) });
      this.sendMessage(i, { kind: "rip", command: "response", entries }, ctx);
    }
    this.active.delete(i); // 새 주소로 참여하면 다시 Request 부터
    for (const r of this.routes.values()) {
      if (r.out === i && r.metric < RIP_INFINITY) {
        r.metric = RIP_INFINITY;
        this.lost = true;
      }
    }
    this.kick(ctx);
  }

  /** 인터페이스 번호가 바뀜 (VLAN 서브 인터페이스 추가·삭제). map[옛 번호] = 새 번호, 사라졌으면 undefined */
  remap(map: (old: number) => number | undefined): void {
    for (const r of this.routes.values()) {
      const n = map(r.out);
      if (n === undefined) {
        if (r.metric < RIP_INFINITY) this.lost = true;
        r.metric = RIP_INFINITY;
      } else r.out = n;
    }
    this.active = new Set([...this.active].map(map).filter((n): n is number => n !== undefined));
  }

  /** 라우터 제거: 이웃에게 모든 경로 철회를 알린다 (DHCP Release 처럼 마지막 인사) */
  shutdown(ctx: NodeContext): void {
    if (!this.config.enabled) return;
    for (const i of this.active) {
      if (!this.host.participates(i)) continue;
      const entries = this.withdrawAll();
      if (entries.length > 0) this.sendMessage(i, { kind: "rip", command: "response", entries }, ctx);
    }
  }

  /** 라우팅 테이블 표시용 (쓸 수 있는 경로만) */
  rows(): RipRoute[] {
    return [...this.routes.values()].filter((r) => this.usable(r));
  }
}
