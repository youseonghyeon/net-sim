// 공유기의 경로 판단 (리눅스 main 테이블 + mwan3): 직접 연결된 대역·스태틱 라우트의 최장 일치, 인터넷으로 내보낼 회선(흐름이 쓰던 회선·정책 규칙·지금 회선),
// 공유기 자신이 만든 패킷의 출발지(ownSource)와 길(sendOwn), 디폴트 라우트를 쓸 수 없는 사유(WAN·LAN 대역 겹침, 넥스트 홉이 내 주소)
import { networkOf, sameSubnet, type Ip } from "../addr";
import { LIMITED_BROADCAST_IP, type Ipv4Packet } from "../packet";
import type { Emit, NetInterface } from "./iface";
import type { MultiWan, WanName } from "./mwan";
import type { NatTable } from "./nat";
import type { NodeContext } from "./node";
import { staticRouteLabel, type RouterStaticRoute } from "./routercfg";
import type { WanLine } from "./wanline";

/** 경로 판단이 공유기에게서 빌리는 것 */
export interface RouteHost {
  readonly lan: NetInterface;
  readonly w1: WanLine;
  readonly w2: WanLine;
  /** 멀티 WAN 을 켰나 (lan4 = WAN2) */
  wan2On(): boolean;
  mwan(): MultiWan;
  emitLan(ctx: NodeContext): Emit;
}

/** main 테이블에서 디폴트 라우트가 아닌 경로: 그 회선에 직접 연결된 대역(via 없음) 또는 스태틱 라우트(route = 번호) */
export interface MainRoute {
  line: WanName;
  via?: Ip;
  route?: number;
}

/**
 * 인터넷으로 내보내는 회선. rule = 이 회선을 고른 정책 규칙 번호, fallback = 규칙의 회선을 쓸 수 없어 지금 회선으로,
 * main = mwan3 정책이 아니라 main 테이블의 경로(직접 연결된 대역·스태틱 라우트)로 고름
 */
export interface OutLine {
  name: WanName;
  iface: NetInterface;
  nat: NatTable;
  emit: Emit;
  rule?: number;
  fallback?: boolean;
  main?: MainRoute;
}

export class RouterRoutes {
  /** 스태틱 라우트 (main 테이블) */
  routes: RouterStaticRoute[] = [];

  constructor(private readonly host: RouteHost) {}

  private get lan(): NetInterface {
    return this.host.lan;
  }
  private get w1(): WanLine {
    return this.host.w1;
  }
  private get w2(): WanLine {
    return this.host.w2;
  }
  private get wan(): NetInterface {
    return this.host.w1.iface;
  }
  private get wan2(): NetInterface {
    return this.host.w2.iface;
  }
  private get wan2On(): boolean {
    return this.host.wan2On();
  }
  private get mwan(): MultiWan {
    return this.host.mwan();
  }
  private emitLan(ctx: NodeContext): Emit {
    return this.host.emitLan(ctx);
  }

  /** 지금 인터넷으로 내보내는 회선: 인터페이스·NAT·송신 */
  private out(ctx: NodeContext): OutLine {
    return this.line(this.wan2On && this.mwan.active === "wan2" ? "wan2" : "wan", ctx);
  }

  line(w: WanName, ctx: NodeContext): OutLine {
    const l = w === "wan2" ? this.w2 : this.w1;
    return { name: l.name, iface: l.iface, nat: l.nat, emit: l.emit(ctx) };
  }

  /**
   * LAN 에서 나가는 이 패킷의 회선: 이미 다른 회선의 흐름(그 회선으로 들어온 포트 포워딩의 응답, 그 회선으로 시작한 연결)이고
   * 그 회선이 살아 있으면 그쪽으로 (mwan3 의 conntrack mark — 되돌아갈 때 쓰던 연결이 끊기지 않게).
   * 목적지가 main 테이블의 경로(회선에 직접 연결된 대역·스태틱 라우트)면 그 경로 (mwan3_connected — 정책을 거치지 않는다).
   * 그 밖의 새 흐름은 출발지가 맞는 정책 규칙의 회선(쓸 수 있으면), 아니면 지금 회선
   */
  outFor(pkt: Ipv4Packet, ctx: NodeContext): OutLine {
    const o = this.out(ctx);
    const main = this.mainRoute(pkt.dst);
    if (this.wan2On) {
      if (o.nat.carries(pkt) && this.mwan.usable(o.name) && (!main || main.line !== o.name)) return o;
      const other: WanName = o.name === "wan" ? "wan2" : "wan";
      if (this.mwan.usable(other) && this.line(other, ctx).nat.carries(pkt) && (!main || main.line !== other)) return this.line(other, ctx);
    }
    if (main) return { ...this.line(main.line, ctx), main };
    if (!this.wan2On || o.nat.carries(pkt)) return o;
    const hit = this.mwan.ruleFor(pkt.src);
    if (!hit) return o;
    const want = hit.rule.line;
    if (want === o.name) return { ...o, rule: hit.index };
    return this.mwan.usable(want) ? { ...this.line(want, ctx), rule: hit.index } : { ...o, rule: hit.index, fallback: true };
  }

  /**
   * main 테이블에서 이 목적지의 가장 긴 일치 경로 (디폴트 라우트 제외): LAN·회선마다 직접 연결된 대역과 스태틱 라우트.
   * 길이가 같으면 먼저 생긴 경로 — LAN, WAN1, WAN2, 스태틱 라우트 순 (스태틱 라우트는 인터페이스가 올라온 뒤에 들어간다).
   * 가장 긴 것이 LAN 이거나 맞는 경로가 없으면 undefined. 스태틱 라우트는 넥스트 홉이 그 인터페이스 대역 안일 때만 들어간다
   * (리눅스는 넥스트 홉에 닿을 수 없는 경로를 넣지 않는다 — "Nexthop has invalid gateway"), 넥스트 홉이 없으면 그 인터페이스로 바로(on-link).
   * 0.0.0.0/0 은 디폴트 라우트라 mwan3_connected 가 아니다 (회선 설정·mwan3 정책이 정함).
   * 경로는 주소가 있는 동안 남는다 — 수동 주소 회선은 케이블이 빠져도(netifd force_link 1), DHCP 회선은 주소를 잃으면 빠진다
   */
  private mainRoute(dst: Ip): MainRoute | undefined {
    let best: { prefix: number; route?: MainRoute } | undefined;
    const offer = (ip: Ip, prefix: number, route?: MainRoute) => {
      if (sameSubnet(dst, ip, prefix) && (!best || prefix > best.prefix)) best = { prefix, ...(route ? { route } : {}) };
    };
    if (this.lan.ip) offer(this.lan.ip, this.lan.prefix);
    if (this.wan.ip) offer(this.wan.ip, this.wan.prefix, { line: "wan" });
    if (this.wan2On && this.wan2.ip) offer(this.wan2.ip, this.wan2.prefix, { line: "wan2" });
    this.routes.forEach((r, i) => {
      if (r.dest.prefix === 0) return;
      const i4 = r.iface === "wan2" ? (this.wan2On ? this.wan2 : undefined) : this.wan;
      if (!i4?.ip) return;
      if (!r.via) offer(r.dest.ip, r.dest.prefix, { line: r.iface, via: dst, route: i });
      else if (sameSubnet(r.via, i4.ip, i4.prefix) && r.via !== i4.ip) offer(r.dest.ip, r.dest.prefix, { line: r.iface, via: r.via, route: i });
    });
    return best?.route;
  }

  /** 이 목적지의 main 테이블 경로가 그 회선의 스태틱 라우트면 넥스트 홉 (on-link 면 대상 자신) */
  staticVia(dst: Ip, line: WanName): Ip | undefined {
    const r = this.mainRoute(dst);
    return r?.route !== undefined && r.line === line ? r.via : undefined;
  }

  /** LAN 으로 가는 목적지인가 (LAN 대역 안이고, 더 긴 스태틱 라우트가 없음) */
  toLan(dst: Ip): boolean {
    return !!this.lan.ip && sameSubnet(dst, this.lan.ip, this.lan.prefix) && !this.mainRoute(dst);
  }

  /** 공유기 자신이 만든 패킷: 목적지가 main 테이블의 경로(직접 연결된 대역·스태틱 라우트)이고 출발지가 그 회선의 주소면 그 경로로 보낸다. 보냈으면 true */
  private sendMain(pkt: Ipv4Packet, ctx: NodeContext): boolean {
    const r = this.mainRoute(pkt.dst);
    if (!r) return false;
    const o = this.line(r.line, ctx);
    if (pkt.src !== o.iface.ip) return false;
    o.iface.sendIp(pkt, ctx, o.emit, r.via);
    return true;
  }

  /** 공유기 자신이 이 목적지로 보낼 때의 출발지: main 테이블의 경로면 그 회선 주소 */
  private mainSource(dst: Ip | undefined): Ip | undefined {
    const r = dst ? this.mainRoute(dst) : undefined;
    return r ? (r.line === "wan2" ? this.wan2.ip : this.wan.ip) : undefined;
  }

  /**
   * 공유기 자신이 만든 바깥 패킷의 출발지 (한 곳): 상대가 보내던 내 주소가 아직 살아 있는 회선의 것이면 그 주소(멀티 WAN — mwan3 의
   * "from <회선 주소>" 규칙), 목적지가 main 테이블 경로(직접 연결된 대역·스태틱 라우트)면 그 회선 주소, 아니면 지금 회선의 주소.
   * 회선 주소는 링크가 살아 있을 때만 (수동 WAN 은 케이블 없이도 주소가 있다)
   */
  ownSource(dst?: Ip, local?: Ip): Ip | undefined {
    const sticky = this.stickySource(local) ?? this.mainSource(dst);
    if (sticky) return sticky;
    const l = this.wan2On && this.mwan.active === "wan2" ? this.w2 : this.w1;
    return l.linkUp ? l.iface.ip : undefined;
  }

  /** 공유기 자신이 만든 바깥 패킷 보내기 (한 곳): LAN 대역이면 LAN, main 테이블 경로면 그 경로, 아니면 출발지 주소의 회선 (두 회선 주소가 같거나 모르는 출발지면 지금 회선) */
  sendOwn(pkt: Ipv4Packet, ctx: NodeContext): void {
    if (this.toLan(pkt.dst)) {
      this.lan.sendIp(pkt, ctx, this.emitLan(ctx));
      return;
    }
    if (this.sendMain(pkt, ctx)) return;
    const o = !this.wan2On || this.wan.ip === this.wan2.ip ? this.out(ctx) : pkt.src === this.wan2.ip ? this.line("wan2", ctx) : pkt.src === this.wan.ip ? this.line("wan", ctx) : this.out(ctx);
    o.iface.sendIp(pkt, ctx, o.emit);
  }

  /** 표시용: LuCI 상태 → 라우트 처럼 main 테이블 (디폴트 라우트는 그 회선을 디폴트 라우트로 쓸 때만) */
  routeRows(): string[][] {
    const rows: string[][] = [];
    const conn = (name: string, i: NetInterface) => {
      if (i.ip) rows.push([name, `${networkOf(i.ip, i.prefix)}/${i.prefix}`, "", "직접 연결"]);
    };
    conn("lan", this.lan);
    conn("wan", this.wan);
    if (this.wan.ip && this.wan.gateway) rows.push(["wan", "0.0.0.0/0", this.wan.gateway, "디폴트 라우트"]);
    if (this.wan2On) {
      conn("wan2", this.wan2);
      if (this.wan2.ip && this.wan2.gateway && this.mwan.wan2Member) rows.push(["wan2", "0.0.0.0/0", this.wan2.gateway, "디폴트 라우트 (예비)"]);
    }
    for (const r of this.routes) {
      const i = r.iface === "wan2" ? (this.wan2On ? this.wan2 : undefined) : this.wan;
      const why =
        r.dest.prefix === 0
          ? "디폴트 라우트는 회선 설정·멀티 WAN 이 정함"
          : !i
            ? "멀티 WAN 이 꺼져 WAN2 가 없음"
            : !i.ip
              ? `${r.iface} 에 주소 없음`
              : !r.via
                ? ""
                : r.via === i.ip
                  ? "넥스트 홉이 내 주소"
                  : !sameSubnet(r.via, i.ip, i.prefix)
                    ? `넥스트 홉이 ${r.iface} 대역(${networkOf(i.ip, i.prefix)}/${i.prefix}) 밖`
                    : "";
      rows.push([r.iface, `${r.dest.ip}/${r.dest.prefix}`, r.via ?? "", why ? `스태틱 — 쓰이지 않음 (${why})` : r.via ? "스태틱" : "스태틱 (on-link)"]);
    }
    return rows;
  }

  /** 스태틱 라우트 설정 (바뀌었을 때만 기록) */
  setRoutes(routes: RouterStaticRoute[], ctx: NodeContext): void {
    if (routes.map(staticRouteLabel).join() === this.routes.map(staticRouteLabel).join()) return;
    this.routes = routes.map((r) => ({ ...r, dest: { ...r.dest } }));
    ctx.trace("ip.config", "sys", routes.length ? `스태틱 라우트: ${routes.map(staticRouteLabel).join(", ")} — 이 대역은 mwan3 정책을 거치지 않고 main 테이블의 이 경로로 (그 회선의 NAT 로 나간다)` : "스태틱 라우트 없음", { routes: routes.length });
  }

  /** 내 WAN 주소 (멀티 WAN 이면 WAN2 주소도) */
  isWanAddr(ip: Ip): boolean {
    return (!!this.wan.ip && ip === this.wan.ip) || (this.wan2On && !!this.wan2.ip && ip === this.wan2.ip);
  }

  /** 상대가 보내던 내 주소가 아직 살아 있는 회선의 주소면 그 주소 (멀티 WAN 일 때만) */
  private stickySource(local: Ip | undefined): Ip | undefined {
    if (!this.wan2On || !local) return undefined;
    if (local === this.wan.ip && this.w1.linkUp && this.mwan.lines.wan.online) return local;
    if (local === this.wan2.ip && this.w2.linkUp && this.mwan.usable("wan2")) return local;
    return undefined;
  }

  /** 이 WAN 회선의 대역이 LAN 대역과 겹치나 (공유기 뒤 공유기를 둘 다 192.168.0.x 로 둔 경우) */
  private overlapsLan(iface: NetInterface): boolean {
    return !!iface.ip && !!this.lan.ip && sameSubnet(iface.ip, this.lan.ip, Math.min(iface.prefix, this.lan.prefix));
  }

  /**
   * 이 회선의 디폴트 라우트를 쓸 수 없는 사유. 넥스트 홉이 내 주소이거나 LAN 대역 안이면 그 경로로는 인터넷에 못 나간다
   * (리눅스는 넥스트 홉을 연결된 대역으로 찾는데, 그게 LAN 쪽이거나 나 자신이다). 게이트웨이가 아예 없으면 인터페이스가 기존대로 알린다
   */
  defaultRouteProblem(iface: NetInterface = this.wan): string | undefined {
    const gw = iface.gateway;
    const lan = this.lan.ip;
    if (!iface.ip || !gw || !lan) return undefined;
    const label = iface === this.wan2 ? "WAN2" : "WAN";
    const both = `${label} ${iface.ip}/${iface.prefix} 와 LAN ${lan}/${this.lan.prefix}`;
    if (gw === lan) return `디폴트 라우트의 넥스트 홉 ${gw} 가 내 LAN 주소 (${both} 가 같은 대역) → 쓸 수 없는 경로라 인터넷으로 못 나감`;
    if (gw === this.wan.ip || gw === this.wan2.ip) return `디폴트 라우트의 넥스트 홉 ${gw} 가 내 주소 → 쓸 수 없는 경로라 인터넷으로 못 나감`;
    if (sameSubnet(gw, lan, this.lan.prefix)) return `디폴트 라우트의 넥스트 홉 ${gw} 가 LAN 대역 안 (${both}) → 넥스트 홉을 LAN 쪽에서 찾게 돼 인터넷으로 못 나감`;
    return undefined;
  }

  /**
   * WAN 회선으로 보내려는 목적지의 경로를 리눅스처럼 판단한다: 연결된 대역(LAN 이 먼저 — 부팅 때 LAN 브리지가 먼저 올라온다) → 그 회선의 대역 → 디폴트 라우트.
   * 못 보내면 사유, 보내도 되면 undefined
   */
  wanRouteProblem(iface: NetInterface, dst: Ip): string | undefined {
    if (!iface.ip || !this.lan.ip) return undefined;
    if (this.overlapsLan(iface) && sameSubnet(dst, this.lan.ip, this.lan.prefix)) {
      const label = iface === this.wan2 ? "WAN2" : "WAN";
      return `${dst} 는 ${label} 대역(${iface.ip}/${iface.prefix})이면서 LAN 대역(${this.lan.ip}/${this.lan.prefix})이기도 함 → 연결된 LAN 경로가 먼저라 ${label} 로 보낼 수 없음`;
    }
    if (sameSubnet(dst, iface.ip, iface.prefix)) return undefined;
    const main = this.mainRoute(dst);
    if (main?.via && (main.line === "wan2" ? this.wan2 : this.wan) === iface) return undefined; // 스태틱 라우트 — 디폴트 라우트를 쓰지 않는다
    const why = this.defaultRouteProblem(iface);
    return why && `${dst} 는 외부 → ${why}`;
  }

  /**
   * WAN2 를 디폴트 라우트로 쓰지 않는데 WAN2 로 내보내려는 패킷(공유기 자신의 답 — 받은 주소에서)의 목적지가 WAN2 의 대역·스태틱 라우트가 아니면:
   * WAN2 에는 디폴트 라우트가 없으니(받은 게이트웨이도 쓰지 않음) main 테이블의 디폴트 라우트인 WAN1 으로 나간다 (출발지 주소는 그대로). 처리했으면 true
   */
  wan2NoDefault(pkt: Ipv4Packet, ctx: NodeContext): boolean {
    if (!this.wan2On || this.mwan.wan2Member || !this.wan2.ip || pkt.dst === LIMITED_BROADCAST_IP || sameSubnet(pkt.dst, this.wan2.ip, this.wan2.prefix)) return false;
    if (this.mainRoute(pkt.dst)?.line === "wan2") return false;
    ctx.trace("ip.forward", "L3", `${pkt.src} → ${pkt.dst}: WAN2 는 디폴트 라우트로 쓰지 않아 WAN2 의 게이트웨이로 보내지 않음 → main 테이블의 디폴트 라우트(WAN1)로 (출발지 주소는 그대로)`, { dst: pkt.dst, out: "wan" });
    this.wan.sendIp(pkt, ctx, this.w1.emit(ctx));
    return true;
  }

  /** WAN 인터페이스로 나가기 직전의 경로 판단 (공유기 자신이 만든 패킷도). 못 보내면 기록하고 true */
  noRouteOut(iface: NetInterface, pkt: Ipv4Packet, ctx: NodeContext): boolean {
    if (pkt.dst === LIMITED_BROADCAST_IP) return false; // DHCP 등 브로드캐스트는 경로와 무관
    const why = this.wanRouteProblem(iface, pkt.dst);
    if (!why) return false;
    ctx.trace("ip.no-route", "L3", `No route: ${pkt.src} → ${pkt.dst} 를 보내려 했지만 ${why} → 드롭`, { dst: pkt.dst });
    return true;
  }
}
