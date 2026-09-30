// DHCPv6 프리픽스 위임 (DHCPv6-PD, RFC 8415 IA_PD) 의 클라이언트 쪽: 공유기 WAN 이 ISP 에게 /56 을 받는다.
// 받은 프리픽스는 공유기가 LAN 에 /64 로 잘라 RA 로 알린다 — 그래서 IPv6 는 NAT 없이 집 안 장치마다 공인 주소를 갖는다.
//
// 학습 포인트: IPv4 의 공유기는 공인 주소 "하나" 를 받아 NAT 로 나눠 쓴다. IPv6 의 공유기는 주소가 아니라 "프리픽스" 를 받아
// LAN 에 그대로 나눠 준다. ISP 는 그 프리픽스로 오는 패킷을 공유기에게 보내는 경로를 이때 만든다(위임 = 경로).
import type { Ip, Mac } from "../addr";
import { DHCP6_CLIENT_PORT, DHCP6_MULTICAST, DHCP6_SERVER_PORT, type Dhcp6Message } from "../packet";
import type { Emit } from "./iface";
import type { Ipv6Interface } from "./ipv6";
import type { NodeContext, TimerHandle } from "./node";

export const DHCP6_TIMER_TAG = "dhcp6-timeout";

export type Dhcp6State = "idle" | "soliciting" | "requesting" | "bound" | "failed";

export const DHCP6_STATE_LABEL: Record<Dhcp6State, string> = {
  idle: "대기",
  soliciting: "Solicit 보냄 (ISP 찾는 중)",
  requesting: "Request 보냄",
  bound: "위임받음",
  failed: "실패 · ISP 응답 없음",
};

export class Dhcp6PdClient {
  static readonly TIMEOUT = 1000;
  static readonly MAX_TRIES = 3;

  state: Dhcp6State = "idle";
  delegated: { prefix: Ip; length: number } | undefined;
  private serverId: Mac | undefined;
  private offered: { prefix: Ip; length: number } | undefined;
  private xid: number;
  private tries = 0;
  private timer: TimerHandle | undefined;

  constructor(
    private readonly mac: Mac,
    private readonly wan6: Ipv6Interface,
    seed: number,
    /** 위임이 생기거나(프리픽스) 사라질 때(undefined) */
    private readonly onChange: (d: { prefix: Ip; length: number } | undefined, ctx: NodeContext, emit: Emit) => void,
  ) {
    this.xid = 0x6000 + (Math.abs(seed) % 0x1000);
  }

  /** WAN 링크 로컬이 준비되면: Solicit 부터 */
  start(ctx: NodeContext, emit: Emit): void {
    this.cancel();
    this.state = "soliciting";
    this.tries = 0;
    this.offered = undefined;
    this.xid += 1;
    this.send("solicit", ctx, emit);
  }

  private send(type: "solicit" | "request" | "release", ctx: NodeContext, emit: Emit): void {
    const src = this.wan6.linkLocal;
    if (!this.wan6.owns(src)) return;
    this.tries += 1;
    const msg: Dhcp6Message = {
      kind: "dhcp6",
      type,
      xid: this.xid,
      clientId: this.mac,
      ...(this.serverId && type !== "solicit" ? { serverId: this.serverId } : {}),
      ...(type === "request" && this.offered ? { prefix: this.offered } : type === "release" && this.delegated ? { prefix: this.delegated } : {}),
    };
    const what =
      type === "solicit"
        ? `DHCPv6 Solicit (IA_PD): "LAN 에 나눠 줄 프리픽스를 위임해 주세요" → 모든 DHCP 서버(ff02::1:2)${this.tries > 1 ? ` (재시도 ${this.tries}/${Dhcp6PdClient.MAX_TRIES})` : ""}`
        : type === "request"
          ? `DHCPv6 Request: 제안받은 ${this.offered?.prefix}/${this.offered?.length} 를 쓰겠다고 확정 요청${this.tries > 1 ? ` (재시도 ${this.tries}/${Dhcp6PdClient.MAX_TRIES})` : ""}`
          : `DHCPv6 Release: 위임받은 ${this.delegated?.prefix}/${this.delegated?.length} 를 돌려줌`;
    ctx.trace("dhcp6.sent", "app", `[wan] ${what}`, { type, xid: this.xid });
    this.wan6.send({ kind: "ipv6", src, dst: DHCP6_MULTICAST, hopLimit: 1, payload: { kind: "udp", srcPort: DHCP6_CLIENT_PORT, dstPort: DHCP6_SERVER_PORT, payload: msg } }, ctx, emit);
    if (type !== "release") this.timer = ctx.timer(Dhcp6PdClient.TIMEOUT, DHCP6_TIMER_TAG, { xid: this.xid, type });
  }

  handle(from: Ip, m: Dhcp6Message, frameId: number, ctx: NodeContext, emit: Emit): void {
    if (m.clientId !== this.mac || m.xid !== this.xid) {
      ctx.trace("dhcp6.received", "app", `[wan] 다른 요청에 대한 DHCPv6 ${m.type} → 무시`, { xid: m.xid }, frameId);
      return;
    }
    if (m.status || !m.prefix) {
      this.cancel();
      this.state = "failed";
      ctx.trace("dhcp6.timeout", "app", `[wan] ISP ${from} 가 위임할 프리픽스가 없다고 답함 (${m.status ?? "IA_PD 없음"}) → LAN 에 IPv6 글로벌 주소를 줄 수 없음`, {}, frameId);
      return;
    }
    if (m.type === "advertise" && this.state === "soliciting") {
      this.cancel();
      this.serverId = m.serverId;
      this.offered = m.prefix;
      ctx.trace("dhcp6.received", "app", `[wan] DHCPv6 Advertise 수신: ISP ${from} 가 ${m.prefix.prefix}/${m.prefix.length} 를 제안 → Request 로 확정 요청`, { prefix: m.prefix.prefix }, frameId);
      this.state = "requesting";
      this.tries = 0;
      this.send("request", ctx, emit);
      return;
    }
    if (m.type === "reply" && this.state === "requesting") {
      this.cancel();
      this.state = "bound";
      this.delegated = m.prefix;
      ctx.trace(
        "dhcp6.bound",
        "app",
        `[wan] DHCPv6 Reply: ${m.prefix.prefix}/${m.prefix.length} 를 위임받음 → LAN 에 첫 /64 를 RA 로 알린다 (IPv4 는 공인 주소 하나를 NAT 로 나눠 쓰지만, IPv6 는 프리픽스를 받아 LAN 장치마다 공인 주소)`,
        { prefix: m.prefix.prefix, length: m.prefix.length },
        frameId,
      );
      this.onChange(m.prefix, ctx, emit);
      return;
    }
    ctx.trace("dhcp6.received", "app", `[wan] 지금 상태(${DHCP6_STATE_LABEL[this.state]})에서 기다리지 않은 DHCPv6 ${m.type} → 무시`, {}, frameId);
  }

  onTimer(data: unknown, ctx: NodeContext, emit: Emit): void {
    const { xid, type } = data as { xid: number; type: "solicit" | "request" };
    if (xid !== this.xid) return;
    this.timer = undefined;
    if ((type === "solicit" && this.state !== "soliciting") || (type === "request" && this.state !== "requesting")) return;
    if (this.tries < Dhcp6PdClient.MAX_TRIES) {
      ctx.trace("dhcp6.timeout", "app", `[wan] DHCPv6 ${type === "solicit" ? "Advertise" : "Reply"} 를 ${Dhcp6PdClient.TIMEOUT}ms 동안 못 받음 → 다시`, { tries: this.tries });
      this.send(type, ctx, emit);
      return;
    }
    this.state = "failed";
    ctx.trace("dhcp6.timeout", "app", `[wan] DHCPv6 ${Dhcp6PdClient.MAX_TRIES}번에 응답 없음 → 프리픽스 위임 실패 (WAN 이 ISP 에 이어졌는지, ISP 가 IPv6 를 주는지 확인)`, {});
  }

  /** 장치 제거·IPv6 끔: 위임을 돌려준다 */
  release(ctx: NodeContext, emit: Emit): void {
    if (this.state === "bound" && this.delegated) this.send("release", ctx, emit);
    this.stop(ctx, emit);
  }

  /** 링크 다운 등: 위임을 잊는다 (LAN 에서도 거둔다) */
  stop(ctx: NodeContext, emit: Emit): void {
    this.cancel();
    const had = this.delegated;
    this.state = "idle";
    this.delegated = undefined;
    this.offered = undefined;
    if (had) this.onChange(undefined, ctx, emit);
  }

  private cancel(): void {
    this.timer?.cancel();
    this.timer = undefined;
  }
}
