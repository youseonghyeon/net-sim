// 공유기의 내부 스위치: LAN 포트 4개와 무선 단말 슬롯을 한 브리지로 — MAC 학습·플러딩·필터링, 루프 방지, IGMP 스누핑.
// 무선 단말에게 가는 것은 전파 송출로 적는다. 브리지의 LAN 인터페이스(공유기 자신)로 온 것은 공유기에게 넘긴다
import { BROADCAST_MAC, isMulticastMac, type Mac } from "../addr";
import { describeFrame, type EthernetFrame } from "../packet";
import type { Emit } from "./iface";
import { IgmpSnoop } from "./igmp";
import type { NodeContext } from "./node";
import { ROUTER_LAN_PORTS, ROUTER_RADIO_PORTS, ROUTER_WAN2_PORT, routerPortName } from "./routercfg";
import { guardLoop } from "./switch";

const BRIDGE_PORTS = [...ROUTER_LAN_PORTS, ...ROUTER_RADIO_PORTS];

export interface MacEntry {
  port: number;
  learnedAt: number;
}

/** 내부 스위치가 공유기에게서 빌리는 것 */
export interface BridgeHost {
  /** 브리지의 LAN 인터페이스 MAC (공유기 자신) */
  readonly lanMac: Mac;
  /** 멀티 WAN 을 켰나 (lan4 = WAN2 라 브리지에서 빠진다) */
  wan2On(): boolean;
  ssid(): string;
  /** 공유기 자신에게 온 프레임 (브로드캐스트 포함) */
  deliver(frame: EthernetFrame, ctx: NodeContext): void;
  /** 플러딩한 멀티캐스트: 공유기 LAN IPv6 가 가입한 그룹이면 공유기도 받는다 */
  multicast(frame: EthernetFrame, ctx: NodeContext): void;
}

export class RouterBridge {
  readonly macTable = new Map<Mac, MacEntry>();
  private readonly seen = new Map<number, number>();
  /** IGMP 스누핑 */
  readonly igmp = new IgmpSnoop();

  constructor(private readonly host: BridgeHost) {}

  /** LAN 으로 내보내기: 배운 포트로, 모르면 브리지 포트 전부로 */
  emit(ctx: NodeContext): Emit {
    return (frame) => {
      if (frame.dst !== BROADCAST_MAC) {
        const entry = this.macTable.get(frame.dst);
        if (entry) {
          ctx.send(entry.port, frame);
          return;
        }
      }
      for (const p of this.ports()) if (ctx.isPortConnected(p)) ctx.send(p, frame);
    };
  }

  /** LAN 브리지 포트 (멀티 WAN 이면 lan4 는 WAN2 라 빠진다) */
  ports(): number[] {
    return this.host.wan2On() ? BRIDGE_PORTS.filter((p) => p !== ROUTER_WAN2_PORT) : BRIDGE_PORTS;
  }

  /** LAN 포트·무선 슬롯으로 들어온 프레임 */
  receive(port: number, frame: EthernetFrame, ctx: NodeContext): void {
    const pn = routerPortName(port);
    if (frame.vlan !== undefined) {
      ctx.trace("vlan.drop", "L2", `${pn} 에 VLAN ${frame.vlan} 태그 프레임 → 공유기 LAN 포트는 태그를 이해하지 못해 드롭 (스위치 쪽 포트를 액세스로)`, { port, vlan: frame.vlan }, frame.id);
      return;
    }
    ctx.trace("frame.receive", "L2", `${pn} 수신: ${describeFrame(frame)} [${frame.src} → ${frame.dst === BROADCAST_MAC ? "브로드캐스트" : frame.dst}]`, { port, src: frame.src, dst: frame.dst }, frame.id);
    if (!guardLoop(this.seen, port, frame, ctx, pn)) return;
    frame = { ...frame, hops: (frame.hops ?? 0) + 1 };
    const existing = this.macTable.get(frame.src);
    if ((!existing || existing.port !== port) && ctx.isPortConnected(port)) {
      this.macTable.set(frame.src, { port, learnedAt: ctx.now });
      ctx.trace("switch.learn", "L2", `내부 스위치 MAC 테이블 학습: ${frame.src} → ${pn}`, { mac: frame.src, port }, frame.id);
    }
    if (frame.dst === BROADCAST_MAC) {
      this.flood(port, frame, ctx, "브로드캐스트");
      this.host.deliver(frame, ctx);
      return;
    }
    // 멀티캐스트는 내부 스위치가 모든 LAN 포트로 뿌리고, 공유기 LAN IPv6 가 가입한 그룹(모든 노드·모든 라우터·solicited-node)이면 공유기도 받는다
    if (isMulticastMac(frame.dst)) {
      const only = this.igmp.observe(port, 1, frame, ctx, (p) => routerPortName(p));
      if (only) {
        for (const p of only) if (ctx.isPortConnected(p) && this.ports().includes(p)) ctx.send(p, frame);
        return;
      }
      this.flood(port, frame, ctx, `${frame.dst} 는 MAC 테이블에 없음`);
      this.host.multicast(frame, ctx);
      return;
    }
    if (frame.dst === this.host.lanMac) {
      this.host.deliver(frame, ctx);
      return;
    }
    const entry = this.macTable.get(frame.dst);
    if (!entry) {
      this.flood(port, frame, ctx, `${frame.dst} 는 MAC 테이블에 없음`);
      return;
    }
    if (entry.port === port) {
      ctx.trace("switch.filter", "L2", `목적지 ${frame.dst} 가 수신 포트와 같음 → 필터링`, { port }, frame.id);
      return;
    }
    const radio = ROUTER_RADIO_PORTS.includes(entry.port);
    ctx.trace(
      "switch.forward",
      "L2",
      radio
        ? `내부 스위치: ${frame.dst} 는 무선 단말 → 전파로 송출 (SSID ${this.host.ssid()}; 다른 단말도 전파는 받지만 암호화되어 읽지 못한다)`
        : `내부 스위치: ${frame.dst} → ${routerPortName(entry.port)} 로 전달`,
      { dst: frame.dst, port: entry.port },
      frame.id,
    );
    ctx.send(entry.port, frame);
  }

  private flood(inPort: number, frame: EthernetFrame, ctx: NodeContext, reason: string): void {
    const ports = this.ports().filter((p) => p !== inPort && ctx.isPortConnected(p));
    if (ports.length === 0) return;
    const wired = ports.filter((p) => ROUTER_LAN_PORTS.includes(p));
    const radio = ports.filter((p) => ROUTER_RADIO_PORTS.includes(p));
    ctx.trace(
      "switch.flood",
      "L2",
      `${reason} → 다른 LAN 포트로 플러딩 [${wired.map((p) => `lan${p}`).join(", ")}]${radio.length ? ` + 전파로 무선 단말 ${radio.length}대` : ""}`,
      { inPort, ports, reason },
      frame.id,
    );
    for (const p of ports) ctx.send(p, frame);
  }

  /** IGMP 스누핑 (켤 때 쿼리를 보내 가입한 기기들이 다시 알리게) */
  setIgmp(on: boolean, ctx: NodeContext): void {
    const was = this.igmp.enabled;
    this.igmp.setEnabled(on, ctx, "공유기 내부 스위치");
    if (!on || was) return;
    ctx.trace("igmp.snoop", "L2", "IGMP 스누핑 켜짐 → General Query 를 LAN 포트로 (가입한 기기는 다시 알린다)", {});
    const q = IgmpSnoop.query(this.host.lanMac, ctx);
    for (const p of this.ports()) if (ctx.isPortConnected(p)) ctx.send(p, q);
  }

  /** LAN 포트·무선 슬롯의 링크: 내려가면 그 포트로 배운 MAC 을 버린다 (무선 슬롯은 로그 없이) */
  onLink(port: number, up: boolean, ctx: NodeContext): void {
    if (ROUTER_RADIO_PORTS.includes(port)) {
      if (!up) this.forgetPort(port);
      return;
    }
    if (up) {
      ctx.trace("link.up", "L1", `lan${port} 포트 링크 연결됨`, { port });
      return;
    }
    ctx.trace("link.down", "L1", `lan${port} 포트 링크 다운`, { port });
    this.forgetPort(port);
  }

  /** 그 포트로 배운 MAC 을 버린다 */
  forgetPort(port: number): void {
    for (const [mac, e] of this.macTable) if (e.port === port) this.macTable.delete(mac);
  }
}
