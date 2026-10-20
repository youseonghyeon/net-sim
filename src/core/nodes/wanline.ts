// 공유기의 바깥 회선 하나 (WAN1·WAN2): 인터페이스·DHCP 클라이언트·NAT·주소 방식·링크 상태를 한데 묶는다.
// 두 회선이 같은 규칙으로 주소를 얻고 놓게 — 전에는 필드가 회선마다 따로 있고 수동/DHCP 전환·링크 처리도 두 벌이었다
import type { Ip } from "../addr";
import type { DhcpClient } from "./dhcp";
import type { Emit, NetInterface } from "./iface";
import type { WanName } from "./mwan";
import { NatTable } from "./nat";
import type { NodeContext } from "./node";

export type WanMode = "dhcp" | "static";

export interface WanAddressing {
  mode: WanMode;
  ip?: Ip;
  prefix?: number;
  gateway?: Ip;
}

export class WanLine {
  mode: WanMode;
  linkUp = false;
  /** 이 회선의 NAT (회선마다 공인 주소가 달라 매핑도 따로) */
  readonly nat = new NatTable();

  constructor(
    readonly name: WanName,
    readonly port: number,
    /** 로그의 이름 ([wan] · [wan2]) 과 포트 이름 */
    readonly label: string,
    readonly portLabel: string,
    readonly iface: NetInterface,
    readonly client: DhcpClient,
    mode: WanMode = "dhcp",
  ) {
    this.mode = mode;
  }

  emit(ctx: NodeContext): Emit {
    return (frame) => ctx.send(this.port, frame);
  }

  /** 지금 설정과 주소 방식·수동 주소가 다른가 */
  differs(w: WanAddressing): boolean {
    const i = this.iface;
    return w.mode !== this.mode || (w.mode === "static" && (w.ip !== i.ip || (w.prefix ?? 24) !== i.prefix || w.gateway !== i.gateway));
  }

  /**
   * 주소 방식·수동 주소를 반영한다: 수동이면 DHCP 를 멈추고 주소를 넣은 뒤(링크가 있으면 ARP Probe), 자동이면 주소를 비우고
   * 링크가 있으면 DHCP 를 시작한다. 방식이 그대로인 자동 회선은 로그 없이 DHCP 만 다시 시작 (멈춰 있던 것)
   */
  setAddressing(w: WanAddressing, ctx: NodeContext): void {
    const switched = w.mode !== this.mode;
    this.mode = w.mode;
    if (w.mode === "static") {
      this.client.stop();
      this.iface.configure(w.ip || undefined, w.prefix ?? 24, w.gateway || undefined);
      this.iface.arpCache.clear();
      this.iface.clearPending();
      ctx.trace("ip.config", "sys", w.ip ? `[${this.label}] 수동 설정 적용: ${w.ip}/${w.prefix ?? 24}, 게이트웨이 ${w.gateway ?? "없음"}` : `[${this.label}] 수동 설정으로 전환 (주소 미입력)`, { ...w });
      if (w.ip && this.linkUp) this.iface.claim(ctx, this.emit(ctx)); // 같은 주소를 쓰는 장비가 있나 (ARP Probe)
      return;
    }
    this.iface.clearAddress();
    if (switched) ctx.trace("ip.config", "sys", `[${this.label}] 자동(DHCP) 로 전환 → 회선에서 주소를 받는다`, { ...w });
    if (this.linkUp) this.client.start(ctx, this.emit(ctx));
    else this.client.stop();
  }

  /** 링크가 올라옴: 자동 회선은 DHCP 를 시작한다. 수동 회선이고 주소가 있으면 true (이어서 할 일은 장치가) */
  linkOn(ctx: NodeContext): boolean {
    this.linkUp = true;
    ctx.trace("link.up", "L1", `${this.portLabel} 포트 링크 연결됨`, { port: this.port });
    if (this.mode === "dhcp") {
      this.client.start(ctx, this.emit(ctx));
      return false;
    }
    return !!this.iface.ip;
  }

  /** 링크가 내려감 (로그만 — 장치가 회선 이탈을 알린 뒤 release 로 주소를 놓는다) */
  linkOff(ctx: NodeContext): void {
    this.linkUp = false;
    ctx.trace("link.down", "L1", `${this.portLabel} 포트 링크 다운`, { port: this.port });
  }

  /** 링크 다운 뒤: 대기 패킷을 버리고, 자동 회선은 받은 주소를 놓는다 (수동 주소는 남는다 — netifd force_link) */
  release(ctx: NodeContext): void {
    this.iface.clearPending();
    if (this.mode !== "dhcp") return;
    const had = this.iface.ip;
    this.iface.clearAddress();
    this.client.stop();
    if (had) ctx.trace("dhcp.release", "app", `[${this.label}] 링크 다운으로 주소 ${had} 해제`, { ip: had });
  }

  /** 꺼짐 (WAN2 를 다시 LAN 포트로): DHCP 를 멈추고 주소를 비운다 */
  off(): void {
    this.client.stop();
    this.iface.clearAddress();
    this.linkUp = false;
  }
}
