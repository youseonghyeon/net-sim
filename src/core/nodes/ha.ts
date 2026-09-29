// 이중화 (HA, VRRP 식): 게이트웨이·NAT 박스 두 대가 가상 주소(VIP)를 함께 두고, 한 대(master)만 그 주소로 일한다.
// 호스트는 기본 게이트웨이를 VIP 로 두므로, master 가 죽어 backup 이 이어받아도 호스트 설정은 그대로다.
//
// - 선출: 우선순위가 높은 쪽이 master (같으면 실제 주소가 큰 쪽). 높은 쪽이 돌아오면 다시 가져간다(preempt, VRRP 기본값).
// - 가상 MAC 00:00:5e:00:01:<VRID> 를 master 가 쓴다. 넘겨받은 새 master 는 Gratuitous ARP 로 스위치가 새 포트를 배우게 한다
//   (MAC 이 같으므로 호스트의 ARP 캐시는 바뀔 필요가 없다).
// - 방화벽 HA 처럼 장비 단위로 넘어간다: VIP 를 둔 인터페이스 중 하나라도 링크가 죽으면(인터페이스 추적) 전부 넘긴다.
//
// 실제 VRRP 는 master 가 1초마다 광고하고, backup 은 3초 동안 못 들으면 master 가 된다(Master_Down_Interval).
// 이 시뮬레이터의 시계는 조용하면 멈추므로 주기 광고 대신 변화가 있을 때만 광고한다(RIP 와 같은 방식):
//   시작·링크 복구·설정 변경 → 내 우선순위를 알림,  master 가 물러날 때(링크 다운·제거·끔) → 우선순위 0 광고,
//   backup 은 우선순위 0 을 들으면 skew 시간((256 − 우선순위)/256 초) 뒤 master 가 된다.
// 그래서 "말없이 죽은 master" 는 없다고 본다 — 시뮬레이터 안의 고장은 모두 링크 다운·제거로 일어난다.
// 세션(NAT 테이블·방화벽 흐름·IPsec SA) 동기화는 없다 → 넘어가면 진행 중이던 연결은 끊기고 새 연결부터 된다.
import type { Ip, Mac } from "../addr";
import { ipToInt } from "../addr";
import { VRRP_MULTICAST_IP, type Ipv4Packet, type VrrpPacket } from "../packet";
import type { NodeContext } from "./node";

export interface HaConfig {
  enabled: boolean;
  /** 가상 라우터 번호 (1~255). 같은 쌍은 같은 번호 */
  vrid: number;
  /** 우선순위 (1~254). 높은 쪽이 master */
  priority: number;
  /** 인터페이스별 가상 주소 (인덱스 = 인터페이스, 없으면 그 인터페이스는 HA 에 참여하지 않음) */
  vips: (Ip | undefined)[];
}

export const DEFAULT_HA: HaConfig = { enabled: false, vrid: 1, priority: 100, vips: [] };
export const HA_TIMER_TAG = "vrrp-down";
/** 시작할 때 master 광고를 기다리는 시간 (VRRP: 광고 간격 1초 × 3) */
export const MASTER_DOWN = 3000;

export type HaState = "init" | "backup" | "master";
export const HA_STATE_LABEL: Record<HaState, string> = { init: "시작 전", backup: "backup (대기)", master: "master (일하는 중)" };

/** VRRP 가상 MAC: 00:00:5e:00:01:<VRID> */
export function virtualMac(vrid: number): Mac {
  return `00:00:5e:00:01:${(vrid & 0xff).toString(16).padStart(2, "0")}`;
}

/** 스큐 시간: 우선순위가 높을수록 먼저 master 가 된다 (VRRP: (256 − 우선순위)/256 초) */
export function skewMs(priority: number): number {
  return Math.round(((256 - priority) * 1000) / 256);
}

/** HA 가 장치에게서 알아야 하는 것 */
export interface HaHost {
  ifaceCount(): number;
  ifaceName(i: number): string;
  ifaceIp(i: number): Ip | undefined;
  linkUp(i: number): boolean;
  /** 인터페이스 i 로 VRRP 광고 (224.0.0.18 멀티캐스트) */
  send(i: number, pkt: Ipv4Packet, ctx: NodeContext): void;
  /** master 가 되면 VIP·가상 MAC 을 켜고 Gratuitous ARP, 물러나면 끈다 */
  setVip(i: number, vip: { ip: Ip; mac: Mac } | undefined, ctx: NodeContext): void;
}

export class Ha {
  config: HaConfig = { ...DEFAULT_HA, vips: [] };
  state: HaState = "init";
  /** 마지막으로 들은 master (표시용) */
  masterIp: Ip | undefined;
  private timerToken = 0;
  /** 이번 타이머가 유효한지 확인하는 번호 */
  private armed: number | undefined;

  constructor(private readonly host: HaHost) {}

  /** VIP 를 둔 인터페이스 */
  private vipIfaces(): number[] {
    const out: number[] = [];
    this.config.vips.forEach((v, i) => {
      if (v && i < this.host.ifaceCount()) out.push(i);
    });
    return out;
  }

  /** 지금 쓸 수 있는 우선순위: VIP 인터페이스 중 하나라도 링크·주소가 없으면 0 (인터페이스 추적) */
  effectivePriority(): number {
    if (!this.config.enabled) return 0;
    const ifs = this.vipIfaces();
    if (ifs.length === 0) return 0;
    return ifs.every((i) => this.host.linkUp(i) && this.host.ifaceIp(i)) ? this.config.priority : 0;
  }

  setConfig(cfg: HaConfig, ctx: NodeContext): void {
    const same = JSON.stringify(cfg) === JSON.stringify(this.config);
    if (same) return;
    const wasMaster = this.state === "master";
    if (wasMaster) this.resign(ctx, "설정이 바뀜");
    this.config = { ...cfg, vips: [...cfg.vips] };
    this.state = "init";
    this.masterIp = undefined;
    ctx.trace(
      "ha.config",
      "sys",
      cfg.enabled
        ? `이중화(VRRP 식) 켜짐: 그룹 ${cfg.vrid}, 우선순위 ${cfg.priority}, 가상 주소 ${this.vipIfaces().map((i) => `${this.host.ifaceName(i)} ${cfg.vips[i]}`).join(", ") || "(없음)"} — 가상 MAC ${virtualMac(cfg.vrid)}`
        : "이중화 꺼짐",
      { ...cfg },
    );
    if (cfg.enabled) this.start(ctx);
  }

  /** 시작(또는 링크 복구): 내 우선순위를 알리고, master 광고를 기다린다 */
  private start(ctx: NodeContext): void {
    const p = this.effectivePriority();
    this.lastPriority = p;
    if (p === 0) {
      this.state = "backup";
      ctx.trace("ha.state", "L3", `이중화: VIP 인터페이스의 링크·주소가 모두 준비되지 않아 backup 으로 대기 (우선순위 0)`, { priority: 0 });
      return;
    }
    this.state = "backup";
    ctx.trace("ha.state", "L3", `이중화 시작: backup 으로 대기하며 우선순위 ${p} 를 알림 → ${MASTER_DOWN / 1000}초 안에 더 높은 master 가 답하지 않으면 master 가 됨`, { priority: p });
    this.advertise(ctx, p);
    this.arm(MASTER_DOWN + skewMs(p), ctx);
  }

  private arm(ms: number, ctx: NodeContext): void {
    this.armed = ++this.timerToken;
    ctx.timer(ms, HA_TIMER_TAG, { token: this.armed });
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const token = (data as { token: number }).token;
    if (token !== this.armed) return;
    this.armed = undefined;
    if (!this.config.enabled || this.state === "master") return;
    if (this.effectivePriority() === 0) return;
    this.becomeMaster(ctx);
  }

  private becomeMaster(ctx: NodeContext): void {
    this.state = "master";
    this.masterIp = undefined;
    const vrid = this.config.vrid;
    ctx.trace(
      "ha.master",
      "L3",
      `이중화: master 가 됨 (우선순위 ${this.config.priority}) → 가상 주소 ${this.vipIfaces().map((i) => this.config.vips[i]).join(", ")} 와 가상 MAC ${virtualMac(vrid)} 을 가져오고 Gratuitous ARP 로 알림 — 스위치가 이 MAC 의 새 포트를 배운다`,
      { vrid, priority: this.config.priority },
    );
    for (const i of this.vipIfaces()) this.host.setVip(i, { ip: this.config.vips[i]!, mac: virtualMac(vrid) }, ctx);
    this.advertise(ctx, this.config.priority);
  }

  /** master 에서 물러난다: 가상 주소를 놓고 우선순위 0 광고 (backup 이 곧바로 이어받게) */
  private resign(ctx: NodeContext, why: string): void {
    if (this.state !== "master") return;
    for (const i of this.vipIfaces()) this.host.setVip(i, undefined, ctx);
    this.state = "backup";
    ctx.trace("ha.backup", "L3", `이중화: master 에서 물러남 (${why}) → 가상 주소를 놓고 우선순위 0 광고 — backup 이 곧 이어받는다`, { why });
    this.advertise(ctx, 0);
  }

  /** VIP 인터페이스마다 광고 (링크가 살아 있는 곳만) */
  private advertise(ctx: NodeContext, priority: number): void {
    for (const i of this.vipIfaces()) {
      const src = this.host.ifaceIp(i);
      if (!src || !this.host.linkUp(i)) continue;
      const msg: VrrpPacket = { kind: "vrrp", vrid: this.config.vrid, priority, vip: this.config.vips[i]! };
      this.host.send(i, { kind: "ipv4", src, dst: VRRP_MULTICAST_IP, ttl: 255, payload: msg }, ctx);
    }
  }

  /** 링크·주소가 바뀜: master 는 추적 인터페이스가 죽으면 물러나고, 살아나면 다시 경쟁에 나선다 */
  onLinks(ctx: NodeContext): void {
    if (!this.config.enabled) return;
    const p = this.effectivePriority();
    const was = this.lastPriority;
    this.lastPriority = p;
    if (this.state === "master" && p === 0) {
      const down = this.vipIfaces().filter((i) => !this.host.linkUp(i) || !this.host.ifaceIp(i)).map((i) => this.host.ifaceName(i));
      this.resign(ctx, `${down.join(", ")} 링크 다운 — 인터페이스 추적`);
      return;
    }
    if (this.state !== "master" && p > 0 && was === 0) this.start(ctx);
  }
  /** 지난번 우선순위 (0 → 양수가 되면 링크가 살아난 것: 다시 경쟁에 나선다) */
  private lastPriority = 0;

  /** 광고 수신 */
  handle(i: number, src: Ip, msg: VrrpPacket, frameId: number, ctx: NodeContext): void {
    if (!this.config.enabled || msg.vrid !== this.config.vrid) return;
    const name = this.host.ifaceName(i);
    const mine = this.effectivePriority();
    if (this.state === "master") {
      if (msg.priority === 0) {
        ctx.trace("ha.advert", "L3", `[${name}] ${src} 의 VRRP 광고 (우선순위 0 — 물러남) 수신 → 내가 master 이므로 광고로 답함`, { from: src, priority: 0 }, frameId);
        this.advertise(ctx, this.config.priority);
        return;
      }
      if (msg.priority > mine || (msg.priority === mine && ipToInt(src) > ipToInt(this.host.ifaceIp(i) ?? "0.0.0.0"))) {
        ctx.trace("ha.advert", "L3", `[${name}] 더 높은 우선순위 ${msg.priority} 의 ${src} 광고 수신 (나는 ${mine}) → master 를 넘긴다 (preempt)`, { from: src, priority: msg.priority }, frameId);
        this.resign(ctx, `더 높은 우선순위의 ${src} 가 있음`);
        this.masterIp = src;
        return;
      }
      ctx.trace("ha.advert", "L3", `[${name}] 낮은 우선순위 ${msg.priority} 의 ${src} 광고 수신 (나는 ${mine}) → 내가 master 임을 광고로 알림`, { from: src, priority: msg.priority }, frameId);
      this.advertise(ctx, this.config.priority);
      return;
    }
    // backup (또는 시작 전)
    if (msg.priority === 0) {
      if (mine === 0) {
        ctx.trace("ha.advert", "L3", `[${name}] master ${src} 가 물러남 (우선순위 0) → 나도 링크가 준비되지 않아(우선순위 0) 이어받지 못함`, { from: src }, frameId);
        return;
      }
      ctx.trace("ha.advert", "L3", `[${name}] master ${src} 가 물러남 (우선순위 0) → ${skewMs(mine)}ms(skew) 뒤 master 가 됨`, { from: src, priority: 0 }, frameId);
      this.masterIp = undefined;
      this.arm(skewMs(mine), ctx);
      return;
    }
    const higher = msg.priority > mine || (msg.priority === mine && ipToInt(src) > ipToInt(this.host.ifaceIp(i) ?? "0.0.0.0"));
    if (higher) {
      this.armed = undefined; // master(또는 곧 master 가 될 쪽)가 있으므로 기다림을 멈춘다
      this.masterIp = src;
      ctx.trace("ha.advert", "L3", `[${name}] ${src} 의 VRRP 광고 (우선순위 ${msg.priority}) 수신 → 나(${mine})보다 높으므로 backup 유지`, { from: src, priority: msg.priority }, frameId);
      return;
    }
    // 나보다 낮은 쪽이 master 거나 경쟁 중: 내 우선순위를 알린다 (그쪽이 master 면 물러나고, 내 타이머가 끝나면 내가 master)
    ctx.trace("ha.advert", "L3", `[${name}] 낮은 우선순위 ${msg.priority} 의 ${src} 광고 수신 (나는 ${mine}) → 내 우선순위를 알리고 master 를 가져감 (preempt)`, { from: src, priority: msg.priority }, frameId);
    this.advertise(ctx, mine);
    this.arm(skewMs(mine), ctx);
  }

  /** 장치 제거·전원 끔: master 면 우선순위 0 으로 물러남을 알린다 */
  shutdown(ctx: NodeContext): void {
    if (this.config.enabled) this.resign(ctx, "장치 제거");
  }

  /** 표시용 한 줄 */
  summary(): string | undefined {
    if (!this.config.enabled) return undefined;
    const p = this.effectivePriority();
    return `${HA_STATE_LABEL[this.state]} · 그룹 ${this.config.vrid} · 우선순위 ${this.config.priority}${p === 0 ? " (링크 다운으로 0)" : ""}${this.state !== "master" && this.masterIp ? ` · master ${this.masterIp}` : ""}`;
  }
}
