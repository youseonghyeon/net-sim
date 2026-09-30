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
// 주기 광고(설정 advert, 기본 꺼짐)를 켜면 실제처럼 master 가 1초마다 광고하고, backup 은 광고를 들을 때마다
// Master_Down(3초 + skew) 감시를 다시 건다 — 둘 다 배경 타이머라 시계를 스스로 움직이지 않고, 패킷이 오가거나 "+N초" 로
// 시간이 흐를 때만 돈다. 그래서 끄면 "말없이 죽은 master"(케이블을 모두 뽑아 물러남 광고도 못 보냄)를 모르고, 켜면 시간이
// 흐르는 동안 backup 이 알아채 이어받는다. 감시는 장비 단위라 어느 VIP 인터페이스로든 광고를 들으면 살아 있는 것으로 본다.
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
  /** 세션 동기화 (pfsync 식): master 의 NAT 매핑·방화벽 흐름을 backup 에 복사 */
  sync?: boolean;
  /** 주기 광고: master 는 1초마다 광고, backup 은 3초 + skew 동안 못 들으면 master 가 된다 (배경 타이머) */
  advert?: boolean;
}

export const DEFAULT_HA: HaConfig = { enabled: false, vrid: 1, priority: 100, vips: [] };
export const HA_TIMER_TAG = "vrrp-down";
/** 시작할 때 master 광고를 기다리는 시간 (VRRP: 광고 간격 1초 × 3) */
export const MASTER_DOWN = 3000;
/** 주기 광고 간격 (VRRP 기본 1초) */
export const ADVERT_INTERVAL = 1000;

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
  /** master 가 backup(후보)의 알림을 들음: 세션 동기화면 지금까지의 상태를 전부 복사해 준다 */
  onBackupSeen?(ctx: NodeContext): void;
  /** master 가 되면 VIP·가상 MAC 을 켜고 Gratuitous ARP, 물러나면 끈다 */
  setVip(i: number, vip: { ip: Ip; mac: Mac } | undefined, ctx: NodeContext): void;
  /** master 에서 물러남: 넘겨줄 수 없는 세션(IPsec SA·원격 접속 터널)을 비운다 — 새 master 가 다시 협상한다 */
  onResign?(ctx: NodeContext): void;
}

export class Ha {
  config: HaConfig = { ...DEFAULT_HA, vips: [] };
  state: HaState = "init";
  /** 마지막으로 들은 master (표시용) */
  masterIp: Ip | undefined;
  private timerToken = 0;
  /** 이번 타이머가 유효한지 확인하는 번호 */
  private armed: number | undefined;
  /** 주기 광고 (master): 지금 유효한 배경 타이머 번호 */
  private advertising: number | undefined;
  /** Master_Down 감시 (backup): 지금 유효한 배경 타이머 번호 */
  private watching: number | undefined;

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
    // 주기 광고만 바뀜: 선출을 다시 하지 않고(넘어가지 않게) 광고·감시 타이머만 켜고 끈다
    const rest = (c: HaConfig) => JSON.stringify({ ...c, advert: undefined });
    if (this.config.enabled && rest(cfg) === rest(this.config)) {
      this.config = { ...cfg, vips: [...cfg.vips] };
      this.advertising = undefined;
      this.watching = undefined;
      ctx.trace(
        "ha.config",
        "sys",
        cfg.advert
          ? `이중화 주기 광고 켜짐: master 는 ${ADVERT_INTERVAL / 1000}초마다 광고, backup 은 ${MASTER_DOWN / 1000}초 + skew 동안 못 들으면 이어받음 (시간이 흐를 때만 돈다)`
          : "이중화 주기 광고 꺼짐: 변화가 있을 때만 광고",
        { advert: cfg.advert === true },
      );
      if (this.state === "master") this.scheduleAdvert(ctx);
      else if (this.masterIp) this.watch(ctx);
      return;
    }
    const wasMaster = this.state === "master";
    if (wasMaster) this.resign(ctx, "설정이 바뀜");
    this.config = { ...cfg, vips: [...cfg.vips] };
    this.state = "init";
    this.masterIp = undefined;
    this.advertising = undefined;
    this.watching = undefined;
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
    this.advertise(ctx, p, true);
    this.arm(MASTER_DOWN + skewMs(p), ctx);
  }

  /** 우선순위가 같을 때 가르는 이 장비의 식별 주소 */
  private rid(): Ip {
    const first = this.vipIfaces()[0];
    return (first !== undefined ? this.host.ifaceIp(first) : undefined) ?? "0.0.0.0";
  }

  /** 상대가 나보다 앞서는지: 우선순위, 같으면 식별 주소 */
  private outranks(msg: VrrpPacket, mine: number): boolean {
    return msg.priority > mine || (msg.priority === mine && ipToInt(msg.rid) > ipToInt(this.rid()));
  }

  /** 토폴로지가 다시 이어짐(케이블 연결): master 는 한 번 광고해, 갈라졌던 동안 생긴 다른 master 와 정리한다 */
  poke(ctx: NodeContext): void {
    if (this.config.enabled && this.state === "master") this.advertise(ctx, this.config.priority);
  }

  private arm(ms: number, ctx: NodeContext): void {
    this.armed = ++this.timerToken;
    ctx.timer(ms, HA_TIMER_TAG, { token: this.armed });
  }

  /** master: 다음 주기 광고 (배경 타이머) */
  private scheduleAdvert(ctx: NodeContext): void {
    if (!this.config.advert) return;
    this.advertising = ++this.timerToken;
    ctx.timer(ADVERT_INTERVAL, HA_TIMER_TAG, { advert: this.advertising }, true);
  }

  /** backup: master 광고를 들었다 → Master_Down 감시를 다시 건다 (배경 타이머) */
  private watch(ctx: NodeContext): void {
    if (!this.config.advert) return;
    this.watching = ++this.timerToken;
    ctx.timer(MASTER_DOWN + skewMs(this.effectivePriority()), HA_TIMER_TAG, { watch: this.watching }, true);
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const d = data as { token?: number; advert?: number; watch?: number };
    if (d.advert !== undefined) {
      if (d.advert !== this.advertising) return;
      this.advertising = undefined;
      if (!this.config.enabled || this.state !== "master") return;
      this.advertise(ctx, this.config.priority);
      this.scheduleAdvert(ctx);
      return;
    }
    if (d.watch !== undefined) {
      if (d.watch !== this.watching) return;
      this.watching = undefined;
      // 이미 다른 이유로 master 가 되려고 기다리는 중(armed)이면 그쪽에 맡긴다
      if (!this.config.enabled || this.state === "master" || this.armed !== undefined) return;
      const mine = this.effectivePriority();
      if (mine === 0) return;
      ctx.trace(
        "ha.state",
        "L3",
        `이중화: master ${this.masterIp ?? "?"} 의 광고를 ${(MASTER_DOWN + skewMs(mine)) / 1000}초 동안 못 들음 (Master_Down = 광고 간격 ${ADVERT_INTERVAL / 1000}초 × 3 + skew) → master 가 말없이 죽은 것으로 보고 이어받음`,
        { master: this.masterIp, priority: mine },
      );
      this.becomeMaster(ctx);
      return;
    }
    const token = d.token;
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
    this.watching = undefined;
    this.advertise(ctx, this.config.priority);
    this.scheduleAdvert(ctx);
  }

  /** master 에서 물러난다: 가상 주소를 놓고 우선순위 0 광고 (backup 이 곧바로 이어받게) */
  private resign(ctx: NodeContext, why: string): void {
    if (this.state !== "master") return;
    for (const i of this.vipIfaces()) this.host.setVip(i, undefined, ctx);
    this.state = "backup";
    this.advertising = undefined;
    ctx.trace("ha.backup", "L3", `이중화: master 에서 물러남 (${why}) → 가상 주소를 놓고 우선순위 0 광고 — backup 이 곧 이어받는다`, { why });
    this.host.onResign?.(ctx);
    this.advertise(ctx, 0);
  }

  /** VIP 인터페이스마다 광고 (링크가 살아 있는 곳만) */
  private advertise(ctx: NodeContext, priority: number, candidate = false): void {
    const rid = this.rid();
    for (const i of this.vipIfaces()) {
      const src = this.host.ifaceIp(i);
      if (!src || !this.host.linkUp(i)) continue;
      const msg: VrrpPacket = { kind: "vrrp", vrid: this.config.vrid, priority, vip: this.config.vips[i]!, rid, ...(candidate ? { candidate: true } : {}) };
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
      if (this.outranks(msg, mine)) {
        ctx.trace("ha.advert", "L3", `[${name}] 더 높은 우선순위 ${msg.priority} 의 ${src} 광고 수신 (나는 ${mine}) → master 를 넘긴다 (preempt)`, { from: src, priority: msg.priority }, frameId);
        // 넘기기 전에 지금까지의 세션을 새 master(아직 후보) 에게 전부 복사해 준다 — 넘어가도 이어지게
        if (msg.candidate) this.host.onBackupSeen?.(ctx);
        this.resign(ctx, `더 높은 우선순위의 ${src} 가 있음`);
        this.masterIp = src;
        return;
      }
      ctx.trace("ha.advert", "L3", `[${name}] 낮은 우선순위 ${msg.priority} 의 ${src} 광고 수신 (나는 ${mine}) → 내가 master 임을 광고로 알림`, { from: src, priority: msg.priority }, frameId);
      this.advertise(ctx, this.config.priority);
      if (msg.candidate) this.host.onBackupSeen?.(ctx);
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
    if (this.outranks(msg, mine)) {
      if (msg.candidate) {
        // 아직 master 가 아닌 후보의 알림: 그쪽이 master 가 될 때까지 내 기다림은 그대로 (그 사이 master 가 비지 않게)
        ctx.trace("ha.advert", "L3", `[${name}] 후보 ${src} 의 시작 알림 (우선순위 ${msg.priority}) 수신 → 나(${mine})보다 높지만 아직 master 가 아니므로 기다림은 그대로`, { from: src, priority: msg.priority }, frameId);
        return;
      }
      this.armed = undefined; // master 가 있으므로 기다림을 멈춘다
      this.masterIp = src;
      ctx.trace(
        "ha.advert",
        "L3",
        `[${name}] master ${src} 의 VRRP 광고 (우선순위 ${msg.priority}) 수신 → 나(${mine})보다 높으므로 backup 유지${this.config.advert ? ` — Master_Down 감시 다시 시작 (${(MASTER_DOWN + skewMs(mine)) / 1000}초)` : ""}`,
        { from: src, priority: msg.priority },
        frameId,
      );
      this.watch(ctx);
      return;
    }
    // 나보다 낮은 쪽이 master 거나 경쟁 중: 내 우선순위를 알린다 (그쪽이 master 면 물러나고, 내 타이머가 끝나면 내가 master)
    ctx.trace("ha.advert", "L3", `[${name}] 낮은 우선순위 ${msg.priority} 의 ${src} 광고 수신 (나는 ${mine}) → 내 우선순위를 알리고 master 를 가져감 (preempt)`, { from: src, priority: msg.priority }, frameId);
    this.advertise(ctx, mine, true);
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
