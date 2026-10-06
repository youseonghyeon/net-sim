// 멀티 WAN 페일오버 (GL.iNet·OpenWrt mwan3 식): 회선 두 개(WAN1 = 주 회선, WAN2 = 예비 — 다른 통신사·LTE·휴대폰 테더링) 중
// 살아 있는 첫 회선으로 내보낸다.
// - 회선이 살았는지: 링크·주소가 있고, 추적 주소(track, 예: 8.8.8.8)에 그 회선으로 보낸 ping 이 답하는가.
//   5초마다(배경 타이머) 회선마다 ping 하나 — 직전 ping 의 답이 없었으면 실패 1, 3번 이어지면 끊김, 끊긴 회선이 2번 이어 답하면 살아남
//   (mwan3 의 interval·down·up). 케이블이 빠지면(링크 다운) 기다리지 않고 바로 끊김
// - 넘어갈 때 진행 중이던 연결은 끊긴다: 새 회선의 공인 주소로 NAT 되어 상대에게는 다른 출발지(다른 연결)로 보인다 — 실제 mwan3 도 같다
// - 추적 주소를 비우면 링크·주소만 본다 (회선이 링크는 살아 있는데 인터넷이 안 되는 장애는 모른다)
// 생략: 로드 밸런싱(회선 나눠 쓰기), 회선 3개 이상, 추적 주소 여러 개(reliability), 회선마다 다른 추적 주소
import type { Ip } from "../addr";
import type { NodeContext } from "./node";

export const MWAN_TIMER_TAG = "mwan-tick";
/** 추적 ping 간격 (배경 타이머) */
export const MWAN_INTERVAL = 5000;
/** 이만큼 이어 실패하면 끊김 */
export const MWAN_DOWN = 3;
/** 끊긴 회선이 이만큼 이어 답하면 다시 살아남 */
export const MWAN_UP = 2;
/** 추적 ping 의 ICMP id (회선마다 +1) */
export const MWAN_ICMP_ID = 0x4d57;

export type WanName = "wan" | "wan2";
export const WAN_LABEL: Record<WanName, string> = { wan: "WAN1", wan2: "WAN2" };

interface LineState {
  /** 지금 살아 있다고 보는지 */
  online: boolean;
  fails: number;
  oks: number;
  /** 마지막으로 보낸 추적 ping (seq, 답을 받았는지) */
  probe: { seq: number; answered: boolean } | undefined;
}

/** 장치가 회선마다 알려 주는 것·해 주는 것 */
export interface MwanIo {
  /** 회선이 쓸 수 있는 상태인지 (링크·주소) */
  ready(w: WanName): boolean;
  /** 링크는 있고 주소를 받는 중인지 (켜질 때 WAN1 의 DHCP 를 기다려 예비 회선으로 잠깐 넘어가지 않게) */
  waiting(w: WanName): boolean;
  /** 그 회선으로 추적 주소에 ping 하나 (출발지 = 그 회선 주소, 그 회선으로만) */
  probe(w: WanName, track: Ip, seq: number, ctx: NodeContext): void;
  /** 쓰는 회선이 바뀜 */
  onSwitch(from: WanName, to: WanName, why: string, ctx: NodeContext): void;
}

export class MultiWan {
  enabled = false;
  track: Ip | undefined;
  readonly lines: Record<WanName, LineState> = { wan: fresh(), wan2: fresh() };
  /** 지금 내보내는 회선 */
  active: WanName = "wan";
  private seq = 0;
  private tick = 0;

  constructor(private readonly io: MwanIo) {}

  setConfig(enabled: boolean, track: Ip | undefined, ctx: NodeContext): void {
    if (enabled === this.enabled && track === this.track) return;
    const was = this.enabled;
    this.enabled = enabled;
    this.track = track;
    for (const w of ["wan", "wan2"] as const) this.lines[w] = { ...fresh(), online: this.io.ready(w) };
    if (!enabled) {
      if (was) ctx.trace("mwan.config", "sys", `멀티 WAN 꺼짐 — lan4 는 다시 LAN 포트, 모든 트래픽은 WAN1 로`, {});
      this.switchTo("wan", "멀티 WAN 꺼짐", ctx);
      return;
    }
    ctx.trace("mwan.config", "sys", `멀티 WAN (페일오버) 켜짐: WAN1 이 주 회선, WAN2(lan4) 가 예비. ${track ? `${MWAN_INTERVAL / 1000}초마다 회선마다 ${track} 에 ping — ${MWAN_DOWN}번 이어 실패하면 끊김, ${MWAN_UP}번 이어 답하면 살아남` : "추적 주소가 없어 링크·주소만 본다"}`, { track: track ?? "" });
    this.decide(ctx, "설정");
    this.arm(ctx);
  }

  private arm(ctx: NodeContext): void {
    if (!this.enabled || !this.track) return;
    ctx.timer(MWAN_INTERVAL, MWAN_TIMER_TAG, { tick: ++this.tick }, true);
  }

  /** 회선의 링크·주소가 바뀜: 끊겼으면 바로 끊김, 생겼으면 (추적을 기다리지 않고) 살아 있다고 본다 */
  onLine(w: WanName, ctx: NodeContext): void {
    if (!this.enabled) return;
    const l = this.lines[w];
    const ready = this.io.ready(w);
    if (!ready && l.online) {
      this.lines[w] = { ...fresh(), online: false };
      ctx.trace("mwan.down", "L3", `멀티 WAN: ${WAN_LABEL[w]} 링크 다운·주소 없음 → 끊김 (추적을 기다리지 않음)`, { wan: w });
    } else if (ready && !l.online && l.fails === 0 && l.oks === 0 && !l.probe) {
      this.lines[w] = { ...fresh(), online: true };
      ctx.trace("mwan.up", "L3", `멀티 WAN: ${WAN_LABEL[w]} 링크·주소 생김 → 쓸 수 있음${this.track ? ` (추적 ping 으로 계속 확인)` : ""}`, { wan: w });
    }
    this.decide(ctx, `${WAN_LABEL[w]} ${ready ? "연결" : "끊김"}`);
  }

  /** 추적 ping 의 답 */
  onReply(w: WanName, seq: number): boolean {
    const p = this.lines[w].probe;
    if (!p || p.seq !== seq) return false;
    p.answered = true;
    return true;
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    if ((data as { tick: number }).tick !== this.tick || !this.enabled || !this.track) return;
    for (const w of ["wan", "wan2"] as const) {
      const l = this.lines[w];
      if (!this.io.ready(w)) {
        l.probe = undefined;
        continue;
      }
      if (l.probe) {
        if (l.probe.answered) {
          l.fails = 0;
          l.oks++;
          if (!l.online && l.oks >= MWAN_UP) {
            l.online = true;
            ctx.trace("mwan.up", "L3", `멀티 WAN: ${WAN_LABEL[w]} 의 추적 ping 이 ${MWAN_UP}번 이어 답함 → 다시 살아남`, { wan: w });
          }
        } else {
          l.oks = 0;
          l.fails++;
          if (l.online) {
            if (l.fails >= MWAN_DOWN) {
              l.online = false;
              ctx.trace("mwan.down", "L3", `멀티 WAN: ${WAN_LABEL[w]} 로 보낸 추적 ping(${this.track})이 ${MWAN_DOWN}번 이어 답이 없음 → 끊김 (링크는 살아 있지만 그 회선으로는 인터넷이 안 됨)`, { wan: w, fails: l.fails });
            } else ctx.trace("mwan.check", "L3", `멀티 WAN: ${WAN_LABEL[w]} 추적 ping 답 없음 (${l.fails}/${MWAN_DOWN})`, { wan: w, fails: l.fails });
          }
        }
      }
      l.probe = { seq: ++this.seq, answered: false };
      this.io.probe(w, this.track, this.seq, ctx);
    }
    this.decide(ctx, "추적");
    this.arm(ctx);
  }

  /** 살아 있는 첫 회선으로 (WAN1 이 우선 — 살아나면 되돌아간다). WAN1 이 아직 주소를 받는 중이면(켜질 때) 기다린다 */
  private decide(ctx: NodeContext, why: string): void {
    if (!this.enabled) return;
    const wan1Coming = this.active === "wan" && this.io.waiting("wan");
    const want: WanName = this.lines.wan.online || wan1Coming ? "wan" : this.lines.wan2.online ? "wan2" : "wan";
    this.switchTo(want, why, ctx);
  }

  private switchTo(to: WanName, why: string, ctx: NodeContext): void {
    if (to === this.active) return;
    const from = this.active;
    this.active = to;
    this.io.onSwitch(from, to, why, ctx);
  }

  /** 표시용 */
  rows(): string[][] {
    return (["wan", "wan2"] as const).map((w) => {
      const l = this.lines[w];
      return [WAN_LABEL[w], l.online ? "살아 있음" : "끊김", this.active === w ? "사용 중" : "대기", this.track ? `실패 ${l.fails} · 성공 ${l.oks}` : "추적 안 함"];
    });
  }
}

function fresh(): LineState {
  return { online: false, fails: 0, oks: 0, probe: undefined };
}
