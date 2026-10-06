import { IgmpSnoop } from "./igmp";
import { isBroadcastMac, isMulticastMac, type Mac } from "../addr";
import { describeFrame, MAX_L2_HOPS, type EthernetFrame } from "../packet";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";
import { Stp, STP_TIMER_TAG, type StpConfig } from "./stp";
import { bridgeIdLabel } from "../packet";

interface MacEntry {
  port: number;
  vlan: number;
  learnedAt: number;
}

/** 포트 모드: 액세스(VLAN 번호, 태그 없음) 또는 트렁크(모든 VLAN 을 태그 달아 실어 나름) */
export type PortVlan = number | "trunk";
export const DEFAULT_VLAN = 1;

/**
 * 학습형 L2 스위치: 출발지 MAC 학습, 목적지 MAC 조회, 모르면 플러딩.
 * VLAN: 액세스 포트는 소속 VLAN 하나, 트렁크 포트는 802.1Q 태그로 여러 VLAN. MAC 테이블과 플러딩은 VLAN 마다 따로.
 */
export class Switch implements SimNode {
  readonly type = "switch" as const;
  /** "vlan:mac" → 항목 */
  readonly macTable = new Map<string, MacEntry>();
  readonly id: string;
  readonly portCount: number;
  private readonly portNames: string[];
  /** 포트별 VLAN 설정. 없으면 액세스 VLAN 1 */
  readonly portVlan = new Map<number, PortVlan>();
  /** 최근 본 프레임 id → 수신 포트. 같은 프레임이 다시 오면 L2 루프 */
  private readonly seen = new Map<number | string, number>();
  /** 연결 상태 (STP 가 포트 역할을 정할 때 본다) */
  private readonly up = new Set<number>();
  readonly stp: Stp = new Stp({
    portCount: () => this.portCount,
    portName: (p) => this.portName(p),
    connected: (p) => this.up.has(p),
    send: (p, frame, ctx) => ctx.send(p, frame),
    topologyChanged: (ctx) => {
      if (this.macTable.size === 0) return;
      this.macTable.clear();
      ctx.trace("stp.tc", "L2", `STP 토폴로지 변경 → MAC 테이블 비움 (경로가 바뀌었으니 다시 배운다)`, {});
    },
  });

  /** ports: 포트 개수(이름은 port N) 또는 포트 이름 목록 */
  constructor(id: string, ports: number | string[] = 4) {
    this.id = id;
    this.portNames = typeof ports === "number" ? Array.from({ length: ports }, (_, i) => `port ${i}`) : ports;
    this.portCount = this.portNames.length;
  }

  /** IGMP 스누핑 */
  readonly igmp = new IgmpSnoop();

  setIgmp(on: boolean, ctx: NodeContext, mac = "00:00:00:00:00:00"): void {
    const was = this.igmp.enabled;
    this.igmp.setEnabled(on, ctx, "스위치");
    if (!on || was) return;
    // 스누핑 쿼리어: 켤 때 쿼리를 보내 이미 가입한 기기들이 다시 알리게 한다 (그래야 표가 채워진다)
    ctx.trace("igmp.snoop", "L2", "IGMP 스누핑 켜짐 → General Query 를 모든 포트로 (가입한 기기는 다시 알린다)", {});
    for (let p = 0; p < this.portCount; p++) if (ctx.isPortConnected(p) && this.stp.forwarding(p)) this.sendOut(p, this.vlanOf(p) === "trunk" ? 1 : (this.vlanOf(p) as number), IgmpSnoop.query(mac, ctx), ctx);
  }

  setStp(cfg: StpConfig, mac: string, ctx: NodeContext): void {
    this.stp.setConfig(cfg, mac, ctx);
  }

  portName(port: number): string {
    return this.portNames[port] ?? `port ${port}`;
  }

  vlanOf(port: number): PortVlan {
    return this.portVlan.get(port) ?? DEFAULT_VLAN;
  }

  /** VLAN 을 쓰고 있는지 (설정이 하나라도 기본과 다르면) */
  get vlanAware(): boolean {
    for (const v of this.portVlan.values()) if (v !== DEFAULT_VLAN) return true;
    return false;
  }

  setVlans(cfg: Map<number, PortVlan>, ctx: NodeContext): void {
    let changed = false;
    for (let p = 0; p < this.portCount; p++) {
      const next = cfg.get(p) ?? DEFAULT_VLAN;
      if (this.vlanOf(p) !== next) {
        changed = true;
        this.portVlan.set(p, next);
        ctx.trace("ip.config", "sys", `${this.portName(p)}: ${next === "trunk" ? "트렁크 (모든 VLAN, 태그 있음)" : `액세스 VLAN ${next}`}`, { port: p, vlan: next });
      }
    }
    if (changed) {
      this.macTable.clear();
      ctx.trace("ip.config", "sys", `VLAN 설정 변경 → MAC 테이블 비움`, {});
    }
  }

  private key(vlan: number, mac: Mac): string {
    return `${vlan}:${mac}`;
  }

  receive(port: number, frame: EthernetFrame, ctx: NodeContext): void {
    const label = describeFrame(frame);
    const pn = this.portName(port);
    const mode = this.vlanOf(port);
    ctx.trace("frame.receive", "L2", `${pn} 수신: ${label} [${frame.src} → ${frame.dst}]${frame.vlan !== undefined ? ` (VLAN ${frame.vlan} 태그)` : ""}`, { port, src: frame.src, dst: frame.dst, vlan: frame.vlan }, frame.id);
    // STP: BPDU 는 내가 처리하고 넘기지 않는다 (STP 를 끈 스위치는 보통 멀티캐스트처럼 넘긴다)
    if (frame.payload.kind === "bpdu" && this.stp.config.enabled) {
      this.stp.handle(port, frame.payload, frame.id, ctx);
      return;
    }
    if (!this.stp.forwarding(port)) {
      ctx.trace("stp.discard", "L2", `${pn} 는 STP 대체 포트(차단) → 데이터 프레임을 받지 않고 버림 (루프 방지)`, { port }, frame.id);
      return;
    }
    // 같은 프레임이 다른 VLAN 으로 돌아오는 건 루프가 아니다 (예: 투명 방화벽이 VLAN 10 과 20 을 이음). VLAN 별로 본다
    const scope = mode === "trunk" ? `t${frame.vlan ?? "-"}` : `a${mode}`;
    if (!guardLoop(this.seen, port, frame, ctx, pn, scope)) return;
    frame = { ...frame, hops: (frame.hops ?? 0) + 1 };

    // 이 프레임이 속한 VLAN 결정
    let vlan: number;
    if (mode === "trunk") {
      if (frame.vlan === undefined) {
        ctx.trace("vlan.drop", "L2", `${pn} 는 트렁크인데 태그 없는 프레임 → 드롭 (상대 포트도 트렁크여야 함)`, { port }, frame.id);
        return;
      }
      vlan = frame.vlan;
      frame = { ...frame, vlan: undefined };
    } else {
      if (frame.vlan !== undefined) {
        ctx.trace("vlan.drop", "L2", `${pn} 는 액세스 포트(VLAN ${mode})인데 VLAN ${frame.vlan} 태그 프레임 → 드롭 (트렁크로 바꿔야 함)`, { port }, frame.id);
        return;
      }
      vlan = mode;
    }

    const existing = this.macTable.get(this.key(vlan, frame.src));
    if ((!existing || existing.port !== port) && ctx.isPortConnected(port)) {
      this.macTable.set(this.key(vlan, frame.src), { port, vlan, learnedAt: ctx.now });
      const v = this.vlanAware ? ` (VLAN ${vlan})` : "";
      ctx.trace(
        "switch.learn",
        "L2",
        existing ? `MAC 테이블 갱신: ${frame.src} → ${pn}${v} (이전 ${this.portName(existing.port)})` : `MAC 테이블 학습: ${frame.src} → ${pn}${v}`,
        { mac: frame.src, port, vlan },
        frame.id,
      );
    }

    if (isBroadcastMac(frame.dst)) {
      this.flood(port, vlan, frame, ctx, "브로드캐스트");
      return;
    }
    // 멀티캐스트 MAC 은 출발지로 쓰이지 않아 학습되는 일이 없다 — MLD·IGMP 스누핑이 없는 스위치는 브로드캐스트처럼 뿌린다
    if (isMulticastMac(frame.dst)) {
      const only = this.igmp.observe(port, vlan, frame, ctx, (p) => this.portName(p));
      if (only) {
        for (const p of only) if (ctx.isPortConnected(p) && this.stp.forwarding(p) && (this.vlanOf(p) === "trunk" || this.vlanOf(p) === vlan)) this.sendOut(p, vlan, frame, ctx);
        return;
      }
      this.flood(port, vlan, frame, ctx, `멀티캐스트 ${frame.dst} (${this.igmp.enabled ? "링크 로컬 제어·IGMP" : "스누핑 없는 스위치는 브로드캐스트처럼"})`);
      return;
    }
    const entry = this.macTable.get(this.key(vlan, frame.dst));
    if (!entry) {
      this.flood(port, vlan, frame, ctx, `${frame.dst} 는 ${this.vlanAware ? `VLAN ${vlan} 의 ` : ""}MAC 테이블에 없음`);
      return;
    }
    if (!this.stp.forwarding(entry.port)) {
      ctx.trace("stp.discard", "L2", `${this.portName(entry.port)} 는 STP 차단 포트 → 보내지 않음`, { port: entry.port }, frame.id);
      return;
    }
    if (entry.port === port) {
      ctx.trace("switch.filter", "L2", `목적지 ${frame.dst} 가 수신 포트(${pn})와 같음 → 필터링(전달 안 함)`, { port }, frame.id);
      return;
    }
    ctx.trace("switch.forward", "L2", `MAC 테이블 조회: ${frame.dst} → ${this.portName(entry.port)} 로 전달${this.vlanAware ? ` (VLAN ${vlan})` : ""}`, { dst: frame.dst, port: entry.port, vlan }, frame.id);
    this.sendOut(entry.port, vlan, frame, ctx);
  }

  /** 포트 모드에 맞춰 태그를 붙이거나 뗀 뒤 송신 */
  private sendOut(port: number, vlan: number, frame: EthernetFrame, ctx: NodeContext): void {
    if (this.vlanOf(port) === "trunk") {
      ctx.trace("vlan.tag", "L2", `${this.portName(port)} 는 트렁크 → 802.1Q 태그 VLAN ${vlan} 를 붙여 송신`, { port, vlan }, frame.id);
      ctx.send(port, { ...frame, vlan });
      return;
    }
    ctx.send(port, frame);
  }

  /** 같은 VLAN 의 액세스 포트 + 모든 트렁크 포트로 */
  private flood(inPort: number, vlan: number, frame: EthernetFrame, ctx: NodeContext, reason: string): void {
    const ports: number[] = [];
    const excluded: number[] = [];
    for (let p = 0; p < this.portCount; p++) {
      if (p === inPort || !ctx.isPortConnected(p) || !this.stp.forwarding(p)) continue;
      const m = this.vlanOf(p);
      if (m === "trunk" || m === vlan) ports.push(p);
      else excluded.push(p);
    }
    const v = this.vlanAware ? ` (VLAN ${vlan}${excluded.length ? `; 다른 VLAN 포트 ${excluded.map((p) => this.portName(p)).join(", ")} 제외` : ""})` : "";
    ctx.trace(
      "switch.flood",
      "L2",
      `${reason} → ${this.portName(inPort)} 제외 플러딩 [${ports.map((p) => this.portName(p)).join(", ")}]${v}`,
      { inPort, ports, reason, vlan },
      frame.id,
    );
    for (const p of ports) this.sendOut(p, vlan, frame, ctx);
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    if (up) this.up.add(port);
    else this.up.delete(port);
    if (!up) {
      this.igmp.linkDown(port);
      for (const [k, e] of this.macTable) if (e.port === port) this.macTable.delete(k);
      ctx.trace("link.down", "L1", `${this.portName(port)} 링크 다운 → 그 포트의 MAC 학습 정보 삭제`, { port });
    }
    this.stp.onLink(port, up, ctx);
  }

  onTimer(tag: string, _data: unknown, ctx: NodeContext): void {
    if (tag === STP_TIMER_TAG) this.stp.onTimer(ctx);
  }

  /** 장치 제거: 이웃이 내게서 들은 STP 정보를 거두게 한다 */
  onRemove(ctx: NodeContext): void {
    this.stp.withdraw(ctx);
  }

  snapshot(): NodeSnapshot {
    const vlans = new Set<number>();
    for (let p = 0; p < this.portCount; p++) {
      const m = this.vlanOf(p);
      if (m !== "trunk") vlans.add(m);
    }
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [
        ["포트 수", String(this.portCount)],
        ...(this.vlanAware ? [["VLAN", [...vlans].sort((a, b) => a - b).join(", ")] as [string, string]] : []),
        ...(this.stp.config.enabled
          ? [["STP", `${this.stp.isRoot ? "루트 브리지" : `루트 ${bridgeIdLabel(this.stp.root)} · 비용 ${this.stp.rootCost}`} · 내 ID ${bridgeIdLabel(this.stp.me)}`] as [string, string]]
          : []),
      ],
      tables: [
        ...(this.igmp.enabled ? [{ title: "IGMP 스누핑 (그룹 → 포트)", columns: ["그룹", "VLAN", "포트"], rows: this.igmp.rows((p) => this.portName(p)) }] : []),
        ...(this.stp.config.enabled ? [{ title: "STP 포트", columns: ["포트", "역할", "건너편 스위치"], rows: this.stp.rows() }] : []),
        {
          title: "MAC 테이블",
          columns: this.vlanAware ? ["VLAN", "MAC", "포트", "학습 시각"] : ["MAC", "포트", "학습 시각"],
          rows: [...this.macTable.entries()].map(([k, e]) => {
            const mac = k.slice(k.indexOf(":") + 1);
            return this.vlanAware ? [String(e.vlan), mac, this.portName(e.port), `${e.learnedAt}ms`] : [mac, this.portName(e.port), `${e.learnedAt}ms`];
          }),
        },
      ],
    };
  }
}

/**
 * L2 루프 안전장치. 같은 프레임을 두 번째 보거나 홉 수가 한도를 넘으면 버린다.
 * 실제 이더넷에는 이런 장치가 없어서(TTL 없음) STP 로 루프를 미리 끊어야 한다 — 그 점을 로그로 알려준다.
 */
export function guardLoop(seen: Map<number | string, number>, port: number, frame: EthernetFrame, ctx: NodeContext, portName: string, scope?: string): boolean {
  if ((frame.hops ?? 0) >= MAX_L2_HOPS) {
    ctx.trace("switch.loop", "L2", `프레임이 스위치 ${MAX_L2_HOPS}개를 넘게 돌았음 → L2 루프로 판단해 드롭. 실제 이더넷엔 TTL 이 없어 STP 가 없으면 브로드캐스트 폭주가 난다`, { port }, frame.id);
    return false;
  }
  const key = scope === undefined ? frame.id : `${frame.id}:${scope}`;
  const prev = seen.get(key);
  if (prev !== undefined) {
    ctx.trace("switch.loop", "L2", `같은 프레임을 ${portName} 에서 다시 받음 (처음은 다른 포트) → L2 루프 감지, 드롭. 케이블이 두 경로로 이어져 있음`, { port, first: prev }, frame.id);
    return false;
  }
  seen.set(key, port);
  if (seen.size > 512) {
    const oldest = seen.keys().next().value;
    if (oldest !== undefined) seen.delete(oldest);
  }
  return true;
}
