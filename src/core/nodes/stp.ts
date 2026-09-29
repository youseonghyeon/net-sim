// 스패닝 트리 (STP, 802.1D 축소판): 스위치를 여러 경로로 이으면 생기는 L2 루프를, 포트 몇 개를 막아(차단) 나무 모양으로 만든다.
// 이더넷 프레임에는 TTL 이 없어 루프가 있으면 브로드캐스트가 영원히 돈다 — 그래서 실제 스위치는 기본으로 STP 를 켠다.
//
// 1. 루트 선출: 브리지 ID(우선순위 + MAC)가 가장 작은 스위치가 루트
// 2. 루트 포트: 루트가 아닌 스위치는 루트까지 비용이 가장 작은 포트 하나 (같으면 보낸 스위치 ID·포트 번호가 작은 쪽)
// 3. 지정 포트: 각 링크에서 루트에 더 가까운 쪽 포트가 전달을 맡는다
// 4. 나머지(대체 포트)는 차단: 데이터 프레임을 받지도 보내지도 않고 BPDU 만 듣는다
//
// 실제 STP 는 루트가 2초마다 BPDU 를 보내고, 20초(Max Age) 동안 못 들으면 정보를 버리며, 포트가 전달을 시작하기까지 30초를 기다린다.
// 이 시뮬레이터는 시계가 조용하면 멈추므로 RIP·이중화처럼 변화가 있을 때만 BPDU 를 보낸다(RSTP 처럼 곧바로 전환).
// 루트가 사라지면 남은 정보가 돌며 비용이 늘어나는데, Message Age 가 20 을 넘으면 버려서 결국 새 루트로 모인다.
// 토폴로지가 바뀌면(포트 역할 변화) MAC 테이블을 비운다 (Topology Change).
import type { Mac } from "../addr";
import { bridgeIdLabel, STP_MAX_AGE, STP_MULTICAST_MAC, type BpduPacket, type BridgeId, type EthernetFrame } from "../packet";
import type { NodeContext } from "./node";

export interface StpConfig {
  enabled: boolean;
  /** 브리지 우선순위 (0~61440, 4096 단위). 작을수록 루트가 되기 쉽다. 기본 32768 */
  priority: number;
}

export const DEFAULT_STP: StpConfig = { enabled: false, priority: 32768 };
/** 포트 비용 (1Gbps = 4) */
export const STP_PORT_COST = 4;

export type StpRole = "root" | "designated" | "alternate" | "disabled";
export const STP_ROLE_LABEL: Record<StpRole, string> = {
  root: "루트 포트 (전달)",
  designated: "지정 포트 (전달)",
  alternate: "대체 포트 (차단)",
  disabled: "연결 없음",
};

/** 우선순위 벡터: 앞 항목부터 작을수록 좋다 */
interface Vector {
  root: BridgeId;
  cost: number;
  bridge: BridgeId;
  port: number;
}

function cmpId(a: BridgeId, b: BridgeId): number {
  return a.prio - b.prio || (a.mac < b.mac ? -1 : a.mac > b.mac ? 1 : 0);
}

function cmpVec(a: Vector, b: Vector): number {
  return cmpId(a.root, b.root) || a.cost - b.cost || cmpId(a.bridge, b.bridge) || a.port - b.port;
}

/** STP 가 스위치에게서 알아야 하는 것 */
export interface StpHost {
  portCount(): number;
  portName(p: number): string;
  connected(p: number): boolean;
  send(p: number, frame: EthernetFrame, ctx: NodeContext): void;
  /** 포트 역할이 바뀜 → MAC 테이블을 비운다 */
  topologyChanged(ctx: NodeContext): void;
}

export class Stp {
  config: StpConfig = { ...DEFAULT_STP };
  /** 이 스위치의 브리지 MAC */
  mac: Mac = "00:00:00:00:00:00";
  /** 포트마다 마지막으로 받은 BPDU (그 링크 건너편 스위치가 알린 것) */
  private readonly heard = new Map<number, BpduPacket>();
  roles: StpRole[] = [];
  /** 내가 아는 루트와 비용 (루트 포트로 받은 것 + 포트 비용) */
  root: BridgeId = { prio: 32768, mac: "00:00:00:00:00:00" };
  rootCost = 0;
  rootPort: number | undefined;
  private age = 0;

  constructor(private readonly host: StpHost) {}

  get me(): BridgeId {
    return { prio: this.config.priority, mac: this.mac };
  }

  get isRoot(): boolean {
    return this.config.enabled && cmpId(this.root, this.me) === 0;
  }

  /** 이 포트로 데이터 프레임을 주고받는지 (STP 를 끄면 전부) */
  forwarding(p: number): boolean {
    if (!this.config.enabled) return true;
    const r = this.roles[p];
    return r === "root" || r === "designated";
  }

  setConfig(cfg: StpConfig, mac: Mac, ctx: NodeContext): void {
    if (cfg.enabled === this.config.enabled && cfg.priority === this.config.priority && mac === this.mac) return;
    this.config = { ...cfg };
    this.mac = mac;
    this.heard.clear();
    ctx.trace(
      "stp.config",
      "sys",
      cfg.enabled ? `STP 켜짐: 브리지 ID ${bridgeIdLabel(this.me)} (우선순위 ${cfg.priority}) — 처음엔 내가 루트라고 알리고, 더 작은 ID 를 들으면 따른다` : "STP 꺼짐 → 모든 포트 전달",
      { ...cfg },
    );
    this.roles = [];
    this.recompute(ctx, true);
  }

  /** 받은 BPDU */
  handle(p: number, bpdu: BpduPacket, frameId: number, ctx: NodeContext): void {
    if (!this.config.enabled) return;
    const name = this.host.portName(p);
    if (bpdu.age > STP_MAX_AGE) {
      ctx.trace("stp.bpdu", "L2", `[${name}] BPDU 의 Message Age ${bpdu.age} 가 ${STP_MAX_AGE} 을 넘음 → 오래된 정보로 보고 버림`, { port: p, age: bpdu.age }, frameId);
      this.heard.delete(p);
      this.recompute(ctx, false);
      return;
    }
    const prev = this.heard.get(p);
    this.heard.set(p, bpdu);
    const same = prev && cmpVec(prev, bpdu) === 0 && prev.age === bpdu.age;
    ctx.trace("stp.bpdu", "L2", `[${name}] BPDU 수신: 루트 ${bridgeIdLabel(bpdu.root)}, 비용 ${bpdu.cost}, 보낸 스위치 ${bridgeIdLabel(bpdu.bridge)}${same ? " (전과 같음)" : ""}`, { port: p, root: bridgeIdLabel(bpdu.root), cost: bpdu.cost }, frameId);
    const changed = this.recompute(ctx, false);
    // 이 링크에서 내가 지정 포트인데 상대가 더 나쁜 정보를 보냄: 내 BPDU 로 알려 준다 (상대가 모르고 있으므로)
    if (!changed && this.roles[p] === "designated" && cmpVec(this.myVector(p), bpdu) < 0) this.sendOn(p, ctx);
  }

  onLink(p: number, up: boolean, ctx: NodeContext): void {
    if (!this.config.enabled) return;
    if (!up) this.heard.delete(p);
    this.recompute(ctx, up);
  }

  /** 이 포트로 보낼 내 벡터 */
  private myVector(p: number): Vector {
    return { root: this.root, cost: this.rootCost, bridge: this.me, port: p };
  }

  /**
   * 루트·루트 포트·포트 역할을 다시 계산한다. 바뀐 게 있으면(또는 force) 지정 포트로 BPDU 를 보낸다.
   * @returns 역할이나 루트 정보가 바뀌었는지
   */
  private recompute(ctx: NodeContext, force: boolean): boolean {
    const n = this.host.portCount();
    // 1. 가장 좋은 루트 후보: 나 자신 또는 각 포트로 들은 정보 + 포트 비용
    // 비교 순서: 루트 ID → 루트까지 비용 → 보낸 스위치 ID → 보낸 포트 → 받은 내 포트 번호
    let best: { root: BridgeId; cost: number; via?: number; age: number } = { root: this.me, cost: 0, age: 0 };
    let bestKey: Vector | undefined;
    for (let p = 0; p < n; p++) {
      const h = this.heard.get(p);
      if (!h || !this.host.connected(p)) continue;
      const key: Vector = { root: h.root, cost: h.cost + STP_PORT_COST, bridge: h.bridge, port: h.port };
      const selfBetter = cmpId(this.me, h.root) <= 0; // 들은 루트가 나보다 크거나 같으면 내가 루트
      if (selfBetter) continue;
      if (!bestKey || cmpVec(key, bestKey) < 0 || (cmpVec(key, bestKey) === 0 && p < best.via!)) {
        bestKey = key;
        best = { root: h.root, cost: key.cost, via: p, age: h.age + 1 };
      }
    }
    const rootChanged = cmpId(best.root, this.root) !== 0 || best.cost !== this.rootCost || best.via !== this.rootPort;
    this.root = best.root;
    this.rootCost = best.cost;
    this.rootPort = best.via;
    this.age = best.age;
    // 2. 포트 역할
    const roles: StpRole[] = [];
    for (let p = 0; p < n; p++) {
      if (!this.host.connected(p)) roles.push("disabled");
      else if (p === best.via) roles.push("root");
      else {
        const h = this.heard.get(p);
        roles.push(!h || cmpVec(this.myVector(p), h) < 0 ? "designated" : "alternate");
      }
    }
    const changedPorts = roles.map((r, p) => (r !== this.roles[p] ? p : -1)).filter((p) => p >= 0 && roles[p] !== "disabled");
    const prevRoles = this.roles;
    this.roles = roles;
    if (rootChanged) {
      ctx.trace(
        "stp.root",
        "L2",
        this.isRoot
          ? `STP: 내가 루트 브리지 (${bridgeIdLabel(this.me)}) — 더 작은 브리지 ID 를 듣지 못함. 모든 연결 포트가 지정 포트`
          : `STP: 루트 브리지 ${bridgeIdLabel(this.root)}, 루트까지 비용 ${this.rootCost}, 루트 포트 ${this.host.portName(this.rootPort!)}`,
        { root: bridgeIdLabel(this.root), cost: this.rootCost, rootPort: this.rootPort },
      );
    }
    for (const p of changedPorts) {
      const was = prevRoles[p];
      ctx.trace(
        roles[p] === "alternate" ? "stp.block" : "stp.port",
        "L2",
        `STP: ${this.host.portName(p)} → ${STP_ROLE_LABEL[roles[p]!]}${was && was !== "disabled" ? ` (이전 ${STP_ROLE_LABEL[was]})` : ""}${roles[p] === "alternate" ? " — 이 링크 건너편이 루트에 더 가까워, 여기를 막아 루프를 끊는다" : ""}`,
        { port: p, role: roles[p] },
      );
    }
    const topo = changedPorts.some((p) => prevRoles[p] !== undefined && prevRoles[p] !== "disabled");
    if (topo) this.host.topologyChanged(ctx);
    const changed = rootChanged || changedPorts.length > 0;
    // 바뀌면 연결된 모든 포트로 알린다 (실제 STP 는 지정 포트로만 보내고 이웃의 옛 정보는 Max Age 20초로 사라지게 두지만,
    // 여기엔 주기 BPDU·만료 타이머가 없으므로 루트·차단 포트 건너편 이웃에게도 바뀐 정보를 직접 알려 옛 정보를 덮어쓴다)
    if (changed || force) for (let p = 0; p < n; p++) if (roles[p] !== "disabled") this.sendOn(p, ctx);
    return changed;
  }

  private sendOn(p: number, ctx: NodeContext): void {
    const bpdu: BpduPacket = { kind: "bpdu", root: { ...this.root }, cost: this.rootCost, bridge: this.me, port: p, age: this.isRoot ? 0 : this.age };
    const frame: EthernetFrame = { kind: "ethernet", id: ctx.nextPacketId(), src: this.mac, dst: STP_MULTICAST_MAC, payload: bpdu };
    this.host.send(p, frame, ctx);
  }

  rows(): string[][] {
    return this.roles.map((r, p) => (r === "disabled" ? undefined : [this.host.portName(p), STP_ROLE_LABEL[r], this.heard.get(p) ? bridgeIdLabel(this.heard.get(p)!.bridge) : "-"])).filter((x): x is string[] => !!x);
  }
}
