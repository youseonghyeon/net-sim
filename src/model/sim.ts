// 편집 중인 토폴로지를 항상 살아 있는 시뮬레이션(Network)에 동기화하고, 시뮬레이션 시계를 돌린다.
import { effect, signal } from "@preact/signals";
import { ipToInt } from "../core/addr";
import { Network, type ActionSpec, type Transmission } from "../core/network";
import { DHCP_MAX_ATTEMPTS, DHCP_STATE_LABEL, Host } from "../core/nodes/host";
import { Internet } from "../core/nodes/internet";
import type { SimNode } from "../core/nodes/node";
import { Router } from "../core/nodes/router";
import { Switch } from "../core/nodes/switch";
import { topology } from "./store";
import { DEFAULT_WAN, DEVICE_SPECS, type Device, type Topology } from "./topology";

/** 1x 재생 속도에서 실제 1초당 흐르는 시뮬레이션 시간(ms). 링크 10ms 가 0.4초 */
const BASE_RATE = 25;
const TRACE_CAP = 4000;

/** 화면에 보이는 시뮬레이션 시각. 이벤트 사이를 부드럽게 이동하며, 조용할 때는 멈춘다 */
export const simTime = signal(0);
export const running = signal(true);
export const speed = signal(1);
/** 트레이스나 노드 상태가 바뀔 때마다 증가 → 패널이 다시 읽는다 */
export const simVersion = signal(0);

interface SyncedDevice {
  net: string;
  services: string;
}

class SimController {
  net = new Network();
  private syncedConfig = new Map<string, SyncedDevice>();
  private syncedCables = new Map<string, number>();
  private lastFrame = 0;

  constructor() {
    effect(() => this.sync(topology.value));
    requestAnimationFrame(this.frame);
  }

  /** 시계와 로그를 0 으로 되돌리고 현재 토폴로지로 다시 시작 */
  reset(): void {
    this.net = new Network();
    this.syncedConfig = new Map();
    this.syncedCables = new Map();
    simTime.value = 0;
    this.sync(topology.peek());
  }

  /** 케이블에서 다음 프레임 1개를 유실시킨다 (실험) */
  dropNext(cableId: string): void {
    this.net.dropNextOn(cableId);
    this.bump();
  }

  // ---------- 토폴로지 → 네트워크 동기화 ----------

  private sync(t: Topology): void {
    const net = this.net;
    net.runUntil(this.settleTime());

    const cableIds = new Set(t.cables.map((c) => c.id));
    for (const id of [...this.syncedCables.keys()]) {
      if (!cableIds.has(id)) {
        net.disconnect(id);
        this.syncedCables.delete(id);
      }
    }
    const deviceIds = new Set(t.devices.map((d) => d.id));
    for (const id of [...this.syncedConfig.keys()]) {
      if (!deviceIds.has(id)) {
        net.removeNode(id);
        this.syncedConfig.delete(id);
      }
    }
    for (const d of t.devices) {
      const key: SyncedDevice = { net: configKey(d), services: JSON.stringify(d.host?.services ?? []) };
      const prev = this.syncedConfig.get(d.id);
      if (prev === undefined) {
        net.addNode(makeNode(d));
      } else {
        if (prev.net !== key.net) applyConfig(net, d);
        if (prev.services !== key.services) {
          const node = net.nodes.get(d.id);
          if (node instanceof Host) node.setServices(d.host?.services ?? [], net.contextFor(d.id));
        }
      }
      this.syncedConfig.set(d.id, key);
    }
    for (const c of t.cables) {
      const loss = c.loss ?? 0;
      const prevLoss = this.syncedCables.get(c.id);
      if (prevLoss === undefined) {
        try {
          net.connect(c.a.device, c.a.port, c.b.device, c.b.port, 10, c.id);
          net.setLinkLoss(c.id, loss);
          this.syncedCables.set(c.id, loss);
        } catch (e) {
          console.warn("cable sync failed", c, e);
        }
      } else if (prevLoss !== loss) {
        net.setLinkLoss(c.id, loss);
        this.syncedCables.set(c.id, loss);
      }
    }
    this.bump();
  }

  // ---------- 시계 ----------

  private readonly frame = (ts: number): void => {
    const dt = this.lastFrame ? Math.min(100, ts - this.lastFrame) : 0;
    this.lastFrame = ts;
    if (running.value) this.advance(dt);
    requestAnimationFrame(this.frame);
  };

  private advance(dtMs: number): void {
    const net = this.net;
    let t = simTime.peek();
    if (net.peekNextTime() === undefined && net.inFlight(t).length === 0) return; // 조용함: 시계 정지
    t += (dtMs * BASE_RATE * speed.peek()) / 1000;
    let changed = false;
    for (;;) {
      const next = net.peekNextTime();
      if (next === undefined) break;
      if (next > t) {
        if (net.inFlight(t).length > 0) break; // 패킷이 움직이는 중이면 애니메이션을 기다린다
        t = next; // 아무것도 안 움직이면 다음 이벤트로 점프
      }
      net.step();
      changed = true;
    }
    simTime.value = t;
    if (changed) this.bump();
    net.pruneTransmissions(t - 5000);
  }

  /** 일시정지 상태에서 이벤트 하나 진행 */
  step(): void {
    const net = this.net;
    if (net.peekNextTime() === undefined) return;
    net.step();
    simTime.value = net.now;
    this.bump();
  }

  act(action: ActionSpec): void {
    const net = this.net;
    net.runUntil(this.settleTime());
    net.scheduleAction(net.now, action);
    net.runUntil(net.now);
    this.bump();
  }

  /** 사용자 개입 시각: 애니메이션 시계를 정수 ms 로 올려서 이후 이벤트 시각이 깔끔하게 떨어지게 한다 */
  private settleTime(): number {
    const t = Math.max(this.net.now, Math.ceil(simTime.peek()));
    if (t !== simTime.peek()) simTime.value = t;
    return t;
  }

  clearLog(): void {
    this.net.trace.length = 0;
    this.bump();
  }

  private bump(): void {
    if (this.net.trace.length > TRACE_CAP) this.net.trace.splice(0, this.net.trace.length - TRACE_CAP + 500);
    simVersion.value = simVersion.peek() + 1;
  }

  // ---------- 조회 ----------

  node(id: string): SimNode | undefined {
    return this.net.nodes.get(id);
  }

  inFlight(): Transmission[] {
    return this.net.inFlight(simTime.peek());
  }
}

function validIp(s: string | undefined): string | undefined {
  if (!s) return undefined;
  try {
    ipToInt(s);
    return s;
  } catch {
    return undefined;
  }
}

/** 입력 중인 불완전한 주소는 "없음" 으로 취급해 시뮬레이션에 넘긴다 */
function effectiveHost(d: Device) {
  const h = d.host!;
  return { ipMode: h.ipMode, ip: h.ipMode === "static" ? validIp(h.ip) : undefined, prefix: h.prefix, gateway: h.ipMode === "static" ? validIp(h.gateway) : undefined };
}

function effectiveRouter(d: Device, current?: Router) {
  const r = d.router!;
  const w = r.wan ?? DEFAULT_WAN;
  return {
    lanIp: validIp(r.lanIp) ?? current?.lan.ip ?? "192.168.0.1",
    lanPrefix: r.lanPrefix,
    dhcp: { enabled: r.dhcp.enabled, start: validIp(r.dhcp.start) ?? current?.dhcp.start ?? r.dhcp.start, end: validIp(r.dhcp.end) ?? current?.dhcp.end ?? r.dhcp.end },
    wan: w.ipMode === "static" ? { mode: "static" as const, ip: validIp(w.ip), prefix: w.prefix, gateway: validIp(w.gateway) } : { mode: "dhcp" as const },
  };
}

/** 라우터 WAN 인터페이스 MAC: LAN MAC 의 4번째 옥텟을 01 로 */
function wanMacOf(mac: string): string {
  return mac.replace(/^02:00:00:00/, "02:00:00:01");
}

function configKey(d: Device): string {
  if (d.host) return JSON.stringify({ mac: d.mac, host: effectiveHost(d) });
  if (d.router) return JSON.stringify({ mac: d.mac, router: effectiveRouter(d) });
  return d.mac;
}

function makeNode(d: Device): SimNode {
  const spec = DEVICE_SPECS[d.kind];
  if (spec.role === "switch") return new Switch(d.id, spec.ports.map((p) => p.name));
  if (spec.role === "router") return new Router({ id: d.id, mac: d.mac, wanMac: wanMacOf(d.mac), ...effectiveRouter(d) });
  if (spec.role === "internet") return new Internet({ id: d.id, mac: d.mac });
  return new Host({ id: d.id, mac: d.mac, ...effectiveHost(d), services: d.host?.services ?? [] });
}

function applyConfig(net: Network, d: Device): void {
  const node = net.nodes.get(d.id);
  if (node instanceof Host && d.host) node.configure(effectiveHost(d), net.contextFor(d.id));
  else if (node instanceof Router && d.router) node.configure(effectiveRouter(d, node), net.contextFor(d.id));
}

export const sim = new SimController();

export function togglePlay(): void {
  running.value = !running.value;
}

/** 호스트의 화면 표시용 주소 상태 */
export function hostStatus(id: string): { text: string; tone: "ok" | "warn" | "muted"; mono: boolean } | null {
  const node = sim.node(id);
  if (node instanceof Host) {
    if (node.ip) return { text: `${node.ip}/${node.iface.prefix}`, tone: "ok", mono: true };
    if (!node.linkUp) return { text: "케이블 없음", tone: "muted", mono: false };
    if (node.ipMode === "static") return { text: "IP 없음 · 수동 입력 필요", tone: "warn", mono: false };
    switch (node.dhcp.state) {
      case "discovering":
      case "requesting":
        return { text: `DHCP 요청 중 (${node.dhcp.attempts}/${DHCP_MAX_ATTEMPTS})`, tone: "warn", mono: false };
      case "failed":
        return { text: "DHCP 실패 · IP 없음", tone: "warn", mono: false };
      default:
        return { text: "IP 없음", tone: "warn", mono: false };
    }
  }
  if (node instanceof Router) return { text: `${node.lan.ip}/${node.lan.prefix}`, tone: "ok", mono: true };
  if (node instanceof Internet) return { text: `ISP ${node.iface.ip}/${node.iface.prefix}`, tone: "ok", mono: true };
  return null;
}

/** 라우터 타일의 WAN 줄 */
export function wanStatus(id: string): { text: string; tone: "ok" | "warn" | "muted"; mono: boolean } | null {
  const node = sim.node(id);
  if (!(node instanceof Router)) return null;
  if (node.wan.ip) return { text: `WAN ${node.wan.ip}`, tone: "ok", mono: true };
  if (!node.wanLinkUp) return { text: "WAN 연결 없음", tone: "muted", mono: false };
  if (node.wanMode === "static") return { text: "WAN 주소 수동 입력 필요", tone: "warn", mono: false };
  return { text: `WAN ${DHCP_STATE_LABEL[node.wanClient.state]}`, tone: node.wanClient.state === "failed" ? "warn" : "muted", mono: false };
}
