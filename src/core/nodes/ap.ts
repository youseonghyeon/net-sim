// 무선 AP: 유선 포트 하나와 전파(라디오 슬롯 N개) 사이를 잇는 L2 브리지.
// 학습 포인트: 무선도 같은 브로드캐스트 도메인이고, 전파는 같은 채널의 모든 단말에 닿는다(그래서 암호화가 필요하다).
import { isBroadcastMac, type Mac } from "../addr";
import { describeFrame, type EthernetFrame } from "../packet";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";
import { guardLoop } from "./switch";

interface StationEntry {
  port: number;
  learnedAt: number;
}

export const AP_RADIO_SLOTS = 8;

/**
 * 포트 0 = 유선(eth0), 1..N = 무선 단말 슬롯.
 * 유선 → 무선: 브로드캐스트/모르는 MAC 은 전파로 송출(모든 단말이 받음), 아는 단말은 그 단말로.
 * 무선 → 유선/무선: 단말 MAC 학습, 목적지가 다른 단말이면 AP 가 중계, 아니면 유선으로.
 */
export class AccessPoint implements SimNode {
  static readonly ETH_PORT = 0;

  readonly type = "ap" as const;
  readonly id: string;
  readonly portCount: number;
  ssid: string;
  readonly stations = new Map<Mac, StationEntry>();
  /** 유선 쪽에서 배운 MAC (라우터 등) */
  readonly wired = new Map<Mac, StationEntry>();
  private readonly seen = new Map<number, number>();

  constructor(id: string, ssid: string, slots = AP_RADIO_SLOTS) {
    this.id = id;
    this.ssid = ssid;
    this.portCount = 1 + slots;
  }

  private radioPorts(ctx: NodeContext): number[] {
    const out: number[] = [];
    for (let p = 1; p < this.portCount; p++) if (ctx.isPortConnected(p)) out.push(p);
    return out;
  }

  portName(port: number): string {
    return port === AccessPoint.ETH_PORT ? "eth0" : `무선 슬롯 ${port}`;
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    if (port === AccessPoint.ETH_PORT) {
      ctx.trace(up ? "link.up" : "link.down", "L1", up ? `eth0 링크 연결됨` : `eth0 링크 끊김`, { port });
      if (!up) this.wired.clear();
      return;
    }
    if (!up) for (const [mac, e] of this.stations) if (e.port === port) this.stations.delete(mac);
  }

  receive(port: number, frame: EthernetFrame, ctx: NodeContext): void {
    const label = describeFrame(frame);
    if (!guardLoop(this.seen, port, frame, ctx, this.portName(port))) return;
    frame = { ...frame, hops: (frame.hops ?? 0) + 1 };

    if (port === AccessPoint.ETH_PORT) {
      ctx.trace("frame.receive", "L2", `eth0 수신: ${label} [${frame.src} → ${frame.dst}]`, { port, src: frame.src, dst: frame.dst }, frame.id);
      if (!this.wired.has(frame.src)) this.wired.set(frame.src, { port, learnedAt: ctx.now });
      this.toAir(port, frame, ctx);
      return;
    }

    // 무선 단말에서 온 프레임
    ctx.trace("frame.receive", "L2", `무선 수신 (SSID ${this.ssid}): ${label} [${frame.src} → ${frame.dst}]`, { port, src: frame.src, dst: frame.dst }, frame.id);
    const known = this.stations.get(frame.src);
    if (!known || known.port !== port) {
      this.stations.set(frame.src, { port, learnedAt: ctx.now });
      ctx.trace("switch.learn", "L2", `단말 등록: ${frame.src} → 무선 슬롯 ${port}`, { mac: frame.src, port }, frame.id);
    }
    if (isBroadcastMac(frame.dst)) {
      const others = this.radioPorts(ctx).filter((p) => p !== port);
      ctx.trace(
        "wifi.air",
        "L2",
        `브로드캐스트 → 유선(eth0)과 다른 무선 단말 ${others.length}대로 중계 — 무선도 같은 브로드캐스트 도메인`,
        { ports: others },
        frame.id,
      );
      if (ctx.isPortConnected(AccessPoint.ETH_PORT)) ctx.send(AccessPoint.ETH_PORT, frame);
      for (const p of others) ctx.send(p, frame);
      return;
    }
    const station = this.stations.get(frame.dst);
    if (station) {
      if (station.port === port) {
        ctx.trace("switch.filter", "L2", `목적지 ${frame.dst} 가 보낸 단말 자신 → 필터링`, { port }, frame.id);
        return;
      }
      ctx.trace("switch.forward", "L2", `단말 ↔ 단말 중계: ${frame.dst} 는 무선 슬롯 ${station.port} → AP 가 전파로 다시 보냄 (단말끼리 직접 통신하지 않는다)`, { dst: frame.dst, port: station.port }, frame.id);
      ctx.send(station.port, frame);
      return;
    }
    if (!ctx.isPortConnected(AccessPoint.ETH_PORT)) {
      ctx.trace("link.unconnected", "L1", `${frame.dst} 는 단말 목록에 없고 eth0 에 케이블이 없음 → 폐기`, {}, frame.id);
      return;
    }
    ctx.trace("switch.forward", "L2", `${frame.dst} 는 무선 단말이 아님 → 유선(eth0)으로 전달`, { dst: frame.dst }, frame.id);
    ctx.send(AccessPoint.ETH_PORT, frame);
  }

  /** 유선에서 온 프레임을 전파로 */
  private toAir(_inPort: number, frame: EthernetFrame, ctx: NodeContext): void {
    const radios = this.radioPorts(ctx);
    if (radios.length === 0) {
      ctx.trace("wifi.air", "L2", `연결된 무선 단말이 없음 → 송출할 곳 없음`, {}, frame.id);
      return;
    }
    if (isBroadcastMac(frame.dst)) {
      ctx.trace("wifi.air", "L2", `전파로 송출 (SSID ${this.ssid}): 브로드캐스트 → 단말 ${radios.length}대 모두 받음`, { ports: radios }, frame.id);
      for (const p of radios) ctx.send(p, frame);
      return;
    }
    const station = this.stations.get(frame.dst);
    if (station && ctx.isPortConnected(station.port)) {
      ctx.trace(
        "wifi.air",
        "L2",
        `전파로 송출 (SSID ${this.ssid}): ${frame.dst} 단말에게 — 같은 채널의 다른 단말도 전파는 받지만 암호화되어 읽지 못한다`,
        { dst: frame.dst, port: station.port },
        frame.id,
      );
      ctx.send(station.port, frame);
      return;
    }
    ctx.trace("wifi.air", "L2", `${frame.dst} 는 아직 모르는 단말 → 전파로 모두에게 송출 (${radios.length}대)`, { ports: radios }, frame.id);
    for (const p of radios) ctx.send(p, frame);
  }

  onTimer(): void {}

  snapshot(): NodeSnapshot {
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [
        ["SSID", this.ssid],
        ["연결된 단말", `${this.stations.size}대`],
      ],
      tables: [
        {
          title: "단말 목록",
          columns: ["MAC", "슬롯", "등록 시각"],
          rows: [...this.stations.entries()].map(([mac, e]) => [mac, String(e.port), `${e.learnedAt}ms`]),
        },
      ],
    };
  }
}
