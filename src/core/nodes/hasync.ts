// 이중화 세션 동기화 (pfsync 식, IP 프로토콜 240, 224.0.0.240): master 가 새로 만든 NAT 매핑·방화벽 흐름을 모아
// backup 에게 복사해 둔다. 넘어가도 backup 이 같은 공인 포트·같은 흐름으로 이어 가므로 진행 중인 연결이 끊기지 않는다.
// 새 backup 이 들어오면(후보 알림) 지금까지의 상태를 전부 복사(bulk)한다. IPsec 터널(SA)은 복사하지 않는다.
import type { Ip } from "../addr";
import { PFSYNC_MULTICAST_IP, type Ipv4Packet, type PfsyncPacket } from "../packet";
import type { Firewall } from "./firewall";
import type { Ha } from "./ha";
import type { NatTable } from "./nat";
import type { NodeContext } from "./node";

/** 같은 순간 생긴 상태를 모아 한 패킷으로 보내는 타이머 */
export const HA_SYNC_TAG = "ha-sync";

type NatState = PfsyncPacket["nat"][number];

/** 세션 동기화가 장치에게서 빌리는 것 */
export interface SyncHost {
  readonly ha: Ha;
  /** 장치의 NAT 테이블·방화벽 (장치 생성자에서 만들어지므로 그때그때 읽는다) */
  nat(): NatTable | undefined;
  firewall(): Firewall;
  /** 동기화 패킷을 보낼 인터페이스: 가상 주소를 둔 안쪽 인터페이스 (없으면 아무 VIP 인터페이스) */
  syncIface(): number | undefined;
  ifaceIp(i: number): Ip | undefined;
  ifaceName(i: number): string;
  /** 인터페이스 i 로 pfsync 멀티캐스트 송신 */
  send(i: number, pkt: Ipv4Packet, ctx: NodeContext): void;
}

export class SessionSync {
  private pending: { nat: NatState[]; flows: string[] } | undefined;
  private lastBulkAt: number | undefined;

  constructor(private readonly host: SyncHost) {}

  /** 지금 복사해 줄 차례인지: 동기화를 켠 master */
  private syncing(): boolean {
    const ha = this.host.ha;
    return ha.config.enabled && ha.config.sync === true && ha.state === "master";
  }

  /** 새 상태를 모아 두었다가 같은 순간의 것은 한 패킷으로 보낸다 */
  queue(add: { nat: NatState[]; flows: string[] }, ctx: NodeContext): void {
    if (!this.syncing()) return;
    if (!this.pending) {
      this.pending = { nat: [], flows: [] };
      ctx.timer(0, HA_SYNC_TAG, {});
    }
    for (const e of add.nat) this.pending.nat.push({ proto: e.proto, lanIp: e.lanIp, innerId: e.innerId, publicId: e.publicId });
    this.pending.flows.push(...add.flows);
  }

  flush(ctx: NodeContext): void {
    const p = this.pending;
    this.pending = undefined;
    if (!p || !this.syncing()) return;
    this.sendSync({ kind: "pfsync", vrid: this.host.ha.config.vrid, nat: p.nat, flows: p.flows }, ctx);
  }

  /** 새 backup 을 봄: 지금까지의 상태를 전부 복사 (후보 알림은 VIP 인터페이스마다 오므로 같은 순간에는 한 번만) */
  bulk(ctx: NodeContext): void {
    if (!this.syncing() || this.lastBulkAt === ctx.now) return;
    this.lastBulkAt = ctx.now;
    const nat = (this.host.nat()?.values() ?? []).map((e) => ({ proto: e.proto, lanIp: e.lanIp, innerId: e.innerId, publicId: e.publicId }));
    this.sendSync({ kind: "pfsync", vrid: this.host.ha.config.vrid, nat, flows: this.host.firewall().flowKeys(), bulk: true }, ctx);
  }

  private sendSync(msg: PfsyncPacket, ctx: NodeContext): void {
    const i = this.host.syncIface();
    if (i === undefined || (msg.nat.length === 0 && msg.flows.length === 0)) return;
    ctx.trace("ha.sync", "L3", `세션 동기화 송신 (pfsync${msg.bulk ? ", 전체 복사" : ""}): NAT 매핑 ${msg.nat.length}개, 방화벽 흐름 ${msg.flows.length}개 → backup 이 받아 두면 넘어가도 진행 중인 연결이 이어진다`, { nat: msg.nat.length, flows: msg.flows.length, bulk: msg.bulk === true });
    this.host.send(i, { kind: "ipv4", src: this.host.ifaceIp(i)!, dst: PFSYNC_MULTICAST_IP, ttl: 255, payload: msg }, ctx);
  }

  /** 받은 세션 동기화: backup 이면 매핑·흐름을 그대로 받아 둔다 */
  receive(port: number, pkt: Ipv4Packet, msg: PfsyncPacket, frameId: number, ctx: NodeContext): void {
    const ha = this.host.ha;
    if (!ha.config.enabled || !ha.config.sync || msg.vrid !== ha.config.vrid || ha.state === "master") return;
    for (const e of msg.nat) this.host.nat()?.importEntry(e, ctx.now);
    for (const k of msg.flows) this.host.firewall().importFlow(k);
    ctx.trace("ha.sync", "L3", `[${this.host.ifaceName(port)}] ${pkt.src} 의 세션 동기화 수신${msg.bulk ? " (전체 복사)" : ""}: NAT 매핑 ${msg.nat.length}개, 방화벽 흐름 ${msg.flows.length}개를 받아 둠`, { from: pkt.src, nat: msg.nat.length, flows: msg.flows.length }, frameId);
  }
}
