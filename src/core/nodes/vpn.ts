// 사이트 간 VPN (WireGuard 식): 게이트웨이·NAT 박스가 상대 사설 대역으로 가는 패킷을 암호화해 UDP 51820 에 담아
// 상대의 공인 주소로 보낸다(캡슐화). 받은 쪽은 풀어서(복호화) 자기 LAN 으로 넘긴다.
// 학습 포인트: 인터넷 위의 장비는 바깥 헤더(공인 ↔ 공인 UDP)만 보고, 사설 주소끼리의 통신이 NAT 없이 그대로 이어진다.
//
// 실제 WireGuard 처럼 받은 패킷의 출발지(주소·포트)를 상대 주소로 기억해 거기로 답한다(엔드포인트 로밍) —
// 그래서 한쪽이 공유기 NAT 뒤에 있어도, 그쪽이 먼저 보내면 반대쪽도 NAT 가 연 구멍으로 답할 수 있다.
// 핸드셰이크·키 교환·keepalive 는 생략하고 "설정하면 바로 준비된 터널" 로 본다.
import { sameSubnet, type Ip } from "../addr";
import { VPN_PORT, type Ipv4Packet } from "../packet";
import type { NodeContext } from "./node";

export interface VpnConfig {
  enabled: boolean;
  /** 상대 터널 끝의 공인 주소 */
  peer?: Ip;
  /** 상대 쪽 사설 대역 (이 대역으로 가는 패킷을 터널로 보내고, 이 대역에서 온 것만 받는다 — WireGuard 의 AllowedIPs) */
  remote: { dest: Ip; prefix: number }[];
}

export const DEFAULT_VPN: VpnConfig = { enabled: false, remote: [] };

export class Vpn {
  config: VpnConfig = { ...DEFAULT_VPN, remote: [] };
  /** 상대에게서 마지막으로 받은 출발지 (NAT 뒤라면 NAT 가 바꾼 주소·포트) */
  endpoint: { ip: Ip; port: number } | undefined;
  sent = 0;
  received = 0;

  setConfig(cfg: VpnConfig, ctx: NodeContext): void {
    const same = JSON.stringify(cfg) === JSON.stringify(this.config);
    this.config = { ...cfg, remote: cfg.remote.map((r) => ({ ...r })) };
    if (same) return;
    if (this.endpoint && this.endpoint.ip !== cfg.peer) this.endpoint = undefined;
    ctx.trace(
      "vpn.config",
      "sys",
      cfg.enabled
        ? `VPN 켜짐: ${cfg.remote.map((r) => `${r.dest}/${r.prefix}`).join(", ") || "(상대 대역 없음)"} 로 가는 패킷을 암호화해 ${cfg.peer ?? "(상대 주소 없음)"}:${VPN_PORT} 로 보냄`
        : "VPN 꺼짐",
      { ...cfg },
    );
  }

  /** 이 목적지가 터널로 갈 대역이면 그 대역 (가장 긴 마스크) */
  match(dst: Ip): { dest: Ip; prefix: number } | undefined {
    if (!this.config.enabled || !this.config.peer) return undefined;
    let best: { dest: Ip; prefix: number } | undefined;
    for (const r of this.config.remote) {
      let hit = false;
      try {
        hit = sameSubnet(dst, r.dest, r.prefix);
      } catch {
        hit = false;
      }
      if (hit && (!best || r.prefix > best.prefix)) best = r;
    }
    return best;
  }

  /** 터널의 바깥 목적지: 상대에게서 받은 적이 있으면 그 출발지, 없으면 설정한 공인 주소:51820 */
  target(): { ip: Ip; port: number } | undefined {
    if (this.endpoint) return this.endpoint;
    return this.config.peer ? { ip: this.config.peer, port: VPN_PORT } : undefined;
  }

  /** 원래 패킷을 바깥 UDP 패킷으로 감싼다 (src = 내 터널 주소) */
  encapsulate(inner: Ipv4Packet, src: Ip): Ipv4Packet | undefined {
    const t = this.target();
    if (!t) return undefined;
    this.sent++;
    return { kind: "ipv4", src, dst: t.ip, ttl: 64, payload: { kind: "udp", srcPort: VPN_PORT, dstPort: t.port, payload: { kind: "vpn", inner } } };
  }

  /** 받은 터널 패킷을 풀어도 되는지. 안 되면 이유 */
  refuse(outer: Ipv4Packet, inner: Ipv4Packet): string | undefined {
    if (!this.config.enabled) return "VPN 이 꺼져 있음";
    const allowed = this.config.remote.some((r) => {
      try {
        return sameSubnet(inner.src, r.dest, r.prefix);
      } catch {
        return false;
      }
    });
    if (!allowed) return `안쪽 출발지 ${inner.src} 가 상대 대역(${this.config.remote.map((r) => `${r.dest}/${r.prefix}`).join(", ") || "없음"})이 아님 — 허용하지 않은 주소 (WireGuard AllowedIPs)`;
    // 바깥 출발지가 설정한 공인 주소와 달라도 받는다 (상대가 NAT 뒤) — 이후에는 그 주소로 답한다 (learn)
    void outer;
    return undefined;
  }

  /** 받은 터널 패킷의 출발지를 상대 주소로 기억 (NAT 뒤에서 와도 거기로 답하도록) */
  learn(outer: Ipv4Packet, srcPort: number): boolean {
    this.received++;
    const changed = !this.endpoint || this.endpoint.ip !== outer.src || this.endpoint.port !== srcPort;
    this.endpoint = { ip: outer.src, port: srcPort };
    return changed;
  }
}
