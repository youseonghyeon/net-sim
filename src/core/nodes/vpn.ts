// 사이트 간 VPN: 게이트웨이·NAT 박스가 상대 사설 대역으로 가는 패킷을 암호화해 상대의 공인 주소로 보낸다(캡슐화).
// 받은 쪽은 풀어서(복호화) 자기 LAN 으로 넘긴다. 방식은 두 가지:
//
// WireGuard 식 (기본): UDP 51820 에 담는다. 받은 패킷의 출발지(주소·포트)를 상대 주소로 기억해 거기로 답한다(엔드포인트 로밍) —
// 그래서 한쪽이 공유기 NAT 뒤에 있어도, 그쪽이 먼저 보내면 반대쪽도 NAT 가 연 구멍으로 답할 수 있다.
// 핸드셰이크·키 교환·keepalive 는 생략하고 "설정하면 바로 준비된 터널" 로 본다.
//
// IPsec (IKEv2 + ESP, 기업 방화벽·클라우드 VPN 게이트웨이의 표준): 첫 패킷이 오면 IKE 로 터널(SA)부터 맺는다.
//   IKE_SA_INIT (UDP 500) — 암호 방식 합의 + NAT 감지: 보낸 쪽이 적은 자기 주소가 받은 헤더와 다르면 중간에 NAT
//   IKE_AUTH — 사전 공유 키(PSK)로 서로 인증 → 터널 수립. 그동안 온 패킷은 기다렸다가 보낸다
//   데이터는 ESP (IP 프로토콜 50). ESP 는 포트가 없어 NAT 를 못 지나므로, NAT 를 감지했으면 UDP 4500 에 싣는다 (NAT-T)
// 재협상(rekey)·DPD·암호 방식 목록은 생략한다.
import { sameSubnet, type Ip } from "../addr";
import { IKE_PORT, NAT_T_PORT, VPN_PORT, type IkeMessage, type Ipv4Packet } from "../packet";
import type { NodeContext } from "./node";

export type VpnMode = "wireguard" | "ipsec";
export const VPN_MODE_LABEL: Record<VpnMode, string> = { wireguard: "WireGuard", ipsec: "IPsec" };
/** IKE 응답을 기다리는 시간. 지나면 기다리던 패킷을 버리고, 다음 패킷이 오면 다시 협상한다 */
export const IKE_TIMEOUT = 2000;
export const IKE_TIMER_TAG = "ike-timeout";
/** 터널이 맺어지기를 기다리며 쌓아 두는 패킷 수 */
const IKE_QUEUE = 32;

/** IPsec 을 위해 VPN 이 장치에 부탁하는 것: 바깥(인터넷 쪽) 출발지 주소와 바깥 패킷 송신 (NAT 하지 않음) */
export interface VpnIo {
  source(dst: Ip): Ip | undefined;
  send(outer: Ipv4Packet, ctx: NodeContext, frameId?: number): void;
}

type IpsecState = "idle" | "init" | "auth" | "up";

export interface VpnConfig {
  enabled: boolean;
  /** 없으면 WireGuard 식 */
  mode?: VpnMode;
  /** IPsec 사전 공유 키 (양쪽이 같아야 IKE_AUTH 가 성공) */
  psk?: string;
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
  /** IPsec 터널(SA) 상태 */
  private sa: { state: IpsecState; spi: number; natT: boolean; peer?: { ip: Ip; port: number }; seq: number } = { state: "idle", spi: 0, natT: false, seq: 0 };
  /** IKE 응답자로서 IKE_SA_INIT 을 받아 IKE_AUTH 를 기다리는 협상 */
  private pending: { spi: number; nat: boolean } | undefined;
  private queue: { inner: Ipv4Packet; frameId?: number }[] = [];
  private attempts = 0;

  constructor(private readonly io?: VpnIo) {}

  get mode(): VpnMode {
    return this.config.mode ?? "wireguard";
  }

  setConfig(cfg: VpnConfig, ctx: NodeContext): void {
    const same = JSON.stringify(cfg) === JSON.stringify(this.config);
    this.config = { ...cfg, remote: cfg.remote.map((r) => ({ ...r })) };
    if (same) return;
    if (this.endpoint && this.endpoint.ip !== cfg.peer) this.endpoint = undefined;
    this.resetSa();
    const how = this.mode === "ipsec" ? `IPsec 으로 ${cfg.peer ?? "(상대 주소 없음)"} 와 터널을 맺어 (IKE UDP ${IKE_PORT} → ESP)` : `암호화해 ${cfg.peer ?? "(상대 주소 없음)"}:${VPN_PORT} 로`;
    ctx.trace(
      "vpn.config",
      "sys",
      cfg.enabled ? `VPN 켜짐: ${cfg.remote.map((r) => `${r.dest}/${r.prefix}`).join(", ") || "(상대 대역 없음)"} 로 가는 패킷을 ${how} 보냄` : "VPN 꺼짐",
      { ...cfg },
    );
  }

  private resetSa(): void {
    this.sa = { state: "idle", spi: 0, natT: false, seq: 0 };
    this.pending = undefined;
    this.queue = [];
  }

  /** 표시용: IPsec 터널 상태 한 줄 */
  saSummary(): string | undefined {
    if (this.mode !== "ipsec") return undefined;
    const s = this.sa;
    if (s.state === "up") return `터널 수립됨 · ${s.natT ? "NAT-T (UDP 4500)" : "ESP"} · 상대 ${s.peer?.ip ?? "?"} · SPI 0x${hex(s.spi)}`;
    if (s.state === "init" || s.state === "auth") return `IKE 협상 중 (${s.state === "init" ? "IKE_SA_INIT" : "IKE_AUTH"})`;
    return "터널 없음 (첫 패킷이 오면 IKE 로 맺음)";
  }

  get ipsecUp(): boolean {
    return this.sa.state === "up";
  }

  // ---------- IPsec ----------

  /** 터널로 보낼 패킷: 터널이 있으면 ESP 로, 없으면 쌓아 두고 IKE 협상을 시작한다 */
  sendIpsec(inner: Ipv4Packet, ctx: NodeContext, frameId?: number): void {
    if (this.sa.state === "up") {
      this.sendEsp(inner, ctx, frameId);
      return;
    }
    if (this.queue.length >= IKE_QUEUE) {
      ctx.trace("vpn.drop", "L3", `IPsec: 터널을 맺는 중이라 기다리는 패킷이 너무 많음 → ${inner.src} → ${inner.dst} 드롭`, {}, frameId);
      return;
    }
    this.queue.push({ inner, frameId });
    if (this.sa.state === "idle") this.startIke(ctx, frameId);
  }

  private startIke(ctx: NodeContext, frameId?: number): void {
    const peer = this.config.peer;
    const src = peer ? this.io?.source(peer) : undefined;
    if (!peer || !src) {
      this.failQueue(ctx, `상대 ${peer ?? "(주소 없음)"} 로 가는 바깥 경로가 없어 IKE 를 보낼 수 없음 (상대 공인 주소와 디폴트 라우트를 확인)`, frameId);
      return;
    }
    this.attempts++;
    this.sa = { state: "init", spi: spiOf(src, peer, this.attempts), natT: false, seq: 0 };
    ctx.trace(
      "vpn.ike",
      "L4",
      `IPsec: ${peer} 와 터널이 없음 → IKE_SA_INIT 요청 (UDP ${IKE_PORT}: 암호 방식 제안 + NAT 감지용으로 내 주소 ${src}·상대 주소 ${peer} 를 적어 보냄). 터널이 맺어질 때까지 패킷은 기다림`,
      { peer, spi: this.sa.spi },
      frameId,
    );
    this.sendIke(src, peer, IKE_PORT, IKE_PORT, { kind: "ike", exchange: "IKE_SA_INIT", response: false, spi: this.sa.spi, natSrc: src, natDst: peer }, ctx, frameId);
    ctx.timer(IKE_TIMEOUT, IKE_TIMER_TAG, { spi: this.sa.spi });
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const spi = (data as { spi: number }).spi;
    if (spi !== this.sa.spi || (this.sa.state !== "init" && this.sa.state !== "auth")) return;
    const step = this.sa.state === "init" ? "IKE_SA_INIT" : "IKE_AUTH";
    this.sa = { state: "idle", spi: 0, natT: false, seq: 0 };
    this.failQueue(ctx, `${step} 응답 없음 (timeout ${IKE_TIMEOUT / 1000}초) — 상대가 IPsec VPN 을 켰는지, UDP ${IKE_PORT}/${NAT_T_PORT} 가 막히지 않았는지 확인. 다음 패킷이 오면 다시 협상`);
  }

  private failQueue(ctx: NodeContext, why: string, frameId?: number): void {
    const n = this.queue.length;
    this.queue = [];
    ctx.trace("vpn.drop", "L3", `IPsec 터널을 맺지 못함: ${why}${n ? ` → 기다리던 패킷 ${n}개 드롭` : ""}`, { dropped: n }, frameId);
  }

  private sendIke(src: Ip, dst: Ip, srcPort: number, dstPort: number, m: IkeMessage, ctx: NodeContext, frameId?: number): void {
    this.io?.send({ kind: "ipv4", src, dst, ttl: 64, payload: { kind: "udp", srcPort, dstPort, payload: m } }, ctx, frameId);
  }

  private sendEsp(inner: Ipv4Packet, ctx: NodeContext, frameId?: number): void {
    const peer = this.sa.peer!;
    const src = this.io?.source(peer.ip);
    if (!src) {
      ctx.trace("vpn.drop", "L3", `IPsec: 상대 ${peer.ip} 로 가는 바깥 경로가 없어 터널로 보낼 수 없음 → 드롭 (디폴트 라우트를 확인)`, { dst: inner.dst }, frameId);
      return;
    }
    this.sent++;
    const esp = { kind: "esp" as const, spi: this.sa.spi, seq: ++this.sa.seq, inner };
    const outer: Ipv4Packet = this.sa.natT
      ? { kind: "ipv4", src, dst: peer.ip, ttl: 64, payload: { kind: "udp", srcPort: NAT_T_PORT, dstPort: peer.port, payload: esp } }
      : { kind: "ipv4", src, dst: peer.ip, ttl: 64, payload: esp };
    ctx.trace(
      "vpn.encap",
      "L3",
      `IPsec 캡슐화: ${inner.src} → ${inner.dst} 패킷을 암호화해 ${this.sa.natT ? `UDP ${src}:4500 → ${peer.ip}:${peer.port} (NAT-T) 안의 ESP` : `ESP (IP 프로토콜 50) ${src} → ${peer.ip}`} 로 보냄 — SPI 0x${hex(this.sa.spi)}, seq ${esp.seq}`,
      { inner: `${inner.src}>${inner.dst}`, peer: peer.ip },
      frameId,
    );
    this.io?.send(outer, ctx, frameId);
  }

  /** IKE 메시지 처리. IPsec VPN 이 아니면 false (장치가 보통 UDP 로 처리) */
  handleIke(outer: Ipv4Packet, srcPort: number, dstPort: number, m: IkeMessage, ctx: NodeContext, frameId?: number): boolean {
    if (!this.config.enabled || this.mode !== "ipsec") return false;
    const me = outer.dst;
    if (m.exchange === "IKE_SA_INIT" && !m.response) {
      // 응답자: 적혀 온 주소와 실제 헤더가 다르면 중간 어딘가에 NAT 가 있다 (보낸 쪽 앞 또는 내 앞)
      const nat = m.natSrc !== outer.src || m.natDst !== me;
      this.pending = { spi: m.spi, nat };
      ctx.trace(
        "vpn.ike",
        "L4",
        `IPsec: ${outer.src} 에서 IKE_SA_INIT 요청 → 응답. NAT 감지: ${nat ? `있음 (적혀 온 주소 ${m.natSrc} → ${m.natDst} 와 실제 헤더 ${outer.src} → ${me} 가 다름) → 이후는 UDP 4500 (NAT-T)` : "없음 → 데이터는 ESP 로"}`,
        { from: outer.src, nat },
        frameId,
      );
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "IKE_SA_INIT", response: true, spi: m.spi, nat }, ctx, frameId);
      return true;
    }
    if (m.exchange === "IKE_SA_INIT" && m.response) {
      if (this.sa.state !== "init" || m.spi !== this.sa.spi) return true; // 이미 끝났거나 지난 협상
      const natT = m.nat === true;
      this.sa = { ...this.sa, state: "auth", natT };
      const port = natT ? NAT_T_PORT : IKE_PORT;
      ctx.trace(
        "vpn.ike",
        "L4",
        `IPsec: IKE_SA_INIT 응답 수신 (NAT ${natT ? "있음 → 여기부터 UDP 4500 (NAT-T)" : "없음"}) → IKE_AUTH 요청: 사전 공유 키(PSK)로 만든 인증 값을 보냄`,
        { from: outer.src, natT },
        frameId,
      );
      this.sendIke(me, this.config.peer ?? outer.src, port, port, { kind: "ike", exchange: "IKE_AUTH", response: false, spi: m.spi, auth: this.config.psk ?? "" }, ctx, frameId);
      ctx.timer(IKE_TIMEOUT, IKE_TIMER_TAG, { spi: this.sa.spi });
      return true;
    }
    if (m.exchange === "IKE_AUTH" && !m.response) {
      const p = this.pending;
      if (!p || p.spi !== m.spi) {
        ctx.trace("vpn.drop", "L4", `IPsec: IKE_SA_INIT 없이 온 IKE_AUTH (from ${outer.src}) → 무시`, { from: outer.src }, frameId);
        return true;
      }
      this.pending = undefined;
      if ((m.auth ?? "") !== (this.config.psk ?? "")) {
        ctx.trace("vpn.drop", "L4", `IPsec: ${outer.src} 의 IKE_AUTH 인증 실패 — 사전 공유 키(PSK)가 다름 → AUTHENTICATION_FAILED 로 거절. 양쪽 PSK 를 똑같이 맞추세요`, { from: outer.src }, frameId);
        this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "IKE_AUTH", response: true, spi: m.spi, error: "AUTHENTICATION_FAILED" }, ctx, frameId);
        return true;
      }
      this.establish(m.spi, p.nat, { ip: outer.src, port: srcPort }, "응답자", ctx, frameId);
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "IKE_AUTH", response: true, spi: m.spi }, ctx, frameId);
      this.flush(ctx);
      return true;
    }
    // IKE_AUTH 응답 (시작한 쪽)
    if (this.sa.state !== "auth" || m.spi !== this.sa.spi) return true;
    if (m.error) {
      this.sa = { state: "idle", spi: 0, natT: false, seq: 0 };
      this.failQueue(ctx, `상대 ${outer.src} 가 ${m.error} 로 거절 — 사전 공유 키(PSK)가 다름. 양쪽 PSK 를 똑같이 맞추세요`, frameId);
      return true;
    }
    this.establish(m.spi, this.sa.natT, { ip: outer.src, port: srcPort }, "시작한 쪽", ctx, frameId);
    this.flush(ctx);
    return true;
  }

  private establish(spi: number, natT: boolean, peer: { ip: Ip; port: number }, role: string, ctx: NodeContext, frameId?: number): void {
    this.sa = { state: "up", spi, natT, peer, seq: 0 };
    ctx.trace(
      "vpn.up",
      "L4",
      `IPsec 터널 수립 (${role}): 상대 ${peer.ip} 와 인증 성공 → 이제 ${this.config.remote.map((r) => `${r.dest}/${r.prefix}`).join(", ")} 로 가는 패킷은 ${natT ? "UDP 4500 (NAT-T) 안의 ESP" : "ESP"} 로 암호화 — SPI 0x${hex(spi)}`,
      { peer: peer.ip, natT },
      frameId,
    );
  }

  private flush(ctx: NodeContext): void {
    const q = this.queue;
    this.queue = [];
    for (const x of q) this.sendEsp(x.inner, ctx, x.frameId);
  }

  /** 받은 ESP: 터널이 없으면 이유 */
  refuseEsp(): string | undefined {
    if (!this.config.enabled || this.mode !== "ipsec") return "IPsec VPN 이 꺼져 있음";
    if (this.sa.state !== "up") return "이 상대와 맺은 IPsec 터널(SA)이 없음 — IKE 협상이 끝나지 않았거나 설정이 바뀌어 터널이 내려감";
    return undefined;
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

  /** 터널의 바깥 목적지: 상대에게서 받은 적이 있으면 그 출발지, 없으면 설정한 공인 주소:51820 (IPsec 은 IKE 로 정한 상대) */
  target(): { ip: Ip; port: number } | undefined {
    if (this.mode === "ipsec" && this.sa.state === "up" && this.sa.peer) return this.sa.peer;
    if (this.mode === "wireguard" && this.endpoint) return this.endpoint;
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

function hex(n: number): string {
  return n.toString(16).padStart(8, "0");
}

/** 결정론적 SPI: 두 주소와 시도 횟수로 만든다 (실제로는 난수) */
function spiOf(a: Ip, b: Ip, n: number): number {
  let h = 0x811c9dc5;
  for (const ch of `${a}>${b}#${n}`) h = Math.imul(h ^ ch.charCodeAt(0), 0x01000193) >>> 0;
  return h >>> 0 || 1;
}
