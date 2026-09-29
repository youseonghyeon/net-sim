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
// DPD (Dead Peer Detection): 조용한 터널은 상대가 죽거나 경로가 끊겨도 모른다. 빈 INFORMATIONAL 요청으로 상대가 살아 있고 이 SA 를
//   아는지 확인한다 — 응답이 없으면 SA 를 지우고(다음 패킷에 재협상), 상대가 모르면 INVALID_SPI 로 알려 SA 를 버리게 한다.
//   주기 타이머가 없는 시계 구조라 사용자 동작(vpn-dpd)으로만 보낸다. WireGuard 식은 대상이 아니다 (핸드셰이크·SA 가 없다)
// 재협상(rekey)·암호 방식 목록은 생략한다.
import { sameSubnet, type Ip } from "../addr";
import { IKE_PORT, NAT_T_PORT, VPN_PORT, type IkeMessage, type Ipv4Packet } from "../packet";
import { IKE_RETRANSMITS, IkeRetransmit, espPacket, hex, ikePacket, natAtInitiator, natAtResponder, spiOf } from "./ike";
import type { NodeContext } from "./node";

export type VpnMode = "wireguard" | "ipsec";
export const VPN_MODE_LABEL: Record<VpnMode, string> = { wireguard: "WireGuard", ipsec: "IPsec" };
export { IKE_RETRANSMITS, IKE_TIMEOUT } from "./ike";
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
  /** 시작한 쪽의 IKE 요청 재전송 */
  private readonly ike: IkeRetransmit;
  private attempts = 0;
  /** DPD 요청을 보내고 응답을 기다리는 중 */
  private dpdPending = false;

  constructor(private readonly io?: VpnIo) {
    this.ike = new IkeRetransmit(IKE_TIMER_TAG, (pkt, ctx, frameId) => this.io?.send(pkt, ctx, frameId));
  }

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
    this.ike.clear();
    this.pending = undefined;
    this.queue = [];
    this.dpdPending = false;
  }

  /** 표시용: IPsec 터널 상태 한 줄 */
  saSummary(): string | undefined {
    if (this.mode !== "ipsec") return undefined;
    const s = this.sa;
    if (s.state === "up") return `터널 수립됨 · ${s.natT ? "NAT-T (UDP 4500)" : "ESP"} · 상대 ${s.peer?.ip ?? "?"} · SPI 0x${hex(s.spi)}${this.dpdPending ? " · DPD 확인 중" : ""}`;
    if (s.state === "init" || s.state === "auth") return `IKE 협상 중 (${s.state === "init" ? "IKE_SA_INIT" : "IKE_AUTH"})`;
    return "터널 없음 (첫 패킷이 오면 IKE 로 맺음)";
  }

  get ipsecUp(): boolean {
    return this.sa.state === "up";
  }

  /** DPD 응답을 기다리는 중인지 (UI 표시용) */
  get dpdWaiting(): boolean {
    return this.dpdPending;
  }

  /**
   * 사용자의 "상대 확인 (DPD)": 지금 SA 의 경로로(NAT-T 면 UDP 4500) 빈 INFORMATIONAL 을 보내 상대가 살아 있고 이 SA 를 아는지 확인.
   * 응답이 오면 터널 유지, 재전송 뒤에도 없으면 SA 삭제(다음 패킷에 재협상), 상대가 모르면(INVALID_SPI) SA 를 버린다
   */
  dpd(ctx: NodeContext): void {
    if (!this.config.enabled || this.mode !== "ipsec") {
      ctx.trace("vpn.dpd", "L4", `DPD 는 IPsec VPN 에서만 → 보내지 않음 (WireGuard 식은 SA 가 없음)`, { dpd: "none" });
      return;
    }
    const peer = this.sa.peer;
    if (this.sa.state !== "up" || !peer) {
      ctx.trace("vpn.dpd", "L4", `IPsec: 연결된 터널(SA) 없음 → DPD 를 보내지 않음 (터널로 갈 첫 패킷이 오면 IKE 로 맺음)`, { dpd: "none" });
      return;
    }
    if (this.dpdPending) {
      ctx.trace("vpn.dpd", "L4", `IPsec: 이미 DPD 응답을 기다리는 중 → 다시 보내지 않음`, { dpd: "busy" });
      return;
    }
    const src = this.io?.source(peer.ip);
    if (!src) {
      ctx.trace("vpn.drop", "L3", `IPsec DPD: 상대 ${peer.ip} 로 가는 바깥 경로가 없어 보낼 수 없음 (디폴트 라우트를 확인)`, { dst: peer.ip });
      return;
    }
    this.dpdPending = true;
    const port = this.sa.natT ? NAT_T_PORT : IKE_PORT;
    ctx.trace("vpn.dpd", "L4", `IPsec DPD: 상대 ${peer.ip} 에 빈 INFORMATIONAL 요청 (SPI 0x${hex(this.sa.spi)}, UDP ${port}${this.sa.natT ? " NAT-T" : ""}) → 상대가 살아 있고 이 터널을 아는지 확인`, { peer: peer.ip, spi: this.sa.spi, dpd: "request" });
    this.ike.request(src, peer.ip, port, { kind: "ike", exchange: "INFORMATIONAL", response: false, spi: this.sa.spi, dpd: true }, ctx, undefined, peer.port);
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
    this.sa = { state: "init", spi: spiOf(`${src}>${peer}#${this.attempts}`), natT: false, seq: 0 };
    ctx.trace(
      "vpn.ike",
      "L4",
      `IPsec: ${peer} 와 터널이 없음 → IKE_SA_INIT 요청 (UDP ${IKE_PORT}: 암호 방식 제안 + NAT 감지용으로 내 주소 ${src}·상대 주소 ${peer} 를 적어 보냄). 터널이 맺어질 때까지 패킷은 기다림`,
      { peer, spi: this.sa.spi },
      frameId,
    );
    this.ike.request(src, peer, IKE_PORT, { kind: "ike", exchange: "IKE_SA_INIT", response: false, spi: this.sa.spi, natSrc: src, natDst: peer }, ctx, frameId);
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const current = this.sa.state === "init" ? "IKE_SA_INIT" : this.sa.state === "auth" ? "IKE_AUTH" : this.sa.state === "up" && this.dpdPending ? "INFORMATIONAL" : undefined;
    const { verdict, step, tries } = this.ike.check(data, this.sa.spi, current);
    if (verdict === "ignore") return;
    const dpd = step === "INFORMATIONAL";
    if (verdict === "retransmit") {
      ctx.trace(dpd ? "vpn.dpd" : "vpn.ike", "L4", `IPsec${dpd ? " DPD" : ""}: ${dpd ? "INFORMATIONAL" : step} 응답 없음 → 같은 요청을 다시 보냄 (재전송 ${tries + 1}/${IKE_RETRANSMITS})`, { retransmit: tries + 1, step });
      this.ike.resend(ctx);
      return;
    }
    if (dpd) {
      // 상대가 죽었거나 경로가 끊김: SA 를 지운다 (터널로 갈 다음 패킷이 오면 다시 협상)
      const peer = this.sa.peer?.ip;
      this.sa = { state: "idle", spi: 0, natT: false, seq: 0 };
      this.ike.clear();
      this.dpdPending = false;
      ctx.trace("vpn.drop", "L4", `IPsec DPD: 상대 ${peer} 응답 없음 (재전송 ${IKE_RETRANSMITS}번 뒤 timeout) → 상대가 죽었거나 경로가 끊긴 것으로 보고 SA 삭제. 터널로 갈 다음 패킷이 오면 다시 협상`, { dpd: "dead", peer });
      return;
    }
    this.sa = { state: "idle", spi: 0, natT: false, seq: 0 };
    this.ike.clear();
    this.failQueue(ctx, `${step} 응답 없음 (재전송 ${IKE_RETRANSMITS}번 뒤 timeout) — 상대가 IPsec VPN 을 켰는지, UDP ${IKE_PORT}/${NAT_T_PORT} 가 막히지 않았는지 확인. 다음 패킷이 오면 다시 협상`);
  }

  private failQueue(ctx: NodeContext, why: string, frameId?: number): void {
    const n = this.queue.length;
    this.queue = [];
    ctx.trace("vpn.drop", "L3", `IPsec 터널을 맺지 못함: ${why}${n ? ` → 기다리던 패킷 ${n}개 드롭` : ""}`, { dropped: n }, frameId);
  }

  private sendIke(src: Ip, dst: Ip, srcPort: number, dstPort: number, m: IkeMessage, ctx: NodeContext, frameId?: number): void {
    this.io?.send(ikePacket(src, dst, srcPort, dstPort, m), ctx, frameId);
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
    const outer = espPacket(src, peer, this.sa.natT, esp);
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
    if (!this.config.enabled || this.mode !== "ipsec" || m.ra) return false; // 원격 접속 협상은 원격 접속 서버가
    const me = outer.dst;
    if (m.exchange === "INFORMATIONAL" && m.dpd && !m.response) {
      // DPD 요청: 이 SA 를 알면 빈 응답, 모르면(설정 변경·재시작으로 사라짐) INVALID_SPI 로 알려 상대가 옛 SA 를 버리게.
      // 양쪽이 동시에 협상을 시작하면 두 끝의 SPI 가 엇갈린 채 둘 다 up 이 된다(사이트 간 ESP 는 상대당 SA 하나라 SPI 를 보지 않는다) —
      // 그래서 SA 의 상대 주소에서 온 것도 이 터널로 본다
      if (this.sa.state === "up" && (m.spi === this.sa.spi || outer.src === this.sa.peer?.ip)) {
        ctx.trace("vpn.dpd", "L4", `IPsec DPD: ${outer.src} 의 빈 INFORMATIONAL 요청 → 이 상대와 맺은 터널이 있음 → 빈 응답으로 살아 있다고 알림`, { from: outer.src, dpd: "reply" }, frameId);
        this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "INFORMATIONAL", response: true, spi: m.spi, dpd: true }, ctx, frameId);
      } else {
        ctx.trace("vpn.drop", "L4", `IPsec DPD: ${outer.src} 가 이쪽에 없는 터널(SPI 0x${hex(m.spi)})을 확인함 (설정 변경·재시작으로 SA 가 사라짐) → INVALID_SPI 로 알려 상대가 옛 SA 를 버리게 함`, { from: outer.src, dpd: "unknown" }, frameId);
        this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "INFORMATIONAL", response: true, spi: m.spi, error: "INVALID_SPI", dpd: true }, ctx, frameId);
      }
      return true;
    }
    if (m.exchange === "INFORMATIONAL" && m.response) {
      if (!this.dpdPending || this.sa.state !== "up" || m.spi !== this.sa.spi) return true; // 이미 끝난 확인
      this.dpdPending = false;
      this.ike.clear();
      if (m.error === "INVALID_SPI") {
        this.sa = { state: "idle", spi: 0, natT: false, seq: 0 };
        ctx.trace("vpn.drop", "L4", `IPsec DPD: 상대 ${outer.src} 가 이 터널을 모른다고 알림 (INVALID_SPI — 상대의 설정 변경·재시작) → SA 삭제. 터널로 갈 다음 패킷이 오면 다시 협상`, { from: outer.src, dpd: "invalid" }, frameId);
        return true;
      }
      ctx.trace("vpn.dpd", "L4", `IPsec DPD: 상대 ${outer.src} 가 빈 응답 → 살아 있고 이 터널을 앎 → 터널 유지`, { from: outer.src, dpd: "alive" }, frameId);
      return true;
    }
    if (m.exchange === "INFORMATIONAL") return true; // 그 밖의 알림은 쓰지 않는다
    if (m.exchange === "IKE_SA_INIT" && !m.response) {
      // 응답자: 적혀 온 주소와 실제 헤더가 다르면 중간 어딘가에 NAT 가 있다 (보낸 쪽 앞 또는 내 앞)
      // 상대가 적은 자기 주소가 실제 출발지와 다르면 상대 앞에 NAT, 상대가 적은 내 주소가 실제 목적지와 다르면 내 앞에 NAT
      const { remoteNat, localNat, nat } = natAtResponder(m, outer.src, me);
      this.pending = { spi: m.spi, nat };
      const where = [remoteNat ? "상대 앞" : "", localNat ? "내 앞" : ""].filter(Boolean).join("·");
      ctx.trace(
        "vpn.ike",
        "L4",
        `IPsec: ${outer.src} 에서 IKE_SA_INIT 요청 → 응답. NAT 감지: ${nat ? `${where}에 있음 (적혀 온 주소 ${m.natSrc} → ${m.natDst} 와 실제 헤더 ${outer.src} → ${me} 가 다름) → 이후는 UDP 4500 (NAT-T)` : "없음 → 데이터는 ESP 로"}`,
        { from: outer.src, nat, remoteNat, localNat },
        frameId,
      );
      // 응답에도 내 쪽에서 본 주소를 적어 보낸다 (상대도 NAT 위치를 안다)
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "IKE_SA_INIT", response: true, spi: m.spi, nat, natSrc: me, natDst: outer.src }, ctx, frameId);
      return true;
    }
    if (m.exchange === "IKE_SA_INIT" && m.response) {
      if (this.sa.state !== "init" || m.spi !== this.sa.spi) return true; // 이미 끝났거나 지난 협상
      // 상대가 본 내 주소가 내 주소와 다르면 내 앞에 NAT, 상대가 적은 자기 주소가 실제 출발지와 다르면 상대 앞에 NAT
      const { localNat, remoteNat, natT } = natAtInitiator(m, outer.src, me);
      this.sa = { ...this.sa, state: "auth", natT };
      const port = natT ? NAT_T_PORT : IKE_PORT;
      ctx.trace(
        "vpn.ike",
        "L4",
        `IPsec: IKE_SA_INIT 응답 수신 (NAT ${natT ? `${[localNat ? "내 앞" : "", remoteNat ? "상대 앞" : ""].filter(Boolean).join("·") || ""}에 있음 → 여기부터 UDP 4500 (NAT-T)` : "없음"}) → IKE_AUTH 요청: 사전 공유 키(PSK)로 만든 인증 값을 보냄`,
        { from: outer.src, natT, localNat, remoteNat },
        frameId,
      );
      this.ike.request(me, this.config.peer ?? outer.src, port, { kind: "ike", exchange: "IKE_AUTH", response: false, spi: m.spi, auth: this.config.psk ?? "" }, ctx, frameId);
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
      this.ike.clear();
      this.failQueue(ctx, `상대 ${outer.src} 가 ${m.error} 로 거절 — 사전 공유 키(PSK)가 다름. 양쪽 PSK 를 똑같이 맞추세요`, frameId);
      return true;
    }
    this.ike.clear();
    this.establish(m.spi, this.sa.natT, { ip: outer.src, port: srcPort }, "시작한 쪽", ctx, frameId);
    this.flush(ctx);
    return true;
  }

  private establish(spi: number, natT: boolean, peer: { ip: Ip; port: number }, role: string, ctx: NodeContext, frameId?: number): void {
    this.sa = { state: "up", spi, natT, peer, seq: 0 };
    this.dpdPending = false; // 옛 SA 에 걸어 둔 DPD 는 끝난 것으로
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

  /**
   * SA 없이 ESP 가 옴: 상대는 옛 터널을 쓰고 있다 (이쪽 설정이 바뀌었거나 껐다 켜서 터널이 내려감).
   * 실제로는 INVALID_SPI 알림으로 알리지만, 여기서는 이쪽이 곧바로 새로 협상해 상대의 옛 터널을 갈아 끼운다
   */
  onOrphanEsp(from: Ip, ctx: NodeContext, frameId?: number): void {
    if (!this.config.enabled || this.mode !== "ipsec" || this.sa.state !== "idle") return;
    ctx.trace("vpn.ike", "L4", `IPsec: ${from} 이 이쪽에 없는 터널(SA)로 ESP 를 보냄 — 상대는 옛 터널을 쓰는 중 → 새로 협상해 갈아 끼움`, { from }, frameId);
    this.startIke(ctx, frameId);
  }

  /**
   * 인증된 ESP 의 바깥 출발지가 SA 의 상대와 다름: NAT 매핑이나 상대 공인 주소가 바뀐 것 → 이후 그 주소로 답한다
   * (NAT-T 의 주소 갱신, RFC 7296 2.23)
   */
  followPeer(src: Ip, srcPort: number | undefined, ctx: NodeContext, frameId?: number): void {
    const p = this.sa.peer;
    if (this.sa.state !== "up" || !p) return;
    const port = this.sa.natT ? (srcPort ?? p.port) : p.port;
    if (p.ip === src && p.port === port) return;
    this.sa = { ...this.sa, peer: { ip: src, port } };
    ctx.trace("vpn.ike", "L4", `IPsec: 상대의 바깥 주소가 ${p.ip}:${p.port} → ${src}:${port} 로 바뀜 (NAT 매핑·공인 주소 변경) → 이제 그쪽으로 답함`, { from: src }, frameId);
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
