// 공유기 VPN (ipTIME 식 L2TP/IPsec): 집 공유기가 VPN 서버가 되어, 출장지 노트북이 집 LAN 의 한 장치처럼 붙는다.
// 두 겹 포장이다:
//   바깥 겹 IPsec (IKEv1 축소판): Main Mode 로 NAT 감지·사전 공유 키(PSK) 인증 → Quick Mode 로 UDP 1701 을 보호할 ESP SA (전송 모드).
//     NAT 가 있으면(호텔·카페 와이파이) UDP 4500 에 싣는다 (NAT-T). 실제 Main Mode 의 6개 메시지는 두 번의 요청·응답으로 줄였다
//   안쪽 겹 L2TP (UDP 1701) + PPP: 터널(SCCRQ/SCCRP)·세션(ICRQ/ICRP)을 열고, PPP 로 계정을 확인하고(CHAP — MS-CHAPv2 축소판)
//     주소를 받는다(IPCP). 그 뒤로는 IP 패킷을 PPP 에 실어 보낸다
// 회사 원격 접속 VPN(ravpn.ts, IKEv2)과 다른 점:
//   - 서버가 공유기에 내장 (전용 장비가 아니다), 설정은 PSK·계정·할당 IP 세 칸 (ipTIME 설정 화면)
//   - 노트북은 공유기 LAN 대역의 주소를 받는다 (예: 192.168.0.50) — 공유기가 그 주소의 ARP 에 대신 답해(프록시 ARP) 집 장치들이 LAN 안의 기기처럼 본다
//   - 모든 트래픽이 집으로 간다 (full tunnel — Windows·iOS 의 기본값) → 해외에서도 집 공유기의 공인 주소(한국 IP)로 인터넷에 나간다
// 재협상·LCP 협상·L2TP 의 신뢰성 있는 제어 채널(Ns/Nr)·Hello 는 생략. DPD 는 없다 (L2TP/IPsec 은 보통 쓰지 않음)
import { isMcastIp } from "../packet";
import { intToIp, ipToInt, prefixToMask, type Ip } from "../addr";
import { IKE_PORT, L2TP_PORT, NAT_T_PORT, l2tpPartLabel, type EspPacket, type IkeMessage, type Ipv4Packet, type L2tpPacket, type PppFrame } from "../packet";
import { IKE_RETRANSMITS, IKE_TIMEOUT, IkeRetransmit, espPacket, hex, ikePacket, natAtInitiator, natAtResponder, spiOf } from "./ike";
import type { NodeContext } from "./node";
import { RA_TIMER_TAG, type RaClientConfig, type RaClientState, type RaIo } from "./ravpn";

export interface L2tpServerConfig {
  enabled: boolean;
  /** 사전 공유 키 (IPsec) */
  psk: string;
  /** 할당 IP 범위 (공유기 LAN 대역에서 DHCP 가 쓰지 않는 주소) */
  poolStart: Ip;
  poolEnd: Ip;
  /** 접속 계정 (PPP CHAP) */
  users: { name: string; password: string }[];
}

export const DEFAULT_L2TP_SERVER: L2tpServerConfig = { enabled: false, psk: "", poolStart: "192.168.0.50", poolEnd: "192.168.0.59", users: [] };

/** 서버가 공유기에게서 빌리는 것 */
export interface L2tpServerHost {
  /** 바깥 패킷을 WAN 으로 (공유기 자신의 패킷이라 NAT 하지 않음) */
  send(outer: Ipv4Packet, ctx: NodeContext, frameId?: number): void;
  /** IPCP 로 알릴 DNS (공유기 LAN 주소 — DNS 포워더) */
  dns(): Ip | undefined;
  /** 공유기 LAN 대역 (할당 주소가 그 안이어야 집 장치들이 LAN 기기처럼 본다) */
  lan(): { ip: Ip; prefix: number } | undefined;
  /** 공유기 WAN 주소 (서버가 먼저 보내는 알림 — 설정 변경으로 끊을 때의 StopCCN) */
  wanIp(): Ip | undefined;
}

/** 붙어 있는(또는 붙는 중인) 클라이언트 하나: ESP SA 와 그 위의 L2TP 터널·세션·PPP 상태 */
interface ServerSa {
  spi: number;
  cid: string;
  peer: { ip: Ip; port: number };
  natT: boolean;
  seq: number;
  tunnelId?: number;
  sessionId?: number;
  /** CHAP 으로 확인한 사용자 */
  user?: string;
  /** IPCP 로 준 주소 */
  vip?: Ip;
  /** 거절로 끝남 (CHAP Failure·IPCP Nak): 표에서 빠지고, 같은 요청이 다시 오면(거절이 사라짐) 이 거절을 다시 보낸다 */
  failed?: PppFrame;
}

const CONTROL_LABEL: Record<NonNullable<L2tpPacket["control"]>, string> = {
  SCCRQ: "터널 열기 요청 (SCCRQ)",
  SCCRP: "터널 열기 응답 (SCCRP)",
  ICRQ: "세션 열기 요청 (ICRQ)",
  ICRP: "세션 열기 응답 (ICRP)",
  CDN: "세션 끊기 (CDN)",
  StopCCN: "터널 끊기 (StopCCN)",
};

// ---------- 서버 (공유기) ----------

export class L2tpServer {
  config: L2tpServerConfig = { ...DEFAULT_L2TP_SERVER, users: [] };
  /** SPI → 클라이언트 */
  private readonly sas = new Map<number, ServerSa>();
  /** 할당 주소 → 클라이언트 (PPP 까지 끝난 것) */
  private readonly byVip = new Map<Ip, ServerSa>();
  /** Main Mode 1 을 받고 PSK 인증(Main Mode 2)을 기다리는 협상 ("바깥 주소:spi" → NAT 감지 결과) */
  private readonly mm = new Map<string, boolean>();
  /** PSK 를 확인하고 Quick Mode 를 기다리는 협상 ("바깥 주소:spi" → NAT 감지 결과) */
  private readonly authed = new Map<string, boolean>();
  /** 클라이언트 식별 → 지난번 준 주소 (다시 붙으면 같은 주소) */
  private readonly leases = new Map<string, Ip>();
  private nextTunnel = 1;

  constructor(private readonly host: L2tpServerHost) {}

  setConfig(cfg: L2tpServerConfig, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.config)) return;
    // 꺼진 채 칸만 바뀜: 조용히 (켤 때 알린다)
    if (!cfg.enabled && !this.config.enabled) {
      this.config = { ...cfg, users: cfg.users.map((u) => ({ ...u })) };
      return;
    }
    // 계정만 바뀜: 붙어 있는 세션은 그대로 (인증은 접속할 때 한 번 — 지운 계정은 다시 붙을 때 막힌다)
    const rest = (c: L2tpServerConfig) => JSON.stringify({ ...c, users: undefined });
    if (rest(cfg) === rest(this.config)) {
      this.config = { ...cfg, users: cfg.users.map((u) => ({ ...u })) };
      if (cfg.enabled) ctx.trace("vpn.config", "sys", `VPN 서버 계정 변경: ${cfg.users.map((u) => u.name).join(", ") || "없음 (아무도 접속할 수 없음)"} — 붙어 있는 세션은 끊지 않음`, { users: cfg.users.map((u) => u.name) });
      return;
    }
    // 붙어 있던(L2TP 터널까지 연) 클라이언트에게 끊는다고 알린다 (실제는 xl2tpd·charon 재시작) — 말없이 지우면 노트북은 계속 "연결됨"
    this.hangUpAll(cfg.enabled ? "VPN 서버 설정이 바뀜" : "VPN 서버를 끔", ctx);
    this.config = { ...cfg, users: cfg.users.map((u) => ({ ...u })) };
    this.sas.clear();
    this.byVip.clear();
    this.mm.clear();
    this.authed.clear();
    this.leases.clear();
    ctx.trace(
      "vpn.config",
      "sys",
      cfg.enabled
        ? `VPN 서버 켜짐 (L2TP/IPsec): 사전 공유 키로 IPsec 을 맺고, 계정(${cfg.users.map((u) => u.name).join(", ") || "없음"})을 확인한 클라이언트에게 ${cfg.poolStart} ~ ${cfg.poolEnd} 에서 주소를 줌 — 그 클라이언트는 집 LAN 안의 기기처럼 보인다`
        : "VPN 서버 꺼짐",
      { enabled: cfg.enabled, poolStart: cfg.poolStart, poolEnd: cfg.poolEnd, users: cfg.users.map((u) => u.name) },
    );
  }

  private hangUpAll(why: string, ctx: NodeContext): void {
    const me = this.host.wanIp();
    const open = [...this.sas.values()].filter((s) => s.tunnelId !== undefined && !s.failed);
    if (!me || open.length === 0) return;
    ctx.trace("vpn.drop", "L4", `VPN 서버: ${why} → L2TP 터널을 연 ${open.length}개 연결에 터널 끊기(StopCCN)를 보내고 세션을 비움 (노트북은 끊김으로 바뀌어 다시 연결해야 함)`, { l2tp: "StopCCN", count: open.length });
    for (const s of open) this.sendL2tp(s, me, { kind: "l2tp", tunnelId: s.tunnelId!, sessionId: s.sessionId ?? 0, control: "StopCCN" }, ctx);
  }

  /** PPP 까지 끝나 주소를 받은 클라이언트 */
  get connected(): { user: string; vip: Ip; peer: Ip; natT: boolean }[] {
    return [...this.byVip.values()].map((s) => ({ user: s.user ?? "", vip: s.vip!, peer: s.peer.ip, natT: s.natT }));
  }

  /** 이 주소가 붙어 있는 VPN 클라이언트의 주소인지 (프록시 ARP·라우팅) */
  owns(ip: Ip): boolean {
    return this.config.enabled && this.byVip.has(ip);
  }

  /** 이 주소가 할당 IP 범위 안인지 */
  inPool(ip: Ip): boolean {
    try {
      const n = ipToInt(ip);
      return this.config.enabled && n >= ipToInt(this.config.poolStart) && n <= ipToInt(this.config.poolEnd);
    } catch {
      return false;
    }
  }

  private allocate(cid: string): Ip | undefined {
    const used = new Set([...this.byVip.values()].filter((s) => s.cid !== cid).map((s) => s.vip!));
    const prev = this.leases.get(cid);
    if (prev && !used.has(prev) && this.inPool(prev)) return prev;
    let a: number;
    let b: number;
    try {
      a = ipToInt(this.config.poolStart);
      b = ipToInt(this.config.poolEnd);
    } catch {
      return undefined;
    }
    // LAN 대역 밖은 줄 수 없다 (집 장치가 LAN 기기로 보지 못함) — 범위를 LAN 의 호스트 주소(네트워크·브로드캐스트 주소 제외)로 좁힌다.
    // 한 칸씩 건너뛰며 훑으면 시작을 잘못 넣었을 때(10.0.0.1 ~ 192.168.0.59) 수십억 번 돈다
    const lan = this.host.lan();
    let lo = a;
    let hi = b;
    if (lan) {
      const mask = prefixToMask(lan.prefix);
      const net = (ipToInt(lan.ip) & mask) >>> 0;
      const bcast = (net | ~mask) >>> 0;
      lo = Math.max(a, net + 1);
      hi = Math.min(b, bcast - 1);
    }
    for (let n = lo; n <= hi; n++) {
      const ip = intToIp(n);
      if (ip === lan?.ip || used.has(ip) || [...this.leases.entries()].some(([k, v]) => v === ip && k !== cid)) continue;
      return ip;
    }
    // 빈 주소가 없으면 지금 붙어 있지 않은 클라이언트의 지난 임대를 넘긴다
    for (const [k, v] of this.leases) {
      if (k === cid || used.has(v)) continue;
      this.leases.delete(k);
      return v;
    }
    return undefined;
  }

  private sendIke(me: Ip, to: Ip, srcPort: number, dstPort: number, m: IkeMessage, ctx: NodeContext, frameId?: number): void {
    this.host.send(ikePacket(me, to, srcPort, dstPort, m), ctx, frameId);
  }

  /** IKEv1 (L2TP/IPsec) 요청. 처리했으면 true */
  handleIke(outer: Ipv4Packet, srcPort: number, dstPort: number, m: IkeMessage, ctx: NodeContext, frameId?: number): boolean {
    if (!this.config.enabled || !m.l2tp || m.response) return false;
    const me = outer.dst;
    const key = `${outer.src}:${m.spi}`;
    if (m.exchange === "MAIN_MODE" && m.auth === undefined) {
      const { nat, remoteNat, localNat } = natAtResponder(m, outer.src, me);
      this.mm.set(key, nat);
      const where = remoteNat && localNat ? "클라이언트와 이 공유기 모두 NAT 뒤" : remoteNat ? "클라이언트가 공유기 뒤" : "이 공유기 앞에 NAT — 공유기 뒤 공유기";
      ctx.trace("vpn.ike", "L4", `VPN 서버: ${outer.src} 의 IKE Main Mode (암호 방식·키 교환·NAT 감지) → 응답. NAT ${nat ? `있음 (${where} — 이후 UDP 4500, NAT-T)` : "없음"}`, { from: outer.src, nat, remoteNat, localNat, l2tp: true }, frameId);
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "MAIN_MODE", response: true, spi: m.spi, nat, natSrc: me, natDst: outer.src, l2tp: true }, ctx, frameId);
      return true;
    }
    if (m.exchange === "MAIN_MODE") {
      // PSK 인증 (Main Mode 의 ID·HASH). 이미 확인한 협상이 다시 오면(응답이 사라짐) 같은 응답을 다시 보낸다
      const nat = this.mm.get(key) ?? this.authed.get(key);
      if (nat === undefined) {
        ctx.trace("vpn.drop", "L4", `VPN 서버: Main Mode 첫 교환 없이 온 인증 (from ${outer.src}) → 무시`, { from: outer.src }, frameId);
        return true;
      }
      if ((m.auth ?? "") !== this.config.psk) {
        // 협상 기록은 남겨 둔다: 이 거절이 사라져 같은 인증이 다시 오면 같은 거절을 다시 보내야 노트북이 이유("사전 공유 키가 다름")를 안다
        ctx.trace("vpn.drop", "L4", `VPN 서버: ${outer.src} 의 IPsec 인증 실패 — 사전 공유 키가 다름 → AUTHENTICATION-FAILED`, { from: outer.src, l2tp: true }, frameId);
        this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "MAIN_MODE", response: true, spi: m.spi, error: "AUTHENTICATION_FAILED", l2tp: true }, ctx, frameId);
        return true;
      }
      this.mm.delete(key);
      this.authed.set(key, nat);
      ctx.trace("vpn.ike", "L4", `VPN 서버: ${outer.src} 의 사전 공유 키 확인 (Main Mode 끝 — IPsec 1단계 SA) → Quick Mode 를 기다림`, { from: outer.src, l2tp: true }, frameId);
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "MAIN_MODE", response: true, spi: m.spi, l2tp: true }, ctx, frameId);
      return true;
    }
    if (m.exchange === "QUICK_MODE") {
      const nat = this.authed.get(key);
      const existing = this.sas.get(m.spi);
      if (nat === undefined && !existing) {
        ctx.trace("vpn.drop", "L4", `VPN 서버: PSK 인증 없이 온 Quick Mode (from ${outer.src}) → 무시`, { from: outer.src }, frameId);
        return true;
      }
      if (!existing) {
        // 같은 클라이언트의 옛 SA (다시 접속) 는 치운다
        for (const s of [...this.sas.values()]) if (s.cid === (m.cid ?? outer.src)) this.drop(s);
        this.sas.set(m.spi, { spi: m.spi, cid: m.cid ?? outer.src, peer: { ip: outer.src, port: srcPort }, natT: nat!, seq: 0 });
        ctx.trace(
          "vpn.ike",
          "L4",
          `VPN 서버: ${outer.src} 의 Quick Mode → UDP 1701 (L2TP) 을 보호할 ESP SA 를 만듦 (전송 모드${nat ? ", UDP 4500 안 — NAT-T" : ""}) — SPI 0x${hex(m.spi)}. 이제 L2TP 를 기다림`,
          { from: outer.src, spi: m.spi, natT: nat, l2tp: true },
          frameId,
        );
      }
      this.authed.delete(key);
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "QUICK_MODE", response: true, spi: m.spi, l2tp: true }, ctx, frameId);
      return true;
    }
    if (m.exchange === "INFORMATIONAL") {
      // 클라이언트가 IPsec SA 를 지움 (Delete)
      const s = this.sas.get(m.spi);
      if (s) {
        this.drop(s);
        ctx.trace("vpn.drop", "L4", `VPN 서버: ${outer.src} 가 IPsec SA 를 지움 (Delete)${s.vip ? ` → ${s.user ?? "?"} 의 주소 ${s.vip} 를 돌려받음` : ""}`, { from: outer.src, l2tp: true }, frameId);
      }
      return true;
    }
    return false;
  }

  private drop(s: ServerSa): void {
    this.sas.delete(s.spi);
    if (s.vip && this.byVip.get(s.vip) === s) this.byVip.delete(s.vip);
  }

  /**
   * 받은 ESP: 내 SA 것이면 풀어 안쪽 L2TP 를 처리한다. 클라이언트가 보낸 IP 패킷(PPP 데이터)이면 그 패킷을 돌려주고(공유기가 LAN·인터넷으로),
   * 제어(L2TP·PPP 협상)면 여기서 답하고 null, 내 SA 것이 아니면 undefined
   */
  receive(outer: Ipv4Packet, srcPort: number | undefined, esp: EspPacket, ctx: NodeContext, frameId?: number): Ipv4Packet | null | undefined {
    if (!this.config.enabled) return undefined;
    const s = this.sas.get(esp.spi);
    if (!s) return this.orphan(outer, srcPort, esp, ctx, frameId);
    // 클라이언트 쪽 NAT 매핑이 바뀌었으면 그쪽으로 답한다
    s.peer = { ip: outer.src, port: s.natT ? (srcPort ?? s.peer.port) : s.peer.port };
    const u = esp.inner.payload;
    if (s.failed) {
      // 거절한 요청이 다시 옴 (거절이 사라짐): 같은 거절을 다시 — 그래야 노트북이 timeout 이 아니라 진짜 이유로 끝난다
      const p0 = u.kind === "udp" && u.payload.kind === "l2tp" ? u.payload.ppp : undefined;
      if (p0 && (p0.proto === "chap" || p0.proto === "ipcp")) {
        ctx.trace("vpn.drop", "L4", `VPN 서버: 이미 거절한 ${p0.proto === "chap" ? "계정 인증 (CHAP)" : "주소 요청 (IPCP)"} 이 다시 옴 (지난 거절이 사라진 것) → 같은 거절을 다시 보냄`, { from: outer.src, resent: true }, frameId);
        this.sendL2tp(s, outer.dst, { kind: "l2tp", tunnelId: s.tunnelId ?? 0, sessionId: s.sessionId ?? 0, ppp: s.failed }, ctx, frameId);
      }
      return null;
    }
    if (u.kind !== "udp" || u.payload.kind !== "l2tp" || u.dstPort !== L2TP_PORT) {
      ctx.trace("vpn.drop", "L3", `VPN 서버: ESP 안이 L2TP(UDP 1701)가 아님 → 드롭 (이 SA 는 L2TP 만 보호한다)`, { from: outer.src }, frameId);
      return null;
    }
    const l = u.payload;
    const me = outer.dst;
    const who = s.user ? `${s.user} (${s.vip ?? outer.src})` : outer.src;
    if (l.control === "SCCRQ") {
      s.tunnelId ??= this.nextTunnel++;
      ctx.trace("vpn.ike", "L4", `VPN 서버: ${outer.src} 의 L2TP 터널 열기 요청 (SCCRQ) → 터널 ${s.tunnelId} 로 응답 (SCCRP)`, { from: outer.src, l2tp: "SCCRQ" }, frameId);
      this.sendL2tp(s, me, { kind: "l2tp", tunnelId: s.tunnelId, sessionId: 0, control: "SCCRP" }, ctx, frameId);
      return null;
    }
    if (l.control === "ICRQ") {
      s.sessionId ??= 1;
      ctx.trace("vpn.ike", "L4", `VPN 서버: ${outer.src} 의 L2TP 세션 열기 요청 (ICRQ) → 세션 ${s.sessionId} (ICRP) — 이제 이 세션 위에서 PPP`, { from: outer.src, l2tp: "ICRQ" }, frameId);
      this.sendL2tp(s, me, { kind: "l2tp", tunnelId: s.tunnelId ?? 0, sessionId: s.sessionId, control: "ICRP" }, ctx, frameId);
      return null;
    }
    if (l.control === "CDN" || l.control === "StopCCN") {
      const vip = s.vip;
      this.drop(s);
      ctx.trace("vpn.drop", "L4", `VPN 서버: ${who} 가 연결을 끊음 (${CONTROL_LABEL[l.control]})${vip ? ` → 주소 ${vip} 를 돌려받음` : ""}`, { from: outer.src, l2tp: l.control }, frameId);
      return null;
    }
    const p = l.ppp;
    if (!p) return null;
    const reply = (ppp: NonNullable<L2tpPacket["ppp"]>) => this.sendL2tp(s, me, { kind: "l2tp", tunnelId: s.tunnelId ?? 0, sessionId: s.sessionId ?? 0, ppp }, ctx, frameId);
    if (p.proto === "lcp") {
      ctx.trace("vpn.eap", "L4", `VPN 서버: PPP 링크 설정 (LCP) → 계정 인증을 요구 — CHAP(MS-CHAPv2) challenge 를 보냄`, { from: outer.src, ppp: "challenge" }, frameId);
      reply({ proto: "chap", code: "challenge" });
      return null;
    }
    if (p.proto === "chap" && p.code === "response") {
      const u2 = this.config.users.find((x) => x.name === p.user);
      if (!u2 || u2.password !== (p.secret ?? "")) {
        const why = !p.user ? "사용자 이름이 비어 있음" : !u2 ? `계정 ${p.user} 가 목록에 없음` : `${p.user} 의 비밀번호가 다름`;
        ctx.trace("vpn.drop", "L4", `VPN 서버: ${outer.src} 의 PPP 계정 인증 실패 (CHAP) — ${why} → CHAP Failure, 이 연결을 닫음`, { from: outer.src, user: p.user, ppp: "failure" }, frameId);
        s.failed = { proto: "chap", code: "failure" };
        reply(s.failed);
        return null;
      }
      s.user = u2.name;
      ctx.trace("vpn.eap", "L4", `VPN 서버: 계정 ${u2.name} 인증 성공 (CHAP) → 이제 주소(IPCP)`, { from: outer.src, user: u2.name, ppp: "success" }, frameId);
      reply({ proto: "chap", code: "success" });
      return null;
    }
    if (p.proto === "ipcp" && p.code === "configure-request") {
      if (!s.user) {
        ctx.trace("vpn.drop", "L4", `VPN 서버: 계정 인증 전에 온 주소 요청 (IPCP) → 무시`, { from: outer.src }, frameId);
        return null;
      }
      // 이미 준 주소가 있으면(응답이 사라져 다시 옴) 같은 것을
      const vip = s.vip ?? this.allocate(s.cid);
      if (!vip) {
        ctx.trace("vpn.drop", "L4", `VPN 서버: 할당 IP ${this.config.poolStart} ~ ${this.config.poolEnd} 에 줄 주소가 없음 (다 찼거나 LAN 대역 밖) → IPCP Nak, 이 연결을 닫음`, { from: outer.src }, frameId);
        s.failed = { proto: "ipcp", code: "configure-nak" };
        reply(s.failed);
        return null;
      }
      if (!s.vip) {
        for (const o of [...this.byVip.values()]) if (o.cid === s.cid && o !== s) this.drop(o); // 같은 기기의 옛 세션
        s.vip = vip;
        this.byVip.set(vip, s);
        this.leases.set(s.cid, vip);
        ctx.trace(
          "vpn.up",
          "L4",
          `VPN 서버: 접속 수립 (L2TP/IPsec) — ${s.user} 에게 집 LAN 주소 ${vip} 를 줌 (IPCP) → 공유기가 ${vip} 의 ARP 에 대신 답해(프록시 ARP) 집 장치들이 LAN 안의 기기처럼 보고, 이 기기의 인터넷도 집 공유기를 거쳐 나간다`,
          { peer: outer.src, vip, user: s.user, natT: s.natT, l2tp: true },
          frameId,
        );
      }
      const dns = this.host.dns();
      reply({ proto: "ipcp", code: "configure-ack", ip: vip, ...(dns ? { dns } : {}) });
      return null;
    }
    if (p.proto === "ip") {
      if (!s.vip || p.packet.src !== s.vip) {
        ctx.trace("vpn.drop", "L3", `VPN 서버: PPP 로 온 패킷의 출발지 ${p.packet.src} 가 준 주소(${s.vip ?? "없음"})가 아님 → 드롭`, { from: outer.src }, frameId);
        return null;
      }
      ctx.trace("vpn.decap", "L3", `VPN 서버 복호화: ${outer.src} 에서 온 ESP → UDP 1701 L2TP → PPP 를 풀어 ${p.packet.src} → ${p.packet.dst} 패킷을 꺼냄 (집 LAN 기기가 보낸 것처럼 처리)`, { from: outer.src, inner: `${p.packet.src}>${p.packet.dst}` }, frameId);
      return p.packet;
    }
    return null;
  }

  /** L2TP 하나를 ESP(전송 모드)에 담아 클라이언트로 */
  private sendL2tp(s: ServerSa, me: Ip, l: L2tpPacket, ctx: NodeContext, frameId?: number): void {
    const inner: Ipv4Packet = { kind: "ipv4", src: me, dst: s.peer.ip, ttl: 64, payload: { kind: "udp", srcPort: L2TP_PORT, dstPort: L2TP_PORT, payload: l } };
    const esp: EspPacket = { kind: "esp", spi: s.spi, seq: ++s.seq, inner, transport: true };
    this.host.send(espPacket(me, s.peer, s.natT, esp), ctx, frameId);
  }

  /** 할당 주소로 가는 패킷을 그 클라이언트의 PPP → L2TP → ESP 로. 처리했으면 true */
  sendTo(packet: Ipv4Packet, me: Ip, ctx: NodeContext, frameId?: number): boolean {
    const s = this.byVip.get(packet.dst);
    if (!s || !this.config.enabled) return false;
    ctx.trace("vpn.encap", "L3", `VPN 서버 캡슐화: ${packet.src} → ${packet.dst}(VPN 클라이언트) 패킷을 PPP → L2TP(UDP 1701) → ESP 에 담아 ${s.peer.ip}${s.natT ? `:${s.peer.port} (NAT-T)` : ""} 로 — SPI 0x${hex(s.spi)}`, { inner: `${packet.src}>${packet.dst}`, peer: s.peer.ip }, frameId);
    this.sendL2tp(s, me, { kind: "l2tp", tunnelId: s.tunnelId ?? 0, sessionId: s.sessionId ?? 0, ppp: { proto: "ip", packet } }, ctx, frameId);
    return true;
  }

  /**
   * 내 SA 가 아닌 ESP: 안이 L2TP 면 공유기가 잊은 연결(설정 변경·WAN 주소를 잃음)이다 → INVALID-SPI 로 알려 노트북이 다시 접속하게.
   * 말없이 버리면 노트북은 계속 "연결됨" 인 채 모든 트래픽을 잃는다. L2TP 가 아니면(공유기 뒤 IKEv2 서버로 포워딩할 ESP) undefined
   */
  private orphan(outer: Ipv4Packet, srcPort: number | undefined, esp: EspPacket, ctx: NodeContext, frameId?: number): null | undefined {
    const u = esp.inner.payload;
    if (!esp.transport || u.kind !== "udp" || u.payload.kind !== "l2tp") return undefined;
    ctx.trace("vpn.drop", "L4", `VPN 서버: 모르는 연결(SPI 0x${hex(esp.spi)})의 L2TP/IPsec 패킷 (from ${outer.src}) — 공유기가 그 연결을 잊음(설정 변경·WAN 주소를 잃음) → INVALID-SPI 로 알림 (노트북이 다시 접속)`, { from: outer.src, l2tp: true, invalid: true }, frameId);
    const port = srcPort !== undefined ? NAT_T_PORT : IKE_PORT;
    this.sendIke(outer.dst, outer.src, port, srcPort ?? IKE_PORT, { kind: "ike", exchange: "INFORMATIONAL", response: true, spi: esp.spi, error: "INVALID_SPI", l2tp: true }, ctx, frameId);
    return null;
  }

  rows(): string[][] {
    return [...this.sas.values()].filter((s) => !s.failed).map((s) => [s.user ?? "-", s.vip ?? (s.user ? "주소 대기" : "인증 대기"), `${s.peer.ip}${s.natT ? `:${s.peer.port}` : ""}`, s.natT ? "NAT-T" : "ESP"]);
  }

  /** 요약: 접속 수와 "kim 192.168.0.50" */
  clientsLabel(): string {
    const up = [...this.byVip.values()];
    return `접속 ${up.length}명${up.length ? ` (${up.map((s) => `${s.user} ${s.vip}`).join(", ")})` : ""}`;
  }

  /** 꺼지거나 지워질 때: 붙어 있던 세션을 모두 비운다 */
  clear(): void {
    this.sas.clear();
    this.byVip.clear();
    this.mm.clear();
    this.authed.clear();
  }
}

// ---------- 클라이언트 (노트북 — Windows 의 "L2TP/IPsec 및 미리 공유한 키") ----------

type Phase = "mm1" | "mm2" | "qm" | "sccrq" | "icrq" | "lcp" | "chap" | "ipcp" | "up";
const PHASE_LABEL: Record<Phase, string> = {
  mm1: "IPsec Main Mode",
  mm2: "IPsec 인증 (PSK)",
  qm: "IPsec Quick Mode",
  sccrq: "L2TP 터널",
  icrq: "L2TP 세션",
  lcp: "PPP 링크",
  chap: "PPP 계정 인증",
  ipcp: "PPP 주소 받기",
  up: "연결됨",
};

export class L2tpClient {
  config: RaClientConfig = { enabled: false, psk: "", type: "l2tp" };
  state: RaClientState = "off";
  vip: Ip | undefined;
  /** IPCP 로 받은 DNS (연결된 동안 이것으로 묻는다) */
  dns: Ip | undefined;
  /** full tunnel 이라 사내 대역 목록이 없다 (화면 호환용) */
  readonly routes: { dest: Ip; prefix: number }[] = [];
  reason: string | undefined;
  readonly dpdWaiting = false;
  private phase: Phase = "mm1";
  private sa: { spi: number; natT: boolean; peer?: { ip: Ip; port: number }; seq: number; tunnelId: number; sessionId: number } = { spi: 0, natT: false, seq: 0, tunnelId: 0, sessionId: 0 };
  private attempts = 0;
  private readonly ike: IkeRetransmit;
  /** L2TP·PPP 요청 재전송 (마지막 요청과 시도 횟수) */
  private last: { l: L2tpPacket; phase: Phase; tries: number; id: number } | undefined;
  private lastId = 0;

  constructor(
    private readonly io: RaIo & { myIp(): Ip | undefined; local?(dst: Ip): boolean },
    private readonly cid: string,
  ) {
    this.ike = new IkeRetransmit(RA_TIMER_TAG, (pkt, ctx) => this.io.send(pkt, ctx));
  }

  setConfig(cfg: RaClientConfig, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.config)) return;
    if (this.state === "up") this.disconnect(ctx, "설정이 바뀜");
    this.config = { ...cfg };
    this.state = "off";
    this.reason = undefined;
    ctx.trace("vpn.config", "sys", cfg.enabled ? `VPN 켜짐 (L2TP/IPsec): ${cfg.server ?? "(서버 주소 없음)"} 에 접속 — 사전 공유 키로 IPsec, 계정(${cfg.user ?? "없음"})으로 PPP 인증` : "VPN 꺼짐", { ...cfg, password: undefined });
    this.connect(ctx);
  }

  connect(ctx: NodeContext): void {
    if (!this.config.enabled || this.state === "init" || this.state === "auth" || this.state === "up") return;
    const me = this.io.myIp();
    const server = this.config.server;
    if (!me || !server) return;
    this.attempts++;
    this.sa = { spi: spiOf(`l2tp:${this.cid}@${me}>${server}#${this.attempts}`), natT: false, seq: 0, tunnelId: 0, sessionId: 0 };
    this.state = "init";
    this.phase = "mm1";
    this.reason = undefined;
    this.last = undefined;
    ctx.trace("vpn.ike", "L4", `VPN (L2TP/IPsec): 서버 ${server} 에 IKE Main Mode 요청 (암호 방식·키 교환, NAT 감지용으로 내 주소 ${me} 를 적어 보냄)`, { peer: server, spi: this.sa.spi, l2tp: true });
    this.request({ kind: "ike", exchange: "MAIN_MODE", response: false, spi: this.sa.spi, natSrc: me, natDst: server, l2tp: true, cid: this.cid }, IKE_PORT, ctx);
  }

  private request(msg: IkeMessage, port: number, ctx: NodeContext): void {
    const me = this.io.myIp();
    const server = this.config.server;
    if (!me || !server) return;
    this.ike.request(me, server, port, msg, ctx);
  }

  private fail(why: string, ctx: NodeContext, frameId?: number, label = "VPN 접속 실패"): void {
    this.state = "failed";
    this.reason = why;
    this.ike.clear();
    this.last = undefined;
    this.vip = undefined;
    this.dns = undefined;
    ctx.trace("vpn.drop", "L4", `${label} (L2TP/IPsec): ${why}`, { l2tp: true }, frameId);
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const d = data as { l2tp?: boolean; phase?: Phase; tries?: number; id?: number };
    if (d.l2tp) {
      const l = this.last;
      if (!l || l.id !== d.id || l.tries !== d.tries || this.phase !== d.phase || this.state === "up" || this.state === "failed" || this.state === "off") return;
      if (l.tries < IKE_RETRANSMITS) {
        ctx.trace("vpn.ike", "L4", `VPN (L2TP/IPsec): ${PHASE_LABEL[l.phase]} 응답 없음 → 다시 보냄 (재전송 ${l.tries + 1}/${IKE_RETRANSMITS})`, { retransmit: l.tries + 1, l2tp: true });
        this.transmitL2tp(l.l, l.phase, ctx, l.tries + 1, l.id);
        return;
      }
      this.fail(`${PHASE_LABEL[l.phase]} 에 서버 응답 없음 (재전송 ${IKE_RETRANSMITS}번 뒤 timeout) — 서버의 VPN 서버 설정을 확인`, ctx);
      return;
    }
    const cur = this.phase === "mm1" || this.phase === "mm2" ? "MAIN_MODE" : this.phase === "qm" ? "QUICK_MODE" : undefined;
    const { verdict, step, tries } = this.ike.check(data, this.sa.spi, this.state === "init" || this.state === "auth" ? cur : undefined);
    if (verdict === "ignore") return;
    if (verdict === "retransmit") {
      ctx.trace("vpn.ike", "L4", `VPN (L2TP/IPsec): IKE ${step === "MAIN_MODE" ? "Main Mode" : "Quick Mode"} 응답 없음 → 다시 보냄 (재전송 ${tries + 1}/${IKE_RETRANSMITS})`, { retransmit: tries + 1, step, l2tp: true });
      this.ike.resend(ctx);
      return;
    }
    this.fail(`IKE ${step === "MAIN_MODE" ? "Main Mode" : "Quick Mode"} 응답 없음 (재전송 ${IKE_RETRANSMITS}번 뒤 timeout) — 서버 주소, 공유기의 VPN 서버, UDP 500·4500 이 막히지 않았는지 확인`, ctx);
  }

  /** 서버에서 온 IKE 응답. 처리했으면 true */
  handleIke(outer: Ipv4Packet, srcPort: number, dstPort: number, m: IkeMessage, ctx: NodeContext, frameId?: number): boolean {
    if (!m.l2tp || !m.response || outer.src !== this.config.server) return false;
    if (m.spi !== this.sa.spi) {
      if (dstPort !== IKE_PORT && dstPort !== NAT_T_PORT) return false;
      ctx.trace("vpn.ike", "L4", `VPN (L2TP/IPsec): 지난 협상(SPI 0x${hex(m.spi)})의 늦게 온 응답 → 무시`, { from: outer.src, late: true }, frameId);
      return true;
    }
    if (m.exchange === "INFORMATIONAL" && m.error === "INVALID_SPI") {
      if (this.state !== "up") return true;
      ctx.trace("vpn.ike", "L4", `VPN (L2TP/IPsec): 공유기가 이 연결을 모른다고 알림 (INVALID-SPI — 공유기 설정 변경·WAN 주소를 잃음 등) → 다시 접속`, { from: outer.src, l2tp: true, invalid: true }, frameId);
      this.reset("off");
      this.connect(ctx);
      return true;
    }
    const me = outer.dst;
    if (m.exchange === "MAIN_MODE" && this.phase === "mm1") {
      const { localNat, remoteNat, natT } = natAtInitiator(m, outer.src, me);
      this.sa = { ...this.sa, natT };
      this.state = "auth";
      this.phase = "mm2";
      ctx.trace("vpn.ike", "L4", `VPN (L2TP/IPsec): Main Mode 응답 (NAT ${natT ? `${localNat ? "내 앞(호텔·카페 공유기)" : "서버 앞"}에 있음 → 여기부터 UDP 4500` : "없음"}) → 사전 공유 키로 만든 인증 값을 보냄`, { from: outer.src, natT, localNat, remoteNat, l2tp: true }, frameId);
      this.request({ kind: "ike", exchange: "MAIN_MODE", response: false, spi: this.sa.spi, auth: this.config.psk, l2tp: true, cid: this.cid }, natT ? NAT_T_PORT : IKE_PORT, ctx);
      return true;
    }
    if (m.exchange === "MAIN_MODE" && this.phase === "mm2") {
      if (m.error) {
        this.fail("서버가 IPsec 인증을 거절 (AUTHENTICATION-FAILED) — 사전 공유 키가 다름. 공유기 VPN 서버의 사전 공유 키와 같게", ctx, frameId);
        return true;
      }
      this.phase = "qm";
      ctx.trace("vpn.ike", "L4", `VPN (L2TP/IPsec): 사전 공유 키 확인됨 (IPsec 1단계 끝) → Quick Mode: UDP 1701 (L2TP) 을 보호할 ESP SA 요청`, { from: outer.src, l2tp: true }, frameId);
      this.request({ kind: "ike", exchange: "QUICK_MODE", response: false, spi: this.sa.spi, l2tp: true, cid: this.cid }, this.sa.natT ? NAT_T_PORT : IKE_PORT, ctx);
      return true;
    }
    if (m.exchange === "QUICK_MODE" && this.phase === "qm") {
      this.ike.clear();
      this.sa = { ...this.sa, peer: { ip: outer.src, port: srcPort } };
      ctx.trace("vpn.ike", "L4", `VPN (L2TP/IPsec): IPsec SA 수립 (ESP 전송 모드${this.sa.natT ? ", NAT-T" : ""}) → 이 통로 안에서 L2TP 터널 열기 요청 (SCCRQ)`, { from: outer.src, l2tp: true }, frameId);
      this.sendL2tp({ kind: "l2tp", tunnelId: 0, sessionId: 0, control: "SCCRQ" }, "sccrq", ctx);
      return true;
    }
    return true;
  }

  /** L2TP·PPP 요청 하나를 보내고 응답을 기다린다 (1초마다 다시, 2번까지) */
  private sendL2tp(l: L2tpPacket, phase: Phase, ctx: NodeContext): void {
    this.phase = phase;
    this.transmitL2tp(l, phase, ctx, 0, ++this.lastId);
  }

  private transmitL2tp(l: L2tpPacket, phase: Phase, ctx: NodeContext, tries: number, id: number): void {
    this.last = { l, phase, tries, id };
    this.sendRaw(l, ctx);
    ctx.timer(IKE_TIMEOUT, RA_TIMER_TAG, { l2tp: true, phase, tries, id });
  }

  /** L2TP 하나를 ESP(전송 모드)에 담아 서버로 */
  private sendRaw(l: L2tpPacket, ctx: NodeContext): void {
    const me = this.io.myIp();
    const peer = this.sa.peer;
    if (!me || !peer) return;
    const inner: Ipv4Packet = { kind: "ipv4", src: me, dst: peer.ip, ttl: 64, payload: { kind: "udp", srcPort: L2TP_PORT, dstPort: L2TP_PORT, payload: l } };
    const esp: EspPacket = { kind: "esp", spi: this.sa.spi, seq: ++this.sa.seq, inner, transport: true };
    this.io.send(espPacket(me, peer, this.sa.natT, esp), ctx);
  }

  /**
   * 받은 ESP: 내 SA 것이면 풀어 L2TP·PPP 협상을 진행하거나(null), PPP 로 온 IP 패킷이면 목적지를 내 실제 주소로 되돌려 돌려준다.
   * 내 SA 것이 아니면 undefined
   */
  unwrap(outer: Ipv4Packet, esp: EspPacket, ctx: NodeContext, frameId: number): Ipv4Packet | undefined | null {
    if (this.state === "off" || this.state === "failed" || outer.src !== this.config.server || esp.spi !== this.sa.spi) return undefined;
    const u = esp.inner.payload;
    if (u.kind !== "udp" || u.payload.kind !== "l2tp") return undefined;
    const l = u.payload;
    const reply = (ppp: NonNullable<L2tpPacket["ppp"]>, phase: Phase) => this.sendL2tp({ kind: "l2tp", tunnelId: this.sa.tunnelId, sessionId: this.sa.sessionId, ppp }, phase, ctx);
    if (l.control === "SCCRP" && this.phase === "sccrq") {
      this.sa.tunnelId = l.tunnelId;
      ctx.trace("vpn.ike", "L4", `VPN (L2TP/IPsec): L2TP 터널 ${l.tunnelId} 열림 (SCCRP) → 세션 열기 요청 (ICRQ)`, { l2tp: "SCCRP" }, frameId);
      this.sendL2tp({ kind: "l2tp", tunnelId: this.sa.tunnelId, sessionId: 0, control: "ICRQ" }, "icrq", ctx);
      return null;
    }
    if (l.control === "ICRP" && this.phase === "icrq") {
      this.sa.sessionId = l.sessionId;
      ctx.trace("vpn.ike", "L4", `VPN (L2TP/IPsec): L2TP 세션 ${l.sessionId} 열림 (ICRP) → 이 세션 위에서 PPP 링크 설정 (LCP)`, { l2tp: "ICRP" }, frameId);
      reply({ proto: "lcp", code: "configure-request" }, "lcp");
      return null;
    }
    if (l.control === "CDN" || l.control === "StopCCN") {
      // 공유기가 먼저 끊음 (설정 변경·VPN 서버 끔): 실패로 두고 "다시 연결" 을 기다린다 (Windows 도 끊김으로 남는다)
      this.fail(`공유기가 연결을 끊음 (${CONTROL_LABEL[l.control]}) — 공유기 VPN 서버의 설정이 바뀌었거나 꺼짐. 확인한 뒤 "다시 연결"`, ctx, frameId, "VPN 끊김");
      return null;
    }
    const p = l.ppp;
    if (!p) return null;
    if (p.proto === "chap" && p.code === "challenge" && this.phase === "lcp") {
      const user = this.config.user?.trim();
      if (!user) {
        this.fail("서버가 PPP 계정 인증(CHAP)을 요구하는데 계정이 없음 — VPN 설정에 사용자 이름·비밀번호를 넣으세요 (공유기 VPN 서버에 등록한 계정)", ctx, frameId);
        return null;
      }
      ctx.trace("vpn.eap", "L4", `VPN (L2TP/IPsec): 서버가 계정 인증(CHAP challenge)을 요청 → 계정 ${user} 의 비밀번호로 만든 응답을 보냄`, { user, ppp: "response" }, frameId);
      reply({ proto: "chap", code: "response", user, secret: this.config.password ?? "" }, "chap");
      return null;
    }
    if (p.proto === "chap" && p.code === "failure" && this.phase === "chap") {
      this.fail("서버가 계정 인증을 거절 (CHAP Failure) — 계정 또는 비밀번호가 틀림. 공유기 VPN 서버에 등록한 계정·비밀번호를 확인하세요", ctx, frameId);
      return null;
    }
    if (p.proto === "chap" && p.code === "success" && this.phase === "chap") {
      ctx.trace("vpn.eap", "L4", `VPN (L2TP/IPsec): 계정 인증 성공 (CHAP Success) → 주소 요청 (IPCP)`, { ppp: "success" }, frameId);
      reply({ proto: "ipcp", code: "configure-request", ip: "0.0.0.0" }, "ipcp");
      return null;
    }
    if (p.proto === "ipcp" && this.phase === "ipcp") {
      if (p.code !== "configure-ack" || !p.ip) {
        this.fail("서버에 줄 주소가 없음 (IPCP Nak) — 공유기 VPN 서버의 할당 IP 범위를 확인", ctx, frameId);
        return null;
      }
      this.last = undefined;
      this.state = "up";
      this.phase = "up";
      this.vip = p.ip;
      this.dns = p.dns;
      ctx.trace(
        "vpn.up",
        "L4",
        `VPN 연결됨 (L2TP/IPsec): 집 LAN 주소 ${p.ip} 를 받음 (IPCP${p.dns ? `, DNS ${p.dns}` : ""}) → 이제 모든 트래픽을 출발지 ${p.ip} 로 PPP → L2TP → ESP 에 담아 집 공유기로 보냄 (full tunnel — 인터넷도 집을 거쳐 나간다)`,
        { peer: outer.src, vip: p.ip, natT: this.sa.natT, l2tp: true },
        frameId,
      );
      return null;
    }
    if (p.proto === "ip" && this.state === "up") {
      const me = this.io.myIp();
      if (!me || p.packet.dst !== this.vip) return null;
      ctx.trace("vpn.decap", "L3", `VPN 복호화 (L2TP/IPsec): ESP → L2TP → PPP 를 풀어 ${p.packet.src} → ${p.packet.dst}(내 VPN 주소) 패킷을 꺼냄`, { from: outer.src, inner: `${p.packet.src}>${p.packet.dst}` }, frameId);
      return { ...p.packet, dst: me };
    }
    ctx.trace("vpn.drop", "L4", `VPN (L2TP/IPsec): 지금 단계(${PHASE_LABEL[this.phase]})에서 기다리지 않은 L2TP${l2tpPartLabel(l)} → 무시`, {}, frameId);
    return null;
  }

  /**
   * 내보낼 패킷을 가로챈다 (full tunnel): 터널 자신·서버·직접 연결된 서브넷(호텔 LAN)·브로드캐스트를 빼고 모두
   * 출발지를 VPN 주소로 바꿔 PPP → L2TP → ESP 로. 가로챘으면 true
   */
  intercept(pkt: Ipv4Packet, ctx: NodeContext): boolean {
    if (this.state !== "up" || !this.vip || !this.sa.peer) return false;
    const p = pkt.payload;
    if (p.kind === "esp" || (p.kind === "udp" && (p.payload.kind === "ike" || p.payload.kind === "esp" || p.payload.kind === "l2tp" || p.payload.kind === "dhcp"))) return false;
    if (pkt.dst === this.config.server || pkt.dst === "255.255.255.255" || isMcastIp(pkt.dst)) return false;
    if (this.io.local?.(pkt.dst)) return false;
    const inner: Ipv4Packet = { ...pkt, src: this.vip };
    ctx.trace("vpn.encap", "L3", `VPN 캡슐화 (L2TP/IPsec, full tunnel): ${pkt.dst} 로 가는 패킷의 출발지를 VPN 주소 ${this.vip} 로 바꿔 PPP → L2TP(UDP 1701) → ${this.sa.natT ? "UDP 4500 (NAT-T) 안의 " : ""}ESP 로 집 공유기 ${this.sa.peer.ip} 에 보냄`, { inner: `${this.vip}>${pkt.dst}`, peer: this.sa.peer.ip });
    this.sendRaw({ kind: "l2tp", tunnelId: this.sa.tunnelId, sessionId: this.sa.sessionId, ppp: { proto: "ip", packet: inner } }, ctx);
    return true;
  }

  /** 연결 해제: L2TP 를 끊고(StopCCN) IPsec SA 도 지운다(Delete) */
  disconnect(ctx: NodeContext, why: string): void {
    if (this.state === "up") {
      this.sendRaw({ kind: "l2tp", tunnelId: this.sa.tunnelId, sessionId: this.sa.sessionId, control: "StopCCN" }, ctx);
      const me = this.io.myIp();
      const server = this.config.server;
      if (me && server) {
        const port = this.sa.natT ? NAT_T_PORT : IKE_PORT;
        this.io.send(ikePacket(me, server, port, this.sa.peer?.port ?? port, { kind: "ike", exchange: "INFORMATIONAL", response: false, spi: this.sa.spi, l2tp: true, cid: this.cid }), ctx);
      }
      ctx.trace("vpn.drop", "L4", `VPN 끊음 (${why}) → L2TP 터널 끊기(StopCCN)·IPsec SA 지움(Delete), 주소 ${this.vip} 를 내려놓음`, { l2tp: true });
    }
    this.reset("off");
  }

  private reset(state: RaClientState): void {
    this.state = state;
    this.vip = undefined;
    this.dns = undefined;
    this.last = undefined;
    this.ike.clear();
  }

  lost(ctx: NodeContext, why: string): void {
    if (this.state === "off" || this.state === "failed") return;
    ctx.trace("vpn.drop", "L4", `VPN 끊김 (L2TP/IPsec): ${why}`, { l2tp: true });
    this.reset("off");
  }

  reconnect(ctx: NodeContext): void {
    if (this.state === "up") this.disconnect(ctx, "다시 연결");
    this.reset("off");
    this.connect(ctx);
  }

  /** L2TP/IPsec 에는 DPD 버튼이 없다 (보통 쓰지 않음) */
  dpd(ctx: NodeContext): void {
    ctx.trace("vpn.dpd", "L4", `L2TP/IPsec 연결에는 DPD 를 보내지 않음 (IKEv2 원격 접속에서만)`, { dpd: "none" });
  }

  onDpdTick(): void {}

  summary(): string | undefined {
    if (!this.config.enabled) return undefined;
    if (this.state === "up") return `연결됨 (L2TP/IPsec) · 집 LAN 주소 ${this.vip} · 모든 트래픽을 집으로 (full tunnel)`;
    if (this.state === "init" || this.state === "auth") return `연결 중 (${PHASE_LABEL[this.phase]})`;
    if (this.state === "failed") return `${this.reason?.startsWith("공유기가 연결을 끊음") ? "끊김" : "실패"} · ${this.reason ?? ""}`;
    return "대기 (주소를 받으면 접속)";
  }
}
