// 원격 접속 VPN (IPsec IKEv2 원격 접속 축소판): 재택 노트북 한 대가 인터넷 너머 회사 VPN 장비에 붙어, 사내 대역을 사설 주소로 쓴다.
// 사이트 간 VPN(vpn.ts)은 두 사무실의 장비끼리 대역 대 대역을 잇지만, 원격 접속은
//  - 클라이언트가 여럿 (서버는 클라이언트마다 터널을 따로 둔다)
//  - 서버가 클라이언트에게 가상 주소(풀에서 하나)와 터널로 보낼 사내 대역(split tunnel)을 알려 준다 (IKE_AUTH 의 Configuration Payload)
//  - 클라이언트가 보내는 안쪽 패킷의 출발지는 그 가상 주소 — 사내 서버는 가상 주소로 답하고, 회사 VPN 장비가 그 주소를 가진 터널로 돌려보낸다
// 협상은 사이트 간과 같은 IKE_SA_INIT(NAT 감지) → IKE_AUTH(PSK). 집 공유기 NAT 뒤라 보통 UDP 4500 (NAT-T) 로 간다.
// 서버에 사용자 계정이 있으면 PSK 확인 뒤 계정 인증(EAP-MSCHAPv2 축소판)을 한 번 더 한다:
//   IKE_AUTH(PSK + IDi = 사용자 이름) → 서버: EAP 요청(challenge) → IKE_AUTH(EAP 응답) → 서버: EAP 성공 + 가상 주소, 또는 AUTHENTICATION_FAILED
//   PSK 는 모두가 같이 쓰는 비밀이라 한 명을 막으려면 모두의 키를 바꿔야 하지만, 계정은 사람마다라 그 사람만 지우면 된다
//   (목록에서 지워도 이미 붙은 세션은 다시 붙을 때까지 유지 — 실제 장비도 인증은 접속할 때 한 번)
// 연결 해제는 INFORMATIONAL(Delete) 로 알려 가상 주소를 돌려준다. DPD 는 클라이언트가 사용자 동작으로 보내는 빈 INFORMATIONAL.
// 재협상(rekey)은 생략.
import { ipToInt, intToIp, sameSubnet, type Ip } from "../addr";
import { IKE_PORT, NAT_T_PORT, type EspPacket, type IkeMessage, type Ipv4Packet } from "../packet";
import { IKE_RETRANSMITS, IkeRetransmit, espPacket, hex, ikePacket, natAtInitiator, natAtResponder, spiOf } from "./ike";
import type { NodeContext } from "./node";

export interface RaServerConfig {
  enabled: boolean;
  psk: string;
  /** 가상 주소 풀 */
  poolStart: Ip;
  poolEnd: Ip;
  /** 클라이언트에게 알려 줄 사내 대역 (이 대역으로 가는 것만 터널로) */
  routes: { dest: Ip; prefix: number }[];
  /** 사용자 계정 (EAP). 비어 있으면 PSK 만으로 접속 */
  users?: { name: string; password: string }[];
}

export const DEFAULT_RA_SERVER: RaServerConfig = { enabled: false, psk: "", poolStart: "10.99.0.10", poolEnd: "10.99.0.50", routes: [] };

export interface RaClientConfig {
  enabled: boolean;
  /** 회사 VPN 장비의 공인 주소 */
  server?: Ip;
  psk: string;
  /** 사용자 계정 (서버가 계정 인증을 요구할 때) */
  user?: string;
  password?: string;
}

export const DEFAULT_RA_CLIENT: RaClientConfig = { enabled: false, psk: "" };
export const RA_TIMER_TAG = "ra-ike";
const inRoutes = (ip: Ip, routes: { dest: Ip; prefix: number }[]) =>
  routes.some((r) => {
    try {
      return sameSubnet(ip, r.dest, r.prefix);
    } catch {
      return false;
    }
  });
const routesLabel = (routes: { dest: Ip; prefix: number }[]) => routes.map((r) => `${r.dest}/${r.prefix}`).join(", ") || "(없음)";

/** 원격 접속 서버·클라이언트가 장치에게서 빌리는 것: 바깥 출발지 주소와 바깥 패킷 송신 (NAT 하지 않음) */
export interface RaIo {
  source(dst: Ip): Ip | undefined;
  send(outer: Ipv4Packet, ctx: NodeContext, frameId?: number): void;
}

interface RaClientSa {
  vip: Ip;
  cid: string;
  /** 계정 인증(EAP)으로 붙었으면 사용자 이름 */
  user?: string;
  /** IKE_AUTH 를 두 번(EAP) 주고받아 붙었음 — 이후 교환의 Message ID 가 하나 늘어난다 (strongSwan 로그 표시용) */
  eap?: true;
  peer: { ip: Ip; port: number };
  natT: boolean;
  spi: number;
  seq: number;
}

// ---------- 서버 (게이트웨이·NAT 박스) ----------

export class RaServer {
  config: RaServerConfig = { ...DEFAULT_RA_SERVER, routes: [] };
  /** 가상 주소 → 붙어 있는 클라이언트 */
  readonly clients = new Map<Ip, RaClientSa>();
  /** IKE_SA_INIT 을 받고 IKE_AUTH 를 기다리는 협상 ("바깥 주소:포트:spi" → NAT 감지 결과) — 집 사설 주소가 같은 노트북끼리 섞이지 않게 */
  private readonly pending = new Map<string, boolean>();
  /** 클라이언트 식별 → 지난번 준 가상 주소 (다시 붙으면 같은 주소) */
  private readonly leases = new Map<string, Ip>();
  /** PSK 를 확인하고 EAP 요청을 보내 EAP 응답을 기다리는 협상 ("바깥 주소:포트:spi" → NAT 감지 결과·클라이언트 식별) */
  private readonly eapPending = new Map<string, { nat: boolean; cid: string }>();
  /**
   * 클라이언트("바깥 주소:포트")마다 마지막으로 보낸 IKE_AUTH 최종 응답(성공·실패): 그 응답이 사라져 같은 요청이 다시 오면
   * 인증·주소 할당을 다시 하지 않고 같은 응답을 다시 보낸다 (RFC 7296 2.1 — 응답자는 마지막 응답을 기억한다)
   */
  private readonly lastAuth = new Map<string, { spi: number; eap: boolean; response: IkeMessage; label: string }>();

  constructor(private readonly io: RaIo) {}

  private get users(): { name: string; password: string }[] {
    return this.config.users ?? [];
  }

  setConfig(cfg: RaServerConfig, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.config)) return;
    // 사용자 계정만 바뀜: 붙어 있는 세션은 그대로 둔다 (인증은 접속할 때 한 번 — 지운 사용자도 다시 붙을 때 막힌다)
    const { users: nextUsers, ...nextRest } = cfg;
    const { users: prevUsers, ...prevRest } = this.config;
    if (JSON.stringify(nextRest) === JSON.stringify(prevRest)) {
      this.config = { ...this.config, users: (nextUsers ?? []).map((u) => ({ ...u })) };
      if (!this.config.enabled) return;
      const kept = [...this.clients.values()].filter((c) => c.user && !this.users.some((u) => u.name === c.user)).map((c) => c.user!);
      ctx.trace(
        "vpn.config",
        "sys",
        `원격 접속 VPN 서버 사용자 계정 변경: ${this.users.length ? `${this.users.map((u) => u.name).join(", ")} (PSK 확인 뒤 EAP 로 계정 확인)` : "없음 (PSK 만으로 접속)"}${kept.length ? ` — 목록에서 빠진 ${kept.join(", ")} 의 세션은 끊지 않음 (다시 붙을 때 인증 실패)` : ""}`,
        { users: this.users.map((u) => u.name), before: (prevUsers ?? []).map((u) => u.name) },
      );
      return;
    }
    this.config = { ...cfg, routes: cfg.routes.map((r) => ({ ...r })), ...(cfg.users ? { users: cfg.users.map((u) => ({ ...u })) } : {}) };
    this.clients.clear();
    this.pending.clear();
    this.eapPending.clear();
    this.lastAuth.clear();
    this.leases.clear();
    ctx.trace(
      "vpn.config",
      "sys",
      cfg.enabled
        ? `원격 접속 VPN 서버 켜짐: ${this.users.length ? `PSK 와 사용자 계정(${this.users.map((u) => u.name).join(", ")}, EAP)을 확인한 뒤 ` : ""}접속한 클라이언트에게 ${cfg.poolStart} ~ ${cfg.poolEnd} 에서 가상 주소를 주고, ${routesLabel(cfg.routes)} 로 가는 것만 터널로 보내게 알림 (IKE UDP ${IKE_PORT})`
        : "원격 접속 VPN 서버 꺼짐",
      { ...cfg, ...(cfg.users ? { users: cfg.users.map((u) => u.name) } : {}) },
    );
  }

  /**
   * 이중화 master 에서 물러남: 붙어 있던 클라이언트 터널과 진행 중인 협상을 비운다. SA 는 새 master 에 복사되지 않으므로
   * 클라이언트는 새 master 에게서 INVALID_SPI 를 받고 다시 접속한다 (지난 임대 기록은 남겨 돌아오면 같은 주소를 준다)
   */
  dropAll(ctx: NodeContext, why: string): void {
    const clients = [...this.clients.values()].map((c) => (c.user ? `${c.user} ${c.vip}` : c.vip));
    const negotiating = this.pending.size + this.eapPending.size;
    this.clients.clear();
    this.pending.clear();
    this.eapPending.clear();
    this.lastAuth.clear();
    if (!clients.length && !negotiating) return;
    const what = [clients.length ? `붙어 있던 클라이언트 ${clients.length}명(${clients.join(", ")})의 터널` : "", negotiating ? `진행 중인 협상 ${negotiating}개` : ""].filter(Boolean).join("과 ");
    ctx.trace("vpn.drop", "L4", `원격 접속: ${why} → ${what}을 지움 — SA 는 새 master 에 복사되지 않으므로 클라이언트는 새 master 에게서 INVALID_SPI 를 받고 다시 접속`, { why, clients: clients.length });
  }

  /** 이 주소가 붙어 있는 클라이언트의 가상 주소인지 (라우팅: 그 클라이언트 터널로) */
  owns(ip: Ip): boolean {
    return this.config.enabled && this.clients.has(ip);
  }

  private allocate(cid: string): Ip | undefined {
    const prev = this.leases.get(cid);
    if (prev && ![...this.clients.values()].some((c) => c.vip === prev && c.cid !== cid)) return prev;
    let a: number;
    let b: number;
    try {
      a = ipToInt(this.config.poolStart);
      b = ipToInt(this.config.poolEnd);
    } catch {
      return undefined;
    }
    const used = new Set([...this.clients.values()].filter((c) => c.cid !== cid).map((c) => c.vip));
    for (let n = a; n <= b; n++) {
      const ip = intToIp(n);
      if (!used.has(ip) && ![...this.leases.entries()].some(([k, v]) => v === ip && k !== cid)) return ip;
    }
    // 빈 주소가 없으면 지금 붙어 있지 않은 클라이언트의 지난 임대 중 가장 오래된 것을 넘겨준다
    for (const [k, v] of this.leases) {
      if (k === cid || used.has(v)) continue;
      this.leases.delete(k);
      return v;
    }
    return undefined;
  }

  private sendIke(src: Ip, dst: Ip, srcPort: number, dstPort: number, m: IkeMessage, ctx: NodeContext, frameId?: number): void {
    this.io.send(ikePacket(src, dst, srcPort, dstPort, m), ctx, frameId);
  }

  /** 원격 접속 IKE 메시지. 처리했으면 true */
  handleIke(outer: Ipv4Packet, srcPort: number, dstPort: number, m: IkeMessage, ctx: NodeContext, frameId?: number): boolean {
    if (!this.config.enabled || !m.ra || m.response) return false;
    const me = outer.dst;
    if (m.exchange === "IKE_SA_INIT") {
      const { nat, remoteNat, localNat } = natAtResponder(m, outer.src, me);
      this.pending.set(`${outer.src}:${srcPort}:${m.spi}`, nat);
      ctx.trace("vpn.ike", "L4", `원격 접속: ${outer.src} 의 IKE_SA_INIT → 응답. NAT 감지: ${nat ? "있음 (클라이언트가 공유기 뒤) → 이후 UDP 4500 (NAT-T)" : "없음"}`, { from: outer.src, nat, remoteNat, localNat }, frameId);
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "IKE_SA_INIT", response: true, spi: m.spi, nat, natSrc: me, natDst: outer.src, ra: true }, ctx, frameId);
      return true;
    }
    if (m.exchange === "INFORMATIONAL" && m.dpd) {
      // DPD: 빈 INFORMATIONAL — 이 SPI 의 터널을 알면 빈 응답, 모르면 INVALID_SPI (클라이언트가 옛 SA 를 버리고 다시 접속)
      const c = [...this.clients.values()].find((x) => x.spi === m.spi && x.cid === m.cid);
      if (!c) {
        ctx.trace("vpn.drop", "L4", `원격 접속: ${outer.src} 의 DPD 가 이쪽에 없는 터널(SPI 0x${hex(m.spi)})을 확인함 (서버 설정 변경·재시작으로 SA 가 사라짐) → INVALID_SPI 로 알림 (클라이언트가 다시 접속하도록)`, { from: outer.src, dpd: "unknown" }, frameId);
        this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "INFORMATIONAL", response: true, spi: m.spi, error: "INVALID_SPI", ra: true, dpd: true }, ctx, frameId);
        return true;
      }
      ctx.trace("vpn.dpd", "L4", `원격 접속: ${c.user ? `${c.user} (${c.vip})` : c.vip} 의 DPD 요청 (빈 INFORMATIONAL) → 이 터널을 앎 → 빈 응답으로 살아 있다고 알림`, { from: outer.src, dpd: "reply", vip: c.vip, ...(c.eap ? { mid: 3 } : {}) }, frameId);
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "INFORMATIONAL", response: true, spi: m.spi, ra: true, dpd: true }, ctx, frameId);
      return true;
    }
    if (m.exchange === "INFORMATIONAL") {
      const c = [...this.clients.values()].find((x) => x.cid === m.cid);
      if (m.cid) this.leases.delete(m.cid); // 끊었으니 가상 주소를 풀로 돌려준다
      this.lastAuth.delete(`${outer.src}:${srcPort}`);
      if (c) {
        this.clients.delete(c.vip);
        ctx.trace("vpn.drop", "L4", `원격 접속: ${c.peer.ip} 가 연결을 끊음 (Delete) → 가상 주소 ${c.vip} 의 터널을 내림`, { vip: c.vip }, frameId);
      }
      return true;
    }
    // 마지막 응답(성공·실패)이 사라져 같은 IKE_AUTH 가 다시 옴: 인증·주소 할당을 다시 하지 않고 같은 응답을 다시 보낸다
    const last = this.lastAuth.get(`${outer.src}:${srcPort}`);
    if (last && last.spi === m.spi && last.eap === (m.eap === "response")) {
      ctx.trace(
        "vpn.ike",
        "L4",
        `원격 접속: ${outer.src} 가 이미 답한 IKE_AUTH 를 다시 보냄 (지난 응답이 사라진 것) → 기억해 둔 응답(${last.label})을 그대로 다시 보냄 — 인증·주소 할당은 다시 하지 않음`,
        { from: outer.src, resent: true, mid: last.eap ? 2 : 1 },
        frameId,
      );
      this.sendIke(me, outer.src, dstPort, srcPort, last.response, ctx, frameId);
      return true;
    }
    // IKE_AUTH 의 EAP 응답: 계정 확인
    if (m.eap === "response") {
      const key = `${outer.src}:${srcPort}:${m.spi}`;
      const e = this.eapPending.get(key);
      if (!e) {
        ctx.trace("vpn.drop", "L4", `원격 접속: EAP 요청 없이 온 EAP 응답 (from ${outer.src}) → 무시`, { from: outer.src }, frameId);
        return true;
      }
      this.eapPending.delete(key);
      if (!this.users.length) {
        // 그사이 계정 목록이 비었다: 이제 PSK 만 보는 서버 — PSK 는 이미 확인했다
        this.grant(outer, srcPort, dstPort, m.spi, e.nat, e.cid, undefined, true, ctx, frameId);
        return true;
      }
      const u = this.users.find((x) => x.name === m.user);
      if (!u || u.password !== (m.eapSecret ?? "")) {
        const why = !m.user ? "사용자 이름이 비어 있음" : !u ? `사용자 ${m.user} 가 계정 목록에 없음` : `${m.user} 의 비밀번호가 다름`;
        ctx.trace("vpn.drop", "L4", `원격 접속: ${outer.src} 의 계정 인증 실패 (EAP-MSCHAPv2) — ${why} → EAP 실패 + AUTHENTICATION_FAILED 로 거절`, { from: outer.src, user: m.user, eap: "failure" }, frameId);
        this.finalAuth(outer, srcPort, dstPort, true, { kind: "ike", exchange: "IKE_AUTH", response: true, spi: m.spi, error: "AUTHENTICATION_FAILED", eap: "failure", ra: true }, "EAP 실패 · AUTHENTICATION_FAILED", ctx, frameId);
        return true;
      }
      this.grant(outer, srcPort, dstPort, m.spi, e.nat, e.cid, u.name, true, ctx, frameId);
      return true;
    }
    // IKE_AUTH
    // IKE_AUTH 는 NAT-T 면 4500 으로 오므로 포트가 바뀐다 → 같은 바깥 주소·spi 의 협상을 찾는다
    const key = [...this.pending.keys()].find((k) => k.startsWith(`${outer.src}:`) && k.endsWith(`:${m.spi}`));
    const nat = key !== undefined ? this.pending.get(key) : undefined;
    if ((nat === undefined || key === undefined) && this.eapPending.has(`${outer.src}:${srcPort}:${m.spi}`)) {
      // 이미 EAP 요청을 보낸 협상의 IKE_AUTH 가 다시 옴: EAP 요청이 사라진 것 → 같은 응답을 다시 보낸다 (응답자는 마지막 응답을 다시 보낼 뿐)
      ctx.trace("vpn.eap", "L4", `원격 접속: ${outer.src} 가 IKE_AUTH 를 다시 보냄 (EAP 요청이 사라진 것) → EAP-MSCHAPv2 요청을 다시 보냄`, { from: outer.src, user: m.user, eap: "request", resent: true }, frameId);
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "IKE_AUTH", response: true, spi: m.spi, eap: "request", ra: true }, ctx, frameId);
      return true;
    }
    if (nat === undefined || key === undefined) {
      ctx.trace("vpn.drop", "L4", `원격 접속: IKE_SA_INIT 없이 온 IKE_AUTH (from ${outer.src}) → 무시`, { from: outer.src }, frameId);
      return true;
    }
    this.pending.delete(key);
    if ((m.auth ?? "") !== this.config.psk) {
      ctx.trace("vpn.drop", "L4", `원격 접속: ${outer.src} 의 인증 실패 — 사전 공유 키(PSK)가 다름 → AUTHENTICATION_FAILED`, { from: outer.src }, frameId);
      this.finalAuth(outer, srcPort, dstPort, false, { kind: "ike", exchange: "IKE_AUTH", response: true, spi: m.spi, error: "AUTHENTICATION_FAILED", ra: true }, "AUTHENTICATION_FAILED · PSK 다름", ctx, frameId);
      return true;
    }
    const cid = m.cid ?? outer.src;
    if (this.users.length) {
      // 계정 인증: PSK 는 맞음 → EAP 요청(MSCHAPv2 challenge)을 보내고 응답을 기다린다
      this.eapPending.set(`${outer.src}:${srcPort}:${m.spi}`, { nat, cid });
      ctx.trace(
        "vpn.eap",
        "L4",
        `원격 접속: ${outer.src} 의 사전 공유 키(PSK) 확인 → 이 서버는 사용자 계정 인증을 요구 → EAP-MSCHAPv2 요청(challenge)을 보냄${m.user ? ` (IDi: ${m.user})` : ""}`,
        { from: outer.src, user: m.user, eap: "request" },
        frameId,
      );
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "IKE_AUTH", response: true, spi: m.spi, eap: "request", ra: true }, ctx, frameId);
      return true;
    }
    this.grant(outer, srcPort, dstPort, m.spi, nat, cid, undefined, false, ctx, frameId);
    return true;
  }

  /** IKE_AUTH 의 마지막 응답: 기억해 두고 보낸다 (사라져서 같은 요청이 다시 오면 그대로 다시 보내려고). eapReq = EAP 응답(두 번째 IKE_AUTH)에 대한 것 */
  private finalAuth(outer: Ipv4Packet, srcPort: number, dstPort: number, eapReq: boolean, response: IkeMessage, label: string, ctx: NodeContext, frameId?: number): void {
    this.lastAuth.set(`${outer.src}:${srcPort}`, { spi: response.spi, eap: eapReq, response, label });
    this.sendIke(outer.dst, outer.src, dstPort, srcPort, response, ctx, frameId);
  }

  /** 인증을 마침: 가상 주소를 주고 그 클라이언트의 터널(SA)을 연다. 계정 인증(EAP)이면 user, eapReq = EAP 응답(두 번째 IKE_AUTH)으로 마침 */
  private grant(outer: Ipv4Packet, srcPort: number, dstPort: number, spi: number, nat: boolean, cid: string, user: string | undefined, eapReq: boolean, ctx: NodeContext, frameId?: number): void {
    const vip = this.allocate(cid);
    if (!vip) {
      ctx.trace("vpn.drop", "L4", `원격 접속: 가상 주소 풀 ${this.config.poolStart} ~ ${this.config.poolEnd} 이 다 찼거나 잘못됨 → INTERNAL_ADDRESS_FAILURE`, { from: outer.src }, frameId);
      this.finalAuth(outer, srcPort, dstPort, eapReq, { kind: "ike", exchange: "IKE_AUTH", response: true, spi, error: "INTERNAL_ADDRESS_FAILURE", ra: true }, "INTERNAL_ADDRESS_FAILURE", ctx, frameId);
      return;
    }
    for (const [k, c] of this.clients) if (c.cid === cid) this.clients.delete(k); // 같은 클라이언트의 옛 터널
    this.leases.set(cid, vip);
    this.clients.set(vip, { vip, cid, ...(user !== undefined ? { user } : {}), ...(eapReq ? { eap: true as const } : {}), peer: { ip: outer.src, port: srcPort }, natT: nat, spi, seq: 0 });
    ctx.trace(
      "vpn.up",
      "L4",
      `원격 접속 수립: ${outer.src} ${user !== undefined ? `사용자 ${user} 계정 인증 성공 (EAP-MSCHAPv2)` : "인증 성공"} → 가상 주소 ${vip} 를 주고, ${routesLabel(this.config.routes)} 로 가는 것만 터널로 보내라고 알림 (${nat ? "UDP 4500 (NAT-T) 안의 ESP" : "ESP"})`,
      { peer: outer.src, vip, natT: nat, ...(user !== undefined ? { user } : {}) },
      frameId,
    );
    this.finalAuth(
      outer,
      srcPort,
      dstPort,
      eapReq,
      { kind: "ike", exchange: "IKE_AUTH", response: true, spi, ra: true, ...(user !== undefined ? { eap: "success" as const } : {}), assigned: vip, routes: this.config.routes.map((r) => ({ ...r })) },
      `${user !== undefined ? "EAP 성공" : "인증 성공"} + 가상 주소 ${vip}`,
      ctx,
      frameId,
    );
  }

  /** 받은 ESP 가 원격 접속 클라이언트 것이면 그 클라이언트 (안쪽 출발지 = 가상 주소이고 SPI 가 그 터널의 것) */
  clientFor(outer: Ipv4Packet, esp: EspPacket): RaClientSa | undefined {
    if (!this.config.enabled) return undefined;
    const c = this.clients.get(esp.inner.src);
    return c && c.spi === esp.spi && outer.kind === "ipv4" ? c : undefined;
  }

  /** 이 주소가 가상 주소 풀 안인지 */
  inPool(ip: Ip): boolean {
    try {
      const n = ipToInt(ip);
      return this.config.enabled && n >= ipToInt(this.config.poolStart) && n <= ipToInt(this.config.poolEnd);
    } catch {
      return false;
    }
  }

  /**
   * 모르는 터널로 온 원격 접속 ESP (서버 설정이 바뀌었거나 이중화로 넘어와 SA 가 없음): 클라이언트에게 INVALID_SPI 로 알려
   * 다시 접속하게 한다 (그러지 않으면 클라이언트는 "연결됨" 인 채 보내는 것이 전부 사라진다)
   */
  orphan(outer: Ipv4Packet, srcPort: number | undefined, esp: EspPacket, ctx: NodeContext, frameId?: number): void {
    ctx.trace("vpn.drop", "L3", `원격 접속: ${outer.src} 에서 모르는 터널(SPI 0x${hex(esp.spi)})의 ESP → 드롭하고 INVALID_SPI 로 알림 (클라이언트가 다시 접속하도록)`, { from: outer.src }, frameId);
    const port = srcPort ?? IKE_PORT;
    this.sendIke(outer.dst, outer.src, srcPort !== undefined ? NAT_T_PORT : IKE_PORT, port, { kind: "ike", exchange: "INFORMATIONAL", response: true, spi: esp.spi, error: "INVALID_SPI", ra: true }, ctx, frameId);
  }

  /** 인증된 ESP 가 다른 바깥 주소·포트에서 왔으면(공유기 NAT 매핑 변경) 그쪽으로 답한다 */
  follow(c: RaClientSa, src: Ip, srcPort: number | undefined): void {
    c.peer = { ip: src, port: c.natT ? (srcPort ?? c.peer.port) : c.peer.port };
  }

  /** 가상 주소로 가는 패킷을 그 클라이언트 터널로 */
  sendTo(inner: Ipv4Packet, ctx: NodeContext, frameId?: number): boolean {
    const c = this.clients.get(inner.dst);
    if (!c) return false;
    const src = this.io.source(c.peer.ip);
    if (!src) {
      ctx.trace("vpn.drop", "L3", `원격 접속: 클라이언트 ${c.peer.ip} 로 가는 바깥 경로가 없음 → 드롭`, { dst: inner.dst }, frameId);
      return true;
    }
    const esp: EspPacket = { kind: "esp", spi: c.spi, seq: ++c.seq, inner };
    const outer = espPacket(src, c.peer, c.natT, esp);
    ctx.trace("vpn.encap", "L3", `원격 접속 캡슐화: ${inner.src} → ${inner.dst}(가상 주소) 패킷을 클라이언트 ${c.peer.ip}${c.natT ? `:${c.peer.port} (NAT-T)` : ""} 로 가는 ESP 에 담음 — SPI 0x${hex(c.spi)}`, { inner: `${inner.src}>${inner.dst}`, peer: c.peer.ip }, frameId);
    this.io.send(outer, ctx, frameId);
    return true;
  }

  rows(): string[][] {
    return [...this.clients.values()].map((c) => [c.user ?? "-", c.vip, `${c.peer.ip}${c.natT ? `:${c.peer.port}` : ""}`, c.natT ? "NAT-T" : "ESP"]);
  }

  /** 요약: 접속 수와, 계정으로 붙은 클라이언트는 "kim 10.99.0.10" 처럼 */
  clientsLabel(): string {
    const named = [...this.clients.values()].filter((c) => c.user);
    return `접속 ${this.clients.size}명${named.length ? ` (${named.map((c) => `${c.user} ${c.vip}`).join(", ")})` : ""}`;
  }
}

// ---------- 클라이언트 (노트북·PC) ----------

export type RaClientState = "off" | "init" | "auth" | "up" | "failed";

export class RaClient {
  config: RaClientConfig = { ...DEFAULT_RA_CLIENT };
  state: RaClientState = "off";
  vip: Ip | undefined;
  routes: { dest: Ip; prefix: number }[] = [];
  reason: string | undefined;
  /** eap: 계정 인증으로 IKE_AUTH 를 두 번 주고받음 — 이후 요청의 Message ID 가 하나 늘어난다 (strongSwan 로그 표시용) */
  private sa: { spi: number; natT: boolean; peer?: { ip: Ip; port: number }; seq: number; eap?: boolean } = { spi: 0, natT: false, seq: 0 };
  private attempts = 0;
  /** DPD 요청을 보내고 응답을 기다리는 중 */
  private dpdPending = false;
  private readonly ike: IkeRetransmit;

  constructor(
    private readonly io: RaIo & { myIp(): Ip | undefined; local?(dst: Ip): boolean },
    /** 클라이언트 식별 (MAC) */
    private readonly cid: string,
  ) {
    this.ike = new IkeRetransmit(RA_TIMER_TAG, (pkt, ctx) => this.io.send(pkt, ctx));
  }

  setConfig(cfg: RaClientConfig, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.config)) return;
    const wasUp = this.state === "up";
    if (wasUp) this.disconnect(ctx, "설정이 바뀜");
    this.config = { ...cfg };
    this.state = "off";
    this.reason = undefined;
    ctx.trace("vpn.config", "sys", cfg.enabled ? `원격 접속 VPN 켜짐: ${cfg.server ?? "(서버 주소 없음)"} 에 접속` : "원격 접속 VPN 꺼짐", { ...cfg });
    this.connect(ctx);
  }

  /** 주소가 있고 켜져 있으면 접속 시작 (주소를 받거나 링크가 살아날 때도 부른다) */
  connect(ctx: NodeContext): void {
    if (!this.config.enabled || this.state === "init" || this.state === "auth" || this.state === "up") return;
    const me = this.io.myIp();
    const server = this.config.server;
    if (!me || !server) return;
    this.attempts++;
    this.sa = { spi: spiOf(`ra:${this.cid}@${me}>${server}#${this.attempts}`), natT: false, seq: 0 };
    this.state = "init";
    this.reason = undefined;
    this.dpdPending = false;
    ctx.trace("vpn.ike", "L4", `원격 접속: 서버 ${server} 에 IKE_SA_INIT 요청 (NAT 감지용으로 내 주소 ${me} 를 적어 보냄)`, { peer: server, spi: this.sa.spi });
    this.request({ kind: "ike", exchange: "IKE_SA_INIT", response: false, spi: this.sa.spi, natSrc: me, natDst: server, ra: true }, IKE_PORT, ctx);
  }

  private request(msg: IkeMessage, port: number, ctx: NodeContext): void {
    const me = this.io.myIp();
    const server = this.config.server;
    if (!me || !server) return;
    this.ike.request(me, server, port, msg, ctx);
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const cur = this.state === "init" ? "IKE_SA_INIT" : this.state === "auth" ? "IKE_AUTH" : this.state === "up" && this.dpdPending ? "INFORMATIONAL" : undefined;
    const { verdict, step, tries } = this.ike.check(data, this.sa.spi, cur);
    if (verdict === "ignore") return;
    const dpd = step === "INFORMATIONAL";
    if (verdict === "retransmit") {
      // Message ID: EAP 로 IKE_AUTH 가 두 번이면 두 번째 IKE_AUTH 는 2, 그 뒤 DPD 는 3
      const mid = this.sa.eap ? (dpd ? 3 : step === "IKE_AUTH" ? 2 : undefined) : undefined;
      ctx.trace(dpd ? "vpn.dpd" : "vpn.ike", "L4", `원격 접속: ${dpd ? "DPD (INFORMATIONAL)" : step} 응답 없음 → 다시 보냄 (재전송 ${tries + 1}/${IKE_RETRANSMITS})`, { retransmit: tries + 1, step, ...(mid !== undefined ? { mid } : {}) });
      this.ike.resend(ctx);
      return;
    }
    if (dpd) {
      // 서버가 죽었거나 경로가 끊김: SA 를 지우고 끊김 상태로 ("다시 연결" 을 기다림)
      const server = this.config.server;
      this.dpdPending = false;
      this.ike.clear();
      this.state = "failed";
      this.reason = `DPD 에 서버 응답 없음 (재전송 ${IKE_RETRANSMITS}번 뒤 timeout) — 서버가 꺼졌거나 경로가 끊김. 경로를 확인한 뒤 "다시 연결"`;
      this.vip = undefined;
      this.routes = [];
      ctx.trace("vpn.drop", "L4", `원격 접속 끊김: DPD 에 서버 ${server} 응답 없음 (재전송 ${IKE_RETRANSMITS}번 뒤 timeout) → 서버가 죽었거나 경로가 끊긴 것으로 보고 SA 삭제. 경로를 확인한 뒤 "다시 연결"`, { dpd: "dead", peer: server });
      return;
    }
    this.fail(`${step} 응답 없음 (재전송 ${IKE_RETRANSMITS}번 뒤 timeout) — 서버 주소, 서버의 원격 접속 VPN, UDP 500·4500 이 막히지 않았는지 확인`, ctx);
  }

  private fail(why: string, ctx: NodeContext, frameId?: number): void {
    this.state = "failed";
    this.reason = why;
    this.ike.clear();
    ctx.trace("vpn.drop", "L4", `원격 접속 실패: ${why}`, {}, frameId);
  }

  /** 서버에서 온 IKE 응답. 처리했으면 true */
  handleIke(outer: Ipv4Packet, srcPort: number, dstPort: number, m: IkeMessage, ctx: NodeContext, frameId?: number): boolean {
    if (!m.ra || !m.response || outer.src !== this.config.server) return false;
    if (m.spi !== this.sa.spi) {
      // 내 IKE 포트로 온 지난 교환의 응답 (예: DPD 를 기다리다 "다시 연결" 한 뒤 늦게 온 DPD 응답): VPN 클라이언트가 받아 버린다 —
      // 호스트로 넘기면 "UDP 포트를 듣는 프로그램 없음" 으로 서버에 ICMP Port Unreachable 을 돌려보낸다
      if (dstPort !== IKE_PORT && dstPort !== NAT_T_PORT) return false;
      ctx.trace(
        m.dpd ? "vpn.dpd" : "vpn.ike",
        "L4",
        `원격 접속: 서버 ${outer.src} 의 ${m.exchange} 응답(SPI 0x${hex(m.spi)})이 지금 협상(SPI 0x${hex(this.sa.spi)})의 것이 아님 → 지난 교환의 늦게 온 응답으로 보고 무시`,
        { from: outer.src, late: true },
        frameId,
      );
      return true;
    }
    if (m.exchange === "INFORMATIONAL" && m.error === "INVALID_SPI") {
      if (this.state !== "up") return true;
      const byDpd = this.dpdPending;
      this.dpdPending = false;
      ctx.trace("vpn.ike", "L4", `원격 접속: ${byDpd ? "DPD 에 " : ""}서버가 이 터널을 모른다고 알림 (INVALID_SPI — 서버 설정 변경·이중화 전환 등) → ${byDpd ? "옛 SA 를 버리고 " : ""}다시 접속`, { from: outer.src }, frameId);
      this.state = "off";
      this.vip = undefined;
      this.routes = [];
      this.connect(ctx);
      return true;
    }
    if (m.exchange === "INFORMATIONAL" && m.dpd) {
      if (this.state !== "up" || !this.dpdPending) return true; // 이미 끝난 확인
      this.dpdPending = false;
      this.ike.clear();
      ctx.trace("vpn.dpd", "L4", `원격 접속: 서버 ${outer.src} 가 DPD 에 빈 응답 → 서버가 살아 있고 이 터널을 앎 → 터널 유지`, { from: outer.src, dpd: "alive", ...(this.sa.eap ? { mid: 3 } : {}) }, frameId);
      return true;
    }
    const me = outer.dst;
    const user = this.config.user?.trim() || undefined;
    if (m.exchange === "IKE_SA_INIT" && this.state === "init") {
      const { localNat, remoteNat, natT } = natAtInitiator(m, outer.src, me);
      this.sa = { ...this.sa, natT };
      this.state = "auth";
      const port = natT ? NAT_T_PORT : IKE_PORT;
      ctx.trace("vpn.ike", "L4", `원격 접속: IKE_SA_INIT 응답 (NAT ${natT ? `${localNat ? "내 앞(집 공유기)" : "상대 앞"}에 있음 → 여기부터 UDP 4500` : "없음"}) → IKE_AUTH 요청: PSK 인증 + 가상 주소 요청${user ? ` (IDi: 사용자 ${user})` : ""}`, { from: outer.src, natT, localNat, remoteNat }, frameId);
      this.request({ kind: "ike", exchange: "IKE_AUTH", response: false, spi: this.sa.spi, auth: this.config.psk, ra: true, cid: this.cid, ...(user ? { user } : {}) }, port, ctx);
      return true;
    }
    if (m.exchange === "IKE_AUTH" && this.state === "auth" && m.eap === "request") {
      // 서버가 계정 인증(EAP)을 요구: 계정이 있으면 비밀번호로 만든 응답을 한 번 더 IKE_AUTH 로
      if (!user) {
        this.fail("서버가 사용자 계정 인증(EAP)을 요구하는데 이 노트북에 계정이 없음 — 원격 접속 VPN 설정에 사용자 이름·비밀번호를 넣으세요", ctx, frameId);
        return true;
      }
      ctx.trace("vpn.eap", "L4", `원격 접속: 서버가 계정 인증(EAP-MSCHAPv2)을 요청 → 사용자 ${user} 의 비밀번호로 만든 응답을 IKE_AUTH 로 보냄`, { from: outer.src, user, eap: "response" }, frameId);
      this.sa = { ...this.sa, eap: true };
      this.request({ kind: "ike", exchange: "IKE_AUTH", response: false, spi: this.sa.spi, ra: true, cid: this.cid, user, eap: "response", eapSecret: this.config.password ?? "" }, this.sa.natT ? NAT_T_PORT : IKE_PORT, ctx);
      return true;
    }
    if (m.exchange === "IKE_AUTH" && this.state === "auth") {
      this.ike.clear();
      if (m.error || !m.assigned) {
        this.fail(
          m.eap === "failure"
            ? "서버가 계정 인증을 거절 (EAP 실패, AUTHENTICATION_FAILED) — 계정 또는 비밀번호가 틀림. 사용자 이름·비밀번호를 확인하세요"
            : m.error === "AUTHENTICATION_FAILED"
              ? "서버가 인증을 거절 (AUTHENTICATION_FAILED) — 사전 공유 키(PSK)가 다름"
              : "서버에 줄 가상 주소가 없음 (INTERNAL_ADDRESS_FAILURE) — 서버의 가상 주소 풀을 확인",
          ctx,
          frameId,
        );
        return true;
      }
      this.state = "up";
      this.vip = m.assigned;
      this.routes = (m.routes ?? []).map((r) => ({ ...r }));
      this.sa = { ...this.sa, peer: { ip: outer.src, port: srcPort }, seq: 0 };
      ctx.trace(
        "vpn.up",
        "L4",
        `원격 접속 연결됨: ${m.eap === "success" ? `계정 인증 성공 (EAP) → ` : ""}가상 주소 ${m.assigned} 를 받음 → ${routesLabel(this.routes)} 로 가는 패킷은 출발지를 ${m.assigned} 로 바꿔 ${this.sa.natT ? "UDP 4500 (NAT-T) 안의 ESP" : "ESP"} 로 회사에 보냄. 나머지는 평소처럼 인터넷으로 (split tunnel)`,
        { peer: outer.src, vip: m.assigned, natT: this.sa.natT, ...(m.eap === "success" ? { eap: "success" } : {}) },
        frameId,
      );
      return true;
    }
    return true;
  }

  /** 연결 해제: 서버에 Delete 를 알리고 터널을 내린다 */
  disconnect(ctx: NodeContext, why: string): void {
    if (this.state === "up") {
      const me = this.io.myIp();
      const server = this.config.server;
      if (me && server) {
        const port = this.sa.natT ? NAT_T_PORT : IKE_PORT;
        this.io.send({ kind: "ipv4", src: me, dst: server, ttl: 64, payload: { kind: "udp", srcPort: port, dstPort: port, payload: { kind: "ike", exchange: "INFORMATIONAL", response: false, spi: this.sa.spi, ra: true, cid: this.cid } } }, ctx);
      }
      ctx.trace("vpn.drop", "L4", `원격 접속 끊음 (${why}) → 서버에 Delete 를 알리고 가상 주소 ${this.vip} 를 내려놓음`, {});
    }
    this.state = "off";
    this.vip = undefined;
    this.routes = [];
    this.dpdPending = false;
  }

  /** 주소를 잃음·링크 다운: 터널이 끊긴 것으로 (서버에는 알릴 수 없다) */
  lost(ctx: NodeContext, why: string): void {
    if (this.state === "off" || this.state === "failed") return;
    ctx.trace("vpn.drop", "L4", `원격 접속 끊김: ${why}`, {});
    this.state = "off";
    this.vip = undefined;
    this.routes = [];
    this.dpdPending = false;
  }

  /** DPD 응답을 기다리는 중인지 (UI 표시용) */
  get dpdWaiting(): boolean {
    return this.dpdPending;
  }

  /**
   * 사용자의 "상대 확인 (DPD)": 지금 SA 의 경로로(NAT-T 면 UDP 4500) 빈 INFORMATIONAL 을 보내 서버가 살아 있고 이 터널을 아는지 확인.
   * 응답이 오면 터널 유지, 재전송 뒤에도 없으면 SA 를 지우고 끊김, 서버가 모르면(INVALID_SPI) 다시 접속
   */
  dpd(ctx: NodeContext): void {
    const me = this.io.myIp();
    const peer = this.sa.peer;
    if (!this.config.enabled || this.state !== "up" || !peer || !me) {
      ctx.trace("vpn.dpd", "L4", `원격 접속: 연결된 터널 없음 → DPD 를 보내지 않음 (먼저 접속하세요)`, { dpd: "none" });
      return;
    }
    if (this.dpdPending) {
      ctx.trace("vpn.dpd", "L4", `원격 접속: 이미 DPD 응답을 기다리는 중 → 다시 보내지 않음`, { dpd: "busy" });
      return;
    }
    this.dpdPending = true;
    const port = this.sa.natT ? NAT_T_PORT : IKE_PORT;
    ctx.trace("vpn.dpd", "L4", `원격 접속 DPD: 서버 ${peer.ip} 에 빈 INFORMATIONAL 요청 (SPI 0x${hex(this.sa.spi)}, UDP ${port}${this.sa.natT ? " NAT-T" : ""}) → 서버가 살아 있고 이 터널을 아는지 확인`, { peer: peer.ip, spi: this.sa.spi, dpd: "request", ...(this.sa.eap ? { mid: 3 } : {}) });
    this.ike.request(me, peer.ip, port, { kind: "ike", exchange: "INFORMATIONAL", response: false, spi: this.sa.spi, ra: true, cid: this.cid, dpd: true }, ctx, undefined, peer.port);
  }

  /**
   * 내보낼 패킷을 가로챈다: 사내 대역으로 가는 것이면 출발지를 가상 주소로 바꿔 ESP 로 감싸 서버로. 가로챘으면 true
   * (호스트의 다른 코드는 실제 주소를 쓰고, 여기서 가상 주소로 바꾼다 — 받을 때 되돌린다)
   */
  intercept(pkt: Ipv4Packet, ctx: NodeContext): boolean {
    if (this.state !== "up" || !this.vip || !this.sa.peer) return false;
    // 터널 자신(ESP·NAT-T·IKE)과 서버로 가는 것은 가로채지 않는다 — 가로채면 바깥 패킷이 다시 터널로 들어가 끝없이 감싼다
    const p = pkt.payload;
    if (p.kind === "esp" || (p.kind === "udp" && (p.payload.kind === "ike" || p.payload.kind === "esp")) || pkt.dst === this.config.server) return false;
    // 직접 연결된 서브넷(집 LAN)은 사내 대역과 겹쳐도 그대로 (더 구체적인 경로가 이긴다)
    if (this.io.local?.(pkt.dst)) return false;
    if (!inRoutes(pkt.dst, this.routes)) return false;
    const me = this.io.myIp();
    if (!me) return false;
    const inner: Ipv4Packet = { ...pkt, src: this.vip };
    const esp: EspPacket = { kind: "esp", spi: this.sa.spi, seq: ++this.sa.seq, inner };
    const peer = this.sa.peer;
    const outer = espPacket(me, peer, this.sa.natT, esp);
    ctx.trace("vpn.encap", "L3", `원격 접속 캡슐화: ${pkt.dst} 는 사내 대역 → 출발지를 가상 주소 ${this.vip} 로 바꿔 ${this.sa.natT ? "UDP 4500 (NAT-T) 안의 " : ""}ESP 로 서버 ${peer.ip} 에 보냄 — SPI 0x${hex(this.sa.spi)}`, { inner: `${this.vip}>${pkt.dst}`, peer: peer.ip });
    this.io.send(outer, ctx);
    return true;
  }

  /**
   * 받은 ESP: 내 터널 것이면 풀어서 (목적지 가상 주소 → 실제 주소로 되돌려) 돌려준다.
   * 내 터널 것이 아니면 undefined (호출한 쪽이 기록), 서버에서 왔지만 지금 SA 의 SPI 가 아니면 여기서 이유를 기록하고 null
   */
  unwrap(outer: Ipv4Packet, esp: EspPacket, ctx: NodeContext, frameId: number): Ipv4Packet | undefined | null {
    const inner = esp.inner;
    if (this.state !== "up" || !this.vip || outer.src !== this.config.server || inner.dst !== this.vip) return undefined;
    if (esp.spi !== this.sa.spi) {
      // 지난 SA 를 든 장비(물러난 이중화 옛 master 등)가 보낸 것: 지금 터널의 키가 아니라 풀 수 없다
      ctx.trace("vpn.drop", "L3", `원격 접속: 서버 ${outer.src} 에서 온 ESP 의 SPI 0x${hex(esp.spi)} 가 지금 터널(SPI 0x${hex(this.sa.spi)})의 것이 아님 (지난 SA) → 풀지 않고 드롭`, { from: outer.src }, frameId);
      return null;
    }
    const me = this.io.myIp();
    if (!me) return undefined;
    if (!inRoutes(inner.src, this.routes)) {
      ctx.trace("vpn.drop", "L3", `원격 접속: 터널로 온 패킷의 출발지 ${inner.src} 가 사내 대역이 아님 → 드롭`, {}, frameId);
      return undefined;
    }
    ctx.trace("vpn.decap", "L3", `원격 접속 복호화: 서버 ${outer.src} 에서 온 ESP 를 풀어 ${inner.src} → ${inner.dst}(내 가상 주소) 패킷을 꺼냄`, { from: outer.src, inner: `${inner.src}>${inner.dst}` }, frameId);
    return { ...inner, dst: me };
  }

  /** 사용자의 "다시 연결": DPD 를 기다리던 중이면 그 확인도 끝낸다 (늦게 온 DPD 응답은 handleIke 가 무시) */
  reconnect(ctx: NodeContext): void {
    if (this.state === "up") this.disconnect(ctx, "다시 연결");
    this.state = "off";
    this.dpdPending = false;
    this.ike.clear();
    this.connect(ctx);
  }

  summary(): string | undefined {
    if (!this.config.enabled) return undefined;
    if (this.state === "up") return `연결됨 · 가상 주소 ${this.vip} · ${routesLabel(this.routes)} 는 터널로${this.dpdPending ? " · DPD 확인 중" : ""}`;
    if (this.state === "init" || this.state === "auth") return "연결 중 (IKE 협상)";
    if (this.state === "failed") return `${this.reason?.startsWith("DPD") ? "끊김" : "실패"} · ${this.reason ?? ""}`;
    return "대기 (주소를 받으면 접속)";
  }
}
