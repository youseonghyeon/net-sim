// 원격 접속 VPN (IPsec IKEv2 원격 접속 축소판): 재택 노트북 한 대가 인터넷 너머 회사 VPN 장비에 붙어, 사내 대역을 사설 주소로 쓴다.
// 사이트 간 VPN(vpn.ts)은 두 사무실의 장비끼리 대역 대 대역을 잇지만, 원격 접속은
//  - 클라이언트가 여럿 (서버는 클라이언트마다 터널을 따로 둔다)
//  - 서버가 클라이언트에게 가상 주소(풀에서 하나)와 터널로 보낼 사내 대역(split tunnel)을 알려 준다 (IKE_AUTH 의 Configuration Payload)
//  - 클라이언트가 보내는 안쪽 패킷의 출발지는 그 가상 주소 — 사내 서버는 가상 주소로 답하고, 회사 VPN 장비가 그 주소를 가진 터널로 돌려보낸다
// 협상은 사이트 간과 같은 IKE_SA_INIT(NAT 감지) → IKE_AUTH(PSK). 집 공유기 NAT 뒤라 보통 UDP 4500 (NAT-T) 로 간다.
// 연결 해제는 INFORMATIONAL(Delete) 로 알려 가상 주소를 돌려준다. 재협상·DPD·사용자 계정 인증(EAP)은 생략.
import { ipToInt, intToIp, sameSubnet, type Ip } from "../addr";
import { IKE_PORT, NAT_T_PORT, type EspPacket, type IkeMessage, type Ipv4Packet } from "../packet";
import type { NodeContext } from "./node";

export interface RaServerConfig {
  enabled: boolean;
  psk: string;
  /** 가상 주소 풀 */
  poolStart: Ip;
  poolEnd: Ip;
  /** 클라이언트에게 알려 줄 사내 대역 (이 대역으로 가는 것만 터널로) */
  routes: { dest: Ip; prefix: number }[];
}

export const DEFAULT_RA_SERVER: RaServerConfig = { enabled: false, psk: "", poolStart: "10.99.0.10", poolEnd: "10.99.0.50", routes: [] };

export interface RaClientConfig {
  enabled: boolean;
  /** 회사 VPN 장비의 공인 주소 */
  server?: Ip;
  psk: string;
}

export const DEFAULT_RA_CLIENT: RaClientConfig = { enabled: false, psk: "" };
export const RA_TIMER_TAG = "ra-ike";
const RA_TIMEOUT = 1000;
const RA_RETRANSMITS = 2;

const hex = (n: number) => n.toString(16).padStart(8, "0");
function spiOf(a: string, b: string, n: number): number {
  let h = 0x811c9dc5;
  for (const ch of `ra:${a}>${b}#${n}`) h = Math.imul(h ^ ch.charCodeAt(0), 0x01000193) >>> 0;
  return h >>> 0 || 1;
}
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

  constructor(private readonly io: RaIo) {}

  setConfig(cfg: RaServerConfig, ctx: NodeContext): void {
    if (JSON.stringify(cfg) === JSON.stringify(this.config)) return;
    this.config = { ...cfg, routes: cfg.routes.map((r) => ({ ...r })) };
    this.clients.clear();
    this.pending.clear();
    this.leases.clear();
    ctx.trace(
      "vpn.config",
      "sys",
      cfg.enabled
        ? `원격 접속 VPN 서버 켜짐: 접속한 클라이언트에게 ${cfg.poolStart} ~ ${cfg.poolEnd} 에서 가상 주소를 주고, ${routesLabel(cfg.routes)} 로 가는 것만 터널로 보내게 알림 (IKE UDP ${IKE_PORT})`
        : "원격 접속 VPN 서버 꺼짐",
      { ...cfg },
    );
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
    this.io.send({ kind: "ipv4", src, dst, ttl: 64, payload: { kind: "udp", srcPort, dstPort, payload: m } }, ctx, frameId);
  }

  /** 원격 접속 IKE 메시지. 처리했으면 true */
  handleIke(outer: Ipv4Packet, srcPort: number, dstPort: number, m: IkeMessage, ctx: NodeContext, frameId?: number): boolean {
    if (!this.config.enabled || !m.ra || m.response) return false;
    const me = outer.dst;
    if (m.exchange === "IKE_SA_INIT") {
      const nat = m.natSrc !== outer.src || m.natDst !== me;
      this.pending.set(`${outer.src}:${srcPort}:${m.spi}`, nat);
      ctx.trace("vpn.ike", "L4", `원격 접속: ${outer.src} 의 IKE_SA_INIT → 응답. NAT 감지: ${nat ? "있음 (클라이언트가 공유기 뒤) → 이후 UDP 4500 (NAT-T)" : "없음"}`, { from: outer.src, nat, remoteNat: m.natSrc !== outer.src, localNat: m.natDst !== me }, frameId);
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "IKE_SA_INIT", response: true, spi: m.spi, nat, natSrc: me, natDst: outer.src, ra: true }, ctx, frameId);
      return true;
    }
    if (m.exchange === "INFORMATIONAL") {
      const c = [...this.clients.values()].find((x) => x.cid === m.cid);
      if (m.cid) this.leases.delete(m.cid); // 끊었으니 가상 주소를 풀로 돌려준다
      if (c) {
        this.clients.delete(c.vip);
        ctx.trace("vpn.drop", "L4", `원격 접속: ${c.peer.ip} 가 연결을 끊음 (Delete) → 가상 주소 ${c.vip} 의 터널을 내림`, { vip: c.vip }, frameId);
      }
      return true;
    }
    // IKE_AUTH
    // IKE_AUTH 는 NAT-T 면 4500 으로 오므로 포트가 바뀐다 → 같은 바깥 주소·spi 의 협상을 찾는다
    const key = [...this.pending.keys()].find((k) => k.startsWith(`${outer.src}:`) && k.endsWith(`:${m.spi}`));
    const nat = key !== undefined ? this.pending.get(key) : undefined;
    if (nat === undefined || key === undefined) {
      ctx.trace("vpn.drop", "L4", `원격 접속: IKE_SA_INIT 없이 온 IKE_AUTH (from ${outer.src}) → 무시`, { from: outer.src }, frameId);
      return true;
    }
    this.pending.delete(key);
    if ((m.auth ?? "") !== this.config.psk) {
      ctx.trace("vpn.drop", "L4", `원격 접속: ${outer.src} 의 인증 실패 — 사전 공유 키(PSK)가 다름 → AUTHENTICATION_FAILED`, { from: outer.src }, frameId);
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "IKE_AUTH", response: true, spi: m.spi, error: "AUTHENTICATION_FAILED", ra: true }, ctx, frameId);
      return true;
    }
    const cid = m.cid ?? outer.src;
    const vip = this.allocate(cid);
    if (!vip) {
      ctx.trace("vpn.drop", "L4", `원격 접속: 가상 주소 풀 ${this.config.poolStart} ~ ${this.config.poolEnd} 이 다 찼거나 잘못됨 → INTERNAL_ADDRESS_FAILURE`, { from: outer.src }, frameId);
      this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "IKE_AUTH", response: true, spi: m.spi, error: "INTERNAL_ADDRESS_FAILURE", ra: true }, ctx, frameId);
      return true;
    }
    for (const [k, c] of this.clients) if (c.cid === cid) this.clients.delete(k); // 같은 클라이언트의 옛 터널
    this.leases.set(cid, vip);
    this.clients.set(vip, { vip, cid, peer: { ip: outer.src, port: srcPort }, natT: nat, spi: m.spi, seq: 0 });
    ctx.trace(
      "vpn.up",
      "L4",
      `원격 접속 수립: ${outer.src} 인증 성공 → 가상 주소 ${vip} 를 주고, ${routesLabel(this.config.routes)} 로 가는 것만 터널로 보내라고 알림 (${nat ? "UDP 4500 (NAT-T) 안의 ESP" : "ESP"})`,
      { peer: outer.src, vip, natT: nat },
      frameId,
    );
    this.sendIke(me, outer.src, dstPort, srcPort, { kind: "ike", exchange: "IKE_AUTH", response: true, spi: m.spi, ra: true, assigned: vip, routes: this.config.routes.map((r) => ({ ...r })) }, ctx, frameId);
    return true;
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
    const outer: Ipv4Packet = c.natT
      ? { kind: "ipv4", src, dst: c.peer.ip, ttl: 64, payload: { kind: "udp", srcPort: NAT_T_PORT, dstPort: c.peer.port, payload: esp } }
      : { kind: "ipv4", src, dst: c.peer.ip, ttl: 64, payload: esp };
    ctx.trace("vpn.encap", "L3", `원격 접속 캡슐화: ${inner.src} → ${inner.dst}(가상 주소) 패킷을 클라이언트 ${c.peer.ip}${c.natT ? `:${c.peer.port} (NAT-T)` : ""} 로 가는 ESP 에 담음 — SPI 0x${hex(c.spi)}`, { inner: `${inner.src}>${inner.dst}`, peer: c.peer.ip }, frameId);
    this.io.send(outer, ctx, frameId);
    return true;
  }

  rows(): string[][] {
    return [...this.clients.values()].map((c) => [c.vip, `${c.peer.ip}${c.natT ? `:${c.peer.port}` : ""}`, c.natT ? "NAT-T" : "ESP"]);
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
  private sa: { spi: number; natT: boolean; peer?: { ip: Ip; port: number }; seq: number } = { spi: 0, natT: false, seq: 0 };
  private attempts = 0;
  private last: { msg: IkeMessage; port: number; tries: number } | undefined;

  constructor(
    private readonly io: RaIo & { myIp(): Ip | undefined; local?(dst: Ip): boolean },
    /** 클라이언트 식별 (MAC) */
    private readonly cid: string,
  ) {}

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
    this.sa = { spi: spiOf(`${this.cid}@${me}`, server, this.attempts), natT: false, seq: 0 };
    this.state = "init";
    this.reason = undefined;
    ctx.trace("vpn.ike", "L4", `원격 접속: 서버 ${server} 에 IKE_SA_INIT 요청 (NAT 감지용으로 내 주소 ${me} 를 적어 보냄)`, { peer: server, spi: this.sa.spi });
    this.request({ kind: "ike", exchange: "IKE_SA_INIT", response: false, spi: this.sa.spi, natSrc: me, natDst: server, ra: true }, IKE_PORT, ctx);
  }

  private request(msg: IkeMessage, port: number, ctx: NodeContext, tries = 0): void {
    const me = this.io.myIp();
    const server = this.config.server;
    if (!me || !server) return;
    this.last = { msg, port, tries };
    this.io.send({ kind: "ipv4", src: me, dst: server, ttl: 64, payload: { kind: "udp", srcPort: port, dstPort: port, payload: msg } }, ctx);
    ctx.timer(RA_TIMEOUT, RA_TIMER_TAG, { spi: msg.spi, step: msg.exchange, tries });
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const { spi, step, tries } = data as { spi: number; step: string; tries: number };
    const cur = this.state === "init" ? "IKE_SA_INIT" : this.state === "auth" ? "IKE_AUTH" : undefined;
    const last = this.last;
    if (spi !== this.sa.spi || step !== cur || !last || last.tries !== tries) return;
    if (tries < RA_RETRANSMITS) {
      ctx.trace("vpn.ike", "L4", `원격 접속: ${step} 응답 없음 → 다시 보냄 (재전송 ${tries + 1}/${RA_RETRANSMITS})`, { retransmit: tries + 1, step });
      this.request(last.msg, last.port, ctx, tries + 1);
      return;
    }
    this.fail(`${step} 응답 없음 (재전송 ${RA_RETRANSMITS}번 뒤 timeout) — 서버 주소, 서버의 원격 접속 VPN, UDP 500·4500 이 막히지 않았는지 확인`, ctx);
  }

  private fail(why: string, ctx: NodeContext, frameId?: number): void {
    this.state = "failed";
    this.reason = why;
    this.last = undefined;
    ctx.trace("vpn.drop", "L4", `원격 접속 실패: ${why}`, {}, frameId);
  }

  /** 서버에서 온 IKE 응답. 처리했으면 true */
  handleIke(outer: Ipv4Packet, srcPort: number, m: IkeMessage, ctx: NodeContext, frameId?: number): boolean {
    if (!m.ra || !m.response || outer.src !== this.config.server || m.spi !== this.sa.spi) return false;
    if (m.exchange === "INFORMATIONAL" && m.error === "INVALID_SPI") {
      if (this.state !== "up") return true;
      ctx.trace("vpn.ike", "L4", `원격 접속: 서버가 이 터널을 모른다고 알림 (INVALID_SPI — 서버 설정 변경·이중화 전환 등) → 다시 접속`, { from: outer.src }, frameId);
      this.state = "off";
      this.vip = undefined;
      this.routes = [];
      this.connect(ctx);
      return true;
    }
    const me = outer.dst;
    if (m.exchange === "IKE_SA_INIT" && this.state === "init") {
      const localNat = m.natDst !== undefined && m.natDst !== me;
      const remoteNat = m.natSrc !== undefined && m.natSrc !== outer.src;
      const natT = m.nat === true || localNat || remoteNat;
      this.sa = { ...this.sa, natT };
      this.state = "auth";
      const port = natT ? NAT_T_PORT : IKE_PORT;
      ctx.trace("vpn.ike", "L4", `원격 접속: IKE_SA_INIT 응답 (NAT ${natT ? `${localNat ? "내 앞(집 공유기)" : "상대 앞"}에 있음 → 여기부터 UDP 4500` : "없음"}) → IKE_AUTH 요청: PSK 인증 + 가상 주소 요청`, { from: outer.src, natT, localNat, remoteNat }, frameId);
      this.request({ kind: "ike", exchange: "IKE_AUTH", response: false, spi: this.sa.spi, auth: this.config.psk, ra: true, cid: this.cid }, port, ctx);
      return true;
    }
    if (m.exchange === "IKE_AUTH" && this.state === "auth") {
      this.last = undefined;
      if (m.error || !m.assigned) {
        this.fail(m.error === "AUTHENTICATION_FAILED" ? "서버가 인증을 거절 (AUTHENTICATION_FAILED) — 사전 공유 키(PSK)가 다름" : "서버에 줄 가상 주소가 없음 (INTERNAL_ADDRESS_FAILURE) — 서버의 가상 주소 풀을 확인", ctx, frameId);
        return true;
      }
      this.state = "up";
      this.vip = m.assigned;
      this.routes = (m.routes ?? []).map((r) => ({ ...r }));
      this.sa = { ...this.sa, peer: { ip: outer.src, port: srcPort }, seq: 0 };
      ctx.trace(
        "vpn.up",
        "L4",
        `원격 접속 연결됨: 가상 주소 ${m.assigned} 를 받음 → ${routesLabel(this.routes)} 로 가는 패킷은 출발지를 ${m.assigned} 로 바꿔 ${this.sa.natT ? "UDP 4500 (NAT-T) 안의 ESP" : "ESP"} 로 회사에 보냄. 나머지는 평소처럼 인터넷으로 (split tunnel)`,
        { peer: outer.src, vip: m.assigned, natT: this.sa.natT },
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
  }

  /** 주소를 잃음·링크 다운: 터널이 끊긴 것으로 (서버에는 알릴 수 없다) */
  lost(ctx: NodeContext, why: string): void {
    if (this.state === "off" || this.state === "failed") return;
    ctx.trace("vpn.drop", "L4", `원격 접속 끊김: ${why}`, {});
    this.state = "off";
    this.vip = undefined;
    this.routes = [];
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
    const outer: Ipv4Packet = this.sa.natT
      ? { kind: "ipv4", src: me, dst: peer.ip, ttl: 64, payload: { kind: "udp", srcPort: NAT_T_PORT, dstPort: peer.port, payload: esp } }
      : { kind: "ipv4", src: me, dst: peer.ip, ttl: 64, payload: esp };
    ctx.trace("vpn.encap", "L3", `원격 접속 캡슐화: ${pkt.dst} 는 사내 대역 → 출발지를 가상 주소 ${this.vip} 로 바꿔 ${this.sa.natT ? "UDP 4500 (NAT-T) 안의 " : ""}ESP 로 서버 ${peer.ip} 에 보냄 — SPI 0x${hex(this.sa.spi)}`, { inner: `${this.vip}>${pkt.dst}`, peer: peer.ip });
    this.io.send(outer, ctx);
    return true;
  }

  /** 받은 ESP: 내 터널 것이면 풀어서 (목적지 가상 주소 → 실제 주소로 되돌려) 돌려준다. 아니면 undefined */
  unwrap(outer: Ipv4Packet, inner: Ipv4Packet, ctx: NodeContext, frameId: number): Ipv4Packet | undefined {
    if (this.state !== "up" || !this.vip || outer.src !== this.config.server || inner.dst !== this.vip) return undefined;
    const me = this.io.myIp();
    if (!me) return undefined;
    if (!inRoutes(inner.src, this.routes)) {
      ctx.trace("vpn.drop", "L3", `원격 접속: 터널로 온 패킷의 출발지 ${inner.src} 가 사내 대역이 아님 → 드롭`, {}, frameId);
      return undefined;
    }
    ctx.trace("vpn.decap", "L3", `원격 접속 복호화: 서버 ${outer.src} 에서 온 ESP 를 풀어 ${inner.src} → ${inner.dst}(내 가상 주소) 패킷을 꺼냄`, { from: outer.src, inner: `${inner.src}>${inner.dst}` }, frameId);
    return { ...inner, dst: me };
  }

  /** 사용자의 "다시 연결" */
  reconnect(ctx: NodeContext): void {
    if (this.state === "up") this.disconnect(ctx, "다시 연결");
    this.state = "off";
    this.connect(ctx);
  }

  summary(): string | undefined {
    if (!this.config.enabled) return undefined;
    if (this.state === "up") return `연결됨 · 가상 주소 ${this.vip} · ${routesLabel(this.routes)} 는 터널로`;
    if (this.state === "init" || this.state === "auth") return "연결 중 (IKE 협상)";
    if (this.state === "failed") return `실패 · ${this.reason ?? ""}`;
    return "대기 (주소를 받으면 접속)";
  }
}
