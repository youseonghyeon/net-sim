// DDNS (동적 DNS — GL.iNet 의 glddns.com, ipTIME 의 iptime.org): 가정용 회선은 공인 주소가 바뀐다. 공유기가 "이 이름은 지금 내 주소" 를
// DDNS 서버에 알리고(갱신), 밖의 기기는 주소 대신 이름으로 접속한다(VPN 서버 주소를 이름으로).
// - 서버는 요청의 출발지 주소를 등록한다: 공유기 앞에 다른 NAT 가 있으면 그 NAT 의 공인 주소가 등록된다 (공유기 WAN 주소가 아니라)
// - 갱신 시점: WAN 이 주소를 받거나 바뀔 때, 설정이 바뀔 때, 그리고 10분마다(배경 타이머 — 앞 NAT 의 주소가 바뀐 것은 공유기가 모른다)
// - 이름은 기기마다 하나 (다른 기기가 이미 등록한 이름이면 badauth)
// 실제는 HTTPS(dyndns2) — 여기서는 UDP 8245 한 쌍으로 줄였다. 이름의 TTL 은 30초(캐시가 옛 주소를 오래 들고 있지 않게)
import type { Ip } from "../addr";
import { DDNS_PORT, type DdnsMessage, type Ipv4Packet } from "../packet";
import type { NodeContext } from "./node";

/** DDNS 갱신 서버 (인터넷 노드가 흉내) */
export const DDNS_SERVER: Ip = "198.51.100.60";
/** DDNS 이름의 영역 (이 아래 이름만 등록·응답) */
export const DDNS_ZONE = "glddns.com";
export const DDNS_TIMER_TAG = "ddns-timer";
/** DDNS 이름의 TTL(초): 주소가 바뀌므로 짧게 — DNS 서버·리졸버 캐시가 이만큼만 기억한다 */
export const DDNS_TTL = 30;
/** 응답을 기다리는 시간과 재전송 횟수 */
const DDNS_TIMEOUT = 2000;
const DDNS_TRIES = 3;
/** 주기 확인 (배경 타이머): 앞 NAT 의 주소가 바뀌어도 알아채게 (ddns-scripts 의 check_interval 기본 10분) */
export const DDNS_CHECK = 600_000;

export interface DdnsConfig {
  enabled: boolean;
  /** 전체 이름 (예: myhome.glddns.com) */
  hostname: string;
}

export type DdnsState = "off" | "updating" | "ok" | "failed";

/** 공유기의 DDNS 클라이언트 */
export class DdnsClient {
  config: DdnsConfig = { enabled: false, hostname: "" };
  state: DdnsState = "off";
  /** 서버가 등록했다고 알려 준 주소 */
  ip: Ip | undefined;
  reason: string | undefined;
  /** 마지막으로 갱신을 보낼 때의 WAN 주소 (바뀌면 다시 보낸다) */
  private sentFrom: Ip | undefined;
  private pending: { id: number; tries: number } | undefined;
  private idSeq: number;
  private tick = 0;

  constructor(
    private readonly io: { wanIp(): Ip | undefined; device: string; send(pkt: Ipv4Packet, ctx: NodeContext): void },
    seed: number,
  ) {
    this.idSeq = 0x300 + (Math.abs(seed) % 0x1000);
  }

  setConfig(cfg: DdnsConfig, ctx: NodeContext): void {
    if (cfg.enabled === this.config.enabled && cfg.hostname === this.config.hostname) return;
    const wasOn = this.config.enabled;
    this.config = { ...cfg };
    this.pending = undefined;
    this.sentFrom = undefined;
    this.ip = undefined;
    this.reason = undefined;
    this.state = cfg.enabled ? "updating" : "off";
    if (!cfg.enabled) {
      if (wasOn) ctx.trace("ddns.config", "sys", `DDNS 꺼짐 — 서버의 이름은 마지막 주소 그대로 남는다 (지우지 않음)`, {});
      return;
    }
    ctx.trace("ddns.config", "sys", `DDNS 켜짐: ${cfg.hostname} 을(를) 이 공유기의 공인 주소로 등록 (서버 ${DDNS_SERVER}, WAN 주소가 바뀔 때마다·10분마다 갱신)`, { hostname: cfg.hostname });
    this.update(ctx, "설정");
    this.arm(ctx);
  }

  /** WAN 주소가 생기거나 바뀜 */
  onWanAddress(ctx: NodeContext): void {
    if (!this.config.enabled) return;
    const ip = this.io.wanIp();
    if (!ip || ip === this.sentFrom) return;
    this.update(ctx, this.sentFrom ? `WAN 주소가 ${this.sentFrom} → ${ip} 로 바뀜` : `WAN 주소 ${ip} 를 받음`);
  }

  /** 갱신 요청을 보낸다 */
  update(ctx: NodeContext, why: string, tries = 1): void {
    const src = this.io.wanIp();
    if (!this.config.enabled || !src) return;
    const id = tries === 1 ? ++this.idSeq : this.pending!.id;
    this.pending = { id, tries };
    this.sentFrom = src;
    if (this.state !== "ok") this.state = "updating";
    ctx.trace("ddns.update", "app", `DDNS: ${why} → ${DDNS_SERVER} 에 "${this.config.hostname} 은 지금 이 요청을 보낸 주소" 갱신 요청${tries > 1 ? ` (재전송 ${tries}/${DDNS_TRIES})` : ""}`, { hostname: this.config.hostname, tries });
    const m: DdnsMessage = { kind: "ddns", op: "update", id, hostname: this.config.hostname, device: this.io.device };
    this.io.send({ kind: "ipv4", src, dst: DDNS_SERVER, ttl: 64, payload: { kind: "udp", srcPort: DDNS_PORT, dstPort: DDNS_PORT, payload: m } }, ctx);
    ctx.timer(DDNS_TIMEOUT, DDNS_TIMER_TAG, { id, tries });
  }

  private arm(ctx: NodeContext): void {
    ctx.timer(DDNS_CHECK, DDNS_TIMER_TAG, { periodic: ++this.tick }, true);
  }

  onTimer(data: unknown, ctx: NodeContext): void {
    const d = data as { id?: number; tries?: number; periodic?: number };
    if (d.periodic !== undefined) {
      if (d.periodic !== this.tick || !this.config.enabled) return;
      if (!this.pending) this.update(ctx, "주기 확인 (10분 — 앞쪽 NAT 의 공인 주소가 바뀌어도 알아채게)");
      this.arm(ctx);
      return;
    }
    if (!this.pending || this.pending.id !== d.id || this.pending.tries !== d.tries) return;
    if ((d.tries ?? 1) < DDNS_TRIES) {
      this.update(ctx, `${DDNS_TIMEOUT / 1000}초 동안 응답 없음`, (d.tries ?? 1) + 1);
      return;
    }
    this.pending = undefined;
    this.state = "failed";
    this.reason = `DDNS 서버 ${DDNS_SERVER} 가 응답하지 않음 (WAN·인터넷 연결 확인)`;
    ctx.trace("ddns.failed", "app", `DDNS 갱신 실패: ${this.reason} — 다음 주소 변경·주기 확인 때 다시 시도`, { hostname: this.config.hostname });
  }

  /** 서버 응답 */
  handle(m: DdnsMessage, frameId: number, ctx: NodeContext): void {
    if (!this.pending || m.id !== this.pending.id) {
      ctx.trace("ddns.update", "app", `DDNS: 기다리지 않는 응답 (id ${m.id}) → 무시`, { late: true }, frameId);
      return;
    }
    this.pending = undefined;
    if (m.result === "good" || m.result === "nochg") {
      this.state = "ok";
      this.ip = m.ip;
      this.reason = undefined;
      ctx.trace("ddns.ok", "app", m.result === "good" ? `DDNS 등록됨: ${m.hostname} = ${m.ip} (서버가 본 출발지 주소${m.ip !== this.sentFrom ? ` — WAN 주소 ${this.sentFrom} 가 아님: 앞에 NAT 가 있어 그 공인 주소가 등록됨` : ""})` : `DDNS: ${m.hostname} 은 이미 ${m.ip} (그대로, nochg)`, { hostname: m.hostname, ip: m.ip, result: m.result }, frameId);
      return;
    }
    this.state = "failed";
    this.reason = m.result === "badauth" ? `${m.hostname} 은 다른 기기가 등록한 이름 (badauth) — 다른 이름을 쓰세요` : `${m.hostname} 은 ${DDNS_ZONE} 아래 이름이 아님 (notfqdn)`;
    ctx.trace("ddns.failed", "app", `DDNS 거절: ${this.reason}`, { hostname: m.hostname, result: m.result }, frameId);
  }

  summary(): string | undefined {
    if (!this.config.enabled) return undefined;
    if (this.state === "ok") return `${this.config.hostname} = ${this.ip}`;
    if (this.state === "failed") return `실패 · ${this.reason}`;
    return `${this.config.hostname} · 갱신 중 (WAN 주소를 기다림)`;
  }
}

/** DDNS 서버 (인터넷 노드): 이름 → 주소·등록한 기기 */
export class DdnsService {
  readonly records = new Map<string, { ip: Ip; device: string; at: number }>();

  /** 갱신 요청 처리: 등록하고 응답 메시지를 돌려준다 */
  handle(from: Ip, m: DdnsMessage, ctx: NodeContext, frameId?: number): DdnsMessage {
    const name = m.hostname.trim().toLowerCase().replace(/\.$/, "");
    const reply = (result: DdnsMessage["result"], ip?: Ip): DdnsMessage => ({ kind: "ddns", op: "response", id: m.id, hostname: name, result, ...(ip ? { ip } : {}) });
    if (!name.endsWith(`.${DDNS_ZONE}`) || name.length <= DDNS_ZONE.length + 1) {
      ctx.trace("ddns.server", "app", `DDNS 서버: ${name} 은(는) ${DDNS_ZONE} 아래 이름이 아님 → notfqdn`, { name, result: "notfqdn" }, frameId);
      return reply("notfqdn");
    }
    const cur = this.records.get(name);
    if (cur && cur.device !== m.device) {
      ctx.trace("ddns.server", "app", `DDNS 서버: ${name} 은(는) 다른 기기(${cur.device})가 등록한 이름 → badauth (기존 ${cur.ip} 유지)`, { name, result: "badauth" }, frameId);
      return reply("badauth");
    }
    if (cur && cur.ip === from) {
      cur.at = ctx.now;
      ctx.trace("ddns.server", "app", `DDNS 서버: ${name} = ${from} 그대로 → nochg`, { name, ip: from, result: "nochg" }, frameId);
      return reply("nochg", from);
    }
    this.records.set(name, { ip: from, device: m.device ?? "", at: ctx.now });
    ctx.trace("ddns.server", "app", `DDNS 서버: ${name} 의 A 레코드를 요청의 출발지 ${from} 로${cur ? ` 바꿈 (전: ${cur.ip})` : " 등록"} → good. 이제 공인 DNS 가 이 이름을 ${from} 로 답한다`, { name, ip: from, result: "good" }, frameId);
    return reply("good", from);
  }

  lookup(name: string): Ip | undefined {
    return this.records.get(name.trim().toLowerCase().replace(/\.$/, ""))?.ip;
  }

  rows(): string[][] {
    return [...this.records.entries()].map(([n, r]) => [n, r.ip, r.device, `${r.at}ms`]);
  }
}
