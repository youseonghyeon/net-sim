// 포트 공개 (docker run -p 식): 장비 자신의 주소로 온 TCP 연결을 안쪽 대상(컨테이너·VM)으로 넘긴다.
// 도커의 userland proxy(docker-proxy)·Docker Desktop 의 포트 포워더처럼 FULLNAT 으로 흉내 낸다:
//   목적지 = 대상 주소:포트, 출발지 = 이 장비가 대상 쪽으로 나가는 인터페이스 주소:프록시 포트 → 대상은 "이 장비가 보낸 연결" 로 본다.
// 포트 포워딩(NAT 박스의 DNAT)과 다른 점:
//   - 바깥 인터페이스만이 아니라 장비 자신의 어느 주소로 와도 받는다 (bind 0.0.0.0) — 같은 장비 안(lo)·안쪽 브리지에서 와도
//   - bind 를 127.0.0.1 처럼 한 주소로 좁히면 그 주소로 온 것만 (docker run -p 127.0.0.1:5432:5432 — LAN 에서는 못 들어옴)
//   - 응답이 이 장비로 돌아오므로 대상의 기본 게이트웨이가 어디든 된다
// TCP 만 (UDP 공개는 생략). 흐름은 양쪽 FIN 뒤 ACK·RST 면 끝난 것으로 보고 2초(TIME_WAIT) 뒤 다음 연결 때 치운다 (타이머 없음)
import type { Ip } from "../addr";
import type { Ipv4Packet, TcpSegment } from "../packet";
import type { NodeContext } from "./node";

export interface PublishRule {
  /** 이 장비에서 받을 포트 (호스트 포트) */
  port: number;
  /** 받을 주소: "0.0.0.0" = 이 장비의 모든 주소, 그 밖은 그 주소로 온 것만 */
  bind: Ip;
  /** 넘길 대상 (컨테이너·VM) */
  to: Ip;
  toPort: number;
}

/** 장비가 빌려주는 것 */
export interface PublishHost {
  /** 이 장비의 주소인지 */
  owns(ip: Ip): boolean;
  /** 대상 쪽으로 나갈 때 쓸 내 주소 (경로가 없으면 undefined) */
  sourceFor(dst: Ip): Ip | undefined;
  /** 바꾼 패킷을 라우팅해 내보낸다 (NAT 변환은 하지 않음 — 이미 주소를 바꿨다) */
  send(pkt: Ipv4Packet, inPort: number, frameId: number, ctx: NodeContext): void;
}

interface Flow {
  client: Ip;
  clientPort: number;
  /** 클라이언트가 접속한 내 주소·포트 */
  addr: Ip;
  port: number;
  to: Ip;
  toPort: number;
  /** 대상 쪽으로 보낼 때의 내 주소·프록시 포트 */
  src: Ip;
  proxyPort: number;
  finClient?: boolean;
  finTarget?: boolean;
  /** 끝난 시각 (양쪽 FIN 뒤 ACK·RST) */
  closedAt?: number;
}

/** 프록시 포트 범위 (NAT 의 공인 포트·TCP 임시 포트와 겹치지 않게) */
const PROXY_PORT_START = 61000;
const PROXY_PORT_COUNT = 1000;
const TIME_WAIT = 2000;

export class PortPublish {
  rules: PublishRule[] = [];
  /** "클라이언트:포트>내 주소:포트" → 흐름 */
  private readonly flows = new Map<string, Flow>();
  /** 프록시 포트 → 흐름 (돌아오는 것) */
  private readonly byProxy = new Map<number, Flow>();
  private nextPort = PROXY_PORT_START;

  constructor(private readonly host: PublishHost) {}

  setRules(rules: PublishRule[], ctx: NodeContext): void {
    const key = (rs: PublishRule[]) => rs.map((r) => `${r.bind}:${r.port}>${r.to}:${r.toPort}`).join(",");
    if (key(rules) === key(this.rules)) return;
    this.rules = rules.map((r) => ({ ...r }));
    // 규칙이 바뀌면 진행 중인 흐름은 그대로 둔다 (docker 도 컨테이너를 다시 만들기 전에는 열린 연결을 끊지 않는다)
    ctx.trace(
      "ip.config",
      "sys",
      rules.length ? `포트 공개 규칙 변경: ${rules.map((r) => `${r.bind}:${r.port} → ${r.to}:${r.toPort}`).join(", ")}` : "포트 공개 규칙 없음",
      { publish: rules.map((r) => ({ ...r })) },
    );
  }

  /** 받은 TCP 를 처리했으면 true (공개 포트로 온 것·그 응답) */
  handle(inPort: number, pkt: Ipv4Packet, frameId: number, ctx: NodeContext): boolean {
    const seg = pkt.payload;
    if (seg.kind !== "tcp" || (this.rules.length === 0 && this.byProxy.size === 0)) return false;
    // 1) 대상이 보낸 응답: 내 주소의 프록시 포트로 온다 → 클라이언트가 접속한 주소·포트에서 보낸 것으로 되돌린다
    const back = this.byProxy.get(seg.dstPort);
    if (back && pkt.dst === back.src && pkt.src === back.to && seg.srcPort === back.toPort) {
      this.track(back, seg, false, ctx);
      const out: Ipv4Packet = { ...pkt, src: back.addr, dst: back.client, payload: { ...seg, srcPort: back.port, dstPort: back.clientPort } };
      if (seg.syn)
        ctx.trace("port.publish", "L4", `포트 공개 응답: ${back.to}:${back.toPort} 의 SYN·ACK 를 ${back.addr}:${back.port} 에서 보낸 것으로 바꿔 ${back.client}:${back.clientPort} 에게`, { client: back.client, to: back.to, back: true }, frameId);
      this.host.send(out, inPort, frameId, ctx);
      return true;
    }
    // 2) 공개 포트로 온 연결
    if (!this.host.owns(pkt.dst)) return false;
    const rule = this.rules.find((r) => r.port === seg.dstPort && (r.bind === "0.0.0.0" || r.bind === pkt.dst));
    if (!rule) {
      const other = this.rules.find((r) => r.port === seg.dstPort);
      if (!other) return false;
      // 그 포트는 다른 주소(예: 127.0.0.1)에만 공개됨 — 이 주소에서는 아무도 듣지 않으니 RST 로 거부 (Connection refused)
      if (seg.rst) return true;
      ctx.trace("port.publish", "L4", `포트 ${seg.dstPort} 는 ${other.bind} 에만 공개됨 → ${pkt.dst}:${seg.dstPort} 에서는 듣는 프로그램이 없어 RST 로 거부 (LAN 에서도 받으려면 공개 주소를 0.0.0.0 으로)`, { port: seg.dstPort, bind: other.bind, refused: true }, frameId);
      const rst: Ipv4Packet = {
        kind: "ipv4",
        src: pkt.dst,
        dst: pkt.src,
        ttl: 64,
        payload: { kind: "tcp", srcPort: seg.dstPort, dstPort: seg.srcPort, seq: 0, ack: seg.seq + (seg.syn ? 1 : 0) + seg.len, rst: true, ackFlag: true, len: 0 },
      };
      this.host.send(rst, inPort, frameId, ctx);
      return true;
    }
    const key = `${pkt.src}:${seg.srcPort}>${pkt.dst}:${seg.dstPort}`;
    let f = this.flows.get(key);
    if (f?.closedAt !== undefined && seg.syn && !seg.ack) {
      this.forget(f);
      f = undefined;
    }
    if (!f) {
      if (!seg.syn || seg.ack) {
        ctx.trace("ip.drop", "L4", `포트 공개 ${pkt.dst}:${seg.dstPort} 로 온 세그먼트지만 진행 중인 연결이 아님 (SYN 없음) → 드롭`, { port: seg.dstPort }, frameId);
        return true;
      }
      const src = this.host.sourceFor(rule.to);
      if (!src) {
        ctx.trace("ip.no-route", "L3", `포트 공개 ${rule.bind}:${rule.port} → ${rule.to}:${rule.toPort}: 대상으로 가는 경로가 없음 → 드롭`, { to: rule.to }, frameId);
        return true;
      }
      const proxyPort = this.allocate(ctx.now);
      if (proxyPort === undefined) {
        ctx.trace("ip.drop", "L4", `포트 공개: 프록시 포트가 모두 쓰이는 중 → 드롭`, {}, frameId);
        return true;
      }
      f = { client: pkt.src, clientPort: seg.srcPort, addr: pkt.dst, port: seg.dstPort, to: rule.to, toPort: rule.toPort, src, proxyPort };
      this.flows.set(key, f);
      this.byProxy.set(proxyPort, f);
      ctx.trace(
        "port.publish",
        "L4",
        `포트 공개 (docker -p ${rule.bind === "0.0.0.0" ? "" : `${rule.bind}:`}${rule.port}:${rule.toPort}): ${pkt.src}:${seg.srcPort} → ${pkt.dst}:${seg.dstPort} 연결을 ${rule.to}:${rule.toPort} 로 넘김 — 출발지는 내 주소 ${src}:${proxyPort} (대상은 이 장비가 연 연결로 본다)`,
        { client: pkt.src, bind: rule.bind, port: rule.port, to: rule.to, toPort: rule.toPort, src, proxyPort },
        frameId,
      );
    }
    this.track(f, seg, true, ctx);
    const out: Ipv4Packet = { ...pkt, src: f.src, dst: f.to, payload: { ...seg, srcPort: f.proxyPort, dstPort: f.toPort } };
    this.host.send(out, inPort, frameId, ctx);
    return true;
  }

  /** FIN·RST 로 흐름이 끝났는지 기록 */
  private track(f: Flow, seg: TcpSegment, fromClient: boolean, ctx: NodeContext): void {
    if (seg.rst) f.closedAt ??= ctx.now;
    if (seg.fin) {
      if (fromClient) f.finClient = true;
      else f.finTarget = true;
    } else if (f.finClient && f.finTarget && seg.ack) f.closedAt ??= ctx.now;
  }

  private forget(f: Flow): void {
    this.flows.delete(`${f.client}:${f.clientPort}>${f.addr}:${f.port}`);
    if (this.byProxy.get(f.proxyPort) === f) this.byProxy.delete(f.proxyPort);
  }

  /** 다음 프록시 포트 (끝난 지 2초 지난 흐름은 치운다) */
  private allocate(now: number): number | undefined {
    for (const f of [...this.flows.values()]) if (f.closedAt !== undefined && now - f.closedAt >= TIME_WAIT) this.forget(f);
    for (let i = 0; i < PROXY_PORT_COUNT; i++) {
      const p = this.nextPort;
      this.nextPort = PROXY_PORT_START + ((this.nextPort - PROXY_PORT_START + 1) % PROXY_PORT_COUNT);
      if (!this.byProxy.has(p)) return p;
    }
    return undefined;
  }

  /** 표: 공개 규칙과 진행 중인 연결 */
  rows(): string[][] {
    return this.rules.map((r) => {
      const n = [...this.flows.values()].filter((f) => f.port === r.port && f.to === r.to && f.closedAt === undefined).length;
      return [`${r.bind}:${r.port}`, `${r.to}:${r.toPort}`, n ? `연결 ${n}` : "-"];
    });
  }

  clear(): void {
    this.flows.clear();
    this.byProxy.clear();
  }
}
