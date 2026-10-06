// IGMP 스누핑 (스위치·공유기 내부 스위치): 호스트의 IGMP Membership Report·Leave 를 엿들어 그룹마다 받을 포트를 배우고,
// 멀티캐스트 스트림(IPTV)을 그 포트로만 보낸다. 끄면 멀티캐스트는 브로드캐스트처럼 모든 포트로 — 보지 않는 기기의 링크까지 채운다.
// 줄인 것: 쿼리어(IGMP Query)·가입 만료·라우터 포트 학습(리포트는 그대로 플러딩), IGMPv3 출발지 지정, MLD(IPv6)
import type { Ip } from "../addr";
import { ALL_HOSTS_IP, isMcastIp, mcastMac, type EthernetFrame } from "../packet";
import type { NodeContext } from "./node";

/** 224.0.0.x 는 링크 로컬 제어(VRRP·RIP 등) — 스누핑해도 늘 플러딩 */
const isLinkLocalMcast = (ip: Ip) => ip.startsWith("224.0.0.");

export class IgmpSnoop {
  enabled = false;
  /** "VLAN:그룹" → 가입한 포트 */
  readonly groups = new Map<string, Set<number>>();

  setEnabled(on: boolean, ctx: NodeContext, who: string): void {
    if (on === this.enabled) return;
    this.enabled = on;
    this.groups.clear();
    ctx.trace("ip.config", "sys", on ? `${who}: IGMP 스누핑 켜짐 — 가입(Report)을 엿들어 멀티캐스트를 가입한 포트로만 보낸다` : `${who}: IGMP 스누핑 꺼짐 — 멀티캐스트는 모든 포트로`, { igmp: on });
  }

  /**
   * 들어온 프레임을 본다: IGMP 면 가입·탈퇴를 배우고(전달은 호출한 쪽이 평소대로), 스트림이면 보낼 포트를 정한다.
   * 돌려준 값: undefined = 평소대로(플러딩), 배열 = 이 포트로만 (빈 배열이면 아무 데도)
   */
  observe(port: number, vlan: number, frame: EthernetFrame, ctx: NodeContext, portName: (p: number) => string): number[] | undefined {
    if (!this.enabled || frame.payload.kind !== "ipv4") return undefined;
    const pkt = frame.payload;
    const p = pkt.payload;
    if (p.kind === "igmp") {
      const key = `${vlan}:${p.group}`;
      const set = this.groups.get(key) ?? new Set<number>();
      if (p.type === "report") {
        const fresh = !set.has(port);
        set.add(port);
        this.groups.set(key, set);
        if (fresh) ctx.trace("igmp.snoop", "L2", `IGMP 스누핑: ${portName(port)} 의 ${pkt.src} 가 그룹 ${p.group} 에 가입 → 이 그룹은 [${[...set].map(portName).join(", ")}] 로만`, { group: p.group, port }, frame.id);
      } else if (p.type === "query") {
        return undefined;
      } else {
        // 같은 포트 뒤(허브·아래 스위치)에 아직 보는 기기가 있으면 그 기기가 이 Leave 를 듣고 다시 가입을 알린다 (그룹별 쿼리에 답하듯)
        set.delete(port);
        if (set.size) this.groups.set(key, set);
        else this.groups.delete(key);
        ctx.trace("igmp.snoop", "L2", `IGMP 스누핑: ${portName(port)} 의 ${pkt.src} 가 그룹 ${p.group} 탈퇴 → ${set.size ? `남은 포트 [${[...set].map(portName).join(", ")}]` : "받을 포트 없음 (이제 아무 데도 보내지 않음)"}`, { group: p.group, port }, frame.id);
      }
      return undefined;
    }
    if (!isMcastIp(pkt.dst) || isLinkLocalMcast(pkt.dst)) return undefined;
    const members = this.groups.get(`${vlan}:${pkt.dst}`);
    if (!members) {
      ctx.trace("igmp.snoop", "L2", `IGMP 스누핑: 그룹 ${pkt.dst} 에 가입한 포트가 없음 → 아무 데도 보내지 않음 (보는 기기가 없다)`, { group: pkt.dst }, frame.id);
      return [];
    }
    const out = [...members].filter((x) => x !== port);
    ctx.trace("igmp.snoop", "L2", `IGMP 스누핑: 그룹 ${pkt.dst} 는 가입한 포트 [${out.map(portName).join(", ") || "없음"}] 로만 (다른 포트는 채우지 않는다)`, { group: pkt.dst, ports: out }, frame.id);
    return out;
  }

  /** General Query (스누핑 쿼리어): 기기들이 가입한 그룹을 다시 알리게 한다 — 스누핑을 켤 때 */
  static query(srcMac: string, ctx: NodeContext): EthernetFrame {
    return { kind: "ethernet", id: ctx.nextPacketId(), src: srcMac, dst: mcastMac(ALL_HOSTS_IP), payload: { kind: "ipv4", src: "0.0.0.0", dst: ALL_HOSTS_IP, ttl: 1, payload: { kind: "igmp", type: "query", group: "0.0.0.0" } } };
  }

  /** 링크가 내려간 포트는 모든 그룹에서 뺀다 */
  linkDown(port: number): void {
    for (const [k, set] of this.groups) {
      set.delete(port);
      if (!set.size) this.groups.delete(k);
    }
  }

  rows(portName: (p: number) => string): string[][] {
    return [...this.groups.entries()].map(([k, set]) => {
      const [vlan, group] = k.split(":");
      return [group!, vlan === "1" ? "—" : vlan!, [...set].map(portName).join(", ")];
    });
  }
}
