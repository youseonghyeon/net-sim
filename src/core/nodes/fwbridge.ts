// 투명(브리지) 방화벽 장비: IP 없이 케이블 사이에 끼어 지나가는 패킷만 검사한다 ("bump in the wire").
// 학습 포인트: 방화벽은 라우터가 아니어도 된다. 주소가 없으니 ping 대상도 아니고 traceroute 홉에도 안 보이며,
// 주소·경로·서브넷을 하나도 안 바꾸고 "어디에 꽂느냐" 만으로 무엇을 보호할지 정한다.
import { describeFrame, type EthernetFrame } from "../packet";
import { Firewall, type FirewallConfig } from "./firewall";
import type { NodeContext, NodeSnapshot, SimNode } from "./node";

export class FirewallBridge implements SimNode {
  /** 위쪽 포트 = outside (인터넷/상위 방향). 여기서 들어오면 인바운드, 여기로 나가면 아웃바운드 */
  static readonly OUTSIDE = 0;
  static readonly INSIDE = 1;

  readonly type = "firewall" as const;
  readonly id: string;
  readonly portCount = 2;
  readonly firewall: Firewall;
  private readonly linkUp = [false, false];

  constructor(id: string, config?: FirewallConfig) {
    this.id = id;
    this.firewall = new Firewall(config);
  }

  portName(port: number): string {
    return port === FirewallBridge.OUTSIDE ? "outside" : "inside";
  }

  configure(cfg: FirewallConfig, ctx: NodeContext): void {
    this.firewall.setConfig(cfg, ctx, "투명 방화벽");
  }

  onLink(port: number, up: boolean, ctx: NodeContext): void {
    this.linkUp[port] = up;
    ctx.trace(up ? "link.up" : "link.down", "L1", `${this.portName(port)} 링크 ${up ? "연결됨" : "끊김"}`, { port });
  }

  receive(port: number, frame: EthernetFrame, ctx: NodeContext): void {
    const out = port === FirewallBridge.OUTSIDE ? FirewallBridge.INSIDE : FirewallBridge.OUTSIDE;
    const label = describeFrame(frame);
    ctx.trace("frame.receive", "L2", `${this.portName(port)} 수신: ${label} [${frame.src} → ${frame.dst}]`, { port, src: frame.src, dst: frame.dst }, frame.id);
    if (!ctx.isPortConnected(out)) {
      ctx.trace("link.unconnected", "L1", `${this.portName(out)} 에 케이블이 없음 → 드롭`, { port: out }, frame.id);
      return;
    }
    // IP 패킷만 규칙에 걸린다. ARP 는 L2 라 그대로 통과 (실제 투명 방화벽도 ARP 는 통과시킨다). DHCP·DNS 는 IP 라 규칙 대상
    if (frame.payload.kind === "ipv4") {
      const dir = port === FirewallBridge.OUTSIDE ? "in" : "out";
      if (!this.firewall.check(frame.payload, dir, ctx, frame.id)) return;
    }
    ctx.send(out, { ...frame, hops: (frame.hops ?? 0) + 1 });
  }

  onTimer(): void {}

  snapshot(): NodeSnapshot {
    const c = this.firewall.config;
    return {
      id: this.id,
      type: this.type,
      label: this.id,
      info: [
        ["모드", "투명 (브리지, IP 없음)"],
        ["방화벽", c.enabled ? `켜짐 · 규칙 ${c.rules.length}개 · 기본 ${c.defaultPolicy === "allow" ? "허용" : "차단"}` : "꺼짐 (모두 통과)"],
        ["Stateful 검사", c.stateful ? "켜짐" : "꺼짐"],
        ["outside", this.linkUp[0] ? "연결됨" : "링크 다운"],
        ["inside", this.linkUp[1] ? "연결됨" : "링크 다운"],
      ],
      tables: [{ title: "방화벽 규칙", columns: ["#", "규칙"], rows: this.firewall.rows() }],
    };
  }
}
