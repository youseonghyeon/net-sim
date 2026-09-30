import type { Layer } from "./packet";

export type TraceKind =
  | "action"
  | "link.transmit"
  | "link.unconnected"
  | "link.up"
  | "link.down"
  | "link.lost"
  | "frame.send"
  | "frame.receive"
  | "frame.drop"
  | "arp.cache.hit"
  | "arp.cache.miss"
  | "arp.request.sent"
  | "arp.request.received"
  | "arp.reply.sent"
  | "arp.reply.received"
  | "arp.cache.update"
  | "arp.probe"
  | "ip.conflict"
  | "ip.conflict.clear"
  | "arp.timeout"
  /** IPv6 NDP: ARP 요청·응답에 해당하는 NS·NA, 이웃 캐시, DAD (ICMPv6 위라 L3) */
  | "ndp.ns.sent"
  | "ndp.ns.received"
  | "ndp.na.sent"
  | "ndp.na.received"
  | "ndp.cache.hit"
  | "ndp.cache.miss"
  | "ndp.cache.update"
  | "ndp.timeout"
  | "ndp.dad"
  | "ndp.dad.fail"
  /** IPv6 라우터 찾기 (NDP RS/RA) 와 SLAAC */
  | "ndp.rs.sent"
  | "ndp.rs.received"
  | "ndp.ra.sent"
  | "ndp.ra.received"
  | "slaac.addr"
  | "slaac.router"
  | "slaac.timeout"
  | "timer.stale"
  | "switch.learn"
  | "switch.flood"
  | "switch.forward"
  | "switch.filter"
  | "switch.loop"
  | "ip.route"
  | "ip.no-route"
  | "ip.no-address"
  | "ip.queued"
  | "ip.dequeue"
  | "ip.drop"
  | "ip.config"
  | "ip.forward"
  | "ip.ttl-expired"
  | "nat.translate"
  | "nat.restore"
  | "nat.miss"
  | "inet.forward"
  | "inet.reply"
  | "icmp.echo.sent"
  | "icmp.echo.received"
  | "icmp.reply.sent"
  | "icmp.reply.received"
  | "icmp.timeout"
  | "icmp.failed"
  | "icmp.ttl-exceeded"
  | "icmp.ttl-received"
  | "icmp.unreachable.sent"
  | "icmp.unreachable.received"
  | "trace.start"
  | "trace.probe"
  | "trace.hop"
  | "trace.timeout"
  | "trace.done"
  | "trace.failed"
  | "dhcp.discover.sent"
  | "dhcp.discover.received"
  | "dhcp.offer.sent"
  | "dhcp.offer.received"
  | "dhcp.request.sent"
  | "dhcp.request.received"
  | "dhcp.ack.sent"
  | "dhcp.ack.received"
  | "dhcp.nak.sent"
  | "dhcp.nak.received"
  | "dhcp.bound"
  | "dhcp.timeout"
  | "dhcp.failed"
  | "dhcp.release"
  | "dhcp.ignore"
  | "dhcp.disabled"
  | "dhcp.pool.exhausted"
  | "dhcp.misconfigured"
  | "dhcp.relay.forward"
  | "dhcp.relay.return"
  | "dhcp.relay.miss"
  | "dhcp.lease"
  /** DHCPv6 프리픽스 위임 (IA_PD): 공유기(클라이언트) ↔ ISP(서버) */
  | "dhcp6.sent"
  | "dhcp6.received"
  | "dhcp6.bound"
  | "dhcp6.delegate"
  | "dhcp6.timeout"
  | "tcp.connect"
  | "tcp.received"
  | "tcp.syn.sent"
  | "tcp.syn.received"
  | "tcp.synack.sent"
  | "tcp.synack.received"
  | "tcp.ack.sent"
  | "tcp.ack.received"
  | "tcp.established"
  | "tcp.data.sent"
  | "tcp.data.received"
  | "tcp.dup"
  | "tcp.out-of-order"
  | "tcp.retransmit"
  | "tcp.failed"
  | "tcp.fin.sent"
  | "tcp.fin.received"
  | "tcp.closed"
  | "tcp.rst.sent"
  | "tcp.rst.received"
  | "tcp.refused"
  | "tcp.ignore"
  | "tcp.cookie"
  /** Happy Eyeballs 축소판: IPv6 연결 실패 → IPv4 로 다시 */
  | "tcp.fallback"
  | "proxy.config"
  | "proxy.use"
  | "proxy.request"
  | "proxy.relay"
  | "proxy.deny"
  | "proxy.fail"
  | "link.loss"
  | "hub.repeat"
  | "nat.forward.rule"
  | "nat.forward.reply"
  | "dns.query.sent"
  | "dns.query.received"
  | "dns.response.sent"
  | "dns.response.received"
  | "dns.cache.hit"
  | "dns.forward"
  | "dns.timeout"
  | "dns.nxdomain"
  | "dns.no-server"
  | "dns.resolved"
  | "fw.allow"
  | "fw.deny"
  | "fw.established"
  | "wifi.air"
  | "wifi.associate"
  | "wifi.disassociate"
  | "wifi.no-base"
  | "vlan.tag"
  | "vlan.untag"
  | "vlan.drop"
  | "rip.config"
  | "rip.request"
  | "rip.response"
  | "rip.receive"
  | "rip.learn"
  | "rip.withdraw"
  | "rip.ignore"
  | "lb.config"
  | "lb.pick"
  | "lb.relay"
  | "lb.down"
  | "lb.fail"
  | "lb.forward"
  | "vpn.config"
  | "vpn.encap"
  | "vpn.decap"
  | "vpn.drop"
  | "vpn.ike"
  | "vpn.up"
  /** 원격 접속 계정 인증 (EAP) 단계: 서버의 요청(challenge), 클라이언트의 응답 */
  | "vpn.eap"
  /** DPD (Dead Peer Detection): 빈 INFORMATIONAL 요청·응답, 상대가 살아 있음 */
  | "vpn.dpd"
  | "ha.config"
  | "ha.state"
  | "ha.advert"
  | "ha.master"
  | "ha.backup"
  | "ha.sync"
  | "ssh.open"
  | "stp.config"
  | "stp.bpdu"
  | "stp.root"
  | "stp.port"
  | "stp.block"
  | "stp.discard"
  | "stp.tc";

export interface TraceEvent {
  seq: number;
  time: number;
  nodeId: string;
  kind: TraceKind;
  layer: Layer;
  summary: string;
  details?: Record<string, unknown>;
  packetId?: number;
}

/** 실패·드롭 계열 (UI 에서 붉게 표시) */
export const BAD_KINDS: ReadonlySet<TraceKind> = new Set<TraceKind>([
  "frame.drop",
  "ip.drop",
  "ip.no-route",
  "ip.no-address",
  "ip.ttl-expired",
  "nat.miss",
  "tcp.retransmit",
  "tcp.failed",
  "tcp.rst.sent",
  "tcp.rst.received",
  "tcp.refused",
  "tcp.out-of-order",
  "proxy.deny",
  "proxy.fail",
  "arp.timeout",
  "ndp.timeout",
  "ndp.dad.fail",
  "slaac.timeout",
  "ip.conflict",
  "link.unconnected",
  "link.lost",
  "link.loss",
  "switch.loop",
  "dhcp.timeout",
  "dhcp.failed",
  "dhcp6.timeout",
  "icmp.timeout",
  "icmp.failed",
  "icmp.ttl-received",
  "icmp.unreachable.received",
  "trace.timeout",
  "trace.failed",
  "dhcp.nak.sent",
  "dhcp.nak.received",
  "dhcp.disabled",
  "dhcp.pool.exhausted",
  "dhcp.misconfigured",
  "dhcp.relay.miss",
  "dns.timeout",
  "dns.nxdomain",
  "dns.no-server",
  "fw.deny",
  "wifi.disassociate",
  "wifi.no-base",
  "vlan.drop",
  "lb.down",
  "lb.fail",
  "vpn.drop",
]);
