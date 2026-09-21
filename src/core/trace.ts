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
  | "arp.timeout"
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
  | "vlan.drop";

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
  "arp.timeout",
  "link.unconnected",
  "link.lost",
  "link.loss",
  "switch.loop",
  "dhcp.timeout",
  "dhcp.failed",
  "icmp.timeout",
  "icmp.failed",
  "icmp.ttl-received",
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
]);
