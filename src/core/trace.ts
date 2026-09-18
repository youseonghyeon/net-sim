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
  | "dhcp.lease";

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

/** 실패·폐기 계열 (UI 에서 붉게 표시) */
export const BAD_KINDS: ReadonlySet<TraceKind> = new Set<TraceKind>([
  "frame.drop",
  "ip.drop",
  "ip.no-route",
  "ip.no-address",
  "ip.ttl-expired",
  "nat.miss",
  "arp.timeout",
  "link.unconnected",
  "link.lost",
  "dhcp.timeout",
  "dhcp.failed",
  "icmp.timeout",
  "icmp.failed",
  "dhcp.nak.sent",
  "dhcp.nak.received",
  "dhcp.disabled",
  "dhcp.pool.exhausted",
]);
