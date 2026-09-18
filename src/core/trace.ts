import type { Layer } from "./packet";

export type TraceKind =
  | "action"
  | "link.transmit"
  | "link.unconnected"
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
  | "ip.queued"
  | "ip.dequeue"
  | "ip.drop"
  | "icmp.echo.sent"
  | "icmp.echo.received"
  | "icmp.reply.sent"
  | "icmp.reply.received";

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
