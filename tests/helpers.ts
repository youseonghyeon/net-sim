// 테스트 공용 조립 도우미: 토폴로지를 NetworkSync 로 올리고 조용해질 때까지 돌린 뒤, 이름으로 장치를 찾는 접근자를 준다.
import type { Host } from "../src/core/nodes/host";
import type { L3Node } from "../src/core/nodes/l3";
import type { Switch } from "../src/core/nodes/switch";
import type { TcpConn } from "../src/core/nodes/tcp";
import type { SimNode } from "../src/core/nodes/node";
import type { ActionSpec } from "../src/core/network";
import type { Ipv4Packet } from "../src/core/packet";
import type { TraceEvent } from "../src/core/trace";
import { NetworkSync } from "../src/model/netSync";
import type { Topology } from "../src/model/topology";

export interface LoadOptions {
  /** `runToIdle` 의 이벤트 상한 (없으면 코어 기본값) */
  maxEvents?: number;
}

export function loadTopology(t: Topology, opts: LoadOptions = {}) {
  const s = new NetworkSync();
  const run = () => s.net.runToIdle(opts.maxEvents);
  s.sync(t);
  run();
  const id = (name: string) => t.devices.find((d) => d.name === name)!.id;
  const node = <T extends SimNode = SimNode>(name: string) => s.net.nodes.get(id(name)) as T;
  const host = (name: string) => node<Host>(name);
  const l3 = (name: string) => node<L3Node>(name);
  const sw = (name: string) => node<Switch>(name);
  /** 지금 시각에 동작을 넣고 조용해질 때까지 돌린 뒤, 그동안 쌓인 트레이스 */
  const act = (a: ActionSpec): TraceEvent[] => {
    const from = s.net.trace.length;
    s.net.scheduleAction(s.net.now, a);
    run();
    return s.net.trace.slice(from);
  };
  /** 토폴로지를 바꿔 다시 동기화하고 조용해질 때까지 돌린 뒤, 그동안 쌓인 트레이스 */
  const apply = (next: Topology): TraceEvent[] => {
    const from = s.net.trace.length;
    s.sync(next);
    run();
    return s.net.trace.slice(from);
  };
  const lastConn = (name: string): TcpConn => [...host(name).tcp.conns.values()].filter((c) => c.role === "client").at(-1)!;
  const serverConns = (name: string) => [...host(name).tcp.conns.values()].filter((c) => c.role === "server");
  /** 그 장치에 도착한 IPv4 패킷 (프레임 기록 기준) */
  const wire = (name: string) =>
    [...s.net.frameLog.values()].flat().filter((x) => x.to === id(name) && x.frame.payload.kind === "ipv4").map((x) => x.frame.payload as Ipv4Packet);
  return { s, t, id, node, host, l3, sw, act, apply, lastConn, serverConns, wire };
}
