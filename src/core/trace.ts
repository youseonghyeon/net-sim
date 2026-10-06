import type { Layer } from "./packet";

export type TraceKind =
  | "action"
  | "link.transmit"
  | "link.unconnected"
  | "link.up"
  /** 포트 공개 (docker -p 식 FULLNAT) */
  | "port.publish"
  /** P2P (NAT 트래버설): STUN·시그널링·홀 펀칭·TURN 릴레이 */
  | "p2p.stun"
  | "p2p.signal"
  | "p2p.connect"
  | "p2p.punch"
  | "p2p.relay"
  | "p2p.connected"
  | "p2p.failed"
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
  /** NUD (이웃 도달 확인): STALE → DELAY → PROBE → REACHABLE (실패는 ndp.timeout) */
  | "ndp.nud"
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
  /** CONNECT 터널이 열림 (프록시가 대상에 연결됨, 끝 클라이언트가 200 Connection established 를 받음) */
  | "proxy.tunnel"
  /** TLS: ClientHello (클라이언트가 보냄·서버가 받음) */
  | "tls.hello"
  /** TLS 핸드셰이크 완료 — 그 뒤 내용은 암호화 */
  | "tls.established"
  /** TLS 핸드셰이크 실패 (TLS 가 아닌 상대, 평문 요청이 HTTPS 포트로) */
  | "tls.fail"
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
  /** 액티브 헬스 체크: 실패(아직 DOWN 전)·UP 복귀 */
  | "lb.check"
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
  /** DPI: 흐름의 앱을 알아봄 / 막을 앱이라 끊음 */
  | "dpi.app"
  | "dpi.block"
  /** DNS 필터(AdGuard Home·자녀 보호)가 이름을 막음 */
  | "dns.blocked"
  /** DNS 가로채기: 다른 DNS 서버로 가던 질의를 공유기가 대신 받음 */
  | "dns.hijack"
  /** 멀티 WAN: 설정·추적 ping·회선 살아남/끊김·전환 */
  | "mwan.config"
  | "mwan.check"
  | "mwan.up"
  | "mwan.down"
  | "mwan.switch"
  /** DDNS: 설정·갱신 요청·등록됨·실패, 서버 쪽 처리 */
  | "ddns.config"
  | "ddns.update"
  | "ddns.ok"
  | "ddns.failed"
  | "ddns.server"
  /** WireGuard 핸드셰이크 (Initiation·Response) */
  | "vpn.handshake"
  /** WireGuard keepalive (빈 데이터) */
  | "vpn.keepalive"
  /** WireGuard 엔드포인트 로밍 (피어의 바깥 주소가 바뀜) */
  | "vpn.roam"
  /** VPN 이 끊겨 킬 스위치가 꺼진 공유기가 WAN 으로 바로 내보냄 (실제 주소 노출) */
  | "vpn.leak"
  /** 킬 스위치가 VPN 밖으로 나가는 것을 막음 */
  | "vpn.killswitch"
  /** 메시 VPN (Tailscale·ZeroTier): 로그인·netmap·후보 주소·홀 펀칭(disco)·직접 경로·릴레이·터널 입출·실패, 조정 서버 쪽 처리 */
  | "mesh.login"
  | "mesh.netmap"
  | "mesh.endpoint"
  | "mesh.disco"
  | "mesh.direct"
  | "mesh.relay"
  | "mesh.encap"
  | "mesh.decap"
  | "mesh.drop"
  | "mesh.control"
  /** GoodCloud: 공유기의 등록·연결 유지, 원격 관리 요청, 클라우드 서버 쪽 처리 */
  | "cloud.register"
  | "cloud.manage"
  | "cloud.server"
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
  "tls.fail",
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
  "vpn.leak",
  "ddns.failed",
  "mwan.down",
  "dpi.block",
  "p2p.failed",
  "mesh.drop",
]);
