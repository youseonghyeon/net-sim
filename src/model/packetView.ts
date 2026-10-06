// 패킷 상세 보기 (순수): 로그 한 줄이 가리키는 프레임을 실제 도구의 출력 형식으로 바꾼다.
// - tcpdumpLine: 같은 패킷을 tcpdump -n -e 가 찍는 한 줄로
// - headerLayers: 이더넷 → ARP/IPv4 → ICMP/TCP/UDP → DHCP/DNS/RIP 필드를 실제 번호(타입·코드·옵션)와 함께
// - practitionerLines: 장치가 내린 판단을 실무 명령의 출력(시스코 debug, iptables LOG, dhclient, ping, curl …)으로
// 시뮬레이터에 없는 필드(체크섬, 윈도우 크기, IP ID 등)는 넣지 않고, 길이는 근사값이다.
import type { DhcpOp, EspPacket, EthernetFrame, IcmpPacket, Icmpv6Packet, IkeMessage, Ipv4Packet, Ipv6Packet, L2tpPacket, OvpnMessage, P2pMessage, StunMessage, TcpSegment, TsMessage, UdpPacket, WgMessage } from "../core/packet";
import { describeOriginal, IP_PROTO, IP6_NEXT_HEADER, tcpFlags, UNREACHABLE_FLAG, UNREACHABLE6_CODE, cloudLabel, ovpnLength, tsLabel, tsLength, wgLength } from "../core/packet";
import { scopeLabel6 } from "../core/addr6";
import type { TraceEvent } from "../core/trace";

export interface HeaderLayer {
  /** 계층 이름 (예: "IPv4") */
  title: string;
  rows: [label: string, value: string][];
}

export interface PractitionerLine {
  /** 어디서 보는 출력인지 (예: "tcpdump", "시스코 debug ip nat") */
  tool: string;
  line: string;
}

const DHCP_TYPE: Record<DhcpOp, [number, string]> = {
  discover: [1, "Discover"],
  offer: [2, "Offer"],
  request: [3, "Request"],
  nak: [6, "NAK"],
  ack: [5, "ACK"],
  release: [7, "Release"],
  forcerenew: [9, "ForceRenew"],
};

// ---------- 길이 (근사) ----------

const ICMP_ECHO_LEN = 64; // ping 기본: 데이터 56 + ICMP 헤더 8
function l4Length(p: Ipv4Packet["payload"]): number {
  if (p.kind === "icmp") return p.type === "echo-request" || p.type === "echo-reply" ? ICMP_ECHO_LEN : 36;
  if (p.kind === "tcp") return 20 + p.len;
  if (p.kind === "esp") return espLength(p);
  if (p.kind === "vrrp") return 12; // VRRPv3 머리 8 + 가상 주소 4
  if (p.kind === "pfsync") return 12 + (p.nat.length + p.flows.length) * 64; // 머리 + 상태 하나당 대략
  if (p.kind === "igmp") return 8; // IGMPv2
  return 8 + appLength(p);
}
/** ICMPv6·TCP·UDP 길이 (IPv6 헤더 40 은 빼고) */
function l6Length(p: Ipv6Packet["payload"]): number {
  if (p.kind === "icmp6") {
    if (p.type === "echo-request" || p.type === "echo-reply") return ICMP_ECHO_LEN;
    if (p.type === "ns") return p.sll ? 32 : 24; // 머리 24 + 링크 계층 주소 옵션 8
    if (p.type === "na") return p.tll ? 32 : 24;
    if (p.type === "rs") return 8 + (p.sll ? 8 : 0);
    if (p.type === "ra") return 16 + p.prefixes.length * 32 + (p.rdnss?.length ? 8 + 16 * p.rdnss.length : 0) + (p.sll ? 8 : 0);
    return 48 + 8; // 오류: 머리 8 + 원래 패킷 앞부분
  }
  if (p.kind === "tcp") return 20 + p.len;
  return 8 + appLength(p);
}

/** ESP 머리(SPI 4 + seq 4) + IV 16 + 암호화된 원래 IP 패킷 + 패딩·무결성 값 약 16 */
function espLength(e: EspPacket): number {
  return 8 + 16 + 20 + l4Length(e.inner.payload) + 16;
}
function appLength(u: UdpPacket): number {
  const m = u.payload;
  if (m.kind === "dhcp") return 300;
  if (m.kind === "dns") return 12 + m.name.length + 6 + (m.answer ? (m.qtype === "AAAA" ? 28 : 16) : 0);
  if (m.kind === "vpn") return 32 + 20 + l4Length(m.inner.payload); // WireGuard 머리 32 + 암호화된 원래 IP 패킷
  if (m.kind === "esp") return espLength(m);
  if (m.kind === "ike") return (u.dstPort === 4500 || u.srcPort === 4500 ? 4 : 0) + (m.exchange === "IKE_SA_INIT" ? 336 : 224); // NAT-T 는 앞에 0 4바이트(Non-ESP 표시)
  if (m.kind === "dhcp6") return 4 + 14 + (m.serverId ? 14 : 0) + 16 + (m.prefix ? 29 : 0); // 머리 + Client ID + Server ID + IA_PD (+ IAPREFIX)
  if (m.kind === "l2tp") return 12 + pppLength(m.ppp); // L2TP 머리 + PPP
  if (m.kind === "stun") return 20 + (m.mapped ? 12 : 0) + (m.relayed ? 12 : 0) + (m.peer ? 12 : 0) + (m.data ? 4 + p2pLength(m.data) : 0); // 머리 20 + 속성
  if (m.kind === "p2p") return p2pLength(m);
  if (m.kind === "wg") return wgLength(m, m.inner ? 20 + l4Length(m.inner.payload) : 0);
  if (m.kind === "ddns") return 60 + m.hostname.length; // 실제는 HTTPS 요청 — 대략의 크기
  if (m.kind === "ovpn") return ovpnLength(m, m.inner ? 20 + l4Length(m.inner.payload) : 0);
  if (m.kind === "cloud") return 60 + (m.status ? 40 : 0);
  if (m.kind === "mcast") return 1316; // RTP/MPEG-TS 7개

  if (m.kind === "ts") {
    const inner = m.inner ?? m.msg?.inner;
    return tsLength(m, inner ? 20 + l4Length(inner.payload) : 0);
  }
  return 4 + m.entries.length * 20; // RIP
}

/** P2P 앱 메시지 길이 (근사): 머리 + 이름 + 후보 */
function p2pLength(m: P2pMessage): number {
  return 8 + m.from.length + (m.to?.length ?? 0) + (m.candidates?.length ?? 0) * 12;
}

/** PPP 길이 (근사): 제어는 짧게, IP 를 실었으면 그 IP 패킷 */
function pppLength(p: L2tpPacket["ppp"]): number {
  if (!p) return 20; // 제어 메시지의 AVP
  if (p.proto === "ip") return 4 + 20 + l4Length(p.packet.payload);
  return 4 + (p.proto === "chap" ? 49 : 10);
}

// ---------- tcpdump 한 줄 ----------

/** 같은 패킷을 tcpdump -n -e 형식 한 줄로 (MAC 주소 포함) */
export function tcpdumpLine(frame: EthernetFrame): string {
  const p = frame.payload;
  if (p.kind === "bpdu") {
    // BPDU 는 EtherType 이 아니라 802.3 길이 + LLC (DSAP 0x42) 로 실린다
    const port = (0x8000 + p.port + 1).toString(16);
    return `${frame.src} > ${frame.dst}, 802.3, length 60: LLC, dsap STP (0x42) Individual, ssap STP (0x42) Command, ctrl 0x03: STP 802.1d, Config, Flags [none], bridge-id ${p.bridge.prio.toString(16)}.${p.bridge.mac}.${port}, length 35 (root ${p.root.prio.toString(16)}.${p.root.mac}, root-pathcost ${p.cost}, message-age ${p.age}s)`;
  }
  const eth = `${frame.src} > ${frame.dst}${frame.vlan !== undefined ? `, 802.1Q vlan ${frame.vlan}` : ""}, ethertype ${p.kind === "arp" ? "ARP (0x0806)" : p.kind === "ipv6" ? "IPv6 (0x86dd)" : "IPv4 (0x0800)"}: `;
  if (p.kind === "ipv6") return eth + ip6Line(p);
  if (p.kind === "arp") {
    return eth + (p.op === "request" ? `ARP, Request who-has ${p.targetIp} tell ${p.senderIp}, length 28` : `ARP, Reply ${p.senderIp} is-at ${p.senderMac}, length 28`);
  }
  return eth + ipLine(p);
}

function ipLine(pkt: Ipv4Packet): string {
  const p = pkt.payload;
  if (p.kind === "icmp") return `IP ${pkt.src} > ${pkt.dst}: ${icmpText(p)}, length ${l4Length(p)}`;
  if (p.kind === "tcp") return `IP ${pkt.src}.${p.srcPort} > ${pkt.dst}.${p.dstPort}: ${tcpText(p)}`;
  if (p.kind === "esp") return `IP ${pkt.src} > ${pkt.dst}: ${espText(p)}, length ${espLength(p)}`;
  if (p.kind === "pfsync") return `IP ${pkt.src} > ${pkt.dst}: pfsync${p.bulk ? " (bulk update)" : ""}, INS ST count ${p.nat.length + p.flows.length}, length ${l4Length(p)}`;
  if (p.kind === "vrrp") return `IP ${pkt.src} > ${pkt.dst}: VRRPv3, Advertisement, vrid ${p.vrid}, prio ${p.priority}, intvl 100cs, length 12`;
  if (p.kind === "igmp") return `IP ${pkt.src} > ${pkt.dst}: igmp ${p.type === "report" ? "v2 report" : "leave"} ${p.group}`;
  return `IP ${pkt.src}.${p.srcPort} > ${pkt.dst}.${p.dstPort}: ${udpText(p)}`;
}

/** tcpdump 의 IPv6 표기: 포트는 주소 뒤에 점으로 (2001:db8::1.80) */
function ip6Line(pkt: Ipv6Packet): string {
  const p = pkt.payload;
  if (p.kind === "icmp6") return `${pkt.src} > ${pkt.dst}: ${icmp6Text(p)}, length ${l6Length(p)}`;
  if (p.kind === "tcp") return `${pkt.src}.${p.srcPort} > ${pkt.dst}.${p.dstPort}: ${tcpText(p)}`;
  return `${pkt.src}.${p.srcPort} > ${pkt.dst}.${p.dstPort}: ${udpText(p)}`;
}

function icmp6Text(p: Icmpv6Packet): string {
  if (p.type === "ns") return `ICMP6, neighbor solicitation, who has ${p.target}`;
  if (p.type === "na") return `ICMP6, neighbor advertisement, tgt is ${p.target}`;
  if (p.type === "rs") return "ICMP6, router solicitation";
  if (p.type === "ra") return "ICMP6, router advertisement";
  if (p.type === "time-exceeded") return "ICMP6, time exceeded in-transit";
  if (p.type === "unreachable") {
    const o = p.original;
    return p.code === "net" ? `ICMP6, destination unreachable, unreachable route ${o.dst}` : p.code === "host" ? `ICMP6, destination unreachable, unreachable address ${o.dst}` : `ICMP6, destination unreachable, unreachable port, ${o.dst} ${o.l4.kind} port ${o.l4.kind === "icmp" ? "?" : o.l4.dstPort}`;
  }
  return `ICMP6, echo ${p.type === "echo-request" ? "request" : "reply"}, id ${p.id}, seq ${p.seq}`;
}

function icmpText(p: IcmpPacket): string {
  if (p.type === "time-exceeded") return "ICMP time exceeded in-transit";
  if (p.type === "unreachable") {
    const o = p.original;
    if (p.code === "port" && o.l4.kind !== "icmp") return `ICMP ${o.dst} ${o.l4.kind} port ${o.l4.dstPort} unreachable`;
    return `ICMP ${p.code} ${o.dst} unreachable`;
  }
  return `ICMP echo ${p.type === "echo-request" ? "request" : "reply"}, id ${p.id}, seq ${p.seq}`;
}

/** tcpdump 의 TCP 플래그 표기: S, S., ., P., F., R. */
function tcpFlagChars(t: TcpSegment): string {
  if (t.rst) return t.ackFlag ? "R." : "R";
  if (t.syn) return t.ackFlag ? "S." : "S";
  if (t.fin) return t.ackFlag ? "F." : "F";
  if (t.len > 0) return "P.";
  return ".";
}

function tcpText(t: TcpSegment): string {
  const parts = [`Flags [${tcpFlagChars(t)}]`];
  if (t.syn || t.fin || t.len > 0 || t.rst) parts.push(t.len > 0 ? `seq ${t.seq}:${t.seq + t.len}` : `seq ${t.seq}`);
  if (t.ackFlag) parts.push(`ack ${t.ack}`);
  parts.push(`length ${t.len}`);
  let s = parts.join(", ");
  // SSH(22)·TLS(HTTPS)는 암호화되어 tcpdump 가 내용을 풀지 않는다
  if (t.len > 0 && (t.srcPort === 445 || t.dstPort === 445)) s += ": SMB-over-TCP packet:(raw data)";
  else if (t.len > 0 && t.data && !t.tls && t.srcPort !== 22 && t.dstPort !== 22) s += `: HTTP: ${/^(GET|CONNECT) /.test(t.data) ? `${t.data} HTTP/1.1` : t.data.replace(/ \(\d+\/\d+\)$/, "").replace(/^HTTP (\d+)/, "HTTP/1.1 $1")}`;
  return s;
}

/** tcpdump 의 ESP 표기 (안은 암호화되어 풀지 못한다) */
function espText(e: EspPacket): string {
  return `ESP(spi=0x${e.spi.toString(16).padStart(8, "0")},seq=0x${e.seq.toString(16)})`;
}

function udpText(u: UdpPacket): string {
  const m = u.payload;
  // tcpdump 는 터널 안을 풀지 못한다 — 암호화되어 있으므로 그냥 UDP 로 보인다
  if (m.kind === "vpn") return `UDP, length ${appLength(u)}`;
  if (m.kind === "esp") return `UDP-encap: ${espText(m)}, length ${appLength(u)}`;
  if (m.kind === "ike") {
    const encap = u.dstPort === 4500 || u.srcPort === 4500 ? "NONESP-encap: " : "";
    // IKEv1 (L2TP/IPsec): Main Mode = phase 1 Identity Protection, Quick Mode = phase 2
    if (m.exchange === "MAIN_MODE") return `${encap}isakmp: phase 1 ${m.response ? "R" : "I"} ident`;
    if (m.exchange === "QUICK_MODE") return `${encap}isakmp: phase 2/others ${m.response ? "R" : "I"} oakley-quick-mode`;
    return `${encap}isakmp: ${m.exchange === "IKE_SA_INIT" ? "parent_sa ikev2_init" : m.exchange === "IKE_AUTH" ? "child_sa  ikev2_auth" : "child_sa  inf2"}[${m.response ? "R" : "I"}]`;
  }
  if (m.kind === "dhcp") {
    const fromClient = m.op === "discover" || m.op === "request" || m.op === "release";
    return `BOOTP/DHCP, ${fromClient ? "Request" : "Reply"} from ${m.clientMac}, length ${appLength(u)} (DHCP-Message Option 53: ${DHCP_TYPE[m.op][1]})`;
  }
  if (m.kind === "dns") {
    const qt = m.qtype ?? "A";
    if (m.op === "query") return `${m.id}+ ${qt}? ${m.name}. (${appLength(u)})`;
    if (m.answer) return `${m.id} 1/0/0 ${qt} ${m.answer} (${appLength(u)})`;
    if (m.rcode === "NODATA") return `${m.id} 0/0/0 (${appLength(u)})`;
    return `${m.id} ${m.rcode === "NXDOMAIN" ? "NXDomain" : "ServFail"} 0/0/0 (${appLength(u)})`;
  }
  if (m.kind === "dhcp6") return `dhcp6 ${m.type}`;
  // L2TP 는 ESP 안에 있어 실제 선에서는 보이지 않는다 (복호화한 쪽에서 볼 때의 표기)
  if (m.kind === "l2tp") return `l2tp:[${m.control ? "TLS" : "LS"}](${m.tunnelId}/${m.sessionId})${m.control ? ` *MSGTYPE(${m.control})` : m.ppp ? ` {${m.ppp.proto === "ip" ? "IP" : `${m.ppp.proto.toUpperCase()} ${m.ppp.code}`}}` : ""}`;
  // tcpdump 는 STUN·앱 메시지를 풀지 않는다
  if (m.kind === "stun" || m.kind === "p2p") return `UDP, length ${appLength(u)}`;
  // WireGuard 도 암호화돼 tcpdump 는 길이만 (148 = Initiation, 92 = Response, 32 = keepalive)
  if (m.kind === "wg") return `UDP, length ${appLength(u)}`;
  if (m.kind === "ddns") return `UDP, length ${appLength(u)}`;
  // OpenVPN 도 tcpdump 는 길이만 (제어 채널은 tls-crypt·TLS, 데이터는 암호화)
  if (m.kind === "ovpn") return `UDP, length ${appLength(u)}`;
  // Tailscale·ZeroTier 도 tcpdump 는 길이만 (WireGuard·암호화)
  if (m.kind === "ts") return `UDP, length ${appLength(u)}`;
  if (m.kind === "cloud") return `UDP, length ${appLength(u)}`;
  if (m.kind === "mcast") return `UDP, length ${appLength(u)}`;
  return `RIPv2, ${m.command === "request" ? "Request" : "Response"}, length: ${appLength(u)}`;
}

// ---------- 계층별 헤더 ----------

export function headerLayers(frame: EthernetFrame): HeaderLayer[] {
  const layers: HeaderLayer[] = [];
  const p = frame.payload;
  const eth: HeaderLayer = {
    title: "이더넷 (L2)",
    rows: [
      ["목적지 MAC", `${frame.dst}${frame.dst === "ff:ff:ff:ff:ff:ff" ? " (브로드캐스트)" : frame.dst.startsWith("01:00:5e") ? " (멀티캐스트)" : frame.dst.startsWith("33:33") ? " (IPv6 멀티캐스트 — 33:33 + 주소 끝 32비트)" : ""}`],
      ["출발지 MAC", frame.src],
      ["EtherType", p.kind === "arp" ? "0x0806 (ARP)" : p.kind === "ipv6" ? "0x86DD (IPv6)" : "0x0800 (IPv4)"],
    ],
  };
  if (frame.vlan !== undefined) eth.rows.splice(2, 0, ["802.1Q 태그", `0x8100, VLAN ${frame.vlan}`]);
  layers.push(eth);
  if (p.kind === "arp") {
    layers.push({
      title: "ARP",
      rows: [
        ["동작 (opcode)", p.op === "request" ? "1 (요청)" : "2 (응답)"],
        ["보낸이 MAC", p.senderMac],
        ["보낸이 IP", `${p.senderIp}${p.senderIp === "0.0.0.0" ? " (ARP Probe — 아직 주소를 쓰지 않음)" : ""}`],
        ["대상 MAC", p.targetMac],
        ["대상 IP", p.targetIp],
      ],
    });
    return layers;
  }
  if (p.kind === "bpdu") {
    eth.rows[2] = ["길이 / LLC", "802.3 길이 필드 + LLC (DSAP·SSAP 0x42 = STP) — IP 없이 이더넷 위에 바로"];
    layers.push({
      title: "STP BPDU (Configuration)",
      rows: [
        ["루트 브리지 ID", `${p.root.prio}.${p.root.mac} (우선순위.MAC — 가장 작은 스위치가 루트)`],
        ["루트까지 비용", String(p.cost)],
        ["보낸 브리지 ID", `${p.bridge.prio}.${p.bridge.mac}`],
        ["보낸 포트", `${p.port}`],
        ["Message Age", `${p.age} (루트에서 거친 스위치 수, 20 을 넘으면 버림)`],
      ],
    });
    return layers;
  }
  if (p.kind === "ipv6") {
    layers.push(...ip6Layers(p));
    return layers;
  }
  layers.push(...ipLayers(p));
  return layers;
}

function ip6Layers(p: Ipv6Packet): HeaderLayer[] {
  const l4 = p.payload;
  const nh = IP6_NEXT_HEADER[l4.kind];
  const layers: HeaderLayer[] = [
    {
      title: "IPv6 (L3)",
      rows: [
        ["버전", "6"],
        ["출발지", `${p.src} (${scopeLabel6(p.src)}${p.src === "::" ? " — DAD: 아직 주소를 쓰지 않음" : ""})`],
        ["목적지", `${p.dst} (${scopeLabel6(p.dst)}${p.dst === "ff02::1" ? " — 모든 노드" : p.dst.startsWith("ff02::1:ff") ? " — solicited-node 그룹" : ""})`],
        ["Hop Limit", `${p.hopLimit}${p.hopLimit === 255 && l4.kind === "icmp6" && (l4.type === "ns" || l4.type === "na") ? " (NDP 는 255 — 라우터를 거쳐 온 가짜를 거르려고)" : ""}`],
        ["Next Header", `${nh.num} (${nh.label})`],
        ["페이로드 길이", `${l6Length(l4)} (근사, 헤더 40바이트 고정 — 체크섬·단편화 필드 없음)`],
      ],
    },
  ];
  if (l4.kind === "icmp6") layers.push(icmp6Layer(l4));
  else if (l4.kind === "tcp") layers.push(...tcpLayers(l4));
  else layers.push(...udpLayers(l4));
  return layers;
}

function icmp6Layer(p: Icmpv6Packet): HeaderLayer {
  if (p.type === "ns")
    return {
      title: "ICMPv6 · NDP",
      rows: [
        ["타입 / 코드", "135 / 0 (Neighbor Solicitation — ARP 요청에 해당)"],
        ["대상 주소", p.target],
        ...(p.sll ? ([["옵션 1 출발지 링크 계층 주소", p.sll]] as [string, string][]) : ([["옵션", "없음 (DAD — 출발지가 :: 라 링크 계층 주소도 싣지 않음)"]] as [string, string][])),
      ],
    };
  if (p.type === "na")
    return {
      title: "ICMPv6 · NDP",
      rows: [
        ["타입 / 코드", "136 / 0 (Neighbor Advertisement — ARP 응답에 해당)"],
        ["플래그", `R=${p.router ? 1 : 0} (라우터) · S=${p.solicited ? 1 : 0} (요청에 대한 답) · O=${p.override ? 1 : 0} (캐시 덮어쓰기)`],
        ["대상 주소", p.target],
        ...(p.tll ? ([["옵션 2 대상 링크 계층 주소", p.tll]] as [string, string][]) : []),
      ],
    };
  if (p.type === "rs")
    return {
      title: "ICMPv6 · NDP",
      rows: [
        ["타입 / 코드", "133 / 0 (Router Solicitation — 라우터를 찾는다)"],
        ...(p.sll ? ([["옵션 1 출발지 링크 계층 주소", p.sll]] as [string, string][]) : []),
      ],
    };
  if (p.type === "ra") {
    const rows: [string, string][] = [
      ["타입 / 코드", "134 / 0 (Router Advertisement)"],
      ["Cur Hop Limit", `${p.curHopLimit} (호스트가 쓸 기본 Hop Limit)`],
      ["플래그", `M=${p.managed ? 1 : 0} (주소는 DHCPv6) · O=${p.other ? 1 : 0} (그 밖의 정보는 DHCPv6) — 둘 다 0 이면 SLAAC 만`],
      ["라우터 수명", `${p.routerLifetime}초${p.routerLifetime === 0 ? " (나를 기본 게이트웨이로 쓰지 말라)" : " (0 이 아니면 기본 게이트웨이 후보)"}`],
    ];
    for (const x of p.prefixes) rows.push(["옵션 3 프리픽스 정보", `${x.prefix}/${x.length} · L=${x.onLink ? 1 : 0} A=${x.autonomous ? 1 : 0} · 유효 수명 ${x.valid}초${x.valid === 0 ? " (거둠 — 이 프리픽스로 만든 주소를 지우라)" : ""}`]);
    if (p.rdnss?.length) rows.push(["옵션 25 RDNSS", `${p.rdnss.join(", ")} (DNS 서버, RFC 8106)`]);
    if (p.sll) rows.push(["옵션 1 출발지 링크 계층 주소", p.sll]);
    return { title: "ICMPv6 · NDP", rows };
  }
  if (p.type === "time-exceeded" || p.type === "unreachable") {
    const code = p.type === "time-exceeded" ? "3 / 0 (Time Exceeded — Hop Limit 초과)" : `1 / ${UNREACHABLE6_CODE[p.code]} (Destination Unreachable — ${p.code === "net" ? "no route to destination" : p.code === "host" ? "address unreachable" : "port unreachable"}, traceroute 표기 ${UNREACHABLE_FLAG[p.code]})`;
    return { title: "ICMPv6", rows: [["타입 / 코드", code], ["안에 담긴 원래 패킷", describeOriginal(p.original)]] };
  }
  return {
    title: "ICMPv6",
    rows: [
      ["타입 / 코드", p.type === "echo-request" ? "128 / 0 (Echo 요청)" : "129 / 0 (Echo 응답)"],
      ["식별자 (id)", String(p.id)],
      ["순서 (seq)", String(p.seq)],
    ],
  };
}

/** IPv4 부터 위 계층. VPN 터널이면 암호화 층 뒤에 "터널 안(복호화하면)" 원래 패킷을 겹겹이 */
function ipLayers(p: Ipv4Packet, inTunnel = false): HeaderLayer[] {
  const layers: HeaderLayer[] = [];
  const l4 = p.payload;
  const proto = `${IP_PROTO[l4.kind].num} (${IP_PROTO[l4.kind].label})`;
  layers.push({
    title: "IPv4 (L3)",
    rows: [
      ["출발지", p.src],
      ["목적지", p.dst],
      ["TTL", String(p.ttl)],
      ["프로토콜", proto],
      ["전체 길이", `${20 + l4Length(l4)} (근사)`],
    ],
  });
  if (l4.kind === "icmp") layers.push(icmpLayer(l4));
  else if (l4.kind === "tcp") layers.push(...tcpLayers(l4));
  else if (l4.kind === "esp") layers.push(espLayer(l4, false), ...espInner(l4));
  else if (l4.kind === "pfsync")
    layers.push({
      title: "세션 동기화 (pfsync)",
      rows: [
        ["종류", l4.bulk ? "전체 복사 (새 backup 에게)" : "새 상태 추가 (INS ST)"],
        ["그룹 (VRID)", String(l4.vrid)],
        ["NAT 매핑", l4.nat.length ? l4.nat.slice(0, 4).map((e) => `${e.lanIp}:${e.innerId} → 공인 ${e.publicId} (${e.proto.toUpperCase()})`).join(", ") + (l4.nat.length > 4 ? ` 외 ${l4.nat.length - 4}` : "") : "없음"],
        ["방화벽 흐름", `${l4.flows.length}개`],
      ],
    });
  else if (l4.kind === "vrrp")
    layers.push({
      title: "VRRP",
      rows: [
        ["버전 / 종류", "3 / 1 (Advertisement)"],
        ["가상 라우터 번호 (VRID)", `${l4.vrid} → 가상 MAC 00:00:5e:00:01:${l4.vrid.toString(16).padStart(2, "0")}`],
        ["우선순위", `${l4.priority}${l4.priority === 0 ? " (master 가 물러남 — backup 이 곧 이어받음)" : ""}`],
        ["가상 주소", l4.vip],
      ],
    });
  else if (l4.kind === "igmp")
    layers.push({
      title: "IGMP",
      rows: [
        ["종류", l4.type === "report" ? "0x16 (v2 Membership Report — 이 그룹을 받겠다)" : "0x17 (Leave Group — 그만 받겠다)"],
        ["그룹", l4.group],
        ["스누핑", "IGMP 스누핑 스위치는 이것을 엿들어 그룹마다 받을 포트를 배운다"],
      ],
    });
  else {
    layers.push(...udpLayers(l4));
    if (l4.payload.kind === "esp") layers.push(espLayer(l4.payload, true), ...espInner(l4.payload));
    if (l4.payload.kind === "vpn") {
      const inner = l4.payload.inner;
      layers.push({
        title: "VPN (WireGuard 식)",
        rows: [
          ["종류", "전송 데이터 (type 4)"],
          ["안쪽", "암호화됨 — 인터넷 위의 장비는 아래 원래 패킷을 볼 수 없다"],
          ["원래 패킷 (복호화하면)", `${inner.src} → ${inner.dst}`],
        ],
      });
      layers.push(...ipLayers(inner, true));
    }
    if (l4.payload.kind === "wg") {
      const m = l4.payload;
      layers.push(wgLayer(m));
      if (m.inner && !m.obf) layers.push(...ipLayers(m.inner, true));
    }
    if (l4.payload.kind === "ovpn") {
      layers.push(ovpnLayer(l4.payload));
      if (l4.payload.inner) layers.push(...ipLayers(l4.payload.inner, true));
    }
    if (l4.payload.kind === "ts") {
      const m = l4.payload;
      layers.push(tsLayer(m));
      if (m.msg) layers.push(tsLayer(m.msg));
      const inner = m.inner ?? m.msg?.inner;
      if (inner) layers.push(...ipLayers(inner, true));
    }
  }
  return inTunnel ? layers.map((l) => ({ ...l, title: `터널 안 · ${l.title}` })) : layers;
}

const OVPN_OPCODE: Record<OvpnMessage["op"], string> = {
  "reset-client": "7 (P_CONTROL_HARD_RESET_CLIENT_V2)",
  "reset-server": "8 (P_CONTROL_HARD_RESET_SERVER_V2)",
  "tls-client": "4 (P_CONTROL_V1 — TLS ClientHello)",
  "tls-server": "4 (P_CONTROL_V1 — TLS ServerHello·인증서)",
  "tls-auth": "4 (P_CONTROL_V1 — TLS 클라이언트 인증서·계정)",
  "tls-ok": "4 (P_CONTROL_V1 — TLS Finished)",
  "tls-fail": "4 (P_CONTROL_V1 — TLS alert / AUTH_FAILED)",
  "push-request": "4 (P_CONTROL_V1 — PUSH_REQUEST)",
  "push-reply": "4 (P_CONTROL_V1 — PUSH_REPLY)",
  data: "9 (P_DATA_V2)",
  ping: "9 (P_DATA_V2 — keepalive ping)",
  exit: "9 (P_DATA_V2 — EXIT / RESTART 알림)",
};

/** Tailscale·ZeroTier 층 */
function tsLayer(m: TsMessage): HeaderLayer {
  const brand = m.net === "zerotier" ? "ZeroTier" : "Tailscale";
  const rows: [string, string][] = [["메시지", tsLabel(m).replace(`${brand} `, "")]];
  if (m.network) rows.push([m.net === "zerotier" ? "네트워크 ID" : "tailnet", m.network]);
  if (m.name) rows.push(["기기 이름", m.name]);
  if (m.key) rows.push(["보낸 노드 키", `${m.key.slice(0, 8)}…`]);
  if (m.to) rows.push(["받을 노드 키", `${m.to.slice(0, 8)}… — 릴레이는 이 키의 기기에게 전해 준다 (내용은 못 봄)`]);
  if (m.endpoints?.length) rows.push(["후보 주소", m.endpoints.map((e) => `${e.ip}:${e.port}`).join(", ")]);
  if (m.self) rows.push(["내 주소", `${m.self.ip}/${m.self.prefix} (${m.self.name})`]);
  if (m.peers) rows.push(["피어", m.peers.map((p) => `${p.name} ${p.ip}${p.routes.length ? ` [${p.routes.map((r) => `${r.dest}/${r.prefix}`).join(", ")}]` : ""}${p.exitNode ? " exit" : ""}`).join(" · ") || "(없음)"]);
  if (m.routes?.length) rows.push(["알린 대역 (서브넷 라우터)", m.routes.map((r) => `${r.dest}/${r.prefix}`).join(", ")]);
  if (m.seen) rows.push(["내가 본 당신 주소", `${m.seen.ip}:${m.seen.port}`]);
  if (m.reason) rows.push(["이유", m.reason]);
  if (m.op === "data") rows.push(["안쪽", "WireGuard 로 암호화 — 두 끝만 아래 원래 패킷을 본다"]);
  return { title: brand, rows };
}

/** OpenVPN 층: 바깥에서 보이는 opcode·세션 id 와, 두 끝이 풀면 보이는 내용 */
function ovpnLayer(m: OvpnMessage): HeaderLayer {
  const rows: [string, string][] = [
    ["opcode", OVPN_OPCODE[m.op]],
    ["세션 id", String(m.sid)],
  ];
  if (m.crypt) rows.push(["tls-crypt", `키 ${m.crypt.slice(0, 11)}… 로 감쌈 — 같은 키가 없으면 열지 못하고(서버는 답하지 않음), 중간 장비도 인증서를 못 본다`]);
  else if (m.op !== "data" && m.op !== "ping" && m.op !== "exit") rows.push(["tls-crypt", "없음 — 제어 채널의 TLS 핸드셰이크(인증서)가 중간 장비에도 보인다"]);
  if (m.cert) rows.push([m.op === "tls-server" ? "서버 인증서" : "클라이언트 인증서", `CN=${m.cert.cn}, 발급 CA ${m.cert.ca.slice(0, 11)}…`]);
  if (m.user) rows.push(["계정 (auth-user-pass)", `${m.user} / ••••`]);
  if (m.op === "tls-fail") rows.push(["결과", m.reason === "AUTH_FAILED" ? "AUTH_FAILED" : m.reason === "revoked" ? "인증서 폐기됨 (CRL)" : "인증서 확인 실패 (다른 CA)"]);
  if (m.push) rows.push(["PUSH_REPLY", [m.push.redirectGateway ? "redirect-gateway def1" : "", ...m.push.routes.map((r) => `route ${r.dest}/${r.prefix}`), m.push.dns ? `dhcp-option DNS ${m.push.dns}` : "", `ifconfig ${m.push.ip}/${m.push.prefix}`].filter(Boolean).join(", ")]);
  if (m.op === "data" && m.inner) rows.push(["안쪽", "암호화됨 — 두 끝만 아래 원래 패킷을 본다"]);
  if (m.reason === "restart") rows.push(["알림", "서버가 다시 시작함 — 클라이언트는 다시 연결"]);
  return { title: "OpenVPN", rows };
}

function wgLayer(m: WgMessage): HeaderLayer {
  // 난독화: 밖(중간 장비·tcpdump)에서는 모양을 알아볼 수 없다 — 두 끝만 WireGuard 로 푼다
  if (m.type === "junk")
    return { title: "UDP 내용 (난독화)", rows: [["모양", "알아볼 수 없음 — 핸드셰이크 앞에 섞은 쓰레기 패킷 (AmneziaWG 식). 받는 쪽은 버린다"]] };
  if (m.obf)
    return {
      title: "UDP 내용 (난독화)",
      rows: [
        ["모양", "알아볼 수 없음 — 머리·크기를 흐트러뜨려 DPI 가 WireGuard 로 알아보지 못한다"],
        ["두 끝이 풀면", m.type === "initiation" ? "WireGuard 핸드셰이크 시작 (Initiation)" : m.type === "response" ? "WireGuard 핸드셰이크 응답 (Response)" : m.inner ? `WireGuard 데이터 (안: ${m.inner.src} → ${m.inner.dst})` : "WireGuard keepalive"],
      ],
    };
  if (m.type === "initiation")
    return {
      title: "WireGuard",
      rows: [
        ["종류", "1 (Handshake Initiation, 148바이트)"],
        ["보낸 세션 번호 (sender)", String(m.sender)],
        ["정적 공개 키", `${m.static ?? "?"} — 상대 공개 키로 암호화돼 상대만 읽음`],
        ["mac1", `받는 쪽 공개 키 ${m.to ?? "?"} 로 만든 값 — 받는 쪽은 이것부터 확인하고 맞지 않으면 답하지 않는다`],
      ],
    };
  if (m.type === "response")
    return {
      title: "WireGuard",
      rows: [
        ["종류", "2 (Handshake Response, 92바이트)"],
        ["보낸 세션 번호 (sender)", String(m.sender)],
        ["받는 세션 번호 (receiver)", `${m.receiver} — 시작한 쪽이 Initiation 에 적은 번호`],
        ["결과", "세션 키 생성 (1-RTT). 이제 양쪽이 데이터를 암호화해 주고받는다"],
      ],
    };
  return {
    title: "WireGuard",
    rows: [
      ["종류", m.inner ? "4 (Transport Data)" : "4 (Transport Data, 빈 내용 = keepalive)"],
      ["받는 세션 번호 (receiver)", String(m.receiver)],
      ["counter", `${m.counter ?? 0} (재전송 공격 방지)`],
      ...(m.inner
        ? ([
            ["안쪽", "암호화됨 — 인터넷 위의 장비는 아래 원래 패킷을 볼 수 없다"],
            ["원래 패킷 (복호화하면)", `${m.inner.src} → ${m.inner.dst}`],
          ] as [string, string][])
        : ([["안쪽", "없음 — 받았다는 표시(keepalive)"]] as [string, string][])),
    ],
  };
}

function espLayer(e: EspPacket, natT: boolean): HeaderLayer {
  return {
    title: natT ? "ESP (IPsec, UDP 4500 안 — NAT-T)" : "ESP (IPsec)",
    rows: [
      ["SPI", `0x${e.spi.toString(16).padStart(8, "0")} (이 터널의 번호)`],
      ["순서 번호", `${e.seq} (재전송 공격 방지)`],
      ...(e.transport
        ? ([
            ["모드", "전송 모드 — 바깥 IP 헤더를 그대로 두고 그 뒤(UDP 1701 L2TP)만 암호화. 안쪽 IP 헤더가 따로 없다"],
            ["안쪽", "암호화됨 — 인터넷 위의 장비는 아래 L2TP·PPP 를 볼 수 없다"],
          ] as [string, string][])
        : ([
            ["안쪽", "암호화됨 — 인터넷 위의 장비는 아래 원래 패킷을 볼 수 없다"],
            ["원래 패킷 (복호화하면)", `${e.inner.src} → ${e.inner.dst}`],
          ] as [string, string][])),
    ],
  };
}

/** ESP 의 안쪽: 터널 모드는 원래 IP 패킷 통째, 전송 모드(L2TP/IPsec)는 IP 헤더 없이 그 뒤(UDP 1701)부터 */
function espInner(e: EspPacket): HeaderLayer[] {
  if (e.transport && e.inner.payload.kind === "udp") return udpLayers(e.inner.payload).map((l) => ({ ...l, title: `ESP 안 · ${l.title}` }));
  return ipLayers(e.inner, true);
}

function ikeLayer(m: IkeMessage): HeaderLayer {
  const rows: [string, string][] = [
    [
      "교환",
      `${m.exchange === "IKE_SA_INIT" ? "34 (IKE_SA_INIT)" : m.exchange === "IKE_AUTH" ? "35 (IKE_AUTH)" : m.exchange === "MAIN_MODE" ? `2 (Identity Protection = Main Mode — ${m.auth !== undefined || (m.response && m.error) ? "ID·HASH: PSK 인증" : "SA·KE·NAT-D"})` : m.exchange === "QUICK_MODE" ? "32 (Quick Mode)" : "37 (INFORMATIONAL)"} ${m.response ? "응답" : "요청"}`,
    ],
    ["SPI", `0x${m.spi.toString(16).padStart(8, "0")}`],
  ];
  if (m.natSrc) rows.push(["NAT_DETECTION_SOURCE_IP", `${m.natSrc} (실제로는 해시)`]);
  if (m.natDst) rows.push(["NAT_DETECTION_DESTINATION_IP", `${m.natDst} (실제로는 해시)`]);
  if (m.nat !== undefined) rows.push(["NAT 감지 결과", m.nat ? "NAT 있음 → 이후 UDP 4500" : "NAT 없음"]);
  if (m.user !== undefined) rows.push(["IDi (사용자 이름)", m.user]);
  if (m.auth !== undefined) rows.push(["AUTH", "사전 공유 키로 만든 인증 값 (키 자체는 보내지 않음)"]);
  // EAP 는 IKE_AUTH 의 암호화된 SK 페이로드 안에 있다 — tcpdump 는 ikev2_auth 로만 보고, 두 끝만 풀어 본다
  if (m.eap === "request") rows.push(["EAP (SK 페이로드 안)", "코드 1 (Request) · 타입 26 (MSCHAPv2) — 서버의 challenge"]);
  if (m.eap === "response") rows.push(["EAP (SK 페이로드 안)", "코드 2 (Response) · 타입 26 (MSCHAPv2) — 비밀번호로 만든 응답 값 (비밀번호 자체는 보내지 않음)"]);
  if (m.eap === "success") rows.push(["EAP (SK 페이로드 안)", "코드 3 (Success) — 계정 인증 성공"]);
  if (m.eap === "failure") rows.push(["EAP (SK 페이로드 안)", "코드 4 (Failure) — 계정 또는 비밀번호가 틀림"]);
  if (m.error) rows.push(["알림 (Notify)", `${m.error === "AUTHENTICATION_FAILED" ? 24 : m.error === "INTERNAL_ADDRESS_FAILURE" ? 36 : 11} (${m.error})`]);
  if (m.assigned) rows.push(["가상 주소 (CP INTERNAL_IP4_ADDRESS)", m.assigned]);
  if (m.routes?.length) rows.push(["사내 대역 (CP INTERNAL_IP4_SUBNET)", m.routes.map((r) => `${r.dest}/${r.prefix}`).join(", ")]);
  if (m.dpd && !m.error) rows.push(["DPD", "페이로드 없는 빈 INFORMATIONAL — 상대가 살아 있고 이 SA 를 아는지 확인 (응답도 빈 INFORMATIONAL)"]);
  if (m.exchange === "INFORMATIONAL" && !m.error && !m.dpd) rows.push(["Delete", "터널을 내린다 (연결 해제)"]);
  if (m.exchange === "QUICK_MODE") rows.push(["보호할 것", "UDP 1701 (L2TP) — ESP 전송 모드 (두 장치 사이의 L2TP 만 암호화)"]);
  return { title: m.exchange === "MAIN_MODE" || m.exchange === "QUICK_MODE" ? "IKEv1 (앱 — L2TP/IPsec)" : "IKEv2 (앱)", rows };
}

function icmpLayer(p: IcmpPacket): HeaderLayer {
  if (p.type !== "time-exceeded" && p.type !== "unreachable") {
    return {
      title: "ICMP",
      rows: [
        ["타입 / 코드", p.type === "echo-request" ? "8 / 0 (Echo 요청)" : "0 / 0 (Echo 응답)"],
        ["식별자 (id)", String(p.id)],
        ["순서 (seq)", String(p.seq)],
      ],
    };
  }
  const code =
    p.type === "time-exceeded"
      ? "11 / 0 (Time Exceeded — TTL 초과)"
      : `3 / ${p.code === "net" ? 0 : p.code === "host" ? 1 : 3} (Destination ${p.code === "net" ? "Net" : p.code === "host" ? "Host" : "Port"} Unreachable, traceroute 표기 ${UNREACHABLE_FLAG[p.code]})`;
  return {
    title: "ICMP",
    rows: [
      ["타입 / 코드", code],
      ["안에 담긴 원래 패킷", describeOriginal(p.original)],
    ],
  };
}

/** TCP 층과, TLS 레코드면 그 위의 TLS 층 (응용 데이터의 HTTP 헤더는 TLS 안에 있어 TLS 층에 둔다) */
function tcpLayers(t: TcpSegment): HeaderLayer[] {
  if (t.ovpn) {
    const tcp = tcpLayer({ kind: "tcp", srcPort: t.srcPort, dstPort: t.dstPort, seq: t.seq, ack: t.ack, syn: t.syn, ackFlag: t.ackFlag, fin: t.fin, rst: t.rst, len: t.len });
    tcp.rows.push(["데이터", "OpenVPN 패킷 (앞 2바이트 = 길이, TCP 스트림 위)"]);
    return [tcp, ovpnLayer(t.ovpn), ...(t.ovpn.inner ? ipLayers(t.ovpn.inner, true) : [])];
  }
  if (!t.tls) return [tcpLayer(t)];
  const tcp = tcpLayer({ kind: "tcp", srcPort: t.srcPort, dstPort: t.dstPort, seq: t.seq, ack: t.ack, syn: t.syn, ackFlag: t.ackFlag, fin: t.fin, rst: t.rst, len: t.len });
  tcp.rows.push(["데이터", "TLS 레코드 (아래)"]);
  const rows: [string, string][] = [];
  if (t.tls === "client-hello") {
    rows.push(["레코드", "Handshake (22) · ClientHello (1)"]);
    rows.push(["SNI (서버 이름)", t.sni ? `${t.sni} — 암호화 전이라 중간 장비(프록시·방화벽)도 본다` : "없음 (주소로 접속)"]);
  } else if (t.tls === "server-hello") {
    rows.push(["레코드", "Handshake (22) · ServerHello (2)"]);
    rows.push(["그 뒤", "인증서·Finished 는 암호화 (TLS 1.3)"]);
  } else {
    rows.push(["레코드", "Application Data (23) · 암호화됨 — 중간 장비는 길이만 본다"]);
    const inner = [t.tls === "finished" ? "Finished (핸드셰이크 끝)" : t.data, t.via !== undefined ? `Via ${t.via}` : "", t.cookie ? `Cookie: ${t.cookie}` : "", t.setCookie ? `Set-Cookie: ${t.setCookie}` : "", t.origin ? `X-Served-By: ${t.origin}` : ""].filter(Boolean);
    rows.push(["안 (두 끝만 풂)", inner.join(" · ")]);
  }
  return [tcp, { title: "TLS 1.3", rows }];
}

function tcpLayer(t: TcpSegment): HeaderLayer {
  const rows: [string, string][] = [
    ["출발지 포트", String(t.srcPort)],
    ["목적지 포트", `${t.dstPort}${t.dstPort === 80 ? " (HTTP)" : t.dstPort === 443 ? " (HTTPS)" : t.dstPort === 22 ? " (SSH)" : t.dstPort === 3128 ? " (HTTP 프록시)" : t.dstPort === 445 ? " (SMB 파일 공유)" : ""}`],
    ["순서 번호 (seq)", String(t.seq)],
    ["확인 번호 (ack)", t.ackFlag ? String(t.ack) : "- (ACK 플래그 없음)"],
    ["플래그", `${tcpFlags(t)} [${tcpFlagChars(t)}]`],
    ["데이터 길이", `${t.len}B`],
  ];
  if (t.data) rows.push(["데이터 (요약)", t.srcPort === 22 || t.dstPort === 22 ? "SSH 암호화 데이터 (내용은 다루지 않음)" : t.data]);
  if (t.target && t.method === "CONNECT") rows.push(["요청 (CONNECT)", `CONNECT ${t.target} HTTP/1.1 — 프록시에게 대상까지 TCP 터널을 열어 달라는 요청`]);
  else if (t.target) rows.push(["요청 대상 (절대 URI)", `http://${t.target.replace(/:80$/, "")}/ — 프록시에게 대신 받아 달라는 요청`]);
  if (t.via !== undefined) rows.push(["Via (HTTP 헤더 흉내)", `로드밸런서·프록시 ${t.via}개 거침`]);
  if (t.cookie) rows.push(["Cookie", t.cookie]);
  if (t.setCookie) rows.push(["Set-Cookie", `${t.setCookie}; path=/ — 로드밸런서가 넣은 세션 고정 쿠키`]);
  if (t.origin) rows.push(["X-Served-By (흉내)", t.origin]);
  return { title: "TCP (L4)", rows };
}

function udpLayers(u: UdpPacket): HeaderLayer[] {
  const m = u.payload;
  const udp: HeaderLayer = { title: "UDP (L4)", rows: [["출발지 포트", String(u.srcPort)], ["목적지 포트", String(u.dstPort)], ["길이", `${8 + appLength(u)} (근사)`]] };
  if (m.kind === "dhcp") {
    const [n, name] = DHCP_TYPE[m.op];
    const fromClient = m.op === "discover" || m.op === "request" || m.op === "release";
    const rows: [string, string][] = [
      ["op", fromClient ? "1 (BOOTREQUEST)" : "2 (BOOTREPLY)"],
      ["트랜잭션 id (xid)", `0x${m.xid.toString(16)}`],
      ["클라이언트 MAC (chaddr)", m.clientMac],
    ];
    if (m.yiaddr) rows.push(["줄 주소 (yiaddr)", m.yiaddr]);
    if (m.giaddr) rows.push(["릴레이 주소 (giaddr)", m.giaddr]);
    rows.push(["옵션 53 메시지 종류", `${n} (${name})`]);
    if (m.requestedIp) rows.push(["옵션 50 요청 주소", m.requestedIp]);
    if (m.serverId) rows.push(["옵션 54 서버 식별자", m.serverId]);
    if (m.options?.prefix !== undefined) rows.push(["옵션 1 서브넷 마스크", `/${m.options.prefix}`]);
    if (m.options?.router) rows.push(["옵션 3 기본 게이트웨이", m.options.router]);
    if (m.options?.dns) rows.push(["옵션 6 DNS 서버", m.options.dns]);
    if (m.options?.leaseTime) rows.push(["옵션 51 임대 시간", `${m.options.leaseTime}초`]);
    return [udp, { title: "DHCP (앱)", rows }];
  }
  if (m.kind === "dns") {
    const rows: [string, string][] = [
      ["id", String(m.id)],
      ["QR", m.op === "query" ? "0 (질의)" : "1 (응답)"],
      ["질문", `${m.name} ${m.qtype ?? "A"}${m.qtype === "AAAA" ? " (IPv6 주소)" : ""}`],
    ];
    if (m.op === "response")
      rows.push([
        "응답",
        m.answer
          ? `${m.name} ${m.qtype ?? "A"} ${m.answer}`
          : m.rcode === "NODATA"
            ? `없음 (rcode 0 NOERROR, 답 0개 — 이름은 있지만 ${m.qtype ?? "A"} 레코드가 없음)`
            : `없음 (rcode ${m.rcode === "NXDOMAIN" ? "3 NXDOMAIN" : "2 SERVFAIL"})`,
      ]);
    return [udp, { title: "DNS (앱)", rows }];
  }
  if (m.kind === "vpn" || m.kind === "esp" || m.kind === "wg" || m.kind === "ovpn" || m.kind === "ts") return [udp];
  if (m.kind === "mcast") return [udp, { title: "멀티캐스트 스트림 (앱)", rows: [["채널", m.name], ["그룹", m.group], ["순번", `${m.seq}/${m.total}`]] }];
  if (m.kind === "cloud")
    return [
      udp,
      {
        title: "GoodCloud (앱)",
        rows: [
          ["메시지", cloudLabel(m)],
          ["기기", `${m.name ?? ""} (${m.device})`],
          ...(m.status ? ([["상태", `WAN ${m.status.wan} · 기기 ${m.status.clients}대 · VPN ${m.status.vpn}`]] as [string, string][]) : []),
          ["참고", "실제는 HTTPS(WebSocket) — 여기서는 UDP 로 줄임. 공유기가 먼저 연 연결이라 포트 포워딩이 필요 없다"],
        ],
      },
    ];
  if (m.kind === "ddns")
    return [
      udp,
      {
        title: "DDNS (앱)",
        rows: [
          ["요청", m.op === "update" ? `GET /nic/update?hostname=${m.hostname} (실제는 HTTPS — 여기서는 UDP 8245 로 줄임)` : `응답 ${m.result}${m.ip ? ` ${m.ip}` : ""}`],
          ["이름", m.hostname],
          ...(m.op === "update" ? ([["주소", "적지 않음 — 서버가 이 요청의 출발지(공인 주소)를 등록"]] as [string, string][]) : []),
        ],
      },
    ];
  if (m.kind === "ike") return [udp, ikeLayer(m)];
  if (m.kind === "dhcp6") {
    const TYPE: Record<typeof m.type, string> = { solicit: "1 (Solicit)", advertise: "2 (Advertise)", request: "3 (Request)", reply: "7 (Reply)", release: "8 (Release)" };
    const rows: [string, string][] = [
      ["msg-type", TYPE[m.type]],
      ["트랜잭션 id", `0x${m.xid.toString(16)}`],
      ["옵션 1 Client ID", `DUID-LL ${m.clientId}`],
    ];
    if (m.serverId) rows.push(["옵션 2 Server ID", `DUID-LL ${m.serverId}`]);
    const what =
      m.type === "advertise" ? "이 프리픽스를 위임하겠다는 제안" : m.type === "reply" ? "이 프리픽스를 통째로 맡긴다 (위임 확정)" : m.type === "request" ? "제안받은 이 프리픽스를 쓰겠다는 확정 요청" : m.type === "release" ? "이 프리픽스를 돌려준다" : "이 프리픽스를 원한다";
    rows.push(["옵션 25 IA_PD", m.prefix ? `옵션 26 IAPREFIX ${m.prefix.prefix}/${m.prefix.length} — ${what}` : m.status ? `옵션 13 Status ${m.status} (위임할 프리픽스 없음)` : "프리픽스를 위임해 달라는 요청 (IAPREFIX 없음)"]);
    return [udp, { title: "DHCPv6 (앱)", rows }];
  }
  if (m.kind === "l2tp") return [udp, ...l2tpLayers(m)];
  if (m.kind === "stun") return [udp, stunLayer(m), ...(m.data ? [p2pLayer(m.data, true)] : [])];
  if (m.kind === "p2p") return [udp, p2pLayer(m, false)];
  return [
    udp,
    {
      title: "RIP (앱)",
      rows: [
        ["명령", m.command === "request" ? "1 (Request)" : "2 (Response)"],
        ["버전", "2"],
        ...m.entries.map((e, i): [string, string] => [`경로 ${i + 1}`, `${e.dest}/${e.prefix} 메트릭 ${e.metric}${e.metric >= 16 ? " (도달 불가·철회)" : ""}`]),
      ],
    },
  ];
}

const STUN_TYPE: Record<StunMessage["op"], string> = {
  "binding-request": "0x0001 Binding Request",
  "binding-response": "0x0101 Binding Success Response",
  "allocate-request": "0x0003 Allocate Request (TURN)",
  "allocate-response": "0x0103 Allocate Success Response (TURN)",
  send: "0x0016 Send Indication (TURN)",
  data: "0x0017 Data Indication (TURN)",
};

function stunLayer(m: StunMessage): HeaderLayer {
  const ep = (e: { ip: string; port: number }) => `${e.ip}:${e.port}`;
  const rows: [string, string][] = [
    ["메시지 종류", STUN_TYPE[m.op]],
    ["트랜잭션 ID", `0x${m.txid.toString(16).padStart(8, "0")} (요청과 응답의 짝)`],
  ];
  if (m.mapped) rows.push(["XOR-MAPPED-ADDRESS", `${ep(m.mapped)} — 서버가 본 요청의 출발지 = NAT 바깥의 내 주소:포트`]);
  if (m.relayed) rows.push(["XOR-RELAYED-ADDRESS", `${ep(m.relayed)} — 상대에게 알려 줄 릴레이 주소`]);
  if (m.peer) rows.push(["XOR-PEER-ADDRESS", `${ep(m.peer)} — ${m.op === "send" ? "릴레이가 보낼 상대" : "릴레이에 보낸 상대"}`]);
  return { title: m.op.startsWith("binding") ? "STUN (앱)" : "TURN (앱)", rows };
}

function p2pLayer(m: P2pMessage, inRelay: boolean): HeaderLayer {
  const rows: [string, string][] = [
    ["종류", P2P_OP_TEXT[m.op]],
    ["보낸 이", m.from],
  ];
  if (m.to) rows.push(["받을 이", m.to]);
  if (m.candidates?.length) rows.push(["후보 (ICE)", m.candidates.map((c) => `${c.type} ${c.ip}:${c.port}`).join(", ")]);
  if (m.nat) rows.push(["내 NAT 짐작", m.nat === "symmetric" ? "symmetric (상대마다 바깥 포트가 다름 — 홀 펀칭이 어려움)" : m.nat === "cone" ? "cone (바깥 포트가 상대와 무관)" : "없음 (공인 주소)"]);
  if (m.error) rows.push(["오류", m.error]);
  return { title: `${inRelay ? "TURN 안 · " : ""}P2P 앱`, rows };
}

const P2P_OP_TEXT: Record<P2pMessage["op"], string> = {
  register: "register — 시그널링 서버에 이름 등록 (서버가 본 바깥 주소로 나중에 연락)",
  registered: "registered — 등록됨",
  unregister: "unregister — 등록 해제 (앱을 끄거나 이름을 바꿈)",
  busy: "busy — 다른 상대와 연결 중이라 거절",
  offer: "offer — 내 후보 주소들을 상대에게 (시그널링 서버 경유)",
  answer: "answer — 상대의 후보 주소들 (시그널링 서버 경유)",
  relay: "relay — 직접 안 되니 이 TURN 릴레이 주소로 보내 달라",
  punch: "punch — 상대 후보로 직접 보내 내 NAT 에 구멍을 뚫는다",
  "punch-ack": "punch-ack — 구멍으로 들어온 것을 확인",
  error: "error",
};

/** L2TP 와 그 위의 PPP (데이터면 PPP 안의 IP 까지) — L2TP/IPsec 의 안쪽 겹 */
function l2tpLayers(l: L2tpPacket): HeaderLayer[] {
  const CONTROL: Record<NonNullable<L2tpPacket["control"]>, string> = {
    SCCRQ: "1 SCCRQ (터널 열기 요청)",
    SCCRP: "2 SCCRP (터널 열기 응답)",
    ICRQ: "10 ICRQ (세션 열기 요청)",
    ICRP: "11 ICRP (세션 열기 응답)",
    CDN: "14 CDN (세션 끊기)",
    StopCCN: "4 StopCCN (터널 끊기)",
  };
  const l2tp: HeaderLayer = {
    title: "L2TP (UDP 1701)",
    rows: [
      ["종류", l.control ? "제어 메시지" : "데이터 (PPP 를 실음)"],
      ["터널 / 세션 번호", `${l.tunnelId} / ${l.sessionId}`],
      ...(l.control ? [["메시지", CONTROL[l.control]] as [string, string]] : []),
    ],
  };
  const p = l.ppp;
  if (!p) return [l2tp];
  if (p.proto === "ip") return [l2tp, { title: "PPP", rows: [["프로토콜", "0x0021 (IPv4) — 이 아래가 원래 IP 패킷"]] }, ...ipLayers(p.packet, true)];
  const rows: [string, string][] =
    p.proto === "lcp"
      ? [["프로토콜", "0xc021 (LCP)"], ["코드", "1 (Configure-Request) — 링크 설정 (축소: 곧바로 인증으로)"]]
      : p.proto === "chap"
        ? [
            ["프로토콜", "0xc223 (CHAP — MS-CHAPv2)"],
            ["코드", { challenge: "1 (Challenge)", response: "2 (Response)", success: "3 (Success)", failure: "4 (Failure)" }[p.code]],
            ...(p.user ? [["사용자 이름", p.user] as [string, string]] : []),
            ...(p.code === "response" ? [["응답 값", "비밀번호로 만든 값 (비밀번호 자체는 보내지 않는다)"] as [string, string]] : []),
          ]
        : [
            ["프로토콜", "0x8021 (IPCP)"],
            ["코드", { "configure-request": "1 (Configure-Request)", "configure-ack": "2 (Configure-Ack)", "configure-nak": "3 (Configure-Nak)" }[p.code]],
            ["IP 주소", p.ip ?? "0.0.0.0 (주소를 달라는 뜻)"],
            ...(p.dns ? [["DNS (옵션 129)", p.dns] as [string, string]] : []),
          ];
  return [l2tp, { title: "PPP", rows }];
}

/** conntrack -E 의 새 흐름 한 줄: 원래 방향 + [UNREPLIED] + 돌아올 방향(NAT 가 바꾼 주소) */
function conntrackNew(inside: Ipv4Packet, outside: Ipv4Packet): string {
  const a = inside.payload;
  const b = outside.payload;
  if (a.kind === "icmp" && b.kind === "icmp" && a.type === "echo-request" && b.type === "echo-request") {
    return `[NEW] icmp     1 30 src=${inside.src} dst=${inside.dst} type=8 code=0 id=${a.id} [UNREPLIED] src=${outside.dst} dst=${outside.src} type=0 code=0 id=${b.id}`;
  }
  if ((a.kind === "tcp" || a.kind === "udp") && (b.kind === "tcp" || b.kind === "udp")) {
    const state = a.kind === "tcp" ? " SYN_SENT" : "";
    return `[NEW] ${a.kind}      ${a.kind === "tcp" ? 6 : 17} ${a.kind === "tcp" ? 120 : 30}${state} src=${inside.src} dst=${inside.dst} sport=${a.srcPort} dport=${a.dstPort} [UNREPLIED] src=${outside.dst} dst=${outside.src} sport=${b.dstPort} dport=${b.srcPort}`;
  }
  return `[NEW] src=${inside.src} dst=${inside.dst} [UNREPLIED] src=${outside.dst} dst=${outside.src}`;
}

// ---------- 장치 판단을 실무 명령 출력으로 ----------

const detail = (ev: TraceEvent, key: string): string | undefined => {
  const v = ev.details?.[key];
  return v === undefined || v === null ? undefined : String(v);
};

/**
 * strongSwan 로그의 IKE Message ID (교환 순서: IKE_SA_INIT 0, IKE_AUTH 1, 그다음 INFORMATIONAL 2).
 * 계정 인증(EAP)이면 IKE_AUTH 가 두 번(1·2)이라 그 뒤가 하나씩 밀린다 — 원격 접속이 트레이스에 mid 로 적어 둔다
 */
const ikeMessageId = (ev: TraceEvent) => {
  const mid = detail(ev, "mid");
  if (mid !== undefined) return Number(mid);
  const step = detail(ev, "step");
  return step === "IKE_AUTH" ? 1 : step === "INFORMATIONAL" ? 2 : 0;
};

/**
 * 로그 한 줄을 실무에서 보는 출력으로. frames 는 그 장치가 받은/내보낸 프레임.
 * 대응하는 실무 출력이 없는 종류는 tcpdump 한 줄만 (프레임이 있을 때)
 */
export function practitionerLines(ev: TraceEvent, frames: { received?: EthernetFrame; sent?: EthernetFrame }, deviceName: (id: string) => string = (id) => id): PractitionerLine[] {
  const out: PractitionerLine[] = [];
  const f = frames.received ?? frames.sent;
  const ip = f && f.payload.kind === "ipv4" ? f.payload : undefined;
  const ip6 = f && f.payload.kind === "ipv6" ? f.payload : undefined;
  const len = ip ? 20 + l4Length(ip.payload) : ip6 ? 40 + l6Length(ip6.payload) : 0;
  // 공유기 VPN (L2TP/IPsec): IKEv2 원격 접속의 strongSwan 줄 대신 IKEv1 charon·xl2tpd·pppd 줄
  const l2tp = ev.kind.startsWith("vpn.") && (detail(ev, "l2tp") !== undefined || detail(ev, "ppp") !== undefined);
  if (l2tp) l2tpLines(ev, ip, out);
  else if (ev.kind.startsWith("vpn.") && detail(ev, "wg") !== undefined) wgLines(ev, frames, out);
  else if (ev.kind.startsWith("vpn.") && detail(ev, "ovpn") !== undefined) ovpnLines(ev, frames, out);
  else if (ev.kind.startsWith("mesh.")) meshLines(ev, out);
  else switch (ev.kind) {
    case "ip.forward":
      if (ip) out.push({ tool: "시스코 debug ip packet", line: `IP: s=${ip.src}, d=${ip.dst} (${detail(ev, "out") ?? "?"}), len ${len}, forward` });
      if (ip6) out.push({ tool: "시스코 debug ipv6 packet", line: `IPV6: source ${ip6.src}\n      dest ${ip6.dst} (${detail(ev, "out") ?? "?"})\n      traffic class 0, flow 0x0, len ${len}, prot ${IP6_NEXT_HEADER[ip6.payload.kind].num}, hops ${ip6.hopLimit}, forwarding` });
      break;
    case "ndp.cache.update":
      if (detail(ev, "ip") && detail(ev, "mac")) out.push({ tool: "리눅스 ip -6 neigh", line: `${detail(ev, "ip")} dev eth0 lladdr ${detail(ev, "mac")} ${detail(ev, "state") ?? "REACHABLE"}` });
      break;
    case "ndp.nud":
      // NUD 상태가 바뀐 줄: ip -6 neigh 의 상태 칸 그대로
      if (detail(ev, "ip") && detail(ev, "state")) out.push({ tool: "리눅스 ip -6 neigh", line: `${detail(ev, "ip")} dev eth0 lladdr ${detail(ev, "mac") ?? "?"}${detail(ev, "router") === "true" ? " router" : ""} ${detail(ev, "state")}` });
      break;
    case "slaac.addr":
      if (detail(ev, "ip") && !detail(ev, "removed") && !detail(ev, "kept")) out.push({ tool: "리눅스 ip -6 addr", line: `inet6 ${detail(ev, "ip")}/64 scope global dynamic` });
      break;
    case "slaac.router":
      if (detail(ev, "router") && !detail(ev, "removed") && !detail(ev, "suspect")) out.push({ tool: "리눅스 ip -6 route", line: `default via ${detail(ev, "router")} dev eth0 proto ra metric 1024 expires ${Number(detail(ev, "lifetime") ?? 1800) - 1}sec hoplimit 64 pref medium` });
      break;
    case "ndp.timeout":
      if (detail(ev, "nud") === "failed") out.push({ tool: "리눅스 ip -6 neigh", line: `${detail(ev, "ip") ?? "?"} dev eth0  FAILED` });
      break;
    case "ndp.dad.fail":
      out.push({ tool: "리눅스 커널 로그 (dmesg)", line: `IPv6: eth0: IPv6 duplicate address ${detail(ev, "ip") ?? "?"} used by ${detail(ev, "mac") ?? "?"} detected!` });
      break;
    case "ip.no-route":
      if (ip) out.push({ tool: "시스코 debug ip packet", line: `IP: s=${ip.src}, d=${ip.dst}, len ${len}, unroutable` });
      break;
    case "nat.translate": {
      const sent = frames.sent?.payload.kind === "ipv4" ? frames.sent.payload : undefined;
      if (ip && sent) out.push({ tool: "시스코 debug ip nat", line: `NAT: s=${ip.src}->${sent.src}, d=${ip.dst} [${detail(ev, "publicId") ?? ""}]` });
      if (ip && sent) out.push({ tool: "리눅스 conntrack -E", line: conntrackNew(ip, sent) });
      break;
    }
    case "nat.restore": {
      const sent = frames.sent?.payload.kind === "ipv4" ? frames.sent.payload : undefined;
      if (ip && sent) out.push({ tool: "시스코 debug ip nat", line: `NAT*: s=${ip.src}, d=${ip.dst}->${sent.dst} [${detail(ev, "publicId") ?? ""}]` });
      break;
    }
    case "dpi.app":
    case "dpi.block": {
      // netifyd (GL.iNet DPI 엔진) 의 흐름 기록
      const app = detail(ev, "app") ?? "unknown";
      const l4 = ip?.payload;
      const ports = l4 && (l4.kind === "tcp" || l4.kind === "udp") ? [l4.srcPort, l4.dstPort] : [0, 0];
      out.push({ tool: "netifyd (DPI)", line: `${ip ? `${ip.src}:${ports[0]} -> ${ip.dst}:${ports[1]}` : "?"} [${l4?.kind.toUpperCase() ?? "?"}] app: ${app}${ev.kind === "dpi.block" ? " → blocked" : ""}` });
      break;
    }
    case "dns.blocked": {
      // AdGuard Home 쿼리 로그 (웹 화면의 한 줄을 텍스트로)
      const why = /은\(는\) (.+) → 업스트림/.exec(ev.summary)?.[1] ?? "";
      out.push({ tool: "AdGuard Home 쿼리 로그", line: `${detail(ev, "to") ?? "?"}  ${detail(ev, "qtype") ?? "A"} ${detail(ev, "name") ?? "?"}  Blocked — ${why}` });
      break;
    }
    case "dns.hijack":
      out.push({ tool: "iptables -t nat (PREROUTING)", line: `REDIRECT udp -- ${detail(ev, "from") ?? "0.0.0.0/0"} ${detail(ev, "to") ?? "0.0.0.0/0"} udp dpt:53 redir ports 53` });
      break;
    case "ddns.update":
      // OpenWrt ddns-scripts (GL.iNet 도 이것) 의 로그
      if (!detail(ev, "late")) out.push({ tool: "OpenWrt ddns-scripts", line: `: Update needed - L: '${ip?.src ?? "?"}' <> R: (DNS 에 등록된 주소)` });
      break;
    case "ddns.ok":
      out.push({ tool: "OpenWrt ddns-scripts", line: `: Update successful - IP '${detail(ev, "ip") ?? "?"}' send` });
      out.push({ tool: "dyndns2 응답", line: `${detail(ev, "result") ?? "good"} ${detail(ev, "ip") ?? ""}`.trim() });
      break;
    case "ddns.failed":
      if (detail(ev, "result")) out.push({ tool: "dyndns2 응답", line: String(detail(ev, "result")) });
      out.push({ tool: "OpenWrt ddns-scripts", line: detail(ev, "result") === "badauth" ? `: Error sending update to DDNS Provider: 'badauth'` : `: Can not connect to DDNS Provider` });
      break;
    case "fw.deny":
    case "fw.allow":
      if (ip6) {
        const l4 = ip6.payload;
        const rest = l4.kind === "icmp6" ? ` PROTO=ICMPv6 TYPE=${l4.type === "echo-request" ? 128 : l4.type === "echo-reply" ? 129 : l4.type === "time-exceeded" ? 3 : l4.type === "unreachable" ? 1 : l4.type === "ns" ? 135 : 136} CODE=0` : ` PROTO=${l4.kind.toUpperCase()} SPT=${l4.srcPort} DPT=${l4.dstPort}`;
        out.push({ tool: ev.kind === "fw.deny" ? "리눅스 ip6tables LOG (DROP 전에 기록)" : "리눅스 ip6tables LOG", line: `${ev.kind === "fw.deny" ? "[DROP] " : "[ACCEPT] "}SRC=${ip6.src} DST=${ip6.dst} LEN=${len} HOPLIMIT=${ip6.hopLimit}${rest}` });
      }
      if (ip) {
        const l4 = ip.payload;
        const ports = l4.kind === "tcp" || l4.kind === "udp" ? ` SPT=${l4.srcPort} DPT=${l4.dstPort}` : "";
        const proto = l4.kind.toUpperCase();
        out.push({ tool: ev.kind === "fw.deny" ? "리눅스 iptables LOG (DROP 전에 기록)" : "리눅스 iptables LOG", line: `${ev.kind === "fw.deny" ? "[DROP] " : "[ACCEPT] "}SRC=${ip.src} DST=${ip.dst} LEN=${len} TTL=${ip.ttl} PROTO=${proto}${ports}` });
      }
      break;
    case "dhcp.discover.sent":
      out.push({ tool: "리눅스 dhclient", line: `DHCPDISCOVER on eth0 to 255.255.255.255 port 67` });
      break;
    case "dhcp.offer.received":
      out.push({ tool: "리눅스 dhclient", line: `DHCPOFFER of ${detail(ev, "yiaddr") ?? "?"} from ${detail(ev, "serverId") ?? "?"}` });
      break;
    case "dhcp.request.sent":
      out.push({ tool: "리눅스 dhclient", line: `DHCPREQUEST for ${detail(ev, "requestedIp") ?? "?"} on eth0 to 255.255.255.255 port 67` });
      break;
    case "dhcp.ack.received":
      out.push({ tool: "리눅스 dhclient", line: `DHCPACK of ${detail(ev, "yiaddr") ?? "?"} from ${detail(ev, "serverId") ?? "?"}` });
      break;
    case "dhcp.bound":
      out.push({ tool: "리눅스 dhclient", line: `bound to ${detail(ev, "ip") ?? "?"} -- renewal in 43200 seconds.` });
      break;
    case "arp.cache.update":
    case "arp.reply.received":
      if (detail(ev, "ip") && detail(ev, "mac")) out.push({ tool: "리눅스 ip neigh", line: `${detail(ev, "ip")} dev eth0 lladdr ${detail(ev, "mac")} REACHABLE` });
      break;
    case "switch.learn":
      out.push({ tool: "시스코 show mac address-table", line: `   1    ${detail(ev, "mac") ?? "?"}    DYNAMIC     ${detail(ev, "port") !== undefined ? `Gi0/${detail(ev, "port")}` : "?"}` });
      break;
    case "rip.learn":
      out.push({ tool: "시스코 debug ip rip", line: `RIP: received v2 update from ${detail(ev, "nextHop") ?? "?"}\n     ${detail(ev, "dest")}/${detail(ev, "prefix")} via 0.0.0.0 in ${detail(ev, "metric")} hops` });
      break;
    case "icmp.reply.received":
      if (ip) out.push({ tool: "ping", line: `64 bytes from ${ip.src}: icmp_seq=${detail(ev, "seq") ?? "?"} ttl=${ip.ttl} time=${detail(ev, "rtt") ?? "?"} ms` });
      if (ip6) out.push({ tool: "ping (IPv6)", line: `64 bytes from ${ip6.src}: icmp_seq=${detail(ev, "seq") ?? "?"} ttl=${ip6.hopLimit} time=${detail(ev, "rtt") ?? "?"} ms` });
      break;
    case "icmp.unreachable.received":
      if (ip6 && ip6.payload.kind === "icmp6" && ip6.payload.type === "unreachable") {
        out.push({ tool: "ping (IPv6)", line: `From ${ip6.src} icmp_seq=… Destination unreachable: ${ip6.payload.code === "net" ? "No route" : ip6.payload.code === "host" ? "Address unreachable" : "Port unreachable"}` });
      }
      if (ip && ip.payload.kind === "icmp" && ip.payload.type === "unreachable") {
        out.push({ tool: "ping", line: `From ${ip.src} icmp_seq=… Destination ${ip.payload.code === "net" ? "Net" : ip.payload.code === "host" ? "Host" : "Port"} Unreachable` });
      }
      break;
    case "tcp.refused":
      out.push({ tool: "curl", line: `curl: (7) Failed to connect to ${ip?.src ?? "?"} port ${ip?.payload.kind === "tcp" ? ip.payload.srcPort : "?"}: Connection refused` });
      break;
    case "trace.hop":
      out.push({ tool: "traceroute", line: ` ${detail(ev, "ttl")}  ${detail(ev, "ip")}  ${detail(ev, "rtt")} ms` });
      break;
    case "dns.resolved":
    case "dns.response.received":
      {
        const pk = ip ?? ip6;
        const d = pk && pk.payload.kind === "udp" && pk.payload.payload.kind === "dns" ? pk.payload.payload : undefined;
        if (d?.answer) out.push({ tool: "dig", line: `${d.name}.\t\t300\tIN\t${d.qtype ?? "A"}\t${d.answer}` });
      }
      break;
    case "ssh.open": {
      // conn id = "내주소:포트-상대주소:포트"
      const [local, remote] = (detail(ev, "conn") ?? "").split("-");
      const [rip, rport] = (remote ?? "?:?").split(":");
      if (ev.summary.includes("가 인증함")) out.push({ tool: "sshd (auth.log)", line: `Accepted publickey for user from ${rip} port ${rport} ssh2` });
      else out.push({ tool: "ssh -v", line: `debug1: Authenticated to ${rip} ([${rip}]:${rport}) using "publickey".` });
      void local;
      break;
    }
    case "vpn.ike":
      if (detail(ev, "retransmit") !== undefined) out.push({ tool: "strongSwan (charon)", line: `11[IKE] retransmit ${detail(ev, "retransmit")} of request with message ID ${ikeMessageId(ev)}` });
      else if (detail(ev, "spi") !== undefined) out.push({ tool: "strongSwan (charon)", line: `07[IKE] initiating IKE_SA vpn[1] to ${detail(ev, "peer") ?? "?"}` });
      else if (detail(ev, "resent") === "true") out.push({ tool: "strongSwan (charon)", line: `13[IKE] received retransmit of request with ID ${detail(ev, "mid") ?? 1}, retransmitting response` });
      if (detail(ev, "localNat") === "true") out.push({ tool: "strongSwan (charon)", line: `08[IKE] local host is behind NAT, sending keep alives` });
      if (detail(ev, "remoteNat") === "true") out.push({ tool: "strongSwan (charon)", line: `08[IKE] remote host is behind NAT` });
      break;
    case "vpn.eap":
      if (detail(ev, "resent") === "true") out.push({ tool: "strongSwan (charon)", line: `13[IKE] received retransmit of request with ID 1, retransmitting response` });
      else if (detail(ev, "eap") === "request") out.push({ tool: "strongSwan (charon)", line: `13[IKE] initiating EAP_MSCHAPV2 method (id 0x01)` });
      if (detail(ev, "eap") === "response") out.push({ tool: "strongSwan (charon)", line: `13[IKE] server requested EAP_MSCHAPV2 authentication (id 0x01)` });
      break;
    case "vpn.dpd": {
      const d = detail(ev, "dpd");
      const mid = detail(ev, "mid") ?? 2; // EAP 로 붙었으면 3
      if (detail(ev, "retransmit") !== undefined) out.push({ tool: "strongSwan (charon)", line: `11[IKE] retransmit ${detail(ev, "retransmit")} of request with message ID ${ikeMessageId(ev)}` });
      else if (d === "request") {
        out.push({ tool: "strongSwan (charon)", line: `15[IKE] sending DPD request` });
        out.push({ tool: "strongSwan (charon)", line: `15[ENC] generating INFORMATIONAL request ${mid} [ ]` });
      } else if (d === "reply") {
        out.push({ tool: "strongSwan (charon)", line: `16[ENC] parsed INFORMATIONAL request ${mid} [ ]` });
        out.push({ tool: "strongSwan (charon)", line: `16[ENC] generating INFORMATIONAL response ${mid} [ ]` });
      } else if (d === "alive") out.push({ tool: "strongSwan (charon)", line: `16[ENC] parsed INFORMATIONAL response ${mid} [ ]` });
      break;
    }
    case "vpn.up":
      if (detail(ev, "user") !== undefined) out.push({ tool: "strongSwan (charon)", line: `09[IKE] authentication of '${detail(ev, "user")}' with EAP successful` });
      if (detail(ev, "user") !== undefined || detail(ev, "eap") === "success") out.push({ tool: "strongSwan (charon)", line: `09[IKE] EAP method EAP_MSCHAPV2 succeeded, MSK established` });
      out.push({ tool: "strongSwan (charon)", line: `09[IKE] IKE_SA vpn[1] established between ${ip?.dst ?? "?"}...${detail(ev, "peer") ?? "?"}` });
      out.push({ tool: "strongSwan (charon)", line: `09[IKE] CHILD_SA vpn{1} established${detail(ev, "natT") === "true" ? " (UDP-encapsulated, NAT-T)" : ""}` });
      break;
    case "vpn.drop":
      // 계정 인증(EAP)·DPD 실패를 먼저 (문구가 PSK·재전송 실패와 겹치지 않게)
      if (detail(ev, "eap") === "failure") {
        // 서버의 계정 확인 실패: 비밀번호가 다르면 MSCHAPv2 검증 실패(축소판은 재시도 없이 첫 실패에서 끝), 목록에 없으면 그 사용자의 키가 없음.
        // "failed for peer" 뒤는 상대의 IKE ID (IDi = 사용자 이름), "no EAP key found" 의 앞은 서버 자신의 ID (받은 IKE_AUTH 의 목적지 주소)
        const user = detail(ev, "user") ?? "%any";
        if (ev.summary.includes("의 비밀번호가 다름")) out.push({ tool: "strongSwan (charon)", line: `12[IKE] EAP-MS-CHAPv2 verification failed, retry (1)` });
        else out.push({ tool: "strongSwan (charon)", line: `12[IKE] no EAP key found for hosts '${ip?.dst ?? "?"}' - '${user}'` });
        out.push({ tool: "strongSwan (charon)", line: `12[IKE] EAP method EAP_MSCHAPV2 failed for peer ${user}` });
      } else if (ev.summary.includes("EAP 실패, AUTHENTICATION_FAILED")) out.push({ tool: "strongSwan (charon)", line: `12[IKE] received EAP_FAILURE, EAP authentication failed` });
      else if (ev.summary.includes("계정 인증(EAP)을 요구하는데")) out.push({ tool: "strongSwan (charon)", line: `12[IKE] no EAP key found for hosts '${ip?.src ?? "?"}' - '%any'` });
      else if (detail(ev, "dpd") === "invalid") out.push({ tool: "strongSwan (charon)", line: `12[IKE] received INVALID_SPI notify error` });
      else if (ev.summary.includes("AUTHENTICATION_FAILED 로 거절 —")) out.push({ tool: "strongSwan (charon)", line: `12[IKE] received AUTHENTICATION_FAILED notify error` });
      else if (ev.summary.includes("PSK)가 다름 → AUTHENTICATION_FAILED")) out.push({ tool: "strongSwan (charon)", line: `05[IKE] tried 1 shared key for '${ip?.dst ?? "?"}' - '${ip?.src ?? "?"}', but MAC mismatched` });
      else if (ev.summary.includes("재전송") && ev.summary.includes("timeout")) out.push({ tool: "strongSwan (charon)", line: `11[IKE] giving up after 2 retransmits` });
      break;
    case "lb.forward":
      if (detail(ev, "vip")) out.push({ tool: "리눅스 ipvsadm -Lnc", line: `TCP 01:00  ${(detail(ev, "state") ?? "ESTABLISHED").padEnd(11)} ${detail(ev, "client")}  ${detail(ev, "vip")}  ${detail(ev, "backend")}` });
      break;
    case "lb.down":
      // 액티브 헬스 체크로 뺀 것은 HAProxy 의 상태 변경 줄, 요청이 실패해 뺀 것(패시브)은 nginx error.log
      if (detail(ev, "check") === "true") out.push({ tool: "HAProxy 로그", line: `Server backend/${detail(ev, "backend") ?? "?"} is DOWN, reason: ${String(detail(ev, "reason") ?? "").includes("timeout") ? "Layer4 timeout" : "Layer4 connection problem"}. ${detail(ev, "left") ?? "?"} active and 0 backup servers left.` });
      else out.push({ tool: "nginx error.log", line: `connect() failed while connecting to upstream, upstream: "http://${detail(ev, "backend") ?? "?"}/" — upstream server temporarily disabled` });
      break;
    case "lb.check":
      if (detail(ev, "up") === "true") out.push({ tool: "HAProxy 로그", line: `Server backend/${detail(ev, "backend") ?? "?"} is UP, reason: Layer4 check passed. ${detail(ev, "left") ?? "?"} active and 0 backup servers online.` });
      break;
    case "proxy.use":
      if (detail(ev, "method") === "CONNECT") {
        out.push({ tool: "curl -v", line: `* Uses proxy env variable https_proxy == 'http://${detail(ev, "proxy") ?? "?"}'` });
        out.push({ tool: "curl -v", line: `* Establish HTTP proxy tunnel to ${String(detail(ev, "dst") ?? "?")}:${String(detail(ev, "port") ?? 443)}` });
        out.push({ tool: "curl -v", line: `> CONNECT ${String(detail(ev, "dst") ?? "?")}:${String(detail(ev, "port") ?? 443)} HTTP/1.1` });
        break;
      }
      out.push({ tool: "curl -v", line: `* Uses proxy env variable http_proxy == 'http://${detail(ev, "proxy") ?? "?"}'` });
      out.push({ tool: "curl -v", line: `> GET http://${String(detail(ev, "dst") ?? "?")}/ HTTP/1.1` });
      break;
    case "proxy.tunnel":
      // 끝 클라이언트가 CONNECT 응답을 받은 줄 (프록시 쪽 줄은 access.log 가 터널이 닫힐 때 남는다)
      if (detail(ev, "client") === "true") {
        out.push({ tool: "curl -v", line: `< HTTP/1.1 200 Connection established` });
        out.push({ tool: "curl -v", line: `* CONNECT tunnel established, response 200` });
      }
      break;
    case "tls.hello":
      if (detail(ev, "role") === "client") out.push({ tool: "curl -v", line: `* TLSv1.3 (OUT), TLS handshake, Client hello (1):` });
      break;
    case "tls.established":
      if (detail(ev, "role") === "client") {
        out.push({ tool: "curl -v", line: `* TLSv1.3 (IN), TLS handshake, Server hello (2):` });
        out.push({ tool: "curl -v", line: `* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256` });
        if (detail(ev, "sni") !== undefined) out.push({ tool: "curl -v", line: `*  subject: CN=${String(detail(ev, "sni"))}` });
      }
      break;
    case "tls.fail":
      if (ev.summary.startsWith("TLS 핸드셰이크 실패")) out.push({ tool: "curl", line: `curl: (35) OpenSSL/3.0.13: error:0A00010B:SSL routines::wrong version number` });
      else out.push({ tool: "nginx (응답 본문)", line: `400 Bad Request — The plain HTTP request was sent to HTTPS port` });
      break;
    case "tcp.cookie":
      out.push({ tool: "curl -v", line: `< Set-Cookie: ${detail(ev, "cookie") ?? "?"}; path=/` });
      break;
    case "proxy.relay":
    case "proxy.deny":
    case "proxy.fail": {
      // Squid access.log: 시각 경과ms 클라이언트 결과/상태 바이트 메서드 URL 사용자 계층/상대 형식. 요청 하나의 결과가 아닌 줄(터널 중계 드롭)은 기록이 없다
      if (detail(ev, "result") === undefined) break;
      const target = detail(ev, "target");
      // CONNECT 는 URL 자리에 호스트:포트만 남는다 (경로는 암호화된 터널 안이라 프록시가 모른다)
      const connect = detail(ev, "method") === "CONNECT";
      const url = detail(ev, "url") ?? (target ? (connect ? target : `http://${target.replace(/:80$/, "")}/`) : "-");
      const code = detail(ev, "result") ?? "-";
      // 대상에 연결해 본 것(응답 전달·연결 실패)은 HIER_DIRECT, 연결하지 않은 것(차단·이름 실패·대상 없음)은 HIER_NONE
      const hier = detail(ev, "ip") ? `HIER_DIRECT/${detail(ev, "ip")}` : "HIER_NONE/-";
      out.push({ tool: "Squid access.log", line: `${(ev.time / 1000).toFixed(3)}      0 ${detail(ev, "client") ?? "-"} ${code} ${detail(ev, "bytes") ?? 200} ${connect ? "CONNECT" : "GET"} ${url} - ${hier} ${connect && code.startsWith("TCP_TUNNEL") ? "-" : "text/html"}` });
      break;
    }
    case "port.publish":
      // 새로 넘긴 연결: 도커가 -p 마다 띄우는 userland proxy 프로세스 (ps 에 보이는 명령 줄)
      if (detail(ev, "to") !== undefined && detail(ev, "back") === undefined && detail(ev, "refused") === undefined)
        out.push({ tool: "ps (docker-proxy)", line: `docker-proxy -proto tcp -host-ip ${detail(ev, "bind") ?? "0.0.0.0"} -host-port ${detail(ev, "port") ?? "?"} -container-ip ${detail(ev, "to")} -container-port ${detail(ev, "toPort") ?? "?"}` });
      if (detail(ev, "refused") === "true") out.push({ tool: "curl", line: `curl: (7) Failed to connect to ${ip?.dst ?? "?"} port ${detail(ev, "port") ?? "?"}: Connection refused` });
      break;
    case "lb.relay":
      out.push({ tool: "nginx access.log", line: `${ip?.dst ?? "-"} - - "GET / HTTP/1.1" ${(detail(ev, "status") ?? "HTTP 200").replace("HTTP ", "").split(" ")[0]} ${detail(ev, "bytes") ?? "-"} upstream=${detail(ev, "backend") ?? "?"}` });
      break;
  }
  if (f) out.push({ tool: "tcpdump -n -e", line: tcpdumpLine(f) });
  if (frames.sent && frames.received && JSON.stringify(frames.sent) !== JSON.stringify(frames.received)) {
    out.push({ tool: `tcpdump (${deviceName(ev.nodeId)} 이 내보낸 쪽)`, line: tcpdumpLine(frames.sent) });
  }
  return out;
}

/**
 * 공유기 VPN (L2TP/IPsec) 트레이스의 실무 로그: 리눅스로 같은 서버·클라이언트를 만들면 쓰는 strongSwan(IKEv1)·xl2tpd·pppd 의 줄.
 * 서버 쪽 트레이스는 요약이 "VPN 서버" 로 시작한다
 */
/**
 * WireGuard: 리눅스 커널 모듈의 디버그 로그 (echo module wireguard +p > /sys/kernel/debug/dynamic_debug/control 로 켠다 — dmesg).
 * 피어 번호는 장치마다 1부터 (여기서는 피어를 하나로 보고 1)
 */
function wgLines(ev: TraceEvent, frames: { received?: EthernetFrame; sent?: EthernetFrame }, out: PractitionerLine[]): void {
  const tool = "리눅스 커널 로그 (wireguard dyndbg)";
  const ep = (f: EthernetFrame | undefined, dir: "src" | "dst") => {
    if (!f || f.payload.kind !== "ipv4" || f.payload.payload.kind !== "udp") return "?";
    const u = f.payload.payload;
    return dir === "src" ? `${f.payload.src}:${u.srcPort}` : `${f.payload.dst}:${u.dstPort}`;
  };
  const from = ep(frames.received, "src");
  const to = ep(frames.sent, "dst");
  const line = (l: string) => out.push({ tool, line: `wireguard: wg0: ${l}` });
  switch (ev.kind) {
    case "vpn.handshake":
      if (detail(ev, "from") !== undefined) {
        line(`Receiving handshake initiation from peer 1 (${from})`);
        line(`Sending handshake response to peer 1 (${from})`);
        line(`Keypair ${detail(ev, "local") ?? 1} created for peer 1`);
      } else {
        const tries = Number(detail(ev, "tries") ?? 1);
        if (ev.summary.includes("받지 못함")) line(`Retrying handshake with peer 1 (${to}) because we stopped hearing back after 15 seconds`);
        else if (tries > 1) line(`Handshake for peer 1 (${to}) did not complete after 5 seconds, retrying (try ${tries})`);
        line(`Sending handshake initiation to peer 1 (${to})`);
      }
      break;
    case "vpn.up":
      line(`Receiving handshake response from peer 1 (${from})`);
      line(`Keypair 1 created for peer 1`);
      break;
    case "vpn.keepalive":
      if (detail(ev, "from") !== undefined) line(`Receiving keepalive packet from peer 1 (${from})`);
      else line(`Sending keepalive packet to peer 1 (${to})`);
      break;
    case "vpn.drop":
      if (detail(ev, "reason") === "mac1") line(`Invalid MAC of handshake, dropping packet from ${from}`);
      else if (detail(ev, "reason") === "unknown-key") line(`Invalid handshake initiation from ${from}`);
      else if (detail(ev, "src") !== undefined) line(`Packet has unallowed src IP (${detail(ev, "src")}) from peer 1 (${from})`);
      else if (detail(ev, "failed") === "true") line(`Handshake for peer 1 did not complete after 3 attempts, giving up`);
      break;
  }
}

/** 메시 VPN: tailscale ping / tailscaled 로그의 해당 줄 */
function meshLines(ev: TraceEvent, out: PractitionerLine[]): void {
  const zt = detail(ev, "mesh") === "zerotier";
  const sm = ev.summary;
  if (zt) {
    if (ev.kind === "mesh.netmap") out.push({ tool: "zerotier-cli listnetworks", line: `200 listnetworks <nwid> <name> <mac> OK PRIVATE zt0 ${sm.match(/내 주소 ([0-9.]+)/)?.[1] ?? "?"}/24` });
    return;
  }
  const peer = String(detail(ev, "peer") ?? "");
  if (ev.kind === "mesh.direct") {
    const at = sm.match(/직접 경로 ([0-9.]+:\d+)/)?.[1] ?? "?";
    out.push({ tool: "tailscale ping", line: `pong from ${peer || "peer"} via ${at} in 20ms` });
  } else if (ev.kind === "mesh.relay" && sm.includes("직접 경로를 찾지 못함")) {
    out.push({ tool: "tailscale ping", line: `pong from ${peer || "peer"} via DERP(tok) in 60ms` });
    out.push({ tool: "tailscale ping", line: "direct connection not established" });
  } else if (ev.kind === "mesh.login" && sm.includes("로그인 (노드 키")) out.push({ tool: "tailscaled 로그", line: "control: client.Login(false, 0)" });
  else if (ev.kind === "mesh.netmap") out.push({ tool: "tailscaled 로그", line: `netmap: self: ${sm.match(/내 주소 ([0-9.]+)/)?.[1] ?? "?"} peers: ${detail(ev, "peers") ?? 0}` });
  else if (ev.kind === "mesh.endpoint") out.push({ tool: "tailscaled 로그", line: `magicsock: endpoints changed: ${sm.match(/([0-9.]+:\d+)/)?.[1] ?? "?"} (stun)` });
  else if (ev.kind === "mesh.drop" && sm.includes("거절")) out.push({ tool: "tailscaled 로그", line: "control: login: 403 Forbidden" });
}

/** OpenVPN 로그 (verb 3) 의 해당 줄 — 서버·클라이언트 양쪽 (요약문으로 어느 단계인지 가린다) */
function ovpnLines(ev: TraceEvent, frames: { received?: EthernetFrame; sent?: EthernetFrame }, out: PractitionerLine[]): void {
  const tool = "openvpn 로그 (verb 3)";
  const ep = (f: EthernetFrame | undefined) => {
    if (!f || f.payload.kind !== "ipv4") return "?";
    const p = f.payload.payload;
    return p.kind === "udp" || p.kind === "tcp" ? `${f.payload.src}:${p.srcPort}` : f.payload.src;
  };
  const from = ep(frames.received);
  const line = (l: string) => out.push({ tool, line: l });
  const sm = ev.summary;
  const server = sm.startsWith("OpenVPN 서버");
  const cn = /CN=([^ ,)]+(?: [^ ,)(]+)*)/.exec(sm)?.[1];
  if (ev.kind === "vpn.handshake") {
    if (server && sm.includes("HARD_RESET_CLIENT")) line(`TLS: Initial packet from [AF_INET]${from}, sid=${Number(detail(ev, "sid") ?? 0).toString(16).padStart(8, "0")} ${"0".repeat(8)}`);
    else if (server && sm.includes("VERIFY OK")) {
      line(`${from} VERIFY OK: depth=1, CN=GL.iNet CA`);
      line(`${from} VERIFY OK: depth=0, CN=${cn ?? "?"}`);
    } else if (!server && sm.includes("VERIFY OK")) {
      line("VERIFY OK: depth=1, CN=GL.iNet CA");
      line("VERIFY OK: depth=0, CN=server");
    } else if (!server && sm.includes("TLS 완료")) line("Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 2048 bits RSA");
    else if (!server && sm.includes("TCP 연결됨")) line("TCP connection established");
    else if (!server && sm.includes("(SYN)")) line(`Attempting to establish TCP connection with [AF_INET]${sm.match(/TCP ([0-9.]+:\d+)/)?.[1] ?? "?"}`);
  } else if (ev.kind === "vpn.up") {
    const push = String(detail(ev, "push") ?? "");
    const who = String(detail(ev, "cn") ?? "client");
    if (server) line(`${who}/${from} SENT CONTROL [${who}]: 'PUSH_REPLY,${push}' (status=1)`);
    else {
      line(`PUSH: Received control message: 'PUSH_REPLY,${push}'`);
      line("Initialization Sequence Completed");
    }
  } else if (ev.kind === "vpn.drop") {
    if (sm.includes("tls-crypt unwrap")) {
      line("tls-crypt unwrap error: packet authentication failed");
      line(`TLS Error: tls-crypt unwrapping failed from [AF_INET]${from}`);
    } else if (sm.includes("certificate revoked") || (server && sm.includes("CRL"))) line(`${from} VERIFY ERROR: depth=0, error=certificate revoked: CN=${cn ?? "?"}`);
    else if (server && sm.includes("VERIFY ERROR")) line(`${from} VERIFY ERROR: depth=0, error=unable to get local issuer certificate: CN=${cn ?? "?"}`);
    else if (server && sm.includes("AUTH_FAILED")) line(`${from} TLS Auth Error: Auth Username/Password verification failed for peer`);
    else if (!server && sm.includes("AUTH_FAILED")) line("AUTH: Received control message: AUTH_FAILED");
    else if (!server && sm.includes("VERIFY ERROR")) line("VERIFY ERROR: depth=1, error=unable to get local issuer certificate: CN=GL.iNet CA");
    else if (!server && sm.includes("SYN timeout")) line(`TCP: connect to [AF_INET]${sm.match(/TCP ([0-9.]+:\d+)/)?.[1] ?? "?"} failed: Connection timed out`);
    else if (!server && sm.includes("응답 없음")) line("TLS Error: TLS key negotiation failed to occur within 3 seconds (check your network connectivity)");
    else if (!server && sm.includes("Inactivity timeout")) line("[server] Inactivity timeout (--ping-restart), restarting");
    else if (sm.includes("RESTART")) line("SIGUSR1[soft,server-pushed-connection-reset] received, process restarting");
    else if (sm.includes("duplicate-cn")) line(`MULTI: new connection by client '${cn ?? "?"}' will cause previous active sessions by this client to be dropped.  Remember to use the --duplicate-cn option if you want multiple clients using the same certificate or username to concurrently connect.`);
    else if (sm.includes("explicit-exit-notify") || sm.includes("FIN")) line(server ? `${cn ?? "client"}/${from} SIGTERM[soft,remote-exit] received, client-instance exiting` : "SIGTERM[hard,] received, process exiting");
  }
}

function l2tpLines(ev: TraceEvent, ip: Ipv4Packet | undefined, out: PractitionerLine[]): void {
  const server = ev.summary.startsWith("VPN 서버");
  const from = detail(ev, "from") ?? ip?.src ?? "?";
  const charon = (line: string) => out.push({ tool: "strongSwan (charon, IKEv1)", line });
  const xl2tpd = (line: string) => out.push({ tool: "xl2tpd", line: `xl2tpd[1234]: ${line}` });
  const pppd = (line: string) => out.push({ tool: "pppd", line: `pppd[2345]: ${line}` });
  const ctl = detail(ev, "l2tp");
  const ppp = detail(ev, "ppp");
  switch (ev.kind) {
    case "vpn.ike":
      if (detail(ev, "retransmit") !== undefined) {
        if (detail(ev, "step") !== undefined) charon(`11[IKE] sending retransmit ${detail(ev, "retransmit")} of request message ID 0, seq 1`);
      } else if (ctl === "SCCRQ") xl2tpd(`Connection established to ${from}, 1701.  Local: 1, Remote: 1 (ref=0/0).  LNS session is 'default'`);
      else if (ctl === "ICRQ") xl2tpd(`Call established with ${from}, PID: 2345, Local: 1, Remote: 1, Serial: 1`);
      else if (ctl === "SCCRP") xl2tpd(`Connection established to ${ip?.src ?? "?"}, 1701.  Local: 1, Remote: 1 (ref=0/0).`);
      else if (ctl === "ICRP") xl2tpd(`Call established with ${ip?.src ?? "?"}, Local: 1, Remote: 1, Serial: 1`);
      else if (!server && detail(ev, "spi") !== undefined) charon(`07[IKE] initiating Main Mode IKE_SA L2TP-PSK[1] to ${detail(ev, "peer") ?? "?"}`);
      else if (server && detail(ev, "nat") !== undefined) {
        charon(`05[IKE] ${from} is initiating a Main Mode IKE_SA`);
        if (detail(ev, "localNat") === "true") charon(`05[IKE] local host is behind NAT, sending keep alives`);
        if (detail(ev, "remoteNat") === "true") charon(`05[IKE] remote host is behind NAT`);
      } else if (server && detail(ev, "spi") !== undefined) charon(`07[IKE] CHILD_SA L2TP-PSK{1} established with SPIs ${Number(detail(ev, "spi")).toString(16).padStart(8, "0")}_i … and TS ${ip?.dst ?? "?"}/32[udp/l2f] === ${from}/32[udp/l2f]`);
      else if (ev.summary.includes("사전 공유 키 확인")) charon(`06[IKE] IKE_SA L2TP-PSK[1] established between ${ip?.dst ?? "?"}[${ip?.dst ?? "?"}]...${from}[${from}]`);
      else if (ev.summary.includes("IPsec SA 수립")) charon(`07[IKE] CHILD_SA L2TP-PSK{1} established … and TS ${ip?.dst ?? "?"}/32[udp/l2f] === ${from}/32[udp/l2f]`);
      else if (detail(ev, "natT") === "true") {
        if (detail(ev, "localNat") === "true") charon(`08[IKE] local host is behind NAT, sending keep alives`);
        if (detail(ev, "remoteNat") === "true") charon(`08[IKE] remote host is behind NAT`);
      }
      break;
    case "vpn.eap":
      if (server && ppp === "challenge") pppd(`sent [CHAP Challenge id=0x1 <…>, name = "l2tpd"]`);
      else if (!server && ppp === "response") {
        pppd(`rcvd [CHAP Challenge id=0x1 <…>, name = "l2tpd"]`);
        pppd(`sent [CHAP Response id=0x1 <…>, name = "${detail(ev, "user") ?? "?"}"]`);
      } else if (server && ppp === "success") pppd(`MSCHAP-v2 peer authentication succeeded for ${detail(ev, "user") ?? "?"}`);
      else if (!server && ppp === "success") pppd(`CHAP authentication succeeded`);
      break;
    case "vpn.up":
      if (server) pppd(`remote IP address ${detail(ev, "vip") ?? "?"}`);
      else pppd(`local  IP address ${detail(ev, "vip") ?? "?"}`);
      break;
    case "vpn.drop":
      if (ppp === "failure") pppd(`Peer ${detail(ev, "user") ?? "?"} failed MSCHAP-v2 authentication`);
      else if (ev.summary.includes("CHAP Failure")) pppd(`MS-CHAP authentication failed: E=691 Authentication failure`);
      else if (ev.summary.includes("사전 공유 키가 다름 → AUTHENTICATION-FAILED")) charon(`06[IKE] invalid HASH_V1 payload length, decryption failed?`);
      else if (ev.summary.includes("재전송") && ev.summary.includes("timeout")) {
        if (ev.summary.includes("IKE")) charon(`11[IKE] giving up after 2 retransmits`);
        else xl2tpd(`Maximum retries exceeded for tunnel 1.  Closing.`);
      } else if (ctl === "StopCCN" || ctl === "CDN") xl2tpd(`control_finish: Connection closed to ${from}, port 1701 (Goodbye!), Local: 1, Remote: 1`);
      break;
  }
}
