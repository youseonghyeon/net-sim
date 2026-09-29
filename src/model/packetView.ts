// 패킷 상세 보기 (순수): 로그 한 줄이 가리키는 프레임을 실제 도구의 출력 형식으로 바꾼다.
// - tcpdumpLine: 같은 패킷을 tcpdump -n -e 가 찍는 한 줄로
// - headerLayers: 이더넷 → ARP/IPv4 → ICMP/TCP/UDP → DHCP/DNS/RIP 필드를 실제 번호(타입·코드·옵션)와 함께
// - practitionerLines: 장치가 내린 판단을 실무 명령의 출력(시스코 debug, iptables LOG, dhclient, ping, curl …)으로
// 시뮬레이터에 없는 필드(체크섬, 윈도우 크기, IP ID 등)는 넣지 않고, 길이는 근사값이다.
import type { DhcpOp, EspPacket, EthernetFrame, IcmpPacket, IkeMessage, Ipv4Packet, TcpSegment, UdpPacket } from "../core/packet";
import { describeOriginal, IP_PROTO, tcpFlags, UNREACHABLE_FLAG } from "../core/packet";
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
};

// ---------- 길이 (근사) ----------

const ICMP_ECHO_LEN = 64; // ping 기본: 데이터 56 + ICMP 헤더 8
function l4Length(p: Ipv4Packet["payload"]): number {
  if (p.kind === "icmp") return p.type === "echo-request" || p.type === "echo-reply" ? ICMP_ECHO_LEN : 36;
  if (p.kind === "tcp") return 20 + p.len;
  if (p.kind === "esp") return espLength(p);
  if (p.kind === "vrrp") return 12; // VRRPv3 머리 8 + 가상 주소 4
  if (p.kind === "pfsync") return 12 + (p.nat.length + p.flows.length) * 64; // 머리 + 상태 하나당 대략
  return 8 + appLength(p);
}
/** ESP 머리(SPI 4 + seq 4) + IV 16 + 암호화된 원래 IP 패킷 + 패딩·무결성 값 약 16 */
function espLength(e: EspPacket): number {
  return 8 + 16 + 20 + l4Length(e.inner.payload) + 16;
}
function appLength(u: UdpPacket): number {
  const m = u.payload;
  if (m.kind === "dhcp") return 300;
  if (m.kind === "dns") return 12 + m.name.length + 6 + (m.answer ? 16 : 0);
  if (m.kind === "vpn") return 32 + 20 + l4Length(m.inner.payload); // WireGuard 머리 32 + 암호화된 원래 IP 패킷
  if (m.kind === "esp") return espLength(m);
  if (m.kind === "ike") return (u.dstPort === 4500 || u.srcPort === 4500 ? 4 : 0) + (m.exchange === "IKE_SA_INIT" ? 336 : 224); // NAT-T 는 앞에 0 4바이트(Non-ESP 표시)
  return 4 + m.entries.length * 20; // RIP
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
  const eth = `${frame.src} > ${frame.dst}${frame.vlan !== undefined ? `, 802.1Q vlan ${frame.vlan}` : ""}, ethertype ${p.kind === "arp" ? "ARP (0x0806)" : "IPv4 (0x0800)"}: `;
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
  return `IP ${pkt.src}.${p.srcPort} > ${pkt.dst}.${p.dstPort}: ${udpText(p)}`;
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
  // SSH(22)는 암호화되어 tcpdump 가 내용을 풀지 않는다
  if (t.len > 0 && t.data && t.srcPort !== 22 && t.dstPort !== 22) s += `: HTTP: ${t.data.startsWith("GET") ? `${t.data} HTTP/1.1` : t.data.replace(/ \(\d+\/\d+\)$/, "").replace(/^HTTP (\d+)/, "HTTP/1.1 $1")}`;
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
  if (m.kind === "ike") return `${u.dstPort === 4500 || u.srcPort === 4500 ? "NONESP-encap: " : ""}isakmp: ${m.exchange === "IKE_SA_INIT" ? "parent_sa ikev2_init" : m.exchange === "IKE_AUTH" ? "child_sa  ikev2_auth" : "child_sa  inf2"}[${m.response ? "R" : "I"}]`;
  if (m.kind === "dhcp") {
    const fromClient = m.op === "discover" || m.op === "request" || m.op === "release";
    return `BOOTP/DHCP, ${fromClient ? "Request" : "Reply"} from ${m.clientMac}, length ${appLength(u)} (DHCP-Message Option 53: ${DHCP_TYPE[m.op][1]})`;
  }
  if (m.kind === "dns") {
    if (m.op === "query") return `${m.id}+ A? ${m.name}. (${appLength(u)})`;
    if (m.answer) return `${m.id} 1/0/0 A ${m.answer} (${appLength(u)})`;
    return `${m.id} ${m.rcode === "NXDOMAIN" ? "NXDomain" : "ServFail"} 0/0/0 (${appLength(u)})`;
  }
  return `RIPv2, ${m.command === "request" ? "Request" : "Response"}, length: ${appLength(u)}`;
}

// ---------- 계층별 헤더 ----------

export function headerLayers(frame: EthernetFrame): HeaderLayer[] {
  const layers: HeaderLayer[] = [];
  const p = frame.payload;
  const eth: HeaderLayer = {
    title: "이더넷 (L2)",
    rows: [
      ["목적지 MAC", `${frame.dst}${frame.dst === "ff:ff:ff:ff:ff:ff" ? " (브로드캐스트)" : frame.dst.startsWith("01:00:5e") ? " (멀티캐스트)" : ""}`],
      ["출발지 MAC", frame.src],
      ["EtherType", p.kind === "arp" ? "0x0806 (ARP)" : "0x0800 (IPv4)"],
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
  layers.push(...ipLayers(p));
  return layers;
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
  else if (l4.kind === "tcp") layers.push(tcpLayer(l4));
  else if (l4.kind === "esp") layers.push(espLayer(l4, false), ...ipLayers(l4.inner, true));
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
  else {
    layers.push(...udpLayers(l4));
    if (l4.payload.kind === "esp") layers.push(espLayer(l4.payload, true), ...ipLayers(l4.payload.inner, true));
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
  }
  return inTunnel ? layers.map((l) => ({ ...l, title: `터널 안 · ${l.title}` })) : layers;
}

function espLayer(e: EspPacket, natT: boolean): HeaderLayer {
  return {
    title: natT ? "ESP (IPsec, UDP 4500 안 — NAT-T)" : "ESP (IPsec)",
    rows: [
      ["SPI", `0x${e.spi.toString(16).padStart(8, "0")} (이 터널의 번호)`],
      ["순서 번호", `${e.seq} (재전송 공격 방지)`],
      ["안쪽", "암호화됨 — 인터넷 위의 장비는 아래 원래 패킷을 볼 수 없다"],
      ["원래 패킷 (복호화하면)", `${e.inner.src} → ${e.inner.dst}`],
    ],
  };
}

function ikeLayer(m: IkeMessage): HeaderLayer {
  const rows: [string, string][] = [
    ["교환", `${m.exchange === "IKE_SA_INIT" ? "34 (IKE_SA_INIT)" : m.exchange === "IKE_AUTH" ? "35 (IKE_AUTH)" : "37 (INFORMATIONAL)"} ${m.response ? "응답" : "요청"}`],
    ["SPI", `0x${m.spi.toString(16).padStart(8, "0")}`],
  ];
  if (m.natSrc) rows.push(["NAT_DETECTION_SOURCE_IP", `${m.natSrc} (실제로는 해시)`]);
  if (m.natDst) rows.push(["NAT_DETECTION_DESTINATION_IP", `${m.natDst} (실제로는 해시)`]);
  if (m.nat !== undefined) rows.push(["NAT 감지 결과", m.nat ? "NAT 있음 → 이후 UDP 4500" : "NAT 없음"]);
  if (m.auth !== undefined) rows.push(["AUTH", "사전 공유 키로 만든 인증 값 (키 자체는 보내지 않음)"]);
  if (m.error) rows.push(["알림 (Notify)", `${m.error === "AUTHENTICATION_FAILED" ? 24 : m.error === "INTERNAL_ADDRESS_FAILURE" ? 36 : 11} (${m.error})`]);
  if (m.assigned) rows.push(["가상 주소 (CP INTERNAL_IP4_ADDRESS)", m.assigned]);
  if (m.routes?.length) rows.push(["사내 대역 (CP INTERNAL_IP4_SUBNET)", m.routes.map((r) => `${r.dest}/${r.prefix}`).join(", ")]);
  if (m.exchange === "INFORMATIONAL" && !m.error) rows.push(["Delete", "터널을 내린다 (연결 해제)"]);
  return { title: "IKEv2 (앱)", rows };
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

function tcpLayer(t: TcpSegment): HeaderLayer {
  const rows: [string, string][] = [
    ["출발지 포트", String(t.srcPort)],
    ["목적지 포트", `${t.dstPort}${t.dstPort === 80 ? " (HTTP)" : t.dstPort === 443 ? " (HTTPS)" : t.dstPort === 22 ? " (SSH)" : t.dstPort === 3128 ? " (HTTP 프록시)" : ""}`],
    ["순서 번호 (seq)", String(t.seq)],
    ["확인 번호 (ack)", t.ackFlag ? String(t.ack) : "- (ACK 플래그 없음)"],
    ["플래그", `${tcpFlags(t)} [${tcpFlagChars(t)}]`],
    ["데이터 길이", `${t.len}B`],
  ];
  if (t.data) rows.push(["데이터 (요약)", t.srcPort === 22 || t.dstPort === 22 ? "SSH 암호화 데이터 (내용은 다루지 않음)" : t.data]);
  if (t.target) rows.push(["요청 대상 (절대 URI)", `http://${t.target.replace(/:80$/, "")}/ — 프록시에게 대신 받아 달라는 요청`]);
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
      ["질문", `${m.name} A`],
    ];
    if (m.op === "response") rows.push(["응답", m.answer ? `${m.name} A ${m.answer}` : `없음 (rcode ${m.rcode === "NXDOMAIN" ? "3 NXDOMAIN" : "2 SERVFAIL"})`]);
    return [udp, { title: "DNS (앱)", rows }];
  }
  if (m.kind === "vpn" || m.kind === "esp") return [udp];
  if (m.kind === "ike") return [udp, ikeLayer(m)];
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
 * 로그 한 줄을 실무에서 보는 출력으로. frames 는 그 장치가 받은/내보낸 프레임.
 * 대응하는 실무 출력이 없는 종류는 tcpdump 한 줄만 (프레임이 있을 때)
 */
export function practitionerLines(ev: TraceEvent, frames: { received?: EthernetFrame; sent?: EthernetFrame }, deviceName: (id: string) => string = (id) => id): PractitionerLine[] {
  const out: PractitionerLine[] = [];
  const f = frames.received ?? frames.sent;
  const ip = f && f.payload.kind === "ipv4" ? f.payload : undefined;
  const len = ip ? 20 + l4Length(ip.payload) : 0;
  switch (ev.kind) {
    case "ip.forward":
      if (ip) out.push({ tool: "시스코 debug ip packet", line: `IP: s=${ip.src}, d=${ip.dst} (${detail(ev, "out") ?? "?"}), len ${len}, forward` });
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
    case "fw.deny":
    case "fw.allow":
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
      break;
    case "icmp.unreachable.received":
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
      if (ip && ip.payload.kind === "udp" && ip.payload.payload.kind === "dns" && ip.payload.payload.answer) {
        out.push({ tool: "dig", line: `${ip.payload.payload.name}.\t\t300\tIN\tA\t${ip.payload.payload.answer}` });
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
      if (detail(ev, "retransmit") !== undefined) out.push({ tool: "strongSwan (charon)", line: `11[IKE] retransmit ${detail(ev, "retransmit")} of request with message ID ${detail(ev, "step") === "IKE_AUTH" ? 1 : 0}` });
      else if (detail(ev, "spi") !== undefined) out.push({ tool: "strongSwan (charon)", line: `07[IKE] initiating IKE_SA vpn[1] to ${detail(ev, "peer") ?? "?"}` });
      if (detail(ev, "localNat") === "true") out.push({ tool: "strongSwan (charon)", line: `08[IKE] local host is behind NAT, sending keep alives` });
      if (detail(ev, "remoteNat") === "true") out.push({ tool: "strongSwan (charon)", line: `08[IKE] remote host is behind NAT` });
      break;
    case "vpn.up":
      out.push({ tool: "strongSwan (charon)", line: `09[IKE] IKE_SA vpn[1] established between ${ip?.dst ?? "?"}...${detail(ev, "peer") ?? "?"}` });
      out.push({ tool: "strongSwan (charon)", line: `09[IKE] CHILD_SA vpn{1} established${detail(ev, "natT") === "true" ? " (UDP-encapsulated, NAT-T)" : ""}` });
      break;
    case "vpn.drop":
      if (ev.summary.includes("AUTHENTICATION_FAILED 로 거절 —")) out.push({ tool: "strongSwan (charon)", line: `12[IKE] received AUTHENTICATION_FAILED notify error` });
      else if (ev.summary.includes("PSK)가 다름 → AUTHENTICATION_FAILED")) out.push({ tool: "strongSwan (charon)", line: `05[IKE] tried 1 shared key for '${ip?.dst ?? "?"}' - '${ip?.src ?? "?"}', but MAC mismatched` });
      else if (ev.summary.includes("재전송") && ev.summary.includes("timeout")) out.push({ tool: "strongSwan (charon)", line: `11[IKE] giving up after 2 retransmits` });
      break;
    case "lb.forward":
      if (detail(ev, "vip")) out.push({ tool: "리눅스 ipvsadm -Lnc", line: `TCP 01:00  ${(detail(ev, "state") ?? "ESTABLISHED").padEnd(11)} ${detail(ev, "client")}  ${detail(ev, "vip")}  ${detail(ev, "backend")}` });
      break;
    case "lb.down":
      out.push({ tool: "nginx error.log", line: `connect() failed while connecting to upstream, upstream: "http://${detail(ev, "backend") ?? "?"}/" — upstream server temporarily disabled` });
      break;
    case "proxy.use":
      out.push({ tool: "curl -v", line: `* Uses proxy env variable http_proxy == 'http://${detail(ev, "proxy") ?? "?"}'` });
      out.push({ tool: "curl -v", line: `> GET http://${String(detail(ev, "dst") ?? "?")}/ HTTP/1.1` });
      break;
    case "tcp.cookie":
      out.push({ tool: "curl -v", line: `< Set-Cookie: ${detail(ev, "cookie") ?? "?"}; path=/` });
      break;
    case "proxy.relay":
    case "proxy.deny":
    case "proxy.fail": {
      // Squid access.log: 시각 경과ms 클라이언트 결과/상태 바이트 메서드 URL 사용자 계층/상대 형식
      const target = detail(ev, "target");
      const url = detail(ev, "url") ?? (target ? `http://${target.replace(/:80$/, "")}/` : "-");
      const code = detail(ev, "result") ?? "-";
      // 대상에 연결해 본 것(응답 전달·연결 실패)은 HIER_DIRECT, 연결하지 않은 것(차단·이름 실패·대상 없음)은 HIER_NONE
      const hier = detail(ev, "ip") ? `HIER_DIRECT/${detail(ev, "ip")}` : "HIER_NONE/-";
      out.push({ tool: "Squid access.log", line: `${(ev.time / 1000).toFixed(3)}      0 ${detail(ev, "client") ?? "-"} ${code} ${detail(ev, "bytes") ?? 200} GET ${url} - ${hier} text/html` });
      break;
    }
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
