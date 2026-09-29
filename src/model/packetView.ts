// 패킷 상세 보기 (순수): 로그 한 줄이 가리키는 프레임을 실제 도구의 출력 형식으로 바꾼다.
// - tcpdumpLine: 같은 패킷을 tcpdump -n -e 가 찍는 한 줄로
// - headerLayers: 이더넷 → ARP/IPv4 → ICMP/TCP/UDP → DHCP/DNS/RIP 필드를 실제 번호(타입·코드·옵션)와 함께
// - practitionerLines: 장치가 내린 판단을 실무 명령의 출력(시스코 debug, iptables LOG, dhclient, ping, curl …)으로
// 시뮬레이터에 없는 필드(체크섬, 윈도우 크기, IP ID 등)는 넣지 않고, 길이는 근사값이다.
import type { DhcpOp, EthernetFrame, IcmpPacket, Ipv4Packet, TcpSegment, UdpPacket } from "../core/packet";
import { describeOriginal, tcpFlags, UNREACHABLE_FLAG } from "../core/packet";
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
  return 8 + appLength(p);
}
function appLength(u: UdpPacket): number {
  const m = u.payload;
  if (m.kind === "dhcp") return 300;
  if (m.kind === "dns") return 12 + m.name.length + 6 + (m.answer ? 16 : 0);
  return 4 + m.entries.length * 20; // RIP
}

// ---------- tcpdump 한 줄 ----------

/** 같은 패킷을 tcpdump -n -e 형식 한 줄로 (MAC 주소 포함) */
export function tcpdumpLine(frame: EthernetFrame): string {
  const eth = `${frame.src} > ${frame.dst}${frame.vlan !== undefined ? `, 802.1Q vlan ${frame.vlan}` : ""}, ethertype ${frame.payload.kind === "arp" ? "ARP (0x0806)" : "IPv4 (0x0800)"}: `;
  const p = frame.payload;
  if (p.kind === "arp") {
    return eth + (p.op === "request" ? `ARP, Request who-has ${p.targetIp} tell ${p.senderIp}, length 28` : `ARP, Reply ${p.senderIp} is-at ${p.senderMac}, length 28`);
  }
  return eth + ipLine(p);
}

function ipLine(pkt: Ipv4Packet): string {
  const p = pkt.payload;
  if (p.kind === "icmp") return `IP ${pkt.src} > ${pkt.dst}: ${icmpText(p)}, length ${l4Length(p)}`;
  if (p.kind === "tcp") return `IP ${pkt.src}.${p.srcPort} > ${pkt.dst}.${p.dstPort}: ${tcpText(p)}`;
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
  if (t.len > 0 && t.data) s += `: HTTP: ${t.data.startsWith("GET") ? `${t.data} HTTP/1.1` : t.data.replace(/ \(\d+\/\d+\)$/, "").replace(/^HTTP (\d+)/, "HTTP/1.1 $1")}`;
  return s;
}

function udpText(u: UdpPacket): string {
  const m = u.payload;
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
  const l4 = p.payload;
  const proto = l4.kind === "icmp" ? "1 (ICMP)" : l4.kind === "tcp" ? "6 (TCP)" : "17 (UDP)";
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
  else layers.push(...udpLayers(l4));
  return layers;
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
    ["목적지 포트", `${t.dstPort}${t.dstPort === 80 ? " (HTTP)" : t.dstPort === 443 ? " (HTTPS)" : ""}`],
    ["순서 번호 (seq)", String(t.seq)],
    ["확인 번호 (ack)", t.ackFlag ? String(t.ack) : "- (ACK 플래그 없음)"],
    ["플래그", `${tcpFlags(t)} [${tcpFlagChars(t)}]`],
    ["데이터 길이", `${t.len}B`],
  ];
  if (t.data) rows.push(["데이터 (요약)", t.data]);
  if (t.via !== undefined) rows.push(["Via (HTTP 헤더 흉내)", `로드밸런서 ${t.via}개 거침`]);
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
    case "lb.down":
      out.push({ tool: "nginx error.log", line: `connect() failed while connecting to upstream, upstream: "http://${detail(ev, "backend") ?? "?"}/" — upstream server temporarily disabled` });
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
