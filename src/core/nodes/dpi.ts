// DPI (Deep Packet Inspection — GL.iNet 의 흐름 제어, Netify 엔진 식): 공유기가 지나가는 흐름마다 "무슨 앱인가" 를 알아본다.
// 내용을 풀지 않고(암호화돼 못 푼다) 보이는 것만 본다:
// - TLS ClientHello 의 SNI (접속할 이름은 암호화 전이라 보인다) → 이름으로 앱 (youtube.com → YouTube)
// - 공유기 DNS 포워더가 답해 준 이름 → 그 주소로 가는 흐름 (DNS 로 배운 주소)
// - 프로토콜의 모양: WireGuard(첫 메시지 종류·크기 148바이트), IKE·ESP(IPsec), L2TP, DNS, STUN, 포트(SSH 22, HTTP 80, QUIC 443/UDP)
// 앱마다·기기마다 트래픽(패킷·바이트)을 세고, 막을 앱·카테고리를 고르면 TCP 는 RST 를 주입해 끊고 UDP 는 드롭한다.
// 난독화한 VPN(모양을 흐트러뜨린 WireGuard)은 "알 수 없는 UDP" 로 보여 VPN 차단을 지나간다 — "알 수 없음" 까지 막으면 그것도 막힌다.
// 생략: 흐름 수 상한 이상의 기억(오래된 것부터 버림), 앱 시그니처 갱신, 대역폭 제한(QoS — 대역폭 모델이 없다)
import type { Ip } from "../addr";
import type { Ipv4Packet } from "../packet";
import { normalizeName } from "./dns";

export type DpiCategory = "동영상" | "SNS" | "게임" | "VPN" | "웹" | "기본" | "알 수 없음";
export type AppId =
  | "youtube"
  | "netflix"
  | "twitch"
  | "instagram"
  | "facebook"
  | "tiktok"
  | "x"
  | "roblox"
  | "minecraft"
  | "steam"
  | "google"
  | "naver"
  | "github"
  | "ads"
  | "wireguard"
  | "ipsec"
  | "l2tp"
  | "openvpn"
  | "ssh"
  | "dns"
  | "http"
  | "https"
  | "quic"
  | "p2p"
  | "ping"
  | "unknown";

export const APPS: Record<AppId, { label: string; category: DpiCategory }> = {
  youtube: { label: "YouTube", category: "동영상" },
  netflix: { label: "Netflix", category: "동영상" },
  twitch: { label: "Twitch", category: "동영상" },
  instagram: { label: "Instagram", category: "SNS" },
  facebook: { label: "Facebook", category: "SNS" },
  tiktok: { label: "TikTok", category: "SNS" },
  x: { label: "X", category: "SNS" },
  roblox: { label: "Roblox", category: "게임" },
  minecraft: { label: "Minecraft", category: "게임" },
  steam: { label: "Steam", category: "게임" },
  google: { label: "Google", category: "웹" },
  naver: { label: "네이버", category: "웹" },
  github: { label: "GitHub", category: "웹" },
  ads: { label: "광고·추적", category: "웹" },
  wireguard: { label: "WireGuard", category: "VPN" },
  ipsec: { label: "IPsec (IKE·ESP)", category: "VPN" },
  l2tp: { label: "L2TP", category: "VPN" },
  openvpn: { label: "OpenVPN", category: "VPN" },
  ssh: { label: "SSH", category: "기본" },
  dns: { label: "DNS", category: "기본" },
  http: { label: "HTTP", category: "웹" },
  https: { label: "HTTPS (이름 모름)", category: "웹" },
  quic: { label: "QUIC (UDP 443)", category: "웹" },
  p2p: { label: "P2P·STUN", category: "기본" },
  ping: { label: "ping (ICMP)", category: "기본" },
  unknown: { label: "알 수 없음", category: "알 수 없음" },
};

/** 이름 → 앱 (그 이름과 하위 이름) */
const DOMAIN_APPS: [string, AppId][] = [
  ["youtube.com", "youtube"],
  ["netflix.com", "netflix"],
  ["twitch.tv", "twitch"],
  ["instagram.com", "instagram"],
  ["facebook.com", "facebook"],
  ["tiktok.com", "tiktok"],
  ["x.com", "x"],
  ["roblox.com", "roblox"],
  ["minecraft.net", "minecraft"],
  ["steampowered.com", "steam"],
  ["google.com", "google"],
  ["naver.com", "naver"],
  ["github.com", "github"],
  ["doubleclick.net", "ads"],
  ["googlesyndication.com", "ads"],
  ["google-analytics.com", "ads"],
];

export function appOfName(raw: string): AppId | undefined {
  const n = normalizeName(raw);
  return DOMAIN_APPS.find(([d]) => n === d || n.endsWith(`.${d}`))?.[1];
}

export interface DpiConfig {
  enabled: boolean;
  /** 막을 앱 */
  blockApps: AppId[];
  /** 막을 카테고리 (그 카테고리의 앱 모두) */
  blockCategories: DpiCategory[];
}

export const DEFAULT_DPI: DpiConfig = { enabled: false, blockApps: [], blockCategories: [] };

interface Flow {
  app: AppId;
  /** 그 앱이라고 본 근거 */
  why: string;
  client: Ip;
  blocked: boolean;
}

/** 흐름 기억 상한 */
const FLOW_CAP = 512;

export interface DpiVerdict {
  app: AppId;
  why: string;
  /** 막을지 */
  block: boolean;
  /** 이 패킷에서 앱을 새로 알아봤는지 (로그는 이때만) */
  fresh: boolean;
}

export class Dpi {
  config: DpiConfig = { ...DEFAULT_DPI, blockApps: [], blockCategories: [] };
  private readonly flows = new Map<string, Flow>();
  /** DNS 로 배운 주소 → 앱 */
  private readonly ipApps = new Map<Ip, { app: AppId; name: string }>();
  /** 기기 → 앱 → 패킷·바이트 */
  readonly stats = new Map<Ip, Map<AppId, { pkts: number; bytes: number }>>();

  /** 공유기 DNS 포워더가 이름을 답함: 그 주소를 그 앱으로 기억 */
  learnDns(name: string, ip: Ip): void {
    const app = appOfName(name);
    if (app) this.ipApps.set(ip, { app, name: normalizeName(name) });
  }

  isBlocked(app: AppId): boolean {
    return this.config.blockApps.includes(app) || this.config.blockCategories.includes(APPS[app].category);
  }

  /**
   * 지나가는 패킷 하나 (out = LAN → 밖, in = 밖 → LAN, client = LAN 쪽 기기). 흐름의 앱을 알아보고(더 구체적인 근거가 나오면 바꾼다)
   * 세고, 막을지 알려 준다. 꺼져 있으면 undefined
   */
  inspect(pkt: Ipv4Packet, dir: "out" | "in", client: Ip): DpiVerdict | undefined {
    if (!this.config.enabled) return undefined;
    const key = flowKey(pkt, dir);
    let f = this.flows.get(key);
    const seen = classify(pkt, dir === "out" ? pkt.dst : pkt.src, this.ipApps);
    let fresh = false;
    if (!f) {
      f = { ...seen, client, blocked: false };
      this.flows.set(key, f);
      if (this.flows.size > FLOW_CAP) this.flows.delete(this.flows.keys().next().value!);
      fresh = true;
    } else if (seen.strong && f.app !== seen.app && (f.app === "https" || f.app === "unknown" || f.app === "http" || f.app === "quic")) {
      // 처음엔 포트로만 짐작했던 흐름: 더 확실한 근거(SNI 등)로 바꾼다
      f.app = seen.app;
      f.why = seen.why;
      fresh = true;
    }
    const s = this.stats.get(client) ?? new Map();
    this.stats.set(client, s);
    const c = s.get(f.app) ?? { pkts: 0, bytes: 0 };
    c.pkts++;
    c.bytes += ipLength(pkt);
    s.set(f.app, c);
    const block = this.isBlocked(f.app);
    if (block && !f.blocked) {
      f.blocked = true;
      fresh = true;
    }
    return { app: f.app, why: f.why, block, fresh };
  }

  /** 표: 기기·앱·패킷·바이트 (바이트 많은 순) */
  rows(): string[][] {
    const out: { client: Ip; app: AppId; pkts: number; bytes: number }[] = [];
    for (const [client, m] of this.stats) for (const [app, c] of m) out.push({ client, app, ...c });
    return out.sort((a, b) => b.bytes - a.bytes).map((r) => [r.client, `${APPS[r.app].label}${this.isBlocked(r.app) ? " · 차단" : ""}`, APPS[r.app].category, `${r.pkts}개 · ${r.bytes}B`]);
  }

  /** 상태를 비운다 (설정 변경 — 막는 기준이 바뀌면 새 흐름부터) */
  resetFlows(): void {
    this.flows.clear();
  }
}

function flowKey(pkt: Ipv4Packet, dir: "out" | "in"): string {
  const p = pkt.payload;
  const [a, b] = dir === "out" ? [pkt.src, pkt.dst] : [pkt.dst, pkt.src];
  if (p.kind === "tcp" || p.kind === "udp") {
    const [pa, pb] = dir === "out" ? [p.srcPort, p.dstPort] : [p.dstPort, p.srcPort];
    return `${p.kind}:${a}:${pa}>${b}:${pb}`;
  }
  if (p.kind === "icmp" && (p.type === "echo-request" || p.type === "echo-reply")) return `icmp:${a}>${b}:${p.id}`;
  return `${p.kind}:${a}>${b}`;
}

function ipLength(pkt: Ipv4Packet): number {
  const p = pkt.payload;
  if (p.kind === "tcp") return 40 + p.len;
  if (p.kind === "udp") return 28 + 100;
  return 84;
}

/** 패킷 하나의 앱 (strong = 이름·모양처럼 확실한 근거, 아니면 포트 짐작) */
function classify(pkt: Ipv4Packet, remote: Ip, ipApps: Map<Ip, { app: AppId; name: string }>): { app: AppId; why: string; strong: boolean } {
  const p = pkt.payload;
  if (p.kind === "esp") return { app: "ipsec", why: "ESP (IP 프로토콜 50)", strong: true };
  if (p.kind === "icmp") return { app: "ping", why: "ICMP", strong: true };
  if (p.kind === "udp") {
    const m = p.payload;
    if (m.kind === "wg" && !m.obf) return { app: "wireguard", why: m.type === "initiation" ? "WireGuard 모양 (메시지 종류 1, 148바이트)" : "WireGuard 모양 (메시지 종류·세션 번호)", strong: true };
    if (m.kind === "ike" || m.kind === "esp") return { app: "ipsec", why: m.kind === "ike" ? `IKE (UDP ${p.dstPort === 4500 || p.srcPort === 4500 ? 4500 : 500})` : "UDP 4500 안의 ESP (NAT-T)", strong: true };
    if (m.kind === "l2tp") return { app: "l2tp", why: "L2TP (UDP 1701)", strong: true };
    if (m.kind === "dns") return { app: "dns", why: "DNS (UDP 53)", strong: true };
    if (m.kind === "stun" || m.kind === "p2p") return { app: "p2p", why: m.kind === "stun" ? "STUN 모양" : "P2P 앱", strong: true };
    if (m.kind === "dhcp" || m.kind === "dhcp6") return { app: "dns", why: "DHCP", strong: true };
    if (p.dstPort === 443 || p.srcPort === 443) return { app: "quic", why: "UDP 443 (QUIC 로 짐작)", strong: false };
    return { app: "unknown", why: m.kind === "wg" ? "모양을 알아볼 수 없는 UDP (난독화된 VPN 일 수 있음)" : `알아볼 수 없는 UDP ${p.dstPort}`, strong: false };
  }
  if (p.kind !== "tcp") return { app: "unknown", why: p.kind, strong: false };
  if (p.sni) {
    const app = appOfName(p.sni);
    return app ? { app, why: `TLS SNI ${p.sni}`, strong: true } : { app: "https", why: `TLS SNI ${p.sni} (모르는 이름)`, strong: false };
  }
  const learned = ipApps.get(remote);
  if (learned) return { app: learned.app, why: `DNS 로 배운 주소 (${learned.name} = ${remote})`, strong: true };
  const port = Math.min(p.dstPort, p.srcPort);
  if (port === 22 || p.dstPort === 22 || p.srcPort === 22) return { app: "ssh", why: "TCP 22", strong: false };
  if (p.dstPort === 80 || p.srcPort === 80) return { app: "http", why: "TCP 80", strong: false };
  if (p.dstPort === 443 || p.srcPort === 443) return { app: "https", why: "TCP 443 (SNI 를 아직 못 봄)", strong: false };
  if (p.dstPort === 1194 || p.srcPort === 1194) return { app: "openvpn", why: "TCP 1194", strong: false };
  return { app: "unknown", why: `TCP ${p.dstPort}`, strong: false };
}
