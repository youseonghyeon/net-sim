// AdGuard Home (GL.iNet 공유기의 앱) 과 자녀 보호: 공유기의 DNS 포워더 앞에서 이름을 거른다.
// - 차단 목록(광고·추적)·사용자 규칙에 걸린 이름은 업스트림에 묻지 않고 0.0.0.0 (또는 NXDOMAIN) 으로 답한다 → 광고 서버에 아예 접속하지 않는다
// - 규칙은 그 이름과 하위 이름 모두 (AdGuard 의 ||example.com^). 예외(허용) 규칙이 이긴다
// - 자녀 보호: 기기(LAN 주소)마다 카테고리(SNS·게임·동영상)를 막는다 — 같은 DNS 필터로
// - DNS 가로채기: DNS 를 8.8.8.8 처럼 직접 적은 기기는 공유기를 거치지 않아 걸러지지 않는다. 켜면 LAN 에서 나가는 UDP 53 을
//   공유기가 대신 받는다 (iptables REDIRECT — 기기는 8.8.8.8 이 답한 줄 안다). DoH(HTTPS 위의 DNS)는 못 막는다
// 쿼리 로그(최근 50개)·통계(질의·차단 수)를 남긴다. 생략: 목록 자동 갱신, 안전 검색, 시간 예약(벽시계 없음)
import type { Ip } from "../addr";
import { normalizeName, type DnsRecord } from "./dns";

export type ParentalCategory = "sns" | "game" | "video";

/** 차단 목록 (AdGuard DNS filter 의 일부를 흉내) */
export const AD_DOMAINS = ["doubleclick.net", "googlesyndication.com", "google-analytics.com", "adservice.google.com", "app-measurement.com"];

export const PARENTAL_CATEGORIES: Record<ParentalCategory, { label: string; domains: string[] }> = {
  sns: { label: "SNS", domains: ["instagram.com", "facebook.com", "tiktok.com", "x.com"] },
  game: { label: "게임", domains: ["roblox.com", "minecraft.net", "steampowered.com"] },
  video: { label: "동영상", domains: ["youtube.com", "twitch.tv", "netflix.com"] },
};

/** 위 이름들의 공인 주소 (인터넷 노드의 공인 DNS 가 답한다 — 자동완성 목록에는 넣지 않는다) */
export const FILTER_ZONE: DnsRecord[] = [
  { name: "doubleclick.net", ip: "142.250.76.130" },
  { name: "googlesyndication.com", ip: "142.250.76.162" },
  { name: "google-analytics.com", ip: "142.250.76.142" },
  { name: "adservice.google.com", ip: "142.250.76.98" },
  { name: "app-measurement.com", ip: "142.250.76.174" },
  { name: "instagram.com", ip: "157.240.215.174" },
  { name: "facebook.com", ip: "157.240.215.35" },
  { name: "tiktok.com", ip: "23.38.83.48" },
  { name: "x.com", ip: "104.244.42.1" },
  { name: "roblox.com", ip: "128.116.123.3" },
  { name: "minecraft.net", ip: "13.107.246.40" },
  { name: "steampowered.com", ip: "23.192.228.84" },
  { name: "youtube.com", ip: "142.250.207.14" },
  { name: "twitch.tv", ip: "151.101.66.167" },
  { name: "netflix.com", ip: "54.155.178.5" },
];

export interface AdguardConfig {
  enabled: boolean;
  /** 광고·추적 차단 목록 */
  ads: boolean;
  /** 차단 응답: 0.0.0.0 (AdGuard 기본) 또는 NXDOMAIN */
  mode: "zero" | "nxdomain";
  /** 사용자 차단 규칙 (이름과 하위 이름) */
  custom: string[];
  /** 예외 (차단보다 먼저) */
  allow: string[];
  /** DNS 가로채기 */
  forceDns: boolean;
  /** 자녀 보호: 기기마다 막을 카테고리 */
  parental: { ip: Ip; categories: ParentalCategory[] }[];
}

export const DEFAULT_ADGUARD: AdguardConfig = { enabled: false, ads: true, mode: "zero", custom: [], allow: [], forceDns: false, parental: [] };

export interface AdguardVerdict {
  /** 걸린 규칙 (화면·로그용) */
  rule: string;
  /** 어느 목록 */
  list: string;
}

/** 이름이 규칙(그 이름 또는 하위 이름)에 걸리는지 */
function covers(rule: string, name: string): boolean {
  const r = normalizeName(rule);
  return !!r && (name === r || name.endsWith(`.${r}`));
}

export class Adguard {
  config: AdguardConfig = { ...DEFAULT_ADGUARD, custom: [], allow: [], parental: [] };
  readonly stats = { total: 0, blocked: 0 };
  readonly log: { at: number; client: Ip; name: string; qtype: string; result: string }[] = [];

  /** 이 질의를 막는지. 막으면 이유, 아니면 undefined. 켜져 있지 않으면 늘 undefined */
  check(rawName: string, client: Ip): AdguardVerdict | undefined {
    const c = this.config;
    if (!c.enabled) return undefined;
    const name = normalizeName(rawName);
    const allow = c.allow.find((r) => covers(r, name));
    if (allow) return undefined;
    const custom = c.custom.find((r) => covers(r, name));
    if (custom) return { rule: `||${normalizeName(custom)}^`, list: "사용자 규칙" };
    if (c.ads) {
      const ad = AD_DOMAINS.find((r) => covers(r, name));
      if (ad) return { rule: `||${ad}^`, list: "광고·추적 (AdGuard DNS filter)" };
    }
    const kid = c.parental.find((p) => p.ip === client);
    for (const cat of kid?.categories ?? []) {
      const hit = PARENTAL_CATEGORIES[cat].domains.find((r) => covers(r, name));
      if (hit) return { rule: `||${hit}^`, list: `자녀 보호 · ${PARENTAL_CATEGORIES[cat].label}` };
    }
    return undefined;
  }

  record(now: number, client: Ip, name: string, qtype: string, result: string, blocked: boolean): void {
    this.stats.total++;
    if (blocked) this.stats.blocked++;
    this.log.push({ at: now, client, name: normalizeName(name), qtype, result });
    if (this.log.length > 50) this.log.shift();
  }

  rows(): string[][] {
    return [...this.log].reverse().map((e) => [`${e.at}ms`, e.client, `${e.name} ${e.qtype}`, e.result]);
  }

  summary(): string {
    const pct = this.stats.total ? Math.round((this.stats.blocked / this.stats.total) * 100) : 0;
    return `질의 ${this.stats.total} · 차단 ${this.stats.blocked} (${pct}%)`;
  }
}
