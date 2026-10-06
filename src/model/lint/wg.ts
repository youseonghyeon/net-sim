// WireGuard 규칙: 공유기 서버(피어 목록·터널 대역)와 클라이언트(공유기·노트북·폰)가 가리키는 서버의 켜짐·포트·공개 키·등록·주소.
// WireGuard 는 틀리면 거절하지 않고 침묵하므로(timeout 만 보인다) 로그만으로는 원인을 찾기 어렵다 — 그래서 구성 검사가 짚어 준다
import { DDNS_ZONE_NAME, ddnsHostname, wgPublicKeyOf, type Device } from "../topology";
import { contains, fmtSubnet, overlaps, subnetOf, validIp } from "./addr";
import type { LintContext } from "./context";

/** "10.0.0.2/32" (프리픽스가 없으면 dflt) — netSync 의 parseCidr 와 같은 기준 */
function cidr(text: string | undefined, dflt: number): { ip: string; prefix: number } | undefined {
  const m = /^\s*([0-9.]+)\s*(?:\/\s*(\d{1,2}))?\s*$/.exec(text ?? "");
  if (!m || !validIp(m[1])) return undefined;
  const prefix = m[2] === undefined ? dflt : Number(m[2]);
  return prefix >= 0 && prefix <= 32 ? { ip: m[1]!, prefix } : undefined;
}

/** AllowedIPs 목록에 이 주소가 드는지 (0.0.0.0/0 포함) */
function allowedHas(list: string, ip: string): boolean {
  return list
    .split(/[,\s]+/)
    .map((x) => cidr(x, 32))
    .some((c) => !!c && (c.prefix === 0 || contains(subnetOf(c.ip, c.prefix)!, ip)));
}

interface Client {
  d: Device;
  role: "client" | "host";
  /** 무엇의 설정인지 (문구용) */
  where: string;
  server: string;
  port: number;
  serverKey: string;
  address: string;
  allowedIps: string;
  dns: string;
}

function clientsOf(devices: Device[]): Client[] {
  const out: Client[] = [];
  for (const d of devices) {
    const c = d.router?.wgClient;
    if (c?.enabled) out.push({ d, role: "client", where: "WireGuard 클라이언트", server: c.server, port: c.port, serverKey: c.serverKey, address: c.address, allowedIps: c.allowedIps, dns: c.dns });
    const h = d.host?.ra;
    if (h?.enabled && h.type === "wireguard" && h.wg) out.push({ d, role: "host", where: "VPN (WireGuard)", server: h.server, port: h.wg.port, serverKey: h.wg.serverKey, address: h.wg.address, allowedIps: h.wg.allowedIps, dns: h.wg.dns });
  }
  return out;
}

/** 공유기의 수동 WAN 주소 (자동이면 모름 — 판단하지 않는다) */
function routerWanIp(x: Device): string | undefined {
  return x.router?.wan?.ipMode === "static" ? validIp(x.router.wan.ip) : undefined;
}

/**
 * 엔드포인트(주소:포트)를 받는 공유기를 찾는다: WAN 주소가 그 주소인 공유기. 그 공유기가 WireGuard 서버를 켜지 않고
 * 그 UDP 포트를 안쪽으로 포워딩하면 포워딩 대상(수동 WAN 주소의 공유기)으로 따라간다 (공유기 뒤 Brume). 모르면 undefined (침묵)
 */
function serverAt(devices: Device[], self: Device, ip: string, port: number): { srv: Device; port: number; via?: Device } | undefined {
  let srv = devices.find((x) => x !== self && routerWanIp(x) === ip);
  let p = port;
  let via: Device | undefined;
  for (let hop = 0; srv && !(srv.router?.wgServer?.enabled && srv.router.wgServer.port === p) && hop < 4; hop++) {
    const fwd = srv.router?.forwards?.find((f) => f.proto === "udp" && f.publicPort === p);
    if (!fwd) break;
    const lan = validIp(fwd.lanIp);
    via = srv;
    p = fwd.lanPort;
    srv = lan ? devices.find((x) => x !== self && routerWanIp(x) === lan) : undefined;
  }
  return srv ? { srv, port: p, ...(via ? { via } : {}) } : undefined;
}

/** 이 DDNS 이름을 켜 둔 공유기 */
function ddnsOwner(devices: Device[], name: string): Device | undefined {
  return devices.find((x) => x.router?.ddns?.enabled && ddnsHostname(x.router.ddns.name) === name);
}

// 규칙 20d: DDNS — 이름이 비었거나 쓸 수 없음, 두 공유기가 같은 이름
export function ddnsRules({ t, add }: LintContext): void {
  const seen = new Map<string, Device>();
  for (const d of t.devices) {
    const c = d.router?.ddns;
    if (!c?.enabled) continue;
    const name = ddnsHostname(c.name);
    if (!name) {
      add({ deviceId: d.id, severity: "warn", code: "ddns.name-invalid", message: `DDNS 이름 "${c.name}" 을(를) 쓸 수 없음 (영문 소문자·숫자·- 만) → 갱신하지 않음`, fix: `${d.name} → DDNS → 이름 (예: myhome → myhome.${DDNS_ZONE_NAME})` });
      continue;
    }
    const prev = seen.get(name);
    if (prev) {
      add({ deviceId: d.id, severity: "error", code: "ddns.name-taken", message: `${prev.name} 도 DDNS 이름 ${name} 을(를) 씀 → 이름은 기기마다 하나라 나중에 갱신하는 쪽이 거절됨 (badauth)`, fix: `${d.name} → DDNS → 다른 이름`, related: [prev.id] });
      continue;
    }
    seen.set(name, d);
  }
}

// 규칙 20c: WireGuard
export function wireguardRules({ t, add }: LintContext): void {
  // 서버 쪽: 피어 주소 중복, 터널 대역이 LAN 과 겹침, 피어 없음
  for (const d of t.devices) {
    const s = d.router?.wgServer;
    if (!s?.enabled) continue;
    const addr = cidr(s.address, 24);
    const tunnel = addr ? subnetOf(addr.ip, addr.prefix) : undefined;
    const lan = subnetOf(validIp(d.router!.lanIp), d.router!.lanPrefix);
    if (tunnel && lan && overlaps(tunnel, lan)) {
      add({ deviceId: d.id, severity: "error", code: "wg.overlap", message: `WireGuard 터널 대역 ${fmtSubnet(tunnel)} 이 LAN ${fmtSubnet(lan)} 과 겹침 → 같은 주소가 LAN 과 터널에 함께 생겨 응답이 엉뚱한 곳으로 감`, fix: `${d.name} → WireGuard 서버 → 터널 주소를 LAN 과 다른 대역으로 (예: 10.0.0.1/24)` });
    }
    const peers = s.peers.filter((p) => p.publicKey.trim() !== "");
    if (peers.length === 0) {
      add({ deviceId: d.id, severity: "warn", code: "wg.no-peers", message: "WireGuard 서버에 등록한 클라이언트(피어)가 없음 → 아무도 붙을 수 없음 (WireGuard 는 등록된 공개 키에만 답한다)", fix: `${d.name} → WireGuard 서버 → 피어 추가 (클라이언트의 공개 키와 터널 주소)` });
    }
    const seen = new Map<string, string>();
    const keys = new Map<string, string>();
    for (const p of peers) {
      const k = p.publicKey.trim();
      if (keys.has(k)) {
        add({ deviceId: d.id, severity: "error", code: "wg.peer-key-duplicate", message: `피어 ${keys.get(k) || "(이름 없음)"} 와 ${p.name || "(이름 없음)"} 의 공개 키가 같음 → 앞의 피어만 쓰이고 뒤의 것은 무시됨 (공개 키가 곧 신원)`, fix: `${d.name} → WireGuard 서버 → 중복 피어를 지우거나 그 기기의 공개 키로` });
        continue;
      }
      keys.set(k, p.name);
      const ip = validIp(p.ip.trim());
      if (!ip) continue;
      if (lan && contains(lan, ip)) {
        add({ deviceId: d.id, severity: "error", code: "wg.peer-in-lan", message: `피어 ${p.name || "(이름 없음)"} 의 터널 주소 ${ip} 가 집 LAN ${fmtSubnet(lan)} 안 → LAN 기기는 그 주소를 같은 서브넷으로 보고 ARP 로 찾아 공유기를 거치지 않음 (닿지 않음)`, fix: `${d.name} → WireGuard 서버 → 피어 주소를 터널 대역(${tunnel ? fmtSubnet(tunnel) : "예: 10.0.0.0/24"}) 안으로` });
      } else if (tunnel && !contains(tunnel, ip)) {
        add({ deviceId: d.id, severity: "warn", code: "wg.peer-outside", message: `피어 ${p.name || "(이름 없음)"} 의 터널 주소 ${ip} 가 서버 터널 대역 ${fmtSubnet(tunnel)} 밖 → 동작은 하지만 LAN 기기의 응답이 기본 게이트웨이(이 공유기)로 와야 해 경로가 엇갈리기 쉬움`, fix: `${d.name} → WireGuard 서버 → 피어 주소를 ${fmtSubnet(tunnel)} 안으로` });
      }
      const prev = seen.get(ip);
      if (prev !== undefined) {
        add({ deviceId: d.id, severity: "error", code: "wg.peer-duplicate", message: `피어 ${prev || "(이름 없음)"} 와 ${p.name || "(이름 없음)"} 의 터널 주소가 ${ip} 로 같음 → 그 주소로 가는 패킷은 한쪽에만 감 (AllowedIPs 가 겹침)`, fix: `${d.name} → WireGuard 서버 → 피어마다 다른 터널 주소` });
      }
      seen.set(ip, p.name);
    }
  }
  // 클라이언트 쪽: 가리킨 서버의 켜짐·포트·공개 키·등록·터널 주소, DNS 가 터널 밖
  for (const c of clientsOf(t.devices)) {
    const { d } = c;
    const me = cidr(c.address, 32);
    if (!me) {
      add({ deviceId: d.id, severity: "error", code: "wg.no-address", message: `${c.where} 에 내 터널 주소가 없음 → 터널로 보낼 출발지가 없어 VPN 을 쓰지 못함${c.role === "client" && d.router?.wgClient?.killSwitch ? " (킬 스위치가 켜져 있어 LAN 기기의 인터넷이 막힘)" : ""}`, fix: `${d.name} → ${c.where} → 내 터널 주소 (서버 관리자가 정해 준 주소, 예: 10.0.0.2/32)` });
    }
    const dns = validIp(c.dns.trim());
    if (dns && !allowedHas(c.allowedIps, dns)) {
      add({
        deviceId: d.id,
        severity: "warn",
        code: "wg.dns-outside",
        message:
          c.role === "client"
            ? `${c.where} 의 DNS ${dns} 가 AllowedIPs(${c.allowedIps || "없음"}) 밖 → 공유기는 그 DNS 를 쓰지 않고 원래 업스트림에 WAN 으로 묻는다 (DNS 질의가 VPN 밖으로 샘)`
            : `${c.where} 의 DNS ${dns} 가 AllowedIPs(${c.allowedIps || "없음"}) 밖 → DNS 질의가 터널로 가지 않음 (사설 주소면 닿지 않고, 공인 주소면 VPN 밖으로 새어 나감)`,
        fix: `${d.name} → ${c.where} → AllowedIPs 에 ${dns} 를 넣거나 DNS 를 비우기`,
      });
    }
    const server = validIp(c.server.trim());
    const name = server ? undefined : c.server.trim().toLowerCase().replace(/\.$/, "");
    let found: ReturnType<typeof serverAt>;
    if (server) found = serverAt(t.devices, d, server, c.port);
    else if (name) {
      // 서버를 DDNS 이름으로 적음: 그 이름을 켜 둔 공유기가 서버 (이 서비스의 이름인데 아무도 등록하지 않으면 NXDOMAIN)
      const owner = ddnsOwner(t.devices, name);
      if (!owner && name.endsWith(`.${DDNS_ZONE_NAME}`)) {
        add({ deviceId: d.id, severity: "warn", code: "wg.name-unknown", message: `서버 이름 ${name} 을(를) DDNS 로 등록한 공유기가 없음 → 이름을 풀지 못해(NXDOMAIN) 연결 실패`, fix: `서버 공유기 → 인터넷 → DDNS 켜고 이름을 ${name.slice(0, -(DDNS_ZONE_NAME.length + 1))} 로, 또는 ${d.name} 의 서버 주소를 고치기` });
        continue;
      }
      found = owner && owner !== d ? { srv: owner, port: c.port } : undefined;
    }
    if (!found) continue;
    const { srv, via } = found;
    const s = srv.router?.wgServer;
    const where = via ? `${via.name} 가 UDP ${c.port} 을 포워딩하는 대상` : server;
    if (!s?.enabled) {
      add({ deviceId: d.id, severity: "warn", code: "wg.server-off", message: `${srv.name} (${where}) 에 WireGuard 서버가 꺼져 있음 → 핸드셰이크에 답이 없어 연결 실패`, fix: `${srv.name} → WireGuard 서버 켜기`, related: [srv.id] });
      continue;
    }
    if (s.port !== found.port) {
      add({ deviceId: d.id, severity: "error", code: "wg.port-mismatch", message: `${c.where} 가 ${srv.name} 의 UDP ${found.port} 로 보내지만 서버는 ${s.port} 을 들음 → 핸드셰이크가 닿지 않아 연결 실패`, fix: `${d.name} → ${c.where} → 서버 포트를 ${s.port} 로`, related: [srv.id] });
      continue;
    }
    if (c.serverKey.trim() !== wgPublicKeyOf(srv, "server")) {
      add({ deviceId: d.id, severity: "error", code: "wg.server-key", message: `${c.where} 에 적은 서버 공개 키가 ${srv.name} 의 공개 키와 다름 → 서버가 핸드셰이크를 읽지 못하고 아무 답도 하지 않음 (mac1 불일치, timeout)`, fix: `${d.name} → ${c.where} → 서버 공개 키를 ${srv.name} 의 WireGuard 서버 공개 키로`, related: [srv.id] });
      continue;
    }
    const myKey = wgPublicKeyOf(d, c.role);
    const peer = s.peers.find((p) => p.publicKey.trim() === myKey);
    if (!peer) {
      add({ deviceId: d.id, severity: "error", code: "wg.not-registered", message: `${srv.name} 의 WireGuard 서버 피어 목록에 이 장치의 공개 키가 없음 → 서버가 핸드셰이크에 답하지 않음 (모르는 키에는 침묵, timeout)`, fix: `${srv.name} → WireGuard 서버 → 피어 추가: ${d.name} 의 공개 키와 터널 주소`, related: [srv.id] });
      continue;
    }
    const pip = validIp(peer.ip.trim());
    if (me && pip && me.ip !== pip) {
      add({ deviceId: d.id, severity: "error", code: "wg.address-mismatch", message: `내 터널 주소 ${me.ip} 가 ${srv.name} 에 등록된 주소 ${pip} 와 다름 → 핸드셰이크는 되지만 서버가 데이터를 버림 (그 피어가 쓸 수 있는 출발지가 아님 — cryptokey routing)`, fix: `${d.name} → ${c.where} → 내 터널 주소를 ${pip} 로`, related: [srv.id] });
    }
  }
}
