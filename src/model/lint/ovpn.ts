// OpenVPN 규칙: 공유기 서버(터널 대역·포트)와 노트북 앱(설정 파일)이 가리키는 서버의 켜짐·전송·CA·인증서·폐기·tls-crypt·계정.
// 인증서가 틀리면 로그에 VERIFY ERROR 가 남지만, tls-crypt 키가 틀리면 서버가 침묵해 timeout 만 보인다 — 그래서 구성 검사가 짚어 준다
import { DDNS_ZONE_NAME, ovpnCaOfDevice, ovpnTlsCryptOfDevice, type Device } from "../topology";
import { fmtSubnet, overlaps, subnetOf, validIp } from "./addr";
import type { LintContext } from "./context";
import { ddnsOwner, followTarget, frontRouter, routerWanIp } from "./wg";

function cidr(text: string | undefined, dflt: number): { ip: string; prefix: number } | undefined {
  const m = /^\s*([0-9.]+)\s*(?:\/\s*(\d{1,2}))?\s*$/.exec(text ?? "");
  if (!m || !validIp(m[1])) return undefined;
  const prefix = m[2] === undefined ? dflt : Number(m[2]);
  return prefix >= 0 && prefix <= 32 ? { ip: m[1]!, prefix } : undefined;
}

const isServer = (proto: "udp" | "tcp") => (x: Device, port: number) => !!x.router?.ovpnServer?.enabled && x.router.ovpnServer.proto === proto && x.router.ovpnServer.port === port;

// 규칙 20e: OpenVPN
export function ovpnRules({ t, m, add }: LintContext): void {
  // 서버 쪽: 터널 대역, 같은 포트의 포트 포워딩
  for (const d of t.devices) {
    const s = d.router?.ovpnServer;
    if (!s?.enabled) continue;
    const net = cidr(s.subnet, 24);
    if (!net || net.prefix > 30) {
      add({ deviceId: d.id, severity: "error", code: "ovpn.subnet-invalid", message: `OpenVPN 터널 대역 "${s.subnet}" 을(를) 쓸 수 없음 → 클라이언트에게 줄 가상 주소가 없어 PUSH 단계에서 멈춤`, fix: `${d.name} → VPN → OpenVPN 서버 → 터널 대역 (예: 10.8.0.0/24)` });
    } else {
      const tunnel = subnetOf(net.ip, net.prefix)!;
      const lan = subnetOf(validIp(d.router!.lanIp), d.router!.lanPrefix);
      if (lan && overlaps(tunnel, lan))
        add({ deviceId: d.id, severity: "error", code: "ovpn.overlap", message: `OpenVPN 터널 대역 ${fmtSubnet(tunnel)} 이 LAN ${fmtSubnet(lan)} 과 겹침 → 같은 주소가 LAN 과 터널에 함께 생겨 응답이 엉뚱한 곳으로 감`, fix: `${d.name} → VPN → OpenVPN 서버 → 터널 대역을 LAN 과 다르게 (예: 10.8.0.0/24)` });
      const wg = cidr(d.router?.wgServer?.enabled ? d.router.wgServer.address : undefined, 24);
      const wgNet = wg ? subnetOf(wg.ip, wg.prefix) : undefined;
      if (wgNet && overlaps(tunnel, wgNet))
        add({ deviceId: d.id, severity: "error", code: "ovpn.overlap", message: `OpenVPN 터널 대역 ${fmtSubnet(tunnel)} 이 WireGuard 터널 대역 ${fmtSubnet(wgNet)} 과 겹침 → 그 주소로 가는 패킷이 어느 터널로 갈지 엇갈림`, fix: `${d.name} → VPN → OpenVPN 서버 → 터널 대역을 다르게` });
    }
    if (d.router?.forwards?.some((f) => (f.proto ?? "tcp") === s.proto && f.publicPort === s.port))
      add({ deviceId: d.id, severity: "warn", code: "ovpn.port-clash", message: `${s.proto.toUpperCase()} ${s.port} 포트 포워딩 규칙이 있지만 OpenVPN 서버가 그 포트를 먼저 받음 → 포워딩 대상에는 닿지 않음`, fix: `${d.name} → OpenVPN 서버 포트를 바꾸거나 그 포트 포워딩을 지우기` });
  }
  // 클라이언트 쪽
  const byServer = new Map<string, Device>();
  for (const d of t.devices) {
    const r = d.host?.ra;
    if (!r?.enabled || r.type !== "openvpn") continue;
    const o = r.ovpn;
    const where = "VPN (OpenVPN)";
    if (!o || !r.server.trim() || !o.ca.trim() || !o.cn.trim()) {
      add({ deviceId: d.id, severity: "error", code: "ovpn.incomplete", message: `${where} 설정 파일이 비어 있음 (${!r.server.trim() ? "서버 주소" : !o?.ca.trim() ? "CA" : "내 인증서"}) → 연결하지 않음`, fix: `${d.name} → ${where} → "공유기에서 설정 파일 가져오기"` });
      continue;
    }
    const server = validIp(r.server.trim());
    const name = server ? undefined : r.server.trim().toLowerCase().replace(/\.$/, "");
    let found: ReturnType<typeof followTarget>;
    if (server) found = followTarget(t.devices, d, t.devices.find((x) => x !== d && routerWanIp(x) === server), o.port, o.proto, isServer(o.proto));
    else if (name) {
      const owner = ddnsOwner(t.devices, name);
      if (!owner && name.endsWith(`.${DDNS_ZONE_NAME}`)) {
        add({ deviceId: d.id, severity: "warn", code: "ovpn.name-unknown", message: `서버 이름 ${name} 을(를) DDNS 로 등록한 공유기가 없음 → 이름을 풀지 못해(NXDOMAIN) 연결 실패`, fix: `서버 공유기 → 인터넷 → DDNS 켜기, 또는 ${d.name} 의 서버 주소를 고치기` });
        continue;
      }
      found = owner && owner !== d ? followTarget(t.devices, d, owner, o.port, o.proto, isServer(o.proto)) : undefined;
      const front = owner ? frontRouter(m, owner) : undefined;
      if (found && owner && front && !front.router?.forwards?.some((f) => (f.proto ?? "tcp") === o.proto && f.publicPort === o.port)) {
        add({ deviceId: d.id, severity: "warn", code: "ovpn.server-behind-nat", message: `${owner.name} 는 ${front.name} 뒤에 있어 ${name} 이(가) ${front.name} 의 공인 주소를 가리킴 → ${front.name} 에 ${o.proto.toUpperCase()} ${o.port} 포트 포워딩이 없어 닿지 않음`, fix: `${front.name} → 보안 → 포트 포워딩: ${o.proto.toUpperCase()} ${o.port} → ${owner.name} 의 WAN 주소`, related: [front.id, owner.id] });
        continue;
      }
    }
    if (!found) continue;
    const { srv, via } = found;
    const s = srv.router?.ovpnServer;
    const at = via ? `${via.name} 가 ${o.proto.toUpperCase()} ${o.port} 을 포워딩하는 대상` : (server ?? name);
    if (!s?.enabled) {
      add({ deviceId: d.id, severity: "warn", code: "ovpn.server-off", message: `${srv.name} (${at}) 에 OpenVPN 서버가 꺼져 있음 → 연결 실패`, fix: `${srv.name} → VPN → OpenVPN 서버 켜기`, related: [srv.id] });
      continue;
    }
    if (s.proto !== o.proto || s.port !== found.port) {
      add({ deviceId: d.id, severity: "error", code: "ovpn.proto-mismatch", message: `${where} 는 ${o.proto.toUpperCase()} ${found.port} 로 보내지만 ${srv.name} 의 서버는 ${s.proto.toUpperCase()} ${s.port} 에서 받음 → 응답 없음`, fix: `${d.name} → ${where} → 전송·포트를 ${s.proto.toUpperCase()} ${s.port} 로 (또는 설정 파일을 다시 가져오기)`, related: [srv.id] });
      continue;
    }
    const ca = ovpnCaOfDevice(srv);
    const tls = s.tlsCrypt ? ovpnTlsCryptOfDevice(srv) : "";
    if (o.tlsCrypt.trim() !== tls) {
      add({ deviceId: d.id, severity: "error", code: "ovpn.tls-crypt-mismatch", message: tls ? `${where} 의 tls-crypt 키가 ${srv.name} 의 것과 ${o.tlsCrypt.trim() ? "다름" : "없음"} → 서버가 패킷을 열지 못해 아무 답도 하지 않음 (timeout)` : `${srv.name} 는 tls-crypt 를 쓰지 않는데 ${where} 는 tls-crypt 키로 감쌈 → 서버가 읽지 못해 답이 없음`, fix: `${d.name} → ${where} → 설정 파일을 다시 가져오기`, related: [srv.id] });
      continue;
    }
    if (o.ca.trim() !== ca) {
      add({ deviceId: d.id, severity: "error", code: "ovpn.ca-mismatch", message: `${where} 의 CA 가 ${srv.name} 의 CA 와 다름 → 서버 인증서를 믿지 못해 연결을 끊음 (VERIFY ERROR)`, fix: `${d.name} → ${where} → 설정 파일을 다시 가져오기`, related: [srv.id] });
      continue;
    }
    if (o.certCa.trim() !== ca) {
      add({ deviceId: d.id, severity: "error", code: "ovpn.cert-foreign", message: `${where} 의 내 인증서는 ${srv.name} 의 CA 가 발급한 것이 아님 → 서버가 거절함`, fix: `${d.name} → ${where} → 설정 파일을 다시 가져오기 (새 인증서 발급)`, related: [srv.id] });
      continue;
    }
    if (s.revoked.includes(o.cn.trim())) {
      add({ deviceId: d.id, severity: "warn", code: "ovpn.revoked", message: `${where} 의 인증서 CN=${o.cn.trim()} 는 ${srv.name} 에서 폐기됨 (CRL) → 거절됨`, fix: `${srv.name} → OpenVPN 서버 → 폐기 해제, 또는 ${d.name} 에 새 이름으로 인증서 발급`, related: [srv.id] });
      continue;
    }
    const users = s.users.filter((u) => u.name.trim());
    if (users.length) {
      const u = users.find((x) => x.name.trim() === (r.user ?? "").trim());
      if (!r.user?.trim())
        add({ deviceId: d.id, severity: "error", code: "ovpn.no-account", message: `${srv.name} 의 OpenVPN 서버는 계정을 요구하는데 ${where} 에 계정이 없음 → AUTH_FAILED`, fix: `${d.name} → ${where} → 계정·비밀번호`, related: [srv.id] });
      else if (!u || u.password !== (r.password ?? ""))
        add({ deviceId: d.id, severity: "error", code: "ovpn.account-mismatch", message: `${where} 의 계정 ${r.user.trim()} 이(가) ${u ? "비밀번호가 다름" : `${srv.name} 의 목록에 없음`} → AUTH_FAILED`, fix: `${d.name} → ${where} → 계정·비밀번호를 ${srv.name} 의 것과 같게`, related: [srv.id] });
    }
    const key = `${srv.id}|${o.cn.trim()}`;
    const prev = byServer.get(key);
    if (prev) add({ deviceId: d.id, severity: "warn", code: "ovpn.duplicate-cn", message: `${prev.name} 와 같은 인증서(CN=${o.cn.trim()})로 ${srv.name} 에 붙음 → 나중에 붙은 쪽이 앞 기기를 밀어냄 (인증서는 기기마다 따로)`, fix: `${d.name} → ${where} → "공유기에서 설정 파일 가져오기" 로 이 기기 이름의 인증서를 받기`, related: [prev.id, srv.id] });
    else byServer.set(key, d);
  }
}
