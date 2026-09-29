// VPN 규칙: 사이트 간 VPN(WireGuard·IPsec)과 원격 접속 VPN.
import type { Device } from "../topology";
import { contains, fmtSubnet, ipInt, overlaps, subnetOf, validIp, type Subnet } from "./addr";
import type { LintContext } from "./context";

/** WireGuard 기본 포트 (코어 packet.ts 의 VPN_PORT 와 같은 값 — lint 는 코어에 의존하지 않는다) */
const VPN_PORT = 51820;
/** IPsec IKE 포트 (NAT 뒤 게이트웨이는 500·4500 을 포워딩해야 한다) */
const IKE_PORT = 500;

// 규칙 17: 사이트 간 VPN — 상대 주소 없음, 상대 대역이 우리 LAN 과 겹침, 두 사이트가 같은 상대에 연결, 상대가 VPN 을 안 켬(포워딩 너머까지 따라감), 상대 대역 목록에 우리 LAN 이 없음
export function siteVpnRules({ t, m, add }: LintContext): void {
  const vpnOf = (d: Device) => (d.l3?.vpn?.enabled ? d.l3.vpn : undefined);
  const publicIp = (d: Device) => {
    const c = d.l3?.interfaces[0];
    return c?.ipMode === "static" ? validIp(c.ip) : undefined;
  };
  const lanSubnets = (d: Device) => m.allGws.filter((g) => g.device === d && g.subnet && !g.uplink).map((g) => g.subnet!);
  const remotesOf = (v: NonNullable<ReturnType<typeof vpnOf>>) => v.remote.map((r) => subnetOf(validIp(r.dest), r.prefix)).filter((x): x is Subnet => !!x);
  for (const d of t.devices) {
    const v = vpnOf(d);
    if (!v) continue;
    const peer = validIp(v.peer);
    if (!peer) {
      add({ deviceId: d.id, severity: "warn", code: "vpn.no-peer", message: "VPN 을 켰지만 상대 공인 주소가 없음 → 터널로 보낼 곳이 없음", fix: `${d.name} → VPN → 상대 공인 주소에 상대 터널 장비의 공인(outside) 주소` });
      continue;
    }
    const mine = lanSubnets(d);
    const remotes = remotesOf(v);
    const clash = remotes.flatMap((r) => mine.filter((l) => overlaps(r, l)).map((l) => `${fmtSubnet(r)} ↔ ${fmtSubnet(l)}`));
    if (clash.length) {
      add({
        deviceId: d.id,
        severity: "error",
        code: "vpn.overlap",
        message: `VPN 상대 대역이 우리 LAN 과 겹침 (${clash.join(", ")}) → 같은 주소가 양쪽에 있어 어느 쪽으로 보낼지 구분할 수 없음`,
        fix: "한쪽 사무실의 사설 대역을 바꾸기 (예: 192.168.1.0/24 와 192.168.2.0/24)",
      });
    }
    // 이중화 짝(같은 그룹·같은 바깥 가상 주소)은 한 번에 한 대만 일하므로 같은 상대를 써도 된다
    const haPair = (x: Device) => {
      const a = d.l3?.ha;
      const b = x.l3?.ha;
      return !!a?.enabled && !!b?.enabled && a.vrid === b.vrid && !!validIp(a.vips[0]) && a.vips[0] === b.vips[0];
    };
    const shared = t.devices.filter((x) => x !== d && vpnOf(x) && validIp(vpnOf(x)!.peer) === peer && !haPair(x));
    if (shared.length) {
      add({
        deviceId: d.id,
        severity: "warn",
        code: "vpn.shared-peer",
        message: `${shared.map((x) => x.name).join(", ")} 도 같은 상대 ${peer} 로 VPN 을 연결함 → 상대는 터널 하나만 두므로 마지막에 보낸 쪽으로 답이 가서 서로의 응답을 빼앗음`,
        fix: "상대 하나에는 한 사이트만 연결하기 (여러 사이트를 잇는다면 사이트마다 상대 쪽 터널 장비를 따로 두기)",
        related: shared.map((x) => x.id),
      });
    }
    let peerDev = t.devices.find((x) => x !== d && x.l3 && publicIp(x) === peer);
    if (!peerDev) continue; // 상대가 이 토폴로지에 없거나 주소를 DHCP 로 받으면 판단하지 않는다
    // 상대 공인 주소가 VPN 을 안 켠 NAT 박스이고 UDP 51820 을 안쪽으로 포워딩하면, 그 안쪽 장비가 진짜 상대
    const tunnelPort = v.mode === "ipsec" ? IKE_PORT : VPN_PORT;
    const fwd = vpnOf(peerDev) ? undefined : peerDev.l3?.forwards?.find((f) => f.proto === "udp" && f.publicPort === tunnelPort);
    if (fwd) {
      const inner = t.devices.find((x) => x.l3 && x.l3.interfaces.some((i) => i.ipMode === "static" && validIp(i.ip) === validIp(fwd.lanIp)));
      // IPsec 상대가 NAT 뒤면 NAT 가 반드시 감지되어 IKE_AUTH·ESP 는 UDP 4500 으로 온다 → 4500 포워딩도 필요
      if (v.mode === "ipsec" && !peerDev.l3?.forwards?.some((f) => f.proto === "udp" && f.publicPort === 4500 && validIp(f.lanIp) === validIp(fwd.lanIp))) {
        add({
          deviceId: d.id,
          severity: "warn",
          code: "vpn.natt-closed",
          message: `상대 ${peerDev.name} 가 UDP 500 만 ${fwd.lanIp} 로 포워딩함 → NAT 뒤라 IKE_AUTH·ESP 가 UDP 4500 (NAT-T) 으로 가는데 그 포트가 막혀 터널이 맺어지지 않음`,
          fix: `${peerDev.name} → 포트 포워딩에 UDP 4500 → ${fwd.lanIp}:4500 추가`,
          related: [peerDev.id],
        });
      }
      if (!inner) continue;
      peerDev = inner;
    }
    const pv = vpnOf(peerDev);
    if (!pv) {
      add({ deviceId: d.id, severity: "warn", code: "vpn.peer-off", message: `상대 ${peerDev.name} (${peer}) 가 VPN 을 켜지 않음 → 터널 패킷을 풀지 못해 드롭`, fix: `${peerDev.name} → VPN 을 켜고 상대 주소·대역을 이쪽과 짝으로 설정`, related: [peerDev.id] });
      continue;
    }
    const modeName = (x: typeof v) => (x.mode === "ipsec" ? "IPsec" : "WireGuard");
    if ((pv.mode ?? "wireguard") !== (v.mode ?? "wireguard")) {
      add({
        deviceId: d.id,
        severity: "error",
        code: "vpn.mode-mismatch",
        message: `VPN 방식이 다름: 여기는 ${modeName(v)}, 상대 ${peerDev.name} 는 ${modeName(pv)} → 서로 알아듣지 못해 터널이 맺어지지 않음`,
        fix: "양쪽 VPN 방식을 같게 (기업 방화벽·클라우드 VPN 게이트웨이끼리는 보통 IPsec)",
        related: [peerDev.id],
      });
      continue;
    }
    if (v.mode === "ipsec" && !(v.psk ?? "") && !(pv.psk ?? "")) {
      add({ deviceId: d.id, severity: "warn", code: "vpn.psk-empty", message: `IPsec 사전 공유 키(PSK)가 양쪽 다 비어 있음 → 누구나 이 터널에 붙을 수 있음`, fix: `${d.name} 와 ${peerDev.name} 의 VPN → 사전 공유 키에 같은 긴 문자열`, related: [peerDev.id] });
    }
    if (v.mode === "ipsec" && (v.psk ?? "") !== (pv.psk ?? "")) {
      add({
        deviceId: d.id,
        severity: "error",
        code: "vpn.psk-mismatch",
        message: `IPsec 사전 공유 키(PSK)가 상대 ${peerDev.name} 와 다름 → IKE_AUTH 에서 AUTHENTICATION_FAILED 로 인증 실패`,
        fix: `${d.name} 와 ${peerDev.name} 의 VPN → 사전 공유 키를 똑같이`,
        related: [peerDev.id],
      });
    }
    const theirRemotes = remotesOf(pv);
    // 우리 쪽 대역 = 직접 연결된 LAN + 스태틱 라우팅으로 뒤에 둔 대역. 장비 사이 연결 구간(/30 등)도 섞여 있으므로
    // 상대가 그중 하나도 허용하지 않을 때만 지적한다 (일부만 터널에 태우는 것은 흔한 설계라 오탐이 된다)
    const site = [...mine, ...(d.l3?.routes ?? []).map((r) => subnetOf(validIp(r.dest), r.prefix)).filter((x): x is Subnet => !!x && x.prefix > 0)];
    const missing = site.some((l) => theirRemotes.some((r) => overlaps(r, l))) ? [] : site;
    if (missing.length) {
      add({
        deviceId: d.id,
        severity: "warn",
        code: "vpn.one-way",
        message: `상대 ${peerDev.name} 의 VPN 대역에 우리 LAN ${missing.map(fmtSubnet).join(", ")} 이 없음 → 이쪽에서 보낸 패킷을 상대가 받지 않고(허용 안 한 주소), 응답도 터널로 돌아오지 않음`,
        fix: `${peerDev.name} → VPN → 상대 쪽 사설 대역에 ${missing.map(fmtSubnet).join(", ")} 추가`,
        related: [peerDev.id],
      });
    }
  }
}

// 규칙 20: 원격 접속 VPN — 서버 대역·풀, 클라이언트가 가리키는 서버의 PSK·켜짐
export function remoteAccessRules({ t, m, add }: LintContext): void {
  const ownsIp = (x: Device, ip: string) => !!x.l3 && (x.l3.interfaces.some((c) => c.ipMode === "static" && validIp(c.ip) === ip) || (x.l3.ha?.enabled === true && x.l3.ha.vips.includes(ip)));
  for (const d of t.devices) {
    const ra = d.l3?.ra;
    if (!ra?.enabled) continue;
    if (ra.routes.length === 0) {
      add({ deviceId: d.id, severity: "warn", code: "ra.no-routes", message: "원격 접속 VPN 서버에 알려 줄 사내 대역이 없음 → 클라이언트가 붙어도 터널로 보낼 곳이 없음", fix: `${d.name} → 원격 접속 VPN 서버 → 사내 대역 추가 (예: 안쪽 LAN)` });
    }
    const a = validIp(ra.poolStart);
    const b = validIp(ra.poolEnd);
    if (!a || !b || ipInt(a)! > ipInt(b)!) {
      add({ deviceId: d.id, severity: "error", code: "ra.pool-invalid", message: `가상 주소 풀(${ra.poolStart || "?"} ~ ${ra.poolEnd || "?"})이 올바르지 않음 → 클라이언트에게 줄 주소가 없어 INTERNAL_ADDRESS_FAILURE`, fix: `${d.name} → 원격 접속 VPN 서버 → 풀 시작 ≤ 끝 인 주소 두 개 (예: 10.99.0.10 ~ 10.99.0.50)` });
      continue;
    }
    const lans = m.allGws.filter((g) => g.device === d && g.subnet).map((g) => g.subnet!);
    const pushed = ra.routes.map((r) => subnetOf(validIp(r.dest), r.prefix)).filter((x): x is Subnet => !!x);
    const siteRemote = d.l3!.vpn?.enabled ? d.l3!.vpn.remote.map((r) => subnetOf(validIp(r.dest), r.prefix)).filter((x): x is Subnet => !!x) : [];
    // 풀 범위 [a, b] 와 대역이 조금이라도 겹치는지 (양 끝이 대역 안이거나, 대역이 풀 안에 들어감)
    const overlapsPool = (n: Subnet) => contains(n, a) || contains(n, b) || (n.net >= ipInt(a)! && n.net <= ipInt(b)!);
    if ([...lans, ...pushed, ...siteRemote].some(overlapsPool)) {
      add({ deviceId: d.id, severity: "error", code: "ra.pool-overlap", message: `가상 주소 풀(${ra.poolStart} ~ ${ra.poolEnd})이 이미 쓰는 대역과 겹침 → 같은 주소가 양쪽에 생겨 응답이 엉뚱한 곳으로 감`, fix: `${d.name} → 원격 접속 VPN 서버 → 풀을 쓰지 않는 대역으로 (예: 10.99.0.10 ~ 10.99.0.50)` });
    }
  }
  for (const d of t.devices) {
    const c = d.host?.ra;
    if (!c?.enabled) continue;
    const server = validIp(c.server);
    if (!server) continue;
    // 이중화 쌍이면 가상 주소를 가진 장비가 둘 — 모두 봐야 넘어가도 접속된다
    const srvs = t.devices.filter((x) => x !== d && ownsIp(x, server));
    for (const srv of srvs) {
      if (!srv.l3?.ra?.enabled) {
        add({ deviceId: d.id, severity: "warn", code: "ra.server-off", message: `${srv.name} (${server}) 에 원격 접속 VPN 서버가 꺼져 있음 → IKE 에 답이 없어 접속 실패${srvs.length > 1 ? " (이중화 쌍이면 넘어갈 때)" : ""}`, fix: `${srv.name} → 원격 접속 VPN 서버 켜기`, related: [srv.id] });
      } else if (srv.l3.ra.psk !== c.psk) {
        add({ deviceId: d.id, severity: "error", code: "ra.psk-mismatch", message: `원격 접속 VPN 사전 공유 키(PSK)가 서버 ${srv.name} 와 다름 → 인증 실패 (AUTHENTICATION_FAILED)`, fix: `${d.name} 의 원격 접속 VPN → 사전 공유 키를 서버와 같게`, related: [srv.id] });
      }
    }
  }
}
