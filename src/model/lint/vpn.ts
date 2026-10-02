// VPN 규칙: 사이트 간 VPN(WireGuard·IPsec)과 원격 접속 VPN.
import { natOn, type Device } from "../topology";
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

// 규칙 20: 원격 접속 VPN — 서버 대역·풀, 클라이언트가 가리키는 서버의 PSK·켜짐·사용자 계정(EAP)
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
    if (c.type === "l2tp") {
      l2tpClientRules(d, server, t.devices, add);
      continue;
    }
    // IKEv2 클라이언트가 공유기 VPN 서버(L2TP/IPsec)를 가리킴 — 공유기가 UDP 500 을 안쪽으로 포워딩하면 IKEv2 는 그쪽이 받는다 (공유기는 L2TP 의 IKE 만 가로챔)
    const router = t.devices.find((x) => x !== d && routerWanIp(x) === server);
    if (router?.router?.vpnServer?.enabled && !udpForward(router, IKE_PORT)) {
      add({ deviceId: d.id, severity: "error", code: "ra.type-mismatch", message: `${router.name} 는 공유기 VPN 서버(L2TP/IPsec)인데 이 클라이언트는 IKEv2 로 접속 → 공유기가 IKEv2 에 답하지 않아 접속 실패`, fix: `${d.name} 의 VPN → 종류를 L2TP/IPsec 으로`, related: [router.id] });
      continue;
    }
    // 이중화 쌍이면 가상 주소를 가진 장비가 둘 — 모두 봐야 넘어가도 접속된다.
    // 서버가 NAT 뒤면: 공인 주소의 장비(엣지 NAT)가 원격 접속을 켜지 않고 UDP 500 을 안쪽으로 포워딩할 때 그 안쪽 장비가 진짜 서버
    // (사이트 간 규칙과 같게). 포워딩 대상이 이 토폴로지에 없으면 판단하지 않는다 (오탐 금지)
    /** 포워딩으로 찾은 서버 → 포워딩한 엣지 NAT */
    const via = new Map<Device, Device>();
    const srvs = t.devices
      .filter((x) => x !== d && ownsIp(x, server))
      .flatMap((x) => {
        const fwd = !natOn(x) || x.l3?.ra?.enabled ? undefined : x.l3?.forwards?.find((f) => f.proto === "udp" && f.publicPort === IKE_PORT);
        const lan = fwd ? validIp(fwd.lanIp) : undefined;
        if (!fwd) return [x];
        const inner = lan ? t.devices.filter((y) => y !== x && y !== d && ownsIp(y, lan)) : [];
        for (const y of inner) via.set(y, x);
        return inner;
      });
    for (const srv of srvs) {
      if (!srv.l3?.ra?.enabled) {
        const where = via.has(srv) ? `${via.get(srv)!.name} 가 ${server} 의 UDP ${IKE_PORT} 을 포워딩하는 대상` : server;
        add({ deviceId: d.id, severity: "warn", code: "ra.server-off", message: `${srv.name} (${where}) 에 원격 접속 VPN 서버가 꺼져 있음 → IKE 에 답이 없어 접속 실패${srvs.length > 1 ? " (이중화 쌍이면 넘어갈 때)" : ""}`, fix: `${srv.name} → 원격 접속 VPN 서버 켜기`, related: [srv.id] });
      } else if (srv.l3.ra.psk !== c.psk) {
        add({ deviceId: d.id, severity: "error", code: "ra.psk-mismatch", message: `원격 접속 VPN 사전 공유 키(PSK)가 서버 ${srv.name} 와 다름 → 인증 실패 (AUTHENTICATION_FAILED)`, fix: `${d.name} 의 원격 접속 VPN → 사전 공유 키를 서버와 같게`, related: [srv.id] });
      } else {
        // 계정 인증 (EAP): 서버에 계정이 있으면 클라이언트 계정이 그 목록에 같은 비밀번호로 있어야 한다 (코어처럼 이름은 앞뒤 공백을 떼고 본다)
        const users = (srv.l3.ra.users ?? []).filter((u) => u.name.trim() !== "");
        if (users.length === 0) continue;
        const name = c.user?.trim();
        const account = name ? users.find((u) => u.name.trim() === name) : undefined;
        if (!name) {
          add({ deviceId: d.id, severity: "error", code: "ra.no-account", message: `서버 ${srv.name} 가 사용자 계정 인증(EAP)을 요구하는데 이 클라이언트에 계정이 없음 → 접속 실패`, fix: `${d.name} 의 원격 접속 VPN → 사용자 이름·비밀번호 (서버 계정 목록에 있는 것)`, related: [srv.id] });
        } else if (!account || account.password !== (c.password ?? "")) {
          add({
            deviceId: d.id,
            severity: "error",
            code: "ra.account-mismatch",
            message: `${!account ? `사용자 ${name} 가 서버 ${srv.name} 의 계정 목록에 없음` : `사용자 ${name} 의 비밀번호가 서버 ${srv.name} 와 다름`} → 계정 인증 실패 (EAP 실패, AUTHENTICATION_FAILED)`,
            fix: !account ? `${srv.name} → 원격 접속 VPN 서버 → 사용자 계정에 ${name} 추가, 또는 ${d.name} 의 사용자 이름을 목록에 있는 것으로` : `${d.name} 의 원격 접속 VPN → 비밀번호를 서버 계정과 같게`,
            related: [srv.id],
          });
        }
      }
    }
  }
}

/** 공유기의 수동 WAN 주소 (자동이면 모름 — 판단하지 않는다) */
function routerWanIp(x: Device): string | undefined {
  return x.router?.wan?.ipMode === "static" ? validIp(x.router.wan.ip) : undefined;
}

/** 공유기의 UDP 포워딩 규칙 (그 공인 포트) */
function udpForward(x: Device, port: number) {
  return x.router?.forwards?.find((f) => f.proto === "udp" && f.publicPort === port);
}

// 규칙 20b: 공유기 VPN 서버 (L2TP/IPsec) — 할당 IP 범위, 계정
export function routerVpnRules({ t, m, add }: LintContext): void {
  for (const d of t.devices) {
    const v = d.router?.vpnServer;
    if (!v?.enabled) continue;
    const r = d.router!;
    const a = validIp(v.poolStart);
    const b = validIp(v.poolEnd);
    const lan = subnetOf(validIp(r.lanIp), r.lanPrefix);
    if (!a || !b || ipInt(a)! > ipInt(b)!) {
      add({ deviceId: d.id, severity: "error", code: "router.vpn-pool", message: `VPN 서버의 할당 IP 범위(${v.poolStart || "?"} ~ ${v.poolEnd || "?"})가 올바르지 않음 → 접속한 기기에게 줄 주소가 없어 실패 (IPCP Nak)`, fix: `${d.name} → VPN 서버 → 할당 IP 를 시작 ≤ 끝 인 LAN 주소 두 개로 (예: 192.168.0.50 ~ 192.168.0.59)` });
    } else if (lan && (!contains(lan, a) || !contains(lan, b))) {
      add({ deviceId: d.id, severity: "error", code: "router.vpn-pool", message: `VPN 서버의 할당 IP 범위(${v.poolStart} ~ ${v.poolEnd})가 LAN 대역 ${fmtSubnet(lan)} 밖 → 집 장치들이 LAN 기기로 보지 못해 그 주소는 주지 않음`, fix: `${d.name} → VPN 서버 → 할당 IP 를 LAN 대역 안에서 DHCP 범위 밖으로` });
    } else {
      const lanIp = validIp(r.lanIp);
      const da = validIp(r.dhcp.start);
      const db = validIp(r.dhcp.end);
      const inPool = (ip: string) => ipInt(ip)! >= ipInt(a)! && ipInt(ip)! <= ipInt(b)!;
      // 같은 LAN(케이블로 이어진 세그먼트)의 장치가 할당 IP 안의 주소를 고정으로 씀
      const lanKey = m.allGws.find((g) => g.device === d && g.gwKind === "router")?.key;
      const taken = (lanKey ? (m.membersOf(lanKey)?.addrs ?? []) : []).filter((x) => x.device !== d && inPool(x.ip));
      if (taken.length > 0) {
        add({ deviceId: d.id, severity: "warn", code: "router.vpn-pool", message: `VPN 서버의 할당 IP 범위(${v.poolStart} ~ ${v.poolEnd})의 ${taken.map((x) => `${x.ip}(${x.device.name})`).join(", ")} 를 LAN 장치가 고정으로 씀 → 그 주소를 받은 VPN 기기와 충돌 (집 장치의 패킷이 VPN 기기가 아니라 그 장치로 감)`, fix: `${d.name} → VPN 서버 → 할당 IP 를 쓰지 않는 주소로, 또는 그 장치의 주소를 바꾸기`, related: taken.map((x) => x.device.id) });
      }
      if (lanIp && inPool(lanIp)) {
        add({ deviceId: d.id, severity: "error", code: "router.vpn-pool", message: `VPN 서버의 할당 IP 범위(${v.poolStart} ~ ${v.poolEnd})에 공유기 자신의 LAN 주소 ${lanIp} 가 들어 있음 → 그 주소를 받은 기기와 공유기가 충돌`, fix: `${d.name} → VPN 서버 → 할당 IP 에서 ${lanIp} 를 빼기` });
      } else if (r.dhcp.enabled && da && db && ipInt(da)! <= ipInt(b)! && ipInt(a)! <= ipInt(db)!) {
        add({ deviceId: d.id, severity: "warn", code: "router.vpn-pool", message: `VPN 서버의 할당 IP 범위(${v.poolStart} ~ ${v.poolEnd})가 DHCP 범위(${r.dhcp.start} ~ ${r.dhcp.end})와 겹침 → 같은 주소가 VPN 기기와 LAN 기기에 함께 생길 수 있음`, fix: `${d.name} → VPN 서버 → 할당 IP 를 DHCP 범위 밖으로 (예: 192.168.0.50 ~ 192.168.0.59)` });
      }
    }
    if (v.users.filter((u) => u.name.trim() !== "").length === 0) {
      add({ deviceId: d.id, severity: "warn", code: "router.vpn-no-users", message: "VPN 서버에 계정이 없음 → 아무도 접속할 수 없음 (L2TP/IPsec 은 사전 공유 키 뒤에 계정 인증을 꼭 거친다)", fix: `${d.name} → VPN 서버 → 계정 추가` });
    }
  }
}

/** L2TP/IPsec 클라이언트가 가리키는 공유기: 켜짐·종류·사전 공유 키·계정 */
function l2tpClientRules(d: Device, server: string, devices: Device[], add: LintContext["add"]): void {
  const c = d.host!.ra!;
  const ikev2 = devices.find((x) => x !== d && x.l3?.ra?.enabled && x.l3.interfaces.some((i) => i.ipMode === "static" && validIp(i.ip) === server));
  if (ikev2) {
    add({ deviceId: d.id, severity: "error", code: "ra.type-mismatch", message: `${ikev2.name} 는 회사 원격 접속 VPN(IKEv2) 서버인데 이 클라이언트는 L2TP/IPsec 으로 접속 → 서버가 IKEv1 에 답하지 않아 접속 실패`, fix: `${d.name} 의 VPN → 종류를 IKEv2 로`, related: [ikev2.id] });
    return;
  }
  let srv = devices.find((x) => x !== d && routerWanIp(x) === server);
  // 공유기 뒤 공유기: 앞 공유기가 VPN 서버를 켜지 않고 UDP 500 을 안쪽으로 포워딩하면 그 대상(수동 WAN 주소의 공유기)이 서버. 대상을 모르면 침묵
  for (let hop = 0; srv && !srv.router?.vpnServer?.enabled && hop < 4; hop++) {
    const fwd = udpForward(srv, IKE_PORT);
    if (!fwd) break;
    const lan = validIp(fwd.lanIp);
    srv = lan ? devices.find((x) => x !== d && routerWanIp(x) === lan) : undefined;
  }
  if (!srv) return;
  const v = srv.router!.vpnServer;
  if (!v?.enabled) {
    add({ deviceId: d.id, severity: "warn", code: "ra.server-off", message: `${srv.name} (${server}) 에 VPN 서버(L2TP/IPsec)가 꺼져 있음 → IKE 에 답이 없어 접속 실패`, fix: `${srv.name} → VPN 서버 켜기`, related: [srv.id] });
    return;
  }
  if (v.psk !== c.psk) {
    add({ deviceId: d.id, severity: "error", code: "ra.psk-mismatch", message: `사전 공유 키가 ${srv.name} 의 VPN 서버와 다름 → IPsec 인증 실패 (AUTHENTICATION-FAILED)`, fix: `${d.name} 의 VPN → 사전 공유 키를 ${srv.name} 와 같게`, related: [srv.id] });
    return;
  }
  const users = v.users.filter((u) => u.name.trim() !== "");
  const name = c.user?.trim();
  const account = name ? users.find((u) => u.name.trim() === name) : undefined;
  if (!name) {
    add({ deviceId: d.id, severity: "error", code: "ra.no-account", message: `L2TP/IPsec 은 계정 인증(PPP CHAP)을 꼭 거치는데 이 클라이언트에 계정이 없음 → 접속 실패`, fix: `${d.name} 의 VPN → 사용자 이름·비밀번호 (${srv.name} VPN 서버의 계정)`, related: [srv.id] });
  } else if (!account || account.password !== (c.password ?? "")) {
    add({
      deviceId: d.id,
      severity: "error",
      code: "ra.account-mismatch",
      message: `${!account ? `계정 ${name} 가 ${srv.name} VPN 서버에 없음` : `계정 ${name} 의 비밀번호가 ${srv.name} VPN 서버와 다름`} → 계정 인증 실패 (CHAP Failure)`,
      fix: !account ? `${srv.name} → VPN 서버 → 계정에 ${name} 추가, 또는 ${d.name} 의 사용자 이름을 등록된 것으로` : `${d.name} 의 VPN → 비밀번호를 ${srv.name} 계정과 같게`,
      related: [srv.id],
    });
  }
}
