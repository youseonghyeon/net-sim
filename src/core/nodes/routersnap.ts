// 공유기의 인스펙터 스냅샷: 개요 줄(회선·서비스·VPN 상태)과 표(DHCP 임대·NAT·멀티 WAN·VPN 피어·MAC·ARP·IPv6)
import { APPS } from "./dpi";
import { DHCP_STATE_LABEL } from "./dhcp";
import { DHCP6_STATE_LABEL } from "./dhcp6";
import { WAN_LABEL } from "./mwan";
import { NAT_TYPE_LABEL } from "./nat";
import type { NodeSnapshot } from "./node";
import { shortFp } from "./openvpn";
import { routerPortName } from "./routercfg";
import type { Router } from "./router";
import { shortKey } from "./wg";

export function routerSnapshot(r: Router): NodeSnapshot {
  const wanState = r.wan.ip
    ? `${r.wan.ip}/${r.wan.prefix}`
    : !r.w1.linkUp
      ? "없음 (링크 다운)"
      : r.w1.mode === "dhcp"
        ? `없음 (DHCP: ${DHCP_STATE_LABEL[r.w1.client.state]})`
        : "없음 (수동 입력 필요)";
  return {
    id: r.id,
    type: r.type,
    label: r.id,
    info: [
      ["LAN IP", `${r.lan.ip}/${r.lan.prefix}`],
      ["LAN MAC", r.lan.mac],
      ["WAN IP", wanState],
      ["WAN 게이트웨이", r.wan.gateway ?? "없음"],
      ["DHCP 서비스", r.dhcp.enabled ? `켜짐 · ${r.dhcp.start} ~ ${r.dhcp.end}` : "꺼짐"],
      ["DNS 포워더", r.dnsForwarder.config.enabled ? `켜짐 · 업스트림 ${r.dnsForwarder.config.upstream ?? "없음"}` : "꺼짐"],
      ["무선", r.wifi.enabled ? `켜짐 · SSID ${r.wifi.ssid}` : "꺼짐"],
      ["방화벽", r.firewall.config.enabled ? `켜짐 · 규칙 ${r.firewall.config.rules.length}개 · 기본 ${r.firewall.config.defaultPolicy === "allow" ? "허용" : "차단"}` : "꺼짐"],
      ["NAT", `${NAT_TYPE_LABEL[r.w1.nat.type]}${r.hairpin ? " · 헤어핀 NAT 켜짐" : ""}`],
      ...(r.ipv6Enabled
        ? ([
            ["WAN IPv6", r.wan6.summary() || "없음"],
            ["IPv6 기본 게이트웨이", r.wan6.defaultRouter ? `${r.wan6.defaultRouter} (ISP 의 RA)` : "없음"],
            ["프리픽스 위임", r.pd.delegated ? `${r.pd.delegated.prefix}/${r.pd.delegated.length} (DHCPv6-PD)` : DHCP6_STATE_LABEL[r.pd.state]],
            ["LAN IPv6", r.lan6.addrs.some((a) => a.origin === "manual") ? `${r.lan6.summary()} · RA 로 알림` : "없음 (위임 대기)"],
            ["IPv6 인바운드 기본 차단", r.inbound6.config.enabled ? "켜짐 (Stateful — 안에서 시작한 통신의 응답만)" : "꺼짐 (바깥에서 바로 들어옴)"],
          ] as [string, string][])
        : []),
      ...(r.vpnServer.config.enabled
        ? ([["VPN 서버", `켜짐 (L2TP/IPsec) · 할당 IP ${r.vpnServer.config.poolStart} ~ ${r.vpnServer.config.poolEnd} · ${r.vpnServer.clientsLabel()}`]] as [string, string][])
        : []),
      ...(r.mesh.config.enabled ? ([[r.mesh.brand, r.mesh.summary()!]] as [string, string][]) : []),
      ...(r.admin.config.enabled ? ([["관리 화면", `HTTP 80·HTTPS 443${r.admin.config.ssh ? "·SSH 22" : ""} · ${r.admin.config.allow.length ? "허용 목록만" : "LAN"}${r.admin.config.remote ? " + WAN(원격)" : ""}`]] as [string, string][]) : []),
      ...(r.cloud.enabled ? ([["GoodCloud", r.cloud.summary()!]] as [string, string][]) : []),
      ...(r.tor.enabled ? ([["Tor", r.tor.summary()!]] as [string, string][]) : []),
      ...(r.admin.samba.enabled ? ([["네트워크 저장소", `SMB (TCP 445) · ${r.admin.samba.wan ? "LAN + WAN (위험)" : "LAN 만"}`]] as [string, string][]) : []),
      ...(r.dropIn ? ([["드롭인 게이트웨이", `켜짐 · WAN 쪽 LAN 기기의 게이트웨이 ${r.wan.ip ?? "?"}`]] as [string, string][]) : []),
      ...(r.blocked.size ? ([["기기 차단", [...r.blocked].join(", ")]] as [string, string][]) : []),
      ...(r.ovpn.enabled
        ? ([["OpenVPN 서버", `켜짐 · ${r.ovpn.config.proto.toUpperCase()} ${r.ovpn.config.port} · 터널 ${r.ovpn.config.subnet ? `${r.ovpn.config.subnet.ip}/${r.ovpn.config.subnet.prefix}` : "대역 없음"} · CA ${shortFp(r.ovpn.config.ca)}${r.ovpn.config.tlsCrypt ? " · tls-crypt" : ""} · ${r.ovpn.connected}개 연결`]] as [string, string][])
        : []),
      ...(r.wgServerCfg?.enabled
        ? ([["WireGuard 서버", `켜짐 · ${r.wgServerCfg.address ? `${r.wgServerCfg.address.ip}/${r.wgServerCfg.address.prefix}` : "터널 주소 없음"} · UDP ${r.wgServerCfg.listenPort} · 공개 키 ${shortKey(r.wgs.publicKey)} · 피어 ${r.wgServerCfg.peers.length}개 중 ${r.wgs.connected}개 연결`]] as [string, string][])
        : []),
      ...(r.wgClientCfg?.enabled ? ([["WireGuard 클라이언트", r.wgClientSummary()!]] as [string, string][]) : []),
      ...(r.ddns.config.enabled ? ([["DDNS", r.ddns.summary()!]] as [string, string][]) : []),
      ...(r.dpi.config.enabled ? ([["DPI", `켜짐${r.dpi.config.blockCategories.length + r.dpi.config.blockApps.length ? ` · 차단 ${[...r.dpi.config.blockCategories, ...r.dpi.config.blockApps.map((a) => APPS[a].label)].join(", ")}` : " · 세기만"}`]] as [string, string][]) : []),
      ...(r.adguard.config.enabled ? ([["AdGuard Home", `${r.adguard.summary()}${r.adguard.config.forceDns ? " · DNS 가로채기" : ""}`]] as [string, string][]) : []),
      ...(r.wan2On
        ? ([
            ["WAN2 (lan4)", r.wan2.ip ? `${r.wan2.ip}/${r.wan2.prefix}` : !r.w2.linkUp ? "없음 (링크 다운)" : r.w2.mode === "dhcp" ? `없음 (DHCP: ${DHCP_STATE_LABEL[r.w2.client.state]})` : "없음 (수동 입력 필요)"],
            ["멀티 WAN", `${WAN_LABEL[r.mwan.active]} 사용 중 · WAN1 ${r.mwan.lines.wan.online ? "살아 있음" : "끊김"} · WAN2 ${r.mwan.wan2Member ? (r.mwan.lines.wan2.online ? "살아 있음" : "끊김") : "디폴트 라우트로 안 씀"}${r.mwan.track ? ` · 추적 ${r.mwan.track}` : " · 추적 안 함"}`],
          ] as [string, string][])
        : []),
    ],
    tables: [
      { title: "DHCP 임대", columns: ["IP", "MAC", "시각"], rows: r.dhcpServer.rows() },
      ...(r.dnsForwarder.cache.size > 0 ? [{ title: "DNS 캐시", columns: ["이름", "IP", "출처"], rows: r.dnsForwarder.rows() }] : []),
      ...(r.dpi.config.enabled ? [{ title: "DPI 앱별 트래픽", columns: ["기기", "앱", "카테고리", "트래픽"], rows: r.dpi.rows() }] : []),
      ...(r.adguard.config.enabled ? [{ title: "AdGuard 쿼리 로그", columns: ["시각", "기기", "질의", "결과"], rows: r.adguard.rows() }] : []),
      { title: r.wan2On ? "NAT 테이블 (WAN1)" : "NAT 테이블", columns: ["내부", "→ 외부", "시각"], rows: r.w1.nat.rows(r.wan.ip) },
      ...(r.wan2On
        ? [
            { title: "NAT 테이블 (WAN2)", columns: ["내부", "→ 외부", "시각"], rows: r.w2.nat.rows(r.wan2.ip) },
            { title: "멀티 WAN (mwan3 status)", columns: ["회선", "상태", "사용", "추적"], rows: r.mwan.rows() },
            ...(r.mwan.rules.length ? [{ title: "멀티 WAN 정책 규칙 (mwan3 rules)", columns: ["#", "출발지", "회선", "지금", "새 연결"], rows: r.mwan.ruleRows() }] : []),
          ]
        : []),
      ...(r.rt.routes.length || r.wan2On ? [{ title: "라우팅 테이블 (main)", columns: ["네트워크", "대상", "IPv4 게이트웨이", "종류"], rows: r.rt.routeRows() }] : []),
      ...(r.vpnServer.config.enabled ? [{ title: "VPN 접속", columns: ["사용자", "할당 IP", "접속 주소", "방식"], rows: r.vpnServer.rows() }] : []),
      ...(r.wgServerCfg?.enabled ? [{ title: "WireGuard 서버 피어 (wg show)", columns: ["피어", "공개 키", "엔드포인트", "AllowedIPs", "최근 핸드셰이크", "전송"], rows: r.wgs.rows() }] : []),
      ...(r.igmp.enabled ? [{ title: "IGMP 스누핑 (그룹 → 포트)", columns: ["그룹", "VLAN", "포트"], rows: r.igmp.rows((p) => routerPortName(p)) }] : []),
      ...(r.admin.config.enabled || r.admin.samba.enabled ? [{ title: "관리 화면·저장소 연결", columns: ["연결", "상태", "보냄 / 받음"], rows: r.admin.rows() }] : []),
      ...(r.mesh.config.enabled ? [{ title: `${r.mesh.brand} 피어 (${r.mesh.config.net === "zerotier" ? "zerotier-cli peers" : "tailscale status"})`, columns: ["이름", "메시 주소", "경로", "알린 대역", "패킷"], rows: r.mesh.rows() }] : []),
      ...(r.ovpn.enabled ? [{ title: "OpenVPN 클라이언트 (status)", columns: ["인증서 CN", "실제 주소", "가상 주소", "계정", "상태"], rows: r.ovpn.rows() }] : []),
      ...(r.wgClientCfg?.enabled ? [{ title: "WireGuard 클라이언트 (wg show)", columns: ["피어", "공개 키", "엔드포인트", "AllowedIPs", "최근 핸드셰이크", "전송"], rows: r.wgc.rows() }] : []),
      ...(r.wgClientCfg?.enabled ? [{ title: "NAT 테이블 (VPN 터널)", columns: ["내부", "→ 터널 주소", "시각"], rows: r.wgClient.nat.rows(r.wgClientCfg.address?.ip) }] : []),
      { title: "포트 포워딩", columns: ["공인 포트", "내부"], rows: r.w1.nat.forwardRows(r.wan.ip) },
      ...(r.firewall.config.enabled ? [{ title: "방화벽 규칙", columns: ["#", "규칙"], rows: r.firewall.rows() }] : []),
      {
        title: "내부 스위치 MAC 테이블",
        columns: ["MAC", "포트", "학습 시각"],
        rows: [...r.macTable.entries()].map(([mac, e]) => [mac, routerPortName(e.port), `${e.learnedAt}ms`]),
      },
      { title: "ARP 캐시 (LAN)", columns: ["IP", "MAC", "학습 시각"], rows: r.lan.arpRows() },
      { title: "ARP 캐시 (WAN)", columns: ["IP", "MAC", "학습 시각"], rows: r.wan.arpRows() },
      ...(r.ipv6Enabled
        ? [
            { title: "IPv6 주소", columns: ["인터페이스", "주소", "상태"], rows: [...r.lan6.addrRows().map((r) => ["lan", r[0]!, `${r[1]} · ${r[2]}`]), ...r.wan6.addrRows().map((r) => ["wan", r[0]!, `${r[1]} · ${r[2]}`])] },
            { title: "이웃 캐시 (LAN)", columns: ["IPv6", "MAC", "학습 시각"], rows: r.lan6.neighborRows() },
            { title: "이웃 캐시 (WAN)", columns: ["IPv6", "MAC", "학습 시각"], rows: r.wan6.neighborRows() },
          ]
        : []),
    ],
  };}
