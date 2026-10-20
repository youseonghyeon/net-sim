# 리팩터링 조사 (2026-10-19)

다섯 영역(공유기 코어 · 호스트/TCP 앱 · L3·공용 부품 · 모델/동기화/구성 검사 · UI)을 따로 읽기 전용으로 조사한 결과를 합친 것. 코드는 고치지 않았다. "확인" 은 스크래치 테스트로 재현한 것, "추측" 은 코드만 읽은 것.

## 0. 공통 결론

- 반복 결함(LESSONS 4h·4k·4u·4zh·4zk·4zl·4zm)의 뿌리는 거의 모두 **"같은 결정을 여러 곳에서 각자 내린다"** 이다: 출구 회선·출발지 주소(공유기 12곳), 안쪽 목적지 분기(9곳), WAN1/WAN2 수신(두 벌), 주소를 잃을 때 알릴 곳(호스트 4곳·공유기 4곳, 목록이 서로 다름), 설정 반영(netSync 세 목록), 주소 파싱(validIp 4벌·parseCidr 3벌+), 화면 검증 vs 구성 검사.
- 그래서 가치가 큰 리팩터링은 "파일 쪼개기" 보다 **결정 지점을 하나로 모으는 인터페이스**(Egress·Ingress·HostService·VpnClient·설정 적용기·AddrIndex·validate)다. 파일 분할은 그 뒤에 거의 기계적으로 따라온다.
- 지금은 그 리팩터링을 받칠 **안전망이 부족**하다: 예제 전체 골든 트레이스 도구가 없고(4j 때 임시로만), ui-check 는 236번 출력하고 6번만 실패시킨다.

## 1. 조사 중 나온 결함

| 상태 | 내용 | 위치 |
|---|---|---|
| 고침 b4c33b8 | 고정 IP 를 바꾸거나 고정 → DHCP 로 바꾸면 SIP 가 다시 등록하지 않아 받는 전화가 실패 (주소를 잃을 때 알리는 곳마다 목록이 다름) | host.ts:603-620 |
| 고침 fc1827d | 잘못된 JSON(`dnsServer` 에 `records` 없음, `lb` 에 `backends` 없음, 방화벽 규칙에 `src` 없음)을 불러오면 parse 는 통과하고 동기화에서 TypeError — sim effect 에 예외 처리가 없어 반쯤 적용된 채 남음 | topology.ts:1527-1640, netSync.ts:409/442/459, sim.ts:33 |
| 고침 09a91d0 | 패킷 색: Tor·SIP·STUN·P2P·RTP·멀티캐스트·GoodCloud·L2TP·DHCPv6 가 모두 "DHCP" 색 (분류가 기본값으로 떨어짐) | packet.ts:1054-1222, Canvas.tsx:510 |
| 고침 1048671 | WireGuard 화면의 대역 검사가 `10.0.0.2/24/5` 를 통과시키지만 시뮬레이션은 그 값을 버림 | wg.tsx:26 vs netSync.ts:367 |
| 고침 1048671 | 호스트 DHCP 서비스 칸은 "시작 > 끝" 을 보지 않음 (구성 검사만 dhcp.range-invalid) | host.tsx:266 |
| 고침 1048671 | IPv4 프리픽스 칸 6곳이 24.5 같은 값을 그대로 저장 | ui.tsx:159 외 5곳 |
| 확인·고침 18859be | LAN 기기가 WireGuard 서버 터널 주소(10.0.0.1)로 연 TCP 만 관리 화면 처리를 거치지 않음 | router.ts:1371 |
| 아님 | 멀티 WAN 전환 때 Tor 회로·메시 재로그인을 하지 않음, OpenVPN 은 WAN1 주소 변경만 앎 — 확인 결과 Tor 는 가드의 DESTROY 로 회로를 새로 만들고, 메시는 주기 refresh(STUN)로 새 주소를 알려 이어짐 | router.ts:323-328, 558-573 |
| 확인·고침 cf8f67e | WAN2 를 쓰는 동안 공유기 자신의 이름 해석(WireGuard 서버 이름 다시 풀기)이 안 됨 (resolver 가 WAN1 에 묶임, WAN2 수신에 응답 분기 없음) | router.ts:518, 1629 |
| 확인·고침 77ba743 | IKE 재전송 타이머 핸들을 버려 협상이 끝난 뒤 조용해지면 시계가 +1000ms 점프 | ike.ts:72 |
| 확인·고침 b9fa4ef | ARP timeout 이 다른 인터페이스의 대기열을 지울 수 있음 (타이머 데이터에 인터페이스가 없음) | router.ts:2488-2513, l3.ts:1146 |
| 확인·고침 49564d2 | 원격 접속 클라이언트가 PSK 로 거절될 때 strongSwan 실무 줄이 안 나옴 (요약문 문자열 매칭에 안 걸림) | ravpn.ts:580, packetView.ts |
| 규칙대로 고침 c1b0c42 (실패 재현은 못 함) | 진단 탭 P2P 칸이 `simVersion` 을 읽지 않아 갱신되지 않을 수 있음 (4zi 와 같은 모양) | diag.tsx:369 |
| 추측 | WAN1·WAN2 수신 순서가 다름(mesh/ovpn), WAN2 에 L2TP·드롭인·서버 꺼짐 안내가 말없이 없음 | router.ts:1636 vs 2170 |
| 고침 057192c | (교란 표에서) OpenVPN 서버를 껐다 켜면 노트북이 한 번 다시 붙으려다 포기 — 실제는 connect-retry 로 계속 | openvpn.ts |
| 아님 | (교란 표에서) L2TP 서버를 껐다 켜면 스스로 다시 붙지 않음 — StopCCN 으로 "끊김 · 다시 연결" 을 알리고, 실제 OS 클라이언트도 자동 재시도 없음 | l2tp.ts |
| 고침 a028f50 | (경로 표에서) 드롭인 기기가 공유기 LAN 주소로 보낸 관리 화면·DNS·ping 을 "호스트끼리 직접 통신" 으로 드롭, DNS 답의 출발지가 물은 주소와 다름 | router.ts handleWanIp |
| 고침 8462f4c | 공유기 메시 주소로 물은 DNS 에 LAN 주소로 답함 (DNS 포워더 `answersAt` 목록에 메시만 빠짐) — 호스트 리졸버가 답의 출발지를 보지 않아 가려져 있었고, 리졸버도 실제처럼 물은 서버의 답만 받게 고침 | router.ts answersAt, dns.ts DnsResolver.handle |
| 고침 (설정 적용기) | 게이트웨이 칸 하나(헤어핀 등)를 바꾸면 켠 적 없는 "이중화 꺼짐 · 원격 접속 VPN 서버 꺼짐" 이 찍힘 — 처음 넣은 설정과 정리한 설정의 모양이 달라 꺼짐 → 꺼짐을 변경으로 봄 (`tests/config-noise.test.ts`) | ha.ts·ravpn.ts setConfig |
| 고침 f366199 | 답을 받아도 취소하지 않는 일반 timer 가 IKE 말고도 남아, 불러온 뒤 마지막 일보다 시계가 더 감 (rip·ha·p2p·ncpwg·iptime·wireguard·ddns·openvpn·tailscale·k3s·tor·sip — 0.01~5초). 동작은 같고 시각만 밀림 — 4단계 "타이머 라우터" 에서 함께 | 각 모듈 |

## 2. 안전망 (리팩터링 전에)

1. **예제 전체 골든 트레이스 하네스** — 예제마다 고정 동작(ping·ssh 등)을 돌려 `nodeId:kind` 시퀀스와 실무 출력(practitionerLines)을 저장하고 비교. 의도된 차이는 건별로 승인. 세 조사가 모두 첫 단계로 꼽음. (S~M)
2. **ui-check 단언** — `expect(label, cond)` 로 어긋남을 모아 구간 끝에 실패, 섹션은 정확 일치로 찾기. 지금 기다림 37개가 실패 문구도 받아들인다. (S)
3. **설정 반영 불변식 테스트** — "처음부터 불러온 노드" 와 "기본 장치로 만든 뒤 설정을 바꾼 노드" 의 설정 스냅샷이 같아야 한다. 예제 42종에서 약 1초, 지금 통과(4zl 같은 결함을 그 자리에서 잡음). (S)
4. **공유기 경로 커버리지 표 테스트** — 들어오는 길 {LAN, 드롭인, WAN1, WAN2, WireGuard, OpenVPN, 메시, L2TP, IPv6} × 기능 {DPI, 방화벽, 기기 차단, 킬 스위치, 관리 화면, DNS 답, Unreachable}. AGENTS 점검 항목 "새 들어오는 길" 을 기억 대신 테스트로. (S)
5. **VPN 협상 적합성 테스트** — 프로토콜마다 {setup, start, isUp, failReason} 를 등록하면 마지막 메시지 손실·한쪽 리셋·동시 시작·끈 뒤 늦은 패킷·주소 변경·HA 물러남을 자동으로. 4u 점검 항목을 테스트로. (S~M)

## 3. 구조 개선 (가치 순)

### 공유기 (router.ts 2637줄)
- **WanLine** — wan/wan2·wanClient/wan2Client·nat/nat2·wanMode·wanLinkUp 병렬 필드와 거의 같은 수동/DHCP 전환·링크 처리 두 벌을 `class WanLine { iface; client; nat; mode; linkUp; setAddressing(); onLink() }` 로. 기계적. (S~M)
- **RouteTable + Egress** — 출구 판단 12곳(out·outFor·mainRoute·sendMain·mainSource·stickySource + 송신 클로저 9개)을 `resolveEgress(dst, {src, local, flow, own})` → `{kind, line, src, nextHop, nat}` 하나로. "지금 회선의 내 주소" 식이 지금 세 벌이고 서로 다르다(4zk). 공유기 자신이 만든 것과 지나가는 것을 타입으로 구분. 이후 NetInterface 의 `outbound`·`nextHop` 훅 제거. (M~L)
- **수신 파이프라인 하나** — `WanListener { lines; claim() }` 의 순서 있는 목록으로 WAN1·WAN2 수신을 한 함수에. "WAN1 만" 은 `lines` 로 드러난다. (M)
- **안쪽 분기·자신 처리 하나** — `classifyInside(dst)`(자신/터널 피어/L2TP/LAN/드롭인) + `deliverInside()`(TTL·통지 한 번) + `LocalServices.deliver()`(자신에게 온 것 6벌). 그 뒤 `lan.outbound` 의 숨은 터널 우회 제거. (M)
- **TunnelService 인터페이스** — WireGuard·OpenVPN·메시·L2TP 서버를 `{ lines; claims; open; owns; inSubnet; sendTo; policy; onAddress(필수) }` 로. 주소 변경 알림 누락을 컴파일러가 잡는다. (M) — **함** (`nodes/tunnelsvc.ts` `{label; via; address; owns; send; noPeer; access; onAddress}`, WireGuard 서버·OpenVPN·메시). L2TP 는 넣지 않음: 붙은 기기에게 LAN 대역 주소를 주고 프록시 ARP 로 LAN 기기처럼 다루는 다른 모델이고, 트레이스 문구도 다르다. WAN 수신(`claims`)도 넣지 않음: WireGuard 포트 처리가 서버·클라이언트·"꺼짐" 안내를 함께 한다.
- **변경 알림 하나** — 회선·주소가 바뀌는 모든 지점에서 `EgressListener` 목록에 한 함수로. (S)
- **설정 적용 한 경로** — 생성자(일부 필드)·netSync 생성 직후 setter 13개·configure(27단계)를 "신원만 생성 → configure(initial)" 로, 단계 명시(주소 → 테이블 → 서비스 → 터널). (M) — **함**: netSync 의 생성 직후 setter 목록을 `configure` 한 번으로, `configure` 를 네 단계로(뒤 단계가 앞 단계의 결과를 본다 — 터널·DDNS 는 새 WAN 주소, AdGuard 는 DNS 포워더, 메시는 포트 포워딩). 생성자는 "부팅 때 설정(로그 없이)" 으로 남김: 신원만 만들고 configure 로 다 넣으면 불러오기마다 "LAN 주소 변경·DHCP 켜짐" 같은 변경 로그가 생겨 사실과 다르다. 골든 차이는 세 예제에서 "WireGuard 서버 설정" 한 줄의 순서뿐
- **파일 분할** (위가 끝나면 기계적) — RouterBridge·Router6·VpnHub·RouterServices·Forwarder, 하위 모듈은 좁은 `RouterCore` 에만 의존. 타이머 등록 방식·snapshot 기여 방식 함께. (L, 행동 위험 낮음) — **함** (router.ts 2,550 → 1,614줄): `routercfg`(설정 타입·포트 번호)·`routersip`·`router6`·`routerwgc`(WireGuard 클라이언트)·`routerroute`(경로 판단)·`routerbridge`(내부 스위치)·`routersnap`. 모듈마다 자기 Host 인터페이스(l3tunnel 과 같은 방식 — 공통 `RouterCore` 하나보다 좁다). 남은 router.ts 는 수신 분기·포워딩·드롭인·헤어핀·L2TP/터널 라우팅·timer·configure. 골든 불변. 함께 고침: ui-check `ha-advert` 의 시계 값은 화면을 읽는 순간에 따라 0~3ms 흔들려(이번 변경과 무관, HA 예제엔 공유기 없음) 끝자리를 ⟨*⟩ 로

### 호스트·TCP (host.ts 1962줄, tcp.ts 1050줄)
- **HostService + 주소 수명주기** — `onAddressUp / onAddressLost / onLinkDown` 을 등록된 서비스 전부에 한 함수로 (위 SIP 결함 수정). (S~M)
- **타입 있는 타이머 라우팅** — `onTimer` case 25개, `data as` 43개, 지난 클라이언트 타이머 거르는 방식 세 가지 → `timerKey<T>()` + `TimerRouter.on()`, 모르는 태그는 테스트에서 예외. (S~M) — **보류**: 지난 timer 는 핸들 취소로 고쳤고(f366199, `tests/timers-idle.test.ts` 가 예제마다 고정), VPN 클라이언트 timer 는 `VpnClient.timer` 가, 진단 timer 는 `HostDiagnostics.timer` 가 맡아 호스트 switch 에 남은 `data as` 는 몇 곳뿐 — 등록식으로 바꾸는 이득이 작다
- **VpnClient 인터페이스** — `RaClient | L2tpClient | WgClient | OvpnClient` instanceof 분기 9곳+UI 2곳, 빈 메서드 흉내, 늦은 패킷 목록 손 나열 → `{ claim; intercept; connect; lost; reconnect; dpd?; timers; retire() }`. (M) — **함** (`nodes/vpnclient.ts` `{kind; label; receive; timer; vpnDns; lateTcp; …}`, 호스트의 instanceof 9곳·UI 2곳 → 0, 빈 메서드 흉내(handleIke·unwrap·onDpdTick) 제거, IPsec 둘의 받기는 `receiveIpsec` 공용). `Host.ra` 타입은 네 클래스의 합집합으로 둠(테스트가 종류별 필드를 본다). 골든·교란 표 불변. 달라진 것 하나: WireGuard·OpenVPN 클라이언트가 켜진 채 ESP 를 받으면(IKEv2 에서 종류를 바꾼 뒤 늦게 온 것) "내 원격 접속 터널 것이 아님" 대신 "지금 VPN 연결의 것이 아님 (끊었거나 종류를 바꾼 뒤 늦게 온 패킷)" 으로 무시 — 그 상황을 맞게 말한다
- **루프백을 비동기로 (`ctx.defer`)** — 4h·4k 의 재진입 결함(루프백 수정 커밋 5건)과 `onCreated`·"상태 먼저" 코드 7곳의 근본 원인. 같은 시각, 현재 이벤트 직후 처리(리눅스 netif_rx 백로그). 루프백 테스트 약 22개의 트레이스 순서가 바뀜. (M) — **함**: `ctx.defer` 를 새로 두지 않고 0ms 일반 timer(`LOOPBACK_TAG`)로 — 같은 시각, 이미 줄 선 일 다음. `onCreated`(lb·proxy·sshjump 5곳)를 없애고 connect 가 돌려준 연결을 바로 기록. 예상과 달리 바뀐 테스트는 1개(프록시가 자기 웹 서버를 대상으로 할 때 "받아 오는 대로 보냄" ACK 가 이제 응답보다 먼저 나간다 — 원격 뒤 서버와 같은 순서, 테스트를 "응답 뒤에 또 보내지 않는다" 는 원래 의도대로 순서 단언으로), 골든 불변
- **TCP 연결 소유자** — onFinish·onEstablished·onRelay 고리 순서가 서로 다름(실제 순서 결함 커밋 있음) → `connect(..., {owner})`·`listen(port, owner)`. 이어서 프록시 터널·SSH 점프 채널의 같은 짝 관리 코드를 `TcpSplice` 로. (M, S) — **TcpSplice 함** (`nodes/tcpsplice.ts`: 짝 등록·반대편·FIN 전달·끝나면 반대편 닫기(실패면 RST)·둘 다 끝나면 정리, 골든 불변). **소유자는 보류**: 앱마다 자기 맵(LB pending·checking, 프록시 pending·tunnels, 점프 pending·channels)으로 연결을 알아보고 맵이 서로 겹치지 않아, 훅마다 묻는 순서가 달라도 결과가 같다 — 바꾸면 훅 체인만 옮겨 적는 셈
- **진단 분리·IPv4/IPv6 쌍 통합** — ping·traceroute 등 약 480줄을 `HostDiagnostics` + `AddressFamily` 어댑터로. (M) — **분리만 함** (`nodes/hostdiag.ts` `HostDiagnostics`: ping·반복 ping 통계·traceroute·nslookup 과 Echo 응답·Time Exceeded·Unreachable·ARP/NDP timeout·제 timer 처리, host.ts 1,972 → 1,332줄, 골든 불변). IPv4/IPv6 쌍 합치기(sendPing/sendPing6·startTrace/startTrace6)는 하지 않음: 두 쪽의 확인 순서·실패 문구가 달라(게이트웨이 없음 vs IPv6 출발지 없음·RA) 하나로 접으면 문구가 바뀐다
- 장기: TcpConn 의 앱 필드 16개를 `TcpApp` 전략(SSH·TLS·HTTP·CONNECT)으로. (L)

### L3·공용 부품
- **packet 표를 타입으로** — `describeFrame`·`shortLabel`·`frameCategory` if 사슬을 `{ [K in kind]: { describe; short; category } }` 로, 빠지면 컴파일 오류 (위 색 결함 수정). packet.ts 를 프로토콜별 파일로 + barrel. (S~M)
- **인터넷 노드 서비스 레지스트리** — "사설 출발지 드롭" 7벌, 손 목록 `simulatedPublicIps`, UDP 서비스가 TTL 을 안 봄, DNS 로직이 onTimer 안 → `InternetService { addrs; udp?; tcp?; timers?; rows? }`, 서버 목록·알려진 서버는 자동. (M)
- **Router·L3Node 공용 부품만** — 합치지 않고 RouteTable(최장 일치·넥스트 홉 검증), ttlExpire·echoReply, 헤어핀, `NatTable.forwardFor()` 만 공유. 10개 개념이 겹친다. (S~M)
- **이웃 대기열 공용화** — ARP·NDP 대기열·타이머를 `NeighborQueue<P>` 하나로, 타이머 데이터에 인터페이스 식별자. L2 훅(proxyArp·arpSource·vip)은 `ArpPolicy` 객체 하나로. (M)
- **협상 공용 부품** — `Retransmitter`(취소 가능)·`ReplyCache`·`LateSink`. 상태머신은 합치지 않는다. (M)

### 모델·동기화·구성 검사
- **설정 적용기 맵** — 장치마다 effective 객체 하나에서 변경 감지 키와 적용을 함께: `Appliers<C, N> = { [K in keyof Required<C>]: (n, v, ctx) => void }` 로 필드를 빠뜨리면 컴파일 오류. (M) — 불변식 테스트(2-3)와 짝. — **함**: 호스트 서비스 11칸은 `HOST_SERVICES`(칸마다 정리한 값 `of` + 적용 `apply` — 변경 감지 키도 같은 목록에서, 4zl 같은 키 누락이 구조적으로 불가), 게이트웨이는 `Appliers<L3Node, L3Config>`(칸이 빠지면 컴파일 오류). 공유기·호스트·게이트웨이 모두 만든 직후에도 같은 목록 전체를 적용(개별 setter 5줄 제거) — 골든 불변
- **불러오기 정리 조합기** — `bool/port/text/list/obj` 로 설정 종류마다 완전한 값을 돌려주는 정리, 기본값도 같은 정의에서. 엉뚱한 입력으로 parse → sync → lint 예외 없음 테스트 (위 JSON 결함 수정). (M)
- **파싱 한 모듈 `model/parse.ts`** — ip4·ip6·cidr4·cidrList·port·intIn·hostname, UI 오류 문구도 같은 파서에서. 포트 범위 검사 약 35곳. (S)
- **구성 검사 AddrIndex** — `owners(ip)`·`publicTarget(ip, port, proto)`(공유기·게이트웨이 포워딩·포트 공개를 같은 방식으로)·`isLeased(key)`. routerWanIp 두 벌, 포워딩 따라가기 두 벌, 섞인 체인에서 침묵하는 문제 해소. 예제 공인 주소 범용 테스트도 여기서. (M) — **중복만 정리**: `lint/reach.ts`(공유기 수동 WAN 주소·포트 포워딩 따라가기·DDNS 주인·앞 공유기)로 모으고 L2TP 규칙의 따로 쓴 따라가기 루프·`routerWanIp` 두 번째 벌을 없앰(검사 결과 불변). **보류**: 게이트웨이(L3)의 포트 포워딩·포트 공개까지 같은 따라가기로 넓히는 것 — 지금 침묵하는 섞인 체인에서 새 경고가 생기는 동작 변화라 오탐 여부를 예제별로 따로 봐야 한다
- **packetView 의 타입 있는 details** — 요약문 문자열 매칭 약 20곳, `detail()` 131곳 → 화면이 읽는 약 30개 종류만 `DetailsOf<K>` + reason 코드, 포맷터를 프로토콜별 레지스트리로. (M) — **사유 코드만 함**: 한국어 문구 매칭 22곳(원격 접속·사이트 간 IPsec·L2TP·WireGuard·OpenVPN·메시·SSH·TLS·AdGuard)을 내보내는 쪽 details 의 `cause`·`side`·`step`·`ike`·`direct`·`op` 와 값(`why`·`self`·`path`·`endpoint`)으로, `tests/packetview-guard.test.ts` 가 다시 생기지 않게 막음(허용: "OpenVPN 서버"·"VPN 서버" 이름표 접두어 두 곳, 영어 프로토콜 토큰 매칭은 남김). 골든 불변. 덤으로 OpenVPN 서버 이름 풀기 실패의 사유에 "응답 없음" 이 들어 있으면 "TLS key negotiation failed" 를 잘못 붙이던 가능성이 없어짐. `DetailsOf<K>` 타입·포맷터 레지스트리는 보류 (300개 종류의 타입화는 조사 문서 4절의 "하지 않는 것")
- **topology.ts 분할** — specs·기능별 settings(타입·기본값·정리 한곳)·file·geometry·cables·wireless, topology.ts 는 다시 내보내기만. (S~M) — **함** (`model/topo/` 7개, settings 의 정리 함수는 `normalizeTopology` 가 쓰므로 export, 기존 import 그대로)
- **store·sim** — 동기화 예외 처리(알림 + 다시 만들기), 임대 재계산은 DHCP 트레이스가 있을 때만. (S)

### UI
- **validate 공용 모듈** — UI `Field error=`·구성 검사·effective* 가 같은 함수 (`staticRouteProblem` 이 선례). 파싱 모듈과 같이. (M)
- **`<IntInput>`** — 숫자 칸 16곳 통일 (프리픽스 24.5 결함). (S)
- **`useSub(d, key)` 설정 훅** — 패치 클로저 55개, 보일 때와 고칠 때 기본값이 다른 곳 4곳(꺼진 상태에서 칸을 고치면 기능이 켜지는 잠재 결함). (S~M)
- **simView 선택자** — UI 의 `sim.node()` 16파일·instanceof 약 43회, "이 IP 는 누구" 조회 5벌, 상태 점 색 두 규칙 → 순수 함수 + `useSim(f)`(안에서 simVersion 을 읽어 4zi 를 구조로 막음). (M)
- **`<ListEditor>`** — 목록 편집기 19벌(계정 3벌·대역 경로 5벌), 줄 오류 클래스 5종. ui-check 선택자와 같이. (M)
- **Canvas 분리** — 팬·드래그마다 모든 장치 다시 그림, 상태 O(n²) → ViewportGroup·memo·공유 computed, 파일을 interaction·DeviceView·packets·geometry 로. 이득은 측정 먼저(perf-check 에 팬·드래그 시나리오). (M~L)
- ui-check 를 helpers + sections 파일로. (S)

## 4. 하지 않는 것이 나은 것
- Router 와 L3Node 를 한 클래스·공통 베이스로 합치기 (모델이 다르고 트레이스 문구가 전부 바뀜)
- IKEv2·L2TP·WireGuard·OpenVPN 상태머신을 한 프레임워크로 (부품과 적합성 테스트로 충분)
- 범용 이벤트 버스·패킷 플러그인 (프레임마다 도는 코드, 순서 있는 고정 목록이면 충분)
- `Device` 를 판별 유니온으로, TraceKind 300개 전부에 타입, 외부 스키마 라이브러리
- styles.css 파일 분할 (토큰을 잘 지키고 있음, 충돌은 이름 문제), ToggleRow 같은 겉모양 정리
- 조립된 모듈 내부(wg·openvpn·l2tp·tailscale·tor·ddns·mwan·ha·stp·igmp·nat·firewall) — 이미 응집돼 있고 IO 가 좁다

## 5. 권장 순서
1. 안전망: 골든 트레이스 하네스 → ui-check 단언 → 설정 불변식 테스트 → 경로 커버리지 표 → 협상 적합성 (모두 행동 변화 없음)
2. 확인된 결함 수정 + 그 자리의 구조: HostService(SIP), 정리 조합기(JSON), packet 표(색), parse/validate·IntInput(화면 검증)
3. 공유기: WanLine → Egress → 수신 파이프라인 → 안쪽 분기·LocalServices → TunnelService → 변경 알림 → 설정 한 경로 → 파일 분할
4. 호스트: 타이머 라우터 → VpnClient → 비동기 루프백 → TCP 소유자·TcpSplice → 진단 분리
5. 모델: 설정 적용기 맵 + topology 분할 → AddrIndex → packetView details
6. UI: useSub → simView → ListEditor → (측정 후) Canvas
7. 공용 부품: 인터넷 레지스트리, NeighborQueue/ArpPolicy, 협상 부품

각 단계는 골든 차이를 건별로 검토하고, 의도된 차이만 승인한다.
