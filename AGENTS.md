# net-sim — 에이전트 작업 지침

Packet Tracer 식으로 직접 구성하는 네트워크 학습 시뮬레이터. 디자인 품질이 최우선(`DESIGN.md` 참조). 실제 소켓/OS 스택 없음. 모든 시뮬레이션은 결정론적.

## 구조
- `src/core/` — 순수 TS 시뮬레이션 코어. DOM 의존 금지. 모든 동작은 테스트로 고정한다.
  - `network.ts` — 노드/링크 그래프, 이벤트 큐, 트레이스 기록, 사용자 동작(`ActionSpec`) 기록·재생
  - `nodes/*.ts` — 노드 구현 (`SimNode` 인터페이스). 노드는 `NodeContext` 를 통해서만 송신/타이머/트레이스
  - `packet.ts` — 계층별 패킷 모델 (학습에 필요한 필드만). IPv6 는 이더넷 payload 의 별도 종류 `ipv6`(`Ipv6Packet`, ICMPv6 는 `icmp6`) — IPv4 코드는 `ipv4` 만 보므로 IPv6 를 모르는 장치는 그대로 무시한다
  - `addr6.ts` — IPv6 주소(늘 RFC 5952 표준 표기 문자열: 비교 = 문자열 비교)·프리픽스·EUI-64·solicited-node·33:33 MAC
  - `trace.ts` — `TraceKind` 목록. 새 이벤트 종류를 추가하면 여기에 먼저 등록
  - `packet.ts` 의 `hasPorts`·`isControl`·`IP_PROTO`: 장비들은 IPv4 안의 종류를 나열하지 않고 이 판별로 나눈다(포트가 있나 / 라우터끼리의 제어 멀티캐스트인가). 새 IP 프로토콜은 여기부터 넣는다
  - L3 장치(`nodes/l3.ts`)는 라우팅·NAT·방화벽·릴레이만 직접 하고, VPN 터널 끝은 `nodes/l3tunnel.ts`(`TunnelEnds`: 받은 터널 패킷을 사이트 간·원격 접속으로 나누고 풀기, 터널로 보내기), 이중화 세션 동기화는 `nodes/hasync.ts`(`SessionSync`)에 맡긴다. IPsec 협상(재전송·NAT 감지·SPI·패킷 조립)은 두 VPN 이 `nodes/ike.ts` 를 같이 쓴다
  - 프레임 기록: `Network.frameLog`(프레임 id → 링크에 실린 기록, 2만 id 상한)와 `framesAt(packetId, nodeId, time)` — 로그 줄의 장치가 받은/내보낸 프레임. 라우터·NAT 는 홉마다 새 L2 프레임(새 id)을 만들므로, 받는 중에 새로 보낸 프레임은 `cause` 로 원래 id 에 이어 둔다(ARP 를 기다렸다 나중에 보낸 것은 이어지지 않음)
  - `scenarios/` — 테스트용 고정 토폴로지
- `src/core/nodes/ipv6.ts` — `Ipv6Interface`(인터페이스별 링크 로컬 + 수동 주소, 이웃 캐시, NDP NS/NA, DAD). 호스트는 `Host.v6`, 게이트웨이·NAT 박스는 물리 인터페이스마다 `L3Node.v6[i]`(서브 인터페이스는 IPv4 만)
- `src/model/` — 편집 가능한 토폴로지 모델(`topology.ts`: 장치 종류·포트·앵커 좌표·무선 파생·`planCable` 검증·`cloneDevices`/`alignDevices`·JSON 직렬화 `serializeTopology`/`parseTopology`), 예제 40종의 레지스트리는 `examples.ts`(`EXAMPLES`, 메뉴 순서 = 기본 → 기능 단위 → 라우팅 → L2 → 보안 → 서비스 → 인터넷 → VPN → 무선 → IPv6 → 종합), 예제 함수는 `examples/` 에 메뉴 묶음별 파일(basic·parts·routing·l2·security·services·internet·vpn(GL.iNet 식)·wireless·ipv6·overview(종합), 조립 도우미 `build.ts`. 메뉴에서 뺀 구성 중 테스트가 기대는 것은 `tests/fixtures.ts`) — 새 예제는 묶음 파일에 함수를 넣고 `EXAMPLES` 에 등록 —과 앱 상태(`store.ts`: Preact signals, localStorage 저장, 되돌리기 스택 — 모든 편집은 `setTopology` 를 거치고 드래그는 `beginCoalesce/endCoalesce` 로 한 단계, 선택은 단일/다중/케이블/케이블 여러 개, 클립보드). `store.ts` 는 브라우저 API 를 `typeof` 로 감싸 vitest 에서도 import 된다(`tests/store.test.ts`). 시뮬레이션 실행 시 코어 `Network` 로 변환한다.
  - 영역(`Zone`): 장치 뒤에 그리는 주석 네모(`topology.zones`). 시뮬레이션·구성 검사와 무관 — 끌기·복사 규칙은 `docs/features/ui.md`. 예제에 넣을 땐 `zoneAround` 로 계산한다.
  - `lint.ts` — 구성 검사(순수). 토폴로지만 보고 "설정 한 칸 빠짐" 을 `LintIssue[]` 로. 오탐이 미탐보다 나쁘므로 주소를 모르는(DHCP) 인터페이스가 끼면 침묵. `lint.ts` 는 입구(규칙 실행 순서 `RULES`)이고 구현은 `lint/`(공용 `addr`·`segments`·`context` + 주제별 규칙 `addressing`·`routing`·`l2`·`lb`·`services`·`vpn`·`ha`, 규칙은 `(ctx: LintContext) => void`). 주소 규칙 중 `dhcp.gateway-mismatch`(기본 게이트웨이 옵션(3)이 세그먼트 라우터의 실제·가상 주소 어느 것과도 다름, 추가 풀은 풀 서브넷 안 라우터 인터페이스의 세그먼트 기준)·`host.prefix-mismatch`(수동 호스트 IP 는 라우터 서브넷 안인데 프리픽스가 다름)는 주소·서브넷을 모르는 라우터 인터페이스가 끼면 침묵. `dhcp.range-invalid`(호스트 DHCP 서비스의 기본 풀이 거꾸로이거나 서버 서브넷 밖 — 코어 `DhcpServer.rangeProblem` 과 같은 기준, 이때와 서버 IP 가 없을 때는 서버가 응답하지 않으니 그 서버의 게이트웨이·DNS 안내 규칙은 침묵). 규칙 추가 시 `tests/lint.test.ts` 에 걸리는/안 걸리는 케이스 + 모든 예제 이슈 0 유지(`tests/topology.test.ts`).
  - 순수(테스트 가능) 층: `netSync.ts`(`NetworkSync`: 토폴로지 → `Network` diff 동기화, `effective*` 입력 정리, `makeNode`/`applyConfig`), `simClock.ts`(`advanceClock`: 애니메이션 시계), `status.ts`(타일 문구·서비스 배지). `sim.ts` 는 이 셋을 신호·rAF 로 감싸기만 한다. 새 동기화 로직은 `sim.ts` 가 아니라 `netSync.ts` 에 넣고 `tests/netSync.test.ts` 로 고정한다.
- `src/app/` — Preact UI. `Canvas.tsx`(SVG 캔버스·케이블 드래그·패킷 카드), `Palette.tsx`(`PALETTE_GROUPS` — 새 장치는 알맞은 묶음에), `Inspector.tsx` + `inspector/*`(탭 `개요/설정/진단/표`, 공유기·게이트웨이 설정은 `ConfigGroups` 묶음 — 새 설정 섹션은 알맞은 묶음에, ui-check 는 섹션을 찾기 전 `goGroup`), `PacketDetail.tsx`·`LogDrawer.tsx`(패킷 상세는 `model/packetView.ts` — 새 트레이스 종류에 실무 출력이 있으면 `practitionerLines` 에 추가하고 `tests/packetView.test.ts` 로 형식 고정. 로그 줄 수를 늘릴 땐 `npm run perf-check -- --log`), `App.tsx`(상단바·`FileMenu`), `styles.css`(토큰 + 컴포넌트). 상세(선택·패널 접기·로그 보관 상한 등)는 `docs/features/ui.md`.
- `tests/` — vitest. 코어는 트레이스 순서(`nodeId:kind` 시퀀스)를 그대로 단언하는 방식을 유지한다.

## 규칙
- 디자인 결정은 `DESIGN.md` 의 토큰·원칙을 따른다. 새 색은 토큰으로만, 카드/그림자 남발 금지, 대문자 라벨 금지.
- UI 문구는 한국어·존댓말·문장형. 에러 문구는 "무엇이 잘못됐고 어떻게 고치는지" 를 담는다.
- 용어는 **실무 통용어**를 쓴다(쉬운 말로 풀어 쓰지 않는다): DHCP 임대/임대 갱신/임대 해제, 기본 게이트웨이 옵션(3)·DNS 서버 옵션(6), 인바운드/아웃바운드/양방향, Stateful 검사, 디폴트 라우트, 스태틱 라우팅, 넥스트 홉, No route, 드롭, 패킷 손실, 링크 다운, IP 미설정, 업스트림 DNS, 재귀 질의, timeout(영어 그대로, "타임아웃" 으로 쓰지 않음). 장치 이름(라우터·게이트웨이·NAT)은 바꾸지 않는다. 새 문구를 넣을 때 이 목록과 어긋나면 목록을 따른다.
- 트레이스 요약문은 "무엇을 보고 → 어떤 결정 → 결과" 가 한 줄에 드러나게 쓴다.
- 코어에 비결정성(난수, Date.now)을 넣지 않는다. 되감기는 "재구성 + 동작 재투입 + N 스텝" 으로 구현한다.
- 새 장치 종류는 `DEVICE_SPECS` 에 추가하고 `Icons.tsx` 에 아이콘을 넣는다. 케이블은 포트에서 수직으로 나가므로 포트의 `side` 가 곧 케이블 방향이다. 스위치는 실물처럼 아래쪽 포트 한 줄만 두고(업링크 포트 없음), 위쪽 장치로 가는 케이블은 짧게 나갔다가 타일 뒤로 올라간다.

## 문서
- `DESIGN.md` 디자인 토큰·원칙. `docs/LESSONS.md` 개발 중 반복된 문제와 교훈(새 실수를 하면 여기에 추가). `docs/TROUBLESHOOTING.md` 사용자가 보는 통신 실패 문구 → 원인 → 고치는 법(새 실패 문구를 추가하면 여기도 갱신). `docs/ROADMAP.md` 다음 후보와 우선순위(기준: 새 학습 포인트, 장치보다 "상자 안의 소프트웨어"). `docs/features/*.md` 기능별 구현 상세 — 아래 "기능별 문서" 표 참고.

## 검증
```
npm run typecheck   # tsc
npm test            # vitest (코어)
npm run ui-check    # Playwright 스모크 (개발 서버 자동 기동, .shots/ 에 스크린샷. 헬퍼 goTab/loadEx/clearUi — 인스펙터 탭·파일 메뉴를 거친다)
npm run perf-check  # 프로덕션 빌드로 예제 전부 + 단말 52대 스트레스를 CPU 4배 감속에서 6초씩: fps·p95·긴 프레임·점유율·라벨 깜빡임. --headed, --throttle N, --only=id, --log(로그 연 채로)
```
코어 변경은 `npm test`, UI 변경은 `npm run ui-check` 까지 통과해야 완료. 캔버스 매 프레임 코드(PacketLayer·ActiveCables·sim tick)를 건드리면 `npm run perf-check` 도 (개발 서버는 preact 디버그 훅 때문에 느려 측정에 쓰지 않는다).

## 배포 (porta-hub 와 같은 방식)
- `Dockerfile`: node:24-alpine 에서 `vite build` → `nginxinc/nginx-unprivileged`(8080, uid 101) 가 `dist/` 서빙. 설정은 `deploy/nginx.conf`(`/healthz`, `/assets/` 영구 캐시, 나머지는 `index.html` 폴백).
- `.github/workflows/docker-image.yml`: main push → `npm run typecheck` + `npm test` 게이트 → ghcr 푸시(`<sha>`, `latest`) → `deploy/values.yaml` 의 `image.tag` 를 sed 로 갱신해 봇 커밋. GITHUB_TOKEN 푸시는 워크플로를 다시 트리거하지 않는다.
- `deploy/`: Helm 차트(Deployment 는 readOnlyRootFilesystem + `/tmp` emptyDir, Service, Ingress 는 tailscale 클래스 + funnel). `argocd/application.yaml`: namespace `app`, automated prune/selfHeal. 시크릿 없음.
- 차트를 고치면 `helm lint deploy && helm template net-sim deploy` 로 렌더를 확인한다. 브라우저 스모크(`ui-check`)는 CI 에서 돌리지 않는다.

## 시뮬레이션 연결 방식
- `src/model/sim.ts` 의 `SimController` 가 토폴로지 signal 을 구독해 `NetworkSync.sync` 로 `Network` 에 diff 반영한다(장치 추가/삭제, 케이블 connect/disconnect, 설정 변경 → `node.configure`). 위치 이동만 있으면 `sync` 가 false 를 돌려 패널이 재렌더되지 않는다.
- 케이블 지연은 길이와 무관하게 `CABLE_LATENCY`(10ms) 고정 — 결정(2026-09-28): 현실 LAN 전파 지연은 사실상 0이고, 배치만 바꿔도 RTT·timeout 이 달라지면 안 되며, 구간당 같은 박자라 홉 수가 보인다. 화면상 긴 케이블이 빨라 보이는 건 감수한다.
- 시계: 패킷이 링크 위에 있을 때만 흐르고, 대기 이벤트만 있으면 그 시각으로 점프, 아무것도 없으면 정지. 사용자 개입 시각은 정수 ms 로 올림.
- 배경 타이머(`ctx.timer(delay, tag, data, true)`, 결정 2026-09-30): 주기 동작(광고·헬스 체크·DPD)은 이것으로만 — 스스로 시계를 움직이지 않고 다른 일로 시간이 그 시각을 지날 때만 발화한다(`Network` 의 별도 큐 `bg`, `step` 은 다음 일반 이벤트보다 이른 것부터, 같은 시각이면 일반 이벤트 먼저, 일반 이벤트가 없으면 `step`·`runToIdle`·`advanceClock` 은 멈춘다 — 조용하면 정지하는 원칙 그대로). 시간을 흘리는 길: 패킷 이동(애니메이션 중 지나간 것은 `stepUntil`, 다음 이벤트로 점프할 때도 배경 타이머 시각에서 멈춰 그 타이머가 보낸 프레임이 화면에 지나간다), timeout, `runUntil`(상한 `maxEvents`), 상단바 "+10초"(`SimController.fastForward`). 주기 동작은 기능별 설정으로 켜고 기본 꺼짐(기존 예제·로그 불변). 새 주기 동작은 일반 타이머로 넣지 않는다 — `runToIdle` 이 끝나지 않는다.
- 안전장치: L2 루프는 스위치가 같은 프레임 재수신/홉 16 초과 시 드롭(`switch.loop`), 같은 두 장치 사이 두 번째 케이블은 UI 가 거부, 한 프레임에 이벤트 4000 초과 시 일시정지. 장치 제거 시 `onRemove` 로 DHCP Release 를 보내고 그 프레임은 케이블이 빠져도 배달(`Transmission.graceful`).
- `NodeContext.now` 는 읽을 때의 시각(getter)이고 `ctx.timer` 도 부르는 순간의 시각 기준이다: DNS 응답을 기다린 콜백처럼 앞선 이벤트의 ctx 를 들고 있다가 나중에 불러도 타이머·RTT 가 과거 기준이 되지 않게(2026-09-30 IPv6 리뷰에서 발견 — 거짓 재전송·시계 역행)


## 기능별 문서
기능을 고치기 전에 그 문서를 먼저 읽고, 고친 뒤에는 같은 문서를 갱신한다(동작·한계·구성 검사 이름·예제). 새 기능은 알맞은 파일에 한 덩어리로 추가한다.

| 문서 | 내용 |
|---|---|
| `docs/features/core.md` | 노드 클래스, 이름 해석, NAT TCP 매핑·포트 포워딩, DHCP INIT-REBOOT, IP 충돌, 진단 자동완성, 주소 변경 정합성, traceroute·ICMP Unreachable, TCP·SSH·HTTPS, 링크 손실 |
| `docs/features/l2.md` | 무선(노트북 유선·무선 NIC 포함), VLAN, STP, IGMP 스누핑 |
| `docs/features/routing.md` | RIP, 이중화(VRRP·세션 동기화), 게이트웨이 NAT·포트 공개(도커 예제), NAT 종류·P2P·헤어핀 |
| `docs/features/vpn.md` | 사이트 간 VPN(WireGuard 식·IPsec·DPD), 원격 접속 VPN(EAP), 공유기 L2TP, WireGuard, OpenVPN, 메시 VPN, DPI·난독화, Tor |
| `docs/features/services.md` | 로드밸런서(L7·L4·세션 고정), 포워드 프록시, DDNS, 멀티 WAN, AdGuard, 공유기 관리, Samba, SIP |
| `docs/features/ipv6.md` | 링크 로컬·NDP·SLAAC·NUD·듀얼 스택·공유기 PD·인터넷 IPv6 |
| `docs/features/ui.md` | 캔버스·인스펙터·로그 서랍·영역의 동작 상세 |

## 점검 항목 (반복된 결함 — 새 기능마다 확인)
- **새 VPN 협상(종류)을 넣으면** ① 마지막 응답(거절 포함)이 사라질 때 같은 응답을 다시 보내는가 ② 서버가 상태를 잊을 때(설정 변경·재시작·주소를 잃음) 클라이언트가 알게 되는 길이 있는가 ③ 끊은 뒤·종류를 바꾼 뒤 늦게 온 패킷이 Port Unreachable 로 새지 않는가 ④ 구성 검사가 포트 포워딩(공유기 뒤 공유기)을 따라가는가 — 원격 접속 VPN 리뷰에서 나온 것을 L2TP 에서 그대로 되풀이했다(`docs/LESSONS.md` 4u).
- **TcpStack 에 앱 흐름(LB·프록시·SSH 같은 고리)을 새로 넣으면** "뒤 서버·대상 = 자기 자신" 루프백 테스트를 반드시 하나 둔다 — 세 번 어겼다(`docs/LESSONS.md` 4h·4k).
- **주기 동작은 배경 타이머로만** — 일반 타이머로 넣으면 `runToIdle` 이 끝나지 않는다(위 "배경 타이머").
- **새 들어오는 길(WAN 수신 경로)을 넣으면** 기존 기능(방화벽·포트 포워딩·VPN·DPI·킬 스위치)이 그 길에서도 먼저 적용되는지 하나씩 확인한다(`docs/LESSONS.md` 4zh).

## 로드맵
1~14 (편집기·DHCP·NAT·TCP·DNS·방화벽·무선·VLAN·RIP·로드밸런서·프록시·VPN·이중화·STP·IPv6) 모두 완료, 실제 네트워크 연결은 하지 않기로 결정(2026-09-19). GL.iNet Brume 3 계획 1~9단계(WireGuard·DDNS·멀티 WAN·AdGuard·DPI·OpenVPN·메시 VPN·공유기 관리·Samba·IGMP·SIP·Tor) 완료(2026-10-07). 다음 후보·우선순위·결정 이력은 `docs/ROADMAP.md`.
