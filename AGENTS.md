# net-sim — 에이전트 작업 지침

Packet Tracer 식으로 직접 구성하는 네트워크 학습 시뮬레이터. 디자인 품질이 최우선(`DESIGN.md` 참조). 실제 소켓/OS 스택 없음. 모든 시뮬레이션은 결정론적.

## 구조
- `src/core/` — 순수 TS 시뮬레이션 코어. DOM 의존 금지. 모든 동작은 테스트로 고정한다.
  - `network.ts` — 노드/링크 그래프, 이벤트 큐, 트레이스 기록, 사용자 동작(`ActionSpec`) 기록·재생
  - `nodes/*.ts` — 노드 구현 (`SimNode` 인터페이스). 노드는 `NodeContext` 를 통해서만 송신/타이머/트레이스
  - `packet.ts` — 계층별 패킷 모델 (학습에 필요한 필드만)
  - `trace.ts` — `TraceKind` 목록. 새 이벤트 종류를 추가하면 여기에 먼저 등록
  - `scenarios/` — 테스트용 고정 토폴로지
- `src/model/` — 편집 가능한 토폴로지 모델(`topology.ts`: 장치 종류·포트·앵커 좌표·무선 파생·`planCable` 검증·`cloneDevices`/`alignDevices`·JSON 직렬화 `serializeTopology`/`parseTopology`), 예제 15종과 레지스트리는 `examples.ts`(`EXAMPLES`, 새 예제는 여기에)과 앱 상태(`store.ts`: Preact signals, localStorage 저장, 되돌리기 스택 — 모든 편집은 `setTopology` 를 거치고 드래그는 `beginCoalesce/endCoalesce` 로 한 단계, 선택은 단일/다중/케이블, 클립보드). `store.ts` 는 브라우저 API 를 `typeof` 로 감싸 vitest 에서도 import 된다(`tests/store.test.ts`). 시뮬레이션 실행 시 코어 `Network` 로 변환한다.
  - 영역(`Zone`): 장치 뒤에 그리는 주석 네모(`topology.zones`, 없으면 []). 시뮬레이션·구성 검사와 무관. 몸통은 포인터를 안 받고 이름표·테두리만 잡히며, 끌면 영역만 옮긴다(안의 장치는 그대로 — 사용자 요청). 복사: 영역 선택 시 영역 + 안의 장치(타일 중심 기준 `devicesInZone`), 장치 선택 시 안의 장치가 전부 선택된 영역도 함께. 붙여 넣으면 장치 선택에 영역이 딸려(`Selection.zoneIds`, `selectedZoneIds`) 끌기·삭제를 함께 한다. 예제에 넣을 땐 `zoneAround` 로 계산한다.
  - `lint.ts` — 구성 검사(순수). 토폴로지만 보고 "설정 한 칸 빠짐" 을 `LintIssue[]` 로. 오탐이 미탐보다 나쁘므로 주소를 모르는(DHCP) 인터페이스가 끼면 침묵. 규칙 추가 시 `tests/lint.test.ts` 에 걸리는/안 걸리는 케이스 + 모든 예제 이슈 0 유지(`tests/topology.test.ts`).
  - 순수(테스트 가능) 층: `netSync.ts`(`NetworkSync`: 토폴로지 → `Network` diff 동기화, `effective*` 입력 정리, `makeNode`/`applyConfig`), `simClock.ts`(`advanceClock`: 애니메이션 시계), `status.ts`(타일 문구·서비스 배지). `sim.ts` 는 이 셋을 신호·rAF 로 감싸기만 한다. 새 동기화 로직은 `sim.ts` 가 아니라 `netSync.ts` 에 넣고 `tests/netSync.test.ts` 로 고정한다.
- `src/app/` — Preact UI. `Canvas.tsx`(SVG 캔버스: 빈 곳 드래그 = 영역 선택, ⌥/가운데 버튼 = 팬, Shift+클릭 토글, 묶음 이동, 케이블 드래그 — 포트 칸(`[data-port]`, 투명 히트 영역)을 잡고 끌면 어느 도구든 그 포트에서 시작하고 포트 칸에 놓으면 그 포트로(`planCable(t,a,b,aPort,bPort)`, 검증 `portProblem`), 구성 검사 배지), `Palette.tsx`(140px, 맨 위 도구 3개 가로 + `PALETTE_GROUPS` 묶음별 캡션·2열 격자. 새 장치는 알맞은 묶음에 넣는다), `Inspector.tsx` + `inspector/*`(ui: 공용 부품 Section/Field/Toggle, panels: 네트워크·영역·케이블·다중 선택, l3: 게이트웨이·NAT·RIP·VLAN, rules: 방화벽·포트 포워딩, host: 호스트·무선·서비스, router: 공유기, diag: 진단·표. 우측 속성: 단일 장치 패널(탭 `개요/설정/진단/표`, 신호 `deviceTab` — 장치를 바꿔도 탭 유지, 없는 탭이면 개요)·다중 선택 `MultiPanel`·케이블·네트워크 요약 + 구성 검사 목록. 패널은 접기(⌘\, 40px 레일, 장치 더블클릭으로 다시 열림)·넓게(480)·끌어서 폭 조절, 섹션은 제목 클릭으로 접힘 — 상태는 `store.ts` 의 `inspectorOpen/inspectorWidth/collapsedSections`, localStorage. 동적 제목 섹션은 `id` 를 준다. 머리 줄(`.panel-head`)은 sticky 라 스크롤해도 편집 중인 장치가 보이고, 넓게·접기 버튼은 그 위에 겹쳐 고정), `LogDrawer.tsx`(계층 칩 + "선택한 장치만" 필터, 장치 이름을 누르면 캔버스에서 선택, 위쪽 가장자리 끌기로 높이 조절 — `store.ts` 의 `logHeight`(localStorage), 최대는 상단바 바로 아래, 한참 아래로 끌면 접힘. 보관은 `sim.ts` `TRACE_CAP`(50,000), 창에는 최근 500줄 + "이전 기록 더 보기" 로 2000줄씩. 갱신은 200ms 에 한 번(`logTick`), 줄은 `LogRow`(내용이 같으면 다시 그리지 않음), `.row` 는 `content-visibility: auto`. 줄 수를 늘릴 땐 `npm run perf-check -- --log` 로 스트레스 구성을 잰다), `App.tsx`(상단바: 재생·되돌리기·`FileMenu`(예제·JSON 내려받기/불러오기·비우기)·단축키), `styles.css`(토큰 + 컴포넌트).
- `tests/` — vitest. 코어는 트레이스 순서(`nodeId:kind` 시퀀스)를 그대로 단언하는 방식을 유지한다.

## 규칙
- 디자인 결정은 `DESIGN.md` 의 토큰·원칙을 따른다. 새 색은 토큰으로만, 카드/그림자 남발 금지, 대문자 라벨 금지.
- UI 문구는 한국어·존댓말·문장형. 에러 문구는 "무엇이 잘못됐고 어떻게 고치는지" 를 담는다.
- 용어는 **실무 통용어**를 쓴다(쉬운 말로 풀어 쓰지 않는다): DHCP 임대/임대 갱신/임대 해제, 기본 게이트웨이 옵션(3)·DNS 서버 옵션(6), 인바운드/아웃바운드/양방향, Stateful 검사, 디폴트 라우트, 스태틱 라우팅, 넥스트 홉, No route, 드롭, 패킷 손실, 링크 다운, IP 미설정, 업스트림 DNS, 재귀 질의, timeout(영어 그대로, "타임아웃" 으로 쓰지 않음). 장치 이름(라우터·게이트웨이·NAT)은 바꾸지 않는다. 새 문구를 넣을 때 이 목록과 어긋나면 목록을 따른다.
- 트레이스 요약문은 "무엇을 보고 → 어떤 결정 → 결과" 가 한 줄에 드러나게 쓴다.
- 코어에 비결정성(난수, Date.now)을 넣지 않는다. 되감기는 "재구성 + 동작 재투입 + N 스텝" 으로 구현한다.
- 새 장치 종류는 `DEVICE_SPECS` 에 추가하고 `Icons.tsx` 에 아이콘을 넣는다. 케이블은 포트에서 수직으로 나가므로 포트의 `side` 가 곧 케이블 방향이다. 스위치는 실물처럼 아래쪽 포트 한 줄만 두고(업링크 포트 없음), 위쪽 장치로 가는 케이블은 짧게 나갔다가 타일 뒤로 올라간다.

## 문서
- `DESIGN.md` 디자인 토큰·원칙. `docs/LESSONS.md` 개발 중 반복된 문제와 교훈(새 실수를 하면 여기에 추가). `docs/TROUBLESHOOTING.md` 사용자가 보는 통신 실패 문구 → 원인 → 고치는 법(새 실패 문구를 추가하면 여기도 갱신). `docs/ROADMAP.md` 다음 후보와 우선순위(기준: 새 학습 포인트, 장치보다 "상자 안의 소프트웨어").

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
- 노드 클래스: `Host`(DhcpClient + 선택적 DhcpServer/DnsServer + DnsResolver + ping + TcpStack), `Switch`, `Hub`(학습 없이 전부 반복), `Router`(LAN 브리지 + DhcpServer + DNS 포워더 + WAN DhcpClient + NatTable/포트 포워딩), `L3Node`(게이트웨이/NAT 박스: 인터페이스 N개, 직접 연결 → 스태틱 라우팅 → 디폴트 라우트, DHCP 릴레이(목적지가 내 주소·브로드캐스트인 DHCP 만 처리하고 나머지는 전달 — 릴레이 경로에 라우터가 더 있어도 됨), NAT 는 outside 에서 + 포트 포워딩. 동적 NAT 매핑은 상대를 가리지 않는 endpoint-independent(full cone) 방식이라, 안에서 연 포트로 바깥 누구든 들어올 수 있다 — 실제 가정용 공유기의 흔한 동작과 같고 학습 단순화를 위해 유지. 바깥에서 사설 주소로 직접 온 패킷은 TCP·UDP·ICMP 모두 드롭), `Internet`(ISP DhcpServer + 공인 DNS 8.8.8.8/1.1.1.1 + 공인 서버 대역 ping/TCP 응답 + 외부 클라이언트 198.51.100.7), `FirewallBridge`(`nodes/fwbridge.ts`, 투명 방화벽 장비: 포트 0 outside/1 inside, IP 없음, IPv4 만 `Firewall.check` 후 반대 포트로, ARP 는 통과(DHCP 는 IP 라 규칙 대상). 구성 검사는 양쪽 케이블을 하나로 접어 전선처럼 본다). 공용 모듈: `nodes/dhcp.ts`, `nodes/dns.ts`, `nodes/tcp.ts`, `nodes/nat.ts`, `nodes/firewall.ts`(지나가는 패킷만 검사, 방향은 업링크 기준 in/out, 안쪽끼리는 lan, Stateful 검사는 initiator 패킷만 흐름 등록).
- 무선: 모델의 `wirelessLinks(topology)` 가 SSID·거리(`WIFI_RANGE`)로 단말→기지 연결을 파생하고, `sim.ts` 가 이를 `wl_<단말id>_<기지id>_<슬롯>` 케이블로 `Network` 에 넣는다(지연 20ms, 기지·슬롯이 바뀌면 다른 링크로 보고 재연결). 기지 포트는 `PortSpec.radio`(그리지 않음, 케이블 금지). 코어 `AccessPoint`(포트 0 = eth0, 1..8 = 무선 슬롯), `Router.RADIO_PORTS`(5..12). 슬롯 할당은 `slotTable` 로 안정화.
- VLAN: `EthernetFrame.vlan` 은 802.1Q 태그(트렁크 링크에서만). `Switch.portVlan`(액세스 번호 | "trunk"), MAC 테이블 키 `"vlan:mac"`, 플러딩은 같은 VLAN 액세스 포트 + 트렁크. `L3Node.meta[i] = {port, vlan?}` 로 인터페이스 i 가 물리 포트/태그에 매핑되며 서브 인터페이스는 물리 인터페이스 뒤에 붙는다(`setSubinterfaces`). 호스트·공유기는 태그 프레임을 드롭하고, 허브·AP 는 L1/L2 반복기라 태그를 그대로 넘긴다. 스위치 루프 가드는 `프레임 id + 들어온 VLAN` 으로 본다(투명 방화벽이 한 스위치의 두 VLAN 을 이어도 루프가 아님).
- 이름 해석: `ActionSpec.dst` 는 IP 또는 이름. 호스트가 `looksLikeName` 이면 리졸버로 먼저 해석(캐시 → 설정된 DNS → 실패 사유). DNS 서버 설정은 `NetInterface.dns`(수동 또는 DHCP 옵션).
- 안전장치: L2 루프는 스위치가 같은 프레임 재수신/홉 16 초과 시 드롭(`switch.loop`), 같은 두 장치 사이 두 번째 케이블은 UI 가 거부, 한 프레임에 이벤트 4000 초과 시 일시정지. 장치 제거 시 `onRemove` 로 DHCP Release 를 보내고 그 프레임은 케이블이 빠져도 배달(`Transmission.graceful`).
- 동적 라우팅(`nodes/rip.ts`, RIPv2 축소판): `L3Node.rip`(설정 `L3Settings.rip {enabled, defaultRoute}`). 224.0.0.9 / MAC 01:00:5e:00:00:09 멀티캐스트, UDP 520, 메트릭 = 홉 수(16 = 철회). **주기 업데이트·timeout 없음** — 시계가 조용하면 멈추는 구조라 30초 주기 타이머를 넣으면 시계가 끝없이 점프한다. 대신 변화(링크·주소·설정·수신)가 생기면 `kick` → 250ms 뒤 트리거 업데이트(Probe 200ms 뒤라 새 주소로 보냄), 새로 참여한 인터페이스는 Request 도. split horizon + poison reverse, 보내는 인터페이스 자신의 서브넷은 광고 안 함, NAT outside 는 참여 안 함, 경로를 하나라도 잃으면(링크 다운·이웃의 철회) 다음 업데이트에서 모든 인터페이스로 Request 를 보내 대체 경로를 다시 듣는다(주기 업데이트 대신 — 다른 이웃의 16 에 '대답' 하는 방식은 poison reverse 끼리 끝없이 주고받아 금지). 인터페이스 주소가 바뀌거나 서브 인터페이스가 사라지기 직전 `retire` 로 옛 주소에서 전부 철회를 보내고, 서브 인터페이스 번호가 밀리면 `remap`. 장치 제거 시 전부 철회. 수렴 테스트는 삼각형만으로는 부족 — 4대 일렬·백본(스위치 공유)까지 `runToIdle` 이 끝나는지 본다(`tests/rip.test.ts`). 조회는 연결 → 스태틱·RIP 중 긴 마스크(같으면 스태틱) → 스태틱 디폴트 → RIP 디폴트. 한계: 스위치 너머 이웃이 사라진 건 모른다(문서화). 호스트·공유기 WAN·인터넷은 가입하지 않은 멀티캐스트 MAC 을 로그 없이 거른다(`isMulticastMac`). 구성 검사는 양쪽 다 RIP 면 "돌아오는 경로/업링크 디폴트/릴레이 경로" 규칙을 침묵.
- 로드밸런서(`nodes/lb.ts` `LoadBalancer`, 리버스 프록시·L7): 서버의 서비스 토글(`HostSettings.lb`)과 전용 장비(`kind: "lb"`, 호스트 계열·LB 켜진 채 생성)가 같은 모듈을 쓴다. `TcpStack` 의 `TcpHost.onRequest`(요청을 앱이 맡아 ACK 만 하고 나중에 `respond`) / `onFinish`(연결 종료 알림) 고리로 붙는다. LB 가 백엔드로 `connect` 해서 응답을 받으면 같은 크기로 클라이언트에 전달하고 세그먼트에 `origin`(X-Served-By 흉내)을 실어 클라이언트 `TcpConn.servedBy` 에 남긴다(진단 목록 "응답 …"). 분배: 라운드 로빈·최소 연결. 헬스 체크는 **패시브**(거부·timeout 이면 10초 빼고 같은 요청을 다음 백엔드로, 전부 실패면 502) — 액티브 주기 체크는 시계 구조상 없음. 호스트의 실제 listen 포트 = 서비스 포트 + LB 포트(`syncListening`). 구성 검사 `lb.no-backend`·`lb.backend-closed`·`lb.loop`(백엔드를 따라가 자기로 돌아옴). 요청은 거친 LB 수를 `via` 로 싣고 5개 이상이면 508 Loop Detected, 뒤에서 온 상태 줄(502·508)과 `servedBy` 는 그대로 전달. LB 의 백엔드 연결은 `connect(…, onCreated)` 에서 등록한다 — 내 주소로 가는 루프백은 `connect` 안에서 끝까지 동기로 진행되기 때문. TCP 클라이언트는 요청 뒤 10초 동안 응답이 없으면 RST 후 실패(`TCP_READ_TIMEOUT`, HTTP read timeout 흉내) — 중간 LB 가 끊겨도 영원히 기다리지 않게, LB 에게는 백엔드 실패가 된다. `transmit` 은 상태를 갱신한 **뒤** 보낸다(루프백 재진입).
- DHCP INIT-REBOOT(RFC 2131 4.3.2): `DhcpClient` 가 마지막 주소를 기억해 `start()`(링크 업·로밍·임대 갱신)에서 Discover 대신 서버 식별자 없는 Request 를 보낸다. 서버는 그 네트워크 주소가 아니거나 남의 임대면 Nak, 내 임대 기록이면 Ack, 기록이 없으면 침묵(클라이언트는 timeout 후 Discover). Nak·실패·Release 면 기억을 지운다.
- IP 충돌(RFC 5227 축소판, `NetInterface`): 고정 주소는 `claim()` — ARP Probe(보낸이 0.0.0.0) 후 200ms 동안 주장하는 장비가 없으면 Gratuitous ARP. 응답이 오면 `conflict.refused` 로 그 주소를 쓰지 않고(송신·ARP 응답 안 함), 충돌 상대가 다른 주소를 알리면 다시 claim. 쓰는 중 충돌은 기록 + Gratuitous ARP 방어(10초에 한 번). 노드는 `"arp-probe"` 타이머에서 `finishProbe` 를 부른다. DHCP 로 받은 주소는 Probe 없이 바로 announce. 타일은 `… 충돌` 경고.
- 진단 자동완성(`model/reach.ts` `probeTargets`): 토폴로지를 복제한 `NetworkSync` 에서 후보마다 ping/TCP·traceroute 를 실제로 돌려 닿는지·홉 수·실패 이유(방화벽/NAT 사설 주소/No route/VLAN/충돌)를 얻고, 출발 호스트 기준 위치(같은 서브넷/다른 서브넷/인터넷/이름)로 묶는다. 화면 시뮬레이션과 무관(복제본). UI 는 `app/TargetPicker.tsx`, 진단 입력값은 장치별로 기억(`diagMemory`).
- 주소 변경 시 정합성: 호스트/라우터/L3 모두 주소가 바뀌면 ARP 캐시·대기열을 비우고 TCP 연결을 정리하며 Gratuitous ARP 를 보낸다. DHCP 서버는 인터페이스/범위 변경 시 범위 밖 임대를 무효화한다.
- traceroute: 라우터 계열이 포워딩할 때 TTL 을 줄이고 0 이면 ICMP Time Exceeded(원 패킷 식별 정보 내장)를 들어온 인터페이스 주소로 보낸다. NAT 는 내장 정보로 역변환, 방화벽 Stateful 검사는 원 요청의 응답으로 취급. `Host.traceroute`(ICMP Echo 방식, 홉당 프로브 1개, 1000ms 타임아웃 → `*`, 16 홉). ICMP Destination Unreachable 은 없어 No route·차단은 `*` 로만 보인다.
- TCP 는 학습용 축소판: 누적 ACK, 타임아웃 재전송(RTO 400ms, 3회), 순서 어긋난 세그먼트는 버리고 중복 ACK. 슬라이딩 윈도우·빠른 재전송 없음. 앱은 "GET / 100B → 응답 1000B×3 → 서버 FIN".
- 링크 손실: `Network.setLinkLoss`(xorshift 결정론 난수), `dropNextOn`(1회). 손실 프레임은 `Transmission.lost/lostAt` 으로 캔버스에서 중간에 사라진다.

## 로드맵
1. ✅ 디자인 시스템 + 캔버스 에디터
2. ✅ DHCP·ping·패킷 애니메이션·이벤트 로그 (라이브 시뮬레이션)
3. ✅ 인터넷 노드 + 라우터 WAN(DHCP) + NAT(ICMP id 기반)
4. ✅ TCP + 케이블 손실 실험 + NAT 포트 변환
5. ✅ 기능 단위 장치(게이트웨이·NAT 박스·호스트 DHCP 서버) + 스태틱 라우팅 + DHCP 릴레이/서브넷별 풀 + 서비스 배지 + 기능 단위 예제
6. ✅ DNS + 포트 포워딩 + 허브 (에이전트 2개 병렬: 파일 경계를 나누고 공용 타입을 먼저 넣은 뒤 진행)
7. ✅ 방화벽 (라우터·게이트웨이·NAT 박스)
8. ✅ 무선 (AP·스마트폰·공유기 Wi-Fi)
9. ✅ VLAN (액세스/트렁크, 게이트웨이 서브 인터페이스)
10. 실제 네트워크 연결은 하지 않기로 결정(2026-09-19). 이후 작업은 품질(리뷰·테스트·문서)과 사용자가 새로 요청하는 것
11. ✅ 편집 도구 묶음(2026-09-20): JSON 저장/불러오기, 되돌리기, 다중 선택/복사, 일괄 설정·ping, 구성 검사, traceroute, 예제 12종
12. ✅ 동적 라우팅 RIP + DHCP INIT-REBOOT(2026-09-28)
13a. ✅ 로드밸런서(2026-09-29): 공용 모듈 + 서버 토글 + 전용 장비, 예제 "로드밸런서 (서버 토글 vs 전용 장비)"
13. ✅ 예제 정리(2026-09-28): "인터넷의 뼈대"(가장자리 트리·중심 그물, 공인 DNS 8.8.8.8 직접 조립)·"도메인으로 회사 웹 서버 접속" 추가, 이름·묶음을 학습 순서(기본 → 기능 단위 → 라우팅 → L2 → 보안 → 인터넷 → 무선)로, 15종
14. 심화 학습(사용자 결정, 나중에): IPv6, VPN (로드밸런서는 2026-09-29 완료) — `docs/ROADMAP.md`
