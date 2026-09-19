# net-sim — 에이전트 작업 지침

Packet Tracer 식으로 직접 구성하는 네트워크 학습 시뮬레이터. 디자인 품질이 최우선(`DESIGN.md` 참조). 실제 소켓/OS 스택 없음. 모든 시뮬레이션은 결정론적.

## 구조
- `src/core/` — 순수 TS 시뮬레이션 코어. DOM 의존 금지. 모든 동작은 테스트로 고정한다.
  - `network.ts` — 노드/링크 그래프, 이벤트 큐, 트레이스 기록, 사용자 동작(`ActionSpec`) 기록·재생
  - `nodes/*.ts` — 노드 구현 (`SimNode` 인터페이스). 노드는 `NodeContext` 를 통해서만 송신/타이머/트레이스
  - `packet.ts` — 계층별 패킷 모델 (학습에 필요한 필드만)
  - `trace.ts` — `TraceKind` 목록. 새 이벤트 종류를 추가하면 여기에 먼저 등록
  - `scenarios/` — 테스트용 고정 토폴로지
- `src/model/` — 편집 가능한 토폴로지 모델(`topology.ts`: 장치 종류·포트·앵커 좌표)과 앱 상태(`store.ts`: Preact signals, localStorage 저장). 시뮬레이션 실행 시 코어 `Network` 로 변환한다.
- `src/app/` — Preact UI. `Canvas.tsx`(SVG 캔버스: 이동/팬/줌/케이블 드래그), `Palette.tsx`, `Inspector.tsx`(우측 속성), `App.tsx`(상단바·로그 서랍), `styles.css`(토큰 + 컴포넌트).
- `tests/` — vitest. 코어는 트레이스 순서(`nodeId:kind` 시퀀스)를 그대로 단언하는 방식을 유지한다.

## 규칙
- 디자인 결정은 `DESIGN.md` 의 토큰·원칙을 따른다. 새 색은 토큰으로만, 카드/그림자 남발 금지, 대문자 라벨 금지.
- UI 문구는 한국어·존댓말·문장형. 에러 문구는 "무엇이 잘못됐고 어떻게 고치는지" 를 담는다.
- 트레이스 요약문은 "무엇을 보고 → 어떤 결정 → 결과" 가 한 줄에 드러나게 쓴다.
- 코어에 비결정성(난수, Date.now)을 넣지 않는다. 되감기는 "재구성 + 동작 재투입 + N 스텝" 으로 구현한다.
- 새 장치 종류는 `DEVICE_SPECS` 에 추가하고 `Icons.tsx` 에 아이콘을 넣는다. 케이블은 포트에서 수직으로 나가므로 포트의 `side` 가 곧 케이블 방향이다. 스위치는 실물처럼 아래쪽 포트 한 줄만 두고(업링크 포트 없음), 위쪽 장치로 가는 케이블은 짧게 나갔다가 타일 뒤로 올라간다.

## 문서
- `DESIGN.md` 디자인 토큰·원칙. `docs/LESSONS.md` 개발 중 반복된 문제와 교훈(새 실수를 하면 여기에 추가). `docs/TROUBLESHOOTING.md` 사용자가 보는 통신 실패 문구 → 원인 → 고치는 법(새 실패 문구를 추가하면 여기도 갱신). `docs/ROADMAP.md` 다음 후보와 우선순위(기준: 새 학습 포인트, 장치보다 "상자 안의 소프트웨어").

## 검증
```
npm run typecheck   # tsc
npm test            # vitest (코어)
npm run ui-check    # Playwright 스모크 (개발 서버 자동 기동, .shots/ 에 스크린샷)
```
코어 변경은 `npm test`, UI 변경은 `npm run ui-check` 까지 통과해야 완료.

## 시뮬레이션 연결 방식
- `src/model/sim.ts` 의 `SimController` 가 토폴로지 signal 을 구독해 `Network` 에 diff 로 반영한다(장치 추가/삭제, 케이블 connect/disconnect, 설정 변경 → `node.configure`).
- 시계: 패킷이 링크 위에 있을 때만 흐르고, 대기 이벤트만 있으면 그 시각으로 점프, 아무것도 없으면 정지. 사용자 개입 시각은 정수 ms 로 올림.
- 노드 클래스: `Host`(DhcpClient + 선택적 DhcpServer/DnsServer + DnsResolver + ping + TcpStack), `Switch`, `Hub`(학습 없이 전부 반복), `Router`(LAN 브리지 + DhcpServer + DNS 포워더 + WAN DhcpClient + NatTable/포트 포워딩), `L3Node`(게이트웨이/NAT 박스: 인터페이스 N개, 직접 연결 → 정적 경로 → 기본 경로, DHCP 릴레이, NAT 는 outside 에서 + 포트 포워딩), `Internet`(ISP DhcpServer + 공인 DNS 8.8.8.8/1.1.1.1 + 공인 서버 대역 ping/TCP 응답 + 외부 클라이언트 198.51.100.7). 공용 모듈: `nodes/dhcp.ts`, `nodes/dns.ts`, `nodes/tcp.ts`, `nodes/nat.ts`, `nodes/firewall.ts`(지나가는 패킷만 검사, 방향은 업링크 기준 in/out, 안쪽끼리는 lan, 상태 추적은 initiator 패킷만 흐름 등록).
- 무선: 모델의 `wirelessLinks(topology)` 가 SSID·거리(`WIFI_RANGE`)로 단말→기지 연결을 파생하고, `sim.ts` 가 이를 `wl_<단말id>` 케이블로 `Network` 에 넣는다(지연 20ms). 기지 포트는 `PortSpec.radio`(그리지 않음, 케이블 금지). 코어 `AccessPoint`(포트 0 = eth0, 1..8 = 무선 슬롯), `Router.RADIO_PORTS`(5..12). 슬롯 할당은 `slotTable` 로 안정화.
- 이름 해석: `ActionSpec.dst` 는 IP 또는 이름. 호스트가 `looksLikeName` 이면 리졸버로 먼저 해석(캐시 → 설정된 DNS → 실패 사유). DNS 서버 설정은 `NetInterface.dns`(수동 또는 DHCP 옵션).
- 안전장치: L2 루프는 스위치가 같은 프레임 재수신/홉 16 초과 시 폐기(`switch.loop`), 같은 두 장치 사이 두 번째 케이블은 UI 가 거부, 한 프레임에 이벤트 4000 초과 시 일시정지. 장치 제거 시 `onRemove` 로 DHCP Release 를 보내고 그 프레임은 케이블이 빠져도 배달(`Transmission.graceful`).
- 주소 변경 시 정합성: 호스트/라우터/L3 모두 주소가 바뀌면 ARP 캐시·대기열을 비우고 TCP 연결을 정리하며 Gratuitous ARP 를 보낸다. DHCP 서버는 인터페이스/범위 변경 시 범위 밖 임대를 무효화한다.
- TCP 는 학습용 축소판: 누적 ACK, 타임아웃 재전송(RTO 400ms, 3회), 순서 어긋난 세그먼트는 버리고 중복 ACK. 슬라이딩 윈도우·빠른 재전송 없음. 앱은 "GET / 100B → 응답 1000B×3 → 서버 FIN".
- 링크 손실: `Network.setLinkLoss`(xorshift 결정론 난수), `dropNextOn`(1회). 유실 프레임은 `Transmission.lost/lostAt` 으로 캔버스에서 중간에 사라진다.

## 로드맵
1. ✅ 디자인 시스템 + 캔버스 에디터
2. ✅ DHCP·ping·패킷 애니메이션·이벤트 로그 (라이브 시뮬레이션)
3. ✅ 인터넷 노드 + 라우터 WAN(DHCP) + NAT(ICMP id 기반)
4. ✅ TCP + 케이블 손실 실험 + NAT 포트 변환
5. ✅ 기능 단위 장치(게이트웨이·NAT 박스·호스트 DHCP 서버) + 정적 경로 + DHCP 릴레이/서브넷별 풀 + 서비스 배지 + 기능 단위 예제
6. ✅ DNS + 포트 포워딩 + 허브 (에이전트 2개 병렬: 파일 경계를 나누고 공용 타입을 먼저 넣은 뒤 진행)
7. ✅ 방화벽 (라우터·게이트웨이·NAT 박스)
8. ✅ 무선 (AP·스마트폰·공유기 Wi-Fi)
9. 이후 후보는 `docs/ROADMAP.md` (VLAN → 실제 인터넷 연결)
