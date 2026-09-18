# net-sim — 에이전트 작업 지침

네트워크 학습용 이산 이벤트 시뮬레이터. 실제 소켓/OS 스택 없음. 모든 동작은 결정론적.

## 구조
- `src/core/` — 순수 TS 시뮬레이션 코어. DOM 의존 금지. 모든 동작은 테스트로 고정한다.
  - `network.ts` — 노드/링크 그래프, 이벤트 큐, 트레이스 기록, 사용자 동작(`ActionSpec`) 기록·재생
  - `nodes/*.ts` — 노드 구현 (`SimNode` 인터페이스). 노드는 `NodeContext` 를 통해서만 송신/타이머/트레이스
  - `packet.ts` — 계층별 패킷 모델 (학습에 필요한 필드만)
  - `trace.ts` — `TraceKind` 목록. 새 이벤트 종류를 추가하면 여기에 먼저 등록
  - `scenarios/` — 토폴로지 + 레이아웃 + 퀵 액션. 새 단계는 새 시나리오 파일로
- `src/ui/` — 브라우저 UI (vanilla TS + SVG). 코어 상태를 읽기만 하고, 변경은 `Network` API 로만.
- `tests/` — vitest. 트레이스 순서(`nodeId:kind` 시퀀스)를 그대로 단언하는 방식을 유지한다.

## 규칙
- 트레이스 요약문은 한국어, "무엇을 보고 → 어떤 결정 → 결과" 가 한 줄에 드러나게 쓴다. 실패·폐기 계열 kind 는 `ui/log.ts` 의 `BAD_KINDS` 에 등록.
- 되감기는 "시나리오 재구성 + 기록된 동작 재투입 + N 스텝" 으로 구현되어 있다. 따라서 코어에 비결정성(난수, Date.now)을 넣지 않는다.
- 새 사용자 동작은 `ActionSpec` 유니온에 추가하고 `Network.runAction` 에서 처리한다.
- 새 노드 타입은 `NodeType` 에 추가하고 `ui/topology.ts` 의 앵커/도형, `ui/style.css` 색상을 함께 넣는다.

## 검증
```
npm run typecheck   # tsc
npm test            # vitest (코어)
npm run ui-check    # Playwright 스모크 (개발 서버 자동 기동, .shots/ 에 스크린샷)
```
코어 변경은 `npm test`, UI 변경은 `npm run ui-check` 까지 통과해야 완료.

## 로드맵
1. 단일 서브넷: ARP + ICMP ping (완료)
2. DHCP: Discover/Offer/Request/Ack
3. 라우터/게이트웨이: 서브넷 2개, TTL 감소, 다른 서브넷은 게이트웨이 MAC 으로
4. NAT + 외부망: 변환 테이블, 응답 역변환
5. TCP: 3-way handshake, 시퀀스 번호, 드롭/재전송
