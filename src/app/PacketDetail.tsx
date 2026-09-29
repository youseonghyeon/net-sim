// 패킷 상세: 이벤트 로그의 펼친 줄과 캔버스에서 누른 패킷 카드가 같이 쓴다.
// 도구 출력(tcpdump·장비 명령 한 줄씩, 도구 이름이 제목 역할) → 계층별 헤더 → (로그 줄이면) 원본 기록
import { Fragment } from "preact";
import type { EthernetFrame } from "../core/packet";
import type { TraceEvent } from "../core/trace";
import { headerLayers, practitionerLines, tcpdumpLine, type HeaderLayer, type PractitionerLine } from "../model/packetView";
import { sim } from "../model/sim";

function ToolLines({ lines }: { lines: PractitionerLine[] }) {
  if (lines.length === 0) return null;
  return (
    <section class="pkt-lines">
      {lines.map((l, i) => (
        <div key={i} class="pkt-line">
          <span class="pkt-tool">{l.tool}</span>
          <code class="mono">{l.line}</code>
        </div>
      ))}
    </section>
  );
}

function FrameLayers({ title, layers }: { title: string; layers: HeaderLayer[] }) {
  return (
    <section class="pkt-frame">
      <h5>{title}</h5>
      {layers.map((l) => (
        <div key={l.title} class="pkt-layer">
          <span class="pkt-layer-title">{l.title}</span>
          <dl>
            {l.rows.map(([k, v]) => (
              <Fragment key={k}>
                <dt>{k}</dt>
                <dd class="mono">{v}</dd>
              </Fragment>
            ))}
          </dl>
        </div>
      ))}
    </section>
  );
}

/** 펼친 로그 줄: 그 장치가 받은/내보낸 프레임 */
export function PacketDetail({ e, name }: { e: TraceEvent; name: string | undefined }) {
  const frames = e.packetId !== undefined ? sim.net.framesAt(e.packetId, e.nodeId, e.time) : {};
  const lines = practitionerLines(e, frames, () => name ?? e.nodeId);
  const changed = frames.received && frames.sent && JSON.stringify(frames.received) !== JSON.stringify(frames.sent);
  return (
    <div class="pkt-detail" onClick={(ev) => ev.stopPropagation()}>
      <ToolLines lines={lines} />
      {frames.received && <FrameLayers title={changed ? `${name ?? "장치"} 가 받은 프레임` : "프레임"} layers={headerLayers(frames.received)} />}
      {changed && frames.sent && <FrameLayers title={`${name ?? "장치"} 가 내보낸 프레임 (바뀐 것: 주소·TTL·태그 등)`} layers={headerLayers(frames.sent)} />}
      {!frames.received && frames.sent && <FrameLayers title="프레임" layers={headerLayers(frames.sent)} />}
      {e.packetId === undefined && lines.length === 0 && <p class="pkt-none">이 줄은 특정 패킷이 아니라 장치 안의 상태 변화입니다.</p>}
      <details class="pkt-raw">
        <summary>원본 기록 (JSON)</summary>
        <pre>{JSON.stringify({ kind: e.kind, packetId: e.packetId, ...e.details }, null, 2)}</pre>
      </details>
    </div>
  );
}

/** 캔버스에서 누른 패킷 하나 (링크 위를 지나는 프레임) */
export function FrameDetail({ frame }: { frame: EthernetFrame }) {
  return (
    <div class="pkt-detail pkt-card-body">
      <ToolLines lines={[{ tool: "tcpdump -n -e", line: tcpdumpLine(frame) }]} />
      <FrameLayers title="프레임" layers={headerLayers(frame)} />
    </div>
  );
}
