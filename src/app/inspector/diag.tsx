// 진단(ping·traceroute·TCP 연결·DHCP 임대 갱신, 인터넷의 외부 접속)과 표 탭(현재 상태·라이브 테이블).
import { useState } from "preact/hooks";
import { Host } from "../../core/nodes/host";
import { TCP_STATE_LABEL } from "../../core/nodes/tcp";
import { Internet } from "../../core/nodes/internet";
import { L3Node } from "../../core/nodes/l3";
import type { SnapshotTable as SnapshotTableData } from "../../core/nodes/node";
import { Router } from "../../core/nodes/router";
import { sim, simVersion } from "../../model/sim";
import { topology } from "../../model/store";
import { looksLikeName } from "../../core/nodes/dns";
import { type Device } from "../../model/topology";
import { Icon } from "../Icons";
import { TargetPicker } from "../TargetPicker";
import { probeTargetsCached } from "../../model/reach";
import { Section, validIp } from "./ui";

/** 인터넷 노드: 바깥의 클라이언트가 우리 공인 주소로 접속을 시도 (포트 포워딩 실험) */
export function InternetDiagSection({ d }: { d: Device }) {
  void simVersion.value;
  const [inetDst, setInetDst] = useDiagField(d.id, "inet", "");
  const [inetPort, setInetPort] = useDiagField(d.id, "inetPort", "80");
  const publics: { ip: string; name: string }[] = [];
  for (const other of topology.value.devices) {
    const n = sim.node(other.id);
    if (n instanceof Router && n.wan.ip) publics.push({ ip: n.wan.ip, name: `${other.name} WAN` });
    if (n instanceof L3Node && n.nat && n.ifaces[0]?.ip) publics.push({ ip: n.ifaces[0].ip, name: `${other.name} outside` });
  }
  const go = () => {
    const dst = (inetDst || publics[0]?.ip || "").trim();
    const p = Math.min(65535, Math.max(1, Number(inetPort) || 80));
    if (!dst || !validIp(dst)) return;
    sim.act({ kind: "inet-connect", nodeId: d.id, dst, port: p });
  };
  return (
    <Section title="외부에서 접속">
      <p class="note">인터넷 저편의 클라이언트(198.51.100.7)가 우리 공인 주소로 TCP 연결을 시도합니다. 포트 포워딩 규칙이 없으면 NAT 에서 드롭됩니다.</p>
      <div class="ping-row tcp-row">
        <input class="input mono" list={`publics-${d.id}`} placeholder="공인 주소" value={inetDst || publics[0]?.ip || ""} onInput={(e) => setInetDst(e.currentTarget.value)} onKeyDown={(e) => e.key === "Enter" && go()} />
        <datalist id={`publics-${d.id}`}>
          {publics.map((p) => (
            <option key={p.ip} value={p.ip}>
              {p.name}
            </option>
          ))}
        </datalist>
        <input class="input mono port" type="number" min={1} max={65535} value={inetPort} onInput={(e) => setInetPort(e.currentTarget.value)} title="포트" />
        <button class="btn" onClick={go} title="외부 접속 (인바운드) 테스트">
          <Icon name="send" size={14} />
          접속
        </button>
      </div>
      {(() => {
        const node = sim.node(d.id);
        if (!(node instanceof Internet)) return null;
        const conns = [...node.tcp.conns.values()].filter((c) => c.localIp === Internet.REMOTE_CLIENT).slice(-3).reverse();
        if (conns.length === 0) return null;
        return (
          <ul class="ping-log tcp-log">
            {conns.map((c) => (
              <li key={c.id} class={c.state === "FAILED" ? "failed" : c.state === "CLOSED" && c.bytesReceived > 0 ? "ok" : ""}>
                <span class="mono">
                  → {c.remoteIp}:{c.remotePort}
                </span>
                <span>{c.state === "FAILED" ? `실패 · ${c.reason ?? ""}` : c.state === "CLOSED" ? `종료됨 · 받음 ${c.bytesReceived}B` : TCP_STATE_LABEL[c.state]}</span>
              </li>
            ))}
          </ul>
        );
      })()}
    </Section>
  );
}

// ---------- 시뮬레이션 상태 ----------

export function StatusSection({ d }: { d: Device }) {
  void simVersion.value;
  const node = sim.node(d.id);
  if (!node || node.type === "switch") return null;
  const snap = node.snapshot();
  return (
    <Section title={node.type === "hub" ? "허브" : "현재 상태"}>
      {snap.info.map(([k, v]) => (
        <div key={k} class="stat-row">
          <span>{k}</span>
          <b class="mono">{v}</b>
        </div>
      ))}
    </Section>
  );
}

export function LiveTables({ d }: { d: Device }) {
  void simVersion.value;
  const node = sim.node(d.id);
  if (!node) return null;
  return (
    <>
      {node.snapshot().tables.map((t) => (
        <Section key={t.title} title={t.title}>
          <SnapshotTable t={t} />
        </Section>
      ))}
    </>
  );
}

export function SnapshotTable({ t }: { t: SnapshotTableData }) {
  return (
    <table class="table">
      <thead>
        <tr>
          {t.columns.map((c) => (
            <th key={c}>{c}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {t.rows.length === 0 ? (
          <tr>
            <td class="empty" colSpan={t.columns.length}>
              비어 있음
            </td>
          </tr>
        ) : (
          t.rows.map((r, i) => (
            <tr key={i}>
              {r.map((c, j) => (
                <td key={j} class="mono">
                  {c}
                </td>
              ))}
            </tr>
          ))
        )}
      </tbody>
    </table>
  );
}

/** ping, TCP 연결, DHCP 임대 갱신 */
/** 진단 입력값을 장치별로 기억 (다른 장치에 갔다 와도 마지막 값이 남는다) */
export const diagMemory = new Map<string, { ping?: string; tcp?: string; port?: string; inet?: string; inetPort?: string }>();

export function useDiagField(deviceId: string, key: "ping" | "tcp" | "port" | "inet" | "inetPort", initial: string): [string, (v: string) => void] {
  const mem = diagMemory.get(deviceId) ?? {};
  const [v, setV] = useState(mem[key] ?? initial);
  const set = (next: string) => {
    diagMemory.set(deviceId, { ...(diagMemory.get(deviceId) ?? {}), [key]: next });
    setV(next);
  };
  return [v, set];
}

export function DiagSection({ d }: { d: Device }) {
  void simVersion.value;
  const node = sim.node(d.id);
  const [pingDst, setPingDst] = useDiagField(d.id, "ping", "");
  const [tcpDst, setTcpDst] = useDiagField(d.id, "tcp", "");
  const [tcpPort, setTcpPort] = useDiagField(d.id, "port", "80");
  if (!(node instanceof Host)) return null;

  const okTarget = (v: string) => validIp(v) || (looksLikeName(v) && /^[a-z0-9.-]+$/i.test(v));
  const send = () => {
    const dst = pingDst.trim();
    if (!dst || !okTarget(dst)) return;
    sim.act({ kind: "ping", nodeId: d.id, dst });
  };
  const trace = () => {
    const dst = pingDst.trim();
    if (!dst || !okTarget(dst)) return;
    sim.act({ kind: "traceroute", nodeId: d.id, dst });
  };
  const tr = node.traceroutes.at(-1);
  const port = Math.min(65535, Math.max(1, Number(tcpPort) || 80));
  const connect = () => {
    const dst = tcpDst.trim();
    if (!dst || !okTarget(dst)) return;
    sim.act({ kind: "tcp-connect", nodeId: d.id, dst, port });
  };
  return (
    <Section>
      <div class="ping-row">
        <TargetPicker value={pingDst} onInput={setPingDst} onSubmit={send} placeholder="ping 보낼 주소 또는 이름" load={() => probeTargetsCached(topology.peek(), d.id, "ping")} />
        <button class="btn" onClick={send}>
          <Icon name="send" size={14} />
          ping
        </button>
        <button class="btn" onClick={trace} title="traceroute: TTL 을 1 부터 늘려 가며 보내 경로의 라우터를 차례로 알아냅니다">
          경로
        </button>
      </div>
      {node.pings.length > 0 && (
        <ul class="ping-log">
          {node.pings.slice(-5).reverse().map((p) => (
            <li key={p.seq} class={p.status}>
              <span class="mono">{p.resolved ? `${p.dst} (${p.resolved})` : p.dst}</span>
              <span>{p.status === "ok" ? `응답 ${p.rtt}ms` : p.status === "failed" ? `실패 · ${p.reason}` : "응답 기다리는 중"}</span>
            </li>
          ))}
        </ul>
      )}
      {tr && (
        <div class={`trace-result ${tr.status}`}>
          <div class="trace-head">
            <span class="mono">traceroute {tr.resolved && tr.resolved !== tr.dst ? `${tr.dst} (${tr.resolved})` : tr.dst}</span>
            <span>{tr.status === "done" ? `${tr.hops.length}홉` : tr.status === "failed" ? `실패 · ${tr.reason}` : "찾는 중…"}</span>
          </div>
          <ol class="trace-hops">
            {tr.hops.map((h) => {
              const who = h.ip ? topology.value.devices.find((x) => {
                const n = sim.node(x.id);
                if (n instanceof Host) return n.ip === h.ip;
                if (n instanceof Router) return n.lan.ip === h.ip || n.wan.ip === h.ip;
                if (n instanceof L3Node) return n.ifaces.some((f) => f.ip === h.ip);
                if (n instanceof Internet) return n.iface.ip === h.ip;
                return false;
              })?.name : undefined;
              return (
                <li key={h.ttl}>
                  <span class="ttl mono">{h.ttl}</span>
                  <span class="mono">
                    {h.ip ?? "*"}
                    {h.flag && <b class="hop-flag" title={h.flag === "!N" ? "Net Unreachable: 그 장치에 목적지 경로가 없음" : h.flag === "!H" ? "Host Unreachable: 목적지 주소에 ARP 응답이 없음" : "Port Unreachable"}> {h.flag}</b>}
                  </span>
                  <span class="who">{who ?? (h.ip ? "" : "응답 없음")}</span>
                  <span class="rtt">{h.rtt !== undefined ? `${h.rtt}ms` : ""}</span>
                </li>
              );
            })}
          </ol>
        </div>
      )}
      <div class="ping-row tcp-row">
        <TargetPicker value={tcpDst} onInput={setTcpDst} onSubmit={connect} placeholder="서버 주소 또는 이름" load={() => probeTargetsCached(topology.peek(), d.id, "tcp", port)} />
        <input class="input mono port" type="number" min={1} max={65535} value={tcpPort} onInput={(e) => setTcpPort(e.currentTarget.value)} title="포트" />
        <button class="btn" onClick={connect} title="TCP 연결 (3-way handshake → 요청 → 응답 → 종료)">
          <Icon name="send" size={14} />
          연결
        </button>
      </div>
      {(() => {
        const conns = [...node.tcp.conns.values()].filter((c) => c.role === "client").slice(-3).reverse();
        if (conns.length === 0) return null;
        return (
          <ul class="ping-log tcp-log">
            {conns.map((c) => (
              <li key={c.id} class={c.state === "FAILED" || c.status?.startsWith("HTTP 5") ? "failed" : c.state === "CLOSED" && c.bytesReceived > 0 ? "ok" : ""}>
                <span class="mono">
                  {c.remoteIp}:{c.remotePort}
                </span>
                <span>
                  {c.state === "FAILED"
                    ? `실패 · ${c.reason ?? ""}`
                    : c.status?.startsWith("HTTP 5")
                      ? `${c.status}${c.servedBy ? ` · ${c.servedBy}` : ""}`
                      : c.state === "CLOSED"
                        ? `종료됨 · 받음 ${c.bytesReceived}B${c.servedBy ? ` · 응답 ${c.servedBy}` : ""}`
                        : TCP_STATE_LABEL[c.state]}
                </span>
              </li>
            ))}
          </ul>
        );
      })()}
      <p class="note">TCP 연결은 3-way handshake 뒤 "GET /" 요청을 보내고, 서버 응답 3세그먼트를 받은 다음 FIN 으로 닫습니다. 자세한 기록은 "표" 탭의 TCP 연결 표와 로그에서 봅니다.</p>
      {node.ipMode === "dhcp" && (
        <button class="btn wide" onClick={() => sim.act({ kind: "dhcp-renew", nodeId: d.id })} disabled={!node.linkUp}>
          <Icon name="refresh" size={14} />
          DHCP 임대 갱신
        </button>
      )}
    </Section>
  );
}
