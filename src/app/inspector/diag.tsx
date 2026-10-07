// 진단(ping·traceroute·DNS 조회·TCP 연결·DHCP 임대 갱신, 인터넷의 외부 접속)과 표 탭(현재 상태·라이브 테이블).
import { Fragment } from "preact";
import { useState } from "preact/hooks";
import { Host } from "../../core/nodes/host";
import { endpoint, TCP_STATE_LABEL } from "../../core/nodes/tcp";
import { isIpv6, sameSubnet6 } from "../../core/addr6";
import { Internet } from "../../core/nodes/internet";
import { L3Node } from "../../core/nodes/l3";
import type { SnapshotTable as SnapshotTableData } from "../../core/nodes/node";
import { Router } from "../../core/nodes/router";
import { sim, simVersion } from "../../model/sim";
import { topology } from "../../model/store";
import { looksLikeName, PUBLIC_ZONE, type QType } from "../../core/nodes/dns";
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
  // IPv6: NAT 가 없어 공유기 뒤 장치의 주소가 곧 공인 주소 (위임받은 프리픽스 안)
  const inet = sim.node(d.id);
  if (inet instanceof Internet) {
    for (const other of topology.value.devices) {
      const n = sim.node(other.id);
      if (!(n instanceof Host)) continue;
      for (const a of n.v6.globals) if ([...inet.delegations.keys()].some((p) => sameSubnet6(a.ip, p, Internet.PD_LENGTH))) publics.push({ ip: a.ip, name: `${other.name} (IPv6, NAT 없음)` });
    }
  }
  const go = () => {
    const dst = (inetDst || publics[0]?.ip || "").trim();
    const p = Math.min(65535, Math.max(1, Number(inetPort) || 80));
    if (!dst || !(validIp(dst) || isIpv6(dst))) return;
    sim.act({ kind: "inet-connect", nodeId: d.id, dst, port: p });
  };
  return (
    <Section title="외부에서 접속">
      <p class="note">인터넷 저편의 클라이언트(198.51.100.7, IPv6 는 2001:db8:beef::7)가 우리 공인 주소로 TCP 연결을 시도합니다. IPv4 는 포트 포워딩 규칙이 없으면 NAT 에서 드롭되고, IPv6 는 NAT 가 없어 집 안 장치의 주소로 바로 가므로 공유기의 IPv6 인바운드 기본 차단이 막습니다.</p>
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
        const conns = [...node.tcp.conns.values()].filter((c) => c.localIp === Internet.REMOTE_CLIENT || c.localIp === Internet.REMOTE_CLIENT6).slice(-3).reverse();
        if (conns.length === 0) return null;
        return (
          <ul class="ping-log tcp-log">
            {conns.map((c) => (
              <li key={c.id} class={c.state === "FAILED" ? "failed" : (c.state === "CLOSED" && c.bytesReceived > 0) || (c.ssh?.open && c.state === "ESTABLISHED") ? "ok" : ""}>
                <span class="mono">→ {endpoint(c.remoteIp, c.remotePort)}</span>
                <span>
                  {c.state === "FAILED"
                    ? `실패 · ${c.reason ?? ""}`
                    : c.state === "CLOSED"
                      ? `종료됨 · 받음 ${c.bytesReceived}B`
                      : c.ssh?.open && c.state === "ESTABLISHED"
                        ? "SSH 세션 열림"
                        : TCP_STATE_LABEL[c.state]}
                </span>
                {c.ssh && c.state === "ESTABLISHED" && (
                  <button class="btn ghost small" onClick={() => sim.act({ kind: "tcp-close", nodeId: d.id, conn: c.id })} title="FIN 을 보내 세션을 닫습니다">
                    연결 해제
                  </button>
                )}
              </li>
            ))}
          </ul>
        );
      })()}
    </Section>
  );
}

/** 인터넷 노드: ISP 가 고객의 공인 주소를 바꾼다 (FORCERENEW) — 가정용 회선의 주소가 바뀌는 순간 (DDNS 가 필요한 이유) */
export function IspRenumberSection({ d }: { d: Device }) {
  void simVersion.value;
  const node = sim.node(d.id);
  if (!(node instanceof Internet)) return null;
  const leases = [...node.dhcpServer.leases.entries()].map(([ip, l]) => {
    const owner = topology.value.devices.find((x) => {
      const n = sim.node(x.id);
      return n instanceof Router ? n.wan.mac === l.mac : n instanceof L3Node ? n.ifaces.some((f) => f.mac === l.mac) : n instanceof Host ? n.iface.mac === l.mac : false;
    });
    return { ip, name: owner?.name ?? l.mac };
  });
  return (
    <Section title="공인 주소 바꾸기">
      <p class="note">ISP 가 고객 회선의 공인 주소를 바꿉니다(DHCP FORCERENEW). 가정용 회선은 이렇게 주소가 바뀌어, 집으로 접속하려면 DDNS 이름을 씁니다.</p>
      {leases.length === 0 && <p class="note">자동(DHCP)으로 공인 주소를 받은 장치가 없습니다.</p>}
      {leases.map((l) => (
        <div key={l.ip} class="toggle-row">
          <span>
            {l.name} <span class="mono muted">{l.ip}</span>
          </span>
          <button class="btn ghost small" onClick={() => sim.act({ kind: "isp-renumber", nodeId: d.id, ip: l.ip })} title="이 고객에게 다른 공인 주소를 줍니다">
            주소 바꾸기
          </button>
        </div>
      ))}
    </Section>
  );
}

/** GoodCloud 관리 화면 흉내: 등록한 공유기를 열면 클라우드가 공유기가 연결해 둔 주소로 요청한다 */
export function CloudManageSection({ d }: { d: Device }) {
  void simVersion.value;
  const node = sim.node(d.id);
  if (!(node instanceof Internet) || node.cloud.devices.size === 0) return null;
  return (
    <Section title="GoodCloud 원격 관리">
      <p class="note">공유기가 먼저 클라우드에 연결해 둔 길로 요청이 들어갑니다 — 공유기의 관리 포트를 인터넷에 열지 않아도 됩니다.</p>
      {[...node.cloud.devices.entries()].map(([dev, x]) => (
        <div key={dev} class="toggle-row">
          <span>
            {x.name} <span class="mono muted">{x.lastStatus ? `WAN ${x.lastStatus.wan} · 기기 ${x.lastStatus.clients}대` : `${x.at.ip}:${x.at.port}`}</span>
          </span>
          <button class="btn ghost small" onClick={() => sim.act({ kind: "cloud-manage", nodeId: d.id, device: dev })} title="클라우드 화면에서 이 공유기를 엽니다">
            원격 관리
          </button>
        </div>
      ))}
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

/** DNS 조회 (nslookup): 이름·레코드 종류·물어볼 서버(비우면 설정된 DNS). 캐시를 거치지 않아 질의·응답이 매번 캔버스에 지나간다 */
function DnsLookup({ d, node }: { d: Device; node: Host }) {
  void simVersion.value; // 부모와 props 가 같아도 조회 기록이 바뀌면 다시 그린다
  const [name, setName] = useDiagField(d.id, "dns", "");
  const [server, setServer] = useDiagField(d.id, "dnsServer", "");
  const [qtype, setQtype] = useDiagField(d.id, "dnsType", "A");
  // 제안: DNS 서버 서비스를 켠 호스트의 주소·레코드 이름, 공유기의 DNS 포워더, 공인 DNS
  const servers: { ip: string; label: string }[] = [];
  const names = new Set<string>(PUBLIC_ZONE.map((r) => r.name));
  const mine = node.resolver.server;
  if (mine) servers.push({ ip: mine, label: "지금 설정된 DNS" });
  for (const other of topology.value.devices) {
    const n = sim.node(other.id);
    if (n instanceof Host && n.dnsServer.config.enabled) {
      if (n.ip) servers.push({ ip: n.ip, label: `${other.name} DNS 서버` });
      for (const r of n.dnsServer.config.records) names.add(r.name);
    }
    if (n instanceof Router && n.lan.ip && n.dnsForwarder.config.enabled) servers.push({ ip: n.lan.ip, label: `${other.name} DNS 포워더` });
  }
  servers.push({ ip: "8.8.8.8", label: "공인 DNS" }, { ip: "1.1.1.1", label: "공인 DNS" });
  const uniq = servers.filter((x, i) => servers.findIndex((y) => y.ip === x.ip) === i);
  const go = () => {
    const n = name.trim();
    if (!n) return;
    const sv = server.trim();
    sim.act({ kind: "dns-lookup", nodeId: d.id, name: n, qtype: qtype === "AAAA" ? "AAAA" : "A", ...(sv ? { server: sv } : {}) });
  };
  const enter = (e: KeyboardEvent) => e.key === "Enter" && go();
  return (
    <>
      <div class="ping-row dns-row">
        <input class="input mono" list={`dns-names-${d.id}`} value={name} placeholder="DNS 로 찾을 이름" onInput={(e) => setName(e.currentTarget.value)} onKeyDown={enter} />
        <datalist id={`dns-names-${d.id}`}>
          {[...names].map((n) => (
            <option key={n} value={n} />
          ))}
        </datalist>
        <select class="input qtype mono" value={qtype} onChange={(e) => setQtype(e.currentTarget.value as QType)} title="레코드 종류: A = IPv4 주소, AAAA = IPv6 주소">
          <option value="A">A</option>
          <option value="AAAA">AAAA</option>
        </select>
        <button class="btn" onClick={go} title="nslookup: 캐시를 거치지 않고 DNS 서버에 묻습니다 (답도 캐시에 넣지 않음)">
          조회
        </button>
      </div>
      <div class="ping-row dns-server-row">
        <input class="input mono" list={`dns-servers-${d.id}`} value={server} placeholder={mine ? `DNS 서버 (비우면 ${mine})` : "DNS 서버 (비우면 설정된 DNS)"} onInput={(e) => setServer(e.currentTarget.value)} onKeyDown={enter} title="이 서버에만 묻습니다 (nslookup 이름 서버)" />
        <datalist id={`dns-servers-${d.id}`}>
          {uniq.map((x) => (
            <option key={x.ip} value={x.ip}>
              {x.label}
            </option>
          ))}
        </datalist>
      </div>
      {node.lookups.length > 0 && (
        <ul class="ping-log dns-log">
          {node.lookups.slice().reverse().map((r) => (
            <li key={r.seq} class={r.status === "ok" && !r.blocked ? "ok" : r.status === "failed" || r.blocked ? "failed" : ""}>
              <span class="mono">
                {r.name} {r.qtype}
                {r.server && <small class="via">서버 {r.server}{r.magicDns ? " (MagicDNS)" : ""}</small>}
              </span>
              <span class={r.status === "ok" ? "mono" : undefined}>
                {r.status === "ok" ? (
                  <>
                    {/* IPv6 는 콜론 뒤에서만 줄을 바꾼다 (그룹 중간에서 끊기지 않게) */}
                    {r.answer!.split(":").map((g, i) => (
                      <Fragment key={i}>
                        {i > 0 && ":"}
                        {i > 0 && <wbr />}
                        {g}
                      </Fragment>
                    ))}
                    {r.blocked && " · 막은 이름"}
                  </>
                ) : r.status === "failed" ? (
                  `실패 · ${r.reason}`
                ) : (
                  "응답 기다리는 중"
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

/** 반복 ping(ping -c N): 마지막 실행의 진행·통계를 한 줄로 — 진행 중이면 항상, 끝났으면 마지막 ping 이 그 실행의 것일 때만 (첫 요청도 못 보내고 멈춘 실행은 그 실패 줄로 충분) */
function PingRunSummary({ node }: { node: Host }) {
  void simVersion.value; // 부모와 props 가 같아도 진행 상황이 바뀌면 다시 그린다 (LESSONS 4zi)
  const run = node.pingRuns.at(-1);
  if (!run || run.stopped || (run.done && node.pings.at(-1)?.run !== run.id)) return null;
  const recs = node.pings.filter((p) => p.run === run.id);
  const rx = recs.filter((p) => p.status === "ok").length;
  const s = run.stats;
  const text = s
    ? `${s.received}/${s.transmitted} 응답 · 손실 ${+s.loss.toFixed(1)}%${s.avg !== undefined ? ` · 평균 ${Math.round(s.avg * 10) / 10}ms` : ""}`
    : `${rx}/${run.sent} 응답 · ${run.count - run.sent}개 남음`;
  return (
    <li class={`ping-stats ${s ? (s.loss === 0 ? "ok" : "failed") : ""}`}>
      <span class="mono">
        {run.dst} · {run.count}회
      </span>
      <span>{text}</span>
    </li>
  );
}

/** P2P 연결: 상대 이름(다른 장치의 P2P 앱 이름)으로 연결하고 지금 상태를 한 줄로 */
function P2pDiag({ d, node, peer, setPeer }: { d: Device; node: Host; peer: string; setPeer: (v: string) => void }) {
  const names = topology.value.devices
    .filter((x) => x.id !== d.id && x.host?.p2p?.enabled)
    .map((x) => x.host!.p2p!.name?.trim() || x.name)
    .filter((n, i, all) => all.indexOf(n) === i);
  const go = () => {
    const name = peer.trim() || names[0];
    if (name) sim.act({ kind: "p2p-connect", nodeId: d.id, peer: name });
  };
  const s = node.p2p.session;
  const summary = node.p2p.summary();
  return (
    <>
      <div class="ping-row p2p-row">
        <input class="input mono" list={`p2p-peers-${d.id}`} value={peer} placeholder={names[0] ? `P2P 상대 이름 (예: ${names[0]})` : "P2P 상대 이름"} onInput={(e) => setPeer(e.currentTarget.value)} onKeyDown={(e) => e.key === "Enter" && go()} />
        <datalist id={`p2p-peers-${d.id}`}>
          {names.map((n) => (
            <option key={n} value={n} />
          ))}
        </datalist>
        <button class="btn" onClick={go} title="STUN 으로 내 바깥 주소 확인 → 시그널링 서버로 후보 교환 → 홀 펀칭 → 안 되면 TURN 릴레이">
          <Icon name="send" size={14} />
          P2P 연결
        </button>
      </div>
      {summary && (
        <ul class="ping-log">
          <li class={s?.phase === "connected" ? "ok" : s?.phase === "failed" ? "failed" : ""}>
            <span>{summary}</span>
          </li>
        </ul>
      )}
    </>
  );
}

/** ping, TCP 연결, DHCP 임대 갱신 */
/** 진단 입력값을 장치별로 기억 (다른 장치에 갔다 와도 마지막 값이 남는다) */
export const diagMemory = new Map<string, { ping?: string; tcp?: string; port?: string; inet?: string; inetPort?: string; p2p?: string; dns?: string; dnsServer?: string; dnsType?: string; pingCount?: string }>();

export function useDiagField(deviceId: string, key: "ping" | "tcp" | "port" | "inet" | "inetPort" | "p2p" | "dns" | "dnsServer" | "dnsType" | "pingCount", initial: string): [string, (v: string) => void] {
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
  const [pingCount, setPingCount] = useDiagField(d.id, "pingCount", "1");
  const [tcpDst, setTcpDst] = useDiagField(d.id, "tcp", "");
  const [tcpPort, setTcpPort] = useDiagField(d.id, "port", "80");
  const [p2pPeer, setP2pPeer] = useDiagField(d.id, "p2p", "");
  if (!(node instanceof Host)) return null;

  const okTarget = (v: string) => validIp(v) || isIpv6(v) || (looksLikeName(v) && /^[a-z0-9.-]+$/i.test(v));
  const send = () => {
    const dst = pingDst.trim();
    if (!dst || !okTarget(dst)) return;
    const count = Number(pingCount) || 1;
    sim.act({ kind: "ping", nodeId: d.id, dst, ...(count > 1 ? { count } : {}) });
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
        <select class="input count" value={pingCount} onChange={(e) => setPingCount(e.currentTarget.value)} title="보낼 횟수 (ping -c): 여러 번이면 1초 간격으로 보내고 끝나면 손실률·RTT 통계">
          <option value="1">1회</option>
          <option value="4">4회</option>
          <option value="10">10회</option>
        </select>
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
          <PingRunSummary node={node} />
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
                if (n instanceof Host) return n.ip === h.ip || n.v6.owns(h.ip!);
                if (n instanceof Router) return n.lan.ip === h.ip || n.wan.ip === h.ip;
                if (n instanceof L3Node) return n.ifaces.some((f) => f.ip === h.ip) || n.v6.some((v) => v.owns(h.ip!));
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
      <DnsLookup d={d} node={node} />
      <div class="ping-row tcp-row">
        <TargetPicker value={tcpDst} onInput={setTcpDst} onSubmit={connect} placeholder="서버 주소 또는 이름" load={() => probeTargetsCached(topology.peek(), d.id, "tcp", port)} />
        <input class="input mono port" type="number" min={1} max={65535} value={tcpPort} onInput={(e) => setTcpPort(e.currentTarget.value)} title="포트" />
        <button class="btn" onClick={connect} title={port === 22 ? "SSH 접속 (3-way handshake → 버전·키 교환·인증 → 세션을 열어 둠)" : port === 443 ? "HTTPS 연결 (3-way handshake → TLS 핸드셰이크 → 암호화된 요청·응답 → 종료)" : "TCP 연결 (3-way handshake → 요청 → 응답 → 종료)"}>
          <Icon name="send" size={14} />
          {port === 22 ? "SSH 접속" : port === 443 ? "HTTPS 연결" : "연결"}
        </button>
      </div>
      {(() => {
        const clients = [...node.tcp.conns.values()].filter((c) => c.role === "client" && !c.probe);
        // 열린 SSH 세션은 오래됐어도 항상 보인다 (연결 해제 버튼)
        const open = clients.filter((c) => c.ssh && c.state !== "CLOSED" && c.state !== "FAILED");
        const conns = [...open, ...clients.filter((c) => !open.includes(c)).slice(-3).reverse()];
        if (conns.length === 0) return null;
        return (
          <ul class="ping-log tcp-log">
            {conns.map((c) => {
              // 4xx·5xx: 연결은 됐지만 요청이 실패 (프록시 차단 403, 백엔드·대상 문제 502·503)
              const httpErr = /^HTTP [45]/.test(c.status ?? "");
              const cookie = c.setCookie ? ` · 쿠키 받음` : c.cookie ? ` · 쿠키 보냄` : "";
              return (
                <li key={c.id} class={c.state === "FAILED" || httpErr ? "failed" : (c.state === "CLOSED" && c.bytesReceived > 0) || (c.ssh?.open && c.state === "ESTABLISHED") ? "ok" : ""} title={c.setCookie ? `Set-Cookie: ${c.setCookie}` : c.cookie ? `Cookie: ${c.cookie}` : undefined}>
                  <span class="mono" title={c.target ? `프록시 ${c.remoteIp}:${c.remotePort} 경유` : undefined}>
                    {c.target ?? endpoint(c.remoteIp, c.remotePort)}
                    {c.target && <small class="via">프록시 경유</small>}
                  </span>
                  <span>
                    {c.state === "FAILED"
                      ? `실패 · ${c.reason ?? ""}`
                      : httpErr
                        ? `${c.status}${c.servedBy ? ` · ${c.servedBy}` : ""}`
                        : c.state === "CLOSED"
                          ? `종료됨 · 받음 ${c.bytesReceived}B${c.servedBy ? ` · 응답 ${c.servedBy}` : ""}${cookie}`
                          : c.ssh?.open && c.state === "ESTABLISHED"
                            ? "SSH 세션 열림"
                            : c.ssh && c.state === "ESTABLISHED"
                              ? `SSH 키 교환 중 (${c.ssh.step}/6)`
                              : c.tunnel === "wait" && c.state === "ESTABLISHED"
                                ? "CONNECT 응답 대기"
                                : c.tls && !c.tls.done && c.state === "ESTABLISHED"
                                  ? "TLS 핸드셰이크 중"
                                  : TCP_STATE_LABEL[c.state]}
                  </span>
                  {c.ssh && c.state === "ESTABLISHED" && (
                    <button class="btn ghost small" onClick={() => sim.act({ kind: "tcp-close", nodeId: d.id, conn: c.id })} title="FIN 을 보내 세션을 닫습니다">
                      연결 해제
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        );
      })()}
      {node.p2p.config.enabled && <P2pDiag d={d} node={node} peer={p2pPeer} setPeer={setP2pPeer} />}
      <p class="note">
        TCP 연결은 3-way handshake 뒤 "GET /" 요청을 보내고, 서버 응답 3세그먼트를 받은 다음 FIN 으로 닫습니다. 포트 443 은 HTTPS 로, TLS 핸드셰이크 뒤 같은 요청·응답을 암호화해 주고받습니다. 포트 22 는 SSH 로, 키 교환·인증 뒤 세션을 열어 둡니다 — 그 사이 경로를 바꿔 보고 "연결 해제" 로 닫아 보세요. 자세한 기록은 "표" 탭의 TCP 연결 표와 로그에서 봅니다.
      </p>
      {node.ipMode === "dhcp" && (
        <button class="btn wide" onClick={() => sim.act({ kind: "dhcp-renew", nodeId: d.id })} disabled={!node.linkUp}>
          <Icon name="refresh" size={14} />
          DHCP 임대 갱신
        </button>
      )}
    </Section>
  );
}
