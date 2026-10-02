// 리뷰 재현: 게이트웨이 NAT 켜기 + 포트 공개(docker -p, nodes/publish.ts) + 예제 정리 (d0730c5..a0e1ab5).
// 각 it 는 그때 실패하던 결함 하나를 고정한다 (관찰은 고치기 전 동작, 기대는 expect). 결함 8 은 고친 방식(드롭 + 이유)에 맞춰 단언을 옮겼다.
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { lintTopology } from "../src/model/lint";
import { exampleDockerTopology, examplePublishTopology, exampleRipTopology, exampleVpnTopology } from "../src/model/examples";
import { createDevice, type Device, type FirewallSettings, type L3Settings, type Topology } from "../src/model/topology";

const patchL3 = (t: Topology, name: string, f: (l3: L3Settings) => L3Settings): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.name === name ? { ...d, l3: f(d.l3!) } : d)),
});
const patchDev = (t: Topology, name: string, f: (d: Device) => Device): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? f(d) : d)) });

describe("포트 공개 (PortPublish)", () => {
  it("결함 1: 규칙을 지워도 진행 중인 흐름은 그대로 둔다고 했지만, 클라이언트 쪽 세그먼트가 더는 넘어가지 않는다", () => {
    // Docker VM 이 22 → web:22 를 공개, 맥 터미널이 VM 주소:22 로 SSH 세션을 연 뒤 규칙을 지우고 연결 해제
    let t = exampleDockerTopology();
    t = patchDev(t, "web", (d) => ({ ...d, host: { ...d.host!, services: [80, 22] } }));
    t = patchL3(t, "Docker VM", (l3) => ({ ...l3, publish: [...(l3.publish ?? []), { port: 22, bind: "0.0.0.0", to: "172.18.0.2", toPort: 22 }] }));
    const x = loadTopology(t);
    x.act({ kind: "tcp-connect", nodeId: x.id("맥 터미널"), dst: "192.168.64.2", port: 22 });
    const conn = x.lastConn("맥 터미널");
    expect(conn).toMatchObject({ state: "ESTABLISHED", ssh: { open: true } });
    x.apply(patchL3(t, "Docker VM", (l3) => ({ ...l3, publish: (l3.publish ?? []).filter((r) => r.port !== 22) })));
    const tr = x.act({ kind: "tcp-close", nodeId: x.id("맥 터미널"), conn: conn.id });
    // 관찰: Docker VM 이 FIN 을 "NAT 테이블에 없는 TCP 포트 22 → 드롭" 으로 버리고, 클라이언트는 FIN 재전송 3회 뒤 timeout,
    //       web 쪽 세션은 ESTABLISHED 로 영원히 남는다
    expect(tr.some((e) => e.nodeId === x.id("Docker VM") && e.kind === "nat.miss")).toBe(false);
    expect(x.lastConn("맥 터미널").state).toBe("CLOSED");
    expect(x.serverConns("web").at(-1)!.state).toBe("CLOSED");
  });

  it("결함 2: 공개한 장비의 방화벽(기본 차단 + Stateful + 인바운드 TCP 80 허용)에서 포트 포워딩은 되지만 포트 공개는 응답이 막힌다", () => {
    // 회사 NAT 에 같은 방화벽: 공인 :80 은 포트 포워딩, :8080 은 포트 공개 — 둘 다 웹 서버 192.168.1.2:80 으로
    const fw: FirewallSettings = {
      enabled: true,
      defaultPolicy: "deny",
      stateful: true,
      rules: [{ action: "allow", proto: "tcp", direction: "in", src: "", dst: "", dstPort: "80" }],
    };
    const t = patchL3(examplePublishTopology(), "회사 NAT", (l3) => ({ ...l3, firewall: fw, publish: [{ port: 8080, bind: "0.0.0.0", to: "192.168.1.2", toPort: 80 }] }));
    const x = loadTopology(t);
    x.act({ kind: "tcp-connect", nodeId: x.id("맥북"), dst: "203.0.113.109", port: 80 });
    expect(x.lastConn("맥북")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 }); // 포트 포워딩: 응답은 Stateful 로 통과
    const tr = x.act({ kind: "tcp-connect", nodeId: x.id("맥북"), dst: "203.0.113.109", port: 8080 });
    // 관찰: SYN 은 규칙 1 로 허용되지만, 되돌린 SYN·ACK(203.0.113.109:8080 → 클라이언트)를 "아웃바운드 … 기본 정책 차단" 으로 드롭
    //       (Stateful 이 기억한 흐름은 바꾼 뒤의 10.10.0.1:61000 → 192.168.1.2:80 이라 역방향 키가 맞지 않음) → SYN timeout
    expect(tr.some((e) => e.nodeId === x.id("회사 NAT") && e.kind === "fw.deny")).toBe(false);
    expect(x.lastConn("맥북")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
  });

  it("결함 3: 다른 주소에만 공개된 포트로 온 SYN 에 보내는 RST(Connection refused)가 방화벽 '인바운드' 기본 차단에 걸려 클라이언트는 timeout", () => {
    // 흔한 NAT 방화벽(아웃바운드만 허용 + Stateful). 8080 은 안쪽 주소 10.10.0.1 에만 공개
    const fw: FirewallSettings = {
      enabled: true,
      defaultPolicy: "deny",
      stateful: true,
      rules: [{ action: "allow", proto: "any", direction: "out", src: "", dst: "", dstPort: "" }],
    };
    const t = patchL3(examplePublishTopology(), "회사 NAT", (l3) => ({ ...l3, firewall: fw, publish: [{ port: 8080, bind: "10.10.0.1", to: "192.168.1.2", toPort: 80 }] }));
    const x = loadTopology(t);
    const tr = x.act({ kind: "tcp-connect", nodeId: x.id("맥북"), dst: "203.0.113.109", port: 8080 });
    expect(tr.some((e) => e.kind === "port.publish" && e.summary.includes("10.10.0.1 에만 공개됨"))).toBe(true);
    // 관찰: 장비가 만든 RST 를 forward() 로 보내 FORWARD 방화벽이 "인바운드 TCP 203.0.113.109:8080 → 203.0.113.108:… 기본 정책 차단" 으로 드롭
    expect(tr.some((e) => e.nodeId === x.id("회사 NAT") && e.kind === "fw.deny" && e.summary.includes("TCP 203.0.113.109:8080 →"))).toBe(false);
    expect(x.lastConn("맥북")).toMatchObject({ state: "FAILED", reason: "연결 거부 (RST)" });
  });

  it("결함 4: 맺어지지 못한 연결(대상 다운)의 흐름이 영원히 남아 프록시 포트가 새고, 1000번 뒤에는 대상이 돌아와도 공개 포트가 죽는다", () => {
    const base = exampleDockerTopology();
    const webId = base.devices.find((d) => d.name === "web")!.id;
    const noWeb: Topology = { ...base, cables: base.cables.filter((c) => c.a.device !== webId && c.b.device !== webId) };
    const x = loadTopology(noWeb);
    for (let i = 0; i < 1000; i++) {
      x.s.net.scheduleAction(x.s.net.now, { kind: "tcp-connect", nodeId: x.id("맥 터미널"), dst: "127.0.0.1", port: 8080 });
      x.s.net.runToIdle();
    }
    // 관찰: 클라이언트는 모두 포기했는데 표는 ['0.0.0.0:8080', '192.168.64.2:8080', '연결 1000']
    expect(x.l3("macOS").publish.rows()[0]![2]).toBe("-");
    x.apply(base); // web 케이블을 되돌림
    const tr = x.act({ kind: "tcp-connect", nodeId: x.id("맥 터미널"), dst: "127.0.0.1", port: 8080 });
    // 관찰: macOS "포트 공개: 프록시 포트가 모두 쓰이는 중 → 드롭" 으로 timeout
    expect(tr.some((e) => e.summary.includes("프록시 포트가 모두 쓰이는 중"))).toBe(false);
    expect(x.lastConn("맥 터미널")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
  });

  it("결함 5: NAT 가 동적으로 고른 공인 포트가 공개 포트와 같으면, 안쪽에서 나간 연결의 응답을 포트 공개가 가로채 드롭", () => {
    const base = exampleDockerTopology();
    const probe = loadTopology(base);
    probe.act({ kind: "tcp-connect", nodeId: probe.id("web"), dst: "google.com", port: 80 });
    expect(probe.lastConn("web")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    const used = [...probe.l3("Docker VM").nat!.entries.values()].find((e) => e.proto === "tcp")!.publicId; // 40001
    // 같은 구성에 그 포트를 공개 (docker run -p 40001:5432 db). NAT 는 포트 포워딩 포트는 건너뛰지만 공개 포트는 모른다
    const t = patchL3(base, "Docker VM", (l3) => ({ ...l3, publish: [...(l3.publish ?? []), { port: used, bind: "0.0.0.0", to: "172.18.0.3", toPort: 5432 }] }));
    const x = loadTopology(t);
    const tr = x.act({ kind: "tcp-connect", nodeId: x.id("web"), dst: "google.com", port: 80 });
    // 관찰: Docker VM "포트 공개 192.168.64.2:40001 로 온 세그먼트지만 진행 중인 연결이 아님 (SYN 없음) → 드롭" → web 은 SYN timeout
    expect(tr.some((e) => e.nodeId === x.id("Docker VM") && e.summary.includes("진행 중인 연결이 아님"))).toBe(false);
    expect(x.lastConn("web")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
  });

  it("결함 6: '장비 자신의 어느 주소로 와도' 받는다지만, VPN 터널로 풀려 온 TCP 는 포트 공개를 거치지 않고 드롭", () => {
    const t = patchL3(exampleVpnTopology(), "사무실 B NAT", (l3) => ({ ...l3, publish: [{ port: 8080, bind: "0.0.0.0", to: "192.168.2.20", toPort: 80 }] }));
    const x = loadTopology(t);
    x.act({ kind: "tcp-connect", nodeId: x.id("pc-b"), dst: "192.168.2.1", port: 8080 }); // 같은 사무실: 된다
    expect(x.lastConn("pc-b")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    x.act({ kind: "tcp-connect", nodeId: x.id("pc-a"), dst: "192.168.2.20", port: 80 }); // 터널 너머 직접: 된다
    expect(x.lastConn("pc-a")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    const tr = x.act({ kind: "tcp-connect", nodeId: x.id("pc-a"), dst: "192.168.2.1", port: 8080 });
    // 관찰: 사무실 B NAT "터널로 온 TCP 가 나에게 왔지만 듣는 서비스 없음 → 드롭" (TunnelEnds.deliver 가 ICMP 만 장치에 넘김)
    expect(tr.some((e) => e.summary.includes("터널로 온 TCP 가 나에게 왔지만"))).toBe(false);
    expect(x.lastConn("pc-a")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
  });

  it("결함 8: 공개로 넘긴 패킷의 TTL 이 다하면 Time Exceeded 를 장비 자신에게 보내 자기 주소를 ARP 로 묻는다 (공개 규칙 순환)", () => {
    // 잘못된 구성: macOS 9000 → VM:9000, VM 9000 → macOS:9000 (서로 넘김). TTL 로 끝나는 것은 맞다
    let t = exampleDockerTopology();
    t = patchL3(t, "macOS", (l3) => ({ ...l3, publish: [...(l3.publish ?? []), { port: 9000, bind: "0.0.0.0", to: "192.168.64.2", toPort: 9000 }] }));
    t = patchL3(t, "Docker VM", (l3) => ({ ...l3, publish: [...(l3.publish ?? []), { port: 9000, bind: "0.0.0.0", to: "192.168.64.1", toPort: 9000 }] }));
    const x = loadTopology(t);
    const tr = x.act({ kind: "tcp-connect", nodeId: x.id("맥 터미널"), dst: "127.0.0.1", port: 9000 });
    // 결정: 포트 공개가 다시 연 연결은 출발지가 나 자신이라 Time Exceeded 를 보내지 않고, 이유를 남기고 드롭한다
    expect(tr.some((e) => e.kind === "ip.drop" && e.summary.includes("TTL 이 다함") && e.summary.includes("순환"))).toBe(true);
    // 관찰: Docker VM "ARP 요청 브로드캐스트: "192.168.64.2 의 MAC은?" (나는 192.168.64.2 …)" — 통지의 목적지가 자기 주소(바꾼 패킷의 출발지)
    const selfArp = tr.filter((e) => e.kind === "arp.request.sent" && e.nodeId === x.id("Docker VM") && e.summary.includes('"192.168.64.2 의 MAC은?"'));
    expect(selfArp).toEqual([]);
  });
});

describe("게이트웨이 NAT 켜기", () => {
  it("결함 7: 실행 중에 NAT 를 켜면 if0 이 RIP 에서 빠지지만 이웃에게 철회하지 않아, 이웃이 옛 경로로 보내 NAT outside 에서 드롭 (처음부터 켠 구성은 된다)", () => {
    const base = exampleRipTopology();
    const natOnB = patchL3(base, "gw-b", (l3) => ({ ...l3, nat: { enabled: true } }));
    const fresh = loadTopology(natOnB);
    fresh.act({ kind: "ping", nodeId: fresh.id("pc-a"), dst: "192.168.2.10" });
    expect(fresh.host("pc-a").pings.at(-1)!.status).toBe("ok"); // gw-a 는 192.168.2.0/24 를 gw-c 경유(2홉)로 안다

    const x = loadTopology(base);
    x.apply(natOnB);
    // 관찰: gw-a 에 "192.168.2.0/24 via 10.0.12.2 m1" 이 남고, ping 은 gw-b "[if0] 목적지 192.168.2.10 는 내 공인 주소가 아님 → 드롭" 으로 실패
    expect(x.l3("gw-a").rip.rows().find((r) => r.dest === "192.168.2.0")?.nextHop).toBe("10.0.13.3");
    x.act({ kind: "ping", nodeId: x.id("pc-a"), dst: "192.168.2.10" });
    expect(x.host("pc-a").pings.at(-1)!.status).toBe("ok");
  });

  it("결함 9: 구성 검사 vpn 상대 추적이 NAT 를 끈 게이트웨이의 (남아 있는) 포트 포워딩도 따라가 침묵 — 실제로는 터널이 안 맺어진다", () => {
    // 사무실 B 앞을 NAT 박스 대신 게이트웨이로: UDP 51820 → 뒤의 VPN 게이트웨이. NAT 를 켰다 끄면 포워딩 규칙은 모델에 남는다(UI 는 숨김)
    const base = exampleVpnTopology();
    const build = (nat: boolean): Topology => {
      const devices: Device[] = base.devices.map((d) =>
        d.name === "사무실 B NAT"
          ? {
              ...d,
              kind: "gateway",
              l3: {
                interfaces: [d.l3!.interfaces[0]!, { ipMode: "static", ip: "10.0.0.1", prefix: 24, gateway: "" }, { ipMode: "static", ip: "", prefix: 24, gateway: "" }],
                routes: [{ dest: "192.168.2.0", prefix: 24, via: "10.0.0.2" }],
                nat: { enabled: nat },
                forwards: [{ publicPort: 51820, lanIp: "10.0.0.2", lanPort: 51820, proto: "udp" }],
              },
            }
          : d,
      );
      const gw = createDevice("gateway", 640, 128, devices);
      gw.name = "vpn-gw-b";
      gw.l3 = {
        interfaces: [
          { ipMode: "static", ip: "10.0.0.2", prefix: 24, gateway: "10.0.0.1" },
          { ipMode: "static", ip: "192.168.2.1", prefix: 24, gateway: "" },
          { ipMode: "static", ip: "", prefix: 24, gateway: "" },
        ],
        routes: [],
        vpn: { enabled: true, peer: "203.0.113.11", remote: [{ dest: "192.168.1.0", prefix: 24 }] },
      };
      devices.push(gw);
      const front = devices.find((d) => d.name === "사무실 B NAT")!;
      const swB = devices.find((d) => d.name === "sw-b")!;
      const cables = base.cables.filter((c) => !(c.a.device === front.id && c.b.device === swB.id));
      cables.push({ id: "c-front-gw", a: { device: front.id, port: 1 }, b: { device: gw.id, port: 0 } }, { id: "c-gw-sw", a: { device: gw.id, port: 1 }, b: { device: swB.id, port: 3 } });
      return { devices, cables };
    };
    const on = loadTopology(build(true));
    on.act({ kind: "ping", nodeId: on.id("pc-a"), dst: "192.168.2.10" });
    expect(on.host("pc-a").pings.at(-1)!.status).toBe("ok"); // NAT 켜짐: 포워딩으로 터널이 이어진다

    const off = build(false);
    const x = loadTopology(off);
    x.act({ kind: "ping", nodeId: x.id("pc-a"), dst: "192.168.2.10" });
    expect(x.host("pc-a").pings.at(-1)!.status).toBe("failed"); // NAT 꺼짐: 포워딩을 하지 않아 터널 패킷이 앞 게이트웨이에서 버려진다
    // 관찰: [] — lint/vpn.ts 는 natOn 없이 l3.forwards 를 따라가 뒤의 VPN 게이트웨이를 상대로 본다
    expect(lintTopology(off).map((i) => i.code)).toContain("vpn.peer-off");
  });
});
