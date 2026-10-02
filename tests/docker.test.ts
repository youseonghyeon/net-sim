// 도커 네트워크 (맥의 Docker Desktop 구조) + 게이트웨이 NAT 켜기 + 포트 공개(docker -p 식 FULLNAT)
import { describe, expect, it } from "vitest";
import { lintTopology } from "../src/model/lint";
import { loadTopology } from "./helpers";
import { exampleDockerTopology, exampleTwoGatewaysTopology } from "../src/model/examples";
import type { Topology } from "../src/model/topology";
import type { L3Node } from "../src/core/nodes/l3";
import { practitionerLines } from "../src/model/packetView";
import { serviceBadgesOf } from "../src/model/status";

const load = (t: Topology = exampleDockerTopology()) => loadTopology(t);
const patchL3 = (t: Topology, name: string, f: (l3: NonNullable<Topology["devices"][number]["l3"]>) => NonNullable<Topology["devices"][number]["l3"]>): Topology => ({
  ...t,
  devices: t.devices.map((d) => (d.name === name ? { ...d, l3: f(d.l3!) } : d)),
});

describe("도커 네트워크 (Docker Desktop)", () => {
  it("구성 검사 이슈가 없고, macOS·Docker VM 은 NAT 를 켠 게이트웨이다", () => {
    const { t, node } = load();
    expect(lintTopology(t)).toEqual([]);
    expect(node<L3Node>("macOS").nat).toBeDefined();
    expect(node<L3Node>("Docker VM").outside).toBe(0);
    expect(serviceBadgesOf(node("Docker VM"))).toContain("NAT");
  });

  it("맥 터미널 → 127.0.0.1:8080 (localhost): macOS 포트 공개 → Docker VM 포트 공개 → web:80. web 은 브리지 게이트웨이가 연 연결로 본다", () => {
    const x = load();
    const tr = x.act({ kind: "tcp-connect", nodeId: x.id("맥 터미널"), dst: "127.0.0.1", port: 8080 });
    expect(x.lastConn("맥 터미널")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    expect(x.serverConns("web").at(-1)!.remoteIp).toBe("172.18.0.1");
    const pub = tr.filter((e) => e.kind === "port.publish" && !e.details?.back).map((e) => x.t.devices.find((d) => d.id === e.nodeId)!.name);
    expect(pub).toEqual(["macOS", "Docker VM"]);
    // 실무 출력: docker-proxy 프로세스 줄
    const first = tr.find((e) => e.kind === "port.publish" && e.nodeId === x.id("Docker VM"))!;
    expect(practitionerLines(first, {}).map((l) => l.line)).toContain("docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8080 -container-ip 172.18.0.2 -container-port 80");
  });

  it("맥 터미널 → 172.18.0.2 ping 은 실패: 컨테이너 대역은 VM 안이라 맥에는 경로가 없어 인터넷 쪽으로 나가 버려진다", () => {
    const x = load();
    const tr = x.act({ kind: "ping", nodeId: x.id("맥 터미널"), dst: "172.18.0.2" });
    expect(x.host("맥 터미널").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.kind === "ip.drop" && e.summary.includes("사설 주소 172.18.0.2 는 인터넷에서 라우팅되지 않음"))).toBe(true);
  });

  it("집 PC → 맥 주소:8080 은 되고, :5432 는 맥의 127.0.0.1 에만 공개돼 RST 로 거부된다. 맥 터미널의 127.0.0.1:5432 는 db 로", () => {
    const x = load();
    const mac = x.node<L3Node>("macOS").ifaces[0]!.ip!;
    x.act({ kind: "tcp-connect", nodeId: x.id("집 PC"), dst: mac, port: 8080 });
    expect(x.lastConn("집 PC")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    const tr = x.act({ kind: "tcp-connect", nodeId: x.id("집 PC"), dst: mac, port: 5432 });
    expect(x.lastConn("집 PC")).toMatchObject({ state: "FAILED", reason: "연결 거부 (RST)" });
    expect(tr.some((e) => e.kind === "port.publish" && e.summary.includes("127.0.0.1 에만 공개됨"))).toBe(true);
    x.act({ kind: "tcp-connect", nodeId: x.id("맥 터미널"), dst: "127.0.0.1", port: 5432 });
    expect(x.lastConn("맥 터미널")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
    expect(x.serverConns("db").at(-1)!.remoteIp).toBe("172.18.0.1");
  });

  it("사용자 정의 브리지의 web 은 db 를 이름으로 찾고(내장 DNS), 인터넷은 VM → 맥 → 공유기 NAT 세 번", () => {
    const x = load();
    x.act({ kind: "ping", nodeId: x.id("web"), dst: "db" });
    expect(x.host("web").pings.at(-1)).toMatchObject({ status: "ok", resolved: "172.18.0.3" });
    const tr = x.act({ kind: "ping", nodeId: x.id("web"), dst: "google.com" });
    expect(x.host("web").pings.at(-1)!.status).toBe("ok");
    const nat = tr.filter((e) => e.kind === "nat.translate" && e.summary.includes("ICMP")).map((e) => x.t.devices.find((d) => d.id === e.nodeId)!.name);
    expect(nat).toEqual(["Docker VM", "macOS", "집 공유기"]);
  });

  it("기본 브리지의 old-app: 이름으로는 못 찾고(NXDOMAIN), 다른 브리지로는 못 가며(DOCKER-ISOLATION), 인터넷은 된다", () => {
    const x = load();
    x.act({ kind: "ping", nodeId: x.id("old-app"), dst: "web" });
    expect(x.host("old-app").pings.at(-1)).toMatchObject({ status: "failed", reason: "없는 이름" });
    const tr = x.act({ kind: "ping", nodeId: x.id("old-app"), dst: "172.18.0.2" });
    expect(x.host("old-app").pings.at(-1)!.status).toBe("failed");
    expect(tr.some((e) => e.nodeId === x.id("Docker VM") && e.kind === "fw.deny")).toBe(true);
    x.act({ kind: "ping", nodeId: x.id("old-app"), dst: "google.com" });
    expect(x.host("old-app").pings.at(-1)!.status).toBe("ok");
  });

  it("공개 포트의 연결이 끝나면 2초 뒤 같은 클라이언트 포트로 다시 연결해도 새 흐름으로 이어진다 (TIME_WAIT 뒤 정리)", () => {
    const x = load();
    for (let i = 0; i < 3; i++) {
      x.act({ kind: "tcp-connect", nodeId: x.id("맥 터미널"), dst: "127.0.0.1", port: 8080 });
      expect(x.lastConn("맥 터미널")).toMatchObject({ state: "CLOSED", bytesReceived: 3000 });
      x.s.net.runUntil(x.s.net.now + 3000);
    }
    expect(x.node<L3Node>("Docker VM").publish.rows()[0]).toEqual(["0.0.0.0:8080", "172.18.0.2:80", "-"]);
  });

  it("포트 공개 대상으로 가는 경로가 없으면 No route 로 드롭 (클라이언트는 timeout)", () => {
    const t = patchL3(exampleDockerTopology(), "Docker VM", (l3) => ({ ...l3, publish: [{ port: 8080, bind: "0.0.0.0", to: "10.9.9.9", toPort: 80 }] }));
    const x = load(t);
    const tr = x.act({ kind: "tcp-connect", nodeId: x.id("맥 터미널"), dst: "127.0.0.1", port: 8080 });
    expect(x.lastConn("맥 터미널").state).toBe("FAILED");
    expect(tr.some((e) => e.nodeId === x.id("Docker VM") && e.kind === "port.publish" && e.summary.includes("10.9.9.9:80"))).toBe(true);
  });
});

describe("게이트웨이 NAT 켜기", () => {
  it("실행 중에 켜고 끈다: 켜면 안쪽 출발지를 if0 주소로 바꾸고, 끄면 그대로 라우팅", () => {
    // 게이트웨이 2단 예제의 gw-1 (if0 이 NAT 박스 쪽 10.0.0.0/24) 에 NAT 를 켜 본다
    const base = exampleTwoGatewaysTopology();
    const x = load(base);
    const pc = x.t.devices.find((d) => d.name === "pc-1")!.id;
    const gw = x.node<L3Node>("gw-1");
    expect(gw.nat).toBeUndefined();
    const on = patchL3(base, "gw-1", (l3) => ({ ...l3, nat: { enabled: true } }));
    const tr1 = x.apply(on);
    expect(tr1.some((e) => e.summary.startsWith("NAT 켜짐 (MASQUERADE)"))).toBe(true);
    const tr2 = x.act({ kind: "ping", nodeId: pc, dst: "8.8.8.8" });
    expect(x.host("pc-1").pings.at(-1)!.status).toBe("ok");
    expect(tr2.some((e) => e.nodeId === x.id("gw-1") && e.kind === "nat.translate")).toBe(true);
    // 끄면 NAT 하지 않는다
    const tr3 = x.apply(base);
    expect(tr3.some((e) => e.summary.startsWith("NAT 꺼짐"))).toBe(true);
    const tr4 = x.act({ kind: "ping", nodeId: pc, dst: "8.8.8.8" });
    expect(x.host("pc-1").pings.at(-1)!.status).toBe("ok");
    expect(tr4.some((e) => e.nodeId === x.id("gw-1") && e.kind === "nat.translate")).toBe(false);
  });

  it("NAT 를 켠 게이트웨이 뒤 대역은 위쪽 장비에 돌아오는 경로가 없어도 구성 검사가 지적하지 않는다 (NAT 박스와 같다)", () => {
    const base = exampleTwoGatewaysTopology();
    const noReturn = patchL3(base, "nat-1", (l3) => ({ ...l3, routes: [] }));
    expect(lintTopology(noReturn).length).toBeGreaterThan(0);
    const withNat = patchL3(patchL3(noReturn, "gw-1", (l3) => ({ ...l3, nat: { enabled: true } })), "gw-2", (l3) => ({ ...l3, nat: { enabled: true } }));
    expect(lintTopology(withNat).filter((i) => i.deviceId === withNat.devices.find((d) => d.name === "nat-1")!.id)).toEqual([]);
  });
});
