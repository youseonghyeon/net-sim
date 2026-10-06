// 리뷰 (8798d3e Samba·IGMP 스누핑): 결함 재현 — 실패해야 하는 테스트
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleIgmpTopology, examplePartsTopology, exampleRipTopology, exampleWireguardTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import { createDevice, newId, type Topology, type RouterSettings } from "../src/model/topology";

const G = "239.1.1.1";
const snoop = (t: Topology, on: boolean): Topology => ({ ...t, devices: t.devices.map((d) => (d.kind === "switch" ? { ...d, switch: { ...d.switch!, igmpSnooping: on } } : d)) });
const rxOf = (L: ReturnType<typeof loadTopology>, name: string) => L.host(name).streamRx.get(G) ?? 0;

/** 거실 TV 자리에 허브를 두고 그 뒤에 TV 두 대 */
function hubTopology(): Topology {
  const t = exampleIgmpTopology();
  const sw = t.devices.find((d) => d.name === "거실 스위치")!;
  const tv = t.devices.find((d) => d.name === "거실 TV")!;
  const hub = createDevice("hub", 272, 300, t.devices);
  hub.name = "허브";
  t.devices.push(hub);
  const tv2 = createDevice("pc", 272, 400, t.devices);
  tv2.name = "안방 TV";
  t.devices.push(tv2);
  t.cables = t.cables.filter((c) => c.a.device !== tv.id && c.b.device !== tv.id);
  t.cables.push(
    { id: newId("cable"), a: { device: sw.id, port: 3 }, b: { device: hub.id, port: 0 } },
    { id: newId("cable"), a: { device: hub.id, port: 1 }, b: { device: tv.id, port: 0 } },
    { id: newId("cable"), a: { device: hub.id, port: 2 }, b: { device: tv2.id, port: 0 } },
  );
  return t;
}

describe("IGMP 스누핑 리뷰", () => {
  it("TV 가 가입한 뒤에 스누핑을 켜면, 가입한 TV 가 스트림을 받지 못한다 (스누핑 켤 때 그룹 표를 비우고 다시 배울 길이 없음)", () => {
    const L = loadTopology(exampleIgmpTopology());
    L.act({ kind: "mcast-join", nodeId: L.id("거실 TV"), group: G });
    L.apply(snoop(L.t, true));
    expect(L.host("거실 TV").groups.has(G)).toBe(true); // 전제: TV 는 가입한 채
    const before = rxOf(L, "거실 TV");
    L.act({ kind: "mcast-send", nodeId: L.id("IPTV 서버"), group: G });
    expect(rxOf(L, "거실 TV") - before).toBe(5);
  });

  it("허브 뒤 TV 두 대 중 한 대가 탈퇴하면 남은 TV 도 스트림을 잃는다 (쿼리어 없이 Leave 한 번에 포트를 뺌)", () => {
    const L = loadTopology(snoop(hubTopology(), true));
    L.act({ kind: "mcast-join", nodeId: L.id("거실 TV"), group: G });
    L.act({ kind: "mcast-join", nodeId: L.id("안방 TV"), group: G });
    L.act({ kind: "mcast-send", nodeId: L.id("IPTV 서버"), group: G });
    expect([rxOf(L, "거실 TV"), rxOf(L, "안방 TV")]).toEqual([5, 5]); // 전제: 둘 다 받는다
    L.act({ kind: "mcast-leave", nodeId: L.id("거실 TV"), group: G });
    const before = rxOf(L, "안방 TV");
    L.act({ kind: "mcast-send", nodeId: L.id("IPTV 서버"), group: G });
    expect(rxOf(L, "안방 TV") - before).toBe(5);
  });

  it("스위치 두 대 일렬: 아래 스위치의 TV 하나가 탈퇴하면 위 스위치가 업링크 포트를 빼 같은 아래 스위치의 다른 TV 도 잃는다", () => {
    const t = snoop(exampleIgmpTopology(), true);
    const sw = t.devices.find((d) => d.name === "거실 스위치")!;
    const tv = t.devices.find((d) => d.name === "거실 TV")!;
    const pc = t.devices.find((d) => d.name === "안방 PC")!;
    const sw2 = createDevice("switch", 344, 300, t.devices);
    sw2.name = "안방 스위치";
    sw2.switch = { vlans: {}, igmpSnooping: true };
    t.devices.push(sw2);
    t.cables = t.cables.filter((c) => ![tv.id, pc.id].includes(c.a.device) && ![tv.id, pc.id].includes(c.b.device));
    t.cables.push(
      { id: newId("cable"), a: { device: sw.id, port: 3 }, b: { device: sw2.id, port: 0 } },
      { id: newId("cable"), a: { device: sw2.id, port: 1 }, b: { device: tv.id, port: 0 } },
      { id: newId("cable"), a: { device: sw2.id, port: 3 }, b: { device: pc.id, port: 0 } },
    );
    const L = loadTopology(t);
    L.act({ kind: "mcast-join", nodeId: L.id("거실 TV"), group: G });
    L.act({ kind: "mcast-join", nodeId: L.id("안방 PC"), group: G });
    L.act({ kind: "mcast-send", nodeId: L.id("IPTV 서버"), group: G });
    expect([rxOf(L, "거실 TV"), rxOf(L, "안방 PC")]).toEqual([5, 5]); // 전제: 둘 다 받는다
    L.act({ kind: "mcast-leave", nodeId: L.id("거실 TV"), group: G });
    const before = rxOf(L, "안방 PC");
    L.act({ kind: "mcast-send", nodeId: L.id("IPTV 서버"), group: G });
    expect(rxOf(L, "안방 PC") - before).toBe(5);
  });

  it("가입한 TV 의 케이블을 뺐다 다시 꽂으면 그룹은 가입한 채인데 스트림을 받지 못한다 (링크 업에 Report 를 다시 보내지 않음)", () => {
    const L = loadTopology(snoop(exampleIgmpTopology(), true));
    L.act({ kind: "mcast-join", nodeId: L.id("거실 TV"), group: G });
    const tv = L.id("거실 TV");
    const full = L.t;
    L.apply({ ...full, cables: full.cables.filter((c) => c.a.device !== tv && c.b.device !== tv) });
    L.apply(full);
    expect(L.host("거실 TV").groups.has(G)).toBe(true);
    expect(L.host("거실 TV").iface.ip).toBeTruthy(); // 전제: 다시 주소를 받았다
    const before = rxOf(L, "거실 TV");
    L.act({ kind: "mcast-send", nodeId: L.id("IPTV 서버"), group: G });
    expect(rxOf(L, "거실 TV") - before).toBe(5);
  });

  it("같은 그룹에 가입한 호스트가 다른 호스트의 Report 를 받으면 '목적지 IP 가 내 IP 아님 → 드롭' 이라는 잘못된 줄을 남긴다", () => {
    const L = loadTopology(exampleIgmpTopology());
    L.act({ kind: "mcast-join", nodeId: L.id("거실 TV"), group: G });
    const tr = L.act({ kind: "mcast-join", nodeId: L.id("안방 PC"), group: G });
    const bad = tr.filter((e) => e.nodeId === L.id("거실 TV") && e.kind === "ip.drop");
    expect(bad.map((e) => e.summary)).toEqual([]);
  });

  it("RIP MAC(01:00:5e:00:00:09)과 겹치는 그룹 225.0.0.9 의 스트림을 RIP 게이트웨이가 유니캐스트처럼 라우팅한다 (멀티캐스트 판별이 224./239. 접두사뿐)", () => {
    const L = loadTopology(exampleRipTopology());
    const tr = L.act({ kind: "mcast-send", nodeId: L.id("pc-a"), group: "225.0.0.9" });
    const routed = tr.filter((e) => (e.kind === "ip.forward" || e.kind === "ip.no-route") && JSON.stringify(e.details ?? {}).includes("225.0.0.9"));
    expect(routed.map((e) => `${e.kind}: ${e.summary}`)).toEqual([]);
  });
});

const HOME = "집 Brume 3";
const router = (t: Topology, name: string, p: Partial<RouterSettings>): Topology => ({ ...t, devices: t.devices.map((d) => (d.name === name ? { ...d, router: { ...d.router!, ...p } } : d)) });

describe("Samba 구성 검사 리뷰", () => {
  it("nat.forward-smb: 바깥 포트를 바꿔(8445 → 안쪽 445) SMB 를 열어도 잡아야 한다", () => {
    const t = router(exampleWireguardTopology(), HOME, { forwards: [{ publicPort: 8445, lanIp: "192.168.8.20", lanPort: 445 }] });
    expect(lintTopology(t).map((i) => i.code)).toContain("nat.forward-smb");
  });

  it("nat.forward-smb: NAT 박스의 445 포트 포워딩은 검사하지 않는다 (공유기 forwards 만 봄)", () => {
    const t = examplePartsTopology();
    const nat = t.devices.find((d) => d.kind === "nat")!;
    nat.l3 = { ...nat.l3!, forwards: [{ publicPort: 445, lanIp: "192.168.2.20", lanPort: 445 }] };
    expect(lintTopology(t).map((i) => i.code)).toContain("nat.forward-smb");
  });

});
