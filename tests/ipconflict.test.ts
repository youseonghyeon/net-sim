import { describe, expect, it } from "vitest";
import { Network } from "../src/core/network";
import { Host } from "../src/core/nodes/host";
import { Internet } from "../src/core/nodes/internet";
import { L3Node } from "../src/core/nodes/l3";
import { Switch } from "../src/core/nodes/switch";

/** 통신사 스위치 아래 인터넷 + 두 집의 NAT (outside 고정 주소) */
function twoNats(bIp: string) {
  const net = new Network();
  net.addNode(new Internet({ id: "inet", mac: "02:00:00:ff:00:01" }));
  net.addNode(new Switch("isp", 4));
  const nat = (id: string, n: number, ip: string) =>
    new L3Node({
      id,
      kind: "nat",
      outside: 0,
      interfaces: [
        { name: "outside", mac: `02:00:00:10:00:0${n}`, mode: "static", ip, prefix: 24, gateway: "203.0.113.1" },
        { name: "inside", mac: `02:00:00:11:00:0${n}`, mode: "static", ip: "192.168.0.1", prefix: 24 },
      ],
    });
  net.addNode(nat("a", 1, "203.0.113.101"));
  net.addNode(new Host({ id: "pcA", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "192.168.0.10", prefix: 24, gateway: "192.168.0.1" }));
  net.connect("inet", 0, "isp", 0);
  net.connect("a", 0, "isp", 1);
  net.connect("pcA", 0, "a", 1);
  net.runToIdle();
  net.addNode(nat("b", 2, bIp));
  net.connect("b", 0, "isp", 2);
  net.runToIdle();
  return net;
}

describe("IP 충돌 (RFC 5227 축소판)", () => {
  it("두 장비가 동시에 같은 주소를 쓰려 하면 둘 다 포기하고, 한쪽이 주소를 바꾸면 다른 쪽이 다시 확인해 되찾는다", () => {
    const net = new Network();
    net.addNode(new Internet({ id: "inet", mac: "02:00:00:ff:00:01" }));
    net.addNode(new Switch("isp", 4));
    const mk = (id: string, n: number) =>
      new L3Node({
        id,
        kind: "nat",
        outside: 0,
        interfaces: [
          { name: "outside", mac: `02:00:00:10:00:0${n}`, mode: "static", ip: "203.0.113.101", prefix: 24, gateway: "203.0.113.1" },
          { name: "inside", mac: `02:00:00:11:00:0${n}`, mode: "static", ip: "192.168.0.1", prefix: 24 },
        ],
      });
    net.addNode(mk("a", 1));
    net.addNode(mk("b", 2));
    net.addNode(new Host({ id: "pcA", mac: "02:00:00:00:00:0a", ipMode: "static", ip: "192.168.0.10", prefix: 24, gateway: "192.168.0.1" }));
    net.connect("inet", 0, "isp", 0);
    net.connect("a", 0, "isp", 1);
    net.connect("b", 0, "isp", 2);
    net.connect("pcA", 0, "a", 1);
    net.runToIdle();
    const a = net.nodes.get("a") as L3Node;
    const b = net.nodes.get("b") as L3Node;
    expect(a.ifaces[0]!.conflict?.refused).toBe(true);
    expect(b.ifaces[0]!.conflict?.refused).toBe(true);
    b.configure(
      [
        { mode: "static", ip: "203.0.113.102", prefix: 24, gateway: "203.0.113.1" },
        { mode: "static", ip: "192.168.0.1", prefix: 24 },
      ],
      net.contextFor("b"),
    );
    net.runToIdle();
    expect(a.ifaces[0]!.conflict).toBeUndefined();
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pcA", dst: "1.1.1.1" });
    net.runToIdle();
    expect(net.getHost("pcA").pings.at(-1)).toMatchObject({ status: "ok" });
  });

  it("고정 주소는 ARP Probe 뒤에 쓰기 시작한다 (충돌 없음 → Gratuitous ARP)", () => {
    const net = twoNats("203.0.113.102");
    const b = net.nodes.get("b") as L3Node;
    expect(b.ifaces[0]!.conflict).toBeUndefined();
    const seq = net.trace.filter((e) => e.nodeId === "b" && (e.kind === "arp.probe" || (e.kind === "arp.request.sent" && e.summary.includes("Gratuitous")))).map((e) => e.kind);
    expect(seq).toEqual(["arp.probe", "arp.probe", "arp.request.sent"]);
  });

  it("이미 쓰는 주소를 넣으면 Probe 에 응답이 와서 그 주소를 쓰지 않고, 기존 주인의 통신은 멀쩡하다", () => {
    const net = twoNats("203.0.113.101"); // 복사해서 같은 공인 IP
    const b = net.nodes.get("b") as L3Node;
    expect(b.ifaces[0]!.conflict).toMatchObject({ refused: true, mac: "02:00:00:10:00:01" });
    expect(net.trace.some((e) => e.nodeId === "b" && e.kind === "ip.conflict" && e.summary.includes("쓰지 않음"))).toBe(true);
    // b 는 이 주소로 Gratuitous ARP 를 보내지 않았다 → 인터넷의 ARP 캐시는 a 그대로
    expect(net.transmissions.some((t) => t.from.node === "b" && t.frame.payload.kind === "arp" && t.frame.payload.senderIp === "203.0.113.101")).toBe(false);
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pcA", dst: "1.1.1.1" });
    net.runToIdle();
    expect(net.getHost("pcA").pings.at(-1)).toMatchObject({ status: "ok" });
    // 다른 주소로 바꾸면 충돌 상태가 풀린다
    b.configure(
      [
        { mode: "static", ip: "203.0.113.102", prefix: 24, gateway: "203.0.113.1" },
        { mode: "static", ip: "192.168.0.1", prefix: 24 },
      ],
      net.contextFor("b"),
    );
    net.runToIdle();
    expect(b.ifaces[0]!.conflict).toBeUndefined();
  });

  it("쓰는 중에 다른 장비가 같은 주소를 주장하면 충돌을 기록하고 Gratuitous ARP 로 방어한다 (10초에 한 번)", () => {
    const net = twoNats("203.0.113.102");
    const a = net.nodes.get("a") as L3Node;
    // 인터넷이 .101 → a 를 배운 상태에서
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pcA", dst: "1.1.1.1" });
    net.runToIdle();
    // 장비 b 가 확인 없이 .101 을 주장하는 Gratuitous ARP 를 두 번 보낸다
    const ctx = net.contextFor("b");
    const garp = () =>
      ctx.send(0, {
        kind: "ethernet",
        id: ctx.nextPacketId(),
        src: "02:00:00:10:00:02",
        dst: "ff:ff:ff:ff:ff:ff",
        payload: { kind: "arp", op: "request", senderMac: "02:00:00:10:00:02", senderIp: "203.0.113.101", targetMac: "00:00:00:00:00:00", targetIp: "203.0.113.101" },
      });
    const inet = net.nodes.get("inet") as Internet;
    garp();
    net.runToIdle();
    // 첫 주장: 인터넷 캐시가 b 로 바뀌었다가 a 의 방어(Gratuitous ARP)로 a 로 돌아온다 → 응답이 옆집으로 새지 않는다
    expect(inet.iface.arpCache.get("203.0.113.101")?.mac).toBe("02:00:00:10:00:01");
    net.scheduleAction(net.now, { kind: "ping", nodeId: "pcA", dst: "1.1.1.1" });
    net.runToIdle();
    expect(net.getHost("pcA").pings.at(-1)).toMatchObject({ status: "ok" });
    // 10초 안의 두 번째 주장은 기록만 한다 (서로 방어하며 폭주하지 않게)
    garp();
    net.runToIdle();
    const logs = net.trace.filter((e) => e.nodeId === "a" && e.kind === "ip.conflict").map((e) => e.summary);
    expect(logs).toHaveLength(2);
    expect(logs[0]).toContain("방어");
    expect(logs[1]).toContain("기록만");
    expect(a.ifaces[0]!.conflict).toMatchObject({ refused: false, mac: "02:00:00:10:00:02" });

  });
});
