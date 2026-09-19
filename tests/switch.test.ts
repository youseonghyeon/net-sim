import { describe, expect, it } from "vitest";
import { BROADCAST_MAC } from "../src/core/addr";
import { Network } from "../src/core/network";
import { Host } from "../src/core/nodes/host";
import { Switch } from "../src/core/nodes/switch";
import type { EthernetFrame } from "../src/core/packet";

let seq = 0;
function frame(src: string, dst: string): EthernetFrame {
  return {
    kind: "ethernet",
    id: ++seq,
    src,
    dst,
    payload: { kind: "arp", op: "request", senderMac: src, senderIp: "10.0.0.1", targetMac: "00:00:00:00:00:00", targetIp: "10.0.0.2" },
  };
}

function build() {
  const net = new Network();
  const sw = net.addNode(new Switch("sw", 4));
  net.addNode(new Host({ id: "a", mac: "aa:aa:aa:aa:aa:aa" }));
  net.addNode(new Host({ id: "b", mac: "bb:bb:bb:bb:bb:bb" }));
  net.addNode(new Host({ id: "c", mac: "cc:cc:cc:cc:cc:cc" }));
  net.connect("a", 0, "sw", 0);
  net.connect("b", 0, "sw", 1);
  net.connect("c", 0, "sw", 2);
  return { net, sw };
}

function sentTo(net: Network, fromNode: string): string[] {
  return net.transmissions.filter((t) => t.from.node === fromNode).map((t) => t.to.node);
}

describe("Switch", () => {
  it("브로드캐스트는 수신 포트 제외 연결된 포트로만 플러딩하고 출발지 MAC 을 학습한다", () => {
    const { net, sw } = build();
    const ctx = (net as any).ctx("sw");
    sw.receive(0, frame("aa:aa:aa:aa:aa:aa", BROADCAST_MAC), ctx);
    expect(sentTo(net, "sw").sort()).toEqual(["b", "c"]); // port 3 은 미연결
    expect(sw.macTable.get("1:aa:aa:aa:aa:aa:aa")?.port).toBe(0);
  });

  it("모르는 유니캐스트는 플러딩, 아는 유니캐스트는 해당 포트로만 전달", () => {
    const { net, sw } = build();
    const ctx = (net as any).ctx("sw");
    sw.receive(0, frame("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"), ctx);
    expect(sentTo(net, "sw").sort()).toEqual(["b", "c"]);
    net.transmissions.length = 0;
    sw.receive(1, frame("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa"), ctx);
    expect(sentTo(net, "sw")).toEqual(["a"]);
    expect(net.trace.some((e) => e.kind === "switch.forward")).toBe(true);
  });

  it("목적지가 수신 포트와 같으면 필터링한다", () => {
    const { net, sw } = build();
    const ctx = (net as any).ctx("sw");
    sw.receive(0, frame("aa:aa:aa:aa:aa:aa", BROADCAST_MAC), ctx);
    net.transmissions.length = 0;
    sw.receive(0, frame("cc:cc:cc:cc:cc:cc", "aa:aa:aa:aa:aa:aa"), ctx);
    expect(sentTo(net, "sw")).toEqual([]);
    expect(net.trace.at(-1)?.kind).toBe("switch.filter");
  });
});
