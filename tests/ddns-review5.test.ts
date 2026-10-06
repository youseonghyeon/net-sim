// DDNS 리뷰(2026-10-07) 회귀 테스트 — 리뷰어 재현을 그대로 둠
import { describe, expect, it } from "vitest";
import { loadTopology } from "./helpers";
import { exampleDdnsTopology } from "../src/model/examples";
import { lintTopology } from "../src/model/lint";
import type { Router } from "../src/core/nodes/router";
import type { Internet } from "../src/core/nodes/internet";
import type { Topology } from "../src/model/topology";
import { builder, cable } from "../src/model/examples/build";
import { wgPublicKeyOf } from "../src/model/topology";
const log = (..._a: unknown[]): void => {};

/** 집: ISP 공유기(outer, DDNS) 뒤에 Brume(inner, WireGuard 서버). outer 가 UDP 51820 을 inner 로 포워딩 */
function behindIsp(opts: { ddnsOn: "outer" | "inner"; forward: boolean }): Topology {
  const base = exampleDdnsTopology();
  const { devices, add } = builder();
  // re-use the example's devices but insert an outer router in front of home
  for (const d of base.devices) devices.push(d);
  const home = devices.find((d) => d.name === "집 Brume 3")!;
  const outer = add("router", 568, -120, "집 ISP 공유기");
  outer.router = {
    ...outer.router!,
    lanIp: "192.168.1.1",
    lanPrefix: 24,
    dhcp: { enabled: true, start: "192.168.1.100", end: "192.168.1.199" },
    forwards: opts.forward ? [{ publicPort: 51820, lanIp: "192.168.1.2", lanPort: 51820, proto: "udp" }] : [],
    ...(opts.ddnsOn === "outer" ? { ddns: { enabled: true, name: "myhome" } } : {}),
  };
  home.router = {
    ...home.router!,
    wan: { ipMode: "static", ip: "192.168.1.2", prefix: 24, gateway: "192.168.1.1" },
    ...(opts.ddnsOn === "outer" ? { ddns: { enabled: false, name: "" } } : {}),
  };
  const isp = devices.find((d) => d.name === "통신사 구간")!;
  const cables = base.cables.filter((c) => !(c.a.device === isp.id && c.b.device === home.id) && !(c.b.device === isp.id && c.a.device === home.id));
  cables.push(cable(isp, 6, outer, 0), cable(outer, 1, home, 0));
  void wgPublicKeyOf;
  return { devices, cables };
}

describe("lint: DDNS name + port forwarding", () => {
  it("DDNS on the ISP router, WG server on Brume behind it (forward UDP 51820): runtime works, lint should be clean", () => {
    const t = behindIsp({ ddnsOn: "outer", forward: true });
    const issues = lintTopology(t);
    log("lint:", issues.map((i) => `${i.code}: ${i.message}`));
    const L = loadTopology(t);
    log("phone:", L.host("카페 폰").ra.state, "ddns", L.node<Router>("집 ISP 공유기").ddns.state, L.node<Internet>("internet-1").ddns.lookup("myhome.glddns.com"));
    L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "192.168.8.20" });
    log("ping:", L.host("카페 폰").pings.at(-1)!.status);
    expect(issues).toEqual([]);
  });

  it("DDNS on Brume behind the ISP router WITHOUT forward: runtime fails, lint should warn", () => {
    const t = behindIsp({ ddnsOn: "inner", forward: false });
    const issues = lintTopology(t);
    log("lint:", issues.map((i) => `${i.code}: ${i.message}`));
    const L = loadTopology(t);
    L.act({ kind: "ping", nodeId: L.id("카페 폰"), dst: "192.168.8.20" });
    log("phone:", L.host("카페 폰").ra.state, "ping:", L.host("카페 폰").pings.at(-1)!.status);
    expect(L.host("카페 폰").pings.at(-1)!.status).toBe("failed");
    expect(issues.length).toBeGreaterThan(0);
  });
});
