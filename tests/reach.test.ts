import { describe, expect, it } from "vitest";
import { probeTargets } from "../src/model/reach";
import { EXAMPLES } from "../src/model/topology";

const byName = (t: ReturnType<(typeof EXAMPLES)["router"]["build"]>, n: string) => t.devices.find((d) => d.name === n)!.id;

describe("진단 자동완성: 닿는 후보", () => {
  it("공유기 예제: 같은 서브넷·인터넷·이름으로 묶이고 모두 닿으며 홉 수가 나온다", () => {
    const t = EXAMPLES.router.build();
    const r = probeTargets(t, byName(t, "pc-1"), "ping");
    const g = (v: string) => r.candidates.find((c) => c.value === v)!;
    expect(g("192.168.0.20")).toMatchObject({ group: "same", ok: true, hops: 1 });
    expect(g("8.8.8.8")).toMatchObject({ group: "internet", ok: true });
    expect(g("google.com")).toMatchObject({ group: "name", ok: true, resolved: "142.250.196.110" });
    // 그룹 순서: 같은 서브넷 → … → 이름
    const groups = r.candidates.map((c) => c.group);
    expect(groups.indexOf("same")).toBeLessThan(groups.indexOf("name"));
  });

  it("도커 예제: LAN 의 PC 에서 컨테이너 사설 주소는 닿지 않고 이유가 붙는다", () => {
    const t = EXAMPLES.docker.build();
    const r = probeTargets(t, byName(t, "pc-1"), "ping");
    const web = r.candidates.find((c) => c.value === "172.18.0.2")!;
    expect(web.ok).toBe(false);
    expect(web.group).toBe("routed");
    expect(web.reason).toBeTruthy();
  });

  it("방화벽 장비 예제: ping 은 방화벽 차단, TCP 80 은 닿는다", () => {
    const t = EXAMPLES.fwbox.build();
    const pc = byName(t, "pc-1");
    const ping = probeTargets(t, pc, "ping").candidates.find((c) => c.value === "192.168.0.20")!;
    expect(ping).toMatchObject({ ok: false });
    expect(ping.reason).toContain("방화벽");
    const tcp = probeTargets(t, pc, "tcp", 80).candidates.find((c) => c.value === "192.168.0.20")!;
    expect(tcp).toMatchObject({ ok: true });
  });

  it("출발 호스트에 IP 가 없으면 이유를 알려준다", () => {
    const t = EXAMPLES.router.build();
    const cut = { ...t, cables: t.cables.filter((c) => c.a.device !== byName(t, "pc-1") && c.b.device !== byName(t, "pc-1")) };
    expect(probeTargets(cut, byName(t, "pc-1"), "ping").note).toContain("IP 미설정");
  });
});
