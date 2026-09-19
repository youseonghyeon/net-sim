import { describe, expect, it } from "vitest";
import { createDevice, normalizeTopology, type Device } from "../src/model/topology";

describe("normalizeTopology", () => {
  it("저장된 게이트웨이의 서브 인터페이스·방화벽·포워딩 설정을 잃지 않는다", () => {
    const devices: Device[] = [];
    const gw = createDevice("gateway", 0, 0, devices);
    const l3In: NonNullable<Device["l3"]> = {
      ...gw.l3!,
      subinterfaces: [{ port: 1, vlan: 10, ip: "192.168.10.1", prefix: 24, relay: "" }],
      firewall: { enabled: true, defaultPolicy: "deny", stateful: true, rules: [] },
      forwards: [{ publicPort: 8080, lanIp: "192.168.10.5", lanPort: 80 }],
    };
    gw.l3 = l3In;
    devices.push(gw);
    const out = normalizeTopology({ devices, cables: [] });
    const l3 = out.devices[0]!.l3!;
    expect(l3.subinterfaces).toEqual(l3In.subinterfaces);
    expect(l3.firewall?.defaultPolicy).toBe("deny");
    expect(l3.forwards).toHaveLength(1);
    expect(l3.interfaces).toHaveLength(l3In.interfaces.length);
  });
});
