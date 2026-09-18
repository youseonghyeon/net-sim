import { describe, expect, it } from "vitest";
import { broadcastOf, ipToInt, intToIp, networkOf, sameSubnet } from "../src/core/addr";

describe("addr", () => {
  it("ip <-> int 왕복", () => {
    expect(ipToInt("10.0.0.1")).toBe(0x0a000001);
    expect(intToIp(0xc0a80101)).toBe("192.168.1.1");
    expect(intToIp(ipToInt("255.255.255.255"))).toBe("255.255.255.255");
  });

  it("잘못된 IP 는 예외", () => {
    expect(() => ipToInt("10.0.0")).toThrow();
    expect(() => ipToInt("10.0.0.256")).toThrow();
    expect(() => ipToInt("a.b.c.d")).toThrow();
  });

  it("서브넷 계산", () => {
    expect(networkOf("192.168.1.77", 24)).toBe("192.168.1.0");
    expect(broadcastOf("192.168.1.77", 24)).toBe("192.168.1.255");
    expect(networkOf("10.1.2.3", 8)).toBe("10.0.0.0");
    expect(networkOf("10.1.2.3", 0)).toBe("0.0.0.0");
    expect(networkOf("10.1.2.3", 32)).toBe("10.1.2.3");
    expect(sameSubnet("10.0.0.1", "10.0.0.200", 24)).toBe(true);
    expect(sameSubnet("10.0.0.1", "10.0.1.1", 24)).toBe(false);
    expect(sameSubnet("10.0.0.1", "10.0.1.1", 16)).toBe(true);
  });
});
