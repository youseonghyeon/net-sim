// 주소·대역 읽기 (model/parse.ts): 시뮬레이션·구성 검사·화면 칸이 같은 기준을 쓴다 — 화면만 통과시키던 값이 다시 생기지 않게
import { describe, expect, it } from "vitest";
import { badCidrs, ip4, isHostname, parseCidr, parseCidrList, toInt } from "../src/model/parse";
import { cidrError, cidrListError, hostError } from "../src/app/inspector/ui";

describe("parse", () => {
  it("ip4: 네 칸·0~255 십진수만", () => {
    expect(ip4("10.0.0.1")).toBe("10.0.0.1");
    for (const bad of ["", undefined, "10.0.0", "10.0.0.256", "10.0.0.1.2", "a.b.c.d", "10.0.0.-1"]) expect(ip4(bad)).toBeUndefined();
  });

  it("parseCidr: 길이가 없으면 기본값, 슬래시가 둘이면 거부", () => {
    expect(parseCidr("10.0.0.2", 32)).toEqual({ ip: "10.0.0.2", prefix: 32 });
    expect(parseCidr(" 10.0.0.0 / 24 ", 32)).toEqual({ ip: "10.0.0.0", prefix: 24 });
    for (const bad of ["10.0.0.2/24/5", "10.0.0.2/33", "10.0.0.2/", "/24", "10.0.0/24"]) expect(parseCidr(bad, 32)).toBeUndefined();
  });

  it("parseCidrList·badCidrs: 쉼표·공백으로 나눠 읽을 수 있는 것과 없는 것", () => {
    expect(parseCidrList("10.0.0.0/24, 192.168.8.5 x/1")).toEqual([
      { dest: "10.0.0.0", prefix: 24 },
      { dest: "192.168.8.5", prefix: 32 },
    ]);
    expect(badCidrs("10.0.0.0/24, 10.0.0.2/24/5 x/1")).toEqual(["10.0.0.2/24/5", "x/1"]);
    expect(badCidrs("")).toEqual([]);
  });

  it("toInt: 반올림·범위 안으로·못 읽으면 기본값", () => {
    expect(toInt("24.5", 0, 32, 24)).toBe(25);
    expect(toInt("40", 0, 32, 24)).toBe(32);
    expect(toInt("-3", 1, 32, 24)).toBe(1);
    expect(toInt("abc", 1, 4094, 10)).toBe(10);
    expect(toInt("5000", 1, 4094, 10)).toBe(4094);
  });

  it("isHostname", () => {
    expect(isHostname("myhome.glddns.com")).toBe(true);
    expect(isHostname("myhome")).toBe(false);
    expect(isHostname("-x.com")).toBe(false);
  });
});

describe("화면 칸 검증은 같은 파서를 쓴다", () => {
  it("cidrError: 시뮬레이션이 버리는 값을 화면도 거부", () => {
    expect(cidrError("10.0.0.2/24/5", true, "10.0.0.2/32")).toBe("예: 10.0.0.2/32");
    expect(cidrError("10.0.0.2/32", true, "10.0.0.2/32")).toBeUndefined();
    expect(cidrError("", true, "x")).toBe("필요한 값입니다");
    expect(cidrError("", false, "x")).toBeUndefined();
  });

  it("cidrListError: 읽을 수 없는 첫 항목을 짚는다", () => {
    expect(cidrListError("192.168.8.0/24, 1.2.3.4/8/1", "192.168.8.0/24")).toBe("1.2.3.4/8/1 — 예: 192.168.8.0/24");
    expect(cidrListError("", "x")).toBeUndefined();
  });

  it("hostError: 주소 또는 이름", () => {
    expect(hostError("203.0.113.30", "203.0.113.30")).toBeUndefined();
    expect(hostError("myhome.glddns.com", "203.0.113.30")).toBeUndefined();
    expect(hostError("myhome", "203.0.113.30")).toBe("예: myhome.glddns.com");
    expect(hostError("203.0.113", "203.0.113.30")).toBe("예: 203.0.113.30 또는 myhome.glddns.com");
    expect(hostError(" ", "x")).toBe("필요한 값입니다");
  });
});
