// 실무 출력은 요약문의 한국어 문구가 아니라 트레이스 details 의 사유 코드(cause·side·step·ike…)로 고른다.
// 문구를 다듬으면 실무 줄이 소리 없이 사라졌다 (PSK 거절의 strongSwan 줄 누락 — 리팩터링 조사 2026-10-20). 이 테스트가 그 매칭을 막는다
import { describe, expect, it } from "vitest";
import src from "../src/model/packetView.ts?raw";

/** 허용: "<모듈 이름> 서버" 접두어로 서버 쪽 기록을 가르는 두 곳 (문구가 아니라 로그 줄의 이름표) */
const ALLOWED = ['sm.startsWith("OpenVPN 서버")', 'ev.summary.startsWith("VPN 서버")'];

describe("packetView 는 요약문의 한국어 문구로 고르지 않는다", () => {
  it("summary 를 한국어 문자열·정규식으로 매칭하는 곳이 없다", () => {
    const hits = src
      .split("\n")
      .map((line, i) => ({ line: line.trim(), n: i + 1 }))
      .filter(({ line }) => /(summary|\bsm)\s*\.\s*(includes|startsWith|endsWith|match)\(|\.(exec|test)\((ev\.)?summary|\.(exec|test)\(sm\)/.test(line))
      .filter(({ line }) => /[가-힣]/.test(line))
      .filter(({ line }) => !ALLOWED.some((a) => line.includes(a)));
    expect(hits.map((h) => `packetView.ts:${h.n} ${h.line.slice(0, 120)}`)).toEqual([]);
  });
});
