import { describe, expect, it } from "vitest";
import { Scheduler } from "../src/core/scheduler";

describe("Scheduler", () => {
  it("시간 → 우선순위 → 삽입 순으로 꺼낸다", () => {
    const s = new Scheduler<string>();
    s.push(30, "c");
    s.push(10, "a2", 1);
    s.push(10, "a1", 0);
    s.push(20, "b");
    s.push(10, "a3", 1);
    const out: string[] = [];
    for (let x = s.pop(); x; x = s.pop()) out.push(x.payload);
    expect(out).toEqual(["a1", "a2", "a3", "b", "c"]);
  });
});
