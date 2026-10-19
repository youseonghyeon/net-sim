// 인터넷 노드(ISP): 대역 설정, ISP 구간에 손으로 적은 공인 주소 (ISP 는 DHCP 로 나눠 준 가입자 대역만 안다)
import type { LintContext } from "./context";
import { DEVICE_SPECS } from "../topology";
import { effectiveIspNet, ispNetProblem } from "../isp";
import { SUBSCRIBER_PREFIX } from "../../core/nodes/internet";

// 규칙 6b: ISP
export function ispRules({ t, m, add, leased }: LintContext): void {
  for (const d of t.devices) {
    if (DEVICE_SPECS[d.kind].role !== "internet") continue;
    const problem = d.internet ? ispNetProblem(d.internet.net) : undefined;
    const net = effectiveIspNet(d.internet?.net);
    if (problem) add({ deviceId: d.id, severity: "error", code: "isp.net-invalid", message: `ISP 대역 ${problem} → 기본 대역 ${net.ip}/${net.prefix} 로 동작`, fix: `${d.name} → 설정 → ISP 대역 (공인 대역 /16 ~ /28, "무작위" 로 골라도 됨)` });
    // 같은 ISP 구간에 손으로 적은 주소: ISP 는 그 주소로 가는 길을 모른다 (고정 IP 등록은 하지 않는다)
    const members = m.membersOf(`${d.id}:0`);
    for (const a of members?.addrs ?? []) {
      if (a.device.id === d.id || leased?.has(a.key)) continue;
      add({
        deviceId: a.device.id,
        severity: "warn",
        code: "isp.static-address",
        message: `${a.label} ${a.ip} 를 ISP 구간(${d.name})에 손으로 적었음 → ISP 는 DHCP 로 나눠 준 가입자 대역(/${SUBSCRIBER_PREFIX})만 라우팅해 이 주소로는 통신이 안 됨`,
        fix: `${a.device.name} → 그 인터페이스를 자동(DHCP)으로 (ISP 가 늘 같은 대역을 준다 — 바깥에서 찾게 하려면 그 주소나 DDNS 이름을 쓴다)`,
        related: [d.id],
      });
    }
  }
}
