// 로드밸런서 규칙: 백엔드 없음·닫힌 백엔드·로드밸런서끼리 순환·L7 에 SSH 포트·L4 에 쿠키 세션 고정.
import type { Device } from "../topology";
import { validIp, validPort } from "./addr";
import type { LintContext } from "./context";

// 규칙 14: 로드밸런서 — 백엔드가 없거나, 백엔드로 적은 서버가 그 포트를 열지 않거나, 로드밸런서끼리 순환
// 백엔드는 시뮬레이션(netSync effectiveLb)과 같은 기준으로 거른다: 올바른 주소 + 포트 1~65535
export function lbRules({ t, add }: LintContext): void {
  const lbBackends = (d: Device) => (d.host?.lb?.backends ?? []).filter((b) => validIp(b.ip) && validPort(b.port));
  // "주소:포트" → 그 자리에서 듣는 로드밸런서 장치 (수동 주소만: 주소를 모르면 판단하지 않는다)
  const lbAt = new Map<string, Device>();
  for (const d of t.devices) {
    const lb = d.host?.lb;
    if (lb?.enabled && d.host!.ipMode === "static" && validIp(d.host!.ip) && validPort(lb.port)) lbAt.set(`${d.host!.ip}:${lb.port}`, d);
  }
  for (const d of t.devices) {
    const lb = d.host?.lb;
    if (!lb?.enabled) continue;
    // 순환: 백엔드를 따라가다 자기 자신으로 돌아오면 요청이 로드밸런서 사이를 돈다 (시뮬레이션은 Via 5개에서 508 로 끊음)
    const seen = new Set<string>();
    const stack = lbBackends(d).map((b) => `${b.ip}:${b.port}`);
    let loop = false;
    while (stack.length && !loop) {
      const k = stack.pop()!;
      const next = lbAt.get(k);
      if (!next) continue;
      if (next === d) loop = true;
      else if (!seen.has(next.id)) {
        seen.add(next.id);
        stack.push(...lbBackends(next).map((b) => `${b.ip}:${b.port}`));
      }
    }
    if (loop) {
      add({
        deviceId: d.id,
        severity: "error",
        code: "lb.loop",
        message: d.host?.lb?.mode === "l4" ? `백엔드를 따라가면 이 로드밸런서로 돌아옴 → 패킷이 로드밸런서 사이를 돌다 TTL 이 다해 드롭 (연결 timeout)` : `백엔드를 따라가면 이 로드밸런서로 돌아옴 → 요청이 로드밸런서 사이를 돌다 508 Loop Detected`,
        fix: `${d.name} → 로드밸런서 → 백엔드에서 자기 자신이나 자기를 가리키는 로드밸런서를 빼고 실제 서버를 넣기`,
      });
    }
    if (d.host?.lb?.port === 22 && d.host.lb.mode !== "l4") {
      add({
        deviceId: d.id,
        severity: "warn",
        code: "lb.ssh-port",
        message: "로드밸런서가 포트 22 를 받음 → 이 로드밸런서는 HTTP 요청만 나누는 L7 프록시라 SSH 세션은 백엔드로 이어지지 않음",
        fix: `${d.name} → 로드밸런서 → 받는 포트를 80 등 웹 포트로 (SSH 는 백엔드 서버에 바로 접속)`,
      });
    }
    if (lb.mode === "l4" && lb.sticky === "cookie") {
      add({
        deviceId: d.id,
        severity: "warn",
        code: "lb.cookie-l4",
        message: "L4 주소 변환은 HTTP 를 보지 않아 쿠키를 넣지도 읽지도 못함 → 쿠키 세션 고정이 동작하지 않고 연결마다 분배 방식대로 나뉨",
        fix: `${d.name} → 로드밸런서 → 세션 고정을 출발지 IP 로 바꾸거나, 방식을 L7 프록시로`,
      });
    }
    const backends = lbBackends(d);
    if (backends.length === 0) {
      add({
        deviceId: d.id,
        severity: "warn",
        code: "lb.no-backend",
        message: `로드밸런서에 백엔드가 없음 → 포트 ${lb.port} 로 온 요청에 모두 502 Bad Gateway`,
        fix: `${d.name} → 로드밸런서 → 백엔드 추가 (뒤 서버의 주소와 포트)`,
      });
      continue;
    }
    for (const b of backends) {
      // 같은 주소가 여러 곳(다른 사설망)에 있으면 어느 것인지 알 수 없어 침묵
      const owners = t.devices.filter((x) => x.host?.ipMode === "static" && x.host.ip === b.ip);
      if (owners.length !== 1) continue;
      const target = owners[0]!;
      const listens = (target.host!.services ?? []).includes(b.port) || (target.host!.lb?.enabled === true && target.host!.lb.port === b.port) || (target.host!.proxy?.enabled === true && target.host!.proxy.port === b.port);
      if (listens) continue;
      add({
        deviceId: d.id,
        severity: "warn",
        code: "lb.backend-closed",
        message: `백엔드 ${b.ip}:${b.port} (${target.name}) 가 포트 ${b.port} 를 열지 않음 → 그쪽으로 간 요청은 거부되고 다른 백엔드로 넘어감`,
        fix: `${target.name} → 서비스에서 ${b.port === 80 ? "웹 서버" : `포트 ${b.port}`}를 켜거나, ${d.name} 의 백엔드 목록에서 빼기`,
        related: [target.id],
      });
    }
  }
}
