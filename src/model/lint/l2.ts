// L2 규칙: VLAN 트렁크 불일치, 스위치 고리(루프)에 STP 꺼짐.
import { DEVICE_SPECS, type Device } from "../topology";
import type { LintContext } from "./context";
import { portName } from "./segments";

// 규칙 13a·13b: VLAN 트렁크
export function vlanTrunkRules({ m, add }: LintContext): void {
  // 규칙 13a: 트렁크 포트에 태그를 모르는 장치
  for (const { device, sw, swPort } of m.onTrunk) {
    add({
      deviceId: device.id,
      severity: "error",
      code: "vlan.host-on-trunk",
      message: `${sw.name} 의 트렁크 포트 ${portName(sw, swPort)} 에 연결됨 → ${DEVICE_SPECS[device.kind].label} 는 802.1Q 태그를 이해하지 못해 통신 불가`,
      fix: `${sw.name} → VLAN → ${portName(sw, swPort)} 를 액세스(VLAN 번호)로 바꾸기`,
      related: [sw.id],
    });
  }
  // 규칙 13b: 서브 인터페이스가 있는 포트의 상대가 트렁크가 아님
  for (const { device, port, peer, peerPort } of m.subifNotTrunk) {
    const isSwitch = peer.kind === "switch";
    add({
      deviceId: device.id,
      severity: "error",
      code: "vlan.subif-not-trunk",
      message: `${portName(device, port)} 에 VLAN 서브 인터페이스가 있는데 상대 ${peer.name} ${portName(peer, peerPort)} 가 트렁크가 아님 → 태그 프레임이 드롭됨`,
      fix: isSwitch ? `${peer.name} → VLAN → ${portName(peer, peerPort)} 를 트렁크로 바꾸기` : `${portName(device, port)} 을 스위치의 트렁크 포트에 연결하거나 서브 인터페이스를 지우기`,
      related: [peer.id],
    });
  }
}

// 규칙 19: L2 장비(스위치·허브·공유기 LAN·투명 방화벽)끼리 이은 케이블이 고리를 이루는데, 그 고리의 스위치가 STP 를 안 켬
//   → 브로드캐스트가 끝없이 돈다 (여기서는 안전장치가 드롭). 고리에 실제로 속한 장비만 본다 (고리 컴포넌트에 매달린 가지는 제외)
export function loopStpRule({ t, add }: LintContext): void {
  const isL2 = (d: Device | undefined, port: number) =>
    !!d && (d.kind === "switch" || d.kind === "hub" || d.kind === "firewall" || (DEVICE_SPECS[d.kind].role === "router" && port !== 0));
  const byId = new Map(t.devices.map((d) => [d.id, d]));
  const edges = t.cables.filter((c) => c.a.device !== c.b.device && isL2(byId.get(c.a.device), c.a.port) && isL2(byId.get(c.b.device), c.b.port));
  // 한 케이블을 빼도 두 끝이 여전히 이어져 있으면 그 케이블은 고리 위에 있다
  const connectedWithout = (skip: number, from: string, to: string) => {
    const seen = new Set([from]);
    const stack = [from];
    while (stack.length) {
      const x = stack.pop()!;
      if (x === to) return true;
      edges.forEach((e, k) => {
        if (k === skip) return;
        const y = e.a.device === x ? e.b.device : e.b.device === x ? e.a.device : undefined;
        if (y && !seen.has(y)) {
          seen.add(y);
          stack.push(y);
        }
      });
    }
    return false;
  };
  const inLoop = new Set<string>();
  edges.forEach((e, k) => {
    if (connectedWithout(k, e.a.device, e.b.device)) {
      inLoop.add(e.a.device);
      inLoop.add(e.b.device);
    }
  });
  for (const id of inLoop) {
    const d = byId.get(id)!;
    if (d.kind !== "switch" || d.switch?.stp?.enabled) continue;
    add({
      deviceId: d.id,
      severity: "warn",
      code: "switch.loop-no-stp",
      message: "L2 케이블이 고리(루프)를 이루는데 이 스위치는 STP 가 꺼져 있음 → 브로드캐스트가 고리를 끝없이 돈다 (여기서는 안전장치가 드롭)",
      fix: `${d.name} → STP 켜기 (고리에 있는 스위치 모두). 실제 스위치는 기본으로 켜져 있다`,
    });
  }
  // 스위치 없이 허브·공유기 LAN·투명 방화벽끼리만 고리: STP 를 켤 장비가 없다
  const loopDevices = [...inLoop].map((id) => byId.get(id)!);
  if (loopDevices.length > 0 && !loopDevices.some((d) => d.kind === "switch")) {
    const d = loopDevices[0]!;
    add({ deviceId: d.id, severity: "warn", code: "switch.loop-no-stp", message: "허브·공유기 LAN·투명 방화벽끼리 케이블이 고리를 이룸 → STP 를 켤 수 있는 스위치가 없어 브로드캐스트가 돈다", fix: "고리를 이루는 케이블 하나를 빼거나, 가운데에 STP 를 켠 스위치를 두기" });
  }
}
