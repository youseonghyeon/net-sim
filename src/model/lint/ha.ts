// 이중화 규칙 (VRRP 식).
import { contains, fmtSubnet, subnetOf, validIp } from "./addr";
import type { LintContext } from "./context";
import { portName } from "./segments";

// 규칙 18: 이중화 (VRRP 식) — 가상 주소가 서브넷 밖, 짝이 없음, 같은 세그먼트 짝의 그룹·가상 주소 불일치
export function haRules({ t, m, add }: LintContext): void {
  for (const d of t.devices) {
    const ha = d.l3?.ha;
    if (!ha?.enabled) continue;
    const vipIfs = ha.vips.map((v, i) => ({ vip: validIp(v), i })).filter((x): x is { vip: string; i: number } => !!x.vip);
    if (vipIfs.length === 0) {
      add({ deviceId: d.id, severity: "warn", code: "ha.no-vip", message: "이중화를 켰지만 가상 주소가 없음 → 넘겨줄 것이 없음", fix: `${d.name} → 이중화 → 인터페이스마다 쌍이 함께 쓸 가상 주소 입력` });
      continue;
    }
    let peers = 0;
    for (const { vip, i } of vipIfs) {
      const c = d.l3!.interfaces[i];
      const own = c?.ipMode === "static" ? subnetOf(validIp(c.ip), c.prefix) : undefined;
      if (own && !contains(own, vip)) {
        add({ deviceId: d.id, severity: "error", code: "ha.vip-outside-subnet", message: `가상 주소 ${vip} 가 ${portName(d, i)} 의 서브넷 ${fmtSubnet(own)} 밖 → 이웃이 ARP 로 찾을 수 없음`, fix: `${d.name} → 이중화 → ${portName(d, i)} 가상 주소를 ${fmtSubnet(own)} 안의 빈 주소로` });
      }
      const key = `${d.id}:${i}`;
      if (!m.linked.has(key) || m.stranded.has(key)) continue;
      for (const g of m.gwsOf(key)) {
        if (g.device === d || !g.device.l3?.ha?.enabled) continue;
        const other = g.device.l3.ha;
        const theirVip = validIp(other.vips[g.port]);
        if (other.vrid === ha.vrid) {
          const sharesAny = other.vips.some((v) => validIp(v) && ha.vips.includes(v));
          if (!sharesAny) {
            // 가상 주소가 하나도 겹치지 않는 같은 번호 = 서로 다른 쌍이 번호를 같이 씀 → 한 선출로 묶인다
            add({ deviceId: d.id, severity: "error", code: "ha.vrid-shared", message: `다른 이중화 쌍(${g.device.name})이 같은 세그먼트에서 같은 그룹 번호 ${ha.vrid} 를 씀 → 네 대가 하나의 선출로 묶여 한 쌍은 master 를 잃음`, fix: "쌍마다 다른 그룹 번호(VRID)를", related: [g.device.id] });
            continue;
          }
          peers++;
          if (i === vipIfs[0]!.i && (ha.sync === true) !== (other.sync === true)) {
            add({ deviceId: d.id, severity: "warn", code: "ha.sync-mismatch", message: `짝 ${g.device.name} 와 세션 동기화 설정이 다름 → 한쪽으로 넘어갈 때만 진행 중인 연결이 끊김`, fix: "쌍의 두 장비 모두 세션 동기화를 켜거나 끄기", related: [g.device.id] });
          }
          if (i === vipIfs[0]!.i && (ha.advert === true) !== (other.advert === true)) {
            add({ deviceId: d.id, severity: "warn", code: "ha.advert-mismatch", message: `짝 ${g.device.name} 와 주기 광고 설정이 다름 → 주기 광고를 켠 backup 은 광고를 기다리다 시간이 흐르면 master 가 되고, 켜지 않은 master 의 답을 들으면 물러나기를 되풀이함`, fix: "쌍의 두 장비 모두 주기 광고를 켜거나 끄기 (실제 VRRP 도 광고 간격이 같아야 함)", related: [g.device.id] });
          }
          if (theirVip !== vip) {
            add({ deviceId: d.id, severity: "error", code: "ha.vip-mismatch", message: `짝 ${g.device.name} 의 ${portName(g.device, g.port)} 가상 주소(${theirVip ?? "없음"})가 내 것(${vip})과 다름 → 넘어가면 호스트가 쓰던 주소가 사라짐`, fix: "쌍의 두 장비에 같은 가상 주소를 넣기", related: [g.device.id] });
          }
        } else if (theirVip === vip) {
          add({ deviceId: d.id, severity: "error", code: "ha.vrid-mismatch", message: `${g.device.name} 도 가상 주소 ${vip} 를 쓰지만 그룹 번호가 다름 (${ha.vrid} ↔ ${other.vrid}) → 서로를 짝으로 보지 않아 둘 다 master 가 됨`, fix: "쌍의 두 장비에 같은 그룹 번호(VRID)를", related: [g.device.id] });
        }
      }
    }
    if (peers === 0 && vipIfs.some(({ i }) => m.linked.has(`${d.id}:${i}`))) {
      add({ deviceId: d.id, severity: "warn", code: "ha.no-peer", message: `같은 세그먼트에 그룹 ${ha.vrid} 짝이 없음 → 혼자 master 라 고장 나면 이어받을 장비가 없음`, fix: "같은 스위치들에 두 번째 장비를 연결하고 같은 그룹 번호·가상 주소로 이중화를 켜기" });
    }
  }
}
