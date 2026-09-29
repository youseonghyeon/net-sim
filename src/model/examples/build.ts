// 예제 조립 도우미. 예제 묶음 파일(basic.ts 등)이 공유한다.
import { type Cable, type Device, type DeviceKind, createDevice, newId } from "../topology";

/** 장치를 차례로 만든다. 이름·MAC 은 앞서 만든 장치 기준으로 정해지므로 만드는 순서가 곧 번호 순서다 */
export function builder() {
  const devices: Device[] = [];
  const add = (kind: DeviceKind, x: number, y: number, name?: string): Device => {
    const d = createDevice(kind, x, y, devices);
    if (name) d.name = name;
    devices.push(d);
    return d;
  };
  return { devices, add };
}

/** 케이블 하나: a 장치의 ap 번 포트 ↔ b 장치의 bp 번 포트 */
export function cable(a: Device, ap: number, b: Device, bp: number): Cable {
  return { id: newId("cable"), a: { device: a.id, port: ap }, b: { device: b.id, port: bp } };
}

/** 게이트웨이·NAT 박스의 수동 주소 인터페이스 (/24) */
export function iface(ip: string, gateway = "") {
  return { ipMode: "static" as const, ip, prefix: 24, gateway };
}
