// 장치 종류와 사양: 포트(이름·위치·무선 슬롯)·역할·팔레트 묶음

export type DeviceKind = "pc" | "laptop" | "phone" | "server" | "lb" | "switch" | "hub" | "ap" | "router" | "gateway" | "nat" | "firewall" | "internet";
export type Role = "host" | "switch" | "hub" | "ap" | "router" | "l3" | "internet" | "firewall";
export type PortSide = "top" | "bottom";

export interface PortSpec {
  name: string;
  side: PortSide;
  /** 무선 슬롯: 케이블을 꽂을 수 없고 화면에 포트로 그리지 않는다 */
  radio?: boolean;
}

/** 무선 전파가 닿는 거리 (캔버스 픽셀). 이 안에 있고 SSID 가 같으면 붙는다 */
export const WIFI_RANGE = 300;
const radioSlots = (n: number): PortSpec[] => Array.from({ length: n }, (_, i) => ({ name: `무선 ${i + 1}`, side: "top" as const, radio: true }));

export interface DeviceSpec {
  kind: DeviceKind;
  label: string;
  role: Role;
  width: number;
  height: number;
  ports: PortSpec[];
  namePrefix: string;
}

const lanPorts = (n: number, side: PortSide, prefix = "eth", from = 0): PortSpec[] =>
  Array.from({ length: n }, (_, i) => ({ name: `${prefix}${from + i}`, side }));

export const DEVICE_SPECS: Record<DeviceKind, DeviceSpec> = {
  pc: { kind: "pc", label: "PC", role: "host", width: 64, height: 64, ports: [{ name: "eth0", side: "top" }], namePrefix: "pc" },
  // 노트북: 유선 eth0 + 무선 wlan0 (무선은 Wi-Fi 를 켰을 때만). 둘 다 붙어 있으면 유선을 쓴다
  laptop: { kind: "laptop", label: "노트북", role: "host", width: 64, height: 64, ports: [{ name: "eth0", side: "top" }, { name: "wlan0", side: "top", radio: true }], namePrefix: "laptop" },
  phone: { kind: "phone", label: "스마트폰", role: "host", width: 44, height: 64, ports: [{ name: "wlan0", side: "top", radio: true }], namePrefix: "phone" },
  server: { kind: "server", label: "서버", role: "host", width: 64, height: 64, ports: [{ name: "eth0", side: "top" }], namePrefix: "srv" },
  // 로드밸런서 전용 장비: 호스트처럼 주소 하나를 갖고(VIP) 뒤 서버들에 요청을 나눈다. 서버의 LB 서비스 토글과 같은 모듈(core/nodes/lb.ts)
  lb: { kind: "lb", label: "로드밸런서", role: "host", width: 64, height: 64, ports: [{ name: "eth0", side: "top" }], namePrefix: "lb" },
  switch: {
    kind: "switch",
    label: "스위치",
    role: "switch",
    width: 152,
    height: 44,
    // 실물처럼 포트는 아래쪽 한 줄. 라우터/게이트웨이도 이 줄에 꽂는다
    ports: lanPorts(8, "bottom", "eth", 1),
    namePrefix: "sw",
  },
  hub: {
    kind: "hub",
    label: "허브",
    role: "hub",
    width: 120,
    height: 44,
    ports: lanPorts(4, "bottom", "port", 1),
    namePrefix: "hub",
  },
  ap: {
    kind: "ap",
    label: "무선 AP",
    role: "ap",
    width: 120,
    height: 44,
    // eth0 하나 + 무선 슬롯 8개 (코어 AccessPoint 의 포트 배치와 같다)
    ports: [{ name: "eth0", side: "top" }, ...radioSlots(8)],
    namePrefix: "ap",
  },
  router: {
    kind: "router",
    label: "라우터",
    role: "router",
    width: 152,
    height: 62,
    // wan, lan1~4, 무선 슬롯 8개 (코어 Router.RADIO_PORTS = 5..12)
    ports: [{ name: "wan", side: "top" }, ...lanPorts(4, "bottom", "lan", 1), ...radioSlots(8)],
    namePrefix: "rt",
  },
  gateway: {
    kind: "gateway",
    label: "게이트웨이",
    role: "l3",
    width: 152,
    height: 62,
    ports: [
      { name: "if0", side: "top" },
      { name: "if1", side: "bottom" },
      { name: "if2", side: "bottom" },
    ],
    namePrefix: "gw",
  },
  nat: {
    kind: "nat",
    label: "NAT",
    role: "l3",
    width: 152,
    height: 62,
    ports: [
      { name: "outside", side: "top" },
      { name: "inside", side: "bottom" },
    ],
    namePrefix: "nat",
  },
  firewall: {
    kind: "firewall",
    label: "방화벽",
    role: "firewall",
    width: 152,
    height: 62,
    // 투명(브리지) 방화벽: 위 = outside(인터넷 방향), 아래 = inside(보호할 쪽). IP 없음
    ports: [
      { name: "outside", side: "top" },
      { name: "inside", side: "bottom" },
    ],
    namePrefix: "fw",
  },
  internet: {
    kind: "internet",
    label: "인터넷",
    role: "internet",
    width: 152,
    height: 48,
    ports: [{ name: "isp", side: "bottom" }],
    namePrefix: "internet",
  },
};

/** 팔레트 묶음: 패킷이 나가는 순서(단말 → 스위칭 → 라우팅·경계 → 인터넷) */
export const PALETTE_GROUPS: { label: string; kinds: DeviceKind[] }[] = [
  { label: "단말", kinds: ["pc", "laptop", "phone", "server"] },
  { label: "스위칭", kinds: ["hub", "switch", "ap"] },
  { label: "라우팅·경계", kinds: ["router", "gateway", "nat", "firewall", "lb", "internet"] },
];
export const PALETTE_ORDER: DeviceKind[] = PALETTE_GROUPS.flatMap((g) => g.kinds);
