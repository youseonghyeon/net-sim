import { beforeEach, describe, expect, it } from "vitest";
import {
  addDevice,
  beginCoalesce,
  canRedo,
  canUndo,
  clearAll,
  connectDevices,
  copySelected,
  duplicateSelected,
  endCoalesce,
  exportJson,
  importJson,
  loadExample,
  moveDevices,
  paste,
  redo,
  removeSelected,
  selectAll,
  selectedDeviceIds,
  selection,
  toggleDeviceSelection,
  topology,
  undo,
  updateDevices,
} from "../src/model/store";

beforeEach(() => {
  clearAll();
  // 히스토리는 모듈 전역이라 테스트마다 비운다
  while (canUndo.value) undo();
  while (canRedo.value) redo();
  clearAll();
  while (canUndo.value) undo();
});

describe("되돌리기", () => {
  it("추가 → 연결 → 삭제를 한 단계씩 되돌리고 다시 실행한다", () => {
    const sw = addDevice("switch", 0, 0);
    const pc = addDevice("pc", 0, 200);
    expect(connectDevices(pc.id, sw.id).cable).toBeDefined();
    expect(topology.value.cables).toHaveLength(1);
    undo();
    expect(topology.value.cables).toHaveLength(0);
    expect(topology.value.devices).toHaveLength(2);
    undo();
    expect(topology.value.devices).toHaveLength(1);
    redo();
    redo();
    expect(topology.value.devices).toHaveLength(2);
    expect(topology.value.cables).toHaveLength(1);
    expect(canRedo.value).toBe(false);
    // 새 편집을 하면 다시 실행 스택은 사라진다
    undo();
    addDevice("hub", 300, 0);
    expect(canRedo.value).toBe(false);
  });

  it("드래그(연속 이동)는 한 단계로 묶이고, 되돌리면 시작 위치로 간다", () => {
    const pc = addDevice("pc", 0, 0);
    const starts = new Map([[pc.id, { x: 0, y: 0 }]]);
    beginCoalesce();
    moveDevices(starts, 10, 0);
    moveDevices(starts, 50, 0);
    moveDevices(starts, 96, 8);
    endCoalesce();
    expect(topology.value.devices[0]).toMatchObject({ x: 96, y: 8 });
    undo();
    expect(topology.value.devices[0]).toMatchObject({ x: 0, y: 0 });
    redo();
    expect(topology.value.devices[0]).toMatchObject({ x: 96, y: 8 });
  });

  it("되돌린 뒤 사라진 장치는 선택에서 빠진다", () => {
    const a = addDevice("pc", 0, 0);
    const b = addDevice("pc", 100, 0);
    selection.value = { type: "devices", ids: [a.id, b.id] };
    undo(); // b 삭제
    expect(selectedDeviceIds(selection.value)).toEqual([a.id]);
    expect(selection.value?.type).toBe("device");
  });
});

describe("다중 선택·복사", () => {
  it("Shift+클릭 토글과 전체 선택", () => {
    const a = addDevice("pc", 0, 0);
    const b = addDevice("pc", 100, 0);
    selection.value = null;
    toggleDeviceSelection(a.id);
    expect(selection.value).toEqual({ type: "device", id: a.id });
    toggleDeviceSelection(b.id);
    expect(selection.value).toEqual({ type: "devices", ids: [a.id, b.id] });
    toggleDeviceSelection(a.id);
    expect(selection.value).toEqual({ type: "device", id: b.id });
    selectAll();
    expect(selectedDeviceIds(selection.value)).toHaveLength(2);
  });

  it("복사·붙여넣기는 묶음 안의 케이블·설정을 따라오고 새 이름·MAC 을 받는다", () => {
    const sw = addDevice("switch", 0, 0);
    const pc = addDevice("pc", 0, 200);
    const srv = addDevice("server", 200, 200);
    connectDevices(pc.id, sw.id);
    connectDevices(srv.id, sw.id);
    selection.value = { type: "devices", ids: [sw.id, pc.id] }; // srv 는 빼고
    expect(copySelected()).toBe(2);
    const pasted = paste();
    expect(pasted.map((d) => d.kind)).toEqual(["switch", "pc"]);
    expect(pasted.map((d) => d.name)).toEqual(["sw-2", "pc-2"]);
    const t = topology.value;
    expect(t.devices).toHaveLength(5);
    expect(t.cables).toHaveLength(3); // sw-pc 복제, sw-srv 는 srv 가 없어 안 따라옴
    expect(new Set(t.devices.map((d) => d.mac)).size).toBe(5);
    expect(selectedDeviceIds(selection.value)).toEqual(pasted.map((d) => d.id));
    // 두 번째 붙여넣기는 더 비켜 놓는다
    const again = paste();
    expect(again[0]!.x).toBeGreaterThan(pasted[0]!.x);
    // 되돌리기 한 번 = 붙여넣기 한 번
    undo();
    expect(topology.value.devices).toHaveLength(5);
  });

  it("복제(⌘D)와 여러 개 삭제", () => {
    const a = addDevice("pc", 0, 0);
    selection.value = { type: "device", id: a.id };
    const dup = duplicateSelected();
    expect(dup).toHaveLength(1);
    expect(topology.value.devices).toHaveLength(2);
    selectAll();
    removeSelected();
    expect(topology.value.devices).toHaveLength(0);
    expect(selection.value).toBeNull();
  });

  it("일괄 설정: 선택한 호스트만 바뀐다", () => {
    const a = addDevice("pc", 0, 0);
    const b = addDevice("pc", 100, 0);
    const c = addDevice("pc", 200, 0);
    updateDevices([a.id, b.id], (d) => ({ ...d, host: { ...d.host!, ipMode: "static", gateway: "192.168.0.5" } }));
    const byId = new Map(topology.value.devices.map((d) => [d.id, d]));
    expect(byId.get(a.id)!.host!.gateway).toBe("192.168.0.5");
    expect(byId.get(b.id)!.host!.ipMode).toBe("static");
    expect(byId.get(c.id)!.host!.ipMode).toBe("dhcp");
  });
});

describe("JSON 저장·불러오기", () => {
  it("내려받은 JSON 을 다시 올리면 같은 토폴로지가 되고, 깨진 파일은 이유를 말한다", () => {
    loadExample("parts");
    const before = topology.value;
    const text = exportJson();
    expect(JSON.parse(text)).toMatchObject({ app: "net-sim", version: 1 });
    clearAll();
    const r = importJson(text);
    expect(r).toEqual({ devices: before.devices.length });
    expect(topology.value.devices.map((d) => d.name)).toEqual(before.devices.map((d) => d.name));
    expect(topology.value.cables).toHaveLength(before.cables.length);
    expect(importJson("{not json").error).toContain("JSON");
    expect(importJson(JSON.stringify({ devices: [{ id: "x", kind: "toaster", name: "t", x: 0, y: 0 }], cables: [] })).error).toContain("모르는 장치 종류");
    expect(importJson(JSON.stringify({ devices: [] })).error).toContain("cables");
    // 실패해도 기존 토폴로지는 그대로
    expect(topology.value.devices).toHaveLength(before.devices.length);
    // 불러오기도 되돌릴 수 있다
    undo();
    expect(topology.value.devices).toHaveLength(0);
  });

  it("사라진 장치를 가리키는 케이블·빈 설정은 정규화로 정리된다", () => {
    const r = importJson(
      JSON.stringify({
        devices: [
          { id: "a", kind: "pc", name: "pc-9", x: 0, y: 0 },
          { id: "b", kind: "gateway", name: "gw-9", x: 0, y: 200 },
        ],
        cables: [
          { id: "c1", a: { device: "a", port: 0 }, b: { device: "b", port: 1 } },
          { id: "c2", a: { device: "a", port: 0 }, b: { device: "ghost", port: 0 } },
        ],
      }),
    );
    expect(r.error).toBeUndefined();
    const t = topology.value;
    expect(t.cables).toHaveLength(1);
    expect(t.devices[0]!.host?.ipMode).toBe("dhcp");
    expect(t.devices[1]!.l3?.interfaces).toHaveLength(3);
    expect(t.devices.every((d) => d.mac)).toBe(true);
  });
});
