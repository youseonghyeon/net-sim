// (time, priority, seq) 순으로 꺼내는 결정론적 이벤트 큐.

export interface Scheduled<T> {
  time: number;
  priority: number;
  seq: number;
  payload: T;
}

export class Scheduler<T> {
  private heap: Scheduled<T>[] = [];
  private seq = 0;

  get size(): number {
    return this.heap.length;
  }

  /** 조건을 만족하는 항목 수 (취소된 타이머 등을 빼고 세기 위해) */
  count(pred: (payload: T) => boolean): number {
    let n = 0;
    for (const item of this.heap) if (pred(item.payload)) n++;
    return n;
  }

  push(time: number, payload: T, priority = 0): Scheduled<T> {
    const item: Scheduled<T> = { time, priority, seq: this.seq++, payload };
    this.heap.push(item);
    this.siftUp(this.heap.length - 1);
    return item;
  }

  peek(): Scheduled<T> | undefined {
    return this.heap[0];
  }

  pop(): Scheduled<T> | undefined {
    const heap = this.heap;
    if (heap.length === 0) return undefined;
    const top = heap[0];
    const last = heap.pop()!;
    if (heap.length > 0) {
      heap[0] = last;
      this.siftDown(0);
    }
    return top;
  }

  private less(a: Scheduled<T>, b: Scheduled<T>): boolean {
    if (a.time !== b.time) return a.time < b.time;
    if (a.priority !== b.priority) return a.priority < b.priority;
    return a.seq < b.seq;
  }

  private siftUp(i: number): void {
    const h = this.heap;
    while (i > 0) {
      const parent = (i - 1) >> 1;
      if (!this.less(h[i]!, h[parent]!)) break;
      [h[i], h[parent]] = [h[parent]!, h[i]!];
      i = parent;
    }
  }

  private siftDown(i: number): void {
    const h = this.heap;
    for (;;) {
      const l = 2 * i + 1;
      const r = l + 1;
      let m = i;
      if (l < h.length && this.less(h[l]!, h[m]!)) m = l;
      if (r < h.length && this.less(h[r]!, h[m]!)) m = r;
      if (m === i) return;
      [h[i], h[m]] = [h[m]!, h[i]!];
      i = m;
    }
  }
}
