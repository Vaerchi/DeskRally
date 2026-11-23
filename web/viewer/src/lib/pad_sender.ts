/**
 * Coalesces the trackpad's pointer moves and wheel deltas to a fixed cadence.
 *
 * A finger reports far more moves than the guest needs, and every one used to become an input event
 * the instant it arrived. Here only the LATEST cursor position is kept and sent once per tick, and
 * wheel notches are SUMMED (distance is never dropped, only batched). `flush()` sends whatever is
 * pending immediately and is called before any button event, so a click always lands at the newest
 * position and never overtakes a move that preceded it.
 *
 * The scheduler is injected (a timer in the app, a manual queue in tests); nothing here reads a clock.
 */
export interface PadSenderDeps {
  /** Run `cb` once, later. Returns a cancel function. */
  schedule(cb: () => void): () => void;
  /** Send the cursor's CURRENT position (the sender does not carry coordinates: the newest wins). */
  sendMove(): void;
  sendWheel(dx: number, dy: number): void;
}

export interface PadSender {
  move(): void;
  wheel(dx: number, dy: number): void;
  /** Send everything pending now, move first so a scroll happens where the cursor is. */
  flush(): void;
  pending(): boolean;
}

export function createPadSender(deps: PadSenderDeps): PadSender {
  let moveDirty = false;
  let wx = 0;
  let wy = 0;
  let cancel: (() => void) | null = null;

  const pending = () => moveDirty || wx !== 0 || wy !== 0;
  const flush = () => {
    if (cancel) {
      cancel();
      cancel = null;
    }
    if (moveDirty) {
      moveDirty = false;
      deps.sendMove();
    }
    if (wx !== 0 || wy !== 0) {
      const x = wx;
      const y = wy;
      wx = 0;
      wy = 0;
      deps.sendWheel(x, y);
    }
  };
  const arm = () => {
    if (cancel) return;
    cancel = deps.schedule(() => {
      cancel = null;
      flush();
    });
  };
  return {
    move() {
      moveDirty = true;
      arm();
    },
    wheel(dx, dy) {
      wx += dx;
      wy += dy;
      arm();
    },
    flush,
    pending,
  };
}
export const PAD_SEND_INTERVAL_MS = 16;
