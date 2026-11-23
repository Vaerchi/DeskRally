/** Only display-layout session endings qualify for a fresh automatic connection. */
export const DISPLAY_LAYOUT_END_PREFIX = "session ended: the display layout on this machine changed";
export function isDisplayLayoutEnd(message: string): boolean {
  return message.startsWith(DISPLAY_LAYOUT_END_PREFIX);
}

/** Give the agent time to re-register its new display layout. */
export const LAYOUT_RECONNECT_DELAY_MS = 1500;

/** Bound automatic layout reconnects across connections in this console. */
export class LayoutReconnectBudget {
  private attempts: number[] = [];
  constructor(private readonly max = 3, private readonly windowMs = 600_000) {}
  take(now: number): boolean {
    this.attempts = this.attempts.filter(at => at > now - this.windowMs);
    if (this.attempts.length >= this.max) return false;
    this.attempts.push(now);
    return true;
  }
}
