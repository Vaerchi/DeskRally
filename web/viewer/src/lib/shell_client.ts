// Under the Hood SYSTEM terminal (docs/76), console side: the protocol over the session's one `shell` data channel.
// Text messages are JSON control; binary messages are terminal bytes (VT). The agent decides everything that matters
// (grant, confirmation token, gate, expiry); this client only speaks the protocol and reports state.
//
// Opening is two steps because the agent always demands its confirmation token for a SYSTEM shell: the technician
// confirms in the console (typed machine name), we send `open`; the agent answers `needs_confirmation` with a token,
// and we resend `open` with it once. Audit events do NOT travel here (the agent sends them on the session channel).

/** The parts of RTCDataChannel the client uses (a fake is enough in tests). */
export interface ShellChannelLike {
  readyState: RTCDataChannelState;
  binaryType: BinaryType;
  send(data: string | ArrayBuffer | ArrayBufferView): void;
  close(): void;
  onopen: ((ev: Event) => void) | null;
  onmessage: ((ev: MessageEvent) => void) | null;
  onclose: ((ev: Event) => void) | null;
}

export type ShellState =
  | { kind: "connecting" }
  | { kind: "opening" }
  | { kind: "open"; shellId: string }
  | { kind: "refused"; reason: string }
  | { kind: "closed"; reason: string; exitCode: number | null }
  | { kind: "disconnected" };

export interface ShellClientEvents {
  onState(state: ShellState): void;
  onOutput(bytes: Uint8Array): void;
}

/** The largest single input message; the agent closes the channel on anything bigger than 16 KiB. */
export const MAX_SHELL_INPUT_BYTES = 8 * 1024;

export class ShellClient {
  private state: ShellState = { kind: "connecting" };
  private pendingOpen: { cols: number; rows: number } | null = null;
  private tokenRetried = false;
  private readonly encoder = new TextEncoder();

  constructor(private readonly dc: ShellChannelLike, private readonly events: ShellClientEvents) {
    dc.binaryType = "arraybuffer";
    dc.onopen = () => {
      if (this.pendingOpen) this.sendOpen(this.pendingOpen.cols, this.pendingOpen.rows);
    };
    dc.onmessage = (ev) => this.onMessage(ev.data);
    dc.onclose = () => this.set({ kind: "disconnected" });
  }

  get current(): ShellState {
    return this.state;
  }

  /** Ask for a shell (after the technician confirmed in the console). Sent as soon as the channel opens. */
  open(cols: number, rows: number): void {
    this.pendingOpen = { cols, rows };
    this.tokenRetried = false;
    this.set({ kind: "opening" });
    if (this.dc.readyState === "open") this.sendOpen(cols, rows);
  }

  /** Keystrokes / paste, chunked under the agent's message cap. Ignored unless a shell is open. */
  input(data: string | Uint8Array): void {
    if (this.state.kind !== "open" || this.dc.readyState !== "open") return;
    const bytes = typeof data === "string" ? this.encoder.encode(data) : data;
    for (let i = 0; i < bytes.length; i += MAX_SHELL_INPUT_BYTES) {
      this.dc.send(bytes.slice(i, i + MAX_SHELL_INPUT_BYTES));
    }
  }

  resize(cols: number, rows: number): void {
    if (this.state.kind === "open" && this.dc.readyState === "open") {
      this.dc.send(JSON.stringify({ t: "resize", cols: clamp(cols), rows: clamp(rows) }));
    }
  }

  /** Close the shell (the agent kills its whole process tree and records it). */
  close(): void {
    if (this.dc.readyState === "open") this.dc.send(JSON.stringify({ t: "close" }));
  }

  /** Close the channel itself (leaving the tab or the session). */
  dispose(): void {
    this.dc.onopen = null;
    this.dc.onmessage = null;
    this.dc.onclose = null;
    try {
      this.dc.close();
    } catch {
      // already closed
    }
  }

  private sendOpen(cols: number, rows: number, token?: string): void {
    this.dc.send(JSON.stringify({ t: "open", cols: clamp(cols), rows: clamp(rows), ...(token ? { token } : {}) }));
  }

  private onMessage(data: unknown): void {
    if (data instanceof ArrayBuffer) {
      this.events.onOutput(new Uint8Array(data));
      return;
    }
    if (typeof data !== "string") return;
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(data) as Record<string, unknown>;
    } catch {
      return;
    }
    switch (msg.t) {
      case "needs_confirmation": {
        // The technician already confirmed in the console; answer the agent's token once. A second request means
        // the agent did not accept it: stop rather than loop.
        const token = typeof msg.token === "string" ? msg.token : "";
        if (!this.tokenRetried && token && this.pendingOpen) {
          this.tokenRetried = true;
          this.sendOpen(this.pendingOpen.cols, this.pendingOpen.rows, token);
        } else {
          this.set({ kind: "refused", reason: "the agent did not accept the confirmation" });
        }
        break;
      }
      case "opened":
        this.set({ kind: "open", shellId: typeof msg.shell_id === "string" ? msg.shell_id : "" });
        break;
      case "refused":
        this.set({ kind: "refused", reason: typeof msg.reason === "string" ? msg.reason : "refused" });
        break;
      case "closed":
        this.set({
          kind: "closed",
          reason: typeof msg.reason === "string" ? msg.reason : "closed",
          exitCode: typeof msg.exit_code === "number" ? msg.exit_code : null,
        });
        break;
    }
  }

  private set(state: ShellState): void {
    this.state = state;
    this.events.onState(state);
  }
}

function clamp(n: number): number {
  return Math.max(1, Math.min(500, Math.floor(n) || 1));
}
