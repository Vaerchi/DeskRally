import type { CommandShell, ControlClient, RunReceipt } from "./control";

type PostReceipt = (receipt: RunReceipt, signal: AbortSignal) => Promise<number>;
const MAX_PENDING = 100;
const RETRY_WINDOW_MS = 10 * 60 * 1000;

export class RunReceiptQueue {
  private pending = 0;

  enqueue(receipt: RunReceipt, post: PostReceipt): void {
    // Refuse new receipts at capacity so accepted receipts retain their retry windows.
    if (this.pending >= MAX_PENDING) {
      console.warn("Run receipt queue is full");
      return;
    }
    this.pending++;
    void this.relay(receipt, post);
  }

  private async relay(receipt: RunReceipt, post: PostReceipt): Promise<void> {
    const deadline = Date.now() + RETRY_WINDOW_MS;
    const abort = new AbortController();
    const timeout = setTimeout(() => abort.abort(), RETRY_WINDOW_MS);
    try {
      for (let delay = 1000; Date.now() < deadline; delay = Math.min(delay * 2, 30000)) {
        let status = 0;
        try {
          status = await post(receipt, abort.signal);
        } catch {
          // A failed fetch is retried within the same deadline.
        }
        if (status === 200) return;
        if (status !== 0 && status !== 429 && (status < 500 || status >= 600)) {
          console.warn("Run receipt refused", status);
          return;
        }
        const remaining = deadline - Date.now();
        if (remaining <= 0) break;
        await new Promise<void>((resolve) => setTimeout(resolve, Math.min(delay, remaining)));
      }
      console.warn("Run receipt relay expired");
    } finally {
      clearTimeout(timeout);
      this.pending--;
    }
  }
}

const queue = new RunReceiptQueue();

/** Negotiation and correlation for one control channel. Queued receipts outlive it. */
export class RunReceiptSession {
  private supported = false;
  private readonly requests = new Set<string>();

  constructor(private readonly post: PostReceipt) {}

  setFeatures(features: readonly string[]): void {
    this.supported = features.includes("run_receipt_v1");
  }

  dispatch(control: Pick<ControlClient, "runCommand">, command: string, shell: CommandShell, asUser: boolean, requestId: string): void {
    if (this.supported && requestId) {
      this.requests.add(requestId);
      control.runCommand(command, shell, asUser, requestId);
    } else {
      control.runCommand(command, shell, asUser);
    }
  }

  receive(receipt: RunReceipt): void {
    if (this.requests.delete(receipt.requestId)) queue.enqueue(receipt, this.post);
  }
}
