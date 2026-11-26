// docs/77 phase 3 (3c): the console side of streamed downloads on the agent's `files` data channel.
//
// One file at a time. Bytes are written to the sink IN ORDER, one write at a time, and the agent is credited with what
// has been WRITTEN (not merely received): it never runs more than its window (8 MiB) ahead, so a slow disk bounds this
// side's memory too. The running SHA-256 must equal the digest announced in `start`; otherwise the sink is aborted
// (the browser discards a FileSystemWritableFileStream's swap file), as it is on any error, cancel or silence.
//
// Wire: see the agent's file_stream.rs. console -> agent: get / credit / cancel. agent -> console: start, binary
// chunks, done, error.
import { Sha256Stream } from "./sha256_stream";

/** Where streamed bytes go: a FileSystemWritableFileStream in practice. */
export interface StreamSink {
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(): Promise<void>;
}

export interface StreamResult {
  name: string;
  size: number;
  sha256: string;
}

/** The subset of RTCDataChannel this client uses (a fake in tests). */
export interface FilesChannelLike {
  readyState: string;
  binaryType: string;
  send(data: string): void;
  close(): void;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: unknown) => void) | null;
}

/** Credit the agent after this many newly written bytes (and always at the end). */
export const CREDIT_EVERY = 256 * 1024;
/** No message from the agent for this long ends the download (once it has started). */
export const SILENCE_MS = 60_000;
/** Before `start` the agent is hashing the whole file (up to 4 GiB; a slow disk takes minutes): wait this long for it
 *  (3b review SEC-003). */
export const START_WAIT_MS = 10 * 60_000;
/** The largest file this client accepts (the agent's lease limit, docs/77 phase 3b). Review M3: never trust the
 *  announced size beyond it. */
export const DEFAULT_MAX_BYTES = 4 * 1024 * 1024 * 1024;
/** The agent may be at most its window (8 MiB) ahead of what was written; more than this is refused (review M3). */
export const MAX_AHEAD = 8 * 1024 * 1024 + 1024 * 1024;
const SHA256_RE = /^[0-9a-f]{64}$/;

interface Pending {
  id: string;
  sink: StreamSink;
  onProgress?: (written: number, size: number) => void;
  resolve: (r: StreamResult) => void;
  reject: (e: Error) => void;
  start?: { name: string; size: number; sha256: string };
  received: number;
  written: number;
  credited: number;
  hash: Sha256Stream;
  writing: Promise<void>;
  failed: boolean;
  silence?: ReturnType<typeof setTimeout>;
}

export class FileStreamClient {
  private chan: FilesChannelLike | null = null;
  private opening: Promise<FilesChannelLike> | null = null;
  private current: Pending | null = null;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly open: () => FilesChannelLike | null,
    private readonly silenceMs = SILENCE_MS,
    private readonly maxBytes = DEFAULT_MAX_BYTES,
    private readonly startWaitMs = START_WAIT_MS,
  ) {}

  /**
   * Stream `path` (relative to the agent's transfer folder, e.g. a staged name) into `sink`. Queued: one at a time. The
   * sink may be a function that opens it: it is then called INSIDE the queue (review L6: two queued Gets cannot pick the
   * same local name before either exists).
   */
  get(
    path: string,
    sink: StreamSink | (() => Promise<StreamSink>),
    onProgress?: (written: number, size: number) => void,
  ): Promise<StreamResult> {
    const run = () => this.run(path, sink, onProgress);
    const p = this.queue.then(run, run);
    this.queue = p.catch(() => undefined);
    return p;
  }

  /** Stop the download in flight (the sink is aborted). */
  cancel(): void {
    const p = this.current;
    if (!p) return;
    this.send({ t: "cancel", id: p.id });
    void this.fail(p, new Error("cancelled"));
  }

  /** Drop the channel: the next get opens a fresh one, so chunks still in flight for an ended download can never be
   *  read as the next one's (review L5). The agent ends whatever was streaming when its channel closes. */
  private resetChannel(): void {
    const ch = this.chan;
    this.chan = null;
    if (ch) {
      ch.onmessage = null;
      ch.onclose = null;
      try { ch.close(); } catch { /* already closed */ }
    }
  }

  close(): void {
    this.chan?.close();
    this.chan = null;
  }

  private channel(): Promise<FilesChannelLike> {
    if (this.chan && this.chan.readyState === "open") return Promise.resolve(this.chan);
    if (this.opening) return this.opening;
    this.opening = new Promise<FilesChannelLike>((resolve, reject) => {
      const ch = this.open();
      if (!ch) {
        reject(new Error("the session is not connected"));
        return;
      }
      ch.binaryType = "arraybuffer";
      ch.onmessage = (ev) => this.onMessage(ev.data);
      ch.onclose = () => {
        if (this.chan === ch) this.chan = null;
        const p = this.current;
        if (p) void this.fail(p, new Error("the transfer channel closed"));
        reject(new Error("the transfer channel closed"));
      };
      ch.onopen = () => {
        this.chan = ch;
        resolve(ch);
      };
      if (ch.readyState === "open") {
        // Already open (it opened before the handler was attached).
        this.chan = ch;
        resolve(ch);
      }
    }).finally(() => {
      this.opening = null;
    });
    return this.opening;
  }

  private send(msg: object): void {
    try {
      this.chan?.send(JSON.stringify(msg));
    } catch {
      /* a closed channel is reported by onclose */
    }
  }

  private async run(
    path: string,
    sinkOrOpen: StreamSink | (() => Promise<StreamSink>),
    onProgress?: (w: number, s: number) => void,
  ): Promise<StreamResult> {
    const sink = typeof sinkOrOpen === "function" ? await sinkOrOpen() : sinkOrOpen;
    let ch: FilesChannelLike;
    try {
      ch = await this.channel();
    } catch (e) {
      await sink.abort().catch(() => undefined);
      throw e;
    }
    return new Promise<StreamResult>((resolve, reject) => {
      const p: Pending = {
        id: crypto.randomUUID(),
        sink,
        onProgress,
        resolve,
        reject,
        received: 0,
        written: 0,
        credited: 0,
        hash: new Sha256Stream(),
        writing: Promise.resolve(),
        failed: false,
      };
      this.current = p;
      this.armSilence(p);
      ch.send(JSON.stringify({ t: "get", id: p.id, path }));
    });
  }

  private armSilence(p: Pending): void {
    if (p.silence) clearTimeout(p.silence);
    // Before `start` the agent is still hashing the file: a longer wait (never shorter than the configured silence).
    const wait = p.start ? this.silenceMs : Math.max(this.silenceMs, this.startWaitMs);
    p.silence = setTimeout(() => {
      this.send({ t: "cancel", id: p.id });
      void this.fail(p, new Error(p.start ? "the remote machine stopped sending" : "the remote machine did not start sending"));
    }, wait);
  }

  private async fail(p: Pending, e: Error): Promise<void> {
    if (p.failed) return;
    p.failed = true;
    if (p.silence) clearTimeout(p.silence);
    if (this.current === p) this.current = null;
    // Bytes of this download may still be on the way: never read them as the next one's (review L5).
    if (p.start) this.resetChannel();
    await p.writing.catch(() => undefined);
    await p.sink.abort().catch(() => undefined);
    p.reject(e);
  }

  private onMessage(data: unknown): void {
    const p = this.current;
    if (!p || p.failed) return;
    this.armSilence(p);
    if (typeof data === "string") {
      let msg: { t?: string; id?: string; name?: unknown; size?: unknown; sha256?: unknown; bytes?: unknown; message?: unknown };
      try {
        msg = JSON.parse(data);
      } catch {
        void this.fail(p, new Error("protocol error"));
        return;
      }
      if (msg.id !== undefined && msg.id !== p.id) return; // a late message for an earlier download
      if (msg.t === "start") {
        if (p.start || typeof msg.name !== "string" || typeof msg.size !== "number" || !Number.isSafeInteger(msg.size) ||
          msg.size < 0 || typeof msg.sha256 !== "string" || !SHA256_RE.test(msg.sha256)) {
          void this.fail(p, new Error("protocol error"));
          return;
        }
        if (msg.size > this.maxBytes) {
          this.send({ t: "cancel", id: p.id });
          void this.fail(p, new Error(`the file is larger than ${Math.round(this.maxBytes / (1024 * 1024))} MiB`));
          return;
        }
        p.start = { name: msg.name, size: msg.size, sha256: msg.sha256 };
        if (msg.size === 0) this.credit(p, true); // nothing to write: ask for done at once
      } else if (msg.t === "done") {
        void this.finish(p, msg.bytes);
      } else if (msg.t === "error") {
        void this.fail(p, new Error(typeof msg.message === "string" ? msg.message : "the download failed"));
      } else {
        void this.fail(p, new Error("protocol error"));
      }
      return;
    }
    const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : null;
    if (!bytes || !p.start) {
      void this.fail(p, new Error("protocol error"));
      return;
    }
    p.received += bytes.length;
    if (p.received - p.written > MAX_AHEAD) {
      // An agent that ignores credits would grow this tab's queued copies without bound (review M3).
      this.send({ t: "cancel", id: p.id });
      void this.fail(p, new Error("the remote machine sent faster than it was allowed to"));
      return;
    }
    if (p.received > p.start.size) {
      this.send({ t: "cancel", id: p.id });
      void this.fail(p, new Error("the remote machine sent more than the file's size"));
      return;
    }
    p.hash.update(bytes);
    // Writes are chained: in order, one at a time. A copy, because the channel may reuse its buffer.
    const chunk = bytes.slice();
    p.writing = p.writing.then(async () => {
      if (p.failed) return;
      await p.sink.write(chunk);
      p.written += chunk.length;
      p.onProgress?.(p.written, p.start!.size);
      this.credit(p, p.written === p.start!.size);
    }).catch((e) => {
      this.send({ t: "cancel", id: p.id });
      void this.fail(p, e instanceof Error ? e : new Error(String(e)));
    });
  }

  private credit(p: Pending, force: boolean): void {
    if (force || p.written - p.credited >= CREDIT_EVERY) {
      p.credited = p.written;
      this.send({ t: "credit", id: p.id, written: p.written });
    }
  }

  private async finish(p: Pending, bytes: unknown): Promise<void> {
    await p.writing.catch(() => undefined);
    if (p.failed) return;
    const s = p.start;
    if (!s || bytes !== s.size || p.written !== s.size) {
      void this.fail(p, new Error("the download ended early"));
      return;
    }
    if (p.hash.digestHex() !== s.sha256) {
      void this.fail(p, new Error("the file changed while it was being copied; nothing was saved"));
      return;
    }
    if (p.silence) clearTimeout(p.silence);
    try {
      await p.sink.close();
    } catch (e) {
      p.failed = true;
      if (this.current === p) this.current = null;
      p.reject(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    p.failed = true; // settled
    if (this.current === p) this.current = null;
    p.resolve({ ...s });
  }
}
