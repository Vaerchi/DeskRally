/**
 * Canonical bidirectional file-transfer codec + minimal client (browser side, M8).
 *
 * Byte-for-byte mirror of the Rust `crates/agent-core/src/file_transfer.rs`. Messages ride as the
 * payload of a `Frame` tagged `ChannelId.FileTransfer` on the single "frames" data channel (see
 * transport.ts). Two categories share the channel, dispatched on the **first payload byte**:
 *
 *  - **Control** (`Offer`/`Done`/`Ack`/`Request`/`Error`) — JSON, adjacently tagged
 *    `{"t":<variant>,"c":<content>}` exactly like input.ts. JSON always starts with `{` (0x7B =
 *    {@link CONTROL_TAG}). Transfer ids are UUID strings; digests are lowercase hex.
 *  - **`Chunk`** — the bulk path — a compact binary payload `[0x01][id:16][seq:u32 BE][raw data]`
 *    ({@link CHUNK_TAG} = 0x01), carrying raw file bytes with **no base64**.
 *
 * Keep this in lockstep with the Rust unit tests: the exact JSON strings here are the same literals
 * the Rust `round_trip_control` asserts.
 */

/** Leading byte of a binary {@link Chunk} payload. */
export const CHUNK_TAG = 0x01;
/** Leading byte of a JSON control payload — `{`. */
export const CONTROL_TAG = 0x7b;
/** Max raw bytes per {@link Chunk} (48 KiB — safe under the SCTP data-channel message ceiling). */
export const MAX_CHUNK_DATA = 48 * 1024;

/** Announce an incoming file (upload offer, or download reply). */
export interface Offer {
  id: string;
  name: string;
  size: number;
  sha256: string;
}

/** One binary run of a transfer's bytes. */
export interface Chunk {
  id: string;
  seq: number;
  data: Uint8Array;
}

/** A single file-transfer message (control or chunk). Mirror of the Rust `Message` enum. */
export type Message =
  | { t: "Offer"; c: Offer }
  | { t: "Chunk"; c: Chunk }
  | { t: "Done"; c: { id: string } }
  | { t: "Ack"; c: { id: string; ok: boolean; message: string } }
  | { t: "Request"; c: { id: string; path: string } }
  | { t: "Error"; c: { id: string; message: string } }
  /**
   * Agent → controller only: the tamper-evident audit record this transfer produced (ADR-008).
   * `event` is the agent's `AuditEvent` as an opaque JSON object — the controller does not
   * interpret it, it forwards it verbatim to `POST /audit/ingest` (see `lib/audit_forward.ts`),
   * and the control plane re-hashes the canonical form to verify it.
   */
  | { t: "Audit"; c: { id: string; event: unknown } };

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// --- uuid <-> 16 bytes -------------------------------------------------------------------------

/** Convert a hyphenated UUID string to its 16 raw bytes (for a binary chunk header). */
export function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, "");
  if (hex.length !== 32) throw new Error(`invalid uuid: ${uuid}`);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Convert 16 raw bytes to a hyphenated (8-4-4-4-12) lowercase UUID string. */
export function bytesToUuid(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw new Error(`invalid uuid bytes: ${bytes.length}`);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// --- codec -------------------------------------------------------------------------------------

/**
 * Encode one {@link Message} to its wire bytes: JSON for control, compact binary for a chunk.
 * Byte-compatible with the Rust `file_transfer::encode`.
 */
export function encodeMessage(msg: Message): Uint8Array {
  if (msg.t === "Chunk") {
    const { id, seq, data } = msg.c;
    const out = new Uint8Array(1 + 16 + 4 + data.length);
    out[0] = CHUNK_TAG;
    out.set(uuidToBytes(id), 1);
    new DataView(out.buffer).setUint32(17, seq >>> 0, /* littleEndian */ false); // big-endian
    out.set(data, 21);
    return out;
  }
  // Control: adjacently-tagged JSON. Serialize the exact key order Rust/serde emits.
  return encoder.encode(JSON.stringify(controlToJson(msg)));
}

/**
 * Decode one {@link Message} from wire bytes, dispatching on the leading byte
 * (CONTROL_TAG → JSON, CHUNK_TAG → binary chunk).
 */
export function decodeMessage(bytes: Uint8Array): Message {
  if (bytes.length === 0) throw new Error("empty file-transfer payload");
  const tag = bytes[0];
  if (tag === CONTROL_TAG) {
    const obj = JSON.parse(decoder.decode(bytes)) as Message;
    if (!obj || typeof obj.t !== "string") throw new Error("malformed control message");
    return obj;
  }
  if (tag === CHUNK_TAG) {
    if (bytes.length < 21) throw new Error(`truncated chunk: ${bytes.length} bytes`);
    const id = bytesToUuid(bytes.slice(1, 17));
    const seq = new DataView(bytes.buffer, bytes.byteOffset + 17, 4).getUint32(0, false);
    const data = bytes.slice(21);
    return { t: "Chunk", c: { id, seq, data } };
  }
  throw new Error(`unrecognized file-transfer tag byte 0x${tag.toString(16)}`);
}

/**
 * Produce the plain object serialized for a control message, pinning the field order to match
 * Rust/serde's output (so the JSON strings are byte-identical). Chunk is not a control message.
 */
function controlToJson(msg: Exclude<Message, { t: "Chunk" }>): unknown {
  switch (msg.t) {
    case "Offer":
      return { t: "Offer", c: { id: msg.c.id, name: msg.c.name, size: msg.c.size, sha256: msg.c.sha256 } };
    case "Done":
      return { t: "Done", c: { id: msg.c.id } };
    case "Ack":
      return { t: "Ack", c: { id: msg.c.id, ok: msg.c.ok, message: msg.c.message } };
    case "Request":
      return { t: "Request", c: { id: msg.c.id, path: msg.c.path } };
    case "Error":
      return { t: "Error", c: { id: msg.c.id, message: msg.c.message } };
    case "Audit":
      return { t: "Audit", c: { id: msg.c.id, event: msg.c.event } };
  }
}

// --- helpers -----------------------------------------------------------------------------------

/** Lowercase-hex SHA-256 of `data` (via Web Crypto). Matches Rust `file_transfer::sha256_hex`. */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  // Copy into a fresh ArrayBuffer-backed view so the BufferSource type is unambiguous (a view over
  // a SharedArrayBuffer is not a valid digest input under strict DOM typings).
  const buf = new Uint8Array(data).buffer;
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Split `data` into ordered {@link Chunk}s of ≤ {@link MAX_CHUNK_DATA} bytes, seq starting at 0. */
export function chunkFile(id: string, data: Uint8Array): Chunk[] {
  const chunks: Chunk[] = [];
  for (let off = 0, seq = 0; off < data.length; off += MAX_CHUNK_DATA, seq++) {
    chunks.push({ id, seq, data: data.slice(off, off + MAX_CHUNK_DATA) });
  }
  return chunks;
}

/** Random UUID v4 string (for a new transfer id). */
export function newTransferId(): string {
  return crypto.randomUUID();
}

// --- bounds ------------------------------------------------------------------------------------

/** Default per-file cap (128 MiB). Understood as the "download too large" ceiling in the UI. */
export const DEFAULT_MAX_FILE_BYTES = 128 * 1024 * 1024;
/** Default concurrent inbound transfers per client. */
export const DEFAULT_MAX_ACTIVE_TRANSFERS = 4;
/** Default hard cap on chunk count per transfer (protects metadata when the peer streams 1B chunks). */
export const DEFAULT_MAX_PARTS_PER_TRANSFER = 8192;
/** Default per-transfer inactivity timeout in milliseconds. */
export const DEFAULT_INACTIVITY_MS = 60_000;
/** Default absolute age cap in milliseconds; a legitimate transfer at 128 MiB fits well inside. */
export const DEFAULT_MAX_AGE_MS = 10 * 60_000;
/** Default shared-pool working-byte budget across all client instances. */
export const DEFAULT_POOL_MAX_BYTES = 512 * 1024 * 1024;
/** Default shared-pool concurrent-lease cap, INCLUDING zero-byte transfers. */
export const DEFAULT_POOL_MAX_LEASES = 8;
/**
 * We reserve 4x the advertised transfer size at Offer time. The peer's advertised bytes need to
 * survive as ordered parts, then as an assembled buffer, then as a byte copy for the
 * digest API, then as WebCrypto's own internal snapshot — this bounds CLIENT-MANAGED work,
 * deliberately not attempting to model arbitrary callback retention or browser-engine overhead.
 */
export const RESERVE_MULTIPLIER = 4;

/** A lease against a {@link DownloadMemoryBudget}. Idempotent release. */
export interface DownloadMemoryLease {
  release(): void;
}

/**
 * Shared working-byte + lease-count budget for inbound downloads. The default instance is a
 * MODULE-LEVEL singleton, so a client that reconnects (fresh instance) still contends with any
 * async hash work its predecessor started — a viewer cannot bypass outstanding reservations by
 * dropping and remaking the client. Tests inject a small pool per case; nothing else does.
 */
export class DownloadMemoryBudget {
  private used = 0;
  private leases = 0;
  private readonly maxBytes: number;
  private readonly maxLeases: number;

  constructor(maxBytes = DEFAULT_POOL_MAX_BYTES, maxLeases = DEFAULT_POOL_MAX_LEASES) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new Error("maxBytes must be a nonneg safe integer");
    if (!Number.isSafeInteger(maxLeases) || maxLeases <= 0) throw new Error("maxLeases must be a positive safe integer");
    this.maxBytes = maxBytes;
    this.maxLeases = maxLeases;
  }

  /** Reserve `bytes` and a lease. Returns null if either would exceed the pool. */
  tryAcquire(bytes: number): DownloadMemoryLease | null {
    if (!Number.isSafeInteger(bytes) || bytes < 0) return null;
    if (this.leases + 1 > this.maxLeases) return null;
    if (this.used + bytes > this.maxBytes) return null;
    this.used += bytes;
    this.leases += 1;
    let released = false;
    return {
      release: () => {
        if (released) return;
        released = true;
        this.used -= bytes;
        this.leases -= 1;
      },
    };
  }

  /** Introspection for tests. */
  stats(): { used: number; leases: number; maxBytes: number; maxLeases: number } {
    return { used: this.used, leases: this.leases, maxBytes: this.maxBytes, maxLeases: this.maxLeases };
  }
}

const sharedPool = new DownloadMemoryBudget();

// --- options / validation ---------------------------------------------------------------------

export interface FileTransferLimits {
  maxFileBytes?: number;
  maxActiveTransfers?: number;
  maxPartsPerTransfer?: number;
  inactivityMs?: number;
  maxAgeMs?: number;
}

export interface FileTransferOptions {
  /** Bounded, own-string error surfaces for rejected/aborted inbound transfers. */
  onDownloadError?: (info: { id?: string; name?: string; reason: string }) => void;
  limits?: FileTransferLimits;
  /** Injectable monotonic clock for tests. */
  clock?: () => number;
  /** Injectable shared pool; defaults to the module-level singleton. */
  memoryBudget?: DownloadMemoryBudget;
  /**
   * F06 explicit approval surface. When SET, the client will admit an unsolicited Offer under the
   * F07 bounds, hash-verify it, HOLD the bytes internally, and emit a bounded metadata snapshot
   * here. `onDownload` is only ever called for offers matched by `request()` or after the caller
   * invokes `approveDownload(id)`. When UNSET, unsolicited Offers are refused before reserving.
   */
  onPendingDownloadsChanged?: (pending: readonly PendingDownloadMeta[]) => void;
  /** Cap on the outstanding `request()` map (default 32). Bounds unbounded outbound issuance. */
  maxPendingRequests?: number;
  /** Per-request deadline in ms (default 60_000). The peer must reply within this window. */
  requestDeadlineMs?: number;
}

interface ResolvedLimits {
  maxFileBytes: number;
  maxActiveTransfers: number;
  maxPartsPerTransfer: number;
  inactivityMs: number;
  maxAgeMs: number;
}

function positiveSafeInt(v: unknown, dflt: number, label: string): number {
  if (v === undefined) return dflt;
  if (typeof v !== "number" || !Number.isFinite(v) || !Number.isSafeInteger(v) || v <= 0) {
    throw new Error(`${label} must be a positive finite safe integer`);
  }
  return v;
}

function resolveLimits(l?: FileTransferLimits): ResolvedLimits {
  return {
    maxFileBytes: positiveSafeInt(l?.maxFileBytes, DEFAULT_MAX_FILE_BYTES, "maxFileBytes"),
    maxActiveTransfers: positiveSafeInt(l?.maxActiveTransfers, DEFAULT_MAX_ACTIVE_TRANSFERS, "maxActiveTransfers"),
    maxPartsPerTransfer: positiveSafeInt(l?.maxPartsPerTransfer, DEFAULT_MAX_PARTS_PER_TRANSFER, "maxPartsPerTransfer"),
    inactivityMs: positiveSafeInt(l?.inactivityMs, DEFAULT_INACTIVITY_MS, "inactivityMs"),
    maxAgeMs: positiveSafeInt(l?.maxAgeMs, DEFAULT_MAX_AGE_MS, "maxAgeMs"),
  };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA256_RE = /^[0-9a-f]{64}$/i;
const MAX_NAME_LEN = 4096;
const MAX_PATH_LEN = 4096;

/** Bounds for the F06 explicit-approval surfaces. */
export const DEFAULT_MAX_PENDING_REQUESTS = 32;
export const DEFAULT_REQUEST_DEADLINE_MS = 60_000;

/** Metadata about a completed, verified download awaiting the operator's explicit Save. */
export interface PendingDownloadMeta {
  id: string;
  name: string;
  size: number;
}

/** Extended completed-download payload delivered on `onDownload`. */
export interface DeliveredDownload {
  /** The request UUID from `FileTransferClient.request()` for source "requested"; the offer id for "approved". */
  id: string;
  name: string;
  bytes: Uint8Array;
  sha256: string;
  verified: boolean;
  /** Origin: matched a viewer-issued request, vs. an unsolicited offer the operator approved. */
  source: "requested" | "approved";
}

/**
 * Strip C0/C1 control characters and Unicode bidi/format code points. Ordinary Unicode letters,
 * punctuation, and CJK/emoji stay. Applied for BOTH display and the browser "Save as" name.
 */
export function sanitizeDisplayName(name: string): string {
  // Strip C0/C1 controls and the bidi-OVERRIDE format code points that can spoof filename
  // direction (LRE/RLE/PDF/LRO/RLO + LRI/RLI/FSI/PDI + BOM). Ordinary ZWJ/ZWNJ, LRM/RLM, and CJK
  // joining marks are NOT stripped — they appear inside legitimate filenames (Persian, Indic,
  // family emoji ZWJ sequences), and dropping them would corrupt those names on save.
  // eslint-disable-next-line no-control-regex
  return name
    .replace(/[\x00-\x1F\x7F-\x9F]/g, "")
    .replace(/[\u202A-\u202E\u2066-\u2069\uFEFF]/g, "")
    .slice(0, MAX_NAME_LEN);
}

/** Return the last `/`- or `\`-separated segment of `p`, or `"download"` if empty. */
export function basenameOf(p: string): string {
  const s = String(p ?? "").replace(/\\/g, "/");
  const idx = s.lastIndexOf("/");
  const tail = idx >= 0 ? s.slice(idx + 1) : s;
  const cleaned = sanitizeDisplayName(tail).trim();
  return cleaned.length > 0 ? cleaned : "download";
}

function canonId(id: unknown): string | null {
  if (typeof id !== "string") return null;
  if (!UUID_RE.test(id)) return null;
  return id.toLowerCase();
}

// --- minimal client ---------------------------------------------------------------------------

interface Download {
  offer: Offer;
  parts: Uint8Array[];
  nextSeq: number;
  received: number;
  lease: DownloadMemoryLease;
  createdAt: number;
  lastActivity: number;
  timer: ReturnType<typeof setTimeout> | null;
  finalizing: boolean;
  cancelled: boolean;
  /** How this download reached us — a viewer request the peer echoed, or an unsolicited push. */
  source: "requested" | "unsolicited";
  /** For `requested`: basename derived from the request path (never from the peer's Offer.name). */
  expectedBasename?: string;
  /** For `unsolicited`: once verified, bytes are held here awaiting `approveDownload(id)`. */
  heldBytes?: Uint8Array;
  heldSha?: string;
  /** True after the finalizer completed successfully but the operator has not yet approved. */
  held: boolean;
}

interface PendingRequest {
  id: string;
  expectedBasename: string;
  deadline: number;
  timer: ReturnType<typeof setTimeout> | null;
}

/**
 * Minimal bidirectional file-transfer client with F07 lifecycle bounds and F06 integrity gating.
 * See {@link FileTransferOptions}. Backward compatible: legacy `(send, onDownload, onAudit)`
 * constructors work unchanged; the fourth options argument is optional.
 */
export class FileTransferClient {
  private readonly send: (payload: Uint8Array) => void;
  private readonly pendingAcks = new Map<string, (ack: { ok: boolean; message: string }) => void>();
  private readonly downloads = new Map<string, Download>();
  private readonly pendingRequests = new Map<string, PendingRequest>();
  readonly onDownload: (file: DeliveredDownload) => void;
  readonly onAudit: (event: unknown) => void;
  private readonly onDownloadError: (info: { id?: string; name?: string; reason: string }) => void;
  private readonly onPendingDownloadsChanged?: (pending: readonly PendingDownloadMeta[]) => void;
  private readonly limits: ResolvedLimits;
  private readonly clock: () => number;
  private readonly pool: DownloadMemoryBudget;
  private readonly maxPendingRequests: number;
  private readonly requestDeadlineMs: number;
  private disposed = false;

  constructor(
    send: (payload: Uint8Array) => void,
    onDownload: (file: DeliveredDownload) => void = () => {},
    onAudit: (event: unknown) => void = () => {},
    options: FileTransferOptions = {},
  ) {
    this.send = send;
    this.onDownload = onDownload;
    this.onAudit = onAudit;
    this.onDownloadError = options.onDownloadError ?? (() => {});
    this.onPendingDownloadsChanged = options.onPendingDownloadsChanged;
    this.limits = resolveLimits(options.limits);
    this.clock = options.clock ?? (() => performance.now());
    this.pool = options.memoryBudget ?? sharedPool;
    this.maxPendingRequests = positiveSafeInt(
      options.maxPendingRequests,
      DEFAULT_MAX_PENDING_REQUESTS,
      "maxPendingRequests",
    );
    this.requestDeadlineMs = positiveSafeInt(
      options.requestDeadlineMs,
      DEFAULT_REQUEST_DEADLINE_MS,
      "requestDeadlineMs",
    );
  }

  /** Snapshot of unsolicited, verified, held-for-approval downloads. Metadata only — never bytes. */
  private snapshotPending(): readonly PendingDownloadMeta[] {
    const out: PendingDownloadMeta[] = [];
    for (const [, dl] of this.downloads) {
      if (dl.held && !dl.cancelled && dl.source === "unsolicited") {
        out.push({ id: dl.offer.id, name: basenameOf(dl.offer.name), size: dl.offer.size });
      }
    }
    return out;
  }

  private emitPending(): void {
    if (!this.onPendingDownloadsChanged) return;
    try {
      // Reentrancy: the observer may call approveDownload/dismissDownload/dispose synchronously.
      // We snapshot fresh state each call, and the mutating APIs re-emit as needed.
      this.onPendingDownloadsChanged(this.snapshotPending());
    } catch {
      /* observer errors must not tear down the client */
    }
  }

  async upload(name: string, bytes: Uint8Array): Promise<{ ok: boolean; message: string }> {
    const { ok, message } = await this.uploadWithId(name, bytes);
    return { ok, message };
  }

  /**
   * {@link upload}, also returning the transfer id: docs/58's "Upload here" places a completed upload
   * by that id. On success `message` is the name it landed under (the agent never replaces a file, so
   * it may be `name (2).ext`).
   */
  async uploadWithId(name: string, bytes: Uint8Array): Promise<{ ok: boolean; message: string; id: string }> {
    const id = newTransferId();
    const result = await this.uploadAs(id, name, bytes);
    return { ...result, id };
  }

  private async uploadAs(id: string, name: string, bytes: Uint8Array): Promise<{ ok: boolean; message: string }> {
    if (this.disposed) return { ok: false, message: "client disposed" };
    const sha256 = await sha256Hex(bytes);
    if (this.disposed) return { ok: false, message: "client disposed" };
    this.sendMsg({ t: "Offer", c: { id, name, size: bytes.length, sha256 } });
    for (const chunk of chunkFile(id, bytes)) {
      if (this.disposed) return { ok: false, message: "client disposed" };
      this.sendMsg({ t: "Chunk", c: chunk });
    }
    if (this.disposed) return { ok: false, message: "client disposed" };
    this.sendMsg({ t: "Done", c: { id } });
    return new Promise((resolve) => {
      if (this.disposed) {
        resolve({ ok: false, message: "client disposed" });
        return;
      }
      this.pendingAcks.set(id, resolve);
    });
  }

  /**
   * Frame a Request for the file at `path`. Mints a UUID, tracks the outstanding request in a bounded
   * map so a matching inbound Offer/Chunks/Done can be delivered as `source: 'requested'`. Any of
   * disposed / limit reached / invalid path / (astronomically unlikely) UUID collision fails
   * SYNCHRONOUSLY by throwing — the caller must catch and surface (no fake success reaches the UI).
   * The entry is inserted BEFORE `send` so a synchronous re-entrant Offer during send can find it;
   * a throw from `send` clears the entry and rethrows.
   */
  request(path: string): string {
    if (this.disposed) throw new Error("client disposed");
    if (typeof path !== "string" || path.length === 0 || path.length > MAX_PATH_LEN) {
      throw new Error("invalid path");
    }
    if (this.pendingRequests.size >= this.maxPendingRequests) {
      throw new Error("too many pending requests");
    }
    const id = newTransferId();
    if (this.pendingRequests.has(id) || this.downloads.has(id)) throw new Error("id collision");
    const deadline = this.clock() + this.requestDeadlineMs;
    const entry: PendingRequest = { id, expectedBasename: basenameOf(path), deadline, timer: null };
    this.pendingRequests.set(id, entry);
    this.scheduleRequest(id, entry);
    try {
      this.sendMsg({ t: "Request", c: { id, path } });
    } catch (e) {
      const cur = this.pendingRequests.get(id);
      if (cur === entry) {
        if (entry.timer !== null) clearTimeout(entry.timer);
        this.pendingRequests.delete(id);
      }
      throw e;
    }
    return id;
  }

  private scheduleRequest(id: string, entry: PendingRequest): void {
    const delay = Math.min(2_147_483_647, Math.max(0, entry.deadline - this.clock()));
    entry.timer = setTimeout(() => {
      entry.timer = null;
      if (this.disposed || this.pendingRequests.get(id) !== entry) return;
      if (this.clock() >= entry.deadline) {
        this.pendingRequests.delete(id);
        // Expired with no Offer: tell the operator instead of leaving the request silently open.
        if (!this.downloads.has(id)) this.report(id, entry.expectedBasename, "the remote machine did not answer in time");
      } else this.scheduleRequest(id, entry); // clamped/early timers must leave a future wakeup
    }, delay);
  }

  /** Abandon an outstanding `request()` — later Offers for that id will be treated as unsolicited. */
  cancelRequest(id: string): void {
    const cur = this.pendingRequests.get(id);
    if (!cur) return;
    if (cur.timer !== null) clearTimeout(cur.timer);
    this.pendingRequests.delete(id);
  }

  /**
   * Explicit-approval hand-off for an unsolicited Offer whose hash verified. Calls `onDownload`
   * exactly ONCE for `id` iff the entry is complete/held/not-cancelled/not-disposed/not-expired,
   * then releases the lease. Returns whether the approval fired. Any other state (still assembling,
   * cancelled, disposed, expired, or unknown id) fails closed — this is the last chance to admit an
   * offer the peer sent without a matching request.
   */
  approveDownload(id: string): boolean {
    if (this.disposed) return false;
    const key = canonId(id);
    if (!key) return false;
    const dl = this.downloads.get(key);
    if (!dl || dl.cancelled) return false;
    if (dl.source !== "unsolicited" || !dl.held || !dl.heldBytes || !dl.heldSha) return false;
    if (this.isExpired(dl)) {
      this.abortDownload(key, "transfer expired");
      return false;
    }
    const bytes = dl.heldBytes;
    const sha = dl.heldSha;
    const name = basenameOf(dl.offer.name);
    // Block reentrant approvals, but keep ownership through the consumer's synchronous save.
    // Treat delivery like a finalizer so reentrant dispose cannot release these live bytes early.
    dl.cancelled = true;
    dl.heldBytes = undefined;
    dl.held = false;
    dl.finalizing = true;
    if (dl.timer !== null) clearTimeout(dl.timer);
    dl.timer = null;
    try {
      this.onDownload({ id: key, name, bytes, sha256: sha, verified: true, source: "approved" });
    } catch {
      /* consumer errors must not leak state */
    } finally {
      if (this.downloads.get(key) === dl) this.downloads.delete(key);
      dl.lease.release();
    }
    this.emitPending();
    return true;
  }

  /** Drop a held unsolicited download without delivering it. Frees the lease. */
  dismissDownload(id: string): void {
    const key = canonId(id);
    if (!key) return;
    const dl = this.downloads.get(key);
    if (!dl || dl.cancelled || dl.source !== "unsolicited" || !dl.held) return;
    dl.cancelled = true;
    dl.heldBytes = undefined;
    dl.parts = [];
    if (dl.timer !== null) clearTimeout(dl.timer);
    dl.timer = null;
    this.downloads.delete(key);
    dl.lease.release();
    this.emitPending();
  }

  /** Route one inbound `ChannelId.FileTransfer` payload. */
  handleMessage(payload: Uint8Array): void {
    if (this.disposed) return;
    if (payload.length === 0) return;
    const tag = payload[0];

    // BINARY CHUNK PATH — reject oversize BEFORE `.slice` copies the payload body.
    if (tag === CHUNK_TAG) {
      if (payload.length < 21) return;
      let id: string;
      try {
        id = bytesToUuid(payload.slice(1, 17)); // 16-byte header alloc only
      } catch {
        return;
      }
      const seq = new DataView(payload.buffer, payload.byteOffset + 17, 4).getUint32(0, false);
      const dataLen = payload.length - 21;
      const dl = this.downloads.get(id);
      // Duplicates arriving while the finalizer runs OR while held-for-approval are silently ignored.
      if (!dl || dl.finalizing || dl.cancelled || dl.held) return;

      // Recheck expiry on inbound activity; a stale chunk cannot revive a dead transfer.
      if (this.isExpired(dl)) {
        this.abortDownload(id, "transfer expired");
        return;
      }
      if (dataLen === 0) {
        // Normal zero-byte files carry no chunks; an empty chunk is malformed.
        this.abortDownload(id, "empty chunk");
        return;
      }
      if (dataLen > MAX_CHUNK_DATA) {
        this.abortDownload(id, "chunk exceeds 48KiB");
        return;
      }
      if (seq !== dl.nextSeq) {
        this.abortDownload(id, "out-of-order chunk");
        return;
      }
      if (dl.parts.length >= this.limits.maxPartsPerTransfer) {
        this.abortDownload(id, "too many parts");
        return;
      }
      if (dl.received + dataLen > dl.offer.size) {
        this.abortDownload(id, "bytes beyond declared size");
        return;
      }
      const data = payload.slice(21); // safe copy — every bound passed
      dl.parts.push(data);
      dl.received += dataLen;
      dl.nextSeq += 1;
      this.touch(dl);
      return;
    }

    // JSON CONTROL PATH.
    let msg: Message;
    try {
      msg = decodeMessage(payload);
    } catch {
      return;
    }
    if (msg.t === "Chunk") {
      // JSON pretending to be a Chunk is not a protocol-legal control message; ignore silently
      // rather than routing peer-supplied `data` into the binary machinery.
      return;
    }
    this.handleControl(msg);
  }

  private handleControl(msg: Exclude<Message, { t: "Chunk" }>): void {
    switch (msg.t) {
      case "Ack": {
        const id = canonId(msg.c?.id);
        if (!id) return;
        const resolve = this.pendingAcks.get(id);
        if (resolve) {
          this.pendingAcks.delete(id);
          resolve({ ok: !!msg.c.ok, message: typeof msg.c.message === "string" ? msg.c.message.slice(0, 4096) : "" });
        }
        return;
      }
      case "Offer": {
        this.acceptOffer(msg.c);
        return;
      }
      case "Done": {
        const id = canonId(msg.c?.id);
        if (!id) return;
        const dl = this.downloads.get(id);
        // A duplicate Done arriving after we've begun (or completed) finalizing is silently dropped —
        // never reassembled again from empty parts.
        if (!dl || dl.finalizing || dl.cancelled || dl.held) return;
        if (this.isExpired(dl)) {
          this.abortDownload(id, "transfer expired");
          return;
        }
        if (dl.received !== dl.offer.size) {
          // Reject BEFORE assembly — a short/long transfer cannot reach `onDownload`.
          this.abortDownload(id, "declared size not met");
          return;
        }
        dl.finalizing = true;
        void this.finishDownload(id, dl);
        return;
      }
      case "Error": {
        const id = canonId(msg.c?.id);
        if (!id) return;
        // A request the agent refused BEFORE any Offer (not permitted, not found, unsafe path) has
        // no download entry, so abortDownload below cannot report it; without this the operator
        // saw "waiting for the agent…" forever. Do not echo peer strings; the reason is our own.
        const refused = this.pendingRequests.get(id);
        this.cancelRequest(id);
        if (refused && !this.downloads.has(id)) {
          this.report(id, refused.expectedBasename, "the remote machine refused the request (not permitted, not found, or not allowed)");
        }
        // Do not echo peer strings; report an own bounded reason.
        this.abortDownload(id, "peer aborted");
        // An upload the agent refused or aborted with an `Error` (limit, disk, out-of-order chunk)
        // gets no `Ack`, so settle its pending promise here; otherwise the caller waits until the
        // client is disposed and its upload batch never advances.
        const resolveUpload = this.pendingAcks.get(id);
        if (resolveUpload) {
          this.pendingAcks.delete(id);
          resolveUpload({ ok: false, message: "upload refused or aborted by the remote machine" });
        }
        return;
      }
      case "Audit": {
        try {
          this.onAudit(msg.c?.event);
        } catch {
          /* audit forwarder failures must not tear down the client */
        }
        return;
      }
      case "Request":
        // Agent-directed; not a client-side input.
        return;
    }
  }

  private acceptOffer(raw: Offer): void {
    // Validate primitives BEFORE storing anything the peer controls.
    const id = canonId(raw?.id);
    if (!id) {
      this.report(undefined, undefined, "invalid offer id");
      return;
    }
    // Even an invalid duplicate must not send an Error that terminates the original stream.
    if (this.downloads.has(id)) return;

    // Correlate against outstanding viewer requests. Consume the pending entry EXACTLY ONCE, even
    // if downstream validation rejects — a late/duplicate Offer for the same id can never consume
    // another expectation on the same map.
    let source: "requested" | "unsolicited" = "unsolicited";
    let expectedBasename: string | undefined;
    const pending = this.pendingRequests.get(id);
    if (pending) {
      // Deadline check on the clock (a coarse timer may not have run yet).
      if (this.clock() >= pending.deadline) {
        // Late — drop the stale entry and treat as unsolicited.
        if (pending.timer !== null) clearTimeout(pending.timer);
        this.pendingRequests.delete(id);
      } else {
        source = "requested";
        expectedBasename = pending.expectedBasename;
        if (pending.timer !== null) clearTimeout(pending.timer);
        this.pendingRequests.delete(id);
      }
    }

    // Unsolicited Offer without an approval observer: reject BEFORE reserving anything.
    if (source === "unsolicited" && !this.onPendingDownloadsChanged) {
      this.report(id, typeof raw?.name === "string" ? raw.name : undefined, "unsolicited download refused");
      this.trySendError(id, "unsolicited");
      return;
    }

    if (typeof raw.name !== "string" || raw.name.length > MAX_NAME_LEN) {
      this.report(id, undefined, "invalid offer name");
      this.trySendError(id, "invalid offer");
      return;
    }
    if (
      typeof raw.size !== "number" ||
      !Number.isFinite(raw.size) ||
      !Number.isSafeInteger(raw.size) ||
      raw.size < 0
    ) {
      this.report(id, raw.name, "invalid offer size");
      this.trySendError(id, "invalid offer");
      return;
    }
    if (typeof raw.sha256 !== "string" || !SHA256_RE.test(raw.sha256)) {
      this.report(id, raw.name, "invalid offer sha256");
      this.trySendError(id, "invalid offer");
      return;
    }
    if (raw.size > this.limits.maxFileBytes) {
      this.report(
        id,
        raw.name,
        `download exceeds ${this.limits.maxFileBytes / (1024 * 1024)} MiB limit`,
      );
      this.trySendError(id, "offer too large");
      return;
    }

    // Active-transfer cap (per-client).
    if (this.activeCount() >= this.limits.maxActiveTransfers) {
      this.report(id, raw.name, "too many concurrent downloads");
      this.trySendError(id, "too many concurrent downloads");
      return;
    }

    // Reserve 4x the advertised size (see RESERVE_MULTIPLIER doc). Zero-byte transfers still
    // consume one lease so the peer cannot flood the pool with empty offers.
    const reserve = raw.size * RESERVE_MULTIPLIER;
    const lease = this.pool.tryAcquire(reserve);
    if (!lease) {
      this.report(id, raw.name, "download memory budget exhausted");
      this.trySendError(id, "memory budget exhausted");
      return;
    }

    // Store an own, immutable-shape copy — never retain the attacker-owned object.
    const now = this.clock();
    const dl: Download = {
      offer: { id, name: raw.name.slice(0, MAX_NAME_LEN), size: raw.size, sha256: raw.sha256.toLowerCase() },
      parts: [],
      nextSeq: 0,
      received: 0,
      lease,
      createdAt: now,
      lastActivity: now,
      timer: null,
      finalizing: false,
      cancelled: false,
      source,
      expectedBasename,
      held: false,
    };
    this.downloads.set(id, dl);
    this.schedule(id, dl);
  }

  private activeCount(): number {
    // Downloading AND finalizing both count against the per-client cap and the pool.
    return this.downloads.size;
  }

  private touch(dl: Download): void {
    dl.lastActivity = this.clock();
    // Reschedule the inactivity clamp; absolute-age still fires from the original createdAt.
    if (dl.timer !== null) clearTimeout(dl.timer);
    dl.timer = null;
    this.schedule(dl.offer.id, dl);
  }

  private schedule(id: string, dl: Download): void {
    const now = this.clock();
    const inactivityDeadline = dl.lastActivity + this.limits.inactivityMs;
    const ageDeadline = dl.createdAt + this.limits.maxAgeMs;
    const deadline = Math.min(inactivityDeadline, ageDeadline);
    // Browsers clamp oversized timer delays to a few milliseconds. Recheck the monotonic deadline
    // on wake instead of expiring a transfer early when configured with a long timeout.
    const delay = Math.min(2_147_483_647, Math.max(0, deadline - now));
    dl.timer = setTimeout(() => {
      dl.timer = null;
      if (this.disposed) return;
      const current = this.downloads.get(id);
      if (!current || current !== dl || current.cancelled) return;
      if (this.isExpired(dl)) this.abortDownload(id, "transfer expired");
      else this.schedule(id, dl);
    }, delay);
  }

  private isExpired(dl: Download): boolean {
    const now = this.clock();
    return now - dl.createdAt >= this.limits.maxAgeMs || now - dl.lastActivity >= this.limits.inactivityMs;
  }

  private abortDownload(id: string, reason: string): void {
    const dl = this.downloads.get(id);
    if (!dl || dl.cancelled) return;
    const wasHeld = dl.held;
    // Finalizing entries with an unsettled digest remain counted until the digest settles. A HELD
    // entry (digest already settled, awaiting operator approval) releases immediately.
    if (!dl.finalizing || wasHeld) this.downloads.delete(id);
    if (dl.timer !== null) {
      clearTimeout(dl.timer);
      dl.timer = null;
    }
    dl.cancelled = true;
    dl.parts = [];
    dl.heldBytes = undefined;
    if (!dl.finalizing || wasHeld) dl.lease.release();
    this.trySendError(id, reason);
    this.report(id, dl.offer.name, reason);
    if (wasHeld) this.emitPending();
  }

  private async finishDownload(id: string, dl: Download): Promise<void> {
    let releaseLease = true;
    try {
      const bytes = new Uint8Array(dl.offer.size);
      let off = 0;
      for (const p of dl.parts) {
        bytes.set(p, off);
        off += p.length;
      }
      dl.parts = []; // free intermediate views before the digest snapshot
      let sha: string;
      try {
        sha = await sha256Hex(bytes);
      } catch {
        if (!dl.cancelled && !this.disposed) this.report(id, dl.offer.name, "digest failed");
        return;
      }
      // The finalizer OWNS lease/id release through settle; cancellation observed here still lets
      // the finally block clean up. A cancelled entry with a settled hash releases immediately.
      if (dl.cancelled || this.disposed) return;
      if (this.isExpired(dl)) {
        // Downgrade to a non-finalizing abort so the lease is freed here.
        dl.finalizing = false;
        this.abortDownload(id, "transfer expired");
        releaseLease = false; // abortDownload already released
        return;
      }
      if (sha !== dl.offer.sha256) {
        this.report(id, dl.offer.name, "sha256 mismatch");
        // No Error wire message here: the peer's Done is what we're rejecting, and it is bounded.
        return;
      }
      if (dl.source === "requested") {
        // Delivered directly: the operator asked for this by path. The name is our OWN basename —
        // never the peer's Offer.name — so a `screenshot-*.png` peer name cannot route as an
        // approved unsolicited push.
        const name = dl.expectedBasename ?? basenameOf(dl.offer.name);
        try {
          this.onDownload({ id, name, bytes, sha256: sha, verified: true, source: "requested" });
        } catch {
          /* consumer failure must not leak reservations */
        }
        return;
      }
      // Unsolicited + observer configured: HOLD the bytes inside the Download under the SAME lease.
      // The metadata snapshot is emitted for the approval UI; onDownload is NOT called.
      dl.heldBytes = bytes;
      dl.heldSha = sha;
      dl.held = true;
      dl.finalizing = false;
      releaseLease = false;
      // Reschedule so the operator-approval clock uses the same expiry bounds.
      if (dl.timer !== null) clearTimeout(dl.timer);
      dl.timer = null;
      this.schedule(id, dl);
      this.emitPending();
    } catch {
      if (!dl.cancelled && !this.disposed) this.report(id, dl.offer.name, "download processing failed");
    } finally {
      if (releaseLease) {
        if (dl.timer !== null) clearTimeout(dl.timer);
        dl.timer = null;
        dl.parts = [];
        const current = this.downloads.get(id);
        if (current === dl) this.downloads.delete(id);
        dl.lease.release();
      }
    }
  }

  private trySendError(id: string, message: string): void {
    if (this.disposed) return;
    try {
      this.sendMsg({ t: "Error", c: { id, message: message.slice(0, 256) } });
    } catch {
      /* transport may be gone; nothing to do */
    }
  }

  private report(id: string | undefined, name: string | undefined, reason: string): void {
    // Bound peer names and strip display controls; reason strings are supplied locally.
    const info = {
      id: id ? String(id).slice(0, 64) : undefined,
      name: name ? sanitizeDisplayName(String(name).slice(0, MAX_NAME_LEN)) : undefined,
      reason: String(reason).slice(0, 256),
    };
    try {
      this.onDownloadError(info);
    } catch {
      /* error surface failures must not tear down the client */
    }
  }

  /**
   * Idempotently tear down: clear timers, drop receiving buffers, resolve pending upload acks
   * with `{ok:false}`, suppress any late callbacks, and stop accepting inbound frames. Finalizing
   * transfers keep their lease until their in-flight digest settles (their `finally` releases).
   */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    for (const [, entry] of this.pendingRequests) {
      if (entry.timer !== null) clearTimeout(entry.timer);
    }
    this.pendingRequests.clear();
    for (const [, dl] of this.downloads) {
      if (dl.timer !== null) {
        clearTimeout(dl.timer);
        dl.timer = null;
      }
      dl.cancelled = true;
      dl.heldBytes = undefined;
      // Held-for-approval entries are treated as HELD, not still-running finalizers: release now.
      if (!dl.finalizing || dl.held) {
        dl.parts = [];
        dl.lease.release();
      }
    }
    this.downloads.clear();
    // Signal the observer that the prompt list is now empty (client is gone).
    if (this.onPendingDownloadsChanged) {
      try {
        this.onPendingDownloadsChanged([]);
      } catch {
        /* observer errors must not tear down the client */
      }
    }
    for (const [, resolve] of this.pendingAcks) {
      try {
        resolve({ ok: false, message: "client disposed" });
      } catch {
        /* consumer failure must not leak state */
      }
    }
    this.pendingAcks.clear();
  }

  private sendMsg(msg: Message): void {
    this.send(encodeMessage(msg));
  }
}
