/**
 * Central session recordings, console side (docs/63 R3). The pure model behind
 * `components/RecordingsPanel.tsx`, `components/RecordingPlayer.tsx` and
 * `components/RecordingPolicySection.tsx`: wire parsing, the status and PROVENANCE wording, the
 * list rows (joined with the session and machine lists the server does not repeat), the playback
 * error messages, and the tenant policy form. No DOM, so vitest pins every rule.
 *
 * Wire shapes are those of control-plane/http_recording_playback.go and http_recording_policy.go.
 */

const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

export interface RecordingListItem {
  id: string;
  session_id: string;
  machine_id: string;
  /** uploading | evidence_complete | playback_ready | playback_failed | expired | deleted | lost (open set). */
  state: string;
  playable: boolean;
  /** Machine code: matches_session_audit | no_matching_stop_event. The UI words it itself (see provenanceView). */
  provenance: string;
  provenance_label: string;
  segment_count: number;
  declared_bytes: number;
  truncated: string | null;
  dropped_frames: number | null;
  playback_error: string;
  evidence_complete_at: string;
  expires_at: string;
  // Joined by the server with the same authorization as the row (omitted when unknown). There is no capture time in
  // the schema, so the times are the SESSION's.
  machine_name: string;
  machine_alias: string;
  technician_id: string;
  technician_name: string;
  session_started_at: string;
  session_ended_at: string;
}

export interface RecordingSegmentInfo {
  index: number;
  declared_bytes: number;
  sha256: string;
  playback: { bytes: number; width: number; height: number; start_ms: number; duration_ms: number; frames: number } | null;
}

export interface RecordingDetail extends RecordingListItem {
  provenance_note: string;
  segments: RecordingSegmentInfo[];
  frames: number | null;
  payload_bytes: number | null;
  expired_at: string | null;
  deleted_at: string | null;
}

export interface RecordingPlaylistItem {
  index: number;
  /** Relative to the playlist URL: always `segments/{n}/stream`. */
  url: string;
  start_ms: number;
  duration_ms: number;
  width: number;
  height: number;
  bytes: number;
}

export interface RecordingPlaylist {
  recording_id: string;
  mime: string;
  segments: RecordingPlaylistItem[];
  total_duration_ms: number;
  provenance: string;
  provenance_label: string;
  provenance_note: string;
  truncated: string | null;
  dropped_frames: number | null;
}

export interface RecordingPage {
  recordings: RecordingListItem[];
  /** "" when there is nothing further. */
  next_cursor: string;
}

/** GET/PUT /tenant/recording-policy. */
export interface RecordingPolicy {
  retention_days: number;
  max_recording_bytes: number;
  quota_bytes: number;
  enabled: boolean;
  /** false: this deployment has no recording volume or key, so nothing is stored whatever the policy says. */
  storage_available: boolean;
}

/** The PUT body: EVERY field, always (the server refuses a body that omits or adds one). */
export interface RecordingPolicyBody {
  retention_days: number;
  max_recording_bytes: number;
  quota_bytes: number;
}

// ---------------------------------------------------------------------------
// Parsing (defensive: an unexpected shape is an error, never a half-filled row)
// ---------------------------------------------------------------------------

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown, d = ""): string => (typeof v === "string" ? v : d);
const num = (v: unknown, d = 0): number => (typeof v === "number" && Number.isFinite(v) ? v : d);
const strOrNull = (v: unknown): string | null => (typeof v === "string" ? v : null);
const numOrNull = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

export function parseRecordingListItem(v: unknown): RecordingListItem | null {
  if (!isObj(v) || typeof v.id !== "string" || v.id === "" || typeof v.state !== "string") return null;
  return {
    id: v.id,
    session_id: str(v.session_id),
    machine_id: str(v.machine_id),
    state: v.state,
    playable: v.playable === true,
    provenance: str(v.provenance),
    provenance_label: str(v.provenance_label),
    segment_count: num(v.segment_count),
    declared_bytes: num(v.declared_bytes),
    truncated: strOrNull(v.truncated),
    dropped_frames: numOrNull(v.dropped_frames),
    playback_error: str(v.playback_error),
    evidence_complete_at: str(v.evidence_complete_at),
    expires_at: str(v.expires_at),
    machine_name: str(v.machine_name),
    machine_alias: str(v.machine_alias),
    technician_id: str(v.technician_id),
    technician_name: str(v.technician_name),
    session_started_at: str(v.session_started_at),
    session_ended_at: str(v.session_ended_at),
  };
}

export function parseRecordingPage(body: unknown): RecordingPage | null {
  if (!isObj(body) || !Array.isArray(body.recordings)) return null;
  const recordings: RecordingListItem[] = [];
  for (const r of body.recordings) {
    const item = parseRecordingListItem(r);
    if (item === null) return null;
    recordings.push(item);
  }
  return { recordings, next_cursor: str(body.next_cursor) };
}

export function parseRecordingDetail(body: unknown): RecordingDetail | null {
  const base = parseRecordingListItem(body);
  if (base === null || !isObj(body)) return null;
  const segments: RecordingSegmentInfo[] = [];
  if (Array.isArray(body.segments)) {
    for (const s of body.segments) {
      if (!isObj(s)) return null;
      const p = s.playback;
      segments.push({
        index: num(s.index),
        declared_bytes: num(s.declared_bytes),
        sha256: str(s.sha256),
        playback: isObj(p)
          ? { bytes: num(p.bytes), width: num(p.width), height: num(p.height), start_ms: num(p.start_ms), duration_ms: num(p.duration_ms), frames: num(p.frames) }
          : null,
      });
    }
  }
  return {
    ...base,
    provenance_note: str(body.provenance_note),
    segments,
    frames: numOrNull(body.frames),
    payload_bytes: numOrNull(body.payload_bytes),
    expired_at: strOrNull(body.expired_at),
    deleted_at: strOrNull(body.deleted_at),
  };
}

/** The playlist's item URLs are only ever `segments/{n}/stream`; anything else is refused (never fetched). */
const SEGMENT_URL = /^segments\/(\d{1,4})\/stream$/;

export function parseRecordingPlaylist(body: unknown): RecordingPlaylist | null {
  if (!isObj(body) || typeof body.recording_id !== "string" || !Array.isArray(body.segments)) return null;
  const segments: RecordingPlaylistItem[] = [];
  for (const s of body.segments) {
    if (!isObj(s) || typeof s.url !== "string" || !SEGMENT_URL.test(s.url)) return null;
    segments.push({
      index: num(s.index), url: s.url, start_ms: num(s.start_ms), duration_ms: num(s.duration_ms),
      width: num(s.width), height: num(s.height), bytes: num(s.bytes),
    });
  }
  if (segments.length === 0) return null;
  return {
    recording_id: body.recording_id,
    mime: str(body.mime),
    segments,
    total_duration_ms: num(body.total_duration_ms),
    provenance: str(body.provenance),
    provenance_label: str(body.provenance_label),
    provenance_note: str(body.provenance_note),
    truncated: strOrNull(body.truncated),
    dropped_frames: numOrNull(body.dropped_frames),
  };
}

export function parseRecordingPolicy(body: unknown): RecordingPolicy | null {
  if (!isObj(body)) return null;
  const { retention_days, max_recording_bytes, quota_bytes } = body;
  if (typeof retention_days !== "number" || typeof max_recording_bytes !== "number" || typeof quota_bytes !== "number") return null;
  return {
    retention_days, max_recording_bytes, quota_bytes,
    enabled: body.enabled === true,
    storage_available: body.storage_available === true,
  };
}

// ---------------------------------------------------------------------------
// Status and provenance wording
// ---------------------------------------------------------------------------

export type Tone = "good" | "pending" | "bad" | "neutral";

export interface StatusView {
  label: string;
  tone: Tone;
  detail: string;
}

/**
 * The status shown for a recording. Expired and deleted BOTH read "Expired": a recording past its retention
 * is not "missing" (docs/63 D2) — its audit row outlives the file on purpose. "Lost" is the separate restore
 * state, where the file should exist and does not.
 */
/** Words for a recording whose row survived a restore but whose file did not (docs/63 C11). */
export const LOST_DETAIL = "The file is missing after a restore, so it cannot be played or downloaded.";

export function recordingStatus(state: string): StatusView {
  switch (state) {
    case "uploading":
      return { label: "Uploading", tone: "pending", detail: "The machine is still sending this recording." };
    case "evidence_complete":
      return { label: "Evidence complete", tone: "pending", detail: "The original recording is stored; the playable copy is still being prepared." };
    case "playback_ready":
      return { label: "Playback ready", tone: "good", detail: "" };
    case "playback_failed":
      return { label: "Playback failed", tone: "bad", detail: "The original recording is stored and can be downloaded, but a playable copy could not be made." };
    case "expired":
    case "deleted":
      return { label: "Expired", tone: "neutral", detail: "Removed under the retention policy. The audit record of the session remains." };
    case "lost":
      return { label: "Lost", tone: "bad", detail: LOST_DETAIL };
    default:
      return { label: state === "" ? "Unknown" : state, tone: "neutral", detail: "" };
  }
}

export const PROVENANCE_MATCHES = "Agent-signed; matches session audit";
export const PROVENANCE_NO_STOP = "Agent-signed; no matching stop event";
/** Shown with EVERY provenance label: neither is a claim of independent verification. */
export const PROVENANCE_CAVEAT =
  "Neither label is independent capture verification: whoever controls the endpoint's agent key can fabricate either.";

export interface ProvenanceView {
  label: string;
  tooltip: string;
  /** Whether the label is one of the two the server can produce. */
  known: boolean;
}

/**
 * C4 wording, from the machine code (never from the server's free text, and never the word "verified").
 * An unrecognised code gets a neutral "not stated" label, so a future code cannot be silently shown as a
 * stronger claim than the server made.
 */
export function provenanceView(code: string): ProvenanceView {
  switch (code) {
    case "matches_session_audit":
      return {
        label: PROVENANCE_MATCHES,
        tooltip: `The machine's agent signed this recording, and a signed stop event in the session audit trail carries the same digests. ${PROVENANCE_CAVEAT}`,
        known: true,
      };
    case "no_matching_stop_event":
      return {
        label: PROVENANCE_NO_STOP,
        tooltip: `The machine's agent signed this recording, but no signed stop event in the session audit trail matches it (for example the session ended abnormally). ${PROVENANCE_CAVEAT}`,
        known: true,
      };
    default:
      return { label: "Provenance not stated", tooltip: PROVENANCE_CAVEAT, known: false };
  }
}

/** Short flags shown beside a recording: an incomplete capture must never read as a complete one. */
export function recordingFlags(r: Pick<RecordingListItem, "truncated" | "dropped_frames">): string[] {
  const flags: string[] = [];
  if (r.truncated) flags.push(`Truncated (${r.truncated})`);
  if (r.dropped_frames != null && r.dropped_frames > 0) {
    flags.push(`${r.dropped_frames} frame${r.dropped_frames === 1 ? "" : "s"} dropped`);
  }
  return flags;
}

/** Playback is offered only for a ready recording. */
export const canPlay = (r: Pick<RecordingListItem, "state" | "playable">): boolean => r.state === "playback_ready" && r.playable;

/** The evidence ZIP exists while the evidence copy does (not while uploading, and not after expiry or loss). */
export const canDownloadEvidence = (state: string): boolean =>
  state === "evidence_complete" || state === "playback_ready" || state === "playback_failed";

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${n} B`;
  if (n < MIB) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < GIB) return `${(n / MIB).toFixed(1)} MiB`;
  return `${(n / GIB).toFixed(2)} GiB`;
}

export function formatDurationMs(ms: number): string {
  const total = Math.max(0, Math.round(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

// ---------------------------------------------------------------------------
// List rows
// ---------------------------------------------------------------------------

export interface RecordingRow {
  item: RecordingListItem;
  status: StatusView;
  provenance: ProvenanceView;
  flags: string[];
  machine: string;
  technician: string;
  started: string;
  ended: string;
  size: string;
  canPlay: boolean;
  canDownload: boolean;
}

/**
 * The rows to show. The server names the machine, technician and session times itself (same authorization as the
 * row); a value it omitted falls back to the id (never blank), and the times to a dash.
 */
export function recordingRows(items: readonly RecordingListItem[]): RecordingRow[] {
  return items.map((item) => ({
    item,
    status: recordingStatus(item.state),
    provenance: provenanceView(item.provenance),
    flags: recordingFlags(item),
    machine: item.machine_alias || item.machine_name || item.machine_id || "—",
    technician: item.technician_name || item.technician_id || "—",
    started: item.session_started_at,
    ended: item.session_ended_at,
    size: formatBytes(item.declared_bytes),
    canPlay: canPlay(item),
    canDownload: canDownloadEvidence(item.state),
  }));
}

// ---------------------------------------------------------------------------
// Playback and request errors
// ---------------------------------------------------------------------------

/**
 * The words for a refused recording request. `code` is the server's `error` field (a closed set for these
 * routes), `status` the HTTP status. Expiry (410) is stated as expiry, never as "missing".
 */
export function recordingErrorMessage(status: number, code: string): string {
  switch (status) {
    case 401:
      return "Your session has ended. Sign in again.";
    case 403:
      return "You do not have permission to view recordings for this machine.";
    case 404:
      return "This recording was not found, or it belongs to a machine outside your groups.";
    case 409:
      if (code === "playback_pending") return "Playback is still being prepared. Try again in a minute.";
      if (code === "playback_failed") return "A playable copy could not be made for this recording. The original can still be downloaded as evidence.";
      return "This recording is not in a state that can be played.";
    case 410:
      if (code === "lost") return "This recording is lost: " + LOST_DETAIL;
      return "This recording has expired and was removed under the retention policy.";
    case 416:
      return "The player asked for a part of the recording that does not exist.";
    case 503:
      return "Playback is withheld because the audit log is unavailable, so the viewing could not be recorded. Try again shortly.";
    default:
      return `The recording could not be loaded (HTTP ${status}).`;
  }
}

/** The relative URL for a playlist item under the control-plane base: `{base}/recordings/{id}/segments/{n}/stream`. */
export function segmentStreamUrl(base: string, recordingId: string, item: Pick<RecordingPlaylistItem, "url">): string | null {
  const m = SEGMENT_URL.exec(item.url);
  if (m === null || !/^[0-9a-f-]{36}$/.test(recordingId)) return null;
  return `${base.replace(/\/+$/, "")}/recordings/${recordingId}/segments/${Number(m[1])}/stream`;
}

export function downloadUrl(base: string, recordingId: string): string {
  return `${base.replace(/\/+$/, "")}/recordings/${encodeURIComponent(recordingId)}/download`;
}

// ---------------------------------------------------------------------------
// Tenant policy form
// ---------------------------------------------------------------------------

export const RETENTION_PRESETS = [30, 90] as const;

export interface PolicyForm {
  /** "off" | "30" | "90" | "custom" */
  retention: string;
  customDays: string;
  maxMiB: string;
  quotaGiB: string;
}

/** Decimal text for a byte count in `unit`, trimmed ("1024", "0.5"). */
function unitText(bytes: number, unit: number): string {
  return String(Math.round((bytes / unit) * 100) / 100);
}

export function policyToForm(p: Pick<RecordingPolicy, "retention_days" | "max_recording_bytes" | "quota_bytes">): PolicyForm {
  const d = p.retention_days;
  return {
    retention: d === 0 ? "off" : (RETENTION_PRESETS as readonly number[]).includes(d) ? String(d) : "custom",
    customDays: d === 0 || (RETENTION_PRESETS as readonly number[]).includes(d) ? "" : String(d),
    maxMiB: unitText(p.max_recording_bytes, MIB),
    quotaGiB: unitText(p.quota_bytes, GIB),
  };
}

export type PolicyParse = { ok: true; body: RecordingPolicyBody } | { ok: false; error: string };

const MAX_BYTES_CEILING = GIB;
const QUOTA_CEILING = 1125899906842624;

/**
 * Validate the form and build the PUT body. The body ALWAYS carries all three fields (the server refuses
 * anything less, so a stale or partial client can never switch storage on by omission). A size field the
 * user did not touch is sent as the stored byte count exactly, so a value that is not a whole MiB/GiB is not
 * rounded behind their back.
 */
export function parsePolicyForm(form: PolicyForm, current: Pick<RecordingPolicy, "max_recording_bytes" | "quota_bytes">): PolicyParse {
  let days: number;
  if (form.retention === "off") days = 0;
  else if (form.retention === "custom") {
    const t = form.customDays.trim();
    if (!/^\d{1,3}$/.test(t)) return { ok: false, error: "Enter the number of days to keep recordings (1 to 365)." };
    days = Number(t);
    if (days < 1 || days > 365) return { ok: false, error: "Retention must be between 1 and 365 days." };
  } else {
    days = Number(form.retention);
    if (!(RETENTION_PRESETS as readonly number[]).includes(days)) return { ok: false, error: "Choose how long to keep recordings." };
  }

  const size = (text: string, unit: number, stored: number): number | null => {
    const t = text.trim();
    if (t === unitText(stored, unit)) return stored;
    if (!/^\d+(\.\d{1,2})?$/.test(t)) return null;
    return Math.round(Number(t) * unit);
  };
  const max = size(form.maxMiB, MIB, current.max_recording_bytes);
  if (max === null) return { ok: false, error: "Enter the largest single recording in MiB, for example 512." };
  if (max < 1 || max > MAX_BYTES_CEILING) return { ok: false, error: "The largest single recording must be between 1 byte and 1024 MiB." };
  const quota = size(form.quotaGiB, GIB, current.quota_bytes);
  if (quota === null) return { ok: false, error: "Enter the total storage quota in GiB, for example 20." };
  if (quota > QUOTA_CEILING) return { ok: false, error: "The storage quota is too large." };
  if (days > 0 && quota === 0) return { ok: false, error: "A quota of 0 would refuse every recording. Enter at least 1 GiB, or turn storage off." };
  if (days > 0 && quota < max) return { ok: false, error: "The quota must be at least as large as the largest single recording." };
  return { ok: true, body: { retention_days: days, max_recording_bytes: max, quota_bytes: quota } };
}

/** Whether saving this body turns central storage ON (needs the explicit confirmation). */
export const turnsStorageOn = (current: Pick<RecordingPolicy, "retention_days">, body: RecordingPolicyBody): boolean =>
  current.retention_days === 0 && body.retention_days > 0;

/**
 * Recordings live on the server's own disk, outside the database backup (docs/63 C11). Said plainly wherever a
 * tenant turns storage on or reads about it, because retention is a deletion policy and not a durability promise.
 */
export const RECORDINGS_NOT_BACKED_UP = "Recordings are not backed up. A disk or server loss deletes them.";

export const STORAGE_ON_CONFIRMATION =
  "Turn on central recording storage? From now on, recordings made on this organization's machines are uploaded to this server " +
  "and kept for the retention period, where Owners, Admins and Auditors can watch them. Screen content may include " +
  "sensitive information. Recordings already on machines are not affected. " + RECORDINGS_NOT_BACKED_UP;

export const STORAGE_OFF_NOTE =
  "Off (0 days): new recordings stay only on the guest machine (72 hours, then deleted there) and are not uploaded. Recordings already on the server stay until their scheduled deletion date.";
