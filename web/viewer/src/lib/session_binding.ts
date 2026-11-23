// docs/69: binding a live session to both ends' keys, the console's side.
//
// The console generates an ephemeral Ed25519 key BEFORE it asks for a session and sends the public half
// as `console_pubkey`; the control plane answers with `device_binding` (the machine's enrolled key and a
// grant naming our key). Once the Control channel is up, `runConsoleBinding` runs the exchange:
//
//   console -> agent  BindStart { grant, console_nonce }
//   agent  -> console BindAgentProof { agent_nonce, sig }      verified against device_pubkey
//   console -> agent  BindConsoleProof { sig }                 signed with our ephemeral key
//   agent  -> console BindResult { ok, reason }
//
// Both proofs sign RMTSESSBINDv1 bytes over the two DTLS certificate fingerprints AS EACH END SEES THEM,
// read here from getStats() (never from SDP). A man in the middle runs two DTLS legs, so the two ends hold
// different fingerprint pairs and neither proof verifies. The byte layout is pinned against the Rust
// implementation (crates/protocol/src/session_binding.rs) by a shared golden vector.

import { decodeControl } from "./control";
import { ChannelId } from "./protocol";

/** The `device_binding` envelope from a session-start response. */
export interface DeviceBinding {
  mode: "warn" | "require";
  /** Present when the session can be bound. */
  device_pubkey?: string;
  grant?: string;
  /** Present when it cannot (why), e.g. an older console or a machine without an enrolled key. */
  unavailable?: string;
  /** docs/69 6.2: the server's hint that this machine's agent speaks binding v2 (from its reported version). A hint
   *  only: a wrong "true" costs one unverified session, a wrong "false" hides the comparison code. */
  v2?: boolean;
}

/** Decode `device_binding` from a session-start response; undefined when absent (an older server). */
export function parseDeviceBinding(body: unknown): DeviceBinding | undefined {
  const raw = (body as Record<string, unknown> | null)?.device_binding as Record<string, unknown> | undefined;
  if (!raw || typeof raw !== "object") return undefined;
  const mode = raw.mode === "require" ? "require" : "warn";
  const out: DeviceBinding = { mode };
  if (typeof raw.device_pubkey === "string" && /^[0-9a-f]{64}$/.test(raw.device_pubkey) && typeof raw.grant === "string" && raw.grant !== "") {
    out.device_pubkey = raw.device_pubkey;
    out.grant = raw.grant;
  } else {
    out.unavailable = typeof raw.unavailable === "string" ? raw.unavailable : "no binding material";
  }
  if (raw.v2 === true) out.v2 = true;
  return out;
}

export const SESSION_BIND_DOMAIN_TAG = new Uint8Array([
  0x52, 0x4d, 0x54, 0x53, 0x45, 0x53, 0x53, 0x42, 0x49, 0x4e, 0x44, 0x76, 0x31, 0, 0, 0, // "RMTSESSBINDv1\0\0\0"
]);
export const ROLE_AGENT = 1;
export const ROLE_CONSOLE = 2;

export interface BindTranscript {
  sessionId: Uint8Array; // 16 raw UUID bytes
  agentCertSha256: Uint8Array; // 32
  consoleCertSha256: Uint8Array; // 32
  agentNonce: Uint8Array; // 32
  consoleNonce: Uint8Array; // 32
}

/** RMTSESSBINDv1 preimage: tag || version || session || agent_fp || console_fp || agent_nonce || console_nonce || role. */
export function transcriptBytes(t: BindTranscript, role: number): Uint8Array<ArrayBuffer> {
  const parts: [Uint8Array, number][] = [
    [t.sessionId, 16], [t.agentCertSha256, 32], [t.consoleCertSha256, 32], [t.agentNonce, 32], [t.consoleNonce, 32],
  ];
  for (const [p, n] of parts) if (p.length !== n) throw new Error("binding transcript field has the wrong length");
  const out = new Uint8Array(16 + 1 + 16 + 32 * 4 + 1);
  out.set(SESSION_BIND_DOMAIN_TAG, 0);
  out[16] = 1;
  let o = 17;
  for (const [p] of parts) { out.set(p, o); o += p.length; }
  out[o] = role;
  return out;
}

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error("not hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** A canonical UUID string as its 16 raw bytes. */
export function uuidBytes(id: string): Uint8Array<ArrayBuffer> {
  const hex = id.replace(/-/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new Error("not a uuid");
  return hexToBytes(hex);
}

/** An SDP/stats fingerprint ("AB:CD:..", 32 bytes) as raw bytes; null for anything else. */
export function parseColonFingerprint(s: string): Uint8Array | null {
  const parts = s.split(":");
  if (parts.length !== 32 || parts.some((p) => !/^[0-9a-fA-F]{2}$/.test(p))) return null;
  return new Uint8Array(parts.map((p) => parseInt(p, 16)));
}

export type LiveFingerprints =
  | { ok: true; console: Uint8Array; agent: Uint8Array }
  | { ok: false; reason: "multiple_transports" | "unsupported_browser" };

/** The live DTLS association's certificate fingerprints from a stats report (docs/69 §3.3): exactly one
 *  transport, SHA-256 certificates on both sides. Anything else fails closed. */
export function fingerprintsFromStats(report: RTCStatsReport | Map<string, Record<string, unknown>>): LiveFingerprints {
  const all = [...(report as Map<string, Record<string, unknown>>).values()];
  // EVERY transport counts (connected or not): with max-bundle there is exactly one; a second means a transport the
  // binding would not cover.
  const transports = all.filter((s) => s.type === "transport");
  if (transports.length > 1) return { ok: false, reason: "multiple_transports" };
  const tr = transports[0];
  if (!tr) return { ok: false, reason: "unsupported_browser" };
  const byId = (id: unknown) => all.find((s) => s.id === id && s.type === "certificate");
  const local = byId(tr.localCertificateId);
  const remote = byId(tr.remoteCertificateId);
  const fp = (c: Record<string, unknown> | undefined) =>
    c && String(c.fingerprintAlgorithm).toLowerCase() === "sha-256" && typeof c.fingerprint === "string"
      ? parseColonFingerprint(c.fingerprint)
      : null;
  const consoleFp = fp(local);
  const agentFp = fp(remote);
  if (!consoleFp || !agentFp) return { ok: false, reason: "unsupported_browser" };
  return { ok: true, console: consoleFp, agent: agentFp };
}

/** What a brokered connection carries into the exchange: its key and the server's answer for it. */
export interface SessionBindingMaterial {
  key: ConsoleKey | null;
  device: DeviceBinding | undefined;
}

/** The SHA-256 fingerprint every `a=fingerprint` line of one SDP names, or null when there is none, a line uses
 *  another algorithm only, or two lines disagree (BUNDLE: one certificate for the whole session). */
export function fingerprintFromSdp(sdp: string | undefined | null): Uint8Array | null {
  if (!sdp) return null;
  const values = [...sdp.matchAll(/^a=fingerprint:sha-256 ([0-9A-Fa-f:]+)\s*$/gim)].map((m) => m[1].toUpperCase());
  if (values.length === 0 || values.some((v) => v !== values[0])) return null;
  return parseColonFingerprint(values[0]);
}

/** Fallback for browsers without certificate stats (Firefox): the fingerprints of the APPLIED local and remote
 *  descriptions. The browser completes DTLS only when the peer's certificate matches the remote description's
 *  fingerprint, so these name exactly the certificates the live association uses (docs/69 §3.3). */
export function fingerprintsFromDescriptions(localSdp: string | undefined | null, remoteSdp: string | undefined | null): LiveFingerprints {
  const consoleFp = fingerprintFromSdp(localSdp);
  const agentFp = fingerprintFromSdp(remoteSdp);
  if (!consoleFp || !agentFp) return { ok: false, reason: "unsupported_browser" };
  return { ok: true, console: consoleFp, agent: agentFp };
}

/** The console's ephemeral key for ONE connection. The private half never leaves WebCrypto. */
export interface ConsoleKey {
  publicHex: string;
  sign(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array>;
}

/** Generate the per-connection key, or null when the browser has no WebCrypto Ed25519. */
export async function createConsoleKey(subtle: SubtleCrypto | undefined = globalThis.crypto?.subtle): Promise<ConsoleKey | null> {
  if (!subtle) return null;
  try {
    const pair = (await subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
    const raw = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
    return {
      publicHex: bytesToHex(raw),
      sign: async (bytes) => new Uint8Array(await subtle.sign({ name: "Ed25519" }, pair.privateKey, bytes)),
    };
  } catch {
    return null;
  }
}

/** Verify an Ed25519 signature with a raw public key (hex). False on any failure. */
export async function verifyEd25519(pubHex: string, msg: Uint8Array<ArrayBuffer>, sigHex: string, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<boolean> {
  try {
    const key = await subtle.importKey("raw", hexToBytes(pubHex), { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify({ name: "Ed25519" }, key, hexToBytes(sigHex), msg);
  } catch {
    return false;
  }
}

/** Where a session stands. `verified` is the only state that may say the machine is who it claims. */
export type BindingStatus =
  | { state: "pending" }
  | { state: "verified"; code?: string }
  | { state: "unverified"; why: string }
  | { state: "failed"; reason: BindingFailureReason };

/** The closed set the control plane records (POST /sessions/{id}/binding-failed). */
export type BindingFailureReason =
  | "bad_signature" | "fingerprint_mismatch" | "no_proof" | "multiple_transports" | "unsupported_browser" | "agent_refused"
  // A person compared the 6-digit codes on both ends and reported they differ (docs/69 6.1, detection).
  | "sas_mismatch";

export interface ConsoleBindingDeps {
  binding: DeviceBinding | undefined;
  key: ConsoleKey | null;
  /** The control-plane session id (from the session-start response, never signaling's). */
  sessionId: string;
  sendStart(grant: string, consoleNonceHex: string): void;
  sendConsoleProof(sigHex: string): void;
  /** Binding v2 senders; when both are present AND the server hints v2, the exchange runs v2 (commitment first). */
  sendStartV2?(grant: string, commitmentHex: string): void;
  sendConsoleProofV2?(consoleNonceHex: string, sigHex: string): void;
  /** docs/69 6.1: the build the ROUTED agent announced (signaling's `brokered`). v2 runs only when this says >= 0.1.33
   *  as well as the server's hint: the hint is decided before routing and can be stale (a rolled-back agent). */
  peerAgentVersion?(): string | undefined;
  /** Resolves with the agent's proof, or null on timeout. */
  /** Resolves with the agent's proof, `{ refused }` when the agent answered BindStart with a negative BindResult
   *  (it refused the grant), or null on timeout. */
  awaitAgentProof(timeoutMs: number): Promise<{ agentNonceHex: string; sigHex: string } | { refused: string | null } | null>;
  /** Resolves with the agent's verdict, or null on timeout. */
  awaitResult(timeoutMs: number): Promise<{ ok: boolean; reason: string | null } | null>;
  stats(): Promise<RTCStatsReport | undefined>;
  /** The applied local and remote SDP (fallback when stats carry no certificates). */
  descriptions?(): { local?: string | null; remote?: string | null };
  randomBytes(n: number): Uint8Array;
  verify?: typeof verifyEd25519;
  /** How long to wait for the agent's proof. Default BIND_REPLY_TIMEOUT_MS. A caller with no person waiting on held
   *  input (the headless runner) can afford to wait longer. */
  proofTimeoutMs?: number;
  /** At warn, when the proof does not arrive in time, the session settles "unverified" at once (so input is not held
   *  long against an older agent) and the exchange keeps listening for a LATE proof. An enforcing agent whose local
   *  startup was slow answers late; without this it would wait for a console proof that never comes and end the
   *  session (Codex enforce-step3 r2). A late proof gets the full checks; its outcome is reported here: `verified`,
   *  or `failed` (which ends the session). Never called after the window passes with nothing. */
  onLateStatus?(status: BindingStatus): void;
}

/** How long a warn session keeps listening for a late agent proof after settling "unverified". The enforcing agent
 *  gives up BINDING_DEADLINE (10 s) after its loop starts, so anything later cannot help. */
export const LATE_PROOF_WINDOW_MS = 30_000;

/** Control messages that may go out BEFORE the peer is verified: the binding exchange itself and session
 *  setup that carries nothing the technician typed or chose to send (docs/69). Everything else waits. */
const PRE_BINDING_CONTROL = new Set([
  "BindStart", "BindConsoleProof", "BindStartV2", "BindConsoleProofV2", "InstallSessionPolicy", "RequestMonitors", "SelectMonitor", "WatchedMonitors",
  "FrameDisplayed", "RequestQuality", "SetQuality", "SetBackground", "RequestBackstageFeatures",
]);

/** The outbound-hold predicate for an unverified session: only the frames above pass. */
export function allowedBeforeBinding(frame: { channel: ChannelId; payload: Uint8Array }): boolean {
  if (frame.channel !== ChannelId.Control) return false;
  try {
    return PRE_BINDING_CONTROL.has(decodeControl(frame.payload).t);
  } catch {
    return false;
  }
}

/** How long the console waits for each agent reply. An older agent never answers. */
export const BIND_REPLY_TIMEOUT_MS = 5_000;

/** Run the exchange. Never throws: every path ends in a status. `failed` means: end the session. */
export async function runConsoleBinding(d: ConsoleBindingDeps): Promise<BindingStatus> {
  try {
    return await runConsoleBindingSteps(d);
  } catch {
    // A stats read or a WebCrypto call threw DURING an exchange: a failure in every mode (the held traffic must
    // not be released to a peer we could not check).
    return { state: "failed", reason: "unsupported_browser" };
  }
}

/** The first agent build that speaks binding v2 (control-plane/session_binding.go bindingV2MinAgent). */
const BINDING_V2_MIN_AGENT: readonly [number, number, number] = [0, 1, 33];

/** Whether an announced agent build ("0.1.33+74408a1f") is at least BINDING_V2_MIN_AGENT. Unknown or unparsable: no. */
export function speaksBindingV2(version: string | undefined): boolean {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:[+-].*)?$/.exec(version?.trim() ?? "");
  if (!m) return false;
  const v = [Number(m[1]), Number(m[2]), Number(m[3])];
  for (let i = 0; i < 3; i++) {
    if (v[i] !== BINDING_V2_MIN_AGENT[i]) return v[i] > BINDING_V2_MIN_AGENT[i];
  }
  return true;
}

async function runConsoleBindingSteps(d: ConsoleBindingDeps): Promise<BindingStatus> {
  const mode = d.binding?.mode ?? "warn";
  const unbound = (why: string): BindingStatus =>
    mode === "require" ? { state: "failed", reason: "no_proof" } : { state: "unverified", why };
  if (!d.binding?.grant || !d.binding.device_pubkey) return unbound(d.binding?.unavailable ?? "the server sent no binding material");
  if (!d.key) return mode === "require" ? { state: "failed", reason: "unsupported_browser" } : { state: "unverified", why: "this browser cannot verify sessions" };
  let sessionId: Uint8Array;
  try { sessionId = uuidBytes(d.sessionId); } catch { return unbound("the session id is not a uuid"); }

  // Narrowed once here: the late path below runs in a closure, where property narrowing does not survive.
  const ready = { ...d, binding: { ...d.binding, device_pubkey: d.binding.device_pubkey }, key: d.key };
  const consoleNonce = d.randomBytes(32);
  // v2 only when the server hints it AND the agent this connection was actually routed to announced a v2 build; one
  // version per connection, no mid-connection fallback (Codex release-1333 r3).
  let finish: (r: { agentNonceHex: string; sigHex: string } | { refused: string | null }) => Promise<BindingStatus>;
  if (d.binding.v2 && d.sendStartV2 && d.sendConsoleProofV2 && speaksBindingV2(d.peerAgentVersion?.())) {
    const commitment = await commitV2(consoleNonce);
    d.sendStartV2(d.binding.grant, bytesToHex(commitment));
    finish = (r) => finishExchangeV2(ready, sessionId, consoleNonce, commitment, r);
  } else {
    d.sendStart(d.binding.grant, bytesToHex(consoleNonce));
    finish = (r) => finishExchange(ready, sessionId, consoleNonce, r);
  }
  const reply = await d.awaitAgentProof(d.proofTimeoutMs ?? BIND_REPLY_TIMEOUT_MS);
  if (!reply) {
    const late = d.onLateStatus;
    if (mode !== "require" && late) {
      // Settle now; finish the exchange if the proof turns up. The same nonce, key and connection: nothing is re-sent.
      void (async () => {
        let status: BindingStatus | null;
        try {
          const lateReply = await d.awaitAgentProof(LATE_PROOF_WINDOW_MS);
          status = lateReply ? await finish(lateReply) : null;
        } catch {
          status = { state: "failed", reason: "unsupported_browser" };
        }
        if (status) late(status);
      })();
    }
    return unbound("the agent did not answer (it may need an update)");
  }
  return finish(reply);
}

/** Everything after the agent's reply: its proof is checked against the live fingerprints, ours is sent, and the
 *  agent's verdict decides. Shared by the on-time and the late path. */
async function finishExchange(
  d: ConsoleBindingDeps & { binding: DeviceBinding & { device_pubkey: string }; key: ConsoleKey },
  sessionId: Uint8Array,
  consoleNonce: Uint8Array,
  reply: { agentNonceHex: string; sigHex: string } | { refused: string | null },
): Promise<BindingStatus> {
  // An explicit refusal is a verification FAILURE in every mode, not the silence of an older agent.
  if ("refused" in reply) return { state: "failed", reason: "agent_refused" };
  const proof = reply;

  const fps = await liveFingerprints(d);
  if (!fps.ok) return { state: "failed", reason: fps.reason };
  const transcript: BindTranscript = {
    sessionId,
    agentCertSha256: fps.agent,
    consoleCertSha256: fps.console,
    agentNonce: hexToBytes(proof.agentNonceHex),
    consoleNonce,
  };
  const verify = d.verify ?? verifyEd25519;
  if (!(await verify(d.binding.device_pubkey, transcriptBytes(transcript, ROLE_AGENT), proof.sigHex))) {
    return { state: "failed", reason: "bad_signature" };
  }
  const sig = await d.key.sign(transcriptBytes(transcript, ROLE_CONSOLE));
  d.sendConsoleProof(bytesToHex(sig));
  const result = await d.awaitResult(BIND_REPLY_TIMEOUT_MS);
  if (!result || !result.ok) return { state: "failed", reason: "agent_refused" };
  return { state: "verified" };
}

/** The live DTLS fingerprints: certificate stats, else the applied descriptions (Firefox). */
async function liveFingerprints(d: ConsoleBindingDeps): Promise<LiveFingerprints> {
  const report = await d.stats();
  let fps: LiveFingerprints = report ? fingerprintsFromStats(report) : { ok: false, reason: "unsupported_browser" };
  // No certificate stats (Firefox): fall back to the applied descriptions. Two transports stays a failure.
  if (!fps.ok && fps.reason === "unsupported_browser" && d.descriptions) {
    const desc = d.descriptions();
    fps = fingerprintsFromDescriptions(desc.local, desc.remote);
  }
  return fps;
}

/** v2 after the agent's reply: verify its proof over the v2 transcript (which names the commitment), then REVEAL
 *  the nonce with our proof over the transcript and the opening. Verified carries the comparison code. */
async function finishExchangeV2(
  d: ConsoleBindingDeps & { binding: DeviceBinding & { device_pubkey: string }; key: ConsoleKey },
  sessionId: Uint8Array,
  consoleNonce: Uint8Array,
  commitment: Uint8Array,
  reply: { agentNonceHex: string; sigHex: string } | { refused: string | null },
): Promise<BindingStatus> {
  if ("refused" in reply) return { state: "failed", reason: "agent_refused" };
  const fps = await liveFingerprints(d);
  if (!fps.ok) return { state: "failed", reason: fps.reason };
  const t: BindTranscriptV2 = {
    sessionId,
    agentCertSha256: fps.agent,
    consoleCertSha256: fps.console,
    devicePubkey: hexToBytes(d.binding.device_pubkey),
    consolePubkey: hexToBytes(d.key.publicHex),
    commitment,
    agentNonce: hexToBytes(reply.agentNonceHex),
  };
  const verify = d.verify ?? verifyEd25519;
  if (!(await verify(d.binding.device_pubkey, agentSigningBytesV2(t), reply.sigHex))) {
    return { state: "failed", reason: "bad_signature" };
  }
  const sig = await d.key.sign(consoleSigningBytesV2(t, consoleNonce));
  d.sendConsoleProofV2!(bytesToHex(consoleNonce), bytesToHex(sig));
  const result = await d.awaitResult(BIND_REPLY_TIMEOUT_MS);
  if (!result || !result.ok) return { state: "failed", reason: "agent_refused" };
  return { state: "verified", code: formatComparisonCode(await comparisonCodeV2(t, consoleNonce)) };
}

// ---- binding v2 bytes, pinned against crates/protocol/src/session_binding.rs by the same golden values ----

const ascii = (s: string) => new TextEncoder().encode(s);
export const SESSION_BIND_V2_TAG = ascii("RMTSESSBINDv2\0");
export const BIND_COMMIT_V2_TAG = ascii("RMTBIND-COMMIT-v2\0");
export const SAS_V2_TAG = ascii("RMTSASv2\0");

export interface BindTranscriptV2 {
  sessionId: Uint8Array; // 16
  agentCertSha256: Uint8Array; // 32
  consoleCertSha256: Uint8Array; // 32
  devicePubkey: Uint8Array; // 32
  consolePubkey: Uint8Array; // 32
  commitment: Uint8Array; // 32
  agentNonce: Uint8Array; // 32
}

function concatBytes(parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
}

/** SHA-256("RMTBIND-COMMIT-v2\0" || nonce). */
export function commitV2(consoleNonce: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes([BIND_COMMIT_V2_TAG, consoleNonce]));
}

/** u8(2) || session || agent_fp || console_fp || device_pk || console_pk || commitment || agent_nonce. */
export function v2Common(t: BindTranscriptV2): Uint8Array<ArrayBuffer> {
  return concatBytes([new Uint8Array([2]), t.sessionId, t.agentCertSha256, t.consoleCertSha256, t.devicePubkey, t.consolePubkey, t.commitment, t.agentNonce]);
}

export function agentSigningBytesV2(t: BindTranscriptV2): Uint8Array<ArrayBuffer> {
  return concatBytes([SESSION_BIND_V2_TAG, v2Common(t), new Uint8Array([ROLE_AGENT])]);
}

export function consoleSigningBytesV2(t: BindTranscriptV2, consoleNonce: Uint8Array): Uint8Array<ArrayBuffer> {
  return concatBytes([SESSION_BIND_V2_TAG, v2Common(t), new Uint8Array([ROLE_CONSOLE]), consoleNonce]);
}

/** u32_be(SHA-256(SAS tag || common || console_nonce)[0..4]) mod 1_000_000. */
export async function comparisonCodeV2(t: BindTranscriptV2, consoleNonce: Uint8Array): Promise<number> {
  const d = await sha256(concatBytes([SAS_V2_TAG, v2Common(t), consoleNonce]));
  return (((d[0] << 24) >>> 0) + (d[1] << 16) + (d[2] << 8) + d[3]) % 1_000_000;
}

/** "123 456", zero-padded: the form both screens show. */
export function formatComparisonCode(code: number): string {
  const s = String(code % 1_000_000).padStart(6, "0");
  return `${s.slice(0, 3)} ${s.slice(3)}`;
}
