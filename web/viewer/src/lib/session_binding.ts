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
  | { state: "verified" }
  | { state: "unverified"; why: string }
  | { state: "failed"; reason: BindingFailureReason };

/** The closed set the control plane records (POST /sessions/{id}/binding-failed). */
export type BindingFailureReason =
  | "bad_signature" | "fingerprint_mismatch" | "no_proof" | "multiple_transports" | "unsupported_browser" | "agent_refused";

export interface ConsoleBindingDeps {
  binding: DeviceBinding | undefined;
  key: ConsoleKey | null;
  /** The control-plane session id (from the session-start response, never signaling's). */
  sessionId: string;
  sendStart(grant: string, consoleNonceHex: string): void;
  sendConsoleProof(sigHex: string): void;
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
  "BindStart", "BindConsoleProof", "InstallSessionPolicy", "RequestMonitors", "SelectMonitor", "WatchedMonitors",
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
  d.sendStart(d.binding.grant, bytesToHex(consoleNonce));
  const reply = await d.awaitAgentProof(d.proofTimeoutMs ?? BIND_REPLY_TIMEOUT_MS);
  if (!reply) {
    const late = d.onLateStatus;
    if (mode !== "require" && late) {
      // Settle now; finish the exchange if the proof turns up. The same nonce, key and connection: nothing is re-sent.
      void (async () => {
        let status: BindingStatus | null;
        try {
          const lateReply = await d.awaitAgentProof(LATE_PROOF_WINDOW_MS);
          status = lateReply ? await finishExchange(ready, sessionId, consoleNonce, lateReply) : null;
        } catch {
          status = { state: "failed", reason: "unsupported_browser" };
        }
        if (status) late(status);
      })();
    }
    return unbound("the agent did not answer (it may need an update)");
  }
  return finishExchange(ready, sessionId, consoleNonce, reply);
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

  const report = await d.stats();
  let fps: LiveFingerprints = report ? fingerprintsFromStats(report) : { ok: false, reason: "unsupported_browser" };
  // No certificate stats (Firefox): fall back to the applied descriptions. Two transports stays a failure.
  if (!fps.ok && fps.reason === "unsupported_browser" && d.descriptions) {
    const desc = d.descriptions();
    fps = fingerprintsFromDescriptions(desc.local, desc.remote);
  }
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
