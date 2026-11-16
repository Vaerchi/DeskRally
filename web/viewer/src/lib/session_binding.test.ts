import { ChannelId } from "./protocol";
import { describe, expect, it } from "vitest";
import {
  allowedBeforeBinding, bytesToHex, createConsoleKey, fingerprintFromSdp, fingerprintsFromDescriptions, fingerprintsFromStats, hexToBytes, parseDeviceBinding, ROLE_AGENT, ROLE_CONSOLE,
  runConsoleBinding, transcriptBytes, uuidBytes, verifyEd25519, type BindingStatus, type BindTranscript, type ConsoleBindingDeps,
} from "./session_binding";

const subtle = globalThis.crypto.subtle;

// GOLDEN VECTOR, pinned identically in crates/protocol/src/session_binding.rs (golden_vector_v1).
const PREIMAGE_ROLE_AGENT_HEX =
  "524d545345535342494e44763100000001" +
  "22222222222222222222222222222222" +
  "a1".repeat(32) + "b2".repeat(32) + "c3".repeat(32) + "d4".repeat(32) +
  "01";

const golden = (): BindTranscript => ({
  sessionId: new Uint8Array(16).fill(0x22),
  agentCertSha256: new Uint8Array(32).fill(0xa1),
  consoleCertSha256: new Uint8Array(32).fill(0xb2),
  agentNonce: new Uint8Array(32).fill(0xc3),
  consoleNonce: new Uint8Array(32).fill(0xd4),
});

describe("transcript bytes", () => {
  it("match the Rust golden vector, and the console role differs only in the last byte", () => {
    expect(bytesToHex(transcriptBytes(golden(), ROLE_AGENT))).toBe(PREIMAGE_ROLE_AGENT_HEX);
    const c = transcriptBytes(golden(), ROLE_CONSOLE);
    expect(bytesToHex(c.slice(0, -1))).toBe(PREIMAGE_ROLE_AGENT_HEX.slice(0, -2));
    expect(c[c.length - 1]).toBe(ROLE_CONSOLE);
  });
  it("refuse a field of the wrong length", () => {
    expect(() => transcriptBytes({ ...golden(), agentNonce: new Uint8Array(31) }, ROLE_AGENT)).toThrow();
  });
});

const colon = (byte: number) => Array.from({ length: 32 }, () => byte.toString(16).padStart(2, "0").toUpperCase()).join(":");
const statsWith = (entries: Record<string, unknown>[]) => new Map(entries.map((e) => [String(e.id), e]));

describe("fingerprintsFromStats", () => {
  const certs = [
    { id: "L", type: "certificate", fingerprint: colon(0xb2), fingerprintAlgorithm: "sha-256" },
    { id: "R", type: "certificate", fingerprint: colon(0xa1), fingerprintAlgorithm: "sha-256" },
  ];
  it("reads the single transport's certificates", () => {
    const r = fingerprintsFromStats(statsWith([{ id: "T", type: "transport", dtlsState: "connected", localCertificateId: "L", remoteCertificateId: "R" }, ...certs]));
    expect(r.ok && bytesToHex(r.console)).toBe("b2".repeat(32));
    expect(r.ok && bytesToHex(r.agent)).toBe("a1".repeat(32));
  });
  it("fails closed on two transports, no transport, or a non-SHA-256 certificate", () => {
    const t = (id: string) => ({ id, type: "transport", dtlsState: "connected", localCertificateId: "L", remoteCertificateId: "R" });
    expect(fingerprintsFromStats(statsWith([t("T1"), t("T2"), ...certs]))).toEqual({ ok: false, reason: "multiple_transports" });
    expect(fingerprintsFromStats(statsWith(certs))).toEqual({ ok: false, reason: "unsupported_browser" });
    expect(fingerprintsFromStats(statsWith([t("T"), certs[0], { ...certs[1], fingerprintAlgorithm: "sha-1" }])))
      .toEqual({ ok: false, reason: "unsupported_browser" });
  });
});

describe("parseDeviceBinding", () => {
  it("accepts material, reports why it is unavailable, and ignores an older server", () => {
    expect(parseDeviceBinding({ device_binding: { mode: "warn", device_pubkey: "ab".repeat(32), grant: "{}" } }))
      .toEqual({ mode: "warn", device_pubkey: "ab".repeat(32), grant: "{}" });
    expect(parseDeviceBinding({ device_binding: { mode: "require", unavailable: "machine has no enrolled device key" } }))
      .toEqual({ mode: "require", unavailable: "machine has no enrolled device key" });
    expect(parseDeviceBinding({ device_binding: { mode: "warn", device_pubkey: "not-a-key", grant: "{}" } })?.unavailable).toBeTruthy();
    expect(parseDeviceBinding({})).toBeUndefined();
  });
});

const SESSION = "22222222-2222-4222-8222-222222222222";

/** A simulated agent: a real Ed25519 device key, signing ITS view of the association. */
async function simulatedAgent() {
  const pair = (await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pub = bytesToHex(new Uint8Array(await subtle.exportKey("raw", pair.publicKey)));
  const sign = async (t: BindTranscript, role: number) => bytesToHex(new Uint8Array(await subtle.sign({ name: "Ed25519" }, pair.privateKey, transcriptBytes(t, role))));
  return { pub, sign };
}

function statsFor(consoleFp: number, agentFp: number) {
  return statsWith([
    { id: "T", type: "transport", dtlsState: "connected", localCertificateId: "L", remoteCertificateId: "R" },
    { id: "L", type: "certificate", fingerprint: colon(consoleFp), fingerprintAlgorithm: "sha-256" },
    { id: "R", type: "certificate", fingerprint: colon(agentFp), fingerprintAlgorithm: "sha-256" },
  ]) as unknown as RTCStatsReport;
}

/** Wire a console run to a simulated agent whose own view is (agentOwn, agentSeesConsole). */
async function run(opts: { agentView?: [number, number]; consoleView?: [number, number]; mode?: "warn" | "require"; agentSilent?: boolean; agentRefuses?: boolean; noMaterial?: boolean; noKey?: boolean; lateProof?: boolean; lateNever?: boolean; onLate?: (s: BindingStatus) => void }) {
  let proofCalls = 0;
  const agent = await simulatedAgent();
  const key = opts.noKey ? null : await createConsoleKey(subtle);
  const [agentOwn, agentSeesConsole] = opts.agentView ?? [0xa1, 0xb2];
  const [consoleOwn, consoleSeesAgent] = opts.consoleView ?? [0xb2, 0xa1];
  let consoleNonce = "";
  const agentNonce = new Uint8Array(32).fill(0xc3);
  let consoleSig = "";
  const deps: ConsoleBindingDeps = {
    binding: opts.noMaterial ? { mode: opts.mode ?? "warn", unavailable: "x" } : { mode: opts.mode ?? "warn", device_pubkey: agent.pub, grant: "{}" },
    key,
    sessionId: SESSION,
    sendStart: (_g, n) => { consoleNonce = n; },
    sendConsoleProof: (s) => { consoleSig = s; },
    awaitAgentProof: async () => {
      proofCalls += 1;
      if (opts.agentSilent) return null;
      // A slow enforcing agent: the on-time wait sees nothing; the proof arrives during the late window (or never).
      if ((opts.lateProof || opts.lateNever) && proofCalls === 1) return null;
      if (opts.lateNever) return null;
      const t: BindTranscript = {
        sessionId: uuidBytes(SESSION), agentCertSha256: new Uint8Array(32).fill(agentOwn),
        consoleCertSha256: new Uint8Array(32).fill(agentSeesConsole), agentNonce, consoleNonce: hexToBytes(consoleNonce),
      };
      return { agentNonceHex: bytesToHex(agentNonce), sigHex: await agent.sign(t, ROLE_AGENT) };
    },
    awaitResult: async () => {
      // The agent verifies the console's proof over ITS view with the granted key.
      const t: BindTranscript = {
        sessionId: uuidBytes(SESSION), agentCertSha256: new Uint8Array(32).fill(agentOwn),
        consoleCertSha256: new Uint8Array(32).fill(agentSeesConsole), agentNonce, consoleNonce: hexToBytes(consoleNonce),
      };
      const ok = !opts.agentRefuses && !!key && (await verifyEd25519(key.publicHex, transcriptBytes(t, ROLE_CONSOLE), consoleSig, subtle));
      return { ok, reason: ok ? null : "console_proof_refused" };
    },
    stats: async () => statsFor(consoleOwn, consoleSeesAgent),
    randomBytes: (n) => new Uint8Array(n).fill(0xd4),
    verify: (p, m, s) => verifyEd25519(p, m, s, subtle),
    onLateStatus: opts.onLate,
  };
  return runConsoleBinding(deps);
}

describe("runConsoleBinding", () => {
  it("verifies an honest agent", async () => {
    expect(await run({})).toEqual({ state: "verified" });
  });
  it("fails a man in the middle (each end sees the attacker's certificate)", async () => {
    // The agent's peer is the attacker (0xee); the console's peer is the attacker too (0xff).
    expect(await run({ agentView: [0xa1, 0xee], consoleView: [0xb2, 0xff] })).toEqual({ state: "failed", reason: "bad_signature" });
  });
  it("treats a silent (older) agent as unverified in warn and failed in require", async () => {
    expect((await run({ agentSilent: true })).state).toBe("unverified");
    expect(await run({ agentSilent: true, mode: "require" })).toEqual({ state: "failed", reason: "no_proof" });
  });
  it("handles missing material and a browser without Ed25519 per mode", async () => {
    expect((await run({ noMaterial: true })).state).toBe("unverified");
    expect((await run({ noMaterial: true, mode: "require" })).state).toBe("failed");
    expect((await run({ noKey: true })).state).toBe("unverified");
    expect(await run({ noKey: true, mode: "require" })).toEqual({ state: "failed", reason: "unsupported_browser" });
  });
  it("fails when the agent refuses the console's proof", async () => {
    expect(await run({ agentRefuses: true })).toEqual({ state: "failed", reason: "agent_refused" });
  });
});

describe("allowedBeforeBinding", () => {
  const ctrl = (t: string, c?: unknown) => ({ channel: ChannelId.Control, payload: new TextEncoder().encode(JSON.stringify(c === undefined ? { t } : { t, c })) });
  it("passes the binding exchange and plain setup, and holds anything the technician sends", () => {
    expect(allowedBeforeBinding(ctrl("BindStart", { grant: "{}", console_nonce: "ab".repeat(32) }))).toBe(true);
    expect(allowedBeforeBinding(ctrl("RequestMonitors"))).toBe(true);
    expect(allowedBeforeBinding(ctrl("InstallSessionPolicy", { signed_policy: "{}" }))).toBe(true);
    expect(allowedBeforeBinding(ctrl("RunCommand", { command: "whoami", shell: "cmd" }))).toBe(false);
    expect(allowedBeforeBinding({ channel: ChannelId.Input, payload: new Uint8Array([1]) })).toBe(false);
    expect(allowedBeforeBinding({ channel: ChannelId.Clipboard, payload: new Uint8Array([1]) })).toBe(false);
    expect(allowedBeforeBinding({ channel: ChannelId.Chat, payload: new Uint8Array([1]) })).toBe(false);
    expect(allowedBeforeBinding({ channel: ChannelId.Control, payload: new Uint8Array([0xff]) })).toBe(false);
  });
});

describe("runConsoleBinding never throws", () => {
  it("maps an exception during the exchange to failed in every mode", async () => {
    for (const mode of ["warn", "require"] as const) {
      const status = await runConsoleBinding({
        binding: { mode, device_pubkey: "ab".repeat(32), grant: "{}" },
        key: { publicHex: "cd".repeat(32), sign: async () => { throw new Error("webcrypto"); } },
        sessionId: SESSION,
        sendStart: () => {}, sendConsoleProof: () => {},
        awaitAgentProof: async () => ({ agentNonceHex: "c3".repeat(32), sigHex: "00".repeat(64) }),
        awaitResult: async () => null,
        stats: async () => { throw new Error("stats"); },
        randomBytes: (n) => new Uint8Array(n),
      });
      expect(status.state).toBe("failed");
    }
  });
});

describe("SDP fingerprint fallback (browsers without certificate stats)", () => {
  const sdp = (...fps: string[]) => ["v=0", "o=- 1 2 IN IP4 127.0.0.1", ...fps.map((f) => `a=fingerprint:${f}`), ""].join("\r\n");
  it("reads one SHA-256 fingerprint, consistent across BUNDLEd sections", () => {
    expect(bytesToHex(fingerprintFromSdp(sdp(`sha-256 ${colon(0xb2)}`, `sha-256 ${colon(0xb2)}`))!)).toBe("b2".repeat(32));
    expect(fingerprintFromSdp(sdp(`sha-256 ${colon(0xb2)}`, `sha-256 ${colon(0xb3)}`))).toBeNull();
    expect(fingerprintFromSdp(sdp(`sha-1 ${"AB:".repeat(19)}AB`))).toBeNull();
    expect(fingerprintFromSdp(undefined)).toBeNull();
  });
  it("runConsoleBinding falls back to the applied descriptions when stats carry no certificates", async () => {
    const r = fingerprintsFromDescriptions(sdp(`sha-256 ${colon(0xb2)}`), sdp(`sha-256 ${colon(0xa1)}`));
    expect(r.ok && bytesToHex(r.console)).toBe("b2".repeat(32));
    expect(r.ok && bytesToHex(r.agent)).toBe("a1".repeat(32));
  });
});

describe("an explicit refusal of BindStart", () => {
  it("fails in every mode (it is not the silence of an older agent)", async () => {
    for (const mode of ["warn", "require"] as const) {
      const status = await runConsoleBinding({
        binding: { mode, device_pubkey: "ab".repeat(32), grant: "{}" },
        key: { publicHex: "cd".repeat(32), sign: async () => new Uint8Array(64) },
        sessionId: SESSION,
        sendStart: () => {}, sendConsoleProof: () => {},
        awaitAgentProof: async () => ({ refused: "grant_refused" }),
        awaitResult: async () => null,
        stats: async () => undefined,
        randomBytes: (n) => new Uint8Array(n),
      });
      expect(status).toEqual({ state: "failed", reason: "agent_refused" });
    }
  });
});

describe("a late agent proof (an enforcing agent whose loop started late, Codex enforce-step3 r2)", () => {
  const late = (extra: Parameters<typeof run>[0]) =>
    new Promise<{ first: BindingStatus; late: BindingStatus }>((resolve, reject) => {
      let first: BindingStatus | null = null;
      let lateStatus: BindingStatus | null = null;
      const done = () => { if (first && lateStatus) resolve({ first, late: lateStatus }); };
      run({ ...extra, onLate: (st) => { lateStatus = st; done(); } }).then((st) => { first = st; done(); }, reject);
    });
  it("settles unverified at once at warn, then upgrades to verified with the full checks", async () => {
    const r = await late({ lateProof: true });
    expect(r.first.state).toBe("unverified");
    expect(r.late).toEqual({ state: "verified" });
  });
  it("fails a late proof from a man in the middle", async () => {
    const r = await late({ lateProof: true, agentView: [0xa1, 0xee], consoleView: [0xb2, 0xff] });
    expect(r.first.state).toBe("unverified");
    expect(r.late).toEqual({ state: "failed", reason: "bad_signature" });
  });
  it("does not wait at require, and reports nothing when no proof ever comes", async () => {
    const calls: BindingStatus[] = [];
    expect(await run({ lateProof: true, mode: "require", onLate: (st) => calls.push(st) })).toEqual({ state: "failed", reason: "no_proof" });
    expect((await run({ lateNever: true, onLate: (st) => calls.push(st) })).state).toBe("unverified");
    await new Promise((r) => setTimeout(r, 20));
    expect(calls).toEqual([]);
  });
});
