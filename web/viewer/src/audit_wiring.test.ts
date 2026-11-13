/**
 * H2 / ADR-008 audit-forwarding wiring: the step that had been missing since H2, and the reason
 * docs/01 §5 sat at `[~]`.
 *
 * The agent chained its audit events and delivered them — inside every backstage `Envelope` and,
 * since ADR-008, on the file-transfer channel too — and `AuditForwarder` knew how to batch and POST
 * them. Nothing connected the two, so every event the agent recorded was dropped by the console and
 * `POST /audit/ingest` never received anything. These tests pin the connections that close that:
 *
 *   1. the transport TAP — every inbound backstage envelope reaches an observer, including one that
 *      answers no pending request;
 *   2. the file-transfer `onAudit` callback reaching the same forwarder, so both halves of the
 *      chain arrive with no gaps in `seq` (a gap fails the control plane's linkage check, which is
 *      worse than a missing row);
 *   3. `ConsoleApiClient.ingestAudit` producing the exact wire shape Go's `auditIngestRequest`
 *      expects, over the authenticated + CSRF-echoing request path;
 *   4. the forwarder existing ONLY for a session with a control-plane id.
 *
 * Following the repo's wiring-test style (`broker_wiring.test.ts`, `m3_wiring.test.ts`): drive the
 * REAL classes with a fake fetch that mirrors the control plane's wire shape, rather than mocking
 * the units against each other.
 */

import { describe, expect, it, vi } from "vitest";

import { auditSessionIdFor, enqueueSealedAuditInto, makeAuditForwarder } from "./App";
import { ChannelBackstageTransport } from "./backstage/channel";
import { BackstageClient, type Envelope } from "./backstage/client";
import { ConsoleApiClient } from "./lib/console_api";
import { FileTransferClient, encodeMessage } from "./lib/file_transfer";
import { AuditForwarder, type AuditEvent } from "./lib/audit_forward";
import { ControlClient, encodeControl } from "./lib/control";

const SESSION = "11111111-1111-4111-8111-111111111111";

function auditEvent(seq: number, over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: `e-${seq}`,
    seq,
    session_id: SESSION,
    technician_id: "u-1",
    machine_id: "m-1",
    occurred_at_unix_ms: 1730000000000 + seq,
    action: { kind: "GetSystemInfo" },
    outcome: { result: "ok" },
    prev_hash: seq === 0 ? "" : `h-${seq - 1}`,
    hash: `h-${seq}`,
    ...over,
  };
}

describe("backstage envelope tap", () => {
  it("hands EVERY inbound envelope to the observer, and still resolves the request", async () => {
    const seen: Envelope[] = [];
    const sent: Uint8Array[] = [];
    const transport = new ChannelBackstageTransport(
      (p) => sent.push(p),
      (env) => seen.push(env),
    );
    const client = new BackstageClient(transport.asBackstageTransport());

    const pending = client.getSystemInfo();
    const envelope = { ok: true, data: { hostname: "WS-1" }, audit: auditEvent(0) };
    transport.handleMessage(new TextEncoder().encode(JSON.stringify(envelope)));

    await pending;
    expect(seen).toHaveLength(1);
    expect((seen[0] as { audit?: AuditEvent }).audit?.seq).toBe(0);
  });

  it("taps an UNSOLICITED envelope — one answering no pending request", () => {
    const seen: Envelope[] = [];
    const transport = new ChannelBackstageTransport(
      () => {},
      (env) => seen.push(env),
    );
    // No request is in flight; handleMessage drops the reply, but the audit event must not be lost.
    transport.handleMessage(
      new TextEncoder().encode(JSON.stringify({ ok: true, audit: auditEvent(7) })),
    );
    expect(seen).toHaveLength(1);
  });

  it("never lets a throwing observer or a malformed frame cost the caller its reply", async () => {
    const transport = new ChannelBackstageTransport(
      () => {},
      () => {
        throw new Error("observer blew up");
      },
    );
    const client = new BackstageClient(transport.asBackstageTransport());
    const pending = client.getSystemInfo();
    transport.handleMessage(
      new TextEncoder().encode(JSON.stringify({ ok: true, data: { hostname: "WS-1" } })),
    );
    await expect(pending).resolves.toBeDefined();
  });
});

describe("both chain halves reach one forwarder", () => {
  it("merges backstage and file-transfer events into a single seq-ordered batch", async () => {
    const posted: { session_id: string; events: AuditEvent[] }[] = [];
    const forwarder = new AuditForwarder(SESSION, async (_url, body) => {
      posted.push(body);
      return { accepted: body.events.length, tail_seq: body.events.length - 1, tail_hash: "t" };
    });

    // The backstage half, through the real transport tap.
    const transport = new ChannelBackstageTransport(
      () => {},
      (env) => forwarder.enqueueEnvelope(env as { ok: boolean; audit?: AuditEvent | null }),
    );
    transport.handleMessage(
      new TextEncoder().encode(JSON.stringify({ ok: true, audit: auditEvent(0) })),
    );

    // The file-transfer half (ADR-008), through the real client's onAudit.
    const ft = new FileTransferClient(
      () => {},
      () => {},
      (event) => forwarder.enqueue(event as AuditEvent),
    );
    ft.handleMessage(encodeMessage({ t: "Audit", c: { id: "x-1", event: auditEvent(1) } }));

    await forwarder.flush();
    expect(posted).toHaveLength(1);
    expect(posted[0].session_id).toBe(SESSION);
    // Both halves, in seq order and with no gap — a gap is what fails the control plane's linkage
    // verification, so "some events arrived" is not good enough.
    expect(posted[0].events.map((e) => e.seq)).toEqual([0, 1]);
    expect(posted[0].events[1].prev_hash).toBe(posted[0].events[0].hash);
  });

  it("drops an event belonging to a DIFFERENT session rather than posting a mixed batch", async () => {
    const posted: { events: AuditEvent[] }[] = [];
    const forwarder = new AuditForwarder(SESSION, async (_url, body) => {
      posted.push(body);
      return { accepted: body.events.length, tail_seq: 0, tail_hash: "t" };
    });
    forwarder.enqueue(auditEvent(0));
    forwarder.enqueue(auditEvent(1, { session_id: "some-other-session" }));
    await forwarder.flush();
    // The control plane rejects a batch whose events disagree with its session_id (audit.go), so a
    // stale event from a previous connection must never ride along.
    expect(posted[0].events.map((e) => e.seq)).toEqual([0]);
  });
});

// REGRESSION (found by the closing review of the change that introduced forwarding).
//
// Installing a grant REPLACES the agent's dispatcher, and `Dispatcher::new` builds a fresh
// `AuditChain` at seq 0. So each grant install starts a NEW chain — and the control plane keys
// chains by `(tenant, session_id)`. Pinning ONE session id across a connection therefore put two
// disjoint chains under one id, which is silently destructive rather than merely wrong.
//
// The fix is in App.tsx (a fresh id per mint, adopted on the agent's ack); what is pinned here is
// the reason it is not optional — reusing a forwarder across a chain restart destroys the trail.
describe("a restarted agent chain must not reuse a forwarder", () => {
  it("silently DISCARDS the new chain and then wedges it, if one forwarder spans both", async () => {
    const posted: { events: AuditEvent[] }[] = [];
    const forwarder = new AuditForwarder(SESSION, async (_url, body) => {
      posted.push(body);
      return { accepted: body.events.length, tail_seq: 0, tail_hash: "t" };
    });

    // Chain A under grant #1.
    forwarder.enqueue(auditEvent(0, { hash: "A0" }));
    forwarder.enqueue(auditEvent(1, { prev_hash: "A0", hash: "A1" }));
    await forwarder.flush();
    expect(posted[0].events.map((e) => e.hash)).toEqual(["A0", "A1"]);

    // Grant #2 installed → the agent starts chain B at seq 0 again, same session id.
    forwarder.enqueue(auditEvent(0, { hash: "B0" }));
    forwarder.enqueue(auditEvent(1, { prev_hash: "B0", hash: "B1" }));
    await forwarder.flush();

    // Nothing was sent: the seq-keyed dedupe swallowed real events that exist nowhere else. This
    // is the damage — not an error, a silent hole in a tamper-evident trail.
    expect(posted).toHaveLength(1);
    expect(forwarder.pendingCount).toBe(0);

    // And chain B's next event would be sent with a prev_hash the stored tail cannot match, so
    // `POST /audit/ingest` rejects the batch from here on (control-plane/audit.go verifyLinkage).
    forwarder.enqueue(auditEvent(2, { prev_hash: "B1", hash: "B2" }));
    await forwarder.flush();
    expect(posted[1].events[0].prev_hash).toBe("B1");
    expect(posted[0].events[1].hash).toBe("A1"); // …which is NOT what the server stored as the tail
  });

  it("keeps both chains intact when each gets its own forwarder, as App.tsx now does", async () => {
    const posted: { session_id: string; events: AuditEvent[] }[] = [];
    const post = async (_url: string, body: { session_id: string; events: AuditEvent[] }) => {
      posted.push(body);
      return { accepted: body.events.length, tail_seq: 0, tail_hash: "t" };
    };
    const grant1 = "aaaaaaaa-1111-4111-8111-111111111111";
    const grant2 = "bbbbbbbb-2222-4222-8222-222222222222";

    const a = new AuditForwarder(grant1, post);
    a.enqueue(auditEvent(0, { session_id: grant1, hash: "A0" }));
    await a.flush(); // App.tsx flushes the outgoing forwarder before swapping

    const b = new AuditForwarder(grant2, post);
    b.enqueue(auditEvent(0, { session_id: grant2, hash: "B0" }));
    await b.flush();

    expect(posted.map((p) => p.session_id)).toEqual([grant1, grant2]);
    expect(posted.map((p) => p.events[0].hash)).toEqual(["A0", "B0"]);
  });
});

describe("makeAuditForwarder", () => {
  it("posts through the authenticated console client to POST /audit/ingest", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = (url: string, init?: RequestInit) => {
      calls.push({ url, init: init ?? {} });
      return Promise.resolve(
        new Response(JSON.stringify({ accepted: 1, tail_seq: 0, tail_hash: "abc" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
    };
    const api = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: fetchImpl as never,
      cookies: () => "rmt_csrf=csrf-token-value",
    });

    const forwarder = makeAuditForwarder(api, SESSION);
    expect(forwarder).not.toBeNull();
    forwarder!.enqueue(auditEvent(0));
    const [res] = await forwarder!.flush();

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/cp/audit/ingest");
    expect(calls[0].init.method).toBe("POST");
    // Same-origin credentials + the double-submit CSRF echo, exactly like every other mutation.
    expect(calls[0].init.credentials).toBe("include");
    expect((calls[0].init.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-token-value");
    // The body is Go's auditIngestRequest, field for field.
    const body = JSON.parse(calls[0].init.body as string);
    expect(Object.keys(body).sort()).toEqual(["events", "session_id"]);
    expect(body.session_id).toBe(SESSION);
    expect(body.events[0].hash).toBe("h-0");
    expect(res).toEqual({ accepted: 1, tail_seq: 0, tail_hash: "abc" });
  });

  it("is null without a control-plane session id — there is nothing to chain events onto", () => {
    const api = new ConsoleApiClient({ baseUrl: "/cp", fetch: (async () => new Response("{}")) as never });
    expect(makeAuditForwarder(api, null)).toBeNull();
  });

  it("keeps events buffered when the control plane is unreachable, so a retry still sends them", async () => {
    let fail = true;
    const api = {
      ingestAudit: vi.fn(async (body: { session_id: string; events: unknown[] }) => {
        if (fail) throw new Error("network down");
        return { accepted: body.events.length, tail_seq: 0, tail_hash: "t" };
      }),
    } as unknown as ConsoleApiClient;

    const forwarder = makeAuditForwarder(api, SESSION)!;
    forwarder.enqueue(auditEvent(0));
    await expect(forwarder.flush()).rejects.toThrow(/network down/);
    // Not dropped: forwarding is a durability measure, and a control plane that blinks must not
    // silently cost the session its trail.
    expect(forwarder.pendingCount).toBe(1);
    fail = false;
    await forwarder.flush();
    expect(forwarder.pendingCount).toBe(0);
  });

  it("passes the teardown flush's keepalive through to ingestAudit (and only then)", async () => {
    const seen: (boolean | undefined)[] = [];
    const api = {
      ingestAudit: vi.fn(async (body: { session_id: string; events: unknown[] }, opts?: { keepalive?: boolean }) => {
        seen.push(opts?.keepalive);
        return { accepted: body.events.length, tail_seq: 0, tail_hash: "t" };
      }),
    } as unknown as ConsoleApiClient;
    const forwarder = makeAuditForwarder(api, SESSION)!;
    forwarder.enqueue(auditEvent(0));
    await forwarder.flush({ keepaliveFirstBatch: true });
    forwarder.enqueue(auditEvent(1));
    await forwarder.flush();
    expect(seen).toEqual([true, undefined]);
  });
});

/**
 * docs/25 F04: the file browser's sealed audit events reach the forwarder — from BOTH replies.
 *
 * The gate is only half the fix. The agent consumes a `seq` for every browse it seals, allowed or
 * refused, and `POST /audit/ingest` verifies strict linkage — so a viewer that decodes a listing and
 * drops its `audit` key does not merely lose one row, it puts a hole in the chain that rejects every
 * later event in the session. This drives the REAL `ControlClient` over REAL encoded bytes into a
 * REAL forwarder, because the failure being guarded against lives exactly in the joins: a handler
 * that forgets to forward, or a decoder that drops the key.
 *
 * The refusal is included deliberately. It is the reply nobody would think to wire up — nothing is
 * displayed from it beyond a message — and it is the one carrying the events an investigator most
 * wants: the attempts that were turned down.
 */
describe("the file browser's sealed audit events", () => {
  it("reach the forwarder from a listing AND from a refusal, in seq order with no gap", async () => {
    const posted: { session_id: string; events: unknown[] }[] = [];
    const api = {
      ingestAudit: vi.fn(async (body: { session_id: string; events: unknown[] }) => {
        posted.push(body);
        return { accepted: body.events.length, tail_seq: 0, tail_hash: "t" };
      }),
    } as unknown as ConsoleApiClient;
    const forwarder = makeAuditForwarder(api, SESSION)!;

    const browsed = auditEvent(0, { action: { kind: "file_browse", path: "C:\\Users" } });
    const refused = auditEvent(1, {
      action: { kind: "file_browse", path: "\\\\attacker\\share" },
      outcome: { result: "denied", reason: "network (UNC) paths are not browsable" },
      prev_hash: "h-0",
    });

    // The App wires exactly these two handlers to the same sink; what is under test here is that
    // both replies actually carry an event through the codec and the client to it.
    const client = new ControlClient(() => {}, {
      onDirectoryListing: (l) => enqueueSealedAuditInto(forwarder, l.audit),
      onDirectoryListingRefused: (r) => enqueueSealedAuditInto(forwarder, r.audit),
    });
    client.handleMessage(
      encodeControl({
        t: "DirectoryListing",
        c: {
          path: "C:\\Users",
          entries: [{ name: "Public", is_dir: true, size: 0, modified_unix: 1700000000 }],
          truncated: false,
          audit: browsed as unknown as Record<string, unknown>,
        },
      }),
    );
    client.handleMessage(
      encodeControl({
        t: "DirectoryListingRefused",
        c: {
          path: "\\\\attacker\\share",
          reason: "network (UNC) paths are not browsable",
          audit: refused as unknown as Record<string, unknown>,
        },
      }),
    );

    await forwarder.flush();
    expect(posted).toHaveLength(1);
    // Deep-equal against the ORIGINAL objects: the control plane re-hashes the canonical preimage,
    // so a single re-typed field reads as the agent forging its own trail.
    expect(posted[0].events).toEqual([browsed, refused]);
    expect((posted[0].events as { seq: number }[]).map((e) => e.seq)).toEqual([0, 1]);
  });

  it("does not buffer anything when the agent sealed none (an unidentified chain)", async () => {
    const api = {
      ingestAudit: vi.fn(async () => ({ accepted: 0, tail_seq: 0, tail_hash: "" })),
    } as unknown as ConsoleApiClient;
    const forwarder = makeAuditForwarder(api, SESSION)!;
    const client = new ControlClient(() => {}, {
      onDirectoryListing: (l) => enqueueSealedAuditInto(forwarder, l.audit),
      onDirectoryListingRefused: (r) => enqueueSealedAuditInto(forwarder, r.audit),
    });

    // The dev/LAN agent seals nothing because its chain has no identity, and sends `audit: null`.
    // Posting a null event would be worse than posting none: `/audit/ingest` 400s the batch and the
    // console swallows flush failures, so the trail would look healthy while carrying nothing.
    client.handleMessage(
      encodeControl({
        t: "DirectoryListing",
        c: { path: "", entries: [], truncated: false, audit: null },
      }),
    );
    client.handleMessage(
      encodeControl({ t: "DirectoryListingRefused", c: { path: "", reason: "no", audit: null } }),
    );
    expect(forwarder.pendingCount).toBe(0);
    await forwarder.flush();
    expect(api.ingestAudit).not.toHaveBeenCalled();
  });
});

/**
 * Loop 91: the recording ack's sealed audit event reaches the session forwarder — VERBATIM.
 *
 * This is the hop the whole recording audit trail rests on, and it is the one that has no type to
 * protect it: the event crosses `control.ts` as an opaque `Record<string, unknown>` and is cast to
 * `AuditEvent` on the way in. The control plane recomputes the event's canonical preimage and
 * treats ANY field-level difference as tampering, so a helpful normalization anywhere along this
 * path would present as the agent having forged its own trail — and because the chain is strictly
 * sequential, that rejection wedges every later event in the session rather than just this one.
 */
describe("a recording ack's sealed audit event", () => {
  it("reaches the forwarder byte-for-byte, with no key added, dropped or re-typed", async () => {
    const posted: { session_id: string; events: unknown[] }[] = [];
    const api = {
      ingestAudit: vi.fn(async (body: { session_id: string; events: unknown[] }) => {
        posted.push(body);
        return { accepted: body.events.length, tail_seq: 0, tail_hash: "t" };
      }),
    } as unknown as ConsoleApiClient;
    const forwarder = makeAuditForwarder(api, SESSION)!;

    // The exact JSON an agent seals: serde's shape, including an internally-tagged action whose
    // field ORDER and numeric types are part of the hashed preimage.
    const sealed = {
      id: "44444444-4444-4444-4444-444444444444",
      seq: 0,
      session_id: SESSION,
      technician_id: "u-1",
      machine_id: "m-1",
      occurred_at_unix_ms: 1730000000000,
      action: {
        kind: "recording_stopped",
        frames: 913,
        payload_bytes: 4211337,
        truncated: "size_limit",
        dropped_frames: 47,
        segment_sha256: ["a".repeat(64), "b".repeat(64)],
        directory: "D:/rec",
      },
      outcome: { result: "ok" },
      prev_hash: "",
      hash: "d".repeat(64),
    };

    enqueueSealedAuditInto(forwarder, sealed);
    await forwarder.flush();

    expect(posted).toHaveLength(1);
    expect(posted[0].session_id).toBe(SESSION);
    // Deep equality against the ORIGINAL object, not a hand-written expectation: an expectation
    // rewritten by hand is exactly how a dropped key survives a review.
    expect(posted[0].events).toEqual([sealed]);
    expect(JSON.stringify(posted[0].events[0])).toBe(JSON.stringify(sealed));
  });

  it("is a no-op when the agent sealed nothing, and when there is no forwarder", async () => {
    const api = {
      ingestAudit: vi.fn(async () => ({ accepted: 0, tail_seq: 0, tail_hash: "" })),
    } as unknown as ConsoleApiClient;
    const forwarder = makeAuditForwarder(api, SESSION)!;

    // The dev/LAN path: signaling vouched for no session, so the agent sealed nothing. That must
    // buffer nothing rather than posting an empty or null event — `POST /audit/ingest` rejects an
    // empty batch with a 400, and the console swallows flush failures, so it would look fine.
    enqueueSealedAuditInto(forwarder, null);
    expect(forwarder.pendingCount).toBe(0);
    await forwarder.flush();
    expect(api.ingestAudit).not.toHaveBeenCalled();

    // And a null forwarder (direct-connect, no control-plane session) must not throw: the recording
    // itself has to keep working on a stack that has no central trail to write to.
    expect(() => enqueueSealedAuditInto(null, { seq: 0, session_id: SESSION })).not.toThrow();
  });

  it("BINDS to the agent's chain on the first event, then drops any other session's", async () => {
    const api = {
      ingestAudit: vi.fn(async () => ({ accepted: 0, tail_seq: 0, tail_hash: "" })),
    } as unknown as ConsoleApiClient;
    const forwarder = makeAuditForwarder(api, SESSION)!;

    // THE INVARIANT THE LOOP-91 RE-KEYING RESTS ON, and the shape it had to become. The agent
    // chains under the session id SIGNALING vouched for — and a deployment that verifies no session
    // tickets vouches for nothing, so the agent falls back to the id inside the installed grant. The
    // console cannot know in advance which of those happened. Keying the forwarder on the brokered
    // id looked obviously right and silently discarded EVERY event on an unticketed stack, with no
    // error anywhere, because flush failures are swallowed by design. So it BINDS to the first event.
    expect(forwarder.boundSessionId).toBeNull();
    //
    // Spread through a plain object because `SealedAuditEvent` is an index-signature record — the
    // deliberately OPAQUE shape the event crosses control.ts as, so nothing on that path can be
    // tempted to normalize a field the control plane is about to re-hash.
    enqueueSealedAuditInto(forwarder, { ...auditEvent(0) });
    expect(forwarder.boundSessionId).toBe(SESSION);
    expect(forwarder.pendingCount).toBe(1);

    // Once bound the filter is exactly as strict as before: a SECOND chain's events are dropped
    // rather than mixed into this batch. That strictness is not optional — the control plane
    // verifies linkage per session, so a mixed batch is rejected outright and the rejection is
    // permanent.
    enqueueSealedAuditInto(forwarder, {
      ...auditEvent(1),
      session_id: "99999999-9999-4999-8999-999999999999",
    });
    expect(forwarder.pendingCount).toBe(1);

    // And an unbound forwarder flushes NOTHING rather than POSTing a null session id, which the
    // control plane answers 400 ("session_id is required") and the console then swallows.
    const empty = makeAuditForwarder(api, SESSION)!;
    await empty.flush();
    expect(api.ingestAudit).not.toHaveBeenCalled();
  });
});

/**
 * Which session id the forwarder is keyed on — the single point where the whole trail can be lost.
 *
 * Found by this loop's own review, after the change had already been written: the first cut read
 * `brokeredSessionRef.current`, which is deliberately NULL for an attended session. That ref
 * expresses OWNERSHIP (teardown must not end a session record it does not own — attended sessions
 * end through their own endpoint), not IDENTITY. An attended ticket is minted by the consent gate,
 * carries a real control-plane session id, and signaling verifies it — so the agent seals a real
 * chain for an attended session, and keying off the ref would have left every one of those events
 * with nothing to forward them. No error anywhere: the console swallows flush failures, and there
 * would have been no flush to fail.
 */
describe("the session id the audit forwarder is keyed on", () => {
  it("is the BROKERED session id, including on the attended path where the ref is null", () => {
    // The ordinary path: acquireBrokeredSession returned a record, and the ref holds it too.
    expect(auditSessionIdFor({ sessionId: "11111111-1111-4111-8111-111111111111" })).toBe(
      "11111111-1111-4111-8111-111111111111",
    );

    // THE ATTENDED PATH: `preAcquired` carries the ticket the consent gate minted, and its session
    // id is exactly what signaling vouches for and the agent stamps into every event — even though
    // `brokeredSessionRef` stays null so teardown leaves the record alone.
    const attended = { sessionId: "22222222-2222-4222-8222-222222222222" };
    expect(auditSessionIdFor(attended)).toBe("22222222-2222-4222-8222-222222222222");
  });

  it("is null for a direct-connect session, which has no session record to chain onto", () => {
    // Both spellings of "there is none": the control plane was unreachable (null) and the dev path
    // never asked (undefined). The agent seals nothing in this case either, so the two sides agree.
    expect(auditSessionIdFor(null)).toBeNull();
    expect(auditSessionIdFor(undefined)).toBeNull();
    // And a null id makes no forwarder at all, rather than one keyed on the string "null".
    expect(makeAuditForwarder({} as unknown as ConsoleApiClient, auditSessionIdFor(null))).toBeNull();
  });
});
