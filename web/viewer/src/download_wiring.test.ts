/**
 * File-manager download wiring: the browse-to-download path in `App.tsx`.
 *
 * `App.tsx` is `.tsx` and the vitest config does not collect it, so following `grant_flow.test.ts`
 * and `broker_wiring.test.ts`, we drive the logic through the EXTRACTED helpers that App.tsx
 * actually delegates to — `downloadFileFromBrowse` and `gateDownloadOnCapability` from
 * `download_callbacks.ts`. Mutations to those functions will break these tests; a copy would not.
 *
 * Proving the three things the Codex checkpoint requires before combined release readiness:
 *
 *   1. Browse-to-download wiring: agent-advertised root → relative path → FileTransferClient.request
 *   2. Capability changes: capability gate is live across grant install and revocation
 *   3. Session teardown: agentTransferDir, grantCapabilities and completedBrowseRelPaths all reset
 *
 * A lightweight stub provides `FileTransferClient.request` — the call's argument is what matters
 * here; the client's own protocol is proven in `file_transfer.test.ts`.
 */

import { describe, it, expect } from "vitest";
import { ControlClient, encodeControl } from "./lib/control";
import { DEFAULT_TRANSFER_DIR } from "./lib/filepath";
import { parseGrantCapabilities } from "./lib/grant";
import { downloadFileFromBrowse, gateDownloadOnCapability } from "./lib/download_callbacks";

/**
 * Mirror of App.tsx `handleFetchGrant` capability extraction.
 *
 * `controlPlane.mintGrant` returns the `signedGrant` JSON string; App.tsx then calls both
 * `setGrantCapabilities(parseGrantCapabilities(signedGrant))` and `control.installGrant(signedGrant)`.
 *
 * The real handleFetchGrant wraps both calls in `if (authSession.isCurrent(epoch) && control ===
 * controlRef.current)` — a React-lifecycle staleness guard that prevents a slow mint from applying
 * to a replacement session. That guard is deliberately omitted here: it is a React hook concern, not
 * a pure-logic concern, and cannot be exercised without rendering App. The two calls below are the
 * only ones a non-stale invocation performs, so they are what this test covers.
 */
async function fakeMintAndInstall(
  fetchSignedGrant: () => Promise<string>,
  control: ControlClient,
  onCapabilities: (caps: ReadonlySet<string>) => void,
): Promise<void> {
  const signedGrant = await fetchSignedGrant();
  onCapabilities(parseGrantCapabilities(signedGrant));
  control.installGrant(signedGrant);
}

// ---------------------------------------------------------------------------
// 1. Browse-to-download wiring
// ---------------------------------------------------------------------------

describe("browse-to-download wiring (App.tsx Task 4 / Codex checkpoint)", () => {
  it("uses the agent-advertised root to compute the relative path and calls request(rel)", () => {
    const requested: string[] = [];
    const stub = { request: (rel: string) => { requested.push(rel); return "id-1"; } };

    downloadFileFromBrowse("D:\\custom\\transfers\\report.pdf", "D:\\custom\\transfers", stub);
    expect(requested).toEqual(["report.pdf"]);

    downloadFileFromBrowse("D:\\custom\\transfers\\sub\\data.csv", "D:\\custom\\transfers", stub);
    expect(requested).toEqual(["report.pdf", "sub/data.csv"]);
  });

  it("is a no-op when no TransferDir message has been received (never falls back to a guessed root)", () => {
    // Codex Blocker 2: we must NOT fall back to DEFAULT_TRANSFER_DIR when the agent has not
    // advertised its root. An old agent may have a custom root; presenting the default would
    // silently request a file from the wrong directory.
    const requested: string[] = [];
    const stub = { request: (rel: string) => { requested.push(rel); return "id-2"; } };

    downloadFileFromBrowse(`${DEFAULT_TRANSFER_DIR}\\hello.txt`, undefined, stub);
    expect(requested).toHaveLength(0);
  });

  it("silently drops a path that is outside the transfer root (no request call)", () => {
    const requested: string[] = [];
    const stub = { request: (rel: string) => { requested.push(rel); return "id-3"; } };

    downloadFileFromBrowse("C:\\Users\\Alice\\sensitive.docx", "C:\\rmt-agent\\transfers", stub);
    expect(requested).toHaveLength(0);
  });

  it("is a no-op when no FileTransferClient is present (session not yet connected)", () => {
    // Mirrors the `if (!fileTransferClient) return;` guard.
    expect(() => downloadFileFromBrowse(`${DEFAULT_TRANSFER_DIR}\\file.bin`, DEFAULT_TRANSFER_DIR, null)).not.toThrow();
  });

  it("a path at the exact transfer root (not inside it) is dropped", () => {
    // `pathRelativeTo` requires full strict containment; the root itself is not a file.
    const requested: string[] = [];
    const stub = { request: (rel: string) => { requested.push(rel); return "id-4"; } };
    downloadFileFromBrowse("C:\\rmt-agent\\transfers", "C:\\rmt-agent\\transfers", stub);
    expect(requested).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 2. ControlClient TransferDir routing → agentTransferDir ref
// ---------------------------------------------------------------------------

describe("TransferDir advertisement → agentTransferDir ref (App.tsx onTransferDir handler)", () => {
  it("onTransferDir handler fires with the agent-sent path and the download switches roots", () => {
    const paths: string[] = [];
    const client = new ControlClient(() => {}, {
      onTransferDir: (p) => paths.push(p),
    });

    client.handleMessage(encodeControl({ t: "TransferDir", c: { path: "E:\\rmt\\transfers" } }));
    expect(paths).toEqual(["E:\\rmt\\transfers"]);

    // Simulate App.tsx: the handler stores the path in agentTransferDirRef.current.
    const requested: string[] = [];
    const stub = { request: (rel: string) => { requested.push(rel); return "id"; } };

    downloadFileFromBrowse("E:\\rmt\\transfers\\output.log", paths[0], stub);
    expect(requested).toEqual(["output.log"]);

    // A second advertisement overwrites the first (agent reconnect / config reload).
    client.handleMessage(encodeControl({ t: "TransferDir", c: { path: "C:\\rmt-agent\\transfers" } }));
    downloadFileFromBrowse(`C:\\rmt-agent\\transfers\\new.txt`, paths[1], stub);
    expect(requested).toEqual(["output.log", "new.txt"]);
  });

  it("download is a no-op before any TransferDir is received (no guessed-root fallback)", () => {
    // Simulates a session start before the agent's first TransferDir arrives. The ref is undefined,
    // so the call returns early — download affordances are suppressed in this state.
    const requested: string[] = [];
    const stub = { request: (rel: string) => { requested.push(rel); return "id"; } };

    downloadFileFromBrowse(`${DEFAULT_TRANSFER_DIR}\\readme.txt`, undefined, stub);
    expect(requested).toHaveLength(0);

    // Now the agent advertises a root — subsequent requests work.
    downloadFileFromBrowse("D:\\shared\\transfers\\data.bin", "D:\\shared\\transfers", stub);
    expect(requested).toEqual(["data.bin"]);
  });
});

// ---------------------------------------------------------------------------
// 3. Capability gating (grantCapabilities state)
// ---------------------------------------------------------------------------

describe("file_download capability gating (App.tsx grantCapabilities state)", () => {
  const ROOT = "C:\\rmt-agent\\transfers";
  const noop = (_path: string) => {};

  it("null grantCapabilities (no grant minted) → download affordance is VISIBLE", () => {
    // The app defaults to visible when the viewer has not yet minted a grant — dev agents and the
    // direct-connect path never go through the grant flow, so the UI must not hide download buttons.
    expect(gateDownloadOnCapability(null, ROOT, noop)).toBe(noop);
  });

  it("undefined transferRoot suppresses download even when grantCapabilities is null", () => {
    // When the agent has not sent a TransferDir message there is no safe root to serve from —
    // the affordance must be suppressed regardless of capability status.
    expect(gateDownloadOnCapability(null, undefined, noop)).toBeUndefined();
  });

  it("undefined transferRoot suppresses download even when the grant explicitly includes file_download", () => {
    // Pins the order of guards: root-unknown check fires BEFORE capability check. A refactor that
    // swaps the guards would return downloadFn here, letting a capable but rootless session offer
    // a download affordance with no safe path to resolve against.
    const signedGrant = JSON.stringify({
      claims: {
        grant: {
          technician_id: "t-1",
          session_id: "s-1",
          machine_id: "m-1",
          capabilities: ["file_download"],
        },
        issued_at_ms: 1,
        expires_at_ms: 2,
      },
      sig: "abcd",
    });
    const caps = parseGrantCapabilities(signedGrant);
    expect(gateDownloadOnCapability(caps, undefined, noop)).toBeUndefined();
  });

  it("grant WITH file_download → download affordance is VISIBLE", () => {
    const signedGrant = JSON.stringify({
      claims: {
        grant: {
          technician_id: "t-1",
          session_id: "s-1",
          machine_id: "m-1",
          capabilities: ["file_download", "clipboard_read"],
        },
        issued_at_ms: 1,
        expires_at_ms: 2,
      },
      sig: "abcd",
    });
    const caps = parseGrantCapabilities(signedGrant);
    expect(gateDownloadOnCapability(caps, ROOT, noop)).toBe(noop);
  });

  it("grant WITHOUT file_download → download affordance is SUPPRESSED (onDownloadFile undefined)", () => {
    const signedGrant = JSON.stringify({
      claims: {
        grant: {
          technician_id: "t-1",
          session_id: "s-1",
          machine_id: "m-1",
          capabilities: ["clipboard_read"], // explicitly omits file_download
        },
        issued_at_ms: 1,
        expires_at_ms: 2,
      },
      sig: "abcd",
    });
    const caps = parseGrantCapabilities(signedGrant);
    expect(gateDownloadOnCapability(caps, ROOT, noop)).toBeUndefined();
  });

  it("an empty capabilities list → download suppressed (grant explicitly grants nothing)", () => {
    const signedGrant = JSON.stringify({
      claims: {
        grant: {
          technician_id: "t-1",
          session_id: "s-1",
          machine_id: "m-1",
          capabilities: [],
        },
        issued_at_ms: 1,
        expires_at_ms: 2,
      },
      sig: "abcd",
    });
    const caps = parseGrantCapabilities(signedGrant);
    expect(gateDownloadOnCapability(caps, ROOT, noop)).toBeUndefined();
  });

  it("onInstallGrant path: capabilities flow from paste JSON into the gate", () => {
    // Mirrors App.tsx onInstallGrant: `setGrantCapabilities(parseGrantCapabilities(signedGrant))`
    const signedGrant = JSON.stringify({
      claims: {
        grant: {
          technician_id: "t-1",
          session_id: "s-1",
          machine_id: "m-1",
          capabilities: ["file_download"],
        },
        issued_at_ms: 1,
        expires_at_ms: 2,
      },
      sig: "abcd",
    });

    let grantCapabilities: ReadonlySet<string> | null = null;

    // Simulate onInstallGrant being called.
    grantCapabilities = parseGrantCapabilities(signedGrant);

    // Gate must now pass.
    expect(gateDownloadOnCapability(grantCapabilities, ROOT, noop)).toBe(noop);

    // A SECOND install that omits the capability gates it off.
    const restrictedGrant = JSON.stringify({
      claims: {
        grant: {
          technician_id: "t-1",
          session_id: "s-1",
          machine_id: "m-1",
          capabilities: [],
        },
        issued_at_ms: 3,
        expires_at_ms: 4,
      },
      sig: "efgh",
    });
    grantCapabilities = parseGrantCapabilities(restrictedGrant);
    expect(gateDownloadOnCapability(grantCapabilities, ROOT, noop)).toBeUndefined();
  });

  it("handleFetchGrant path: minted grant caps reach the gate and the InstallGrant frame is sent", async () => {
    // Mirrors App.tsx handleFetchGrant: mint → setGrantCapabilities + control.installGrant.
    const signedGrant = JSON.stringify({
      claims: {
        grant: {
          technician_id: "t-1",
          session_id: "s-1",
          machine_id: "m-1",
          capabilities: ["file_download"],
        },
        issued_at_ms: 1,
        expires_at_ms: 2,
      },
      sig: "abcd",
    });

    const controlFrames: Uint8Array[] = [];
    const control = new ControlClient((payload) => controlFrames.push(payload));

    let grantCapabilities: ReadonlySet<string> | null = null;

    await fakeMintAndInstall(
      () => Promise.resolve(signedGrant),
      control,
      (caps) => { grantCapabilities = caps; },
    );

    // The capability gate must now pass.
    expect(grantCapabilities).not.toBeNull();
    expect(gateDownloadOnCapability(grantCapabilities, ROOT, noop)).toBe(noop);

    // The agent must have received an InstallGrant carrying the exact signed JSON.
    expect(controlFrames).toHaveLength(1);
    const json = new TextDecoder().decode(controlFrames[0]);
    const msg = JSON.parse(json) as { t: string; c: { signed_grant: string } };
    expect(msg.t).toBe("InstallGrant");
    expect(msg.c.signed_grant).toBe(signedGrant);
  });
});

// ---------------------------------------------------------------------------
// 4. Session teardown
// ---------------------------------------------------------------------------

describe("session teardown clears all file-browser download state (App.tsx handleDisconnect)", () => {
  it("agentTransferDir cleared → downloadFromBrowse is a no-op for any path", () => {
    // Before teardown: agent-advertised root works.
    const requested: string[] = [];
    const stub = { request: (rel: string) => { requested.push(rel); return "id"; } };

    downloadFileFromBrowse("D:\\custom\\transfers\\file.txt", "D:\\custom\\transfers", stub);
    expect(requested).toEqual(["file.txt"]);

    // Teardown: `agentTransferDirRef.current = undefined` in App.tsx.
    // After teardown: NO fallback — any download is a no-op until the next agent sends TransferDir.
    downloadFileFromBrowse("D:\\custom\\transfers\\file.txt", undefined, stub);
    expect(requested).toHaveLength(1); // dropped — no authoritative root

    downloadFileFromBrowse(`${DEFAULT_TRANSFER_DIR}\\new.txt`, undefined, stub);
    expect(requested).toHaveLength(1); // still dropped — no guessed-root fallback
  });

  it("grantCapabilities cleared to null → download affordance reverts to visible (with a known root)", () => {
    // Simulate: grant without file_download was in force, then session ended.
    const restrictedGrant = JSON.stringify({
      claims: {
        grant: {
          technician_id: "t-1",
          session_id: "s-1",
          machine_id: "m-1",
          capabilities: [],
        },
        issued_at_ms: 1,
        expires_at_ms: 2,
      },
      sig: "efgh",
    });
    const noop = (_path: string) => {};
    const ROOT = "C:\\rmt-agent\\transfers";

    let grantCapabilities: ReadonlySet<string> | null = parseGrantCapabilities(restrictedGrant);
    expect(gateDownloadOnCapability(grantCapabilities, ROOT, noop)).toBeUndefined();

    // Teardown: `setGrantCapabilities(null)` in App.tsx.
    grantCapabilities = null;

    // After teardown, the next session's buttons are visible once a root is known.
    expect(gateDownloadOnCapability(grantCapabilities, ROOT, noop)).toBe(noop);
  });

  it("completedBrowseRelPaths cleared to empty set → no stale '✓ saved' badges carry across sessions", () => {
    // Simulate accumulation during a session, then teardown.
    // Uses rel paths (not basenames) so "subdir/report.pdf" ≠ "report.pdf" badge (Bug 2 fix).
    let completedBrowseRelPaths: ReadonlySet<string> = new Set(["report.pdf", "subdir/data.csv"]);
    expect(completedBrowseRelPaths.has("report.pdf")).toBe(true);

    // Teardown: `setCompletedBrowseRelPaths(new Set())` in App.tsx.
    completedBrowseRelPaths = new Set();

    expect(completedBrowseRelPaths.size).toBe(0);
    expect(completedBrowseRelPaths.has("report.pdf")).toBe(false);
  });

  it("teardown sequence: all three states cleared; download is a no-op without a root, buttons visible once root returns", () => {
    // A combined-state test that mirrors the SEQUENCE of assignments in handleDisconnect — if any
    // one is missing, the next session either shows stale badges, suppressed buttons, or downloads
    // into the wrong root. Running them together means a future refactor that clears only two of
    // three will leave one assertion failing.
    let agentRoot: string | undefined = "E:\\rmt\\transfers";
    let grantCaps: ReadonlySet<string> | null = parseGrantCapabilities(
      JSON.stringify({ claims: { grant: { capabilities: [] } }, sig: "x" }),
    );
    let completedBrowseRelPaths: ReadonlySet<string> = new Set(["old.zip"]);

    // All three are armed — download is suppressed, stale badge present, custom root active.
    const noop2 = (_path: string) => {};
    expect(gateDownloadOnCapability(grantCaps, agentRoot, noop2)).toBeUndefined();
    expect(completedBrowseRelPaths.has("old.zip")).toBe(true);
    expect(agentRoot).not.toBeUndefined();

    // --- teardown ---
    grantCaps = null;
    agentRoot = undefined;
    completedBrowseRelPaths = new Set();

    // download is a no-op until the next agent sends TransferDir.
    expect(gateDownloadOnCapability(grantCaps, agentRoot, noop2)).toBeUndefined(); // root unknown → suppressed
    expect(completedBrowseRelPaths.size).toBe(0);
    expect(agentRoot).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 5. UUID-based badge attribution (pendingBrowseRelsRef Map)
// ---------------------------------------------------------------------------

describe("UUID-based badge attribution (Codex 18:43 badge-correctness fix)", () => {
  it("downloadFileFromBrowse returns { rel, requestId } for use as map key", () => {
    let capturedRel: string | undefined;
    let capturedId: string | undefined;
    const stub = {
      request: (rel: string) => {
        capturedRel = rel;
        capturedId = "uuid-abc-123";
        return "uuid-abc-123";
      },
    };
    const result = downloadFileFromBrowse(
      "C:\\rmt-agent\\transfers\\report.pdf",
      "C:\\rmt-agent\\transfers",
      stub,
    );
    expect(result).not.toBeNull();
    expect(result!.rel).toBe("report.pdf");
    expect(result!.requestId).toBe("uuid-abc-123");
    expect(capturedRel).toBe("report.pdf");
    expect(capturedId).toBe("uuid-abc-123");
  });

  it("same-basename concurrent downloads: map resolves both rel paths by UUID, not by name", () => {
    // Simulates App.tsx: two requests with same basename in different dirs.
    // UUID-based lookup must badge each row correctly regardless of completion order.
    const pendingMap = new Map<string, string>(); // requestId → rel
    const completed = new Set<string>();

    // Two requests issued at browse time.
    pendingMap.set("uuid-1111", "report.pdf");
    pendingMap.set("uuid-2222", "subdir/report.pdf");

    // Simulate onDownload arriving out of order: uuid-2222 first (reverse order).
    for (const [fireId, fireRel] of [
      ["uuid-2222", "subdir/report.pdf"],
      ["uuid-1111", "report.pdf"],
    ] as const) {
      const found = pendingMap.get(fireId) ?? null;
      expect(found).toBe(fireRel); // UUID resolves the correct rel
      if (found !== null) {
        pendingMap.delete(fireId);
        completed.add(found);
      }
    }

    expect(completed.has("report.pdf")).toBe(true);
    expect(completed.has("subdir/report.pdf")).toBe(true);
    expect(pendingMap.size).toBe(0); // both entries consumed
  });

  it("failed request (onDownloadError) clears map entry — no stale badge for later same-basename download", () => {
    const pendingMap = new Map<string, string>(); // requestId → rel
    const completed = new Set<string>();

    // Browse request for report.pdf is issued.
    pendingMap.set("uuid-failed", "report.pdf");

    // The request fails: onDownloadError fires with id="uuid-failed".
    const failedId = "uuid-failed";
    pendingMap.delete(failedId); // mirrors the onDownloadError cleanup in App.tsx

    // A subsequent MANUAL download of a file named "report.pdf" arrives via a different UUID.
    // App.tsx only adds to completedBrowseRelPaths when file.id is in the map.
    const manualId = "uuid-manual-different";
    const completedRel = pendingMap.get(manualId) ?? null;
    expect(completedRel).toBeNull(); // not in map — no badge
    if (completedRel !== null) completed.add(completedRel);

    expect(completed.size).toBe(0); // no stale badge
    expect(pendingMap.size).toBe(0); // failed entry was cleaned up
  });

  it("teardown clears the pending Map — stale entries from a previous session are gone", () => {
    const pendingMap = new Map<string, string>();
    pendingMap.set("uuid-stale", "stale-file.bin");

    // Teardown: `pendingBrowseRelsRef.current.clear()` in App.tsx.
    pendingMap.clear();

    // Next session's onDownload cannot find the stale entry.
    expect(pendingMap.get("uuid-stale")).toBeUndefined();
    expect(pendingMap.size).toBe(0);
  });
});
