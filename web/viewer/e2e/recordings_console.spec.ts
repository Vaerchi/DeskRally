// docs/63 R3: central session recordings in the console, against a mocked control plane (the harness of
// help_requests.spec.ts, without the peer fakes: no session is started). The server's own rules (capability, group
// scope, audit-before-content, retention) are its tested contract (control-plane/recording_console_test.go); this
// spec proves the console: the Recordings area exists only when the list route lets the principal in, the wording
// of status and provenance, the player advancing segment to segment through same-origin stream URLs, the refusals
// (403/410/503/409) in plain words, and the policy form (every field sent, confirmation before storage turns ON).
//
// The `page` fixture is pinned by playwright.config.ts (PINNED_STORAGE).
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect, type Page } from "@playwright/test";
import { openAppMenu } from "./nav";

type Row = Record<string, unknown>;

const WEBM = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "fixtures", "recording_golden.webm"));
const ID = (n: number) => `00000000-0000-4000-8000-00000000000${n}`;

const rec = (n: number, extra: Row = {}): Row => ({
  id: ID(n), session_id: `s-${n}`, machine_id: `m-${n}`, state: "playback_ready", playable: true,
  provenance: "matches_session_audit", provenance_label: "Agent-signed; matches session audit",
  segment_count: 2, declared_bytes: 5 * 1024 * 1024, truncated: null, dropped_frames: null,
  evidence_complete_at: "2026-10-31T10:00:00Z", expires_at: "2026-11-30T10:00:00Z",
  // joined by the SERVER (control-plane/http_recording_playback.go recContextJSON)
  machine_name: "HOST-1", machine_alias: "Front desk", technician_id: "u-1", technician_name: "Tess Tech",
  session_started_at: "2026-10-31T09:00:00Z", session_ended_at: "2026-10-31T09:30:00Z", ...extra,
});

const playlist = (n: number): Row => ({
  recording_id: ID(n), mime: 'video/webm; codecs="vp8"', total_duration_ms: 95_000,
  provenance: "matches_session_audit", provenance_label: "Agent-signed; matches session audit",
  provenance_note: "n", truncated: null, dropped_frames: 0,
  segments: [
    { index: 0, url: "segments/0/stream", start_ms: 0, duration_ms: 47_000, width: 800, height: 600, bytes: WEBM.length },
    { index: 1, url: "segments/1/stream", start_ms: 48_000, duration_ms: 47_000, width: 1024, height: 768, bytes: WEBM.length },
  ],
});

const detail = (n: number, extra: Row = {}): Row => ({
  ...rec(n), provenance_note: "n", frames: 120, payload_bytes: 1000, expired_at: null, deleted_at: null,
  segments: [
    { index: 0, declared_bytes: 100, sha256: "a".repeat(64), playback: { bytes: 1, width: 800, height: 600, start_ms: 0, duration_ms: 47_000, frames: 60 } },
    { index: 1, declared_bytes: 100, sha256: "b".repeat(64), playback: { bytes: 1, width: 1024, height: 768, start_ms: 48_000, duration_ms: 47_000, frames: 60 } },
  ],
  ...extra,
});

async function harness(page: Page) {
  const cp = {
    listStatus: 200, list: [] as Row[], listCalls: 0,
    details: new Map<string, Row>(),
    playlistStatus: 200, playlistBody: null as Row | null, playlistCalls: 0,
    streams: [] as string[], streamStatus: 200, streamBody: null as Row | null,
    policy: { retention_days: 0, max_recording_bytes: 1024 ** 3, quota_bytes: 20 * 1024 ** 3, enabled: false, storage_available: true } as Row,
    policyStatus: 200, putStatus: 200, puts: [] as unknown[],
    sessions: [] as Row[], joinCalls: [] as string[],
  };
  await page.route(/.*/, (route) => new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
  await page.route("**/cp/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/me") return route.fulfill({ json: { email: "auditor@example.test" } });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [{ id: "m-1", name: "HOST-1", alias: "Front desk", group_id: "g1", device_id: "d1" }], presence_known: true } });
    if (path === "/cp/sessions") { return route.fulfill({ json: { sessions: cp.sessions } }); }
    if (path === "/cp/users") { cp.joinCalls.push(path); return route.fulfill({ json: { users: [] } }); }
    if (path === "/cp/audit") return route.fulfill({ json: { events: [] } });
    if (path === "/cp/help-requests") return route.fulfill({ json: { requests: [] } });
    if (path === "/cp/platform/me") return route.fulfill({ json: { operator: false } });
    if (path === "/cp/session-transfers/incoming") return route.fulfill({ json: { transfers: [] } });
    if (path === "/cp/tenant/recording-policy") {
      if (req.method() === "PUT") {
        cp.puts.push(req.postDataJSON());
        if (cp.putStatus !== 200) return route.fulfill({ status: cp.putStatus, json: { error: "missing capability manage_tenant" } });
        const b = req.postDataJSON() as Row;
        cp.policy = { ...b, enabled: (b.retention_days as number) > 0, storage_available: true };
        return route.fulfill({ json: cp.policy });
      }
      return cp.policyStatus === 200 ? route.fulfill({ json: cp.policy }) : route.fulfill({ status: cp.policyStatus, json: { error: "forbidden" } });
    }
    if (path === "/cp/recordings") {
      cp.listCalls++;
      return cp.listStatus === 200
        ? route.fulfill({ json: { recordings: cp.list, next_cursor: "" } })
        : route.fulfill({ status: cp.listStatus, json: { error: "forbidden" } });
    }
    const one = /^\/cp\/recordings\/([^/]+)$/.exec(path);
    if (one) {
      const d = cp.details.get(one[1]);
      return d ? route.fulfill({ json: d }) : route.fulfill({ status: 404, json: { error: "not_found" } });
    }
    const pl = /^\/cp\/recordings\/([^/]+)\/playlist$/.exec(path);
    if (pl) {
      cp.playlistCalls++;
      if (cp.playlistStatus !== 200) return route.fulfill({ status: cp.playlistStatus, json: cp.playlistBody ?? { error: "x" } });
      return route.fulfill({ json: cp.playlistBody ?? playlist(1) });
    }
    const st = /^\/cp\/recordings\/([^/]+)\/segments\/(\d+)\/stream$/.exec(path);
    if (st) {
      cp.streams.push(path);
      if (cp.streamStatus !== 200) return route.fulfill({ status: cp.streamStatus, json: cp.streamBody ?? { error: "x" } });
      return route.fulfill({ status: 200, contentType: "video/webm", body: WEBM });
    }
    return route.fulfill({ json: {} });
  });
  return cp;
}

const open = async (page: Page) => { await page.goto(test.info().project.use.baseURL!); await openAppMenu(page); };

test("the Recordings area exists only when the list route admits the principal (403 and 404 leave it out)", async ({ page }) => {
  const cp = await harness(page);
  cp.listStatus = 403;
  await open(page);
  await expect.poll(() => cp.listCalls).toBeGreaterThan(0);
  await expect(page.getByRole("tab", { name: "Audit", exact: true })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Recordings", exact: true })).toHaveCount(0);

  const cp2Page = await page.context().newPage();
  const cp2 = await harness(cp2Page);
  cp2.listStatus = 404; // central recording not deployed
  await open(cp2Page);
  await expect.poll(() => cp2.listCalls).toBeGreaterThan(0);
  await expect(cp2Page.getByRole("tab", { name: "Recordings", exact: true })).toHaveCount(0);

  const p3 = await page.context().newPage();
  const cp3 = await harness(p3);
  await open(p3);
  await expect(p3.getByRole("tab", { name: "Recordings", exact: true })).toBeVisible();
  expect(cp3.listCalls).toBeGreaterThan(0);
});

test("the list words status and provenance exactly, flags truncation, and says expired (never missing)", async ({ page }) => {
  const cp = await harness(page);
  cp.list = [
    rec(1),
    rec(2, { provenance: "no_matching_stop_event", provenance_label: "Agent-signed; no matching stop event", truncated: "queue_full", dropped_frames: 117 }),
    rec(3, { state: "evidence_complete", playable: false }),
    rec(4, { state: "playback_failed", playable: false, playback_error: "invalid_ivf" }),
    rec(5, { state: "expired", playable: false }),
    rec(6, { state: "lost", playable: false }),
  ];
  await open(page);
  await page.getByRole("tab", { name: "Recordings", exact: true }).click();

  const r1 = page.getByTestId(`recording-row-${ID(1)}`);
  await expect(r1).toContainText("Front desk");
  await expect(r1).toContainText("Tess Tech");
  await expect(r1).toContainText("2026-10-31 09:00:00");
  await expect(r1).toContainText("5.0 MiB");
  await expect(page.getByTestId(`recording-status-${ID(1)}`)).toHaveText("Playback ready");
  const p1 = page.getByTestId(`recording-provenance-${ID(1)}`);
  await expect(p1).toHaveText("Agent-signed; matches session audit");
  await expect(p1).toHaveAttribute("title", /independent capture verification/);
  await expect(page.getByTestId(`recording-flags-${ID(1)}`)).toHaveText("—");
  await expect(page.getByTestId(`recording-play-${ID(1)}`)).toBeVisible();
  await expect(page.getByTestId(`recording-evidence-${ID(1)}`)).toHaveAttribute("href", `/cp/recordings/${ID(1)}/download`);

  await expect(page.getByTestId(`recording-provenance-${ID(2)}`)).toHaveText("Agent-signed; no matching stop event");
  await expect(page.getByTestId(`recording-provenance-${ID(2)}`)).toHaveAttribute("title", /independent capture verification/);
  await expect(page.getByTestId(`recording-flags-${ID(2)}`)).toContainText("Truncated (queue_full)");
  await expect(page.getByTestId(`recording-flags-${ID(2)}`)).toContainText("117 frames dropped");

  await expect(page.getByTestId(`recording-status-${ID(3)}`)).toHaveText("Evidence complete");
  await expect(page.getByTestId(`recording-play-${ID(3)}`)).toHaveCount(0);
  await expect(page.getByTestId(`recording-evidence-${ID(3)}`)).toBeVisible();
  await expect(page.getByTestId(`recording-status-${ID(4)}`)).toHaveText("Playback failed");
  await expect(page.getByTestId(`recording-play-${ID(4)}`)).toHaveCount(0);
  await expect(page.getByTestId(`recording-status-${ID(5)}`)).toHaveText("Expired");
  await expect(page.getByTestId(`recording-evidence-${ID(5)}`)).toHaveCount(0);
  await expect(page.getByTestId(`recording-status-${ID(6)}`)).toHaveText("Lost");
  await expect(page.getByTestId(`recording-lost-detail-${ID(6)}`)).toContainText("missing after a restore");
  await expect(page.getByTestId(`recording-play-${ID(6)}`)).toHaveCount(0);
  await expect(page.getByTestId(`recording-evidence-${ID(6)}`)).toHaveCount(0);
  // the join is the server's: the Recordings area never asks for the user list
  expect(cp.joinCalls).toEqual([]);
  // Retention-expired is never worded as "missing": only a Lost row (files gone after a restore) says that.
  for (const n of [1, 2, 3, 4, 5]) {
    await expect(page.getByTestId(`recording-row-${ID(n)}`)).not.toContainText(/missing/i);
  }
  // the word "verified" is never used as a claim
  await expect(page.getByTestId("recordings-panel")).not.toContainText(/\bverified\b/i);
});

test("Play loads the playlist once and the video advances segment to segment through same-origin stream URLs", async ({ page }) => {
  const cp = await harness(page);
  cp.list = [rec(1)];
  cp.details.set(ID(1), detail(1));
  await open(page);
  await page.getByRole("tab", { name: "Recordings", exact: true }).click();
  expect(cp.playlistCalls).toBe(0); // listing does not start playback (the playlist fetch is what the server audits)
  await page.getByTestId(`recording-play-${ID(1)}`).click();

  const video = page.getByTestId("recording-video");
  await expect(video).toHaveAttribute("src", `/cp/recordings/${ID(1)}/segments/0/stream`);
  await expect(page.getByTestId("recording-segment-position")).toContainText("Segment 1 of 2");
  expect(cp.playlistCalls).toBe(1);

  // The first segment ends -> the second loads; the end of the last is "finished".
  await video.evaluate((v) => v.dispatchEvent(new Event("ended")));
  await expect(video).toHaveAttribute("src", `/cp/recordings/${ID(1)}/segments/1/stream`);
  await expect(page.getByTestId("recording-segment-position")).toContainText("Segment 2 of 2");
  await expect(page.getByTestId("recording-segment-position")).toContainText("1024×768");
  await video.evaluate((v) => v.dispatchEvent(new Event("ended")));
  await expect(page.getByTestId("recording-segment-position")).toContainText("finished");
  await expect(video).toHaveAttribute("src", `/cp/recordings/${ID(1)}/segments/1/stream`);

  // integrity and the evidence download
  await expect(page.getByTestId("recording-player-provenance")).toHaveText("Agent-signed; matches session audit");
  await expect(page.getByTestId("recording-player-complete")).toBeVisible();
  await expect(page.getByTestId("recording-digest-0")).toContainText("a".repeat(64));
  await expect(page.getByTestId("recording-download")).toHaveAttribute("href", `/cp/recordings/${ID(1)}/download`);
  expect(cp.playlistCalls).toBe(1);
});

test("a truncated recording shows its truncation and dropped frames in the player", async ({ page }) => {
  const cp = await harness(page);
  cp.list = [rec(1, { truncated: "disk_full", dropped_frames: 9 })];
  cp.details.set(ID(1), detail(1, { truncated: "disk_full", dropped_frames: 9 }));
  await open(page);
  await page.getByRole("tab", { name: "Recordings", exact: true }).click();
  await page.getByTestId(`recording-play-${ID(1)}`).click();
  await expect(page.getByTestId("recording-player-flags")).toContainText("Truncated (disk_full)");
  await expect(page.getByTestId("recording-player-flags")).toContainText("9 frames dropped");
  await expect(page.getByTestId("recording-player-complete")).toHaveCount(0);
});

for (const [status, body, text] of [
  [410, { error: "expired" }, "has expired"],
  [403, { error: "forbidden" }, "do not have permission"],
  [503, { error: "audit_unavailable" }, "audit log is unavailable"],
  [409, { error: "playback_pending" }, "still being prepared"],
] as const) {
  test(`a ${status} on the playlist is explained in plain words, with no video`, async ({ page }) => {
    const cp = await harness(page);
    cp.list = [rec(1)];
    cp.details.set(ID(1), detail(1));
    cp.playlistStatus = status;
    cp.playlistBody = body;
    await open(page);
    await page.getByRole("tab", { name: "Recordings", exact: true }).click();
    await page.getByTestId(`recording-play-${ID(1)}`).click();
    await expect(page.getByTestId("recording-player-error")).toContainText(text);
    await expect(page.getByTestId("recording-video")).toHaveCount(0);
  });
}

test("opening an expired recording says expired and offers no download", async ({ page }) => {
  const cp = await harness(page);
  cp.list = [rec(5, { state: "expired", playable: false })];
  cp.details.set(ID(5), detail(5, { state: "expired", playable: false, expired_at: "2026-10-30T00:00:00Z" }));
  await open(page);
  await page.getByRole("tab", { name: "Recordings", exact: true }).click();
  await page.getByTestId(`recording-details-${ID(5)}`).click();
  await expect(page.getByTestId("recording-player-error")).toContainText("expired");
  await expect(page.getByTestId("recording-player-error")).not.toContainText(/missing/i);
  await expect(page.getByTestId("recording-download")).toHaveCount(0);
  expect(cp.playlistCalls).toBe(0);
});

test("a stream refusal after the playlist (video error) is explained from the stream's own status", async ({ page }) => {
  const cp = await harness(page);
  cp.list = [rec(1)];
  cp.details.set(ID(1), detail(1));
  cp.streamStatus = 410;
  cp.streamBody = { error: "expired" };
  await open(page);
  await page.getByRole("tab", { name: "Recordings", exact: true }).click();
  await page.getByTestId(`recording-play-${ID(1)}`).click();
  await expect(page.getByTestId("recording-player-error")).toContainText("has expired");
});

test("policy: default is OFF with 'guest machine only' wording; turning ON asks first, then PUTs EVERY field", async ({ page }) => {
  const cp = await harness(page);
  await open(page);
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  const state = page.getByTestId("recording-policy-state");
  await expect(state).toContainText("recordings stay only on the guest machine");
  await expect(page.getByTestId("recording-retention-off")).toBeChecked();
  await expect(page.getByTestId("recording-policy-not-backed-up")).toHaveText("Recordings are not backed up. A disk or server loss deletes them.");

  await page.getByTestId("recording-retention-90").check();
  await page.getByTestId("recording-policy-save").click();
  // confirmation first: nothing was sent
  await expect(page.getByTestId("recording-policy-confirm")).toContainText("uploaded to this server");
  expect(cp.puts).toHaveLength(0);
  await page.getByTestId("recording-policy-confirm-no").click();
  await expect(page.getByTestId("recording-policy-confirm")).toHaveCount(0);
  expect(cp.puts).toHaveLength(0);

  await page.getByTestId("recording-policy-save").click();
  await page.getByTestId("recording-policy-confirm-yes").click();
  await expect(page.getByTestId("recording-policy-saved")).toBeVisible();
  expect(cp.puts).toEqual([{ retention_days: 90, max_recording_bytes: 1024 ** 3, quota_bytes: 20 * 1024 ** 3 }]);
  await expect(state).toContainText("kept for 90 days");

  // changing an already-ON policy needs no second confirmation, and still sends every field
  await page.getByTestId("recording-retention-custom").check();
  await page.getByTestId("recording-retention-days").fill("45");
  await page.getByTestId("recording-max-mib").fill("512");
  await page.getByTestId("recording-quota-gib").fill("8");
  await page.getByTestId("recording-policy-save").click();
  await expect(page.getByTestId("recording-policy-confirm")).toHaveCount(0);
  await expect.poll(() => cp.puts.length).toBe(2);
  expect(cp.puts[1]).toEqual({ retention_days: 45, max_recording_bytes: 512 * 1024 ** 2, quota_bytes: 8 * 1024 ** 3 });

  // turning it OFF is one click, 0 days, other fields preserved
  await page.getByTestId("recording-retention-off").check();
  await page.getByTestId("recording-policy-save").click();
  await expect.poll(() => cp.puts.length).toBe(3);
  expect(cp.puts[2]).toEqual({ retention_days: 0, max_recording_bytes: 512 * 1024 ** 2, quota_bytes: 8 * 1024 ** 3 });
});

test("policy: an invalid value is refused locally (no PUT); a 403 names the Owner; no read access hides the section", async ({ page }) => {
  const cp = await harness(page);
  await open(page);
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  await page.getByTestId("recording-retention-custom").check();
  await page.getByTestId("recording-retention-days").fill("400");
  await page.getByTestId("recording-policy-save").click();
  await expect(page.getByTestId("recording-policy-error")).toContainText("between 1 and 365");
  expect(cp.puts).toHaveLength(0);

  await page.getByTestId("recording-retention-days").fill("30");
  cp.putStatus = 403;
  await page.getByTestId("recording-policy-save").click();
  await page.getByTestId("recording-policy-confirm-yes").click();
  await expect(page.getByTestId("recording-policy-error")).toContainText("Only an Owner");
  await expect(page.getByTestId("recording-policy-saved")).toHaveCount(0);

  const p2 = await page.context().newPage();
  const cp2 = await harness(p2);
  cp2.policyStatus = 403;
  await open(p2);
  await p2.getByRole("tab", { name: "Security", exact: true }).click();
  await expect(p2.getByTestId("tenant-security")).toBeVisible();
  await expect(p2.getByTestId("recording-policy-form")).toHaveCount(0);
});

const session = (id: string, extra: Row = {}): Row => ({
  id, tenant_id: "t", machine_id: "m-1", technician_id: "u-1", started_at: "2026-10-31T09:00:00Z", ended_at: "2026-10-31T09:30:00Z",
  consent_policy: "", granted_caps: [], machine_group_id: "g1", machine_device_id: "d1", machine_name: "HOST-1", machine_alias: "", note: "", ...extra,
});

test("session history links to the recording only for rows the server gave a recording_id; the link opens it in the player", async ({ page }) => {
  const cp = await harness(page);
  cp.sessions = [session("s-1", { recording_id: ID(1) }), session("s-2")];
  cp.list = [rec(1)];
  cp.details.set(ID(1), detail(1));
  await open(page);
  await page.getByRole("tab", { name: "Sessions", exact: true }).click();
  await expect(page.getByTestId("session-recording-s-1")).toBeVisible();
  await expect(page.getByTestId("session-recording-s-2")).toHaveCount(0);
  await page.getByTestId("session-recording-s-1").click();
  await expect(page.getByTestId("recordings-panel")).toBeVisible();
  await expect(page.getByTestId("recording-video")).toHaveAttribute("src", `/cp/recordings/${ID(1)}/segments/0/stream`);
});

test("without the Recordings area (list refused) a session row offers no recording link even if an id were present", async ({ page }) => {
  const cp = await harness(page);
  cp.listStatus = 403;
  cp.sessions = [session("s-1", { recording_id: ID(1) })];
  await open(page);
  await expect.poll(() => cp.listCalls).toBeGreaterThan(0);
  await page.getByRole("tab", { name: "Sessions", exact: true }).click();
  await expect(page.getByText("HOST-1").first()).toBeVisible();
  await expect(page.getByTestId("session-recording-s-1")).toHaveCount(0);
});
