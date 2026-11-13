/**
 * Unit tests for the management-console panel model (M3): the pure row/badge/format helpers the
 * panel components render with, plus the two composed flows the panels wire onto them —
 * End-session-then-refresh (SessionsPanel) and create-tenant outcome mapping (PlatformPanel) —
 * exercised against a fake in-memory ConsoleApi exactly as the components compose them.
 */
import { describe, it, expect } from "vitest";
import {
  ConsoleApiError,
  type APIToken,
  type ConsoleApi,
  type CreateTenantInput,
  type AttendedSessionRecord,
  type EnrollmentToken,
  type MachineGroup,
  type MachineProperty,
  type MachineRecord,
  type MgmtAuditEvent,
  type SessionSignaling,
  type DeploymentMode,
  type SessionRecord,
  type Tenant,
  type TenantWebhook,
  type UserSummary,
} from "./console_api";
import {
  AUDIT_LIMIT_CHOICES,
  DEFAULT_AUDIT_LIMIT,
  DEPLOYMENT_MODES,
  allowlistEmptyStateText,
  attendedHandoff,
  capsSummary,
  datetimeLocalToUtcRfc3339,
  deletePropertyAndRefresh,
  endSessionAndRefresh,
  bulkGroupSummary,
  bulkStatusSummary,
  endSessionButtonProps,
  filterAuditEventsByText,
  filterMachinesByText,
  machineOnlineTitle,
  formatActor,
  formatAuditTarget,
  formatDurationSeconds,
  groupLabel,
  groupNameFor,
  machineDisplayText,
  machineDisplayTooltip,
  prunedSelection,
  metadataSummary,
  sessionDurationSeconds,
  sessionStatus,
  sessionTone,
  setPropertyAndRefresh,
  setSessionNoteAndRefresh,
  capabilityLabel,
  reportChartRows,
  technicianLabel,
  filterSessionsByText,
  sortPropertiesByKey,
  sortSessionsNewestFirst,
  submitCreateTenant,
  tenantTone,
  validatePropertyForm,
  validateTenantForm,
  filterUsersByText,
  filterTenantsByText,
  filterEnrollmentTokensByText,
  filterAPITokensByText,
  filterMachineGroupsByText,
  filterWebhooksByText,
  buildActiveSessionMap,
  formatSessionSince,
  sessionBadgeTooltip,
  formatDeliveryTime,
  isAgentVersionOutdated,
  endSessionConfirmText,
} from "./console_panels";

function session(id: string, startedAt: string, endedAt?: string): SessionRecord {
  return {
    id,
    tenant_id: "t-1",
    machine_id: "pk-1",
    technician_id: "u-1",
    started_at: startedAt,
    ...(endedAt ? { ended_at: endedAt } : {}),
    consent_policy: "none",
    granted_caps: null,
    machine_group_id: "g-1",
    machine_device_id: "dev-1",
    machine_name: "M",
    machine_alias: "",
    note: "",
  };
}

describe("session helpers", () => {
  it("derives live/ended status and badge tone from ended_at", () => {
    const live = session("a", "2026-07-28T10:00:00Z");
    const ended = session("b", "2026-07-28T09:00:00Z", "2026-07-28T09:30:00Z");
    expect(sessionStatus(live)).toBe("live");
    expect(sessionStatus(ended)).toBe("ended");
    expect(sessionTone(live)).toBe("good");
    expect(sessionTone(ended)).toBe("neutral");
  });

  it("sorts newest-first by started_at, sinking unparseable timestamps", () => {
    const rows = [
      session("old", "2026-07-28T08:00:00Z"),
      session("bad", "not-a-time"),
      session("new", "2026-07-28T11:00:00Z"),
      session("mid", "2026-07-28T10:00:00Z"),
    ];
    expect(sortSessionsNewestFirst(rows).map((r) => r.id)).toEqual(["new", "mid", "old", "bad"]);
    // Non-mutating: the input order survives.
    expect(rows.map((r) => r.id)).toEqual(["old", "bad", "new", "mid"]);
  });

  it("summarizes granted caps, dashing null/empty (Go marshals a nil slice as null)", () => {
    expect(capsSummary(["shell", "process_list"])).toBe("shell, process_list");
    expect(capsSummary([])).toBe("—");
    expect(capsSummary(null)).toBe("—");
    expect(capsSummary(undefined)).toBe("—");
  });
});

describe("bulkStatusSummary (bulk machine status)", () => {
  const r = (machine_id: string, ok: boolean, error?: string) => ({ machine_id, ok, error });

  it("reports 'N updated' when every machine succeeded", () => {
    expect(bulkStatusSummary([r("m-1", true), r("m-2", true)])).toBe("2 updated");
    expect(bulkStatusSummary([])).toBe("0 updated");
  });

  it("reports 'N updated, M failed' when some were skipped", () => {
    expect(bulkStatusSummary([r("m-1", true), r("m-2", false, "denied"), r("m-3", false, "unknown machine")])).toBe(
      "1 updated, 2 failed",
    );
  });
});

describe("bulkGroupSummary (bulk machine group reassignment)", () => {
  const r = (machine_id: string, ok: boolean, error?: string) => ({ machine_id, ok, error });

  it("reports 'N moved' when every machine succeeded", () => {
    expect(bulkGroupSummary([r("m-1", true), r("m-2", true)])).toBe("2 moved");
    expect(bulkGroupSummary([])).toBe("0 moved");
  });

  it("reports 'N moved, M failed' when some were skipped", () => {
    expect(bulkGroupSummary([r("m-1", true), r("m-2", false, "denied")])).toBe("1 moved, 1 failed");
  });
});

describe("prunedSelection (bulk selection confined to visible rows)", () => {
  it("keeps only selected ids that are still visible", () => {
    const kept = prunedSelection(new Set(["a", "b", "c"]), ["b", "c", "d"]);
    expect([...kept].sort()).toEqual(["b", "c"]);
  });

  it("drops the WHOLE selection when the visible set is disjoint (filter switched away)", () => {
    expect(prunedSelection(new Set(["a", "b"]), ["x", "y"]).size).toBe(0);
    expect(prunedSelection(new Set(["a"]), []).size).toBe(0);
  });

  it("keeps every id when all are still visible (a superset view)", () => {
    const kept = prunedSelection(new Set(["a", "b"]), ["a", "b", "c", "d"]);
    expect([...kept].sort()).toEqual(["a", "b"]);
  });
});

describe("formatDurationSeconds (usage-hours report)", () => {
  it("drops leading zero units but always shows seconds", () => {
    expect(formatDurationSeconds(0)).toBe("0s");
    expect(formatDurationSeconds(45)).toBe("45s");
    expect(formatDurationSeconds(90)).toBe("1m 30s");
    expect(formatDurationSeconds(3600)).toBe("1h 0m 0s");
    expect(formatDurationSeconds(3661)).toBe("1h 1m 1s");
  });

  it("floors and clamps a fractional / negative / non-finite input to 0s+", () => {
    expect(formatDurationSeconds(59.9)).toBe("59s");
    expect(formatDurationSeconds(-10)).toBe("0s");
    expect(formatDurationSeconds(Number.NaN)).toBe("0s");
  });
});

describe("sessionDurationSeconds", () => {
  it("returns exact seconds for an ended session", () => {
    const s = session("x", "2026-01-01T00:00:00Z", "2026-01-01T01:23:45Z");
    // 1h 23m 45s = 5025 seconds
    expect(sessionDurationSeconds(s)).toBe(5025);
  });

  it("uses the supplied now for a live (no ended_at) session", () => {
    const startMs = Date.parse("2026-06-15T10:00:00Z");
    const nowMs = startMs + 65_000; // 65 s later
    const s = session("y", "2026-06-15T10:00:00Z");
    expect(sessionDurationSeconds(s, nowMs)).toBe(65);
  });

  it("clamps to 0 when ended_at is before started_at (clock skew)", () => {
    const s = session("z", "2026-01-01T01:00:00Z", "2026-01-01T00:59:00Z");
    expect(sessionDurationSeconds(s)).toBe(0);
  });

  it("returns 0 when started_at is unparseable", () => {
    const s = session("bad", "not-a-date", "2026-01-01T00:01:00Z");
    expect(sessionDurationSeconds(s)).toBe(0);
  });

  it("pin: two sessions with different durations produce different values", () => {
    // Catches mutations that return a constant (e.g., always 0 or always start-start).
    const s10m = session("m", "2026-01-01T00:00:00Z", "2026-01-01T00:10:00Z");
    const s2h = session("m2", "2026-01-01T00:00:00Z", "2026-01-01T02:00:00Z");
    expect(sessionDurationSeconds(s10m)).toBe(600);
    expect(sessionDurationSeconds(s2h)).toBe(7200);
    expect(sessionDurationSeconds(s10m)).not.toBe(sessionDurationSeconds(s2h));
  });
});

describe("audit helpers", () => {
  it("renders the actor, defaulting empty (system-initiated) to \"system\"", () => {
    expect(formatActor({ actor_user_id: "u-9" })).toBe("u-9");
    expect(formatActor({})).toBe("system");
  });

  it("renders the target as kind:id, kind alone, or a dash", () => {
    expect(formatAuditTarget({ target_kind: "machine", target_id: "m-1" })).toBe("machine:m-1");
    expect(formatAuditTarget({ target_kind: "tenant" })).toBe("tenant");
    expect(formatAuditTarget({})).toBe("—");
  });

  it("renders metadata compactly and blanks absent metadata", () => {
    expect(metadataSummary({ device_id: "dev-1" })).toBe('{"device_id":"dev-1"}');
    expect(metadataSummary(undefined)).toBe("");
    expect(metadataSummary(null)).toBe("");
    const c: Record<string, unknown> = {};
    c.self = c;
    expect(metadataSummary(c)).toBe("[object Object]");
  });

  it("offers bounded limit choices including the default", () => {
    expect(AUDIT_LIMIT_CHOICES).toContain(DEFAULT_AUDIT_LIMIT);
    expect([...AUDIT_LIMIT_CHOICES].every((n) => n > 0 && n <= 200)).toBe(true);
  });
});

describe("endSessionAndRefresh", () => {
  it("ends the session then returns the refreshed list newest-first", async () => {
    const calls: string[] = [];
    const refreshed = [
      session("s-old", "2026-07-28T08:00:00Z"),
      session("s-new", "2026-07-28T11:00:00Z", "2026-07-28T11:30:00Z"),
    ];
    const api = {
      endSession: async (id: string) => {
        calls.push(`end:${id}`);
        return refreshed[1];
      },
      listSessions: async () => {
        calls.push("list");
        return refreshed;
      },
    };

    const out = await endSessionAndRefresh(api, "s-new");

    // End happens BEFORE the re-list, so the refreshed rows include the stamp.
    expect(calls).toEqual(["end:s-new", "list"]);
    expect(out.map((r) => r.id)).toEqual(["s-new", "s-old"]);
  });

  it("propagates an end failure without re-listing", async () => {
    let listed = false;
    const api = {
      endSession: async () => {
        throw new ConsoleApiError(404, "could not end session: unknown session");
      },
      listSessions: async () => {
        listed = true;
        return [];
      },
    };
    await expect(endSessionAndRefresh(api, "nope")).rejects.toMatchObject({ kind: "not_found" });
    expect(listed).toBe(false);
  });

  it("FORWARDS the applied date filter to the re-list (ending a session must not revert a filtered view)", async () => {
    let seen: { since?: string; until?: string } | undefined | "none" = "none";
    const api = {
      endSession: async () => session("s-1", "2026-08-02T00:00:00Z"),
      listSessions: async (filter?: { since?: string; until?: string }) => {
        seen = filter;
        return [];
      },
    };
    const filter = { since: "2026-08-01T00:00:00Z" };
    await endSessionAndRefresh(api, "s-1", filter);
    expect(seen).toEqual(filter);
  });
});

describe("setSessionNoteAndRefresh", () => {
  it("saves the note BEFORE re-listing, and returns the list newest-first", async () => {
    const calls: string[] = [];
    const refreshed = [
      session("s-old", "2026-07-28T08:00:00Z"),
      session("s-new", "2026-07-28T11:00:00Z"),
    ];
    const api = {
      setSessionNote: async (id: string, note: string) => {
        calls.push(`note:${id}:${note}`);
        return refreshed[1];
      },
      listSessions: async () => {
        calls.push("list");
        return refreshed;
      },
    };

    const out = await setSessionNoteAndRefresh(api, "s-new", "call back at 5pm");

    expect(calls).toEqual(["note:s-new:call back at 5pm", "list"]);
    expect(out.map((r) => r.id)).toEqual(["s-new", "s-old"]);
  });

  it("propagates a save failure without re-listing", async () => {
    let listed = false;
    const api = {
      setSessionNote: async () => {
        throw new ConsoleApiError(403, "denied");
      },
      listSessions: async () => {
        listed = true;
        return [];
      },
    };
    await expect(setSessionNoteAndRefresh(api, "s-1", "x")).rejects.toMatchObject({ kind: "forbidden" });
    expect(listed).toBe(false);
  });

  it("FORWARDS the applied date filter to the re-list (saving a note must not revert a filtered view)", async () => {
    let seen: { since?: string; until?: string } | undefined | "none" = "none";
    const api = {
      setSessionNote: async () => session("s-1", "2026-08-02T00:00:00Z"),
      listSessions: async (filter?: { since?: string; until?: string }) => {
        seen = filter;
        return [];
      },
    };
    const filter = { until: "2026-08-31T23:59:59Z" };
    await setSessionNoteAndRefresh(api, "s-1", "note", filter);
    expect(seen).toEqual(filter);
  });
});

describe("tenant helpers", () => {
  it("exposes exactly the deployment modes 0001_core.sql accepts", () => {
    expect(DEPLOYMENT_MODES).toEqual(["saas", "self_hosted"]);
  });

  it("tones a tenant row by its disabled flag", () => {
    expect(tenantTone({ disabled: false })).toBe("good");
    expect(tenantTone({ disabled: true })).toBe("bad");
  });

  it("validateTenantForm trims and requires slug + name", () => {
    const ok = validateTenantForm({ slug: "  acme ", name: " Acme ", mode: "saas" });
    expect(ok).toEqual({ ok: true, input: { slug: "acme", name: "Acme", deploymentMode: "saas" } });
    expect(validateTenantForm({ slug: " ", name: "Acme", mode: "saas" }).ok).toBe(false);
    expect(validateTenantForm({ slug: "acme", name: "", mode: "self_hosted" }).ok).toBe(false);
    expect(validateTenantForm({ slug: "acme", name: "Acme", mode: "unknown" as DeploymentMode })).toEqual({
      ok: false,
      message: 'unknown deployment mode "unknown"',
    });
  });
});

describe("submitCreateTenant", () => {
  const created: Tenant = {
    id: "t-2",
    slug: "acme",
    name: "Acme",
    deployment_mode: "saas",
    created_at: "2026-07-28T12:00:00Z",
    disabled: false,
  };

  function apiWith(createTenant: ConsoleApi["createTenant"]) {
    return { createTenant };
  }

  it("creates via the API with the trimmed input and returns the tenant", async () => {
    const inputs: CreateTenantInput[] = [];
    const api = apiWith(async (input) => {
      inputs.push(input);
      return created;
    });
    const out = await submitCreateTenant(api, { slug: " acme ", name: " Acme ", mode: "saas" });
    expect(out).toEqual({ ok: true, tenant: created });
    expect(inputs).toEqual([{ slug: "acme", name: "Acme", deploymentMode: "saas" }]);
  });

  it("maps a 409 conflict to slugTaken for the inline field error", async () => {
    const api = apiWith(async () => {
      throw new ConsoleApiError(409, "could not create tenant: tenant slug already in use");
    });
    const out = await submitCreateTenant(api, { slug: "acme", name: "Acme", mode: "saas" });
    expect(out).toEqual({
      ok: false,
      slugTaken: true,
      message: "could not create tenant: tenant slug already in use",
      status: 409,
    });
  });

  it("keeps other failures (e.g. 403) as non-slug errors", async () => {
    const api = apiWith(async () => {
      throw new ConsoleApiError(403, "could not create tenant: capability denied");
    });
    const out = await submitCreateTenant(api, { slug: "acme", name: "Acme", mode: "saas" });
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.slugTaken).toBe(false);
      expect(out.message).toMatch(/capability denied/);
      // PlatformPanel tells a lapsed second factor (403) from other refusals by this status.
      expect(out.status).toBe(403);
    }
  });

  it("rejects an invalid form locally without calling the API", async () => {
    let called = false;
    const api = apiWith(async () => {
      called = true;
      return created;
    });
    const out = await submitCreateTenant(api, { slug: "", name: "", mode: "saas" });
    expect(out).toEqual({ ok: false, slugTaken: false, message: "slug and name are required" });
    expect(called).toBe(false);
  });

  it("returns ok:false, slugTaken:false, and the error message for a plain TypeError (non-API network error)", async () => {
    const api = apiWith(() => Promise.reject(new TypeError("Failed to fetch")));
    const out = await submitCreateTenant(api, { slug: "acme", name: "Acme", mode: "saas" });
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.slugTaken).toBe(false);
      expect(out.message).toBe("Failed to fetch");
    }
  });
});

describe("attended-session helpers (docs/12 §9)", () => {
  it("maps states to tones and connectability", async () => {
    const { attendedTone, canConnectAttended, attendedPollDone, attendedStateHint } = await import(
      "./console_panels"
    );
    expect(attendedTone("pending")).toBe("neutral");
    expect(attendedTone("redeemed")).toBe("neutral");
    expect(attendedTone("consented")).toBe("good");
    expect(attendedTone("active")).toBe("good");
    expect(attendedTone("declined")).toBe("bad");
    expect(attendedTone("expired")).toBe("bad");
    expect(attendedTone("ended")).toBe("neutral");

    // Connect mirrors the SERVER gate: only consented/active.
    expect(canConnectAttended("pending")).toBe(false);
    expect(canConnectAttended("redeemed")).toBe(false);
    expect(canConnectAttended("consented")).toBe(true);
    expect(canConnectAttended("active")).toBe(true);
    expect(canConnectAttended("declined")).toBe(false);
    // terminal states must never re-enable Connect
    expect(canConnectAttended("expired")).toBe(false);
    expect(canConnectAttended("ended")).toBe(false);

    expect(attendedPollDone("declined")).toBe(true);
    expect(attendedPollDone("ended")).toBe(true);
    expect(attendedPollDone("expired")).toBe(true);
    expect(attendedPollDone("redeemed")).toBe(false);
    // live states must not stop the poll prematurely
    expect(attendedPollDone("active")).toBe(false);
    expect(attendedPollDone("consented")).toBe(false);
    expect(attendedPollDone("pending")).toBe(false);

    for (const s of ["pending", "redeemed", "consented", "active", "declined", "ended", "expired"] as const) {
      expect(attendedStateHint(s)).toBeTruthy();
    }
    // exact strings so a changed hint string fails
    expect(attendedStateHint("consented")).toBe("Consent granted — you can connect.");
    expect(attendedStateHint("declined")).toBe("The user declined the session.");
    expect(attendedStateHint("expired")).toBe("The code or session expired.");
  });

  it("groups an attend code in fours like the Go GroupAttendCode", async () => {
    const { groupAttendCode } = await import("./console_panels");
    expect(groupAttendCode("ABCDEFGHJKMNP")).toBe("ABCD-EFGH-JKMN-P");
    expect(groupAttendCode("ABCD")).toBe("ABCD");
    expect(groupAttendCode("")).toBe("");
  });

  it("startAttendedFlow validates the group and maps create failures", async () => {
    const { startAttendedFlow } = await import("./console_panels");
    const created = {
      session: { id: "as-1", state: "pending" },
      code: "ABCD",
      join_code: "ABCD",
      join_url: "/join#ABCD",
    };
    const api = {
      createAttendedSession: (groupId: string, reason?: string) => {
        expect(groupId).toBe("g-1");
        expect(reason).toBe("help");
        return Promise.resolve(created as never);
      },
    };

    expect(await startAttendedFlow(api, "  ", "help")).toEqual({
      ok: false,
      message: "group id is required",
    });
    expect(await startAttendedFlow(api, " g-1 ", " help ")).toEqual({ ok: true, created });

    const failing = {
      createAttendedSession: () =>
        Promise.reject(new ConsoleApiError(403, "could not create attended session: denied")),
    };
    const out = await startAttendedFlow(failing, "g-1", "");
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.message).toMatch(/denied/);
  });

  it("connectAttendedFlow maps the pre-consent 409 to awaitingConsent", async () => {
    const { connectAttendedFlow } = await import("./console_panels");
    const gateClosed = {
      connectAttendedSession: () =>
        Promise.reject(new ConsoleApiError(409, "could not connect: awaiting consent")),
    };
    expect(await connectAttendedFlow(gateClosed, "as-1")).toEqual({
      ok: false,
      awaitingConsent: true,
      message: "could not connect: awaiting consent",
    });

    const denied = {
      connectAttendedSession: () => Promise.reject(new ConsoleApiError(403, "denied")),
    };
    const out = await connectAttendedFlow(denied, "as-1");
    expect(out).toMatchObject({ ok: false, awaitingConsent: false });

    const connected = {
      session: { id: "as-1", state: "active" },
      signaling: { url: "ws://x/ws", device_id: "d", session_id: "as-1", ticket: {} },
    };
    const open = { connectAttendedSession: () => Promise.resolve(connected as never) };
    expect(await connectAttendedFlow(open, "as-1")).toEqual({ ok: true, connected });

    const networkError = {
      connectAttendedSession: () => Promise.reject(new TypeError("Network error")),
    };
    const netOut = await connectAttendedFlow(networkError, "as-1");
    expect(netOut.ok).toBe(false);
    if (!netOut.ok) {
      expect(netOut.awaitingConsent).toBe(false);
      expect(netOut.message).toBe("Network error");
    }
  });

  it("pollAttendedSession swallows poll failures (transient network → retry)", async () => {
    const { pollAttendedSession } = await import("./console_panels");
    const flaky = { getAttendedSession: () => Promise.reject(new Error("net down")) };
    expect(await pollAttendedSession(flaky, "as-1")).toBeNull();
    const fine = {
      getAttendedSession: () => Promise.resolve({ id: "as-1", state: "consented" } as never),
    };
    expect(await pollAttendedSession(fine, "as-1")).toMatchObject({ state: "consented" });
  });

  it("promoteResultMessage: not promoted → no message", async () => {
    const { promoteResultMessage } = await import("./console_panels");
    const out = promoteResultMessage(false, undefined);
    expect(out).toEqual({ pending: false, text: null });
  });

  it("promoteResultMessage: promoted but no result yet → pending", async () => {
    const { promoteResultMessage } = await import("./console_panels");
    const out = promoteResultMessage(true, undefined);
    expect(out).toEqual({ pending: true });
  });

  it("promoteResultMessage: result success → success text", async () => {
    const { promoteResultMessage } = await import("./console_panels");
    const out = promoteResultMessage(true, { success: true, at: "2026-09-28T12:00:00Z" });
    expect(out).toMatchObject({ pending: false });
    if (!("text" in out)) throw new Error("expected text");
    expect(out.text).toContain("succeeded");
  });

  it("promoteResultMessage: result failure with error → failure text containing error", async () => {
    const { promoteResultMessage } = await import("./console_panels");
    const out = promoteResultMessage(true, {
      success: false,
      error: "elevated installation process exited with code 1",
      at: "2026-09-28T12:00:00Z",
    });
    expect(out).toMatchObject({ pending: false });
    if (!("text" in out)) throw new Error("expected text");
    expect(out.text).toContain("failed");
    expect(out.text).toContain("elevated installation process exited with code 1");
  });

  it("promoteResultMessage: result failure without error → generic failure text", async () => {
    const { promoteResultMessage } = await import("./console_panels");
    const out = promoteResultMessage(true, { success: false, at: "2026-09-28T12:00:00Z" });
    expect(out).toMatchObject({ pending: false });
    if (!("text" in out)) throw new Error("expected text");
    expect(out.text).toContain("unknown error");
  });
});

describe("machine-property helpers (docs/01 §4)", () => {
  it("validatePropertyForm trims + requires the key, but allows an empty value", () => {
    expect(validatePropertyForm({ key: "  site ", value: " HQ " })).toEqual({
      ok: true,
      key: "site",
      value: " HQ ", // value is NOT trimmed — a property value may be meaningfully whitespace
    });
    expect(validatePropertyForm({ key: "note", value: "" })).toEqual({ ok: true, key: "note", value: "" });
    expect(validatePropertyForm({ key: "  ", value: "x" })).toEqual({ ok: false, message: "key is required" });
  });

  it("sortPropertiesByKey orders A→Z without mutating the input", () => {
    const input: MachineProperty[] = [
      { key: "site", value: "HQ" },
      { key: "rack", value: "R7" },
      { key: "asset", value: "A1" },
    ];
    expect(sortPropertiesByKey(input).map((p) => p.key)).toEqual(["asset", "rack", "site"]);
    expect(input[0].key).toBe("site"); // original array untouched (copy-then-sort)
  });

  it("setPropertyAndRefresh sets BEFORE re-listing and returns the sorted result", async () => {
    const calls: string[] = [];
    const api = {
      setMachineProperty: async (id: string, key: string, value: string) => {
        calls.push(`set:${id}:${key}=${value}`);
        return { key, value };
      },
      listMachineProperties: async (id: string) => {
        calls.push(`list:${id}`);
        return [
          { key: "site", value: "HQ" },
          { key: "rack", value: "R7" },
        ];
      },
    };
    const out = await setPropertyAndRefresh(api, "pk-1", "site", "HQ");
    expect(calls).toEqual(["set:pk-1:site=HQ", "list:pk-1"]); // set happens before the re-list
    expect(out.map((p) => p.key)).toEqual(["rack", "site"]); // returned sorted
  });

  it("deletePropertyAndRefresh deletes BEFORE re-listing and returns the sorted result", async () => {
    const calls: string[] = [];
    const api = {
      deleteMachineProperty: async (id: string, key: string) => {
        calls.push(`del:${id}:${key}`);
      },
      listMachineProperties: async (id: string) => {
        calls.push(`list:${id}`);
        return [{ key: "rack", value: "R7" }];
      },
    };
    const out = await deletePropertyAndRefresh(api, "pk-1", "site");
    expect(calls).toEqual(["del:pk-1:site", "list:pk-1"]);
    expect(out.map((p) => p.key)).toEqual(["rack"]);
  });

  it("propagates a delete failure without re-listing", async () => {
    let listed = false;
    const api = {
      deleteMachineProperty: async () => {
        throw new ConsoleApiError(404, "could not delete machine property: unknown property");
      },
      listMachineProperties: async () => {
        listed = true;
        return [];
      },
    };
    await expect(deletePropertyAndRefresh(api, "pk-1", "gone")).rejects.toMatchObject({
      kind: "not_found",
    });
    expect(listed).toBe(false);
  });
});

describe("allowlistEmptyStateText", () => {
  it("distinguishes loading, load-failure (unknown), and a genuinely-empty (open) list", () => {
    // Loading takes precedence.
    expect(allowlistEmptyStateText(true, false)).toMatch(/loading/i);
    expect(allowlistEmptyStateText(true, true)).toMatch(/loading/i);
    // A load FAILURE must say UNKNOWN — never assert the API is open (the bug: a locked-out admin's GET
    // 403s, cidrs stays [], and "open to any network" would be the exact opposite of reality).
    const failed = allowlistEmptyStateText(false, true);
    expect(failed).toMatch(/unknown/i);
    expect(failed).not.toMatch(/open/i);
    // Only a SUCCESSFUL load with no entries is "open".
    expect(allowlistEmptyStateText(false, false)).toMatch(/open to any network/i);
  });
});

describe("datetimeLocalToUtcRfc3339 (audit time filter)", () => {
  it("treats a minute-precision datetime-local value as UTC and appends :00Z", () => {
    expect(datetimeLocalToUtcRfc3339("2026-08-17T12:00")).toBe("2026-08-17T12:00:00Z");
    expect(datetimeLocalToUtcRfc3339("2026-01-02T03:04")).toBe("2026-01-02T03:04:00Z");
  });

  it("keeps seconds when the input already has them", () => {
    expect(datetimeLocalToUtcRfc3339("2026-08-17T12:00:30")).toBe("2026-08-17T12:00:30Z");
  });

  it("returns empty for an empty/whitespace value (no filter)", () => {
    expect(datetimeLocalToUtcRfc3339("")).toBe("");
    expect(datetimeLocalToUtcRfc3339("   ")).toBe("");
  });
});

describe("groupNameFor (Deploy tab group labels)", () => {
  const groups = [
    { id: "g1", name: "Front Office" },
    { id: "g2", name: "Back Office" },
  ];
  it("returns the group's name for a known id", () => {
    expect(groupNameFor(groups, "g1")).toBe("Front Office");
    expect(groupNameFor(groups, "g2")).toBe("Back Office");
  });
  it("falls back to the id itself when the group is not in the list (out of scope / empty)", () => {
    expect(groupNameFor(groups, "gX")).toBe("gX");
    expect(groupNameFor([], "g1")).toBe("g1");
  });
});

describe("groupLabel (machine group cell — fetched list, then joined name, then id)", () => {
  const groups = [{ id: "g1", name: "Front Office" }];
  it("prefers the fetched group name", () => {
    expect(groupLabel(groups, "g1", "STALE")).toBe("Front Office");
  });
  it("falls back to the machine's joined group_name when the fetched list misses (e.g. it failed to load)", () => {
    expect(groupLabel([], "g1", "Front Office")).toBe("Front Office");
    expect(groupLabel(groups, "g2", "Warehouse")).toBe("Warehouse");
  });
  it("falls back to the raw id only when neither a fetched name nor a joined name is available", () => {
    expect(groupLabel([], "g9", undefined)).toBe("g9");
    expect(groupLabel([], "g9", "")).toBe("g9");
  });
});

describe("reportChartRows (chart rows keyed on the UNIQUE id, not the display label)", () => {
  it("keys the sessions report on machine_id — so two machines with the SAME name do NOT collide", () => {
    const rows = reportChartRows(
      "sessions",
      [],
      [
        { machine_id: "m-1", machine_name: "HOST", count: 3 },
        { machine_id: "m-2", machine_name: "HOST", count: 1 }, // same display name, different machine
      ],
      [],
    );
    expect(rows).toEqual([
      { key: "m-1", label: "HOST", value: 3 },
      { key: "m-2", label: "HOST", value: 1 },
    ]);
    // The KEYS are distinct even though the labels collide — the whole point of the fix.
    expect(new Set(rows.map((r) => r.key)).size).toBe(2);
  });

  it("keys the technicians report on technician_id (label is the resolved email)", () => {
    expect(
      reportChartRows("technicians", [], [], [{ technician_id: "u-1", technician: "t@x.test", count: 5 }]),
    ).toEqual([{ key: "u-1", label: "t@x.test", value: 5 }]);
  });

  it("keys the audit report on the action (naturally unique), label = action", () => {
    expect(reportChartRows("actions", [{ action: "session.start", count: 9 }], [], [])).toEqual([
      { key: "session.start", label: "session.start", value: 9 },
    ]);
  });
});

describe("capabilityLabel (roles reference — humanize the rbac key)", () => {
  it("replaces underscores with spaces so a snake_case cap key reads naturally", () => {
    expect(capabilityLabel("manage_tenant")).toBe("manage tenant");
    expect(capabilityLabel("view_machines")).toBe("view machines");
    expect(capabilityLabel("backstage_shell")).toBe("backstage shell");
  });
  it("leaves a key with no underscore unchanged", () => {
    expect(capabilityLabel("audit")).toBe("audit");
  });
});

describe("technicianLabel (technician cell — user email, then raw id)", () => {
  const users = [
    { id: "u1", email: "tech@acme.test" },
    { id: "u2", email: "" },
  ];
  it("resolves a known id to its email", () => {
    expect(technicianLabel(users, "u1")).toBe("tech@acme.test");
  });
  it("falls back to the raw id for an unknown id (e.g. a departed user no longer in the list)", () => {
    expect(technicianLabel(users, "u9")).toBe("u9");
    expect(technicianLabel([], "u1")).toBe("u1");
  });
  it("falls back to the raw id when the matched user has an empty email", () => {
    expect(technicianLabel(users, "u2")).toBe("u2");
  });
});

/**
 * LOOP 82: the attended → live-session hand-off.
 *
 * These exist because the mapping used to be spread across two component hops with NO coverage at
 * all: AttendedPanel exploded the connect response into `onConnect(session, signaling, policy)` and
 * App.tsx reassembled it. Neither is unit-testable, and the failure mode is silent — drop the signed
 * policy and the session runs with full control while the console still shows the group as view-only.
 * That is the same shape loop 80's review found twice on the unattended path.
 */
describe("attendedHandoff", () => {
  // Cast rather than built out: `attendedHandoff` reads only `url` and `device_id` and forwards the
  // rest by reference, so spelling out a full signed ticket would add noise without adding coverage.
  const signaling = {
    url: "wss://sig.example.com/ws",
    device_id: "11111111-1111-1111-1111-111111111111",
    session_id: "sess-9",
    ticket: "tkt",
  } as unknown as SessionSignaling;
  const session = {
    id: "att-1",
    tenant_id: "ten-1",
    group_id: "grp-1",
    state: "active",
    reason: "printer jam",
  } as unknown as AttendedSessionRecord;

  it("forwards the signed session policy into the pre-acquired envelope", () => {
    const h = attendedHandoff({
      session,
      signaling,
      session_policy: { access: "view_only", signed: "SIGNED-BLOB" },
    });
    expect(h.preAcquired.sessionPolicy).toEqual({ access: "view_only", signed: "SIGNED-BLOB" });
  });

  // The complement. Without it, a mapping that fabricated a policy would pass the test above while
  // putting every ordinary attended session into view-only — the fleet-wide interaction loop 80 caught.
  it("carries no policy when the group enforces nothing", () => {
    const h = attendedHandoff({ session, signaling });
    expect(h.preAcquired.sessionPolicy).toBeUndefined();
  });

  // The device id must be the EPHEMERAL one redemption minted, which lives on the signaling envelope.
  // The attended session's own id is a different thing entirely, and the agent binds its policy and
  // its ticket to the device — so confusing the two makes the agent reject a valid policy.
  it("takes the device id from the signaling envelope, not the session record", () => {
    const h = attendedHandoff({ session, signaling });
    expect(h.deviceId).toBe(signaling.device_id);
    expect(h.signalingUrl).toBe(signaling.url);
    expect(h.preAcquired.sessionId).toBe(session.id);
    expect(h.preAcquired.signaling).toBe(signaling);
  });

  it("labels the workspace with the guest's stated reason, falling back when there is none", () => {
    expect(attendedHandoff({ session, signaling }).label).toBe("Attended: printer jam");
    const noReason = { ...session, reason: "" } as unknown as AttendedSessionRecord;
    expect(attendedHandoff({ session: noReason, signaling }).label).toBe("Attended session");
  });
});

// machineDisplayText / machineDisplayTooltip — the pure helpers SessionsPanel uses for its
// machine column. Testing the helpers rather than inline JSX expressions means a regression in
// the component's display logic (wrong field priority, missing fallback) will fail here.
describe("machineDisplayText / machineDisplayTooltip", () => {
  it("shows alias as display text and hostname as tooltip when alias is set", () => {
    expect(machineDisplayText("Lobby PC", "DESKTOP-ABC123")).toBe("Lobby PC");
    expect(machineDisplayTooltip("Lobby PC", "DESKTOP-ABC123")).toBe("DESKTOP-ABC123");
  });

  it("shows machine_name as display text and no tooltip when alias is empty", () => {
    expect(machineDisplayText("", "HOST")).toBe("HOST");
    expect(machineDisplayTooltip("", "HOST")).toBeUndefined();
  });

  it("shows a dash when both alias and machine_name are absent", () => {
    expect(machineDisplayText("", "")).toBe("—");
  });
});

// filterMachinesByText — client-side text filter for the fleet table. Testing the pure helper
// rather than the component keeps mutations in filterMachinesByText visible to vitest.
describe("filterMachinesByText", () => {
  function machine(overrides: Partial<MachineRecord> & { id: string; device_id: string; name: string }): MachineRecord {
    return { tenant_id: "t-1", group_id: "g-1", ...overrides };
  }

  const A = machine({ id: "m-1", device_id: "aaaa-0001", name: "DESKTOP-ALPHA", alias: "Alpha PC", group_name: "London", note: "the operator's workstation" });
  const B = machine({ id: "m-2", device_id: "bbbb-0002", name: "LAPTOP-BETA",   alias: "",         group_name: "Remote",  note: "" });
  const C = machine({ id: "m-3", device_id: "cccc-0003", name: "SERVER-GAMMA",  alias: undefined,  group_name: "DC",      note: "rack 7" });
  const rows = [A, B, C] as const;

  it("returns all rows for an empty query", () => {
    expect(filterMachinesByText(rows, "")).toEqual(rows);
  });

  it("returns the same array reference for an empty query (no copy created)", () => {
    expect(filterMachinesByText(rows, "")).toBe(rows);
  });

  it("returns all rows for a whitespace-only query", () => {
    expect(filterMachinesByText(rows, "   ")).toEqual(rows);
  });

  it("returns the same array reference for a whitespace-only query", () => {
    expect(filterMachinesByText(rows, "   ")).toBe(rows);
  });

  it("matches by alias (friendly name)", () => {
    expect(filterMachinesByText(rows, "Alpha PC")).toEqual([A]);
  });

  it("matches by alias case-insensitively", () => {
    expect(filterMachinesByText(rows, "alpha pc")).toEqual([A]);
  });

  it("matches by hostname (name field)", () => {
    expect(filterMachinesByText(rows, "LAPTOP-BETA")).toEqual([B]);
  });

  it("matches by partial hostname case-insensitively", () => {
    expect(filterMachinesByText(rows, "gamma")).toEqual([C]);
  });

  it("matches by device id", () => {
    expect(filterMachinesByText(rows, "bbbb")).toEqual([B]);
  });

  it("matches by group name", () => {
    expect(filterMachinesByText(rows, "London")).toEqual([A]);
    expect(filterMachinesByText(rows, "dc")).toEqual([C]);
  });

  it("matches by note", () => {
    expect(filterMachinesByText(rows, "rack 7")).toEqual([C]);
    expect(filterMachinesByText(rows, "workstation")).toEqual([A]);
  });

  it("returns multiple rows when the query matches more than one", () => {
    // "DESKTOP" and "LAPTOP" both contain "top"; "Alpha PC" and "rack 7" do not
    const result = filterMachinesByText(rows, "top");
    expect(result).toContain(A); // DESKTOP-ALPHA contains "top"
    expect(result).toContain(B); // LAPTOP-BETA contains "top"
    expect(result).not.toContain(C);
  });

  it("returns an empty array when nothing matches", () => {
    expect(filterMachinesByText(rows, "zzz-no-match")).toEqual([]);
  });

  it("does not match on a machine with absent alias and absent note", () => {
    // B has alias "" and note "" — only its name/device/group contribute
    expect(filterMachinesByText([B], "workstation")).toEqual([]);
  });

  it("matches by OS label", () => {
    const D = machine({ id: "m-4", device_id: "dddd-0004", name: "DESK-DELTA", os: "Windows 11 Pro" });
    expect(filterMachinesByText([...rows, D], "windows")).toEqual([D]);
    expect(filterMachinesByText([...rows, D], "Windows 11")).toEqual([D]);
  });

  it("matches by OS label case-insensitively", () => {
    const D = machine({ id: "m-4", device_id: "dddd-0004", name: "DESK-DELTA", os: "Windows 11 Pro" });
    expect(filterMachinesByText([D], "WINDOWS 11 PRO")).toEqual([D]);
  });

  it("does not match by OS when os field is absent", () => {
    // A, B, C have no os field — searching for a plausible OS string returns nothing
    expect(filterMachinesByText(rows, "Windows")).toEqual([]);
  });

  it("matches by logged_in_user", () => {
    const D = machine({ id: "m-4", device_id: "dddd-0004", name: "DESK-DELTA", logged_in_user: "CORP\\alice" });
    expect(filterMachinesByText([...rows, D], "CORP\\alice")).toEqual([D]);
    expect(filterMachinesByText([...rows, D], "corp")).toEqual([D]);
  });

  it("matches by logged_in_user case-insensitively", () => {
    const D = machine({ id: "m-4", device_id: "dddd-0004", name: "DESK-DELTA", logged_in_user: "CORP\\Alice" });
    expect(filterMachinesByText([D], "corp\\alice")).toEqual([D]);
  });

  it("does not match by logged_in_user when the field is absent", () => {
    // A, B, C have no logged_in_user — searching for a username returns nothing
    expect(filterMachinesByText(rows, "alice")).toEqual([]);
  });
});

// machineOnlineTitle — tooltip text for the presence dot in the fleet table.
// Three states: presenceKnown+online=true, presenceKnown+online=false, unavailable.
describe("machineOnlineTitle", () => {
  it("returns 'online' when presence is known and machine is online", () => {
    expect(machineOnlineTitle(true, true)).toBe("online");
  });

  it("returns 'offline' when presence is known and machine is offline", () => {
    expect(machineOnlineTitle(false, true)).toBe("offline");
  });

  it("returns 'status unavailable' when presence feed was unreachable (presenceKnown=false)", () => {
    // Even if online=false is in the record, an unreachable feed means we cannot trust it.
    expect(machineOnlineTitle(false, false)).toBe("status unavailable");
    expect(machineOnlineTitle(true, false)).toBe("status unavailable");
  });

  it("returns 'status unavailable' when online field is absent (tri-state unknown)", () => {
    expect(machineOnlineTitle(undefined, true)).toBe("status unavailable");
  });

  it("returns 'status unavailable' when both presence unavailable and online absent", () => {
    expect(machineOnlineTitle(undefined, false)).toBe("status unavailable");
  });
});

// filterSessionsByText — client-side text filter for the sessions table. Testing the pure helper
// rather than the component keeps mutations in filterSessionsByText visible to vitest.
describe("filterSessionsByText", () => {
  function sess(overrides: Partial<SessionRecord> & { id: string }): SessionRecord {
    return {
      tenant_id: "t-1",
      machine_id: "pk-1",
      technician_id: "tech@example.com",
      started_at: "2026-09-26T10:00:00Z",
      consent_policy: "none",
      granted_caps: null,
      machine_group_id: "g-1",
      machine_device_id: "dev-aaaa-0001",
      machine_name: "DESKTOP-ALPHA",
      machine_alias: "Alpha PC",
      note: "the operator's workstation",
      ...overrides,
    };
  }

  const A = sess({ id: "s-1", machine_name: "DESKTOP-ALPHA", machine_alias: "Alpha PC", machine_device_id: "dev-aaaa-0001", technician_id: "alice@example.com", note: "the operator's workstation" });
  const B = sess({ id: "s-2", machine_name: "LAPTOP-BETA",   machine_alias: "",         machine_device_id: "dev-bbbb-0002", technician_id: "bob@example.com",   note: "" });
  const C = sess({ id: "s-3", machine_name: "SERVER-GAMMA",  machine_alias: "Gamma",    machine_device_id: "dev-cccc-0003", technician_id: "carol@example.com", note: "rack 7" });
  const rows = [A, B, C] as const;

  it("returns all rows for an empty query", () => {
    expect(filterSessionsByText(rows, "")).toEqual(rows);
  });

  it("returns the same array reference for an empty query (no copy created)", () => {
    expect(filterSessionsByText(rows, "")).toBe(rows);
  });

  it("returns all rows for a whitespace-only query", () => {
    expect(filterSessionsByText(rows, "   ")).toEqual(rows);
  });

  it("returns the same array reference for a whitespace-only query", () => {
    expect(filterSessionsByText(rows, "   ")).toBe(rows);
  });

  it("matches by machine alias", () => {
    expect(filterSessionsByText(rows, "Alpha PC")).toEqual([A]);
  });

  it("matches by machine alias case-insensitively", () => {
    expect(filterSessionsByText(rows, "alpha pc")).toEqual([A]);
  });

  it("matches by machine hostname", () => {
    expect(filterSessionsByText(rows, "LAPTOP-BETA")).toEqual([B]);
  });

  it("matches by machine_name even when machine_alias is also set (both fields are OR'd)", () => {
    // A has machine_alias "Alpha PC" AND machine_name "DESKTOP-ALPHA"; querying by hostname must
    // still match, proving the predicate does not short-circuit on alias.
    expect(filterSessionsByText(rows, "DESKTOP-ALPHA")).toEqual([A]);
    expect(filterSessionsByText(rows, "desktop-alpha")).toEqual([A]);
  });

  it("matches by partial hostname case-insensitively", () => {
    expect(filterSessionsByText(rows, "gamma")).toEqual([C]);
  });

  it("matches by device id", () => {
    expect(filterSessionsByText(rows, "bbbb")).toEqual([B]);
  });

  it("matches by technician id", () => {
    expect(filterSessionsByText(rows, "alice@")).toEqual([A]);
    expect(filterSessionsByText(rows, "carol")).toEqual([C]);
  });

  it("matches by note", () => {
    expect(filterSessionsByText(rows, "rack 7")).toEqual([C]);
    expect(filterSessionsByText(rows, "workstation")).toEqual([A]);
  });

  it("returns multiple rows when the query matches more than one", () => {
    // "example.com" is in every technician_id
    const result = filterSessionsByText(rows, "example.com");
    expect(result).toContain(A);
    expect(result).toContain(B);
    expect(result).toContain(C);
  });

  it("returns an empty array when nothing matches", () => {
    expect(filterSessionsByText(rows, "zzz-no-match")).toEqual([]);
  });

  it("does not match on a session with blank alias and blank note", () => {
    // B has alias "" and note "" — only machine_name/device_id/technician_id contribute
    expect(filterSessionsByText([B], "workstation")).toEqual([]);
  });
});

// filterAuditEventsByText — client-side text filter for the audit table. Testing the pure helper
// rather than the component keeps mutations in filterAuditEventsByText visible to vitest.
describe("filterAuditEventsByText", () => {
  function event(overrides: Partial<MgmtAuditEvent> & { id: string; action: string }): MgmtAuditEvent {
    return {
      tenant_id: "tenant-1",
      occurred_at: "2026-09-26T10:00:00Z",
      ...overrides,
    };
  }

  const A = event({ id: "e1", action: "machine.enroll", actor_user_id: "alice@example.com", target_kind: "machine", target_id: "dev-001" });
  const B = event({ id: "e2", action: "session.start", actor_user_id: "bob@example.com", target_kind: "session", target_id: "sess-abc" });
  const C = event({ id: "e3", action: "auth.login", actor_user_id: "carol@corp.io", target_kind: "user", target_id: "user-xyz", metadata: { ip: "192.168.1.1" } });
  // D has no optional fields — exercises the absent-field safety guards.
  const D = event({ id: "e4", action: "system.health_check" });

  const rows = [A, B, C, D] as const;

  it("returns all rows unchanged for an empty query", () => {
    expect(filterAuditEventsByText(rows, "")).toEqual(rows);
  });

  it("returns the same array reference for an empty query (early-return mutation pin)", () => {
    expect(filterAuditEventsByText(rows, "")).toBe(rows);
  });

  it("returns the same array reference for a whitespace-only query", () => {
    expect(filterAuditEventsByText(rows, "   ")).toBe(rows);
  });

  it("matches by action (exact prefix)", () => {
    expect(filterAuditEventsByText(rows, "machine.enroll")).toEqual([A]);
  });

  it("matches by source IP (IPv4 substring and IPv6), and an event without one is simply not matched", () => {
    const v4 = event({ id: "e5", action: "auth.login", source_ip: "198.51.100.7" });
    const v6 = event({ id: "e6", action: "auth.login", source_ip: "2001:DB8::42" });
    const all = [v4, v6, D];
    expect(filterAuditEventsByText(all, "198.51.100")).toEqual([v4]);
    expect(filterAuditEventsByText(all, "2001:db8::42")).toEqual([v6]);
    expect(filterAuditEventsByText(all, "203.0.113")).toEqual([]);
  });

  it("matches by action case-insensitively", () => {
    expect(filterAuditEventsByText(rows, "SESSION.START")).toEqual([B]);
  });

  it("matches by action substring", () => {
    // "auth" matches "auth.login"
    expect(filterAuditEventsByText(rows, "auth")).toEqual([C]);
  });

  it("matches by actor_user_id", () => {
    expect(filterAuditEventsByText(rows, "alice@example.com")).toEqual([A]);
    expect(filterAuditEventsByText(rows, "carol@")).toEqual([C]);
  });

  it("matches by target_kind", () => {
    expect(filterAuditEventsByText(rows, "session")).toContain(B);
  });

  it("matches by target_id", () => {
    expect(filterAuditEventsByText(rows, "sess-abc")).toEqual([B]);
    expect(filterAuditEventsByText(rows, "user-xyz")).toEqual([C]);
  });

  it("matches by metadata JSON content", () => {
    // C has metadata { ip: "192.168.1.1" } — JSON.stringify produces '{"ip":"192.168.1.1"}'
    expect(filterAuditEventsByText(rows, "192.168.1")).toEqual([C]);
    expect(filterAuditEventsByText(rows, '"ip"')).toEqual([C]);
  });

  it("does not throw when actor, target_kind, target_id, and metadata are all absent", () => {
    // D has only action and the required fields — no optional fields set
    expect(() => filterAuditEventsByText([D], "system")).not.toThrow();
    expect(filterAuditEventsByText([D], "system")).toEqual([D]);
  });

  it("returns multiple rows when the query matches more than one", () => {
    // "example.com" is in actor_user_id of A and B
    const result = filterAuditEventsByText(rows, "example.com");
    expect(result).toContain(A);
    expect(result).toContain(B);
    expect(result).not.toContain(C);
  });

  it("returns an empty array when nothing matches", () => {
    expect(filterAuditEventsByText(rows, "zzz-no-match")).toEqual([]);
  });

  it("does not match target_kind/target_id when both are absent", () => {
    // D has no target_kind or target_id — "machine" should not match it
    expect(filterAuditEventsByText([D], "machine")).toEqual([]);
  });

  it("does not match by occurred_at (time queries belong to the server-side date-range filter)", () => {
    // All events share "2026-09-26" in occurred_at — none should match on that value
    expect(filterAuditEventsByText(rows, "2026-09-26")).toEqual([]);
  });

  it("does not match by internal id or tenant_id fields", () => {
    expect(filterAuditEventsByText([A], "tenant-1")).toEqual([]);
    expect(filterAuditEventsByText([A], "e1")).toEqual([]);
  });
});

// filterUsersByText — client-side text filter for the users table. Testing the pure helper
// rather than the component keeps mutations in filterUsersByText visible to vitest.
describe("filterUsersByText", () => {
  const admin: UserSummary = {
    id: "u-1",
    email: "alice@example.com",
    display_name: "Alice Smith",
    disabled: false,
    roles: ["admin"],
  };
  const tech: UserSummary = {
    id: "u-2",
    email: "bob@example.com",
    display_name: "Bob Jones",
    disabled: false,
    roles: ["technician"],
  };
  const disabled: UserSummary = {
    id: "u-3",
    email: "carol@example.com",
    display_name: "Carol Williams",
    disabled: true,
    roles: [],
  };
  const rows = [admin, tech, disabled] as const;

  it("returns all rows unchanged for an empty query", () => {
    expect(filterUsersByText(rows, "")).toEqual(rows);
  });

  it("returns the same array reference for an empty query (early-return mutation pin)", () => {
    expect(filterUsersByText(rows, "")).toBe(rows);
  });

  it("returns the same array reference for a whitespace-only query", () => {
    expect(filterUsersByText(rows, "   ")).toBe(rows);
  });

  it("matches by email (exact prefix)", () => {
    expect(filterUsersByText(rows, "alice@example.com")).toEqual([admin]);
  });

  it("matches by email case-insensitively", () => {
    expect(filterUsersByText(rows, "ALICE@")).toEqual([admin]);
  });

  it("matches by email substring", () => {
    expect(filterUsersByText(rows, "example.com")).toEqual([admin, tech, disabled]);
  });

  it("matches by display_name", () => {
    expect(filterUsersByText(rows, "Bob Jones")).toEqual([tech]);
  });

  it("matches by display_name case-insensitively", () => {
    expect(filterUsersByText(rows, "alice smith")).toEqual([admin]);
  });

  it("matches by display_name substring", () => {
    expect(filterUsersByText(rows, "Williams")).toEqual([disabled]);
  });

  it("matches by role", () => {
    expect(filterUsersByText(rows, "admin")).toEqual([admin]);
    expect(filterUsersByText(rows, "technician")).toEqual([tech]);
  });

  it("matches by role case-insensitively", () => {
    expect(filterUsersByText(rows, "ADMIN")).toEqual([admin]);
  });

  it("does not match by disabled boolean or internal id", () => {
    expect(filterUsersByText(rows, "true")).toEqual([]);
    expect(filterUsersByText(rows, "false")).toEqual([]);
    expect(filterUsersByText(rows, "u-1")).toEqual([]);
  });

  it("returns an empty array when nothing matches", () => {
    expect(filterUsersByText(rows, "zzz-no-match")).toEqual([]);
  });

  it("returns only the matching row when one of three users matches", () => {
    const result = filterUsersByText(rows, "carol@example.com");
    expect(result).toEqual([disabled]);
  });

  it("handles a user with no roles without throwing", () => {
    expect(() => filterUsersByText([disabled], "admin")).not.toThrow();
    expect(filterUsersByText([disabled], "admin")).toEqual([]);
  });
});

// filterTenantsByText — client-side text filter for the tenants table. Testing the pure helper
// rather than the component keeps mutations in filterTenantsByText visible to vitest.
describe("filterTenantsByText", () => {
  const acme: Tenant = {
    id: "tid-1",
    slug: "acme",
    name: "Acme Corp",
    deployment_mode: "saas",
    created_at: "2026-01-01T00:00:00Z",
    disabled: false,
  };
  const beta: Tenant = {
    id: "tid-2",
    slug: "beta-inc",
    name: "Beta Industries",
    deployment_mode: "self_hosted",
    created_at: "2026-02-01T00:00:00Z",
    disabled: false,
  };
  const gone: Tenant = {
    id: "tid-3",
    slug: "gone-co",
    name: "Gone Company",
    deployment_mode: "saas",
    created_at: "2026-03-01T00:00:00Z",
    disabled: true,
  };
  const rows: readonly Tenant[] = [acme, beta, gone];

  it("returns all rows for an empty query", () => {
    expect(filterTenantsByText(rows, "")).toEqual(rows);
  });

  it("returns the same array reference for an empty query (not a copy)", () => {
    expect(filterTenantsByText(rows, "")).toBe(rows);
  });

  it("returns the same array reference for a whitespace-only query", () => {
    expect(filterTenantsByText(rows, "   ")).toBe(rows);
  });

  it("matches by slug", () => {
    expect(filterTenantsByText(rows, "acme")).toEqual([acme]);
  });

  it("matches by slug case-insensitively", () => {
    expect(filterTenantsByText(rows, "BETA-INC")).toEqual([beta]);
  });

  it("matches by slug substring", () => {
    expect(filterTenantsByText(rows, "gone")).toEqual([gone]);
  });

  it("matches by name", () => {
    expect(filterTenantsByText(rows, "Acme Corp")).toEqual([acme]);
  });

  it("matches by name case-insensitively", () => {
    expect(filterTenantsByText(rows, "beta industries")).toEqual([beta]);
  });

  it("matches by name substring", () => {
    expect(filterTenantsByText(rows, "Company")).toEqual([gone]);
  });

  it("matches by deployment_mode", () => {
    expect(filterTenantsByText(rows, "self_hosted")).toEqual([beta]);
  });

  it("matches by deployment_mode case-insensitively", () => {
    expect(filterTenantsByText(rows, "SAAS")).toEqual([acme, gone]);
  });

  it("matches by id", () => {
    expect(filterTenantsByText(rows, "tid-2")).toEqual([beta]);
  });

  it("matches by id substring", () => {
    expect(filterTenantsByText(rows, "tid-")).toEqual([acme, beta, gone]);
  });

  it("does not match by disabled boolean", () => {
    expect(filterTenantsByText(rows, "true")).toEqual([]);
    expect(filterTenantsByText(rows, "false")).toEqual([]);
  });

  it("does not match by derived status strings (active/disabled are not searchable fields)", () => {
    expect(filterTenantsByText(rows, "active")).toEqual([]);
    expect(filterTenantsByText(rows, "disabled")).toEqual([]);
  });

  it("does not match by created_at", () => {
    expect(filterTenantsByText(rows, "2026-01-01")).toEqual([]);
  });

  it("returns an empty array when nothing matches", () => {
    expect(filterTenantsByText(rows, "zzz-no-match")).toEqual([]);
  });

  it("returns only the matching row when one of three tenants matches", () => {
    const result = filterTenantsByText(rows, "acme");
    expect(result).toEqual([acme]);
  });
});

// filterEnrollmentTokensByText — client-side text filter for the enrollment tokens table.
// Testing the pure helper rather than the component keeps mutations in
// filterEnrollmentTokensByText visible to vitest.
describe("filterEnrollmentTokensByText", () => {
  const tok = (over: Partial<EnrollmentToken> = {}): EnrollmentToken => ({
    id: "tok-aaa",
    tenant_id: "tid-1",
    group_id: "grp-111",
    created_by: "user@example.com",
    created_at: "2026-01-01T00:00:00Z",
    expires_at: "2026-02-01T00:00:00Z",
    max_uses: 5,
    uses: 2,
    revoked: false,
    ...over,
  });

  const active = tok();
  const revoked = tok({ id: "tok-bbb", group_id: "grp-222", revoked: true, created_by: "admin@example.com" });
  const noCreator = tok({ id: "tok-ccc", group_id: "grp-333", created_by: undefined });
  const rows: readonly EnrollmentToken[] = [active, revoked, noCreator];

  it("returns all rows for an empty query", () => {
    expect(filterEnrollmentTokensByText(rows, "")).toEqual(rows);
  });

  it("returns the same array reference for an empty query (not a copy)", () => {
    expect(filterEnrollmentTokensByText(rows, "")).toBe(rows);
  });

  it("returns the same array reference for a whitespace-only query", () => {
    expect(filterEnrollmentTokensByText(rows, "   ")).toBe(rows);
  });

  it("matches by id", () => {
    expect(filterEnrollmentTokensByText(rows, "tok-aaa")).toEqual([active]);
  });

  it("matches by id case-insensitively", () => {
    expect(filterEnrollmentTokensByText(rows, "TOK-BBB")).toEqual([revoked]);
  });

  it("matches by id substring", () => {
    expect(filterEnrollmentTokensByText(rows, "tok-")).toEqual([active, revoked, noCreator]);
  });

  it("matches by group_id", () => {
    expect(filterEnrollmentTokensByText(rows, "grp-111")).toEqual([active]);
  });

  it("matches by group_id case-insensitively", () => {
    expect(filterEnrollmentTokensByText(rows, "GRP-222")).toEqual([revoked]);
  });

  it("matches by group_id substring", () => {
    expect(filterEnrollmentTokensByText(rows, "grp-")).toEqual([active, revoked, noCreator]);
  });

  it("matches by created_by", () => {
    expect(filterEnrollmentTokensByText(rows, "user@example.com")).toEqual([active]);
  });

  it("matches by created_by case-insensitively", () => {
    expect(filterEnrollmentTokensByText(rows, "ADMIN@EXAMPLE.COM")).toEqual([revoked]);
  });

  it("does not match on a token with no created_by when querying a creator", () => {
    expect(filterEnrollmentTokensByText([noCreator], "user@example.com")).toEqual([]);
  });

  it("matches by derived status 'active'", () => {
    expect(filterEnrollmentTokensByText(rows, "active")).toEqual([active, noCreator]);
  });

  it("matches by derived status 'revoked'", () => {
    expect(filterEnrollmentTokensByText(rows, "revoked")).toEqual([revoked]);
  });

  it("does not match by expires_at (excluded from search)", () => {
    expect(filterEnrollmentTokensByText(rows, "2026-02-01")).toEqual([]);
  });

  it("does not match by created_at (excluded from search)", () => {
    expect(filterEnrollmentTokensByText(rows, "2026-01-01")).toEqual([]);
  });

  it("returns an empty array when nothing matches", () => {
    expect(filterEnrollmentTokensByText(rows, "zzz-no-match")).toEqual([]);
  });

  it("returns only the matching row when one of three tokens matches", () => {
    expect(filterEnrollmentTokensByText(rows, "tok-bbb")).toEqual([revoked]);
  });
});

// filterAPITokensByText — client-side text filter for the API tokens table. Testing the pure helper
// rather than the component keeps mutations in filterAPITokensByText visible to vitest.
describe("filterAPITokensByText", () => {
  const t = (over: Partial<APIToken> = {}): APIToken => ({
    id: "tok-aaa",
    name: "ci-bot",
    capabilities: ["view_machines", "view_sessions"],
    created_at: "2026-01-01T00:00:00Z",
    expires_at: "2026-06-01T00:00:00Z",
    revoked_at: null,
    ...over,
  });

  // revoked uses a distinct capability so capability-match tests can distinguish the two rows
  const active = t();
  const revoked = t({ id: "tok-bbb", name: "old-bot", capabilities: ["view_audit"], revoked_at: "2026-02-01T00:00:00Z" });
  const rows = [active, revoked];

  it("returns the same reference for an empty query", () => {
    expect(filterAPITokensByText(rows, "")).toBe(rows);
  });

  it("returns the same reference for a whitespace-only query", () => {
    expect(filterAPITokensByText(rows, "   ")).toBe(rows);
  });

  it("filters by name (case-insensitive)", () => {
    expect(filterAPITokensByText(rows, "CI-BOT")).toEqual([active]);
  });

  it("filters by id", () => {
    expect(filterAPITokensByText(rows, "tok-bbb")).toEqual([revoked]);
  });

  it("filters by capability substring shared by both tokens", () => {
    expect(filterAPITokensByText(rows, "view_")).toEqual([active, revoked]);
  });

  it("filters by capability substring unique to one token", () => {
    expect(filterAPITokensByText(rows, "view_sessions")).toEqual([active]);
  });

  it("filters by 'active' status", () => {
    expect(filterAPITokensByText(rows, "active")).toEqual([active]);
  });

  it("filters by 'revoked' status", () => {
    expect(filterAPITokensByText(rows, "revoked")).toEqual([revoked]);
  });

  it("does not match expires_at date strings (excluded from search)", () => {
    expect(filterAPITokensByText(rows, "2026-06-01")).toEqual([]);
  });

  it("does not match created_at date strings (excluded from search)", () => {
    expect(filterAPITokensByText(rows, "2026-01-01")).toEqual([]);
  });

  it("returns empty for a no-match query", () => {
    expect(filterAPITokensByText(rows, "zzz-no-match")).toEqual([]);
  });
});

// filterMachineGroupsByText — client-side text filter for the machine groups table.
// MachineGroup rows have only name and id; there is no status or derived field.
describe("filterMachineGroupsByText", () => {
  const alpha: MachineGroup = { id: "gid-alpha", name: "Front Office" };
  const beta: MachineGroup = { id: "gid-beta", name: "Back Office" };
  const gamma: MachineGroup = { id: "gid-gamma", name: "Engineering" };
  const rows = [alpha, beta, gamma];

  it("returns the same array reference for an empty query", () => {
    expect(filterMachineGroupsByText(rows, "")).toBe(rows);
  });

  it("returns the same array reference for a whitespace-only query", () => {
    expect(filterMachineGroupsByText(rows, "   ")).toBe(rows);
  });

  it("matches by name (case-insensitive)", () => {
    expect(filterMachineGroupsByText(rows, "office")).toEqual([alpha, beta]);
  });

  it("matches by name exact prefix", () => {
    expect(filterMachineGroupsByText(rows, "Front")).toEqual([alpha]);
  });

  it("matches by name uppercased query", () => {
    expect(filterMachineGroupsByText(rows, "ENGINEERING")).toEqual([gamma]);
  });

  it("matches by id substring", () => {
    expect(filterMachineGroupsByText(rows, "gid-beta")).toEqual([beta]);
  });

  it("matches by id prefix shared by all rows", () => {
    expect(filterMachineGroupsByText(rows, "gid-")).toEqual([alpha, beta, gamma]);
  });

  it("returns only the rows whose name or id contains the query", () => {
    expect(filterMachineGroupsByText(rows, "alpha")).toEqual([alpha]);
  });

  it("returns empty for a no-match query", () => {
    expect(filterMachineGroupsByText(rows, "zzz-no-match")).toEqual([]);
  });
});

// filterWebhooksByText — client-side text filter for the webhooks table. Testing the pure helper
// rather than the component keeps mutations in filterWebhooksByText visible to vitest.
describe("filterWebhooksByText", () => {
  const wh = (over: Partial<TenantWebhook> = {}): TenantWebhook => ({
    id: "wh-aaa",
    url: "https://example.com/hook",
    events: ["session.start"],
    created_at: "2026-09-27T00:00:00Z",
    ...over,
  });

  // "catchall" webhook: empty events array — subscribes to every event.
  // URL deliberately contains no substring "all" so the sentinel branch is the ONLY match path for
  // the query "all". An "all.example.com" URL would hide a sentinel deletion mutation.
  const catchall = wh({ id: "wh-bbb", url: "https://receiver.example.com/hook", events: [] });
  // "filtered" webhook: specific events list
  const filtered = wh();
  const rows = [catchall, filtered];

  it("returns the same reference for an empty query", () => {
    expect(filterWebhooksByText(rows, "")).toBe(rows);
  });

  it("returns the same reference for a whitespace-only query", () => {
    expect(filterWebhooksByText(rows, "   ")).toBe(rows);
  });

  it("filters by URL (case-insensitive)", () => {
    expect(filterWebhooksByText(rows, "RECEIVER.EXAMPLE")).toEqual([catchall]);
  });

  it("filters by URL substring shared by both rows", () => {
    expect(filterWebhooksByText(rows, "example.com")).toEqual([catchall, filtered]);
  });

  it("filters by id", () => {
    expect(filterWebhooksByText(rows, "wh-aaa")).toEqual([filtered]);
  });

  it("filters by event name substring", () => {
    expect(filterWebhooksByText(rows, "session.start")).toEqual([filtered]);
  });

  // Dedicated sentinel test: the catchall webhook's URL and ID contain no "all" substring, so
  // only the sentinel branch `(w.events.length === 0 && q === "all")` can produce this match.
  // Removing the sentinel clause from filterWebhooksByText causes this test to fail.
  it("matches query 'all' via sentinel branch for a webhook with an empty events array", () => {
    expect(filterWebhooksByText([catchall], "all")).toEqual([catchall]);
  });

  it("does not match query 'all' for a webhook that has specific events", () => {
    expect(filterWebhooksByText([filtered], "all")).toEqual([]);
  });

  it("does not match prefix 'al' via sentinel (sentinel requires exact 'all')", () => {
    // catchall URL and ID have no "al" substring — only the sentinel could match, and q !== "all"
    expect(filterWebhooksByText([catchall], "al")).toEqual([]);
  });

  it("does not match created_at date strings (excluded from search)", () => {
    expect(filterWebhooksByText(rows, "2026-09-27")).toEqual([]);
  });

  it("returns empty for a no-match query", () => {
    expect(filterWebhooksByText(rows, "zzz-no-match")).toEqual([]);
  });

  it("asymmetric fixture: url match does not accidentally match id-only row", () => {
    const urlOnly = wh({ id: "wh-unique-id", url: "https://target.example.com/hook" });
    const other = wh({ id: "wh-other", url: "https://other.example.com/hook" });
    expect(filterWebhooksByText([urlOnly, other], "target")).toEqual([urlOnly]);
  });
});

// ---------------------------------------------------------------------------
// buildActiveSessionMap + formatSessionSince
// ---------------------------------------------------------------------------

function liveSession(deviceId: string, startedAt: string): SessionRecord {
  return {
    id: `s-${deviceId}`,
    tenant_id: "t-1",
    machine_id: "pk-1",
    technician_id: "u-1",
    started_at: startedAt,
    consent_policy: "none",
    granted_caps: null,
    machine_group_id: "g-1",
    machine_device_id: deviceId,
    machine_name: "M",
    machine_alias: "",
    note: "",
  };
}

describe("buildActiveSessionMap", () => {
  it("returns an empty map for no sessions", () => {
    expect(buildActiveSessionMap([]).size).toBe(0);
  });

  it("maps a single live session by device_id", () => {
    const s = liveSession("dev-A", "2026-09-26T10:00:00Z");
    const m = buildActiveSessionMap([s]);
    expect(m.get("dev-A")).toBe(s);
    expect(m.size).toBe(1);
  });

  it("maps two live sessions for different devices", () => {
    const a = liveSession("dev-A", "2026-09-26T09:00:00Z");
    const b = liveSession("dev-B", "2026-09-26T10:00:00Z");
    const m = buildActiveSessionMap([a, b]);
    expect(m.get("dev-A")).toBe(a);
    expect(m.get("dev-B")).toBe(b);
  });

  it("excludes sessions that have ended_at set", () => {
    const ended: SessionRecord = { ...liveSession("dev-A", "2026-09-26T08:00:00Z"), ended_at: "2026-09-26T09:00:00Z" };
    const m = buildActiveSessionMap([ended]);
    expect(m.has("dev-A")).toBe(false);
  });

  it("excludes ended sessions while keeping live ones for the same device", () => {
    const ended: SessionRecord = { ...liveSession("dev-A", "2026-09-26T08:00:00Z"), ended_at: "2026-09-26T09:00:00Z" };
    const live = liveSession("dev-A", "2026-09-26T10:00:00Z");
    const m = buildActiveSessionMap([ended, live]);
    expect(m.get("dev-A")).toBe(live);
  });

  it("excludes an ended session on one device while keeping a live session on another (size guard)", () => {
    // Mutation guard: a function that drops the ended_at filter entirely would produce size=2,
    // catching a "keep everything" mutation that the same-device tests above cannot detect.
    const ended: SessionRecord = { ...liveSession("dev-A", "2026-09-26T08:00:00Z"), ended_at: "2026-09-26T09:00:00Z" };
    const live = liveSession("dev-B", "2026-09-26T10:00:00Z");
    const m = buildActiveSessionMap([ended, live]);
    expect(m.size).toBe(1);
    expect(m.has("dev-A")).toBe(false);
    expect(m.get("dev-B")).toBe(live);
  });
});

describe("formatSessionSince", () => {
  const now = new Date("2026-09-26T15:30:00Z");

  it("returns HH:MM when session started today (UTC)", () => {
    expect(formatSessionSince("2026-09-26T09:05:00Z", now)).toBe("09:05");
  });

  it("pads single-digit hours and minutes", () => {
    expect(formatSessionSince("2026-09-26T01:03:00Z", now)).toBe("01:03");
  });

  it("returns Mon DD HH:MM for a session started yesterday", () => {
    expect(formatSessionSince("2026-09-25T14:20:00Z", now)).toBe("Sep 25 14:20");
  });

  it("returns Mon DD HH:MM for a session started in a different month", () => {
    expect(formatSessionSince("2026-08-01T00:00:00Z", now)).toBe("Aug 1 00:00");
  });

  it("returns the raw string for an unparseable timestamp", () => {
    expect(formatSessionSince("not-a-date", now)).toBe("not-a-date");
  });

  it("shows Mon DD HH:MM when the session was one second before midnight and now is one second after (day boundary)", () => {
    // Mutation guard: a local-date comparison would pass on a UTC machine but fail in other timezones.
    const justAfterMidnight = new Date("2026-09-27T00:00:01Z");
    expect(formatSessionSince("2026-09-26T23:59:59Z", justAfterMidnight)).toBe("Sep 26 23:59");
  });

  it("shows HH:MM when session and now are both on the same UTC calendar day near midnight", () => {
    const nearMidnight = new Date("2026-09-26T23:59:59Z");
    expect(formatSessionSince("2026-09-26T00:00:01Z", nearMidnight)).toBe("00:00");
  });

  it("strips seconds — a session at HH:MM:SS shows as HH:MM only", () => {
    expect(formatSessionSince("2026-09-26T10:00:45Z", now)).toBe("10:00");
  });
});

// ---------------------------------------------------------------------------
// sessionBadgeTooltip — composed "Active since … UTC · <technician>" label
// ---------------------------------------------------------------------------

describe("sessionBadgeTooltip", () => {
  const users = [
    { id: "u1", email: "tech@acme.test" },
    { id: "u2", email: "" }, // empty email — should fall back to raw id
  ];
  const now = new Date("2026-09-26T15:00:00Z");

  function sessionStub(technicianId: string, startedAt: string): Pick<SessionRecord, "started_at" | "technician_id"> {
    return { started_at: startedAt, technician_id: technicianId };
  }

  it("shows 'Active since HH:MM UTC · email' for a same-day session with a known technician", () => {
    expect(sessionBadgeTooltip(sessionStub("u1", "2026-09-26T10:00:00Z"), users, now)).toBe(
      "Active since 10:00 UTC · tech@acme.test",
    );
  });

  it("shows 'Active since Mon DD HH:MM UTC · email' for a cross-day session", () => {
    expect(sessionBadgeTooltip(sessionStub("u1", "2026-09-25T14:20:00Z"), users, now)).toBe(
      "Active since Sep 25 14:20 UTC · tech@acme.test",
    );
  });

  it("falls back to raw technician_id when users list is empty (403 / not loaded)", () => {
    expect(sessionBadgeTooltip(sessionStub("u-unknown", "2026-09-26T09:00:00Z"), [], now)).toBe(
      "Active since 09:00 UTC · u-unknown",
    );
  });

  it("falls back to raw technician_id when the user has left (id not in list)", () => {
    expect(sessionBadgeTooltip(sessionStub("u-gone", "2026-09-26T09:00:00Z"), users, now)).toBe(
      "Active since 09:00 UTC · u-gone",
    );
  });

  it("falls back to raw technician_id when the matched user has an empty email", () => {
    expect(sessionBadgeTooltip(sessionStub("u2", "2026-09-26T09:00:00Z"), users, now)).toBe(
      "Active since 09:00 UTC · u2",
    );
  });

  it("omitted now defaults to the real clock — result has the expected shape", () => {
    // Mutation guard for the `now ?? new Date()` default: a mutation that broke the default
    // (e.g. `?? null`) would throw or produce a broken string rather than a well-formed tooltip.
    const result = sessionBadgeTooltip(sessionStub("u1", new Date().toISOString()), users);
    expect(result).toMatch(/^Active since .+ UTC · tech@acme\.test$/);
  });
});

// ---------------------------------------------------------------------------
// endSessionButtonProps — label and disabled flag for the "End session" button
// ---------------------------------------------------------------------------

describe("endSessionButtonProps", () => {
  it("returns 'End session' and enabled when no end is in flight", () => {
    const { label, disabled } = endSessionButtonProps("s-1", null);
    expect(label).toBe("End session");
    expect(disabled).toBe(false);
  });

  it("returns 'Ending…' and disabled when THIS session's end is in flight", () => {
    const { label, disabled } = endSessionButtonProps("s-1", "s-1");
    expect(label).toBe("Ending\u2026");
    expect(disabled).toBe(true);
  });

  it("returns 'End session' and disabled when a DIFFERENT session's end is in flight", () => {
    // Mutation guard: if `disabled` were `pendingId === sessionId` (wrong) this case would pass
    // as enabled, revealing the mutation.
    const { label, disabled } = endSessionButtonProps("s-1", "s-2");
    expect(label).toBe("End session");
    expect(disabled).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// formatDeliveryTime
// ---------------------------------------------------------------------------

describe("formatDeliveryTime", () => {
  const NOW = new Date("2026-09-27T15:30:00Z");

  it("shows HH:MM:SS UTC when the delivery was today", () => {
    expect(formatDeliveryTime("2026-09-27T09:05:42Z", NOW)).toBe("09:05:42 UTC");
  });

  it("shows full date+time when the delivery was on a different day", () => {
    expect(formatDeliveryTime("2026-09-26T23:59:59Z", NOW)).toBe("2026-09-26 23:59:59 UTC");
  });

  it("zero-pads all components", () => {
    // Mutation guard: if pad() were omitted, '09:05:42' would become '9:5:42'.
    expect(formatDeliveryTime("2026-09-27T09:05:02Z", NOW)).toBe("09:05:02 UTC");
  });

  it("shows date+time at UTC midnight boundary (different day from afternoon now)", () => {
    expect(formatDeliveryTime("2026-09-27T00:00:00Z", new Date("2026-09-28T00:00:01Z"))).toBe(
      "2026-09-27 00:00:00 UTC",
    );
  });

  it("returns the raw string when the input is not a valid date", () => {
    expect(formatDeliveryTime("not-a-date", NOW)).toBe("not-a-date");
  });

  it("defaults now to the current date (smoke test: no throw on omitted second arg)", () => {
    // Cannot assert the exact output without a fixed clock, but it must not throw and
    // must return a non-empty string. Mutation guard: if the default param were removed, tsc would
    // error when the second argument is omitted.
    expect(formatDeliveryTime("2026-09-27T12:00:00Z")).toMatch(/UTC$/);
  });
});

describe("isAgentVersionOutdated (docs/01 §6)", () => {
  const CURRENT = "0.0.2+new1234";
  const OLDER = "0.0.1+old5678";

  // M1 guard: no publishedVersion → nothing is outdated
  it("returns false when publishedVersion is null (not configured)", () => {
    expect(isAgentVersionOutdated(OLDER, null)).toBe(false);
  });

  it("returns false when publishedVersion is undefined (not configured)", () => {
    expect(isAgentVersionOutdated(OLDER, undefined)).toBe(false);
  });

  it("returns false when publishedVersion is empty string (not configured)", () => {
    expect(isAgentVersionOutdated(OLDER, "")).toBe(false);
  });

  // M2 guard: no machineVersion → unknown, not outdated
  it("returns false when machineVersion is undefined (never reported)", () => {
    expect(isAgentVersionOutdated(undefined, CURRENT)).toBe(false);
  });

  it("returns false when machineVersion is empty string (never reported)", () => {
    expect(isAgentVersionOutdated("", CURRENT)).toBe(false);
  });

  // M3 guard: same version → current
  it("returns false when versions match", () => {
    expect(isAgentVersionOutdated(CURRENT, CURRENT)).toBe(false);
  });

  // The positive case — a machine with an older build
  it("returns true when machineVersion differs from publishedVersion", () => {
    expect(isAgentVersionOutdated(OLDER, CURRENT)).toBe(true);
  });

  // Symmetric: a newer machine version (e.g. a pre-production build) is also "different"
  it("returns true when machineVersion is newer than publishedVersion", () => {
    expect(isAgentVersionOutdated(CURRENT, OLDER)).toBe(true);
  });
});

describe("endSessionConfirmText (menu redesign wave 9)", () => {
  it("names the machine and who is disconnected, and what it does not do", () => {
    const t = endSessionConfirmText("OFFICE-01", "ed@example.test");
    expect(t).toBe("End the session on OFFICE-01? ed@example.test is disconnected at once. The computer keeps running and nothing on it is closed.");
  });
  it("never shows a bare id in place of a person", () => {
    expect(endSessionConfirmText("OFFICE-01", "aaaaaaaa-1111-4111-8111-111111111111")).toContain("The technician in it is disconnected");
    expect(endSessionConfirmText("OFFICE-01", "")).toContain("The technician in it is disconnected");
  });
});
