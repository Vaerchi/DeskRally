/**
 * Platform area (platform-operator design, slice C): the tenants of this DeskRally installation, as the
 * platform operator sees them, with provisioning and suspend/resume.
 *
 * Every decision is the server's (migration 0055's cp_platform_* functions); this panel only asks in
 * the right order:
 *   - GET /platform/me says whether the caller is an operator and whether the session's second factor
 *     is recent enough to read (`mfa_ok`, 12 h) and to change anything (`mfa_fresh`, 15 min);
 *   - when it is not, the panel asks for an authenticator code (POST /auth/step-up) and then carries on
 *     with what the operator was doing;
 *   - suspend and resume need the target's slug typed exactly and a reason, and the dialog says what a
 *     suspension does and does not stop (agents without session leases keep running sessions);
 *   - a tenant row also opens its hostnames and its public join-page branding review (docs/66 2k); their
 *     changes run through the same single-flight operation, so they get the same second-factor check.
 *
 * A 403 from a change re-checks /platform/me: if the 15-minute window lapsed while the form was open,
 * the step-up is asked for and the change is retried once after it.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { formatIsoUtc } from "../backstage/panels";
import { ConsoleApiError } from "../lib/console_api";
import type { ConsoleApi, DeploymentMode, PlatformTenant, PlatformWhoami } from "../lib/console_api";
import { DEPLOYMENT_MODES, submitCreateTenant } from "../lib/console_panels";
import { createLatestWins } from "../lib/latest_wins";
import { tenantsToCsv } from "../lib/report_csv";
import { saveBytesAsFile } from "./FileTransferPanel";
import { PlatformBrandingReview } from "./PlatformBrandingReview";
import { PlatformHostnames } from "./PlatformHostnames";
import { PlatformReach } from "./PlatformReach";

export interface PlatformPanelProps {
  api: ConsoleApi;
}

/** The one change this panel runs at a time (create, or suspend/resume). Single-flight: while one exists
 *  every other change is refused synchronously (`opRef`) and its controls are disabled. `run` throws on
 *  refusal; `fail` reports a refusal in the change's own form.
 *
 *  `phase` is the synchronous state machine every path checks before acting:
 *    checking  -> its own /platform/me read is in flight;
 *    awaiting  -> waiting for an authenticator code (the prompt is open);
 *    running   -> the request was sent.
 *  Only `check` sends (via `attempt`, which moves to `running` before the first await), a verification
 *  only re-checks an `awaiting` operation, and `retried` allows one resend after a 403 that found the
 *  15-minute window lapsed, so a change is sent at most twice.
 *
 *  While an operation exists the panel is FROZEN: the create fields, the confirmation fields and every
 *  row action are disabled (and openConfirm refuses), so what is on screen is always what is being sent.
 *  `run` is handed `live()`, true only while the panel is mounted and this is still its operation; it
 *  must check it after its request returns, before any UI effect. */
interface Operation {
  id: number;
  kind: "create" | "confirm" | "detail";
  run: (live: () => boolean) => Promise<void>;
  fail: (e: unknown) => void;
  phase: "checking" | "awaiting" | "running";
  retried: boolean;
}

interface Confirm {
  tenant: PlatformTenant;
  suspend: boolean;
}

/** The tenant whose hostnames or branding review is open under the create form (one at a time). */
interface Detail {
  tenant: PlatformTenant;
  view: "hostnames" | "branding";
}

export function filterPlatformTenants(rows: readonly PlatformTenant[], query: string): readonly PlatformTenant[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(
    (t) => t.slug.toLowerCase().includes(q) || t.name.toLowerCase().includes(q) || t.id.toLowerCase().includes(q),
  );
}

const reasonValid = (r: string) => r.trim().length > 0 && r.trim().length <= 500;

export function PlatformPanel({ api }: PlatformPanelProps) {
  const [who, setWho] = useState<PlatformWhoami | null>(null);
  const [rows, setRows] = useState<readonly PlatformTenant[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [textQuery, setTextQuery] = useState("");
  // Tenants (the change flows below) or Reach (read-only request counts, docs/68). Switching never touches an operation.
  const [view, setView] = useState<"tenants" | "reach">("tenants");

  // The running operation. The ref is the synchronous truth (guards and stale-completion checks); the
  // state mirrors it for rendering, so busy labels can never outlive the operation.
  const opRef = useRef<Operation | null>(null);
  const opSeq = useRef(0);
  const [op, setOpState] = useState<{ id: number; kind: Operation["kind"] } | null>(null);
  const setOp = useCallback((o: Operation | null) => {
    opRef.current = o;
    setOpState(o ? { id: o.id, kind: o.kind } : null);
  }, []);
  const creating = op?.kind === "create";
  const changing = op?.kind === "confirm";

  // Step-up prompt. `stepUpGen` identifies the prompt a verification belongs to: Cancel (and unmount)
  // bump it, so a verification still in flight from a cancelled prompt is ignored when it lands and
  // cannot run a change queued afterwards. `verifyingRef` is the synchronous single-flight guard.
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [code, setCode] = useState("");
  const [stepUpError, setStepUpError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const stepUpGen = useRef(0);
  const verifyingRef = useRef(false);
  const verifications = useRef(0); // successful verifications so far (see check())

  // Create form.
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [mode, setMode] = useState<DeploymentMode>("saas");
  const [slugTaken, setSlugTaken] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Suspend / resume confirmation.
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [typedSlug, setTypedSlug] = useState("");
  const [reason, setReason] = useState("");
  const [confirmError, setConfirmError] = useState<string | null>(null);

  // Hostnames / branding review of one tenant.
  const [detail, setDetail] = useState<Detail | null>(null);

  // Latest-wins: only the newest listing may touch rows/error/busy. On unmount, every outstanding
  // listing, verification and operation is orphaned, and `mounted` stops any continuation from starting
  // new work (refresh, completion effects).
  const listGuard = useRef(createLatestWins());
  const mounted = useRef(true);
  useEffect(() => {
    const guard = listGuard.current;
    mounted.current = true;
    return () => {
      mounted.current = false;
      guard.invalidate();
      stepUpGen.current++;
      opRef.current = null;
    };
  }, []);

  // Listing access epoch: bumped whenever an applied /platform/me answer takes listing access away (not
  // an operator, or no second factor within 12 h). A listing requested under an older epoch is
  // discarded, results and failures alike, and the rows are cleared when access goes.
  const accessEpoch = useRef(0);

  /** GET /platform/me. `ok: false` is a FAILED lookup (network, 5xx), which is not the same as a
   *  successful answer saying "not an operator". Pure: it writes no state, because its answer may be
   *  stale by the time it lands (a superseded listing, an abandoned operation). Each caller first checks
   *  that it is still current, then applies the answer with `acceptWho`. */
  const whoSeq = useRef(0); // numbers every lookup at the moment it is SENT
  const whoApplied = useRef(0); // the number of the newest answer applied
  const whoRef = useRef<PlatformWhoami | null>(null); // that answer
  const whoAppliedVerified = useRef(0); // successful verifications when that answer's lookup was SENT
  const loadWho = useCallback(async (): Promise<{ ok: true; who: PlatformWhoami; seq: number } | { ok: false }> => {
    const seq = ++whoSeq.current;
    try {
      return { ok: true, who: await api.platformWhoami(), seq };
    } catch {
      return { ok: false };
    }
  }, [api]);

  const openStepUp = useCallback(() => {
    setStepUpError(null);
    setStepUpOpen(true);
  }, []);

  /** Close the prompt and drop an operation that has NOT been sent (checking or awaiting a code); a
   *  verification still in flight is orphaned. A RUNNING operation is never dropped: its request is out,
   *  and until its own completion ends it no other change can start, so nothing it later writes can
   *  land on a newer change's form. */
  const abandon = useCallback(() => {
    stepUpGen.current++;
    verifyingRef.current = false;
    setVerifying(false);
    setStepUpOpen(false);
    setCode("");
    setStepUpError(null);
    if (opRef.current && opRef.current.phase !== "running") setOp(null);
  }, [setOp]);

  /** Apply a /platform/me answer from a caller that is still current, and return what the caller must
   *  decide by: the answer itself, or — when a lookup SENT LATER has already been applied, so this one is
   *  stale — that newer answer, unchanged. A non-operator answer renders the non-operator notice, which
   *  has no prompt or Cancel, so it first abandons whatever is waiting. */
  const acceptWho = useCallback(
    (r: { who: PlatformWhoami; seq: number }, verifiedAtSend: number): PlatformWhoami => {
      if (r.seq < whoApplied.current && whoRef.current) return whoRef.current;
      whoApplied.current = r.seq;
      whoRef.current = r.who;
      whoAppliedVerified.current = verifiedAtSend;
      if (!r.who.operator) abandon();
      if (!r.who.operator || !r.who.mfa_ok) {
        accessEpoch.current++;
        setRows([]);
        // The per-tenant screens are read access too: unmounting one orphans its outstanding reads
        // (each guards on its own mounted flag), so nothing can repopulate it after the grant went.
        setDetail(null);
      }
      setWho(r.who);
      return r.who;
    },
    [abandon],
  );

  /** The ONLY way a caller obtains an access answer. Repeats the lookup while its answer is an MFA
   *  negative (operator, but no second factor within 12 h or 15 min) that a successful verification
   *  overtook: such an answer predates the verification and is discarded unapplied. Between lookups and
   *  before applying, `current()` (the caller's own identity / latest-listing check) must still hold;
   *  otherwise "gone" and nothing is applied. Each repeat needs another successful verification, so the
   *  loop is bounded by the operator. */
  const readWho = useCallback(
    async (current: () => boolean): Promise<{ kind: "ok"; who: PlatformWhoami } | { kind: "failed" } | { kind: "gone" }> => {
      for (;;) {
        const verifiedBefore = verifications.current;
        const r = await loadWho();
        if (!mounted.current || !current()) return { kind: "gone" };
        if (!r.ok) return { kind: "failed" };
        // The answer that will DECIDE: this one, or a newer already-applied one if this is older. The
        // overtaking rule applies to whichever it is, with the verification count of ITS lookup.
        const newer = !(r.seq < whoApplied.current && whoRef.current);
        const deciding = newer ? r.who : whoRef.current!;
        const decidingVerified = newer ? verifiedBefore : whoAppliedVerified.current;
        const mfaNegative = deciding.operator && !(deciding.mfa_ok && deciding.mfa_fresh);
        if (mfaNegative && verifications.current !== decidingVerified) continue; // nothing applied
        return { kind: "ok", who: acceptWho(r, verifiedBefore) };
      }
    },
    [acceptWho, loadWho],
  );

  const refresh = useCallback(async () => {
    if (!mounted.current) return;
    const token = listGuard.current.begin();
    // A prompt this refresh would open is only opened if no Cancel or verification happened since it
    // began: a refresh sent before Cancel must not reopen the cancelled prompt.
    const promptGen = stepUpGen.current;
    let epoch = -1;
    setBusy(true);
    setError(null);
    try {
      const r = await readWho(() => listGuard.current.isCurrent(token));
      if (r.kind === "gone") return;
      if (r.kind === "failed") {
        setError("Could not check your platform access. Try again.");
        return;
      }
      const w = r.who;
      if (!w.operator) {
        setRows([]);
        return;
      }
      if (!w.mfa_ok) {
        // The listing itself needs a second factor from the last 12 hours. A change waiting on the
        // prompt keeps waiting, and a running one keeps running: refresh never touches the operation.
        setRows([]);
        if (stepUpGen.current === promptGen) openStepUp();
        return;
      }
      epoch = accessEpoch.current;
      const list = await api.listPlatformTenants();
      if (!listGuard.current.isCurrent(token) || accessEpoch.current !== epoch) return;
      setRows(list);
    } catch (e) {
      if (!listGuard.current.isCurrent(token) || accessEpoch.current !== epoch) return;
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (listGuard.current.isCurrent(token)) setBusy(false);
    }
  }, [api, openStepUp, readWho]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  /** Send `o`. Only from `checking` (after a fresh /platform/me) or `awaiting` (after a 403 found the
   *  window lapsed and a code was given): the transition to `running` is synchronous, so a second
   *  caller sees `running` and does nothing. A 403 that turns out to be a lapsed window asks for a code
   *  once per operation; any other refusal, or a second one, is reported and ends the operation. */
  // attempt() retries itself at most once (see below); the ref lets the callback reach its own latest
  // version without listing itself as a dependency.
  const attemptRef = useRef<(o: Operation) => Promise<void>>(async () => {});
  const attempt = useCallback(
    async (o: Operation) => {
      if (o.phase === "running" || opRef.current !== o) return;
      o.phase = "running";
      const verifiedAtSend = verifications.current;
      try {
        await o.run(() => mounted.current && opRef.current === o);
        if (opRef.current === o) setOp(null);
      } catch (e) {
        if (opRef.current !== o) return; // cancelled or unmounted meanwhile
        if (e instanceof ConsoleApiError && e.status === 403 && !o.retried) {
          // Was the refusal the 15-minute window lapsing? As in check(): a "not fresh" answer to a
          // lookup that a successful verification overtook is replaced by a new lookup.
          const again = await readWho(() => opRef.current === o);
          if (again.kind === "gone") return;
          const w = again.kind === "ok" ? again.who : null;
          if (!w || !w.operator) {
            o.fail(e);
            if (opRef.current === o) setOp(null);
            return;
          }
          if (!w.mfa_fresh) {
            o.retried = true;
            o.phase = "awaiting";
            openStepUp();
            return;
          }
          if (verifications.current !== verifiedAtSend) {
            // A verification succeeded after this request went out and the window is fresh now: the
            // 403 was the lapse it cured. Use the one retry (phase awaiting, so attempt() may send).
            o.retried = true;
            o.phase = "awaiting";
            await attemptRef.current(o);
            return;
          }
        }
        o.fail(e);
        setOp(null);
      }
    },
    [openStepUp, readWho, setOp],
  );
  attemptRef.current = attempt;

  /** Check freshness for `o` (phase `checking`), then send it or wait for a code. A failed lookup or a
   *  non-operator answer ends the operation with an error where the operator is looking. */
  const check = useCallback(
    async (o: Operation) => {
      o.phase = "checking";
      const r = await readWho(() => opRef.current === o && o.phase === "checking");
      if (r.kind === "gone") return;
      if (r.kind === "failed") {
        o.fail(new Error("Could not check your platform access. Try again."));
        setOp(null);
        return;
      }
      const w = r.who; // a non-operator answer has already abandoned the operation and prompt
      if (!w.operator) {
        o.fail(new Error("This account is no longer a platform operator."));
        abandon(); // also when the deciding answer was an earlier-applied, newer one
        return;
      }
      if (!w.mfa_fresh) {
        o.phase = "awaiting";
        openStepUp();
        return;
      }
      await attempt(o);
    },
    [abandon, attempt, openStepUp, readWho, setOp],
  );

  /** Start a change. Refused (returns false) while another is checking, waiting for a code or running. */
  const startOperation = useCallback(
    (kind: Operation["kind"], run: Operation["run"], fail: Operation["fail"]): boolean => {
      if (opRef.current) return false;
      const o: Operation = { id: ++opSeq.current, kind, run, fail, phase: "checking", retried: false };
      setOp(o);
      void check(o);
      return true;
    },
    [check, setOp],
  );

  const handleStepUp = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (verifyingRef.current) return;
      verifyingRef.current = true;
      const gen = stepUpGen.current;
      setVerifying(true);
      setStepUpError(null);
      try {
        await api.stepUp(code.trim());
      } catch (err) {
        if (gen !== stepUpGen.current) return; // this prompt was cancelled
        verifyingRef.current = false;
        setVerifying(false);
        setStepUpError(
          err instanceof ConsoleApiError && err.kind === "conflict"
            ? "Your session ended or your second factor changed. Sign in again."
            : "That code was not accepted.",
        );
        return;
      }
      if (gen !== stepUpGen.current) return; // cancelled while verifying: apply nothing, run nothing
      const mine = ++stepUpGen.current;
      verifications.current++;
      verifyingRef.current = false;
      setVerifying(false);
      setCode("");
      setStepUpOpen(false);
      // A verification never sends anything by itself. An operation WAITING for a code is re-checked
      // (a fresh /platform/me decides); one still checking or already running is left alone.
      const o = opRef.current;
      if (o && o.phase === "awaiting") await check(o);
      // Cancelled (or unmounted) while that check ran: this continuation is over.
      if (!mounted.current || stepUpGen.current !== mine) return;
      void refresh();
    },
    [api, check, code, refresh],
  );

  const cancelStepUp = abandon;

  const handleCreate = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      const form = { slug, name, mode };
      setSlugTaken(false);
      setFormError(null);
      startOperation(
        "create",
        async (live) => {
          const outcome = await submitCreateTenant(api, form);
          if (!outcome.ok) {
            // submitCreateTenant folds errors into its outcome; rethrow a 403 so the operation can
            // tell a lapsed second factor from any other refusal.
            if (outcome.status === 403) throw new ConsoleApiError(403, outcome.message);
            if (!live()) return;
            setSlugTaken(outcome.slugTaken);
            setFormError(outcome.slugTaken ? null : outcome.message);
            return;
          }
          if (!live()) return;
          setSlug("");
          setName("");
          setMode("saas");
          void refresh();
        },
        (err) => setFormError(err instanceof Error ? err.message : String(err)),
      );
    },
    [api, slug, name, mode, refresh, startOperation],
  );

  const openConfirm = useCallback((tenant: PlatformTenant, suspend: boolean) => {
    if (opRef.current) return; // frozen while a change is in progress
    setConfirm({ tenant, suspend });
    setTypedSlug("");
    setReason("");
    setConfirmError(null);
  }, []);

  const handleConfirm = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      if (!confirm) return;
      const { tenant, suspend } = confirm;
      // Enforced here, not only by the disabled button.
      if (typedSlug !== tenant.slug) {
        setConfirmError("Type the tenant's slug exactly to confirm.");
        return;
      }
      if (!reasonValid(reason)) {
        setConfirmError("Give a reason (at most 500 characters).");
        return;
      }
      const typed = typedSlug;
      const why = reason.trim();
      setConfirmError(null);
      startOperation(
        "confirm",
        async (live) => {
          await api.setTenantSuspended(tenant.id, suspend, typed, why);
          if (!live()) return;
          setConfirm(null);
          void refresh();
        },
        (err) => setConfirmError(err instanceof Error ? err.message : String(err)),
      );
    },
    [api, confirm, typedSlug, reason, refresh, startOperation],
  );

  /** The hand-off to the hostname and branding screens: their changes are operations of this panel. */
  const startDetailChange = useCallback(
    (run: Operation["run"], fail: Operation["fail"]) => startOperation("detail", run, fail),
    [startOperation],
  );

  const filteredRows = useMemo(() => filterPlatformTenants(rows, textQuery), [rows, textQuery]);

  const handleExport = useCallback(() => {
    const asTenants = filteredRows.map((t) => ({
      id: t.id,
      slug: t.slug,
      name: t.name,
      deployment_mode: t.deployment_mode,
      created_at: t.created_at,
      disabled: Boolean(t.disabled_at),
    }));
    saveBytesAsFile("tenants.csv", new TextEncoder().encode(tenantsToCsv(asTenants)));
  }, [filteredRows]);

  if (who && !who.operator) {
    return (
      <div className="panel panel--platform">
        <p className="panel__empty" data-testid="platform-not-operator">
          The Platform area is for the operator of this DeskRally installation.
        </p>
      </div>
    );
  }

  // Detail screens render only under a CONFIRMED read grant (operator and a second factor within 12 h).
  const detailAllowed = who !== null && who.operator && who.mfa_ok;
  const confirmMatches = confirm !== null && typedSlug === confirm.tenant.slug;
  const reasonOk = reasonValid(reason);

  return (
    <div className="panel panel--platform">
      <div className="panel__toolbar" role="tablist" aria-label="Platform view">
        <button className="panel__action" role="tab" aria-selected={view === "tenants"} onClick={() => setView("tenants")} data-testid="platform-tab-tenants">
          Tenants
        </button>
        <button
          className="panel__action"
          role="tab"
          aria-selected={view === "reach"}
          onClick={() => setView("reach")}
          disabled={op !== null || stepUpOpen}
          title={op !== null || stepUpOpen ? "Finish the change or the verification in progress first." : undefined}
          data-testid="platform-tab-reach"
        >
          Reach
        </button>
      </div>
      {/* Any OPERATOR, not only one with a fresh factor: the tab owns its 403 handling and asks for the code itself,
          so a lapsed factor shows its own prompt instead of an empty pane. The server is the gate either way. */}
      {view === "reach" && who !== null && who.operator && <PlatformReach api={api} />}
      {/* Hidden, not unmounted, so a tenant change in progress keeps its state across a tab switch. */}
      <div hidden={view !== "tenants"}>
      {stepUpOpen && (
        <form className="panel__form" onSubmit={(e) => void handleStepUp(e)} aria-label="Verify it's you" data-testid="platform-stepup">
          <span className="panel__toolbar-title">Verify it's you</span>
          <span>
            {op
              ? "Changing tenants needs an authenticator code from the last 15 minutes."
              : "Viewing tenants needs an authenticator code from the last 12 hours."}
          </span>
          <label className="panel__toolbar-field">
            Code
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              data-testid="platform-stepup-code"
            />
          </label>
          <button className="panel__action" type="submit" disabled={verifying || code.trim() === ""}>
            {verifying ? "Verifying…" : "Verify"}
          </button>
          <button className="panel__action" type="button" onClick={cancelStepUp}>
            Cancel
          </button>
          {stepUpError && (
            <span className="panel__toolbar-error" role="alert" data-testid="platform-stepup-error">
              {stepUpError}
            </span>
          )}
        </form>
      )}

      {confirm && (
        <form
          className="panel__form"
          onSubmit={handleConfirm}
          aria-label={confirm.suspend ? "Suspend tenant" : "Resume tenant"}
          data-testid="platform-confirm"
        >
          <span className="panel__toolbar-title">
            {confirm.suspend ? "Suspend" : "Resume"} {confirm.tenant.name} ({confirm.tenant.slug})
          </span>
          {confirm.suspend ? (
            <span data-testid="platform-confirm-effect">
              Its {confirm.tenant.user_count} user(s) can no longer sign in or start sessions, and its
              agents go offline. Sessions already running end within about a minute.
              {confirm.tenant.unleased_machines && (
                <strong data-testid="platform-unleased-warning">
                  {" "}
                  Some of its machines run agents that do not enforce session leases: sessions already
                  running on those may continue until they end.
                </strong>
              )}
            </span>
          ) : (
            <span data-testid="platform-confirm-effect">Its users can sign in and start sessions again.</span>
          )}
          <label className="panel__toolbar-field">
            Type the slug to confirm
            <input
              value={typedSlug}
              onChange={(e) => setTypedSlug(e.target.value)}
              placeholder={confirm.tenant.slug}
              autoComplete="off"
              spellCheck={false}
              disabled={op !== null}
              data-testid="platform-confirm-slug"
            />
          </label>
          <label className="panel__toolbar-field">
            Reason
            <input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={500}
              disabled={op !== null}
              data-testid="platform-confirm-reason"
            />
          </label>
          <button
            className="panel__action"
            type="submit"
            disabled={op !== null || !confirmMatches || !reasonOk}
            data-testid="platform-confirm-submit"
          >
            {changing ? "Working…" : confirm.suspend ? "Suspend" : "Resume"}
          </button>
          <button className="panel__action" type="button" onClick={() => setConfirm(null)} disabled={changing}>
            Cancel
          </button>
          {confirmError && (
            <span className="panel__toolbar-error" role="alert" data-testid="platform-confirm-error">
              {confirmError}
            </span>
          )}
        </form>
      )}

      {detail && detailAllowed && detail.view === "hostnames" && (
        <PlatformHostnames
          key={`h-${detail.tenant.id}`}
          api={api}
          tenant={detail.tenant}
          frozen={op !== null}
          start={startDetailChange}
          onClose={() => setDetail(null)}
        />
      )}
      {detail && detailAllowed && detail.view === "branding" && (
        <PlatformBrandingReview
          key={`b-${detail.tenant.id}`}
          api={api}
          tenant={detail.tenant}
          frozen={op !== null}
          start={startDetailChange}
          onClose={() => setDetail(null)}
        />
      )}

      <form className="panel__form" onSubmit={handleCreate} aria-label="New tenant">
        <span className="panel__toolbar-title">New tenant</span>
        <label className="panel__toolbar-field">
          Slug
          <input
            value={slug}
            onChange={(e) => {
              setSlug(e.target.value);
              setSlugTaken(false);
            }}
            placeholder="acme"
            aria-invalid={slugTaken}
            disabled={op !== null}
            data-testid="tenant-slug"
          />
        </label>
        {slugTaken && (
          <span className="panel__inline-error" role="alert" data-testid="tenant-slug-taken">
            slug taken
          </span>
        )}
        <label className="panel__toolbar-field">
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corp" disabled={op !== null} data-testid="tenant-name" />
        </label>
        <label className="panel__toolbar-field">
          Mode
          <select value={mode} onChange={(e) => setMode(e.target.value as DeploymentMode)} aria-label="Deployment mode" disabled={op !== null}>
            {DEPLOYMENT_MODES.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>
        <button className="panel__action" type="submit" disabled={op !== null}>
          {creating ? "Creating…" : "Create"}
        </button>
        {formError && (
          <span className="panel__toolbar-error" role="alert" data-testid="tenant-form-error">
            {formError}
          </span>
        )}
      </form>

      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Tenants</span>
        <input
          type="search"
          className="panel__search"
          placeholder="Search slug, name, ID…"
          aria-label="Search tenants"
          value={textQuery}
          onChange={(e) => setTextQuery(e.target.value)}
          data-testid="tenants-search"
        />
        <button className="panel__action" onClick={handleExport} disabled={filteredRows.length === 0} data-testid="tenants-export">
          Export CSV
        </button>
        <button className="panel__action" onClick={() => void refresh()} disabled={busy}>
          {busy ? "Loading…" : "Refresh"}
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="tenants-error">
            {error}
          </span>
        )}
      </div>
      <table className="panel__table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Slug</th>
            <th>Name</th>
            <th>Users</th>
            <th>Mode</th>
            <th>Created (UTC)</th>
            <th>ID</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {filteredRows.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={8}>
                {busy ? "Loading…" : textQuery.trim() ? "No tenants match this search." : "No tenants visible."}
              </td>
            </tr>
          )}
          {filteredRows.map((t) => (
            <tr key={t.id} data-testid={`platform-row-${t.slug}`}>
              <td>
                <span className="panel__badge" data-tone={t.disabled_at ? "bad" : "good"}>
                  {t.disabled_at ? "suspended" : "active"}
                </span>
              </td>
              <td className="panel__name">{t.slug}</td>
              <td>{t.name}</td>
              <td className="panel__mono">{t.user_count}</td>
              <td className="panel__mono">{t.deployment_mode}</td>
              <td className="panel__mono">{formatIsoUtc(t.created_at)}</td>
              <td className="panel__mono">{t.id}</td>
              <td>
                <button className="panel__action" onClick={() => openConfirm(t, !t.disabled_at)} disabled={op !== null}>
                  {t.disabled_at ? "Resume…" : "Suspend…"}
                </button>
                <button className="panel__action" onClick={() => setDetail({ tenant: t, view: "hostnames" })} disabled={op !== null} data-testid={`platform-hostnames-${t.slug}`}>
                  Hostnames…
                </button>
                <button className="panel__action" onClick={() => setDetail({ tenant: t, view: "branding" })} disabled={op !== null} data-testid={`platform-branding-${t.slug}`}>
                  Join page…
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
    </div>
  );
}
