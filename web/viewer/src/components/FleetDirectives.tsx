/**
 * Fleet agent directives, console side (docs/65): remove or reinstall an agent without opening a session.
 *
 * - {@link RemoveAgentDialog}: plain-words effect, typed machine name, authenticator-code step-up, then the
 *   15-minute cancel window with a live countdown and a Cancel button.
 * - {@link ForgetMachineDialog}: "Forget this machine..." (docs/65 sec. 8): the Owner's irreversible end of a retired machine
 *   whose removal will never be confirmed. Plain-words effect, typed machine name, authenticator-code step-up, then the call.
 * - {@link PendingRemovalsPanel}: every ACTIVE removal request this person may act on (GET /directives), with Approve (own
 *   step-up, never offered to the requester), Cancel where the server allows them, and "Forget this machine..." on a removal
 *   the agent never confirmed.
 * - {@link DirectivePolicyToggle}: "Require a second approver for agent removal" (Owner).
 *
 * The control plane enforces every rule (retired-only, step-up freshness, typed name, caps, approver != requester);
 * this file decides what to show and quotes the server's refusal in friendly words. Pure helpers live in
 * lib/fleet_directives.ts.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { ConsoleApiError, type ConsoleApi, type UserSummary } from "../lib/console_api";
import {
  DIRECTIVE_STATE_INFO,
  canApproveDirective,
  canCancelDirective,
  canForgetFromRemoval,
  cancelWindow,
  directiveUiState,
  forgetDialogCopy,
  forgetOutcomeNote,
  formatCountdown,
  friendlyDirectiveError,
  pollIntervalMs,
  removalConfirmationMatches,
  requestLifetimeLeftMs,
  staleNotice,
  type ActiveDirective,
  type AgentDirective,
  type DirectiveAction,
  type DirectivePolicy,
  type ForgetMachineResult,
  type MachineLike,
  type SelfUserId,
} from "../lib/fleet_directives";

/** A ticking clock for countdowns (one timer per mounted consumer). */
function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

/** An Error from the API as the friendly sentence for `action`. */
export function describeDirectiveError(e: unknown, action: DirectiveAction): string {
  if (e instanceof ConsoleApiError) return friendlyDirectiveError({ status: e.status, message: e.message, code: e.code }, action);
  return e instanceof Error ? e.message : String(e);
}

/** Prove the second factor (POST /auth/step-up), mapping its refusal to a sentence. Throws a plain Error. */
async function stepUp(api: ConsoleApi, code: string): Promise<void> {
  try {
    await api.stepUp(code.trim());
  } catch (e) {
    if (e instanceof ConsoleApiError && e.kind === "conflict") throw new Error("Your session ended or your second factor changed. Sign in again.");
    if (e instanceof ConsoleApiError && e.status === 429) throw new Error("Too many wrong codes. Wait a moment and try again.");
    throw new Error("That code was not accepted.");
  }
}

const machineLabel = (m: Pick<MachineLike, "name" | "alias">) => m.alias || m.name;

const TONE_STYLE: Record<string, string> = { ok: "#1a7f37", bad: "#b3261e", warn: "#9a6700", pending: "#0b5cad", neutral: "inherit" };

// ---------------------------------------------------------------------------------------------------------------
// The remove dialog
// ---------------------------------------------------------------------------------------------------------------

export interface RemoveAgentDialogProps {
  api: ConsoleApi;
  machine: MachineLike;
  onClose: () => void;
  /** A removal was requested (or cancelled): the host re-lists. */
  onChanged: (d: AgentDirective) => void;
}

export function RemoveAgentDialog({ api, machine, onClose, onChanged }: RemoveAgentDialogProps) {
  const [typed, setTyped] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [directive, setDirective] = useState<AgentDirective | null>(null);
  const now = useNow();
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  const matches = removalConfirmationMatches(typed, machine);
  const canSubmit = matches && /^\s*\d{6}\s*$/.test(code) && !busy;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    // The typed name is re-checked at submit time, so no path reaches the API without it.
    if (!removalConfirmationMatches(typed, machine) || busy) return;
    setBusy(true);
    setError(null);
    try {
      await stepUp(api, code);
      const d = await api.requestDirective(machine.id, "uninstall", typed.trim());
      if (!mounted.current) return;
      setDirective(d);
      setCode("");
      onChanged(d);
    } catch (err) {
      if (mounted.current) setError(err instanceof ConsoleApiError ? describeDirectiveError(err, "uninstall") : (err as Error).message);
    } finally {
      if (mounted.current) setBusy(false);
    }
  };

  // After the request, keep the row fresh: when the window ends (or every 15 s) read the directive again.
  const directiveId = directive?.id;
  const machineId = machine.id;
  useEffect(() => {
    if (!directiveId) return;
    const t = setInterval(() => {
      void api.listMachineDirectives(machineId).then((all) => {
        const fresh = all.find((x) => x.id === directiveId);
        if (fresh && mounted.current) setDirective(fresh);
      }).catch(() => {});
    }, 15000);
    return () => clearInterval(t);
  }, [api, machineId, directiveId]);

  const cancel = async () => {
    if (!directive || busy) return;
    setBusy(true);
    setError(null);
    try {
      const d = await api.cancelDirective(directive.id, "cancelled from the console");
      if (!mounted.current) return;
      setDirective(d);
      onChanged(d);
    } catch (err) {
      if (mounted.current) setError(describeDirectiveError(err, "cancel"));
    } finally {
      if (mounted.current) setBusy(false);
    }
  };

  const win = directive ? cancelWindow(directive, now) : null;
  const ui = directive ? directiveUiState(directive) : null;

  return (
    <div className="backstage__confirm-backdrop" role="dialog" aria-modal="true" aria-labelledby="remove-agent-title"
      data-testid="remove-agent-dialog" onKeyDown={(ev) => { if (ev.key === "Escape") { ev.stopPropagation(); onClose(); } }}>
      <div className="backstage__confirm" style={{ width: "min(560px, 95vw)", maxHeight: "90vh", overflow: "auto" }}>
        <h2 id="remove-agent-title">Remove the agent from {machineLabel(machine)}</h2>
        {!directive && (
          <form onSubmit={submit}>
            <p data-testid="remove-agent-effect">
              This uninstalls the DeskRally service and deletes its files and its identity from the machine. The machine can
              never reconnect with this identity; a new install would enroll as a new machine. Recordings stored only on the
              machine are deleted, unless central storage already holds them.
            </p>
            <p className="panel__hint">
              You get a 15-minute window to cancel before anything is sent. If your organisation requires a second approver, that
              person must approve first and the window starts again when they do.
            </p>
            <label className="panel__toolbar-field" style={{ display: "block" }}>
              Type the machine's name <strong>{machine.name}</strong>{machine.alias ? <> (or its friendly name <strong>{machine.alias}</strong>)</> : null} to confirm
              <input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false}
                data-testid="remove-agent-confirm-input" style={{ display: "block", width: "100%" }} />
            </label>
            <label className="panel__toolbar-field" style={{ display: "block", marginTop: 8 }}>
              Authenticator code (6 digits)
              <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code"
                data-testid="remove-agent-code" style={{ display: "block", width: "100%" }} />
            </label>
            {error && <p role="alert" className="panel__toolbar-error" data-testid="remove-agent-error">{error}</p>}
            <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
              <button type="submit" className="panel__action panel__action--danger" disabled={!canSubmit} data-testid="remove-agent-submit">
                {busy ? "Working…" : "Request removal"}
              </button>
              <button type="button" className="panel__action" onClick={onClose} data-testid="remove-agent-close">Close</button>
            </div>
          </form>
        )}
        {directive && ui && win && (
          <div data-testid="remove-agent-requested">
            <p data-testid="remove-agent-state">
              <strong>{DIRECTIVE_STATE_INFO[ui].label}.</strong> {DIRECTIVE_STATE_INFO[ui].explain}
            </p>
            {win.kind === "counting" && (
              <p data-testid="remove-agent-countdown" aria-live="off">
                Cancel window: <strong>{formatCountdown(win.msLeft)}</strong> left. At zero the removal is signed and sent when the agent next connects.
              </p>
            )}
            {win.kind === "ended" && <p data-testid="remove-agent-window-ended">The cancel window has ended; the removal is being issued.</p>}
            {win.kind === "needs_approval" && (
              <p data-testid="remove-agent-needs-approval">
                Waiting for a second approver (not you). The request lapses in {formatCountdown(requestLifetimeLeftMs(directive, now))} if nobody approves.
              </p>
            )}
            {error && <p role="alert" className="panel__toolbar-error" data-testid="remove-agent-error">{error}</p>}
            <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
              {canCancelDirective(directive) && (
                <button className="panel__action panel__action--danger" disabled={busy} onClick={() => void cancel()} data-testid="remove-agent-cancel">
                  Cancel removal
                </button>
              )}
              <button className="panel__action" onClick={onClose} data-testid="remove-agent-close">
                Close
              </button>
            </div>
            <p className="panel__hint">Closing this does not cancel it. Track it, approve it or cancel it later under "Pending removals".</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------------------------
// The forget dialog (docs/65 sec. 8)
// ---------------------------------------------------------------------------------------------------------------

export interface ForgetMachineDialogProps {
  api: ConsoleApi;
  machine: MachineLike;
  onClose: () => void;
  /** The machine was forgotten (or was already removed): the host re-lists. */
  onForgotten: (r: ForgetMachineResult) => void;
}

/**
 * "Forget this machine...": the Owner's deliberate, irreversible end of a RETIRED machine whose removal will never be
 * confirmed (or that is simply gone). It uninstalls nothing. The same gates as removal, in the same order: the machine's name
 * typed, an authenticator code sent to `POST /auth/step-up`, and only then `POST /machines/{id}/forget`. The server owns every
 * rule (retired only, step-up freshness, the name, the group scope); this only decides what to show.
 */
export function ForgetMachineDialog({ api, machine, onClose, onForgotten }: ForgetMachineDialogProps) {
  const [typed, setTyped] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<ForgetMachineResult | null>(null);
  const mounted = useRef(true);
  // Keyboard focus stays INSIDE the dialog (it opens on the name field, and returns there after a refusal: the submit button
  // is disabled while the call runs, which would otherwise drop focus to the page), so Escape always reaches the dialog.
  const typedRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  const copy = forgetDialogCopy(machine);
  const canSubmit = removalConfirmationMatches(typed, machine) && /^\s*\d{6}\s*$/.test(code) && !busy;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    // The typed name is re-checked at submit time, so no path reaches the API without it.
    if (!removalConfirmationMatches(typed, machine) || busy) return;
    setBusy(true);
    setError(null);
    try {
      await stepUp(api, code);
      const r = await api.forgetMachine(machine.id, typed.trim());
      if (!mounted.current) return;
      setDone(r);
      setCode("");
      onForgotten(r);
    } catch (err) {
      if (mounted.current) setError(err instanceof ConsoleApiError ? describeDirectiveError(err, "forget") : (err as Error).message);
    } finally {
      if (mounted.current) {
        setBusy(false);
        typedRef.current?.focus();
      }
    }
  };

  return (
    <div className="backstage__confirm-backdrop" role="dialog" aria-modal="true" aria-labelledby="forget-machine-title"
      data-testid="forget-machine-dialog" onKeyDown={(ev) => { if (ev.key === "Escape") { ev.stopPropagation(); onClose(); } }}>
      <div className="backstage__confirm" style={{ width: "min(560px, 95vw)", maxHeight: "90vh", overflow: "auto" }}>
        <h2 id="forget-machine-title">{copy.title}</h2>
        {!done && (
          <form onSubmit={submit}>
            <p data-testid="forget-machine-effect">{copy.effect}</p>
            <p data-testid="forget-machine-when">{copy.when}</p>
            <p className="panel__hint" data-testid="forget-machine-notice"><strong>{copy.notice}</strong></p>
            <label className="panel__toolbar-field" style={{ display: "block" }}>
              Type the machine's name <strong>{machine.name}</strong>{machine.alias ? <> (or its friendly name <strong>{machine.alias}</strong>)</> : null} to confirm
              <input ref={typedRef} autoFocus value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false}
                data-testid="forget-machine-confirm-input" style={{ display: "block", width: "100%" }} />
            </label>
            <label className="panel__toolbar-field" style={{ display: "block", marginTop: 8 }}>
              Authenticator code (6 digits)
              <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code"
                data-testid="forget-machine-code" style={{ display: "block", width: "100%" }} />
            </label>
            {error && <p role="alert" className="panel__toolbar-error" data-testid="forget-machine-error">{error}</p>}
            <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
              <button type="submit" className="panel__action panel__action--danger" disabled={!canSubmit} data-testid="forget-machine-submit">
                {busy ? "Working…" : "Forget this machine"}
              </button>
              <button type="button" className="panel__action" onClick={onClose} data-testid="forget-machine-close">Close</button>
            </div>
          </form>
        )}
        {done && (
          <div data-testid="forget-machine-done">
            <p role="status" data-testid="forget-machine-result">{forgetOutcomeNote(done.outcome, machine)}</p>
            <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
              <button autoFocus className="panel__action" onClick={onClose} data-testid="forget-machine-close">Close</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------------------------
// Pending removals
// ---------------------------------------------------------------------------------------------------------------

/** Store pages read per refresh, and how far "Load more" may widen that. */
const PAGE_BUDGET_STEP = 5;
const PAGE_BUDGET_MAX = 50;

const fmtTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : "");

export interface PendingRemovalsPanelProps {
  api: ConsoleApi;
  /** The signed-in user's id (GET /me user_id): their own requests are never offered Approve. */
  selfUserId: SelfUserId;
  /** Only to show people by email; a caller who cannot read users sees ids. */
  users: readonly UserSummary[];
  /** Changes whenever the host knows something changed (a request): re-reads the directives. */
  reloadToken: number;
  onChanged: () => void;
  /** Open the forget dialog for a removal's machine. Omitted = the row offers no "Forget this machine...". */
  onForget?: (m: MachineLike) => void;
}

export function PendingRemovalsPanel({ api, selfUserId, users, reloadToken, onChanged, onForget }: PendingRemovalsPanelProps) {
  const [rows, setRows] = useState<readonly ActiveDirective[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastOkMs, setLastOkMs] = useState<number | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [pageBudget, setPageBudget] = useState(PAGE_BUDGET_STEP);
  const [rowError, setRowError] = useState<Record<string, string>>({});
  const [approving, setApproving] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const now = useNow();
  const seq = useRef(0);

  const userName = useMemo(() => new Map(users.map((u) => [u.id, u.email])), [users]);
  const person = (id?: string) => (id && id === selfUserId ? "you" : id ? userName.get(id) ?? id : "");

  const rowsRef = useRef<readonly ActiveDirective[]>([]);
  rowsRef.current = rows;
  const budgetRef = useRef(pageBudget);
  budgetRef.current = pageBudget;

  // `silent` (background polls) neither flips the Loading label nor clears an error until a read succeeds.
  const load = useCallback(async (silent = false) => {
    const mine = ++seq.current;
    if (!silent) {
      setLoading(true);
      setError(null);
    }
    try {
      const all = await api.listActiveDirectives({ maxPages: budgetRef.current });
      if (mine !== seq.current) return;
      setRows(all.rows.filter((d) => d.kind === "uninstall"));
      setHasMore(all.hasMore);
      setLastOkMs(Date.now());
      setError(null);
    } catch (e) {
      if (mine !== seq.current) return;
      setError(e instanceof Error ? e.message : String(e));
    }
    if (mine === seq.current) setLoading(false);
  }, [api]);

  useEffect(() => { void load(); }, [load, reloadToken, pageBudget]);

  // Keep the list fresh while mounted: another owner's request or an external approval must show up inside its
  // cancel window. Polls fast (~5 s) while a listed removal is in its window, else slowly; skips while the tab is
  // hidden; re-reads at once when the tab is shown or focused; stops on unmount.
  useEffect(() => {
    // Single flight: at most one read in progress and one pending timer. A focus/visibility event during a read
    // is coalesced into ONE follow-up read; only `run` schedules the next poll.
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let inFlight = false;
    let again = false;
    const schedule = () => {
      clearTimeout(timer);
      if (!stopped) timer = setTimeout(() => void run(), pollIntervalMs(rowsRef.current, Date.now()));
    };
    const run = async () => {
      clearTimeout(timer);
      if (stopped) return;
      if (inFlight) {
        again = true;
        return;
      }
      if (!document.hidden) {
        inFlight = true;
        try {
          await load(true);
        } finally {
          inFlight = false;
        }
      }
      if (again && !stopped) {
        again = false;
        void run();
        return;
      }
      schedule();
    };
    const refreshNow = () => {
      if (!stopped && !document.hidden) void run();
    };
    schedule();
    document.addEventListener("visibilitychange", refreshNow);
    window.addEventListener("focus", refreshNow);
    return () => {
      stopped = true;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", refreshNow);
      window.removeEventListener("focus", refreshNow);
    };
  }, [load]);

  const stale = staleNotice(error !== null, lastOkMs);

  const act = async (id: string, action: DirectiveAction, run: () => Promise<unknown>) => {
    setBusyId(id);
    setRowError((e) => ({ ...e, [id]: "" }));
    try {
      await run();
      setApproving(null);
      setCode("");
      onChanged();
      await load();
    } catch (err) {
      setRowError((e) => ({ ...e, [id]: err instanceof ConsoleApiError ? describeDirectiveError(err, action) : (err as Error).message }));
    } finally {
      setBusyId(null);
    }
  };

  const approve = (d: AgentDirective) => act(d.id, "approve", async () => {
    await stepUp(api, code);
    await api.approveDirective(d.id);
  });

  const cancel = (d: AgentDirective) => act(d.id, "cancel", async () => {
    await api.cancelDirective(d.id, "cancelled from the console");
  });

  return (
    <section className="panel__section" data-testid="pending-removals" aria-labelledby="pending-removals-title">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title" id="pending-removals-title">Pending removals</span>
        <button className="panel__action" onClick={() => void load()} disabled={loading} data-testid="pending-removals-refresh">
          {loading ? "Loading…" : "Refresh"}
        </button>
        {error && <span className="panel__toolbar-error" role="alert" data-testid="pending-removals-error">{error}</span>}
        {stale && <span className="panel__toolbar-error" role="status" data-testid="pending-removals-stale">{stale}</span>}
      </div>
      {hasMore && (
        <p className="panel__hint" data-testid="pending-removals-more">
          More pending removals exist than are shown.{" "}
          <button className="panel__action" disabled={loading || pageBudget >= PAGE_BUDGET_MAX} onClick={() => setPageBudget((b) => Math.min(PAGE_BUDGET_MAX, b + PAGE_BUDGET_STEP))} data-testid="pending-removals-load-more">
            Load more
          </button>
        </p>
      )}
      {rows.length === 0 && !loading && <p className="panel__muted" data-testid="pending-removals-empty">No agent removals are pending.</p>}
      {rows.length > 0 && (
        <table className="panel__table">
          <thead>
            <tr><th>Machine</th><th>State</th><th>Requested</th><th>Approved</th><th>Times</th><th /></tr>
          </thead>
          <tbody>
            {rows.map((d) => {
              const ui = directiveUiState(d);
              const info = DIRECTIVE_STATE_INFO[ui];
              const win = cancelWindow(d, now);
              const rowBusy = busyId === d.id;
              const showApprove = canApproveDirective(d, selfUserId);
              return (
                <tr key={d.id} data-testid={`removal-${d.id}`}>
                  <td data-testid={`removal-machine-${d.id}`}>{d.machine_alias || d.machine_name}</td>
                  <td>
                    <strong data-testid={`removal-state-${d.id}`} style={{ color: TONE_STYLE[info.tone] }}>{info.label}</strong>
                    <div className="panel__hint" data-testid={`removal-explain-${d.id}`}>{info.explain}</div>
                    {d.state_detail ? <div className="panel__hint">{d.state_detail}</div> : null}
                    {d.cancel_reason ? <div className="panel__hint">Reason: {d.cancel_reason}</div> : null}
                    {win.kind === "counting" && (
                      <div data-testid={`removal-countdown-${d.id}`}>Cancel window: {formatCountdown(win.msLeft)} left</div>
                    )}
                    {win.kind === "ended" && <div className="panel__hint">Cancel window ended; being issued.</div>}
                    {win.kind === "needs_approval" && (
                      <div className="panel__hint">Request lapses in {formatCountdown(requestLifetimeLeftMs(d, now))} without an approval.</div>
                    )}
                  </td>
                  <td>
                    <span data-testid={`removal-requester-${d.id}`}>{person(d.requested_by)}</span>
                    <div className="panel__hint">{fmtTime(d.requested_at)}</div>
                  </td>
                  <td data-testid={`removal-approver-${d.id}`}>
                    {d.approved_by ? <>{person(d.approved_by)}<div className="panel__hint">{fmtTime(d.approved_at)}</div></> : d.require_approval ? "needed" : "not required"}
                  </td>
                  <td className="panel__hint">
                    {d.issued_at ? <div>Issued {fmtTime(d.issued_at)}</div> : null}
                    {d.delivered_at ? <div>Delivered {fmtTime(d.delivered_at)}</div> : null}
                    {d.acked_at ? <div>Agent reported {fmtTime(d.acked_at)}</div> : null}
                    {d.cancelled_at ? <div>Cancelled {fmtTime(d.cancelled_at)} {d.cancelled_by ? `by ${person(d.cancelled_by)}` : ""}</div> : null}
                  </td>
                  <td>
                    {showApprove && approving !== d.id && (
                      <button className="panel__action" disabled={rowBusy} onClick={() => { setApproving(d.id); setCode(""); }} data-testid={`removal-approve-${d.id}`}>
                        Approve…
                      </button>
                    )}
                    {showApprove && approving === d.id && (
                      <form onSubmit={(e) => { e.preventDefault(); if (/^\s*\d{6}\s*$/.test(code)) void approve(d); }} style={{ display: "inline-flex", gap: 6 }}>
                        <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code"
                          placeholder="Authenticator code" aria-label="Authenticator code to approve" data-testid={`removal-approve-code-${d.id}`} />
                        <button type="submit" className="panel__action" disabled={rowBusy || !/^\s*\d{6}\s*$/.test(code)} data-testid={`removal-approve-confirm-${d.id}`}>
                          Approve removal
                        </button>
                        <button type="button" className="panel__action" onClick={() => setApproving(null)}>Back</button>
                      </form>
                    )}
                    {canCancelDirective(d) && (
                      <button className="panel__action panel__action--danger" disabled={rowBusy} onClick={() => void cancel(d)} data-testid={`removal-cancel-${d.id}`}>
                        Cancel
                      </button>
                    )}
                    {onForget && canForgetFromRemoval(d) && (
                      <button className="panel__action panel__action--danger" disabled={rowBusy} data-testid={`removal-forget-${d.id}`}
                        title="Permanently remove this machine from DeskRally. It does not uninstall anything."
                        onClick={() => onForget({ id: d.machine_id, name: d.machine_name, alias: d.machine_alias, status: d.machine_status })}>
                        Forget this machine…
                      </button>
                    )}
                    {rowError[d.id] ? <div role="alert" className="panel__toolbar-error" data-testid={`removal-error-${d.id}`}>{rowError[d.id]}</div> : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------------------------------------------
// The tenant policy
// ---------------------------------------------------------------------------------------------------------------

export interface DirectivePolicyToggleProps {
  api: ConsoleApi;
  policy: DirectivePolicy;
  onSaved: (p: DirectivePolicy) => void;
}

export function DirectivePolicyToggle({ api, policy, onSaved }: DirectivePolicyToggleProps) {
  const [draft, setDraft] = useState(policy.require_second_approver);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => { setDraft(policy.require_second_approver); }, [policy.require_second_approver]);
  const dirty = draft !== policy.require_second_approver;

  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!dirty || busy || !/^\s*\d{6}\s*$/.test(code)) return;
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      await stepUp(api, code);
      const p = await api.setDirectivePolicy(draft);
      setCode("");
      setSaved(true);
      onSaved(p);
    } catch (err) {
      setError(err instanceof ConsoleApiError ? describeDirectiveError(err, "policy") : (err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="panel__form" onSubmit={save} data-testid="directive-policy">
      <label className="panel__toolbar-field">
        <input type="checkbox" checked={draft} onChange={(e) => { setDraft(e.target.checked); setSaved(false); }} data-testid="directive-policy-toggle" />
        {" "}Require a second approver for agent removal (recommended)
      </label>
      {!policy.require_second_approver && (
        <span className="panel__hint" data-testid="directive-policy-recommend">
          Recommended: turn this on so no single person can remove an agent alone. It is off now.
        </span>
      )}
      {dirty && (
        <>
          <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code"
            placeholder="Authenticator code" aria-label="Authenticator code to save the policy" data-testid="directive-policy-code" />
          <button type="submit" className="panel__action" disabled={busy || !/^\s*\d{6}\s*$/.test(code)} data-testid="directive-policy-save">
            {busy ? "Saving…" : "Save"}
          </button>
        </>
      )}
      {saved && !dirty && <span role="status" className="panel__hint" data-testid="directive-policy-saved">Saved.</span>}
      {error && <span role="alert" className="panel__toolbar-error" data-testid="directive-policy-error">{error}</span>}
    </form>
  );
}
