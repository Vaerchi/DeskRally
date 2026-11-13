/**
 * User management (docs/01 §5): list the tenant's users, enable/disable their access, assign their role,
 * and mint a first-password / reset SETUP LINK for them. Owner/Admin — the server gates every action
 * (CapManageUsers for enable/disable and setup links, CapManageRoles plus a no-escalation check for role
 * assignment) and refuses acting on yourself. Minting a setup link additionally requires the caller to
 * re-prove their OWN password (a step-up), so a stolen session cannot mint an account-takeover link.
 * Controls are disabled while a mutation is in flight. Thin like the other console panels — it owns only
 * load/refresh/in-flight/error and the transient setup-link state.
 */

import { type FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ASSIGNABLE_ROLES,
  type ConsoleApi,
  type IssuedSetupLink,
  type MachineGroup,
  type SetUserRoleOptions,
  type UserSummary,
} from "../lib/console_api";
import { filterUsersByText } from "../lib/console_panels";
import { createLatestWins } from "../lib/latest_wins";
import { usersToCsv } from "../lib/report_csv";
import { setupLinkUrl } from "../lib/setup_link";
import { accessLabel, isoToLocalInput, localInputToISO } from "../lib/user_access";
import { browserTimeZone, draftFromWindow, draftToWindow, windowLabel, type WindowDraft } from "../lib/access_window";
import { AccessWindowFields } from "./AccessWindowFields";
import { groupOptions } from "../lib/group_tree";
import { scopeLabel, toggleGroup } from "../lib/user_scope";
import { saveBytesAsFile } from "./FileTransferPanel";

export interface UsersPanelProps {
  api: ConsoleApi;
  /** Origin used to build the setup link; defaults to this page's origin (overridable for tests). */
  origin?: string;
}

/**
 * The role to preselect in a user's picker: their single role when they have exactly one assignable
 * preset, else "" (no membership, or a set we cannot represent as one choice) so the picker shows the
 * "Set role…" placeholder rather than silently implying a role the user may not solely hold.
 */
function currentRole(u: UserSummary): string {
  const roles = u.roles ?? [];
  if (roles.length === 1 && (ASSIGNABLE_ROLES as readonly string[]).includes(roles[0])) {
    return roles[0];
  }
  return "";
}

export function UsersPanel({ api, origin }: UsersPanelProps) {
  const [users, setUsers] = useState<readonly UserSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [newEmail, setNewEmail] = useState("");
  const [newName, setNewName] = useState("");
  const [newRole, setNewRole] = useState<string>("technician");
  const [newScope, setNewScope] = useState<string[]>([]);
  // docs/56: optional end of the new user's access (a datetime-local value; "" = never).
  const [newExpiry, setNewExpiry] = useState("");
  // docs/57: optional hours for the new user, sent WITH the invite (never unrestricted first).
  const [newWindow, setNewWindow] = useState<WindowDraft>(() => draftFromWindow(null, browserTimeZone()));
  // The access-expiry editor, for ONE user at a time. `accessDirty` is whether the operator changed
  // anything: an unchanged Save sends nothing, so a stored (possibly already past, possibly to-the-second)
  // expiry is never re-sent through the minute-only input (docs/56 sec. 6).
  const [accessFor, setAccessFor] = useState<{ id: string; email: string } | null>(null);
  const accessForRef = useRef<{ id: string; email: string } | null>(null);
  const [accessValue, setAccessValue] = useState("");
  const [accessNever, setAccessNever] = useState(true);
  const [accessDirty, setAccessDirty] = useState(false);
  // docs/57: the window section of the same editor, with its own dirty flag (unchanged → omitted).
  const [windowDraft, setWindowDraft] = useState<WindowDraft>(() => draftFromWindow(null, browserTimeZone()));
  const [windowDirty, setWindowDirty] = useState(false);
  const [savingAccess, setSavingAccess] = useState(false);
  const [groups, setGroups] = useState<readonly MachineGroup[]>([]);
  // The scope picker lists groups as a tree with path labels (docs/62), so equal names never merge.
  const scopePickerOptions = useMemo(() => groupOptions(groups), [groups]);
  const [creating, setCreating] = useState(false);
  // Setup-link (credential provisioning) state — only ever for ONE user at a time.
  const [setupFor, setSetupFor] = useState<{ id: string; email: string } | null>(null);
  // Mirrors setupFor synchronously so an in-flight mint that resolves AFTER the admin switched away (or
  // closed the panel) can be dropped rather than render one user's one-time token under another's header.
  const setupForRef = useRef<{ id: string; email: string } | null>(null);
  const [stepUpPw, setStepUpPw] = useState("");
  const [issuing, setIssuing] = useState(false);
  const [issued, setIssued] = useState<IssuedSetupLink | null>(null);
  const [copied, setCopied] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [textQuery, setTextQuery] = useState("");

  const filteredUsers = useMemo(() => filterUsersByText(users, textQuery), [users, textQuery]);

  const handleExport = useCallback(() => {
    saveBytesAsFile("users.csv", new TextEncoder().encode(usersToCsv(filteredUsers)));
  }, [filteredUsers]);

  // Latest-wins guard: only the newest listing may touch users/error/busy, so a slower older list landing
  // after a post-write re-list cannot revert the displayed disabled/role state. Invalidated on unmount.
  const listGuard = useRef(createLatestWins());
  useEffect(() => {
    const guard = listGuard.current;
    return () => guard.invalidate();
  }, []);

  const refresh = useCallback(async () => {
    const token = listGuard.current.begin();
    setBusy(true);
    setError(null);
    try {
      const list = await api.listUsers();
      if (!listGuard.current.isCurrent(token)) return; // superseded: a newer listing owns the state
      setUsers(list);
    } catch (e) {
      if (!listGuard.current.isCurrent(token)) return; // a superseded failure must not show
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      // Only the newest listing clears busy (an older one finishing must not hide a newer load).
      if (listGuard.current.isCurrent(token)) setBusy(false);
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Machine groups, for the invite scope picker and the scope display. Best-effort and loaded once:
  // if it fails (or the caller lacks group visibility) the scope still renders by id.
  useEffect(() => {
    let live = true;
    api
      .listMachineGroups()
      .then((gs) => {
        if (live) setGroups(gs);
      })
      .catch(() => {
        /* scope falls back to ids */
      });
    return () => {
      live = false;
    };
  }, [api]);

  const handleToggle = useCallback(
    async (u: UserSummary) => {
      setPending(u.id);
      setError(null);
      try {
        await api.setUserDisabled(u.id, !u.disabled);
        await refresh();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setPending(null);
      }
    },
    [api, refresh],
  );

  const handleSignOut = useCallback(
    async (u: UserSummary) => {
      setPending(u.id);
      setError(null);
      try {
        await api.signOutUser(u.id);
        // No refresh needed — sign-out changes no listed field (the user is not disabled); the button
        // just revokes their sessions server-side.
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setPending(null);
      }
    },
    [api],
  );

  const handleClearLockout = useCallback(
    async (u: UserSummary) => {
      setPending(u.id);
      setError(null);
      try {
        await api.clearUserLockout(u.id);
        // No refresh needed — lockout state is not reflected in any listed field.
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setPending(null);
      }
    },
    [api],
  );

  const handleCreate = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      const email = newEmail.trim();
      if (email === "" || creating) return;
      const expiresAt = newExpiry === "" || newRole === "owner" ? null : localInputToISO(newExpiry);
      if (newExpiry !== "" && newRole !== "owner" && expiresAt === null) {
        setError("Enter a valid date and time for when access ends, or leave it empty.");
        return;
      }
      const win = newRole === "owner" ? { window: null } : draftToWindow(newWindow);
      if ("error" in win) {
        setError(win.error);
        return;
      }
      setCreating(true);
      setError(null);
      try {
        await api.createUser({
          email,
          displayName: newName.trim(),
          role: newRole,
          scopedGroupIds: newScope,
          expiresAt,
          accessWindow: win.window,
        });
        setNewEmail("");
        setNewName("");
        setNewRole("technician");
        setNewScope([]);
        setNewExpiry("");
        setNewWindow(draftFromWindow(null, browserTimeZone()));
        await refresh();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setCreating(false);
      }
    },
    [api, newEmail, newName, newRole, newScope, newExpiry, newWindow, creating, refresh],
  );

  const handleSetRole = useCallback(
    async (u: UserSummary, role: string) => {
      if (role === "" || role === currentRole(u)) return;
      setPending(u.id);
      setError(null);
      try {
        await api.setUserRole(u.id, role);
        await refresh();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setPending(null);
      }
    },
    [api, refresh],
  );

  // docs/56: open the access-expiry editor pre-filled with the user's current value.
  const openAccess = useCallback((u: UserSummary) => {
    accessForRef.current = { id: u.id, email: u.email };
    setAccessFor({ id: u.id, email: u.email });
    setAccessValue(isoToLocalInput(u.access_expires_at));
    setAccessNever(!u.access_expires_at);
    setAccessDirty(false);
    // A user whose memberships carry different hours opens with nothing pre-filled ("Varies"), never as
    // "any time" (docs/57 sec. 6).
    setWindowDraft(draftFromWindow(u.access_window_varies ? null : (u.access_window ?? null), browserTimeZone()));
    setWindowDirty(false);
    setError(null);
  }, []);

  const closeAccess = useCallback(() => {
    accessForRef.current = null;
    setAccessFor(null);
  }, []);

  // The target as the LATEST listing knows it: its role is re-sent with the expiry (the endpoint sets
  // both), so it must be the current one, never the role captured when the editor opened.
  const accessTarget = accessFor ? users.find((u) => u.id === accessFor.id) ?? null : null;
  const accessRole = accessTarget ? currentRole(accessTarget) : "";

  const handleSaveAccess = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      const target = accessFor;
      if (!target || savingAccess) return;
      if (!accessDirty && !windowDirty) {
        closeAccess(); // nothing changed: send nothing (the stored values stay exactly as they are)
        return;
      }
      if (accessRole === "") {
        setError("This user has no single role; set a role first.");
        return;
      }
      const expiresAt = accessNever ? null : localInputToISO(accessValue);
      if (accessDirty && !accessNever && expiresAt === null) {
        setError("Enter a valid date and time (it may fall in a daylight-saving gap), or choose Never.");
        return;
      }
      const win = draftToWindow(windowDraft);
      if (windowDirty && "error" in win) {
        setError(win.error);
        return;
      }
      // Unchanged parts are omitted, so the server preserves them. A user whose hours VARY by membership
      // must state scope, expiry and hours together (docs/57 sec. 4), so all three are sent.
      const varies = accessTarget?.access_window_varies === true;
      if (varies && (!windowDirty || "error" in win)) {
        setError("This user's hours vary by membership; choose the hours (or untick them) to replace them.");
        return;
      }
      const opts: SetUserRoleOptions = {};
      if (accessDirty || varies) opts.expiresAt = accessDirty ? expiresAt : (accessTarget?.access_expires_at ?? null);
      if (windowDirty && !("error" in win)) opts.accessWindow = win.window;
      if (varies) opts.scopedGroupIds = accessTarget?.scoped_group_ids ?? [];
      setSavingAccess(true);
      setError(null);
      try {
        await api.setUserRole(target.id, accessRole, opts);
        // Close only the editor this save belonged to (Close is disabled while saving, but be exact).
        if (accessForRef.current?.id === target.id) closeAccess();
        await refresh();
      } catch (e) {
        if (accessForRef.current?.id === target.id) setError(e instanceof Error ? e.message : String(e));
      } finally {
        setSavingAccess(false);
      }
    },
    [api, accessFor, accessTarget, accessDirty, accessNever, accessValue, accessRole, windowDraft, windowDirty, savingAccess, closeAccess, refresh],
  );

  // Open the setup-link form for a user, clearing any previously shown token. The per-row buttons are
  // disabled while a panel is open, so this is only ever called from a closed state (one user at a time).
  const openSetup = useCallback((u: UserSummary) => {
    setupForRef.current = { id: u.id, email: u.email };
    setSetupFor({ id: u.id, email: u.email });
    setIssued(null);
    setStepUpPw("");
    setCopied(false);
    setError(null);
  }, []);

  const closeSetup = useCallback(() => {
    setupForRef.current = null;
    setSetupFor(null);
    setIssued(null);
    setStepUpPw("");
    setCopied(false);
  }, []);

  const handleIssue = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      const target = setupFor;
      if (!target || issuing || stepUpPw === "") return;
      setIssuing(true);
      setError(null);
      try {
        const link = await api.issuePasswordReset(target.id, stepUpPw);
        // Drop the result if the admin switched away from / closed this target while it was in flight —
        // never render one user's takeover token under a different user's header.
        if (setupForRef.current?.id !== target.id) return;
        setIssued(link);
        setStepUpPw("");
      } catch (e) {
        if (setupForRef.current?.id === target.id) {
          setError(e instanceof Error ? e.message : String(e));
        }
      } finally {
        setIssuing(false);
      }
    },
    [api, setupFor, issuing, stepUpPw],
  );

  const handleRevoke = useCallback(async () => {
    if (!setupFor || revoking) return;
    setRevoking(true);
    setError(null);
    try {
      await api.revokePasswordReset(setupFor.id);
      closeSetup();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRevoking(false);
    }
  }, [api, setupFor, revoking, closeSetup]);

  const link = issued ? setupLinkUrl(origin ?? window.location.origin, issued.token) : "";
  const handleCopy = useCallback(() => {
    if (!link) return;
    void navigator.clipboard?.writeText(link).then(
      () => setCopied(true),
      () => setCopied(false),
    );
  }, [link]);

  return (
    <section className="panel panel--users" data-testid="users">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Users</span>
        <input
          className="panel__search"
          type="search"
          aria-label="Search users"
          placeholder="Search email, name, role…"
          value={textQuery}
          onChange={(e) => setTextQuery(e.target.value)}
          data-testid="users-text-search"
        />
        <button className="panel__action" onClick={() => void refresh()} disabled={busy}>
          {busy ? "Loading…" : "Refresh"}
        </button>
        <button
          className="panel__action"
          onClick={handleExport}
          disabled={filteredUsers.length === 0}
          title="Download the shown users as a CSV (honoring current search)"
          data-testid="users-export"
        >
          Export CSV
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="users-error">
            {error}
          </span>
        )}
      </div>
      <form className="panel__create" onSubmit={handleCreate}>
        <input
          type="email"
          className="panel__input"
          placeholder="email@example.com"
          value={newEmail}
          onChange={(e) => setNewEmail(e.target.value)}
          disabled={creating}
          aria-label="New user email"
          data-testid="user-create-email"
        />
        <input
          type="text"
          className="panel__input"
          placeholder="Display name (optional)"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          disabled={creating}
          aria-label="New user display name"
          data-testid="user-create-name"
        />
        <select
          className="panel__select"
          value={newRole}
          onChange={(e) => {
            setNewRole(e.target.value);
            if (e.target.value === "owner") {
              setNewExpiry("");
              setNewWindow(draftFromWindow(null, browserTimeZone()));
            }
          }}
          disabled={creating}
          aria-label="New user role"
          data-testid="user-create-role"
        >
          {ASSIGNABLE_ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <label className="panel__expiry" title="Leave empty for permanent access. API tokens are not affected.">
          Access ends
          <input
            type="datetime-local"
            className="panel__input"
            value={newExpiry}
            onChange={(e) => setNewExpiry(e.target.value)}
            disabled={creating || newRole === "owner"}
            aria-label="New user access ends (optional)"
            data-testid="user-create-expiry"
          />
        </label>
        {newRole !== "owner" && (
          <AccessWindowFields draft={newWindow} onChange={setNewWindow} disabled={creating} testId="user-create-window" />
        )}
        {groups.length > 0 && (
          <details className="panel__scope" data-testid="user-create-scope">
            <summary>
              {newScope.length === 0 ? "Scope: all groups" : `Scope: ${scopeLabel(newScope, groups)}`}
            </summary>
            <fieldset className="panel__scope-groups">
              <legend className="panel__scope-hint">
                Leave all unchecked for tenant-wide access. A checked group also covers all of its subgroups.
              </legend>
              {scopePickerOptions.map((g) => (
                <label key={g.id} className="panel__scope-group" style={{ marginLeft: `${g.depth}rem` }} data-depth={g.depth}>
                  <input
                    type="checkbox"
                    checked={newScope.includes(g.id)}
                    disabled={creating}
                    onChange={() => setNewScope((prev) => toggleGroup(prev, g.id))}
                    data-testid={`user-create-scope-${g.id}`}
                  />
                  {g.label}
                </label>
              ))}
            </fieldset>
          </details>
        )}
        <button
          type="submit"
          className="panel__action"
          disabled={creating || newEmail.trim() === ""}
          data-testid="user-create-submit"
        >
          {creating ? "Adding…" : "Add user"}
        </button>
      </form>
      {accessFor && (
        <form className="panel__setup" onSubmit={handleSaveAccess} data-testid="access-panel">
          <div className="panel__setup-head">
            <span>
              Access for <strong data-testid="access-target">{accessFor.email}</strong>
            </span>
            <button type="button" className="panel__action" onClick={closeAccess} disabled={savingAccess} data-testid="access-close">
              Close
            </button>
          </div>
          <div className="panel__actions-row">
            <label className="panel__scope-group">
              <input
                type="checkbox"
                checked={accessNever}
                onChange={(e) => {
                  setAccessNever(e.target.checked);
                  setAccessDirty(true);
                }}
                disabled={savingAccess || accessRole === "owner"}
                data-testid="access-never"
              />
              Never expires
            </label>
            <input
              type="datetime-local"
              className="panel__input"
              value={accessValue}
              onChange={(e) => {
                setAccessValue(e.target.value);
                setAccessNever(false);
                setAccessDirty(true);
              }}
              disabled={savingAccess || accessRole === "owner"}
              autoFocus
              aria-label="Access ends"
              data-testid="access-ends"
            />
            <button type="submit" className="panel__action" disabled={savingAccess} data-testid="access-save">
              {savingAccess ? "Saving…" : "Save"}
            </button>
          </div>
          <p className="panel__note">
            {accessRole === "owner"
              ? "Owner access cannot expire."
              : "When access ends, everything this role allowed stops at once; an unattended session ends within about 30 s. API tokens are not affected."}
          </p>
          {accessRole !== "owner" ? (
            <>
              {accessTarget?.access_window_varies && !windowDirty && (
                <p className="panel__note" data-testid="access-window-varies">
                  Hours vary by membership; saving replaces them with the hours chosen here.
                </p>
              )}
              <AccessWindowFields
                draft={windowDraft}
                onChange={(d) => {
                  setWindowDraft(d);
                  setWindowDirty(true);
                }}
                disabled={savingAccess}
                testId="access-window"
                storedZone={accessTarget?.access_window?.time_zone}
              />
              <p className="panel__note">
                Outside these hours the user can sign in but do nothing; an unattended session ends within about
                30 s of the window closing, an attended one continues to its end.
              </p>
            </>
          ) : (
            <p className="panel__note">Owner access cannot be limited to set hours.</p>
          )}
        </form>
      )}
      {setupFor && (
        <div className="panel__setup" data-testid="setup-panel">
          <div className="panel__setup-head">
            <span>
              Credential setup link for <strong data-testid="setup-target">{setupFor.email}</strong>
            </span>
            <button className="panel__action" onClick={closeSetup} data-testid="setup-close">
              Close
            </button>
          </div>
          {!issued ? (
            <form className="panel__setup-form" onSubmit={handleIssue}>
              <p className="panel__note">
                You are minting a single-use link that lets this user set a password. Confirm your OWN
                password to continue — this link is an account-takeover primitive, so it is metered and
                short-lived.
              </p>
              <input
                type="password"
                className="panel__input"
                placeholder="Your password"
                value={stepUpPw}
                onChange={(e) => setStepUpPw(e.target.value)}
                disabled={issuing}
                aria-label="Your password"
                autoComplete="current-password"
                data-testid="setup-stepup-password"
              />
              <button
                type="submit"
                className="panel__action"
                disabled={issuing || stepUpPw === ""}
                data-testid="setup-issue-submit"
              >
                {issuing ? "Creating…" : "Create setup link"}
              </button>
            </form>
          ) : (
            <div className="panel__setup-result">
              <p className="panel__note" data-testid="setup-link-note">
                {issued.firstProvision
                  ? "First-password link — this account had no password yet."
                  : "Password reset link — this replaces the account's current password."}{" "}
                Copy it now: it is shown once, is single-use, and expires{" "}
                {new Date(issued.credentialToken.expires_at).toLocaleString()}.
              </p>
              <p className="panel__mono panel__code" data-testid="setup-link-url">
                {link}
              </p>
              <details>
                <summary>Show token only</summary>
                <p className="panel__mono panel__code" data-testid="setup-link-token">
                  {issued.token}
                </p>
              </details>
              <div className="panel__actions-row">
                <button className="panel__action" onClick={handleCopy} data-testid="setup-link-copy">
                  {copied ? "Copied" : "Copy link"}
                </button>
                <button
                  className="panel__action panel__action--danger"
                  onClick={() => void handleRevoke()}
                  disabled={revoking}
                  data-testid="setup-revoke"
                >
                  {revoking ? "Revoking…" : "Revoke link"}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
      <table className="panel__table">
        <thead>
          <tr>
            <th>Email</th>
            <th>Name</th>
            <th>Role</th>
            <th>Scope</th>
            <th>Access</th>
            <th>Status</th>
            <th className="panel__col--action">Actions</th>
          </tr>
        </thead>
        <tbody>
          {filteredUsers.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={7} data-testid="users-empty">
                {busy ? "Loading…" : textQuery.trim() ? "No users match this search." : "No users."}
              </td>
            </tr>
          )}
          {filteredUsers.map((u) => {
            const roles = u.roles ?? [];
            const selected = currentRole(u);
            return (
              <tr key={u.id} data-testid={`user-row-${u.email}`}>
                <td className="panel__name">{u.email}</td>
                <td>{u.display_name}</td>
                <td data-testid={`user-role-${u.email}`}>{roles.length > 0 ? roles.join(", ") : "—"}</td>
                <td data-testid={`user-scope-${u.email}`}>{scopeLabel(u.scoped_group_ids, groups)}</td>
                <td data-testid={`user-access-${u.email}`}>
                  <span className={u.access_expired ? "panel__badge" : undefined} data-tone={u.access_expired ? "bad" : undefined}>{accessLabel(u)}</span>{" "}
                  {(u.access_window || u.access_window_varies) && (
                    <span className="panel__window-label" data-testid={`user-window-${u.email}`}>
                      {u.access_window ? windowLabel(u.access_window) : "Hours vary by membership"}
                    </span>
                  )}{" "}
                  {u.access_outside_window && !u.access_expired && (
                    <span className="panel__badge" data-tone="pending" data-testid={`user-outside-${u.email}`}>
                      Outside hours
                    </span>
                  )}{" "}
                  <button
                    type="button"
                    className="panel__action"
                    onClick={() => openAccess(u)}
                    disabled={pending !== null || accessFor !== null || selected === ""}
                    title={selected === "" ? "Set a single role first" : "Change when this user's access ends"}
                    aria-label={`Edit access for ${u.email}`}
                    data-testid={`user-access-edit-${u.email}`}
                  >
                    Edit
                  </button>
                </td>
                <td data-testid={`user-status-${u.email}`}>{u.disabled ? "disabled" : "active"}</td>
                <td className="panel__col--action">
                  <select
                    className="panel__select"
                    value={selected}
                    onChange={(e) => void handleSetRole(u, e.target.value)}
                    disabled={pending !== null || accessFor !== null}
                    aria-label={`Role for ${u.email}`}
                    data-testid={`user-role-select-${u.email}`}
                  >
                    {selected === "" && (
                      <option value="" disabled>
                        Set role…
                      </option>
                    )}
                    {ASSIGNABLE_ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                  <button
                    className="panel__action"
                    onClick={() => openSetup(u)}
                    disabled={pending !== null || setupFor !== null}
                    data-testid={`user-setup-${u.email}`}
                  >
                    Setup link
                  </button>
                  <button
                    className="panel__action"
                    onClick={() => void handleSignOut(u)}
                    disabled={pending !== null || u.disabled}
                    title="Revoke all of this user's login sessions (they can sign in again)"
                    data-testid={`user-signout-${u.email}`}
                  >
                    Sign out
                  </button>
                  <button
                    className="panel__action"
                    onClick={() => void handleClearLockout(u)}
                    disabled={pending !== null}
                    title="Clear TOTP throttle counters (unblock after too many failed second-factor attempts)"
                    data-testid={`user-clear-lockout-${u.email}`}
                  >
                    Reset lockout
                  </button>
                  <button
                    className={`panel__action${u.disabled ? "" : " panel__action--danger"}`}
                    onClick={() => void handleToggle(u)}
                    disabled={pending !== null}
                    data-testid={`user-toggle-${u.email}`}
                  >
                    {pending === u.id ? "…" : u.disabled ? "Enable" : "Disable"}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
