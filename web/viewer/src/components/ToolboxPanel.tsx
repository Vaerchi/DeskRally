/**
 * Toolbox area (docs/design-shared-toolbox.md): the caller's saved scripts — the tenant's SHARED items
 * (changed only with manage_toolbox) and the caller's own PERSONAL items — with create / edit / delete.
 * Scripts run inside ordinary sessions, individually or through the bulk-run dialog.
 *
 * The server decides everything (visibility, who may change what, size limits, version conflicts);
 * this panel mirrors its limits so an operator sees them while typing, and reports its refusals
 * verbatim. One save or delete at a time (synchronous guard), and only the newest listing applies.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { formatIsoUtc } from "../backstage/panels";
import type { ConsoleApi, ToolboxItem, ToolboxItemInput, ToolboxListing, ToolboxRunAs, ToolboxScope, ToolboxShell } from "../lib/console_api";
import { createLatestWins } from "../lib/latest_wins";
import type { BulkTask, OpenBulkCore } from "../lib/bulk_run";
import { BulkRunDialog } from "./BulkRunDialog";

export interface ToolboxPanelProps {
  api: ConsoleApi;
  /** Builds the per-device core factory for a bulk run, given a short session-note label and a fresh
   *  bulk id. Absent in previews/tests that do not wire the transport (bulk entry points are hidden). */
  openBulkCore?: (label: string, bulkId: string) => OpenBulkCore;
}

/** UTF-8 byte length (PowerShell's limit) and UTF-16 unit length (cmd's limit, = JS string length). */
export function toolboxBodySize(shell: ToolboxShell, body: string): number {
  return shell === "powershell" ? new TextEncoder().encode(body).length : body.length;
}

/** The client-side mirror of the server's shape rules; the server re-checks everything. */
export function toolboxBodyProblem(shell: ToolboxShell, body: string, limits: { maxPowerShellBytes: number; maxCmdUnits: number }): string | null {
  if (body.trim() === "") return "The script is empty.";
  if (body.includes("\u0000")) return "The script must not contain NUL characters.";
  if (shell === "cmd") {
    if (/[\r\n]/.test(body)) return "A cmd item is a single line.";
    if (body.length > limits.maxCmdUnits) return `A cmd line is at most ${limits.maxCmdUnits} characters.`;
  } else if (toolboxBodySize(shell, body) > limits.maxPowerShellBytes) {
    return `A PowerShell script is at most ${limits.maxPowerShellBytes} bytes.`;
  }
  return null;
}

export function filterToolboxItems(items: readonly ToolboxItem[], query: string): readonly ToolboxItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items.filter((it) => it.name.toLowerCase().includes(q) || it.description.toLowerCase().includes(q));
}

interface Draft extends ToolboxItemInput {
  scope: ToolboxScope;
}

const EMPTY_DRAFT: Draft = { name: "", description: "", shell: "powershell", run_as: "system", body: "", scope: "personal" };

export function ToolboxPanel({ api, openBulkCore }: ToolboxPanelProps) {
  const [bulk, setBulk] = useState<{ task?: BulkTask; compose: boolean } | null>(null);
  const fileBulkInput = useRef<HTMLInputElement>(null);
  const [listing, setListing] = useState<ToolboxListing | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  // The editor: `editing` is the item being edited (null = creating a new one); `draft` its fields.
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<ToolboxItem | null>(null);
  const [draft, setDraft] = useState<Draft>(EMPTY_DRAFT);
  const [formError, setFormError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<ToolboxItem | null>(null);

  // One mutation at a time, decided synchronously (a double click cannot send twice).
  const mutating = useRef(false);
  const [saving, setSaving] = useState(false);

  const listGuard = useRef(createLatestWins());
  const mounted = useRef(true);
  useEffect(() => {
    const guard = listGuard.current;
    mounted.current = true;
    return () => {
      mounted.current = false;
      guard.invalidate();
    };
  }, []);

  const refresh = useCallback(async () => {
    const token = listGuard.current.begin();
    setBusy(true);
    setError(null);
    try {
      const l = await api.listToolbox();
      if (listGuard.current.isCurrent(token)) setListing(l);
    } catch (e) {
      if (listGuard.current.isCurrent(token)) setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (listGuard.current.isCurrent(token)) setBusy(false);
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const limits = { maxPowerShellBytes: listing?.maxPowerShellBytes ?? 16384, maxCmdUnits: listing?.maxCmdUnits ?? 7800 };
  const canManageShared = listing?.canManageShared ?? false;

  /** May the caller change this item? (The server enforces it; this only hides dead controls.) */
  const canChange = (it: ToolboxItem) => (it.scope === "shared" ? canManageShared : it.mine);

  const openNew = () => {
    if (mutating.current) return;
    setEditing(null);
    setDraft({ ...EMPTY_DRAFT, scope: canManageShared ? "shared" : "personal" });
    setFormError(null);
    setEditorOpen(true);
  };

  const openEdit = (it: ToolboxItem) => {
    if (mutating.current) return;
    setEditing(it);
    setDraft({ name: it.name, description: it.description, shell: it.shell, run_as: it.run_as, body: it.body, scope: it.scope });
    setFormError(null);
    setEditorOpen(true);
  };

  const save = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (mutating.current) return;
      const problem = draft.name.trim() === "" ? "A name is required." : toolboxBodyProblem(draft.shell, draft.body, limits);
      if (problem) {
        setFormError(problem);
        return;
      }
      mutating.current = true;
      setSaving(true);
      setFormError(null);
      const input: ToolboxItemInput = {
        name: draft.name,
        description: draft.description,
        shell: draft.shell,
        run_as: draft.run_as,
        body: draft.body,
      };
      try {
        if (editing) await api.updateToolboxItem(editing.id, editing.version, input);
        else await api.createToolboxItem(draft.scope, input);
        if (!mounted.current) return;
        setEditorOpen(false);
        setEditing(null);
        void refresh();
      } catch (err) {
        if (mounted.current) setFormError(err instanceof Error ? err.message : String(err));
      } finally {
        mutating.current = false;
        if (mounted.current) setSaving(false);
      }
    },
    [api, draft, editing, limits, refresh],
  );

  const doDelete = useCallback(async () => {
    const it = confirmDelete;
    if (!it || mutating.current) return;
    mutating.current = true;
    setSaving(true);
    try {
      await api.deleteToolboxItem(it.id, it.version);
      if (!mounted.current) return;
      setConfirmDelete(null);
      void refresh();
    } catch (err) {
      if (mounted.current) setError(err instanceof Error ? err.message : String(err));
    } finally {
      mutating.current = false;
      if (mounted.current) setSaving(false);
    }
  }, [api, confirmDelete, refresh]);

  const items = useMemo(() => filterToolboxItems(listing?.items ?? [], query), [listing, query]);
  const size = toolboxBodySize(draft.shell, draft.body);
  const sizeLimit = draft.shell === "powershell" ? limits.maxPowerShellBytes : limits.maxCmdUnits;
  const sizeUnit = draft.shell === "powershell" ? "bytes" : "characters (UTF-16 units)";

  return (
    <div className="panel panel--toolbox">
      {bulk && openBulkCore && <BulkRunDialog api={api} task={bulk.task} compose={bulk.compose} openBulkCore={openBulkCore} onClose={() => setBulk(null)} />}
      {editorOpen && (
        <form className="panel__form" onSubmit={(e) => void save(e)} aria-label={editing ? "Edit script" : "New script"} data-testid="toolbox-editor">
          <span className="panel__toolbar-title">{editing ? `Edit ${editing.name}` : "New script"}</span>
          <label className="panel__toolbar-field">
            Name
            <input value={draft.name} maxLength={120} onChange={(e) => setDraft({ ...draft, name: e.target.value })} data-testid="toolbox-name" disabled={saving} />
          </label>
          <label className="panel__toolbar-field">
            Description
            <input value={draft.description} maxLength={1000} onChange={(e) => setDraft({ ...draft, description: e.target.value })} data-testid="toolbox-description" disabled={saving} />
          </label>
          {!editing && (
            <label className="panel__toolbar-field">
              Scope
              <select value={draft.scope} onChange={(e) => setDraft({ ...draft, scope: e.target.value as ToolboxScope })} data-testid="toolbox-scope" disabled={saving}>
                <option value="personal">Personal (only me)</option>
                {canManageShared && <option value="shared">Shared (everyone)</option>}
              </select>
            </label>
          )}
          <label className="panel__toolbar-field">
            Shell
            <select value={draft.shell} onChange={(e) => setDraft({ ...draft, shell: e.target.value as ToolboxShell })} data-testid="toolbox-shell" disabled={saving}>
              <option value="powershell">PowerShell</option>
              <option value="cmd">cmd (one line)</option>
            </select>
          </label>
          <label className="panel__toolbar-field">
            Run as
            <select value={draft.run_as} onChange={(e) => setDraft({ ...draft, run_as: e.target.value as ToolboxRunAs })} data-testid="toolbox-runas" disabled={saving}>
              <option value="system">SYSTEM</option>
              <option value="user">Signed-in user</option>
            </select>
          </label>
          <label className="panel__toolbar-field panel__toolbar-field--wide">
            Script
            <textarea
              className="panel__code"
              rows={draft.shell === "cmd" ? 2 : 12}
              spellCheck={false}
              value={draft.body}
              onChange={(e) => setDraft({ ...draft, body: e.target.value })}
              data-testid="toolbox-body"
              disabled={saving}
            />
          </label>
          <span className="panel__hint" data-testid="toolbox-size" data-over={size > sizeLimit}>
            {size} / {sizeLimit} {sizeUnit}. Runs hidden, at most 30 s; output is capped at 64 KiB per stream.
          </span>
          <button className="panel__action" type="submit" disabled={saving} data-testid="toolbox-save">
            {saving ? "Saving…" : "Save"}
          </button>
          <button className="panel__action" type="button" onClick={() => setEditorOpen(false)} disabled={saving}>
            Cancel
          </button>
          {formError && (
            <span className="panel__toolbar-error" role="alert" data-testid="toolbox-form-error">
              {formError}
            </span>
          )}
        </form>
      )}

      {confirmDelete && (
        <div className="panel__form" role="group" aria-label="Delete script" data-testid="toolbox-confirm-delete">
          <span>Delete “{confirmDelete.name}”? This cannot be undone.</span>
          <button className="panel__action" onClick={() => void doDelete()} disabled={saving} data-testid="toolbox-delete-confirm">
            Delete
          </button>
          <button className="panel__action" onClick={() => setConfirmDelete(null)} disabled={saving}>
            Cancel
          </button>
        </div>
      )}

      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Toolbox</span>
        <input
          type="search"
          className="panel__search"
          placeholder="Search name or description…"
          aria-label="Search scripts"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          data-testid="toolbox-search"
        />
        <button className="panel__action" onClick={openNew} disabled={saving} data-testid="toolbox-new">
          New script
        </button>
        {openBulkCore && (
          <button className="panel__action" onClick={() => setBulk({ compose: true })} data-testid="toolbox-adhoc-bulk">
            Run a command on machines…
          </button>
        )}
        {openBulkCore && (
          <>
            <button className="panel__action" onClick={() => fileBulkInput.current?.click()} data-testid="toolbox-file-bulk">
              Send a file to machines…
            </button>
            <input
              ref={fileBulkInput}
              type="file"
              data-testid="toolbox-file-input"
              style={{ display: "none" }}
              onChange={async (e) => {
                const file = e.target.files?.[0];
                e.target.value = ""; // allow re-selecting the same file later
                if (!file) return;
                const bytes = new Uint8Array(await file.arrayBuffer());
                setBulk({ task: { kind: "upload", name: file.name, bytes }, compose: false });
              }}
            />
          </>
        )}
        <button className="panel__action" onClick={() => void refresh()} disabled={busy}>
          {busy ? "Loading…" : "Refresh"}
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="toolbox-error">
            {error}
          </span>
        )}
      </div>
      <table className="panel__table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Scope</th>
            <th>Shell</th>
            <th>Run as</th>
            <th>Updated (UTC)</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {items.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={6}>
                {busy ? "Loading…" : query.trim() ? "No scripts match this search." : "No saved scripts yet."}
              </td>
            </tr>
          )}
          {items.map((it) => (
            <tr key={it.id} data-testid={`toolbox-row-${it.name}`}>
              <td className="panel__name" title={it.description}>
                {it.name}
              </td>
              <td>{it.scope === "shared" ? "Shared" : "Personal"}</td>
              <td className="panel__mono">{it.shell === "powershell" ? "PowerShell" : "cmd"}</td>
              <td>{it.run_as === "user" ? "Signed-in user" : "SYSTEM"}</td>
              <td className="panel__mono">{formatIsoUtc(it.updated_at)}</td>
              <td>
                {openBulkCore && (
                  <button className="panel__action" data-testid={`toolbox-bulk-${it.id}`} onClick={() => {
                    setBulk({ task: { kind: "toolbox", item: { ...it } }, compose: false });
                  }}>
                    Run on machines…
                  </button>
                )}
                {canChange(it) && (
                  <>
                    <button className="panel__action" onClick={() => openEdit(it)} disabled={saving}>
                      Edit
                    </button>
                    <button className="panel__action" onClick={() => setConfirmDelete(it)} disabled={saving}>
                      Delete
                    </button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
