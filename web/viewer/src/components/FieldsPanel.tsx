import { useEffect, useState, type FormEvent } from "react";
import { ConsoleApiError, type ConsoleApi, type MachineField, type MachineFieldInput, type MachineFieldList, type MachineFieldReport } from "../lib/console_api";
import { fieldsInPositionOrder } from "../lib/machine_fields";

const newField: MachineFieldInput = { key: "", label: "", type: "text", choices: null };
const fieldTypes = ["text", "number", "date", "choice", "boolean"] as const;
const errorMessage = (error: unknown) => error instanceof Error ? error.message : String(error);

export function FieldsPanel({ api, canViewMachines }: { api: ConsoleApi; canViewMachines: boolean }) {
  const [list, setList] = useState<MachineFieldList>();
  const [editing, setEditing] = useState<MachineField>();
  const [draft, setDraft] = useState(newField);
  const [choices, setChoices] = useState("");
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const [draggedKey, setDraggedKey] = useState<string>();
  const [reportGeneration, setReportGeneration] = useState(0);
  const fields = list?.fields ?? [];

  const readList = async () => {
    const snapshot = await api.listMachineFields();
    return { ...snapshot, fields: fieldsInPositionOrder(snapshot.fields) };
  };

  useEffect(() => {
    let current = true;
    setList(undefined);
    setMessage("");
    void readList().then(
      (snapshot) => { if (current) setList(snapshot); },
      (error) => { if (current) setMessage(errorMessage(error)); },
    );
    return () => { current = false; };
  }, [api]);

  const resetEditor = () => {
    setEditing(undefined);
    setDraft(newField);
    setChoices("");
  };

  const mutate = async (action: () => Promise<void>) => {
    if (pending) return;
    setPending(true);
    setMessage("");
    let notice = "";
    try {
      try {
        await action();
      } catch (error) {
        if (!(error instanceof ConsoleApiError) || (error.status !== 409 && error.status !== 404)) throw error;
        notice = "Fields changed. The list was reloaded. Review the latest fields and try again.";
      }
      resetEditor();
      setList(undefined);
      setList(await readList());
      setMessage(notice);
      setReportGeneration((generation) => generation + 1);
    } catch (error) {
      setMessage(notice ? `Fields changed. Reload failed. ${errorMessage(error)}` : errorMessage(error));
    } finally {
      setPending(false);
    }
  };

  const save = (event: FormEvent) => {
    event.preventDefault();
    const input = { ...draft, choices: draft.type === "choice" ? choices.split("\n") : null };
    void mutate(async () => {
      if (editing) await api.updateMachineField({ ...input, id: editing.id, version: editing.version });
      else await api.createMachineField(input);
    });
  };

  const move = (key: string, target: number) => {
    if (!list || target < 0 || target >= fields.length) return;
    const keys = fields.map((field) => field.key);
    const from = keys.indexOf(key);
    if (from < 0 || from === target) return;
    keys.splice(from, 1);
    keys.splice(target, 0, key);
    void mutate(async () => { await api.reorderMachineFields(keys, list.order_revision); });
  };

  return (
    <section className="panel panel--fields">
      <h2>Fields</h2>
      <p>Canonical filters match stored values exactly. A legacy value such as <code>1.00</code> only matches that spelling until it is repaired. Repairing values can change membership in saved dynamic groups.</p>
      {message && <p role="alert">{message}</p>}
      {!list && message && (
        <button className="panel__action" disabled={pending} onClick={() => void mutate(async () => {})}>Reload fields</button>
      )}
      {list && (
        <>
          <form className="panel__form" onSubmit={save}>
            <fieldset disabled={pending}>
              <legend>{editing ? `Edit ${editing.label}` : "Create field"}</legend>
              <label>Key <input value={draft.key} required readOnly={!!editing} onChange={(e) => setDraft({ ...draft, key: e.target.value })} /></label>
              <label>Label <input value={draft.label} required onChange={(e) => setDraft({ ...draft, label: e.target.value })} /></label>
              <label>Type <select value={draft.type} onChange={(e) => setDraft({ ...draft, type: e.target.value as MachineFieldInput["type"] })}>
                {fieldTypes.map((type) => <option key={type}>{type}</option>)}
              </select></label>
              {draft.type === "choice" && <label>Choices (one per line) <textarea value={choices} required onChange={(e) => setChoices(e.target.value)} /></label>}
              <button className="panel__action" type="submit">{editing ? "Save field" : "Create field"}</button>
              {editing && <button className="panel__action" type="button" onClick={resetEditor}>Cancel edit</button>}
            </fieldset>
          </form>
          <table className="panel__table">
            <thead><tr><th>Label</th><th>Key</th><th>Type</th><th>Nonconforming</th><th>Actions</th></tr></thead>
            <tbody>
              {fields.map((field, index) => (
                <tr key={field.id} draggable={!pending}
                  onDragStart={(e) => {
                    setDraggedKey(field.key);
                    e.dataTransfer.setData("text/plain", field.key);
                    e.dataTransfer.effectAllowed = "move";
                  }}
                  onDragEnd={() => setDraggedKey(undefined)}
                  onDragOver={(e) => { if (draggedKey !== undefined && !pending) e.preventDefault(); }}
                  onDrop={(e) => {
                    e.preventDefault();
                    if (draggedKey !== undefined) move(draggedKey, index);
                    setDraggedKey(undefined);
                  }}>
                  <td>{field.label}</td><td>{field.key}</td><td>{field.type}</td>
                  <td>{canViewMachines
                    ? <FieldReport key={`${field.version}/${reportGeneration}`} api={api} fieldKey={field.key} />
                    : "Unavailable"}</td>
                  <td>
                    <button className="panel__action" disabled={pending || index === 0} aria-label={`Move ${field.label} up`} onClick={() => move(field.key, index - 1)}>↑</button>
                    <button className="panel__action" disabled={pending || index === fields.length - 1} aria-label={`Move ${field.label} down`} onClick={() => move(field.key, index + 1)}>↓</button>
                    <button className="panel__action" disabled={pending} aria-label={`Edit ${field.label}`} onClick={() => {
                      setEditing(field);
                      setDraft({ key: field.key, label: field.label, type: field.type, choices: field.choices });
                      setChoices(field.choices?.join("\n") ?? "");
                    }}>Edit</button>
                    <button className="panel__action panel__action--danger" disabled={pending} aria-label={`Delete ${field.label}`} onClick={() => {
                      if (window.confirm(`Delete the definition for ${field.label}? Stored properties will be kept.`)) {
                        void mutate(() => api.deleteMachineField(field.key, field));
                      }
                    }}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {!list && !message && <p role="status">Loading fields…</p>}
    </section>
  );
}

function FieldReport({ api, fieldKey }: { api: ConsoleApi; fieldKey: string }) {
  const [page, setPage] = useState<MachineFieldReport>();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let current = true;
    void api.reportMachineField(fieldKey).then(
      (result) => { if (current) setPage(result); },
      (failure) => { if (current) setError(errorMessage(failure)); },
    ).finally(() => { if (current) setPending(false); });
    return () => { current = false; };
  }, [api, fieldKey]);

  const next = async (cursor?: string) => {
    setPending(true);
    setError("");
    try {
      setPage(await api.reportMachineField(fieldKey, cursor));
    } catch (failure) {
      if (failure instanceof ConsoleApiError && failure.status === 409) {
        setPage(undefined);
        setError("The field changed. Restart the report.");
      } else {
        setError(errorMessage(failure));
      }
    } finally {
      setPending(false);
    }
  };

  return (
    <>
      {page && <span>{page.total} <button className="panel__action" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "Hide" : "Show"}</button></span>}
      {error && <span role="alert">{error} {!page && <button disabled={pending} onClick={() => void next()}>Restart report</button>}</span>}
      {pending && <span role="status">Loading…</span>}
      {open && page && (
        <div>
          {page.machines.length === 0 && <span>No nonconforming values.</span>}
          <ul>{page.machines.map((machine) => <li key={machine.machine_id}>{machine.machine_name || machine.machine_id} <code>{JSON.stringify(machine.value)}</code></li>)}</ul>
          <button className="panel__action" disabled={pending} onClick={() => void next()}>First page</button>
          {page.next_cursor && <button className="panel__action" disabled={pending} onClick={() => void next(page.next_cursor)}>Next page</button>}
        </div>
      )}
    </>
  );
}

