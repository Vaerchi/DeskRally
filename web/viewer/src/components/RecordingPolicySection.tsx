/**
 * Tenant central-recording policy (docs/63 D5), inside the Security panel. Retention 0 (the default) means
 * recordings stay ONLY on the guest machine; a positive value uploads them to the server for that many days.
 *
 * The section appears only when the policy can be read (GET needs manage_tenant or view_recordings); a 403/404
 * (a role without either, or a server without the feature) shows nothing. Saving needs manage_tenant (Owner):
 * the console cannot know the caller's capabilities, so the server's 403 is shown in plain words. The PUT
 * always sends every field (lib/recordings.parsePolicyForm), and turning storage ON needs an explicit confirmation.
 */

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { RecordingsNotBackedUpNotice } from "./RecordingsNotBackedUpNotice";
import { ConsoleApiError, type ConsoleApi } from "../lib/console_api";
import {
  RETENTION_PRESETS,
  STORAGE_OFF_NOTE,
  STORAGE_ON_CONFIRMATION,
  parsePolicyForm,
  policyToForm,
  turnsStorageOn,
  type PolicyForm,
  type RecordingPolicy,
  type RecordingPolicyBody,
} from "../lib/recordings";

export function RecordingPolicySection({ api }: { api: ConsoleApi }) {
  const [policy, setPolicy] = useState<RecordingPolicy | null>(null);
  const [hidden, setHidden] = useState(false);
  const [form, setForm] = useState<PolicyForm | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [pending, setPending] = useState<RecordingPolicyBody | null>(null);
  const seq = useRef(0);

  useEffect(() => {
    const id = ++seq.current;
    void (async () => {
      try {
        const p = await api.getRecordingPolicy();
        if (id !== seq.current) return;
        setPolicy(p);
        setForm(policyToForm(p));
      } catch (e) {
        if (id !== seq.current) return;
        if (e instanceof ConsoleApiError && (e.status === 403 || e.status === 404)) setHidden(true);
        else setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => { seq.current++; };
  }, [api]);

  const commit = useCallback(async (body: RecordingPolicyBody) => {
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      const p = await api.setRecordingPolicy(body);
      setPolicy(p);
      setForm(policyToForm(p));
      setSaved(true);
    } catch (e) {
      if (e instanceof ConsoleApiError && e.status === 403) {
        setError("Only an Owner can change the recording policy.");
      } else {
        setError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      setSaving(false);
      setPending(null);
    }
  }, [api]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (policy === null || form === null) return;
    setSaved(false);
    const parsed = parsePolicyForm(form, policy);
    if (!parsed.ok) {
      setError(parsed.error);
      return;
    }
    setError(null);
    if (turnsStorageOn(policy, parsed.body)) {
      setPending(parsed.body); // the explicit confirmation; nothing is sent yet
      return;
    }
    void commit(parsed.body);
  };

  if (hidden) return null;
  const set = (patch: Partial<PolicyForm>) => { setForm((f) => (f ? { ...f, ...patch } : f)); setSaved(false); };

  return (
    <form className="panel__form" noValidate onSubmit={submit} data-testid="recording-policy-form">
      <span className="panel__toolbar-title">Session recording storage</span>
      {form === null ? (
        <span className="panel__toolbar-note" data-testid="recording-policy-loading">
          {error ?? "Loading…"}
        </span>
      ) : (
        <>
          <span className="panel__toolbar-note" data-testid="recording-policy-state">
            {policy?.enabled
              ? `On: recordings are uploaded to the server and kept for ${policy.retention_days} days.`
              : STORE_OFF_TEXT}
          </span>
          {policy && !policy.storage_available && (
            <span className="panel__toolbar-error" data-testid="recording-policy-unavailable">
              This deployment has no recording storage configured, so nothing is stored whatever is chosen here.
            </span>
          )}
          <fieldset className="panel__toolbar-field" style={{ border: 0, padding: 0 }}>
            <legend>Keep recordings on the server for</legend>
            <label><input type="radio" name="rec-retention" checked={form.retention === "off"} onChange={() => set({ retention: "off" })} data-testid="recording-retention-off" /> Off (0 days)</label>
            {RETENTION_PRESETS.map((d) => (
              <label key={d}>
                <input type="radio" name="rec-retention" checked={form.retention === String(d)} onChange={() => set({ retention: String(d) })} data-testid={`recording-retention-${d}`} /> {d} days
              </label>
            ))}
            <label>
              <input type="radio" name="rec-retention" checked={form.retention === "custom"} onChange={() => set({ retention: "custom" })} data-testid="recording-retention-custom" /> Other
            </label>
            {form.retention === "custom" && (
              <input type="number" min={1} max={365} value={form.customDays} onChange={(e) => set({ customDays: e.target.value })}
                aria-label="Retention in days (1 to 365)" placeholder="1 to 365" data-testid="recording-retention-days" />
            )}
          </fieldset>
          <RecordingsNotBackedUpNotice testId="recording-policy-not-backed-up" />
          <span className="panel__toolbar-note">0 = do not store new recordings: they stay only on the guest machine. Recordings already stored remain here until their deletion date.</span>
          <label className="panel__toolbar-field">
            Largest single recording (MiB, at most 1024)
            <input type="number" min={1} max={1024} step="any" value={form.maxMiB} onChange={(e) => set({ maxMiB: e.target.value })} data-testid="recording-max-mib" />
          </label>
          <label className="panel__toolbar-field">
            Total storage quota (GiB)
            <input type="number" min={0} step="any" value={form.quotaGiB} onChange={(e) => set({ quotaGiB: e.target.value })} data-testid="recording-quota-gib" />
          </label>
          <button className="panel__action" type="submit" disabled={saving || pending !== null} data-testid="recording-policy-save">
            {saving ? "Saving…" : "Save"}
          </button>
          {pending !== null && (
            <span role="alertdialog" aria-label="Confirm turning on recording storage" className="panel__toolbar-note" data-testid="recording-policy-confirm">
              {STORAGE_ON_CONFIRMATION}{" "}
              <button type="button" className="panel__action" onClick={() => void commit(pending)} data-testid="recording-policy-confirm-yes">
                Turn on storage
              </button>{" "}
              <button type="button" className="panel__action" onClick={() => setPending(null)} data-testid="recording-policy-confirm-no">
                Cancel
              </button>
            </span>
          )}
          {saved && <span className="panel__toolbar-note" role="status" data-testid="recording-policy-saved">Saved.</span>}
          {error && <span className="panel__toolbar-error" role="alert" data-testid="recording-policy-error">{error}</span>}
        </>
      )}
    </form>
  );
}

const STORE_OFF_TEXT = STORAGE_OFF_NOTE;
