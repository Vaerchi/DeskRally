import { useEffect, useRef, useState } from "react";
import type { ConsoleApi } from "../lib/console_api";

/** One-use enrollment is issued only on a deliberate click, never on render/poll. */
export function ManagedInstallDownload({ api, groupId }: { api: ConsoleApi; groupId: string }) {
  const [available, setAvailable] = useState(false);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const request = useRef<AbortController | null>(null);
  useEffect(() => {
    let active = true;
    setAvailable(false); setWarnings([]);
    void api.managedInstallerAvailable().then((ready) => { if (active) setAvailable(ready); }, () => {});
    // Deployment-pass mode: tell admins before (and after) the pass lapses, since installs then fail.
    void api.managedInstallerWarnings?.().then((w) => { if (active) setWarnings(w); }, () => {});
    return () => { active = false; };
  }, [api]);
  useEffect(() => {
    setBusy(false); setMessage("");
    return () => { request.current?.abort(); request.current = null; };
  }, [api, groupId]);

  async function download() {
    if (!available || !groupId || request.current) return;
    const controller = new AbortController(); request.current = controller;
    const timeout = setTimeout(() => controller.abort(), 120_000);
    setBusy(true); setMessage("");
    try {
      const blob = await api.downloadManagedInstaller(groupId, controller.signal);
      if (controller.signal.aborted) return;
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a"); link.href = url; link.download = "DeskRally-Install.zip";
      document.body.appendChild(link);
      try { link.click(); } finally { link.remove(); setTimeout(() => URL.revokeObjectURL(url), 30_000); }
      setMessage("Download prepared. Extract all files and open DeskRallySetup.exe within 15 minutes. Delete the bundle after installation.");
    } catch {
      if (request.current === controller) setMessage("Could not download the installer. Try again to get a fresh bundle.");
    } finally {
      clearTimeout(timeout);
      if (request.current === controller) { request.current = null; setBusy(false); }
    }
  }

  return <div className="panel__detail" data-testid="managed-install">
    <p>Install permanent access on a Windows computer. The download includes its account setup; no server addresses or tokens to enter.</p>
    <button className="panel__action" type="button" disabled={!available || !groupId || busy} onClick={() => void download()}>
      {busy ? "Preparing installer…" : "Download Windows installer"}
    </button>
    {!available && <p>The preconfigured installer is not available on this server yet.</p>}
    {available && <p>This private download installs one computer in the selected group and expires in 15 minutes. Windows administrator approval is required.</p>}
    {warnings.map((w) => <p key={w} role="alert" data-testid="managed-install-warning">{w}</p>)}
    {message && <p role="status">{message}</p>}
  </div>;
}
