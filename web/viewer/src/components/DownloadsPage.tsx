import { RallyMark } from "./RallyIdentity";
import { useEffect, useState } from "react";
import { desktopDownload } from "../lib/desktop_download";
import { supportDownloadUrl } from "../lib/support_download";

export function DownloadsPage() {
  const name = import.meta.env.VITE_PRODUCT_NAME?.trim() || "DeskRally";
  const [desktop, setDesktop] = useState<ReturnType<typeof desktopDownload>>(null);
  const [loading, setLoading] = useState(true);
  const [attempt, setAttempt] = useState(0);
  const support = supportDownloadUrl(import.meta.env.VITE_SUPPORT_DOWNLOAD_URL);
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true); setDesktop(null);
    const timeout = setTimeout(() => controller.abort(), 8000);
    void fetch("/download/client/manifest.json", { signal: controller.signal, cache: "no-store" })
      .then(async response => {
        if (!response.ok) throw new Error("unavailable");
        const result = desktopDownload(await response.json(), window.location.origin);
        if (active) setDesktop(result);
      }).catch(() => { if (active) setDesktop(null); })
      .finally(() => { clearTimeout(timeout); if (active) setLoading(false); });
    return () => { active = false; controller.abort(); clearTimeout(timeout); };
  }, [attempt]);
  return <div className="join downloads">
    <header className="join__topbar">
      <a className="join__brand" href="/"><RallyMark />{name}</a>
      <span className="join__brandby">Remote support</span>
      <a href="/docs">Server documentation</a>
      <a className="join__signin" href="/console">Technician sign in</a>
    </header>
    <main className="downloads__main">
      <h1>Downloads</h1>
      <p>Choose the Windows app for the computer you are using.</p>
      <div className="downloads__grid">
        <section className="downloads__card" aria-labelledby="desktop-download-title">
          <h2 id="desktop-download-title">Desktop app</h2>
          <p>For technicians connecting to and managing remote computers.</p>
          {loading ? <p role="status">Checking the current release…</p> : desktop ? <>
            <a className="join__downloadbtn" href={desktop.url} download>Download Windows desktop app</a>
            <p className="join__fineprint">Version {desktop.version}</p>
          </> : <><p role="status">The desktop download is temporarily unavailable.</p><button onClick={() => setAttempt(n => n + 1)}>Try again</button></>}
        </section>
        <section className="downloads__card" aria-labelledby="support-download-title">
          <h2 id="support-download-title">One-time support client</h2>
          <p>For a one-time support session. Run it on the computer that needs help and enter the code from your technician.</p>
          {support ? <a className="join__downloadbtn" href={support} download>Download Windows support client</a> : <p>The support download is not available on this site yet.</p>}
          <p className="join__fineprint">Only run this at the request of a technician you contacted for help.</p>
          <a href="/join">Join a support session</a>
        </section>
        <section className="downloads__card" aria-labelledby="permanent-download-title">
          <h2 id="permanent-download-title">Unattended access agent</h2>
          <p>For unattended access. Sign in, select a machine group, and download an installer prepared for your account.</p>
          <a className="join__downloadbtn" href="/console?area=enrollment">Get unattended access agent</a>
          <p className="join__fineprint">Windows administrator approval is required to install it.</p>
        </section>
      </div>
    </main>
  </div>;
}
