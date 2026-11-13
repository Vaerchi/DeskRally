import { lazy, StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { DownloadsPage } from "./components/DownloadsPage";
import { JoinPage } from "./components/JoinPage";
import { SetPasswordPage } from "./components/SetPasswordPage";
import { parseSetupToken } from "./lib/setup_link";
import { SETUP_LINK_PATH } from "./lib/setup_link";
import "./index.css";

// The full technical references belong to the documentation route, not every console session.
const DocsPage = lazy(() => import("./components/DocsPage").then(module => ({ default: module.DocsPage })));

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("#root element not found");

// Path routing without a router: a few PUBLIC landing pages ride the URL, everything else is the
// operator console. Vite's dev server (and any SPA-fallback static host) serves index.html for these
// paths; the secret always rides the FRAGMENT so it never reaches server logs, and we read it here
// client-side only.
//   /join#<code>          the guest landing page the control plane's join_url points at (docs/12 §9)
//   /set-password#<token> the self-service credential-setup page a Users-panel setup link points at
const path = window.location.pathname;
const fragment = window.location.hash;
const isJoin = path === "/join" || path === "/join.html";
const isSetPassword = path === SETUP_LINK_PATH || path === `${SETUP_LINK_PATH}.html`;

function route() {
  if (path === "/docs" || path.startsWith("/docs/")) return <Suspense fallback={<p role="status">Loading documentation…</p>}><DocsPage /></Suspense>;
  if (path === "/downloads" || path === "/downloads/") return <DownloadsPage />;
  if (isJoin)
    return (
      <JoinPage
        code={fragment.replace(/^#/, "")}
        productName={import.meta.env.VITE_PRODUCT_NAME}
        // The default host's origin (docs/66 2i): a tenant-branded page links its attribution to <origin>/docs and is
        // the neutral page without it. main.tsx is the real /join entry; App.tsx's copy is the fallback route.
        defaultOrigin={import.meta.env.VITE_DEFAULT_ORIGIN}
        // The download block renders only when BOTH are set, which step 18's publish guard gates:
        // an unset URL keeps the shipped page download-free (see support_download.ts).
        download={{
          url: import.meta.env.VITE_SUPPORT_DOWNLOAD_URL,
          sha256: import.meta.env.VITE_SUPPORT_DOWNLOAD_SHA256,
        }}
        bundleEnabled={import.meta.env.VITE_SUPPORT_BUNDLE_ENABLED === "true"}
      />
    );
  if (isSetPassword) return <SetPasswordPage token={parseSetupToken(fragment)} />;
  return <App />;
}

createRoot(rootEl).render(<StrictMode>{route()}</StrictMode>);
