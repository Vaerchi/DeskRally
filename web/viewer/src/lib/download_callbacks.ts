/**
 * Pure download-wiring helpers extracted from App.tsx so they can be imported and tested directly.
 *
 * The App component uses these functions inside its `useCallback` closures. Extracting them here
 * means tests exercise the ACTUAL logic rather than copies — mutations to these functions will
 * break the tests, whereas mutations to a copy would not.
 */

import { pathRelativeTo } from "./filepath";

/**
 * Core of App.tsx's `downloadFromBrowse` callback.
 *
 * `transferRoot` is the agent-advertised root from `agentTransferDirRef.current`. When `undefined`
 * (the agent has not sent a `TransferDir` message — typically an older agent with a possibly
 * different configured root), the function returns WITHOUT requesting anything. The UI is expected
 * to suppress the download affordance in this case; this guard is defense-in-depth.
 *
 * The path safety contract is:
 *   - The agent enforces canonical containment in its own `serve_download` handler.
 *   - `pathRelativeTo` is the UI-side gate: only files inside `transferRoot` produce a non-null
 *     relative path. Files outside are silently dropped.
 *
 * NOT falling back to `DEFAULT_TRANSFER_DIR` when `transferRoot` is undefined is intentional:
 * an old agent may have a custom root; presenting the default would silently request a file from
 * the wrong directory (e.g., UI shows C:\rmt-agent\transfers\report.pdf but the agent serves
 * D:\custom\report.pdf).
 */
export function downloadFileFromBrowse(
  absolutePath: string,
  transferRoot: string | undefined,
  fileTransferClient: { request: (rel: string) => string } | null,
): { rel: string; requestId: string } | null {
  if (transferRoot === undefined) return null;
  if (!fileTransferClient) return null;
  const rel = pathRelativeTo(transferRoot, absolutePath);
  if (rel === null) return null;
  const requestId = fileTransferClient.request(rel);
  return { rel, requestId };
}

/**
 * Core of App.tsx's `onDownloadFile` prop expression.
 *
 * Returns the download callback when the capability gate passes, `undefined` when it explicitly
 * blocks. The `?. !== false` expression for `grantCapabilities`:
 *   - `null` (no grant minted yet) → passes through (visible by default for direct-connect / dev)
 *   - A set that INCLUDES `file_download` → passes through
 *   - A set that does NOT include `file_download` → returns `undefined` (suppressed)
 *
 * The root-known check (`transferRoot !== undefined`) is a SEPARATE condition: even when no grant
 * has been minted, download affordances are suppressed when the transfer root is unknown, because
 * there is no safe directory to offer.
 */
export function gateUploadOnCapability(
  grantCapabilities: ReadonlySet<string> | null,
  transferRoot: string | undefined,
  uploadFn: (files: File[]) => void,
): ((files: File[]) => void) | undefined {
  // Same reading as the download gate below: an unknown root offers nothing, a grant that EXPLICITLY
  // omits the capability hides the action, and no grant yet (dev/direct-connect) leaves it visible.
  // The agent still enforces `Capability::FileUpload` on every Offer; this only avoids offering an
  // action the session is known to be refused.
  if (transferRoot === undefined) return undefined;
  return grantCapabilities?.has("file_upload") !== false ? uploadFn : undefined;
}

export function gateDownloadOnCapability(
  grantCapabilities: ReadonlySet<string> | null,
  transferRoot: string | undefined,
  downloadFn: (path: string) => void,
): ((path: string) => void) | undefined {
  if (transferRoot === undefined) return undefined;
  return grantCapabilities?.has("file_download") !== false ? downloadFn : undefined;
}
