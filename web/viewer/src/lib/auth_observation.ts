/** Per-request timeout for the auth-status observation poll (ms). */
export const AUTH_CHECK_TIMEOUT_MS = 25_000;

/**
 * Fires one auth-status check with a bounded per-request timeout.
 *
 * Returns the Response on success, or null on any error (network failure,
 * per-request timeout, or cleanup abort). Null is never treated as expiry
 * — only a 401 response handled by the caller's fetchImpl triggers expiry.
 */
export async function boundedAuthCheck(
  url: string,
  cleanupSignal: AbortSignal,
  timeoutMs: number,
  fetchImpl: (input: string, init: RequestInit) => Promise<Response>,
): Promise<Response | null> {
  if (cleanupSignal.aborted) return null;
  const ctrl = new AbortController();
  const timeoutId = setTimeout(() => ctrl.abort(), timeoutMs);
  const onCleanup = () => ctrl.abort();
  cleanupSignal.addEventListener("abort", onCleanup, { once: true });
  try {
    return await fetchImpl(url, { credentials: "include", cache: "no-store", signal: ctrl.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
    cleanupSignal.removeEventListener("abort", onCleanup);
  }
}
