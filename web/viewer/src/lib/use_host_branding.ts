/**
 * React side of the guest page's host branding (docs/66 stage 2). The logic lives in `host_branding.ts`.
 */

import { useEffect, useState } from "react";
import { NEUTRAL_BRAND, fetchHostBranding, type HostBrand } from "./host_branding";

export interface HostBrandingState {
  /** False until the single lookup has finished (or timed out, or failed). */
  settled: boolean;
  /** The brand to apply. NEUTRAL_BRAND while loading and after any failure: a guest never sees a half-applied brand. */
  brand: HostBrand;
}

const LOADING: HostBrandingState = { settled: false, brand: NEUTRAL_BRAND };

/**
 * Asks the control plane, once per mount, which brand the host the guest opened publishes.
 *
 * The page renders the NEUTRAL skeleton (the page exactly as the deployment ships it) from the first frame and
 * swaps to the brand in ONE state update when, and only when, the whole lookup succeeded. There is no retry: a
 * failure, a timeout or a bad answer leaves the neutral page in place for the life of the page (a reload asks
 * again). Under React StrictMode in development the effect runs twice; the first lookup is abandoned by the
 * cleanup, so at most one result is ever applied.
 */
export function useHostBranding(origin: string): HostBrandingState {
  const [state, setState] = useState<HostBrandingState>(LOADING);
  useEffect(() => {
    const controller = new AbortController();
    let live = true;
    setState((prev) => (prev === LOADING ? prev : LOADING));
    void fetchHostBranding(origin, { signal: controller.signal }).then((brand) => {
      if (live) setState({ settled: true, brand });
    });
    return () => {
      live = false;
      controller.abort();
    };
  }, [origin]);
  return state;
}

/**
 * Puts a tenant's product name in the tab title, as TEXT (the `title` setter never parses markup), and puts
 * the previous title back when the page goes away. A neutral brand leaves the document's own title alone, so
 * an unbranded host sees no change from index.html's `<title>`.
 */
export function useBrandDocumentTitle(name: string): void {
  useEffect(() => {
    if (name === "") return;
    const previous = document.title;
    document.title = name;
    return () => {
      document.title = previous;
    };
  }, [name]);
}
