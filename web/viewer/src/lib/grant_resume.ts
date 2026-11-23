/**
 * Re-establishing the backstage grant after a session RESUMES (signaling restart, transport loss).
 *
 * A recovered session is a brand-new brokered session (new control-plane session id, new signaling
 * connection, new agent-side session and dispatcher). The agent starts that dispatcher with no grant
 * and arms it ONLY on `InstallGrant`, so a technician who had "Get access" before the drop lost it
 * silently: file operations failed with "no backstage grant is installed" until they clicked again.
 *
 * This is deliberately NOT a grant cache. A grant is signed for one session and expires; the viewer
 * never keeps or re-sends the old bytes. Resume remembers only the FACT that the technician held a
 * grant, then asks `POST /grant/mint` for a fresh one bound to the NEW session id. The control plane
 * re-checks the technician's authorization at mint time, so a revoked or demoted technician is
 * refused exactly as if they had clicked the button.
 *
 * Extracted from `App.tsx` (a `.tsx` the vitest config does not collect) so the decisions are tested.
 */
import { ControlPlaneError } from "./controlplane";

/** Waits before each retry after a 429 (so at most `length + 1` mint attempts). */
export const GRANT_RESUME_BACKOFF_MS: readonly number[] = [2_000, 6_000, 15_000];

export type GrantResumeOutcome =
  | "skipped" // never held a grant in this session (or nothing to bind to): nothing is done
  | "installed" // a fresh grant was minted and sent
  | "stale" // the session was replaced/closed while minting: nothing was sent
  | "denied" // 401/403: not re-tried; the panel's own "Get access" affordance stays available
  | "gave-up"; // rate-limited past the backoff budget, or another failure: no loop

export interface GrantResumeDeps {
  /** True when the technician held a grant in the session that just ended. */
  hadGrant: boolean;
  /** The NEW control-plane session id to bind the grant to; null/empty means nothing to bind. */
  sessionId: string | null | undefined;
  /** `POST /grant/mint` for the NEW session. Must always mint fresh: never a cached value. */
  mint: (sessionId: string) => Promise<string>;
  /** Frame the minted grant onto the live control channel. */
  install: (signedGrant: string) => void;
  /** False once the session was replaced, torn down or signed out; checked after every await. */
  isCurrent: () => boolean;
  sleep?: (ms: number) => Promise<void>;
  backoffMs?: readonly number[];
  /** Notified of a 401 (the shared auth boundary must return to sign-in). */
  onUnauthorized?: () => void;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export async function resumeGrant(deps: GrantResumeDeps): Promise<GrantResumeOutcome> {
  if (!deps.hadGrant || !deps.sessionId) return "skipped";
  const sleep = deps.sleep ?? defaultSleep;
  const backoff = deps.backoffMs ?? GRANT_RESUME_BACKOFF_MS;
  for (let attempt = 0; ; attempt++) {
    if (!deps.isCurrent()) return "stale";
    let signed: string;
    try {
      signed = await deps.mint(deps.sessionId);
    } catch (e) {
      if (!deps.isCurrent()) return "stale";
      if (e instanceof ControlPlaneError) {
        if (e.status === 401) {
          deps.onUnauthorized?.();
          return "denied";
        }
        if (e.status === 403) return "denied";
        if (e.status === 429 && attempt < backoff.length) {
          await sleep(backoff[attempt]);
          continue;
        }
      }
      return "gave-up";
    }
    if (!deps.isCurrent()) return "stale";
    deps.install(signed);
    return "installed";
  }
}

export type GrantOpKind = "auto" | "manual";

/**
 * ONE in-flight grant operation per session, shared by the automatic resume and the manual
 * "Get access". Ownership is a token: whoever holds the current token may install, and a holder
 * re-checks `owns` after every await and immediately before installing.
 *  - a manual operation always supersedes whatever is in flight (it takes a new token);
 *  - an automatic one never starts while another operation is in flight (`begin` returns null).
 */
export class GrantOpGuard {
  private current: { token: number; kind: GrantOpKind; sessionId: string } | null = null;
  private next = 1;

  begin(kind: GrantOpKind, sessionId: string): number | null {
    if (kind === "auto" && this.current && this.current.sessionId === sessionId) return null;
    const token = this.next++;
    this.current = { token, kind, sessionId };
    return token;
  }
  owns(token: number): boolean {
    return this.current?.token === token;
  }
  end(token: number): void {
    if (this.current?.token === token) this.current = null;
  }
  /** Teardown: every outstanding holder loses ownership. */
  reset(): void {
    this.current = null;
  }
}
