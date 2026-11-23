/**
 * Wrap an async action so that a second call made while the first is still running is DROPPED.
 *
 * **Why this exists.** `handleConnect` was re-entrant across its `await`. The Connect button carries
 * no `disabled` attribute — deliberately, see AccessPanel — so a technician who clicks Connect on
 * machine A and then, during the one POST /sessions round trip, clicks Connect on machine B, runs
 * both bodies to completion. Call #2's `teardown()` happens BEFORE call #1 has assigned
 * `signalingRef`/`transportRef`, so neither call ever closes the other's transport: two agents end
 * up live, each sealing into its own session-scoped audit chain.
 *
 * Every event then funnels into ONE `AuditForwarder`, which binds to whichever chain's event arrives
 * first and skips every event from the other. The losing session's entire central audit trail —
 * recording digests, file-transfer records, backstage denials — is dropped with no error anywhere,
 * because flush failures are swallowed by design. That is the silent total-trail loss loop 91 was
 * written to eliminate, reappearing at connection scope.
 *
 * **Dropping, not queueing, is the right policy here.** These calls are a human clicking a button;
 * a queued second connect would tear down the session they just watched come up, moments later and
 * with no further input — worse than ignoring the click. The guard is also the honest layer for it:
 * disabling the button would only narrow the window, since the race is between two async bodies and
 * not between two renders.
 *
 * Extracted from `App.tsx` and exported for the same reason `auditSessionIdFor` was: the vitest
 * config does not collect `.tsx`, so a guard defined inline there could not be tested at all — and
 * this one has no visible symptom when it fails.
 */
/**
 * Where the in-flight bit lives. Pass a caller-owned object (a React `useRef` value is the natural
 * one) to make the guard survive the wrapper being rebuilt.
 *
 * **This parameter is not decoration.** The default keeps the flag in the wrapper's closure, so a
 * wrapper recreated by `useMemo`/`useCallback` starts fresh and the guard silently stops guarding.
 * That is one `useCallback` dependency away at all times: `connectImpl` is stable only because
 * `teardown` and `openSessionAuditForwarder` are both `useCallback(…, [])`, and nothing fails if
 * someone later adds a changing dependency. A defence whose failure mode is invisible should not
 * rest on a condition held somewhere else in the file.
 */
export interface InFlightGate {
  running: boolean;
}

export function onceAtATime<A extends unknown[]>(
  fn: (...args: A) => Promise<void>,
  onDropped?: (...args: A) => void,
  gate: InFlightGate = { running: false },
): (...args: A) => Promise<void> {
  return async (...args: A): Promise<void> => {
    if (gate.running) {
      onDropped?.(...args);
      return;
    }
    gate.running = true;
    try {
      await fn(...args);
    } finally {
      // `finally`, so a throwing action does not wedge the wrapper shut forever. `handleConnect`
      // handles its own failures and resolves, but `acquireBrokeredSession` can reject before that
      // point is reached — and a guard that latched on would leave Connect permanently dead with
      // nothing on screen to say why.
      gate.running = false;
    }
  };
}
