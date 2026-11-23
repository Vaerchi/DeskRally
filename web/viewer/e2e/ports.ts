/**
 * Ports the e2e specs bind their throwaway signaling + control-plane on.
 *
 * Overridable via env so the no-skip verification harness (`scripts/verify-all.ps1`) can run the
 * whole suite off ports that other software on the developer's box already holds — e.g. a WebUI
 * squatting :8080 makes every :8080 spec skip with "signaling did not come up", which the harness
 * (correctly) treats as a failure. Defaults preserve the historical values so a developer running
 * `npm run test:e2e` by hand needs no env at all.
 *
 * The Vite dev proxy that the console uses to reach the control plane same-origin (`/cp/*`) is
 * pointed by its OWN env var, `CONTROL_PLANE_ORIGIN` (vite.config.ts); the harness sets it to
 * `http://127.0.0.1:${CP_PORT}` so the proxy and the spawned control plane agree.
 *
 * secure_posture.spec.ts deliberately keeps its own fixed 8180/8181 (it must run alongside a
 * developer's dev stack) and does not read these.
 */
export const SIG_PORT = process.env.RMT_E2E_SIG_PORT ?? "8080";
export const CP_PORT = process.env.RMT_E2E_CP_PORT ?? "8081";

/** The signaling WebSocket URL the browser + agent connect to. */
export const SIGNALING_WS = `ws://127.0.0.1:${SIG_PORT}/ws`;
/** The control-plane base URL (spec-side Node fetches; the browser goes through the /cp proxy). */
export const CP_BASE = `http://127.0.0.1:${CP_PORT}`;
