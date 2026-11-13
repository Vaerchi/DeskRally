/**
 * The signaling WebSocket the manual-connect field should offer by default.
 *
 * WHY THIS EXISTS. The field was hard-coded to `ws://127.0.0.1:8080/ws` — the local dev and e2e
 * rendezvous. On the first real deployment that string was what an operator saw on a production
 * console, which reasonably reads as "this console is pointed at localhost". It was only a default,
 * and the brokered path ignores it, but a control surface that describes itself wrongly is a bug
 * whether or not the wrong value is load-bearing.
 *
 * The deployment topology already answers this: Caddy serves the console and the signaling
 * WebSocket from ONE origin, with signaling at `/ws` (deploy/Caddyfile), and the control plane is
 * configured with a `CP_SIGNALING_URL` that must match. So the correct default on a real deployment
 * is derivable from the page's own origin, exactly as the login form's tenant is.
 *
 * Dev keeps the loopback default, because there the console is served by Vite on :5173 while
 * signaling listens separately on :8080 — the one-origin assumption is a property of the Caddy
 * deployment, not of the product.
 */

/** The dev/e2e rendezvous: Vite serves the console, signaling listens on its own port. */
export const DEV_SIGNALING_URL = "ws://127.0.0.1:8080/ws";

/**
 * `wss://<host>/ws` for a deployed console, the loopback default when served locally.
 *
 * `127.0.0.1` counts as local as well as `localhost`: the e2e suite browses `http://127.0.0.1:5173`,
 * and a "fix" that returned `ws://127.0.0.1:5173/ws` there would point every manual connect at the
 * Vite dev server instead of at signaling.
 *
 * The scheme follows the page's: a console on `http://` cannot open a `wss://` socket without a
 * certificate for that host, and one on `https://` cannot open `ws://` at all (mixed content).
 */
export function defaultSignalingUrl(loc: { protocol: string; hostname: string; host: string }): string {
  const local = loc.hostname === "localhost" || loc.hostname === "127.0.0.1" || loc.hostname === "::1";
  if (local) return DEV_SIGNALING_URL;
  const scheme = loc.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${loc.host}/ws`;
}
