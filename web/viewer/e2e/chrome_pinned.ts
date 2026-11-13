/**
 * Seeds the session-chrome preference to "pinned" (lib/session_chrome.ts).
 *
 * The product default during a live session is a COLLAPSED top bar behind a small tab (Chrome Remote
 * Desktop style). Every spec written before that change drives the session toolbar and the session
 * menu directly, i.e. the always-visible bar — which is exactly the "pinned" layout a user can choose.
 * Seeding it keeps those specs testing the layout they were written against, while
 * session_chrome.spec.ts covers the collapsed default on its own.
 *
 * Applied to the default context in playwright.config.ts and spread into every `browser.newContext`
 * a spec makes itself (a config-level storageState does not reach those).
 */
export const PINNED_STORAGE = {
  cookies: [],
  origins: [
    {
      origin: "http://127.0.0.1:5173",
      localStorage: [{ name: "deskrally.sessionChrome", value: "pinned" }],
    },
  ],
};

/** Spread into `browser.newContext({ ...PINNED, ... })`. */
export const PINNED = { storageState: PINNED_STORAGE };
