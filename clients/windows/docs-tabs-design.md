# Desktop client 0.7.0 — tabs within one organization (design v2, after Codex design review v1)

Requested by Ed (2026-10-16): in a session he could not open the console's Toolbox alongside it. His
choice (asked directly): **tabs within one organization**. Each window stays one organization and one
sign-in; inside it, tabs hold the console and sessions. A second organization still opens its own window
(process), as today.

## Today

One process = one organization (`selectedTenant`, pinned at start). One main window (`g_mainState`)
whose single WebView2 controller fills the client area; `window.open` creates separate popup windows
(`children`). The Windows Hello unlock is a process-level startup gate before the profile is opened.
Navigation, permission and popup policy are per WebView and all key off the one tenant.

## Design

**Model.** The main window holds `tabs` (each a WebView2 controller + webview on the SAME environment and
user-data folder, i.e. the same organization's profile and cookies) and an `active` index. A tab reuses
the existing per-WebView setup (`AttachWebView` / `RegisterHandlers`): same navigation allow-list, same
permission handling, same popup handling. Nothing about the trust model changes: every tab is the same
origin of the same organization, exactly like two browser tabs on that site.

**Window layout.** A Win32 tab control (`WC_TABCONTROL`; 0.7.0 adds the comctl32 v6 dependency to the manifest, which the design wrongly assumed was there) across the
top of the client area; below it, each tab's WebView2 is parented to the main window and only the active
one is visible (`put_IsVisible`) with bounds = client area minus the strip. WM_SIZE / WM_DPICHANGED lay out
both. Tab label = the page's document title (DocumentTitleChanged), truncated to ~32 characters, with a
"+" pseudo-tab at the end.

**Tab identity and lifetime (v2).** Every tab has a stable `tab_id` (monotonic uint64, never reused)
and a state: `creating` (controller requested), `live`, `closing`. All asynchronous callbacks (controller
creation, every WebView2 event handler, consent completion, title changes) capture `(weak window,
tab_id)` and look the tab up by id on entry; a missing or `closing` tab, or a window marked `closing`,
makes the callback a no-op, except the cleanup obligations below. Nothing is ever addressed by index
across an await. The cap (12) counts `creating` + `live` tabs, so rapid requests cannot exceed it. If
controller creation completes for a tab that is no longer `creating` (closed meanwhile) or a window that
is `closing`, the returned controller is `Close()`d immediately and released. Destructive operations
(close tab, close window, select) requested from inside a WebView2 callback (e.g. AcceleratorKeyPressed)
are NOT performed inline: they are posted to the window (`PostMessage(WM_APP_TAB_COMMAND, cmd, tab_id)`)
and executed from the message loop, re-validating the tab id there.

**Commands** (menu bar "Tabs" menu + keyboard). Key matching is EXACT: a command matches only on a
`COREWEBVIEW2_KEY_EVENT_KIND_KEY_DOWN` event (never SYSTEM_KEY_DOWN, which is what Alt/AltGr
combinations produce), only when Ctrl is down and Alt (either side, which also excludes AltGr = Ctrl+Alt)
and both Win keys are up, with Shift exactly as listed, and never on an auto-repeat (`WasKeyDown` set in
the physical key status). Only a matched command sets `Handled`; every other key reaches the page
unchanged. The same pure decoder serves `AcceleratorKeyPressed` (WebView focus) and the main window's
`WM_KEYDOWN` (tab control focus), so both paths behave identically.
- New tab: Ctrl+T or the "+" tab -> a new tab at the organization's console root (`ConsoleUriFor`).
- Close tab: Ctrl+W, or middle-click on a tab; closing the last tab closes the window (as closing it today).
- Next/previous: Ctrl+Tab / Ctrl+Shift+Tab; Ctrl+1..8 = that tab, Ctrl+9 = last.
- Cap: 12 tabs per window, a WebView/resource limit (WebViews in one environment may share renderer
  processes; nothing here promises one process per tab); the "+" is disabled at the cap.

**What stays the same.**
- `window.open` (the viewer's pop-out, downloads pages) keeps opening a separate popup window. **Popups
  are owned by the main window, not by the opener tab**: closing the opener tab leaves its popups open
  (as closing one browser tab leaves windows it opened), and they close with the main window. The
  popup holds only a weak, id-checked reference to its opener tab. A NewWindowRequested whose deferral
  is still pending when its opener tab or the window closes is completed by denying it (no popup) before
  the opener WebView is released.
- Hello: the startup gate runs before the FIRST tab is created; later tabs are created only from the
  unlocked window, so there is no path to a tab before unlock. Enabling/disabling Hello is unchanged.
- Sign-in detection (`CheckSignedIn`) reads the profile's cookie manager, which all tabs share; it runs
  from any tab's WebView and stops once recorded, as today.
- Clipboard consent (v2): each request is bound to `(tab_id, navigation_generation)` captured when the
  PermissionRequested event fires, and the dialog shows the requesting URI's validated origin. Every
  outstanding permission deferral is completed EXACTLY ONCE: allow only if, after the dialog returns,
  the same tab is still `live` and its navigation generation is unchanged; otherwise (navigation, tab
  closing, window closing, dialog cancelled) deny. Tab/window teardown denies and completes every
  outstanding deferral of that tab BEFORE its WebView is released. Dialogs are serialized per window.
- Updates: the updater applies when ALL windows close, unchanged (tabs are in one window).

**Teardown (v2, in this order).** Closing a tab: (1) mark it `closing` (callbacks become no-ops);
(2) deny + complete its outstanding permission deferrals and pending NewWindowRequested deferrals;
(3) remove its event handlers; (4) `Close()` its controller and release it; (5) select the replacement by
stable identity: the tab to the right of the closed one, else to the left, chosen from the `live` list
after removal. Closing the window: mark the window `closing` first (rejects any new tab/popup creation),
then tear down every tab as above, then the popups, then destroy.

**Process failure.** `ProcessFailed` kinds: a RENDER process failure (or unresponsive) affects the WebViews
it served: each affected tab shows the existing error page with a Reload action, others continue. An
UNRESPONSIVE renderer (still running, hung) cannot be relied on to paint anything, so the recovery surface
is NATIVE: a message box owned by the window naming the tab, with "Reload" (CoreWebView2::Reload, or
recreate the tab's controller if reload does not recover) and "Close tab". A
BROWSER process exit is environment-wide: every tab and popup of the window is gone; the window shows
one error with "Restart DeskRally" and does not try to recreate tabs automatically.

## Not in 0.7.0
- Tabs across organizations (rejected by the operator's choice; would need one isolated profile per tab).
- Dragging tabs to reorder or out into windows; restoring tabs after restart; "open link in new tab"
  from the page (the web console has no such affordance yet).

## Tests
- Pure policy (client_policy_test): the command decoder over (event kind, key, Ctrl, Shift, Alt, Win,
  repeat): every command, extra Alt / AltGr (Ctrl+Alt) / Win refused, SYSTEM_KEY_DOWN refused, repeats
  refused, Shift mismatch refused, unrelated keys never handled; cap counting creating + live; next/prev/
  number selection with wraparound; replacement choice after closing the first/middle/last/only tab.
- Lifetime races (SMOKE_TEST hooks that hold an operation open and then release it): close a tab while
  its controller is still being created (the late controller is closed, the cap slot is freed); navigate
  and close during a pending clipboard consent (the deferral is denied and completed exactly once, counted);
  close the opener during a pending popup request (denied, no popup); a queued command naming a removed
  tab is a no-op.
- SMOKE_TEST build: open 3 tabs, switch, close middle/active/last, cap enforcement, last close exits.
- VM acceptance (signed build): real sign-in in tab 1, new tab is signed in (shared profile), start a
  session in tab 1 and open Toolbox in tab 2 while it runs, keyboard shortcuts with focus inside the page,
  Hello-enabled startup shows no tab before unlock, pop-out still opens a window, updater still applies.

## Questions for the reviewer
1. Any security difference between N tabs on one profile/origin and today's one WebView + popups?
2. Is AcceleratorKeyPressed interception of exactly these combinations safe (no other keys swallowed;
   page shortcuts that use Ctrl+T/W lose them — acceptable)?
3. Teardown ordering for a tab with a pending permission deferral or popups it opened?
