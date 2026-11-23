# Guest chat window

**Released October 7, 2026 in agent `0.0.1+163572c`.** New support downloads include it; existing installed agents need the update and a new connection.

## Overview

The guest-facing chat panel (`RmtGuestSessionWindow`) is a small, movable Win32 window that lets
the guest communicate with the technician during a remote support session. It is deliberately
unobtrusive: it starts hidden, never demands focus, and can be moved behind other content.

## Behaviour by life-cycle phase

### 1. Window creation (always hidden)

The window is created hidden in all cases.

- **Tray registration succeeds** — the window stays hidden. The system-tray icon is the only
  entry point until the technician sends the first message.
- **Tray registration fails** — the window is shown immediately as a visible fallback so the
  guest is never left with no session indicator at all.

### 2. Before the technician sends a message

The tray icon provides two actions:
- **Show session** — brings the panel to the foreground at the guest's request.
- **End session…** — reveals the panel with a title-bar reminder to use the End button, prompting a deliberate
  guest action before the session closes.

Seeded history (messages replayed from a previous reconnect), guest echoes, and background status
events (view-only mode, recording, clipboard-sharing) never open the window automatically.

### 3. First live technician message

When the session is active and the first `Posted` event from the Technician arrives:
- The window is shown with `SW_SHOWNA` — **no activation, no foreground steal**.
- The unread count and title bar are updated as normal.
- This trigger fires exactly once per window lifetime.

### 4. After the first reveal

Subsequent technician messages update the unread count and title bar but **do not re-open the
window**. If the guest has hidden or moved the window to the background, it stays there. The guest
controls their own screen.

### 5. Minimise / close while active

- **Minimise (caption button or `SC_MINIMIZE`)** — hides to the tray icon if the tray is
  registered; shows a visible fallback if the tray icon was lost.
- **Close (`[X]`, Alt+F4, taskbar Close)** — same hide-to-tray logic. The indicator remains
  present; ending the session still requires the input-filtered **End session** button inside
  the panel, which only genuine hardware input can actuate.

### 6. Session ended

If the host leaves an ended receipt visible, closing it destroys the window normally. Host teardown
may close the panel directly.

## Window properties

| Property          | Value |
|-------------------|-------|
| Default size      | 360 × 240 logical pixels at 96 DPI |
| Always-on-top     | No — the window can go behind other content |
| Caption / drag    | Yes — the guest can move it freely |
| Activation on reveal | Never (all automatic reveals use `SW_SHOWNA`) |
| Injected input    | Dropped at the pump — the technician cannot click End or close |

## Test coverage

The following tests exercise this behaviour without requiring a deployed session:

| Test | Kind | What it pins |
|------|------|--------------|
| `production_window_starts_hidden_when_tray_is_available` | native | Production factory starts hidden with a real tray icon, visible if tray fails |
| `no_topmost_in_panel_ex_style` | pure | `WS_EX_TOPMOST` absent from both style variants |
| `should_auto_reveal_only_first_live_technician_message` | pure | Auto-reveal predicate: seeded, guest echo, non-chat and repeat-tech messages excluded; first live tech message included; ended phase excluded |
| `initialhidden_trayfallback_and_no_topmost` | native | Real HWND: tray failure shows fallback; tray success keeps hidden; no topmost flag |
| `session_tray_lifecycle_keeps_restore_and_end_available` | native | Full tray lifecycle including hide/restore/teardown |

Local validation: 14 guest-window tests passed, including real Explorer tray registration and handler-driven chat events. The interactive menu-teardown test passed on rerun and three further runs after one initial failure; this is recorded as an intermittent test result. Run the guest tests with `cargo test -p rmt-agent-windows --lib guest_window -- --test-threads=1`.
