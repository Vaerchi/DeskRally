# Troubleshooting a connection without video

Use this guide when DeskRally discovers a machine or its monitors but the remote picture is blank. Monitor discovery alone does not establish that video is arriving. A successful reconnect does not identify the original cause.

## Capture the failure before reconnecting

1. In the session view, expand **Connection details**. If you do not see it, finish any active work before reloading the website or reopening the client window to load the current viewer.
2. Record the time and time zone, connection direction, whether you used the installed app or a browser, and the remote machine name. Note whether the machine is locked and whether its lid is open. Share machine names only with your support contact.
3. Record State, Video track and the displayed video counters. Keep the panel open and record a second reading about ten seconds later. Polling runs only while the panel is expanded, with a pause of about two seconds between completed reads.
4. Note whether the picture is blank, frozen, or black, and whether monitor selection changes anything. A screenshot of the panel is useful; crop unrelated desktop content and personal information.
5. If it is safe to end your own connection, disconnect and reconnect once. Record whether this restores video. Do not restart the remote service or reboot a machine that someone is using just to collect evidence.

## Interpreting the readings

| Observation | What it tells us |
|---|---|
| State is Connected | The connection state reached Connected; this alone does not prove usable video. |
| Video track is present | A video track exists in the local stream; this does not prove frames are arriving or displaying. |
| Bytes received / Packets received increase | The reported inbound video stream is receiving data. These are cumulative counters, not speed measurements. |
| Frames decoded increase | The browser is decoding frames. A blank picture can still require investigation of capture content or display behavior. |
| Counters remain unchanged | Record both readings. A static desktop can reduce frame activity, so this alone does not identify a network or capture fault. |
| Unavailable or a retry message | The browser did not provide that statistic, or the read failed. This is not a measured zero. |

The panel shows a limited view of the first reported inbound video stream. It is not a complete network trace or a per-monitor performance report. It intentionally omits addresses, session tickets, SDP and credentials.

## "No relay connection is available"

A strip below the remote picture with this heading means the signaling server started your session **without a relay credential**. A relay lets a connection succeed on a restrictive network (a strict firewall or NAT) where a direct connection cannot. The server limits how many relay credentials one technician (20 by default) and one organization (80 by default) can hold at once. A credential counts until it expires, normally 2 hours after it was issued, even after the session it was issued for has ended, so opening and closing many sessions in a short time can reach the limit. The limits and the lifetime are server settings (`SIGNALING_TURN_MAX_PER_USER`, `SIGNALING_TURN_MAX_PER_TENANT`, `SIGNALING_TURN_TTL`), and an organization's other technicians draw on the same limit.

The session still starts, and only a direct connection can be tried. On an ordinary network that works and the strip is only a warning. On a restrictive network the connection may fail, and the failure message then says so, for example "Connection lost (likely cause: this account has reached its limit of relay credentials, so only a direct connection was tried)". The viewer says this only for a connection that never came up: a session that connected directly and failed later is not blamed on the relay.

What to do:

1. Wait: the older credentials expire on their own, normally within 2 hours. Closing sessions does not free one, for the reason above: a credential is kept until it expires, even after its session has ended.
2. Ask an administrator if it keeps happening. The limits may be too low for how your team works.

Dismiss hides the strip for that machine, and it stays hidden through every reconnect to the same machine: one the viewer makes by itself (after a lost connection, or when the machine's display layout changes) and the Reconnect button alike. A failure message still names the cause. Disconnecting, or connecting to another machine, ends that: connecting again starts a new session, so the strip returns if the account is still at its limit. A server that predates this notice never shows it, and the messages are unchanged.

## Locked laptop comparison

If you have a separate authorized way to access the laptop, compare DeskRally while the laptop is unlocked and while it is locked. Record each result and whether reconnecting was necessary. Do not infer a lock-screen bug from one successful reconnect: the reported intermittent laptop failure recovered on reconnect, and its cause remains unconfirmed.

## A prompt to open the app is a different issue

Record whether you clicked Connect on the website or inside the DeskRally app. Website-to-app launch can involve the browser's external-app prompt. A connection started inside the app should not tell you to approve a browser prompt. When a connection is already active, another connection may open another app window.

If a misleading prompt recurs, record its exact text and whether another app window opened. Avoid repeatedly clicking Connect while diagnosing it. Include the client version if known; a published update does not prove the installed client has updated.

## Send this short report

- Time/time zone and connection direction:
- App or browser; client version if known:
- Remote machine; locked/unlocked; lid open/closed:
- Blank, black or frozen picture; monitor selection result:
- First Connection details reading:
- Second reading about ten seconds later:
- Whether "No relay connection is available" was shown, and the exact failure message:
- Reconnect result:
- Exact launch-prompt text, if any:

Do not include passwords, MFA codes, enrollment tokens, identity keys or complete agent configuration files. These observations narrow the investigation; they do not establish a root cause by themselves.
