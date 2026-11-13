# Windows Hello and remembered desktop sign-in

Desktop 0.4.0 adds a Windows Hello opening lock and optional remembered server
sign-in. Install the signed release and matching server update before using the
remembered-login option.

## Intended setup

1. Install the accepted desktop update once published. Keep your current app
   open until you are ready to finish its remote sessions and update.
2. Open the organization you use (Main or Loam).
3. In the native **Security** menu, enable Windows Hello and complete Windows'
   PIN, fingerprint, or face verification. The setting is per organization and
   Windows user. Windows must have a supported verification method configured.
4. Close and reopen that app window. Complete Windows Hello before the app loads
   its saved web profile. Canceling or failed verification does not open it.
5. If already signed in, sign out first. On the next DeskRally sign-in, select
   **Remember this app for 30 days**, and enter your password and MFA code if
   enrolled. The checkbox starts unchecked.

DeskRally stores a server-issued session cookie, not your password or Windows
PIN. Windows handles the Hello verification. A remembered session ends at the
earlier of 30 days from sign-in or seven days without authenticated use. Using
the session does not move the 30-day deadline. Merely polling whether a session
is still valid does not reset its inactivity timer.

Normal browser sign-ins retain the existing 12-hour absolute lifetime and the
configured inactivity timeout (30 minutes by default). An existing session is
not upgraded just by installing the desktop app or enabling Hello.

## Daily use and recovery

Each newly launched app process verifies Hello before loading that organization's
profile. A connection launched into a separate app process also verifies. Monitor
pop-outs within an already unlocked process share its unlock. Existing open
windows are not automatically locked by this startup feature; lock Windows when
leaving the computer.

The app-opening lock and server authentication are separate. Hello does not
revive an expired, revoked, or signed-out DeskRally session. After expiry, sign in
with your password and MFA again. **Sign out** ends that saved server sign-in;
administrative sign-out, disabled accounts/tenants, and credential changes still
invalidate access. Password or login-email changes issue an ordinary replacement
session; opt in again on a fresh login if wanted.

If Hello is unavailable, cancel and use the website with normal authentication.
Do not delete the profile to troubleshoot: it contains saved application state.
Disabling the app's Hello setting also requires successful Hello verification.
Disabling that local lock is separate from signing out of the server; sign out
first if you want to remove remembered access.

## Implementation and boundaries

`POST /auth/login` accepts optional `remember_device: true` after the same
password, TOTP, tenant-policy, and throttle checks as an ordinary login. The
server persists the remembered flag on the session, storing only the token hash.
The database migration defaults existing rows to ordinary sessions. Validation
always checks absolute expiry and revocation, and chooses the inactivity timeout
from the persisted flag. Credential epochs, user/tenant status, and existing
authorization checks remain in force.

The desktop adds `DeskRallyHello/1` to its User-Agent only after a successful
Hello startup unlock. The viewer uses that marker to display the opt-in checkbox.
This is a UI convention, **not remote attestation**: authenticated API clients can
also explicitly request a remembered session. The server never treats a User-Agent
as proof of Hello or gives it additional account permissions.

This feature is an app-opening privacy lock, not a passkey and not a claim that
server cookies are cryptographically bound to Windows Hello. It does not defend
against software already running as the same Windows user, profile copying, or
modification of the local app/settings. Do not confuse it with server-verified
passwordless authentication.

Native verification uses Microsoft's desktop
[RequestVerificationForWindowAsync API](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync),
with the app's window as owner. The documented minimum supported Windows build
is 22000; unavailable systems retain ordinary sign-in with Hello left disabled.

## Validation and release requirements

- Backend tests with a real restricted PostgreSQL role: persisted policy, old
  session defaults, exact timeout boundaries, revocation, credential changes,
  full password/TOTP admission, and tenant isolation.
- Viewer: default opt-out, eligible explicit opt-in, normal browser/older-app
  behavior, and preserved desktop-launch/pop-out controls.
- Native: build, existing policy/smoke tests, cancellation/error/closing paths,
  per-tenant settings, and a real Windows Hello enable/reopen/approve check.
- Review final source and record publication/deployment separately in the release
  manifest and operations handoff.

On October 7, real Windows Hello enable and startup approval were verified on
the operator's computer. The startup process exposed no WebView before approval;
after approval it displayed the sign-in page with the Hello marker. This verified
the local opening lock, not a retained production server session: that requires
the server update and a fresh login with the remember option selected.
