package controlplane

// Local authentication: username/password login, server-side sessions, and optional TOTP
// 2FA. This is the concrete replacement for the StubAuthenticator + the TODO(auth) note in
// http.go. It supplies:
//
//   - SessionAuthenticator: an Authenticator that resolves a Principal from the session
//     cookie / Bearer token on every protected request, then loads the caller's RBAC Grant.
//   - AuthService: the public /auth/login + /auth/logout endpoints and the protected TOTP
//     enrollment endpoints.
//
// The persistence seam is UserStore (users, credentials, TOTP secrets, grants). Production
// backs it with pgx against migrations/0002_auth.sql (RLS-scoped); tests and the dev
// skeleton use InMemoryUserStore. This mirrors the repo's existing "interface + in-memory
// fake" testing style (see http_test.go / TenantBinder).
//
// Security posture (docs/03-roadmap.md risk table, CVE-2024-1709): password + TOTP failures
// return one generic error to avoid user/credential enumeration; tokens and secrets are
// never logged; comparisons are constant-time (see VerifyPassword / VerifyTOTP).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Login / auth errors.
var (
	// ErrInvalidCredentials is the single opaque failure returned for unknown user, wrong
	// password, or wrong TOTP code — deliberately indistinguishable to the client.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrTOTPRequired signals the password was correct but the account has TOTP enrolled and
	// no (or an empty) code was supplied, so the client should prompt for one.
	ErrTOTPRequired = errors.New("totp code required")
	// ErrUserDisabled is returned when the user is disabled.
	ErrUserDisabled = errors.New("user disabled")
	// ErrTenantSuspended is returned when the caller's TENANT has been suspended
	// (`tenant.disabled_at`) — the account itself is fine, the whole tenancy is not.
	//
	// It is deliberately DISTINCT from ErrUserDisabled and ErrInvalidCredentials, and that
	// distinction is the point rather than a nicety: this is the one denial a legitimate signed-in
	// technician can hit through no fault of their credential, and answering it as a generic
	// "unauthorized" sends them round a login loop that cannot succeed (login is refused too — see
	// cp_resolve_tenant_by_slug). Naming it lets authMiddleware say "tenant suspended" so the console
	// can tell the operator to contact billing/their provider instead.
	//
	// No enumeration concern: it is only ever returned to a caller who already presented a valid
	// session for that tenant, so it tells them nothing they did not already know.
	ErrTenantSuspended = errors.New("tenant suspended")
	// ErrTOTPEnrollmentRequired signals that the tenant requires 2FA (`tenant.require_2fa = true`)
	// but this user has not completed TOTP enrollment (no confirmed secret). Distinct from
	// ErrTOTPRequired (enrolled but code missing) so the login form can tell the user to enroll
	// rather than to supply a code.
	//
	// Returned only AFTER password verification succeeds — it reveals that the password is correct,
	// which is intentional: the user already knows their own password, and the message they need
	// is "enroll 2FA", not "wrong credentials". An attacker guessing passwords still gets the
	// generic ErrInvalidCredentials path.
	ErrTOTPEnrollmentRequired = errors.New("2fa enrollment required")
	// ErrNoUser is returned by a UserStore when no matching user exists.
	ErrNoUser = errors.New("no such user")
	// ErrUnknownRole is returned by SetUserRole/CreateUser when the role is not an assignable preset.
	// Both the fake and the pg store fail closed on it so they agree (the handler also validates first).
	ErrUnknownRole = errors.New("unknown role")
	// ErrEmailExists is returned by CreateUser when the email already exists in the tenant (the
	// app_user UNIQUE (tenant_id, email)). Surfaced to the console as 409 conflict.
	ErrEmailExists = errors.New("email already in use")
	// ErrLastOwner refuses a role change or disable that would leave a tenant that had an enabled,
	// never-expiring Owner with none (docs/56 sec. 4.2a): the Owner role is the tenant's recovery path.
	ErrLastOwner = errors.New("the tenant must keep at least one active Owner")
	// ErrNoTenant is returned by a TenantResolver when no active tenant matches the slug.
	ErrNoTenant = errors.New("no such tenant")
	// ErrNoPendingTOTP is returned when a confirmation is attempted with no pending enrollment.
	ErrNoPendingTOTP = errors.New("no pending totp enrollment")
	// ErrTooManyAttempts is returned when a credential-verifying endpoint is throttled. The
	// caller learns only that it must wait — never whether the credentials were close.
	ErrTooManyAttempts = errors.New("too many attempts")
	// ErrStaleCredential is returned by SetEmail when the credential epoch advanced between the
	// caller's password verification and the store write — a concurrent password change or reset
	// invalidated the verification window. The handler maps this to 409 and asks the caller to
	// sign in again.
	ErrStaleCredential = errors.New("credential changed; sign in again")
)

// TenantResolver maps a login-supplied tenant slug to its tenant id. This is the privileged
// bootstrap step at login: the returned id is what pins app.current_tenant for every
// subsequent RLS-scoped query. Production wires PgTenantResolver (pgstore.go); when a
// resolver is not configured, AuthService treats the login's Tenant field as the id directly
// (the in-memory / single-tenant path).
type TenantResolver interface {
	ResolveTenant(ctx context.Context, slug string) (tenantID string, err error)
}

// AuthUser is the authentication view of an app_user row plus its local credential and TOTP
// enrollment state. PasswordHash is the PHC argon2id string (empty ⇒ no local credential).
type AuthUser struct {
	ID string
	// MFAGeneration is app_user.mfa_generation (migrations/0054), read in the SAME query as the
	// TOTP secret, so a session marked MFA-verified names the generation its code was checked
	// against. 0 = the user never had a second factor.
	MFAGeneration int64
	TenantID      string
	Email         string
	DisplayName   string
	PasswordHash  string
	Disabled      bool

	// Require2FA is `tenant.require_2fa` for THIS user's tenant, read in the same query as the
	// user row. When true, the tenant Owner has opted all members into mandatory 2FA: login is
	// refused for any user who has not confirmed a TOTP enrollment. Shares TenantSuspended's
	// rationale for riding on AuthUser: the check is on the hot login/session-validate path and
	// adding it here keeps it zero-cost and impossible to skip at any call site.
	Require2FA bool

	// TenantSuspended is `tenant.disabled_at IS NOT NULL` for THIS user's tenant, read in the same
	// query that returned the user (PgUserStore joins `tenant`).
	//
	// It lives on the authentication view — rather than being looked up separately — for the same
	// reason CredentialUpdatedAt does: the user row is loaded on EVERY authenticated request, so
	// carrying the tenant's state alongside it makes re-checking suspension cost nothing, and a
	// check that costs nothing is one nobody is tempted to skip. Before this, `disabled_at` was
	// honoured only by the SQL admission functions (cp_resolve_tenant_by_slug, the enrollment /
	// attended redeem paths) and for the per-user `app_user.disabled_at`, so suspending a tenant
	// stopped new logins and new agents while every technician already holding a session kept full
	// access for up to the 12-hour absolute session TTL (docs/07 loops 11–13, "verified-but-unfixed").
	TenantSuspended bool

	// CredentialUpdatedAt is `user_credential.updated_at` for THIS user, read in the same query
	// that returned PasswordHash — the credential's version (migrations/0018). Zero when the user
	// has no local credential.
	//
	// Read together with the hash on purpose: a session records the version it was authorized by,
	// and if the version could come from a different read than the hash, the pair could describe two
	// different credentials and the epoch check would be comparing the wrong thing.
	CredentialUpdatedAt time.Time

	// TOTPSecret is the base32 shared secret ENFORCED AT LOGIN; empty ⇒ not enrolled.
	// TOTPConfirmed is true once the user has proven possession with a valid code.
	TOTPSecret    string
	TOTPConfirmed bool
	// TOTPPending is an unconfirmed (re-)enrollment secret, held separately so arming a new
	// authenticator never disarms the confirmed one (migrations/0009). It is NEVER enforced at
	// login; ConfirmPendingTOTP promotes it into TOTPSecret.
	TOTPPending string
}

// UserStore is the persistence seam for local auth. Implementations MUST scope by tenant.
//
// Note on RLS: login and session validation run before the per-request tenant GUC is pinned
// (they establish who the caller is). The production pgx implementation therefore runs these
// specific lookups on a privileged bootstrap path that resolves and sets the tenant from the
// looked-up row — never as an unscoped app-role query. The in-memory fake keys by tenant
// explicitly to preserve the same isolation in tests.
type UserStore interface {
	// FindUserByEmail returns the user for a tenant, or ErrNoUser.
	FindUserByEmail(ctx context.Context, tenantID, email string) (*AuthUser, error)
	// FindUserByID returns the user for a tenant, or ErrNoUser. Used to rebuild a Principal
	// from a validated session.
	FindUserByID(ctx context.Context, tenantID, userID string) (*AuthUser, error)
	// SetTOTP stores (or replaces) a user's ENFORCED TOTP secret and its confirmed state,
	// clearing any pending enrollment. This is the administrative/provisioning path (and what
	// tests use to arm 2FA directly); the HTTP enrollment flow goes through
	// SetPendingTOTP + ConfirmPendingTOTP so a half-finished enrollment can never disarm 2FA.
	SetTOTP(ctx context.Context, tenantID, userID, secretB32 string, confirmed bool) error
	// SetPendingTOTP stores an unconfirmed enrollment secret WITHOUT touching the enforced
	// secret or its confirmed state.
	SetPendingTOTP(ctx context.Context, tenantID, userID, secretB32 string) error
	// ConfirmPendingTOTP promotes the pending secret into the enforced one and marks it
	// confirmed. Returns ErrNoPendingTOTP when there is nothing pending, so a confirmation can
	// never activate a secret the caller did not just prove possession of.
	ConfirmPendingTOTP(ctx context.Context, tenantID, userID string) error
	// SetPassword replaces the user's local credential with an already-hashed PHC argon2id
	// string. It NEVER receives a plaintext — hashing is the caller's job (HashPassword), so no
	// implementation can accidentally persist one.
	//
	// Implementations MUST refuse a user outside tenantID (→ ErrNoUser) rather than writing a
	// credential for somebody else's account: this is the one write in the interface that can
	// hand an attacker a login, so it fails closed on any tenant mismatch instead of relying on
	// the caller having resolved the user correctly.
	//
	// It returns the NEW credential epoch — the `updated_at` the store actually persisted, read
	// back from the written row rather than computed by the caller. The replacement session issued
	// after a password change must carry this exact value or it would be stale the instant it was
	// minted; taking it from the storage layer (rather than from time.Now()) is the same principle
	// the audit chain follows — hash what storage returns.
	SetPassword(ctx context.Context, tenantID, userID, phcHash string) (time.Time, error)
	// ChangePassword is SetPassword for a caller that VERIFIED the current password: the write
	// happens only while the credential epoch still equals expectedEpoch (the updated_at its
	// verification read), else ErrStaleCredential. Without the condition, a concurrent change
	// that verified the same old password could land after the owner's recovery change and
	// replace it (security audit 2026-10-18). The email change already works this way (SetEmail).
	ChangePassword(ctx context.Context, tenantID, userID, phcHash string, expectedEpoch time.Time) (time.Time, error)
	// ConsumeTOTPStep records step (the RFC 4226 counter a login code matched) as spent, and
	// reports whether it was still unspent. Implementations MUST make the check and the write ONE
	// atomic operation and MUST refuse any step <= the stored one, so a code accepted once cannot
	// authenticate again for the rest of its skew window (RFC 6238 §5.2) and two concurrent logins
	// replaying the same code cannot both succeed.
	ConsumeTOTPStep(ctx context.Context, tenantID, userID string, step uint64) (bool, error)
	// GrantFor resolves the user's effective RBAC Grant (memberships → capabilities). EXPIRED
	// memberships (docs/56) are left out: this is what the user may DO, on every request.
	GrantFor(ctx context.Context, tenantID, userID string) (*Grant, error)
	// StoredGrantFor returns a Grant built from ALL the user's stored memberships, EXPIRED ONES
	// INCLUDED, each with its ExpiresAt. For the admin paths only (docs/56 sec. 4): who may edit a user,
	// and what an edit preserves, must not change because their access lapsed. Never authorize the
	// user's OWN actions with it.
	StoredGrantFor(ctx context.Context, tenantID, userID string) (*Grant, error)
	// AccessSummary is ONE user's ListUsers row (docs/57 sec. 5): the access aggregates evaluated by
	// the store at one instant (pg: statement_timestamp(), the same SQL as ListUsers), so /me never
	// recomputes expiry or windows on the app clock. ErrNoUser when the id is not in the tenant.
	AccessSummary(ctx context.Context, tenantID, userID string) (UserSummary, error)
	// SetUserAssignment is SetUserRole with an expiry (docs/56): it REPLACES all of the user's
	// memberships with one membership of a.Role scoped to a.ScopedGroupIDs that stops granting at
	// a.ExpiresAt (nil = never). It refuses with ErrLastOwner a change that would leave the tenant
	// with no enabled, never-expiring Owner membership when it had one (checked under a lock on the
	// tenant's Owner memberships, so two concurrent demotions cannot both pass).
	SetUserAssignment(ctx context.Context, tenantID, userID string, a Assignment) error
	// CreateUserAssignment is CreateUser with an expiry on the created membership (docs/56).
	CreateUserAssignment(ctx context.Context, tenantID, userID, email, displayName string, a Assignment) error
	// ListUsers returns the tenant's users as the management view (id/email/display_name/disabled),
	// ordered by email. For the console user-management surface (docs/01 §5); tenant-scoped by the
	// caller-supplied tenantID (and, in pgx, additionally by RLS).
	ListUsers(ctx context.Context, tenantID string) ([]UserSummary, error)
	// SetUserDisabled sets (or clears) a user's disabled flag — `app_user.disabled_at`. A disabled
	// user is refused on the NEXT authenticated request (SessionAuthenticator re-reads Disabled every
	// time), so this takes effect immediately without any session bookkeeping. ErrNoUser when the id
	// is not in the tenant.
	SetUserDisabled(ctx context.Context, tenantID, userID string, disabled bool) error
	// SetUserRole REPLACES all of a user's memberships with a SINGLE tenant-wide membership of the
	// given preset role (docs/01 §5 role assignment). role MUST be an assignable preset — both
	// implementations reject anything else with ErrUnknownRole so they agree (the handler validates
	// first via IsAssignableRole, and additionally enforces the no-escalation rule the store cannot
	// know about). ErrNoUser when the id is not in the tenant. The effective Grant a later request
	// resolves via GrantFor is exactly the new role's capabilities, scoped to scopedGroupIDs.
	// scopedGroupIDs is the membership's machine-group scope: nil/empty writes '{}' (tenant-wide,
	// today's behaviour), a non-empty set scopes the membership to those groups. The handler has
	// already validated that the ids are real groups and that the actor may assign that scope; the
	// store persists exactly these ids and NEVER collapses a non-empty request to '{}'.
	SetUserRole(ctx context.Context, tenantID, userID string, role Role, scopedGroupIDs []string) error
	// CreateUser inserts a NEW user (email + display_name) into the tenant with a SINGLE tenant-wide
	// membership of the given preset role — the console INVITE (docs/01 §5). The caller supplies the
	// uuid (newUUID) so id-generation lives in ONE place and the fake and pg agree on the id. The email
	// must be unique within the tenant — a duplicate is ErrEmailExists; role must be an assignable
	// preset (ErrUnknownRole otherwise). The created user has NO credential yet (external_subject NULL,
	// no password): it is provisioned separately (a first-password setup link) or binds on first OIDC
	// login. The whole write is atomic — a failed membership insert leaves no orphan user.
	// scopedGroupIDs scopes the created membership to those machine groups; nil/empty is tenant-wide.
	CreateUser(ctx context.Context, tenantID, userID, email, displayName string, role Role, scopedGroupIDs []string) error
	// SetEmail replaces the user's login email and advances user_credential.updated_at so that any
	// session verified against the old epoch is immediately invalidated by the credential check.
	// expectedEpoch is the updated_at the caller read during password verification; if the epoch has
	// since advanced (concurrent password change/reset), the whole write is rolled back and
	// ErrStaleCredential is returned. Returns the new epoch on success.
	//
	// ErrNoUser when the id is not in the tenant or the user is disabled.
	// ErrEmailExists when newEmail is already taken within the tenant.
	// ErrStaleCredential when a concurrent credential change invalidated the verification window.
	SetEmail(ctx context.Context, tenantID, userID, newEmail string, expectedEpoch time.Time) (time.Time, error)
}

// UserSummary is the management view of a user for the console user list (docs/01 §5): identity, the
// disabled flag, and the DISTINCT keys of the roles the user holds (sorted; the console shows them and
// seeds the role-assignment control). No credential/TOTP state (that is the authentication view,
// AuthUser). Roles is always non-nil so the JSON is `[]`, never `null`.
type UserSummary struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Disabled    bool     `json:"disabled"`
	Roles       []string `json:"roles"`
	// ScopedGroupIDs is the user's effective machine-group scope, matching Grant.AssignmentScope:
	// an EMPTY slice means tenant-wide (any membership that is tenant-wide makes the whole user
	// tenant-wide), a non-empty slice is the union of the groups their memberships are scoped to.
	// Always non-nil so the JSON is `[]`, never `null`; the console renders empty as "All groups".
	ScopedGroupIDs []string `json:"scoped_group_ids"`
	// AccessExpiresAt is when the user's access ends (docs/56 sec. 5): null when any membership never
	// expires (or there are none), otherwise the LATEST expiry. AccessExpired: they have memberships
	// and every one has expired (they can sign in but may do nothing). Both from the STORED rows.
	AccessExpiresAt *time.Time `json:"access_expires_at"`
	AccessExpired   bool       `json:"access_expired"`
	// AccessWindow (docs/57 sec. 5) is non-null only when EVERY membership carries the same window;
	// AccessWindowVaries: every membership has one but they differ. AccessOutsideWindow is a CURRENT
	// predicate: an unexpired membership exists and every unexpired one is outside its window now.
	AccessWindow        *AccessWindow `json:"access_window"`
	AccessWindowVaries  bool          `json:"access_window_varies"`
	AccessOutsideWindow bool          `json:"access_outside_window"`
}

// Assignment is one membership to write (docs/55 scope + docs/56 expiry).
type Assignment struct {
	Role           Role
	ScopedGroupIDs []string      // nil/empty = tenant-wide
	ExpiresAt      *time.Time    // nil = never
	Window         *AccessWindow // nil = any time (docs/57)
	// WindowSupplied: Window came from this request, so the store verifies its zone against the
	// database's tz data; a PRESERVED window is written exactly as stored (docs/57 sec. 4 r3).
	WindowSupplied bool
	// ExpectTreeVersion (docs/62 R2): the group_tree_version the actor's grant was read at. When set, the
	// write is conditional on the tenant's group tree still being at that version, because who may assign
	// what depends on the tree; a change in between is ErrGroupTreeChanged (409 "groups changed, retry").
	// nil = unconditional (a caller whose authority does not depend on the tree).
	ExpectTreeVersion *int64
}

// -------------------------------------------------------------------------------------
// SessionAuthenticator — the real Authenticator, replacing StubAuthenticator.
// -------------------------------------------------------------------------------------

// SessionAuthenticator resolves the Principal from the request's session cookie or Bearer
// token. It is the production drop-in for StubAuthenticator.
type SessionAuthenticator struct {
	Sessions   *SessionManager
	Users      UserStore
	CookieName string
}

// Authenticate implements Authenticator: extract the bearer token, validate the session
// (expiry + revocation), reload the user (rejecting disabled ones), and build the Grant.
func (a *SessionAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	token := bearerToken(r, a.cookieName())
	if token == "" {
		return nil, ErrInvalidCredentials
	}
	sess, err := a.Sessions.Validate(r.Context(), token)
	if err != nil {
		return nil, err
	}
	u, err := a.Users.FindUserByID(r.Context(), sess.TenantID, sess.UserID)
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, ErrUserDisabled
	}
	// TENANT SUSPENSION, re-evaluated on every request rather than only at admission. Suspending a
	// tenant closed the doors nobody was through yet — login (cp_resolve_tenant_by_slug), enrollment
	// redemption (migrations/0011) and attended redemption (0021) all filter `disabled_at` — but
	// nothing re-examined a technician who was ALREADY inside, so a suspended tenant kept a live
	// console, live sessions and a live backstage shell until the 12-hour absolute TTL ran out.
	//
	// Checked here beside the per-user `Disabled` check because this is the one path every
	// authenticated request goes through, and because `u` is loaded here anyway: the flag rides on
	// the same row read, so the re-check costs no extra round trip.
	if u.TenantSuspended {
		return nil, ErrTenantSuspended
	}
	// CREDENTIAL EPOCH (migrations/0018). The session names the credential version that authorized
	// it; the user we just loaded names the current one. A session issued against a password that
	// has since been replaced is refused here even though nothing revoked it — which is the only
	// way to catch the login that raced a password change and inserted its row AFTER the change's
	// revocation had already committed.
	//
	// This costs no extra query: `u` is loaded on every authenticated request anyway, and it now
	// carries the epoch alongside the hash.
	if !CredentialEpochMatches(sess.CredentialEpoch, u.CredentialUpdatedAt) {
		return nil, ErrSessionCredentialStale
	}
	grant, err := a.Users.GrantFor(r.Context(), sess.TenantID, sess.UserID)
	if err != nil {
		return nil, err
	}
	return &Principal{UserID: u.ID, TenantID: u.TenantID, Grant: grant, SessionID: sess.ID}, nil
}

func (a *SessionAuthenticator) cookieName() string {
	if a.CookieName != "" {
		return a.CookieName
	}
	return DefaultSessionCookie
}

// DefaultSessionCookie is the cookie name carrying the session token.
const DefaultSessionCookie = "cp_session"

// cookieSessionToken returns the session token carried by the session cookie, or "". This is
// the single definition of "authenticated via cookie": bearerToken consults it FIRST (a cookie
// wins over an Authorization header), and csrfMiddleware keys on the same predicate, so the
// CSRF layer can never disagree with the authenticator about which credential is in effect.
func cookieSessionToken(r *http.Request, cookieName string) string {
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// bearerToken pulls the session token from the cookie first, then the Authorization header.
func bearerToken(r *http.Request, cookieName string) string {
	if t := cookieSessionToken(r, cookieName); t != "" {
		return t
	}
	if h := r.Header.Get("Authorization"); h != "" {
		if after, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}

// -------------------------------------------------------------------------------------
// AuthService — the login / logout / TOTP HTTP surface.
// -------------------------------------------------------------------------------------

// AuthService owns the credential-verifying endpoints. Issuer names the deployment in TOTP
// provisioning URIs. SecureCookie should be true in production (HTTPS only).
type AuthService struct {
	Users    UserStore
	Sessions *SessionManager
	// Guard bounds the database work an anonymous client can cause with invalid credentials on
	// /auth/logout (credential_guard.go) and learns the tokens login mints. Nil = unguarded (tests/dev).
	Guard *CredentialGuard
	// MachineGroups validates a group-scoped membership assignment's group ids against the tenant's
	// real groups (docs/55). Optional: only consulted when a role/invite request carries a non-empty
	// scoped_group_ids — a tenant-wide assignment never touches it. When a scope IS requested but this
	// is nil, the handler fails closed rather than writing an unvalidated scope.
	MachineGroups MachineGroupStore
	// Tenants resolves a login's tenant slug to its id (privileged bootstrap). Optional:
	// when nil, the login's Tenant field is used as the tenant id directly.
	Tenants      TenantResolver
	Issuer       string
	TOTP         TOTPConfig
	CookieName   string
	SecureCookie bool
	// Now is injectable for tests; defaults to time.Now.
	Now func() time.Time

	// MgmtAudit records the 2FA lifecycle (totp.enroll / totp.confirm) and failed logins into
	// the management-plane trail read by GET /audit. Optional: when nil those events are not
	// recorded — wire it in production (cmd/controlplane/main.go does).
	MgmtAudit MgmtAuditStore

	// CredentialTokens backs first-password provisioning and administrative reset
	// (auth_password_reset.go). Optional: when nil, none of the three credential-token routes is
	// mounted at all — an unconfigured deployment has no reset path rather than a broken one.
	CredentialTokens CredentialTokenStore

	// Throttle meters the credential-verifying endpoints (throttle.go). It defaults to
	// DefaultThrottleConfig on first use — throttling is ON unless DisableThrottle says
	// otherwise, because an unmetered second factor is brute-forceable.
	Throttle *Throttle
	// DisableThrottle turns metering off. Only for tests that deliberately hammer an endpoint.
	DisableThrottle bool
	throttleOnce    sync.Once

	// loginVerifyHook, when set (tests only), is called with the branch label before each login
	// password verification.
	loginVerifyHook func(path string)

	// PasswordHistory enforces password reuse prevention. When set, HandleChangePassword and
	// HandleRedeemPasswordReset check the candidate password against recent retired hashes before
	// accepting the change, and record the outgoing hash into the history on success. When nil,
	// no history checking or recording occurs — the existing "must differ from current" check on
	// the change path still applies.
	PasswordHistory PasswordHistoryStore

	// pendingMu guards nextPendingAuditAt for the service-wide second-factor pending sample
	// (auth_pending_audit.go). Not exported; zero value is safe (first event always allowed).
	pendingMu          sync.Mutex
	nextPendingAuditAt time.Time
}

// throttle returns the configured limiter, lazily installing the default profile. Returns nil
// (which every Throttle method tolerates) when metering is explicitly disabled.
func (s *AuthService) throttle() *Throttle {
	if s.DisableThrottle {
		return nil
	}
	s.throttleOnce.Do(func() {
		if s.Throttle == nil {
			s.Throttle = NewThrottle(DefaultThrottleConfig)
		}
	})
	return s.Throttle
}

// recordAuthEvent appends a management-plane audit event for an authentication action. Unlike the
// mutating console handlers (which fail the request when they cannot audit), auth events are
// best-effort and logged on failure: a login that already failed must not turn into a 500, and a
// TOTP mutation is audited separately by its handler before it reports success.
func (s *AuthService) recordAuthEvent(ctx context.Context, tenantID, actorUserID, action string, meta map[string]any) error {
	return s.recordAuthEventFor(ctx, tenantID, actorUserID, actorUserID, action, meta)
}

// recordAuthEventFor is recordAuthEvent with the SUBJECT stated separately from the actor.
//
// Every auth event that existed before credential-setup tokens was self-directed — you enroll your
// own second factor, you change your own password — so actor and target were necessarily the same
// principal. An administrative reset is the first one that is not: the interesting question in the
// trail is "whose credential was re-provisioned", and recording the ADMIN there would hide exactly
// the fact a reviewer is looking for.
func (s *AuthService) recordAuthEventFor(ctx context.Context, tenantID, actorUserID, targetUserID, action string, meta map[string]any) error {
	if s.MgmtAudit == nil || tenantID == "" {
		return nil
	}
	var raw json.RawMessage
	if meta != nil {
		b, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		raw = b
	}
	return s.MgmtAudit.RecordEvent(ctx, tenantID, &MgmtAuditEvent{
		ActorUserID: actorUserID,
		Action:      action,
		TargetKind:  "user",
		TargetID:    targetUserID,
		Metadata:    raw,
	})
}

// decodeOptionalJSON is decodeJSONBody (bodylimit.go) for a body that may legitimately be ABSENT:
// an empty body decodes to the zero value and is not an error, but anything present must still be
// valid JSON and must still fit maxBytes. An endpoint whose body is optional must not reject the
// empty one, and must not silently accept garbage either.
//
// Like decodeJSONBody it ANSWERS THE REQUEST itself on failure — 413 for an over-limit body
// (docs/25 F05), 400 with badRequestMsg for anything else — and returns the error so the caller's
// whole error path is a bare return. Callers must not write a second response.
func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any, badRequestMsg string) error {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes)).Decode(dst)
	if err == nil || errors.Is(err, io.EOF) {
		return nil
	}
	if !writeIfBodyTooLarge(w, err) {
		writeError(w, http.StatusBadRequest, badRequestMsg)
	}
	return err
}

func (s *AuthService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *AuthService) totpCfg() TOTPConfig {
	if s.TOTP.Digits == 0 {
		return DefaultTOTPConfig
	}
	return s.TOTP
}

func (s *AuthService) cookieName() string {
	if s.SecureCookie {
		return "__Host-" + DefaultSessionCookie
	}
	if s.CookieName != "" {
		return s.CookieName
	}
	return DefaultSessionCookie
}

type loginRequest struct {
	Tenant   string `json:"tenant"`
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
	// RememberDevice opts this login into a long-lived remembered session (migrations/0053):
	// 30-day absolute TTL and 7-day idle timeout. Full password + TOTP verification still runs
	// before this flag is honored. The UA is not a security boundary; only the persisted session
	// row flag governs TTL enforcement. Omitting the field (or false) issues an ordinary session.
	RememberDevice bool `json:"remember_device"`
}

// HandleLogin is the public POST /auth/login endpoint. It verifies the password (and TOTP
// when enrolled), issues a session, and sets the session cookie. Failures return 401 with a
// generic message; a correct password on a TOTP-enrolled account with no code returns 401
// with {"error":"totp code required"} so the client can prompt for the second factor.
//
// Every genuine credential failure is METERED (per account and per source IP) and AUDITED, so an
// online guessing run against the password or the 6-digit second factor runs into exponential
// lockouts and shows up in GET /audit instead of proceeding silently at full speed. A
// correct-password-but-code-required answer is not a failure and costs no budget.
func (s *AuthService) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	// The same 64 KiB ceiling as before, now through the shared helper so an over-limit body is a 413.
	// The 400 wording stays deliberately flat: this endpoint is pre-auth, and the decoder's own
	// message describes the struct it failed to fill — free schema reconnaissance for an anonymous
	// caller. That is why decodeJSONBody takes the message instead of generating one.
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "invalid request body"); err != nil {
		return
	}
	th := s.throttle()
	// LOGIN BUDGETS (security review 2026-11-01 #3). Three keys are RESERVED atomically before
	// any verification (Throttle.Reserve: check-and-charge in one critical section, so a parallel
	// burst cannot all pass a check made before any failure is recorded) and refunded when the
	// attempt turns out not to be a credential failure:
	//
	//  1. account+source: five free failures, then 2s, 4s ... 15 min. Per (account, source).
	//  2. source (IPv4 address / IPv6 /64): the same curve, shared across accounts.
	//  3. ACCOUNT-WIDE, source-independent (loginAccountFree / loginAccountDelay): the first
	//     loginAccountFree failures inside the 15-minute idle-decay window are free; after that
	//     every further failure, from ANY source or many sources, earns a 30 s gap before the
	//     next verification of that account is admitted. This is a DELAY, deliberately not an
	//     exponential lockout: it caps guessing at ~2 verifications per minute per account (about
	//     2900/day) however many addresses the attacker owns, never grows, never outlives the
	//     attack by more than 30 s, and a refused attempt charges nothing. The cost to the
	//     legitimate owner while an attack is in progress is a 429 with Retry-After of at most
	//     30 s, after which a correct password succeeds (success refunds its own charge and is
	//     never turned into a failure). An attacker cannot lock the owner out, only make them
	//     wait for the next free 30 s slot.
	srcIP := clientIP(r)
	acctSrc := throttleSpec{Key: accountKey("login-source", req.Tenant, req.Email) + ":" + throttleSource(srcIP)}
	ipSpec := throttleSpec{Key: ipKey("login", srcIP)}
	acctWide := throttleSpec{
		Key:  accountKey("login-account", req.Tenant, req.Email),
		Free: loginAccountFree, Base: loginAccountDelay, Max: loginAccountDelay,
	}
	if retry, ok := th.Reserve(acctSrc, ipSpec, acctWide); !ok {
		writeThrottled(w, retry)
		return
	}
	// refund returns the reservation for an attempt that was NOT a credential failure.
	refund := func() { th.Release(acctSrc, ipSpec, acctWide) }
	user, tenantID, err := s.authenticateLocal(r.Context(), req)
	if err != nil {
		var throttled *loginThrottleError
		switch {
		case IsHashCapacityError(err):
			// The password was never examined — the process is at its argon2 bound (docs/25 F01).
			// This is deliberately NOT metered and NOT audited as a login failure: charging it
			// would let anyone able to generate load lock out any account they can name.
			refund()
			WriteHashBusy(w)
		case errors.As(err, &throttled):
			refund()
			writeThrottled(w, throttled.retry)
		case errors.Is(err, ErrTOTPRequired):
			refund()
			s.tryRecordPendingAudit(r, tenantID, req.Email)
			writeError(w, http.StatusUnauthorized, ErrTOTPRequired.Error())
		case errors.Is(err, ErrTOTPEnrollmentRequired):
			refund()
			// The tenant requires 2FA but this account has not enrolled. Distinct from ErrTOTPRequired
			// (enrolled but code missing) so the console can direct the user to enroll rather than
			// to enter a code. 403 rather than 401: the password was correct — the barrier is the
			// enrollment policy, not the credential itself.
			s.tryRecordPendingAudit(r, tenantID, req.Email)
			writeError(w, http.StatusForbidden, ErrTOTPEnrollmentRequired.Error())
		default:
			// The reservation above IS the charge for this failure.
			s.auditLoginFailure(r, tenantID, req.Email)
			// Unknown user, wrong password, wrong code, disabled — one opaque answer.
			writeError(w, http.StatusUnauthorized, ErrInvalidCredentials.Error())
		}
		return
	}
	// Clear only this account/source pair. The shared source budget still meters spraying.
	// Other sources cannot be locked out merely by naming this account.
	// A valid account must never erase the shared source-IP failure budget, so the source and
	// account-wide keys only get THIS attempt's own charge refunded (the account-wide window must
	// keep counting the attacker's failures).
	th.Reset(acctSrc.Key)
	th.Release(ipSpec, acctWide)

	// The session is stamped with the credential version `authenticateLocal` actually verified
	// against — carried on the AuthUser from the same read that returned the hash. If a password
	// change commits between that read and this insert, the stamp is already the OLD version and
	// every request this session makes is refused (migrations/0018).
	//
	// RememberDevice opts into a remembered session (30d/7d idle) via IssueRemembered. Full
	// credential verification ran before this branch — the flag is honored only after the caller
	// proved their identity. Issue (ordinary, 12h/30min) is the default when the flag is absent.
	var (
		token string
		sess  *Session
	)
	if req.RememberDevice {
		token, sess, err = s.Sessions.IssueRemembered(r.Context(), user.TenantID, user.ID, user.CredentialUpdatedAt)
	} else {
		token, sess, err = s.Sessions.Issue(r.Context(), user.TenantID, user.ID, user.CredentialUpdatedAt)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not establish session")
		return
	}
	// A freshly minted token is known-good: tell the credential guard so its holder is never refused
	// by a failure budget an attacker sharing this source address ran down (credential_guard.go).
	s.Guard.NoteValid(token)
	// authenticateLocal only returns a user with a confirmed enrollment after a TOTP code was
	// verified and its step consumed, so this login proved the second factor: record that IN the
	// session, bound to the generation read with the secret (migrations/0054). Not marking it is
	// the fail-closed direction (MFA-gated operations ask for a step-up), so a failure is logged,
	// not surfaced.
	if user.TOTPConfirmed && user.TOTPSecret != "" {
		if ok, merr := s.Sessions.Store.MarkMFAVerified(r.Context(), user.TenantID, user.ID, sess.ID, user.MFAGeneration); merr != nil || !ok {
			log.Printf("login: session not marked MFA-verified for user %s (ok=%v err=%v)", user.ID, ok, merr)
		}
	}
	// The trail already recorded every REJECTED attempt (auth.login_failed). Recording only
	// rejections inverts what the trail is for: after an incident the first question is who could
	// have been at a console, and the successful sign-in is the event that answers it. Unlike the
	// failure event this one NAMES the user — they proved who they were, so the attribution is
	// sound (auth.login_failed leaves the actor empty precisely because it is not).
	//
	// Best-effort and logged, exactly like auditLoginFailure: the session is already issued, so
	// failing the request here would lock out a user who authenticated correctly because the audit
	// store hiccuped. The password-change path below issues a session too but is NOT a login — it
	// is already recorded as auth.password_changed.
	//
	// `remembered` and `expires_at` are included so the trail captures the session shape — a
	// reviewer can see that a long-lived session was started and when it will naturally expire.
	if err := s.recordAuthEvent(r.Context(), user.TenantID, user.ID, "auth.login", map[string]any{
		"ip":         clientIP(r),
		"remembered": req.RememberDevice,
		"expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339),
	}); err != nil {
		log.Printf("could not record auth.login for tenant %s: %v", user.TenantID, err)
	}

	// Double-submit CSRF token (csrf.go): set as a NON-HttpOnly sibling cookie AND returned in
	// the body — the client echoes it in X-CSRF-Token on every mutating cookie-auth request. It is
	// DERIVED FROM the session token, so the middleware can verify the pair belongs together
	// instead of only that the two halves match each other.
	csrf := csrfTokenFor(token)
	http.SetCookie(w, s.sessionCookie(token, sess.ExpiresAt))
	http.SetCookie(w, s.csrfCookie(csrf, sess.ExpiresAt))
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":    user.ID,
		"tenant_id":  user.TenantID,
		"expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339),
		"csrf_token": csrf,
	})
}

// authenticateLocal is the credential-checking core, isolated from HTTP so it is directly
// unit-testable. It always runs a password verification (even for an unknown user, against a
// dummy hash) so response timing does not reveal whether the account exists.
//
// The second return value is the RESOLVED tenant id ("" when the tenant itself did not resolve).
// It is returned even on failure so the caller can file the failed-login audit event in the right
// tenant without repeating the privileged slug lookup.
// Account-wide login budget (see HandleLogin): free failures per idle-decay window, then one
// verification per delay regardless of source.
const (
	loginAccountFree  = 10
	loginAccountDelay = 30 * time.Second
)

// verifyLoginPassword is the one argon2 verification of the login path. The path label feeds the
// test hook so a test can assert that EVERY branch (unknown tenant, unknown user, disabled, real)
// performs exactly one verification, without measuring wall-clock time.
func (s *AuthService) verifyLoginPassword(ctx context.Context, path, hash, password string) (bool, error) {
	if s.loginVerifyHook != nil {
		s.loginVerifyHook(path)
	}
	return VerifyPasswordCtx(ctx, hash, password)
}

type loginThrottleError struct{ retry time.Duration }

func (e *loginThrottleError) Error() string { return "login temporarily throttled" }

func (s *AuthService) authenticateLocal(ctx context.Context, req loginRequest) (*AuthUser, string, error) {
	// Privileged bootstrap: resolve the tenant slug to its id before any RLS-scoped lookup.
	// The id is what pins app.current_tenant for the credential/TOTP queries below.
	tenantID := req.Tenant
	if s.Tenants != nil {
		id, terr := s.Tenants.ResolveTenant(ctx, req.Tenant)
		if terr != nil {
			// Unknown/disabled tenant is indistinguishable from bad credentials to the client:
			// it burns the same argon2 verification as the unknown-user path, otherwise ~100 ms
			// vs ~1 ms would enumerate live (and suspended) tenant slugs (review 2026-11-01 #12).
			if _, verr := s.verifyLoginPassword(ctx, "unknown_tenant", dummyHash, req.Password); IsHashCapacityError(verr) {
				return nil, "", verr
			}
			return nil, "", ErrInvalidCredentials
		}
		tenantID = id
	}
	// Every verification below is the CONTEXT-BOUNDED one (docs/25 F01): argon2 is a shared,
	// process-wide 64 MiB-per-call resource and this is the anonymous endpoint that spends it. A
	// saturation answer is propagated UNCHANGED rather than folded into ErrInvalidCredentials —
	// HandleLogin must be able to tell "no capacity" from "wrong password", because the latter
	// spends the account's throttle budget and an attacker who could trigger it with load alone
	// would hold a remote lockout switch for any account they can name.
	user, err := s.Users.FindUserByEmail(ctx, tenantID, req.Email)
	if err != nil || user == nil || user.PasswordHash == "" {
		// Spend comparable time to a real verification to blunt user enumeration.
		if _, verr := s.verifyLoginPassword(ctx, "unknown_user", dummyHash, req.Password); IsHashCapacityError(verr) {
			return nil, tenantID, verr
		}
		return nil, tenantID, ErrInvalidCredentials
	}
	if user.Disabled {
		if _, verr := s.verifyLoginPassword(ctx, "disabled", user.PasswordHash, req.Password); IsHashCapacityError(verr) {
			return nil, tenantID, verr
		}
		return nil, tenantID, ErrInvalidCredentials
	}
	ok, verr := s.verifyLoginPassword(ctx, "user", user.PasswordHash, req.Password)
	if verr != nil || !ok {
		if IsHashCapacityError(verr) {
			return nil, tenantID, verr
		}
		return nil, tenantID, ErrInvalidCredentials
	}
	// Tenant-level 2FA enforcement: if the tenant has opted all members into mandatory 2FA, refuse
	// a login from any account that has not confirmed a TOTP enrollment. Checked after password
	// verification so it does not leak account existence to an unauthenticated observer — a correct
	// password is the admission ticket to this check.
	if user.Require2FA && !user.TOTPConfirmed {
		return nil, tenantID, ErrTOTPEnrollmentRequired
	}
	// Second factor, if the account has a confirmed TOTP enrollment. A pending (unconfirmed)
	// re-enrollment is deliberately NOT consulted: until it is confirmed, the OLD authenticator
	// is the one that logs in.
	if user.TOTPSecret != "" && user.TOTPConfirmed {
		if strings.TrimSpace(req.TOTPCode) == "" {
			return nil, tenantID, ErrTOTPRequired
		}
		// Account-wide second-factor protection is charged only AFTER proving the password.
		// Anonymous password guesses cannot arm this account-wide lockout.
		totpKey := accountKey("login-totp", tenantID, user.ID)
		if retry, allowed := s.throttle().Allow(totpKey); !allowed {
			return nil, tenantID, &loginThrottleError{retry: retry}
		}
		step, valid, terr := VerifyTOTPStep(user.TOTPSecret, req.TOTPCode, s.now(), s.totpCfg())
		if terr != nil || !valid {
			s.throttle().Fail(totpKey)
			return nil, tenantID, ErrInvalidCredentials
		}
		// RFC 6238 §5.2: a code that has already authenticated must not authenticate again. The
		// skew window keeps each code valid for ~90s, which is ample time to reuse an observed one;
		// spending the step closes that. A store failure fails CLOSED — an unenforceable second
		// factor is not a second factor. Note this deliberately also rejects a second login inside
		// the SAME time step, which is precisely a replay of the same code.
		fresh, cerr := s.Users.ConsumeTOTPStep(ctx, tenantID, user.ID, step)
		if cerr != nil || !fresh {
			s.throttle().Fail(totpKey)
			return nil, tenantID, ErrInvalidCredentials
		}
		s.throttle().Reset(totpKey)
	}
	return user, tenantID, nil
}

// auditLoginFailure files a best-effort auth.login_failed event. The actor is left empty — the
// caller did not authenticate, so attributing the event to the named account would let an attacker
// write another user's audit trail; the attempted email and source IP go into the metadata
// instead. Recording failures are logged, never surfaced: the response is already a 401.
func (s *AuthService) auditLoginFailure(r *http.Request, tenantID, email string) {
	if err := s.recordAuthEvent(r.Context(), tenantID, "", "auth.login_failed", map[string]any{
		"email": auditEmailField(email),
		"ip":    clientIP(r),
	}); err != nil {
		log.Printf("could not record auth.login_failed for tenant %s: %v", tenantID, err)
	}
}

// auditEmailField bounds the attacker-chosen login email an auth.login_failed event records. The
// email is never length-checked before a failed login (the 64 KiB body cap was the only bound), so
// each anonymous failure could append ~64 KiB to the tenant's audit chain under its advisory lock
// (security audit 2026-10-18). No real address exceeds 254 bytes (RFC 5321), so the cut keeps
// every genuine value intact and marks the cut ones.
func auditEmailField(email string) string {
	const max = 254
	if len(email) <= max {
		return email
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(email[cut]) {
		cut--
	}
	return email[:cut] + "…(truncated)"
}

// HandleLogout is POST /auth/logout: revoke the current session and clear the cookie. Safe
// to mount either behind the auth middleware or publicly (it only acts on the presented
// token). Always returns 204 so a stale/absent token is not distinguishable.
func (s *AuthService) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if token := bearerToken(r, s.cookieName()); token != "" {
		// The lookups below are unmetered database work for ANY bearer string, so they run under the
		// credential guard (credential_guard.go): a token that cannot be one of ours is not looked up
		// and gets the usual answer; a plausible one that is not already known-good is charged to its
		// source's failure budget, and a source over budget gets an honest 429 (503 when the global cap
		// is full) rather than a 204 — answering 204 without revoking would tell a legitimate client
		// from a NATed source its session was closed when it was not. A recently-valid token (the
		// common logout) is never refused.
		err := s.Guard.Lookup(r, token, false, func() error {
			// Resolve the session BEFORE revoking it: afterwards the token names nobody, and an
			// unattributed logout cannot close the bracket that auth.login opens. A session that does
			// not validate (already expired, already revoked, forged) yields no event — there is no
			// authenticated identity to attribute one to, and inventing one from an unproven token is
			// the same mistake auth.login_failed avoids.
			sess, verr := s.Sessions.Validate(r.Context(), token)
			if verr == nil && sess != nil {
				if aerr := s.recordAuthEvent(r.Context(), sess.TenantID, sess.UserID, "auth.logout", map[string]any{
					"ip": clientIP(r),
				}); aerr != nil {
					log.Printf("could not record auth.logout for tenant %s: %v", sess.TenantID, aerr)
				}
			}
			ctx, cancel := compensationContext(r)
			_ = s.Sessions.Revoke(ctx, token)
			cancel()
			return verr
		})
		if ref := credentialRefusalOf(err); ref != nil {
			// The server session cannot be revoked now (it survives until its own idle/absolute expiry), but
			// the browser's copy can and should be cleared: the console closes its gate locally on logout and
			// ignores a failed request, so without these headers the user believes they signed out while a
			// live cp_session cookie signs them straight back in on the next page load. Clearing a cookie
			// the server never validated is harmless.
			s.clearSessionCookies(w)
			writeCredentialRefusal(w, ref)
			return
		}
		// Revoked (or never valid): either way it must not keep exempting its holder from the gates.
		s.Guard.Forget(token)
	}
	s.clearSessionCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

// clearSessionCookies expires the session and CSRF cookies in the browser.
func (s *AuthService) clearSessionCookies(w http.ResponseWriter) {
	http.SetCookie(w, s.sessionCookie("", s.now().Add(-time.Hour)))
	http.SetCookie(w, s.csrfCookie("", s.now().Add(-time.Hour)))
}

// enrollTOTPRequest is the body of POST /auth/totp/enroll. Exactly one of the two fields is
// required, and which one depends on what the account already has:
//
//	Code      when a CONFIRMED enrollment exists — re-arming 2FA is proven with the CURRENT factor.
//	Password  on a FIRST enrollment — there is no factor to prove yet, so the first one is proven
//	          with the password (see HandleEnrollTOTP for why a session is not enough).
type enrollTOTPRequest struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

// HandleEnrollTOTP is the protected POST /auth/totp/enroll: generate a secret for the
// authenticated caller, store it as PENDING, and return the otpauth URI + secret so the client can
// render a QR code. Enrollment is completed by HandleConfirmTOTP.
//
// ENROLLING REQUIRES A STEP-UP IN BOTH DIRECTIONS. Two properties make this safe to call on an
// account that already has 2FA:
//
//   - the new secret lands in the pending slot only (migrations/0009), so the CONFIRMED secret
//     keeps being enforced at login until the new one is confirmed — an abandoned re-enroll can no
//     longer silently downgrade the account to password-only;
//   - re-enrolling requires a valid CURRENT code, so someone riding a stolen session (or an XSS
//     foothold) cannot convert that session into a permanent authentication downgrade.
//
// A FIRST enrollment has no current code to demand, and for a long time it therefore demanded
// nothing at all — the session was the whole authorization. That is the wrong default for the one
// operation that decides what the account's second factor will be. Someone riding a stolen session
// could arm THEIR authenticator on an account that had none, and from that moment they hold a
// factor the real owner does not: the owner's later password change no longer locks them out,
// because logging back in now requires a code only the attacker can produce. A session compromise
// becomes durable, and it becomes durable through the very feature meant to prevent that.
//
// So a first enrollment demands the CURRENT PASSWORD. It is the only proof available before any
// second factor exists, and it is proof a session rider does not have — the same reasoning that
// makes /me/password verify the current password rather than trusting the session it arrived on.
//
// An account with NO local credential is answered 409, exactly as /me/password answers it: there is
// nothing to step up with, so arming a factor would be authorized by the session alone. Such an
// account must be given a password first (POST /users/{id}/password-reset → /auth/password/redeem).
// When federated login lands, its assertion becomes the third acceptable proof here.
//
// The attempt is metered and the enrollment is audited.
func (s *AuthService) HandleEnrollTOTP(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req enrollTOTPRequest
	// The body is optional at the transport level (an empty one is well-formed); the step-up below
	// is what rejects it when the account needs a proof. Anything present must still be valid JSON.
	if err := decodeOptionalJSON(w, r, maxSmallJSONBodyBytes, &req, "invalid request body"); err != nil {
		return
	}
	u, err := s.Users.FindUserByID(r.Context(), p.TenantID, p.UserID)
	if err != nil || u == nil {
		writeError(w, http.StatusInternalServerError, "could not resolve user")
		return
	}

	th := s.throttle()
	stepUpFactor := "totp"
	if u.TOTPSecret != "" && u.TOTPConfirmed {
		keys := []string{
			accountKey("totp", p.TenantID, p.UserID),
			ipKey("totp", clientIP(r)),
		}
		if retry, ok := th.Allow(keys...); !ok {
			writeThrottled(w, retry)
			return
		}
		step, valid, verr := VerifyTOTPStep(u.TOTPSecret, req.Code, s.now(), s.totpCfg())
		if verr != nil || !valid {
			th.Fail(keys...)
			s.auditStepUpFailure(r, p, "totp")
			writeError(w, http.StatusForbidden, "current totp code required to re-enroll")
			return
		}
		// SPEND the step, on the same ledger login uses (RFC 6238 §5.2). Verifying without
		// consuming made this step-up far weaker than it reads: the ±1-step skew keeps a code live
		// for ~90s, so any observed one — including the code the victim had just spent logging in,
		// which the ledger already recorded — re-authorized a re-enrollment. That is exactly the
		// session-rider this endpoint's step-up exists to stop, and the defence it needed was
		// already built and already used one function up in this file.
		//
		// Fails CLOSED on a store error, as at login: a step-up whose single-use property cannot be
		// enforced is not a step-up. Rejected identically to a wrong code — telling the caller the
		// code was "already used" would confirm it was genuine.
		fresh, cerr := s.Users.ConsumeTOTPStep(r.Context(), p.TenantID, p.UserID, step)
		if cerr != nil || !fresh {
			th.Fail(keys...)
			s.auditStepUpFailure(r, p, "totp")
			writeError(w, http.StatusForbidden, "current totp code required to re-enroll")
			return
		}
		th.Reset(keys...)
	} else {
		stepUpFactor = "password"
		if u.PasswordHash == "" {
			writeError(w, http.StatusConflict, ErrNoLocalCredential.Error())
			return
		}
		// Metered on the SAME per-session key as /me/password, which is deliberate rather than
		// incidental: both are password guesses made from one authenticated session, so sharing the
		// budget means an attacker riding that session gets one allowance for the secret instead of
		// a fresh one per endpoint to alternate between. passwordThrottleKey explains why the
		// budget is the session's and not the account's — the short version is that keying it on
		// the account would let the rider spend the victim's budget and hold the recovery paths
		// shut.
		keys := []string{passwordThrottleKey(p)}
		if retry, ok := th.Allow(keys...); !ok {
			writeThrottled(w, retry)
			return
		}
		valid, verr := VerifyPasswordCtx(r.Context(), u.PasswordHash, req.Password)
		if IsHashCapacityError(verr) {
			// No argon2 capacity (docs/25 F01) — the password was not examined, so this costs no
			// budget and files no step-up failure.
			WriteHashBusy(w)
			return
		}
		if verr != nil || !valid {
			th.Fail(keys...)
			s.auditStepUpFailure(r, p, "password")
			writeError(w, http.StatusForbidden, "current password required to enroll a second factor")
			return
		}
		th.Reset(keys...)
	}

	secret, err := GenerateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate secret")
		return
	}
	if err := s.Users.SetPendingTOTP(r.Context(), p.TenantID, p.UserID, secret); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store secret")
		return
	}
	// An unauditable credential mutation must be loud, matching the console handlers. `step_up`
	// records WHICH proof was accepted, because "a second factor was armed on this account" and
	// "it was armed by someone who knew the password" are different facts to a reviewer.
	if err := s.recordAuthEvent(r.Context(), p.TenantID, p.UserID, "totp.enroll",
		map[string]any{"reenrollment": u.TOTPConfirmed, "step_up": stepUpFactor, "ip": clientIP(r)}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	account := p.UserID
	if u.Email != "" {
		account = u.Email
	}
	uri := TOTPKeyURI(secret, s.issuer(), account, s.totpCfg())
	// The secret is returned once here (the client needs it for the QR code); it is not
	// logged. After confirmation it should never be returned again.
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      secret,
		"otpauth_uri": uri,
	})
}

type confirmTOTPRequest struct {
	Code string `json:"code"`
}

// HandleConfirmTOTP is the protected POST /auth/totp/confirm: verify a code against the PENDING
// secret and promote it, activating it for future logins. Only a pending secret can be confirmed
// (ConfirmPendingTOTP), so a confirmation can never re-activate an older enrollment, and code
// guessing here is metered exactly like login.
//
// The accepted code is SPENT on the shared replay ledger, as at login and on the enroll step-up —
// it is a live code for the secret being activated, so leaving it unrecorded handed anyone who saw
// it a working login for the rest of its skew window.
func (s *AuthService) HandleConfirmTOTP(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req confirmTOTPRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "invalid request body"); err != nil {
		return
	}
	th := s.throttle()
	keys := []string{
		accountKey("totp", p.TenantID, p.UserID),
		ipKey("totp", clientIP(r)),
	}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return
	}
	u, err := s.Users.FindUserByID(r.Context(), p.TenantID, p.UserID)
	if err != nil || u == nil || u.TOTPPending == "" {
		writeError(w, http.StatusBadRequest, ErrNoPendingTOTP.Error())
		return
	}
	step, valid, verr := VerifyTOTPStep(u.TOTPPending, req.Code, s.now(), s.totpCfg())
	if verr != nil || !valid {
		th.Fail(keys...)
		writeError(w, http.StatusForbidden, "invalid code")
		return
	}
	// SPEND the step, on the one ledger login and the enroll step-up already share (RFC 6238 §5.2).
	// The code presented here is a live code for the secret this call is about to ENFORCE, so
	// verifying without consuming left it good for a login for the rest of its ~90s skew window:
	// whoever read the confirmation code off the setup screen held the account's first login.
	//
	// Fails CLOSED on a store error and is rejected identically to a wrong code — "already used"
	// would confirm to the caller that the code was genuine. Consuming BEFORE the promotion is
	// deliberate: a confirmation that dies at ConfirmPendingTOTP has still burned its code, which is
	// the safe direction to fail in.
	//
	// The ledger is keyed on (user, step), not (user, secret, step), so this also refuses a
	// confirmation sharing a 30s step with the re-enroll step-up that produced the pending secret.
	// That cost is accepted rather than papered over with a second, write-only spend mechanism; see
	// TestConfirmTOTPSharesOneLedgerWithLoginAndEnroll.
	fresh, cerr := s.Users.ConsumeTOTPStep(r.Context(), p.TenantID, p.UserID, step)
	if cerr != nil || !fresh {
		th.Fail(keys...)
		writeError(w, http.StatusForbidden, "invalid code")
		return
	}
	if err := s.Users.ConfirmPendingTOTP(r.Context(), p.TenantID, p.UserID); err != nil {
		if errors.Is(err, ErrNoPendingTOTP) {
			writeError(w, http.StatusBadRequest, ErrNoPendingTOTP.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not confirm enrollment")
		return
	}
	th.Reset(keys...)
	if err := s.recordAuthEvent(r.Context(), p.TenantID, p.UserID, "totp.confirm",
		map[string]any{"ip": clientIP(r)}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"confirmed": true})
}

// -------------------------------------------------------------------------------------
// Password change — POST /me/password (docs/01-feature-parity.md §10 P0)
// -------------------------------------------------------------------------------------

// ErrNoLocalCredential is returned when a password change is attempted on an account that has no
// local credential to change (a purely federated user, once OIDC lands).
var ErrNoLocalCredential = errors.New("account has no local password credential")

// maxPasswordBodyBytes caps the change-password body. The policy's own MaxLen bounds the password
// itself; this bounds the envelope, matching the cap on every other credential endpoint.
const maxPasswordBodyBytes = 1 << 16

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// passwordThrottleKey meters /me/password PER SESSION, not per account and not per source IP.
//
// This is the load-bearing choice, and both alternatives are actively harmful here:
//
//   - Per ACCOUNT is the obvious key and is WRONG for this endpoint specifically. The whole
//     purpose of /me/password is to evict a stolen session; if the budget were the account's,
//     the thief riding that session could spend it — six wrong guesses is enough — and the real
//     owner would then be answered 429 when they try to recover, with the lockout re-armed by one
//     request per window for the session's whole 12-hour life. The endpoint that exists to kick
//     the attacker out would be the one thing the attacker can hold shut.
//   - Per SOURCE IP is wrong because this endpoint is authenticated and typically sits behind a
//     reverse proxy, where clientIP is the proxy for every caller: one user's fumbling would then
//     throttle password changes for every other user of the deployment.
//
// The session is the right budget because a session cannot be minted without the password: an
// attacker holding one stolen session gets exactly one budget and cannot refresh it, while the
// victim — logging in again, which the attacker cannot do — gets a fresh one and can recover.
// A caller with no session id (StubAuthenticator in DEV/tests) falls back to the account key,
// which is no worse than before for a path that has no session to key on.
// The session goes in the KIND, not concatenated into the account: accountKey's components must not
// contain its separator (see its contract), and smuggling a second identifier into `account` would
// make the key ambiguous. Session ids are base64url / uuid text, so they cannot collide with the
// ":" namespace punctuation either.
func passwordThrottleKey(p *Principal) string {
	if p.SessionID == "" {
		return accountKey("password", p.TenantID, p.UserID)
	}
	return accountKey("password|"+p.SessionID, p.TenantID, p.UserID)
}

// HandleChangePassword is the protected POST /me/password: the authenticated caller changes THEIR
// OWN password. It is mounted inside the protected chain, so it is already behind
// csrfMiddleware → authMiddleware → tenantMiddleware; there is no user id in the request, only the
// principal, so it cannot be aimed at another account.
//
// The steps, and the reason each one is not optional:
//
//	verify CURRENT password   A live session alone must not be enough. Sessions are the thing that
//	                          gets stolen (XSS, a borrowed laptop, a leaked bearer token); if a
//	                          session could set a new password, every session compromise would
//	                          become a permanent account takeover with the real owner locked out.
//	                          Verified with the same constant-time VerifyPassword as login.
//	POLICY on the new one     ValidatePassword — length, classes, no identity echo, blocklist.
//	differ from the current   The one reuse check reachable without password history: a "change"
//	                          that changes nothing would otherwise report success and give the
//	                          user a false belief that a compromised password is retired.
//	argon2id, never plaintext HashPassword before the store ever sees it (UserStore.SetPassword
//	                          takes a PHC string, so no implementation can persist a plaintext).
//	revoke OTHER sessions     What actually evicts an attacker. Without it the thief keeps a valid
//	                          server-side session for its full lifetime and the password change is
//	                          cosmetic. The CALLER'S session is deliberately kept, so changing a
//	                          password does not log the user out of the tab they did it in.
//	audit                     auth.password_changed on success, auth.password_change_failed on a
//	                          wrong current password — a run of the latter is exactly the signal a
//	                          SOC wants out of GET /audit.
//
// Metering uses its OWN throttle namespace ("password"), not login's. Sharing it would let anyone
// holding a session burn the victim's LOGIN budget and lock them out of the product — a denial of
// service handed over for no gain.
//
// Not required here: a TOTP code. Re-enrolling TOTP demands the current code because a session
// rider could otherwise downgrade the account's second factor while knowing no secret at all; this
// endpoint already demands the current password, which such a rider does not have.
//
// THE LOGIN RACE, AND WHY THE REVOCATION ABOVE IS NOT ENOUGH ON ITS OWN (closed by
// migrations/0018). SetPassword and the revocation are separate transactions, so a login that READ
// the old hash before SetPassword committed can INSERT its session after the revocation committed —
// producing a live 12-hour session authorized by the password just retired, revoked by nothing. The
// window is about one argon2id verification (~100 ms at 64 MiB), and the attacker must already know
// the old password, which is the exact case a rotation exists for.
//
// Neither reordering nor re-revoking closes it: any revocation happens at SOME instant and the
// racing INSERT can always land after it. So sessions are no longer compared by instant but by
// CREDENTIAL VERSION: `Issue` stamps each session with the `user_credential.updated_at` that its
// caller's own credential read returned, and `SessionAuthenticator.Authenticate` refuses any
// session whose stamp is older than the credential's current one. The racing session still gets
// inserted; it simply carries the pre-change version and is refused on its first request.
//
// That is why `epoch` below comes back from SetPassword rather than from time.Now(): the
// replacement session must carry the version the store actually wrote, or the response to a
// successful password change would hand the caller a session that is stale the moment it is minted.
func (s *AuthService) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req changePasswordRequest
	if err := decodeJSONBody(w, r, maxPasswordBodyBytes, &req, "invalid request body"); err != nil {
		return
	}

	th := s.throttle()
	keys := []string{passwordThrottleKey(p)}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return
	}

	u, err := s.Users.FindUserByID(r.Context(), p.TenantID, p.UserID)
	if err != nil || u == nil {
		writeError(w, http.StatusInternalServerError, "could not resolve user")
		return
	}
	if u.PasswordHash == "" {
		// Nothing to verify against, so there is no way to prove the caller is the account owner
		// rather than someone riding their session. Setting a FIRST password is provisioning, and
		// provisioning belongs on an authenticated admin path — not on a self-service endpoint
		// where a stolen session would be the only credential involved. See docs/01 §10.
		writeError(w, http.StatusConflict, ErrNoLocalCredential.Error())
		return
	}

	ok, verr := VerifyPasswordCtx(r.Context(), u.PasswordHash, req.CurrentPassword)
	if IsHashCapacityError(verr) {
		// No argon2 capacity (docs/25 F01). Not metered, not audited as a failure — the current
		// password was never checked.
		WriteHashBusy(w)
		return
	}
	if verr != nil || !ok {
		th.Fail(keys...)
		s.auditPasswordEvent(r, p, "auth.password_change_failed", nil)
		writeError(w, http.StatusForbidden, ErrInvalidCredentials.Error())
		return
	}
	// The current password is proven. Everything below is a validation failure, not a credential
	// failure, so it costs no throttle budget — a user fumbling the complexity rules is not an
	// attacker and must not be locked out by trying.
	th.Reset(keys...)

	if err := ValidatePassword(req.NewPassword, PasswordIdentity{
		Email: u.Email, DisplayName: u.DisplayName,
	}, DefaultPasswordPolicy); err != nil {
		var pe *PasswordPolicyError
		if errors.As(err, &pe) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":   pe.Error(),
				"reasons": pe.Reasons,
			})
			return
		}
		writeError(w, http.StatusBadRequest, "password does not meet policy")
		return
	}
	same, sameErr := VerifyPasswordCtx(r.Context(), u.PasswordHash, req.NewPassword)
	if IsHashCapacityError(sameErr) {
		WriteHashBusy(w)
		return
	}
	if same {
		writeError(w, http.StatusBadRequest, "new password must differ from the current one")
		return
	}

	// Check password history — rejects reuse of recently retired credentials.
	if err := checkPasswordHistory(r.Context(), s.PasswordHistory, p.TenantID, p.UserID, req.NewPassword); err != nil {
		if IsHashCapacityError(err) {
			WriteHashBusy(w)
			return
		}
		if errors.Is(err, ErrPasswordReused) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not check password history")
		return
	}

	hash, err := HashPasswordCtx(r.Context(), req.NewPassword)
	if IsHashCapacityError(err) {
		WriteHashBusy(w)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not hash password")
		return
	}
	// The epoch comes back from the store, not from this process's clock: it is the version stamp
	// the replacement session below must carry, and only the value storage persisted identifies the
	// row that was actually written.
	oldHash := u.PasswordHash // captured before SetPassword overwrites the credential
	epoch, err := s.Users.ChangePassword(r.Context(), p.TenantID, p.UserID, hash, u.CredentialUpdatedAt)
	if errors.Is(err, ErrStaleCredential) {
		// Another change (or a reset) committed after this request verified the current password;
		// nothing was written. 409 as for the email change: sign in again with the password now set.
		writeError(w, http.StatusConflict, ErrStaleCredential.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update password")
		return
	}
	// Push the retired credential into history so it cannot be immediately recycled. Best-effort:
	// failure is logged but does not roll back the already-committed credential change.
	if s.PasswordHistory != nil && oldHash != "" {
		if err := s.PasswordHistory.RecordPassword(r.Context(), p.TenantID, p.UserID, oldHash); err != nil {
			log.Printf("password changed for user %s but history could not be recorded: %v", p.UserID, err)
		}
	}

	// From here the password IS changed. Every remaining failure therefore says so explicitly
	// rather than returning a bare 500 the user would read as "nothing happened" — they must not
	// go on trying the old password.
	//
	// EVERY session is revoked, INCLUDING the caller's own, and a fresh one is issued in its place.
	// Keeping the presented token alive (the obvious "don't log the user out of this tab" design)
	// silently exempts the one credential most likely to be copied: whoever holds a duplicate of
	// that token — lifted from a browser profile, a proxy access log, an integration that logged a
	// Bearer header — would be precisely the session that survives the eviction. Since the token is
	// what identifies the survivor, and a copy is indistinguishable from the original, the only
	// sound answer is to retire it and mint a new one. The browser adopts the new cookie from this
	// response, so the UX is unchanged; a copied token is dead.
	revoked, rerr := s.Sessions.RevokeOtherSessions(r.Context(), p.TenantID, p.UserID, "")
	if rerr != nil {
		log.Printf("password changed for user %s but sessions could not be revoked: %v", p.UserID, rerr)
		writeError(w, http.StatusInternalServerError,
			"password was changed but existing sessions could not be revoked; revoke them manually")
		return
	}
	// Issue deliberately uses the ORDINARY session path (Issue, not IssueRemembered). A password
	// change is a security event: every prior session — including any remembered one — was just
	// revoked, and silently re-issuing a 30-day token here would undermine that. The user must
	// re-opt in to "remember device" by logging in fresh with remember_device = true.
	token, sess, err := s.Sessions.Issue(r.Context(), p.TenantID, p.UserID, epoch)
	if err != nil {
		// The password changed and every session is gone: the caller is signed out everywhere and
		// must log in with the NEW password. Say so — this is a safe state, not a broken one.
		log.Printf("password changed for user %s but a replacement session could not be issued: %v", p.UserID, err)
		writeError(w, http.StatusInternalServerError,
			"password was changed and all sessions were signed out, but a new session could not be "+
				"issued; sign in again with the new password")
		return
	}
	if err := s.auditPasswordEvent(r, p, "auth.password_changed",
		map[string]any{"sessions_revoked": revoked}); err != nil {
		writeError(w, http.StatusInternalServerError,
			"password was changed but the audit event could not be recorded")
		return
	}
	// The rotated token is known-good: register it with the credential guard so its holder is not refused by a
	// failure budget an attacker sharing this source ran down (credential_guard.go). After the Issue error check,
	// so only a token that exists is registered.
	s.Guard.NoteValid(token)
	// Same cookie pair as login: the rotated session plus its derived CSRF token, so the client
	// keeps working without a re-login and the old CSRF value (derived from the retired token) is
	// replaced along with it.
	csrf := csrfTokenFor(token)
	http.SetCookie(w, s.sessionCookie(token, sess.ExpiresAt))
	http.SetCookie(w, s.csrfCookie(csrf, sess.ExpiresAt))
	writeJSON(w, http.StatusOK, map[string]any{
		"changed": true,
		// How many live sessions were signed out — INCLUDING the caller's own, which was replaced
		// by the one this response carries.
		"sessions_revoked": revoked,
		"csrf_token":       csrf,
		"expires_at":       sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// auditStepUpFailure files a failed re-authentication on a credential-mutating endpoint —
// `factor` names which proof was rejected ("totp" or "password").
//
// Best-effort and logged on failure, exactly like auditLoginFailure: the response is already a 401
// and turning a refused step-up into a 500 would tell an attacker they had found a different kind
// of edge. A RUN of these is the signal a SOC wants, though, because it means something holding a
// live session is guessing at the credential behind it — which a legitimate user's own browser has
// no reason to do.
func (s *AuthService) auditStepUpFailure(r *http.Request, p *Principal, factor string) {
	err := s.recordAuthEvent(r.Context(), p.TenantID, p.UserID, "auth.totp_enroll_denied",
		map[string]any{"factor": factor, "ip": clientIP(r)})
	if err != nil {
		log.Printf("could not record auth.totp_enroll_denied for tenant %s: %v", p.TenantID, err)
	}
}

// auditPasswordEvent files a password-lifecycle event. The source IP always travels with it; the
// caller adds any extra metadata. Failures on the FAILED-attempt path are logged rather than
// surfaced (the response is already a 401, exactly like auditLoginFailure); the success path
// propagates the error so an unauditable credential mutation is loud.
func (s *AuthService) auditPasswordEvent(r *http.Request, p *Principal, action string, meta map[string]any) error {
	if meta == nil {
		meta = map[string]any{}
	}
	meta["ip"] = clientIP(r)
	err := s.recordAuthEvent(r.Context(), p.TenantID, p.UserID, action, meta)
	if err != nil && action == "auth.password_change_failed" {
		log.Printf("could not record %s for tenant %s: %v", action, p.TenantID, err)
		return nil
	}
	return err
}

func (s *AuthService) issuer() string {
	if s.Issuer != "" {
		return s.Issuer
	}
	return "Control Plane"
}

func (s *AuthService) sessionCookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     s.cookieName(),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
}

// csrfCookie is the double-submit sibling of sessionCookie: deliberately NOT HttpOnly (the
// SPA must read it to echo X-CSRF-Token), same SameSite/Secure/lifetime posture otherwise.
func (s *AuthService) csrfCookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     s.csrfCookieName(),
		Value:    value,
		Path:     "/",
		HttpOnly: false,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
}

// dummyHash is a valid argon2id hash of a random throwaway secret, computed once at startup.
// Verifying against it on the unknown-user path spends argon2 work comparable to a real
// verification, so login latency does not leak whether an account exists. It must be a
// well-formed hash (an unparseable one would return early and defeat the equalization).
var dummyHash = mustDummyHash()

func mustDummyHash() string {
	tok, err := newSessionToken()
	if err != nil {
		tok = "unused-fallback-secret"
	}
	h, err := HashPassword(tok)
	if err != nil {
		// Should never happen; fall back to a value that still parses.
		h, _ = HashPasswordWith("unused-fallback-secret", DefaultArgon2Params)
	}
	return h
}

func (s *AuthService) csrfCookieName() string {
	if s.SecureCookie {
		return "__Host-" + CSRFCookieName
	}
	return CSRFCookieName
}
