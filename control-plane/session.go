package controlplane

// Server-side sessions. Login issues an opaque high-entropy bearer token; only its SHA-256
// hash is persisted (like enrollment_token in migrations/0001_core.sql), so a database read
// never yields a usable credential. Every protected request looks the session up by hash and
// re-checks expiry + revocation, so access can be cut immediately by revoking server-side —
// unlike a stateless JWT.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultSessionTTL is the ABSOLUTE lifetime of a freshly issued session. Sane and finite: a
// SYSTEM-level tool must not hand out effectively immortal tokens.
const DefaultSessionTTL = 12 * time.Hour

// DefaultSessionIdleTTL is the INACTIVITY timeout: a session unused for this long is treated as
// expired even if its absolute ExpiresAt is still in the future. This closes the "walked away from
// an unlocked console" gap — `last_seen` was recorded on every request but nothing enforced it.
// Each authenticated request refreshes last-seen, so an active session never idles out.
const DefaultSessionIdleTTL = 30 * time.Minute

// RememberedSessionTTL is the ABSOLUTE lifetime of a remembered (desktop "remember me") session.
// Fixed, not configurable — a configurable maximum is just a knob a misconfiguration can set to
// infinity. The desktop app's Windows Hello unlock path uses this so a session survives reboots
// without re-entering a password. Full credential verification still runs at login.
const RememberedSessionTTL = 30 * 24 * time.Hour

// RememberedSessionIdleTTL is the INACTIVITY timeout for a remembered session. The same idle
// enforcement logic applies — an active session never idles out; an abandoned one does.
const RememberedSessionIdleTTL = 7 * 24 * time.Hour

// Session errors. Lookups fail closed and do not distinguish "no such token" from "expired"
// to the caller beyond these typed errors, which the auth layer collapses to 401.
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionIdle     = errors.New("session idle-timed-out")
	ErrSessionRevoked  = errors.New("session revoked")
	// ErrSessionCredentialStale is the credential-epoch refusal: the password this session was
	// authorized by has since been replaced. See CredentialEpochMatches and migrations/0018.
	ErrSessionCredentialStale = errors.New("session predates the current credential")
)

// Session is one server-side login session. TokenHash is the SHA-256 of the bearer token;
// the plaintext token is returned to the client exactly once, at issue.
type Session struct {
	ID        string
	TenantID  string
	UserID    string
	TokenHash []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
	LastSeen  time.Time
	// CredentialEpoch is user_credential.updated_at as READ IN THE SAME QUERY that returned the
	// password hash this session was authorized by (migrations/0018). Zero when the user has no
	// local credential — or, for a row predating 0018 that the backfill did not reach, unknown,
	// which CredentialEpochMatches treats as older than any credential.
	//
	// It must never be set from the issuing process's clock: the point is to name a VERSION of a
	// stored row, and only the value storage returned identifies that version.
	CredentialEpoch time.Time
	// MFAVerifiedAt / MFAGeneration: when a TOTP code was last verified IN this session and against
	// which app_user.mfa_generation (migrations/0054). Nil / 0 = never. Set only via MarkMFAVerified.
	MFAVerifiedAt *time.Time
	MFAGeneration int64
	// Remembered is true when the login opted in to a long-lived desktop session (migrations/0053):
	// 30-day absolute TTL and 7-day idle timeout instead of the ordinary 12h / 30-min defaults.
	// Set only at issue time; never promoted retroactively. SessionManager.Validate reads this flag
	// from the persisted row to decide the idle timeout — the client UA is never consulted.
	Remembered bool
	// SourceIP / UserAgent are the login request's trusted client address and (sanitised, truncated)
	// User-Agent (user_session.source_ip / user_agent; sourceip.go), taken from the issuing context.
	// Write-only: stored for incident response and never consulted when validating a session, so a
	// roaming user is not signed out by a changed address. "" is stored as NULL.
	SourceIP  string
	UserAgent string
}

// CredentialEpochMatches reports whether a session is still authorized by the CURRENT credential.
//
// This is the whole password-change TOCTOU fix in one comparison (see migrations/0018 for the
// interleaving). A login that read the old password hash carries the old epoch, so a session it
// inserts AFTER the change's revocation has already committed is still refused here — the check is
// on versions, not on instants, and a racing INSERT cannot make an old version new.
//
// Strictly older is the test, not inequality: equal epochs are the normal case (the session was
// issued against exactly this credential), and a session whose epoch is somehow NEWER than the
// credential's is not something to sign the user out over — it can only arise from a clock or
// backfill anomaly, never from the race this closes, and the sessions that DO matter after a
// password change were already revoked outright.
func CredentialEpochMatches(sessionEpoch, credentialEpoch time.Time) bool {
	return !sessionEpoch.Before(credentialEpoch)
}

// Active reports whether the session is currently usable at time now.
func (s *Session) Active(now time.Time) error {
	if s.RevokedAt != nil {
		return ErrSessionRevoked
	}
	if !now.Before(s.ExpiresAt) {
		return ErrSessionExpired
	}
	return nil
}

// SessionStore is the persistence seam for sessions. The production implementation is
// pgx-backed against user_session (RLS-scoped); tests use InMemorySessionStore. Lookups are
// by token hash so the plaintext token never touches storage.
type SessionStore interface {
	Insert(ctx context.Context, s *Session) error
	GetByTokenHash(ctx context.Context, tokenHash []byte) (*Session, error)
	Revoke(ctx context.Context, tokenHash []byte) error
	TouchLastSeen(ctx context.Context, tokenHash []byte, at time.Time) error
	// RevokeAllForUser revokes every live session belonging to a user EXCEPT the one identified
	// by keepTokenHash (pass nil to revoke all of them), returning how many were revoked.
	//
	// This is what makes a password change actually recover an account. Without it, an attacker
	// who had already logged in keeps a valid server-side session for its full 12-hour lifetime,
	// so the victim's "I changed my password" does nothing to evict them. Unlike the by-token
	// operations, this one is TENANT-SCOPED (the caller is authenticated, so the tenant is known)
	// and therefore runs RLS-pinned rather than through the RLS-bypassing bootstrap functions.
	RevokeAllForUser(ctx context.Context, tenantID, userID string, keepTokenHash []byte) (int, error)
	// MarkMFAVerified records a TOTP verification against `generation` in session sessionID, only
	// while that generation is still the user's current one (migrations/0054). false = not marked.
	MarkMFAVerified(ctx context.Context, tenantID, userID, sessionID string, generation int64) (bool, error)
	// MFAFresh reports whether sessionID is live, belongs to userID, was TOTP-verified within maxAge AND
	// that verification is against the user's CURRENT mfa generation (a re-enrollment since then voids
	// it). It is the first reader of Session.MFAVerifiedAt (docs/65 F1 step-up). The age is measured on the
	// store's clock (pg: now()), never the application's.
	MFAFresh(ctx context.Context, tenantID, userID, sessionID string, maxAge time.Duration) (bool, error)
	// SessionLive reports whether sessionID belongs to userID and is neither revoked nor expired, on the
	// store's clock. Directive issuance asks it for the requester and the approver: the sweeper has no
	// request to authenticate, so "the session that asked is still a live session" is read here.
	SessionLive(ctx context.Context, tenantID, userID, sessionID string) (bool, error)
	// StepUpSnapshot is MFAFresh that ALSO returns, from the SAME read of the live session, the exact mfa
	// generation the verification was made against and the user's credential epoch at that moment. A
	// directive records THIS snapshot: reading the generation in a second query would let an MFA reset between
	// the two reads stamp the NEW generation on an OLD verification.
	StepUpSnapshot(ctx context.Context, tenantID, userID, sessionID string, maxAge time.Duration) (StepUp, error)
}

// StepUp is the answer of StepUpSnapshot. CredentialEpoch is the zero time when the store cannot see the
// credential (the fake) or the user has no local credential.
type StepUp struct {
	Fresh           bool
	MFAGeneration   int64
	CredentialEpoch time.Time
}

// HashToken returns the SHA-256 of a bearer token — the value stored and looked up.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// newSessionToken returns a fresh 256-bit URL-safe bearer token.
func newSessionToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// SessionManager issues and validates sessions on top of a SessionStore.
type SessionManager struct {
	Store SessionStore
	TTL   time.Duration
	// IdleTTL is the inactivity timeout enforced by Validate. 0 disables idle enforcement (absolute
	// ExpiresAt still applies). Defaults to DefaultSessionIdleTTL.
	IdleTTL time.Duration
	// Now is injectable for tests; defaults to time.Now.
	Now func() time.Time
}

// NewSessionManager builds a manager with the default absolute + idle TTLs and real clock.
func NewSessionManager(store SessionStore) *SessionManager {
	return &SessionManager{Store: store, TTL: DefaultSessionTTL, IdleTTL: DefaultSessionIdleTTL, Now: time.Now}
}

func (m *SessionManager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *SessionManager) ttl() time.Duration {
	if m.TTL > 0 {
		return m.TTL
	}
	return DefaultSessionTTL
}

// Issue creates and persists a new session for a user and returns the plaintext bearer
// token (shown to the client once) alongside the stored Session.
//
// credentialEpoch is the version of the credential that authorized this session — the
// `user_credential.updated_at` returned by the SAME read that produced the password hash the caller
// verified (AuthUser.CredentialUpdatedAt), or the epoch SetPassword just wrote. It is a REQUIRED
// parameter rather than something this method looks up, because looking it up here would re-read
// the row and reintroduce exactly the gap the epoch exists to close: the value has to come from the
// caller's own credential read to be the version that caller acted on.
//
// Pass the zero time only for a user with no local credential (there is no version to be stale
// against); a zero epoch against a user who HAS one is refused at the next request by design.
func (m *SessionManager) Issue(ctx context.Context, tenantID, userID string, credentialEpoch time.Time) (token string, s *Session, err error) {
	token, err = newSessionToken()
	if err != nil {
		return "", nil, err
	}
	now := m.now()
	s = &Session{
		ID:              newID(),
		TenantID:        tenantID,
		UserID:          userID,
		TokenHash:       HashToken(token),
		CreatedAt:       now,
		ExpiresAt:       now.Add(m.ttl()),
		LastSeen:        now,
		CredentialEpoch: credentialEpoch,
		SourceIP:        sourceIPFrom(ctx),
		UserAgent:       userAgentFrom(ctx),
	}
	if err := m.Store.Insert(ctx, s); err != nil {
		return "", nil, err
	}
	return token, s, nil
}

// IssueRemembered creates and persists a new remembered session (30-day absolute / 7-day idle)
// for a user who explicitly opted in at login via POST /auth/login {"remember_device": true}.
//
// All credential-verification steps (password, TOTP, throttle, tenant checks) MUST have completed
// successfully before this is called — it is called by HandleLogin in the same position Issue is,
// after authenticateLocal returns. It does not skip or weaken any pre-login check; the only
// difference from Issue is the TTL and the Remembered flag persisted to the session row.
//
// The credential-epoch contract is identical to Issue: credentialEpoch must come from the SAME
// credential read that the caller verified the password against, not from this process's clock.
func (m *SessionManager) IssueRemembered(ctx context.Context, tenantID, userID string, credentialEpoch time.Time) (token string, s *Session, err error) {
	token, err = newSessionToken()
	if err != nil {
		return "", nil, err
	}
	now := m.now()
	s = &Session{
		ID:              newID(),
		TenantID:        tenantID,
		UserID:          userID,
		TokenHash:       HashToken(token),
		CreatedAt:       now,
		ExpiresAt:       now.Add(RememberedSessionTTL),
		LastSeen:        now,
		CredentialEpoch: credentialEpoch,
		Remembered:      true,
		SourceIP:        sourceIPFrom(ctx),
		UserAgent:       userAgentFrom(ctx),
	}
	if err := m.Store.Insert(ctx, s); err != nil {
		return "", nil, err
	}
	return token, s, nil
}

// idleTTL returns the effective idle timeout for a session, chosen by its Remembered flag.
//
// Remembered sessions always enforce RememberedSessionIdleTTL (7 days) — the fixed limit cannot
// be suppressed by setting IdleTTL to 0. Ordinary sessions use the manager-level IdleTTL, where 0
// preserves the existing contract ("0 disables idle enforcement, absolute ExpiresAt still applies").
func (m *SessionManager) idleTTL(remembered bool) time.Duration {
	if remembered {
		return RememberedSessionIdleTTL
	}
	return m.IdleTTL
}

// Only the server's session-status route sets this private context key. Observing
// whether a login expired must not refresh its inactivity timer.
type sessionObservationKey struct{}

// Validate resolves a bearer token to its active session, enforcing revocation, absolute expiry,
// AND the inactivity (idle) timeout. The idle check compares against the STORED last-seen (the
// previous request's), so it must run BEFORE this request refreshes it. On success it refreshes
// last-seen (best effort).
//
// The idle timeout is chosen from the persisted Remembered flag: remembered sessions use
// RememberedSessionIdleTTL (7 days); ordinary sessions use IdleTTL / DefaultSessionIdleTTL
// (30 minutes). The absolute ExpiresAt is enforced unconditionally for both kinds.
func (m *SessionManager) Validate(ctx context.Context, token string) (*Session, error) {
	s, err := m.Store.GetByTokenHash(ctx, HashToken(token))
	if err != nil {
		return nil, err
	}
	now := m.now()
	if err := s.Active(now); err != nil {
		return nil, err
	}
	if idle := m.idleTTL(s.Remembered); idle > 0 && now.Sub(s.LastSeen) >= idle {
		return nil, ErrSessionIdle
	}
	if observing, _ := ctx.Value(sessionObservationKey{}).(bool); !observing {
		_ = m.Store.TouchLastSeen(ctx, s.TokenHash, now)
	}
	return s, nil
}

// Revoke immediately invalidates the session backing a bearer token (logout / forced
// sign-out). Idempotent: revoking an unknown token is not an error to the caller here.
func (m *SessionManager) Revoke(ctx context.Context, token string) error {
	return m.Store.Revoke(ctx, HashToken(token))
}

// RevokeOtherSessions revokes every live session of (tenantID, userID) except the one backing
// keepToken, and reports how many it revoked. An EMPTY keepToken revokes all of them.
//
// This is the "sign out everywhere else" primitive a password change depends on. It takes the
// PLAINTEXT token (not a hash) so callers never touch HashToken themselves — the one place the
// session-token→hash mapping lives stays inside this file.
func (m *SessionManager) RevokeOtherSessions(ctx context.Context, tenantID, userID, keepToken string) (int, error) {
	var keep []byte
	if keepToken != "" {
		keep = HashToken(keepToken)
	}
	return m.Store.RevokeAllForUser(ctx, tenantID, userID, keep)
}

// newID returns a random identifier for in-memory/skeleton use. The DB assigns real UUIDs
// via gen_random_uuid(); this keeps the in-memory fake self-contained.
func newID() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// -------------------------------------------------------------------------------------
// InMemorySessionStore — a concurrency-safe fake used by tests and the dev skeleton, so the
// session lifecycle can be exercised without a live Postgres (mirrors how the existing tests
// avoid a DB via interfaces + fakes).
// -------------------------------------------------------------------------------------

type InMemorySessionStore struct {
	mu     sync.Mutex
	byHash map[string]*Session
}

// NewInMemorySessionStore constructs an empty store.
func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{byHash: make(map[string]*Session)}
}

func hashKey(h []byte) string { return base64.RawStdEncoding.EncodeToString(h) }

func (s *InMemorySessionStore) Insert(_ context.Context, sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	s.byHash[hashKey(sess.TokenHash)] = &cp
	return nil
}

func (s *InMemorySessionStore) GetByTokenHash(_ context.Context, tokenHash []byte) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byHash[hashKey(tokenHash)]
	if !ok {
		return nil, ErrSessionNotFound
	}
	cp := *sess
	return &cp, nil
}

func (s *InMemorySessionStore) Revoke(_ context.Context, tokenHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byHash[hashKey(tokenHash)]
	if !ok {
		return ErrSessionNotFound
	}
	if sess.RevokedAt == nil {
		now := time.Now()
		sess.RevokedAt = &now
	}
	return nil
}

// MFAFresh implements SessionStore for the fake. Like MarkMFAVerified it cannot see the user store, so it
// does not re-check that the generation is still current; the generation re-check is pg-only.
func (s *InMemorySessionStore) MFAFresh(_ context.Context, tenantID, userID, sessionID string, maxAge time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, sess := range s.byHash {
		if sess.ID == sessionID && sess.TenantID == tenantID && sess.UserID == userID &&
			sess.RevokedAt == nil && now.Before(sess.ExpiresAt) {
			return sess.MFAVerifiedAt != nil && sess.MFAGeneration > 0 && now.Sub(*sess.MFAVerifiedAt) < maxAge, nil
		}
	}
	return false, nil
}

// StepUpSnapshot implements SessionStore for the fake: the generation is the one the session was verified
// against (the fake cannot see the user store, so it neither re-checks it nor knows the credential epoch).
func (s *InMemorySessionStore) StepUpSnapshot(_ context.Context, tenantID, userID, sessionID string, maxAge time.Duration) (StepUp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, sess := range s.byHash {
		if sess.ID == sessionID && sess.TenantID == tenantID && sess.UserID == userID &&
			sess.RevokedAt == nil && now.Before(sess.ExpiresAt) {
			fresh := sess.MFAVerifiedAt != nil && sess.MFAGeneration > 0 && now.Sub(*sess.MFAVerifiedAt) < maxAge
			return StepUp{Fresh: fresh, MFAGeneration: sess.MFAGeneration}, nil
		}
	}
	return StepUp{}, nil
}

// SessionLive implements SessionStore for the fake.
func (s *InMemorySessionStore) SessionLive(_ context.Context, tenantID, userID, sessionID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, sess := range s.byHash {
		if sess.ID == sessionID && sess.TenantID == tenantID && sess.UserID == userID &&
			sess.RevokedAt == nil && now.Before(sess.ExpiresAt) {
			return true, nil
		}
	}
	return false, nil
}

// MarkMFAVerified implements SessionStore for the fake. It cannot see the user store, so unlike the
// Postgres implementation it does not re-check that `generation` is still current; the platform
// operator check that relies on that runs only against Postgres.
func (s *InMemorySessionStore) MarkMFAVerified(_ context.Context, tenantID, userID, sessionID string, generation int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation <= 0 {
		return false, nil
	}
	now := time.Now()
	for _, sess := range s.byHash {
		if sess.ID == sessionID && sess.TenantID == tenantID && sess.UserID == userID &&
			sess.RevokedAt == nil && now.Before(sess.ExpiresAt) {
			at := now
			sess.MFAVerifiedAt = &at
			sess.MFAGeneration = generation
			return true, nil
		}
	}
	return false, nil
}

// RevokeAllForUser implements SessionStore: revoke every live session of (tenant, user) except
// keepTokenHash. Already-revoked rows are left alone. Expired-but-unrevoked rows are
// revoked too, matching PostgreSQL; the count reports only rows this call changed.
func (s *InMemorySessionStore) RevokeAllForUser(_ context.Context, tenantID, userID string, keepTokenHash []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := ""
	if keepTokenHash != nil {
		keep = hashKey(keepTokenHash)
	}
	now := time.Now()
	n := 0
	for k, sess := range s.byHash {
		if sess.TenantID != tenantID || sess.UserID != userID || sess.RevokedAt != nil {
			continue
		}
		if keep != "" && k == keep {
			continue
		}
		revoked := now
		sess.RevokedAt = &revoked
		n++
	}
	return n, nil
}

func (s *InMemorySessionStore) TouchLastSeen(_ context.Context, tokenHash []byte, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byHash[hashKey(tokenHash)]; ok {
		sess.LastSeen = at
	}
	return nil
}
