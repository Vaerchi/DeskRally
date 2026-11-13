package controlplane

// Attended (on-demand) support sessions (docs/12-attended-sessions-contract.md).
//
// An attended session is a consent-gated, time-boxed, EPHEMERAL enrollment. This file is the
// persistence seam + the two bearer secrets it mints:
//
//   - the ATTEND CODE the user reads back / clicks (Crockford base32, 40 bits), single-use,
//     short-TTL, hashed at rest exactly like an enrollment token; and
//   - the ATTEND TOKEN the guest process holds to authenticate its own callbacks (consent, status),
//     256-bit, also hashed at rest.
//
// It reuses the existing authorization gates unchanged (RMTAGENTAUTHv1 for the guest agent,
// RMTTICKETv1 for the technician), so there is deliberately NO new signed preimage here.
//
// Follows the repo's interface-plus-fakes pattern (EnrollmentTokenStore/MachineStore): an
// AttendedStore interface, an in-memory fake here, and a pgx implementation in
// pgstore_attended.go over `attended_session` + cp_attended_* (migrations/0013).

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// AttendedCodeTTL bounds how long a minted attend code stays redeemable. Deliberately short: it is
// read aloud / clicked immediately, and a short window shrinks the guessing surface.
const AttendedCodeTTL = 10 * time.Minute

// AttendedSessionTTL bounds the ephemeral machine's lifetime (machine.expires_at) once redeemed.
// After it, cp_machine_identity_by_device_id refuses the guest and the reaper removes the row.
const AttendedSessionTTL = 30 * time.Minute

// attendCodeBytes yields 8 Crockford characters (40 random bits), shown as XXXX-XXXX.
// Codes remain single-use, short-lived, hashed at rest, and rate-limited on redemption.
const attendCodeBytes = 5

// crockford is Crockford base32 (no I, L, O, U — the human-confusable letters), the alphabet the
// attend code is displayed and redeemed in. Case-insensitive on redemption.
var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// Attended session states (mirror the CHECK constraint in migrations/0013).
const (
	AttendedPending   = "pending"
	AttendedRedeemed  = "redeemed"
	AttendedConsented = "consented"
	AttendedDeclined  = "declined"
	AttendedActive    = "active"
	AttendedEnded     = "ended"
	AttendedExpired   = "expired"
)

// ErrAttendedInvalid is the ONE error the guest-facing paths return for a bad/expired/spent code or
// a bad attend token. Deliberately undifferentiated — those endpoints are unauthenticated, so a
// prober must not learn which check failed (mirrors ErrEnrollmentTokenInvalid).
var ErrAttendedInvalid = errors.New("invalid attended code or token")

// ErrAttendedNotFound is the sentinel for a session id unknown in the tenant (technician paths).
var ErrAttendedNotFound = errors.New("attended session not found")

// ErrAttendedNotConsented is returned by the connect gate when the session has not reached consent.
var ErrAttendedNotConsented = errors.New("attended session is awaiting consent")

// ErrAttendedNotPromotable refuses a new promotion outside a consented/active session.
var ErrAttendedNotPromotable = errors.New("attended session is not ready for promotion")

// ErrAttendedPromoteCompleteConflict is returned by SetPromoteResult when the session has no
// pending promote (no token was ever stashed, or the session has already ended).
var ErrAttendedPromoteCompleteConflict = errors.New("attended session has no pending promotion")

func attendedCanPromote(state string) bool {
	return state == AttendedConsented || state == AttendedActive
}

// PromoteResult is the outcome the guest reports back after attempting the permanent install. The
// technician panel surfaces it so the technician knows whether to ask the guest to approve UAC,
// retry, or confirm the service is running.
type PromoteResult struct {
	Success bool      `json:"success"`
	Error   string    `json:"error,omitempty"`
	At      time.Time `json:"at"`
}

// AttendedSession is one on-demand session as the API exposes it. Bearer material (code/token
// hashes) is never included — it exists only transiently in Create/Redeem return values.
type AttendedSession struct {
	AgentPubkey  string `json:"-"` // Snapshot from redemption, retained after ephemeral machine cleanup.
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	GroupID      string `json:"group_id"`
	TechnicianID string `json:"technician_id"`
	DeviceID     string `json:"device_id,omitempty"` // the ephemeral machine, set at redeem
	State        string `json:"state"`
	Reason       string `json:"reason,omitempty"`
	ConsentUser  string `json:"consent_user,omitempty"`
	// RequireSessionPolicy records that REDEMPTION told this guest to open the session view-only
	// until a signed policy verifies (migration 0036). It is the control plane's memory of a promise
	// it made to the guest at a moment the group could still change: connect mints a policy for any
	// session carrying this flag, so clearing the group's mandate in between DISCHARGES the floor
	// (with an access=control policy) instead of stranding the guest in it. Write-once, at redeem.
	RequireSessionPolicy bool       `json:"require_session_policy,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	ExpiresAt            time.Time  `json:"expires_at"` // code redemption deadline
	RedeemedAt           *time.Time `json:"redeemed_at,omitempty"`
	ConsentedAt          *time.Time `json:"consented_at,omitempty"`
	EndedAt              *time.Time `json:"ended_at,omitempty"`
	// PromoteToken is the plaintext enrollment token stashed between /promote and the guest's next
	// /status poll. NEVER serialized to the technician — the guest reads it via the status path.
	PromoteToken string `json:"-"`
	// PromoteAttemptNonce is a random 32-hex-char value minted by SetPromoteToken on each new or
	// retry attempt. Returned to the guest via the status response's promote.attempt_nonce field;
	// the guest echoes it in POST /promote-complete. The SQL function compares it atomically so a
	// delayed old attempt cannot write into the cleared slot of a new one. NEVER serialized to the
	// technician — they never need to see it, and it would needlessly widen the exposed surface.
	PromoteAttemptNonce string `json:"-"`
	// PromoteResult is the outcome the guest reports via POST /attended-sessions/promote-complete.
	// nil until the guest calls that endpoint; then set regardless of success/failure.
	PromoteResult *PromoteResult `json:"promote_result,omitempty"`
}

// AttendedRedeem is what redemption hands back to the guest: the server-minted ephemeral identity,
// the signaling coordinates, and the attend token for subsequent guest callbacks.
type AttendedRedeem struct {
	SessionID   string
	DeviceID    string
	TenantID    string
	GroupID     string
	AttendToken string // plaintext, returned exactly once
}

// AttendedStore is the persistence seam. Production wires PgAttendedStore; tests/DEV wire
// InMemoryAttendedStore. The technician methods (Create/Get/MarkActive/End/SetPromoteToken) are
// tenant-scoped (RLS in pgx); the guest methods (Redeem/Consent/ByToken) are PRE-TENANT (the guest
// holds only a code or token, no tenant context) — exactly the enrollment redeem split.
type AttendedStore interface {
	// List applies tenant and capability scope before pagination.
	List(ctx context.Context, tenantID string, scope GroupScope, limit, offset int) ([]AttendedSession, error)

	// Create mints a pending session and its attend code, returning the PLAINTEXT code once. s is
	// populated with the store-assigned ID/State/CreatedAt/ExpiresAt.
	Create(ctx context.Context, tenantID string, s *AttendedSession) (code string, err error)
	// Get resolves one session by id within the tenant. ErrAttendedNotFound when unknown.
	Get(ctx context.Context, tenantID, id string) (*AttendedSession, error)
	// MarkActive advances consented→active (idempotent for already-active). ErrAttendedNotConsented
	// if the session has not consented; ErrAttendedNotFound if unknown.
	MarkActive(ctx context.Context, tenantID, id string) (*AttendedSession, error)
	// ReassignTechnician makes technicianID the session's technician and returns the one it
	// replaced, read under the row lock. A connect by a peer technician (recovering a closed
	// creator tab) is a HANDOFF: audit ingest accepts the agent-signed trail only from the session's
	// technician, so leaving the creator in place lost the second technician's backstage and
	// file-transfer trail (security audit 2026-10-18). Called only once the connect has its ticket
	// and policy, so a connect that fails there never moves ownership.
	ReassignTechnician(ctx context.Context, tenantID, id, technicianID string) (previous string, err error)
	// End advances to ended and reaps the ephemeral machine. Idempotent.
	End(ctx context.Context, tenantID, id string) (*AttendedSession, error)
	// SetPromoteToken atomically admits nonempty tokens only in consented/active sessions.
	// Other states return ErrAttendedNotPromotable; an empty token may clear any existing state.
	SetPromoteToken(ctx context.Context, tenantID, id, plaintext string) error
	// SetRequireSessionPolicy records that redemption told this guest to open FLOORED. There is no
	// bool argument on purpose: the flag is write-once-true, mirroring the agent-side ratchet it
	// serves. A setter that could also clear it would invite a caller to un-promise a floor the
	// guest is already enforcing, and nothing in the product needs that.
	SetRequireSessionPolicy(ctx context.Context, tenantID, id string) error
	// SetPromoteResult records the outcome the guest reports after attempting the permanent install.
	// Keyed by attend token (pre-tenant, like ByToken) since the guest has no session id.
	// attemptNonce must match the nonce minted by SetPromoteToken for this attempt (binding).
	// Returns ErrAttendedPromoteCompleteConflict if the session has no pending promotion, the nonce
	// does not match, or the attempt is otherwise invalid (race, age, grace expiry).
	SetPromoteResult(ctx context.Context, attendToken, attemptNonce string, result PromoteResult) error

	// Redeem validates the code, mints the ephemeral machine (device_id server-side) with the
	// guest's pubkey pinned, records the attend-token hash, and advances to redeemed — atomically.
	// ErrAttendedInvalid for any bad/expired/spent code.
	Redeem(ctx context.Context, code, pubkeyHex, name string) (*AttendedRedeem, error)
	// RedeemScoped is Redeem with the HOST scope pushed into the same call (docs/66 2a.1): unless
	// scope.Unscoped, the code must belong to the tenant that currently holds scope.Host as an ACTIVE
	// assignment. Every rejected class (missing, expired, spent, suspended tenant, foreign tenant, host not
	// active, lock timeout) is the same ErrAttendedInvalid.
	RedeemScoped(ctx context.Context, code, pubkeyHex, name string, scope RedeemScope) (*AttendedRedeem, error)
	// Consent transitions redeemed→consented (accept) or redeemed→declined, keyed by attend token.
	Consent(ctx context.Context, attendToken string, accept bool, consentUser string) (*AttendedSession, error)
	// ByToken resolves the session for a guest holding the attend token (status polling).
	ByToken(ctx context.Context, attendToken string) (*AttendedSession, error)
}

// newPromoteAttemptNonce generates a 32-character hex nonce (16 random bytes) bound to one promote
// attempt. The guest echoes it in POST /promote-complete so the server can reject results from old
// attempts that ran past a retry boundary (the nonce changes with each SetPromoteToken call).
func newPromoteAttemptNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// newAttendCode returns a fresh Crockford base32 attend code (uppercase, ungrouped) and its
// normalized hash for storage.
func newAttendCode() (code string, hash []byte, err error) {
	raw := make([]byte, attendCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	code = crockford.EncodeToString(raw)
	return code, HashToken(normalizeAttendCode(code)), nil
}

// Code hashes are globally unique, including historical invitations. Retry the rare collision
// without ever reusing a code for a different session or exposing another tenant's record.
var errAttendCodeCollision = errors.New("attended code collision")

func mintAttendCode(insert func(string, []byte) error) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		code, hash, err := newAttendCode()
		if err != nil {
			return "", err
		}
		err = insert(code, hash)
		if err == nil {
			return code, nil
		}
		if !errors.Is(err, errAttendCodeCollision) {
			return "", err
		}
	}
	return "", errAttendCodeCollision
}

// normalizeAttendCode canonicalizes a code for hashing/comparison: uppercase, and strip the display
// grouping (`-`) and any whitespace. Redemption is therefore case- and grouping-insensitive.
func normalizeAttendCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		if r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// GroupAttendCode formats a code for display as XXXX-XXXX-… (groups of 4).
func GroupAttendCode(code string) string {
	code = normalizeAttendCode(code)
	var b strings.Builder
	for i, r := range code {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// -------------------------------------------------------------------------------------
// InMemoryAttendedStore — concurrency-safe fake for tests and DEV mode. It owns ephemeral machine
// creation directly (it is handed the in-memory machine store), mirroring what cp_attended_redeem
// does atomically in one transaction on the pg path.
// -------------------------------------------------------------------------------------

type memAttended struct {
	AttendedSession
	codeHash           string     // hashKey of the code's SHA-256
	tokenHash          string     // hashKey of the attend token's SHA-256
	promoteRequested   bool       // true for the current authorized attempt; cleared on explicit revocation
	promoteRequestedAt *time.Time // when the current attempt was authorized; nil when revoked
	promoteAttemptNonce string   // random nonce minted per-attempt; guest echoes in promote-complete
}

// InMemoryAttendedStore is the DEV/test AttendedStore. It requires an InMemoryMachineStore so it
// can mint the ephemeral machine on redeem (the pg path does this inside cp_attended_redeem).
type InMemoryAttendedStore struct {
	mu       sync.Mutex
	sessions map[string]*memAttended // key: session id
	machines *InMemoryMachineStore
	Now      func() time.Time
	// Hosts resolves a host to its CURRENT active assignee for RedeemScoped (docs/66 2a.1). Nil = no host
	// has an active assignment, so a scoped redemption always fails closed.
	Hosts HostScopeSource
}

// NewInMemoryAttendedStore constructs an in-memory attended store over the given machine store.
func NewInMemoryAttendedStore(machines *InMemoryMachineStore) *InMemoryAttendedStore {
	return &InMemoryAttendedStore{sessions: make(map[string]*memAttended), machines: machines}
}

var _ AttendedStore = (*InMemoryAttendedStore)(nil)

func (s *InMemoryAttendedStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Create implements AttendedStore.
func (s *InMemoryAttendedStore) Create(_ context.Context, tenantID string, sess *AttendedSession) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var hash []byte
	code, err := mintAttendCode(func(_ string, candidate []byte) error {
		for _, row := range s.sessions {
			if row.codeHash == hashKey(candidate) {
				return errAttendCodeCollision
			}
		}
		hash = candidate
		return nil
	})
	if err != nil {
		return "", err
	}
	now := s.now()
	cp := memAttended{AttendedSession: *sess, codeHash: hashKey(hash)}
	cp.ID = newUUID()
	cp.TenantID = tenantID
	cp.State = AttendedPending
	cp.CreatedAt = now
	cp.ExpiresAt = now.Add(AttendedCodeTTL)
	cp.DeviceID = ""
	cp.AgentPubkey = ""
	// Overwritten, not copied, for the same reason DeviceID is: the pg store's INSERT names a fixed
	// column list and never re-reads the row, so anything a caller set here that pg does not insert
	// would persist in the FAKE and vanish in production — the divergence class this repo has been
	// bitten by before. A floor is decided at REDEEM, so false is the only legal value at create.
	cp.RequireSessionPolicy = false
	s.sessions[cp.ID] = &cp
	*sess = cp.AttendedSession
	return code, nil
}

// Get implements AttendedStore.
func (s *InMemoryAttendedStore) Get(_ context.Context, tenantID, id string) (*AttendedSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.sessions[id]
	if !ok || t.TenantID != tenantID {
		return nil, ErrAttendedNotFound
	}
	cp := t.AttendedSession
	return &cp, nil
}

// MarkActive implements AttendedStore.
func (s *InMemoryAttendedStore) MarkActive(_ context.Context, tenantID, id string) (*AttendedSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.sessions[id]
	if !ok || t.TenantID != tenantID {
		return nil, ErrAttendedNotFound
	}
	if t.State != AttendedConsented && t.State != AttendedActive {
		return nil, ErrAttendedNotConsented
	}
	t.State = AttendedActive
	cp := t.AttendedSession
	return &cp, nil
}

// ReassignTechnician implements AttendedStore under the mutex.
func (s *InMemoryAttendedStore) ReassignTechnician(_ context.Context, tenantID, id, technicianID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.sessions[id]
	if !ok || t.TenantID != tenantID {
		return "", ErrAttendedNotFound
	}
	prev := t.TechnicianID
	t.TechnicianID = technicianID
	return prev, nil
}

// End implements AttendedStore: mark ended, clear the stashed promote token, reap the ephemeral machine.
func (s *InMemoryAttendedStore) End(ctx context.Context, tenantID, id string) (*AttendedSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.sessions[id]
	if !ok || t.TenantID != tenantID {
		return nil, ErrAttendedNotFound
	}
	if t.State != AttendedEnded {
		now := s.now()
		t.State = AttendedEnded
		t.EndedAt = &now
		t.PromoteToken = ""
	}
	if t.DeviceID != "" && s.machines != nil {
		s.machines.deleteEphemeral(tenantID, t.DeviceID)
	}
	cp := t.AttendedSession
	return &cp, nil
}

// SetPromoteToken implements AttendedStore.
func (s *InMemoryAttendedStore) SetPromoteToken(_ context.Context, tenantID, id, plaintext string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.sessions[id]
	if !ok || t.TenantID != tenantID {
		return ErrAttendedNotFound
	}
	if plaintext != "" && !attendedCanPromote(t.State) {
		return ErrAttendedNotPromotable
	}
	t.PromoteToken = plaintext
	if plaintext != "" {
		// New or retry attempt: stamp authorization and clear any prior result so the UI sees
		// the new attempt's outcome (not a stale failure from a previous attempt).
		t.promoteRequested = true
		if t.promoteRequestedAt == nil {
			now := s.now()
			t.promoteRequestedAt = &now
		}
		t.PromoteResult = nil
		// Mint a new nonce for each new or retry attempt. The guest echoes it in promote-complete
		// so the server can reject a delayed old attempt's result from claiming a new attempt's slot.
		nonce, err := newPromoteAttemptNonce()
		if err != nil {
			return err
		}
		t.promoteAttemptNonce = nonce
		t.PromoteAttemptNonce = nonce
	} else {
		// Explicit revocation (NOT called by End): clear the authorization so a late
		// promote-complete from the guest is rejected.
		t.promoteRequested = false
		t.promoteRequestedAt = nil
		t.promoteAttemptNonce = ""
		t.PromoteAttemptNonce = ""
		// Keep PromoteResult intact — historical record of the last completed attempt.
	}
	return nil
}

// SetRequireSessionPolicy implements AttendedStore.
func (s *InMemoryAttendedStore) SetRequireSessionPolicy(_ context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.sessions[id]
	if !ok || t.TenantID != tenantID {
		return ErrAttendedNotFound
	}
	t.RequireSessionPolicy = true
	return nil
}

// SetPromoteResult implements AttendedStore: record the guest-reported install outcome.
func (s *InMemoryAttendedStore) SetPromoteResult(_ context.Context, attendToken, attemptNonce string, result PromoteResult) error {
	want := hashKey(HashToken(attendToken))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.sessions {
		if t.tokenHash != want {
			continue
		}
		// Accept a result only when:
		//  (a) the session is past pending/redeemed (no promote could have been requested there), AND
		//  (b) the current attempt is still authorized (promoteRequested; cleared on explicit
		//      revocation via SetPromoteToken(""), preserved through End for the grace window), AND
		//  (c) the attempt nonce matches — a delayed old attempt carries the OLD nonce; a new attempt
		//      mints a new nonce via SetPromoteToken, so cross-attempt pollution is rejected here, AND
		//  (d) no result has been written yet (first completion wins), AND
		//  (e) active sessions: attempt is not older than 24 hours, AND
		//  (f) ended sessions: within the 30-minute post-end grace window.
		if t.State == AttendedPending || t.State == AttendedRedeemed || !t.promoteRequested {
			return ErrAttendedPromoteCompleteConflict
		}
		// Nonce check: both non-empty nonces must match. When either is empty (pre-nonce code), skip
		// to preserve compatibility with old in-memory tests that don't set a nonce.
		if attemptNonce != "" && t.promoteAttemptNonce != "" && attemptNonce != t.promoteAttemptNonce {
			return ErrAttendedPromoteCompleteConflict
		}
		if t.PromoteResult != nil {
			return ErrAttendedPromoteCompleteConflict
		}
		// Age bound for active sessions (mirrors the SQL: 24h from promote_requested_at).
		if t.State != AttendedEnded && t.promoteRequestedAt != nil {
			if s.now().After(t.promoteRequestedAt.Add(24 * time.Hour)) {
				return ErrAttendedPromoteCompleteConflict
			}
		}
		// Bounded post-end grace (mirrors the SQL: 30 minutes after ended_at).
		if t.State == AttendedEnded && t.EndedAt != nil {
			if s.now().After(t.EndedAt.Add(30 * time.Minute)) {
				return ErrAttendedPromoteCompleteConflict
			}
		}
		cp := result
		t.PromoteResult = &cp
		return nil
	}
	return ErrAttendedInvalid
}

// Redeem implements AttendedStore: validate code, mint ephemeral machine + attend token, advance.
func (s *InMemoryAttendedStore) Redeem(ctx context.Context, code, pubkeyHex, name string) (*AttendedRedeem, error) {
	return s.RedeemScoped(ctx, code, pubkeyHex, name, RedeemScope{Unscoped: true})
}

// RedeemScoped implements AttendedStore: the host scope is evaluated under the same lock as the redemption.
func (s *InMemoryAttendedStore) RedeemScoped(ctx context.Context, code, pubkeyHex, name string, scope RedeemScope) (*AttendedRedeem, error) {
	attendToken, err := newEnrollmentSecret()
	if err != nil {
		return nil, err
	}
	wantCode := hashKey(HashToken(normalizeAttendCode(code)))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.sessions {
		if t.codeHash != wantCode {
			continue
		}
		if t.State != AttendedPending || !s.now().Before(t.ExpiresAt) {
			return nil, ErrAttendedInvalid
		}
		if !scope.Unscoped {
			if s.Hosts == nil {
				return nil, ErrAttendedInvalid
			}
			if owner, ok := s.Hosts.ActiveTenantForHost(scope.Host); !ok || owner != t.TenantID {
				return nil, ErrAttendedInvalid
			}
		}
		deviceID := newUUID()
		if s.machines != nil {
			exp := s.now().Add(AttendedSessionTTL)
			if err := s.machines.enrollEphemeral(t.TenantID, deviceID, t.GroupID, name, pubkeyHex, exp); err != nil {
				return nil, err
			}
		}
		now := s.now()
		t.State = AttendedRedeemed
		t.DeviceID = deviceID
		t.AgentPubkey = pubkeyHex
		t.RedeemedAt = &now
		t.tokenHash = hashKey(HashToken(attendToken))
		return &AttendedRedeem{
			SessionID:   t.ID,
			DeviceID:    deviceID,
			TenantID:    t.TenantID,
			GroupID:     t.GroupID,
			AttendToken: attendToken,
		}, nil
	}
	return nil, ErrAttendedInvalid
}

// Consent implements AttendedStore.
func (s *InMemoryAttendedStore) Consent(_ context.Context, attendToken string, accept bool, consentUser string) (*AttendedSession, error) {
	want := hashKey(HashToken(attendToken))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.sessions {
		if t.tokenHash != want {
			continue
		}
		if t.State != AttendedRedeemed {
			return nil, ErrAttendedInvalid
		}
		now := s.now()
		if accept {
			t.State = AttendedConsented
			t.ConsentUser = consentUser
			t.ConsentedAt = &now
		} else {
			t.State = AttendedDeclined
		}
		cp := t.AttendedSession
		return &cp, nil
	}
	return nil, ErrAttendedInvalid
}

// ByToken implements AttendedStore.
func (s *InMemoryAttendedStore) ByToken(_ context.Context, attendToken string) (*AttendedSession, error) {
	want := hashKey(HashToken(attendToken))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.sessions {
		if t.tokenHash == want {
			cp := t.AttendedSession
			return &cp, nil
		}
	}
	return nil, ErrAttendedInvalid
}

func (s *InMemoryAttendedStore) List(_ context.Context, tenantID string, scope GroupScope, limit, offset int) ([]AttendedSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AttendedSession, 0)
	for _, row := range s.sessions {
		if row.TenantID == tenantID && scope.Covers(row.GroupID) {
			cp := row.AttendedSession
			if cp.PromoteResult != nil {
				result := *cp.PromoteResult
				cp.PromoteResult = &result
			}
			out = append(out, cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if offset >= len(out) {
		return []AttendedSession{}, nil
	}
	out = out[offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
