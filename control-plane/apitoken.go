package controlplane

// API tokens (docs/01 §8) — the tenant-admin-minted, capability-scoped BEARER credentials for
// PROGRAMMATIC access to the console API. See migrations/0027_api_token.sql for the storage and
// resolve-at-auth-time contract, and apitoken_auth.go for how a presented token becomes a
// Principal.
//
// Like enrollment/session/credential tokens, the plaintext secret is NEVER stored or returned
// after mint: only its SHA-256 lands in `token_hash`. A token is its OWN principal (it belongs to
// no user), so its authorization is an explicit capability SUBSET rather than a role — and that
// subset is bounded to apiTokenGrantableCaps (fleet management + reporting), the capabilities
// whose handlers never key on a real accountable human (see the migration header for why).
//
// Follows the repo's interface-plus-fakes pattern: APITokenStore interface, in-memory fake here,
// pgx implementation in pgstore_apitoken.go.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// APITokenPrefix marks a bearer secret as an API token. The authenticator (apitoken_auth.go)
// routes on this prefix BEFORE hashing, so a session token can never be mistaken for an API token
// or vice-versa; the prefix is part of the hashed value, so a stored hash is unambiguous.
const APITokenPrefix = "rmt_api_"

// MaxAPITokenTTLDays caps an EXPLICIT expiry request. A token may be minted to never expire
// (expires_at NULL) — that is a visible, revocable choice — but an absurdly distant expiry looks
// innocuous in the listing while granting standing access, the same trap MaxEnrollmentTokenTTL
// exists to close. 10 years is past any real automation lifetime; beyond it, re-mint.
const MaxAPITokenTTLDays = 3650

// ErrAPITokenNotFound is the sentinel for revoking a token id unknown in the tenant.
var ErrAPITokenNotFound = errors.New("api token not found")

// apiTokenGrantableCaps is the CLOSED set of capabilities a token may carry — the security
// boundary of the whole feature. It is fleet management + reporting only. Deliberately EXCLUDED:
//
//   - CapStartSession/CapEndSession/CapBackstageShell/CapTransferFiles — a live remote session is
//     written to session_record.technician_id, a NOT NULL FK to app_user; a token has no user row.
//     More than a schema quirk: a session needs a real accountable human, which is exactly what the
//     FK encodes.
//   - CapManageUsers/CapManageRoles — the password-reset / role paths reload the ACTOR user
//     (FindUserByID(p.UserID)) and compare privilege hierarchies; a token id is not a user id.
//   - CapManageEnrollment — enrollment_token.created_by is an FK to app_user.
//   - CapManageTenant — would let a token mint FURTHER tokens (self-propagation) or delete the
//     tenant. Minting is Owner-only; a minted token must not inherit that authority.
//   - CapDeployAgent/CapEnrollMachine — installer/agent-facing, not a programmatic-API surface.
//   - CapElevateSession (loop 87) — mints a signed grant that runs a command with a GUEST's admin
//     token on a live session. It is excluded for the same reason CapStartSession is (it acts on a
//     session, which needs an accountable human) and for a stronger one: it is the only artifact
//     this system signs that GRANTS privilege, so the principal asking for it must be a person.
//     This exclusion is why the capability is new rather than a reuse of CapManageMachines, which
//     IS grantable — see the CapElevateSession doc in rbac.go.
//   - CapRemoveAgent (docs/65) — reinstalls or REMOVES an installed agent without a session. Every gate on
//     that flow (a TOTP step-up in an interactive session, a typed confirmation, an optional second
//     approver) assumes a person, and CapManageMachines, which a token CAN hold, must never be enough to
//     wipe a fleet. Pinned by TestRemoveAgentIsNeverTokenGrantable.
//
// The remaining five drive only handlers that reach the DB tenant-pinned and record audit with an
// opaque actor (0016) — no user-FK, no real-user lookup — so an independent token principal is
// safe on exactly these paths.
var apiTokenGrantableCaps = map[Capability]struct{}{
	CapViewMachines:   {},
	CapManageMachines: {},
	CapManageGroups:   {},
	CapViewSessions:   {},
	CapViewAudit:      {},
}

// APITokenGrantableCapabilities returns the grantable set in a stable order (for the console form
// and error messages). Order matches AllCapabilities.
func APITokenGrantableCapabilities() []Capability {
	out := make([]Capability, 0, len(apiTokenGrantableCaps))
	for _, c := range AllCapabilities {
		if _, ok := apiTokenGrantableCaps[c]; ok {
			out = append(out, c)
		}
	}
	return out
}

// IsAPITokenGrantableCapability reports whether c may be carried by an API token.
func IsAPITokenGrantableCapability(c Capability) bool {
	_, ok := apiTokenGrantableCaps[c]
	return ok
}

// knownCaps is every capability the system defines, for validating client-supplied strings.
var knownCaps = func() map[Capability]struct{} {
	m := make(map[Capability]struct{}, len(AllCapabilities))
	for _, c := range AllCapabilities {
		m[c] = struct{}{}
	}
	return m
}()

// parseAPITokenCapabilities validates a client-supplied capability list for a mint: every entry
// must name a known capability that is grantable to a token; the result is de-duplicated in the
// order first seen. An empty list is rejected — a token with no capabilities is a useless
// credential, and almost certainly a mistake worth surfacing rather than minting.
func parseAPITokenCapabilities(raw []string) ([]Capability, error) {
	if len(raw) == 0 {
		return nil, errors.New("at least one capability is required")
	}
	seen := make(map[Capability]struct{}, len(raw))
	out := make([]Capability, 0, len(raw))
	for _, s := range raw {
		c := Capability(s)
		if _, known := knownCaps[c]; !known {
			return nil, fmt.Errorf("unknown capability %q", s)
		}
		if !IsAPITokenGrantableCapability(c) {
			return nil, fmt.Errorf("capability %q cannot be granted to an API token", s)
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out, nil
}

// APIToken is one token's METADATA as the management API exposes it. It never carries the
// plaintext secret or its hash — the plaintext exists only in Mint's return value.
type APIToken struct {
	ID           string       `json:"id"`
	TenantID     string       `json:"tenant_id"`
	Name         string       `json:"name"`
	Capabilities []Capability `json:"capabilities"`
	CreatedBy    string       `json:"created_by,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	ExpiresAt    *time.Time   `json:"expires_at,omitempty"`
	RevokedAt    *time.Time   `json:"revoked_at,omitempty"`
}

// APITokenStore is the persistence seam for API tokens. Production wires PgAPITokenStore; tests
// and DEV wire InMemoryAPITokenStore.
type APITokenStore interface {
	// Mint generates the high-entropy secret, persists its hash + metadata tenant-pinned,
	// populates the store-assigned fields (ID, TenantID, CreatedAt) into the returned token, and
	// returns the PLAINTEXT (with the APITokenPrefix) — the only time it ever exists outside the
	// client. expiresAt nil means the token never expires.
	Mint(ctx context.Context, tenantID, name string, caps []Capability, createdBy string, expiresAt *time.Time) (plaintext string, tok *APIToken, err error)
	// List returns the tenant's tokens (metadata only), newest first.
	List(ctx context.Context, tenantID string) ([]APIToken, error)
	// Revoke soft-revokes a token by id (sets revoked_at). Idempotent — re-revoking succeeds; an
	// id unknown in the tenant returns ErrAPITokenNotFound.
	Revoke(ctx context.Context, tenantID, id string) error
	// Resolve returns the token whose hash matches the plaintext IF it is live (not revoked, not
	// expired, tenant not suspended). This is the PRE-TENANT auth path: it runs on the pool
	// directly, not tenant-pinned. An unknown/revoked/expired/suspended token returns
	// ErrAPITokenNotFound — nothing more (the caller is unauthenticated by construction).
	Resolve(ctx context.Context, plaintext string) (*APIToken, error)
}

// newAPITokenSecret returns a fresh prefixed bearer secret: APITokenPrefix + 256 bits of
// base64url entropy (the same primitive session/enrollment tokens use).
func newAPITokenSecret() (string, error) {
	raw, err := newEnrollmentSecret()
	if err != nil {
		return "", err
	}
	return APITokenPrefix + raw, nil
}

// cloneCaps copies a capability slice so a stored token never aliases the caller's slice.
func cloneCaps(caps []Capability) []Capability {
	out := make([]Capability, len(caps))
	copy(out, caps)
	return out
}

// -------------------------------------------------------------------------------------
// InMemoryAPITokenStore — concurrency-safe fake for tests and DEV mode. It cannot consult a
// tenant registry, so (like InMemoryEnrollmentTokenStore) it does not enforce tenant suspension;
// DEV has exactly one, always-enabled tenant, and the pg store carries the suspension check.
// -------------------------------------------------------------------------------------

type memAPIToken struct {
	APIToken
	hash string // hashKey of the secret's SHA-256; never exposed
}

// InMemoryAPITokenStore is an in-memory APITokenStore.
type InMemoryAPITokenStore struct {
	mu     sync.Mutex
	tokens map[string]*memAPIToken // key: token id
	// Now is injectable for expiry tests; defaults to time.Now.
	Now func() time.Time
}

// NewInMemoryAPITokenStore constructs an empty in-memory API token store.
func NewInMemoryAPITokenStore() *InMemoryAPITokenStore {
	return &InMemoryAPITokenStore{tokens: make(map[string]*memAPIToken)}
}

var _ APITokenStore = (*InMemoryAPITokenStore)(nil)

func (s *InMemoryAPITokenStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Mint implements APITokenStore.
func (s *InMemoryAPITokenStore) Mint(_ context.Context, tenantID, name string, caps []Capability, createdBy string, expiresAt *time.Time) (string, *APIToken, error) {
	plaintext, err := newAPITokenSecret()
	if err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tok := APIToken{
		ID:           newUUID(),
		TenantID:     tenantID,
		Name:         name,
		Capabilities: cloneCaps(caps),
		CreatedBy:    createdBy,
		CreatedAt:    s.now(),
		ExpiresAt:    expiresAt,
	}
	s.tokens[tok.ID] = &memAPIToken{APIToken: tok, hash: hashKey(HashToken(plaintext))}
	out := tok
	return plaintext, &out, nil
}

// List implements APITokenStore: the tenant's token metadata, newest first.
func (s *InMemoryAPITokenStore) List(_ context.Context, tenantID string) ([]APIToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []APIToken{}
	for _, t := range s.tokens {
		if t.TenantID == tenantID {
			cp := t.APIToken
			cp.Capabilities = cloneCaps(t.Capabilities)
			out = append(out, cp)
		}
	}
	// Newest first, exactly mirroring the pg store's ORDER BY created_at DESC, id DESC — the id
	// tie-break gives both a deterministic total order (Go's sort.Slice is unstable).
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// Revoke implements APITokenStore: idempotent; an id in another tenant is ErrAPITokenNotFound.
func (s *InMemoryAPITokenStore) Revoke(_ context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok || t.TenantID != tenantID {
		return ErrAPITokenNotFound
	}
	if t.RevokedAt == nil {
		now := s.now()
		t.RevokedAt = &now
	}
	return nil
}

// Resolve implements APITokenStore: match by hash, then apply the same liveness predicate the pg
// resolver does (minus tenant suspension, which this fake cannot see).
func (s *InMemoryAPITokenStore) Resolve(_ context.Context, plaintext string) (*APIToken, error) {
	want := hashKey(HashToken(plaintext))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.hash != want {
			continue
		}
		if t.RevokedAt != nil {
			return nil, ErrAPITokenNotFound
		}
		if t.ExpiresAt != nil && !s.now().Before(*t.ExpiresAt) {
			return nil, ErrAPITokenNotFound
		}
		cp := t.APIToken
		cp.Capabilities = cloneCaps(t.Capabilities)
		return &cp, nil
	}
	return nil, ErrAPITokenNotFound
}
