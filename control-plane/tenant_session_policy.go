package controlplane

// Per-tenant session policy (docs/01 §5 seat metering) — the concurrency limit a tenant admin sets and
// the session-start path enforces: how many remote-support sessions the tenant may hold OPEN at once.
// Same shape as the other tenant-scoped settings stores (TenantBrandingStore, TenantIPAllowlistStore):
// an interface, an in-memory fake for tests + DEV, and a pgx impl (PgTenantSessionPolicyStore) over
// `tenant_session_policy` (migrations/0029). Normalization lives in NormalizeSessionPolicy, shared by
// the handler so the fake and pg agree on which inputs are accepted.

import (
	"context"
	"sync"
	"time"
)

// SessionPolicy is a tenant's session settings. Both zeros mean "no limit": a zero MaxConcurrentSessions
// is UNLIMITED concurrency and a zero MaxSessionSeconds is NO maximum age — the same as no row at all, so
// an unset tenant and one explicitly set to 0/0 behave identically.
type SessionPolicy struct {
	MaxConcurrentSessions int `json:"max_concurrent_sessions"`
	// MaxSessionSeconds caps how long a session may stay OPEN before it is reaped (docs/01 §5). 0 = no
	// maximum. Seconds, matching the agent's own max_session_secs.
	MaxSessionSeconds int `json:"max_session_seconds"`
}

// MaxSessionLimit is the ceiling the console/API will accept for MaxConcurrentSessions. It is a sanity
// bound, not a licensing constant: a value this large is indistinguishable from unlimited in practice,
// and it stops a typo (or a hostile client) from persisting an absurd integer. 0 stays "unlimited".
const MaxSessionLimit = 100000

// Bounds for MaxSessionSeconds. A max age BELOW MinSessionSeconds is refused — reaping sessions after a
// few seconds is almost certainly a mistake, and 60s matches the floor the agent enforces on its own
// max_session_secs. MaxSessionSecondsCeiling (30 days) stops an absurd value; 0 stays "no maximum".
const (
	MinSessionSeconds        = 60
	MaxSessionSecondsCeiling = 30 * 24 * 60 * 60
)

// NormalizeSessionPolicy clamps a requested policy into the accepted range and reports whether the INPUT
// was already valid. Out-of-range values are rejected (ok=false) rather than silently accepted — a
// negative or absurd number is almost certainly a client bug, and "−1 means unlimited" is a footgun;
// callers say 0 for "no limit". The clamped value is returned regardless so a caller that ignores ok
// still gets a safe value; the handler stores only when ok (else 400).
func NormalizeSessionPolicy(p SessionPolicy) (SessionPolicy, bool) {
	out := p
	ok := true
	switch {
	case p.MaxConcurrentSessions < 0:
		out.MaxConcurrentSessions = 0
		ok = false
	case p.MaxConcurrentSessions > MaxSessionLimit:
		out.MaxConcurrentSessions = MaxSessionLimit
		ok = false
	}
	// max_session_seconds: 0 = no maximum; otherwise a sane, not-too-short duration.
	switch {
	case p.MaxSessionSeconds < 0, p.MaxSessionSeconds > 0 && p.MaxSessionSeconds < MinSessionSeconds:
		out.MaxSessionSeconds = 0
		ok = false
	case p.MaxSessionSeconds > MaxSessionSecondsCeiling:
		out.MaxSessionSeconds = MaxSessionSecondsCeiling
		ok = false
	}
	return out, ok
}

// TenantMaxAge is the pair returned by TenantSessionPolicyStore.ListTenantsWithMaxAge.
type TenantMaxAge struct {
	TenantID string
	MaxAge   time.Duration
}

// TenantSessionPolicyStore is the persistence seam for per-tenant session policy. Production wires
// PgTenantSessionPolicyStore (RLS-scoped via withTenant); tests + DEV wire the in-memory fake.
type TenantSessionPolicyStore interface {
	// Get returns the tenant's policy, or a zero SessionPolicy (unlimited) when none has been set.
	Get(ctx context.Context, tenantID string) (SessionPolicy, error)
	// Set upserts the tenant's policy (one row per tenant). The caller normalizes/validates first.
	Set(ctx context.Context, tenantID string, p SessionPolicy) error
	// ListTenantsWithMaxAge returns all (tenantID, maxAge) pairs where MaxSessionSeconds > 0. This is
	// a deliberately cross-tenant read: the background session reaper needs to know which tenants to
	// sweep, but tenant_session_policy uses FORCE ROW LEVEL SECURITY so it cannot be queried without a
	// pinned tenant. The pg implementation uses the cp_list_tenant_max_ages() SECURITY DEFINER function
	// (migration 0050) to answer this question with the minimum leak (tenant_id + max_age only).
	ListTenantsWithMaxAge(ctx context.Context) ([]TenantMaxAge, error)
}

// -------------------------------------------------------------------------------------
// InMemoryTenantSessionPolicyStore — concurrency-safe fake. A plain tenantID -> SessionPolicy map; an
// absent entry is the zero SessionPolicy (unlimited), exactly what the pg store returns for no row.
// -------------------------------------------------------------------------------------

type InMemoryTenantSessionPolicyStore struct {
	mu       sync.Mutex
	policies map[string]SessionPolicy
}

// NewInMemoryTenantSessionPolicyStore constructs an empty in-memory session-policy store.
func NewInMemoryTenantSessionPolicyStore() *InMemoryTenantSessionPolicyStore {
	return &InMemoryTenantSessionPolicyStore{policies: make(map[string]SessionPolicy)}
}

var _ TenantSessionPolicyStore = (*InMemoryTenantSessionPolicyStore)(nil)

// Get implements TenantSessionPolicyStore: the stored policy, or the zero value (unlimited) when unset.
func (s *InMemoryTenantSessionPolicyStore) Get(_ context.Context, tenantID string) (SessionPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policies[tenantID], nil
}

// Set implements TenantSessionPolicyStore: overwrite the tenant's policy.
func (s *InMemoryTenantSessionPolicyStore) Set(_ context.Context, tenantID string, p SessionPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[tenantID] = p
	return nil
}

// ListTenantsWithMaxAge implements TenantSessionPolicyStore: returns all tenants whose
// MaxSessionSeconds > 0. The in-memory fake has full visibility (no RLS) so it iterates directly.
func (s *InMemoryTenantSessionPolicyStore) ListTenantsWithMaxAge(_ context.Context) ([]TenantMaxAge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []TenantMaxAge
	for id, p := range s.policies {
		if p.MaxSessionSeconds > 0 {
			out = append(out, TenantMaxAge{
				TenantID: id,
				MaxAge:   time.Duration(p.MaxSessionSeconds) * time.Second,
			})
		}
	}
	return out, nil
}
