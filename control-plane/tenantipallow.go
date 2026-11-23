package controlplane

// Per-tenant IP allow-list (docs/01 §10) — a tenant-scoped set of source CIDRs that restrict which
// networks may reach the AUTHENTICATED console/host API for that tenant.
//
// This is a persistence seam in the same shape as MachinePropertyStore: a TenantIPAllowlistStore
// interface, an in-memory fake for tests + the dev skeleton, and a pgx implementation for production
// (PgTenantIPAllowlistStore in pgstore.go) over the `tenant_ip_allowlist` table in migrations/0025.
//
// ENFORCEMENT and the ANTI-LOCKOUT safeguard live ABOVE this seam (Server.tenantIPAllowMiddleware and
// the /tenant/ip-allowlist handlers in http.go). The store is a dumb, tenant-scoped set of canonical
// CIDR strings: it does not parse, match, or reason about IPs — the handlers normalize a CIDR before
// storing it and reuse the ipallow.go matcher (ParseIPAllowlist/Allows) to enforce and to check
// lockout. Keeping the store dumb means the fake and the pg store agree on exactly one contract (a
// tenant-scoped string set), and all the IP logic is unit-tested once in ipallow.go.

import (
	"context"
	"errors"
	"sort"
	"sync"
)

// ErrTenantIPAllowlistEntryNotFound is the sentinel returned when a delete names a CIDR that is not in
// the tenant's list. Handlers translate it to a 404. An add is idempotent and never returns it.
var ErrTenantIPAllowlistEntryNotFound = errors.New("tenant ip allow-list entry not found")

// ErrWouldLockOut is returned by the *Guarded mutations when the requested change would leave a
// NON-empty list that excludes the acting admin's own source IP. The mutation is NOT applied.
// Handlers translate it to a 400. See CoverageCheck.
var ErrWouldLockOut = errors.New("change would lock the caller out")

// CoverageCheck reports whether a candidate RESULTING allow-list is SAFE for the acting caller — i.e.
// the list is empty (open), or some CIDR in it covers the caller's current source IP. The store treats
// coverage as opaque and calls this WHILE HOLDING the per-tenant lock, so the check runs against the
// true committed state; all IP logic stays in one place (ipallow.go, via the handler's closure). A
// candidate the check rejects means the mutation would lock the caller out (ErrWouldLockOut).
type CoverageCheck func(resulting []string) bool

// TenantIPAllowlistStore is the persistence seam for the per-tenant IP allow-list. Production wires
// PgTenantIPAllowlistStore (RLS-scoped via withTenant); tests and the dev skeleton wire
// InMemoryTenantIPAllowlistStore. Every method is tenant-scoped by the caller-supplied tenantID (and,
// in pgx, additionally by RLS). CIDRs are stored verbatim as the caller-normalized canonical string.
type TenantIPAllowlistStore interface {
	// ListCIDRs returns the tenant's allow-list CIDRs, ordered lexically. An empty slice is the valid
	// answer for a tenant with no restriction (open) — it is what makes the enforcement middleware a
	// no-op for an unconfigured tenant.
	ListCIDRs(ctx context.Context, tenantID string) ([]string, error)
	// AddCIDR adds one canonical CIDR to the tenant's list. Idempotent: re-adding an entry already
	// present is a no-op (never an error).
	AddCIDR(ctx context.Context, tenantID, cidr string) error
	// RemoveCIDR removes one CIDR from the tenant's list. Removing a CIDR not present returns
	// ErrTenantIPAllowlistEntryNotFound — the caller maps that to a 404.
	RemoveCIDR(ctx context.Context, tenantID, cidr string) error
	// AddCIDRGuarded ATOMICALLY adds cidr and enforces the anti-lockout safeguard: while holding an
	// exclusive per-tenant lock, it reads the current list, computes the RESULTING list (current ∪
	// {cidr}), and commits the add ONLY if `safe(resulting)` — otherwise it makes NO change and returns
	// ErrWouldLockOut. The lock + single-transaction read-check-write is what closes the read-check-write
	// TOCTOU a handler-side check leaves open under concurrent requests. Idempotent (re-adding is a no-op).
	AddCIDRGuarded(ctx context.Context, tenantID, cidr string, safe CoverageCheck) error
	// RemoveCIDRGuarded ATOMICALLY removes cidr with the same anti-lockout safeguard: NO change +
	// ErrWouldLockOut when the resulting (current \ {cidr}) non-empty list would exclude the caller,
	// ErrTenantIPAllowlistEntryNotFound when cidr is absent. Removing to an empty (open) list is always safe.
	RemoveCIDRGuarded(ctx context.Context, tenantID, cidr string, safe CoverageCheck) error
}

// -------------------------------------------------------------------------------------
// InMemoryTenantIPAllowlistStore — concurrency-safe TenantIPAllowlistStore fake for tests + dev.
//
// A plain tenant-scoped set: tenantID -> set of canonical CIDR strings. Like the pg store it holds no
// IP logic (the handlers own normalization + matching), so the fake and the pg store agree on the same
// string-set contract; the pg store's RLS isolation is exercised only by the DB-gated isolation test.
// -------------------------------------------------------------------------------------

type InMemoryTenantIPAllowlistStore struct {
	mu    sync.Mutex
	cidrs map[string]map[string]struct{} // tenantID -> set of cidr
}

// NewInMemoryTenantIPAllowlistStore constructs an empty in-memory allow-list store.
func NewInMemoryTenantIPAllowlistStore() *InMemoryTenantIPAllowlistStore {
	return &InMemoryTenantIPAllowlistStore{cidrs: make(map[string]map[string]struct{})}
}

var _ TenantIPAllowlistStore = (*InMemoryTenantIPAllowlistStore)(nil)

// ListCIDRs implements TenantIPAllowlistStore. Sorted to match the pg `ORDER BY cidr` (deterministic
// assertions and a stable console listing).
func (s *InMemoryTenantIPAllowlistStore) ListCIDRs(_ context.Context, tenantID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.cidrs[tenantID]
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out, nil
}

// AddCIDR implements TenantIPAllowlistStore: idempotent add of one CIDR to the tenant's set.
func (s *InMemoryTenantIPAllowlistStore) AddCIDR(_ context.Context, tenantID, cidr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cidrs[tenantID] == nil {
		s.cidrs[tenantID] = make(map[string]struct{})
	}
	s.cidrs[tenantID][cidr] = struct{}{}
	return nil
}

// RemoveCIDR implements TenantIPAllowlistStore: remove one CIDR, ErrTenantIPAllowlistEntryNotFound when
// it is absent — the same 404-vs-200 distinction the pg store makes via RowsAffected.
func (s *InMemoryTenantIPAllowlistStore) RemoveCIDR(_ context.Context, tenantID, cidr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.cidrs[tenantID]
	if _, ok := set[cidr]; !ok {
		return ErrTenantIPAllowlistEntryNotFound
	}
	delete(set, cidr)
	return nil
}

// sortedLocked returns the tenant's CIDRs sorted; caller MUST hold s.mu.
func (s *InMemoryTenantIPAllowlistStore) sortedLocked(tenantID string) []string {
	set := s.cidrs[tenantID]
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// AddCIDRGuarded implements TenantIPAllowlistStore. The whole read-check-write runs under s.mu, so it is
// atomic against concurrent mutations to any tenant (the fake's analogue of the pg advisory lock).
func (s *InMemoryTenantIPAllowlistStore) AddCIDRGuarded(_ context.Context, tenantID, cidr string, safe CoverageCheck) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Candidate resulting = current ∪ {cidr} (idempotent dedup), computed WITHOUT mutating yet.
	resulting := s.sortedLocked(tenantID)
	if _, present := s.cidrs[tenantID][cidr]; !present {
		resulting = append(resulting, cidr)
		sort.Strings(resulting)
	}
	if !safe(resulting) {
		return ErrWouldLockOut
	}
	if s.cidrs[tenantID] == nil {
		s.cidrs[tenantID] = make(map[string]struct{})
	}
	s.cidrs[tenantID][cidr] = struct{}{}
	return nil
}

// RemoveCIDRGuarded implements TenantIPAllowlistStore, atomically under s.mu.
func (s *InMemoryTenantIPAllowlistStore) RemoveCIDRGuarded(_ context.Context, tenantID, cidr string, safe CoverageCheck) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, present := s.cidrs[tenantID][cidr]; !present {
		return ErrTenantIPAllowlistEntryNotFound
	}
	// Candidate resulting = current \ {cidr}, computed WITHOUT mutating yet.
	resulting := make([]string, 0)
	for _, c := range s.sortedLocked(tenantID) {
		if c != cidr {
			resulting = append(resulting, c)
		}
	}
	if !safe(resulting) {
		return ErrWouldLockOut
	}
	delete(s.cidrs[tenantID], cidr)
	return nil
}
