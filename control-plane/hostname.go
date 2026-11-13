package controlplane

// The operator-managed tenant hostname table (docs/66 2a.10, 2b.2, 2c.2): an ASSIGNMENT HISTORY.
//
//   - assign        creates a PENDING assignment (new id)
//   - activate      pending -> active, SAME id (an approval made while pending stays valid)
//   - release       pending|active -> released, terminal, starts the 30-day quarantine
//   - reactivate    a released host + tenant come back as a NEW assignment (new id), so any earlier
//                   branding approval no longer matches
//
// The Pg implementation (pgstore_hostname.go) enforces all of it in SQL (migration 0071); the in-memory fake
// below enforces the same rules and shares one contract test with it (hostname_contract_test.go). Operator
// authorization is a database check (cp_platform_check); the fake delegates it to an injectable predicate.

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	// ErrHostnameTaken: the host (or the tenant) already has a live (pending or active) assignment.
	ErrHostnameTaken = errors.New("hostname or tenant already has a live assignment")
	// ErrHostnameQuarantined: another tenant released the host less than its quarantine ago.
	ErrHostnameQuarantined = errors.New("hostname is quarantined")
	// ErrHostnameState: the assignment is not in a state this operation accepts.
	ErrHostnameState = errors.New("assignment is not in a valid state for this operation")
	// ErrHostnameNotFound: no such assignment.
	ErrHostnameNotFound = errors.New("no such hostname assignment")
	// ErrHostnameInvalid: host shape or quarantine length refused.
	ErrHostnameInvalid = errors.New("invalid hostname request")
	// ErrHostnameBusy: a lock wait on the tenant or host timed out; retry.
	ErrHostnameBusy = errors.New("hostname assignment is busy; retry")
)

// HostnameQuarantineDays is the minimum (and default) quarantine after a release.
const HostnameQuarantineDays = 30

// HostnameAssignment is one row of tenant_hostname_assignment.
type HostnameAssignment struct {
	ID               string     `json:"id"`
	Host             string     `json:"host"`
	TenantID         string     `json:"tenant_id"`
	Kind             string     `json:"kind"`
	State            string     `json:"state"`
	CreatedBy        string     `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	ActivatedAt      *time.Time `json:"activated_at,omitempty"`
	ReleasedAt       *time.Time `json:"released_at,omitempty"`
	ReleasedBy       string     `json:"released_by,omitempty"`
	QuarantinedUntil *time.Time `json:"quarantined_until,omitempty"`
}

// HostnameStore is the operator lifecycle. Every method takes the operator; audit rows are written by the
// store in the same unit of work as the change (the extra map is merged into the audit metadata: override
// reasons, release reasons).
type HostnameStore interface {
	Assign(ctx context.Context, c PlatformCaller, tenantID, host string, extra map[string]any) (*HostnameAssignment, error)
	Activate(ctx context.Context, c PlatformCaller, id string, extra map[string]any) (*HostnameAssignment, error)
	Release(ctx context.Context, c PlatformCaller, id string, quarantineDays int, extra map[string]any) (*HostnameAssignment, error)
	Reactivate(ctx context.Context, c PlatformCaller, releasedID string, activate bool, extra map[string]any) (*HostnameAssignment, error)
	// List returns assignment history ordered by host, creation time, id. tenantID "" lists every tenant's.
	List(ctx context.Context, c PlatformCaller, tenantID string) ([]HostnameAssignment, error)
}

// HostScopeSource answers the one question the in-memory attended store needs to mirror the scoped SQL: which
// tenant currently holds this host as an ACTIVE assignment.
type HostScopeSource interface {
	ActiveTenantForHost(host string) (tenantID string, ok bool)
}

// InMemoryHostnameStore is the DEV/test HostnameStore. It models migration 0071's rules.
type InMemoryHostnameStore struct {
	mu   sync.Mutex
	rows []*HostnameAssignment
	// Now is the clock (tests move it). Nil = time.Now.
	Now func() time.Time
	// Authorize decides whether a caller is an operator. Nil = everyone (the real check is the database's).
	Authorize func(PlatformCaller) bool
	// TenantExists / TenantActive model tenant state. Nil = every tenant exists and is active.
	TenantExists func(id string) bool
	TenantActive func(id string) bool
	// Audit records "<chain>:<action>:<target>" lines for tests.
	Audit []string
	// OnReassign is called, under the store's lock, whenever an assign, release or reactivate changes a tenant's
	// assignment (the database clears the tenant's published branding in the same transaction: docs/66 2b.2,
	// 2c.2). The in-memory branding store hooks it.
	OnReassign func(tenantID string)
}

var _ HostnameStore = (*InMemoryHostnameStore)(nil)
var _ HostScopeSource = (*InMemoryHostnameStore)(nil)

func (s *InMemoryHostnameStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *InMemoryHostnameStore) check(c PlatformCaller) error {
	if c.SessionID == "" || (s.Authorize != nil && !s.Authorize(c)) {
		return ErrPlatformDenied
	}
	return nil
}

func (s *InMemoryHostnameStore) audit(tenantID, action string, a *HostnameAssignment) {
	s.Audit = append(s.Audit, "platform:platform.hostname."+action+":"+a.ID, "tenant:"+tenantID+":tenant.hostname."+action+":"+a.ID)
}

func (s *InMemoryHostnameStore) find(id string) *HostnameAssignment {
	for _, r := range s.rows {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (s *InMemoryHostnameStore) live(host, tenant string) bool {
	for _, r := range s.rows {
		if r.State != "released" && (r.Host == host || r.TenantID == tenant) {
			return true
		}
	}
	return false
}

func (s *InMemoryHostnameStore) quarantinedFor(host, tenant string) bool {
	for _, r := range s.rows {
		if r.Host == host && r.State == "released" && r.TenantID != tenant && r.QuarantinedUntil.After(s.now()) {
			return true
		}
	}
	return false
}

func (s *InMemoryHostnameStore) create(c PlatformCaller, tenantID, host string) (*HostnameAssignment, error) {
	if !hostnameRE.MatchString(host) {
		return nil, ErrHostnameInvalid
	}
	if s.TenantExists != nil && !s.TenantExists(tenantID) {
		return nil, ErrPlatformNoTenant
	}
	if s.quarantinedFor(host, tenantID) {
		return nil, ErrHostnameQuarantined
	}
	if s.live(host, tenantID) {
		return nil, ErrHostnameTaken
	}
	a := &HostnameAssignment{ID: newUUID(), Host: host, TenantID: tenantID, Kind: "subdomain", State: "pending",
		CreatedBy: operatorLabel(c), CreatedAt: s.now()}
	s.rows = append(s.rows, a)
	return a, nil
}

func operatorLabel(c PlatformCaller) string {
	if c.Email != "" {
		return c.Email
	}
	return c.UserID
}

func (s *InMemoryHostnameStore) Assign(_ context.Context, c PlatformCaller, tenantID, host string, _ map[string]any) (*HostnameAssignment, error) {
	if err := s.check(c); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.create(c, tenantID, host)
	if err != nil {
		return nil, err
	}
	if s.OnReassign != nil {
		s.OnReassign(tenantID)
	}
	s.audit(tenantID, "assign", a)
	cp := *a
	return &cp, nil
}

func (s *InMemoryHostnameStore) Activate(_ context.Context, c PlatformCaller, id string, _ map[string]any) (*HostnameAssignment, error) {
	if err := s.check(c); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.find(id)
	if a == nil {
		return nil, ErrHostnameNotFound
	}
	if a.State != "pending" {
		return nil, ErrHostnameState
	}
	if s.quarantinedFor(a.Host, a.TenantID) {
		return nil, ErrHostnameQuarantined
	}
	t := s.now()
	a.State, a.ActivatedAt = "active", &t
	s.audit(a.TenantID, "activate", a)
	cp := *a
	return &cp, nil
}

func (s *InMemoryHostnameStore) Release(_ context.Context, c PlatformCaller, id string, days int, _ map[string]any) (*HostnameAssignment, error) {
	if err := s.check(c); err != nil {
		return nil, err
	}
	if days < HostnameQuarantineDays {
		return nil, ErrHostnameInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.find(id)
	if a == nil {
		return nil, ErrHostnameNotFound
	}
	if a.State == "released" {
		return nil, ErrHostnameState
	}
	t := s.now()
	until := t.Add(time.Duration(days) * 24 * time.Hour)
	a.State, a.ReleasedAt, a.ReleasedBy, a.QuarantinedUntil = "released", &t, operatorLabel(c), &until
	if s.OnReassign != nil {
		s.OnReassign(a.TenantID)
	}
	s.audit(a.TenantID, "release", a)
	cp := *a
	return &cp, nil
}

func (s *InMemoryHostnameStore) Reactivate(_ context.Context, c PlatformCaller, releasedID string, activate bool, _ map[string]any) (*HostnameAssignment, error) {
	if err := s.check(c); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.find(releasedID)
	if old == nil {
		return nil, ErrHostnameNotFound
	}
	if old.State != "released" {
		return nil, ErrHostnameState
	}
	a, err := s.create(c, old.TenantID, old.Host)
	if err != nil {
		return nil, err
	}
	if activate {
		t := s.now()
		a.State, a.ActivatedAt = "active", &t
	}
	if s.OnReassign != nil {
		s.OnReassign(a.TenantID)
	}
	s.audit(a.TenantID, "reactivate", a)
	cp := *a
	return &cp, nil
}

func (s *InMemoryHostnameStore) List(_ context.Context, c PlatformCaller, tenantID string) ([]HostnameAssignment, error) {
	if err := s.check(c); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]HostnameAssignment, 0, len(s.rows))
	for _, r := range s.rows {
		if tenantID == "" || r.TenantID == tenantID {
			out = append(out, *r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// ActiveTenantForHost implements HostScopeSource: the CURRENT active assignee of host (a fresh read each
// call, no cache), provided the tenant is active.
func (s *InMemoryHostnameStore) ActiveTenantForHost(host string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.Host == host && r.State == "active" {
			if s.TenantActive != nil && !s.TenantActive(r.TenantID) {
				return "", false
			}
			return r.TenantID, true
		}
	}
	return "", false
}

// AgeReleased is a TEST helper: moves a host's released rows back in time by d (the pg equivalent updates
// released_at and quarantined_until with triggers disabled).
func (s *InMemoryHostnameStore) AgeReleased(host string, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.Host == host && r.State == "released" {
			t := r.ReleasedAt.Add(-d)
			u := r.QuarantinedUntil.Add(-d)
			r.ReleasedAt, r.QuarantinedUntil = &t, &u
		}
	}
}
