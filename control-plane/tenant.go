package controlplane

// Tenant repository — the provisioning + listing surface over the `tenant` table
// (migrations/0001_core.sql).
//
// RLS makes this surface deliberately asymmetric for the app role:
//   * ListTenants runs tenant-pinned, so rmt_app sees exactly its OWN tenant row (the policy
//     is `id = current_setting('app.current_tenant')`). Cross-tenant listing is not possible
//     from the app connection at all — by design.
//   * CreateTenant provisions a NEW tenant, which the RLS policy forbids for the pinned app
//     connection — so it goes through the SECURITY DEFINER cp_create_tenant function
//     (migrations/0006_tenant_provision.sql), the same privileged-bootstrap pattern as 0003.
//     The handler gates it on CapManageTenant before calling.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// ErrTenantSlugTaken is returned when creating a tenant whose slug already exists.
var ErrTenantSlugTaken = errors.New("tenant slug already in use")

// Tenant is one tenant row as the management API exposes it.
type Tenant struct {
	ID             string    `json:"id"`
	Slug           string    `json:"slug"`
	Name           string    `json:"name"`
	DeploymentMode string    `json:"deployment_mode"` // "saas" | "self_hosted"
	CreatedAt      time.Time `json:"created_at"`
	Disabled       bool      `json:"disabled"`
	// Require2FA reflects the tenant's enforcement policy: when true, every member must have a
	// confirmed TOTP enrollment or their login is refused. Set via PUT /tenant/security-policy.
	Require2FA bool `json:"require_2fa"`
}

// TenantSecurityPolicy is the wire shape for GET/PUT /tenant/security-policy.
type TenantSecurityPolicy struct {
	Require2FA bool `json:"require_2fa"`
}

// ValidDeploymentMode reports whether mode is one of the values 0001_core.sql's CHECK accepts.
func ValidDeploymentMode(mode string) bool { return mode == "saas" || mode == "self_hosted" }

// TenantStore is the persistence seam for tenants.
type TenantStore interface {
	// ListTenants returns the tenant rows visible to the pinned tenant (for the RLS-subject
	// app role that is exactly the caller's own tenant).
	ListTenants(ctx context.Context, tenantID string) ([]Tenant, error)
	// CreateTenant provisions a NEW tenant (privileged; see the file doc). The store assigns
	// ID and CreatedAt (read back into t). Returns ErrTenantSlugTaken on a slug collision.
	CreateTenant(ctx context.Context, tenantID string, t *Tenant) error
	// GetSecurityPolicy returns the current security policy for the pinned tenant.
	GetSecurityPolicy(ctx context.Context, tenantID string) (TenantSecurityPolicy, error)
	// SetRequire2FA updates the require_2fa flag for the pinned tenant.
	SetRequire2FA(ctx context.Context, tenantID string, require bool) error
}

// -------------------------------------------------------------------------------------
// InMemoryTenantStore — concurrency-safe fake for tests and DEV mode. Mirrors the RLS view:
// ListTenants returns only the pinned tenant's row.
// -------------------------------------------------------------------------------------

type InMemoryTenantStore struct {
	mu      sync.Mutex
	tenants map[string]*Tenant // key: tenant id
}

// NewInMemoryTenantStore constructs an empty in-memory tenant store.
func NewInMemoryTenantStore() *InMemoryTenantStore {
	return &InMemoryTenantStore{tenants: make(map[string]*Tenant)}
}

var _ TenantStore = (*InMemoryTenantStore)(nil)

// ListTenants implements TenantStore: only the caller's own tenant row, as RLS would.
func (s *InMemoryTenantStore) ListTenants(_ context.Context, tenantID string) ([]Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tenants[tenantID]; ok {
		return []Tenant{*t}, nil
	}
	return []Tenant{}, nil
}

// GetSecurityPolicy implements TenantStore: returns the current security policy.
func (s *InMemoryTenantStore) GetSecurityPolicy(_ context.Context, tenantID string) (TenantSecurityPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tenants[tenantID]; ok {
		return TenantSecurityPolicy{Require2FA: t.Require2FA}, nil
	}
	return TenantSecurityPolicy{}, nil
}

// SetRequire2FA implements TenantStore: sets the require_2fa flag.
func (s *InMemoryTenantStore) SetRequire2FA(_ context.Context, tenantID string, require bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[tenantID]
	if !ok {
		return ErrNoTenant
	}
	t.Require2FA = require
	return nil
}

// CreateTenant implements TenantStore. The pinned tenantID is irrelevant to creation (a new
// tenant is a new isolation domain), matching cp_create_tenant's SECURITY DEFINER semantics.
func (s *InMemoryTenantStore) CreateTenant(_ context.Context, _ string, t *Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.tenants {
		if strings.EqualFold(existing.Slug, t.Slug) {
			return ErrTenantSlugTaken
		}
	}
	cp := *t
	if cp.ID == "" {
		cp.ID = newUUID()
	}
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	s.tenants[cp.ID] = &cp
	t.ID = cp.ID
	t.CreatedAt = cp.CreatedAt
	return nil
}
