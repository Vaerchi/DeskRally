package controlplane

// Dynamic machine groups (docs/01 §4) — a saved, named machine-property predicate that resolves to a
// LIVE set of machines. Persistence seam in the same shape as the other tenant-scoped stores: a
// DynamicGroupStore interface, an in-memory fake for tests + the dev skeleton, and a pgx implementation
// (PgDynamicGroupStore in pgstore.go) over the `dynamic_group` table in migrations/0026.
//
// The store holds ONLY the predicate. Member RESOLUTION lives in the handler (http.go), which reuses
// the exact "list the caller's visible machines, then intersect with MachineIDsWithProperty" narrowing
// GET /machines uses — so a dynamic group can never widen a caller's reach. Authorization also lives
// above this seam (CapManageGroups to create/delete, CapViewMachines to list/resolve).

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
)

// Bounds on the free-text columns (stored verbatim, echoed into listings + audit), capped like the
// other operator-set strings (maxMachinePropertyKeyLen etc.).
const (
	maxDynamicGroupNameLen = 128
	maxDynamicGroupKeyLen  = 128
	maxDynamicGroupValLen  = 4096
)

// ErrDynamicGroupNotFound is returned when a get/delete names an id absent in the tenant. Handlers → 404.
var ErrDynamicGroupNotFound = errors.New("dynamic group not found")

// ErrDynamicGroupNameTaken is returned when a create collides with an existing name in the tenant.
// Handlers → 409.
var ErrDynamicGroupNameTaken = errors.New("dynamic group name already in use")

// DynamicGroup is one saved predicate. `PropertyValue == ""` means "any value" (see
// MachineIDsWithProperty). The whole shape a client renders; nothing else (its tenant, timestamps) is
// exposed because the caller already knows the tenant from the request.
type DynamicGroup struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	PropertyKey   string `json:"property_key"`
	PropertyValue string `json:"property_value"`
}

// DynamicGroupStore is the persistence seam for dynamic groups. Production wires PgDynamicGroupStore
// (RLS-scoped via withTenant); tests + the dev skeleton wire InMemoryDynamicGroupStore. Every method is
// tenant-scoped by the caller-supplied tenantID (and, in pgx, additionally by RLS).
type DynamicGroupStore interface {
	// ListDynamicGroups returns the tenant's dynamic groups, ordered by name.
	ListDynamicGroups(ctx context.Context, tenantID string) ([]DynamicGroup, error)
	// GetDynamicGroup returns one group by id, or ErrDynamicGroupNotFound.
	GetDynamicGroup(ctx context.Context, tenantID, id string) (*DynamicGroup, error)
	// CreateDynamicGroup inserts a group; it ASSIGNS g.ID (a fresh uuid) and returns
	// ErrDynamicGroupNameTaken if the name already exists in the tenant.
	CreateDynamicGroup(ctx context.Context, tenantID string, g *DynamicGroup) error
	// DeleteDynamicGroup removes one group by id, or ErrDynamicGroupNotFound.
	DeleteDynamicGroup(ctx context.Context, tenantID, id string) error
}

// -------------------------------------------------------------------------------------
// InMemoryDynamicGroupStore — concurrency-safe DynamicGroupStore fake for tests + dev.
// -------------------------------------------------------------------------------------

type InMemoryDynamicGroupStore struct {
	mu     sync.Mutex
	groups map[string]map[string]*DynamicGroup // tenantID -> id -> group
}

// NewInMemoryDynamicGroupStore constructs an empty in-memory dynamic-group store.
func NewInMemoryDynamicGroupStore() *InMemoryDynamicGroupStore {
	return &InMemoryDynamicGroupStore{groups: make(map[string]map[string]*DynamicGroup)}
}

var _ DynamicGroupStore = (*InMemoryDynamicGroupStore)(nil)

// ListDynamicGroups implements DynamicGroupStore. Ordered by name to match the pg `ORDER BY name`.
func (s *InMemoryDynamicGroupStore) ListDynamicGroups(_ context.Context, tenantID string) ([]DynamicGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.groups[tenantID]
	out := make([]DynamicGroup, 0, len(m))
	for _, g := range m {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// GetDynamicGroup implements DynamicGroupStore.
func (s *InMemoryDynamicGroupStore) GetDynamicGroup(_ context.Context, tenantID, id string) (*DynamicGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[tenantID][id]
	if !ok {
		return nil, ErrDynamicGroupNotFound
	}
	cp := *g
	return &cp, nil
}

// CreateDynamicGroup implements DynamicGroupStore: assigns a fresh id, rejects a duplicate name.
func (s *InMemoryDynamicGroupStore) CreateDynamicGroup(_ context.Context, tenantID string, g *DynamicGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.groups[tenantID] {
		if strings.EqualFold(existing.Name, g.Name) {
			return ErrDynamicGroupNameTaken
		}
	}
	if s.groups[tenantID] == nil {
		s.groups[tenantID] = make(map[string]*DynamicGroup)
	}
	g.ID = newUUID()
	cp := *g
	s.groups[tenantID][g.ID] = &cp
	return nil
}

// DeleteDynamicGroup implements DynamicGroupStore.
func (s *InMemoryDynamicGroupStore) DeleteDynamicGroup(_ context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[tenantID][id]; !ok {
		return ErrDynamicGroupNotFound
	}
	delete(s.groups[tenantID], id)
	return nil
}
