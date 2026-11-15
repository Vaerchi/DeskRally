package controlplane

// Machine custom properties (docs/01 §4) — operator-set key/value fields on a machine.
//
// This is a persistence seam in the same shape as MachineStore: a MachinePropertyStore interface,
// an in-memory fake for tests + the dev skeleton, and a pgx implementation for production
// (PgMachinePropertyStore in pgstore.go) over the `machine_property` table in migrations/0024.
//
// AUTHORIZATION LIVES ABOVE THIS SEAM. A property store is a dumb, tenant-scoped key/value bag: it
// does NOT resolve a machine's group or check capabilities, and — deliberately — does NOT itself
// verify the machine exists. The HTTP handlers resolve the machine through MachineStore first (to
// scope RBAC against the machine's REAL group, never a caller-supplied value), so by the time a
// property method is called the machine is already known to exist in the tenant. The pg
// implementation ADDITIONALLY rejects a property that names a machine outside the pinned tenant via
// the composite FK (migrations/0024) — defense-in-depth for a path the handler already guards, and
// what makes the direct-store RLS isolation test meaningful.

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
)

// Bounds on the free-text columns: both are stored verbatim and echoed back into listings + audit
// metadata, so they are capped, same discipline as maxMachineNameLen for machine.hostname.
const (
	maxMachinePropertyKeyLen   = 128
	maxMachinePropertyValueLen = 4096
)

// ErrMachinePropertyNotFound is the sentinel returned when a delete names a key that is not present
// (or a machine with no such property). Handlers translate it to a 404. A SET is an upsert and never
// returns it; a cross-tenant/unknown machine surfaces as ErrMachineNotFound instead (the pg FK).
var ErrMachinePropertyNotFound = errors.New("machine property not found")

// MachineProperty is one operator-set key/value custom field on a machine. It is the WHOLE shape
// ListProperties returns and the whole body a client renders — nothing else about the property
// (its tenant, its machine id, its timestamps) is exposed, all of which the caller already knows
// from the request path.
type MachineProperty struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// MachinePropertyStore is the persistence seam for machine custom properties. Production wires
// PgMachinePropertyStore (RLS-scoped via withTenant); tests and the dev skeleton wire
// InMemoryMachinePropertyStore. Every method is tenant-scoped by the caller-supplied tenantID (and,
// in pgx, additionally by RLS). machineID is the machine PRIMARY KEY (machine.id), the same identity
// GetMachineByID takes and the REST `/machines/{id}/properties` path carries — never the device id.
type MachinePropertyStore interface {
	// ListProperties returns every property on the machine within the tenant, ordered by key. An
	// empty slice is the valid answer for a machine with no properties; it is NOT distinguished from
	// an unknown machine here (the pg SELECT never consults the machine FK), so a handler wanting a
	// 404 for a missing machine resolves it via GetMachineByID first.
	ListProperties(ctx context.Context, tenantID, machineID string) ([]MachineProperty, error)
	// SetProperty upserts one key/value on the machine within the tenant: a new key is inserted, an
	// existing key's value replaced. It does not itself verify the machine exists (see the file doc);
	// the pg implementation rejects a cross-tenant machine with ErrMachineNotFound via the composite
	// FK.
	SetProperty(ctx context.Context, tenantID, machineID, key, value string) error
	// DeleteProperty removes one key from the machine within the tenant. Deleting a key that is not
	// present (or on a machine with no properties) returns ErrMachinePropertyNotFound — the caller
	// maps that to a 404.
	DeleteProperty(ctx context.Context, tenantID, machineID, key string) error
	// MachineIDsWithProperty returns the set of machine PRIMARY KEYS (machine.id) in the tenant that
	// have a property with `key` — and, when `value` is non-empty, exactly that value (an empty
	// `value` matches the key with ANY value). It backs the fleet search/filter (docs/01 §4): the
	// listing handler intersects this set with the machines the caller may already see, so the filter
	// can only ever narrow a listing, never widen it or reveal a machine the caller couldn't list.
	// `key` must be non-empty; the result is a set for O(1) membership.
	MachineIDsWithProperty(ctx context.Context, tenantID, key, value string) (map[string]struct{}, error)
}

// -------------------------------------------------------------------------------------
// InMemoryMachinePropertyStore — concurrency-safe MachinePropertyStore fake for tests + dev.
//
// It is a plain tenant-scoped map, keyed by (tenantID, machineID). Like the pg store it does not
// verify the machine exists on SET (the handler resolves the machine first) — the fake and the pg
// store therefore agree on the KV contract; the pg store's composite-FK rejection is exercised only
// by the RLS isolation test, on a cross-tenant path the handler never reaches.
// -------------------------------------------------------------------------------------

type InMemoryMachinePropertyStore struct {
	mu    sync.Mutex
	props map[string]map[string]string // key: mpKey(tenantID, machineID) -> {propertyKey: value}
}

// NewInMemoryMachinePropertyStore constructs an empty in-memory property store.
func NewInMemoryMachinePropertyStore() *InMemoryMachinePropertyStore {
	return &InMemoryMachinePropertyStore{props: make(map[string]map[string]string)}
}

var _ MachinePropertyStore = (*InMemoryMachinePropertyStore)(nil)

func mpKey(tenantID, machineID string) string { return tenantID + "\x00" + machineID }

// ListProperties implements MachinePropertyStore. Ordered by key to match the pg `ORDER BY key`
// (deterministic assertions).
func (s *InMemoryMachinePropertyStore) ListProperties(_ context.Context, tenantID, machineID string) ([]MachineProperty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.props[mpKey(tenantID, machineID)]
	out := make([]MachineProperty, 0, len(m))
	for k, v := range m {
		out = append(out, MachineProperty{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// SetProperty implements MachinePropertyStore: idempotent create-or-update of one key.
func (s *InMemoryMachinePropertyStore) SetProperty(_ context.Context, tenantID, machineID, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := mpKey(tenantID, machineID)
	if s.props[k] == nil {
		s.props[k] = make(map[string]string)
	}
	s.props[k][key] = value
	return nil
}

// DeleteProperty implements MachinePropertyStore: remove one key, ErrMachinePropertyNotFound when it
// (or the machine) is absent — the same 404-vs-204 distinction the pg store makes via RowsAffected.
func (s *InMemoryMachinePropertyStore) DeleteProperty(_ context.Context, tenantID, machineID, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.props[mpKey(tenantID, machineID)]
	if _, ok := m[key]; !ok {
		return ErrMachinePropertyNotFound
	}
	delete(m, key)
	return nil
}

// MachineIDsWithProperty implements MachinePropertyStore. Walks the tenant's own entries (the map is
// keyed by mpKey(tenantID, machineID)) and collects the machine ids whose bag has `key` — matching
// `value` exactly when it is non-empty. A machine from ANOTHER tenant is never considered: the key is
// prefixed with tenantID, mirroring how RLS scopes the pg query.
func (s *InMemoryMachinePropertyStore) MachineIDsWithProperty(_ context.Context, tenantID, key, value string) (map[string]struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]struct{})
	prefix := tenantID + "\x00"
	for k, bag := range s.props {
		machineID, ok := strings.CutPrefix(k, prefix)
		if !ok {
			continue // another tenant's entry
		}
		v, present := bag[key]
		if !present {
			continue
		}
		if value != "" && v != value {
			continue
		}
		out[machineID] = struct{}{}
	}
	return out, nil
}
