package controlplane

// Dynamic machine groups save predicates that resolve live over the caller's visible machines.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Bounds on the free-text columns (stored verbatim, echoed into listings + audit), capped like the
// other operator-set strings (maxMachinePropertyKeyLen etc.).
const (
	maxDynamicGroupNameLen    = 128
	maxDynamicGroupConditions = 10
)

// ErrDynamicGroupNotFound is returned when a get/delete names an id absent in the tenant. Handlers → 404.
var ErrDynamicGroupNotFound = errors.New("dynamic group not found")

// ErrDynamicGroupNameTaken is returned when a create collides with an existing name in the tenant.
// Handlers → 409.
var ErrDynamicGroupNameTaken = errors.New("dynamic group name already in use")

type Condition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// DynamicGroup stores legacy property predicates with a nil Conditions slice.
type DynamicGroup struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	PropertyKey   string      `json:"property_key"`
	PropertyValue string      `json:"property_value"`
	Match         string      `json:"match"`
	Conditions    []Condition `json:"conditions"`
}

func (g DynamicGroup) effectivePredicate() DynamicGroup {
	if g.Conditions == nil {
		op := "equals"
		if g.PropertyValue == "" {
			op = "exists"
		}
		g.Match = "all"
		g.Conditions = []Condition{{Field: "property:" + g.PropertyKey, Op: op, Value: g.PropertyValue}}
	}
	return g
}

func validateDynamicGroupConditions(match string, conditions []Condition) error {
	if match != "all" && match != "any" {
		return errors.New("match must be all or any")
	}
	if len(conditions) < 1 || len(conditions) > maxDynamicGroupConditions {
		return fmt.Errorf("conditions must contain 1 to %d entries", maxDynamicGroupConditions)
	}
	for i, condition := range conditions {
		if err := condition.validate(); err != nil {
			return fmt.Errorf("condition %d: %w", i+1, err)
		}
	}
	return nil
}

func (c Condition) validate() error {
	if len(c.Value) > maxMachinePropertyValueLen {
		return errors.New("value too long")
	}
	key, property := strings.CutPrefix(c.Field, "property:")
	if property {
		if len(key) == 0 || len(key) > maxMachinePropertyKeyLen {
			return fmt.Errorf("property key must be 1 to %d bytes", maxMachinePropertyKeyLen)
		}
	} else {
		switch c.Field {
		case "os", "hostname", "agent_version":
		case "online":
			if c.Op != "equals" || (c.Value != "true" && c.Value != "false") {
				return errors.New("online requires equals with a value of true or false")
			}
			return nil
		default:
			return errors.New("unknown field")
		}
	}
	switch c.Op {
	case "equals", "not_equals", "contains", "starts_with":
	case "exists", "not_exists":
		if !property || c.Value != "" {
			return errors.New("exists and not_exists require a property field and an empty value")
		}
	case "version_at_least":
		if c.Field != "agent_version" || numericVersion(c.Value) == nil {
			return errors.New("version_at_least requires agent_version and a dotted numeric value")
		}
	default:
		return errors.New("unknown operator")
	}
	return nil
}

// matches evaluates a predicate with its legacy condition already synthesized.
func (g DynamicGroup) matches(m Machine, properties map[string]string, presenceKnown bool) bool {
	wantAll := g.Match == "all"
	for _, condition := range g.Conditions {
		if condition.matches(m, properties, presenceKnown) != wantAll {
			return !wantAll
		}
	}
	return wantAll
}

func (c Condition) matches(m Machine, properties map[string]string, presenceKnown bool) bool {
	if key, property := strings.CutPrefix(c.Field, "property:"); property {
		value, exists := properties[key]
		switch c.Op {
		case "exists":
			return exists
		case "not_exists":
			return !exists
		default:
			return exists && c.matchesText(value)
		}
	}
	switch c.Field {
	case "os":
		return c.matchesText(m.OS)
	case "hostname":
		if c.Op == "not_equals" {
			return c.matchesText(m.Name) && (m.Alias == "" || c.matchesText(m.Alias))
		}
		return c.matchesText(m.Name) || (m.Alias != "" && c.matchesText(m.Alias))
	case "online":
		return presenceKnown && m.Online != nil && strconv.FormatBool(*m.Online) == c.Value
	case "agent_version":
		if c.Op == "version_at_least" {
			return dynamicVersionAtLeast(m.AgentVersion, c.Value)
		}
		return c.matchesText(m.AgentVersion)
	}
	return false
}

func (c Condition) matchesText(value string) bool {
	switch c.Op {
	case "equals":
		return strings.EqualFold(value, c.Value)
	case "not_equals":
		return !strings.EqualFold(value, c.Value)
	case "contains":
		return strings.Contains(strings.ToLower(value), strings.ToLower(c.Value))
	case "starts_with":
		return strings.HasPrefix(strings.ToLower(value), strings.ToLower(c.Value))
	}
	return false
}

var dottedNumericVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

func numericVersion(version string) []string {
	release, _, _ := strings.Cut(version, "+")
	if !dottedNumericVersion.MatchString(release) {
		return nil
	}
	return strings.Split(release, ".")
}

func dynamicVersionAtLeast(version, minimum string) bool {
	actual, target := numericVersion(version), numericVersion(minimum)
	if actual == nil || target == nil {
		return false
	}
	// Compare digit strings to avoid integer overflow. Omitted trailing components are zero.
	for i := 0; i < max(len(actual), len(target)); i++ {
		var a, b string
		if i < len(actual) {
			a = strings.TrimLeft(actual[i], "0")
		}
		if i < len(target) {
			b = strings.TrimLeft(target[i], "0")
		}
		if len(a) != len(b) {
			return len(a) > len(b)
		}
		if a != b {
			return a > b
		}
	}
	return true
}

func (g DynamicGroup) clone() DynamicGroup {
	g.Conditions = slices.Clone(g.Conditions)
	return g
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
		out = append(out, g.clone())
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
	cp := g.clone()
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
	if g.Match == "" {
		g.Match = "all"
	}
	cp := g.clone()
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
