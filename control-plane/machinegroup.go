package controlplane

// Static machine groups (docs/01 §4) — the `machine_group` rows that are the RBAC SCOPE UNIT and the
// container a machine belongs to (machine.group_id). DISTINCT from DYNAMIC groups (dynamicgroup.go),
// which are saved property predicates. Until now machine_group rows could only be created by direct SQL
// (tenant provisioning / tests), so a tenant had no app path to organize its fleet; this store adds
// CREATE + LIST.
//
// Persistence seam in the same shape as the other tenant-scoped stores: a MachineGroupStore interface,
// an in-memory fake for tests + dev, and a pgx implementation (PgMachineGroupStore, pgstore.go) over the
// `machine_group` table in migrations/0001 + 0065 (nesting, docs/62). Authorization lives ABOVE this seam,
// except that a HIERARCHY mutation (create under a parent, reparent, delete) takes a GroupAuthorizer the
// store runs inside its tree-locked transaction against the CURRENT tree (docs/62 R2).

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// maxMachineGroupNameLen caps the group name (stored verbatim, echoed into listings + audit).
const maxMachineGroupNameLen = 128

// ErrMachineGroupNotFound is returned by rename/delete when the id does not resolve within the tenant.
var ErrMachineGroupNotFound = errors.New("machine group not found")

// ErrMachineGroupInUse is returned by delete when the group still has dependents (machines or enrollment
// tokens FK it). The pg store raises it from the foreign-key violation; the handler additionally refuses
// up front when the group still has machines, so both stores agree on the common case.
var ErrMachineGroupInUse = errors.New("machine group is in use")

// validateMachineGroupName trims and validates a group name for create + rename: non-empty, within the
// rune cap, no control characters. Returns the normalized name and whether it is acceptable. Shared so
// create and rename agree (and so the fake and pg stores never disagree on what a valid name is).
func validateMachineGroupName(name string) (string, bool) {
	n := strings.TrimSpace(name)
	if n == "" || utf8.RuneCountInString(n) > maxMachineGroupNameLen {
		return n, false
	}
	if strings.ContainsFunc(n, func(r rune) bool { return unicode.IsControl(r) }) {
		return n, false
	}
	return n, true
}

// MachineGroup is one static machine group: its id (the RBAC scope key + machine.group_id target), its
// display name and, since docs/62, its parent (nil = a root group). ParentID is always present in the JSON
// (null for a root); HANDLERS blank it when the parent is not visible to the caller (R9).
type MachineGroup struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	ParentID *string `json:"parent_id"`
}

// MachineGroupStore is the persistence seam for static machine groups. Production wires
// PgMachineGroupStore (RLS-scoped via withTenant); tests + the dev skeleton wire
// InMemoryMachineGroupStore. Every method is tenant-scoped by the caller-supplied tenantID (and, in
// pgx, additionally by RLS).
type MachineGroupStore interface {
	// ListMachineGroups returns the tenant's machine groups, ordered by (name, id).
	ListMachineGroups(ctx context.Context, tenantID string) ([]MachineGroup, error)
	// GroupTree returns the tenant's structure (id -> parent id, "" = root) together with its
	// group_tree_version. The version is read BEFORE the structure, so a concurrent change can only make
	// the version older than the tree, never newer: a tree-conditional write guarded by it then fails
	// safe (409) rather than succeeding on stale authorization.
	GroupTree(ctx context.Context, tenantID string) (GroupTree, int64, error)
	// CreateMachineGroup inserts a group; it ASSIGNS g.ID (a fresh uuid). g.ParentID, when set, must name a
	// group of this tenant (ErrMachineGroupParentInvalid) and respect the depth cap (ErrMachineGroupTooDeep).
	// Machine-group names are NOT unique — the machine_group table has no unique-name constraint, so groups
	// are distinguished by id and a duplicate name is allowed on BOTH stores (fake-and-pg-must-agree).
	// This is the UNAUTHORIZED primitive (provisioning, tests); handlers use CreateMachineGroupAs.
	CreateMachineGroup(ctx context.Context, tenantID string, g *MachineGroup) error
	// CreateMachineGroupAs is CreateMachineGroup under docs/62 R2: take the tenant tree lock, read the
	// current tree, reload the actor's memberships in the same transaction, run authz, then insert.
	CreateMachineGroupAs(ctx context.Context, tenantID string, actor GroupActor, g *MachineGroup, authz GroupAuthorizer) error
	// MoveMachineGroup reparents group id under newParent (nil = make it a root), same protocol as
	// CreateMachineGroupAs. It returns the updated group and its OLD parent. ErrMachineGroupNotFound,
	// ErrMachineGroupParentInvalid, ErrMachineGroupCycle, ErrMachineGroupTooDeep.
	MoveMachineGroup(ctx context.Context, tenantID string, actor GroupActor, id string, newParent *string, authz GroupAuthorizer) (*MachineGroup, *string, error)
	// RenameMachineGroup sets the group's name (caller validates it first). ErrMachineGroupNotFound if
	// the id does not resolve within the tenant.
	RenameMachineGroup(ctx context.Context, tenantID, id, name string) error
	// RenameMachineGroupIfTree is RenameMachineGroup conditional on the tenant's group tree still being at
	// expectTree (docs/62 R2): a scoped manager's right to rename depends on the tree, so a reparent between
	// the grant read and this write refuses it with ErrGroupTreeChanged. The pg store holds the shared tree
	// lock to the end of its transaction; the fake holds the group lock across check and write.
	RenameMachineGroupIfTree(ctx context.Context, tenantID, id, name string, expectTree int64) error
	// DeleteMachineGroup removes the group. ErrMachineGroupNotFound if it does not resolve;
	// ErrMachineGroupHasChildren if it still has subgroups; ErrMachineGroupInUse if a dependent row
	// (machine / enrollment token) still FKs it. The fake does NOT model foreign keys — the handler refuses
	// up front when the group still has machines, and the pg store maps the FK violation to
	// ErrMachineGroupInUse (so a token-only reference is caught too). Unauthorized primitive.
	DeleteMachineGroup(ctx context.Context, tenantID, id string) error
	// DeleteMachineGroupAs is DeleteMachineGroup under the R2 protocol (lock, tree, reload, authz, delete).
	DeleteMachineGroupAs(ctx context.Context, tenantID string, actor GroupActor, id string, authz GroupAuthorizer) error
}

// -------------------------------------------------------------------------------------
// InMemoryMachineGroupStore — concurrency-safe MachineGroupStore fake for tests + dev.
// -------------------------------------------------------------------------------------

type InMemoryMachineGroupStore struct {
	mu      sync.Mutex
	groups  map[string]map[string]*MachineGroup // tenantID -> id -> group
	version map[string]int64                    // tenantID -> group_tree_version
	// grants lets a hierarchy mutation reload the actor's memberships under the group lock (R2); see
	// LinkGroupStores. Nil = the request-time grant is used as-is.
	grants groupGrantSource
}

// groupGrantSource is the in-memory user store as the group store sees it: an EFFECTIVE grant computed
// against a tree the caller already holds, so no second look at the group store is needed (lock order).
type groupGrantSource interface {
	grantUnderTree(tenantID, userID string, tree GroupTree, version int64) *Grant
}

// NewInMemoryMachineGroupStore constructs an empty in-memory machine-group store.
func NewInMemoryMachineGroupStore() *InMemoryMachineGroupStore {
	return &InMemoryMachineGroupStore{
		groups:  make(map[string]map[string]*MachineGroup),
		version: make(map[string]int64),
	}
}

var _ MachineGroupStore = (*InMemoryMachineGroupStore)(nil)
var _ groupTreeSource = (*InMemoryMachineGroupStore)(nil)

func (s *InMemoryMachineGroupStore) setGrantSource(src groupGrantSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants = src
}

// treeLocked builds a snapshot of one tenant's structure into a freshly allocated map. Caller holds s.mu.
func (s *InMemoryMachineGroupStore) treeLocked(tenantID string) GroupTree {
	m := s.groups[tenantID]
	out := make(GroupTree, len(m))
	for id, g := range m {
		if g.ParentID != nil {
			out[id] = *g.ParentID
		} else {
			out[id] = ""
		}
	}
	return out
}

func (s *InMemoryMachineGroupStore) snapshotTree(tenantID string) (GroupTree, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.treeLocked(tenantID), s.version[tenantID]
}

func (s *InMemoryMachineGroupStore) withTree(tenantID string, fn func(GroupTree, int64) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(s.treeLocked(tenantID), s.version[tenantID])
}

// GroupTree implements MachineGroupStore.
func (s *InMemoryMachineGroupStore) GroupTree(_ context.Context, tenantID string) (GroupTree, int64, error) {
	t, v := s.snapshotTree(tenantID)
	return t, v, nil
}

// ListMachineGroups implements MachineGroupStore. Ordered by (name, id) to match the pg
// `ORDER BY name, id` (names are not unique, so id is the tie-break that keeps the order deterministic).
func (s *InMemoryMachineGroupStore) ListMachineGroups(_ context.Context, tenantID string) ([]MachineGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.groups[tenantID]
	out := make([]MachineGroup, 0, len(m))
	for _, g := range m {
		out = append(out, copyMachineGroup(g))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func copyMachineGroup(g *MachineGroup) MachineGroup {
	cp := *g
	if g.ParentID != nil {
		p := *g.ParentID
		cp.ParentID = &p
	}
	return cp
}

func strOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// createLocked inserts g under the structural rules. Caller holds s.mu.
func (s *InMemoryMachineGroupStore) createLocked(tenantID string, g *MachineGroup) error {
	if s.groups[tenantID] == nil {
		s.groups[tenantID] = make(map[string]*MachineGroup)
	}
	if g.ParentID != nil && *g.ParentID != "" {
		tree := s.treeLocked(tenantID)
		if _, ok := tree[*g.ParentID]; !ok {
			return ErrMachineGroupParentInvalid
		}
		if treeLevel(tree, *g.ParentID)+1 > maxGroupDepth {
			return ErrMachineGroupTooDeep
		}
	} else {
		g.ParentID = nil
	}
	g.ID = newUUID()
	cp := copyMachineGroup(g)
	s.groups[tenantID][g.ID] = &cp
	s.version[tenantID]++
	return nil
}

// CreateMachineGroup implements MachineGroupStore: assign a fresh id and store, tenant-scoped.
func (s *InMemoryMachineGroupStore) CreateMachineGroup(_ context.Context, tenantID string, g *MachineGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createLocked(tenantID, g)
}

// actorGrantLocked is the grant the authorizer sees: the actor's memberships reloaded against the tree the
// caller already holds (the fake's "reload in the transaction"), else the request-time grant. Caller holds
// s.mu; the user store's lock is taken INSIDE it (group before auth).
func (s *InMemoryMachineGroupStore) actorGrantLocked(tenantID string, actor GroupActor, tree GroupTree) *Grant {
	if s.grants != nil && actor.Grant.Reloadable() && actor.UserID != "" {
		return s.grants.grantUnderTree(tenantID, actor.UserID, tree, s.version[tenantID])
	}
	return actor.Grant
}

// CreateMachineGroupAs implements MachineGroupStore.
func (s *InMemoryMachineGroupStore) CreateMachineGroupAs(_ context.Context, tenantID string, actor GroupActor, g *MachineGroup, authz GroupAuthorizer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tree := s.treeLocked(tenantID)
	if authz != nil {
		if err := authz(s.actorGrantLocked(tenantID, actor, tree), tree); err != nil {
			return err
		}
	}
	return s.createLocked(tenantID, g)
}

// MoveMachineGroup implements MachineGroupStore.
func (s *InMemoryMachineGroupStore) MoveMachineGroup(_ context.Context, tenantID string, actor GroupActor, id string, newParent *string, authz GroupAuthorizer) (*MachineGroup, *string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[tenantID][id]
	if !ok {
		return nil, nil, ErrMachineGroupNotFound
	}
	tree := s.treeLocked(tenantID)
	if authz != nil {
		if err := authz(s.actorGrantLocked(tenantID, actor, tree), tree); err != nil {
			return nil, nil, err
		}
	}
	np := strOrEmpty(newParent)
	if err := checkReparent(tree, id, np); err != nil {
		return nil, nil, err
	}
	var old *string
	if g.ParentID != nil {
		o := *g.ParentID
		old = &o
	}
	if np == "" {
		g.ParentID = nil
	} else {
		g.ParentID = &np
	}
	s.version[tenantID]++
	cp := copyMachineGroup(g)
	return &cp, old, nil
}

// RenameMachineGroup implements MachineGroupStore: set the name of an existing group, tenant-scoped.
func (s *InMemoryMachineGroupStore) RenameMachineGroup(_ context.Context, tenantID, id, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[tenantID][id]
	if !ok {
		return ErrMachineGroupNotFound
	}
	g.Name = name
	return nil
}

// RenameMachineGroupIfTree implements MachineGroupStore: the version check and the write both happen under
// the group lock, so a hierarchy mutation cannot land between them.
func (s *InMemoryMachineGroupStore) RenameMachineGroupIfTree(_ context.Context, tenantID, id, name string, expectTree int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version[tenantID] != expectTree {
		return ErrGroupTreeChanged
	}
	g, ok := s.groups[tenantID][id]
	if !ok {
		return ErrMachineGroupNotFound
	}
	g.Name = name
	return nil
}

// hasChildrenLocked reports whether any group names id as its parent. Caller holds s.mu.
func (s *InMemoryMachineGroupStore) hasChildrenLocked(tenantID, id string) bool {
	for _, g := range s.groups[tenantID] {
		if g.ParentID != nil && *g.ParentID == id {
			return true
		}
	}
	return false
}

// DeleteMachineGroup implements MachineGroupStore: remove an existing group, tenant-scoped. The fake
// models no foreign keys — ErrMachineGroupInUse is a pg-store (FK) outcome, and the handler's
// machine-reference check keeps the fake and pg in step for the common case. A group with subgroups is
// refused, exactly as the pg composite FK refuses it (docs/62 D7).
func (s *InMemoryMachineGroupStore) DeleteMachineGroup(_ context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteLocked(tenantID, id)
}

func (s *InMemoryMachineGroupStore) deleteLocked(tenantID, id string) error {
	if _, ok := s.groups[tenantID][id]; !ok {
		return ErrMachineGroupNotFound
	}
	if s.hasChildrenLocked(tenantID, id) {
		return ErrMachineGroupHasChildren
	}
	delete(s.groups[tenantID], id)
	s.version[tenantID]++
	return nil
}

// DeleteMachineGroupAs implements MachineGroupStore.
func (s *InMemoryMachineGroupStore) DeleteMachineGroupAs(_ context.Context, tenantID string, actor GroupActor, id string, authz GroupAuthorizer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[tenantID][id]; !ok {
		return ErrMachineGroupNotFound
	}
	tree := s.treeLocked(tenantID)
	if authz != nil {
		if err := authz(s.actorGrantLocked(tenantID, actor, tree), tree); err != nil {
			return err
		}
	}
	return s.deleteLocked(tenantID, id)
}
