package controlplane

// InMemoryUserStore is a concurrency-safe UserStore fake for tests and the dev skeleton, so
// the full login / session / TOTP flow can be exercised without a live Postgres — matching
// the repo's existing interface-plus-fake testing style (see http_test.go's recordingBinder).
// Production replaces this with a pgx implementation over migrations/0002_auth.sql.

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

type InMemoryUserStore struct {
	mu     sync.Mutex
	users  map[string]*AuthUser // key: tenantID + "\x00" + userID
	grants map[string]*Grant    // key: tenantID + "\x00" + userID
	mfaSeq int64                // last issued mfa_generation (see bumpMFAGeneration)
	// lastTOTPStep is the RFC 4226 counter each user last authenticated with (the user_totp
	// .last_step column, migrations/0012). Held beside the user rather than on AuthUser because
	// it is replay bookkeeping, not part of the authentication VIEW any caller reads.
	lastTOTPStep map[string]uint64 // key: tenantID + "\x00" + userID
	// suspended is `tenant.disabled_at IS NOT NULL`, keyed by TENANT — not copied onto each stored
	// user. Suspension is a fact about the tenancy, and the pg store gets it from a JOIN evaluated
	// at read time; a per-user copy would let the fake report a stale answer for a user added before
	// the suspension, which is exactly the fake-vs-database divergence this repo keeps paying for.
	suspended map[string]bool // key: tenantID
	// tree is the in-memory group store this store resolves coverage through (docs/62; LinkGroupStores).
	// nil = no inheritance (covered == assigned), which is what every test that never nests groups sees.
	// LOCK ORDER: the group store's lock is always taken BEFORE s.mu, never inside it.
	tree groupTreeSource
}

func (s *InMemoryUserStore) setTreeSource(src groupTreeSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tree = src
}

// treeSnapshot takes (and releases) the group store's lock and returns a fresh snapshot of the tenant's
// tree. ok=false when no group store is linked. It must be called BEFORE taking s.mu.
func (s *InMemoryUserStore) treeSnapshot(tenantID string) (tree GroupTree, version int64, ok bool) {
	s.mu.Lock()
	src := s.tree
	s.mu.Unlock()
	if src == nil {
		return nil, 0, false
	}
	t, v := src.snapshotTree(tenantID)
	return t, v, true
}

// expandGrant returns a copy of g whose scopes are resolved against tree (docs/62 R8): covered sets are
// recomputed on EVERY read, into freshly allocated maps, never cached and never shared with the stored
// assignment. With no tree (haveTree false) covered is a fresh copy of assigned.
func expandGrant(g *Grant, tree GroupTree, version int64, haveTree bool) *Grant {
	out := &Grant{UserID: g.UserID, TenantID: g.TenantID, TreeVersion: version, reloadable: true,
		Members: make([]Membership, len(g.Members))}
	for i, m := range g.Members {
		if haveTree {
			m.Scope = expandedScope(m.Scope, tree)
		} else {
			m.Scope = m.Scope.withCovered(m.Scope.assigned)
		}
		out.Members[i] = m
	}
	return out
}

// grantUnderTree implements groupGrantSource: the EFFECTIVE grant for a user against a tree the caller
// already holds (the group store, inside a hierarchy mutation). Takes s.mu; the caller holds the group lock.
func (s *InMemoryUserStore) grantUnderTree(tenantID, userID string, tree GroupTree, version int64) *Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.effectiveGrantLocked(tenantID, userID, tree, version, true)
}

// effectiveGrantLocked builds the effective (unexpired, in-window) grant. Caller holds s.mu.
func (s *InMemoryUserStore) effectiveGrantLocked(tenantID, userID string, tree GroupTree, version int64, haveTree bool) *Grant {
	if g, ok := s.grants[userKey(tenantID, userID)]; ok {
		return expandGrant(g.Effective(time.Now()), tree, version, haveTree)
	}
	return expandGrant(NewGrant(userID, tenantID), tree, version, haveTree)
}

// NewInMemoryUserStore constructs an empty store.
func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{
		users:        make(map[string]*AuthUser),
		grants:       make(map[string]*Grant),
		lastTOTPStep: make(map[string]uint64),
		suspended:    make(map[string]bool),
	}
}

// SetTenantSuspended marks a tenant suspended (or active again), the fake's stand-in for
// `UPDATE tenant SET disabled_at = …`. It affects every user of that tenant, including ones added
// afterwards, because the flag is read at lookup time exactly as the pg store's JOIN is.
func (s *InMemoryUserStore) SetTenantSuspended(tenantID string, suspended bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.suspended[tenantID] = suspended
}

// authView returns the caller-visible copy of a stored user: the row plus the tenant state the pg
// projection joins in. Caller holds s.mu.
func (s *InMemoryUserStore) authView(u *AuthUser) *AuthUser {
	cp := *u
	cp.TenantSuspended = s.suspended[u.TenantID]
	return &cp
}

var _ UserStore = (*InMemoryUserStore)(nil)

func userKey(tenantID, userID string) string { return tenantID + "\x00" + userID }

// AddUser registers a user (copied) and its RBAC grant. The password must already be hashed.
//
// A user that HAS a credential gets a CREDENTIAL EPOCH, because in Postgres it is impossible not to
// have one: `user_credential.updated_at` is NOT NULL, so a row with a hash always carries a
// version. Leaving it zero here would have made the fake and the real store disagree in exactly the
// direction that hides bugs — every in-memory session would compare zero against zero, pass, and
// never exercise the epoch check at all, so a regression that dropped the stamp would go green in
// every test that does not touch a database.
func (s *InMemoryUserStore) AddUser(u *AuthUser, grant *Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *u
	if cp.PasswordHash != "" && cp.CredentialUpdatedAt.IsZero() {
		cp.CredentialUpdatedAt = time.Now().UTC()
	}
	s.users[userKey(u.TenantID, u.ID)] = &cp
	if grant != nil {
		s.grants[userKey(u.TenantID, u.ID)] = grant
	}
}

func (s *InMemoryUserStore) FindUserByEmail(_ context.Context, tenantID, email string) (*AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.TenantID == tenantID && u.Email == email {
			return s.authView(u), nil
		}
	}
	return nil, ErrNoUser
}

func (s *InMemoryUserStore) FindUserByID(_ context.Context, tenantID, userID string) (*AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userKey(tenantID, userID)]
	if !ok {
		return nil, ErrNoUser
	}
	return s.authView(u), nil
}

func (s *InMemoryUserStore) SetTOTP(_ context.Context, tenantID, userID, secretB32 string, confirmed bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userKey(tenantID, userID)]
	if !ok {
		return ErrNoUser
	}
	u.TOTPSecret = secretB32
	u.TOTPConfirmed = confirmed
	u.TOTPPending = ""
	s.bumpMFAGeneration(u)
	return nil
}

// bumpMFAGeneration mirrors the pg store's nextval(mfa_generation_seq): a fresh, never-reused value
// per second-factor change. Caller holds s.mu.
func (s *InMemoryUserStore) bumpMFAGeneration(u *AuthUser) {
	s.mfaSeq++
	u.MFAGeneration = s.mfaSeq
}

// SetPendingTOTP implements UserStore: arm a pending enrollment, leaving the enforced secret and
// its confirmed state exactly as they are (mirrors the pg upsert's pending_secret-only write).
func (s *InMemoryUserStore) SetPendingTOTP(_ context.Context, tenantID, userID, secretB32 string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userKey(tenantID, userID)]
	if !ok {
		return ErrNoUser
	}
	u.TOTPPending = secretB32
	return nil
}

// ConfirmPendingTOTP implements UserStore: promote pending → enforced + confirmed, atomically
// under the mutex. Nothing pending → ErrNoPendingTOTP (never silently confirms an old secret).
func (s *InMemoryUserStore) ConfirmPendingTOTP(_ context.Context, tenantID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userKey(tenantID, userID)]
	if !ok {
		return ErrNoUser
	}
	if u.TOTPPending == "" {
		return ErrNoPendingTOTP
	}
	u.TOTPSecret = u.TOTPPending
	u.TOTPConfirmed = true
	u.TOTPPending = ""
	s.bumpMFAGeneration(u)
	return nil
}

// SetPassword implements UserStore: replace the stored PHC hash. The tenant is part of the map
// key, so a user id from another tenant simply is not found — the same fail-closed answer the pg
// implementation gets from RLS.
//
// It advances the CREDENTIAL EPOCH and returns it (migrations/0018), matching the pg store's
// `RETURNING updated_at`. The stamp must strictly increase, because the whole check is
// `sessionEpoch < credentialEpoch`: two password changes inside one clock tick would otherwise
// share an epoch, and a session issued against the first would still satisfy the second. Windows'
// wall clock has ~15 ms granularity and the tests here change passwords far faster than that, so
// this is not hypothetical — nudging past the previous value keeps the fake honest where the DB
// gets monotonicity from the transaction itself.
func (s *InMemoryUserStore) SetPassword(_ context.Context, tenantID, userID, phcHash string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userKey(tenantID, userID)]
	if !ok {
		return time.Time{}, ErrNoUser
	}
	u.PasswordHash = phcHash
	now := time.Now().UTC()
	if !now.After(u.CredentialUpdatedAt) {
		now = u.CredentialUpdatedAt.Add(time.Nanosecond)
	}
	u.CredentialUpdatedAt = now
	return now, nil
}

// ChangePassword implements UserStore: SetPassword under the epoch compare-and-set, atomically
// under the mutex, as the pg store does it under the user row lock.
func (s *InMemoryUserStore) ChangePassword(_ context.Context, tenantID, userID, phcHash string, expectedEpoch time.Time) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userKey(tenantID, userID)]
	if !ok || u.Disabled || s.suspended[tenantID] {
		return time.Time{}, ErrNoUser
	}
	if expectedEpoch.IsZero() || !u.CredentialUpdatedAt.Equal(expectedEpoch) {
		return time.Time{}, ErrStaleCredential
	}
	u.PasswordHash = phcHash
	now := time.Now().UTC()
	if !now.After(u.CredentialUpdatedAt) {
		now = u.CredentialUpdatedAt.Add(time.Nanosecond)
	}
	u.CredentialUpdatedAt = now
	return now, nil
}

// ConsumeTOTPStep implements UserStore: the check and the write happen together under the mutex,
// so the pg path's single compare-and-set UPDATE and this fake reject a replayed code identically.
// The counter is monotonic and survives a secret change — see migrations/0012.
func (s *InMemoryUserStore) ConsumeTOTPStep(_ context.Context, tenantID, userID string, step uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userKey(tenantID, userID)]; !ok {
		return false, ErrNoUser
	}
	if step <= s.lastTOTPStep[userKey(tenantID, userID)] {
		return false, nil
	}
	s.lastTOTPStep[userKey(tenantID, userID)] = step
	return true, nil
}

func (s *InMemoryUserStore) GrantFor(_ context.Context, tenantID, userID string) (*Grant, error) {
	// The tree snapshot is taken first and its lock released (group store before auth store), then the
	// membership read happens under s.mu: the same "version before rows" order the pg store reads in.
	tree, version, haveTree := s.treeSnapshot(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	// docs/56/57: expired and out-of-window memberships grant nothing (pg filters the same in SQL). A user
	// with no memberships still has an (empty) grant, not an error.
	return s.effectiveGrantLocked(tenantID, userID, tree, version, haveTree), nil
}

// StoredGrantFor implements UserStore: every stored membership, expired ones included (docs/56).
func (s *InMemoryUserStore) StoredGrantFor(_ context.Context, tenantID, userID string) (*Grant, error) {
	tree, version, haveTree := s.treeSnapshot(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.grants[userKey(tenantID, userID)]; ok {
		return expandGrant(g, tree, version, haveTree), nil
	}
	return expandGrant(NewGrant(userID, tenantID), tree, version, haveTree), nil
}

// permanentOwnersLocked counts the tenant's ENABLED users holding a never-expiring Owner membership
// (docs/56 sec. 4.2a), the pg store's same count. Caller holds s.mu.
func (s *InMemoryUserStore) permanentOwnersLocked(tenantID string) int {
	n := 0
	for k, u := range s.users {
		if u.TenantID != tenantID || u.Disabled {
			continue
		}
		g := s.grants[k]
		if g == nil {
			continue
		}
		for _, m := range g.Members {
			if m.Role == RoleOwner && m.ExpiresAt == nil && m.Window == nil {
				n++
				break
			}
		}
	}
	return n
}

// ListUsers implements UserStore: the tenant's users as summaries, ordered by email (matching the
// pg `ORDER BY email` for deterministic assertions and a stable console listing). Each summary carries
// the DISTINCT sorted role keys of the user's memberships (matching the pg aggregate).
func (s *InMemoryUserStore) ListUsers(_ context.Context, tenantID string) ([]UserSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []UserSummary{}
	for _, u := range s.users {
		if u.TenantID == tenantID {
			scope := []string{}
			if g, ok := s.grants[userKey(u.TenantID, u.ID)]; ok {
				if ids := g.AssignmentScope().GroupIDs(); ids != nil {
					scope = ids
				}
			}
			out = append(out, s.summaryLocked(u, scope, time.Now()))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

// summaryLocked builds one user's summary at now (docs/56 sec. 5, docs/57 sec. 5). Caller holds s.mu.
func (s *InMemoryUserStore) summaryLocked(u *AuthUser, scope []string, now time.Time) UserSummary {
	g := s.grants[userKey(u.TenantID, u.ID)]
	window, varies := g.AccessWindowSummary()
	return UserSummary{
		ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Disabled: u.Disabled,
		Roles:               s.rolesForLocked(u.TenantID, u.ID),
		ScopedGroupIDs:      scope,
		AccessExpiresAt:     g.AccessExpiry(),
		AccessExpired:       g.AccessExpired(now),
		AccessWindow:        window,
		AccessWindowVaries:  varies,
		AccessOutsideWindow: g.OutsideWindow(now),
	}
}

// checkSuppliedZone is the fake's twin of the pg write path's zone check (docs/57 sec. 4): a SUPPLIED
// window's zone must load, else ErrUnknownTimeZone before any mutation; a PRESERVED window is unchecked.
func checkSuppliedZone(a Assignment) error {
	if a.Window == nil || !a.WindowSupplied {
		return nil
	}
	_, err := loadZone(a.Window.Zone)
	return err
}

// AccessSummary implements UserStore: one user's ListUsers row.
func (s *InMemoryUserStore) AccessSummary(_ context.Context, tenantID, userID string) (UserSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userKey(tenantID, userID)]
	if !ok {
		return UserSummary{}, ErrNoUser
	}
	scope := []string{}
	if g, ok := s.grants[userKey(tenantID, userID)]; ok {
		if ids := g.AssignmentScope().GroupIDs(); ids != nil {
			scope = ids
		}
	}
	return s.summaryLocked(u, scope, time.Now()), nil
}

// rolesForLocked returns the DISTINCT preset role keys of a user's memberships, sorted ascending, as a
// NON-nil slice (so the JSON is `[]`, never `null`, and matches the pg `array_agg(DISTINCT r.key ORDER
// BY r.key)`). Memberships carrying no role key (e.g. an API-token capability membership) are skipped.
// Caller holds s.mu.
func (s *InMemoryUserStore) rolesForLocked(tenantID, userID string) []string {
	roles := []string{}
	g, ok := s.grants[userKey(tenantID, userID)]
	if !ok || g == nil {
		return roles
	}
	seen := map[string]struct{}{}
	for _, m := range g.Members {
		key := string(m.Role)
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		roles = append(roles, key)
	}
	sort.Strings(roles)
	return roles
}

// SetUserRole implements UserStore: replace the user's memberships with a single tenant-wide membership
// of the preset role. ErrUnknownRole for a non-preset role, ErrNoUser when the id is not in the tenant
// — the same two fail-closed answers the pg store gives (fake-and-pg-must-agree).
func (s *InMemoryUserStore) SetUserRole(ctx context.Context, tenantID, userID string, role Role, scopedGroupIDs []string) error {
	return s.SetUserAssignment(ctx, tenantID, userID, Assignment{Role: role, ScopedGroupIDs: scopedGroupIDs})
}

// SetUserAssignment implements UserStore (docs/56): SetUserRole with an expiry, under the
// permanent-Owner invariant. The mutex makes the before/after count atomic, as pg's Owner lock does.
func (s *InMemoryUserStore) SetUserAssignment(_ context.Context, tenantID, userID string, a Assignment) error {
	if !IsAssignableRole(a.Role) {
		return ErrUnknownRole
	}
	return s.withTreeGuard(tenantID, a.ExpectTreeVersion, func() error { return s.setUserAssignment(tenantID, userID, a) })
}

// withTreeGuard runs fn after confirming the tenant's group tree is still at the version the caller's grant
// was read at (docs/62 R2). expect nil, or no linked group store, runs fn unconditionally. The group lock is
// held across fn so a hierarchy mutation cannot interleave (group before auth, never the reverse).
func (s *InMemoryUserStore) withTreeGuard(tenantID string, expect *int64, fn func() error) error {
	s.mu.Lock()
	src := s.tree
	s.mu.Unlock()
	if expect == nil || src == nil {
		return fn()
	}
	return src.withTree(tenantID, func(_ GroupTree, version int64) error {
		if version != *expect {
			return ErrGroupTreeChanged
		}
		return fn()
	})
}

func (s *InMemoryUserStore) setUserAssignment(tenantID, userID string, a Assignment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := userKey(tenantID, userID)
	if _, ok := s.users[key]; !ok {
		return ErrNoUser
	}
	if err := checkSuppliedZone(a); err != nil {
		return err
	}
	before := s.permanentOwnersLocked(tenantID)
	prev, had := s.grants[key]
	// Groups(nil/empty) is AllGroups (the DB '{}' convention); a non-empty set is a group scope.
	s.grants[key] = NewGrant(userID, tenantID, NewMembership(a.Role, Groups(a.ScopedGroupIDs...)).WithExpiry(a.ExpiresAt).WithWindow(a.Window))
	if before > 0 && s.permanentOwnersLocked(tenantID) == 0 {
		if had {
			s.grants[key] = prev
		} else {
			delete(s.grants, key)
		}
		return ErrLastOwner
	}
	return nil
}

// CreateUser implements UserStore: insert a new credential-less user with one tenant-wide membership of
// the preset role. Mirrors the pg store's fail-closed answers so they agree — ErrUnknownRole for a
// non-preset, ErrEmailExists for a duplicate email in the SAME tenant (the app_user UNIQUE (tenant_id,
// email)). The email compare is exact/case-sensitive, matching Postgres's `text` uniqueness.
func (s *InMemoryUserStore) CreateUser(ctx context.Context, tenantID, userID, email, displayName string, role Role, scopedGroupIDs []string) error {
	return s.CreateUserAssignment(ctx, tenantID, userID, email, displayName, Assignment{Role: role, ScopedGroupIDs: scopedGroupIDs})
}

// CreateUserAssignment implements UserStore: CreateUser with an expiry on the membership (docs/56).
func (s *InMemoryUserStore) CreateUserAssignment(_ context.Context, tenantID, userID, email, displayName string, a Assignment) error {
	if !IsAssignableRole(a.Role) {
		return ErrUnknownRole
	}
	return s.withTreeGuard(tenantID, a.ExpectTreeVersion, func() error {
		return s.createUserAssignment(tenantID, userID, email, displayName, a)
	})
}

func (s *InMemoryUserStore) createUserAssignment(tenantID, userID, email, displayName string, a Assignment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.TenantID == tenantID && u.Email == email {
			return ErrEmailExists
		}
	}
	if err := checkSuppliedZone(a); err != nil {
		return err
	}
	key := userKey(tenantID, userID)
	s.users[key] = &AuthUser{ID: userID, TenantID: tenantID, Email: email, DisplayName: displayName}
	s.grants[key] = NewGrant(userID, tenantID, NewMembership(a.Role, Groups(a.ScopedGroupIDs...)).WithExpiry(a.ExpiresAt).WithWindow(a.Window))
	return nil
}

// SetEmail implements UserStore: replace the user's login email and advance the credential epoch,
// atomically under the mutex. Returns ErrNoUser if the user is absent or disabled, ErrEmailExists
// if newEmail is already taken in the tenant, ErrStaleCredential if expectedEpoch no longer matches
// (a concurrent password change committed between the caller's verification and this write).
func (s *InMemoryUserStore) SetEmail(_ context.Context, tenantID, userID, newEmail string, expectedEpoch time.Time) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userKey(tenantID, userID)]
	if !ok || u.Disabled || s.suspended[tenantID] {
		return time.Time{}, ErrNoUser
	}
	if u.PasswordHash == "" || expectedEpoch.IsZero() || !u.CredentialUpdatedAt.Equal(expectedEpoch) {
		return time.Time{}, ErrStaleCredential
	}
	for _, other := range s.users {
		if other.TenantID == tenantID && other.ID != userID && other.Email == newEmail {
			return time.Time{}, ErrEmailExists
		}
	}
	u.Email = newEmail
	now := time.Now().UTC()
	if !now.After(u.CredentialUpdatedAt) {
		now = u.CredentialUpdatedAt.Add(time.Nanosecond)
	}
	u.CredentialUpdatedAt = now
	return now, nil
}

// SetUserDisabled implements UserStore: flip a user's disabled flag; the tenant is part of the map
// key, so a user id from another tenant simply is not found — the fail-closed answer RLS gives the pg
// store. ErrNoUser when the user is absent in the tenant.
func (s *InMemoryUserStore) SetUserDisabled(_ context.Context, tenantID, userID string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userKey(tenantID, userID)]
	if !ok {
		return ErrNoUser
	}
	before := s.permanentOwnersLocked(tenantID)
	was := u.Disabled
	u.Disabled = disabled
	// docs/56 sec. 4.2a: disabling the last enabled, permanent Owner is refused (pg: the same count
	// under the Owner-membership lock).
	if disabled && before > 0 && s.permanentOwnersLocked(tenantID) == 0 {
		u.Disabled = was
		return ErrLastOwner
	}
	return nil
}

// -------------------------------------------------------------------------------------
// InMemoryAuditStore — concurrency-safe AuditStore fake for tests and the dev skeleton, so the
// H2 backstage audit-chain ingest + linkage verification can be exercised without a live
// Postgres. Production replaces this with PgAuditStore over migrations/0004_audit.sql. Append is
// atomic under the mutex: it re-reads the tail, verifies linkage, and appends, so it is the
// authoritative choke point even under concurrent ingests (mirroring the pgx tx).
// -------------------------------------------------------------------------------------

type InMemoryAuditStore struct {
	mu     sync.Mutex
	chains map[string][]AuditEvent // key: tenantID + "\x00" + sessionID, ordered by seq
	// ingest is the tenant's append log: every stored event in the order it was appended, which
	// is what the export pages over. It mirrors the `ingest_seq` column (migration 0019) — an
	// event's position in this slice IS its ingest_seq. Held as well as `chains` rather than
	// derived from it, because ingest order cannot be recovered from a map of chains: that is the
	// whole reason the column exists.
	ingest map[string][]AuditEvent // key: tenantID
}

// NewInMemoryAuditStore constructs an empty store.
func NewInMemoryAuditStore() *InMemoryAuditStore {
	return &InMemoryAuditStore{
		chains: make(map[string][]AuditEvent),
		ingest: make(map[string][]AuditEvent),
	}
}

var _ AuditStore = (*InMemoryAuditStore)(nil)

func auditKey(tenantID, sessionID string) string { return tenantID + "\x00" + sessionID }

// tailLocked returns the current tail of a chain. Caller holds s.mu.
func (s *InMemoryAuditStore) tailLocked(tenantID, sessionID string) AuditTail {
	chain := s.chains[auditKey(tenantID, sessionID)]
	if len(chain) == 0 {
		return AuditTail{}
	}
	last := chain[len(chain)-1]
	return AuditTail{Exists: true, Seq: last.Seq, Hash: last.Hash}
}

// AuditTail implements AuditStore.
func (s *InMemoryAuditStore) AuditTail(_ context.Context, tenantID, sessionID string) (AuditTail, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tailLocked(tenantID, sessionID), nil
}

// AppendAudit implements AuditStore: verify linkage against the current tail, then append. On any
// linkage break nothing is stored and a *LinkageError is returned.
func (s *InMemoryAuditStore) AppendAudit(_ context.Context, tenantID, sessionID string, events []AuditEvent) (AuditTail, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tail := s.tailLocked(tenantID, sessionID)
	// Idempotent re-send, exactly as PgAuditStore does it (fake and pg must agree).
	skip, err := resolveOverlap(tail, events)
	if err != nil {
		return AuditTail{}, err
	}
	if skip > 0 && skip == len(events) { // an EMPTY batch still reaches verifyLinkage's refusal
		return tail, nil
	}
	events = events[skip:]
	if err := verifyLinkage(tail, events); err != nil {
		return AuditTail{}, err
	}
	key := auditKey(tenantID, sessionID)
	// Copy the slice so the caller can't mutate stored events after the fact.
	s.chains[key] = append(s.chains[key], events...)
	// Same events, in append order — the fake's stand-in for the ingest_seq column. Appending here
	// (rather than sorting on read) is what makes this store's export order match production's:
	// ingest order is a property of WHEN a row arrived and cannot be reconstructed afterwards.
	s.ingest[tenantID] = append(s.ingest[tenantID], events...)
	return s.tailLocked(tenantID, sessionID), nil
}

// ListAuditEventsAsc implements AuditStore.
//
// The ordering must match PgAuditStore's exactly, or paging breaks at a page boundary — the one
// place a divergence shows up as silently skipped rows rather than as an obvious error. Both walk
// the tenant's events in INGEST order and cursor on the ingest position, so the only thing this
// has to get right is that the position of an event in `s.ingest[tenant]` equals its `ingest_seq`.
// That holds because both are assigned at append and neither is ever reordered or deleted.
func (s *InMemoryAuditStore) ListAuditEventsAsc(_ context.Context, tenantID string, q AuditExportQuery) ([]AuditEvent, int64, error) {
	q = q.normalize()
	s.mu.Lock()
	defer s.mu.Unlock()

	wantSession := strings.ToLower(q.SessionID)
	out := []AuditEvent{}
	next := q.AfterIngestSeq
	for i, e := range s.ingest[tenantID] {
		pos := int64(i) // the fake's ingest_seq
		if pos <= q.AfterIngestSeq {
			continue
		}
		// Case-insensitive, because PostgreSQL's `uuid` type canonicalizes to lowercase on the way
		// in while this map keeps whatever string was POSTed (the ingest handler does not parse
		// uuids). Without folding, an uppercase-spelled session id would match here and not there.
		if wantSession != "" && strings.ToLower(e.SessionID) != wantSession {
			continue
		}
		out = append(out, e)
		next = pos
		if len(out) >= q.Limit {
			break
		}
	}
	return out, next, nil
}
