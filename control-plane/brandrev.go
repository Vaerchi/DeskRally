package controlplane

// Branding REVISIONS, operator approval and publication (docs/66 2a.3, 2b.2, 2c.2): stage 1b.
//
//   - every public edit by the Owner inserts a NEW, immutable, normalised revision and moves only the DRAFT
//     pointer; the previously approved revision stays published (no flash of neutral during review);
//   - the platform operator publishes with a COMPARE-AND-SWAP on (tenant, revision id, revision hash,
//     assignment id): it succeeds only if the draft pointer still equals that revision, the stored hash equals
//     the hash the operator saw, and the tenant's current live (pending or active) assignment is the one the
//     operator reviewed. The published pointer is a triple (revision id, hash, assignment id);
//   - the public read publishes only when the published assignment id equals the host's CURRENT ACTIVE
//     assignment and the tenant is active, in ONE fresh lookup (no cache, no coalescing);
//   - an explicit withdrawal clears the published pointer; assign, release and reactivate clear it too (a new
//     owner never inherits);
//   - edit, approve, withdraw and every assignment change serialise on the tenant's pointer-row lock.
//
// The Pg implementation is pgstore_brandrev.go over migration 0072; InMemoryBrandingStore below enforces the
// same rules and shares one contract test with it (brandrev_contract_test.go).

import (
	"context"
	"errors"
	"sort"
	"time"
)

var (
	// ErrBrandingStale: the operator's review no longer matches (the Owner edited, the assignment changed, the
	// hash differs, or there is no draft). Nothing was published. HTTP 409.
	ErrBrandingStale = errors.New("review is stale")
	// ErrBrandingNotPublished: a withdrawal found nothing published.
	ErrBrandingNotPublished = errors.New("nothing is published")
	// ErrBrandingRateLimited: too many revisions in the last hour (or the history is full). HTTP 429.
	ErrBrandingRateLimited = errors.New("too many branding revisions; retry later")
	// ErrBrandingNoLogoToKeep: keep_logo was asked for but the draft has no logo.
	ErrBrandingNoLogoToKeep = errors.New("there is no logo to keep")
)

// Revision budget per tenant: an Owner cannot fill the database with 64 KiB revisions.
const (
	BrandingRevisionsPerHour = 20
	BrandingRevisionsMax     = 1000
)

// BrandingRevision is one immutable row of tenant_branding_revision.
type BrandingRevision struct {
	ID          string       `json:"id"`
	TenantID    string       `json:"-"`
	Seq         int64        `json:"seq"`
	ProductName string       `json:"product_name"`
	AccentColor string       `json:"accent_color"`
	SupportText string       `json:"support_text"`
	Contact     BrandContact `json:"support_contact"`
	LogoSHA256  string       `json:"logo_sha256"`
	HasLogo     bool         `json:"has_logo"`
	LogoPNG     []byte       `json:"-"`
	Hash        string       `json:"normalized_hash"`
	CreatedBy   string       `json:"created_by"`
	CreatedAt   time.Time    `json:"created_at"`
}

// BrandingRevisionInput is a NORMALISED Owner edit (see PrepareBrandingRevision).
type BrandingRevisionInput struct {
	ProductName string
	AccentColor string
	SupportText string
	Contact     BrandContact
	// LogoPNG is the converter's output (a validated PNG of at most 64 KiB), or nil.
	LogoPNG []byte
	// KeepLogo reuses the current draft's logo (same bytes, same hash) instead of LogoPNG.
	KeepLogo bool
}

// PrepareBrandingRevision validates and normalises the text fields of an Owner edit. The logo is converted by
// the caller (the child process) and passed in already derived.
func PrepareBrandingRevision(in BrandingRevisionInput) (BrandingRevisionInput, *BrandFieldError) {
	var ferr *BrandFieldError
	out := in
	if out.ProductName, ferr = NormalizeBrandName(in.ProductName); ferr != nil {
		return in, ferr
	}
	if out.AccentColor, ferr = NormalizeBrandAccent(in.AccentColor); ferr != nil {
		return in, ferr
	}
	if out.SupportText, ferr = NormalizeBrandSupportText(in.SupportText); ferr != nil {
		return in, ferr
	}
	if out.Contact, ferr = NormalizeBrandContact(in.Contact); ferr != nil {
		return in, ferr
	}
	if in.KeepLogo && len(in.LogoPNG) > 0 {
		return in, fieldErr("logo", "send a new logo or keep_logo, not both")
	}
	if len(out.LogoPNG) > 0 {
		if err := VerifyConvertedLogo(out.LogoPNG); err != nil {
			return in, fieldErr("logo", "is not a valid converted logo")
		}
	}
	return out, nil
}

// logoSHA is the lowercase hex SHA-256 of the stored PNG, empty for no logo.
func logoSHA(png []byte) string {
	if len(png) == 0 {
		return ""
	}
	return sha256Hex(png)
}

// BrandingAssignmentRef is the slice of an assignment the branding flows need.
type BrandingAssignmentRef struct {
	ID    string `json:"id"`
	Host  string `json:"host"`
	State string `json:"state"`
}

// BrandingOwnerState is what the Owner (and any member, read-only) sees about their public branding.
type BrandingOwnerState struct {
	Draft      *BrandingRevision      `json:"draft"`
	Published  *BrandingRevision      `json:"published"`
	Assignment *BrandingAssignmentRef `json:"assignment"`
	// Live: the published revision is bound to the tenant's ACTIVE assignment, i.e. guests see it right now.
	Live bool `json:"live"`
	// DraftIsPublished: the draft and the published revision are the same row.
	DraftIsPublished bool `json:"draft_is_published"`
	// PublishedAt: when the operator approved the published revision (absent when nothing is published).
	PublishedAt *time.Time `json:"published_at,omitempty"`
	// Withdrawn: the operator withdrew the last publication and nothing has been approved since (absent for
	// "never approved", and after a hostname change, which starts a new assignment). It carries no operator
	// identity and no reason: a tenant does not see those (docs/66 2a.3).
	Withdrawn *BrandingWithdrawn `json:"withdrawn,omitempty"`
}

// BrandingWithdrawn is the Owner's view of a withdrawal: when, and which revision when that is known.
type BrandingWithdrawn struct {
	At         time.Time `json:"at"`
	RevisionID string    `json:"revision_id,omitempty"`
}

// BrandingReview is what the operator reviews: the DRAFT revision exactly as stored (with its logo bytes) and
// the pointer and assignment facts the approval binds.
type BrandingReview struct {
	TenantID              string                 `json:"tenant_id"`
	Draft                 *BrandingRevision      `json:"draft"`
	PublishedRevisionID   string                 `json:"published_revision_id"`
	PublishedHash         string                 `json:"published_revision_hash"`
	PublishedAssignmentID string                 `json:"published_assignment_id"`
	Assignment            *BrandingAssignmentRef `json:"assignment"`
	// Generation is the pointer row's review generation: the approval must send it back (repair A1).
	Generation int64 `json:"review_generation"`
}

// BrandingApproval is the operator's request: the three things the review showed.
type BrandingApproval struct {
	RevisionID   string `json:"revision_id"`
	Hash         string `json:"normalized_hash"`
	AssignmentID string `json:"assignment_id"`
	// Generation is the review generation the operator's review returned; compared under the pointer lock.
	Generation int64 `json:"review_generation"`
}

// BrandingApprovalResult is what a successful approval published.
type BrandingApprovalResult struct {
	RevisionID      string `json:"revision_id"`
	Hash            string `json:"normalized_hash"`
	AssignmentID    string `json:"assignment_id"`
	Host            string `json:"host"`
	AssignmentState string `json:"assignment_state"`
	ProductName     string `json:"product_name"`
}

// BrandPeer is another tenant's published product name (the confusable comparison set).
type BrandPeer struct {
	TenantID    string
	ProductName string
}

// PublishedBranding is the public read's one result row: the published revision of the host's current active
// assignment. LogoPNG is filled only when the lookup asked for it (the logo route).
type PublishedBranding struct {
	ProductName string
	AccentColor string
	SupportText string
	Contact     BrandContact
	LogoSHA256  string
	LogoPNG     []byte
}

// BrandingRevisionStore is the seam; PgBrandingRevisionStore and InMemoryBrandingStore implement it.
type BrandingRevisionStore interface {
	// CreateRevision inserts a new revision and moves the draft pointer (Owner, tenant-scoped). created is
	// false when the input is identical to the current draft (nothing inserted).
	CreateRevision(ctx context.Context, tenantID, createdBy string, in BrandingRevisionInput) (rev *BrandingRevision, created bool, err error)
	OwnerState(ctx context.Context, tenantID string) (*BrandingOwnerState, error)
	Review(ctx context.Context, c PlatformCaller, tenantID string) (*BrandingReview, error)
	Peers(ctx context.Context, c PlatformCaller) ([]BrandPeer, error)
	Approve(ctx context.Context, c PlatformCaller, tenantID string, a BrandingApproval, extra map[string]any) (*BrandingApprovalResult, error)
	Withdraw(ctx context.Context, c PlatformCaller, tenantID string, extra map[string]any) error
	// PublicLookup is THE public read: one fresh authoritative lookup for a normalised host. (nil, nil) = no row
	// (every non-published state). It is bounded by ctx; the Pg implementation runs it under pgbounded.go.
	PublicLookup(ctx context.Context, host string, wantLogo bool) (*PublishedBranding, error)
}

// ---------------------------------------------------------------------------------------------------------
// InMemoryBrandingStore: the DEV/test implementation. It shares the hostname fake's lock and assignment rows.
// ---------------------------------------------------------------------------------------------------------

type memPointer struct {
	draft                                        *BrandingRevision
	publishedRev, publishedHash, publishedAssign string
	publishedAt                                  time.Time
	withdrawnAt                                  time.Time // zero: no withdrawal on record
	withdrawnRev                                 string
	generation                                   int64
}

// InMemoryBrandingStore models migration 0072 over an InMemoryHostnameStore.
type InMemoryBrandingStore struct {
	Hosts *InMemoryHostnameStore

	revs     map[string][]*BrandingRevision // tenant id -> revisions in seq order
	pointers map[string]*memPointer
}

var _ BrandingRevisionStore = (*InMemoryBrandingStore)(nil)

// NewInMemoryBrandingStore wires the fake to its hostname store (assignment changes clear published).
func NewInMemoryBrandingStore(h *InMemoryHostnameStore) *InMemoryBrandingStore {
	s := &InMemoryBrandingStore{Hosts: h, revs: map[string][]*BrandingRevision{}, pointers: map[string]*memPointer{}}
	h.OnReassign = func(tenant string) {
		if p := s.pointers[tenant]; p != nil {
			p.publishedRev, p.publishedHash, p.publishedAssign = "", "", ""
			p.publishedAt, p.withdrawnAt, p.withdrawnRev = time.Time{}, time.Time{}, "" // a new assignment starts clean
		}
		s.ptr(tenant).generation++ // assign, release and reactivate invalidate every prepared review
	}
	return s
}

func (s *InMemoryBrandingStore) ptr(tenant string) *memPointer {
	p := s.pointers[tenant]
	if p == nil {
		p = &memPointer{}
		s.pointers[tenant] = p
	}
	return p
}

func (s *InMemoryBrandingStore) findRev(tenant, id string) *BrandingRevision {
	for _, r := range s.revs[tenant] {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// liveAssignment is the tenant's pending-or-active assignment (at most one).
func (s *InMemoryBrandingStore) liveAssignment(tenant string) *HostnameAssignment {
	for _, a := range s.Hosts.rows {
		if a.TenantID == tenant && a.State != "released" {
			return a
		}
	}
	return nil
}

func refOf(a *HostnameAssignment) *BrandingAssignmentRef {
	if a == nil {
		return nil
	}
	return &BrandingAssignmentRef{ID: a.ID, Host: a.Host, State: a.State}
}

func copyRev(r *BrandingRevision, withLogo bool) *BrandingRevision {
	if r == nil {
		return nil
	}
	c := *r
	if withLogo {
		c.LogoPNG = append([]byte(nil), r.LogoPNG...)
	} else {
		c.LogoPNG = nil
	}
	return &c
}

func (s *InMemoryBrandingStore) CreateRevision(_ context.Context, tenantID, createdBy string, in BrandingRevisionInput) (*BrandingRevision, bool, error) {
	h := s.Hosts
	h.mu.Lock()
	defer h.mu.Unlock()
	p := s.ptr(tenantID)
	logo := in.LogoPNG
	if in.KeepLogo {
		if p.draft == nil || p.draft.LogoSHA256 == "" {
			return nil, false, ErrBrandingNoLogoToKeep
		}
		logo = p.draft.LogoPNG
	}
	sha := logoSHA(logo)
	hash := BrandingRevisionHash(in.ProductName, in.AccentColor, in.SupportText, in.Contact.Kind, in.Contact.Value, sha)
	if p.draft != nil && p.draft.Hash == hash {
		return copyRev(p.draft, false), false, nil
	}
	revs := s.revs[tenantID]
	recent := 0
	for _, r := range revs {
		if h.now().Sub(r.CreatedAt) < time.Hour {
			recent++
		}
	}
	if recent >= BrandingRevisionsPerHour || len(revs) >= BrandingRevisionsMax {
		return nil, false, ErrBrandingRateLimited
	}
	r := &BrandingRevision{ID: newUUID(), TenantID: tenantID, Seq: int64(len(revs)) + 1, ProductName: in.ProductName,
		AccentColor: in.AccentColor, SupportText: in.SupportText, Contact: in.Contact, LogoSHA256: sha, HasLogo: sha != "",
		LogoPNG: append([]byte(nil), logo...), Hash: hash, CreatedBy: createdBy, CreatedAt: h.now()}
	s.revs[tenantID] = append(revs, r)
	p.draft = r
	p.generation++
	return copyRev(r, false), true, nil
}

func (s *InMemoryBrandingStore) OwnerState(_ context.Context, tenantID string) (*BrandingOwnerState, error) {
	h := s.Hosts
	h.mu.Lock()
	defer h.mu.Unlock()
	st := &BrandingOwnerState{}
	p := s.pointers[tenantID]
	a := s.liveAssignment(tenantID)
	st.Assignment = refOf(a)
	if p == nil {
		return st, nil
	}
	st.Draft = copyRev(p.draft, false)
	if p.publishedRev != "" {
		st.Published = copyRev(s.findRev(tenantID, p.publishedRev), false)
		st.Live = a != nil && a.State == "active" && a.ID == p.publishedAssign
		st.DraftIsPublished = p.draft != nil && p.draft.ID == p.publishedRev
		at := p.publishedAt
		st.PublishedAt = &at
	} else if !p.withdrawnAt.IsZero() {
		st.Withdrawn = &BrandingWithdrawn{At: p.withdrawnAt, RevisionID: p.withdrawnRev}
	}
	return st, nil
}

func (s *InMemoryBrandingStore) tenantKnown(id string) bool {
	return s.Hosts.TenantExists == nil || s.Hosts.TenantExists(id)
}

func (s *InMemoryBrandingStore) Review(_ context.Context, c PlatformCaller, tenantID string) (*BrandingReview, error) {
	h := s.Hosts
	if err := h.check(c); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !s.tenantKnown(tenantID) {
		return nil, ErrPlatformNoTenant
	}
	rv := &BrandingReview{TenantID: tenantID, Assignment: refOf(s.liveAssignment(tenantID))}
	if p := s.pointers[tenantID]; p != nil {
		rv.Draft = copyRev(p.draft, true)
		rv.PublishedRevisionID, rv.PublishedHash, rv.PublishedAssignmentID = p.publishedRev, p.publishedHash, p.publishedAssign
		rv.Generation = p.generation
	}
	return rv, nil
}

func (s *InMemoryBrandingStore) Peers(_ context.Context, c PlatformCaller) ([]BrandPeer, error) {
	h := s.Hosts
	if err := h.check(c); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []BrandPeer
	for tenant, p := range s.pointers {
		if p.publishedRev == "" {
			continue
		}
		live := false
		for _, a := range h.rows {
			if a.ID == p.publishedAssign && a.State != "released" {
				live = true
			}
		}
		if r := s.findRev(tenant, p.publishedRev); live && r != nil {
			out = append(out, BrandPeer{TenantID: tenant, ProductName: r.ProductName})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out, nil
}

func (s *InMemoryBrandingStore) Approve(_ context.Context, c PlatformCaller, tenantID string, a BrandingApproval, _ map[string]any) (*BrandingApprovalResult, error) {
	h := s.Hosts
	if err := h.check(c); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !s.tenantKnown(tenantID) {
		return nil, ErrPlatformNoTenant
	}
	p := s.ptr(tenantID)
	live := s.liveAssignment(tenantID)
	rev := s.findRev(tenantID, a.RevisionID)
	if p.draft == nil || p.draft.ID != a.RevisionID || rev == nil || rev.Hash != a.Hash || live == nil || live.ID != a.AssignmentID || p.generation != a.Generation {
		return nil, ErrBrandingStale
	}
	p.publishedRev, p.publishedHash, p.publishedAssign = rev.ID, rev.Hash, live.ID
	p.publishedAt, p.withdrawnAt, p.withdrawnRev = h.now(), time.Time{}, ""
	p.generation++
	h.Audit = append(h.Audit, "platform:platform.branding.approve:"+tenantID, "tenant:"+tenantID+":tenant.branding.approve:"+tenantID)
	return &BrandingApprovalResult{RevisionID: rev.ID, Hash: rev.Hash, AssignmentID: live.ID, Host: live.Host,
		AssignmentState: live.State, ProductName: rev.ProductName}, nil
}

func (s *InMemoryBrandingStore) Withdraw(_ context.Context, c PlatformCaller, tenantID string, _ map[string]any) error {
	h := s.Hosts
	if err := h.check(c); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !s.tenantKnown(tenantID) {
		return ErrPlatformNoTenant
	}
	p := s.ptr(tenantID)
	if p.publishedRev == "" {
		return ErrBrandingNotPublished
	}
	p.withdrawnAt, p.withdrawnRev = h.now(), p.publishedRev
	p.publishedRev, p.publishedHash, p.publishedAssign, p.publishedAt = "", "", "", time.Time{}
	p.generation++
	h.Audit = append(h.Audit, "platform:platform.branding.withdraw:"+tenantID, "tenant:"+tenantID+":tenant.branding.withdraw:"+tenantID)
	return nil
}

// PublicLookup: the active assignment of host, the tenant active, the published triple matching.
func (s *InMemoryBrandingStore) PublicLookup(ctx context.Context, host string, wantLogo bool) (*PublishedBranding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h := s.Hosts
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, a := range h.rows {
		if a.Host != host || a.State != "active" {
			continue
		}
		if h.TenantActive != nil && !h.TenantActive(a.TenantID) {
			return nil, nil
		}
		p := s.pointers[a.TenantID]
		if p == nil || p.publishedAssign != a.ID {
			return nil, nil
		}
		r := s.findRev(a.TenantID, p.publishedRev)
		if r == nil || r.Hash != p.publishedHash {
			return nil, nil
		}
		out := &PublishedBranding{ProductName: r.ProductName, AccentColor: r.AccentColor, SupportText: r.SupportText,
			Contact: r.Contact, LogoSHA256: r.LogoSHA256}
		if wantLogo {
			out.LogoPNG = append([]byte(nil), r.LogoPNG...)
		}
		return out, nil
	}
	return nil, nil
}
