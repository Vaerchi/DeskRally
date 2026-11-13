package controlplane

// ONE contract suite for branding revisions, operator approval and publication (docs/66 2a.3, 2b.2, 2c.2),
// run against the in-memory fake and against Postgres (migration 0072): the "fake and pg must agree" rule.

import (
	"context"
	"encoding/json"
	"errors"
	"image/color"
	"strings"
	"testing"
	"time"
)

type brandContractFx struct {
	hosts  HostnameStore
	brand  BrandingRevisionStore
	caller PlatformCaller
	// nonOp is a caller the database (or the fake's Authorize) refuses.
	nonOp PlatformCaller
	// tenant makes a fresh tenant and returns its id.
	tenant  func(name string) string
	suspend func(tenant string, on bool)
	age     func(host string, d time.Duration)
	// auditCount counts audit rows: chain is "platform" or "tenant:<id>", prefix e.g. "branding.approve".
	auditCount func(chain, prefix string) int
}

func brandInput(name string) BrandingRevisionInput {
	return BrandingRevisionInput{ProductName: name, AccentColor: "#35654a", SupportText: "Open 9 to 5",
		Contact: BrandContact{Kind: "phone", Value: "15550100199"}}
}

func tinyLogo(t testing.TB, r uint8) []byte {
	t.Helper()
	out, err := ConvertLogo(solidPNG(t, 40, 20, color.NRGBA{R: r, G: 90, B: 60, A: 255}))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (fx *brandContractFx) draft(t *testing.T, tenant, name string) *BrandingRevision {
	t.Helper()
	r, created, err := fx.brand.CreateRevision(context.Background(), tenant, "owner-"+tenant, brandInput(name))
	if err != nil || !created {
		t.Fatalf("create revision %q: created=%v err=%v", name, created, err)
	}
	return r
}

// ba builds an approval request carrying the tenant's CURRENT review generation, so a refusal in a test is
// about the field the test changed and never about a stale generation.
func (fx *brandContractFx) ba(tenant, revID, hash, asgID string) BrandingApproval {
	rv, err := fx.brand.Review(context.Background(), fx.caller, tenant)
	if err != nil {
		panic(err)
	}
	return BrandingApproval{RevisionID: revID, Hash: hash, AssignmentID: asgID, Generation: rv.Generation}
}

func (fx *brandContractFx) approve(tenant string, rev *BrandingRevision, asgID string) (*BrandingApprovalResult, error) {
	return fx.brand.Approve(context.Background(), fx.caller, tenant,
		fx.ba(tenant, rev.ID, rev.Hash, asgID), map[string]any{"override_reason": "test"})
}

func (fx *brandContractFx) public(t *testing.T, host string, logo bool) *PublishedBranding {
	t.Helper()
	p, err := fx.brand.PublicLookup(context.Background(), host, logo)
	if err != nil {
		t.Fatalf("public lookup %s: %v", host, err)
	}
	return p
}

func (fx *brandContractFx) wantPublic(t *testing.T, what, host, wantName string) {
	t.Helper()
	p := fx.public(t, host, false)
	switch {
	case wantName == "" && p != nil:
		t.Fatalf("%s: %s publishes %q, want the neutral outcome", what, host, p.ProductName)
	case wantName != "" && (p == nil || p.ProductName != wantName):
		t.Fatalf("%s: %s publishes %+v, want %q", what, host, p, wantName)
	}
}

func runBrandContract(t *testing.T, fx *brandContractFx) {
	ctx := context.Background()
	t.Run("revisions are immutable, append-only and idempotent", func(t *testing.T) {
		a := fx.tenant("rev")
		r1 := fx.draft(t, a, "Acme One")
		if r1.Seq != 1 || len(r1.Hash) != 64 || r1.LogoSHA256 != "" || r1.HasLogo {
			t.Fatalf("first revision: %+v", r1)
		}
		same, created, err := fx.brand.CreateRevision(ctx, a, "owner", brandInput("Acme One"))
		if err != nil || created || same.ID != r1.ID {
			t.Fatalf("identical edit must be a no-op: created=%v id=%s err=%v", created, same.ID, err)
		}
		r2 := fx.draft(t, a, "Acme Two")
		if r2.Seq != 2 || r2.ID == r1.ID || r2.Hash == r1.Hash {
			t.Fatalf("second revision: %+v", r2)
		}
		// Changing ONLY the accent is an edit too (docs/66 2a.3).
		in := brandInput("Acme Two")
		in.AccentColor = "#1f4d36"
		if r3, created, err := fx.brand.CreateRevision(ctx, a, "owner", in); err != nil || !created || r3.Seq != 3 {
			t.Fatalf("accent-only edit: %+v %v %v", r3, created, err)
		}
		st, err := fx.brand.OwnerState(ctx, a)
		if err != nil || st.Draft == nil || st.Draft.Seq != 3 || st.Published != nil || st.Live || st.Assignment != nil {
			t.Fatalf("owner state: %+v %v", st, err)
		}
		// Another tenant sees nothing of it.
		b := fx.tenant("rev-other")
		if st, _ := fx.brand.OwnerState(ctx, b); st.Draft != nil {
			t.Fatalf("tenant B sees A's draft: %+v", st)
		}
	})

	t.Run("logo bytes, keep_logo and the lookup's logo switch", func(t *testing.T) {
		a := fx.tenant("logo")
		in := brandInput("Logo Co")
		in.LogoPNG = tinyLogo(t, 10)
		r1, _, err := fx.brand.CreateRevision(ctx, a, "o", in)
		if err != nil || !r1.HasLogo || r1.LogoSHA256 != logoSHA(in.LogoPNG) {
			t.Fatalf("logo revision: %+v %v", r1, err)
		}
		keep := brandInput("Logo Co Two")
		keep.KeepLogo = true
		r2, created, err := fx.brand.CreateRevision(ctx, a, "o", keep)
		if err != nil || !created || r2.LogoSHA256 != r1.LogoSHA256 {
			t.Fatalf("keep_logo: %+v %v %v", r2, created, err)
		}
		rv, err := fx.brand.Review(ctx, fx.caller, a)
		if err != nil || rv.Draft == nil || string(rv.Draft.LogoPNG) != string(in.LogoPNG) {
			t.Fatalf("the operator's review must carry the exact logo bytes: %v", err)
		}
		fresh := fx.tenant("logo-none")
		if _, _, err := fx.brand.CreateRevision(ctx, fresh, "o", keep); !errors.Is(err, ErrBrandingNoLogoToKeep) {
			t.Fatalf("keep_logo with no logo: %v", err)
		}
		nologo := fx.draft(t, fresh, "Plain Co")
		keep2 := brandInput("Plain Co Two")
		keep2.KeepLogo = true
		if _, _, err := fx.brand.CreateRevision(ctx, fresh, "o", keep2); !errors.Is(err, ErrBrandingNoLogoToKeep) {
			t.Fatalf("keep_logo on a logo-less draft (%s): %v", nologo.ID, err)
		}

		asg := fx.activeHost(t, a, "logo-co.example.test")
		if _, err := fx.approve(a, r2, asg.ID); err != nil {
			t.Fatal(err)
		}
		p := fx.public(t, asg.Host, false)
		if p == nil || p.LogoSHA256 != r1.LogoSHA256 || p.LogoPNG != nil {
			t.Fatalf("json lookup: %+v (no bytes expected)", p)
		}
		p = fx.public(t, asg.Host, true)
		if p == nil || string(p.LogoPNG) != string(in.LogoPNG) {
			t.Fatalf("logo lookup bytes differ")
		}
	})

	t.Run("approve while pending binds that assignment; activation publishes without a second approval", func(t *testing.T) {
		a := fx.tenant("pend")
		host := "pend-co.example.test"
		asg := fx.mustAssignHost(t, a, host)
		rev := fx.draft(t, a, "Pending Co")
		if _, err := fx.approve(a, rev, asg.ID); err != nil {
			t.Fatalf("approve against a pending assignment: %v", err)
		}
		fx.wantPublic(t, "pending", host, "")
		if _, err := fx.hosts.Activate(ctx, fx.caller, asg.ID, nil); err != nil {
			t.Fatal(err)
		}
		fx.wantPublic(t, "activated, same id", host, "Pending Co")
		st, _ := fx.brand.OwnerState(ctx, a)
		if !st.Live || st.Assignment == nil || st.Assignment.ID != asg.ID {
			t.Fatalf("owner state: %+v", st)
		}
	})

	t.Run("an edit keeps the approved revision published; the next approval replaces it", func(t *testing.T) {
		a := fx.tenant("keep")
		asg := fx.activeHost(t, a, "keep-co.example.test")
		r1 := fx.draft(t, a, "Keep One")
		if _, err := fx.approve(a, r1, asg.ID); err != nil {
			t.Fatal(err)
		}
		fx.wantPublic(t, "approved r1", asg.Host, "Keep One")
		r2 := fx.draft(t, a, "Keep Two")
		fx.wantPublic(t, "edited to r2, r1 still published", asg.Host, "Keep One")
		if st, _ := fx.brand.OwnerState(ctx, a); st.Draft.ID != r2.ID || st.Published.ID != r1.ID || !st.Live || st.DraftIsPublished {
			t.Fatalf("owner state after edit: %+v", st)
		}
		// The operator reviewed r1: it is no longer the draft, so approving it is stale (nothing changes).
		if _, err := fx.approve(a, r1, asg.ID); !errors.Is(err, ErrBrandingStale) {
			t.Fatalf("approve of a superseded revision: %v", err)
		}
		fx.wantPublic(t, "after the refused approval", asg.Host, "Keep One")
		if _, err := fx.approve(a, r2, asg.ID); err != nil {
			t.Fatal(err)
		}
		fx.wantPublic(t, "approved r2", asg.Host, "Keep Two")
	})

	t.Run("stale approvals: hash, assignment, tenant and revision id each fail", func(t *testing.T) {
		a, b := fx.tenant("stale-a"), fx.tenant("stale-b")
		asgA := fx.activeHost(t, a, "stale-a.example.test")
		asgB := fx.activeHost(t, b, "stale-b.example.test")
		revA := fx.draft(t, a, "Stale A")
		revB := fx.draft(t, b, "Stale B")
		bad := []struct {
			what   string
			tenant string
			ap     BrandingApproval
		}{
			{"wrong hash", a, fx.ba(a, revA.ID, revB.Hash, asgA.ID)},
			{"another tenant's assignment id", a, fx.ba(a, revA.ID, revA.Hash, asgB.ID)},
			{"another tenant's revision", a, fx.ba(a, revB.ID, revB.Hash, asgA.ID)},
			{"a revision approved on the other tenant's path", b, fx.ba(b, revA.ID, revA.Hash, asgB.ID)},
			{"unknown revision", a, fx.ba(a, newUUID(), revA.Hash, asgA.ID)},
			{"unknown assignment", a, fx.ba(a, revA.ID, revA.Hash, newUUID())},
		}
		for _, c := range bad {
			if _, err := fx.brand.Approve(ctx, fx.caller, c.tenant, c.ap, nil); !errors.Is(err, ErrBrandingStale) {
				t.Errorf("%s: %v, want a stale refusal", c.what, err)
			}
		}
		fx.wantPublic(t, "after six refusals", asgA.Host, "")
		fx.wantPublic(t, "after six refusals (b)", asgB.Host, "")
		// A tenant with NO assignment cannot be approved at all.
		c := fx.tenant("stale-none")
		revC := fx.draft(t, c, "No Host")
		if _, err := fx.brand.Approve(ctx, fx.caller, c, fx.ba(c, revC.ID, revC.Hash, newUUID()), nil); !errors.Is(err, ErrBrandingStale) {
			t.Errorf("approve without an assignment: %v", err)
		}
	})

	t.Run("release then reactivate: the old approval does not publish again until re-approved", func(t *testing.T) {
		a := fx.tenant("react")
		asg := fx.activeHost(t, a, "react-co.example.test")
		rev := fx.draft(t, a, "React Co")
		if _, err := fx.approve(a, rev, asg.ID); err != nil {
			t.Fatal(err)
		}
		fx.wantPublic(t, "approved", asg.Host, "React Co")
		if _, err := fx.hosts.Release(ctx, fx.caller, asg.ID, 30, map[string]any{"reason": "t"}); err != nil {
			t.Fatal(err)
		}
		fx.wantPublic(t, "released", asg.Host, "")
		if st, _ := fx.brand.OwnerState(ctx, a); st.Published != nil || st.Live {
			t.Fatalf("a release must clear the published pointer: %+v", st)
		}
		again, err := fx.hosts.Reactivate(ctx, fx.caller, asg.ID, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if again.ID == asg.ID {
			t.Fatal("reactivation must create a NEW assignment id")
		}
		fx.wantPublic(t, "reactivated, not re-approved", asg.Host, "")
		if _, err := fx.approve(a, rev, asg.ID); !errors.Is(err, ErrBrandingStale) {
			t.Fatalf("approval against the dead assignment id: %v", err)
		}
		if _, err := fx.approve(a, rev, again.ID); err != nil {
			t.Fatalf("approval against the new id: %v", err)
		}
		fx.wantPublic(t, "re-approved", asg.Host, "React Co")
	})

	t.Run("approve while pending, then release and recreate: neutral until re-approved", func(t *testing.T) {
		a := fx.tenant("recreate")
		host := "recreate.example.test"
		asg := fx.mustAssignHost(t, a, host)
		rev := fx.draft(t, a, "Recreate Co")
		if _, err := fx.approve(a, rev, asg.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := fx.hosts.Release(ctx, fx.caller, asg.ID, 30, map[string]any{"reason": "t"}); err != nil {
			t.Fatal(err)
		}
		nu := fx.mustAssignHost(t, a, host) // same tenant: not quarantined against itself
		if _, err := fx.hosts.Activate(ctx, fx.caller, nu.ID, nil); err != nil {
			t.Fatal(err)
		}
		fx.wantPublic(t, "recreated and activated", host, "")
		if _, err := fx.approve(a, rev, nu.ID); err != nil {
			t.Fatal(err)
		}
		fx.wantPublic(t, "re-approved", host, "Recreate Co")
	})

	t.Run("reassignment to another tenant: neither tenant publishes the other's pointer", func(t *testing.T) {
		a, b := fx.tenant("move-a"), fx.tenant("move-b")
		host := "move.example.test"
		asgA := fx.activeHost(t, a, host)
		revA := fx.draft(t, a, "Move A")
		if _, err := fx.approve(a, revA, asgA.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := fx.hosts.Release(ctx, fx.caller, asgA.ID, 30, map[string]any{"reason": "t"}); err != nil {
			t.Fatal(err)
		}
		if _, err := fx.hosts.Assign(ctx, fx.caller, b, host, nil); !errors.Is(err, ErrHostnameQuarantined) {
			t.Fatalf("quarantine: %v", err)
		}
		fx.age(host, 31*24*time.Hour)
		asgB := fx.activeHost(t, b, host)
		fx.wantPublic(t, "new owner, nothing approved", host, "")
		revB := fx.draft(t, b, "Move B")
		if _, err := fx.approve(a, revA, asgB.ID); !errors.Is(err, ErrBrandingStale) {
			t.Fatalf("A approving against B's assignment: %v", err)
		}
		if _, err := fx.approve(b, revB, asgB.ID); err != nil {
			t.Fatal(err)
		}
		fx.wantPublic(t, "B approved", host, "Move B")
		if st, _ := fx.brand.OwnerState(ctx, a); st.Published != nil || st.Live {
			t.Fatalf("the previous owner still shows a published revision: %+v", st)
		}
	})

	t.Run("explicit withdrawal neutralises at once; a second withdrawal is refused", func(t *testing.T) {
		a := fx.tenant("wd")
		asg := fx.activeHost(t, a, "wd-co.example.test")
		rev := fx.draft(t, a, "Withdraw Co")
		if _, err := fx.approve(a, rev, asg.ID); err != nil {
			t.Fatal(err)
		}
		fx.wantPublic(t, "approved", asg.Host, "Withdraw Co")
		if err := fx.brand.Withdraw(ctx, fx.caller, a, map[string]any{"reason": "complaint"}); err != nil {
			t.Fatal(err)
		}
		fx.wantPublic(t, "withdrawn", asg.Host, "")
		if err := fx.brand.Withdraw(ctx, fx.caller, a, nil); !errors.Is(err, ErrBrandingNotPublished) {
			t.Fatalf("second withdrawal: %v", err)
		}
		// The draft survives a withdrawal: the same reviewed revision can be approved again.
		if _, err := fx.approve(a, rev, asg.ID); err != nil {
			t.Fatalf("re-approve after withdrawal: %v", err)
		}
		fx.wantPublic(t, "re-approved", asg.Host, "Withdraw Co")
	})

	t.Run("the Owner state says when it was approved and tells withdrawn from never approved", func(t *testing.T) {
		a := fx.tenant("ownerstate")
		asg := fx.activeHost(t, a, "ownerstate-co.example.test")
		within := func(what string, got *time.Time, lo, hi time.Time) {
			t.Helper()
			if got == nil || got.Before(lo.Add(-time.Minute)) || got.After(hi.Add(time.Minute)) {
				t.Fatalf("%s: %v is not between %v and %v", what, got, lo, hi)
			}
		}
		state := func() *BrandingOwnerState {
			t.Helper()
			st, err := fx.brand.OwnerState(ctx, a)
			if err != nil {
				t.Fatal(err)
			}
			return st
		}
		// nothing at all, then a draft that was never approved: neither fact is present
		if st := state(); st.PublishedAt != nil || st.Withdrawn != nil {
			t.Fatalf("fresh tenant: %+v", st)
		}
		rev := fx.draft(t, a, "Owner State")
		if st := state(); st.PublishedAt != nil || st.Withdrawn != nil || st.Published != nil {
			t.Fatalf("never approved: %+v", st)
		}
		before := time.Now()
		if _, err := fx.approve(a, rev, asg.ID); err != nil {
			t.Fatal(err)
		}
		after := time.Now()
		st := state()
		within("published_at", st.PublishedAt, before, after)
		if st.Withdrawn != nil {
			t.Fatalf("approved but reported withdrawn: %+v", st)
		}
		// an edit keeps the approval time of the revision that is still live
		fx.draft(t, a, "Owner State Two")
		if st2 := state(); st2.PublishedAt == nil || !st2.PublishedAt.Equal(*st.PublishedAt) {
			t.Fatalf("an edit moved published_at: %v -> %v", st.PublishedAt, st2.PublishedAt)
		}
		before = time.Now()
		if err := fx.brand.Withdraw(ctx, fx.caller, a, map[string]any{"reason": "secret operator reason"}); err != nil {
			t.Fatal(err)
		}
		after = time.Now()
		st = state()
		if st.PublishedAt != nil || st.Published != nil || st.Withdrawn == nil {
			t.Fatalf("withdrawn: %+v", st)
		}
		within("withdrawn.at", &st.Withdrawn.At, before, after)
		if st.Withdrawn.RevisionID != rev.ID {
			t.Fatalf("withdrawn revision %q, want the published one %q", st.Withdrawn.RevisionID, rev.ID)
		}
		// the tenant sees neither the operator nor the reason
		raw, _ := json.Marshal(st)
		for _, leak := range []string{"secret operator reason", fx.caller.Email, fx.caller.UserID, "published_by"} {
			if leak != "" && strings.Contains(string(raw), leak) {
				t.Fatalf("owner state leaks %q: %s", leak, raw)
			}
		}
		// a new approval supersedes the withdrawal
		draft := state().Draft
		if _, err := fx.approve(a, draft, asg.ID); err != nil {
			t.Fatal(err)
		}
		if st := state(); st.Withdrawn != nil || st.PublishedAt == nil {
			t.Fatalf("re-approved: %+v", st)
		}
		// a withdrawal, then a release: a new hostname starts as never approved
		if err := fx.brand.Withdraw(ctx, fx.caller, a, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := fx.hosts.Release(ctx, fx.caller, asg.ID, 30, map[string]any{"reason": "t"}); err != nil {
			t.Fatal(err)
		}
		if st := state(); st.Withdrawn != nil || st.PublishedAt != nil {
			t.Fatalf("after a hostname change: %+v", st)
		}
		// an approval cleared by a hostname change is NOT a withdrawal
		nu := fx.activeHost(t, a, "ownerstate-two.example.test")
		if _, err := fx.approve(a, state().Draft, nu.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := fx.hosts.Release(ctx, fx.caller, nu.ID, 30, map[string]any{"reason": "t"}); err != nil {
			t.Fatal(err)
		}
		if st := state(); st.Withdrawn != nil || st.PublishedAt != nil || st.Published != nil {
			t.Fatalf("a release reported as a withdrawal: %+v", st)
		}
	})

	t.Run("a suspended tenant publishes nothing and resumes cleanly", func(t *testing.T) {
		a := fx.tenant("susp")
		asg := fx.activeHost(t, a, "susp-co.example.test")
		rev := fx.draft(t, a, "Suspend Co")
		if _, err := fx.approve(a, rev, asg.ID); err != nil {
			t.Fatal(err)
		}
		fx.suspend(a, true)
		fx.wantPublic(t, "suspended", asg.Host, "")
		fx.suspend(a, false)
		fx.wantPublic(t, "resumed", asg.Host, "Suspend Co")
	})

	t.Run("an unknown host and a host of another tenant publish nothing", func(t *testing.T) {
		fx.wantPublic(t, "never assigned", "nobody-home.example.test", "")
		a := fx.tenant("only")
		asg := fx.activeHost(t, a, "only-co.example.test")
		rev := fx.draft(t, a, "Only Co")
		_, _ = fx.approve(a, rev, asg.ID)
		fx.wantPublic(t, "sibling host", "only-co2.example.test", "")
	})

	t.Run("peers list published names only", func(t *testing.T) {
		a := fx.tenant("peer")
		asg := fx.activeHost(t, a, "peer-co.example.test")
		rev := fx.draft(t, a, "Peer Co")
		peers, err := fx.brand.Peers(ctx, fx.caller)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range peers {
			if p.ProductName == "Peer Co" {
				t.Fatalf("an unapproved draft is listed as a peer")
			}
		}
		if _, err := fx.approve(a, rev, asg.ID); err != nil {
			t.Fatal(err)
		}
		peers, _ = fx.brand.Peers(ctx, fx.caller)
		found := false
		for _, p := range peers {
			found = found || (p.TenantID == a && p.ProductName == "Peer Co")
		}
		if !found {
			t.Fatalf("published name missing from peers: %+v", peers)
		}
	})

	t.Run("operator authorisation is required for review, approve, withdraw and peers", func(t *testing.T) {
		a := fx.tenant("auth")
		asg := fx.activeHost(t, a, "auth-co.example.test")
		rev := fx.draft(t, a, "Auth Co")
		if _, err := fx.brand.Review(ctx, fx.nonOp, a); !errors.Is(err, ErrPlatformDenied) {
			t.Errorf("review: %v", err)
		}
		if _, err := fx.brand.Approve(ctx, fx.nonOp, a, fx.ba(a, rev.ID, rev.Hash, asg.ID), nil); !errors.Is(err, ErrPlatformDenied) {
			t.Errorf("approve: %v", err)
		}
		if err := fx.brand.Withdraw(ctx, fx.nonOp, a, nil); !errors.Is(err, ErrPlatformDenied) {
			t.Errorf("withdraw: %v", err)
		}
		if _, err := fx.brand.Peers(ctx, fx.nonOp); !errors.Is(err, ErrPlatformDenied) {
			t.Errorf("peers: %v", err)
		}
		fx.wantPublic(t, "after the refusals", asg.Host, "")
	})

	t.Run("approve and withdraw are audited on both chains; a refusal writes nothing", func(t *testing.T) {
		a := fx.tenant("audit")
		asg := fx.activeHost(t, a, "audit-co.example.test")
		rev := fx.draft(t, a, "Audit Co")
		counts := func(action string) (int, int) { return fx.auditCount("platform", action), fx.auditCount(a, action) }
		p0, t0 := counts("approve")
		if _, err := fx.brand.Approve(ctx, fx.caller, a, fx.ba(a, rev.ID, rev.Hash, newUUID()), nil); !errors.Is(err, ErrBrandingStale) {
			t.Fatal(err)
		}
		if p, tt := counts("approve"); p != p0 || tt != t0 {
			t.Fatalf("a stale approval wrote audit rows: platform %d->%d tenant %d->%d", p0, p, t0, tt)
		}
		if _, err := fx.approve(a, rev, asg.ID); err != nil {
			t.Fatal(err)
		}
		if p, tt := counts("approve"); p != p0+1 || tt != t0+1 {
			t.Fatalf("approve audit: platform %d->%d tenant %d->%d", p0, p, t0, tt)
		}
		w0p, w0t := counts("withdraw")
		if err := fx.brand.Withdraw(ctx, fx.caller, a, map[string]any{"reason": "x"}); err != nil {
			t.Fatal(err)
		}
		if p, tt := counts("withdraw"); p != w0p+1 || tt != w0t+1 {
			t.Fatalf("withdraw audit: platform %d->%d tenant %d->%d", w0p, p, w0t, tt)
		}
		if err := fx.brand.Withdraw(ctx, fx.caller, a, nil); !errors.Is(err, ErrBrandingNotPublished) {
			t.Fatal(err)
		}
		if p, tt := counts("withdraw"); p != w0p+1 || tt != w0t+1 {
			t.Fatalf("a refused withdrawal wrote audit rows")
		}
	})

	t.Run("a withdrawal invalidates an approval prepared before it (review generation)", func(t *testing.T) {
		a := fx.tenant("gen")
		asg := fx.activeHost(t, a, "gen-co.example.test")
		rev := fx.draft(t, a, "Generation Co")
		if _, err := fx.approve(a, rev, asg.ID); err != nil {
			t.Fatal(err)
		}
		// Operator B loads the review and PREPARES an approval of exactly the stored draft, hash and assignment.
		rv, err := fx.brand.Review(ctx, fx.caller, a)
		if err != nil {
			t.Fatal(err)
		}
		prepared := BrandingApproval{RevisionID: rv.Draft.ID, Hash: rv.Draft.Hash, AssignmentID: rv.Assignment.ID, Generation: rv.Generation}
		// Operator A withdraws the brand first.
		if err := fx.brand.Withdraw(ctx, fx.caller, a, map[string]any{"reason": "complaint"}); err != nil {
			t.Fatal(err)
		}
		fx.wantPublic(t, "withdrawn", asg.Host, "")
		// Every predicate of the old compare-and-swap still holds (same draft, same hash, same live assignment); only
		// the generation says the review is dead.
		if _, err := fx.brand.Approve(ctx, fx.caller, a, prepared, nil); !errors.Is(err, ErrBrandingStale) {
			t.Fatalf("an approval prepared before the withdrawal: %v, want stale", err)
		}
		fx.wantPublic(t, "after the stale approval", asg.Host, "")
		// A FRESH review carries the new generation and approves normally.
		if _, err := fx.approve(a, rev, asg.ID); err != nil {
			t.Fatalf("fresh review after the withdrawal: %v", err)
		}
		// One review, one approval: replaying the same request is stale too.
		if _, err := fx.brand.Approve(ctx, fx.caller, a, prepared, nil); !errors.Is(err, ErrBrandingStale) {
			t.Fatalf("replayed approval: %v", err)
		}
	})

	t.Run("the hourly revision budget", func(t *testing.T) {
		a := fx.tenant("budget")
		for i := 0; i < BrandingRevisionsPerHour; i++ {
			fx.draft(t, a, "Budget "+string(rune('A'+i)))
		}
		if _, _, err := fx.brand.CreateRevision(ctx, a, "o", brandInput("One Too Many")); !errors.Is(err, ErrBrandingRateLimited) {
			t.Fatalf("revision %d: %v", BrandingRevisionsPerHour+1, err)
		}
		// An identical resubmission is still a no-op, not a refusal.
		if _, created, err := fx.brand.CreateRevision(ctx, a, "o", brandInput("Budget "+string(rune('A'+BrandingRevisionsPerHour-1)))); err != nil || created {
			t.Fatalf("idempotent resubmission over the budget: created=%v err=%v", created, err)
		}
	})
}

// activeHost assigns and activates host for the tenant.
func (fx *brandContractFx) activeHost(t *testing.T, tenant, host string) *HostnameAssignment {
	t.Helper()
	a := fx.mustAssignHost(t, tenant, host)
	act, err := fx.hosts.Activate(context.Background(), fx.caller, a.ID, nil)
	if err != nil {
		t.Fatalf("activate %s: %v", host, err)
	}
	return act
}

func (fx *brandContractFx) mustAssignHost(t *testing.T, tenant, host string) *HostnameAssignment {
	t.Helper()
	a, err := fx.hosts.Assign(context.Background(), fx.caller, tenant, host, nil)
	if err != nil {
		t.Fatalf("assign %s: %v", host, err)
	}
	return a
}

func newFakeBrandFx(t *testing.T) *brandContractFx {
	t.Helper()
	hosts := &InMemoryHostnameStore{}
	op := PlatformCaller{UserID: newUUID(), TenantID: newUUID(), SessionID: newUUID(), Email: "op@test"}
	hosts.Authorize = func(c PlatformCaller) bool { return c.UserID == op.UserID }
	suspended := map[string]bool{}
	hosts.TenantActive = func(id string) bool { return !suspended[id] }
	// The tenant-active hook and the suspension map are read under the hostname store's lock.
	return &brandContractFx{
		hosts:   hosts,
		brand:   NewInMemoryBrandingStore(hosts),
		caller:  op,
		nonOp:   PlatformCaller{UserID: newUUID(), TenantID: op.TenantID, SessionID: newUUID()},
		tenant:  func(string) string { return newUUID() },
		suspend: func(tn string, on bool) { hosts.mu.Lock(); suspended[tn] = on; hosts.mu.Unlock() },
		age:     hosts.AgeReleased,
		auditCount: func(chain, prefix string) int {
			hosts.mu.Lock()
			defer hosts.mu.Unlock()
			n := 0
			for _, l := range hosts.Audit {
				if (chain == "platform" && len(l) > 9 && l[:9] == "platform:" && strings.Contains(l, ".branding."+prefix)) ||
					(chain != "platform" && strings.Contains(l, chain) && strings.Contains(l, ".branding."+prefix) && l[:7] == "tenant:") {
					n++
				}
			}
			return n
		},
	}
}

func TestBrandContractInMemory(t *testing.T) {
	runBrandContract(t, newFakeBrandFx(t))
}
