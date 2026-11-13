package controlplane

// Migration 0072 against a live PostgreSQL: the shared contract suite, then everything only the database can
// prove: the composite-foreign-key ownership of the pointer, immutability, what the application role may NOT
// write, and both orderings of every serialised pair on two real connections (docs/66 2b.2).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type pgBrandFx struct {
	*brandContractFx
	h *pgHostFx
}

func newPgBrandFx(t *testing.T) *pgBrandFx {
	t.Helper()
	h := newPgHostFx(t)
	applyMigrationFile(t, h.pf.su, "migrations/0072_branding_publication.sql")
	applyMigrationFile(t, h.pf.su, "migrations/0075_branding_withdrawn.sql")
	brand := NewPgBrandingRevisionStore(h.pf.app, h.pf.audit)
	pf := h.pf
	fx := &brandContractFx{
		hosts:   h.hostsPg,
		brand:   brand,
		caller:  pf.caller(pf.op, pf.opSession),
		nonOp:   pf.caller(pf.nonOp, newSession(t, pf.su, pf.platform, pf.nonOp, "now()", 0)),
		tenant:  h.hostContractFx.tenant,
		suspend: h.hostContractFx.suspend,
		age:     h.hostContractFx.age,
		auditCount: func(chain, prefix string) int {
			tenant, action := chain, "tenant.branding."+prefix
			if chain == "platform" {
				tenant, action = pf.platform, "platform.branding."+prefix
			}
			var n int
			if err := pf.su.QueryRow(context.Background(), `SELECT count(*) FROM audit_event WHERE tenant_id = $1 AND action = $2`,
				tenant, action).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		},
	}
	return &pgBrandFx{brandContractFx: fx, h: h}
}

func TestBrandContractPg(t *testing.T) {
	fx := newPgBrandFx(t)
	runBrandContract(t, fx.brandContractFx)
	verifyChain(t, fx.h.pf.audit, fx.h.pf.platform)
}

// The pointer can never reference another tenant's revision, even by direct SQL as the table owner; the
// published HASH must be the hash of the revision it names; revisions cannot be updated; the logo hash must be
// the SHA-256 of the bytes.
func TestPgBrandingOwnershipAndImmutabilityHoldAgainstDirectSQL(t *testing.T) {
	fx := newPgBrandFx(t)
	ctx := context.Background()
	su := fx.h.pf.su
	a, b := fx.tenant("own-a"), fx.tenant("own-b")
	asgA := fx.activeHost(t, a, "own-a.example.test")
	revA := fx.draft(t, a, "Own A")
	revB := fx.draft(t, b, "Own B")

	// (5) a cross-tenant draft pointer is refused by the composite FK.
	_, err := su.Exec(ctx, `UPDATE tenant_branding_pointer SET draft_revision_id = $2 WHERE tenant_id = $1`, a, revB.ID)
	if pgCode(err) != "23503" {
		t.Errorf("cross-tenant draft pointer: %v (want a foreign key violation)", err)
	}
	// ... and so is a cross-tenant PUBLISHED pointer.
	_, err = su.Exec(ctx, `UPDATE tenant_branding_pointer SET published_revision_id = $2, published_revision_hash = $3,
		published_assignment_id = $4, published_by = 'x', published_at = now() WHERE tenant_id = $1`, a, revB.ID, revB.Hash, asgA.ID)
	if pgCode(err) != "23503" {
		t.Errorf("cross-tenant published pointer: %v", err)
	}
	// The published HASH must be the revision's.
	_, err = su.Exec(ctx, `UPDATE tenant_branding_pointer SET published_revision_id = $2, published_revision_hash = $3,
		published_assignment_id = $4, published_by = 'x', published_at = now() WHERE tenant_id = $1`, a, revA.ID, revB.Hash, asgA.ID)
	if pgCode(err) != "23503" {
		t.Errorf("published hash that is not the revision's: %v", err)
	}
	// A cross-tenant assignment id is refused too.
	asgB := fx.activeHost(t, b, "own-b.example.test")
	_, err = su.Exec(ctx, `UPDATE tenant_branding_pointer SET published_revision_id = $2, published_revision_hash = $3,
		published_assignment_id = $4, published_by = 'x', published_at = now() WHERE tenant_id = $1`, a, revA.ID, revA.Hash, asgB.ID)
	if pgCode(err) != "23503" {
		t.Errorf("cross-tenant assignment on the pointer: %v", err)
	}
	// All-or-none: a half-set published triple is refused.
	_, err = su.Exec(ctx, `UPDATE tenant_branding_pointer SET published_revision_id = $2 WHERE tenant_id = $1`, a, revA.ID)
	if pgCode(err) != "23514" {
		t.Errorf("half a published triple: %v", err)
	}
	// Revisions are immutable.
	for _, upd := range []string{`UPDATE tenant_branding_revision SET product_name = 'Evil' WHERE id = $1`,
		`UPDATE tenant_branding_revision SET normalized_hash = repeat('0', 64) WHERE id = $1`} {
		if _, err := su.Exec(ctx, upd, revA.ID); pgCode(err) != "23514" {
			t.Errorf("%s: %v", upd, err)
		}
	}
	// The logo hash must match the bytes.
	_, err = su.Exec(ctx, `INSERT INTO tenant_branding_revision (tenant_id, seq, product_name, logo_sha256, logo_png, normalized_hash, created_by)
		VALUES ($1, 99, 'Bad Logo', repeat('a', 64), '\x89504e47'::bytea, repeat('b', 64), 'x')`, a)
	if pgCode(err) != "23514" {
		t.Errorf("logo hash that is not sha256(bytes): %v", err)
	}
	// Control: the honest approval still works afterwards.
	if _, err := fx.approve(a, revA, asgA.ID); err != nil {
		t.Fatal(err)
	}
}

// What the application role may and may not write: it can move the DRAFT pointer and insert revisions for its own
// tenant; it can NOT write the published columns, update or delete a revision, or write another tenant's rows.
func TestPgApplicationRoleCannotPublishOrTamper(t *testing.T) {
	fx := newPgBrandFx(t)
	ctx := context.Background()
	a, b := fx.tenant("role-a"), fx.tenant("role-b")
	asgA := fx.activeHost(t, a, "role-a.example.test")
	revA := fx.draft(t, a, "Role A")
	revB := fx.draft(t, b, "Role B")
	app := fx.h.pf.app

	inTenant := func(tenant string, sql string, args ...any) error {
		return withTenant(ctx, app, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
	}
	denied := func(what string, err error) {
		t.Helper()
		if code := pgCode(err); code != "42501" && code != "23514" && code != "23503" {
			t.Errorf("%s: %v (want a permission or integrity refusal)", what, err)
		}
	}
	denied("publish by the application role", inTenant(a, `UPDATE tenant_branding_pointer SET published_revision_id = $2,
		published_revision_hash = $3, published_assignment_id = $4, published_by = 'owner', published_at = now() WHERE tenant_id = $1`,
		a, revA.ID, revA.Hash, asgA.ID))
	denied("update of a revision", inTenant(a, `UPDATE tenant_branding_revision SET product_name = 'X' WHERE id = $1`, revA.ID))
	denied("delete of a revision", inTenant(a, `DELETE FROM tenant_branding_revision WHERE id = $1`, revA.ID))
	denied("delete of a pointer", inTenant(a, `DELETE FROM tenant_branding_pointer WHERE tenant_id = $1`, a))
	denied("write to an assignment", inTenant(a, `UPDATE tenant_hostname_assignment SET state = 'released' WHERE id = $1`, asgA.ID))
	// Cross-tenant: A's session cannot point A's draft at B's revision (composite FK), cannot insert as B, and
	// cannot even see B's rows.
	denied("cross-tenant draft", inTenant(a, `UPDATE tenant_branding_pointer SET draft_revision_id = $2 WHERE tenant_id = $1`, a, revB.ID))
	if err := inTenant(a, `INSERT INTO tenant_branding_revision (tenant_id, seq, product_name, normalized_hash, created_by)
		VALUES ($1, 50, 'Forged', repeat('c', 64), 'x')`, b); err == nil {
		t.Error("tenant A inserted a revision for tenant B")
	}
	var n int
	_ = withTenant(ctx, app, a, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM tenant_branding_revision WHERE tenant_id = $1`, b).Scan(&n)
	})
	if n != 0 {
		t.Errorf("tenant A reads %d of tenant B's revisions", n)
	}
	// The public function is callable without any tenant pinned (it is pre-tenant), and the hostname table is
	// not directly readable by an unpinned session.
	var rows int
	if err := app.QueryRow(ctx, `SELECT count(*) FROM tenant_hostname_assignment`).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("unpinned read of assignments: %d %v", rows, err)
	}
	if _, err := fx.brand.PublicLookup(ctx, asgA.Host, true); err != nil {
		t.Errorf("public lookup as the application role: %v", err)
	}
}

// ---- both orderings of every serialised pair (docs/66 2b.2 tests 1-4) ------------------------------------

type heldTx struct {
	tx pgx.Tx
}

func beginHeld(t *testing.T, fx *pgBrandFx) *heldTx {
	t.Helper()
	tx, err := fx.h.pf.su.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := tx.Exec(context.Background(), `SELECT set_config('app.current_tenant', $1, true)`, fx.h.pf.platform); err != nil {
		t.Fatal(err)
	}
	return &heldTx{tx}
}

// ownerEdit performs the Owner's edit steps in an OPEN transaction (lock the pointer row, insert, move draft).
func (h *heldTx) ownerEdit(t *testing.T, tenant, name string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := h.tx.Exec(ctx, `SELECT cp_hostname_lock_tenant($1)`, tenant); err != nil {
		t.Fatal(err)
	}
	in := brandInput(name)
	hash := BrandingRevisionHash(in.ProductName, in.AccentColor, in.SupportText, in.Contact.Kind, in.Contact.Value, "")
	var id string
	if err := h.tx.QueryRow(ctx, `INSERT INTO tenant_branding_revision (tenant_id, seq, product_name, accent_color, support_text,
		support_contact_kind, support_contact_value, normalized_hash, created_by)
		VALUES ($1, (SELECT COALESCE(max(seq),0)+1 FROM tenant_branding_revision WHERE tenant_id = $1), $2, $3, $4, $5, $6, $7, 'owner')
		RETURNING id::text`, tenant, in.ProductName, in.AccentColor, in.SupportText, in.Contact.Kind, in.Contact.Value, hash).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := h.tx.Exec(ctx, `UPDATE tenant_branding_pointer SET draft_revision_id = $2 WHERE tenant_id = $1`, tenant, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (h *heldTx) approve(t *testing.T, fx *pgBrandFx, tenant string, rev *BrandingRevision, asg string) {
	t.Helper()
	c := fx.caller
	if _, err := h.tx.Exec(context.Background(), `SELECT * FROM cp_platform_branding_approve($1, $2, $3, $4, $5, $6, (SELECT review_generation FROM tenant_branding_pointer WHERE tenant_id = $3), 'held')`,
		c.UserID, c.SessionID, tenant, rev.ID, rev.Hash, asg); err != nil {
		t.Fatal(err)
	}
}

func (h *heldTx) release(t *testing.T, fx *pgBrandFx, asgID string) {
	t.Helper()
	c := fx.caller
	if _, err := h.tx.Exec(context.Background(), `SELECT * FROM cp_platform_hostname_release($1, $2, $3, 'held', 30)`, c.UserID, c.SessionID, asgID); err != nil {
		t.Fatal(err)
	}
}

func (h *heldTx) withdraw(t *testing.T, fx *pgBrandFx, tenant string) {
	t.Helper()
	c := fx.caller
	if _, err := h.tx.Exec(context.Background(), `SELECT cp_platform_branding_withdraw($1, $2, $3)`, c.UserID, c.SessionID, tenant); err != nil {
		t.Fatal(err)
	}
}

// runBlocked starts fn on a goroutine, proves it is BLOCKED behind the held transaction, runs commit, then
// returns fn's error.
func runBlocked(t *testing.T, held *heldTx, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		t.Fatalf("the operation did not wait for the tenant's branding lock (returned %v)", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := held.tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the blocked operation never finished")
		return nil
	}
}

func TestPgApproveVersusOwnerEditBothOrderings(t *testing.T) {
	ctx := context.Background()
	// (1) the Owner's edit commits FIRST (held), the operator's approval of the reviewed revision then fails stale and
	// the old revision stays published.
	fx := newPgBrandFx(t)
	a := fx.tenant("race1")
	asg := fx.activeHost(t, a, "race1.example.test")
	r1 := fx.draft(t, a, "Race One")
	if _, err := fx.approve(a, r1, asg.ID); err != nil {
		t.Fatal(err)
	}
	r2 := fx.draft(t, a, "Race Two") // the draft the operator reviews
	held := beginHeld(t, fx)
	edited := held.ownerEdit(t, a, "Race Three") // the Owner edits while the operator is reviewing r2
	err := runBlocked(t, held, func() error { _, err := fx.approve(a, r2, asg.ID); return err })
	if !errors.Is(err, ErrBrandingStale) {
		t.Fatalf("approve after a committed edit: %v, want stale", err)
	}
	fx.wantPublic(t, "edit first", asg.Host, "Race One")
	if st, _ := fx.brand.OwnerState(ctx, a); st.Draft.ID != edited {
		t.Fatalf("draft is %s, want the edit %s", st.Draft.ID, edited)
	}

	// (2) the approval commits FIRST (held), the Owner's edit then lands as a NEW unapproved draft and the reviewed
	// revision is what is published.
	fx = newPgBrandFx(t)
	a = fx.tenant("race2")
	asg = fx.activeHost(t, a, "race2.example.test")
	r2 = fx.draft(t, a, "Race Reviewed")
	held = beginHeld(t, fx)
	held.approve(t, fx, a, r2, asg.ID)
	var created bool
	var newRev *BrandingRevision
	err = runBlocked(t, held, func() error {
		var e error
		newRev, created, e = fx.brand.CreateRevision(ctx, a, "owner", brandInput("Race Edit After"))
		return e
	})
	if err != nil || !created {
		t.Fatalf("edit after approve: %v created=%v", err, created)
	}
	fx.wantPublic(t, "approve first", asg.Host, "Race Reviewed")
	st, _ := fx.brand.OwnerState(ctx, a)
	if st.Draft.ID != newRev.ID || st.Published.ID != r2.ID || st.DraftIsPublished {
		t.Fatalf("after approve-then-edit: %+v", st)
	}
}

func TestPgApproveVersusReleaseBothOrderings(t *testing.T) {
	ctx := context.Background()
	// Release commits first: the approval fails stale (no live assignment) and nothing is published.
	fx := newPgBrandFx(t)
	a := fx.tenant("rel1")
	asg := fx.activeHost(t, a, "rel1.example.test")
	rev := fx.draft(t, a, "Release One")
	held := beginHeld(t, fx)
	held.release(t, fx, asg.ID)
	err := runBlocked(t, held, func() error { _, err := fx.approve(a, rev, asg.ID); return err })
	if !errors.Is(err, ErrBrandingStale) {
		t.Fatalf("approve after a release: %v", err)
	}
	fx.wantPublic(t, "release first", asg.Host, "")

	// Approval commits first: the release then clears the published pointer.
	fx = newPgBrandFx(t)
	a = fx.tenant("rel2")
	asg = fx.activeHost(t, a, "rel2.example.test")
	rev = fx.draft(t, a, "Release Two")
	held = beginHeld(t, fx)
	held.approve(t, fx, a, rev, asg.ID)
	err = runBlocked(t, held, func() error {
		_, err := fx.hosts.Release(ctx, fx.caller, asg.ID, 30, map[string]any{"reason": "t"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	fx.wantPublic(t, "approve first, then release", asg.Host, "")
	if st, _ := fx.brand.OwnerState(ctx, a); st.Published != nil {
		t.Fatalf("a published pointer survived the release: %+v", st)
	}
}

func TestPgApproveVersusWithdrawalBothOrderings(t *testing.T) {
	ctx := context.Background()
	// Withdrawal commits first (held), then an approval of the NEXT draft publishes it.
	fx := newPgBrandFx(t)
	a := fx.tenant("wd1")
	asg := fx.activeHost(t, a, "wd1.example.test")
	r1 := fx.draft(t, a, "Withdraw One")
	if _, err := fx.approve(a, r1, asg.ID); err != nil {
		t.Fatal(err)
	}
	r2 := fx.draft(t, a, "Withdraw Two")
	held := beginHeld(t, fx)
	held.withdraw(t, fx, a)
	err := runBlocked(t, held, func() error { _, err := fx.approve(a, r2, asg.ID); return err })
	// The approval was prepared (its review read) BEFORE the withdrawal committed: the generation moved, so it is
	// stale and the withdrawn brand stays neutral. A fresh review then approves it.
	if !errors.Is(err, ErrBrandingStale) {
		t.Fatalf("approve prepared before a withdrawal: %v, want stale", err)
	}
	fx.wantPublic(t, "withdraw then stale approve", asg.Host, "")
	if _, err := fx.approve(a, r2, asg.ID); err != nil {
		t.Fatalf("fresh review after the withdrawal: %v", err)
	}
	fx.wantPublic(t, "withdraw then approve", asg.Host, "Withdraw Two")

	// Approval commits first (held), then the withdrawal clears it.
	fx = newPgBrandFx(t)
	a = fx.tenant("wd2")
	asg = fx.activeHost(t, a, "wd2.example.test")
	r1 = fx.draft(t, a, "Withdraw Three")
	held = beginHeld(t, fx)
	held.approve(t, fx, a, r1, asg.ID)
	err = runBlocked(t, held, func() error { return fx.brand.Withdraw(ctx, fx.caller, a, map[string]any{"reason": "t"}) })
	if err != nil {
		t.Fatalf("withdraw after approve: %v", err)
	}
	fx.wantPublic(t, "approve then withdraw", asg.Host, "")
}

// A1 on two real connections: an approval prepared BEFORE a withdrawal takes the pointer lock AFTER it commits,
// passes the draft, hash and assignment predicates, and must still be refused (the review generation moved).
func TestPgPreparedApprovalIsStaleAfterAWithdrawalCommits(t *testing.T) {
	fx := newPgBrandFx(t)
	a := fx.tenant("a1")
	asg := fx.activeHost(t, a, "a1.example.test")
	rev := fx.draft(t, a, "A One Co")
	if _, err := fx.approve(a, rev, asg.ID); err != nil {
		t.Fatal(err)
	}
	rv, _ := fx.brand.Review(context.Background(), fx.caller, a)
	prepared := BrandingApproval{RevisionID: rev.ID, Hash: rev.Hash, AssignmentID: asg.ID, Generation: rv.Generation}
	held := beginHeld(t, fx)
	held.withdraw(t, fx, a)
	err := runBlocked(t, held, func() error {
		_, err := fx.brand.Approve(context.Background(), fx.caller, a, prepared, nil)
		return err
	})
	if !errors.Is(err, ErrBrandingStale) {
		t.Fatalf("prepared approval after a committed withdrawal: %v, want stale", err)
	}
	fx.wantPublic(t, "withdrawn brand stays neutral", asg.Host, "")
	// Direct SQL cannot make the generation move backwards or be skipped by the trigger: a draft change bumps it.
	var g0, g1 int64
	su := fx.h.pf.su
	_ = su.QueryRow(context.Background(), `SELECT review_generation FROM tenant_branding_pointer WHERE tenant_id = $1`, a).Scan(&g0)
	fx.draft(t, a, "A One Co Two")
	_ = su.QueryRow(context.Background(), `SELECT review_generation FROM tenant_branding_pointer WHERE tenant_id = $1`, a).Scan(&g1)
	if g1 <= g0 {
		t.Errorf("a new draft did not move the generation: %d -> %d", g0, g1)
	}
}

// (6) A deadlock soak: edits, approvals, withdrawals and assignment changes for one tenant from several
// goroutines. Every one of them takes the pointer-row lock first, so there is no lock-order cycle; the soak
// asserts no 40P01 (deadlock), no 55P03 beyond the contention timeout, and that the pointer invariants hold at
// the end.
func TestPgBrandingDeadlockSoak(t *testing.T) {
	fx := newPgBrandFx(t)
	ctx := context.Background()
	a := fx.tenant("soak")
	fx.activeHost(t, a, "soak.example.test")
	var deadlocks, unexpected atomic.Int32
	record := func(err error) {
		switch {
		case err == nil, errors.Is(err, ErrBrandingStale), errors.Is(err, ErrBrandingNotPublished), errors.Is(err, ErrHostnameState),
			errors.Is(err, ErrHostnameTaken), errors.Is(err, ErrBrandingRateLimited), errors.Is(err, ErrHostnameQuarantined):
		case pgCode(err) == "40P01":
			deadlocks.Add(1)
		default:
			unexpected.Add(1)
			t.Logf("unexpected: %v", err)
		}
	}
	deadline := time.Now().Add(4 * time.Second)
	var wg sync.WaitGroup
	worker := func(id int, step func(i int)) {
		defer wg.Done()
		for i := 0; time.Now().Before(deadline); i++ {
			step(i)
		}
	}
	wg.Add(5)
	go worker(0, func(i int) { // Owner edits (bounded by the hourly budget: errors are fine)
		_, _, err := fx.brand.CreateRevision(ctx, a, "owner", brandInput(fmt.Sprintf("Soak %d", i)))
		record(err)
	})
	go worker(1, func(int) { // operator approves whatever the current draft is
		rv, err := fx.brand.Review(ctx, fx.caller, a)
		if err != nil || rv.Draft == nil || rv.Assignment == nil {
			record(err)
			return
		}
		_, err = fx.brand.Approve(ctx, fx.caller, a, BrandingApproval{RevisionID: rv.Draft.ID, Hash: rv.Draft.Hash, AssignmentID: rv.Assignment.ID, Generation: rv.Generation}, nil)
		record(err)
	})
	go worker(2, func(int) { record(fx.brand.Withdraw(ctx, fx.caller, a, nil)) })
	go worker(3, func(int) { // release and reactivate (the same tenant: no quarantine against itself)
		rv, err := fx.brand.Review(ctx, fx.caller, a)
		if err != nil || rv.Assignment == nil {
			record(err)
			return
		}
		if _, err := fx.hosts.Release(ctx, fx.caller, rv.Assignment.ID, 30, map[string]any{"reason": "soak"}); err != nil {
			record(err)
			return
		}
		_, err = fx.hosts.Reactivate(ctx, fx.caller, rv.Assignment.ID, true, nil)
		record(err)
	})
	go worker(4, func(int) { // public reads never block or fail
		if _, err := fx.brand.PublicLookup(ctx, "soak.example.test", true); err != nil {
			record(err)
		}
	})
	wg.Wait()
	if deadlocks.Load() != 0 || unexpected.Load() != 0 {
		t.Fatalf("deadlocks=%d unexpected=%d", deadlocks.Load(), unexpected.Load())
	}
	// Invariant: a published pointer, if any, names a revision of THIS tenant whose hash it carries, and an
	// assignment of THIS tenant (the composite foreign keys), and the lookup agrees with the state.
	var pub *string
	if err := fx.h.pf.su.QueryRow(ctx, `SELECT published_revision_id::text FROM tenant_branding_pointer WHERE tenant_id = $1`, a).Scan(&pub); err != nil {
		t.Fatal(err)
	}
	st, _ := fx.brand.OwnerState(ctx, a)
	p, _ := fx.brand.PublicLookup(ctx, "soak.example.test", false)
	if (p != nil) != st.Live {
		t.Fatalf("lookup (%v) and owner state (live=%v) disagree", p != nil, st.Live)
	}
}

// The public lookup is ONE statement whose plan uses the host index (no sequential scan of the assignments).
func TestPgPublicLookupUsesTheHostIndex(t *testing.T) {
	fx := newPgBrandFx(t)
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		a := fx.tenant(fmt.Sprintf("idx%d", i))
		fx.activeHost(t, a, fmt.Sprintf("idx%d.example.test", i))
	}
	su := fx.h.pf.su
	mustExec(t, su, `ANALYZE tenant_hostname_assignment`)
	c, err := su.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	if _, err := c.Exec(ctx, `SET enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = c.Exec(ctx, `RESET enable_seqscan`) }()
	rows, err := c.Query(ctx, `EXPLAIN SELECT r.product_name FROM tenant_hostname_assignment a
		JOIN tenant t ON t.id = a.tenant_id AND t.disabled_at IS NULL
		JOIN tenant_branding_pointer p ON p.tenant_id = a.tenant_id AND p.published_assignment_id = a.id
		JOIN tenant_branding_revision r ON r.tenant_id = p.tenant_id AND r.id = p.published_revision_id AND r.normalized_hash = p.published_revision_hash
		WHERE a.host = 'idx3.example.test' AND a.state = 'active'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var l string
		_ = rows.Scan(&l)
		plan.WriteString(l + "\n")
	}
	if !strings.Contains(plan.String(), "Index Cond: (host =") {
		t.Errorf("the host lookup does not use the host index:\n%s", plan.String())
	}
}

// The public route over REAL Postgres: it publishes what the operator approved; every state flip is visible on
// the very next request from a SECOND server process sharing the database (no cache anywhere: docs/66 2b.1);
// and a read blocked past the 100 ms statement timeout is neutral on schedule, with the connection destroyed and
// the pool back to idle afterwards.
func TestPgPublicRouteSecondReplicaSeesEveryFlipAndAStalledReadIsCut(t *testing.T) {
	fx := newPgBrandFx(t)
	ctx := context.Background()
	a := fx.tenant("e2e")
	const host = "e2e.example.test"
	asg := fx.activeHost(t, a, host)
	in := brandInput("E2E Support")
	in.LogoPNG = tinyLogo(t, 42)
	rev, _, err := fx.brand.CreateRevision(ctx, a, "owner", in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.approve(a, rev, asg.ID); err != nil {
		t.Fatal(err)
	}
	policy, _ := NewHostPolicy(HostPolicyConfig{DefaultHosts: []string{"main.example.test"}, PublicAuthorities: []string{"main.example.test", host}, Theming: true})
	second := newAppRolePool(t, ctx) // a second replica: its own pool, its own admission, its own everything
	srvB := &Server{HostPolicy: policy, BrandingRevisions: NewPgBrandingRevisionStore(second, nil), BrandingTuning: BrandingTuning{RatePerMinute: -1}}
	srvA := &Server{HostPolicy: policy, BrandingRevisions: fx.brand, BrandingTuning: BrandingTuning{RatePerMinute: -1}}
	get := func(srv *Server, path string) (*httptest.ResponseRecorder, time.Duration) {
		req := httptest.NewRequest("GET", path, nil)
		req.Host, req.RemoteAddr = host, nextIP()+":1"
		rec := httptest.NewRecorder()
		start := time.Now()
		srv.Handler().ServeHTTP(rec, req)
		return rec, time.Since(start)
	}
	published := func(srv *Server) bool {
		rec, _ := get(srv, "/public/branding")
		return strings.Contains(rec.Body.String(), "E2E Support")
	}
	if !published(srvA) || !published(srvB) {
		t.Fatal("approved branding is not published on both replicas")
	}
	if rec, _ := get(srvB, "/public/branding/logo?rev="+logoSHA(in.LogoPNG)); rec.Header().Get("Content-Type") != "image/png" || !bytes.Equal(rec.Body.Bytes(), in.LogoPNG) {
		t.Fatalf("logo over pg: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	// Every flip, applied through replica A's store, is visible on replica B's NEXT request.
	flips := []struct {
		name  string
		apply func()
		undo  func()
	}{
		{"suspend", func() { fx.suspend(a, true) }, func() { fx.suspend(a, false) }},
		{"withdraw", func() {
			if err := fx.brand.Withdraw(ctx, fx.caller, a, map[string]any{"reason": "t"}); err != nil {
				t.Fatal(err)
			}
		}, func() {
			if _, err := fx.approve(a, rev, asg.ID); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, f := range flips {
		f.apply()
		if published(srvB) {
			t.Errorf("%s: replica B still publishes", f.name)
		}
		f.undo()
		if !published(srvB) {
			t.Errorf("%s undone: replica B does not publish", f.name)
		}
	}
	if _, err := fx.hosts.Release(ctx, fx.caller, asg.ID, 30, map[string]any{"reason": "t"}); err != nil {
		t.Fatal(err)
	}
	if published(srvB) {
		t.Fatal("release: replica B still publishes")
	}
	react, err := fx.hosts.Reactivate(ctx, fx.caller, asg.ID, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if published(srvB) {
		t.Fatal("reactivation without re-approval publishes on replica B")
	}
	if _, err := fx.approve(a, rev, react.ID); err != nil {
		t.Fatal(err)
	}
	if !published(srvB) {
		t.Fatal("re-approval is not visible on replica B")
	}

	// A stalled read: another session holds an ACCESS EXCLUSIVE lock on the pointer table, so the lookup blocks
	// until the 100 ms statement timeout / work deadline fires. The answer is neutral, released at 150 ms + jitter.
	blocker, err := fx.h.pf.su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(ctx, `LOCK TABLE tenant_branding_pointer IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	rec, took := get(srvB, "/public/branding")
	if rec.Body.String() != string(NeutralBrandingBody()) {
		t.Errorf("a stalled read must be neutral: %s", rec.Body.String())
	}
	if took < DefaultBrandingFloor || took > DefaultBrandingFloor+DefaultBrandingJitter+150*time.Millisecond {
		t.Errorf("stalled read released after %v", took)
	}
	if srvB.BrandingCutoffTotal("json") != 1 {
		t.Errorf("cutoff counter = %d", srvB.BrandingCutoffTotal("json"))
	}
	_ = blocker.Rollback(ctx)
	eventually(t, 1500*time.Millisecond, "permit and connection recovery", func() bool {
		in, _ := srvB.brandingPool().stats()
		return in == 0 && second.Stat().AcquiredConns() == 0
	})
	if !published(srvB) {
		t.Error("replica B does not recover after the stall")
	}
}

// The assignment binding of the PUBLIC lookup, independent of the clearing the lifecycle functions do: even if a
// published pointer were left naming an OLD assignment (here planted by direct SQL), a host whose CURRENT
// active assignment is a different id publishes nothing (docs/66 2c.2).
func TestPgLookupChecksTheAssignmentBindingEvenIfClearingFailed(t *testing.T) {
	fx := newPgBrandFx(t)
	ctx := context.Background()
	a := fx.tenant("bind")
	old := fx.activeHost(t, a, "bind.example.test")
	rev := fx.draft(t, a, "Bind Co")
	if _, err := fx.approve(a, rev, old.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.hosts.Release(ctx, fx.caller, old.ID, 30, map[string]any{"reason": "t"}); err != nil {
		t.Fatal(err)
	}
	cur, err := fx.hosts.Reactivate(ctx, fx.caller, old.ID, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Plant the OLD triple again (the foreign keys allow it: same tenant, same revision, same hash).
	mustExec(t, fx.h.pf.su, `UPDATE tenant_branding_pointer SET published_revision_id = $2, published_revision_hash = $3,
		published_assignment_id = $4, published_by = 'planted', published_at = now() WHERE tenant_id = $1`, a, rev.ID, rev.Hash, old.ID)
	fx.wantPublic(t, "stale triple planted", "bind.example.test", "")
	// And naming the CURRENT assignment makes it publish: the binding is the only thing that decided.
	mustExec(t, fx.h.pf.su, `UPDATE tenant_branding_pointer SET published_assignment_id = $2 WHERE tenant_id = $1`, a, cur.ID)
	fx.wantPublic(t, "current assignment named", "bind.example.test", "Bind Co")
}

// keep_logo reads the draft AFTER taking the tenant's lock: an edit that is mid-flight (it has dropped the logo and
// not yet committed) is waited for, and the keep request then sees the edit's draft, not the one it would have read
// without the lock.
func TestPgKeepLogoReadsTheDraftAfterTheLock(t *testing.T) {
	fx := newPgBrandFx(t)
	ctx := context.Background()
	a := fx.tenant("keeplock")
	in := brandInput("Keep Lock Co")
	in.LogoPNG = tinyLogo(t, 9)
	if _, _, err := fx.brand.CreateRevision(ctx, a, "owner", in); err != nil {
		t.Fatal(err)
	}
	held := beginHeld(t, fx)
	held.ownerEdit(t, a, "Keep Lock Co No Logo") // the draft is now a logo-less revision, uncommitted
	keep := brandInput("Keep Lock Co Again")
	keep.KeepLogo = true
	err := runBlocked(t, held, func() error { _, _, err := fx.brand.CreateRevision(ctx, a, "owner", keep); return err })
	if !errors.Is(err, ErrBrandingNoLogoToKeep) {
		t.Fatalf("keep_logo after a concurrent logo-less edit: %v, want %v", err, ErrBrandingNoLogoToKeep)
	}
}

// Migration 0075 on rows that existed BEFORE it: only the audit chain knew a withdrawal happened. The backfill
// (re-run here after clearing the new columns, which is exactly the pre-0075 state) recovers a withdrawal that is
// still the tenant's latest branding/hostname event, names the revision only from an approval event, and invents
// nothing otherwise. Also: the column CHECK refuses a withdrawal that coexists with a publication.
func TestPgBrandingWithdrawnBackfillIsHonestAndTheShapeIsEnforced(t *testing.T) {
	ctx := context.Background()
	fx := newPgBrandFx(t)
	su := fx.h.pf.su

	wd := fx.tenant("bf-wd") // approved, withdrawn: the backfill finds it
	asgW := fx.activeHost(t, wd, "bf-wd.example.test")
	revW := fx.draft(t, wd, "Backfill Withdrawn")
	if _, err := fx.approve(wd, revW, asgW.ID); err != nil {
		t.Fatal(err)
	}
	if err := fx.brand.Withdraw(ctx, fx.caller, wd, map[string]any{"reason": "t"}); err != nil {
		t.Fatal(err)
	}

	rel := fx.tenant("bf-rel") // approved, then the hostname released: not a withdrawal
	asgR := fx.activeHost(t, rel, "bf-rel.example.test")
	if _, err := fx.approve(rel, fx.draft(t, rel, "Backfill Released"), asgR.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.hosts.Release(ctx, fx.caller, asgR.ID, 30, map[string]any{"reason": "t"}); err != nil {
		t.Fatal(err)
	}

	wr := fx.tenant("bf-wr") // withdrawn, THEN the hostname released: a new hostname starts clean
	asgX := fx.activeHost(t, wr, "bf-wr.example.test")
	if _, err := fx.approve(wr, fx.draft(t, wr, "Backfill Withdrawn Released"), asgX.ID); err != nil {
		t.Fatal(err)
	}
	if err := fx.brand.Withdraw(ctx, fx.caller, wr, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.hosts.Release(ctx, fx.caller, asgX.ID, 30, map[string]any{"reason": "t"}); err != nil {
		t.Fatal(err)
	}

	nv := fx.tenant("bf-never") // a draft, never approved
	fx.activeHost(t, nv, "bf-never.example.test")
	fx.draft(t, nv, "Backfill Never")

	var wantAt time.Time
	if err := su.QueryRow(ctx, `SELECT withdrawn_at FROM tenant_branding_pointer WHERE tenant_id = $1`, wd).Scan(&wantAt); err != nil {
		t.Fatal(err)
	}
	var wdAudit time.Time
	if err := su.QueryRow(ctx, `SELECT occurred_at FROM audit_event WHERE tenant_id = $1 AND action = 'tenant.branding.withdraw'`, wd).Scan(&wdAudit); err != nil {
		t.Fatal(err)
	}
	// The pre-0075 state: the withdrawal columns do not exist as data.
	if _, err := su.Exec(ctx, `UPDATE tenant_branding_pointer SET withdrawn_at = NULL, withdrawn_revision_id = NULL`); err != nil {
		t.Fatal(err)
	}
	applyMigrationFile(t, su, "migrations/0075_branding_withdrawn.sql")

	got := func(tenant string) (at *time.Time, rev *string) {
		t.Helper()
		if err := su.QueryRow(ctx, `SELECT withdrawn_at, withdrawn_revision_id::text FROM tenant_branding_pointer WHERE tenant_id = $1`, tenant).Scan(&at, &rev); err != nil {
			t.Fatal(err)
		}
		return
	}
	at, rv := got(wd)
	if at == nil || !at.Equal(wdAudit) {
		t.Fatalf("backfilled withdrawn_at = %v, want the audit event's time %v", at, wdAudit)
	}
	if rv == nil || *rv != revW.ID {
		t.Fatalf("backfilled withdrawn_revision_id = %v, want %s (from the approval event)", rv, revW.ID)
	}
	if d := wantAt.Sub(*at); d < -time.Minute || d > time.Minute {
		t.Fatalf("the recorded time %v and the backfilled time %v differ by %v", wantAt, *at, d)
	}
	for name, tenant := range map[string]string{"released after approval": rel, "released after withdrawal": wr, "never approved": nv} {
		if at, rv := got(tenant); at != nil || rv != nil {
			t.Fatalf("%s: backfill invented %v / %v", name, at, rv)
		}
	}
	st, err := fx.brand.OwnerState(ctx, wd)
	if err != nil || st.Withdrawn == nil || st.Withdrawn.RevisionID != revW.ID {
		t.Fatalf("owner state after backfill: %+v %v", st, err)
	}


	// The latest approval decides, not the latest approval whose revision still exists. Two tenants approved A, then
	// approved B and withdrew B. In one B was later deleted; in the other B's approval event lost its revision id.
	// Neither may be recorded as A (an older, surviving approval), nor as anything: the revision stays NULL, the time stays.
	later := func(label string) (tenant string, revA, revB string) {
		tenant = fx.tenant(label)
		asg := fx.activeHost(t, tenant, label+".example.test")
		ra := fx.draft(t, tenant, label+" A")
		if _, err := fx.approve(tenant, ra, asg.ID); err != nil {
			t.Fatal(err)
		}
		rb := fx.draft(t, tenant, label+" B")
		if _, err := fx.approve(tenant, rb, asg.ID); err != nil {
			t.Fatal(err)
		}
		if err := fx.brand.Withdraw(ctx, fx.caller, tenant, nil); err != nil {
			t.Fatal(err)
		}
		return tenant, ra.ID, rb.ID
	}
	delT, delA, delB := later("bf-del")
	badT, badA, badB := later("bf-bad")
	mutT, mutA, mutB := later("bf-mut") // metadata names an id of the wrong shape
	_, _ = badA, mutA
	if _, err := su.Exec(ctx, `UPDATE tenant_branding_pointer SET withdrawn_at = NULL, withdrawn_revision_id = NULL, draft_revision_id = $2 WHERE tenant_id = $1`, delT, delA); err != nil {
		t.Fatal(err)
	}
	if _, err := su.Exec(ctx, `DELETE FROM tenant_branding_revision WHERE tenant_id = $1 AND id = $2`, delT, delB); err != nil {
		t.Fatalf("could not delete the latest approved revision to build the fixture: %v", err)
	}
	if _, err := su.Exec(ctx, `UPDATE tenant_branding_pointer SET withdrawn_at = NULL, withdrawn_revision_id = NULL WHERE tenant_id = ANY($1)`, []string{badT, mutT}); err != nil {
		t.Fatal(err)
	}
	if _, err := su.Exec(ctx, `UPDATE audit_event SET metadata = metadata - 'revision_id'
	    WHERE tenant_id = $1 AND action = 'tenant.branding.approve' AND metadata ->> 'revision_id' = $2`, badT, badB); err != nil {
		t.Fatalf("could not strip the revision id from the approval event: %v", err)
	}
	if _, err := su.Exec(ctx, `UPDATE audit_event SET metadata = jsonb_set(metadata, '{revision_id}', '"not-a-uuid"')
	    WHERE tenant_id = $1 AND action = 'tenant.branding.approve' AND metadata ->> 'revision_id' = $2`, mutT, mutB); err != nil {
		t.Fatalf("could not garble the revision id in the approval event: %v", err)
	}
	applyMigrationFile(t, su, "migrations/0075_branding_withdrawn.sql")
	for name, tenant := range map[string]string{"latest approval's revision deleted": delT, "latest approval has no revision id": badT, "latest approval has a garbled revision id": mutT} {
		at, rv := got(tenant)
		if at == nil {
			t.Fatalf("%s: the withdrawal time was not recovered", name)
		}
		if rv != nil {
			t.Fatalf("%s: withdrawn_revision_id = %s, want NULL (an older approval must not be substituted)", name, *rv)
		}
	}
	_ = delA

	// The shape: a withdrawal never coexists with a publication, and a revision id needs a withdrawal time.
	pub := fx.tenant("bf-shape")
	asgP := fx.activeHost(t, pub, "bf-shape.example.test")
	revP := fx.draft(t, pub, "Backfill Shape")
	if _, err := fx.approve(pub, revP, asgP.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := su.Exec(ctx, `UPDATE tenant_branding_pointer SET withdrawn_at = now() WHERE tenant_id = $1`, pub); err == nil {
		t.Fatal("a withdrawal coexisting with a publication was accepted")
	}
	if _, err := su.Exec(ctx, `UPDATE tenant_branding_pointer SET withdrawn_revision_id = draft_revision_id WHERE tenant_id = $1`, nv); err == nil {
		t.Fatal("a withdrawn revision id without a withdrawal time was accepted")
	}
}
