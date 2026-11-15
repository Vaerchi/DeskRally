package controlplane

// ONE contract suite for the hostname lifecycle and the scoped redemption, run against the in-memory fake and
// against Postgres (migration 0071) - the "fake and pg must agree" rule. The Pg half SKIPS without
// TEST_DATABASE_URL like every pgx test (verify-all treats a skip as a failure).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"
)

type hostContractFx struct {
	hosts    HostnameStore
	attended AttendedStore
	caller   PlatformCaller
	// tenant makes a fresh tenant (with a group and a technician) and returns its id.
	tenant func(name string) string
	// newCode mints a pending attend code for the tenant and returns it with the session id.
	newCode func(tenant string) (code, sessionID string)
	// expire makes the session's code expired.
	expire func(sessionID string)
	// suspend / resume the tenant.
	suspend func(tenant string, on bool)
	// age moves a host's released rows back in time.
	age func(host string, d time.Duration)
}

func randPubkeyHex(t testing.TB) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func (fx *hostContractFx) redeem(t *testing.T, code string, scope RedeemScope) (*AttendedRedeem, error) {
	t.Helper()
	return fx.attended.RedeemScoped(context.Background(), code, randPubkeyHex(t), "GUEST", scope)
}

func (fx *hostContractFx) mustAssign(t *testing.T, tenant, host string) *HostnameAssignment {
	t.Helper()
	a, err := fx.hosts.Assign(context.Background(), fx.caller, tenant, host, nil)
	if err != nil {
		t.Fatalf("assign %s to %s: %v", host, tenant, err)
	}
	return a
}

func hostWantErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: err = %v, want %v", what, err, want)
	}
}

func runHostnameContract(t *testing.T, fx *hostContractFx) {
	ctx := context.Background()
	A, B := fx.tenant("a"), fx.tenant("b")
	scoped := func(h string) RedeemScope { return RedeemScope{Host: h} }
	unscoped := RedeemScope{Unscoped: true}

	// --- shape and authorization ------------------------------------------------------------------
	if _, err := fx.hosts.Assign(ctx, PlatformCaller{}, A, "x1.example.test", nil); !errors.Is(err, ErrPlatformDenied) {
		t.Fatalf("no session: %v, want denied", err)
	}
	for _, bad := range []string{"", "UPPER.example.test", "nodots", "a..b.test", "-a.example.test", "a b.example.test"} {
		if _, err := fx.hosts.Assign(ctx, fx.caller, A, bad, nil); !errors.Is(err, ErrHostnameInvalid) {
			t.Fatalf("assign %q: %v, want invalid", bad, err)
		}
	}

	// --- pending is NOT a scope: neither tenant's code redeems on it --------------------------------
	a1 := fx.mustAssign(t, A, "acme.example.test")
	if a1.State != "pending" || a1.Kind != "subdomain" || a1.ID == "" || a1.ActivatedAt != nil {
		t.Fatalf("assign: %+v", a1)
	}
	codeA, _ := fx.newCode(A)
	_, err := fx.redeem(t, codeA, scoped("acme.example.test"))
	hostWantErr(t, "pending host", err, ErrAttendedInvalid)

	// A tenant has ONE live assignment, a host has ONE live assignment.
	_, err = fx.hosts.Assign(ctx, fx.caller, A, "second.example.test", nil)
	hostWantErr(t, "second live assignment for the tenant", err, ErrHostnameTaken)
	_, err = fx.hosts.Assign(ctx, fx.caller, B, "acme.example.test", nil)
	hostWantErr(t, "host already live", err, ErrHostnameTaken)

	// --- activation keeps the id ---------------------------------------------------------------------
	act, err := fx.hosts.Activate(ctx, fx.caller, a1.ID, nil)
	if err != nil || act.ID != a1.ID || act.State != "active" || act.ActivatedAt == nil {
		t.Fatalf("activate: %+v %v (the id must not change)", act, err)
	}
	_, err = fx.hosts.Activate(ctx, fx.caller, a1.ID, nil)
	hostWantErr(t, "activate an active row", err, ErrHostnameState)
	_, err = fx.hosts.Activate(ctx, fx.caller, newUUID(), nil)
	hostWantErr(t, "activate unknown", err, ErrHostnameNotFound)

	// --- scoped redemption on an ACTIVE host ---------------------------------------------------------
	res, err := fx.redeem(t, codeA, scoped("acme.example.test"))
	if err != nil || res.TenantID != A {
		t.Fatalf("own tenant's code on its active host: %+v %v", res, err)
	}
	_, err = fx.redeem(t, codeA, scoped("acme.example.test"))
	hostWantErr(t, "spent code", err, ErrAttendedInvalid)

	// A foreign tenant's valid code is generic-invalid on the host, and is NOT spent by the attempt.
	codeB, _ := fx.newCode(B)
	_, err = fx.redeem(t, codeB, scoped("acme.example.test"))
	hostWantErr(t, "foreign code on a scoped host", err, ErrAttendedInvalid)
	if res, err := fx.redeem(t, codeB, unscoped); err != nil || res.TenantID != B {
		t.Fatalf("the refused foreign code must still redeem on an unscoped host: %+v %v", res, err)
	}

	// Expired, unknown host, refused (empty) host: the same answer.
	codeA2, sidA2 := fx.newCode(A)
	fx.expire(sidA2)
	_, err = fx.redeem(t, codeA2, scoped("acme.example.test"))
	hostWantErr(t, "expired", err, ErrAttendedInvalid)
	codeA3, _ := fx.newCode(A)
	for _, h := range []string{"unknown.example.test", "", "ACME.example.test"} {
		_, err = fx.redeem(t, codeA3, scoped(h))
		hostWantErr(t, "host "+h, err, ErrAttendedInvalid)
	}
	// ...and that code is still good on its own host.
	if _, err := fx.redeem(t, codeA3, scoped("acme.example.test")); err != nil {
		t.Fatalf("code unspent by the refusals: %v", err)
	}

	// --- a suspended tenant: every predicate of 0021 is kept ------------------------------------------
	codeA4, _ := fx.newCode(A)
	fx.suspend(A, true)
	_, err = fx.redeem(t, codeA4, scoped("acme.example.test"))
	hostWantErr(t, "suspended tenant, scoped", err, ErrAttendedInvalid)
	_, err = fx.redeem(t, codeA4, unscoped)
	hostWantErr(t, "suspended tenant, unscoped (0021 parity)", err, ErrAttendedInvalid)
	fx.suspend(A, false)
	if _, err := fx.redeem(t, codeA4, scoped("acme.example.test")); err != nil {
		t.Fatalf("resumed tenant: %v", err)
	}

	// --- release: scope disappears on the NEXT redemption; terminal; quarantine -----------------------
	_, err = fx.hosts.Release(ctx, fx.caller, a1.ID, 10, nil)
	hostWantErr(t, "quarantine below 30 days", err, ErrHostnameInvalid)
	codeA5, _ := fx.newCode(A)
	rel, err := fx.hosts.Release(ctx, fx.caller, a1.ID, HostnameQuarantineDays, map[string]any{"reason": "test"})
	if err != nil || rel.State != "released" || rel.QuarantinedUntil == nil || rel.ReleasedAt == nil ||
		rel.QuarantinedUntil.Sub(*rel.ReleasedAt) < 30*24*time.Hour-time.Second {
		t.Fatalf("release: %+v %v", rel, err)
	}
	_, err = fx.redeem(t, codeA5, scoped("acme.example.test"))
	hostWantErr(t, "released host", err, ErrAttendedInvalid)
	_, err = fx.hosts.Release(ctx, fx.caller, a1.ID, 30, nil)
	hostWantErr(t, "release twice", err, ErrHostnameState)
	_, err = fx.hosts.Activate(ctx, fx.caller, a1.ID, nil)
	hostWantErr(t, "activate a released row", err, ErrHostnameState)

	// --- reactivation = a NEW assignment id; the quarantine bars OTHER tenants only --------------------
	_, err = fx.hosts.Assign(ctx, fx.caller, B, "acme.example.test", nil)
	hostWantErr(t, "another tenant during quarantine", err, ErrHostnameQuarantined)
	_, err = fx.hosts.Reactivate(ctx, fx.caller, act.ID, true, nil)
	if err != nil {
		t.Fatalf("reactivating the released row: %v", err)
	}
	all, _ := fx.hosts.List(ctx, fx.caller, A)
	var newID string
	for _, r := range all {
		if r.State == "active" {
			newID = r.ID
		}
	}
	if newID == "" || newID == a1.ID {
		t.Fatalf("reactivation must create a NEW assignment id: old %s new %s (%+v)", a1.ID, newID, all)
	}
	if _, err := fx.redeem(t, codeA5, scoped("acme.example.test")); err != nil {
		t.Fatalf("reactivated host scopes A again: %v", err)
	}
	_, err = fx.hosts.Reactivate(ctx, fx.caller, newID, false, nil)
	hostWantErr(t, "reactivate a live row", err, ErrHostnameState)

	// --- reassignment to ANOTHER tenant after the quarantine -------------------------------------------
	if _, err := fx.hosts.Release(ctx, fx.caller, newID, 30, nil); err != nil {
		t.Fatal(err)
	}
	_, err = fx.hosts.Assign(ctx, fx.caller, B, "acme.example.test", nil)
	hostWantErr(t, "before the deadline", err, ErrHostnameQuarantined)
	fx.age("acme.example.test", 31*24*time.Hour)
	b1 := fx.mustAssign(t, B, "acme.example.test")
	if _, err := fx.hosts.Activate(ctx, fx.caller, b1.ID, nil); err != nil {
		t.Fatal(err)
	}
	oldOwnerCode, _ := fx.newCode(A)
	_, err = fx.redeem(t, oldOwnerCode, scoped("acme.example.test"))
	hostWantErr(t, "the previous owner's code on the reused host", err, ErrAttendedInvalid)
	newOwnerCode, _ := fx.newCode(B)
	if res, err := fx.redeem(t, newOwnerCode, scoped("acme.example.test")); err != nil || res.TenantID != B {
		t.Fatalf("the new owner's code: %+v %v", res, err)
	}
	// History is retained, never deleted: A's two rows and B's one are all there.
	hist, err := fx.hosts.List(ctx, fx.caller, "")
	if err != nil {
		t.Fatal(err)
	}
	var onHost int
	for _, r := range hist {
		if r.Host == "acme.example.test" {
			onHost++
		}
	}
	if onHost != 3 {
		t.Fatalf("history rows for the host = %d, want 3: %+v", onHost, hist)
	}

	// --- a concurrent double-assign yields exactly one winner ------------------------------------------
	C, D := fx.tenant("c"), fx.tenant("d")
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i, tn := range []string{C, D} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = fx.hosts.Assign(ctx, fx.caller, tn, "race.example.test", nil)
		}()
	}
	wg.Wait()
	wins := 0
	for _, e := range results {
		if e == nil {
			wins++
		} else if !errors.Is(e, ErrHostnameTaken) {
			t.Fatalf("loser of the double-assign: %v, want ErrHostnameTaken", e)
		}
	}
	if wins != 1 {
		t.Fatalf("double-assign winners = %d, want exactly 1 (%v)", wins, results)
	}
}

// --- fake fixture -------------------------------------------------------------------------------------

func newFakeHostContractFx(t *testing.T) *hostContractFx {
	t.Helper()
	machines := NewInMemoryMachineStore()
	att := NewInMemoryAttendedStore(machines)
	hosts := &InMemoryHostnameStore{}
	suspended := map[string]bool{}
	var mu sync.Mutex
	hosts.TenantActive = func(id string) bool { mu.Lock(); defer mu.Unlock(); return !suspended[id] }
	att.Hosts = hosts
	// The fake attended store does not model suspension itself (the pg predicate of 0021 does), so wrap it.
	return &hostContractFx{
		hosts:    hosts,
		attended: &suspendAwareAttended{InMemoryAttendedStore: att, active: hosts.TenantActive},
		caller:   PlatformCaller{UserID: newUUID(), TenantID: newUUID(), SessionID: newUUID(), Email: "op@test"},
		tenant:   func(string) string { return newUUID() },
		newCode: func(tenant string) (string, string) {
			s := &AttendedSession{GroupID: newUUID(), TechnicianID: newUUID(), Reason: "x"}
			code, err := att.Create(context.Background(), tenant, s)
			if err != nil {
				t.Fatal(err)
			}
			return code, s.ID
		},
		expire: func(id string) {
			att.mu.Lock()
			defer att.mu.Unlock()
			att.sessions[id].ExpiresAt = time.Now().Add(-time.Minute)
		},
		suspend: func(tn string, on bool) { mu.Lock(); suspended[tn] = on; mu.Unlock() },
		age:     hosts.AgeReleased,
	}
}

// suspendAwareAttended adds 0021's "tenant not disabled" predicate to the fake, for both scoped and unscoped.
type suspendAwareAttended struct {
	*InMemoryAttendedStore
	active func(string) bool
}

func (s *suspendAwareAttended) RedeemScoped(ctx context.Context, code, pub, name string, scope RedeemScope) (*AttendedRedeem, error) {
	s.InMemoryAttendedStore.mu.Lock()
	for _, t := range s.InMemoryAttendedStore.sessions {
		if t.codeHash == hashKey(HashToken(normalizeAttendCode(code))) && !s.active(t.TenantID) {
			s.InMemoryAttendedStore.mu.Unlock()
			return nil, ErrAttendedInvalid
		}
	}
	s.InMemoryAttendedStore.mu.Unlock()
	return s.InMemoryAttendedStore.RedeemScoped(ctx, code, pub, name, scope)
}

func TestHostnameContractInMemory(t *testing.T) {
	runHostnameContract(t, newFakeHostContractFx(t))
}
