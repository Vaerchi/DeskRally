package controlplane

// Tests for the machine.logged_in_user column (migration 0048) — the Windows interactive-session
// user reported by the agent at registration time (R65).
//
// Doctrine is identical to machine_agent_version_test.go and machine_require_session_policy_test.go:
//
//  1. THE PROJECTION. PgMachineStore reads a machine row through two independent paths —
//     selectMachine/scanMachine and a separate inline SELECT inside ListMachines. Missing a column
//     from either produced always-empty values in 0032 and 0033; every pg assertion below reads BOTH.
//
//  2. THE FAKE AND THE STORE SHARE ONE CONTRACT. A test against InMemoryMachineStore says nothing
//     about the pg store's semantics. Every rule (empty skipped, oversized skipped, cross-tenant
//     skipped, only-when-different counted) is asserted against both.
//
//  3. SILENCE MUST NEVER BLANK. An absent value means "agent said nothing" (pre-R65 agent,
//     non-Windows, or no interactive session), not "the machine has no user". An empty report must
//     never overwrite a stored value; that would erase real data whenever an older agent reconnects.

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------------------------
// The fake
// ----------------------------------------------------------------------------------------------

func TestInMemoryRecordLoggedInUser(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMachineStore()
	m := &Machine{DeviceID: "dev-1", GroupID: "g1", Name: "HOST"}
	if err := s.EnrollMachine(ctx, "t1", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// Fresh machine: no user has ever been reported.
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.LoggedInUser != "" {
		t.Fatalf("a fresh machine must have no logged_in_user, got %q", got.LoggedInUser)
	}

	// A real value lands and is counted.
	n, err := s.RecordLoggedInUser(ctx, "t1", map[string]string{"dev-1": "CORP\\alice"})
	if err != nil || n != 1 {
		t.Fatalf("record = (%d, %v), want (1, nil)", n, err)
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.LoggedInUser != "CORP\\alice" {
		t.Fatalf("logged_in_user did not stick: %q", got.LoggedInUser)
	}

	// ONLY-WHEN-DIFFERENT. The steady state must not count a change.
	if n, _ := s.RecordLoggedInUser(ctx, "t1", map[string]string{"dev-1": "CORP\\alice"}); n != 0 {
		t.Fatalf("an unchanged user counted %d rows, want 0", n)
	}

	// A different user (e.g. fast-user switch) is a real change.
	if n, _ := s.RecordLoggedInUser(ctx, "t1", map[string]string{"dev-1": "CORP\\bob"}); n != 1 {
		t.Fatalf("a changed user must count 1 row")
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.LoggedInUser != "CORP\\bob" {
		t.Fatalf("user did not advance: %q", got.LoggedInUser)
	}

	// SILENCE MUST NOT BLANK. An empty value means "agent said nothing".
	if n, _ := s.RecordLoggedInUser(ctx, "t1", map[string]string{"dev-1": ""}); n != 0 {
		t.Fatalf("an empty report must change nothing")
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.LoggedInUser != "CORP\\bob" {
		t.Fatalf("an empty report ERASED a stored user: %q", got.LoggedInUser)
	}

	// Oversized is skipped, not truncated — the store holds its own invariant.
	if n, _ := s.RecordLoggedInUser(ctx, "t1", map[string]string{
		"dev-1": strings.Repeat("x", maxLoggedInUserLen+1),
	}); n != 0 {
		t.Fatalf("an oversized value must be skipped")
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.LoggedInUser != "CORP\\bob" {
		t.Fatalf("an oversized report overwrote a stored user: %q", got.LoggedInUser)
	}

	// Exactly at the bound is accepted — establish the boundary from both sides.
	atBound := strings.Repeat("y", maxLoggedInUserLen)
	if n, _ := s.RecordLoggedInUser(ctx, "t1", map[string]string{"dev-1": atBound}); n != 1 {
		t.Fatalf("a value exactly at the bound must be accepted")
	}

	// A device id belonging to another tenant is silently skipped.
	if n, _ := s.RecordLoggedInUser(ctx, "other-tenant", map[string]string{"dev-1": "evil\\attacker"}); n != 0 {
		t.Fatalf("a cross-tenant write must count 0 rows")
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.LoggedInUser != atBound {
		t.Fatalf("a cross-tenant write reached the row: %q", got.LoggedInUser)
	}
}

// ----------------------------------------------------------------------------------------------
// ObservedLoggedInUser — presence.go
// ----------------------------------------------------------------------------------------------

func TestObservedLoggedInUser(t *testing.T) {
	src := NewInMemoryPresenceSource()
	now := time.Now().UTC()

	src.SetOnlineWithLoggedInUser("dev-a", now, "CORP\\alice")
	src.SetOnline("dev-b", now) // no user announcement

	p, err := src.FetchPresence(context.Background())
	if err != nil {
		t.Fatalf("FetchPresence: %v", err)
	}

	user, ok := p.ObservedLoggedInUser("dev-a")
	if !ok || user != "CORP\\alice" {
		t.Fatalf("ObservedLoggedInUser(dev-a) = (%q, %v), want (CORP\\alice, true)", user, ok)
	}

	// dev-b announced no user: the result must be absent (false), not an empty string.
	if user, ok := p.ObservedLoggedInUser("dev-b"); ok {
		t.Fatalf("dev-b announced no user but ObservedLoggedInUser = (%q, true)", user)
	}

	// Unknown device: absent.
	if _, ok := p.ObservedLoggedInUser("dev-x"); ok {
		t.Fatal("unknown device must return (_, false)")
	}
}

// ----------------------------------------------------------------------------------------------
// annotatePresence integration — the write-behind triggered by GET /machines
// ----------------------------------------------------------------------------------------------

func TestListMachinesRefreshesLoggedInUser(t *testing.T) {
	srv, machines, presence := presenceTestServer(t)
	seedMachine(t, machines, "dev-login", "WS-01")  // has "Windows 11 Pro" as OS; no user yet
	seedMachine(t, machines, "dev-same", "WS-02")
	seedMachine(t, machines, "dev-silent", "WS-03")

	// Pre-seed "dev-same" with a user so we can assert it is NOT rewritten when the report matches.
	if _, err := machines.RecordLoggedInUser(context.Background(), "tenant-1",
		map[string]string{"dev-same": "CORP\\alice"}); err != nil {
		t.Fatalf("pre-seed: %v", err)
	}

	now := time.Now().UTC()
	presence.SetOnlineWithLoggedInUser("dev-login", now, "CORP\\bob")
	presence.SetOnlineWithLoggedInUser("dev-same", now, "CORP\\alice") // same as stored
	presence.SetOnline("dev-silent", now)                              // no announcement
	// Foreign tenant device must not materialize or write.
	presence.SetOnlineWithLoggedInUser("dev-foreign", now, "evil\\hacker")

	listMachines(t, srv)

	if m, _ := machines.GetMachine(context.Background(), "tenant-1", "dev-login"); m.LoggedInUser != "CORP\\bob" {
		t.Fatalf("newly reported user = %q, want CORP\\bob", m.LoggedInUser)
	}
	if m, _ := machines.GetMachine(context.Background(), "tenant-1", "dev-same"); m.LoggedInUser != "CORP\\alice" {
		t.Fatalf("unchanged user = %q, want it left as stored", m.LoggedInUser)
	}
	// No announcement must never clear a stored value.
	if m, _ := machines.GetMachine(context.Background(), "tenant-1", "dev-silent"); m.LoggedInUser != "" {
		t.Fatalf("silent machine user = %q, want empty (nothing was stored)", m.LoggedInUser)
	}
	if _, err := machines.GetMachine(context.Background(), "tenant-1", "dev-foreign"); err != ErrMachineNotFound {
		t.Fatalf("a foreign device id materialized via the user refresh")
	}

	// The refresh is bounded: an oversized value is dropped, not truncated.
	presence.SetOnlineWithLoggedInUser("dev-login", now.Add(time.Second), strings.Repeat("x", 300))
	listMachines(t, srv)
	if m, _ := machines.GetMachine(context.Background(), "tenant-1", "dev-login"); m.LoggedInUser != "CORP\\bob" {
		t.Fatalf("oversized announcement overwrote logged_in_user: %q", m.LoggedInUser)
	}
}

// ----------------------------------------------------------------------------------------------
// Postgres: both projections, only-when-different, and RLS as the tenant filter
// ----------------------------------------------------------------------------------------------

// assertPgLoggedInUser reads logged_in_user through both independent pg projections.
// Reading only one is how 0032 and 0033 each shipped an always-empty column.
func assertPgLoggedInUser(t *testing.T, ctx context.Context, store *PgMachineStore, tid, mid, want, where string) {
	t.Helper()
	got, err := store.GetMachineByID(ctx, tid, mid)
	if err != nil {
		t.Fatalf("%s: GetMachineByID: %v", where, err)
	}
	if got.LoggedInUser != want {
		t.Fatalf("%s: selectMachine projection = %q, want %q", where, got.LoggedInUser, want)
	}
	list, err := store.ListMachines(ctx, tid)
	if err != nil {
		t.Fatalf("%s: ListMachines: %v", where, err)
	}
	found := false
	for i := range list {
		if list[i].ID != mid {
			continue
		}
		found = true
		if list[i].LoggedInUser != want {
			t.Fatalf("%s: ListMachines projection = %q, want %q (the SECOND, independent column list)",
				where, list[i].LoggedInUser, want)
		}
	}
	if !found {
		t.Fatalf("%s: machine %s missing from ListMachines", where, mid)
	}
}

// TestPgMachineLoggedInUserUnderRLS drives PgMachineStore as rmt_app: the column reaches both read
// projections, the refresh counts only real changes, silence never blanks, and a cross-tenant write
// cannot reach the row — proving RLS is the tenant filter.
func TestPgMachineLoggedInUserUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAttendedMigration(t, suPool)
	tidA, _ := provisionUser(t, suPool, "liu-a", "alice@liu-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "liu-b", "bob@liu-b.test", "password-5678")
	_, mid := seedGroupMachine(t, suPool, tidA, "liu-dev-a")
	ctx := context.Background()

	store := NewPgMachineStore(newAppRolePool(t, ctx))

	// Migration default: empty through both reads.
	assertPgLoggedInUser(t, ctx, store, tidA, mid, "", "the migration default")

	n, err := store.RecordLoggedInUser(ctx, tidA, map[string]string{"liu-dev-a": "CORP\\alice"})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if n != 1 {
		t.Fatalf("first report changed %d rows, want 1", n)
	}
	assertPgLoggedInUser(t, ctx, store, tidA, mid, "CORP\\alice", "after the first report")

	// IS DISTINCT FROM: the steady state writes nothing.
	if n, _ := store.RecordLoggedInUser(ctx, tidA, map[string]string{"liu-dev-a": "CORP\\alice"}); n != 0 {
		t.Fatalf("an unchanged user wrote %d rows, want 0", n)
	}

	// Silence must not blank the stored value.
	if n, _ := store.RecordLoggedInUser(ctx, tidA, map[string]string{"liu-dev-a": ""}); n != 0 {
		t.Fatalf("an empty report wrote %d rows, want 0", n)
	}
	assertPgLoggedInUser(t, ctx, store, tidA, mid, "CORP\\alice", "after a silent report")

	// A changed user (fast-user switch) lands.
	if n, _ := store.RecordLoggedInUser(ctx, tidA, map[string]string{"liu-dev-a": "CORP\\bob"}); n != 1 {
		t.Fatalf("a changed user must write 1 row")
	}
	assertPgLoggedInUser(t, ctx, store, tidA, mid, "CORP\\bob", "after a user change")

	// CROSS-TENANT. The presence feed hands this method other tenants' device ids as a matter of
	// course. There is no tenant_id predicate in the SQL — RLS is the filter.
	if n, _ := store.RecordLoggedInUser(ctx, tidB, map[string]string{"liu-dev-a": "evil\\attacker"}); n != 0 {
		t.Fatalf("a cross-tenant write reached %d rows, want 0", n)
	}
	assertPgLoggedInUser(t, ctx, store, tidA, mid, "CORP\\bob", "after a cross-tenant attempt")
}
