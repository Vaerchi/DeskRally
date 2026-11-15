package controlplane

// The machine.require_session_policy column (migration 0037) — the UNATTENDED half of the view-only
// floor. Store + BOTH pg projections + the enrollment write path + the presence refresh.
//
// The doctrine this file follows is the one attended_floor_pgstore_test.go's header states, applied
// to a machine column instead of an attended one:
//
//  1. THE PROJECTION. PgMachineStore reads a machine row through two INDEPENDENT code paths —
//     selectMachine/scanMachine (positional, pgstore.go) and a SEPARATE inline SELECT+Scan inside
//     ListMachines. Nothing couples them at compile time, so a column added to one and not the other
//     is a field that is silently always-false out of exactly one read. Migrations 0032 and 0033 both
//     hit that trap. Every pg assertion below therefore reads through BOTH.
//
//  2. THE FAKE AND THE STORE SHARE ONE CONTRACT. A test that only exercises InMemoryMachineStore says
//     nothing about the pg store's semantics, and vice versa. RecordRequireSessionPolicy's
//     only-when-different counting rule is asserted against both.
//
// Note the deliberate ASYMMETRY with 0036's attended flag: that one is write-once-true and its store
// rejects a caller-set value at Create. This one is neither. It mirrors what the AGENT says about
// itself, so it must be settable at enrollment AND flippable in both directions afterwards — an
// operator who clears the config flag has to be able to clear the column, or the machine keeps being
// minted policies for a floor that no longer exists.

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------------------------
// The fake
// ---------------------------------------------------------------------------------------------

func TestInMemoryRecordRequireSessionPolicy(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMachineStore()
	m := &Machine{DeviceID: "dev-1", GroupID: "g1", Name: "HOST"}
	if err := s.EnrollMachine(ctx, "t1", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// Default false: a machine that never reported never asked to floor.
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.RequireSessionPolicy {
		t.Fatalf("a fresh machine must not be flagged")
	}

	n, err := s.RecordRequireSessionPolicy(ctx, "t1", map[string]bool{"dev-1": true})
	if err != nil || n != 1 {
		t.Fatalf("record true = (%d, %v), want (1, nil)", n, err)
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); !got.RequireSessionPolicy {
		t.Fatalf("the flag did not stick")
	}

	// Only-when-DIFFERENT: the steady state writes nothing, so a console poll every few seconds does
	// not churn the table. The pg store enforces this in SQL; the fake must agree, or a test against
	// the fake proves nothing about production.
	if n, _ := s.RecordRequireSessionPolicy(ctx, "t1", map[string]bool{"dev-1": true}); n != 0 {
		t.Fatalf("re-reporting the same value counted %d changes, want 0", n)
	}

	// CLEARING must work. This is the direction 0036's attended flag deliberately forbids and the one
	// this column cannot live without: an operator who turns the config flag off has no other way to
	// tell the control plane.
	if n, _ := s.RecordRequireSessionPolicy(ctx, "t1", map[string]bool{"dev-1": false}); n != 1 {
		t.Fatalf("clearing the flag counted %d changes, want 1", n)
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.RequireSessionPolicy {
		t.Fatalf("the flag did not clear")
	}

	// Unknown and cross-tenant device ids are silently skipped, not errors: the presence feed is
	// cross-tenant and hands this method ids the tenant may not own.
	if n, _ := s.RecordRequireSessionPolicy(ctx, "t1", map[string]bool{"nope": true}); n != 0 {
		t.Fatalf("an unknown device must not count")
	}
	if n, _ := s.RecordRequireSessionPolicy(ctx, "t2", map[string]bool{"dev-1": true}); n != 0 {
		t.Fatalf("another tenant must not reach this machine")
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.RequireSessionPolicy {
		t.Fatalf("a cross-tenant write reached the row")
	}
	if n, _ := s.RecordRequireSessionPolicy(ctx, "t1", nil); n != 0 {
		t.Fatalf("an empty batch must be a no-op")
	}
}

// ---------------------------------------------------------------------------------------------
// The enrollment write path
// ---------------------------------------------------------------------------------------------

// TestRedeemEnrollmentPersistsTheReportedFloorFlag drives the real UNAUTHENTICATED handler and reads
// the stored machine back. All three wire shapes are exercised: `true` alone would pass against a
// hard-coded literal, `false` alone against a dropped field, and the ABSENT case is the older
// installer that must land on the column default rather than erroring.
func TestRedeemEnrollmentPersistsTheReportedFloorFlag(t *testing.T) {
	srv, _ := newTestServer(nil)
	ctx := context.Background()

	tok := &EnrollmentToken{GroupID: "g1", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 5}
	plaintext, err := srv.EnrollmentTokens.MintToken(ctx, "tenant-123", tok)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	pubHex := testPubkeyHex(t)

	for _, tc := range []struct {
		name  string
		field string
		want  bool
	}{
		{"reported true", `,"require_session_policy":true`, true},
		{"reported false", `,"require_session_policy":false`, false},
		{"absent (older installer)", ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out struct {
				Machine Machine `json:"machine"`
			}
			if code := apiJSON(t, srv, "POST", "/enroll/redeem",
				`{"token":"`+plaintext+`","pubkey":"`+pubHex+`","name":"KIOSK"`+tc.field+`}`,
				&out); code != http.StatusCreated {
				t.Fatalf("redeem = %d", code)
			}
			if out.Machine.RequireSessionPolicy != tc.want {
				t.Fatalf("echoed flag = %v, want %v", out.Machine.RequireSessionPolicy, tc.want)
			}
			// And it PERSISTED. The echo alone would pass on a handler that set the field on the
			// response struct after the store call, which is not the same thing at all.
			stored, err := srv.Machines.GetMachine(ctx, "tenant-123", out.Machine.DeviceID)
			if err != nil {
				t.Fatalf("GetMachine: %v", err)
			}
			if stored.RequireSessionPolicy != tc.want {
				t.Fatalf("stored flag = %v, want %v", stored.RequireSessionPolicy, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// The presence refresh — the hop that unstrands ALREADY-ENROLLED agents
// ---------------------------------------------------------------------------------------------

// TestListMachinesRefreshesTheReportedFloorFlag drives GET /machines with a presence feed reporting
// the flag, exactly as signaling would after a reconnect.
//
// This is the hop that matters most in practice. Enrollment runs once, from the config that was
// already on disk; an operator who sets require_session_policy on a machine already in the field
// never re-enrols, so without this refresh the fix would not reach the population it exists for.
func TestListMachinesRefreshesTheReportedFloorFlag(t *testing.T) {
	srv, machines, presence := presenceTestServer(t)
	seedMachine(t, machines, "dev-floor", "FLOOR-01")
	ctx := context.Background()

	presence.SetOnlineRequiringSessionPolicy("dev-floor", time.Now().UTC(), true)
	listMachines(t, srv)

	// Write-BEHIND, matching the machine.os refresh: the response still shows what the request READ,
	// and the next poll shows the refreshed value. So assert the STORE, not the response body.
	if m, _ := machines.GetMachine(ctx, "tenant-1", "dev-floor"); !m.RequireSessionPolicy {
		t.Fatalf("the presence-reported floor flag never reached machine.require_session_policy")
	}

	// CLEARING propagates the same way. Without it, turning the config flag off would leave the
	// machine flagged forever, minting `control` policies for a floor that no longer exists.
	presence.SetOnlineRequiringSessionPolicy("dev-floor", time.Now().UTC().Add(time.Second), false)
	listMachines(t, srv)
	if m, _ := machines.GetMachine(ctx, "tenant-1", "dev-floor"); m.RequireSessionPolicy {
		t.Fatalf("a reported FALSE did not clear the stored flag")
	}

	// A foreign tenant's device announcing the flag must neither materialize a row nor write one.
	presence.SetOnlineRequiringSessionPolicy("dev-foreign", time.Now().UTC(), true)
	listMachines(t, srv)
	if _, err := machines.GetMachine(ctx, "tenant-1", "dev-foreign"); err != ErrMachineNotFound {
		t.Fatalf("a foreign device id materialized via the floor refresh: %v", err)
	}
}

// TestAnUnreportingAgentNeverClearsTheStoredFloorFlag is the other half, and the sharper one.
//
// SILENCE IS NOT FALSE. A pre-loop-86 agent sends no require_session_policy at all. If the refresh
// read a missing field as a reported `false`, the very act of an older agent connecting would clear
// a flag its operator had deliberately set — re-creating the stranding this migration exists to
// prevent, except caused by the fix rather than by the gap.
func TestAnUnreportingAgentNeverClearsTheStoredFloorFlag(t *testing.T) {
	srv, machines, presence := presenceTestServer(t)
	ctx := context.Background()
	m := &Machine{
		TenantID:             "tenant-1",
		DeviceID:             "dev-silent",
		GroupID:              "g1",
		Name:                 "OLD-01",
		RequireSessionPolicy: true,
	}
	if err := machines.EnrollMachine(ctx, "tenant-1", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// Online, announcing nothing about a floor — the pre-loop-86 agent shape.
	presence.SetOnline("dev-silent", time.Now().UTC())
	listMachines(t, srv)

	if got, _ := machines.GetMachine(ctx, "tenant-1", "dev-silent"); !got.RequireSessionPolicy {
		t.Fatalf("an agent that reported NOTHING cleared the stored flag — silence was read as false")
	}
}

// ---------------------------------------------------------------------------------------------
// Postgres: both projections, the INSERT, and RLS
// ---------------------------------------------------------------------------------------------

// TestPgMachineRequireSessionPolicyUnderRLS drives PgMachineStore as rmt_app: the column reaches BOTH
// read projections, the refresh counts only real changes, clearing works, and a cross-tenant write
// cannot reach the row.
func TestPgMachineRequireSessionPolicyUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	// 0013: GetMachineByID's projection includes machine.ephemeral/expires_at. (0037 itself is
	// applied with the core in resetSchema, like 0032/0033 — it is in both machine projections.)
	applyAttendedMigration(t, suPool)
	tidA, _ := provisionUser(t, suPool, "rsp-a", "a@rsp-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "rsp-b", "b@rsp-b.test", "password-1234")
	_, mid := seedGroupMachine(t, suPool, tidA, "dev-rsp")
	ctx := context.Background()

	store := NewPgMachineStore(newAppRolePool(t, ctx))

	// The column DEFAULT: a row seeded without it is not flagged, through both reads.
	assertPgFloorFlag(t, ctx, store, tidA, mid, false, "the migration default")

	n, err := store.RecordRequireSessionPolicy(ctx, tidA, map[string]bool{"dev-rsp": true})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if n != 1 {
		t.Fatalf("record true changed %d rows, want 1", n)
	}
	assertPgFloorFlag(t, ctx, store, tidA, mid, true, "after reporting true")

	// `IS DISTINCT FROM` in the UPDATE means the steady state writes nothing.
	if n, err := store.RecordRequireSessionPolicy(ctx, tidA, map[string]bool{"dev-rsp": true}); err != nil || n != 0 {
		t.Fatalf("re-reporting the same value = (%d, %v), want (0, nil)", n, err)
	}

	if n, err := store.RecordRequireSessionPolicy(ctx, tidA, map[string]bool{"dev-rsp": false}); err != nil || n != 1 {
		t.Fatalf("clearing = (%d, %v), want (1, nil)", n, err)
	}
	assertPgFloorFlag(t, ctx, store, tidA, mid, false, "after reporting false")

	// CROSS-TENANT: RLS is the only tenant filter in that UPDATE (there is no explicit tenant_id
	// predicate), so this is the assertion that proves the filter is real.
	if _, err := store.RecordRequireSessionPolicy(ctx, tidA, map[string]bool{"dev-rsp": true}); err != nil {
		t.Fatalf("re-set: %v", err)
	}
	n, err = store.RecordRequireSessionPolicy(ctx, tidB, map[string]bool{"dev-rsp": false})
	if err != nil {
		t.Fatalf("cross-tenant record errored (it should silently skip): %v", err)
	}
	if n != 0 {
		t.Fatalf("a cross-tenant write counted %d rows, want 0", n)
	}
	assertPgFloorFlag(t, ctx, store, tidA, mid, true, "after a cross-tenant attempt")

	// An empty batch short-circuits before touching the pool.
	if n, err := store.RecordRequireSessionPolicy(ctx, tidA, nil); err != nil || n != 0 {
		t.Fatalf("empty batch = (%d, %v), want (0, nil)", n, err)
	}
}

// TestPgEnrollMachinePersistsTheFloorFlag pins the CREATE half: the INSERT's fixed column list must
// carry require_session_policy, or a fresh enrollment silently lands on the default no matter what
// the agent reported. The fake copies the caller's whole struct, so it cannot catch this.
func TestPgEnrollMachinePersistsTheFloorFlag(t *testing.T) {
	suPool := newTestPool(t)
	applyAttendedMigration(t, suPool)
	tid, _ := provisionUser(t, suPool, "rsp-enroll", "a@rsp-enroll.test", "password-1234")
	gid, _ := seedGroupMachine(t, suPool, tid, "dev-other")
	ctx := context.Background()

	store := NewPgMachineStore(newAppRolePool(t, ctx))
	m := &Machine{
		DeviceID:             "dev-enrolled-flagged",
		GroupID:              gid,
		Name:                 "HOST",
		Pubkey:               "00",
		RequireSessionPolicy: true,
	}
	if err := store.EnrollMachine(ctx, tid, m); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	assertPgFloorFlag(t, ctx, store, tid, m.ID, true, "enrolled with the flag set")

	// The negative control: enrolling WITHOUT it must not fabricate a floor.
	plain := &Machine{DeviceID: "dev-enrolled-plain", GroupID: gid, Name: "HOST", Pubkey: "00"}
	if err := store.EnrollMachine(ctx, tid, plain); err != nil {
		t.Fatalf("enroll plain: %v", err)
	}
	assertPgFloorFlag(t, ctx, store, tid, plain.ID, false, "enrolled without the flag")
}

// assertPgFloorFlag reads the machine through BOTH pg projections and requires them to agree with
// `want`. The two are separate SELECT+Scan pairs with no compile-time coupling — checking only one
// is how migrations 0032 and 0033 each shipped a field that was silently always-false out of the
// other. `where` names the moment, so a failure says which step diverged.
func assertPgFloorFlag(t *testing.T, ctx context.Context, store *PgMachineStore, tid, mid string, want bool, where string) {
	t.Helper()
	got, err := store.GetMachineByID(ctx, tid, mid)
	if err != nil {
		t.Fatalf("%s: GetMachineByID: %v", where, err)
	}
	if got.RequireSessionPolicy != want {
		t.Fatalf("%s: selectMachine projection = %v, want %v", where, got.RequireSessionPolicy, want)
	}
	list, err := store.ListMachines(ctx, tid)
	if err != nil {
		t.Fatalf("%s: ListMachines: %v", where, err)
	}
	var listed *Machine
	for i := range list {
		if list[i].ID == mid {
			listed = &list[i]
		}
	}
	if listed == nil {
		t.Fatalf("%s: machine %s missing from ListMachines", where, mid)
	}
	if listed.RequireSessionPolicy != want {
		t.Fatalf("%s: the SEPARATE inline ListMachines projection = %v, want %v — the column reaches "+
			"one machine read but not the other", where, listed.RequireSessionPolicy, want)
	}
}

// Audit #9: the agent-reported grant-key posture reaches the machine list so the console can flag a
// machine whose view-only mandate / lease / grants are advisory. Live only; silence stays unknown.
func TestListMachinesSurfacesGrantKeyPosture(t *testing.T) {
	srv, machines, presence := presenceTestServer(t)
	seedMachine(t, machines, "dev-pinned", "PINNED-01")
	seedMachine(t, machines, "dev-unpinned", "UNPINNED-01")
	seedMachine(t, machines, "dev-silent", "OLD-01")
	now := time.Now().UTC()
	presence.SetOnlineWithGrantKeyPinned("dev-pinned", now, true)
	presence.SetOnlineWithGrantKeyPinned("dev-unpinned", now, false)
	presence.SetOnline("dev-silent", now)

	got := map[string]*bool{}
	for _, m := range listMachines(t, srv).Machines {
		got[m.DeviceID] = m.GrantKeyPinned
	}
	if p := got["dev-pinned"]; p == nil || !*p {
		t.Fatalf("pinned machine posture = %v, want true", p)
	}
	if p := got["dev-unpinned"]; p == nil || *p {
		t.Fatalf("unpinned machine posture = %v, want explicit false", p)
	}
	if got["dev-silent"] != nil {
		t.Fatalf("an agent that reports no posture must stay unknown (nil), got %v", *got["dev-silent"])
	}
}
