package controlplane

// The machine.agent_version / agent_version_seen_at columns (migration 0039) — step 1 of agent
// auto-update (docs/21 §8), which exists to make "what is actually deployed out there" answerable.
//
// This file follows machine_require_session_policy_test.go's doctrine, because the column arrives by
// the same channel and carries the same hazards:
//
//  1. THE PROJECTION. PgMachineStore reads a machine row through two INDEPENDENT paths —
//     selectMachine/scanMachine (positional) and a SEPARATE inline SELECT+Scan inside ListMachines.
//     Nothing couples them at compile time, and migrations 0032 and 0033 each shipped a column that
//     was silently always-empty out of exactly one of them. Every pg assertion below reads BOTH.
//
//  2. THE FAKE AND THE STORE SHARE ONE CONTRACT. A test against InMemoryMachineStore says nothing
//     about the pg store's semantics. Every rule — empty skipped, oversized skipped, cross-tenant
//     skipped, only-when-different counted — is asserted against both.
//
// THE RULE THAT MATTERS MOST is that SILENCE MUST NEVER BLANK A STORED VERSION. Every other field on
// this path had to learn it the hard way: an older agent that reports nothing is not an agent
// reporting "unknown". If an empty value could overwrite, then a single pre-0039 agent reconnecting
// would erase the very data a rollout is being judged by, and it would do it silently.

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------------------------
// The fake
// ---------------------------------------------------------------------------------------------

func TestInMemoryRecordAgentVersion(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMachineStore()
	m := &Machine{DeviceID: "dev-1", GroupID: "g1", Name: "HOST"}
	if err := s.EnrollMachine(ctx, "t1", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// The default: a machine that has never reported has an UNKNOWN version, and unknown reads as
	// empty everywhere. It must not read as some plausible-looking default.
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.AgentVersion != "" {
		t.Fatalf("a fresh machine must have no version, got %q", got.AgentVersion)
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.AgentVersionSeenAt != nil {
		t.Fatalf("a fresh machine must have no seen_at stamp")
	}

	before := time.Now().UTC()
	n, err := s.RecordAgentVersion(ctx, "t1", map[string]string{"dev-1": "0.0.1+0594362"})
	if err != nil || n != 1 {
		t.Fatalf("record = (%d, %v), want (1, nil)", n, err)
	}
	got, _ := s.GetMachineByID(ctx, "t1", m.ID)
	if got.AgentVersion != "0.0.1+0594362" {
		t.Fatalf("version did not stick: %q", got.AgentVersion)
	}
	if got.AgentVersionSeenAt == nil || got.AgentVersionSeenAt.Before(before) {
		t.Fatalf("seen_at was not stamped on a real change: %v", got.AgentVersionSeenAt)
	}
	firstStamp := *got.AgentVersionSeenAt

	// ONLY-WHEN-DIFFERENT. The steady state writes nothing, which is what stops a console poll from
	// churning every row in the fleet — and it is also what keeps agent_version_seen_at meaning
	// "first observed" instead of degenerating into a second copy of last_seen. The pg store
	// enforces this in SQL via IS DISTINCT FROM; the fake must agree exactly.
	if n, _ := s.RecordAgentVersion(ctx, "t1", map[string]string{"dev-1": "0.0.1+0594362"}); n != 0 {
		t.Fatalf("an unchanged version counted %d rows, want 0", n)
	}
	got, _ = s.GetMachineByID(ctx, "t1", m.ID)
	if !got.AgentVersionSeenAt.Equal(firstStamp) {
		t.Fatalf("seen_at MOVED on an unchanged report: it must mark first observation, not liveness")
	}

	// A real upgrade moves both.
	if n, _ := s.RecordAgentVersion(ctx, "t1", map[string]string{"dev-1": "0.5.0+deadbee"}); n != 1 {
		t.Fatalf("an upgrade must count 1 row")
	}
	got, _ = s.GetMachineByID(ctx, "t1", m.ID)
	if got.AgentVersion != "0.5.0+deadbee" {
		t.Fatalf("upgrade did not advance the version: %q", got.AgentVersion)
	}
	// NOT `.After(firstStamp)`. Windows' time.Now() has ~15ms resolution, so two calls inside one
	// tick return an EQUAL instant and that assertion fails intermittently — it did on the first
	// run of this test. The provable property is that the stamp never goes BACKWARDS; that it MOVES
	// is pinned by the unchanged-report assertion above, which is the direction that actually
	// matters (a stamp that moved when nothing changed would mean it is tracking liveness, not
	// first observation).
	if got.AgentVersionSeenAt == nil || got.AgentVersionSeenAt.Before(firstStamp) {
		t.Fatalf("seen_at went backwards on an upgrade: %v -> %v", firstStamp, got.AgentVersionSeenAt)
	}

	// SILENCE MUST NOT BLANK. An empty value is "said nothing", never "reports unknown".
	if n, _ := s.RecordAgentVersion(ctx, "t1", map[string]string{"dev-1": ""}); n != 0 {
		t.Fatalf("an empty report must change nothing")
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.AgentVersion != "0.5.0+deadbee" {
		t.Fatalf("an empty report ERASED a stored version: %q", got.AgentVersion)
	}

	// Oversized is skipped, not truncated: the store holds its own invariant rather than trusting
	// signaling to have bounded it.
	if n, _ := s.RecordAgentVersion(ctx, "t1", map[string]string{"dev-1": strings.Repeat("x", maxAgentVersionLen+1)}); n != 0 {
		t.Fatalf("an oversized version must be skipped")
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.AgentVersion != "0.5.0+deadbee" {
		t.Fatalf("an oversized report overwrote a stored version: %q", got.AgentVersion)
	}
	// Exactly at the bound is accepted — establish the boundary from both sides, or the assertion
	// above would also pass on a store that rejected everything.
	atBound := strings.Repeat("y", maxAgentVersionLen)
	if n, _ := s.RecordAgentVersion(ctx, "t1", map[string]string{"dev-1": atBound}); n != 1 {
		t.Fatalf("an exactly-at-bound version must be accepted")
	}

	// A device id belonging to another tenant is silently skipped. The presence feed is cross-tenant
	// by construction, so this method is routinely handed ids it must not touch.
	if n, _ := s.RecordAgentVersion(ctx, "other-tenant", map[string]string{"dev-1": "9.9.9+ffffff"}); n != 0 {
		t.Fatalf("a cross-tenant write must count 0 rows")
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.AgentVersion != atBound {
		t.Fatalf("a cross-tenant write reached the row: %q", got.AgentVersion)
	}
}

// ---------------------------------------------------------------------------------------------
// Postgres: both projections, only-when-different, and RLS as the tenant filter
// ---------------------------------------------------------------------------------------------

// assertPgAgentVersion reads the stored version through BOTH independent pg projections and requires
// them to agree. Reading only one is how 0032 and 0033 each shipped an always-empty column.
func assertPgAgentVersion(t *testing.T, ctx context.Context, store *PgMachineStore, tid, mid, want, where string) {
	t.Helper()
	got, err := store.GetMachineByID(ctx, tid, mid)
	if err != nil {
		t.Fatalf("%s: GetMachineByID: %v", where, err)
	}
	if got.AgentVersion != want {
		t.Fatalf("%s: selectMachine projection = %q, want %q", where, got.AgentVersion, want)
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
		if list[i].AgentVersion != want {
			t.Fatalf("%s: ListMachines projection = %q, want %q (the SECOND, independent column list)",
				where, list[i].AgentVersion, want)
		}
	}
	if !found {
		t.Fatalf("%s: machine %s missing from ListMachines", where, mid)
	}
}

// TestPgMachineAgentVersionUnderRLS drives PgMachineStore as rmt_app: the columns reach BOTH read
// projections, the refresh counts only real changes, silence never blanks, and a cross-tenant write
// cannot reach the row — proving RLS is the tenant filter, since the SQL carries no tenant_id
// predicate by deliberate convention.
func TestPgMachineAgentVersionUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	// 0013: GetMachineByID's projection includes machine.ephemeral/expires_at. (0039 itself is
	// applied with the core in resetSchema, like 0032/0033/0037 — it is in both machine projections.)
	applyAttendedMigration(t, suPool)
	tidA, _ := provisionUser(t, suPool, "av-a", "a@av-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "av-b", "b@av-b.test", "password-1234")
	_, mid := seedGroupMachine(t, suPool, tidA, "dev-av")
	ctx := context.Background()

	store := NewPgMachineStore(newAppRolePool(t, ctx))

	// The migration DEFAULT '' — through both reads.
	assertPgAgentVersion(t, ctx, store, tidA, mid, "", "the migration default")

	n, err := store.RecordAgentVersion(ctx, tidA, map[string]string{"dev-av": "0.0.1+0594362"})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if n != 1 {
		t.Fatalf("first report changed %d rows, want 1", n)
	}
	assertPgAgentVersion(t, ctx, store, tidA, mid, "0.0.1+0594362", "after the first report")

	// IS DISTINCT FROM in SQL: the steady state writes nothing.
	if n, _ := store.RecordAgentVersion(ctx, tidA, map[string]string{"dev-av": "0.0.1+0594362"}); n != 0 {
		t.Fatalf("an unchanged version wrote %d rows, want 0", n)
	}

	// Silence must not blank the stored value.
	if n, _ := store.RecordAgentVersion(ctx, tidA, map[string]string{"dev-av": ""}); n != 0 {
		t.Fatalf("an empty report wrote %d rows, want 0", n)
	}
	assertPgAgentVersion(t, ctx, store, tidA, mid, "0.0.1+0594362", "after a silent agent reported")

	// An upgrade lands, and stamps seen_at.
	if n, _ := store.RecordAgentVersion(ctx, tidA, map[string]string{"dev-av": "0.5.0+deadbee"}); n != 1 {
		t.Fatalf("an upgrade must write 1 row")
	}
	assertPgAgentVersion(t, ctx, store, tidA, mid, "0.5.0+deadbee", "after an upgrade")
	got, err := store.GetMachineByID(ctx, tidA, mid)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.AgentVersionSeenAt == nil {
		t.Fatalf("agent_version_seen_at was never stamped by the pg UPDATE")
	}

	// CROSS-TENANT. The presence feed hands this method other tenants' device ids as a matter of
	// course. There is no tenant_id predicate in the SQL — RLS is the filter — so this is the
	// assertion that proves the posture rather than assuming it.
	if n, _ := store.RecordAgentVersion(ctx, tidB, map[string]string{"dev-av": "6.6.6+evil"}); n != 0 {
		t.Fatalf("a cross-tenant write reached %d rows, want 0", n)
	}
	assertPgAgentVersion(t, ctx, store, tidA, mid, "0.5.0+deadbee", "after a cross-tenant attempt")
}
