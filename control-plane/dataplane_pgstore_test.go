package controlplane

// DB-gated integration tests for the data-plane repositories (session records, management
// audit, tenants) and — the load-bearing one — the PgBinder per-request RLS pin, exercised as
// the least-privilege rmt_app role. Like every pgx test these SKIP without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// applyTenantProvisionMigration lays 0006 on top of whatever the test has applied (usually
// after applyAppRoleMigration's 0005 so the audit_event revoke actually fires).
func applyTenantProvisionMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0006_tenant_provision.sql")
	if err != nil {
		t.Fatalf("read 0006: %v", err)
	}
	execScript(t, pool, string(b))
}

// applyMgmtAuditChainMigration lays the audit_event hash-chain migrations on top of the schema
// newTestPool applied: 0014 (chain columns + per-tenant seq unique index) and 0016 (the
// integrity constraints that keep the chain from lying — see the migration header).
// PgMgmtAuditStore.RecordEvent writes the chain columns unconditionally, so every pg test that
// records management audit needs both. They travel together deliberately: a test running 0014
// without 0016 would exercise a schema no deployment has, and 0016 is exactly what makes the
// chain's guarantees true. Everything they add is dropped with the table by resetSchema.
func applyMgmtAuditChainMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, f := range []string{
		"migrations/0014_mgmt_audit_chain.sql",
		"migrations/0016_audit_chain_integrity.sql",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		execScript(t, pool, string(b))
	}
}

// seedGroupMachine adds a machine_group + machine to an EXISTING tenant (contrast
// seedTenantWithMachine, which creates the tenant too). Returns groupID, machineID, deviceID.
func seedGroupMachine(t *testing.T, pool *pgxpool.Pool, tid, deviceID string) (string, string) {
	t.Helper()
	ctx := context.Background()
	var gid, mid string
	if err := pool.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&gid, &mid); err != nil {
		t.Fatalf("gen uuids: %v", err)
	}
	if err := withTenant(ctx, pool, tid, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO machine_group (id, tenant_id, name) VALUES ($1,$2,'G')`, gid, tid); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO machine (id, tenant_id, device_id, group_id, hostname, pubkey)
			 VALUES ($1,$2,$3,$4,'HOST',$5)`, mid, tid, deviceID, gid, []byte{0})
		return err
	}); err != nil {
		t.Fatalf("seed group+machine: %v", err)
	}
	return gid, mid
}

// seedNamedMachine inserts ONE machine with a specific hostname into an existing tenant+group and
// returns its PK. Unlike seedGroupMachine (which names every machine 'HOST'), this lets a test exercise
// the hostname tie-break in the sessions-by-machine report.
func seedNamedMachine(t *testing.T, pool *pgxpool.Pool, tid, gid, deviceID, hostname string) string {
	t.Helper()
	ctx := context.Background()
	var mid string
	if err := pool.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&mid); err != nil {
		t.Fatalf("gen uuid: %v", err)
	}
	if err := withTenant(ctx, pool, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO machine (id, tenant_id, device_id, group_id, hostname, pubkey)
			 VALUES ($1,$2,$3,$4,$5,$6)`, mid, tid, deviceID, gid, hostname, []byte{0})
		return err
	}); err != nil {
		t.Fatalf("seed named machine: %v", err)
	}
	return mid
}

func TestPgSessionRecordStoreLifecycle(t *testing.T) {
	pool := newTestPool(t)
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	gid, mid := seedGroupMachine(t, pool, tid, "dev-sess")
	ctx := context.Background()

	store := NewPgSessionRecordStore(pool)
	rec := &SessionRecord{MachineID: mid, TechnicianID: uid, GrantedCaps: []string{"shell_open", "file_browse"}}
	if err := store.StartSession(ctx, tid, rec); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if rec.ID == "" || rec.StartedAt.IsZero() || rec.ConsentPolicy != "unattended" {
		t.Fatalf("started record = %+v", rec)
	}

	got, err := store.GetSession(ctx, tid, rec.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.MachineID != mid || got.TechnicianID != uid || got.MachineGroupID != gid ||
		got.MachineDeviceID != "dev-sess" || got.MachineName != "HOST" {
		t.Fatalf("joined record = %+v", got)
	}
	if len(got.GrantedCaps) != 2 || got.GrantedCaps[0] != "shell_open" {
		t.Fatalf("granted caps did not round-trip: %v", got.GrantedCaps)
	}
	if got.EndedAt != nil {
		t.Fatal("fresh session already ended")
	}

	list, err := store.ListSessions(ctx, tid, SessionSummaryFilter{})
	if err != nil || len(list) != 1 || list[0].ID != rec.ID {
		t.Fatalf("ListSessions = %+v, %v", list, err)
	}

	// End is idempotent: the second call keeps the first end time.
	end1 := time.Now().UTC().Truncate(time.Microsecond) // Postgres stores microseconds
	ended, err := store.EndSession(ctx, tid, rec.ID, end1)
	if err != nil {
		t.Fatalf("EndSession: %v", err)
	}
	if ended.EndedAt == nil || !ended.EndedAt.Equal(end1) {
		t.Fatalf("ended_at = %v, want %v", ended.EndedAt, end1)
	}
	again, err := store.EndSession(ctx, tid, rec.ID, end1.Add(time.Hour))
	if err != nil {
		t.Fatalf("re-EndSession: %v", err)
	}
	if !again.EndedAt.Equal(end1) {
		t.Fatalf("re-end moved ended_at: %v → %v", end1, again.EndedAt)
	}

	if _, err := store.GetSession(ctx, tid, newUUID()); err != ErrSessionRecordNotFound {
		t.Fatalf("unknown session err = %v, want ErrSessionRecordNotFound", err)
	}
}

// TestPgSessionRecordMachineAlias verifies that machine.alias is denormalized into sessions
// returned by GetSession, ListSessions, EndSession, and SetSessionNote, and that an alias set on
// tenant A's machine is invisible from tenant B's session list.
func TestPgSessionRecordMachineAlias(t *testing.T) {
	pool := newTestPool(t)
	tid, uid := provisionUser(t, pool, "acme", "alias-tech@acme.test", "pw-1234")
	_, mid := seedGroupMachine(t, pool, tid, "alias-dev")
	ctx := context.Background()

	// Set a friendly name directly on the machine row (migration 0032: alias text NOT NULL DEFAULT '').
	if _, err := pool.Exec(ctx, `UPDATE machine SET alias = 'Lobby PC' WHERE id = $1`, mid); err != nil {
		t.Fatalf("set alias: %v", err)
	}

	store := NewPgSessionRecordStore(pool)
	rec := &SessionRecord{MachineID: mid, TechnicianID: uid}
	if err := store.StartSession(ctx, tid, rec); err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	got, err := store.GetSession(ctx, tid, rec.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.MachineAlias != "Lobby PC" {
		t.Fatalf("GetSession MachineAlias = %q, want %q", got.MachineAlias, "Lobby PC")
	}

	list, err := store.ListSessions(ctx, tid, SessionSummaryFilter{})
	if err != nil || len(list) != 1 {
		t.Fatalf("ListSessions = %d rows, %v", len(list), err)
	}
	if list[0].MachineAlias != "Lobby PC" {
		t.Fatalf("ListSessions[0] MachineAlias = %q, want %q", list[0].MachineAlias, "Lobby PC")
	}

	// EndSession and SetSessionNote re-read the record; alias must survive both mutation re-reads.
	noted, err := store.SetSessionNote(ctx, tid, rec.ID, "follow-up done")
	if err != nil {
		t.Fatalf("SetSessionNote: %v", err)
	}
	if noted.MachineAlias != "Lobby PC" {
		t.Fatalf("SetSessionNote MachineAlias = %q, want %q", noted.MachineAlias, "Lobby PC")
	}

	ended, err := store.EndSession(ctx, tid, rec.ID, time.Now())
	if err != nil {
		t.Fatalf("EndSession: %v", err)
	}
	if ended.MachineAlias != "Lobby PC" {
		t.Fatalf("EndSession MachineAlias = %q, want %q", ended.MachineAlias, "Lobby PC")
	}

	// Cross-tenant isolation: tenant B must not see tenant A's sessions or aliases.
	// The superuser (pool) bypasses RLS even with FORCE ROW LEVEL SECURITY — a documented
	// PostgreSQL invariant (see rls_test.go / 0005_app_role.sql). Use rmt_app, the role
	// production connects as and which IS subject to RLS, to prove actual isolation.
	applyAppRoleMigration(t, pool)
	appPool := newAppRolePool(t, ctx)
	appStore := NewPgSessionRecordStore(appPool)
	tidB, _ := provisionUser(t, pool, "borg", "alias-tech@borg.test", "pw-5678")
	listB, err := appStore.ListSessions(ctx, tidB, SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("ListSessions tenant B: %v", err)
	}
	if len(listB) != 0 {
		t.Fatalf("ListSessions tenant B: got %d rows, want 0", len(listB))
	}
}

func TestPgMgmtAuditStore(t *testing.T) {
	pool := newTestPool(t)
	applyMgmtAuditChainMigration(t, pool)
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	_, mid := seedGroupMachine(t, pool, tid, "dev-audit")
	ctx := context.Background()

	store := NewPgMgmtAuditStore(pool)
	first := &MgmtAuditEvent{ActorUserID: uid, Action: "machine.enroll", TargetKind: "machine",
		TargetID: mid, Metadata: json.RawMessage(`{"device_id":"dev-audit"}`)}
	if err := store.RecordEvent(ctx, tid, first); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
	if first.ID == "" || first.OccurredAt.IsZero() {
		t.Fatalf("recorded event = %+v", first)
	}
	// Empty actor/target must store as NULL, not fail the uuid casts.
	if err := store.RecordEvent(ctx, tid, &MgmtAuditEvent{Action: "system.retention"}); err != nil {
		t.Fatalf("RecordEvent (no actor/target): %v", err)
	}

	events, err := store.ListEvents(ctx, tid, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("ListEvents len = %d, want 2", len(events))
	}
	// Newest first.
	if events[0].Action != "system.retention" || events[1].Action != "machine.enroll" {
		t.Fatalf("order = %s, %s", events[0].Action, events[1].Action)
	}
	if events[1].ActorUserID != uid || events[1].TargetID != mid {
		t.Fatalf("event round-trip = %+v", events[1])
	}
	var meta map[string]string
	if err := json.Unmarshal(events[1].Metadata, &meta); err != nil || meta["device_id"] != "dev-audit" {
		t.Fatalf("metadata round-trip = %s (%v)", events[1].Metadata, err)
	}
	if limited, _ := store.ListEvents(ctx, tid, 1); len(limited) != 1 {
		t.Fatalf("limit=1 returned %d", len(limited))
	}

	// 0014: both events came back chained — contiguous seq, genesis prev_hash, verifiable.
	if events[1].Seq == nil || *events[1].Seq != 0 || events[1].PrevHash != MgmtGenesisPrevHash {
		t.Fatalf("first chained event = %+v, want seq 0 with genesis prev_hash", events[1])
	}
	if events[0].Seq == nil || *events[0].Seq != 1 || events[0].PrevHash != events[1].Hash {
		t.Fatalf("second chained event = %+v, want seq 1 linking onto %q", events[0], events[1].Hash)
	}
	if res, err := VerifyMgmtAuditChain(ctx, store, tid); err != nil || !res.OK || res.CheckedEvents != 2 {
		t.Fatalf("verify = %+v (%v), want OK with 2 checked", res, err)
	}
}

// TestPgMgmtAuditFilter proves the audit search (docs/01 §5) against real Postgres: exact-match
// action and/or target_kind filters, applied BEFORE the limit (a newer non-matching event must not
// consume a limit slot), with hostile values treated as parameters not SQL.
func TestPgMgmtAuditFilter(t *testing.T) {
	pool := newTestPool(t)
	applyMgmtAuditChainMigration(t, pool)
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	ctx := context.Background()
	store := NewPgMgmtAuditStore(pool)

	// Record in this order (oldest → newest): the newest is a NON-machine event on purpose.
	for _, e := range []MgmtAuditEvent{
		{ActorUserID: uid, Action: "machine.enroll", TargetKind: "machine"},
		{ActorUserID: uid, Action: "session.start", TargetKind: "session"},
		{ActorUserID: uid, Action: "machine.enroll", TargetKind: "machine"},
		{ActorUserID: uid, Action: "machine.property.set", TargetKind: "machine"},
		{ActorUserID: uid, Action: "tenant.update", TargetKind: "tenant"},
	} {
		ev := e
		if err := store.RecordEvent(ctx, tid, &ev); err != nil {
			t.Fatalf("record %s: %v", e.Action, err)
		}
	}

	count := func(f AuditFilter, limit int) int {
		got, err := store.ListEventsFiltered(ctx, tid, limit, f)
		if err != nil {
			t.Fatalf("ListEventsFiltered(%+v, %d): %v", f, limit, err)
		}
		return len(got)
	}

	if n := count(AuditFilter{}, 0); n != 5 {
		t.Fatalf("no filter = %d, want 5", n)
	}
	if n := count(AuditFilter{Action: "machine.enroll"}, 0); n != 2 {
		t.Fatalf("action=machine.enroll = %d, want 2", n)
	}
	if n := count(AuditFilter{TargetKind: "machine"}, 0); n != 3 {
		t.Fatalf("target_kind=machine = %d, want 3", n)
	}
	if n := count(AuditFilter{Action: "machine.enroll", TargetKind: "machine"}, 0); n != 2 {
		t.Fatalf("action+kind both = %d, want 2", n)
	}
	if n := count(AuditFilter{Action: "session.start", TargetKind: "machine"}, 0); n != 0 {
		t.Fatalf("mismatched action+kind = %d, want 0", n)
	}
	// Limit is applied AFTER the filter: the newest event is tenant.update, but a session filter with
	// limit 1 must still return the (older) session event, not be pre-limited to the newer non-match.
	if n := count(AuditFilter{TargetKind: "session"}, 1); n != 1 {
		t.Fatalf("target_kind=session limit=1 = %d, want 1 (limit must apply after the filter)", n)
	}
	// A value nobody has → empty. (Also exercises the parameterization: a hostile value is data.)
	if n := count(AuditFilter{Action: "'; DROP TABLE audit_event;--"}, 0); n != 0 {
		t.Fatalf("hostile/absent action = %d, want 0", n)
	}
}

// TestPgMgmtAuditFilterActorAndTime proves the actor + closed-time-range filters against real
// Postgres as rmt_app: the WHERE clauses parameterize correctly (actor via a ::text compare, the
// bounds via timestamptz), the boundaries are inclusive, and a non-uuid actor matches nothing WITHOUT
// erroring (which a `$N::uuid` cast would). Mirrors TestInMemoryMgmtAuditFilterActorAndTime so the
// fake and the pg store cannot silently diverge.
func TestPgMgmtAuditFilterActorAndTime(t *testing.T) {
	pool := newTestPool(t)
	applyMgmtAuditChainMigration(t, pool)
	tid, _ := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	ctx := context.Background()
	store := NewPgMgmtAuditStore(pool)

	// actor_user_id is a uuid column (its FK was dropped in 0016), so actors are opaque uuids.
	alice := newUUID()
	bob := newUUID()
	t0 := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	seed := func(actor string, at time.Time) {
		if err := store.RecordEvent(ctx, tid,
			&MgmtAuditEvent{Action: "x", TargetKind: "machine", ActorUserID: actor, OccurredAt: at}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	seed(alice, t0)
	seed(bob, t0.Add(1*time.Hour))
	seed(alice, t0.Add(2*time.Hour))

	count := func(f AuditFilter) int {
		got, err := store.ListEventsFiltered(ctx, tid, 0, f)
		if err != nil {
			t.Fatalf("ListEventsFiltered(%+v): %v", f, err)
		}
		return len(got)
	}

	if n := count(AuditFilter{Actor: alice}); n != 2 {
		t.Fatalf("actor=alice = %d, want 2", n)
	}
	if n := count(AuditFilter{Actor: newUUID()}); n != 0 {
		t.Fatalf("unknown actor = %d, want 0", n)
	}
	if n := count(AuditFilter{Since: t0.Add(1 * time.Hour)}); n != 2 {
		t.Fatalf("since (inclusive) = %d, want 2", n)
	}
	if n := count(AuditFilter{Until: t0.Add(1 * time.Hour)}); n != 2 {
		t.Fatalf("until (inclusive) = %d, want 2", n)
	}
	if n := count(AuditFilter{Since: t0.Add(1 * time.Hour), Until: t0.Add(1 * time.Hour)}); n != 1 {
		t.Fatalf("closed single-instant range = %d, want 1", n)
	}
	if n := count(AuditFilter{Actor: alice, Since: t0.Add(2 * time.Hour)}); n != 1 {
		t.Fatalf("actor+since = %d, want 1", n)
	}
	// A non-uuid actor is data, matches nothing, and must NOT raise a cast error.
	if n := count(AuditFilter{Actor: "not-a-uuid"}); n != 0 {
		t.Fatalf("non-uuid actor = %d, want 0", n)
	}
}

// TestPgMgmtAuditChainTamperAndExport proves the chain catches a privileged in-place edit (the
// exact attack 0006's app-role REVOKE cannot stop) and that the ascending export walk pages
// correctly and stays tenant-isolated. The store runs as rmt_app (RLS-subject) like production:
// its tail read and ascending scan deliberately carry no tenant WHERE clause — RLS scopes them,
// so a superuser pool would (correctly) see cross-tenant rows and is only used to seed + tamper.
func TestPgMgmtAuditChainTamperAndExport(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyMgmtAuditChainMigration(t, suPool)
	tidA, _ := provisionUser(t, suPool, "acme", "tech@acme.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "borg", "tech@borg.test", "password-1234")
	ctx := context.Background()
	pool := newAppRolePool(t, ctx)
	store := NewPgMgmtAuditStore(pool)

	for i, action := range []string{"machine.enroll", "session.start", "session.end"} {
		if err := store.RecordEvent(ctx, tidA, &MgmtAuditEvent{Action: action,
			Metadata: json.RawMessage(`{"i":` + strconv.Itoa(i) + `}`)}); err != nil {
			t.Fatalf("record A %s: %v", action, err)
		}
	}
	if err := store.RecordEvent(ctx, tidB, &MgmtAuditEvent{Action: "tenant.create"}); err != nil {
		t.Fatalf("record B: %v", err)
	}

	// Ascending cursor walk: one event per page, tenant A only, seq 0..2.
	var walked []MgmtAuditEvent
	after := int64(-1)
	for {
		page, err := store.ListEventsAsc(ctx, tidA, after, 1)
		if err != nil {
			t.Fatalf("ListEventsAsc(after=%d): %v", after, err)
		}
		if len(page) == 0 {
			break
		}
		walked = append(walked, page...)
		after = *page[len(page)-1].Seq
	}
	if len(walked) != 3 {
		t.Fatalf("walked %d events, want 3", len(walked))
	}
	for i, e := range walked {
		if *e.Seq != int64(i) || e.TenantID != tidA {
			t.Fatalf("walked[%d] = %+v, want tenant-A seq %d", i, e, i)
		}
	}
	if res, err := VerifyMgmtAuditChain(ctx, store, tidA); err != nil || !res.OK || res.CheckedEvents != 3 {
		t.Fatalf("verify A = %+v (%v), want OK/3", res, err)
	}
	if res, err := VerifyMgmtAuditChain(ctx, store, tidB); err != nil || !res.OK || res.CheckedEvents != 1 {
		t.Fatalf("verify B = %+v (%v), want OK/1", res, err)
	}

	// A superuser edits a mid-chain row in place (bypassing RLS and the app-role REVOKE) —
	// verification must finger exactly that link.
	if ct, err := suPool.Exec(ctx,
		`UPDATE audit_event SET action = 'session.start.forged' WHERE tenant_id = $1::uuid AND seq = 1`,
		tidA); err != nil || ct.RowsAffected() != 1 {
		t.Fatalf("superuser tamper = %v (%d rows)", err, ct.RowsAffected())
	}
	res, err := VerifyMgmtAuditChain(ctx, store, tidA)
	if err != nil {
		t.Fatalf("verify tampered A: %v", err)
	}
	if res.OK || res.FirstBadSeq == nil || *res.FirstBadSeq != 1 ||
		!strings.Contains(res.Reason, "content hash") {
		t.Fatalf("verify tampered A = %+v, want !OK at seq 1 (content hash)", res)
	}
	// Tenant B's chain is untouched.
	if res, err := VerifyMgmtAuditChain(ctx, store, tidB); err != nil || !res.OK {
		t.Fatalf("verify B after A tamper = %+v (%v), want OK", res, err)
	}

	// A row inserted AROUND the chain (no seq/prev_hash/hash) is invisible to the walk — the
	// 0014 CHECK permits all-NULL chain fields and rmt_app keeps INSERT. Verification cannot
	// call that tampering, but it must not report a clean bill either: unchained_events is the
	// signal an auditor reads, so it counts such rows explicitly.
	if _, err := suPool.Exec(ctx,
		`INSERT INTO audit_event (tenant_id, action) VALUES ($1::uuid, 'session.end.forged')`,
		tidB); err != nil {
		t.Fatalf("insert unchained row: %v", err)
	}
	res, err = VerifyMgmtAuditChain(ctx, store, tidB)
	if err != nil {
		t.Fatalf("verify B after unchained insert: %v", err)
	}
	if res.UnchainedEvents != 1 || res.CheckedEvents != 1 {
		t.Fatalf("verify B = %+v, want 1 chained + 1 unchained reported", res)
	}
	// Tenant A's count is unaffected — CountUnchained is tenant-scoped.
	if resA, err := VerifyMgmtAuditChain(ctx, store, tidA); err != nil || resA.UnchainedEvents != 0 {
		t.Fatalf("verify A unchained = %+v (%v), want 0", resA, err)
	}
}

// TestPgMgmtAuditChainTenantScopedTail is the regression for a chain-corrupting tail read: the
// tail that decides the NEXT event's seq/prev_hash must be scoped to the tenant EXPLICITLY, not
// only by RLS. Run deliberately on the SUPERUSER pool (RLS-exempt — the posture a misconfigured
// DATABASE_URL produces): with an unfiltered tail read, tenant A's next event would be stamped
// onto tenant B's higher tail, permanently gapping A's chain.
func TestPgMgmtAuditChainTenantScopedTail(t *testing.T) {
	pool := newTestPool(t)
	applyMgmtAuditChainMigration(t, pool)
	tidA, _ := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	tidB, _ := provisionUser(t, pool, "borg", "tech@borg.test", "password-1234")
	ctx := context.Background()
	store := NewPgMgmtAuditStore(pool)

	// B's chain runs ahead of A's.
	for i := 0; i < 4; i++ {
		if err := store.RecordEvent(ctx, tidB, &MgmtAuditEvent{Action: "session.start"}); err != nil {
			t.Fatalf("record B: %v", err)
		}
	}
	if err := store.RecordEvent(ctx, tidA, &MgmtAuditEvent{Action: "machine.enroll"}); err != nil {
		t.Fatalf("record A: %v", err)
	}
	a2 := &MgmtAuditEvent{Action: "session.start"}
	if err := store.RecordEvent(ctx, tidA, a2); err != nil {
		t.Fatalf("record A2: %v", err)
	}
	if a2.Seq == nil || *a2.Seq != 1 {
		t.Fatalf("A's second event got seq %v, want 1 — the tail read leaked another tenant's chain", a2.Seq)
	}
	for _, tid := range []string{tidA, tidB} {
		if res, err := VerifyMgmtAuditChain(ctx, store, tid); err != nil || !res.OK {
			t.Fatalf("verify %s = %+v (%v), want OK", tid, res, err)
		}
	}
}

// TestPgMgmtAuditChainConcurrentAppends hammers one tenant's chain from parallel goroutines —
// the advisory-lock serialization must yield a contiguous, verifiable chain with no unique-
// index violations (the race the in-memory mutex used to hide).
func TestPgMgmtAuditChainConcurrentAppends(t *testing.T) {
	pool := newTestPool(t)
	applyMgmtAuditChainMigration(t, pool)
	tid, _ := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	ctx := context.Background()
	store := NewPgMgmtAuditStore(pool)

	const writers = 8
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			errs <- store.RecordEvent(ctx, tid, &MgmtAuditEvent{
				Action:   "session.start",
				Metadata: json.RawMessage(`{"writer":` + strconv.Itoa(i) + `}`),
			})
		}(i)
	}
	for i := 0; i < writers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent RecordEvent: %v", err)
		}
	}

	events, err := store.ListEventsAsc(ctx, tid, -1, 0)
	if err != nil || len(events) != writers {
		t.Fatalf("ListEventsAsc = %d events (%v), want %d", len(events), err, writers)
	}
	for i, e := range events {
		if *e.Seq != int64(i) {
			t.Fatalf("seq[%d] = %d, want %d (chain not contiguous under concurrency)", i, *e.Seq, i)
		}
	}
	if res, err := VerifyMgmtAuditChain(ctx, store, tid); err != nil || !res.OK || res.CheckedEvents != writers {
		t.Fatalf("verify = %+v (%v), want OK/%d", res, err, writers)
	}
}

// TestPgTenantStoreAsAppRole proves the provisioning asymmetry under the REAL app role:
// cp_create_tenant (SECURITY DEFINER) lets rmt_app provision a brand-new tenant, while RLS
// still confines its LISTING to its own tenant row — the new tenant never leaks into it.
func TestPgTenantStoreAsAppRole(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyTenantProvisionMigration(t, suPool)
	tid, _ := provisionUser(t, suPool, "own-tenant", "tech@own.test", "password-1234")
	ctx := context.Background()

	appPool := newAppRolePool(t, ctx)
	store := NewPgTenantStore(appPool)

	own, err := store.ListTenants(ctx, tid)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(own) != 1 || own[0].ID != tid || own[0].Slug != "own-tenant" {
		t.Fatalf("app-role tenant listing = %+v, want exactly the own row", own)
	}

	created := &Tenant{Slug: "provisioned-co", Name: "Provisioned Co", DeploymentMode: "saas"}
	if err := store.CreateTenant(ctx, tid, created); err != nil {
		t.Fatalf("CreateTenant as rmt_app: %v", err)
	}
	if created.ID == "" || created.CreatedAt.IsZero() {
		t.Fatalf("created tenant = %+v", created)
	}
	if err := store.CreateTenant(ctx, tid, &Tenant{Slug: "provisioned-co", Name: "Dup", DeploymentMode: "saas"}); err != ErrTenantSlugTaken {
		t.Fatalf("duplicate slug err = %v, want ErrTenantSlugTaken", err)
	}

	// Still only the own row: the freshly provisioned tenant is a different isolation domain.
	own, err = store.ListTenants(ctx, tid)
	if err != nil || len(own) != 1 || own[0].ID != tid {
		t.Fatalf("post-provision listing = %+v, %v (must stay the own row only)", own, err)
	}

	// It genuinely exists — visible to the RLS-bypassing superuser.
	var n int
	if err := suPool.QueryRow(ctx, "SELECT count(*) FROM tenant WHERE id = $1::uuid AND slug='provisioned-co'", created.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("provisioned tenant not found by superuser: n=%d err=%v", n, err)
	}
	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1::uuid", created.ID); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestPgBinderRequestScopedRLS is the binder's load-bearing proof, as rmt_app on a
// single-connection pool (so connection reuse across binds is actually exercised):
//
//	(1) a query on the BOUND connection (no withTenant) is already tenant-confined,
//	(2) the stores pick the bound connection up and stay confined,
//	(3) withTenant on a context bound to a DIFFERENT tenant fails loudly,
//	(4) release resets the GUC — the recycled connection serves the next tenant cleanly and
//	    an unpinned query on it RAISES rather than leaking.
func TestPgBinderRequestScopedRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAttendedMigration(t, suPool) // 0013: PgMachineStore projects machine.ephemeral/expires_at
	ctx := context.Background()

	var tenantA, tenantB string
	if err := suPool.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&tenantA, &tenantB); err != nil {
		t.Fatalf("gen tenant uuids: %v", err)
	}
	seedTenantWithMachine(t, suPool, tenantA, "bind-a")
	seedTenantWithMachine(t, suPool, tenantB, "bind-b")

	// rmt_app pool with EXACTLY ONE connection: every bind reuses the same physical conn.
	cfg, err := pgxpool.ParseConfig(testDBURL())
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.ConnConfig.User = "rmt_app"
	cfg.ConnConfig.Password = ""
	cfg.MaxConns = 1
	appPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect as rmt_app: %v", err)
	}
	t.Cleanup(appPool.Close)

	binder := NewPgBinder(appPool)

	if _, _, err := binder.BindTenant(ctx, ""); err == nil {
		t.Fatal("BindTenant accepted an empty tenant id")
	}

	ctxA, releaseARaw, err := binder.BindTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("BindTenant A: %v", err)
	}
	// The pool is MaxConns=1, so any t.Fatalf between here and the explicit release below would
	// leave the only connection checked out — and appPool.Close() (a t.Cleanup) then blocks
	// FOREVER waiting for it, turning a one-line assertion failure into a silent 10-minute
	// package timeout with the failure message never printed. Deferring the release fixes that
	// (test-body defers unwind before cleanups run); sync.OnceFunc keeps the explicit
	// mid-test release from double-releasing the connection.
	releaseA := sync.OnceFunc(releaseARaw)
	defer releaseA()

	// (1) The bound connection itself — the "general handler path", no withTenant — is confined.
	bc := boundConnFrom(ctxA)
	if bc == nil {
		t.Fatal("bound context carries no connection")
	}
	var n int
	var device string
	if err := bc.conn.QueryRow(ctxA, "SELECT count(*) FROM machine").Scan(&n); err != nil {
		t.Fatalf("bound-conn query: %v", err)
	}
	if n != 1 {
		t.Fatalf("bound conn (tenant A) sees %d machines, want 1", n)
	}
	if err := bc.conn.QueryRow(ctxA, "SELECT device_id FROM machine").Scan(&device); err != nil || device != "dev-bind-a" {
		t.Fatalf("bound conn sees device %q (%v), want dev-bind-a", device, err)
	}

	// (2) A store call with the bound context stays on the pinned connection and confined.
	machines, err := NewPgMachineStore(appPool).ListMachines(ctxA, tenantA)
	if err != nil {
		t.Fatalf("ListMachines via bound ctx: %v", err)
	}
	if len(machines) != 1 || machines[0].DeviceID != "dev-bind-a" {
		t.Fatalf("store via bound ctx = %+v", machines)
	}

	// (3) A store asked for tenant B on a context bound to tenant A must refuse.
	err = withTenant(ctxA, appPool, tenantB, func(pgx.Tx) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "tenant mismatch") {
		t.Fatalf("cross-tenant withTenant on bound ctx = %v, want tenant mismatch error", err)
	}

	releaseA()

	// (4a) The SAME physical connection, recycled unpinned: the RLS policy must RAISE (unset or
	// empty GUC), never return rows.
	err = appPool.QueryRow(ctx, "SELECT count(*) FROM machine").Scan(&n)
	if err == nil {
		t.Fatalf("released conn returned %d machine rows unpinned; must raise", n)
	}
	if !strings.Contains(err.Error(), "app.current_tenant") &&
		!strings.Contains(err.Error(), "invalid input syntax for type uuid") {
		t.Fatalf("unpinned query raised, but not on the tenant GUC: %v", err)
	}

	// (4b) Rebinding the same connection to tenant B serves B cleanly — no residue from A.
	ctxB, releaseB, err := binder.BindTenant(ctx, tenantB)
	if err != nil {
		t.Fatalf("BindTenant B: %v", err)
	}
	defer releaseB()
	if err := boundConnFrom(ctxB).conn.QueryRow(ctxB, "SELECT device_id FROM machine").Scan(&device); err != nil {
		t.Fatalf("bound-conn query (B): %v", err)
	}
	if device != "dev-bind-b" {
		t.Fatalf("rebound conn sees device %q, want dev-bind-b", device)
	}

	// Tidy up the seeded tenants (superuser).
	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tenantA, tenantB); err != nil {
		t.Fatalf("cleanup tenants: %v", err)
	}
}

// TestPgHandlerChainAsAppRole is the end-to-end DB proof: the full HTTP middleware chain
// (auth → PgBinder → handlers → pgx stores) against real Postgres AS rmt_app — enroll a
// machine, start/list/end a session, read the audit trail, provision + list tenants. Every
// row it touches goes through RLS on the request's bound connection.
func TestPgHandlerChainAsAppRole(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyTenantProvisionMigration(t, suPool)
	applyMgmtAuditChainMigration(t, suPool) // PgMgmtAuditStore writes chained rows (0014)
	applyAttendedMigration(t, suPool)       // 0013: PgMachineStore projects machine.ephemeral
	tid, uid := provisionUser(t, suPool, "e2e-tenant", "tech@e2e.test", "password-1234")
	gid, _ := seedGroupMachine(t, suPool, tid, "seeded-dev")
	ctx := context.Background()

	appPool := newAppRolePool(t, ctx)

	// Owner-tier principal (full caps) for the provisioned real user; the grant shape is what
	// SessionAuthenticator would compute — auth itself is already covered by the pg auth tests.
	principal := &Principal{
		UserID:   uid,
		TenantID: tid,
		Grant:    NewGrant(uid, tid, NewMembership(RoleOwner, AllGroups())),
	}
	srv := NewServer(StubAuthenticator{Principal: principal}, NewPgBinder(appPool))
	srv.Machines = NewPgMachineStore(appPool)
	srv.SessionRecords = NewPgSessionRecordStore(appPool)
	srv.MgmtAudit = NewPgMgmtAuditStore(appPool)
	srv.Tenants = NewPgTenantStore(appPool)

	// Enroll a machine (INSERT through RLS WITH CHECK as rmt_app).
	var enrolled struct {
		Machine Machine `json:"machine"`
	}
	if code := apiJSON(t, srv, "POST", "/enroll",
		`{"machine_id":"e2e-dev","group_id":"`+gid+`","name":"E2E"}`, &enrolled); code != http.StatusCreated {
		t.Fatalf("enroll = %d", code)
	}

	// Start a session on it, list it, end it.
	var started struct {
		Session SessionRecord `json:"session"`
	}
	if code := apiJSON(t, srv, "POST", "/sessions", `{"machine_id":"e2e-dev"}`, &started); code != http.StatusCreated {
		t.Fatalf("start session = %d", code)
	}
	sess := started.Session
	if sess.MachineID != enrolled.Machine.ID || sess.TechnicianID != uid || sess.MachineGroupID != gid {
		t.Fatalf("session = %+v", sess)
	}
	if len(sess.GrantedCaps) == 0 {
		t.Fatal("owner session carries no backstage caps")
	}
	var listed struct {
		Sessions []SessionRecord `json:"sessions"`
	}
	if code := apiJSON(t, srv, "GET", "/sessions", "", &listed); code != http.StatusOK || len(listed.Sessions) != 1 {
		t.Fatalf("list sessions = %d, %+v", code, listed.Sessions)
	}
	var ended struct {
		Session SessionRecord `json:"session"`
	}
	if code := apiJSON(t, srv, "POST", "/sessions/"+sess.ID+"/end", "", &ended); code != http.StatusOK || ended.Session.EndedAt == nil {
		t.Fatalf("end session = %d, %+v", code, ended.Session)
	}

	// Audit trail recorded the three mutations (newest first).
	var audit struct {
		Events []MgmtAuditEvent `json:"events"`
	}
	if code := apiJSON(t, srv, "GET", "/audit", "", &audit); code != http.StatusOK {
		t.Fatalf("list audit = %d", code)
	}
	var actions []string
	for _, e := range audit.Events {
		actions = append(actions, e.Action)
	}
	wantActions := []string{"session.end", "session.start", "machine.enroll"}
	if len(actions) != len(wantActions) {
		t.Fatalf("audit actions = %v, want %v", actions, wantActions)
	}
	for i := range wantActions {
		if actions[i] != wantActions[i] {
			t.Fatalf("audit actions = %v, want %v", actions, wantActions)
		}
	}

	// The legacy provisioning route is gone (platform operators use /platform/tenants); the caller's
	// listing is still only its own tenant.
	if code := apiJSON(t, srv, "POST", "/tenants", `{"slug":"e2e-newco","name":"E2E NewCo"}`, nil); code != http.StatusGone {
		t.Fatalf("legacy create tenant = %d, want 410", code)
	}
	var tenants struct {
		Tenants []Tenant `json:"tenants"`
	}
	if code := apiJSON(t, srv, "GET", "/tenants", "", &tenants); code != http.StatusOK {
		t.Fatalf("list tenants = %d", code)
	}
	if len(tenants.Tenants) != 1 || tenants.Tenants[0].ID != tid {
		t.Fatalf("tenant listing = %+v, want only the caller's tenant", tenants.Tenants)
	}

	// DB-enforced append-only: rmt_app cannot UPDATE the management audit trail (0006 revoke).
	err := withTenant(ctx, appPool, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE audit_event SET action = 'tampered'")
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("rmt_app UPDATE audit_event = %v, want permission denied", err)
	}

	// Cross-check via the superuser: the rows genuinely landed in the right tenant.
	var n int
	if err := suPool.QueryRow(ctx,
		"SELECT count(*) FROM session_record WHERE tenant_id = $1::uuid", tid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("session_record rows for tenant = %d (%v), want 1", n, err)
	}
	if err := suPool.QueryRow(ctx,
		"SELECT count(*) FROM audit_event WHERE tenant_id = $1::uuid", tid).Scan(&n); err != nil || n != 3 {
		t.Fatalf("audit_event rows for tenant = %d (%v), want 3 (enroll, start, end)", n, err)
	}
}

// TestPgMgmtAuditChainSurvivesPgNormalization pins the FALSE-TAMPER contract, which is the whole
// reason this chain hashes a canonical re-encoding rather than raw bytes: PostgreSQL NORMALIZES
// several of the values it hashes, so a preimage built from the spelling the CALLER used can
// differ from the preimage rebuilt from the spelling that READS BACK — and then GET /audit/verify
// reports tampering forever on a trail nobody touched. 0006 revokes UPDATE/DELETE from the app
// role, so such a row can never be repaired: permanent corruption, not a transient bug.
//
// The two normalizations that bite, both confirmed against a live server:
//   - jsonb numbers are `numeric`, which drops the sign of NEGATIVE ZERO ('{"a":-0}'::jsonb reads
//     back as {"a": 0}) while Go's encoding/json marshals a negative-zero float64 as "-0".
//   - the `uuid` type re-renders every accepted spelling canonically: braces are stripped and the
//     hyphens are OPTIONAL at each group boundary, so the 32-char dashless form reads back dashed.
//     That form is REACHABLE from outside — handleRevokeEnrollmentToken passes r.PathValue("id")
//     through to the audit target_id verbatim and pgx accepts a dashless uuid parameter — so one
//     crafted URL permanently breaks a tenant's chain.
//
// Each case gets its OWN tenant: a chain that breaks at seq 0 makes every later verify fail at
// that same seq, so sharing one tenant would smear the first bad value over every other case.
// The control cases pin normalizations that are already absorbed, so a fix cannot regress them.
func TestPgMgmtAuditChainSurvivesPgNormalization(t *testing.T) {
	pool := newTestPool(t)
	applyMgmtAuditChainMigration(t, pool)
	ctx := context.Background()
	store := NewPgMgmtAuditStore(pool)

	// build receives ids that really exist in this case's tenant (the uuid columns are FK-checked),
	// and returns them respelled into a form Postgres accepts and normalizes.
	for i, tc := range []struct {
		name  string
		build func(uid, mid string) MgmtAuditEvent
	}{
		// --- normalizations PG applies that the canonicalizer must absorb ---
		{"metadata negative zero", func(_, _ string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "session.start", Metadata: json.RawMessage(`{"delta":-0}`)}
		}},
		{"metadata negative zero with fraction", func(_, _ string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "session.start", Metadata: json.RawMessage(`{"delta":-0.0}`)}
		}},
		{"metadata negative zero nested in array", func(_, _ string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "session.start", Metadata: json.RawMessage(`{"a":{"b":[1,-0,3]}}`)}
		}},
		{"metadata negative zero in exponent form", func(_, _ string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "session.start", Metadata: json.RawMessage(`{"delta":-0e0}`)}
		}},
		{"target id dashless", func(_, mid string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "machine.enroll", TargetKind: "machine",
				TargetID: strings.ReplaceAll(mid, "-", "")}
		}},
		{"target id braced", func(_, mid string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "machine.enroll", TargetKind: "machine",
				TargetID: "{" + mid + "}"}
		}},
		{"target id uppercase dashless", func(_, mid string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "machine.enroll", TargetKind: "machine",
				TargetID: strings.ToUpper(strings.ReplaceAll(mid, "-", ""))}
		}},
		{"target id partially dashed", func(_, mid string) MgmtAuditEvent {
			// PG's uuid parser takes the hyphens independently, so dropping just the first one
			// is still the same uuid.
			return MgmtAuditEvent{Action: "machine.enroll", TargetKind: "machine",
				TargetID: strings.Replace(mid, "-", "", 1)}
		}},
		{"actor id dashless", func(uid, _ string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "totp.confirm", TargetKind: "user",
				ActorUserID: strings.ReplaceAll(uid, "-", ""), TargetID: uid}
		}},

		// --- controls: already-absorbed normalizations, pinned against regression ---
		{"target id uppercase dashed (control)", func(_, mid string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "machine.enroll", TargetKind: "machine",
				TargetID: strings.ToUpper(mid)}
		}},
		{"metadata key order (control)", func(_, _ string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "session.start", Metadata: json.RawMessage(`{"z":1,"a":2}`)}
		}},
		{"metadata exponent spelling (control)", func(_, _ string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "session.start", Metadata: json.RawMessage(`{"n":1e3}`)}
		}},
		{"metadata unicode escape (control)", func(_, _ string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "session.start", Metadata: json.RawMessage(`{"s":"caf\u00e9"}`)}
		}},
		{"metadata empty object (control)", func(_, _ string) MgmtAuditEvent {
			return MgmtAuditEvent{Action: "session.start", Metadata: json.RawMessage(`{}`)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := strconv.Itoa(i)
			tid, uid := provisionUser(t, pool, "norm"+n, "tech"+n+"@norm.test", "password-1234")
			_, mid := seedGroupMachine(t, pool, tid, "dev-norm-"+n)

			e := tc.build(uid, mid)
			if err := store.RecordEvent(ctx, tid, &e); err != nil {
				t.Fatalf("RecordEvent: %v", err)
			}
			res, err := VerifyMgmtAuditChain(ctx, store, tid)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !res.OK {
				t.Fatalf("chain reports TAMPER on an untampered trail: %+v\n"+
					"a value hashed at write time did not survive the Postgres round-trip, "+
					"and 0006's append-only REVOKE makes this row unrepairable", res)
			}
			if res.CheckedEvents != 1 {
				t.Fatalf("checked %d events, want 1", res.CheckedEvents)
			}
		})
	}
}

// TestPgMgmtAuditChainRoundTripGuard exercises RecordEvent's write-time round-trip guard: the
// re-hash of what the INSERT actually stored. Its whole purpose is to catch a Postgres
// normalization the canonicalizer does NOT absorb — and by construction no such normalization is
// known (any that were found got fixed, see TestPgMgmtAuditChainSurvivesPgNormalization), so the
// only honest way to test it is to simulate one via the `corrupt` seam.
//
// What must hold: the append FAILS LOUDLY and the transaction rolls back, leaving the chain
// exactly as it was. That is the entire value of the guard — the alternative is a row that is
// unrepairable under 0006's append-only REVOKE and makes verify report tamper forever.
func TestPgMgmtAuditChainRoundTripGuard(t *testing.T) {
	pool := newTestPool(t)
	applyMgmtAuditChainMigration(t, pool)
	tid, _ := provisionUser(t, pool, "guard", "tech@guard.test", "password-1234")
	ctx := context.Background()
	store := NewPgMgmtAuditStore(pool)

	if err := store.RecordEvent(ctx, tid, &MgmtAuditEvent{Action: "session.start"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Simulate storage rewriting a hashed field under us.
	store.corrupt = func(e *MgmtAuditEvent) { e.Action = e.Action + ".rewritten-by-storage" }
	err := store.RecordEvent(ctx, tid, &MgmtAuditEvent{Action: "machine.enroll"})
	if err == nil {
		t.Fatal("RecordEvent succeeded despite the stored row not re-hashing — the guard is dead")
	}
	if !strings.Contains(err.Error(), "refusing to append") {
		t.Fatalf("guard error = %v, want the 'refusing to append' explanation", err)
	}
	store.corrupt = nil

	// The refused append must have rolled back entirely: no half-written row, no consumed seq.
	res, verr := VerifyMgmtAuditChain(ctx, store, tid)
	if verr != nil {
		t.Fatalf("verify: %v", verr)
	}
	if !res.OK || res.CheckedEvents != 1 || res.UnchainedEvents != 0 {
		t.Fatalf("after a refused append verify = %+v, want ok with exactly the 1 seeded event", res)
	}
	// And the chain is still usable — the refusal did not burn the tenant's next seq.
	next := &MgmtAuditEvent{Action: "session.end"}
	if err := store.RecordEvent(ctx, tid, next); err != nil {
		t.Fatalf("append after a refused append: %v", err)
	}
	if next.Seq == nil || *next.Seq != 1 {
		t.Fatalf("next event got seq %v, want 1 — the refused append leaked a seq", next.Seq)
	}
}

// TestPgMgmtAuditChainLockWaitIsBounded proves an append REFUSES rather than queues when it
// cannot get its tenant's chain lock. The lock is held for microseconds in normal operation, so
// a long wait means a stuck transaction or a flood — and unauthenticated endpoints write audit
// events, so a flood needs no credentials. Unbounded waiters sit on pgxpool connections until
// the pool is empty and EVERY tenant stalls; bounded, the blast radius is one tenant getting
// fast, loud, fail-closed errors.
func TestPgMgmtAuditChainLockWaitIsBounded(t *testing.T) {
	pool := newTestPool(t)
	applyMgmtAuditChainMigration(t, pool)
	tid, _ := provisionUser(t, pool, "lockwait", "tech@lockwait.test", "password-1234")
	ctx := context.Background()
	store := NewPgMgmtAuditStore(pool)

	prev := mgmtAuditLockWait
	mgmtAuditLockWait = 300 * time.Millisecond
	defer func() { mgmtAuditLockWait = prev }()

	// Hold the tenant's chain lock on another connection, using the same key RecordEvent derives.
	holder, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire holder: %v", err)
	}
	defer holder.Release()
	htx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder tx: %v", err)
	}
	if _, err := htx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('mgmt_audit_chain:' || $1, 0))`,
		canonicalUUIDish(tid)); err != nil {
		t.Fatalf("hold lock: %v", err)
	}

	start := time.Now()
	err = store.RecordEvent(ctx, tid, &MgmtAuditEvent{Action: "session.start"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("RecordEvent succeeded while another transaction held the chain lock")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("contended append failed with %v, want the bounded-wait explanation", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("contended append took %s — it queued instead of giving up", elapsed)
	}

	// Releasing the lock restores normal service, and the refused append burned no seq.
	if err := htx.Rollback(ctx); err != nil {
		t.Fatalf("release holder: %v", err)
	}
	holder.Release()
	e := &MgmtAuditEvent{Action: "session.end"}
	if err := store.RecordEvent(ctx, tid, e); err != nil {
		t.Fatalf("append after the lock was released: %v", err)
	}
	if e.Seq == nil || *e.Seq != 0 {
		t.Fatalf("first surviving event got seq %v, want 0", e.Seq)
	}
	if res, err := VerifyMgmtAuditChain(ctx, store, tid); err != nil || !res.OK || res.CheckedEvents != 1 {
		t.Fatalf("verify = %+v (%v), want a clean 1-event chain", res, err)
	}
}
