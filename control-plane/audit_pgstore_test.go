package controlplane

// Integration test for the pgx-backed AuditStore (H2). Like pgstore_test.go it requires a live
// PostgreSQL and is gated behind TEST_DATABASE_URL, so the default `go test ./...` (in-memory
// fakes) never needs a database. To run it:
//
//	TEST_DATABASE_URL=postgres://user:pass@localhost:5432/rmt_test go test ./...

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// applyAuditMigration adds 0004_audit.sql — and 0019, which the export's cursor column lives in —
// on top of the schema newTestPool already applied (0001–0003). It drops the table first so
// re-runs against a persistent test DB are clean.
//
// 0019 is applied here rather than in a separate helper because `PgAuditStore.AppendAudit` writes
// `ingest_seq` unconditionally: a test that laid down 0004 alone would fail on the INSERT, not on
// whatever it was actually asserting. Same reasoning as dataplane_pgstore_test.go's note about
// 0014 and the management chain columns.
func applyAuditMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	execScript(t, pool, `DROP TABLE IF EXISTS backstage_audit_event CASCADE;`)
	for _, f := range []string{"migrations/0004_audit.sql", "migrations/0019_backstage_audit_ingest_seq.sql", "migrations/0041_agent_audit_signatures.sql"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		execScript(t, pool, string(b))
	}
}

func TestPgAuditStoreAppendAndVerify(t *testing.T) {
	pool := newTestPool(t) // skips without TEST_DATABASE_URL; applies 0001–0003; Close via t.Cleanup
	applyAuditMigration(t, pool)

	tid, _ := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	store := NewPgAuditStore(pool)
	ctx := context.Background()

	const sess = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

	// Valid initial chain.
	initial := chainRange(sess, 0, 3)
	wantHash := initial[2].Hash
	tail, err := store.AppendAudit(ctx, tid, sess, initial)
	if err != nil {
		t.Fatalf("initial append: %v", err)
	}
	if tail.Seq != 2 || tail.Hash != wantHash {
		t.Fatalf("tail = %+v, want seq 2 hash %s", tail, wantHash)
	}

	// Continuation extends it.
	if _, err := store.AppendAudit(ctx, tid, sess, chainRange(sess, 3, 2)); err != nil {
		t.Fatalf("continuation: %v", err)
	}
	if got, _ := store.AuditTail(ctx, tid, sess); got.Seq != 4 {
		t.Fatalf("tail after continuation = %+v, want seq 4", got)
	}

	// Broken linkage rejected; tail unchanged (tx rolled back, nothing stored).
	bad := chainRange(sess, 5, 2)
	bad[0].PrevHash = hex64(999)
	if _, err := store.AppendAudit(ctx, tid, sess, bad); err == nil {
		t.Fatal("broken batch should be rejected")
	}
	if got, _ := store.AuditTail(ctx, tid, sess); got.Seq != 4 {
		t.Fatalf("tail after rejected batch = %+v, want seq 4 (unchanged)", got)
	}

	// Duplicate/replay rejected.
	if _, err := store.AppendAudit(ctx, tid, sess, chainRange(sess, 0, 1)); err == nil {
		t.Fatal("replayed seq 0 should be rejected")
	}

	// Cross-session isolation: a second session starts its own chain at seq 0.
	const sessB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	if _, err := store.AppendAudit(ctx, tid, sessB, chainRange(sessB, 0, 1)); err != nil {
		t.Fatalf("session B fresh chain: %v", err)
	}
	if got, _ := store.AuditTail(ctx, tid, sess); got.Seq != 4 {
		t.Fatalf("session A tail after B write = %+v, want seq 4", got)
	}
}

// TestPgBackstageAuditExportUnderRLS is the half the in-memory tests CANNOT carry.
//
// backstage_audit_export_test.go pins the handler and the cursor arithmetic against a map that
// hands back whatever it was given; it would stay green if `ListAuditEventsAsc`'s SELECT dropped a
// column, mangled a jsonb round-trip, ordered by text collation instead of uuid bytes, or ignored
// the tenant. Only a real Postgres can refute those, so this test:
//
//   - runs the export as the LEAST-PRIVILEGE rmt_app role, the role RLS is actually enforced for;
//   - re-hashes every exported row through recomputeHash, so a field that did not survive the
//     INSERT → SELECT round trip fails here rather than being discovered by a SIEM months later;
//   - pages across a CHAIN BOUNDARY, which is where an ordering/cursor mismatch shows up.
//
// **What each tenant assertion actually carries** — worth stating, because the obvious reading is
// wrong. Step (1)'s "no other tenant appeared" is satisfied by `ListAuditEventsAsc`'s own
// `WHERE tenant_id = $1`, so it holds even with the policy bypassed: running this whole test as
// superuser still passes it. RLS is therefore pinned SEPARATELY, in step (0), by reading the table
// with NO tenant predicate at all — once unpinned (must raise) and once bound to tenant A (must
// return only A's rows). Without step (0) the function's name would be an overclaim.
func TestPgBackstageAuditExportUnderRLS(t *testing.T) {
	suPool := newTestPool(t) // skips without TEST_DATABASE_URL
	applyAppRoleMigration(t, suPool)
	applyAuditMigration(t, suPool)
	ctx := context.Background()

	// Reproduce PRODUCTION's privilege posture on this table, which this fixture does not get for
	// free: production applies 0004 then 0005, so 0005's `GRANT ... ON ALL TABLES` covers
	// backstage_audit_event and its guarded `REVOKE UPDATE, DELETE` then makes it append-only.
	// Here 0005 runs FIRST (applyAppRoleMigration above), before the table exists — so the REVOKE
	// is skipped and 0005's ALTER DEFAULT PRIVILEGES silently hands the freshly-created table
	// SELECT/INSERT/UPDATE/DELETE. Without these two statements the append-only assertion at the
	// end of this test FAILS, which is how the gap was found: it had been passing only because an
	// unpinned UPDATE dies on the RLS GUC before privileges are ever consulted.
	//
	// Verified against the real migrated database (rmt_vm, migrations applied 0001..0019 in
	// order): rmt_app holds exactly INSERT + SELECT there.
	execScript(t, suPool, `
		GRANT SELECT, INSERT ON backstage_audit_event TO rmt_app;
		REVOKE UPDATE, DELETE ON backstage_audit_event FROM rmt_app;
	`)

	tidA, _ := provisionUser(t, suPool, "acme-export", "tech@acme-export.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "other-export", "tech@other-export.test", "password-1234")

	cfg, err := pgxpool.ParseConfig(testDBURL())
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.ConnConfig.User = "rmt_app"
	cfg.ConnConfig.Password = ""
	appPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect as rmt_app: %v", err)
	}
	t.Cleanup(appPool.Close)

	store := NewPgAuditStore(appPool)
	// The two chains are seeded in DESCENDING uuid order on purpose: sessA is ingested FIRST but
	// sorts SECOND. Ingest order and (session_id, seq) order therefore disagree, which is the only
	// arrangement that can tell the two apart. Seeding in ascending order — the obvious thing to
	// write — makes both orderings identical, and a mutation that reverted the export to the old
	// (session_id, seq) sort then passed this entire test.
	const sessA = "22222222-0000-0000-0000-000000000000" // ingested 1st, sorts 2nd
	const sessB = "11111111-0000-0000-0000-000000000000" // ingested 2nd, sorts 1st
	if _, err := store.AppendAudit(ctx, tidA, sessA, chainRange(sessA, 0, 3)); err != nil {
		t.Fatalf("seed chain A: %v", err)
	}
	if _, err := store.AppendAudit(ctx, tidA, sessB, chainRange(sessB, 0, 2)); err != nil {
		t.Fatalf("seed chain B: %v", err)
	}
	// Another tenant's chain, which must never appear in tenant A's export.
	const sessOther = "33333333-0000-0000-0000-000000000000"
	if _, err := store.AppendAudit(ctx, tidB, sessOther, chainRange(sessOther, 0, 2)); err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}

	// (0) RLS itself, pinned WITHOUT any tenant predicate — the only assertions here that the
	// store's own WHERE clause cannot satisfy. Unpinned, `current_setting('app.current_tenant')`
	// is unset and the policy must RAISE rather than return rows; pinned to tenant A, a bare
	// `SELECT count(*)` must see A's 5 rows and none of B's 2.
	var n int
	if err := appPool.QueryRow(ctx, `SELECT count(*) FROM backstage_audit_event`).Scan(&n); err == nil {
		t.Fatalf("rmt_app read backstage_audit_event UNPINNED (%d rows); RLS must raise", n)
	}
	if err := withTenant(ctx, appPool, tidA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM backstage_audit_event`).Scan(&n)
	}); err != nil {
		t.Fatalf("pinned count: %v", err)
	}
	if n != 5 {
		t.Fatalf("RLS-confined count = %d, want 5 (tenant A's rows only, with NO tenant_id in the query)", n)
	}

	// (1) Full export: both of tenant A's chains, in INGEST order, and NOTHING of B's.
	// NB: this particular assertion is also satisfied by the store's own WHERE tenant_id — see the
	// function doc. Step (0) is what makes the RLS claim in this test's name true.
	all, cursor, err := store.ListAuditEventsAsc(ctx, tidA, NewAuditExportQuery("", 0))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("exported %d events, want 5 (tenant A only)", len(all))
	}
	if cursor != 4 {
		t.Fatalf("cursor = %d, want 4 (ingest_seq of the 5th event, 0-based)", cursor)
	}
	for _, e := range all {
		if e.SessionID == sessOther {
			t.Fatalf("RLS leak: tenant B's session %s appeared in tenant A's export", e.SessionID)
		}
	}
	wantOrder := []struct {
		session string
		seq     uint64
	}{{sessA, 0}, {sessA, 1}, {sessA, 2}, {sessB, 0}, {sessB, 1}}
	for i, w := range wantOrder {
		if all[i].SessionID != w.session || all[i].Seq != w.seq {
			t.Fatalf("row %d = (%s,%d), want (%s,%d)", i, all[i].SessionID, all[i].Seq, w.session, w.seq)
		}
	}

	// (1b) ingest_seq is DENSE and per-tenant: tenant B's own trail starts at 0 too, so the
	// counter is not a global sequence leaking one tenant's volume to another.
	var bMin, bMax int64
	if err := withTenant(ctx, appPool, tidB, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT min(ingest_seq), max(ingest_seq) FROM backstage_audit_event`).Scan(&bMin, &bMax)
	}); err != nil {
		t.Fatalf("tenant B ingest_seq range: %v", err)
	}
	if bMin != 0 || bMax != 1 {
		t.Fatalf("tenant B ingest_seq range = [%d,%d], want [0,1] — the counter must be per-tenant and dense", bMin, bMax)
	}

	// (2) Every exported row must re-hash to its own hash — proof that the hashed columns survived
	// the INSERT → SELECT round trip. Dropping `occurred_at_ms` from the projection, or truncating
	// a uuid, breaks this here and only here.
	//
	// It does NOT catch jsonb reformatting `action`/`outcome`: the canonical encoder
	// (audit_canonical.go) DECODES them into typed variants and re-encodes in declaration order,
	// so whitespace and key order are deliberately outside the preimage. An earlier version of this
	// comment claimed otherwise — jsonb reformats on every round trip and the hash still matches.
	for i, e := range all {
		h, err := recomputeHash(e)
		if err != nil {
			t.Fatalf("row %d recomputeHash: %v", i, err)
		}
		if h != e.Hash {
			t.Fatalf("row %d (%s,%d) does not re-hash: got %s, stored %s", i, e.SessionID, e.Seq, h, e.Hash)
		}
	}

	// (3) Paging one row at a time, following the returned cursor, must reproduce the unpaged
	// order exactly — including across the A→B chain boundary.
	var paged []AuditEvent
	cur := NewAuditExportQuery("", 1)
	for i := 0; i < 25; i++ {
		page, next, err := store.ListAuditEventsAsc(ctx, tidA, cur)
		if err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
		if len(page) == 0 {
			break
		}
		if next == cur.AfterIngestSeq {
			t.Fatalf("cursor did not advance past %d — a collector would spin forever", next)
		}
		paged = append(paged, page[0])
		cur = AuditExportQuery{Limit: 1, AfterIngestSeq: next}
	}
	if len(paged) != len(all) {
		t.Fatalf("paged %d rows, unpaged %d", len(paged), len(all))
	}
	for i := range all {
		if paged[i].SessionID != all[i].SessionID || paged[i].Seq != all[i].Seq {
			t.Fatalf("paged row %d = (%s,%d), unpaged = (%s,%d)",
				i, paged[i].SessionID, paged[i].Seq, all[i].SessionID, all[i].Seq)
		}
	}

	// (4) THE REGRESSION CASE, against a real database: a collector that has drained the trail and
	// resumes from its cursor must see everything ingested afterwards — including a brand-new
	// session whose uuid sorts BELOW every session it has already read. The original
	// (session_id, seq) cursor returned nothing here, forever, and no in-memory test caught it
	// because none of them appended after exporting.
	const sessLow = "00000000-1111-1111-1111-111111111111" // sorts below BOTH seeded sessions
	if _, err := store.AppendAudit(ctx, tidA, sessLow, chainRange(sessLow, 0, 2)); err != nil {
		t.Fatalf("append a lower-sorting session after the drain: %v", err)
	}
	resumed, _, err := store.ListAuditEventsAsc(ctx, tidA, AuditExportQuery{AfterIngestSeq: cursor})
	if err != nil {
		t.Fatalf("resumed export: %v", err)
	}
	if len(resumed) != 2 {
		t.Fatalf("resumed export returned %d rows, want 2 — events ingested under a lower-sorting "+
			"session id must still reach a resuming collector", len(resumed))
	}
	for _, e := range resumed {
		if e.SessionID != sessLow {
			t.Fatalf("resumed export returned an unexpected session %s", e.SessionID)
		}
	}

	// (5) The session filter narrows to one chain and does not silently widen under the cursor.
	only, _, err := store.ListAuditEventsAsc(ctx, tidA, NewAuditExportQuery(sessB, 0))
	if err != nil {
		t.Fatalf("filtered export: %v", err)
	}
	if len(only) != 2 {
		t.Fatalf("filtered export returned %d rows, want 2", len(only))
	}
	for _, e := range only {
		if e.SessionID != sessB {
			t.Fatalf("filter leaked session %s", e.SessionID)
		}
	}

	// (6) DB-enforced append-only: the export path is read-only, and the role it runs as cannot
	// rewrite the trail it just read (0004's stated contract, enforced by 0005's REVOKE).
	//
	// The UPDATE runs TENANT-PINNED, and the error is matched. An unpinned UPDATE also fails — but
	// with `unrecognized configuration parameter "app.current_tenant"`, because the RLS policy
	// evaluates current_setting() before privileges are ever considered. Asserting only "err !=
	// nil" therefore passed on the GUC error and proved nothing about append-only: the REVOKE could
	// have been dropped entirely and this assertion would still have been green. Verified by hand
	// against the live database — pinned gives "permission denied for table
	// backstage_audit_event", unpinned gives the GUC error.
	updErr := withTenant(ctx, appPool, tidA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE backstage_audit_event SET hash = 'x'`)
		return err
	})
	if updErr == nil {
		t.Fatal("rmt_app UPDATE backstage_audit_event succeeded; the trail must be append-only")
	}
	if !strings.Contains(updErr.Error(), "permission denied") {
		t.Fatalf("UPDATE was refused, but not by privileges: %v — the append-only REVOKE (0005) is "+
			"what this asserts, so any other error means the assertion is passing for the wrong reason", updErr)
	}
}
