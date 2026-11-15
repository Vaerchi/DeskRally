package controlplane

// The Postgres half of audit_idempotent_test.go: the same re-send, overlap and fork cases against
// PgAuditStore, counting rows in the table itself, so the fake and the real store cannot drift
// apart. Like every pgx test this SKIPs without TEST_DATABASE_URL (verify-all treats a skip as a
// failure).

import (
	"context"
	"testing"
)

func TestPgAuditIdempotentResendOverlapAndFork(t *testing.T) {
	pool := newTestPool(t)
	applyAuditMigration(t, pool)
	tid, _ := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	store := NewPgAuditStore(pool)
	ctx := context.Background()
	const sess = "cccccccc-cccc-cccc-cccc-cccccccccccc"

	rows := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM backstage_audit_event WHERE session_id = $1`, sess).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	ingestSeqs := func() (int, int64) {
		t.Helper()
		var n int
		var max int64
		if err := pool.QueryRow(ctx,
			`SELECT count(*), coalesce(max(ingest_seq), -1) FROM backstage_audit_event WHERE tenant_id = $1`,
			tid).Scan(&n, &max); err != nil {
			t.Fatalf("ingest_seq: %v", err)
		}
		return n, max
	}

	batch := chainRange(sess, 0, 3)
	if _, err := store.AppendAudit(ctx, tid, sess, batch); err != nil {
		t.Fatalf("initial: %v", err)
	}

	// 1. The lost-2xx re-send: success, the stored tail, no new rows.
	tail, err := store.AppendAudit(ctx, tid, sess, batch)
	if err != nil {
		t.Fatalf("re-send must succeed: %v", err)
	}
	if tail.Seq != 2 || tail.Hash != batch[2].Hash || rows() != 3 {
		t.Fatalf("after re-send: tail=%+v rows=%d, want seq 2 and 3 rows", tail, rows())
	}

	// 2. Overlap: only the suffix is inserted, and ingest_seq stays dense (no gap, no duplicate).
	over := chainRange(sess, 1, 4) // seq 1..4
	if tail, err = store.AppendAudit(ctx, tid, sess, over); err != nil {
		t.Fatalf("overlap: %v", err)
	}
	if tail.Seq != 4 || rows() != 5 {
		t.Fatalf("after overlap: tail=%+v rows=%d, want seq 4 and 5 rows", tail, rows())
	}
	if n, max := ingestSeqs(); int64(n) != max+1 {
		t.Fatalf("ingest_seq not dense: %d rows, max %d", n, max)
	}

	// 3. A range ending before the tail, and a fork at the tail: refused, nothing stored.
	if _, err := store.AppendAudit(ctx, tid, sess, chainRange(sess, 0, 2)); err == nil {
		t.Fatal("a stored range ending before the tail must be refused")
	}
	if _, err := store.AppendAudit(ctx, tid, sess, forkFrom(sess, 4, 3, 5)); err == nil {
		t.Fatal("a fork at the tail must be refused")
	}
	if _, err := store.AppendAudit(ctx, tid, sess, nil); err == nil {
		t.Fatal("an empty batch must be refused")
	}
	if got, _ := store.AuditTail(ctx, tid, sess); got.Seq != 4 || rows() != 5 {
		t.Fatalf("after refusals: tail=%+v rows=%d, want seq 4 and 5 rows", got, rows())
	}
}
