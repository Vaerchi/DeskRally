package controlplane

// DB-gated tests for migration 0016 — the schema-level integrity of the management audit chain.
// These cover the two ways the chain could be made to LIE that no amount of Go-side care can
// prevent, because both happen underneath the store:
//
//   - a referential action REWRITING a hashed column (false positive: verify cries tamper on an
//     honest trail, permanently, because 0006 revokes UPDATE/DELETE so nothing can repair it), and
//   - a row planted where the walk cannot see it (false negative: verify reports a fully-covered
//     intact chain over forged data).
//
// Like every pgx test they SKIP without TEST_DATABASE_URL.

import (
	"context"
	"strings"
	"testing"
)

// TestPgMgmtAuditChainSurvivesActorDeletion is the regression test for the worst defect this
// chain has had: a SCHEMA-level rewrite of a hashed field.
//
// 0001_core.sql declared `actor_user_id uuid REFERENCES app_user(id) ON DELETE SET NULL`, and
// actor_user_id is inside the hashed preimage. Deleting an app_user therefore made PostgreSQL's
// referential-action trigger NULL that column on every audit row the user ever generated —
// running with the table owner's privileges, so 0006's REVOKE did not apply, and bypassing RLS —
// while leaving seq/prev_hash/hash alone. Verify then re-hashed lpStr("") where lpStr(uuid) had
// been hashed and reported "a field was altered", permanently, for that event and every event
// after it. Ordinary user offboarding would have destroyed the tenant's audit attestation.
//
// Note what does NOT catch this: RecordEvent's write-time round-trip guard sees a perfectly
// consistent row, because the rewrite happens LATER. Only the schema can prevent it, which is why
// 0016 drops the constraint outright.
func TestPgMgmtAuditChainSurvivesActorDeletion(t *testing.T) {
	pool := newTestPool(t)
	applyMgmtAuditChainMigration(t, pool)
	tid, uid := provisionUser(t, pool, "offboard", "leaver@offboard.test", "password-1234")
	ctx := context.Background()
	store := NewPgMgmtAuditStore(pool)

	for _, action := range []string{"session.start", "totp.confirm", "session.end"} {
		if err := store.RecordEvent(ctx, tid, &MgmtAuditEvent{
			ActorUserID: uid, Action: action, TargetKind: "user", TargetID: uid,
		}); err != nil {
			t.Fatalf("record %s: %v", action, err)
		}
	}
	if res, err := VerifyMgmtAuditChain(ctx, store, tid); err != nil || !res.OK || res.CheckedEvents != 3 {
		t.Fatalf("baseline verify = %+v (%v), want a clean 3-event chain", res, err)
	}

	// Offboard the user the way an operator (or a GDPR erasure job) would.
	if _, err := pool.Exec(ctx, `DELETE FROM app_user WHERE id = $1::uuid`, uid); err != nil {
		t.Fatalf("delete the actor: %v", err)
	}

	res, err := VerifyMgmtAuditChain(ctx, store, tid)
	if err != nil {
		t.Fatalf("verify after deleting the actor: %v", err)
	}
	if !res.OK {
		t.Fatalf("deleting an app_user broke the audit chain: %+v\n"+
			"a referential action rewrote actor_user_id, which is a HASHED field — and because "+
			"0006 revokes UPDATE/DELETE from the app role, such a row can never be repaired", res)
	}
	if res.CheckedEvents != 3 {
		t.Fatalf("verify after deletion checked %d events, want 3", res.CheckedEvents)
	}
	// The actor id must still be RECORDED — an audit trail says what happened, and that has to
	// outlive the actor. A dangling id is the correct outcome here, not a NULL.
	events, err := store.ListEvents(ctx, tid, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, e := range events {
		if e.ActorUserID != uid {
			t.Fatalf("event %s lost its actor after the user row was deleted: %q, want %q",
				e.Action, e.ActorUserID, uid)
		}
	}
}

// TestAuditEventSchemaProtectsHashedColumns is the structural guard behind the fix above: no
// column feeding the mgmt-audit preimage may be the target of a referential action that REWRITES
// it. Such an action mutates a hashed field without touching the hash — a permanent false tamper,
// the class this review round was about. Asserting it against the catalog means a future
// migration that re-adds such a constraint fails HERE rather than in production a year later.
//
// ON DELETE CASCADE is deliberately allowed: it removes whole rows rather than rewriting a hashed
// field, so it cannot desynchronize a row from its own hash.
func TestAuditEventSchemaProtectsHashedColumns(t *testing.T) {
	pool := newTestPool(t)
	applyMgmtAuditChainMigration(t, pool)
	ctx := context.Background()

	// The columns fed into mgmtAuditPreimage (mgmtaudit_canonical.go).
	hashed := map[string]bool{
		"id": true, "tenant_id": true, "actor_user_id": true, "action": true,
		"target_kind": true, "target_id": true, "occurred_at": true, "metadata": true,
		"prev_hash": true, "seq": true,
	}

	rows, err := pool.Query(ctx, `
		SELECT c.conname, a.attname, c.confupdtype::text, c.confdeltype::text
		FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid
		JOIN unnest(c.conkey) AS k(attnum) ON true
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
		WHERE t.relname = 'audit_event' AND c.contype = 'f'
	`)
	if err != nil {
		t.Fatalf("read foreign keys: %v", err)
	}
	defer rows.Close()
	checked := 0
	for rows.Next() {
		var name, col, onUpdate, onDelete string
		if err := rows.Scan(&name, &col, &onUpdate, &onDelete); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !hashed[col] {
			continue
		}
		checked++
		// 'n' = SET NULL, 'd' = SET DEFAULT, 'c' = CASCADE. On DELETE, cascade removes the row
		// (safe); on UPDATE, cascade rewrites the value (not safe).
		for _, bad := range []struct{ action, got, forbidden string }{
			{"ON DELETE", onDelete, "n"}, {"ON DELETE", onDelete, "d"},
			{"ON UPDATE", onUpdate, "n"}, {"ON UPDATE", onUpdate, "d"}, {"ON UPDATE", onUpdate, "c"},
		} {
			if bad.got == bad.forbidden {
				t.Fatalf("constraint %s puts a REWRITING referential action (%s = %q) on "+
					"audit_event.%s, which is a HASHED column: any such rewrite silently "+
					"desynchronizes the row from its hash and false-tampers the chain forever "+
					"(0006 makes it unrepairable)", name, bad.action, bad.got, col)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	// tenant_id's ON DELETE CASCADE is expected to still be here; if the query matched nothing at
	// all the guard is vacuous and would never catch a regression.
	if checked == 0 {
		t.Fatal("no foreign keys on hashed audit_event columns were examined — the catalog query " +
			"matched nothing, so this guard proves nothing")
	}
}

// TestPgMgmtAuditChainRejectsHiddenRows covers the other half of 0016: a row must not be able to
// hide from the walk. The verifier pages on `seq > cursor` starting at -1, so before 0016 a row
// planted at a NEGATIVE seq was invisible to /audit/verify and to the NDJSON export while
// GET /audit listed it as a genuine event — verify reporting {ok:true, unchained_events:0} over
// forged data, which is worse than having no chain at all.
func TestPgMgmtAuditChainRejectsHiddenRows(t *testing.T) {
	pool := newTestPool(t)
	applyMgmtAuditChainMigration(t, pool)
	tid, _ := provisionUser(t, pool, "hidden", "tech@hidden.test", "password-1234")
	ctx := context.Background()
	store := NewPgMgmtAuditStore(pool)

	if err := store.RecordEvent(ctx, tid, &MgmtAuditEvent{Action: "session.start"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	plant := func(seq int64, prev, hash string) error {
		_, err := pool.Exec(ctx, `
			INSERT INTO audit_event (id, tenant_id, action, occurred_at, metadata, seq, prev_hash, hash)
			VALUES (gen_random_uuid(), $1::uuid, 'tenant.delete', now(), '{}', $2, $3, $4)
		`, tid, seq, prev, hash)
		return err
	}
	validHash := strings.Repeat("a", 64)

	// A negative seq is refused by the schema outright.
	if err := plant(-1, "", validHash); err == nil {
		t.Fatal("planted a row at seq -1: it is invisible to the chain walk and to the export, " +
			"while GET /audit lists it as a genuine event")
	} else if !strings.Contains(err.Error(), "audit_event_seq_nonneg") {
		t.Fatalf("negative seq rejected by the wrong constraint: %v", err)
	}
	// So are malformed chain fields.
	if err := plant(5, "", "not-a-hash"); err == nil ||
		!strings.Contains(err.Error(), "audit_event_hash_format") {
		t.Fatalf("planting a row with a non-hex hash = %v, want audit_event_hash_format", err)
	}
	if err := plant(5, "zzz", validHash); err == nil ||
		!strings.Contains(err.Error(), "audit_event_prev_hash_format") {
		t.Fatalf("planting a row with a non-hex prev_hash = %v, want audit_event_prev_hash_format", err)
	}

	// The seeded chain is untouched by the refused inserts.
	if res, err := VerifyMgmtAuditChain(ctx, store, tid); err != nil || !res.OK ||
		res.CheckedEvents != 1 || res.UnchainedEvents != 0 {
		t.Fatalf("verify = %+v (%v), want a clean 1-event chain", res, err)
	}

	// An UNCHAINED row (all-NULL chain fields, which 0014's all-or-none CHECK still permits) must
	// stay visible in the coverage arithmetic — that is exactly what UnchainedEvents is for.
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_event (id, tenant_id, action, occurred_at, metadata)
		VALUES (gen_random_uuid(), $1::uuid, 'tenant.delete', now(), '{}')
	`, tid); err != nil {
		t.Fatalf("plant an unchained row: %v", err)
	}
	res, err := VerifyMgmtAuditChain(ctx, store, tid)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.UnchainedEvents != 1 {
		t.Fatalf("verify = %+v, want unchained_events 1 — a row inserted around the chain must "+
			"always be reported, or an auditor reading only `ok` never sees it", res)
	}
}
