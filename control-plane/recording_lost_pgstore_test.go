package controlplane

import (
	"context"
	"testing"
	"time"
)

func TestRecordingLostStorePg(t *testing.T) {
	runRecordingLostStoreSuite(t, func(t *testing.T) *recEnv {
		h := newPgRecHarness(t)
		return &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB,
			session: h.sessionOf}
	})
}

// What only Postgres can prove about 0077: the state machine and the lost_from bookkeeping are enforced by
// the schema whatever the application does, and the tombstone / RLS guarantees of 0066 are intact.
func TestRecordingLostPgConstraints(t *testing.T) {
	h := newPgRecHarness(t)
	ctx := context.Background()
	env := &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB, session: h.sessionOf}
	env.enable(t, h.tenantA, 30, 1<<30, 20<<30)
	r := env.complete(t, h.tenantA, h.machineA)
	exec := func(q string, args ...any) error { _, err := h.su.Exec(ctx, q, args...); return err }

	// Entering lost without naming where from, or naming the wrong state, is refused by the trigger/CHECK.
	if exec(`UPDATE session_recording SET state = 'lost' WHERE id = $1`, r.ID) == nil {
		t.Error("lost without lost_from was accepted")
	}
	if exec(`UPDATE session_recording SET state = 'lost', lost_from = 'playback_ready', lost_at = now() WHERE id = $1`, r.ID) == nil {
		t.Error("lost_from naming a state the row was not in was accepted")
	}
	if exec(`UPDATE session_recording SET lost_from = 'evidence_complete', lost_at = now() WHERE id = $1`, r.ID) == nil {
		t.Error("lost_from set on a row that is not entering lost was accepted")
	}
	if _, err := h.store.MarkLost(ctx, h.tenantA, r.ID); err != nil {
		t.Fatal(err)
	}
	// Once lost, the origin cannot be rewritten without a transition; and a lost row cannot jump to deleted.
	if exec(`UPDATE session_recording SET lost_from = 'playback_failed' WHERE id = $1`, r.ID) == nil {
		t.Error("lost_from was rewritten in place")
	}
	// The loss history is protected on EVERY transition, not only while the state is unchanged: a transition
	// out of lost cannot clear or rewrite lost_from / lost_at, and neither can a plain UPDATE.
	if exec(`UPDATE session_recording SET lost_from = NULL, lost_at = NULL WHERE id = $1`, r.ID) == nil {
		t.Error("lost_from / lost_at were cleared in place")
	}
	if exec(`UPDATE session_recording SET lost_at = now() + interval '1 hour' WHERE id = $1`, r.ID) == nil {
		t.Error("lost_at was rewritten in place")
	}
	if exec(`UPDATE session_recording SET state = 'expired', expired_at = now(), lost_from = NULL, lost_at = NULL WHERE id = $1`, r.ID) == nil {
		t.Error("lost -> expired cleared the loss history")
	}
	if exec(`UPDATE session_recording SET state = 'expired', expired_at = now(), lost_from = 'playback_failed' WHERE id = $1`, r.ID) == nil {
		t.Error("lost -> expired rewrote lost_from")
	}
	if exec(`UPDATE session_recording SET state = 'evidence_complete', lost_from = NULL, lost_at = NULL WHERE id = $1`, r.ID) == nil {
		t.Error("lost -> evidence_complete cleared the loss history")
	}
	if exec(`UPDATE session_recording SET state = 'playback_ready', lost_at = now() + interval '1 hour' WHERE id = $1`, r.ID) == nil {
		t.Error("lost -> playback_ready rewrote lost_at")
	}
	history := func(id string) (string, *time.Time) {
		t.Helper()
		var from *string
		var at *time.Time
		if err := h.su.QueryRow(ctx, `SELECT lost_from, lost_at FROM session_recording WHERE id = $1`, id).Scan(&from, &at); err != nil {
			t.Fatal(err)
		}
		if from == nil {
			return "", at
		}
		return *from, at
	}
	wantFrom, wantAt := history(r.ID)
	if wantFrom != "evidence_complete" || wantAt == nil {
		t.Fatalf("history after the refused updates: %q %v", wantFrom, wantAt)
	}
	// The legitimate paths keep the history: restore, a second life, and expiry.
	if err := h.store.RestoreLost(ctx, h.tenantA, r.ID, RecEvidenceComplete); err != nil {
		t.Fatal(err)
	}
	if f, a := history(r.ID); f != wantFrom || a == nil || !a.Equal(*wantAt) {
		t.Errorf("restore changed the history: %q %v, want %q %v", f, a, wantFrom, wantAt)
	}
	if exec(`UPDATE session_recording SET lost_from = NULL, lost_at = NULL WHERE id = $1`, r.ID) == nil {
		t.Error("history was cleared on a restored (non-lost) row")
	}
	if _, err := h.store.MarkLost(ctx, h.tenantA, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.store.MarkExpired(ctx, h.tenantA, r.ID); err != nil {
		t.Fatal(err)
	}
	if f, a := history(r.ID); f != "evidence_complete" || a == nil {
		t.Errorf("expiry dropped the history: %q %v", f, a)
	}
	if exec(`UPDATE session_recording SET lost_at = NULL, lost_from = NULL WHERE id = $1`, r.ID) == nil {
		t.Error("history was cleared on an expired row")
	}
	// r is expired now; the rest of the checks use fresh rows. Re-establish a lost row for them.
	r = env.complete(t, h.tenantA, h.machineA)
	if _, err := h.store.MarkLost(ctx, h.tenantA, r.ID); err != nil {
		t.Fatal(err)
	}
	if exec(`UPDATE session_recording SET state = 'deleted', expired_at = now(), deleted_at = now() WHERE id = $1`, r.ID) == nil {
		t.Error("lost -> deleted skipped expired")
	}
	if exec(`UPDATE session_recording SET state = 'uploading' WHERE id = $1`, r.ID) == nil {
		t.Error("lost -> uploading was accepted")
	}
	// Only the promising states can be lost: an expired row cannot.
	r2 := env.complete(t, h.tenantA, h.machineA)
	if err := h.store.MarkExpired(ctx, h.tenantA, r2.ID); err != nil {
		t.Fatal(err)
	}
	if exec(`UPDATE session_recording SET state = 'lost', lost_from = 'expired', lost_at = now() WHERE id = $1`, r2.ID) == nil {
		t.Error("expired -> lost was accepted")
	}
	// lost_from / lost_at are both set or both null.
	r3 := env.complete(t, h.tenantA, h.machineA)
	if exec(`UPDATE session_recording SET lost_at = now() WHERE id = $1`, r3.ID) == nil {
		t.Error("lost_at without lost_from was accepted")
	}
	// The replaced CHECK is really in force: an unknown state is still refused.
	if exec(`UPDATE session_recording SET state = 'bogus' WHERE id = $1`, r3.ID) == nil {
		t.Error("an unknown state was accepted")
	}
	// The 0066 tombstone rule survives: the app role still cannot delete a recording row.
	if _, err := h.app.Exec(ctx, `DELETE FROM session_recording WHERE id = $1`, r.ID); err == nil {
		t.Error("the app role deleted a recording row")
	}
	// RLS: another tenant cannot see or move a lost row.
	if _, err := h.store.MarkLost(ctx, h.tenantB, r3.ID); err == nil {
		t.Error("tenant B marked tenant A's recording lost")
	}
}
