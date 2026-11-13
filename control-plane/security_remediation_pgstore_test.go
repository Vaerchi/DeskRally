package controlplane

// These tests reset a database through newTestPool. Run only against an explicitly
// selected disposable test database; they were not executed during the source-only pass.
import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestPgSecurityAuditSignatureRoundTrip(t *testing.T) {
	pool := newTestPool(t)
	applyAuditMigration(t, pool)
	tenant, _ := provisionUser(t, pool, "signature-test", "tech@test.invalid", "password-1234")
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	event := chainRange(testSession, 0, 1)[0]
	event.AgentPubkey = pub
	event.AgentSignature = hex.EncodeToString(ed25519.Sign(key, agentAuditSigningBytes(event.Hash)))
	store := NewPgAuditStore(pool)
	if _, err := store.AppendAudit(context.Background(), tenant, testSession, []AuditEvent{event}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := store.ListAuditEventsAsc(context.Background(), tenant, NewAuditExportQuery("", 100))
	if err != nil || len(rows) != 1 {
		t.Fatalf("export: %d rows, %v", len(rows), err)
	}
	if !validAgentAuditSignature(rows[0], pub) {
		t.Fatal("stored signature/public key did not survive export")
	}
}

func TestPgSecurityAttendedKeySurvivesCleanup(t *testing.T) {
	pool := newTestPool(t)
	applyAttendedMigration(t, pool)
	tenant, user := provisionUser(t, pool, "attended-key-test", "tech@test.invalid", "password-1234")
	group := seedGroup(t, pool, tenant)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	store := NewPgAttendedStore(pool)
	session := &AttendedSession{GroupID: group, TechnicianID: user}
	code, err := store.Create(context.Background(), tenant, session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Redeem(context.Background(), code, pub, "guest"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.End(context.Background(), tenant, session.ID); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Get(context.Background(), tenant, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.AgentPubkey != pub {
		t.Fatal("redemption key was lost during cleanup")
	}
}
