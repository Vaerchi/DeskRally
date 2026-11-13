package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

func TestSecurityAgentAuditSignatureAuthenticatesPinnedOrigin(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	event := AuditEvent{MachineID: "device", Hash: strings.Repeat("a", 64), AgentPubkey: pub}
	event.AgentSignature = hex.EncodeToString(ed25519.Sign(key, agentAuditSigningBytes(event.Hash)))
	if event.AgentSignature != "1188b6bed920ebb0370ec49b92b06cf8c1996b5742537c772bef0fd29fcefedea0c36987bafac7957146c54f956474aa0b6c2fded257dc4df725134bb6daa509" {
		t.Fatal("cross-language audit signature vector changed")
	}
	if !validAgentAuditSignature(event, pub) {
		t.Fatal("genuine agent signature rejected")
	}
	forged := event
	forged.Hash = strings.Repeat("b", 64)
	if validAgentAuditSignature(forged, pub) {
		t.Fatal("rewritten chain authenticated")
	}
	forged = event
	forged.AgentSignature = hex.EncodeToString(ed25519.Sign(key, []byte(event.Hash)))
	if validAgentAuditSignature(forged, pub) {
		t.Fatal("signature from wrong domain accepted")
	}
	forged = event
	forged.AgentSignature = ""
	if validAgentAuditSignature(forged, pub) {
		t.Fatal("unsigned event authenticated")
	}
	if validAgentAuditSignature(event, strings.Repeat("0", 64)) {
		t.Fatal("untrusted key authenticated")
	}

	machines := NewInMemoryMachineStore()
	machines.machines[machineKey("tenant", "device")] = &Machine{ID: "primary", DeviceID: "device", TenantID: "tenant", Pubkey: pub}
	server := &Server{Machines: machines, RequireAgentAuditSignatures: true}
	if err := server.verifyAgentAudit(context.Background(), "tenant", "session", []AuditEvent{event}); err != nil {
		t.Fatal(err)
	}
	if err := server.verifyAgentAudit(context.Background(), "other-tenant", "session", []AuditEvent{event}); err == nil {
		t.Fatal("foreign tenant key accepted")
	}
	if err := server.verifyAgentAudit(context.Background(), "tenant", "session", []AuditEvent{forged}); err == nil {
		t.Fatal("unsigned production event accepted")
	}
}

func TestSecurityAttendedAuditKeySurvivesCleanup(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	machines := NewInMemoryMachineStore()
	attended := NewInMemoryAttendedStore(machines)
	session := &AttendedSession{TechnicianID: "tech", GroupID: "group"}
	code, err := attended.Create(context.Background(), "tenant", session)
	if err != nil {
		t.Fatal(err)
	}
	redeemed, err := attended.Redeem(context.Background(), code, pub, "guest")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attended.End(context.Background(), "tenant", session.ID); err != nil {
		t.Fatal(err)
	}
	event := AuditEvent{MachineID: redeemed.DeviceID, Hash: strings.Repeat("a", 64), AgentPubkey: pub}
	event.AgentSignature = hex.EncodeToString(ed25519.Sign(key, agentAuditSigningBytes(event.Hash)))
	server := &Server{Machines: machines, Attended: attended, RequireAgentAuditSignatures: true}
	if err := server.verifyAgentAudit(context.Background(), "tenant", session.ID, []AuditEvent{event}); err != nil {
		t.Fatal(err)
	}
	if err := server.verifyAgentAudit(context.Background(), "tenant", "other-session", []AuditEvent{event}); err == nil {
		t.Fatal("ephemeral key accepted for another session")
	}
}

func TestSecurityAuditIngestRequiresAgentProof(t *testing.T) {
	srv, store := auditServer(technicianPrincipal())
	srv.RequireAgentAuditSignatures = true
	srv.SessionRecords = NewInMemorySessionRecordStore()
	const deviceID = "33333333-3333-3333-3333-333333333333"
	record := &SessionRecord{TenantID: "tenant-123", MachineID: auditFixtureMachine, MachineDeviceID: deviceID, TechnicianID: auditTechUser}
	if err := srv.SessionRecords.StartSession(context.Background(), "tenant-123", record); err != nil {
		t.Fatal(err)
	}
	session := record.ID
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	machines := NewInMemoryMachineStore()
	machines.machines[machineKey("tenant-123", deviceID)] = &Machine{ID: auditFixtureMachine, DeviceID: deviceID, TenantID: "tenant-123", Pubkey: pub}
	srv.Machines = machines
	event := mkAuditEvent(session, 0, GenesisPrevHash, mustAction(t, "C:/logs"), mustOutcomeOK(t))
	event.MachineID = deviceID // The Windows agent knows its device id, not the row's primary key.
	event.Hash, _ = recomputeHash(event)
	if rec := postIngest(t, srv, auditIngestRequest{SessionID: session, Events: []AuditEvent{event}}); rec.Code != http.StatusForbidden {
		t.Fatalf("unsigned = %d", rec.Code)
	}
	event.AgentPubkey = pub
	event.AgentSignature = hex.EncodeToString(ed25519.Sign(key, agentAuditSigningBytes(event.Hash)))
	if rec := postIngest(t, srv, auditIngestRequest{SessionID: session, Events: []AuditEvent{event}}); rec.Code != http.StatusOK {
		t.Fatalf("signed = %d: %s", rec.Code, rec.Body.String())
	}
	forged := mkAuditEvent(session, 1, event.Hash, mustAction(t, "C:/forged"), mustOutcomeOK(t))
	forged.AgentPubkey, forged.AgentSignature = event.AgentPubkey, event.AgentSignature
	if rec := postIngest(t, srv, auditIngestRequest{SessionID: session, Events: []AuditEvent{forged}}); rec.Code != http.StatusForbidden {
		t.Fatalf("forged = %d", rec.Code)
	}
	if tail, _ := store.AuditTail(context.Background(), "tenant-123", session); tail.Seq != 0 {
		t.Fatal("forged event reached storage")
	}
}
