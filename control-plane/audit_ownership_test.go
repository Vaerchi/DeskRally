package controlplane

// POST /audit/ingest must refuse to append a caller's events to a session that a DIFFERENT
// technician ran.
//
// The identity bind that was already here stops A from attributing events to B. It does not stop A
// from writing A's own events into B's session chain — and because a chain is strictly sequential,
// doing so consumes the seq numbers B's real events were going to use. Every later event B produces
// then fails verifyLinkage permanently. The damage is not a polluted trail; it is a trail that stops
// recording, which is precisely what an intruder who wanted to go unaudited would arrange.
//
// The check FAILS OPEN when the control plane has nothing authoritative to compare against (no
// session record, or a store that errors), because a wrong refusal costs the whole trail while a
// wrong accept costs one forgery that is already stamped with its author. Both directions are pinned
// below — the fail-open cases are as load-bearing as the refusal.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// The machine mkAuditEvent stamps into every event it builds. The session record has to name the
// SAME one or the machine bind refuses the batch — which is the point of the bind, and was worth
// discovering here rather than in production.
const auditFixtureMachine = "22222222-2222-2222-2222-222222222222"

// sessionOwnedBy persists a session record for technician t and returns its id.
func sessionOwnedBy(tb testing.TB, store SessionRecordStore, technician string) string {
	tb.Helper()
	rec := &SessionRecord{
		TenantID:     "tenant-123",
		MachineID:    auditFixtureMachine,
		TechnicianID: technician,
	}
	if err := store.StartSession(context.Background(), "tenant-123", rec); err != nil {
		tb.Fatalf("StartSession: %v", err)
	}
	if rec.ID == "" {
		tb.Fatal("StartSession did not assign an id")
	}
	return rec.ID
}

func TestAuditIngestRefusesAnotherTechniciansSession(t *testing.T) {
	srv, store := auditServer(technicianPrincipal())
	records := NewInMemorySessionRecordStore()
	srv.SessionRecords = records

	// A session run by somebody else in the same tenant.
	otherSession := sessionOwnedBy(t, records, "user-someone-else")

	// The caller's events are honestly attributed to the CALLER — the identity bind passes. Only the
	// session ownership check can catch this, which is the point of the fixture.
	e := mkAuditEvent(otherSession, 0, GenesisPrevHash,
		mustAction(t, "C:/logs"), mustOutcomeOK(t))

	rec := postIngest(t, srv, auditIngestRequest{SessionID: otherSession, Events: []AuditEvent{e}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — a technician appended to another technician's chain, "+
			"which consumes the seq numbers that session's real events need (body %s)",
			rec.Code, rec.Body.String())
	}
	if tail, _ := store.AuditTail(context.Background(), "tenant-123", otherSession); tail.Exists {
		t.Fatal("the batch was refused but something was still stored")
	}
}

// The positive control. Without it, "refuse everything" would pass the test above.
func TestAuditIngestAcceptsTheCallersOwnSession(t *testing.T) {
	srv, store := auditServer(technicianPrincipal())
	records := NewInMemorySessionRecordStore()
	srv.SessionRecords = records

	own := sessionOwnedBy(t, records, auditTechUser)

	e := mkAuditEvent(own, 0, GenesisPrevHash, mustAction(t, "C:/logs"), mustOutcomeOK(t))
	rec := postIngest(t, srv, auditIngestRequest{SessionID: own, Events: []AuditEvent{e}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for the caller's own session (body %s)", rec.Code, rec.Body.String())
	}
	if tail, _ := store.AuditTail(context.Background(), "tenant-123", own); !tail.Exists {
		t.Fatal("the caller's own batch was accepted but nothing was stored")
	}
}

// Fail-open #1: an UNTICKETED session has no session_record at all. Refusing those would break every
// deployment that has not enabled tickets, and would do it by silently destroying audit trails.
func TestAuditIngestAcceptsASessionWithNoRecord(t *testing.T) {
	srv, store := auditServer(technicianPrincipal())
	srv.SessionRecords = NewInMemorySessionRecordStore() // wired, but empty

	e := mkAuditEvent(testSession, 0, GenesisPrevHash, mustAction(t, "C:/logs"), mustOutcomeOK(t))
	rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: []AuditEvent{e}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a session with no record must still be able to forward "+
			"its trail (body %s)", rec.Code, rec.Body.String())
	}
	if tail, _ := store.AuditTail(context.Background(), "tenant-123", testSession); !tail.Exists {
		t.Fatal("nothing was stored for an unticketed session")
	}
}

// Fail-open #2: a transient store failure must not cost the trail. A 403 here would be indefensible —
// the caller may well be the session's technician; the server simply cannot tell right now.
func TestAuditIngestAcceptsWhenTheSessionStoreErrors(t *testing.T) {
	srv, store := auditServer(technicianPrincipal())
	srv.SessionRecords = erroringSessionRecordStore{}

	e := mkAuditEvent(testSession, 0, GenesisPrevHash, mustAction(t, "C:/logs"), mustOutcomeOK(t))
	rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: []AuditEvent{e}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a database blip must not turn into a permanent hole in "+
			"the audit chain (body %s)", rec.Code, rec.Body.String())
	}
	if tail, _ := store.AuditTail(context.Background(), "tenant-123", testSession); !tail.Exists {
		t.Fatal("nothing was stored when the session store errored")
	}
}

// A store whose GetSession fails for a reason that is NOT "not found".
type erroringSessionRecordStore struct{ SessionRecordStore }

func (erroringSessionRecordStore) GetSession(context.Context, string, string) (*SessionRecord, error) {
	return nil, errors.New("connection reset by peer")
}

// --- fixture helpers -------------------------------------------------------

func mustAction(tb testing.TB, path string) json.RawMessage {
	tb.Helper()
	b, err := json.Marshal(map[string]string{"kind": "file_browse", "path": path})
	if err != nil {
		tb.Fatalf("marshal action: %v", err)
	}
	return b
}

func mustOutcomeOK(tb testing.TB) json.RawMessage {
	tb.Helper()
	b, err := json.Marshal(map[string]string{"result": "ok"})
	if err != nil {
		tb.Fatalf("marshal outcome: %v", err)
	}
	return b
}

// An event may not name a machine other than the one the session ran against.
//
// The handler's own comment argued no scope check belongs here. For a GROUP check that is right —
// group access is revocable mid-session, so refusing on it could turn a legitimate half-written
// trail into a permanent hole. But that proves "no GROUP check", not "no check":
// session_record.machine_id passes the very stability test the handler already applies to
// technician_id — one writer, and no UPDATE anywhere touches it.
//
// Without this a technician can seal backstage records naming ANY machine uuid they know (one whose
// group access was revoked, one leaked via a CSV export), and the export re-emits the forgery as an
// authentic tamper-evident record that a SIEM's own re-hash confirms.
func TestAuditIngestRefusesAnEventNamingAnotherMachine(t *testing.T) {
	srv, store := auditServer(technicianPrincipal())
	records := NewInMemorySessionRecordStore()
	srv.SessionRecords = records

	own := sessionOwnedBy(t, records, auditTechUser) // machine-1, per the helper
	e := mkAuditEvent(own, 0, GenesisPrevHash, mustAction(t, "C:/logs"), mustOutcomeOK(t))
	// A different machine, still a canonical uuid — machine_id is a uuid column and the canonical
	// hash encoder rejects anything else, so a non-uuid would fail for the wrong reason.
	e.MachineID = "33333333-3333-3333-3333-333333333333"
	e.Hash = mustRehash(t, e)

	rec := postIngest(t, srv, auditIngestRequest{SessionID: own, Events: []AuditEvent{e}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — an event naming a machine the session did not run "+
			"against was sealed, and the export will re-emit it as authentic (body %s)",
			rec.Code, rec.Body.String())
	}
	if tail, _ := store.AuditTail(context.Background(), "tenant-123", own); tail.Exists {
		t.Fatal("the batch was refused but something was still stored")
	}
}

// Positive control: the session's OWN machine is accepted. Without this, "refuse every machine_id"
// would pass the test above while breaking every real session.
func TestAuditIngestAcceptsTheSessionsOwnMachine(t *testing.T) {
	srv, store := auditServer(technicianPrincipal())
	records := NewInMemorySessionRecordStore()
	srv.SessionRecords = records

	own := sessionOwnedBy(t, records, auditTechUser)
	e := mkAuditEvent(own, 0, GenesisPrevHash, mustAction(t, "C:/logs"), mustOutcomeOK(t))
	e.MachineID = auditFixtureMachine // what sessionOwnedBy records
	e.Hash = mustRehash(t, e)

	rec := postIngest(t, srv, auditIngestRequest{SessionID: own, Events: []AuditEvent{e}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for the session's own machine (body %s)", rec.Code, rec.Body.String())
	}
	if tail, _ := store.AuditTail(context.Background(), "tenant-123", own); !tail.Exists {
		t.Fatal("accepted but nothing stored")
	}
}

func mustRehash(t *testing.T, e AuditEvent) string {
	t.Helper()
	h, err := recomputeHash(e)
	if err != nil {
		t.Fatalf("recomputeHash: %v", err)
	}
	return h
}
