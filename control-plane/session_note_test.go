package controlplane

// Proofs for the §7 session-note feature (SessionRecordStore.SetSessionNote): the store (fake + pg
// under RLS) and the HTTP surface (PATCH /sessions/{id}/note — CapEndSession, group-scoped, validated,
// audited). Complements session_summary_test.go (the sessions-by-machine report).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInMemorySetSessionNote(t *testing.T) {
	ctx := context.Background()
	s := NewInMemorySessionRecordStore()
	rec := &SessionRecord{MachineID: "m1", TechnicianID: "u1", MachineGroupID: "g1", MachineName: "HOST"}
	if err := s.StartSession(ctx, "t1", rec); err != nil {
		t.Fatalf("start: %v", err)
	}
	// A fresh session's note is empty (migration 0031 defaults it to '').
	if got, _ := s.GetSession(ctx, "t1", rec.ID); got.Note != "" {
		t.Fatalf("fresh note = %q, want empty", got.Note)
	}
	// Set a note → it round-trips through the returned record, GetSession, AND ListSessions.
	upd, err := s.SetSessionNote(ctx, "t1", rec.ID, "call back at 5pm")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if upd.Note != "call back at 5pm" {
		t.Fatalf("returned note = %q", upd.Note)
	}
	if got, _ := s.GetSession(ctx, "t1", rec.ID); got.Note != "call back at 5pm" {
		t.Fatalf("get note = %q", got.Note)
	}
	if list, _ := s.ListSessions(ctx, "t1", SessionSummaryFilter{}); len(list) != 1 || list[0].Note != "call back at 5pm" {
		t.Fatalf("list note = %+v", list)
	}
	// Overwrite (not append).
	if _, err := s.SetSessionNote(ctx, "t1", rec.ID, "done"); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if got, _ := s.GetSession(ctx, "t1", rec.ID); got.Note != "done" {
		t.Fatalf("overwrite note = %q", got.Note)
	}
	// Unknown id and wrong tenant both miss (never touch another tenant's row).
	if _, err := s.SetSessionNote(ctx, "t1", newUUID(), "x"); err != ErrSessionRecordNotFound {
		t.Fatalf("unknown id err = %v, want ErrSessionRecordNotFound", err)
	}
	if _, err := s.SetSessionNote(ctx, "t2", rec.ID, "x"); err != ErrSessionRecordNotFound {
		t.Fatalf("wrong-tenant err = %v, want ErrSessionRecordNotFound", err)
	}
}

func TestSetSessionNoteHandler(t *testing.T) {
	tid := "tenant-123"
	ctx := context.Background()
	owner := &Principal{UserID: "u1", TenantID: tid,
		Grant: NewGrant("u1", tid, NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	rec := &SessionRecord{MachineID: "m1", TechnicianID: "u1", MachineGroupID: "group-a", MachineName: "HOST"}
	if err := srv.SessionRecords.StartSession(ctx, tid, rec); err != nil {
		t.Fatalf("seed: %v", err)
	}
	patch := func(hh http.Handler, id, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		hh.ServeHTTP(rr, httptest.NewRequest("PATCH", "/sessions/"+id+"/note", strings.NewReader(body)))
		return rr
	}

	// Owner sets a note → 200 and the note round-trips in the response.
	rr := patch(srv.Handler(), rec.ID, `{"note":"handoff to bob"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("owner = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Session SessionRecord `json:"session"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Session.Note != "handoff to bob" {
		t.Fatalf("returned note = %q, want handoff to bob", resp.Session.Note)
	}
	// A session.note_set audit event was recorded (and it does NOT carry the note content).
	events, err := srv.MgmtAudit.ListEvents(ctx, tid, 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Action == "session.note_set" {
			found = true
			if b, _ := json.Marshal(e.Metadata); strings.Contains(string(b), "handoff to bob") {
				t.Fatalf("audit metadata leaked the note content: %s", b)
			}
		}
	}
	if !found {
		t.Fatalf("no session.note_set audit event in %+v", events)
	}

	// Validation: a control character (bell) → clean 400, note unchanged.
	if rr := patch(srv.Handler(), rec.ID, "{\"note\":\"bad\\u0007bell\"}"); rr.Code != http.StatusBadRequest {
		t.Fatalf("control-char note = %d, want 400", rr.Code)
	}
	// Validation: over the rune cap → 400.
	if rr := patch(srv.Handler(), rec.ID, `{"note":"`+strings.Repeat("x", 4001)+`"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("too-long note = %d, want 400", rr.Code)
	}
	// The rejected writes did not change the stored note.
	if got, _ := srv.SessionRecords.GetSession(ctx, tid, rec.ID); got.Note != "handoff to bob" {
		t.Fatalf("note changed by a rejected write: %q", got.Note)
	}
	// Unknown session → 404.
	if rr := patch(srv.Handler(), newUUID(), `{"note":"x"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown session = %d, want 404", rr.Code)
	}

	// GATE: a ReadOnly viewer holds CapViewSessions but NOT CapEndSession → 403 (a read cap does not
	// grant the write). Shares the SAME store so the session is visible; the cap is what stops it.
	roSrv, _ := newTestServer(&Principal{UserID: "u2", TenantID: tid,
		Grant: NewGrant("u2", tid, NewMembership(RoleReadOnly, AllGroups()))})
	roSrv.SessionRecords = srv.SessionRecords
	if rr := patch(roSrv.Handler(), rec.ID, `{"note":"x"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("readonly = %d, want 403", rr.Code)
	}
	// GROUP-SCOPE: a Technician (has CapEndSession) scoped to group-b cannot note a group-a session.
	scopedSrv, _ := newTestServer(&Principal{UserID: "u3", TenantID: tid,
		Grant: NewGrant("u3", tid, NewMembership(RoleTechnician, Groups("group-b")))})
	scopedSrv.SessionRecords = srv.SessionRecords
	if rr := patch(scopedSrv.Handler(), rec.ID, `{"note":"x"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("group-b technician = %d, want 403", rr.Code)
	}
}

// TestPgSetSessionNoteUnderRLS drives PgSessionRecordStore.SetSessionNote as rmt_app: the note
// round-trips through the joined read, and RLS keeps another tenant from touching (or seeing) it.
func TestPgSetSessionNoteUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	tidA, uidA := provisionUser(t, suPool, "note-a", "a@note-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "note-b", "b@note-b.test", "password-1234")
	_, midA := seedGroupMachine(t, suPool, tidA, "dev-note-a")

	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgSessionRecordStore(appPool)
	rec := &SessionRecord{MachineID: midA, TechnicianID: uidA}
	if err := store.StartSession(ctx, tidA, rec); err != nil {
		t.Fatalf("start: %v", err)
	}
	if got, _ := store.GetSession(ctx, tidA, rec.ID); got.Note != "" {
		t.Fatalf("fresh pg note = %q, want empty", got.Note)
	}
	upd, err := store.SetSessionNote(ctx, tidA, rec.ID, "remember the milk")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if upd.Note != "remember the milk" {
		t.Fatalf("returned note = %q", upd.Note)
	}
	if got, _ := store.GetSession(ctx, tidA, rec.ID); got.Note != "remember the milk" {
		t.Fatalf("get note = %q", got.Note)
	}
	// RLS: tenant B cannot note A's session (the row is invisible under B's tenant → not found)...
	if _, err := store.SetSessionNote(ctx, tidB, rec.ID, "hax"); err != ErrSessionRecordNotFound {
		t.Fatalf("cross-tenant note err = %v, want ErrSessionRecordNotFound", err)
	}
	// ...and A's note is untouched.
	if got, _ := store.GetSession(ctx, tidA, rec.ID); got.Note != "remember the milk" {
		t.Fatalf("note tampered cross-tenant: %q", got.Note)
	}
}
