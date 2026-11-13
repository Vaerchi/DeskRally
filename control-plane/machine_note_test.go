package controlplane

// Proofs for §4 machine NOTE (free-text operator annotation): PATCH /machines/{id}/note + MachineStore.
// SetMachineNote. Mirrors the loop-69 alias, with three note-specific properties: a NEWLINE is ALLOWED
// (multi-line prose) while other control chars are rejected, the 2000-rune cap, and the audit event records
// that a note was set WITHOUT its (possibly sensitive) content. Store + HTTP surface + both pg projections.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInMemorySetMachineNote(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMachineStore()
	m := &Machine{DeviceID: "dev-1", GroupID: "g1"}
	if err := s.EnrollMachine(ctx, "t1", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := s.SetMachineNote(ctx, "t1", m.ID, "RAID degraded\nmonitor"); err != nil {
		t.Fatalf("set note: %v", err)
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.Note != "RAID degraded\nmonitor" {
		t.Fatalf("note = %q, want the multi-line note", got.Note)
	}
	if err := s.SetMachineNote(ctx, "t1", m.ID, ""); err != nil {
		t.Fatalf("clear note: %v", err)
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.Note != "" {
		t.Fatalf("note after clear = %q, want empty", got.Note)
	}
	if err := s.SetMachineNote(ctx, "t1", "no-such-pk", "x"); err == nil {
		t.Fatalf("unknown machine should miss")
	}
	if err := s.SetMachineNote(ctx, "t2", m.ID, "x"); err == nil {
		t.Fatalf("cross-tenant should miss")
	}
}

func TestNormalizeMachineNote(t *testing.T) {
	// A newline / tab / carriage-return is KEPT (a note is multi-line prose); it round-trips verbatim.
	if got, err := normalizeMachineNote("a\nb\tc\rd"); err != nil || got != "a\nb\tc\rd" {
		t.Fatalf("multi-line note = %q, %v; want it kept verbatim", got, err)
	}
	// An empty note is valid (clears).
	if got, err := normalizeMachineNote(""); err != nil || got != "" {
		t.Fatalf("empty note = %q, %v; want empty, nil", got, err)
	}
	// A BELL (other C0 control) is rejected.
	if _, err := normalizeMachineNote("badbell"); err == nil {
		t.Fatalf("a control char should be rejected")
	}
	// Over 2000 runes is rejected; exactly 2000 is fine.
	if _, err := normalizeMachineNote(strings.Repeat("x", 2001)); err == nil {
		t.Fatalf("a 2001-rune note should be rejected")
	}
	if _, err := normalizeMachineNote(strings.Repeat("x", 2000)); err != nil {
		t.Fatalf("a 2000-rune note should be accepted: %v", err)
	}
}

func TestSetMachineNoteHandler(t *testing.T) {
	tid := "tenant-123"
	ctx := context.Background()
	owner := &Principal{UserID: "u1", TenantID: tid,
		Grant: NewGrant("u1", tid, NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	srv.Machines = NewInMemoryMachineStore()

	gA := &MachineGroup{Name: "Group A"}
	gB := &MachineGroup{Name: "Group B"}
	if err := srv.MachineGroups.CreateMachineGroup(ctx, tid, gA); err != nil {
		t.Fatalf("create gA: %v", err)
	}
	if err := srv.MachineGroups.CreateMachineGroup(ctx, tid, gB); err != nil {
		t.Fatalf("create gB: %v", err)
	}
	mA := &Machine{DeviceID: "dev-a", GroupID: gA.ID}
	mB := &Machine{DeviceID: "dev-b", GroupID: gB.ID}
	for _, m := range []*Machine{mA, mB} {
		if err := srv.Machines.EnrollMachine(ctx, tid, m); err != nil {
			t.Fatalf("enroll: %v", err)
		}
	}
	patch := func(hh http.Handler, id, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest("PATCH", "/machines/"+id+"/note", strings.NewReader(body)))
		return rec
	}

	// Owner sets a (secret-bearing) note → 200, echoed + stored, and audited machine.note_set WITHOUT content.
	const secret = "SECRET-NOTE-CONTENT-do-not-log"
	rec := patch(srv.Handler(), mA.ID, `{"note":"`+secret+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner set note = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Machine Machine `json:"machine"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Machine.Note != secret {
		t.Fatalf("returned note = %q, want the secret", resp.Machine.Note)
	}
	if got, _ := srv.Machines.GetMachineByID(ctx, tid, mA.ID); got.Note != secret {
		t.Fatalf("stored note = %q, want the secret", got.Note)
	}
	events, _ := srv.MgmtAudit.ListEvents(ctx, tid, 10)
	foundAudit := false
	for _, e := range events {
		if e.Action == "machine.note_set" && e.TargetID == mA.ID {
			foundAudit = true
			if b, _ := json.Marshal(e.Metadata); strings.Contains(string(b), secret) {
				t.Fatalf("audit metadata LEAKED the note content: %s", b)
			}
		}
	}
	if !foundAudit {
		t.Fatalf("no machine.note_set audit event for %s", mA.ID)
	}

	// A newline is ALLOWED (multi-line prose) → 200; a control char (bell) and an over-long note → 400.
	if rec := patch(srv.Handler(), mA.ID, `{"note":"line1\nline2"}`); rec.Code != http.StatusOK {
		t.Fatalf("multi-line note = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec := patch(srv.Handler(), mA.ID, `{"note":"`+strings.Repeat("x", 2001)+`"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("over-long note = %d, want 400", rec.Code)
	}

	// Clearing (empty note) → 200 and the stored note is empty.
	if rec := patch(srv.Handler(), mA.ID, `{"note":""}`); rec.Code != http.StatusOK {
		t.Fatalf("clear note = %d, want 200", rec.Code)
	}
	if got, _ := srv.Machines.GetMachineByID(ctx, tid, mA.ID); got.Note != "" {
		t.Fatalf("stored note after clear = %q, want empty", got.Note)
	}

	// Unknown machine → 404.
	if rec := patch(srv.Handler(), newUUID(), `{"note":"x"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown machine = %d, want 404", rec.Code)
	}

	// A READ-ONLY viewer (CapViewMachines, NOT CapManageMachines) cannot annotate → 403 (isolates the write cap).
	viewer := &Principal{UserID: "u3", TenantID: tid,
		Grant: NewGrant("u3", tid, NewMembership(RoleReadOnly, AllGroups()))}
	vsrv, _ := newTestServer(viewer)
	vsrv.Machines = srv.Machines
	vsrv.MachineGroups = srv.MachineGroups
	if rec := patch(vsrv.Handler(), mA.ID, `{"note":"nope"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("read-only note = %d, want 403", rec.Code)
	}

	// GROUP SCOPE: an Admin scoped to group A can note mA (group A) but not mB (group B).
	scoped := &Principal{UserID: "u2", TenantID: tid,
		Grant: NewGrant("u2", tid, NewMembership(RoleAdmin, Groups(gA.ID)))}
	ssrv, _ := newTestServer(scoped)
	ssrv.Machines = srv.Machines
	ssrv.MachineGroups = srv.MachineGroups
	if rec := patch(ssrv.Handler(), mA.ID, `{"note":"A-managed"}`); rec.Code != http.StatusOK {
		t.Fatalf("scoped admin note in-scope = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec := patch(ssrv.Handler(), mB.ID, `{"note":"B-blocked"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("scoped admin note out-of-scope = %d, want 403", rec.Code)
	}
	if got, _ := srv.Machines.GetMachineByID(ctx, tid, mB.ID); got.Note != "" {
		t.Fatalf("mB annotated despite denial: %q", got.Note)
	}
}

// TestPgSetMachineNoteUnderRLS drives PgMachineStore.SetMachineNote as rmt_app: a real note both machine
// projections (GetMachineByID and ListMachines) reflect, clearing, a non-uuid id, and RLS isolation.
func TestPgSetMachineNoteUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAttendedMigration(t, suPool) // 0013: GetMachineByID's projection includes machine.ephemeral/expires_at
	tidA, _ := provisionUser(t, suPool, "mn-a", "a@mn-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "mn-b", "b@mn-b.test", "password-1234")
	_, mid := seedGroupMachine(t, suPool, tidA, "dev-note")
	ctx := context.Background()

	appPool := newAppRolePool(t, ctx)
	store := NewPgMachineStore(appPool)

	if err := store.SetMachineNote(ctx, tidA, mid, "Front desk\nRAID degraded"); err != nil {
		t.Fatalf("set note: %v", err)
	}
	if got, _ := store.GetMachineByID(ctx, tidA, mid); got.Note != "Front desk\nRAID degraded" {
		t.Fatalf("GetMachineByID note = %q, want the multi-line note", got.Note)
	}
	list, err := store.ListMachines(ctx, tidA)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listed *Machine
	for i := range list {
		if list[i].ID == mid {
			listed = &list[i]
		}
	}
	if listed == nil || listed.Note != "Front desk\nRAID degraded" {
		t.Fatalf("ListMachines note = %v, want the multi-line note", listed)
	}
	if err := store.SetMachineNote(ctx, tidA, mid, ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got, _ := store.GetMachineByID(ctx, tidA, mid); got.Note != "" {
		t.Fatalf("note after clear = %q, want empty", got.Note)
	}
	if err := store.SetMachineNote(ctx, tidA, "not-a-uuid", "x"); err == nil {
		t.Fatalf("non-uuid id should miss")
	}
	// Cross-tenant: pinned to B, A's machine is invisible; A's note is untouched.
	if err := store.SetMachineNote(ctx, tidA, mid, "keeper"); err != nil {
		t.Fatalf("re-set note: %v", err)
	}
	if err := store.SetMachineNote(ctx, tidB, mid, "hijack"); err == nil {
		t.Fatalf("cross-tenant should miss")
	}
	if got, _ := store.GetMachineByID(ctx, tidA, mid); got.Note != "keeper" {
		t.Fatalf("A note tampered cross-tenant: %q", got.Note)
	}
}
