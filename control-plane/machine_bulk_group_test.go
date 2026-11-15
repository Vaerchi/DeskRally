package controlplane

// Proofs for the §4 BULK machine-group reassignment (POST /machines/bulk-group): many machines moved to ONE
// target group, with the two-way authz SPLIT — the MOVE-IN half (manage the shared target + it exists) is a
// blanket PRECONDITION (a bad/unmanaged target fails the WHOLE request), while the MOVE-OUT half (manage each
// machine's CURRENT group) is per-machine with partial results. Complements machine_group_reassign_test.go
// (single) and machine_bulk_status_test.go (the bulk mold). STRICT in-memory store so unknown ids truly miss.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBulkSetMachineGroupHandler(t *testing.T) {
	tid := "tenant-123"
	ctx := context.Background()
	owner := &Principal{UserID: "u1", TenantID: tid,
		Grant: NewGrant("u1", tid, NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	srv.Machines = NewInMemoryMachineStore() // strict: unknown ids are ErrMachineNotFound

	gA := &MachineGroup{Name: "Group A"}
	gB := &MachineGroup{Name: "Group B"}
	gC := &MachineGroup{Name: "Group C"}
	for _, g := range []*MachineGroup{gA, gB, gC} {
		if err := srv.MachineGroups.CreateMachineGroup(ctx, tid, g); err != nil {
			t.Fatalf("create group: %v", err)
		}
	}
	oA1 := &Machine{DeviceID: "dev-oa1", GroupID: gA.ID}
	oA2 := &Machine{DeviceID: "dev-oa2", GroupID: gA.ID}
	oB1 := &Machine{DeviceID: "dev-ob1", GroupID: gB.ID}
	sA := &Machine{DeviceID: "dev-sa", GroupID: gA.ID}
	sB := &Machine{DeviceID: "dev-sb", GroupID: gB.ID}
	for _, m := range []*Machine{oA1, oA2, oB1, sA, sB} {
		if err := srv.Machines.EnrollMachine(ctx, tid, m); err != nil {
			t.Fatalf("enroll: %v", err)
		}
	}
	post := func(hh http.Handler, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest("POST", "/machines/bulk-group", strings.NewReader(body)))
		return rec
	}
	type bulkResp struct {
		Results []bulkStatusResult `json:"results"`
	}

	// Owner moves the three real machines (two in A, one in B) + one unknown id → target C. 200; the 3 real
	// ones OK and now in C, the unknown fails; each success is audited machine.group_changed with a bulk marker.
	rec := post(srv.Handler(),
		`{"machine_ids":["`+oA1.ID+`","`+oA2.ID+`","`+oB1.ID+`","no-such-pk"],"group_id":"`+gC.ID+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner bulk = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var br bulkResp
	if err := json.Unmarshal(rec.Body.Bytes(), &br); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byID := map[string]bulkStatusResult{}
	for _, r := range br.Results {
		byID[r.MachineID] = r
	}
	if len(br.Results) != 4 || !byID[oA1.ID].OK || !byID[oA2.ID].OK || !byID[oB1.ID].OK {
		t.Fatalf("results = %+v, want the 3 real machines OK", br.Results)
	}
	if u := byID["no-such-pk"]; u.OK || u.Error == "" {
		t.Fatalf("unknown id result = %+v, want ok=false with an error", u)
	}
	for _, m := range []*Machine{oA1, oA2, oB1} {
		if got, _ := srv.Machines.GetMachineByID(ctx, tid, m.ID); got.GroupID != gC.ID {
			t.Fatalf("machine %s group = %q, want C (%s)", m.ID, got.GroupID, gC.ID)
		}
	}
	events, _ := srv.MgmtAudit.ListEvents(ctx, tid, 20)
	n := 0
	for _, e := range events {
		if e.Action == "machine.group_changed" {
			n++
			if b, _ := json.Marshal(e.Metadata); !strings.Contains(string(b), "\"bulk\":true") || !strings.Contains(string(b), gC.ID) {
				t.Fatalf("bulk audit metadata missing bulk marker or target: %s", b)
			}
		}
	}
	if n != 3 {
		t.Fatalf("machine.group_changed audit events = %d, want 3 (one per successful move)", n)
	}

	// Validation: an empty id list and an empty group_id are each a clean 400 (whole request rejected).
	if rec := post(srv.Handler(), `{"machine_ids":[],"group_id":"`+gC.ID+`"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty ids = %d, want 400", rec.Code)
	}
	if rec := post(srv.Handler(), `{"machine_ids":["`+sA.ID+`"],"group_id":""}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty group_id = %d, want 400", rec.Code)
	}
	// A non-existent TARGET group is a BLANKET 404 (the whole request fails — the target is shared).
	if rec := post(srv.Handler(), `{"machine_ids":["`+sA.ID+`"],"group_id":"`+newUUID()+`"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown target = %d, want 404", rec.Code)
	}

	// MOVE-IN is a BLANKET precondition: an Admin scoped to group A moving sA (in A, which they manage) INTO
	// target B (which they do NOT manage) → 403 for the WHOLE request, and sA is untouched. This is the key
	// distinction from the per-machine MOVE-OUT check below.
	scopedA := &Principal{UserID: "u2", TenantID: tid,
		Grant: NewGrant("u2", tid, NewMembership(RoleAdmin, Groups(gA.ID)))}
	asrv, _ := newTestServer(scopedA)
	asrv.Machines = srv.Machines
	asrv.MachineGroups = srv.MachineGroups
	if rec := post(asrv.Handler(), `{"machine_ids":["`+sA.ID+`"],"group_id":"`+gB.ID+`"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("move into unmanaged target = %d, want 403 (blanket)", rec.Code)
	}
	if got, _ := srv.Machines.GetMachineByID(ctx, tid, sA.ID); got.GroupID != gA.ID {
		t.Fatalf("sA moved despite the blanket move-in denial: %q", got.GroupID)
	}

	// MOVE-OUT is PER-MACHINE: the same group-A admin moving [sA (in A, managed), sB (in B, NOT managed)] into
	// target A (which they manage) → 200; sA succeeds, sB is DENIED per-machine, and sB stays in B.
	srec := post(asrv.Handler(), `{"machine_ids":["`+sA.ID+`","`+sB.ID+`"],"group_id":"`+gA.ID+`"}`)
	if srec.Code != http.StatusOK {
		t.Fatalf("scoped bulk = %d, want 200: %s", srec.Code, srec.Body.String())
	}
	var sbr bulkResp
	if err := json.Unmarshal(srec.Body.Bytes(), &sbr); err != nil {
		t.Fatalf("decode scoped: %v", err)
	}
	sByID := map[string]bulkStatusResult{}
	for _, r := range sbr.Results {
		sByID[r.MachineID] = r
	}
	if !sByID[sA.ID].OK {
		t.Fatalf("group-A machine denied to a group-A admin: %+v", sByID[sA.ID])
	}
	if sByID[sB.ID].OK || sByID[sB.ID].Error != "denied" {
		t.Fatalf("group-B machine not denied to a group-A admin: %+v", sByID[sB.ID])
	}
	if got, _ := srv.Machines.GetMachineByID(ctx, tid, sB.ID); got.GroupID != gB.ID {
		t.Fatalf("sB moved despite the per-machine denial: %q", got.GroupID)
	}

	// UP-FRONT GATE: a ReadOnly caller holds no CapManageMachines anywhere → 403 before the loop.
	ro := &Principal{UserID: "u3", TenantID: tid,
		Grant: NewGrant("u3", tid, NewMembership(RoleReadOnly, AllGroups()))}
	rosrv, _ := newTestServer(ro)
	rosrv.Machines = srv.Machines
	rosrv.MachineGroups = srv.MachineGroups
	if rec := post(rosrv.Handler(), `{"machine_ids":["`+sA.ID+`"],"group_id":"`+gA.ID+`"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("readonly bulk = %d, want 403", rec.Code)
	}
}
