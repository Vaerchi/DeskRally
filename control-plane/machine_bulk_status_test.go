package controlplane

// Proofs for the §4 BULK machine-status change (POST /machines/bulk-status): one status applied to many
// machines, each INDEPENDENTLY group-scoped on CapManageMachines, with partial per-machine results, an
// up-front tenant-wide gate, validation, and per-successful-machine audit. Complements machine_status_test.go
// (the single-machine handler). Uses the STRICT in-memory machine store so an unknown id is a genuine miss
// (the permissive DEV store would synthesize one).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBulkSetMachineStatusHandler(t *testing.T) {
	tid := "tenant-123"
	ctx := context.Background()
	owner := &Principal{UserID: "u1", TenantID: tid,
		Grant: NewGrant("u1", tid, NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	srv.Machines = NewInMemoryMachineStore() // strict: unknown ids are ErrMachineNotFound

	mA1 := &Machine{DeviceID: "dev-a1", GroupID: "group-a"}
	mA2 := &Machine{DeviceID: "dev-a2", GroupID: "group-a"}
	mB1 := &Machine{DeviceID: "dev-b1", GroupID: "group-b"}
	for _, m := range []*Machine{mA1, mA2, mB1} {
		if err := srv.Machines.EnrollMachine(ctx, tid, m); err != nil {
			t.Fatalf("enroll: %v", err)
		}
	}
	post := func(hh http.Handler, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest("POST", "/machines/bulk-status", strings.NewReader(body)))
		return rec
	}
	type bulkResp struct {
		Results []bulkStatusResult `json:"results"`
	}

	// Owner bulk-quarantines the three real machines + one unknown id → 200; three OK, the unknown fails.
	rec := post(srv.Handler(),
		`{"machine_ids":["`+mA1.ID+`","`+mA2.ID+`","`+mB1.ID+`","no-such-pk"],"status":"quarantined"}`)
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
	if len(br.Results) != 4 || !byID[mA1.ID].OK || !byID[mA2.ID].OK || !byID[mB1.ID].OK {
		t.Fatalf("results = %+v, want the 3 real machines OK", br.Results)
	}
	if u := byID["no-such-pk"]; u.OK || u.Error == "" {
		t.Fatalf("unknown id result = %+v, want ok=false with an error", u)
	}
	// The three real machines are now quarantined; each success was audited with a bulk marker.
	for _, m := range []*Machine{mA1, mA2, mB1} {
		if got, _ := srv.Machines.GetMachineByID(ctx, tid, m.ID); got.Status != MachineStatusQuarantined {
			t.Fatalf("machine %s status = %q, want quarantined", m.ID, got.Status)
		}
	}
	events, _ := srv.MgmtAudit.ListEvents(ctx, tid, 10)
	n := 0
	for _, e := range events {
		if e.Action == "machine.status_set" {
			n++
			if b, _ := json.Marshal(e.Metadata); !strings.Contains(string(b), "\"bulk\":true") {
				t.Fatalf("bulk audit metadata missing bulk marker: %s", b)
			}
		}
	}
	if n != 3 {
		t.Fatalf("machine.status_set audit events = %d, want 3 (one per successful machine)", n)
	}

	// Validation: a bad status is a clean 400 (whole request rejected, no partial results).
	if rec := post(srv.Handler(), `{"machine_ids":["`+mA1.ID+`"],"status":"deleted"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad status = %d, want 400", rec.Code)
	}
	// An empty id list is a 400 (nothing to do).
	if rec := post(srv.Handler(), `{"machine_ids":[],"status":"active"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty ids = %d, want 400", rec.Code)
	}

	// GROUP-SCOPE: an Admin scoped to group-a bulk-retires a group-a AND a group-b machine → the group-a
	// one succeeds, the group-b one is DENIED per-machine (never silently applied), and its status is untouched.
	scoped := &Principal{UserID: "u2", TenantID: tid,
		Grant: NewGrant("u2", tid, NewMembership(RoleAdmin, Groups("group-a")))}
	ssrv, _ := newTestServer(scoped)
	ssrv.Machines = srv.Machines // share the seeded fleet
	srec := post(ssrv.Handler(), `{"machine_ids":["`+mA1.ID+`","`+mB1.ID+`"],"status":"retired"}`)
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
	if !sByID[mA1.ID].OK {
		t.Fatalf("group-a machine denied to a group-a admin: %+v", sByID[mA1.ID])
	}
	if sByID[mB1.ID].OK || sByID[mB1.ID].Error != "denied" {
		t.Fatalf("group-b machine not denied to a group-a admin: %+v", sByID[mB1.ID])
	}
	// mB1 stays quarantined (from the owner's bulk) — the denied retire did NOT take effect.
	if got, _ := srv.Machines.GetMachineByID(ctx, tid, mB1.ID); got.Status != MachineStatusQuarantined {
		t.Fatalf("mB1 changed despite the per-machine denial: %q", got.Status)
	}

	// UP-FRONT GATE: a ReadOnly caller holds no CapManageMachines anywhere → 403 before the loop.
	ro := &Principal{UserID: "u3", TenantID: tid,
		Grant: NewGrant("u3", tid, NewMembership(RoleReadOnly, AllGroups()))}
	rosrv, _ := newTestServer(ro)
	rosrv.Machines = srv.Machines
	if rec := post(rosrv.Handler(), `{"machine_ids":["`+mA1.ID+`"],"status":"active"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("readonly bulk = %d, want 403", rec.Code)
	}
}
