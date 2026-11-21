package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type machinePropertyListSpy struct {
	MachinePropertyStore
	batches [][]string
}

func (s *machinePropertyListSpy) ListPropertiesForMachines(ctx context.Context, tenant string, ids []string) (map[string]map[string]string, error) {
	s.batches = append(s.batches, append([]string(nil), ids...))
	return s.MachinePropertyStore.ListPropertiesForMachines(ctx, tenant, ids)
}

type machinePropertyFailingAudit struct {
	MgmtAuditStore
}

func (machinePropertyFailingAudit) RecordEvent(context.Context, string, *MgmtAuditEvent) error {
	return errors.New("audit unavailable")
}

func newMachinePropertyFleet(t *testing.T, role Role) (*Server, [3]string) {
	t.Helper()
	const tenant = "tenant-123"
	p := &Principal{UserID: "u1", TenantID: tenant,
		Grant: NewGrant("u1", tenant, NewMembership(role, Groups("group-a")))}
	srv, _ := newTestServer(p)
	srv.Machines = NewInMemoryMachineStore()
	var ids [3]string
	for i, m := range []*Machine{
		{DeviceID: "dev-a1", GroupID: "group-a"},
		{DeviceID: "dev-a2", GroupID: "group-a"},
		{DeviceID: "dev-b1", GroupID: "group-b"},
	} {
		if err := srv.Machines.EnrollMachine(context.Background(), tenant, m); err != nil {
			t.Fatalf("enroll: %v", err)
		}
		ids[i] = m.ID
	}
	return srv, ids
}

func TestListMachinesIncludeProperties(t *testing.T) {
	const tenant = "tenant-123"
	srv, ids := newMachinePropertyFleet(t, RoleReadOnly)
	for i, bag := range []map[string]string{{"site": "HQ", "rack": ""}, {}, {"site": "hidden"}} {
		for key, value := range bag {
			if err := srv.MachineProperties.SetProperty(context.Background(), tenant, ids[i], key, value); err != nil {
				t.Fatal(err)
			}
		}
	}
	spy := &machinePropertyListSpy{MachinePropertyStore: srv.MachineProperties}
	srv.MachineProperties = spy
	h := srv.Handler()
	for _, include := range []bool{false, true} {
		path := "/machines"
		if include {
			path += "?include=properties"
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		var body struct {
			Machines []struct {
				ID         string            `json:"id"`
				Properties map[string]string `json:"properties"`
			} `json:"machines"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s (%v)", path, rec.Code, rec.Body, err)
		}
		got := make(map[string]map[string]string)
		for _, m := range body.Machines {
			got[m.ID] = m.Properties
		}
		want := map[string]map[string]string{ids[0]: nil, ids[1]: nil}
		if include {
			want[ids[0]] = map[string]string{"site": "HQ", "rack": ""}
			want[ids[1]] = map[string]string{}
		}
		if len(body.Machines) != len(want) || !reflect.DeepEqual(got, want) {
			t.Fatalf("GET %s machines = %v, want %v", path, got, want)
		}
		if !include && bytes.Contains(rec.Body.Bytes(), []byte(`"properties"`)) {
			t.Fatalf("plain list unexpectedly includes properties: %s", rec.Body)
		}
	}
	if len(spy.batches) != 1 || len(spy.batches[0]) != 2 {
		t.Fatalf("property lookup batches = %v, want one batch of two visible IDs", spy.batches)
	}
	if got := spy.batches[0]; !slices.Contains(got, ids[0]) || !slices.Contains(got, ids[1]) {
		t.Fatalf("property lookup IDs = %v, want %v", got, ids[:2])
	}
}

func TestBulkSetMachinePropertyHandler(t *testing.T) {
	const tenant = "tenant-123"
	ctx := context.Background()
	srv, ids := newMachinePropertyFleet(t, RoleAdmin)
	h := srv.Handler()
	post := func(req bulkSetMachinePropertyRequest, status int) []bulkStatusResult {
		t.Helper()
		b, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/machines/bulk-property", bytes.NewReader(b)))
		if rec.Code != status {
			t.Fatalf("bulk-property = %d, want %d: %s", rec.Code, status, rec.Body)
		}
		if status != http.StatusOK {
			return nil
		}
		var body struct {
			Results []bulkStatusResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Results
	}
	req := bulkSetMachinePropertyRequest{MachineIDs: append(ids[:], "missing"), Key: "site", Value: "HQ"}
	want := []bulkStatusResult{
		{MachineID: ids[0], OK: true},
		{MachineID: ids[1], OK: true},
		{MachineID: ids[2], Error: "denied"},
		{MachineID: "missing", Error: "unknown machine"},
	}
	if got := post(req, http.StatusOK); !reflect.DeepEqual(got, want) {
		t.Fatalf("set results = %+v, want %+v", got, want)
	}
	checkProperties := func(want map[string]map[string]string) {
		t.Helper()
		if got, err := srv.MachineProperties.ListPropertiesForMachines(ctx, tenant, ids[:]); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("stored properties = %v, %v, want %v", got, err, want)
		}
	}
	checkProperties(map[string]map[string]string{ids[0]: {"site": "HQ"}, ids[1]: {"site": "HQ"}})
	req.Delete = true
	req.Value = strings.Repeat("x", maxMachinePropertyValueLen+1)
	if got := post(req, http.StatusOK); !reflect.DeepEqual(got, want) {
		t.Fatalf("delete results = %+v, want %+v", got, want)
	}
	checkProperties(map[string]map[string]string{})
	want[0] = bulkStatusResult{MachineID: ids[0], Error: "not set"}
	want[1] = bulkStatusResult{MachineID: ids[1], Error: "not set"}
	if got := post(req, http.StatusOK); !reflect.DeepEqual(got, want) {
		t.Fatalf("re-delete results = %+v, want %+v", got, want)
	}

	events, err := srv.MgmtAudit.ListEvents(ctx, tenant, 10)
	if err != nil {
		t.Fatal(err)
	}
	audited := make(map[string]int)
	for _, event := range events {
		if event.Action != "machine.property.set" && event.Action != "machine.property.delete" {
			continue
		}
		var metadata struct {
			Key  string `json:"key"`
			Bulk bool   `json:"bulk"`
		}
		if err := json.Unmarshal(event.Metadata, &metadata); err != nil || metadata.Key != "site" || !metadata.Bulk || event.TargetKind != "machine" {
			t.Fatalf("unexpected audit event %+v (%v)", event, err)
		}
		audited[event.Action+"/"+event.TargetID]++
	}
	wantAudited := make(map[string]int)
	for _, action := range []string{"machine.property.set", "machine.property.delete"} {
		for _, id := range ids[:2] {
			wantAudited[action+"/"+id] = 1
		}
	}
	if !reflect.DeepEqual(audited, wantAudited) {
		t.Fatalf("audited mutations = %v, want %v", audited, wantAudited)
	}

	one := ids[:1]
	for _, invalid := range []bulkSetMachinePropertyRequest{
		{MachineIDs: one},
		{MachineIDs: one, Key: strings.Repeat("x", maxMachinePropertyKeyLen+1)},
		{MachineIDs: one, Key: "site", Value: req.Value},
		{Key: "site"},
		{MachineIDs: make([]string, 201), Key: "site"},
	} {
		post(invalid, http.StatusBadRequest)
	}
	atLimit := make([]string, 200)
	for i := range atLimit {
		atLimit[i] = "missing"
	}
	if got := post(bulkSetMachinePropertyRequest{MachineIDs: atLimit, Key: "site"}, http.StatusOK); len(got) != 200 {
		t.Fatalf("at limit returned %d results, want 200", len(got))
	}
	ro, _ := newMachinePropertyFleet(t, RoleReadOnly)
	rec := httptest.NewRecorder()
	ro.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/machines/bulk-property", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("read-only caller = %d, want 403", rec.Code)
	}

	srv.MgmtAudit = machinePropertyFailingAudit{MgmtAuditStore: srv.MgmtAudit}
	post(bulkSetMachinePropertyRequest{MachineIDs: one, Key: "site", Value: "HQ"}, http.StatusInternalServerError)
	checkProperties(map[string]map[string]string{})
}
