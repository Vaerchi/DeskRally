package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgMachineFieldFixture struct {
	ctx            context.Context
	su, app        *pgxpool.Pool
	p              *Principal
	server         *Server
	store          *PgMachinePropertyStore
	audit          *PgMgmtAuditStore
	group, machine string
}

func newPgMachineFieldFixture(t *testing.T) *pgMachineFieldFixture {
	t.Helper()
	su := newTestPool(t)
	applyAppRoleMigration(t, su)
	applyMachinePropertyMigration(t, su)
	applyMgmtAuditChainMigration(t, su)
	applyMachineDeviceUniqueMigration(t, su)
	applyDeviceIdentityMigration(t, su)
	applyAttendedMigration(t, su)
	ddl, err := os.ReadFile("migrations/0088_machine_field.sql")
	if err != nil {
		t.Fatal(err)
	}
	execScript(t, su, string(ddl))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	tenant, user := provisionUser(t, su, "fields", "fields@example.test", "password-1234")
	p := &Principal{UserID: user, TenantID: tenant, Grant: NewGrant(user, tenant, NewMembership(RoleOwner, AllGroups()))}
	group, machine := seedGroupMachine(t, su, tenant, "field-device")
	app := newAppRolePool(t, ctx)
	srv := NewServer(StubAuthenticator{Principal: p}, NewPgBinder(app))
	store := NewPgMachinePropertyStore(app)
	audit := NewPgMgmtAuditStore(app)
	srv.MachineProperties, srv.MgmtAudit, srv.Machines = store, audit, NewPgMachineStore(app)
	return &pgMachineFieldFixture{ctx: ctx, su: su, app: app, p: p, server: srv, store: store,
		audit: audit, group: group, machine: machine}
}

func fieldRequest(ctx context.Context, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	buf, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(string(buf))).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func requireFieldResponse(t *testing.T, rec *httptest.ResponseRecorder, status int, dst any) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d: %s", rec.Code, status, rec.Body)
	}
	if dst != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
			t.Fatalf("decode %s: %v", rec.Body, err)
		}
	}
}

func (f *pgMachineFieldFixture) create(t *testing.T, key, typ string) MachineField {
	t.Helper()
	var result struct{ Field MachineField }
	requireFieldResponse(t, fieldRequest(f.ctx, f.server.Handler(), "POST", "/machine-fields",
		MachineField{Key: key, Label: key, Type: typ}), 201, &result)
	return result.Field
}

func TestPgMachineFieldIdentityAndPermissions(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	do := func(method, path string, body any, status int) *httptest.ResponseRecorder {
		t.Helper()
		rec := fieldRequest(f.ctx, f.server.Handler(), method, path, body)
		requireFieldResponse(t, rec, status, nil)
		return rec
	}
	owner := f.p.Grant
	field := f.create(t, "order", "number")
	do("PUT", "/machine-field-order", map[string]any{"order_revision": 0, "keys": []string{"order"}}, 409)
	do("PUT", "/machine-field-order", map[string]any{"order_revision": 1, "keys": []string{"missing"}}, 400)
	do("PUT", "/machine-field-order", map[string]any{"order_revision": 1, "keys": []string{"order"}}, 200)
	do("PUT", "/machine-fields/order", MachineField{Label: "Changed", Type: "number"}, 400)
	do("DELETE", "/machine-fields/order", nil, 400)
	do("PUT", "/machine-fields/order", field, 200)
	do("PUT", "/machine-fields/order", field, 409)
	do("DELETE", "/machine-fields/order?id="+field.ID+"&version=1", nil, 409)
	if rec := do("DELETE", "/machine-fields/order?id="+field.ID+"&version=2", nil, 204); rec.Body.Len() != 0 {
		t.Fatalf("DELETE returned body %q", rec.Body.String())
	}
	do("PUT", "/machine-field-order", map[string]any{"order_revision": 2, "keys": []string{}}, 409)
	do("PUT", "/machine-fields/order", field, 404)
	do("DELETE", "/machine-fields/order?id="+field.ID+"&version=1", nil, 404)
	newField := f.create(t, "order", "number")
	if field.ID == newField.ID || newField.Version != 1 {
		t.Fatalf("recreated identity = %+v, old %+v", newField, field)
	}
	do("PUT", "/machine-fields/order", field, 409)
	do("DELETE", "/machine-fields/order?id="+field.ID+"&version=1", nil, 409)
	f.p.Grant = NewGrant(f.p.UserID, f.p.TenantID,
		NewMembership(RoleOwner, Groups(f.group)), NewMembership(RoleReadOnly, AllGroups()))
	do("GET", "/machine-fields", nil, 200)
	do("POST", "/machine-fields", MachineField{Key: "x", Label: "X", Type: "text"}, 403)
	do("PUT", "/machine-fields/order", newField, 403)
	do("DELETE", "/machine-fields/order?id="+newField.ID+"&version=1", nil, 403)
	do("PUT", "/machine-field-order", map[string]any{"order_revision": 4, "keys": []string{"order"}}, 403)
	f.p.Grant = NewGrant(f.p.UserID, f.p.TenantID, NewCapabilityMembership([]Capability{CapManageTenant}, AllGroups()))
	do("GET", "/machine-fields", nil, 200)
	do("GET", "/machine-fields/order/nonconforming", nil, 403)
	f.p.Grant = owner
	if rec := do("GET", "/machine-fields", nil, 200); !strings.Contains(rec.Body.String(), newField.ID) {
		t.Fatalf("missing recreated definition: %s", rec.Body)
	}
}

func TestPgMachineFieldRLS(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	f.create(t, "x", "number")
	other, _ := provisionUser(t, f.su, "fields-other", "other@example.test", "password-1234")
	err := withTenant(f.ctx, f.app, other, func(tx pgx.Tx) error {
		var fields, revisions int
		err := tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM machine_field),
			(SELECT count(*) FROM machine_field_order)`).Scan(&fields, &revisions)
		if err != nil {
			return err
		}
		if fields != 0 || revisions != 0 {
			return fmt.Errorf("cross-tenant rows: %d fields, %d revisions", fields, revisions)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`INSERT INTO machine_field (tenant_id, key, id, label, type, position) VALUES ($1, 'bad', gen_random_uuid(), 'Bad', 'text', 1)`,
		`INSERT INTO machine_field_order (tenant_id, revision) VALUES ($1, 2)`,
	} {
		err := withTenant(f.ctx, f.app, other, func(tx pgx.Tx) error {
			_, err := tx.Exec(f.ctx, query, f.p.TenantID)
			return err
		})
		if pgErrCode(err) != "42501" {
			t.Fatalf("cross-tenant insert = %v", err)
		}
	}
	if err := f.store.SetProperty(f.ctx, other, f.machine, "x", "1"); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("cross-tenant property composite FK = %v", err)
	}
}

func TestPgUndefinedPropertySingleEditPrecedence(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	h := f.server.Handler()
	tenant := f.p.TenantID
	otherGroup, denied := seedGroupMachine(t, f.su, tenant, "undefined-field-denied")
	f.p.Grant = NewGrant(f.p.UserID, tenant, NewMembership(RoleOwner, Groups(f.group)))
	for _, tc := range []struct {
		name, method, id, body string
	}{
		{"malformed denied PUT", "PUT", denied, "{"},
		{"malformed missing PUT", "PUT", newUUID(), "{"},
		{"valid denied PUT", "PUT", denied, `{"value":"legacy"}`},
		{"denied DELETE", "DELETE", denied, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := httptest.NewRecorder()
			if tc.id == denied {
				writeDenied(want, f.p.Grant.RequireMachine(CapManageMachines, otherGroup))
			} else {
				writeError(want, http.StatusNotFound, "unknown machine")
			}
			req := httptest.NewRequest(tc.method, "/machines/"+tc.id+"/properties/legacy",
				strings.NewReader(tc.body)).WithContext(f.ctx)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			requireFieldResponse(t, rec, want.Code, nil)
			if rec.Body.String() != want.Body.String() {
				t.Fatalf("body = %s, want %s", rec.Body, want.Body)
			}
		})
	}
}

func TestPgMachineFieldPropertyHTTP(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	h := f.server.Handler()
	tenant := f.p.TenantID
	_, denied := seedGroupMachine(t, f.su, tenant, "field-denied")
	f.create(t, "n", "number")
	f.p.Grant = NewGrant(f.p.UserID, tenant, NewMembership(RoleOwner, Groups(f.group)))
	path := "/machines/" + f.machine + "/properties/n"
	rec := fieldRequest(f.ctx, h, "PUT", path, map[string]string{"value": " 007.500 "})
	var single struct{ Property MachineProperty }
	requireFieldResponse(t, rec, 200, &single)
	if single.Property.Value != "7.5" {
		t.Fatalf("single canonicalization: %+v", single)
	}
	rec = fieldRequest(f.ctx, h, "PUT", path, map[string]string{"value": "-0"})
	requireFieldResponse(t, rec, 400, nil)
	if !strings.Contains(rec.Body.String(), "invalid value for field n") {
		t.Fatalf("invalid message: %s", rec.Body)
	}
	bulk := bulkSetMachinePropertyRequest{Key: "n", Value: "-00", MachineIDs: []string{denied, "unknown", f.machine}}
	requireFieldResponse(t, fieldRequest(f.ctx, h, "POST", "/machines/bulk-property", bulk), 400, nil)
	props, err := f.store.ListProperties(f.ctx, tenant, f.machine)
	if err != nil || len(props) != 1 || props[0].Value != "7.5" {
		t.Fatalf("invalid batch altered values: %v, %v", props, err)
	}
	bulk.Value = "012.5000"
	var response struct{ Results []bulkStatusResult }
	requireFieldResponse(t, fieldRequest(f.ctx, h, "POST", "/machines/bulk-property", bulk), 200, &response)
	if len(response.Results) != 3 || response.Results[0].MachineID != denied || response.Results[0].Error != "denied" ||
		response.Results[1].Error != "unknown machine" || !response.Results[2].OK || response.Results[2].MachineID != f.machine {
		t.Fatalf("bulk outcomes: %+v", response.Results)
	}
	props, err = f.store.ListProperties(f.ctx, tenant, f.machine)
	if err != nil || len(props) != 1 || props[0].Value != "12.5" {
		t.Fatalf("bulk canonicalization: %v, %v", props, err)
	}
	hex := strings.ToUpper(strings.ReplaceAll(f.machine, "-", ""))
	for _, alias := range []string{hex, "{" + hex + "}",
		hex[:4] + "-" + hex[4:24] + "-" + hex[24:28] + "-" + hex[28:]} {
		var equal bool
		if err := f.app.QueryRow(f.ctx, `SELECT $1::uuid = $2::uuid`, f.machine, alias).Scan(&equal); err != nil || !equal {
			t.Fatalf("PostgreSQL did not accept alias %q: %v", alias, err)
		}
		for _, remove := range []bool{false, true} {
			req := bulkSetMachinePropertyRequest{Key: "n", Value: "5", Delete: remove, MachineIDs: []string{f.machine, alias}}
			requireFieldResponse(t, fieldRequest(f.ctx, h, "POST", "/machines/bulk-property", req), 400, nil)
		}
	}
	undefined := map[string]string{"value": " 007.500 "}
	requireFieldResponse(t, fieldRequest(f.ctx, h, "PUT", path+"-undefined", undefined), 200, &single)
	if single.Property.Value != undefined["value"] {
		t.Fatalf("undefined key was canonicalized: %+v", single)
	}
	bulk.Key = "n-undefined"
	requireFieldResponse(t, fieldRequest(f.ctx, h, "POST", "/machines/bulk-property", bulk), 200, nil)
	bulk.Delete = true
	requireFieldResponse(t, fieldRequest(f.ctx, h, "POST", "/machines/bulk-property", bulk), 200, nil)
	requireFieldResponse(t, fieldRequest(f.ctx, h, "POST", "/machines/bulk-property", bulk), 200, &response)
	if response.Results[2].Error != "not set" {
		t.Fatalf("bulk delete of absent key: %+v", response.Results)
	}
	events, err := f.audit.ListEvents(f.ctx, tenant, 20)
	if err != nil || len(events) != 6 {
		t.Fatalf("audit events: %d, %v", len(events), err)
	}
	for _, event := range events {
		var meta map[string]any
		if err := json.Unmarshal(event.Metadata, &meta); err != nil {
			t.Fatal(err)
		}
		for key := range meta {
			if key != "key" && key != "bulk" && key != "type" && key != "choice_count" {
				t.Fatalf("unexpected audit metadata %s", event.Metadata)
			}
		}
	}
}

func TestPgMachineFieldReordersWithoutChangingVersions(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	a := f.create(t, "a", "number")
	b := f.create(t, "b", "date")
	h := f.server.Handler()
	do := func(keys []string, want int) {
		t.Helper()
		requireFieldResponse(t, fieldRequest(f.ctx, h, "PUT", "/machine-field-order",
			map[string]any{"order_revision": 2, "keys": keys}), want, nil)
	}
	do([]string{"a", "a"}, 400)
	do([]string{"b", "a"}, 200)
	var list machineFieldList
	requireFieldResponse(t, fieldRequest(f.ctx, h, "GET", "/machine-fields", nil), 200, &list)
	if list.OrderRevision != 3 || len(list.Fields) != 2 || list.Fields[0].ID != b.ID ||
		list.Fields[1].ID != a.ID || list.Fields[0].Position != 0 || list.Fields[1].Position != 1 ||
		list.Fields[0].Version != b.Version || list.Fields[1].Version != a.Version {
		t.Fatalf("reordered fields: %+v", list)
	}
	do([]string{"a", "b"}, 409)
}

func TestPgBulkPropertyDatabaseErrorRollsBackEveryRow(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	const first = "00000000-0000-4000-8000-000000000001"
	const second = "00000000-0000-4000-8000-000000000002"
	execScript(t, f.su, `ALTER TABLE machine_property ADD CHECK (
		key <> 'failing' OR machine_id <> '00000000-0000-4000-8000-000000000002'
	)`)
	if err := withTenant(f.ctx, f.app, f.p.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `
			INSERT INTO machine (id, tenant_id, device_id, group_id, hostname, pubkey)
			VALUES ($1, $3, 'first-failure-fixture', $4, 'First', ''::bytea),
			       ($2, $3, 'second-failure-fixture', $4, 'Second', ''::bytea)
		`, first, second, f.p.TenantID, f.group)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ids := []string{first, second}
	req := bulkSetMachinePropertyRequest{Key: "failing", Value: "raw", MachineIDs: ids}
	requireFieldResponse(t, fieldRequest(f.ctx, f.server.Handler(), "POST", "/machines/bulk-property", req), 500, nil)
	props, err := f.store.ListPropertiesForMachines(f.ctx, f.p.TenantID, ids)
	if err != nil || len(props) != 0 {
		t.Fatalf("failed batch left properties: %v, %v", props, err)
	}
	events, err := f.audit.ListEvents(f.ctx, f.p.TenantID, 10)
	if err != nil || len(events) != 0 {
		t.Fatalf("failed batch left audit rows: %v, %v", events, err)
	}
}
