package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestPgMachineFieldReportScopeAndCursor(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	h := f.server.Handler()
	tenant := f.p.TenantID
	field := f.create(t, "n", "number")
	hiddenGroup, hidden := seedGroupMachine(t, f.su, tenant, "field-hidden")
	if err := f.store.SetProperty(f.ctx, tenant, hidden, "n", "1.00"); err != nil {
		t.Fatal(err)
	}
	err := withTenant(f.ctx, f.app, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `
			WITH seeded AS (
				INSERT INTO machine (id, tenant_id, device_id, group_id, hostname, pubkey, ephemeral)
				SELECT gen_random_uuid(), $1, 'report-' || n, $2, 'Host ' || n, ''::bytea, n = 204
				FROM generate_series(1, 204) n RETURNING tenant_id, id, device_id
			)
			INSERT INTO machine_property (tenant_id, machine_id, key, value)
			SELECT tenant_id, id, 'n', CASE WHEN device_id = 'report-203' THEN '1' ELSE '1.00' END FROM seeded
		`, tenant, f.group)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	owner := f.p.Grant
	f.p.Grant = NewGrant(f.p.UserID, tenant,
		NewMembership(RoleReadOnly, Groups(f.group)),
		NewCapabilityMembership([]Capability{CapManageTenant}, Groups(hiddenGroup)))
	path := "/machine-fields/n/nonconforming"
	var first, second machineFieldReport
	requireFieldResponse(t, fieldRequest(f.ctx, h, "GET", path, nil), 200, &first)
	if first.Total != 202 || len(first.Machines) != 200 || first.NextCursor == "" {
		t.Fatalf("first page: count=%d len=%d cursor=%q", first.Total, len(first.Machines), first.NextCursor)
	}
	for i, row := range first.Machines {
		if row.MachineID == hidden || row.MachineName == "" || row.Value != "1.00" ||
			(i > 0 && row.MachineID <= first.Machines[i-1].MachineID) {
			t.Fatalf("invalid row %d: %+v", i, row)
		}
	}
	cursorPath := path + "?cursor=" + first.NextCursor
	requireFieldResponse(t, fieldRequest(f.ctx, h, "GET", cursorPath, nil), 200, &second)
	if second.Total != 202 || len(second.Machines) != 2 || second.NextCursor != "" ||
		second.Machines[0].MachineID <= first.Machines[199].MachineID {
		t.Fatalf("second page: %+v", second)
	}
	requireFieldResponse(t, fieldRequest(f.ctx, h, "GET", path+"?cursor=!!", nil), 400, nil)
	requireFieldResponse(t, fieldRequest(f.ctx, h, "GET", path+"?cursor=", nil), 400, nil)
	cursor, err := readMachineFieldCursor(first.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mutate func(*machineFieldCursor)
		status int
	}{
		{func(c *machineFieldCursor) { c.TenantID = "garbage" }, 400},
		{func(c *machineFieldCursor) { c.TenantID = newUUID() }, 409},
		{func(c *machineFieldCursor) { c.Key = "different" }, 409},
		{func(c *machineFieldCursor) { c.FieldID = newUUID() }, 409},
		{func(c *machineFieldCursor) { c.Version++ }, 409},
	} {
		copy := *cursor
		tc.mutate(&copy)
		raw, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		bad := base64.RawURLEncoding.EncodeToString(raw)
		requireFieldResponse(t, fieldRequest(f.ctx, h, "GET", path+"?cursor="+bad, nil), tc.status, nil)
	}
	f.p.Grant = NewGrant(f.p.UserID, tenant, NewMembership(RoleReadOnly, Groups(hiddenGroup)))
	second = machineFieldReport{}
	requireFieldResponse(t, fieldRequest(f.ctx, h, "GET", cursorPath, nil), 200, &second)
	if second.Total != 1 {
		t.Fatalf("cursor reused previous scope: %+v", second)
	}
	f.p.Grant = owner
	requireFieldResponse(t, fieldRequest(f.ctx, h, "PUT", "/machine-fields/n", field), 200, nil)
	requireFieldResponse(t, fieldRequest(f.ctx, h, "GET", cursorPath, nil), 409, nil)
	requireFieldResponse(t, fieldRequest(f.ctx, h, "DELETE", "/machine-fields/n?id="+field.ID+"&version=2", nil), 204, nil)
	requireFieldResponse(t, fieldRequest(f.ctx, h, "GET", cursorPath, nil), 409, nil)
	f.create(t, "n", "number")
	requireFieldResponse(t, fieldRequest(f.ctx, h, "GET", cursorPath, nil), 409, nil)
}

func TestPgMachineFieldReportCanonicalParity(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	h := f.server.Handler()
	for _, tc := range []struct {
		typ    string
		values []string
	}{
		{"number", []string{"1.00", "-0", "-0.01", "+1", "1.123456", "1.1234567", "01", "0", "1\n", "1\u0085", "999999999999999", "9999999999999999"}},
		{"date", []string{"1900-02-29", "2000-02-29", "2100-02-29", "2004-02-29", "1900-01-01", "2999-12-31", "3000-01-01", "2024-04-31", "2024-00-01", " 2024-01-01 ", "bad"}},
		{"boolean", []string{"true", "false", "TRUE", "true ", "", "false\t"}},
		{"choice", []string{"HQ", "é", "hq", "É", "é ", "", "odd\t"}},
		{"text", []string{"", " x ", "x\t", "한글"}},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			field := MachineField{Key: tc.typ, Label: tc.typ, Type: tc.typ}
			if tc.typ == "choice" {
				field.Choices = []string{"HQ", "é"}
			}
			requireFieldResponse(t, fieldRequest(f.ctx, h, "POST", "/machine-fields", field), 201, nil)
			for _, value := range tc.values {
				if err := f.store.SetProperty(f.ctx, f.p.TenantID, f.machine, tc.typ, value); err != nil {
					t.Fatal(err)
				}
				var report machineFieldReport
				path := "/machine-fields/" + tc.typ + "/nonconforming"
				requireFieldResponse(t, fieldRequest(f.ctx, h, "GET", path, nil), 200, &report)
				conforms := fieldValueConforms(field, value)
				if conforms && (report.Total != 0 || len(report.Machines) != 0) ||
					!conforms && (report.Total != 1 || len(report.Machines) != 1 || report.Machines[0].Value != value) {
					t.Fatalf("value %q, conforms=%v, report=%+v", value, conforms, report)
				}
			}
		})
	}
}

type fieldWebhookObserver struct {
	WebhookStore
	check func(context.Context, string, string) error
	seen  chan error
}

func (s fieldWebhookObserver) ListDeliveriesForEvent(ctx context.Context, tenant, action string) ([]WebhookDelivery, error) {
	s.seen <- s.check(ctx, tenant, action)
	return nil, nil
}

func TestPgMachineFieldAuditRollbackAndDispatchAfterCommit(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	h := f.server.Handler()
	second := seedNamedMachine(t, f.su, f.p.TenantID, f.group, "field-second", "Second")
	ids := []string{f.machine, second}
	req := bulkSetMachinePropertyRequest{Key: "free", Value: "inventoried", MachineIDs: ids}
	seen := make(chan error, 10)
	dispatch := &WebhookDispatcher{Store: fieldWebhookObserver{
		seen: seen,
		check: func(ctx context.Context, tenant, action string) error {
			if action == "machine_field.created" {
				list, err := f.store.listFields(ctx, tenant)
				if err != nil || len(list.Fields) != 1 || list.OrderRevision != 1 {
					return fmt.Errorf("dispatch observed uncommitted definition: %+v, %v", list, err)
				}
				events, err := f.audit.ListEvents(ctx, tenant, 10)
				if err != nil || len(events) != 3 || events[0].Action != action {
					return fmt.Errorf("dispatch observed uncommitted definition audit: %d, %v", len(events), err)
				}
				return nil
			}
			if action != "machine.property.set" {
				return fmt.Errorf("unexpected dispatch %q", action)
			}
			props, err := f.store.ListPropertiesForMachines(ctx, tenant, ids)
			if err != nil || len(props) != 2 {
				return fmt.Errorf("dispatch observed uncommitted properties: %v, %v", props, err)
			}
			events, err := f.audit.ListEvents(ctx, tenant, 10)
			if err != nil || len(events) != 2 {
				return fmt.Errorf("dispatch observed uncommitted audit: %v, %v", len(events), err)
			}
			return nil
		},
	}}
	f.server.Dispatcher = dispatch
	t.Cleanup(dispatch.Stop)
	calls := 0
	f.audit.corrupt = func(event *MgmtAuditEvent) {
		calls++
		if calls == 2 {
			event.Action = "wrong"
		}
	}
	requireFieldResponse(t, fieldRequest(f.ctx, h, "POST", "/machines/bulk-property", req), 500, nil)
	if calls != 2 {
		t.Fatalf("failed before second audit append: %d calls", calls)
	}
	props, err := f.store.ListPropertiesForMachines(f.ctx, f.p.TenantID, ids)
	if err != nil || len(props) != 0 {
		t.Fatalf("failed batch left properties: %v, %v", props, err)
	}
	f.audit.corrupt = func(event *MgmtAuditEvent) { event.Action = "wrong" }
	requireFieldResponse(t, fieldRequest(f.ctx, h, "POST", "/machine-fields",
		MachineField{Key: "failed", Label: "Failed", Type: "text"}), 500, nil)
	requireFieldResponse(t, f.propertyRequest("free", "inventoried", false, false), 500, nil)
	list, err := f.store.listFields(f.ctx, f.p.TenantID)
	if err != nil || len(list.Fields) != 0 || list.OrderRevision != 0 {
		t.Fatalf("failed definition mutation left state: %+v, %v", list, err)
	}
	events, err := f.audit.ListEvents(f.ctx, f.p.TenantID, 10)
	if err != nil || len(events) != 0 {
		t.Fatalf("failed mutations left audit rows: %v, %v", events, err)
	}
	select {
	case err := <-seen:
		t.Fatalf("rolled-back mutation dispatched: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	f.audit.corrupt = nil
	requireFieldResponse(t, fieldRequest(f.ctx, h, "POST", "/machines/bulk-property", req), 200, nil)
	for range ids {
		select {
		case err := <-seen:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("committed batch did not dispatch")
		}
	}
	f.create(t, "committed", "text")
	select {
	case err := <-seen:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("committed definition did not dispatch")
	}
}
