package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func (f *pgMachineFieldFixture) waitForBlockedFieldRequest(t *testing.T, blocker uint32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		err := f.su.QueryRow(f.ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))
		`, int32(blocker)).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("request never waited on the expected transaction")
}

func (f *pgMachineFieldFixture) propertyRequest(key, value string, bulk, remove bool) *httptest.ResponseRecorder {
	h := f.server.Handler()
	if bulk {
		return fieldRequest(f.ctx, h, "POST", "/machines/bulk-property",
			bulkSetMachinePropertyRequest{Key: key, Value: value, Delete: remove, MachineIDs: []string{f.machine}})
	}
	path := "/machines/" + f.machine + "/properties/" + key
	if remove {
		return fieldRequest(f.ctx, h, "DELETE", path, nil)
	}
	return fieldRequest(f.ctx, h, "PUT", path, map[string]string{"value": value})
}

func TestPgMachineFieldDefinitionWinsValueRace(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	for _, bulk := range []bool{false, true} {
		for _, action := range []string{"create", "edit", "delete"} {
			key := fmt.Sprintf("%s-%t", action, bulk)
			t.Run(key, func(t *testing.T) {
				if action != "create" {
					f.create(t, key, "boolean")
				}
				tx := beginTenantTx(t, f.app, f.p.TenantID)
				// Take the production lock with a different accepted tenant spelling.
				alias := strings.ToUpper(strings.ReplaceAll(f.p.TenantID, "-", ""))
				if err := lockMachineFieldsTx(f.ctx, tx, alias, false); err != nil {
					t.Fatal(err)
				}
				var err error
				want := 400
				switch action {
				case "create":
					_, err = tx.Exec(f.ctx, `INSERT INTO machine_field
						(tenant_id, key, id, label, type, position)
						VALUES ($1, $2, gen_random_uuid(), $2, 'number', 0)`, f.p.TenantID, key)
				case "edit":
					_, err = tx.Exec(f.ctx, `UPDATE machine_field SET type = 'number', version = version + 1
						WHERE tenant_id = $1 AND key = $2`, f.p.TenantID, key)
				case "delete":
					_, err = tx.Exec(f.ctx, `DELETE FROM machine_field WHERE tenant_id = $1 AND key = $2`, f.p.TenantID, key)
					want = 200
				}
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- f.propertyRequest(key, "false", bulk, false) }()
				f.waitForBlockedFieldRequest(t, tx.Conn().PgConn().PID())
				if err := tx.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				requireFieldResponse(t, <-done, want, nil)
				props, err := f.store.ListProperties(f.ctx, f.p.TenantID, f.machine)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, prop := range props {
					if prop.Key == key {
						found = prop.Value == "false"
					}
				}
				if found != (action == "delete") {
					t.Fatalf("properties after %s: %v", action, props)
				}
			})
		}
	}
}

func TestPgMachineFieldValueWinsDefinitionRace(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	for _, bulk := range []bool{false, true} {
		for _, action := range []string{"created", "updated", "deleted"} {
			key := fmt.Sprintf("%s-%t", action, bulk)
			t.Run(key, func(t *testing.T) {
				change := machineFieldChange{action: action, field: MachineField{Key: key, Label: key, Type: "number"}}
				if action != "created" {
					old := f.create(t, key, "boolean")
					change.field.ID, change.field.Version = old.ID, old.Version
				}
				// The property edit waits on a SHARE-conflicting row lock after it has
				// acquired the shared fields lock. The definition then queues behind it.
				tx := beginTenantTx(t, f.app, f.p.TenantID)
				if _, err := tx.Exec(f.ctx, `SELECT id FROM machine WHERE id = $1 FOR UPDATE`, f.machine); err != nil {
					t.Fatal(err)
				}
				editDone := make(chan *httptest.ResponseRecorder, 1)
				go func() { editDone <- f.propertyRequest(key, "false", bulk, false) }()
				f.waitForBlockedFieldRequest(t, tx.Conn().PgConn().PID())
				changeDone := make(chan error, 1)
				go func() {
					_, err := f.store.changeFields(f.ctx, f.p, f.audit, &change)
					changeDone <- err
				}()
				deadline := time.Now().Add(2 * time.Second)
				for {
					var waiting bool
					err := f.su.QueryRow(f.ctx, `SELECT EXISTS (
						SELECT 1 FROM pg_stat_activity WHERE wait_event_type = 'Lock'
						AND query LIKE 'SELECT pg_advisory_xact_lock(hashtextextended(''fields:%'
						AND cardinality(pg_blocking_pids(pid)) > 0
					)`).Scan(&waiting)
					if err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("definition never waited for the property edit")
					}
					time.Sleep(10 * time.Millisecond)
				}
				if err := tx.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				requireFieldResponse(t, <-editDone, 200, nil)
				if err := <-changeDone; err != nil {
					t.Fatal(err)
				}
				props, err := f.store.ListProperties(f.ctx, f.p.TenantID, f.machine)
				if err != nil {
					t.Fatal(err)
				}
				for _, prop := range props {
					if prop.Key == key && prop.Value == "false" {
						return
					}
				}
				t.Fatalf("value changed during definition mutation: %v", props)
			})
		}
	}
}

func TestPgMachineFieldConcurrentCap(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	if err := withTenant(f.ctx, f.app, f.p.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO machine_field (tenant_id, key, id, label, type, position)
			SELECT $1, 'seed-' || n, gen_random_uuid(), 'Field', 'text', n
			FROM generate_series(1, $2::int) AS n`, f.p.TenantID, maxMachineFields-1)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	tx := beginTenantTx(t, f.app, f.p.TenantID)
	if err := lockMachineFieldsTx(f.ctx, tx, f.p.TenantID, false); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	for _, key := range []string{"one", "two"} {
		go func() {
			change := machineFieldChange{action: "created", field: MachineField{Key: key, Label: key, Type: "text"}}
			_, err := f.store.changeFields(f.ctx, f.p, f.audit, &change)
			done <- err
		}()
	}
	f.waitForBlockedFieldRequest(t, tx.Conn().PgConn().PID())
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	first, second := <-done, <-done
	if !(first == nil && errors.Is(second, errFieldLimit) || second == nil && errors.Is(first, errFieldLimit)) {
		t.Fatalf("concurrent creates: %v and %v", first, second)
	}
	list, err := f.store.listFields(f.ctx, f.p.TenantID)
	if err != nil || len(list.Fields) != maxMachineFields || list.OrderRevision != 1 {
		t.Fatalf("cap result: fields=%d, revision=%d, error=%v", len(list.Fields), list.OrderRevision, err)
	}
}

func TestPgMachinePropertyMoveAndReparentRaces(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	tenant := f.p.TenantID
	otherGroup := seedGroup(t, f.su, tenant)
	f.create(t, "race", "number")
	for _, bulk := range []bool{false, true} {
		for _, remove := range []bool{false, true} {
			for _, reparent := range []bool{false, true} {
				name := fmt.Sprintf("bulk=%t,delete=%t,reparent=%t", bulk, remove, reparent)
				t.Run(name, func(t *testing.T) {
					f.p.Grant = NewGrant(f.p.UserID, tenant, NewMembership(RoleOwner, Groups(f.group)))
					f.p.Grant.reloadable = true
					if err := withTenant(f.ctx, f.app, tenant, func(tx pgx.Tx) error {
						var err error
						f.p.Grant.TreeVersion, err = groupTreeVersionTx(f.ctx, tx, tenant)
						return err
					}); err != nil {
						t.Fatal(err)
					}
					if err := f.store.SetProperty(f.ctx, tenant, f.machine, "race", "1"); err != nil {
						t.Fatal(err)
					}
					tx := beginTenantTx(t, f.app, tenant)
					var err error
					if reparent {
						_, err = tx.Exec(f.ctx, `UPDATE machine_group SET parent_id = $2 WHERE id = $1`, f.group, otherGroup)
					} else {
						if err := checkGroupTreeVersionTx(f.ctx, tx, tenant, f.p.Grant.TreeVersion); err != nil {
							t.Fatal(err)
						}
						_, err = tx.Exec(f.ctx, `UPDATE machine SET group_id = $2 WHERE id = $1`, f.machine, otherGroup)
					}
					if err != nil {
						t.Fatal(err)
					}
					done := make(chan *httptest.ResponseRecorder, 1)
					go func() { done <- f.propertyRequest("race", "2", bulk, remove) }()
					f.waitForBlockedFieldRequest(t, tx.Conn().PgConn().PID())
					if err := tx.Commit(f.ctx); err != nil {
						t.Fatal(err)
					}
					rec := <-done
					switch {
					case reparent:
						requireFieldResponse(t, rec, 409, nil)
					case bulk:
						requireFieldResponse(t, rec, 200, nil)
						if !strings.Contains(rec.Body.String(), "denied") {
							t.Fatalf("moved target result: %s", rec.Body)
						}
					default:
						want := httptest.NewRecorder()
						writeDenied(want, f.p.Grant.RequireMachine(CapManageMachines, otherGroup))
						requireFieldResponse(t, rec, want.Code, nil)
						if rec.Body.String() != want.Body.String() {
							t.Fatalf("moved target body = %s, want %s", rec.Body, want.Body)
						}
					}
					props, err := f.store.ListProperties(f.ctx, tenant, f.machine)
					if err != nil || len(props) != 1 || props[0].Value != "1" {
						t.Fatalf("racing property write landed: %v, %v", props, err)
					}
					if reparent {
						// A static grant carries no tree precondition. Its write must still work.
						f.p.Grant = NewGrant(f.p.UserID, tenant, NewMembership(RoleOwner, AllGroups()))
						requireFieldResponse(t, f.propertyRequest("race", "2", bulk, remove), 200, nil)
					}
					if err := withTenant(f.ctx, f.app, tenant, func(tx pgx.Tx) error {
						if reparent {
							_, err := tx.Exec(f.ctx, `UPDATE machine_group SET parent_id = NULL WHERE id = $1`, f.group)
							return err
						}
						_, err := tx.Exec(f.ctx, `UPDATE machine SET group_id = $2 WHERE id = $1`, f.machine, f.group)
						return err
					}); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestPgMachinePropertyDeletesSkipFieldsLock(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	for _, bulk := range []bool{false, true} {
		if err := f.store.SetProperty(f.ctx, f.p.TenantID, f.machine, "free", "x"); err != nil {
			t.Fatal(err)
		}
		tx := beginTenantTx(t, f.app, f.p.TenantID)
		if err := lockMachineFieldsTx(f.ctx, tx, f.p.TenantID, false); err != nil {
			t.Fatal(err)
		}
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- f.propertyRequest("free", "", bulk, true) }()
		select {
		case rec := <-done:
			requireFieldResponse(t, rec, 200, nil)
		case <-time.After(2 * time.Second):
			t.Fatal("property DELETE waited on the fields lock")
		}
		if err := tx.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPgMachinePropertyTreeLockTimeoutIsConflict(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	tenant := f.p.TenantID
	if err := withTenant(f.ctx, f.app, tenant, func(tx pgx.Tx) error {
		var err error
		f.p.Grant.TreeVersion, err = groupTreeVersionTx(f.ctx, tx, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.p.Grant.reloadable = true
	oldWait := groupTreeLockWait
	groupTreeLockWait = 50 * time.Millisecond
	t.Cleanup(func() { groupTreeLockWait = oldWait })
	tx := beginTenantTx(t, f.app, tenant)
	if err := lockGroupTreeTx(f.ctx, tx, tenant, false); err != nil {
		t.Fatal(err)
	}
	for _, bulk := range []bool{false, true} {
		for _, remove := range []bool{false, true} {
			requireFieldResponse(t, f.propertyRequest("tree", "true", bulk, remove), 409, nil)
		}
	}
}

func TestPgBulkPropertyLocksRowsInUUIDOrder(t *testing.T) {
	f := newPgMachineFieldFixture(t)
	tenant := f.p.TenantID
	second := seedNamedMachine(t, f.su, tenant, f.group, "field-order-second", "Second")
	first, last := f.machine, second
	if first > last {
		first, last = last, first
	}
	for _, remove := range []bool{false, true} {
		tx := beginTenantTx(t, f.app, tenant)
		if _, err := tx.Exec(f.ctx, `SELECT id FROM machine WHERE id = $1 FOR UPDATE`, first); err != nil {
			t.Fatal(err)
		}
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			done <- fieldRequest(f.ctx, f.server.Handler(), "POST", "/machines/bulk-property",
				bulkSetMachinePropertyRequest{Key: "ordered", Value: "1", Delete: remove, MachineIDs: []string{last, first}})
		}()
		f.waitForBlockedFieldRequest(t, tx.Conn().PgConn().PID())
		// If the bulk request locked its first input before waiting on the lower UUID,
		// this grab fails with lock_not_available.
		if _, err := tx.Exec(f.ctx, `SELECT id FROM machine WHERE id = $1 FOR UPDATE NOWAIT`, last); err != nil {
			t.Fatalf("bulk acquired machine locks in request order: %v", err)
		}
		if err := tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
		requireFieldResponse(t, <-done, 200, nil)
	}
}
