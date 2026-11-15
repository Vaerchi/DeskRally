package controlplane

// Proofs for machine lifecycle status / quarantine (docs/01 §4): the validator, the store (fake + pg
// under RLS), the HTTP surface (CapManageMachines group-scoped gate + validation + audit), and the
// session-start enforcement (a quarantined/retired machine is refused a new session).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestIsValidMachineStatus(t *testing.T) {
	for _, s := range []string{MachineStatusActive, MachineStatusQuarantined, MachineStatusRetired} {
		if !IsValidMachineStatus(s) {
			t.Fatalf("IsValidMachineStatus(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "bogus", "Active", "ACTIVE", "quarantine", "deleted"} {
		if IsValidMachineStatus(s) {
			t.Fatalf("IsValidMachineStatus(%q) = true, want false", s)
		}
	}
}

func TestInMemoryMachineStatus(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMachineStore()
	m := &Machine{DeviceID: "dev-1", GroupID: "g1"}
	if err := s.EnrollMachine(ctx, "t1", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	// A newly enrolled machine defaults to active (mirrors the DB DEFAULT).
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.Status != MachineStatusActive {
		t.Fatalf("new machine status = %q, want active", got.Status)
	}

	// Quarantine is reflected by both read paths and the listing.
	if err := s.SetMachineStatus(ctx, "t1", m.ID, MachineStatusQuarantined); err != nil {
		t.Fatalf("set status: %v", err)
	}
	if got, _ := s.GetMachine(ctx, "t1", "dev-1"); got.Status != MachineStatusQuarantined {
		t.Fatalf("GetMachine status = %q, want quarantined", got.Status)
	}
	list, _ := s.ListMachines(ctx, "t1")
	if len(list) != 1 || list[0].Status != MachineStatusQuarantined {
		t.Fatalf("ListMachines status = %+v, want [quarantined]", list)
	}

	// An invalid status is ErrInvalidMachineStatus; an unknown id (or another tenant's) is ErrMachineNotFound.
	if err := s.SetMachineStatus(ctx, "t1", m.ID, "bogus"); !errors.Is(err, ErrInvalidMachineStatus) {
		t.Fatalf("invalid status err = %v, want ErrInvalidMachineStatus", err)
	}
	if err := s.SetMachineStatus(ctx, "t1", "no-such-pk", MachineStatusRetired); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("unknown machine err = %v, want ErrMachineNotFound", err)
	}
	if err := s.SetMachineStatus(ctx, "t2", m.ID, MachineStatusRetired); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("cross-tenant err = %v, want ErrMachineNotFound", err)
	}
}

func TestSetMachineStatusHandler(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	ctx := context.Background()
	m := &Machine{DeviceID: "dev-h", GroupID: DevDefaultMachineGroupID}
	if err := srv.Machines.EnrollMachine(ctx, "tenant-123", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	h := srv.Handler()
	post := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}

	// Owner quarantines the machine → 200, body carries the new status, and it is audited.
	if rec := post("POST", "/machines/"+m.ID+"/status", `{"status":"quarantined"}`); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "quarantined") {
		t.Fatalf("quarantine = %d body %s, want 200 with quarantined", rec.Code, rec.Body.String())
	}
	audit := post("GET", "/audit?action=machine.status_set", "")
	var ar struct {
		Events []MgmtAuditEvent `json:"events"`
	}
	_ = json.Unmarshal(audit.Body.Bytes(), &ar)
	if len(ar.Events) != 1 || ar.Events[0].TargetID != m.ID {
		t.Fatalf("audit = %+v, want one machine.status_set for %s", ar.Events, m.ID)
	}
	// The listing reflects the new status.
	list := post("GET", "/machines", "")
	if !strings.Contains(list.Body.String(), "quarantined") {
		t.Fatalf("listing did not reflect quarantine: %s", list.Body.String())
	}
	// An invalid status is 400.
	if rec := post("POST", "/machines/"+m.ID+"/status", `{"status":"deleted"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad status = %d, want 400", rec.Code)
	}
	// Reactivate → 200.
	if rec := post("POST", "/machines/"+m.ID+"/status", `{"status":"active"}`); rec.Code != http.StatusOK {
		t.Fatalf("reactivate = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// A Technician holds no CapManageMachines → forbidden for the machine's group.
	techSrv, _ := newTestServer(&Principal{UserID: "u2", TenantID: "tenant-123",
		Grant: NewGrant("u2", "tenant-123", NewMembership(RoleTechnician, AllGroups()))})
	if err := techSrv.Machines.EnrollMachine(ctx, "tenant-123", &Machine{ID: m.ID, DeviceID: "dev-h2", GroupID: DevDefaultMachineGroupID}); err != nil {
		t.Fatalf("enroll for tech srv: %v", err)
	}
	rec := httptest.NewRecorder()
	techSrv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/machines/"+m.ID+"/status", strings.NewReader(`{"status":"quarantined"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("technician set status = %d, want 403", rec.Code)
	}
}

func TestStartSessionRefusedForQuarantinedMachine(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	ctx := context.Background()
	m := &Machine{DeviceID: "dev-quar", GroupID: DevDefaultMachineGroupID}
	if err := srv.Machines.EnrollMachine(ctx, "tenant-123", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	h := srv.Handler()
	start := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"machine_id":"dev-quar"}`)))
		return rec
	}
	const blocked = "reactivate it to start a session"

	// Active: the status gate lets it through (whatever happens downstream, it is NOT our 409).
	if rec := start(); strings.Contains(rec.Body.String(), blocked) {
		t.Fatalf("active machine was blocked as if quarantined: %d %s", rec.Code, rec.Body.String())
	}
	// Quarantined → 409 naming the status.
	if err := srv.Machines.SetMachineStatus(ctx, "tenant-123", m.ID, MachineStatusQuarantined); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if rec := start(); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "quarantined") {
		t.Fatalf("quarantined start = %d body %s, want 409 quarantined", rec.Code, rec.Body.String())
	}
	// Retired → 409 naming the status.
	if err := srv.Machines.SetMachineStatus(ctx, "tenant-123", m.ID, MachineStatusRetired); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if rec := start(); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "retired") {
		t.Fatalf("retired start = %d body %s, want 409 retired", rec.Code, rec.Body.String())
	}
}

// TestSetMachineStatusQuarantineEndsLiveSession proves that quarantine/retire end any open session for the
// machine immediately, and that setting to active does NOT. Mutation guard: removing the
// EndSessionsForMachine call in handleSetMachineStatus leaves the session open → first assertion fails.
func TestSetMachineStatusQuarantineEndsLiveSession(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	ctx := context.Background()
	m := &Machine{DeviceID: "dev-qsr", GroupID: DevDefaultMachineGroupID}
	if err := srv.Machines.EnrollMachine(ctx, "tenant-123", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// Open a live session for this machine.
	rec := &SessionRecord{MachineID: m.ID, TechnicianID: "u1", MachineGroupID: DevDefaultMachineGroupID}
	if err := srv.SessionRecords.StartSession(ctx, "tenant-123", rec); err != nil {
		t.Fatalf("start session: %v", err)
	}

	h := srv.Handler()
	post := func(path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("POST", path, strings.NewReader(body)))
		return rr
	}

	// Quarantining must end the live session immediately.
	if rr := post("/machines/"+m.ID+"/status", `{"status":"quarantined"}`); rr.Code != http.StatusOK {
		t.Fatalf("quarantine = %d %s", rr.Code, rr.Body.String())
	}
	got, err := srv.SessionRecords.GetSession(ctx, "tenant-123", rec.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.EndedAt == nil {
		t.Fatal("session.EndedAt = nil after quarantine; EndSessionsForMachine must be called on quarantine/retire")
	}

	// Negative control: setting to active must NOT end sessions (guards the != MachineStatusActive branch).
	// Re-activate the machine, start a fresh session, set active again — the session stays open.
	post("/machines/"+m.ID+"/status", `{"status":"active"}`)
	rec2 := &SessionRecord{MachineID: m.ID, TechnicianID: "u1", MachineGroupID: DevDefaultMachineGroupID}
	if err := srv.SessionRecords.StartSession(ctx, "tenant-123", rec2); err != nil {
		t.Fatalf("start session2: %v", err)
	}
	if rr := post("/machines/"+m.ID+"/status", `{"status":"active"}`); rr.Code != http.StatusOK {
		t.Fatalf("set-active = %d %s", rr.Code, rr.Body.String())
	}
	got2, err := srv.SessionRecords.GetSession(ctx, "tenant-123", rec2.ID)
	if err != nil {
		t.Fatalf("GetSession2: %v", err)
	}
	if got2.EndedAt != nil {
		t.Fatal("session.EndedAt != nil after active-status set; active must never end sessions")
	}
}

// TestBulkSetMachineStatusEndsLiveSessions proves that the bulk path ends live sessions for every
// quarantined machine. Mutation guard: removing EndSessionsForMachine from applyBulkStatusOne leaves
// sessions open → the EndedAt assertions below fail.
func TestBulkSetMachineStatusEndsLiveSessions(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	ctx := context.Background()

	m1 := &Machine{DeviceID: "dev-bulk1", GroupID: DevDefaultMachineGroupID}
	m2 := &Machine{DeviceID: "dev-bulk2", GroupID: DevDefaultMachineGroupID}
	for _, m := range []*Machine{m1, m2} {
		if err := srv.Machines.EnrollMachine(ctx, "tenant-123", m); err != nil {
			t.Fatalf("enroll %s: %v", m.DeviceID, err)
		}
	}

	r1 := &SessionRecord{MachineID: m1.ID, TechnicianID: "u1", MachineGroupID: DevDefaultMachineGroupID}
	r2 := &SessionRecord{MachineID: m2.ID, TechnicianID: "u1", MachineGroupID: DevDefaultMachineGroupID}
	for _, r := range []*SessionRecord{r1, r2} {
		if err := srv.SessionRecords.StartSession(ctx, "tenant-123", r); err != nil {
			t.Fatalf("start session: %v", err)
		}
	}

	body := `{"machine_ids":["` + m1.ID + `","` + m2.ID + `"],"status":"quarantined"}`
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest("POST", "/machines/bulk-status", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("bulk-status = %d %s", rr.Code, rr.Body.String())
	}

	// Both sessions must be ended.
	for _, r := range []*SessionRecord{r1, r2} {
		got, err := srv.SessionRecords.GetSession(ctx, "tenant-123", r.ID)
		if err != nil {
			t.Fatalf("GetSession machine %s: %v", r.MachineID, err)
		}
		if got.EndedAt == nil {
			t.Fatalf("session for machine %s: EndedAt = nil after bulk quarantine, want non-nil", r.MachineID)
		}
	}

	// Each result carries ok:true.
	var resp struct {
		Results []bulkStatusResult `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode bulk response: %v", err)
	}
	for _, res := range resp.Results {
		if !res.OK {
			t.Fatalf("bulk result for %s: ok=false, error=%q", res.MachineID, res.Error)
		}
	}
}

// TestPgMachineStatus drives PgMachineStore.SetMachineStatus + the status projection as rmt_app: a new
// machine defaults to active, quarantine is reflected by every read path, an invalid status is refused
// before the DB, and a cross-tenant set is ErrMachineNotFound (RLS hides the row).
func TestPgMachineStatus(t *testing.T) {
	suPool := newTestPool(t)
	applyAttendedMigration(t, suPool) // 0013: the machine projection includes ephemeral/expires_at
	applyAppRoleMigration(t, suPool)  // the RLS-subject rmt_app role + grants
	tidA, _ := provisionUser(t, suPool, "ms-a", "a@ms-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "ms-b", "b@ms-b.test", "password-1234")
	ctx := context.Background()

	var gidA, devA string
	if err := suPool.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&gidA, &devA); err != nil {
		t.Fatalf("gen uuids: %v", err)
	}
	if err := withTenant(ctx, suPool, tidA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO machine_group (id, tenant_id, name) VALUES ($1,$2,'G')`, gidA, tidA)
		return err
	}); err != nil {
		t.Fatalf("insert group: %v", err)
	}

	// Store ops run as the RLS-subject app role, so a cross-tenant write is genuinely invisible.
	appPool := newAppRolePool(t, ctx)
	store := NewPgMachineStore(appPool)
	m := &Machine{DeviceID: devA, GroupID: gidA, Name: "host-A"}
	if err := store.EnrollMachine(ctx, tidA, m); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if got, _ := store.GetMachineByID(ctx, tidA, m.ID); got.Status != MachineStatusActive {
		t.Fatalf("new machine status = %q, want active", got.Status)
	}

	if err := store.SetMachineStatus(ctx, tidA, m.ID, MachineStatusQuarantined); err != nil {
		t.Fatalf("set status: %v", err)
	}
	if got, _ := store.GetMachine(ctx, tidA, devA); got.Status != MachineStatusQuarantined {
		t.Fatalf("GetMachine status = %q, want quarantined", got.Status)
	}
	list, _ := store.ListMachines(ctx, tidA)
	if len(list) != 1 || list[0].Status != MachineStatusQuarantined {
		t.Fatalf("ListMachines status = %+v, want [quarantined]", list)
	}

	if err := store.SetMachineStatus(ctx, tidA, m.ID, "bogus"); !errors.Is(err, ErrInvalidMachineStatus) {
		t.Fatalf("invalid status err = %v, want ErrInvalidMachineStatus", err)
	}
	// Cross-tenant (pinned to B, targeting A's machine) is ErrMachineNotFound, and A is untouched.
	if err := store.SetMachineStatus(ctx, tidB, m.ID, MachineStatusRetired); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("cross-tenant set err = %v, want ErrMachineNotFound", err)
	}
	if got, _ := store.GetMachineByID(ctx, tidA, m.ID); got.Status != MachineStatusQuarantined {
		t.Fatalf("A machine should be unchanged, status = %q", got.Status)
	}
}
