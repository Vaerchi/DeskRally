package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const observerTestDevice = "22222222-2222-4222-8222-222222222222"

type observerStartResponse struct {
	Session   SessionRecord `json:"session"`
	Signaling struct {
		Ticket SignedSessionTicket `json:"ticket"`
	} `json:"signaling"`
	SessionPolicy *struct {
		Access   string `json:"access"`
		ViewOnly bool   `json:"view_only"`
		Signed   string `json:"signed"`
	} `json:"session_policy"`
}

func newObserverPGFixture(t *testing.T) *toolboxFixture {
	t.Helper()
	f := newToolboxFixture(t)
	applyMigrationFile(t, f.su, "migrations/0058_observer.sql")
	mustExec(t, f.su, `UPDATE machine SET device_id = $1, agent_version = '0.1.3+x', require_session_policy = false WHERE tenant_id = $2 AND device_id = 'tb-dev'`, observerTestDevice, f.tenant)
	if err := f.ownerSrv.GroupSessionPolicies.Set(t.Context(), f.tenant, f.groupID, GroupSessionPolicy{}); err != nil {
		t.Fatal(err)
	}
	f.ownerSrv.SignalingURL = "ws://signal.example/ws"
	return f
}

func observerStart(t *testing.T, srv *Server, access string) (int, observerStartResponse) {
	t.Helper()
	var out observerStartResponse
	body := fmt.Sprintf(`{"machine_id":%q,"access":%q}`, observerTestDevice, access)
	code := apiJSON(t, srv, "POST", "/sessions", body, &out)
	return code, out
}

func observerEnd(t *testing.T, f *toolboxFixture, id string) {
	t.Helper()
	if _, err := f.ownerSrv.SessionRecords.EndSession(t.Context(), f.tenant, id, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func observerRequirePolicy(t *testing.T, out observerStartResponse, access string) {
	t.Helper()
	p := out.SessionPolicy
	if p == nil || p.Access != access || p.ViewOnly != (access == "view_only") {
		t.Fatalf("policy wrapper = %+v, want %s", p, access)
	}
	var signed struct {
		Claims struct {
			Policy struct {
				Access    string `json:"access"`
				SessionID string `json:"session_id"`
				MachineID string `json:"machine_id"`
			} `json:"policy"`
		} `json:"claims"`
		SigV1 string `json:"sig_v1"`
	}
	if err := json.Unmarshal([]byte(p.Signed), &signed); err != nil {
		t.Fatalf("signed policy: %v", err)
	}
	if signed.Claims.Policy.Access != access || signed.Claims.Policy.SessionID != out.Session.ID || signed.Claims.Policy.MachineID != observerTestDevice {
		t.Fatalf("signed policy binding/access = %+v", signed.Claims.Policy)
	}
	if sig, err := hex.DecodeString(signed.SigV1); err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("invalid signed policy signature %q: %v", signed.SigV1, err)
	}
}

func TestObserverStartPGPermissionsAndArtifacts(t *testing.T) {
	f := newObserverPGFixture(t)
	// These are custom roles, not presets that acquire observe_session in 0058.
	withoutObserve := f.serverFor(observerCustomPrincipal(f.owner, f.tenant,
		CapViewMachines, CapStartSession, CapEndSession, CapViewSessions))
	if code, _ := observerStart(t, withoutObserve, "view_only"); code != http.StatusForbidden {
		t.Fatalf("without observe_session = %d, want 403", code)
	}
	withoutStart := f.serverFor(observerCustomPrincipal(f.owner, f.tenant,
		CapViewMachines, CapObserveSession, CapEndSession, CapViewSessions))
	if code, _ := observerStart(t, withoutStart, "view_only"); code != http.StatusForbidden {
		t.Fatalf("observe_session without start_session = %d, want 403", code)
	}
	withBoth := f.serverFor(observerCustomPrincipal(f.owner, f.tenant,
		CapViewMachines, CapStartSession, CapObserveSession, CapEndSession, CapViewSessions))
	withBoth.SignalingURL = "ws://signal.example/ws"
	code, out := observerStart(t, withBoth, "view_only")
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("authorized observer = %d", code)
	}
	if out.Session.ID == "" || out.Session.Access != "view_only" {
		t.Fatalf("session = %+v", out.Session)
	}
	// Inspect persisted state independently of the HTTP response.
	var stored string
	if err := f.su.QueryRow(t.Context(), `SELECT access FROM session_record WHERE tenant_id = $1 AND id = $2`, f.tenant, out.Session.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "view_only" {
		t.Fatalf("persisted access = %q", stored)
	}
	observerRequirePolicy(t, out, "view_only")
	ticket := out.Signaling.Ticket
	if ticket.Claims.V != 2 || ticket.Claims.Access != "view_only" || ticket.Claims.SessionID != out.Session.ID || ticket.Claims.DeviceID != observerTestDevice || ticket.Claims.TenantID != f.tenant || ticket.Claims.TechnicianID != f.owner {
		t.Fatalf("ticket = %+v", ticket.Claims)
	}
	sig, err := hex.DecodeString(ticket.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(withBoth.Grants.priv.Public().(ed25519.PublicKey), ticketSigningBytes(ticket.Claims), sig) {
		t.Fatal("start ticket signature does not verify")
	}
	events := observerAuditMetadata(t, f, "session.start", out.Session.ID)
	// docs/49 measurement: each start names the agent build serving it (the fixture's 0.1.3+x).
	if len(events) != 1 || events[0]["access"] != "view_only" || events[0]["agent_version"] != "0.1.3+x" {
		t.Fatalf("session.start metadata = %+v", events)
	}
}

func TestObserverStartPGVersionAndAccessValidation(t *testing.T) {
	f := newObserverPGFixture(t)
	for _, tc := range []struct {
		version string
		want    int
	}{
		{"0.1.2+x", http.StatusConflict},
		{"garbage", http.StatusConflict},
		{"0.1.3+x", http.StatusCreated},
	} {
		t.Run(tc.version, func(t *testing.T) {
			mustExec(t, f.su, `UPDATE machine SET agent_version = $1 WHERE tenant_id = $2 AND device_id = $3`, tc.version, f.tenant, observerTestDevice)
			code, out := observerStart(t, f.ownerSrv, "view_only")
			if code != tc.want {
				t.Fatalf("version %q: status %d, want %d", tc.version, code, tc.want)
			}
			if code == http.StatusCreated {
				observerEnd(t, f, out.Session.ID)
			}
		})
	}
	if code, _ := observerStart(t, f.ownerSrv, "admin"); code != http.StatusBadRequest {
		t.Fatalf("access admin = %d, want 400", code)
	}
	// A PRESENT empty or null access is refused, never defaulted to control (only an omitted field is).
	if code, _ := observerStart(t, f.ownerSrv, ""); code != http.StatusBadRequest {
		t.Fatalf("access \"\" = %d, want 400", code)
	}
	var ignored observerStartResponse
	if code := apiJSON(t, f.ownerSrv, "POST", "/sessions", fmt.Sprintf(`{"machine_id":%q,"access":null}`, observerTestDevice), &ignored); code != http.StatusBadRequest {
		t.Fatalf("access null = %d, want 400", code)
	}
	var omitted observerStartResponse
	if code := apiJSON(t, f.ownerSrv, "POST", "/sessions", fmt.Sprintf(`{"machine_id":%q}`, observerTestDevice), &omitted); code != http.StatusCreated || omitted.Session.Access != "control" {
		t.Fatalf("omitted access = %d %q, want 201 control", code, omitted.Session.Access)
	}
	observerEnd(t, f, omitted.Session.ID)
	var open int
	if err := f.su.QueryRow(t.Context(), `SELECT count(*) FROM session_record WHERE tenant_id = $1 AND ended_at IS NULL`, f.tenant).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if open != 0 {
		t.Fatalf("refusals leaked %d open records", open)
	}
}

func TestObserverStartPGAtomicTwoObserverLimitAndRelease(t *testing.T) {
	f := newObserverPGFixture(t)
	// Separate server instances share only Postgres admission state.
	servers := []*Server{f.ownerSrv, f.serverFor(&Principal{
		UserID: f.owner, TenantID: f.tenant,
		Grant: NewGrant(f.owner, f.tenant, NewMembership(RoleOwner, AllGroups())),
	})}
	for _, srv := range servers {
		srv.SignalingURL = "ws://signal.example/ws"
	}
	const n = 3
	results := make([]*httptest.ResponseRecorder, n)
	ready := make(chan struct{})
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-ready
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/sessions", strings.NewReader(fmt.Sprintf(`{"machine_id":%q,"access":"view_only"}`, observerTestDevice)))
			servers[i%len(servers)].Handler().ServeHTTP(w, r)
			results[i] = w
		}(i)
	}
	close(ready)
	wg.Wait()
	var ids []string
	refused := 0
	for _, w := range results {
		switch w.Code {
		case http.StatusCreated, http.StatusOK:
			var out observerStartResponse
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out.Session.ID == "" {
				t.Fatal("successful start has no session id")
			}
			ids = append(ids, out.Session.ID)
		case http.StatusConflict:
			refused++
		default:
			t.Fatalf("concurrent start = %d: %s", w.Code, w.Body.String())
		}
	}
	if len(ids) != 2 || refused != 1 {
		t.Fatalf("admitted %d, refused %d; want 2 and 1", len(ids), refused)
	}
	var open int
	if err := f.su.QueryRow(t.Context(), `SELECT count(*) FROM session_record WHERE tenant_id = $1 AND access = 'view_only' AND ended_at IS NULL`, f.tenant).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if open != 2 {
		t.Fatalf("persisted open observers = %d, want 2", open)
	}
	if code, _ := observerStart(t, servers[1], "view_only"); code != http.StatusConflict {
		t.Fatalf("third observer with two open = %d, want 409", code)
	}
	observerEnd(t, f, ids[0])
	if code, _ := observerStart(t, servers[1], "view_only"); code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("observer after ending one = %d", code)
	}
	if code, _ := observerStart(t, f.ownerSrv, "view_only"); code != http.StatusConflict {
		t.Fatalf("replacement did not consume freed slot: %d", code)
	}
}

func TestObserverStartPGConsumesTenantSessionSeats(t *testing.T) {
	f := newObserverPGFixture(t)
	observerSetTenantSessionCap(t, f, 1)
	code, control := observerStart(t, f.ownerSrv, "control")
	if code != http.StatusCreated {
		t.Fatalf("control start = %d", code)
	}
	if code, _ := observerStart(t, f.ownerSrv, "view_only"); code != http.StatusConflict {
		t.Fatalf("observer with one occupied tenant seat = %d, want 409", code)
	}
	observerEnd(t, f, control.Session.ID)
	code, observer := observerStart(t, f.ownerSrv, "view_only")
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("observer with free tenant seat = %d", code)
	}
	if observer.Session.Access != "view_only" {
		t.Fatalf("access = %q", observer.Session.Access)
	}
	if code, _ := observerStart(t, f.ownerSrv, "control"); code != http.StatusConflict {
		t.Fatalf("control while observer occupies tenant seat = %d, want 409", code)
	}
}

// cancelAfterAdmission cancels the request context the moment admission commits, the way a client
// that disconnects mid-start does. The very next store call in the handler then fails on that context.
type cancelAfterAdmission struct {
	SessionRecordStore
	cancel context.CancelFunc
}

func (c cancelAfterAdmission) StartSessionWithinLimit(ctx context.Context, tenantID string, rec *SessionRecord, limits SessionStartLimits) error {
	err := c.SessionRecordStore.StartSessionWithinLimit(ctx, tenantID, rec, limits)
	c.cancel()
	return err
}

// A start that fails after admission because the client went away must still release its observer
// slot (Codex CP review v1). The cleanup ran on the cancelled request context and failed.
func TestObserverStartPGCancelledStartReleasesItsSlot(t *testing.T) {
	f := newObserverPGFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.ownerSrv.SessionRecords = cancelAfterAdmission{SessionRecordStore: f.ownerSrv.SessionRecords, cancel: cancel}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/sessions", strings.NewReader(fmt.Sprintf(`{"machine_id":%q,"access":"view_only"}`, observerTestDevice))).WithContext(ctx)
	f.ownerSrv.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusCreated || w.Code == http.StatusOK {
		t.Fatalf("a start whose request was cancelled after admission succeeded: %s", w.Body.String())
	}
	var open, total int
	if err := f.su.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE ended_at IS NULL), count(*) FROM session_record WHERE tenant_id = $1 AND access = 'view_only'`, f.tenant).Scan(&open, &total); err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("expected the admitted record to exist (premise), got %d", total)
	}
	if open != 0 {
		t.Fatalf("the cancelled start left %d open observer record(s) holding a slot", open)
	}
}
