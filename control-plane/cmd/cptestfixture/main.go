// Command cptestfixture is a TEST-ONLY control-plane HTTP server for e2e tests that
// require real authentication (SessionAuthenticator + AuthService) instead of the dev-mode
// StubAuthenticator.
//
// It starts with fully in-memory stores, pre-seeds three users (admin + TechA + TechB) in a
// fixed tenant, wires a GrantIssuer from a caller-supplied seed, and prints a single JSON line
// to stdout once the HTTP listener is ready so the test driver can parse credentials and tenant.
//
// NEVER use this binary in production. It has no database, no RLS, fixed seeded passwords,
// and DisableThrottle=true on the auth service. It exists solely to give the e2e test suite a
// CP that enforces REAL login → session-cookie → CSRF before serving protected endpoints.
//
// Environment variables:
//
//	CP_LISTEN                  listen address (default "127.0.0.1:8188")
//	CP_FIXTURE_GRANT_SEED      64 hex chars = 32-byte Ed25519 seed for the grant issuer (required)
//	CP_DEVICE_IDENTITY_TOKEN   shared secret presented by the signaling server to
//	                           GET /internal/devices/{id}/identity (required for agent auth)
//	CP_SIGNALING_URL           signaling WS endpoint returned alongside session tickets
//	                           (default "ws://127.0.0.1:8189/ws")
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	cp "rmt/controlplane"
)

// fixtureGuestEnds is a TEST-ONLY GuestEndStore over the in-memory session records, returning
// PgGuestEndStore's outcomes (not_found, other_device, already_ended, ended). Each report prints
// one FIXTURE_SESSION_END line so an e2e spec can assert which session ended and why (docs/49).
type fixtureGuestEnds struct {
	mu      sync.Mutex
	records *cp.InMemorySessionRecordStore
}

func (f *fixtureGuestEnds) EndSessionForDevice(ctx context.Context, tenantID, sessionID, deviceID string, at time.Time, report cp.SessionEndReport) (cp.GuestEndOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	outcome := func() cp.GuestEndOutcome {
		rec, err := f.records.GetSession(ctx, tenantID, sessionID)
		if err != nil {
			return cp.GuestEndNotFound
		}
		if !strings.EqualFold(rec.MachineDeviceID, deviceID) {
			return cp.GuestEndOtherDevice
		}
		if rec.EndedAt != nil {
			return cp.GuestEndAlreadyEnded
		}
		if _, err := f.records.EndSession(ctx, tenantID, sessionID, at); err != nil {
			return cp.GuestEndNotFound
		}
		return cp.GuestEndEnded
	}()
	age := "none"
	if report.QueueAgeMs != nil {
		age = strconv.FormatInt(*report.QueueAgeMs, 10)
	}
	fmt.Printf("FIXTURE_SESSION_END session=%s device=%s reason=%s queue_age_ms=%s outcome=%s\n",
		sessionID, deviceID, report.Reason, age, outcome)
	return outcome, nil
}

const (
	fixtureTenantID = "16161616-0000-4000-8000-000000000016" // a UUID like every production tenant; the agent end report requires one

	fixtureAdminID    = "aaaaaaaa-0000-4000-8000-000000000001"
	fixtureAdminEmail = "admin@fix16.test"
	fixtureAdminPw    = "admin-fix16-battery-staple-01"

	fixtureTechAID    = "aaaaaaaa-0000-4000-8000-000000000002"
	fixtureTechAEmail = "tech-a@fix16.test"
	fixtureTechAPw    = "tech-a-fix16-battery-staple-02"

	fixtureTechBID    = "aaaaaaaa-0000-4000-8000-000000000003"
	fixtureTechBEmail = "tech-b@fix16.test"
	fixtureTechBPw    = "tech-b-fix16-battery-staple-03"

	fixtureTechCID    = "aaaaaaaa-0000-4000-8000-000000000004"
	fixtureTechCEmail = "tech-c@fix16.test"
	fixtureTechCPw    = "tech-c-fix16-battery-staple-04"
)

// fixtureReady is the JSON payload of the FIXTURE_READY line written to stdout on startup.
type fixtureReady struct {
	Ready         bool   `json:"ready"`
	TenantID      string `json:"tenant_id"`
	AdminEmail    string `json:"admin_email"`
	AdminPassword string `json:"admin_password"`
	TechAID       string `json:"tech_a_id"`
	TechAEmail    string `json:"tech_a_email"`
	TechAPassword string `json:"tech_a_password"`
	TechBID       string `json:"tech_b_id"`
	TechBEmail    string `json:"tech_b_email"`
	TechBPassword string `json:"tech_b_password"`
	TechCID       string `json:"tech_c_id"`
	TechCEmail    string `json:"tech_c_email"`
	TechCPassword string `json:"tech_c_password"`
	GrantPubkey   string `json:"grant_issuer_pubkey"`
	ListenAddr    string `json:"listen_addr"`
}

func main() {
	listen := os.Getenv("CP_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:8188"
	}
	seedHex := os.Getenv("CP_FIXTURE_GRANT_SEED")
	if seedHex == "" {
		log.Fatal("cptestfixture: CP_FIXTURE_GRANT_SEED is required (64 hex chars)")
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		log.Fatalf("cptestfixture: CP_FIXTURE_GRANT_SEED must be 64 valid hex chars: %v", err)
	}

	issuer, err := cp.NewGrantIssuerFromSeed(seed)
	if err != nil {
		log.Fatalf("cptestfixture: NewGrantIssuerFromSeed: %v", err)
	}

	users := cp.NewInMemoryUserStore()
	sessions := cp.NewSessionManager(cp.NewInMemorySessionStore())

	addUser := func(id, email, password string, role cp.Role) {
		hash, herr := cp.HashPassword(password)
		if herr != nil {
			log.Fatalf("cptestfixture: HashPassword(%s): %v", email, herr)
		}
		u := &cp.AuthUser{ID: id, TenantID: fixtureTenantID, Email: email, PasswordHash: hash}
		users.AddUser(u, cp.NewGrant(id, fixtureTenantID, cp.NewMembership(role, cp.AllGroups())))
	}

	addUser(fixtureAdminID, fixtureAdminEmail, fixtureAdminPw, cp.RoleAdmin)
	addUser(fixtureTechAID, fixtureTechAEmail, fixtureTechAPw, cp.RoleTechnician)
	addUser(fixtureTechBID, fixtureTechBEmail, fixtureTechBPw, cp.RoleTechnician)
	addUser(fixtureTechCID, fixtureTechCEmail, fixtureTechCPw, cp.RoleTechnician)

	mgmtAudit := cp.NewInMemoryMgmtAuditStore()

	authSvc := &cp.AuthService{
		Users:           users,
		Sessions:        sessions,
		MgmtAudit:       mgmtAudit,
		Issuer:          "rmt-e2e-fixture",
		DisableThrottle: true,
	}
	sessionAuth := &cp.SessionAuthenticator{Sessions: sessions, Users: users}

	srv := cp.NewServer(sessionAuth, cp.NoopBinder{})
	srv.AuthAPI = authSvc
	srv.Grants = issuer
	machines := cp.NewInMemoryMachineStore()
	srv.Machines = machines
	srv.MachineProperties = cp.NewInMemoryMachinePropertyStore()
	records := cp.NewInMemorySessionRecordStore()
	srv.SessionRecords = records
	// docs/49: mounts /guest-ended, /ended and advertises session_ended_v1 to signaling.
	srv.GuestEnds = &fixtureGuestEnds{records: records}
	// docs/51: session transfer over the same records, so the agent's end report (above) finalizes it.
	srv.SessionTransfers = cp.NewInMemorySessionTransferStore(records, mgmtAudit)
	srv.EnrollmentTokens = cp.NewInMemoryEnrollmentTokenStore()
	srv.TicketRedemptions = cp.NewInMemoryTicketRedemptionStore()
	srv.MgmtAudit = mgmtAudit
	srv.DisableThrottle = true
	srv.SignalingURL = os.Getenv("CP_SIGNALING_URL")
	if srv.SignalingURL == "" {
		srv.SignalingURL = "ws://127.0.0.1:8189/ws"
	}
	if tok := os.Getenv("CP_DEVICE_IDENTITY_TOKEN"); tok != "" {
		srv.DeviceIdentityToken = tok
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("cptestfixture: listen %s: %v", listen, err)
	}

	ready := fixtureReady{
		Ready:         true,
		TenantID:      fixtureTenantID,
		AdminEmail:    fixtureAdminEmail,
		AdminPassword: fixtureAdminPw,
		TechAID:       fixtureTechAID,
		TechAEmail:    fixtureTechAEmail,
		TechAPassword: fixtureTechAPw,
		TechBID:       fixtureTechBID,
		TechBEmail:    fixtureTechBEmail,
		TechBPassword: fixtureTechBPw,
		TechCID:       fixtureTechCID,
		TechCEmail:    fixtureTechCEmail,
		TechCPassword: fixtureTechCPw,
		GrantPubkey:   issuer.PublicKeyHex(),
		ListenAddr:    ln.Addr().String(),
	}
	line, _ := json.Marshal(ready)
	fmt.Printf("FIXTURE_READY %s\n", line)
	log.Printf("cptestfixture: real-auth fixture listening on %s (tenant=%s)", ln.Addr(), fixtureTenantID)

	// FIXTURE-ONLY route: record a machine's agent version, as the signaling presence feed does in
	// production (this fixture has no presence feed). Observe is admitted only for agents >= 0.1.3,
	// so an observer e2e needs it. Not part of the control plane's API; lives only in this binary.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fixture/agent-version", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			DeviceID string `json:"device_id"`
			Version  string `json:"version"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.DeviceID == "" || req.Version == "" {
			http.Error(w, "device_id and version required", http.StatusBadRequest)
			return
		}
		if _, err := machines.RecordAgentVersion(r.Context(), fixtureTenantID, map[string]string{req.DeviceID: req.Version}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/", srv.Handler())
	if err := http.Serve(ln, mux); err != nil {
		log.Fatalf("cptestfixture: serve: %v", err)
	}
}
