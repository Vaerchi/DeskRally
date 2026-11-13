package controlplane

// The HTTP surface of guest help requests (docs/64), through the REAL handlers on BOTH backends
// (forEachBackend: in-memory stores, and Postgres as rmt_app). The store contract is pinned in
// help_request_test.go; these tests pin what only the handlers decide: device authorization of the internal
// routes, current-group authorization of the technician routes, accept through the SAME admission as
// POST /sessions, the audit/webhook side effects, and the retire hook.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// helpPresence is a fixed presence snapshot.
type helpPresence struct{ online map[string]time.Time }

func (p helpPresence) FetchPresence(context.Context) (*Presence, error) {
	return &Presence{Online: p.online}, nil
}

// harnessPresence is the harness servers' default presence: every device the harness knows is online, unless
// the test switches the mode (h.presenceMode = "empty" | "error").
type harnessPresence struct{ h *transferHarness }

func (p harnessPresence) FetchPresence(context.Context) (*Presence, error) {
	mode, _ := p.h.presenceMode.Load().(string)
	switch mode {
	case "error":
		return nil, errors.New("presence unreachable")
	case "empty":
		return &Presence{Online: map[string]time.Time{}}, nil
	}
	p.h.extraMu.Lock()
	defer p.h.extraMu.Unlock()
	on := map[string]time.Time{transferTestDevice: time.Now()}
	for _, d := range p.h.extraDevices {
		on[d] = time.Now()
	}
	return &Presence{Online: on}, nil
}

// internalDo posts to an internal help route with the device-identity token (token "" = none).
func (h *transferHarness) internalDo(device, route, token, body string) (int, map[string]any) {
	h.t.Helper()
	req := httptest.NewRequest("POST", "/internal/devices/"+device+"/"+route, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.srv(h.alice).Handler().ServeHTTP(rec, req)
	return rec.Code, decodeObject(rec.Body.Bytes())
}

func decodeObject(raw []byte) map[string]any {
	var out map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

// createHelp has the machine ask for help through the internal route and returns the request id.
func (h *transferHarness) createHelp(device, op, note string) string {
	h.t.Helper()
	code, out := h.internalDo(device, "help-request", deviceIdentityToken,
		`{"tenant_id":"`+h.tenant+`","op_id":"`+op+`","note":"`+note+`"}`)
	if code != http.StatusCreated && code != http.StatusOK {
		h.t.Fatalf("help-request = %d %v", code, out)
	}
	return str(out["request"].(map[string]any), "id")
}

func (h *transferHarness) listHelp(user string) []map[string]any {
	h.t.Helper()
	code, out := h.do(user, "GET", "/help-requests", "")
	if code != http.StatusOK {
		h.t.Fatalf("list as %s = %d %v", user, code, out)
	}
	var rows []map[string]any
	for _, r := range out["requests"].([]any) {
		rows = append(rows, r.(map[string]any))
	}
	return rows
}

func (h *transferHarness) acceptHelp(user, id, body string) (int, map[string]any) {
	return h.do(user, "POST", "/help-requests/"+id+"/accept", body)
}

func (h *transferHarness) helpStatus(id string) string {
	h.t.Helper()
	v, _, err := h.help.Get(context.Background(), h.tenant, id, time.Now().UTC())
	if err != nil {
		h.t.Fatal(err)
	}
	return v.Status
}

// secondMachine enrolls another machine in `group` and returns (device, machine id).
func (h *transferHarness) secondMachine(group string) (string, string) {
	h.t.Helper()
	dev := newUUID()
	h.extraMu.Lock()
	h.extraDevices = append(h.extraDevices, dev)
	h.extraMu.Unlock()
	if h.pg {
		mid := seedNamedMachine(h.t, h.su, h.tenant, group, dev, "host-"+dev[:6])
		key, err := hex.DecodeString(testPubkeyHex(h.t))
		if err != nil {
			h.t.Fatal(err)
		}
		h.rawSQL(`UPDATE machine SET pubkey = $3, agent_version = $4 WHERE tenant_id = $1 AND id = $2`, h.tenant, mid, key, transferTestAgentOK)
		return dev, mid
	}
	m := &Machine{DeviceID: dev, GroupID: group, Name: "host-2", Pubkey: testPubkeyHex(h.t), AgentVersion: transferTestAgentOK}
	if err := h.machines.EnrollMachine(context.Background(), h.tenant, m); err != nil {
		h.t.Fatal(err)
	}
	return dev, m.ID
}

func (h *transferHarness) moveMachineTo(machineID, group string) {
	h.t.Helper()
	if h.pg {
		h.rawSQL(`UPDATE machine SET group_id = $3 WHERE tenant_id = $1 AND id = $2`, h.tenant, machineID, group)
		return
	}
	if err := h.machines.SetMachineGroup(context.Background(), h.tenant, machineID, group); err != nil {
		h.t.Fatal(err)
	}
}

// Every internal route is authorized exactly like guest-ended: token, UUIDs, a known device, and the
// body's tenant equal to the device's. Nothing is created before authorization completes.
func TestHelpInternalRoutesAuthorization(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		good := `{"tenant_id":"` + h.tenant + `","op_id":"op-1","note":"hi"}`
		other := newUUID()
		for _, route := range []string{"help-request", "help-cancel", "help-status"} {
			body := good
			if route == "help-cancel" {
				body = `{"tenant_id":"` + h.tenant + `","request_id":"` + newUUID() + `"}`
			}
			if route == "help-status" {
				body = `{"tenant_id":"` + h.tenant + `"}`
			}
			for _, tc := range []struct {
				name, device, token, body string
				code                      int
			}{
				{"no token", transferTestDevice, "", body, 401},
				{"bad token", transferTestDevice, "wrong", body, 401},
				{"bad JSON", transferTestDevice, deviceIdentityToken, `{`, 400},
				{"unknown field (a body device id)", transferTestDevice, deviceIdentityToken, strings.TrimSuffix(body, "}") + `,"device_id":"` + other + `"}`, 400},
				{"bad device", "nope", deviceIdentityToken, body, 400},
				{"bad tenant", transferTestDevice, deviceIdentityToken, strings.Replace(body, h.tenant, "nope", 1), 400},
				{"unknown device", other, deviceIdentityToken, body, 404},
				{"tenant mismatch", transferTestDevice, deviceIdentityToken, strings.Replace(body, h.tenant, h.alienTenant, 1), 403},
			} {
				code, out := h.internalDo(tc.device, route, tc.token, tc.body)
				if code != tc.code {
					t.Fatalf("%s / %s = %d %v, want %d", route, tc.name, code, out, tc.code)
				}
			}
		}
		if rows := h.listHelp(h.alice); len(rows) != 0 {
			t.Fatalf("a refused call created a request: %v", rows)
		}
		if h.auditCount(AuditHelpRequested) != 0 {
			t.Fatal("a refused call wrote an audit row")
		}
		// An invalid op id is a 400 before the store.
		for _, op := range []string{"", "has space", strings.Repeat("a", 65)} {
			if code, out := h.internalDo(transferTestDevice, "help-request", deviceIdentityToken,
				`{"tenant_id":"`+h.tenant+`","op_id":"`+op+`"}`); code != 400 {
				t.Fatalf("op %q = %d %v", op, code, out)
			}
		}
	})
}

// Create is idempotent on op_id and on "one open per machine"; the agent view carries no scope ids.
func TestHelpCreateIdempotentAndAgentView(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		code, out := h.internalDo(transferTestDevice, "help-request", deviceIdentityToken,
			`{"tenant_id":"`+h.tenant+`","op_id":"op-1","note":"printer\u0007 is\nbroken"}`)
		wantCode(t, "create", code, http.StatusCreated, out)
		req := out["request"].(map[string]any)
		if out["created"] != true || req["status"] != "open" || req["note"] != "printer is broken" {
			t.Fatalf("created = %v", out)
		}
		for _, k := range []string{"tenant_id", "machine_id", "group_id", "device_id"} {
			if _, leaked := req[k]; leaked {
				t.Fatalf("agent view leaks %s: %v", k, req)
			}
		}
		id := str(req, "id")
		for _, op := range []string{"op-1", "op-2"} {
			code, out = h.internalDo(transferTestDevice, "help-request", deviceIdentityToken,
				`{"tenant_id":"`+h.tenant+`","op_id":"`+op+`"}`)
			wantCode(t, "repeat "+op, code, http.StatusOK, out)
			if out["created"] != false || str(out["request"].(map[string]any), "id") != id {
				t.Fatalf("repeat %s = %v", op, out)
			}
		}
		if n := h.auditCount(AuditHelpRequested); n != 1 {
			t.Fatalf("help.requested rows = %d, want 1", n)
		}
		code, out = h.internalDo(transferTestDevice, "help-status", deviceIdentityToken, `{"tenant_id":"`+h.tenant+`"}`)
		if code != 200 || str(out["request"].(map[string]any), "id") != id {
			t.Fatalf("status = %d %v", code, out)
		}
	})
}

// Cancel is by request id and only for the authenticated device's own request.
func TestHelpCancelByRequestIDForTheDeviceOnly(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		id := h.createHelp(transferTestDevice, "op-1", "x")
		dev2, _ := h.secondMachine(h.group)
		// Another enrolled device (same tenant) cannot cancel it: indistinguishable from an unknown id.
		code, out := h.internalDo(dev2, "help-cancel", deviceIdentityToken, `{"tenant_id":"`+h.tenant+`","request_id":"`+id+`"}`)
		wantCode(t, "foreign device cancel", code, http.StatusNotFound, out)
		if h.helpStatus(id) != HelpStatusOpen {
			t.Fatal("another device cancelled the request")
		}
		code, out = h.internalDo(transferTestDevice, "help-cancel", deviceIdentityToken, `{"tenant_id":"`+h.tenant+`","request_id":"`+id+`"}`)
		wantCode(t, "cancel", code, http.StatusOK, out)
		if out["outcome"] != "cancelled" || h.helpStatus(id) != HelpStatusCancelled {
			t.Fatalf("cancel = %v", out)
		}
		code, out = h.internalDo(transferTestDevice, "help-cancel", deviceIdentityToken, `{"tenant_id":"`+h.tenant+`","request_id":"`+id+`"}`)
		wantCode(t, "retried cancel", code, http.StatusOK, out)
		if out["outcome"] != "already_cancelled" {
			t.Fatalf("retry = %v", out)
		}
		if n := h.auditCount(AuditHelpCancelled); n != 1 {
			t.Fatalf("help.cancelled rows = %d, want 1", n)
		}
		// Accept beat cancel: the cancel gets 409 with the current state.
		id2 := h.createHelp(transferTestDevice, "op-2", "x")
		h.mustAcceptHelp(h.alice, id2)
		code, out = h.internalDo(transferTestDevice, "help-cancel", deviceIdentityToken, `{"tenant_id":"`+h.tenant+`","request_id":"`+id2+`"}`)
		wantCode(t, "cancel after accept", code, http.StatusConflict, out)
		if h.helpStatus(id2) != HelpStatusAccepted {
			t.Fatal("a late cancel un-accepted the request")
		}
	})
}

func (h *transferHarness) mustAcceptHelp(user, id string) map[string]any {
	h.t.Helper()
	code, out := h.acceptHelp(user, id, "")
	if code != http.StatusCreated {
		h.t.Fatalf("accept as %s = %d %v", user, code, out)
	}
	return out
}

// Visibility and acceptance follow the caller's CURRENT grant over the machine's CURRENT group: the
// covered technician sees and accepts; an uncovered one sees nothing and gets the same 404 as an unknown
// id; a read-only user and another tenant likewise.
func TestHelpTechnicianScopingAsymmetric(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		inScope := h.createHelp(transferTestDevice, "op-in", "in scope")
		devOut, midOut := h.secondMachine(h.otherGroup)
		outScope := h.createHelp(devOut, "op-out", "out of scope")
		_ = midOut

		ids := func(rows []map[string]any) map[string]bool {
			m := map[string]bool{}
			for _, r := range rows {
				m[str(r, "id")] = true
			}
			return m
		}
		if got := ids(h.listHelp(h.bob)); !got[inScope] || got[outScope] || len(got) != 1 {
			t.Fatalf("bob (scoped to the machine's group) sees %v", got)
		}
		if got := ids(h.listHelp(h.carol)); !got[inScope] || !got[outScope] {
			t.Fatalf("carol (all groups) sees %v", got)
		}
		if got := h.listHelp(h.dave); len(got) != 0 {
			t.Fatalf("a read-only user sees help requests: %v", got)
		}
		if got := h.listHelp(h.erin); len(got) != 0 {
			t.Fatalf("another tenant sees help requests: %v", got)
		}
		row := h.listHelp(h.bob)[0]
		if row["note_source"] != "guest_machine" || row["requested_from"] != "machine" || row["note"] != "in scope" ||
			str(row, "machine_id") != h.machine || str(row, "group_id") != h.group {
			t.Fatalf("technician view = %v", row)
		}
		// Uncovered / read-only / foreign tenant: 404 and the request is untouched.
		for _, tc := range []struct{ user, id string }{{h.bob, outScope}, {h.dave, inScope}, {h.erin, inScope}} {
			code, out := h.acceptHelp(tc.user, tc.id, "")
			wantCode(t, "accept by an uncovered caller", code, http.StatusNotFound, out)
		}
		if h.helpStatus(outScope) != HelpStatusOpen || h.helpStatus(inScope) != HelpStatusOpen {
			t.Fatal("a refused accept changed a request")
		}
		if len(h.openSessions()) != 0 {
			t.Fatal("a refused accept created a session")
		}
		if code, _ := h.acceptHelp(h.bob, "not-a-uuid", ""); code != http.StatusNotFound {
			t.Fatalf("malformed id = %d", code)
		}
	})
}

// H-C5: moving the machine re-scopes visibility immediately, in both directions, without a cancel.
func TestHelpMovingTheMachineRescopesImmediately(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		id := h.createHelp(transferTestDevice, "op-1", "x")
		if len(h.listHelp(h.bob)) != 1 {
			t.Fatal("bob cannot see the request in his group")
		}
		h.moveMachineTo(h.machine, h.otherGroup)
		if got := h.listHelp(h.bob); len(got) != 0 {
			t.Fatalf("bob still sees a request on a machine that left his group: %v", got)
		}
		if code, out := h.acceptHelp(h.bob, id, ""); code != http.StatusNotFound {
			t.Fatalf("bob accepted after the move = %d %v", code, out)
		}
		if got := h.listHelp(h.carol); len(got) != 1 || str(got[0], "group_id") != h.otherGroup {
			t.Fatalf("carol's view = %v (the machine's CURRENT group must be shown)", got)
		}
		if h.helpStatus(id) != HelpStatusOpen {
			t.Fatal("a move cancelled the request")
		}
		h.moveMachineTo(h.machine, h.group)
		if got := h.listHelp(h.bob); len(got) != 1 {
			t.Fatalf("bob does not see it after the machine came back: %v", got)
		}
	})
}

// Accept creates the bound session in one step, through POST /sessions' own admission and brokering; the
// session audit row carries the request id; a second accept is a 409 naming the state.
func TestHelpAcceptCreatesTheBoundSession(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		id := h.createHelp(transferTestDevice, "op-1", "x")
		out := h.mustAcceptHelp(h.bob, id)
		sess := out["session"].(map[string]any)
		sid := str(sess, "id")
		if str(sess, "machine_id") != h.machine && str(sess, "machine_id") != "" {
			t.Fatalf("session = %v", sess)
		}
		// POST /sessions' own response: the signaling block carries the ticket for THIS session only.
		sig, ok := out["signaling"].(map[string]any)
		if !ok || sig["ticket"] == nil {
			t.Fatalf("accept response lacks the brokered signaling ticket: %v", out)
		}
		hr := out["help_request"].(map[string]any)
		if str(hr, "id") != id || hr["status"] != HelpStatusAccepted {
			t.Fatalf("help_request = %v", hr)
		}
		rec := h.session(sid)
		if rec.MachineID != h.machine || rec.TechnicianID != h.bob || rec.EndedAt != nil {
			t.Fatalf("session record = %+v", rec)
		}
		v, _, err := h.help.Get(context.Background(), h.tenant, id, time.Now().UTC())
		if err != nil || v.Status != HelpStatusAccepted || v.SessionID != sid || v.AcceptedBy != h.bob {
			t.Fatalf("request = %+v (%v), want accepted by bob with session %s", v, err, sid)
		}
		// The session audit row carries the request id; the transition has its own row.
		var found bool
		for _, e := range h.auditFor("session.start", sid) {
			if strings.Contains(string(e.Metadata), id) {
				found = true
			}
		}
		if !found {
			t.Fatalf("session.start audit lacks help_request_id %s", id)
		}
		if n := h.auditCount(AuditHelpAccepted); n != 1 {
			t.Fatalf("help.accepted rows = %d, want 1", n)
		}
		// Single use: another technician (or the same one without a key) gets 409 with the state.
		for _, user := range []string{h.carol, h.bob} {
			code, out := h.acceptHelp(user, id, "")
			wantCode(t, "second accept by "+user, code, http.StatusConflict, out)
			if out["state"] != HelpStatusAccepted {
				t.Fatalf("409 body = %v", out)
			}
		}
		if len(h.openSessions()) != 1 {
			t.Fatalf("open sessions = %d, want 1", len(h.openSessions()))
		}
		if rows := h.listHelp(h.bob); len(rows) != 0 {
			t.Fatalf("an accepted request is still listed: %v", rows)
		}
	})
}

// A lost response is retried with the same idempotency key and returns the SAME session.
func TestHelpAcceptRetryWithKeyReturnsTheSameSession(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		id := h.createHelp(transferTestDevice, "op-1", "x")
		code, first := h.acceptHelp(h.bob, id, `{"op_id":"accept-1"}`)
		wantCode(t, "accept", code, http.StatusCreated, first)
		code, second := h.acceptHelp(h.bob, id, `{"op_id":"accept-1"}`)
		wantCode(t, "retry", code, http.StatusOK, second)
		if str(first["session"].(map[string]any), "id") != str(second["session"].(map[string]any), "id") {
			t.Fatalf("retry returned a different session: %v vs %v", first["session"], second["session"])
		}
		if len(h.openSessions()) != 1 {
			t.Fatalf("a retry opened another session: %d", len(h.openSessions()))
		}
		// A different technician, or a different key, is a conflict.
		if code, out := h.acceptHelp(h.carol, id, `{"op_id":"accept-1"}`); code != http.StatusConflict {
			t.Fatalf("another technician with the same key = %d %v", code, out)
		}
		if code, out := h.acceptHelp(h.bob, id, `{"op_id":"accept-2"}`); code != http.StatusConflict {
			t.Fatalf("same technician, other key = %d %v", code, out)
		}
		if code, out := h.acceptHelp(h.bob, id, `{"op_id":"bad key"}`); code != http.StatusBadRequest {
			t.Fatalf("invalid key = %d %v", code, out)
		}
	})
}

// Two technicians race the same request: exactly one session, one 201, the other a 409.
func TestHelpAcceptRaceExactlyOneWins(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		id := h.createHelp(transferTestDevice, "op-1", "x")
		users := []string{h.alice, h.bob, h.carol, h.frank}
		codes := make([]int, len(users))
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i, u := range users {
			h.srv(u) // build before the race
			wg.Add(1)
			go func(i int, u string) {
				defer wg.Done()
				<-start
				rec := httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/help-requests/"+id+"/accept", nil)
				h.srv(u).Handler().ServeHTTP(rec, req)
				codes[i] = rec.Code
			}(i, u)
		}
		close(start)
		wg.Wait()
		created, conflict := 0, 0
		for _, c := range codes {
			switch c {
			case http.StatusCreated:
				created++
			case http.StatusConflict:
				conflict++
			default:
				t.Fatalf("codes = %v", codes)
			}
		}
		if created != 1 || conflict != len(users)-1 {
			t.Fatalf("codes = %v, want exactly one 201", codes)
		}
		if len(h.openSessions()) != 1 {
			t.Fatalf("open sessions = %d, want 1", len(h.openSessions()))
		}
	})
}

// Accept is admitted through the SAME seat caps as POST /sessions: a full tenant refuses with the same
// 409 and the request stays OPEN (nothing half-done).
func TestHelpAcceptHonoursTheSeatCaps(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		h.setCap(1)
		h.start(h.alice) // takes the only seat
		id := h.createHelp(transferTestDevice, "op-1", "x")
		code, out := h.acceptHelp(h.bob, id, "")
		wantCode(t, "accept at the cap", code, http.StatusConflict, out)
		if !strings.Contains(str(out, "error"), "concurrent session limit") {
			t.Fatalf("409 body = %v", out)
		}
		if h.helpStatus(id) != HelpStatusOpen {
			t.Fatal("a refused admission consumed the request")
		}
		if len(h.openSessions()) != 1 {
			t.Fatalf("open sessions = %d, want 1", len(h.openSessions()))
		}
	})
}

// Presence only decides whether the accept button is worth showing: an offline machine is listed as such
// with can_accept false, and an accept is refused with 409; unknown presence (no feed) is not "offline".
func TestHelpOfflineMachineShowsNoAccept(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		id := h.createHelp(transferTestDevice, "op-1", "x")
		h.srv(h.bob).Presence = nil // the harness default says online; this premise is "no feed"
		rows := h.listHelp(h.bob)
		if _, present := rows[0]["online"]; present || rows[0]["can_accept"] != true {
			t.Fatalf("no presence feed: %v (unknown must not read as offline)", rows[0])
		}
		srv := h.srv(h.bob)
		srv.Presence = helpPresence{online: map[string]time.Time{}}
		rows = h.listHelp(h.bob)
		if rows[0]["online"] != false || rows[0]["can_accept"] != false {
			t.Fatalf("offline machine = %v", rows[0])
		}
		code, out := h.acceptHelp(h.bob, id, "")
		wantCode(t, "accept offline", code, http.StatusConflict, out)
		if !strings.Contains(str(out, "error"), "offline") || h.helpStatus(id) != HelpStatusOpen {
			t.Fatalf("offline accept = %v", out)
		}
		srv.Presence = helpPresence{online: map[string]time.Time{transferTestDevice: time.Now()}}
		if rows = h.listHelp(h.bob); rows[0]["online"] != true || rows[0]["can_accept"] != true {
			t.Fatalf("online machine = %v", rows[0])
		}
		h.mustAcceptHelp(h.bob, id)
	})
}

// H-C5: retiring or quarantining a machine cancels its open request (the single and the bulk route), and
// a later accept refuses.
func TestHelpRetireAndQuarantineCancelTheRequest(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		id := h.createHelp(transferTestDevice, "op-1", "x")
		code, out := h.do(h.frank, "POST", "/machines/"+h.machine+"/status", `{"status":"quarantined"}`)
		wantCode(t, "quarantine", code, http.StatusOK, out)
		if h.helpStatus(id) != HelpStatusCancelled {
			t.Fatalf("request = %s after quarantine", h.helpStatus(id))
		}
		if code, out := h.acceptHelp(h.bob, id, ""); code != http.StatusConflict {
			t.Fatalf("accept after quarantine = %d %v", code, out)
		}
		// Reactivate: a fresh request works again; bulk retire cancels it too.
		code, out = h.do(h.frank, "POST", "/machines/"+h.machine+"/status", `{"status":"active"}`)
		wantCode(t, "reactivate", code, http.StatusOK, out)
		id2 := h.createHelp(transferTestDevice, "op-2", "x")
		code, out = h.do(h.frank, "POST", "/machines/bulk-status", `{"machine_ids":["`+h.machine+`"],"status":"retired"}`)
		wantCode(t, "bulk retire", code, http.StatusOK, out)
		if h.helpStatus(id2) != HelpStatusCancelled {
			t.Fatalf("request = %s after bulk retire", h.helpStatus(id2))
		}
		if n := h.auditCount(AuditHelpCancelled); n != 2 {
			t.Fatalf("help.cancelled rows = %d, want 2", n)
		}
		// A retired machine cannot ask again.
		code, out = h.internalDo(transferTestDevice, "help-request", deviceIdentityToken, `{"tenant_id":"`+h.tenant+`","op_id":"op-3"}`)
		wantCode(t, "request from a retired machine", code, http.StatusConflict, out)
	})
}

// Webhooks fire once per transition (behind the existing event filter), after commit; replays fire nothing.
func TestHelpWebhookDispatchedOncePerTransition(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		var got atomic.Int32
		var mu sync.Mutex
		var bodies []string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			mu.Lock()
			bodies = append(bodies, string(buf[:n]))
			mu.Unlock()
			got.Add(1)
			w.WriteHeader(200)
		}))
		defer ts.Close()
		store := NewInMemoryWebhookStore()
		if err := store.Create(context.Background(), h.tenant, &TenantWebhook{
			ID: "wh-help", URL: ts.URL, Events: []string{AuditHelpRequested, AuditHelpAccepted}, CreatedAt: time.Now().UTC(),
		}, "deadbeefcafe", maxWebhooksPerTenant); err != nil {
			t.Fatal(err)
		}
		d := &WebhookDispatcher{Store: store, Client: ts.Client()}
		for _, u := range []string{h.alice, h.bob} {
			h.srv(u).Dispatcher = d
		}
		waitFor := func(n int32) {
			t.Helper()
			deadline := time.Now().Add(3 * time.Second)
			for got.Load() < n && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(150 * time.Millisecond) // a duplicate would land by now
			if got.Load() != n {
				t.Fatalf("deliveries = %d, want %d", got.Load(), n)
			}
		}
		id := h.createHelp(transferTestDevice, "op-1", "x")
		waitFor(1)
		h.createHelp(transferTestDevice, "op-1", "x") // replay
		h.createHelp(transferTestDevice, "op-2", "x") // second request while open
		waitFor(1)
		h.mustAcceptHelp(h.bob, id)
		waitFor(2)
		mu.Lock()
		defer mu.Unlock()
		if len(bodies) != 2 || !strings.Contains(bodies[0], AuditHelpRequested) || !strings.Contains(bodies[1], AuditHelpAccepted) {
			t.Fatalf("bodies = %v", bodies)
		}
	})
}

// The capability probe signaling reads advertises help_request_v1 only when the store is mounted.
func TestHelpCapabilityAdvertised(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		get := func(s *Server) string {
			req := httptest.NewRequest("GET", "/internal/capabilities", nil)
			req.Header.Set("Authorization", "Bearer "+deviceIdentityToken)
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			return rec.Body.String()
		}
		if body := get(h.srv(h.alice)); !strings.Contains(body, HelpRequestFeature) || !strings.Contains(body, SessionEndedFeature) {
			t.Fatalf("capabilities = %s", body)
		}
		bare := h.build(h.alice)
		bare.HelpRequests = nil
		if body := get(bare); strings.Contains(body, HelpRequestFeature) {
			t.Fatalf("advertised without a store: %s", body)
		}
		// Without the store the routes are not mounted at all.
		req := httptest.NewRequest("POST", "/internal/devices/"+transferTestDevice+"/help-request", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+deviceIdentityToken)
		rec := httptest.NewRecorder()
		bare.Handler().ServeHTTP(rec, req)
		if rec.Code == http.StatusCreated || rec.Code == http.StatusOK {
			t.Fatalf("unmounted route answered %d", rec.Code)
		}
	})
}

// failOnAuditAction fails the management-audit write of ONE action (everything else passes through), so a
// handler's early return after the status write can be forced.
type failOnAuditAction struct {
	MgmtAuditStore
	action string
}

func (f failOnAuditAction) RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	if e.Action == f.action {
		return context.DeadlineExceeded
	}
	return f.MgmtAuditStore.RecordEvent(ctx, tenantID, e)
}

// failCancelStore makes CancelForMachine fail while fail is set (the "cancel that did not happen" case).
type failCancelStore struct {
	HelpRequestStore
	fail *atomic.Bool
}

func (f failCancelStore) CancelForMachine(ctx context.Context, tenantID, machineID, reason string, now time.Time) (*HelpResult, error) {
	if f.fail.Load() {
		return nil, context.DeadlineExceeded
	}
	return f.HelpRequestStore.CancelForMachine(ctx, tenantID, machineID, reason, now)
}

// Review finding 2: the cancel runs right after the status write, BEFORE the audit and session-reap steps, so
// a 500 from either of those cannot leave an open request on a retired machine (single and bulk routes).
func TestHelpCancelRunsBeforeTheStatusAuditCanFail(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		srv := h.srv(h.frank)
		realAudit := srv.MgmtAudit
		srv.MgmtAudit = failOnAuditAction{MgmtAuditStore: realAudit, action: "machine.status_set"}
		defer func() { srv.MgmtAudit = realAudit }()

		id := h.createHelp(transferTestDevice, "op-early", "x")
		code, _ := h.do(h.frank, "POST", "/machines/"+h.machine+"/status", `{"status":"retired"}`)
		if code != http.StatusInternalServerError {
			t.Fatalf("retire with a failing audit = %d, want the 500 that skips the later steps", code)
		}
		if got := h.helpStatus(id); got != HelpStatusCancelled {
			t.Fatalf("request = %s: an early return after the status write skipped the help cancel", got)
		}

		// the bulk route: same ordering
		srv.MgmtAudit = realAudit
		if c, out := h.do(h.frank, "POST", "/machines/"+h.machine+"/status", `{"status":"active"}`); c != http.StatusOK {
			t.Fatalf("reactivate = %d %v", c, out)
		}
		srv.MgmtAudit = failOnAuditAction{MgmtAuditStore: realAudit, action: "machine.status_set"}
		id2 := h.createHelp(transferTestDevice, "op-early-bulk", "x")
		code, out := h.do(h.frank, "POST", "/machines/bulk-status", `{"machine_ids":["`+h.machine+`"],"status":"quarantined"}`)
		wantCode(t, "bulk quarantine", code, http.StatusOK, out)
		if got := h.helpStatus(id2); got != HelpStatusCancelled {
			t.Fatalf("bulk: request = %s after a failed status audit", got)
		}
	})
}

// Review finding 4: a request that survived a FAILED cancel on retire must be cancelled when the machine is
// reactivated, so it can never become acceptable again; a no-op "active" on an active machine cancels nothing.
func TestHelpReactivationCancelsASurvivingRequest(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		srv := h.srv(h.frank)
		fail := &atomic.Bool{}
		realHelp := srv.HelpRequests
		srv.HelpRequests = failCancelStore{HelpRequestStore: realHelp, fail: fail}
		defer func() { srv.HelpRequests = realHelp }()

		// negative control: active -> active leaves a live machine's request alone
		keep := h.createHelp(transferTestDevice, "op-keep", "x")
		if c, out := h.do(h.frank, "POST", "/machines/"+h.machine+"/status", `{"status":"active"}`); c != http.StatusOK {
			t.Fatalf("active on active = %d %v", c, out)
		}
		if got := h.helpStatus(keep); got != HelpStatusOpen {
			t.Fatalf("a no-op status cancelled a live machine's request: %s", got)
		}

		fail.Store(true)
		if c, out := h.do(h.frank, "POST", "/machines/"+h.machine+"/status", `{"status":"retired"}`); c != http.StatusOK {
			t.Fatalf("retire = %d %v", c, out)
		}
		if got := h.helpStatus(keep); got != HelpStatusOpen {
			t.Fatalf("premise: the failed cancel must leave the request open, got %s", got)
		}
		fail.Store(false)
		if c, out := h.do(h.frank, "POST", "/machines/"+h.machine+"/status", `{"status":"active"}`); c != http.StatusOK {
			t.Fatalf("reactivate = %d %v", c, out)
		}
		v, _, err := h.help.Get(context.Background(), h.tenant, keep, time.Now().UTC())
		if err != nil || v.Status != HelpStatusCancelled || v.CancelReason != HelpCancelReactivated {
			t.Fatalf("after reactivation: %+v %v", v, err)
		}
		if code, out := h.acceptHelp(h.bob, keep, ""); code != http.StatusConflict {
			t.Fatalf("accept of the pre-retirement request after reactivation = %d %v", code, out)
		}
	})
}

// Review r2 #5: accept fails CLOSED on presence. Unknown (no source, unreachable) is a retryable 503, offline is
// 409, only positive evidence accepts; none of the refusals changes the request or creates a session.
func TestHelpAcceptRequiresPositiveOnlineEvidence(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		id := h.createHelp(transferTestDevice, "op-1", "x")
		srv := h.srv(h.bob)
		real := srv.Presence
		defer func() { srv.Presence = real }()

		srv.Presence = nil // no presence source wired
		code, out := h.acceptHelp(h.bob, id, "")
		if code != http.StatusServiceUnavailable || out["retry"] != true {
			t.Fatalf("no presence source: accept = %d %v, want a retryable 503", code, out)
		}
		srv.Presence = real
		h.presenceMode.Store("error") // source unreachable
		code, out = h.acceptHelp(h.bob, id, "")
		if code != http.StatusServiceUnavailable || out["retry"] != true {
			t.Fatalf("presence unreachable: accept = %d %v, want a retryable 503", code, out)
		}
		h.presenceMode.Store("empty") // definitely offline
		if code, out = h.acceptHelp(h.bob, id, ""); code != http.StatusConflict {
			t.Fatalf("offline: accept = %d %v, want 409", code, out)
		}
		if got := h.helpStatus(id); got != HelpStatusOpen {
			t.Fatalf("refused accepts changed the request: %s", got)
		}
		if n := h.auditCount(AuditHelpAccepted); n != 0 {
			t.Fatalf("help.accepted rows = %d", n)
		}
		h.presenceMode.Store("") // positively online
		if code, out = h.acceptHelp(h.bob, id, ""); code != http.StatusCreated {
			t.Fatalf("online: accept = %d %v", code, out)
		}
	})
}

// helpBlockingAudit holds the FIRST write of one action until released, then fails it: the original accept
// handler is pinned inside its "session.start" audit while the test interleaves a retry, and then fails.
type helpBlockingAudit struct {
	MgmtAuditStore
	action  string
	reached chan struct{}
	gate    chan struct{}
	once    sync.Once
	rel     sync.Once
}

// release lets the pinned writer proceed (idempotent, so a failing assertion can still free it).
func (b *helpBlockingAudit) release() { b.rel.Do(func() { close(b.gate) }) }

func (b *helpBlockingAudit) RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	if e.Action == b.action {
		first := false
		b.once.Do(func() { first = true })
		if first {
			close(b.reached)
			<-b.gate
			return context.DeadlineExceeded
		}
	}
	return b.MgmtAuditStore.RecordEvent(ctx, tenantID, e)
}

func newBlockingAudit(inner MgmtAuditStore) *helpBlockingAudit {
	return &helpBlockingAudit{MgmtAuditStore: inner, action: "session.start", reached: make(chan struct{}), gate: make(chan struct{})}
}

func (h *transferHarness) sessionEnded(id string) bool {
	h.t.Helper()
	return h.session(id).EndedAt != nil
}

// Review r2 #4. An accept RETRY must not get a ticket while the original handler is still issuing: if the
// original then fails, its compensation ends that very session, and the retry would have reported success for
// a destroyed one. The persisted delivery state makes the retry wait (503, retry) instead of minting a ticket.
func TestHelpAcceptRetryDuringOriginalIssuanceGetsNoTicketThenRecovers(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		srv := h.srv(h.bob)
		real := srv.MgmtAudit
		ba := newBlockingAudit(real)
		srv.MgmtAudit = ba
		defer func() { srv.MgmtAudit = real }()
		defer ba.release()

		id := h.createHelp(transferTestDevice, "op-1", "x")
		type result struct {
			code int
			out  map[string]any
		}
		first := make(chan result, 1)
		go func() {
			code, out := h.acceptHelp(h.bob, id, `{"op_id":"k1"}`)
			first <- result{code, out}
		}()
		<-ba.reached // the original has accepted (session admitted, request accepted) and is inside the audit

		code, out := h.acceptHelp(h.bob, id, `{"op_id":"k1"}`)
		if code == http.StatusOK || code == http.StatusCreated || out["signaling"] != nil {
			t.Fatalf("a retry during the original's issuance got a ticket: %d %v", code, out)
		}
		if code != http.StatusServiceUnavailable || out["retry"] != true {
			t.Fatalf("retry during issuance = %d %v, want a retryable 503", code, out)
		}

		ba.release() // the original fails its audit -> 500, claims the session, ends it, reopens the request
		res := <-first
		if res.code != http.StatusInternalServerError {
			t.Fatalf("original = %d %v, want 500", res.code, res.out)
		}
		if got := h.helpStatus(id); got != HelpStatusOpen {
			t.Fatalf("request = %s after the failed start, want open", got)
		}
		// the retry's next attempt starts afresh and gets a LIVE session
		srv.MgmtAudit = real
		code, out = h.acceptHelp(h.bob, id, `{"op_id":"k1"}`)
		if code != http.StatusCreated {
			t.Fatalf("retry after the compensation = %d %v", code, out)
		}
		sid := out["session"].(map[string]any)["id"].(string)
		if h.sessionEnded(sid) {
			t.Fatal("the retry was handed a session that is already ended")
		}
	})
}

// A pending delivery that is STALE (the original handler is gone) is taken over by the retry. If the original
// then wakes up and fails, its compensation must CLAIM the session first: the claim is lost (already delivered),
// so it must neither end the session nor reopen the request.
func TestHelpCompensationClaimsAnUndeliveredSessionAndLosesToADelivery(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		old := helpIssuanceGrace
		helpIssuanceGrace = 0
		defer func() { helpIssuanceGrace = old }()
		srv := h.srv(h.bob)
		real := srv.MgmtAudit
		ba := newBlockingAudit(real)
		srv.MgmtAudit = ba
		defer func() { srv.MgmtAudit = real }()
		defer ba.release()

		id := h.createHelp(transferTestDevice, "op-1", "x")
		first := make(chan int, 1)
		go func() { code, _ := h.acceptHelp(h.bob, id, `{"op_id":"k1"}`); first <- code }()
		<-ba.reached
		code, out := h.acceptHelp(h.bob, id, `{"op_id":"k1"}`) // takes over and delivers
		if code != http.StatusOK && code != http.StatusCreated {
			t.Fatalf("takeover retry = %d %v", code, out)
		}
		sid := out["session"].(map[string]any)["id"].(string)
		ba.release() // the original now fails
		if c := <-first; c != http.StatusInternalServerError {
			t.Fatalf("original = %d, want 500", c)
		}
		if h.sessionEnded(sid) {
			t.Fatal("the original's compensation ended a session that had been delivered")
		}
		v, _, err := h.help.Get(context.Background(), h.tenant, id, time.Now().UTC())
		if err != nil || v.Status != HelpStatusAccepted || v.SessionID != sid || v.Delivery != HelpDeliveryDelivered {
			t.Fatalf("request after the lost claim = %+v %v, want accepted/delivered for %s", v, err, sid)
		}
	})
}
