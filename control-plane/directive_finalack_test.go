package controlplane

// POST /agent/directives/{id}/final-ack (docs/65 sec. 2b): every scenario runs against the in-memory stores and
// real Postgres ("fake and pg must agree"), through the real HTTP handler, with NO auth of any kind.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// faBody builds a final-ack body signed by priv over the STORED row. No device id: the route takes none.
func (h *dirHarness) faBody(id string, priv ed25519.PrivateKey, from, to, detail string, ts time.Time) string {
	h.t.Helper()
	d := h.row(id)
	a, err := SignDirectiveAck(priv, d.TenantID, d.DeviceID, d.ID, d.KeyFP, from, to, ts.UnixMilli(), detail)
	if err != nil {
		h.t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"from": from, "to": to, "ts_ms": a.TsMs, "detail": detail, "sig": a.Sig})
	return string(raw)
}

// finalAckOn posts to srv's PUBLIC route: no bearer, no cookie.
func finalAckOn(t *testing.T, srv *Server, id, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/agent/directives/"+id+"/final-ack", strings.NewReader(body))
	srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (h *dirHarness) finalAck(id string, priv ed25519.PrivateKey, from, to string) (int, map[string]any) {
	h.t.Helper()
	return finalAckOn(h.t, h.srv(h.owner), id, h.faBody(id, priv, from, to, "msi exit 0", h.nextAckTime()))
}

// executingUninstall: an issued uninstall driven to executing (the state a helper is in after the MSI).
func (h *dirHarness) executingUninstall() string {
	h.t.Helper()
	id := h.mustRequestUninstall(h.owner, h.m)
	h.issueNow(id)
	h.drive(id, h.m, "accepted", "executing")
	return id
}

// auditChannel returns metadata.channel of the newest audit event with the action ("" when absent).
func (h *dirHarness) auditChannel(action string) string {
	h.t.Helper()
	ev, err := h.audit.ListEvents(context.Background(), h.tenant, 1000)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, e := range ev { // newest first
		if e.Action != action {
			continue
		}
		var m map[string]any
		_ = json.Unmarshal(e.Metadata, &m)
		s, _ := m["channel"].(string)
		return s
	}
	h.t.Fatalf("no audit event %s in %v", action, h.auditActions())
	return ""
}

func TestFinalAckAppliedReplayAndTombstone(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		code, out := h.finalAck(id, h.m.Priv, "executing", "complete")
		if code != 200 || str(out, "outcome") != "applied" || str(out, "state") != "complete" {
			t.Fatalf("final-ack = %d %v", code, out)
		}
		if h.machine(h.m.ID).Status != MachineStatusRemoved {
			t.Fatalf("machine = %s, want removed (identical to the signaling path)", h.machine(h.m.ID).Status)
		}
		// Audit: like the signaling path, plus the channel.
		if h.auditCount("directive.complete") != 1 || h.auditCount("machine.removed") != 1 {
			t.Fatalf("audit = %v", h.auditActions())
		}
		if got := h.auditChannel("directive.complete"); got != "final_ack" {
			t.Fatalf("directive.complete channel = %q, want final_ack", got)
		}
		if got := h.auditChannel("directive.executing"); got != "" {
			t.Fatalf("a signaling ack carries a channel %q", got)
		}
		// THE CORE POINT: the response was lost. The helper retries; the machine is already a tombstone,
		// yet the route still answers replay (fresh ts and the identical body alike).
		code, out = h.finalAck(id, h.m.Priv, "executing", "complete")
		if code != 200 || str(out, "outcome") != "replay" || str(out, "state") != "complete" {
			t.Fatalf("replay = %d %v", code, out)
		}
		same := h.faBody(id, h.m.Priv, "executing", "complete", "msi exit 0", h.nextAckTime())
		for i := 0; i < 2; i++ {
			if code, out = finalAckOn(t, h.srv(h.owner), id, same); code != 200 || str(out, "outcome") != "replay" {
				t.Fatalf("identical body replay = %d %v", code, out)
			}
		}
		if h.auditCount("directive.complete") != 1 || h.auditCount("machine.removed") != 1 {
			t.Fatalf("a replay wrote audit rows: %v", h.auditActions())
		}
		// ...and the D-C9 tombstone is untouched: identity still refuses, enrollment of the key too.
		for _, restricted := range []bool{false, true} {
			if code, _ := h.identity(h.m.Device, restricted); code != http.StatusNotFound {
				t.Fatalf("removed machine resolves (restricted=%v) = %d", restricted, code)
			}
		}
		if code, _ := h.redeemEnrollment(h.m.Pub); code != http.StatusForbidden {
			t.Fatalf("enrollment with the removed key = %d, want 403", code)
		}
		if h.machine(h.m.ID).Status != MachineStatusRemoved {
			t.Fatal("tombstone changed")
		}
		// A different terminal result for the same directive is refused.
		if code, out = h.finalAck(id, h.m.Priv, "executing", "failed"); code != 409 || str(out, "outcome") != "refused" {
			t.Fatalf("complete then failed = %d %v", code, out)
		}
	})
}

func TestFinalAckFailedAfterMsiDoesNotRemove(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		code, out := h.finalAck(id, h.m.Priv, "executing", "failed")
		if code != 200 || str(out, "outcome") != "applied" || str(out, "state") != "failed" {
			t.Fatalf("final-ack failed = %d %v", code, out)
		}
		if h.machine(h.m.ID).Status == MachineStatusRemoved {
			t.Fatal("a failed removal tombstoned the machine")
		}
		if got := h.auditChannel("directive.failed"); got != "final_ack" {
			t.Fatalf("channel = %q", got)
		}
		if code, out = h.finalAck(id, h.m.Priv, "executing", "failed"); code != 200 || str(out, "outcome") != "replay" {
			t.Fatalf("replay = %d %v", code, out)
		}
	})
}

func TestFinalAckSignatureIsTheOnlyCredential(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		other := h.addMachineFn(h.group, MachineStatusActive)
		srv := h.srv(h.owner)
		strangerPriv, _ := newDirKey(t)
		for name, priv := range map[string]ed25519.PrivateKey{"other device": other.Priv, "stranger": strangerPriv} {
			if code, out := finalAckOn(t, srv, id, h.faBody(id, priv, "executing", "complete", "", h.nextAckTime())); code != 404 {
				t.Fatalf("%s key = %d %v, want 404", name, code, out)
			}
		}
		good := h.faBody(id, h.m.Priv, "executing", "complete", "x", h.nextAckTime())
		tampered := strings.Replace(good, `"detail":"x"`, `"detail":"y"`, 1)
		if code, _ := finalAckOn(t, srv, id, tampered); code != 404 {
			t.Fatalf("tampered = %d, want 404", code)
		}
		if h.row(id).State != DirectiveExecuting || h.machine(h.m.ID).Status == MachineStatusRemoved {
			t.Fatal("a refused ack moved something")
		}
		// A body that names a device is not even parsed (strict decode): the caller never picks the device.
		var m map[string]any
		_ = json.Unmarshal([]byte(good), &m)
		m["device_id"] = h.m.Device
		raw, _ := json.Marshal(m)
		if code, _ := finalAckOn(t, srv, id, string(raw)); code != 400 {
			t.Fatalf("body with device_id = %d, want 400", code)
		}
		if code, _ := finalAckOn(t, srv, id, good); code != 200 {
			t.Fatalf("the genuine ack = %d", code)
		}
	})
}

func TestFinalAckKeyChangedIsRefused(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		_, newPub := newDirKey(t)
		h.bypassGuard(func() { h.setPubkey(h.m.ID, newPub) })
		code, out := h.finalAck(id, h.m.Priv, "executing", "complete")
		if code != 404 || str(out, "error") != "unknown directive" || out["state"] != nil || out["outcome"] != nil {
			t.Fatalf("key changed = %d %v, want the generic 404 with no state", code, out)
		}
		if h.machine(h.m.ID).Status == MachineStatusRemoved {
			t.Fatal("removed despite a key change")
		}
	})
}

func TestFinalAckUnknownAndWrongKindAreIndistinguishable(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		active := h.addMachineFn(h.group, MachineStatusActive)
		code, out := h.request(h.owner, "reinstall", active)
		if code != http.StatusCreated {
			t.Fatalf("reinstall request = %d %v", code, out)
		}
		reID := dirIDOf(out)
		srv := h.srv(h.owner)
		d := h.row(reID)
		a, _ := SignDirectiveAck(active.Priv, d.TenantID, d.DeviceID, d.ID, d.KeyFP, "executing", "complete", h.nextAckTime().UnixMilli(), "")
		raw, _ := json.Marshal(map[string]any{"from": "executing", "to": "complete", "ts_ms": a.TsMs, "sig": a.Sig})
		c1, o1 := finalAckOn(t, srv, reID, string(raw))
		c2, o2 := finalAckOn(t, srv, newUUID(), string(raw))
		c3, o3 := finalAckOn(t, srv, "not-a-uuid", string(raw))
		if c1 != 404 || c2 != 404 || c3 != 404 || !reflect.DeepEqual(o1, o2) || !reflect.DeepEqual(o1, o3) {
			t.Fatalf("reinstall=%d %v unknown=%d %v malformed=%d %v", c1, o1, c2, o2, c3, o3)
		}
		if h.row(reID).State == DirectiveComplete {
			t.Fatal("a reinstall was completed through the removal route")
		}
	})
}

func TestFinalAckOnlyTerminalRemovalResults(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		for _, c := range [][2]string{{"executing", "reboot_pending"}, {"executing", "accepted"}, {"executing", "removal_unconfirmed"},
			{"executing", "cancelled"}, {"executing", "bogus"}, {"issued", "complete"}} {
			code, out := h.finalAck(id, h.m.Priv, c[0], c[1])
			if code != 409 || str(out, "outcome") != "refused" {
				t.Fatalf("%v = %d %v, want 409 refused", c, code, out)
			}
		}
		if h.row(id).State != DirectiveExecuting {
			t.Fatalf("state moved to %s", h.row(id).State)
		}
	})
}

func TestFinalAckWindow(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		// While ACTIVE there is no deadline: a long-stuck removal can still confirm.
		h.advance(30 * 24 * time.Hour)
		appliedBody := h.faBody(id, h.m.Priv, "executing", "complete", "msi exit 0", h.nextAckTime())
		if code, out := finalAckOn(t, h.srv(h.owner), id, appliedBody); code != 200 || str(out, "outcome") != "applied" {
			t.Fatalf("active, late = %d %v", code, out)
		}
		// Inside 7 days of the result: replay.
		h.advance(6 * 24 * time.Hour)
		if code, out := finalAckOn(t, h.srv(h.owner), id, appliedBody); code != 200 || str(out, "outcome") != "replay" {
			t.Fatalf("day 6, identical body = %d %v", code, out)
		}
		if code, out := h.finalAck(id, h.m.Priv, "executing", "complete"); code != 200 || str(out, "outcome") != "replay" {
			t.Fatalf("day 6 = %d %v", code, out)
		}
		// Past it: 410.
		h.advance(2 * 24 * time.Hour)
		if code, out := h.finalAck(id, h.m.Priv, "executing", "complete"); code != 410 {
			t.Fatalf("day 8 = %d %v, want 410", code, out)
		}
		if h.machine(h.m.ID).Status != MachineStatusRemoved {
			t.Fatal("tombstone changed")
		}
	})
}

func TestFinalAckRateLimited(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		srv := h.newServer(h.srv(h.owner).Auth)
		srv.DisableThrottle = false
		srv.Throttle = NewThrottle(ThrottleConfig{FreeAttempts: 3, BaseDelay: time.Minute})
		wp, _ := newDirKey(t)
		bad := h.faBody(id, wp, "executing", "complete", "", h.nextAckTime())
		limited := false
		for i := 0; i < 8; i++ {
			code, _ := finalAckOn(t, srv, id, bad)
			if code == 429 {
				limited = true
				break
			}
			if code != 404 {
				t.Fatalf("attempt %d = %d, want 404", i, code)
			}
		}
		if !limited {
			t.Fatal("never rate limited")
		}
		if code, _ := finalAckOn(t, srv, id, h.faBody(id, h.m.Priv, "executing", "complete", "", h.nextAckTime())); code != 429 {
			t.Fatalf("genuine ack while limited = %d, want 429", code)
		}
	})
}

func TestFinalAckNotMountedWithoutDirectives(t *testing.T) {
	h := newMemDirHarness(t)
	srv := NewServer(dirAuth{users: h.users, tenant: h.tenant, user: h.owner}, NoopBinder{})
	if code, _ := finalAckOn(t, srv, newUUID(), `{}`); code != 404 {
		t.Fatalf("unconfigured server answers %d, want 404", code)
	}
}
