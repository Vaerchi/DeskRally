package controlplane

// Final-ack route, review round: no pre-authentication oracle, key re-check inside the apply transaction,
// replay independent of timestamp freshness, and a total-volume cap.

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Every PRE-authentication failure is one answer: same status, same body (no oracle on ids, keys or state).
func TestFinalAckPreAuthFailuresAreIdentical(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		other := h.addMachineFn(h.group, MachineStatusActive)
		srv := h.srv(h.owner)
		strangerPriv, _ := newDirKey(t)
		good := h.faBody(id, h.m.Priv, "executing", "complete", "", h.nextAckTime())
		type resp struct {
			code int
			body map[string]any
		}
		var got []resp
		add := func(code int, body map[string]any) { got = append(got, resp{code, body}) }
		c, b := finalAckOn(t, srv, newUUID(), good) // unknown id
		add(c, b)
		c, b = finalAckOn(t, srv, "not-a-uuid", good) // malformed id
		add(c, b)
		c, b = finalAckOn(t, srv, id, h.faBody(id, strangerPriv, "executing", "complete", "", h.nextAckTime()))
		add(c, b)
		c, b = finalAckOn(t, srv, id, h.faBody(id, other.Priv, "executing", "complete", "", h.nextAckTime()))
		add(c, b)
		c, b = finalAckOn(t, srv, id, strings.Replace(good, `"sig":"`, `"sig":"00`, 1)) // corrupted signature
		add(c, b)
		_, newPub := newDirKey(t)
		h.bypassGuard(func() { h.setPubkey(h.m.ID, newPub) })
		c, b = finalAckOn(t, srv, id, good) // key changed
		add(c, b)
		for i, g := range got {
			if g.code != 404 || !reflect.DeepEqual(g.body, got[0].body) || str(g.body, "error") != "unknown directive" || len(g.body) != 1 {
				t.Fatalf("response %d = %d %v, want the identical 404 %v", i, g.code, g.body, got[0].body)
			}
		}
	})
}

// rotatingStore runs a callback between the route's lookup and its apply (a key rotated in that gap).
type rotatingStore struct {
	DirectiveStore
	afterLookup func()
}

func (s *rotatingStore) FinalAckTarget(ctx context.Context, id string) (*DirectiveFinalAckTarget, error) {
	t, err := s.DirectiveStore.FinalAckTarget(ctx, id)
	if err == nil && s.afterLookup != nil {
		s.afterLookup()
	}
	return t, err
}

func TestFinalAckKeyRotatedBetweenLookupAndApply(t *testing.T) {
	for _, to := range []string{"complete", "failed"} {
		to := to
		forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
			id := h.executingUninstall()
			srv := h.newServer(h.srv(h.owner).Auth)
			srv.Directives = &rotatingStore{DirectiveStore: h.dirs, afterLookup: func() {
				_, np := newDirKey(t)
				h.bypassGuard(func() { h.setPubkey(h.m.ID, np) })
			}}
			code, out := finalAckOn(t, srv, id, h.faBody(id, h.m.Priv, "executing", to, "", h.nextAckTime()))
			if code != 409 || str(out, "outcome") != "refused" {
				t.Fatalf("rotated key (%s) = %d %v, want 409 refused", to, code, out)
			}
			if h.row(id).State != DirectiveExecuting || h.machine(h.m.ID).Status == MachineStatusRemoved {
				t.Fatal("something was applied despite the key rotation")
			}
		})
	}
}

// A replay is a replay even when a re-signed copy carries an OLD ts_ms (older than the 1h freshness bound,
// which only guards NEW transitions), and it writes no audit row.
func TestFinalAckReplayIgnoresTimestampFreshness(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		if code, out := h.finalAck(id, h.m.Priv, "executing", "complete"); code != 200 || str(out, "outcome") != "applied" {
			t.Fatalf("apply = %d %v", code, out)
		}
		before := h.auditActions()
		old := h.faBody(id, h.m.Priv, "executing", "complete", "", h.nextAckTime().Add(-3*time.Hour))
		if code, out := finalAckOn(t, h.srv(h.owner), id, old); code != 200 || str(out, "outcome") != "replay" {
			t.Fatalf("old-ts replay = %d %v", code, out)
		}
		if after := h.auditActions(); !reflect.DeepEqual(before, after) {
			t.Fatalf("a replay wrote audit rows: %v -> %v", before, after)
		}
	})
}

// The total-volume cap bounds ALL requests per source, successes included.
func TestFinalAckTotalVolumeCap(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		srv := h.newServer(h.srv(h.owner).Auth)
		srv.DisableThrottle = false
		srv.Throttle = NewThrottle(ThrottleConfig{FreeAttempts: 100})
		srv.FinalAckBurst, srv.FinalAckPerSec = 3, 0.0001
		for i := 0; i < 3; i++ {
			outcome := "replay"
			if i == 0 {
				outcome = "applied"
			}
			code, out := finalAckOn(t, srv, id, h.faBody(id, h.m.Priv, "executing", "complete", "", h.nextAckTime()))
			if code != 200 || str(out, "outcome") != outcome {
				t.Fatalf("request %d = %d %v", i, code, out)
			}
		}
		if code, _ := finalAckOn(t, srv, id, h.faBody(id, h.m.Priv, "executing", "complete", "", h.nextAckTime())); code != 429 {
			t.Fatalf("4th request = %d, want 429 (successes count)", code)
		}
	})
}

// The window is re-judged inside the apply, on the locked row and the store clock: open at the route's
// lookup, closed by apply time -> 410, nothing applied, no audit row.
func TestFinalAckWindowClosesBetweenLookupAndApply(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		if code, out := h.finalAck(id, h.m.Priv, "executing", "complete"); code != 200 || str(out, "outcome") != "applied" {
			t.Fatalf("apply = %d %v", code, out)
		}
		h.advance(6 * 24 * time.Hour) // open at the lookup
		before := h.auditActions()
		srv := h.newServer(h.srv(h.owner).Auth)
		srv.Directives = &rotatingStore{DirectiveStore: h.dirs, afterLookup: func() { h.advance(2 * 24 * time.Hour) }}
		code, out := finalAckOn(t, srv, id, h.faBody(id, h.m.Priv, "executing", "complete", "", h.nextAckTime()))
		if code != 410 {
			t.Fatalf("window closed between lookup and apply = %d %v, want 410", code, out)
		}
		if h.row(id).State != DirectiveComplete || !reflect.DeepEqual(before, h.auditActions()) {
			t.Fatalf("something changed: state=%s audit %v -> %v", h.row(id).State, before, h.auditActions())
		}
	})
}
