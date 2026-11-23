package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeWakeDispatcher struct {
	contexts, forwards []string
	onContext          func(string) (WakeContext, WakeOutcome)
	onForward          func(string, []byte) WakeOutcome
}

func (d *fakeWakeDispatcher) WakeContext(_ context.Context, device string) (WakeContext, WakeOutcome) {
	d.contexts = append(d.contexts, device)
	if d.onContext != nil {
		return d.onContext(device)
	}
	return WakeContext{}, WakeContextReady
}

func (d *fakeWakeDispatcher) Forward(_ context.Context, device string, _ WakeConnRef, artifact []byte) WakeOutcome {
	d.forwards = append(d.forwards, device)
	return d.onForward(device, artifact)
}

type fakeWakeStore struct {
	facts    map[string][]wakeFact
	issueErr error
}

func (s fakeWakeStore) wakeFacts(_ context.Context, _ string, _ []string) (map[string][]wakeFact, error) {
	return s.facts, nil
}

func (s fakeWakeStore) issueWake(_ context.Context, p *Principal, in wakeIssuance) (WakeClaims, error) {
	fact, _ := wakeMatch(in.Target.Facts, in.Relay.Facts)
	return WakeClaims{
		TenantID: p.TenantID, RelayDeviceID: in.Relay.Machine.DeviceID, RequestID: in.RequestID,
		RelayKeySHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		WakeChallenge:  "00000000000000000000000000000000",
		TargetMAC:      fact.MAC, IPv4Network: fact.Network, GatewayMAC: fact.Gateway,
	}, s.issueErr
}

type fakeWakeThrottle time.Duration

func (b fakeWakeThrottle) ReserveWake(context.Context, string, string) (time.Duration, error) {
	return time.Duration(b), nil
}

func TestWakeHandler(t *testing.T) {
	h := newMemDirHarness(t)
	s := h.srv(h.owner)
	target := h.addMachineFn(h.group, MachineStatusActive)
	r1 := h.addMachineFn(h.group, MachineStatusActive)
	r2 := h.addMachineFn(h.otherGroup, MachineStatusActive)
	empty := h.addMachineFn(h.group, MachineStatusActive)
	isolated := h.addMachineFn(h.group, MachineStatusActive)
	now := time.Now()
	report := wakeFact{"02:00:00:00:00:01", "192.0.2.0/24", "02:00:00:00:00:02", now}
	older := report
	older.ReceivedAt = now.Add(-time.Minute)
	differentGateway := report
	differentGateway.Gateway = "02:00:00:00:00:03"
	facts := map[string][]wakeFact{
		target.ID: {report}, r1.ID: {report}, r2.ID: {older}, isolated.ID: {differentGateway},
	}
	presence := onlineAt(now, r1.Device, r2.Device)
	presence.WakeCapableByDevice = map[string]bool{r1.Device: true, r2.Device: true}
	check := func(id string, status int, key, value string) {
		t.Helper()
		got, body := h.doOn(s, http.MethodPost, "/machines/"+id+"/wake", "", "")
		if got != status || (key != "" && body[key] != value) {
			t.Fatalf("wake response = %d %v, want %d %s=%q", got, body, status, key, value)
		}
	}
	check(target.ID, 404, "", "")
	s.WakeOnLAN = true
	s.WakeStore = fakeWakeStore{facts: facts}
	s.WakeThrottle = fakeWakeThrottle(0)
	check(newUUID(), 404, "error", "unknown machine")
	check(target.ID, 503, "error", "presence_unknown")
	s.Presence = fixedPresence{p: presence}
	check(r1.ID, 409, "error", "machine_online")
	check(empty.ID, 409, "error", "no_lan_facts")
	check(isolated.ID, 409, "error", "no_relay")
	s.WakeThrottle = fakeWakeThrottle(time.Second)
	check(target.ID, 429, "", "")
	s.WakeThrottle = fakeWakeThrottle(0)
	for _, tc := range []struct {
		name                                      string
		firstContext, firstForward, secondForward WakeOutcome
		code                                      int
		key, value                                string
		contextCount, forwardCount                int
	}{
		{"context refusal", WakeNotReady, "", WakeWritten, 202, "status", "requested", 2, 1},
		{"forward refusal", WakeContextReady, WakeNotWritten, WakeWritten, 202, "status", "requested", 2, 2},
		{"both refused", WakeContextReady, WakeNotWritten, WakeNotWritten, 409, "error", "unavailable", 2, 2},
		{"failed write", WakeContextReady, WakeWriteFailed, WakeWritten, 202, "status", "uncertain", 1, 1},
		{"missing forward response", WakeContextReady, WakeNoAnswer, WakeWritten, 202, "status", "uncertain", 1, 1},
		{"missing context response", WakeNoAnswer, "", WakeWritten, 202, "status", "requested", 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeWakeDispatcher{
				onContext: func(device string) (WakeContext, WakeOutcome) {
					if device == r1.Device {
						return WakeContext{}, tc.firstContext
					}
					return WakeContext{}, WakeContextReady
				},
				onForward: func(device string, artifact []byte) WakeOutcome {
					var order signedWake
					if err := json.Unmarshal(artifact, &order); err != nil {
						t.Fatal("invalid wake order")
					}
					if order.Claims.TargetMAC != report.MAC || order.Claims.RelayDeviceID != device ||
						order.Claims.ExpiresAtMs-order.Claims.IssuedAtMs != wakeMaxTTL {
						t.Fatal("incorrect wake claims")
					}
					if device == r1.Device {
						return tc.firstForward
					}
					return tc.secondForward
				},
			}
			s.WakeDispatcher = d
			check(target.ID, tc.code, tc.key, tc.value)
			if len(d.contexts) != tc.contextCount || len(d.forwards) != tc.forwardCount || d.contexts[0] != r1.Device {
				t.Fatalf("unexpected attempt order or count")
			}
		})
	}
	for _, tc := range []struct {
		err   error
		code  int
		value string
	}{
		{errWakeChanged, 409, "changed"},
		{errWakeAuditUnavailable, 503, "audit_unavailable"},
		{errors.New("append failed"), 500, "internal_error"},
	} {
		d := &fakeWakeDispatcher{}
		s.WakeDispatcher = d
		s.WakeStore = fakeWakeStore{facts: facts, issueErr: tc.err}
		check(target.ID, tc.code, "error", tc.value)
		if len(d.forwards) != 0 {
			t.Fatal("forwarded after failed issuance")
		}
	}
	checkHints := func(want map[string]string) {
		t.Helper()
		status, body := h.doOn(s, http.MethodGet, "/machines", "", "")
		if status != 200 {
			t.Fatalf("list returned %d", status)
		}
		for _, raw := range body["machines"].([]any) {
			row := raw.(map[string]any)
			hint, _ := row["wake"].(string)
			if hint != want[row["id"].(string)] {
				t.Errorf("unexpected readiness hint %q", hint)
			}
		}
	}
	checkHints(map[string]string{target.ID: "ready", empty.ID: "no_lan_facts", isolated.ID: "no_relay", h.m.ID: "no_lan_facts"})

	// A relay visible to the caller can still be outside their wake authority.
	s.Auth = StubAuthenticator{Principal: &Principal{UserID: h.owner, TenantID: h.tenant,
		Grant: NewGrant(h.owner, h.tenant,
			NewCapabilityMembership([]Capability{CapViewMachines}, AllGroups()),
			NewCapabilityMembership([]Capability{CapWakeMachine}, Groups(h.group))),
	}}
	delete(presence.WakeCapableByDevice, r1.Device)
	check(target.ID, 409, "error", "no_relay")
	checkHints(map[string]string{target.ID: "no_relay", empty.ID: "no_lan_facts", isolated.ID: "no_relay", h.m.ID: "no_lan_facts"})
	s.Auth = StubAuthenticator{Principal: &Principal{UserID: h.owner, TenantID: h.tenant,
		Grant: NewGrant(h.owner, h.tenant, NewMembership(RoleTechnician, Groups(h.group))),
	}}
	check(r2.ID, 404, "error", "unknown machine")

	presence.WakeCapableByDevice[r1.Device] = true
	for range 3 {
		relay := h.addMachineFn(h.group, MachineStatusActive)
		facts[relay.ID] = []wakeFact{older}
		presence.Online[relay.Device] = now
		presence.WakeCapableByDevice[relay.Device] = true
	}
	d := &fakeWakeDispatcher{onContext: func(string) (WakeContext, WakeOutcome) {
		return WakeContext{}, WakeNotReady
	}}
	s.WakeDispatcher = d
	check(target.ID, 409, "error", "unavailable")
	if len(d.contexts) != 3 || len(d.forwards) != 0 {
		t.Fatal("wake exceeded the three-attempt limit")
	}

	s.WakeOnLAN = false
	checkHints(nil)
	s.Auth = nil
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/machines/"+target.ID+"/wake", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled wake route returned %d without authentication", rec.Code)
	}
}
