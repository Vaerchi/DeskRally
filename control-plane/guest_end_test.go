package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type guestEndCall struct {
	tenant, session, device string
	at                      time.Time
	reason                  SessionEndReason
	queueAgeMs              *int64
}

type guestEndStub struct {
	calls   []guestEndCall
	outcome GuestEndOutcome
	err     error
}

func (s *guestEndStub) EndSessionForDevice(_ context.Context, tenant, session, device string, at time.Time, report SessionEndReport) (GuestEndOutcome, error) {
	s.calls = append(s.calls, guestEndCall{tenant, session, device, at, report.Reason, report.QueueAgeMs})
	return s.outcome, s.err
}

func TestGuestEndedHTTP(t *testing.T) {
	const tenant = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	const device = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	const session = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	const other = "dddddddd-dddd-dddd-dddd-dddddddddddd"
	srv, machines := identityServer(t)
	if err := machines.EnrollMachine(context.Background(), tenant, &Machine{
		DeviceID: device, GroupID: groupG, Pubkey: testPubkeyHex(t),
	}); err != nil {
		t.Fatal(err)
	}
	stub := &guestEndStub{outcome: GuestEndEnded}
	srv.GuestEnds = stub
	body := `{"device_id":"` + device + `","tenant_id":"` + tenant + `"}`
	post := func(id, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/internal/sessions/"+id+"/guest-ended", strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	for _, tc := range []struct {
		name, id, body, token string
		code                  int
	}{
		{"no token", session, body, "", 401},
		{"bad token", session, body, "wrong", 401},
		{"bad JSON", session, `{`, deviceIdentityToken, 400},
		{"unknown field", session, strings.TrimSuffix(body, "}") + `,"extra":true}`, deviceIdentityToken, 400},
		{"bad session", "bad", body, deviceIdentityToken, 400},
		{"bad device", session, strings.Replace(body, device, "bad", 1), deviceIdentityToken, 400},
		{"bad tenant", session, strings.Replace(body, tenant, "bad", 1), deviceIdentityToken, 400},
		{"unknown device", session, strings.Replace(body, device, other, 1), deviceIdentityToken, 404},
		{"tenant mismatch", session, strings.Replace(body, tenant, other, 1), deviceIdentityToken, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := post(tc.id, tc.body, tc.token); rec.Code != tc.code {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.code, rec.Body.String())
			}
			if len(stub.calls) != 0 {
				t.Fatal("store called before authorization/validation completed")
			}
		})
	}
	for _, outcome := range []GuestEndOutcome{GuestEndEnded, GuestEndAlreadyEnded, GuestEndOtherDevice, GuestEndNotFound} {
		stub.outcome = outcome
		before := time.Now().UTC()
		rec := post(strings.ToUpper(session), strings.ToUpper(body), deviceIdentityToken)
		// Uppercase only UUIDs: JSON field names remain case-insensitively accepted by encoding/json.
		want := 200
		if outcome == GuestEndOtherDevice {
			want = 403
		}
		if outcome == GuestEndNotFound {
			want = 404
		}
		if rec.Code != want {
			t.Fatalf("%s: status = %d: %s", outcome, rec.Code, rec.Body.String())
		}
		call := stub.calls[len(stub.calls)-1]
		if call.tenant != tenant || call.device != device || call.session != session || call.at.Before(before) || call.at.After(time.Now().UTC()) || call.at.Location() != time.UTC {
			t.Fatalf("store call = %+v", call)
		}
		if want == 200 {
			var got map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got["outcome"] != string(outcome) || len(got) != 1 {
				t.Fatalf("response = %s, error %v", rec.Body.String(), err)
			}
		}
	}
	stub.err = errors.New("database unavailable")
	if rec := post(session, body, deviceIdentityToken); rec.Code != 503 || !strings.Contains(rec.Body.String(), `"outcome":"unavailable"`) {
		t.Fatalf("store error = %d: %s", rec.Code, rec.Body.String())
	}
	calls := len(stub.calls)
	srv.DeviceIdentityToken = ""
	// Unmounted: the request falls through to the protected "/" catch-all (401/404, like the identity
	// and redeem routes' tests) — never 200, and never the store.
	if rec := post(session, body, deviceIdentityToken); rec.Code == 200 {
		t.Fatalf("unmounted route answered %d: %s", rec.Code, rec.Body.String())
	}
	if len(stub.calls) != calls {
		t.Fatal("unmounted route called store")
	}
}
