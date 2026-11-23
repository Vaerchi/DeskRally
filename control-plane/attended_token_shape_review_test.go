package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReviewAttendedTokenEveryByteIsChecked(t *testing.T) {
	for _, route := range []string{"consent", "status"} {
		t.Run(route, func(t *testing.T) {
			srv, _ := newAttendedServer(t)
			spy := &spyAttendedStore{AttendedStore: srv.Attended}
			srv.Attended = spy
			for pos := 0; pos < 43; pos++ {
				t.Run(fmt.Sprint(pos), func(t *testing.T) {
					token := []byte(strings.Repeat("A", 43))
					token[pos] = '#'
					method := http.MethodGet
					if route == "consent" {
						method = http.MethodPost
					}
					body := &readSpy{r: strings.NewReader(`{"decision":"accept"}`)}
					req := httptest.NewRequest(method, "/attended-sessions/"+route, body)
					req.Header.Set("Authorization", "Bearer "+string(token))
					rec := httptest.NewRecorder()
					srv.Handler().ServeHTTP(rec, req)
					var result map[string]string
					if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					if rec.Code != http.StatusForbidden || result["error"] != "invalid attend token" {
						t.Fatalf("not a generic 403: %d %s", rec.Code, rec.Body.String())
					}
					if spy.consentCalls != 0 || spy.byTokenCalls != 0 || body.reads != 0 {
						t.Fatalf("malformed token reached work: consent=%d status=%d body=%d", spy.consentCalls, spy.byTokenCalls, body.reads)
					}
				})
			}
		})
	}
}

func TestReviewAttendedBearerParsingCompatibility(t *testing.T) {
	for _, route := range []string{"consent", "status"} {
		for _, prefix := range []string{"Bearer ", "Bearer   ", "bearer ", "Basic "} {
			t.Run(route+"/"+prefix, func(t *testing.T) {
				srv, _ := newAttendedServer(t)
				token := redeemAttendToken(t, srv)
				spy := &spyAttendedStore{AttendedStore: srv.Attended}
				srv.Attended = spy
				method := http.MethodGet
				if route == "consent" {
					method = http.MethodPost
				}
				req := httptest.NewRequest(method, "/attended-sessions/"+route, strings.NewReader(`{"decision":"accept"}`))
				req.Header.Set("Authorization", prefix+token+"  ")
				rec := httptest.NewRecorder()
				srv.Handler().ServeHTTP(rec, req)
				wantStatus, wantCalls := http.StatusUnauthorized, 0
				if strings.HasPrefix(prefix, "Bearer ") {
					wantStatus, wantCalls = http.StatusOK, 1
				}
				if rec.Code != wantStatus || spy.consentCalls+spy.byTokenCalls != wantCalls {
					t.Fatalf("Bearer parsing changed: status=%d calls=%d; want %d/%d", rec.Code, spy.consentCalls+spy.byTokenCalls, wantStatus, wantCalls)
				}
			})
		}
	}
}
