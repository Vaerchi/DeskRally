package controlplane

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

const promotionTenant = "00000000-0000-0000-0000-0000000000bb"

func consentPromotionFixture(t *testing.T, srv *Server, created attendedCreateResp) attendedRedeemResp {
	t.Helper()
	var redeemed attendedRedeemResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem", `{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`"}`, &redeemed); code != http.StatusCreated {
		t.Fatalf("redeem promotion fixture: %d", code)
	}
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", redeemed.AttendToken, `{"decision":"accept"}`, nil); code != http.StatusOK {
		t.Fatalf("consent promotion fixture: %d", code)
	}
	return redeemed
}

func promotionStateFixture(t *testing.T, state string) (*Server, *AttendedSession) {
	t.Helper()
	srv, _ := newAttendedServer(t)
	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions", `{"group_id":"`+attendTestGroup+`"}`, &created); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	// Seed each legal persisted state independently; these tests exercise promotion admission.
	store := srv.Attended.(*InMemoryAttendedStore)
	store.mu.Lock()
	store.sessions[created.Session.ID].State = state
	store.mu.Unlock()
	return srv, &created.Session
}

func TestPromotionStateHTTPGate(t *testing.T) {
	for _, state := range []string{AttendedPending, AttendedRedeemed, AttendedDeclined, AttendedEnded, AttendedExpired, AttendedConsented, AttendedActive} {
		t.Run(state, func(t *testing.T) {
			srv, session := promotionStateFixture(t, state)
			got := apiJSON(t, srv, "POST", "/attended-sessions/"+session.ID+"/promote", `{}`, nil)
			allowed := state == AttendedConsented || state == AttendedActive
			want := http.StatusConflict
			if allowed {
				want = http.StatusOK
			}
			if got != want {
				t.Fatalf("promote %s: %d, want %d", state, got, want)
			}
			tokens, err := srv.EnrollmentTokens.ListTokens(context.Background(), promotionTenant)
			if err != nil {
				t.Fatal(err)
			}
			expected := 0
			if allowed {
				expected = 1
			}
			if len(tokens) != expected {
				t.Fatalf("minted %d tokens, want %d", len(tokens), expected)
			}
			stored, err := srv.Attended.Get(context.Background(), promotionTenant, session.ID)
			if err != nil {
				t.Fatal(err)
			}
			if (stored.PromoteToken != "") != allowed {
				t.Fatal("unexpected promotion stash")
			}
		})
	}
}

type promotionInterleavingStore struct {
	AttendedStore
	captured string
	fail     bool
}

func (s *promotionInterleavingStore) SetPromoteToken(ctx context.Context, tenant, id, plaintext string) error {
	if plaintext != "" {
		s.captured = plaintext
		if s.fail {
			return errors.New("synthetic stash failure")
		}
		if _, err := s.AttendedStore.End(ctx, tenant, id); err != nil {
			return err
		}
	}
	return s.AttendedStore.SetPromoteToken(ctx, tenant, id, plaintext)
}

func TestPromotionStateRaceRevokesNewToken(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "ended_before_stash", true: "store_failure"}[fail], func(t *testing.T) {
			srv, session := promotionStateFixture(t, AttendedConsented)
			interleave := &promotionInterleavingStore{AttendedStore: srv.Attended, fail: fail}
			srv.Attended = interleave
			got := apiJSON(t, srv, "POST", "/attended-sessions/"+session.ID+"/promote", `{}`, nil)
			want := http.StatusConflict
			if fail {
				want = http.StatusInternalServerError
			}
			if got != want {
				t.Fatalf("promotion response: %d, want %d", got, want)
			}
			if interleave.captured == "" {
				t.Fatal("test never reached post-mint stash")
			}
			if _, err := srv.EnrollmentTokens.RedeemToken(context.Background(), interleave.captured); !errors.Is(err, ErrEnrollmentTokenInvalid) {
				t.Fatalf("failed promotion left a redeemable token: %v", err)
			}
			stored, err := srv.Attended.Get(context.Background(), promotionTenant, session.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.PromoteToken != "" {
				t.Fatal("failed promotion left a stash")
			}
		})
	}
}

func TestPromotionStateMemoryStoreAndCleanup(t *testing.T) {
	for _, state := range []string{AttendedPending, AttendedRedeemed, AttendedDeclined, AttendedEnded, AttendedExpired, AttendedConsented, AttendedActive} {
		t.Run(state, func(t *testing.T) {
			srv, session := promotionStateFixture(t, state)
			err := srv.Attended.SetPromoteToken(context.Background(), promotionTenant, session.ID, "synthetic")
			allowed := state == AttendedConsented || state == AttendedActive
			if allowed && err != nil {
				t.Fatal(err)
			}
			if !allowed && !errors.Is(err, ErrAttendedNotPromotable) {
				t.Fatalf("ineligible stash: %v", err)
			}
			if err := srv.Attended.SetPromoteToken(context.Background(), promotionTenant, session.ID, ""); err != nil {
				t.Fatalf("cleanup: %v", err)
			}
			if err := srv.Attended.SetPromoteToken(context.Background(), "other-tenant", session.ID, "synthetic"); !errors.Is(err, ErrAttendedNotFound) {
				t.Fatalf("foreign stash: %v", err)
			}
		})
	}
}

func TestPromotionStateEndedRemainsObservableToGuest(t *testing.T) {
	srv, _ := newAttendedServer(t)
	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions", `{"group_id":"`+attendTestGroup+`"}`, &created); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	redeemed := consentPromotionFixture(t, srv, created)
	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+created.Session.ID+"/end", `{}`, nil); code != http.StatusOK {
		t.Fatalf("end: %d", code)
	}
	var status struct {
		State   string `json:"state"`
		Promote any    `json:"promote"`
	}
	if code := apiJSONAuth(t, srv, "GET", "/attended-sessions/status", redeemed.AttendToken, "", &status); code != http.StatusOK {
		t.Fatalf("guest status: %d", code)
	}
	if status.State != AttendedEnded || status.Promote != nil {
		t.Fatalf("ended guest status: %#v", status)
	}
}
