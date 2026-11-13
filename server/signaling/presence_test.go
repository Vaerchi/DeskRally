package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeConn satisfies peerConn without a socket.
type presenceConn struct{}

func (presenceConn) WriteJSON(any) error              { return nil }
func (presenceConn) SetWriteDeadline(time.Time) error { return nil }
func (presenceConn) WriteMessage(int, []byte) error   { return nil }
func (presenceConn) Close() error                     { return nil }

const presenceTestToken = "presence-token-that-is-long-enough-to-mount"

func presenceRegistry(t *testing.T, ttl time.Duration, now time.Time) *Registry {
	t.Helper()
	r := NewRegistry(ttl)
	r.now = func() time.Time { return now }
	return r
}

func registerPeer(r *Registry, device string) {
	r.Register(&Peer{DeviceId: device, conn: presenceConn{}})
}

// A snapshot lists exactly the FRESH peers, and reports each one's heartbeat stamp.
func TestPresenceSnapshotListsFreshPeers(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	reg := presenceRegistry(t, 30*time.Second, base)
	registerPeer(reg, "dev-a")
	registerPeer(reg, "dev-b")

	got := reg.Snapshot()
	if len(got) != 2 {
		t.Fatalf("snapshot = %+v, want 2 entries", got)
	}
	for _, e := range got {
		if e.LastSeenUnixMs != base.UnixMilli() {
			t.Fatalf("entry %s last_seen = %d, want %d", e.DeviceID, e.LastSeenUnixMs, base.UnixMilli())
		}
	}

	// A peer registered with an EMPTY device id (reachable on the dev-only insecure path via a
	// malformed register_agent) can match no enrolled machine, so it must not appear.
	registerPeer(reg, "")
	if got := reg.Snapshot(); len(got) != 2 {
		t.Fatalf("snapshot = %+v, want the empty-device-id peer to be skipped", got)
	}

	// Advance past the TTL: both peers are stale, so presence reports nobody.
	reg.now = func() time.Time { return base.Add(31 * time.Second) }
	if got := reg.Snapshot(); len(got) != 0 {
		t.Fatalf("snapshot after TTL = %+v, want empty", got)
	}
	// …but the read must NOT have evicted them — a read-only observability call must not mutate
	// the registry the broker depends on.
	if n := reg.Len(); n != 3 {
		t.Fatalf("registry len after snapshot = %d, want 3 (Snapshot must not evict)", n)
	}
}

// The endpoint is a fleet-enumeration oracle without its token, so an absent, malformed, or wrong
// token must all be refused — and refused without leaking whether any device exists.
func TestPresenceEndpointRequiresServiceToken(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	reg := presenceRegistry(t, 30*time.Second, base)
	registerPeer(reg, "dev-secret")
	h := presenceHandler(reg, presenceTestToken)

	for name, authz := range map[string]string{
		"absent":       "",
		"wrong scheme": "Basic " + presenceTestToken,
		"wrong value":  "Bearer not-the-token-but-still-long-enough-x",
		"empty bearer": "Bearer ",
	} {
		req := httptest.NewRequest("GET", "/internal/presence", nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s token → %d, want 401", name, rec.Code)
		}
		if body := rec.Body.String(); contains(body, "dev-secret") {
			t.Fatalf("%s token leaked a device id: %s", name, body)
		}
	}
}

// With the token, the response carries device ids, freshness and the agent-asserted os — and
// nothing else that helps reach an agent.
func TestPresenceEndpointReturnsDeviceIdsOnly(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	reg := presenceRegistry(t, 30*time.Second, base)
	reg.Register(&Peer{
		DeviceId:     "dev-a",
		Pubkey:       "ed25519:cafebabe",
		Tenant:       "tenant-secret",
		Nat:          NatType("symmetric"),
		OS:           "Windows 11 Pro 25H2 (build 26200)",
		AgentVersion: "0.9.1+deadbeef",
		conn:         presenceConn{},
	})

	req := httptest.NewRequest("GET", "/internal/presence", nil)
	req.Header.Set("Authorization", "Bearer "+presenceTestToken)
	rec := httptest.NewRecorder()
	presenceHandler(reg, presenceTestToken)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("presence = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	var resp PresenceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Devices) != 1 || resp.Devices[0].DeviceID != "dev-a" {
		t.Fatalf("devices = %+v, want just dev-a", resp.Devices)
	}
	if resp.AsOfUnixMs == 0 {
		t.Fatal("as_of_unix_ms not set")
	}
	// ANTI-DRIFT: the control plane is a SEPARATE Go module and cannot import these types, so it
	// parses this shape from a hand-written literal in its own test
	// (control-plane/presence_test.go::TestSignalingPresenceSource). Pin the exact field names here
	// so a rename on this side fails a test instead of silently producing "presence unknown"
	// forever in the console.
	if !contains(body, `"device_id":"dev-a"`) ||
		!contains(body, `"last_seen_unix_ms":`) ||
		!contains(body, `"devices":[`) ||
		!contains(body, `"as_of_unix_ms":`) ||
		!contains(body, `"os":"Windows 11 Pro 25H2 (build 26200)"`) ||
		!contains(body, `"agent_version":"0.9.1+deadbeef"`) {
		t.Fatalf("presence wire shape drifted from the control plane's parser: %s", body)
	}
	// The registry knows the agent's pubkey, tenant and NAT type. None of that may travel: the
	// endpoint answers "which of these ids are up (and what they claim to run)", never "how do I
	// get to them". The os travels DELIBERATELY — it is the refresh input for machine.os.
	for _, secret := range []string{"cafebabe", "tenant-secret", "symmetric"} {
		if contains(body, secret) {
			t.Fatalf("presence response leaked %q: %s", secret, body)
		}
	}
}

// A peer that announced no os (older agent, controller-shaped registration in dev mode) yields the
// exact pre-os wire shape: no "os" key at all, not an empty-string one — a pre-os consumer parsing
// strictly must see nothing new.
func TestPresenceOmitsAnEmptyOS(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	reg := presenceRegistry(t, 30*time.Second, base)
	registerPeer(reg, "dev-old")

	req := httptest.NewRequest("GET", "/internal/presence", nil)
	req.Header.Set("Authorization", "Bearer "+presenceTestToken)
	rec := httptest.NewRecorder()
	presenceHandler(reg, presenceTestToken)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("presence = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); contains(body, `"os"`) {
		t.Fatalf("an absent os must be omitted, not emitted empty: %s", body)
	}
}

// mountPresence must not mount the route without a long enough token — an unauthenticated presence
// feed would enumerate every live device across every tenant.
func TestPresenceRouteNotMountedWithoutAdequateToken(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	for name, token := range map[string]string{
		"empty":     "",
		"too short": "short-token",
	} {
		reg := presenceRegistry(t, 30*time.Second, base)
		registerPeer(reg, "dev-a")
		mux := http.NewServeMux()
		mountPresence(mux, reg, token)

		req := httptest.NewRequest("GET", "/internal/presence", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s token: route responded %d, want 404 (not mounted)", name, rec.Code)
		}
	}

	// With an adequate token it IS mounted and answers.
	reg := presenceRegistry(t, 30*time.Second, base)
	registerPeer(reg, "dev-a")
	mux := http.NewServeMux()
	mountPresence(mux, reg, presenceTestToken)
	req := httptest.NewRequest("GET", "/internal/presence", nil)
	req.Header.Set("Authorization", "Bearer "+presenceTestToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mounted presence = %d, want 200", rec.Code)
	}
}

// A peer that announced no agent_version (older agent) yields no "agent_version" key at all —
// matching the omitempty invariant documented in presence.go so silence is distinguishable from
// a deliberate empty report.
func TestPresenceOmitsAnEmptyAgentVersion(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	reg := presenceRegistry(t, 30*time.Second, base)
	registerPeer(reg, "dev-old")

	req := httptest.NewRequest("GET", "/internal/presence", nil)
	req.Header.Set("Authorization", "Bearer "+presenceTestToken)
	rec := httptest.NewRecorder()
	presenceHandler(reg, presenceTestToken)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("presence = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); contains(body, `"agent_version"`) {
		t.Fatalf("an absent agent_version must be omitted, not emitted empty: %s", body)
	}
}

// require_session_policy travels when the agent asserted it, and is absent (not false) when nil.
// NIL IS NOT FALSE: the control plane writes machine.require_session_policy only for agents that
// actually reported, so an older agent's silence must never clear an operator-set flag.
func TestPresenceRequireSessionPolicy(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)

	trueVal := true
	falseVal := false

	for _, tc := range []struct {
		name   string
		policy *bool
		want   string // substring that must appear; empty means field must be absent
		absent string // substring that must NOT appear
	}{
		{
			name:   "true is emitted as true",
			policy: &trueVal,
			want:   `"require_session_policy":true`,
		},
		{
			name:   "false is emitted as false",
			policy: &falseVal,
			want:   `"require_session_policy":false`,
		},
		{
			name:   "nil is omitted entirely — NIL IS NOT FALSE",
			policy: nil,
			absent: `"require_session_policy"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := presenceRegistry(t, 30*time.Second, base)
			reg.Register(&Peer{
				DeviceId:             "dev-policy",
				RequireSessionPolicy: tc.policy,
				conn:                 presenceConn{},
			})

			req := httptest.NewRequest("GET", "/internal/presence", nil)
			req.Header.Set("Authorization", "Bearer "+presenceTestToken)
			rec := httptest.NewRecorder()
			presenceHandler(reg, presenceTestToken)(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("presence = %d, want 200", rec.Code)
			}
			body := rec.Body.String()
			if tc.want != "" && !contains(body, tc.want) {
				t.Fatalf("require_session_policy wire shape wrong; want %q in: %s", tc.want, body)
			}
			if tc.absent != "" && contains(body, tc.absent) {
				t.Fatalf("nil require_session_policy must be omitted, not emitted; got: %s", body)
			}
		})
	}
}

// presenceAuthorized must return false when want is shorter than presenceTokenMinLen, even when the
// Bearer value matches exactly. This is a defense-in-depth guard: mountPresence never calls
// presenceHandler with a short token, so presenceAuthorized's own len check is the only thing that
// prevents a future call-site from bypassing the mount gate entirely.
func TestPresenceAuthorizedRejectsShortWant(t *testing.T) {
	shortToken := "short" // len=5, well below presenceTokenMinLen=32
	req := httptest.NewRequest("GET", "/internal/presence", nil)
	req.Header.Set("Authorization", "Bearer "+shortToken)
	if presenceAuthorized(req, shortToken) {
		t.Fatal("presenceAuthorized returned true for a want shorter than presenceTokenMinLen; the len guard did not fire")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Audit #9: posture derives from register_agent.features. Silence (no posture_v1) is nil, never false.
func TestGrantKeyPinnedFromFeatures(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want string
	}{
		{"older agent", []string{"directive_v1"}, "nil"},
		{"reports, no pin", []string{"posture_v1"}, "false"},
		{"reports, pinned", []string{"posture_v1", "grant_key_pinned"}, "true"},
		{"pin claim without posture_v1 is not trusted as a report", []string{"grant_key_pinned"}, "nil"},
	} {
		got := "nil"
		if p := grantKeyPinnedFrom(tc.in); p != nil {
			got = fmt.Sprint(*p)
		}
		if got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestPresenceEmitsGrantKeyPinned(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	yes, no := true, false
	for _, tc := range []struct {
		name string
		v    *bool
		want string
		not  string
	}{
		{"true", &yes, `"grant_key_pinned":true`, ""},
		{"false", &no, `"grant_key_pinned":false`, ""},
		{"nil omitted", nil, "", `"grant_key_pinned"`},
	} {
		reg := presenceRegistry(t, 30*time.Second, base)
		reg.Register(&Peer{DeviceId: "dev-p", GrantKeyPinned: tc.v, conn: presenceConn{}})
		req := httptest.NewRequest("GET", "/internal/presence", nil)
		req.Header.Set("Authorization", "Bearer "+presenceTestToken)
		rec := httptest.NewRecorder()
		presenceHandler(reg, presenceTestToken)(rec, req)
		body := rec.Body.String()
		if tc.want != "" && !contains(body, tc.want) {
			t.Errorf("%s: want %q in %s", tc.name, tc.want, body)
		}
		if tc.not != "" && contains(body, tc.not) {
			t.Errorf("%s: %q must be absent: %s", tc.name, tc.not, body)
		}
	}
}

func TestSessionPolicyRequiredFromFeatures(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"directive_v1"}, "nil"},
		{[]string{"posture_v1"}, "false"},
		{[]string{"posture_v1", "grant_key_pinned"}, "false"}, // a pinned key alone is NOT policy-required
		{[]string{"posture_v1", "session_policy_required"}, "true"},
		{[]string{"session_policy_required"}, "nil"},
	} {
		got := "nil"
		if p := sessionPolicyRequiredFrom(tc.in); p != nil {
			got = fmt.Sprint(*p)
		}
		if got != tc.want {
			t.Errorf("%v: got %s, want %s", tc.in, got, tc.want)
		}
	}
}

// Everything a current agent announces (directive + all posture features) must survive boundFeatures
// with room to spare: max 8 entries, 32 bytes each.
func TestAgentFeatureListFitsTheBound(t *testing.T) {
	all := []string{directiveFeature, postureFeature, grantKeyPinnedFeature, sessionPolicyReqFeature}
	if got := boundFeatures(all); len(got) != len(all) {
		t.Fatalf("bound dropped features: %v -> %v", all, got)
	}
	if len(all) > maxAgentFeatures-3 {
		t.Fatalf("only %d spare feature slots left", maxAgentFeatures-len(all))
	}
	for _, f := range all {
		if len(f) > maxFeatureBytes-4 {
			t.Fatalf("feature %q is within 4 bytes of the %d-byte cap", f, maxFeatureBytes)
		}
	}
}

func TestPresenceEmitsSessionPolicyRequired(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	yes := true
	reg := presenceRegistry(t, 30*time.Second, base)
	reg.Register(&Peer{DeviceId: "dev-q", SessionPolicyRequired: &yes, conn: presenceConn{}})
	req := httptest.NewRequest("GET", "/internal/presence", nil)
	req.Header.Set("Authorization", "Bearer "+presenceTestToken)
	rec := httptest.NewRecorder()
	presenceHandler(reg, presenceTestToken)(rec, req)
	if !contains(rec.Body.String(), `"session_policy_required":true`) {
		t.Fatalf("not emitted: %s", rec.Body.String())
	}
}
