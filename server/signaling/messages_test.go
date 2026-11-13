package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func strptr(s string) *string { return &s }

// TestClientMessageRoundTrip encodes each client message, checks the discriminant tag, then
// decodes it back and asserts the payload survives unchanged.
func TestClientMessageRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload any
		wantTag string
	}{
		{
			name:    "register_agent with token",
			payload: &RegisterAgent{Device: "dev-1", Pubkey: "ed25519:abc", Nat: NatPortRestricted, EnrollmentToken: strptr("tok")},
			wantTag: "register_agent",
		},
		{
			name:    "register_agent without token",
			payload: &RegisterAgent{Device: "dev-2", Pubkey: "ed25519:def", Nat: NatOpen},
			wantTag: "register_agent",
		},
		{
			name:    "register_agent with tenant",
			payload: &RegisterAgent{Device: "dev-3", Pubkey: "ed25519:ghi", Tenant: "tenant-1", Nat: NatOpen},
			wantTag: "register_agent",
		},
		{
			name:    "register_agent with os",
			payload: &RegisterAgent{Device: "dev-4", Pubkey: "ed25519:jkl", Nat: NatOpen, OS: "Windows 11 Pro 25H2 (build 26200)"},
			wantTag: "register_agent",
		},
		{
			// *bool(true) must round-trip as *bool(true), not nil.
			name:    "register_agent with require_session_policy true",
			payload: func() *RegisterAgent { v := true; return &RegisterAgent{Device: "dev-5", Pubkey: "ed25519:mno", Nat: NatOpen, RequireSessionPolicy: &v} }(),
			wantTag: "register_agent",
		},
		{
			// *bool(false) must round-trip as *bool(false), not nil — nil means "older agent, asserted nothing".
			name:    "register_agent with require_session_policy false",
			payload: func() *RegisterAgent { v := false; return &RegisterAgent{Device: "dev-6", Pubkey: "ed25519:pqr", Nat: NatOpen, RequireSessionPolicy: &v} }(),
			wantTag: "register_agent",
		},
		{
			name:    "register_agent with agent_version",
			payload: &RegisterAgent{Device: "dev-7", Pubkey: "ed25519:stu", Nat: NatOpen, AgentVersion: "0.4.0+abc1234"},
			wantTag: "register_agent",
		},
		{
			name:    "agent_auth_response",
			payload: &AgentAuthResponse{Device: "dev-1", Nonce: "a0b1", Sig: "b8ba"},
			wantTag: "agent_auth_response",
		},
		{
			name:    "heartbeat",
			payload: &Heartbeat{Device: "dev-1"},
			wantTag: "heartbeat",
		},
		{
			name:    "connect_request",
			payload: &ConnectRequest{Target: "dev-9"},
			wantTag: "connect_request",
		},
		{
			name:    "candidate",
			payload: &CandidateMsg{Session: "sess-1", Candidate: Candidate{Addr: "1.2.3.4:5", Kind: CandidateServerReflexive}},
			wantTag: "candidate",
		},
		{
			name:    "sdp offer",
			payload: &SdpMsg{Session: "sess-sdp", Sdp: "v=0\r\n", Kind: SdpOffer},
			wantTag: "sdp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(ClientToServer{Payload: tt.payload})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(data), `"type":"`+tt.wantTag+`"`) {
				t.Fatalf("encoded message %s missing tag %q: %s", tt.name, tt.wantTag, data)
			}

			var got ClientToServer
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Type != tt.wantTag {
				t.Fatalf("decoded Type=%q, want %q", got.Type, tt.wantTag)
			}
			if !reflect.DeepEqual(got.Payload, tt.payload) {
				t.Fatalf("round-trip mismatch:\n got  %#v\n want %#v", got.Payload, tt.payload)
			}
		})
	}
}

// TestServerMessageRoundTrip does the same for server-originated messages.
func TestServerMessageRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload any
		wantTag string
	}{
		{
			name:    "registered",
			payload: &Registered{ServerPubkey: "ed25519:server"},
			wantTag: "registered",
		},
		{
			name:    "agent_auth_challenge",
			payload: &AgentAuthChallenge{Device: "dev-1", Nonce: "a0b1", ExpiresAtMs: 1730000030000},
			wantTag: "agent_auth_challenge",
		},
		{
			name:    "brokered",
			payload: &Brokered{Session: "s1", PeerDevice: "dev-1", PeerPubkey: "ed25519:peer"},
			wantTag: "brokered",
		},
		{
			name:    "relay_assignment",
			payload: &RelayAssignment{Session: "s1", RelayAddr: "relay-eu-1.example:4444", Token: "tok-uuid"},
			wantTag: "relay_assignment",
		},
		{
			name:    "candidate",
			payload: &CandidateMsg{Session: "s1", Candidate: Candidate{Addr: "[::1]:9", Kind: CandidateRelayed}},
			wantTag: "candidate",
		},
		{
			name:    "rejected",
			payload: &Rejected{Reason: "unauthorized"},
			wantTag: "rejected",
		},
		{
			name:    "sdp answer",
			payload: &SdpMsg{Session: "sess-sdp", Sdp: "v=0\r\n", Kind: SdpAnswer},
			wantTag: "sdp",
		},
		{
			name:    "ice_servers",
			payload: &IceServers{Session: "sess-ice", Servers: []IceServerSpec{{URLs: []string{"stun:stun.example:3478"}}}},
			wantTag: "ice_servers",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(ServerToClient{Payload: tt.payload})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(data), `"type":"`+tt.wantTag+`"`) {
				t.Fatalf("encoded message %s missing tag %q: %s", tt.name, tt.wantTag, data)
			}

			var got ServerToClient
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Type != tt.wantTag {
				t.Fatalf("decoded Type=%q, want %q", got.Type, tt.wantTag)
			}
			if !reflect.DeepEqual(got.Payload, tt.payload) {
				t.Fatalf("round-trip mismatch:\n got  %#v\n want %#v", got.Payload, tt.payload)
			}
		})
	}
}

// TestExactWireShape pins the exact JSON produced for a representative message so a drift from
// the Rust rmt-protocol contract is caught (snake_case fields, string ids, "type" tag).
//
// THE RUST HALF OF THIS CONTRACT is `client_messages_serialize_with_a_type_tag` and
// `register_agent_stays_backward_compatible_without_a_tenant` in
// crates/protocol/src/signaling.rs. rmt/signaling and the Rust workspace are separate modules with
// no shared compiler, so a renamed key compiles perfectly on both sides and silently produces zero
// values on one of them. The only thing that catches that is one test per side naming the SAME
// literal, and each file naming the other by path — which is why the value below is spelled
// identically over there.
func TestExactWireShape(t *testing.T) {
	data, err := json.Marshal(ClientToServer{Payload: &RegisterAgent{
		Device: "d", Pubkey: "pk", Nat: NatSymmetric,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"type", "device", "pubkey", "nat"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing expected field %q in %s", key, data)
		}
	}
	// enrollment_token, tenant, os, require_session_policy, agent_version and logged_in_user are
	// omitempty and must be absent when unset — older agents (and the Rust protocol crate) send
	// none of them.
	//
	// require_session_policy was pinned on the RUST side only until loop 96. That is exactly the
	// half-a-contract defect this comment block exists to prevent, so it is included here now.
	for _, key := range []string{"enrollment_token", "tenant", "os", "require_session_policy", "agent_version", "logged_in_user"} {
		if _, ok := m[key]; ok {
			t.Errorf("%s should be omitted when unset: %s", key, data)
		}
	}
	if m["type"] != "register_agent" {
		t.Errorf("type = %v, want register_agent", m["type"])
	}
	if m["nat"] != "symmetric" {
		t.Errorf("nat = %v, want symmetric", m["nat"])
	}

	// POPULATED SHAPE. The literals below are shared with the Rust test named above; changing one
	// without the other is the drift this pins.
	floor := true
	populated, err := json.Marshal(ClientToServer{Payload: &RegisterAgent{
		Device: "d", Pubkey: "pk", Nat: NatSymmetric,
		OS:                   "Windows 11 Pro 25H2 (build 26200)",
		RequireSessionPolicy: &floor,
		AgentVersion:         "0.4.0+abc1234",
		LoggedInUser:         "CORP\\alice",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var pm map[string]any
	if err := json.Unmarshal(populated, &pm); err != nil {
		t.Fatal(err)
	}
	if pm["os"] != "Windows 11 Pro 25H2 (build 26200)" {
		t.Errorf("os = %v: %s", pm["os"], populated)
	}
	if pm["require_session_policy"] != true {
		t.Errorf("require_session_policy = %v: %s", pm["require_session_policy"], populated)
	}
	// The literal "0.4.0+abc1234" is asserted verbatim in crates/protocol/src/signaling.rs.
	if pm["agent_version"] != "0.4.0+abc1234" {
		t.Errorf("agent_version = %v, want 0.4.0+abc1234: %s", pm["agent_version"], populated)
	}
	// The literal "CORP\\alice" is asserted verbatim in crates/protocol/src/signaling.rs.
	if pm["logged_in_user"] != "CORP\\alice" {
		t.Errorf("logged_in_user = %v, want CORP\\alice: %s", pm["logged_in_user"], populated)
	}
}

// TestBoundAgentVersion is the receipt-side cap on register_agent's agent_version. The field
// arrives BEFORE proof of possession, so it is attacker-controlled on the unauthenticated edge and
// flows straight into the registry and the presence feed; the bound is what keeps that bounded.
// Truncation must never split a UTF-8 sequence, for the same reason boundOSDescription must not.
func TestBoundAgentVersion(t *testing.T) {
	if got := boundAgentVersion(""); got != "" {
		t.Fatalf("empty in, %q out", got)
	}
	real := "0.0.1+0594362"
	if got := boundAgentVersion(real); got != real {
		t.Fatalf("a real version must pass through unchanged, got %q", got)
	}
	exact := strings.Repeat("x", maxAgentVersionBytes)
	if got := boundAgentVersion(exact); got != exact {
		t.Fatalf("an exactly-at-bound value must pass through unchanged (len %d)", len(got))
	}
	if got := boundAgentVersion(strings.Repeat("x", 4096)); len(got) != maxAgentVersionBytes {
		t.Fatalf("oversized ASCII -> %d bytes, want %d", len(got), maxAgentVersionBytes)
	}
	// Straddle: fill to one byte short of the bound, then a 3-byte rune crosses it. The result must
	// back off the whole rune rather than emit a dangling lead byte.
	straddle := strings.Repeat("x", maxAgentVersionBytes-1) + "日"
	got := boundAgentVersion(straddle)
	if len(got) != maxAgentVersionBytes-1 || !utf8.ValidString(got) {
		t.Fatalf("straddling rune -> %d bytes valid=%v, want %d/true", len(got), utf8.ValidString(got), maxAgentVersionBytes-1)
	}
}

// boundOSDescription: the receipt-side cap on register_agent's os. Truncation must never split a
// UTF-8 sequence — a localized ProductName is multi-byte and broken UTF-8 in the presence feed
// would push the damage onto every consumer.
func TestBoundOSDescription(t *testing.T) {
	if got := boundOSDescription(""); got != "" {
		t.Fatalf("empty in, %q out", got)
	}
	small := "Windows 11 Pro 25H2 (build 26200)"
	if got := boundOSDescription(small); got != small {
		t.Fatalf("an in-bound value must pass through unchanged, got %q", got)
	}
	exact := strings.Repeat("x", maxOSDescriptionBytes)
	if got := boundOSDescription(exact); got != exact {
		t.Fatalf("an exactly-at-bound value must pass through unchanged (len %d)", len(got))
	}
	if got := boundOSDescription(strings.Repeat("x", 400)); len(got) != maxOSDescriptionBytes {
		t.Fatalf("oversized ASCII → %d bytes, want %d", len(got), maxOSDescriptionBytes)
	}
	// 3-byte runes: 85×3 = 255 fits exactly; one more rune must drop the whole rune, never leave
	// a dangling lead/continuation byte.
	rune3 := "日"
	if got := boundOSDescription(strings.Repeat(rune3, 86)); len(got) != 255 || !utf8.ValidString(got) {
		t.Fatalf("multi-byte truncation → %d bytes valid=%v, want 255/true", len(got), utf8.ValidString(got))
	}
	// Force a straddle: 254 ASCII bytes then a 3-byte rune puts the rune across the bound; the
	// result must back off to 254, not emit 1 byte of the rune.
	straddle := strings.Repeat("x", 254) + rune3
	if got := boundOSDescription(straddle); len(got) != 254 || !utf8.ValidString(got) {
		t.Fatalf("straddling rune → %d bytes valid=%v, want 254/true", len(got), utf8.ValidString(got))
	}
}

// TestBoundLoggedInUser is the receipt-side cap on register_agent's logged_in_user. Like
// agent_version it is attacker-controlled on the unauthenticated edge and flows straight into the
// registry and the presence feed; the bound is what keeps that contained.
func TestBoundLoggedInUser(t *testing.T) {
	if got := boundLoggedInUser(""); got != "" {
		t.Fatalf("empty in, %q out", got)
	}
	real := "CORP\\alice"
	if got := boundLoggedInUser(real); got != real {
		t.Fatalf("a real value must pass through unchanged, got %q", got)
	}
	exact := strings.Repeat("x", maxLoggedInUserBytes)
	if got := boundLoggedInUser(exact); got != exact {
		t.Fatalf("an exactly-at-bound value must pass through unchanged (len %d)", len(got))
	}
	if got := boundLoggedInUser(strings.Repeat("x", 4096)); len(got) != maxLoggedInUserBytes {
		t.Fatalf("oversized ASCII → %d bytes, want %d", len(got), maxLoggedInUserBytes)
	}
	// Straddle: fill to one byte short of the bound, then a 3-byte rune crosses it.
	straddle := strings.Repeat("x", maxLoggedInUserBytes-1) + "日"
	got := boundLoggedInUser(straddle)
	if len(got) != maxLoggedInUserBytes-1 || !utf8.ValidString(got) {
		t.Fatalf("straddling rune → %d bytes valid=%v, want %d/true", len(got), utf8.ValidString(got), maxLoggedInUserBytes-1)
	}
}

// inventoryBoundHelpers lists the three pre-auth inventory helpers with their byte caps.
var inventoryBoundHelpers = []struct {
	name  string
	fn    func(string) string
	limit int
}{
	{"os", boundOSDescription, maxOSDescriptionBytes},
	{"version", boundAgentVersion, maxAgentVersionBytes},
	{"user", boundLoggedInUser, maxLoggedInUserBytes},
}

// TestBoundInventoryPreservesPrintableText: ordinary values, including non-ASCII, a backslash and
// a '+', are returned unchanged by every helper.
func TestBoundInventoryPreservesPrintableText(t *testing.T) {
	for _, h := range inventoryBoundHelpers {
		for _, v := range []string{"Windows 11 Pro", "CORP\\alice", "0.0.1+0594362", "Windows 11 プロ日本語", "Café Zoë résumé"} {
			if got := h.fn(v); got != v {
				t.Errorf("%s: %q changed to %q", h.name, v, got)
			}
		}
	}
}

// TestBoundInventoryStripsControlChars: C0 (incl. NUL/CR/LF/TAB), DEL and C1 runes are removed, and
// a value made only of them becomes empty.
func TestBoundInventoryStripsControlChars(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Win\ndows", "Windows"},
		{"Win\r\ndows", "Windows"},
		{"Win\x00dows", "Windows"},
		{"Win\tdows", "Windows"},
		{"Win\x7fdows", "Windows"},
		{"Win\u0085dows", "Windows"},
		{"\x00\r\n\t\x7f\u0085\u009f\x1b", ""},
		{"CORP\\\nalice", "CORP\\alice"},
	}
	for _, h := range inventoryBoundHelpers {
		for _, c := range cases {
			if got := h.fn(c.in); got != c.want {
				t.Errorf("%s: %q → %q, want %q", h.name, c.in, got, c.want)
			}
		}
	}
}

// TestBoundInventoryStripsBeforeTruncating: control characters must not consume cap bytes.
func TestBoundInventoryStripsBeforeTruncating(t *testing.T) {
	in := strings.Repeat("x", 10) + "\n" + strings.Repeat("x", 300)
	for _, h := range inventoryBoundHelpers {
		want := strings.Repeat("x", h.limit)
		if got := h.fn(in); got != want {
			t.Errorf("%s: got %d bytes, want %d x's", h.name, len(got), h.limit)
		}
	}
}

// TestBoundInventoryStraddlingRuneAfterStrip: a multi-byte rune crossing the cap is not split even
// when control characters were stripped first.
func TestBoundInventoryStraddlingRuneAfterStrip(t *testing.T) {
	for _, h := range inventoryBoundHelpers {
		in := "\n" + strings.Repeat("x", h.limit-1) + "\r日"
		got := h.fn(in)
		if len(got) != h.limit-1 || !utf8.ValidString(got) {
			t.Errorf("%s: %d bytes valid=%v, want %d/true", h.name, len(got), utf8.ValidString(got), h.limit-1)
		}
	}
}

// TestBoundInventoryNeverEmitsControlRunes: over a mixed table, no output rune is a control rune.
func TestBoundInventoryNeverEmitsControlRunes(t *testing.T) {
	inputs := []string{
		"", "plain", "a\x00b\nc\rd\te\x7ff\u0085g\u009fh",
		strings.Repeat("\x01x", 200), strings.Repeat("日\n", 100), "\u0080\u0081\u0082ok",
		strings.Repeat("x", 63) + "\x00日\u0085" + strings.Repeat("y", 50),
	}
	for _, h := range inventoryBoundHelpers {
		for _, in := range inputs {
			for _, r := range h.fn(in) {
				if unicode.IsControl(r) {
					t.Errorf("%s: %q output contains control rune %U", h.name, in, r)
				}
			}
		}
	}
}

func TestUnknownTypeRejected(t *testing.T) {
	var m ClientToServer
	err := json.Unmarshal([]byte(`{"type":"bogus"}`), &m)
	if err == nil {
		t.Fatal("expected error decoding unknown message type")
	}
}

func TestUnknownServerTypeRejected(t *testing.T) {
	var got ServerToClient
	err := json.Unmarshal([]byte(`{"type":"unknown_server_type_xyz"}`), &got)
	if err == nil {
		t.Fatal("expected error decoding unknown server message type")
	}
}
