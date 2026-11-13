package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The credential must be exactly what coturn's `use-auth-secret` mode computes, or every relayed
// session fails 401 with nothing on our side to explain it. Pinned against a hand-computed vector
// rather than against our own function, which would agree with itself no matter what it did.
func TestTurnCredentialMatchesCoturnSharedSecretScheme(t *testing.T) {
	const secret = "s3cr3t-shared-with-coturn"
	now := time.Unix(1_700_000_000, 0)
	ttl := 12 * time.Hour

	user, pass := turnCredential(secret, "rmt", now, ttl)

	// username = "<unix expiry>:<name>"
	wantUser := "1700043200:rmt"
	if user != wantUser {
		t.Fatalf("username = %q, want %q", user, wantUser)
	}
	// password = base64(HMAC-SHA1(secret, username)) — recomputed independently here.
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(wantUser))
	wantPass := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if pass != wantPass {
		t.Fatalf("password = %q, want %q", pass, wantPass)
	}
	// A credential that never expires defeats the point of issuing it per session.
	exp, err := strconv.ParseInt(strings.SplitN(user, ":", 2)[0], 10, 64)
	if err != nil {
		t.Fatalf("expiry is not an integer: %v", err)
	}
	if exp != now.Add(ttl).Unix() {
		t.Fatalf("expiry %d does not encode now+ttl %d", exp, now.Add(ttl).Unix())
	}
}

// Two sessions must not receive the same credential, or revoking/expiring one affects the other and
// coturn's logs cannot attribute relayed traffic. The expiry is the varying part, so the test moves
// the clock by the smallest unit the scheme can represent.
func TestTurnCredentialsDifferAcrossTime(t *testing.T) {
	const secret = "abc"
	base := time.Unix(1_700_000_000, 0)
	u1, p1 := turnCredential(secret, "rmt", base, time.Hour)
	u2, p2 := turnCredential(secret, "rmt", base.Add(time.Second), time.Hour)
	if u1 == u2 || p1 == p2 {
		t.Fatalf("credentials did not change with the clock: %q/%q vs %q/%q", u1, p1, u2, p2)
	}
	// ...and a different secret yields a different password for the SAME username, which is what
	// makes the secret the thing that authorizes rather than the username.
	_, pOther := turnCredential("different", "rmt", base, time.Hour)
	if pOther == p1 {
		t.Fatal("password did not depend on the secret")
	}
}

// A half-configured TURN (URLs but no secret, or a secret but no URLs) must count as DISABLED.
// Handing a client a TURN URL with no credential produces an ICE server it will try, fail to
// authenticate against, and give up on — a silent loss of the relayed path, which is the one that
// only matters when nothing else worked.
func TestTurnEnabledRequiresBothUrlsAndSecret(t *testing.T) {
	cases := []struct {
		name string
		cfg  TurnConfig
		want bool
	}{
		{"nothing", TurnConfig{}, false},
		{"urls only", TurnConfig{URLs: []string{"turn:x:3478"}}, false},
		{"secret only", TurnConfig{Secret: "s"}, false},
		{"both", TurnConfig{URLs: []string{"turn:x:3478"}, Secret: "s"}, true},
	}
	for _, c := range cases {
		if got := c.cfg.Enabled(); got != c.want {
			t.Fatalf("%s: Enabled() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIceServersForGroupsTransportsUnderOneCredential(t *testing.T) {
	cfg := TurnConfig{
		URLs: []string{
			"turn:turn.example:3478?transport=udp",
			"turn:turn.example:3478?transport=tcp",
		},
		Secret:   "shhh",
		TTL:      time.Hour,
		StunURLs: []string{"stun:stun.example:3478"},
	}
	got := cfg.iceServersFor("sess-1", "rmt", time.Unix(1_700_000_000, 0))

	if len(got) != 2 {
		t.Fatalf("expected a STUN entry and a TURN entry, got %d: %+v", len(got), got)
	}
	// STUN carries NO credential — an empty username must be omitted from the JSON entirely, or the
	// browser receives `username: ""` and hands that to RTCIceServer.
	if got[0].Username != "" || got[0].Credential != "" {
		t.Fatalf("STUN entry carries credentials: %+v", got[0])
	}
	// One credential covers BOTH transports. Splitting them would issue two credentials for one
	// session and double the coturn bookkeeping for no benefit.
	if len(got[1].URLs) != 2 {
		t.Fatalf("TURN transports were split across entries: %+v", got[1])
	}
	if got[1].Username == "" || got[1].Credential == "" {
		t.Fatalf("TURN entry is missing credentials: %+v", got[1])
	}

	// The wire shape, marshalled through the `ServerToClient` ENVELOPE — what actually goes on the
	// socket, and what injects the `type` discriminant.
	//
	// Asserted by FIELD NAME, not as a byte prefix. `marshalTagged` re-marshals the payload through
	// a `map[string]json.RawMessage` to inject the tag, and Go sorts map keys — so this server emits
	// `{"servers":…,"session":…,"type":…}` while serde emits declaration order. JSON object key
	// order carries no meaning and both sides decode by name, so the real cross-language contract is
	// the set of field NAMES and the omitempty behaviour. (An earlier version of this test asserted
	// a byte prefix and failed against correct code — recorded here so it is not "fixed" back.)
	b, err := json.Marshal(ServerToClient{Payload: IceServers{Session: "S", Servers: got}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back struct {
		Type    string `json:"type"`
		Session string `json:"session"`
		Servers []struct {
			URLs       []string `json:"urls"`
			Username   *string  `json:"username"`
			Credential *string  `json:"credential"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("the emitted JSON does not parse: %v (%s)", err, b)
	}
	if back.Type != "ice_servers" || back.Session != "S" || len(back.Servers) != 2 {
		t.Fatalf("envelope drifted: %s", b)
	}
	// STUN: username/credential must be ABSENT, not null and not "". `*string` distinguishes all
	// three, which a plain `string` could not — and absent is what `RTCIceServer` needs.
	if back.Servers[0].Username != nil || back.Servers[0].Credential != nil {
		t.Fatalf("STUN entry emitted credential keys: %s", b)
	}
	if back.Servers[1].Username == nil || back.Servers[1].Credential == nil {
		t.Fatalf("TURN entry omitted its credential keys: %s", b)
	}
	if !strings.HasPrefix(*back.Servers[1].Username, "17000") {
		t.Fatalf("TURN username is not <expiry>:<name>: %q", *back.Servers[1].Username)
	}
}

// With nothing configured the list is EMPTY, not absent and not a placeholder. That is the LAN
// answer — host candidates only — and it must serialize as `[]` rather than `null`, because
// `null` deserializes into the Rust `Vec` as a decode error and would drop the whole message.
func TestIceServersForIsEmptyNotNullWhenUnconfigured(t *testing.T) {
	got := TurnConfig{}.iceServersFor("s", "rmt", time.Now())
	if len(got) != 0 {
		t.Fatalf("expected no ICE servers, got %+v", got)
	}
	b, err := json.Marshal(ServerToClient{Payload: IceServers{Session: "S", Servers: got}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// `[]`, NOT `null`. A nil slice marshals to `null`, which fails to deserialize into the Rust
	// `Vec<IceServerSpec>` and drops the whole message — so the LAN case would lose `ice_servers`
	// entirely rather than receiving an empty one.
	if !strings.Contains(string(b), `"servers":[]`) {
		t.Fatalf("empty list must marshal as [] and not null: %s", b)
	}
	if !strings.Contains(string(b), `"type":"ice_servers"`) {
		t.Fatalf("the envelope did not inject the type tag: %s", b)
	}
}

// STUN without TURN is a legitimate configuration (most home NATs need nothing more), and it must
// not require a secret.
func TestStunOnlyNeedsNoSecret(t *testing.T) {
	cfg := TurnConfig{StunURLs: []string{"stun:stun.example:3478"}}
	got := cfg.iceServersFor("s", "rmt", time.Now())
	if len(got) != 1 || len(got[0].URLs) != 1 || got[0].Username != "" {
		t.Fatalf("expected one credential-less STUN entry, got %+v", got)
	}
}

func TestSplitListTrimsAndDropsBlanks(t *testing.T) {
	got := splitList(" a , ,b,  c ")
	want := []string{"a", "b", "c"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if splitList("") != nil || splitList("  ,  ") != nil {
		t.Fatal("an empty or blank list must yield nil, not a slice of empty strings")
	}
}

func TestSecurityTurnCredentialsAreSessionSpecific(t *testing.T) {
	cfg := TurnConfig{URLs: []string{"turn:relay.invalid"}, Secret: "test-secret", TTL: time.Hour}
	now := time.Unix(1700000000, 0)
	a, b := cfg.iceServersFor("session-a", "rmt", now), cfg.iceServersFor("session-b", "rmt", now)
	if a[0].Username == b[0].Username || a[0].Credential == b[0].Credential {
		t.Fatal("two sessions share credentials")
	}
}

func turnEntries(conn *fakeConn) int {
	n := 0
	for _, m := range conn.messages() {
		if ice, ok := m.Payload.(IceServers); ok {
			for _, s := range ice.Servers {
				if s.Username != "" {
					n++
				}
			}
		}
	}
	return n
}

func turnNoticeOf(conn *fakeConn) string {
	for _, m := range conn.messages() {
		if ice, ok := m.Payload.(IceServers); ok {
			return ice.RelayNotice
		}
	}
	return ""
}

// turnHarness: a verifying broker with a controllable clock. Each connect uses a fresh agent (agents
// are single-session) and a fresh ticket for (tenant, technician).
type turnHarness struct {
	t      *testing.T
	reg    *Registry
	broker *Broker
	now    int64
	n      int
}

func newTurnHarness(t *testing.T, perUser, perTenant int) *turnHarness {
	h := &turnHarness{t: t, reg: NewRegistry(time.Hour), now: 1_730_000_000_000}
	h.broker = NewBroker(h.reg, "ed25519:server", "relay-1:4444", ticketGoldenPubkey(t)).WithTurn(TurnConfig{
		URLs: []string{"turn:turn.example:3478"}, Secret: "s", TTL: time.Hour,
	}).WithTurnLimits(perUser, perTenant)
	h.broker.nowMs = func() int64 { return h.now }
	return h
}

// connect brokers one session and returns the requester's conn and the session id.
func (h *turnHarness) connect(tenant, tech string) (*fakeConn, string) {
	h.n++
	dev := fmt.Sprintf("dev-%d", h.n)
	a := mkPeer(dev, "ed25519:"+dev, NatFullCone, &fakeConn{})
	a.Tenant = tenant
	h.reg.Register(a)
	c := &fakeConn{}
	tk := mintTicket(h.t, TicketClaims{V: 1, SessionID: fmt.Sprintf("sess-%d", h.n), TechnicianID: tech,
		TenantID: tenant, DeviceID: dev, IssuedAtMs: h.now, ExpiresAtMs: h.now + 3_600_000_000})
	s, err := h.broker.ConnectRequest(&Peer{DeviceId: fmt.Sprintf("c%d", h.n), Pubkey: "ed25519:c", conn: c}, dev, tk)
	if err != nil {
		h.t.Fatalf("connect: %v", err)
	}
	return c, s.Id
}

// Audit #14 (repair): the cap counts ISSUED unexpired credentials, not live sessions, so
// start / end / repeat cannot accumulate valid usernames; expiry frees capacity; the requester is told.
func TestSecurityTurnStartEndRepeatIsBounded(t *testing.T) {
	h := newTurnHarness(t, 3, 100)
	issued, notices := 0, 0
	for i := 0; i < 10; i++ {
		c, id := h.connect("t1", "tech-a")
		issued += turnEntries(c)
		if turnNoticeOf(c) != "" {
			notices++
		}
		h.broker.dropSession(id) // the session ENDS; its credential is still valid
	}
	if issued != 3 {
		t.Fatalf("start/end/repeat issued %d live credentials, want exactly the cap (3)", issued)
	}
	if notices != 7 {
		t.Fatalf("requester told about missing relay %d times, want 7", notices)
	}
	// Expiry frees capacity (fake clock moves past the 1h TTL).
	h.now += 3_600_001
	c, _ := h.connect("t1", "tech-a")
	if turnEntries(c) != 1 || turnNoticeOf(c) != "" {
		t.Fatalf("after expiry the credential must be issuable again (entries=%d notice=%q)", turnEntries(c), turnNoticeOf(c))
	}
}

func TestSecurityTurnTenantCapAndIdentityKeying(t *testing.T) {
	h := newTurnHarness(t, 100, 2)
	c1, _ := h.connect("t1", "a")
	c2, _ := h.connect("t1", "b") // different technician, same tenant
	c3, _ := h.connect("t1", "c")
	if turnEntries(c1) != 1 || turnEntries(c2) != 1 || turnEntries(c3) != 0 {
		t.Fatalf("tenant cap: %d %d %d", turnEntries(c1), turnEntries(c2), turnEntries(c3))
	}
	// A different tenant is unaffected.
	c4, _ := h.connect("t2", "a")
	if turnEntries(c4) != 1 {
		t.Fatal("tenant t2 must have its own allowance")
	}
}

// With no ticket verifier the identity is unverified: everyone shares ONE small global bucket. A fresh
// connection must NOT get a fresh allowance, and the empty tenant is not a real tenant's bucket.
func TestSecurityTurnUnverifiedSharesOneSmallBucket(t *testing.T) {
	reg := NewRegistry(time.Hour)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil).WithTurn(TurnConfig{
		URLs: []string{"turn:turn.example:3478"}, Secret: "s", TTL: time.Hour,
	}).WithTurnLimits(100, 100)
	total := 0
	for i := 0; i < 10; i++ {
		dev := fmt.Sprintf("agent-%d", i)
		reg.Register(mkPeer(dev, "ed25519:"+dev, NatFullCone, &fakeConn{}))
		c := &fakeConn{} // a brand-new connection each time
		if _, err := broker.ConnectRequest(&Peer{DeviceId: fmt.Sprintf("c%d", i), Pubkey: "ed25519:c", conn: c}, dev, nil); err != nil {
			t.Fatal(err)
		}
		total += turnEntries(c)
	}
	if total != turnMaxUnverified {
		t.Fatalf("unverified sessions got %d credentials, want the single global bucket of %d", total, turnMaxUnverified)
	}
}

func TestTurnDefaultTTLIsShort(t *testing.T) {
	t.Setenv("SIGNALING_TURN_TTL", "")
	if ttl := turnConfigFromEnv().TTL; ttl > 2*time.Hour {
		t.Fatalf("default TURN TTL %s exceeds 2h", ttl)
	}
}

// Zero caps (TURN_MAX_PER_* left empty) take the built-in defaults, which are production's 20 / 80.
func TestTurnCapsDefaultToProductionValues(t *testing.T) {
	h := newTurnHarness(t, 0, 0)
	issued := 0
	for i := 0; i < 25; i++ {
		c, _ := h.connect("t1", "tech-a")
		issued += turnEntries(c)
	}
	if issued != 20 {
		t.Fatalf("one technician got %d credentials with the default caps, want 20", issued)
	}
	for i := 0; i < 70; i++ { // other technicians fill the tenant's remaining 60 and are then refused
		c, _ := h.connect("t1", fmt.Sprintf("tech-%d", i%10))
		issued += turnEntries(c)
	}
	if issued != 80 {
		t.Fatalf("the tenant got %d credentials with the default caps, want 80", issued)
	}
}
