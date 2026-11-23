package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func nameVector(t *testing.T) (nameAttestation, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../docs/73-name-attestation-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Claims   nameClaims `json:"claims"`
		Preimage string     `json:"preimage_hex"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	preimage, err := hex.DecodeString(vector.Preimage)
	if err != nil {
		t.Fatal(err)
	}
	return nameAttestation{Claims: vector.Claims, Sig: signTestName(t, preimage)}, preimage
}

func signTestName(t *testing.T, preimage []byte) string {
	t.Helper()
	key, err := hex.DecodeString(ticketGoldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(key), preimage))
}

func encodeTestName(t *testing.T, a nameAttestation) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNameAttestationGoldenVector(t *testing.T) {
	a, preimage := nameVector(t)
	if !bytes.Equal(nameSigningBytes(a.Claims), preimage) {
		t.Fatal("name attestation canonical preimage drifted")
	}
	pub := ticketGoldenPubkey(t)
	c := ticketGoldenClaims()
	if got := verifiedDisplayName(pub, encodeTestName(t, a), c, c.ExpiresAtMs); got != a.Claims.DisplayName {
		t.Fatal("golden name failed verification at the inclusive expiry boundary")
	}
	if verifiedDisplayName(pub, encodeTestName(t, a), c, c.ExpiresAtMs+1) != "" {
		t.Fatal("expired name verified")
	}
	if verifyTicket(pub, &SignedSessionTicket{Claims: c, Sig: a.Sig}, c.ExpiresAtMs, c.DeviceID) == nil {
		t.Fatal("name signature verified as a ticket")
	}
}

type nameTestRedeemer struct{ err error }

func (r nameTestRedeemer) Redeem(context.Context, TicketClaims) error { return r.err }

func nameTestBroker(t *testing.T, agentConn peerConn) (*Broker, *Peer) {
	t.Helper()
	c := ticketGoldenClaims()
	reg := NewRegistry(time.Minute)
	agent := &Peer{DeviceId: c.DeviceID, Tenant: c.TenantID, Pubkey: "test-agent", conn: agentConn, MultiSessionCapable: boolPtr(true)}
	reg.Register(agent)
	b := NewBroker(reg, "server", "relay", ticketGoldenPubkey(t)).WithTicketRedeemer(nameTestRedeemer{})
	b.nowMs = func() int64 { return c.ExpiresAtMs }
	return b, agent
}

func TestConnectRequestNameAdmission(t *testing.T) {
	valid, _ := nameVector(t)
	for _, tc := range []struct {
		label  string
		change func(*nameAttestation)
		resign bool
		raw    json.RawMessage
		ledger TicketRedeemer
		want   bool
	}{
		{label: "matching", ledger: nameTestRedeemer{}, want: true},
		{label: "tampered session", ledger: nameTestRedeemer{}, change: func(a *nameAttestation) { a.Claims.SessionID += "x" }},
		{label: "tampered technician", ledger: nameTestRedeemer{}, change: func(a *nameAttestation) { a.Claims.TechnicianID += "x" }},
		{label: "tampered display name", ledger: nameTestRedeemer{}, change: func(a *nameAttestation) { a.Claims.DisplayName += "x" }},
		{label: "tampered expiry", ledger: nameTestRedeemer{}, change: func(a *nameAttestation) { a.Claims.ExpiresAtMs++ }},
		{label: "tampered version", ledger: nameTestRedeemer{}, change: func(a *nameAttestation) { a.Claims.V += 256 }},
		{label: "signed wrong session", ledger: nameTestRedeemer{}, resign: true, change: func(a *nameAttestation) { a.Claims.SessionID += "x" }},
		{label: "signed wrong technician", ledger: nameTestRedeemer{}, resign: true, change: func(a *nameAttestation) { a.Claims.TechnicianID += "x" }},
		{label: "signed wrong expiry", ledger: nameTestRedeemer{}, resign: true, change: func(a *nameAttestation) { a.Claims.ExpiresAtMs++ }},
		{label: "signed expired", ledger: nameTestRedeemer{}, resign: true, change: func(a *nameAttestation) { a.Claims.ExpiresAtMs-- }},
		{label: "signed wrong version", ledger: nameTestRedeemer{}, resign: true, change: func(a *nameAttestation) { a.Claims.V = 2 }},
		{label: "forged signature", ledger: nameTestRedeemer{}, change: func(a *nameAttestation) { a.Sig = strings.Repeat("ff", 64) }},
		{label: "ticket signature", ledger: nameTestRedeemer{}, change: func(a *nameAttestation) { a.Sig = ticketGoldenSigHex }},
		{label: "wrong envelope shape", ledger: nameTestRedeemer{}, raw: json.RawMessage(`["name"]`)},
		{label: "wrong claims shape", ledger: nameTestRedeemer{}, raw: json.RawMessage(`{"claims":"name"}`)},
		{label: "no shared ledger"},
		{label: "shared ledger fail-open", ledger: nameTestRedeemer{errors.New("unavailable")}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			b, agent := nameTestBroker(t, &fakeConn{})
			b.redeemer = tc.ledger
			a := valid
			if tc.change != nil {
				tc.change(&a)
			}
			if tc.resign {
				a.Sig = signTestName(t, nameSigningBytes(a.Claims))
			}
			raw := tc.raw
			if raw == nil {
				raw = encodeTestName(t, a)
			}
			ticket := mintTicket(t, ticketGoldenClaims())
			frame, err := json.Marshal(ClientToServer{Payload: ConnectRequest{Target: agent.DeviceId, Ticket: ticket, NameAttestation: raw}})
			if err != nil {
				t.Fatal(err)
			}
			var msg ClientToServer
			if err := json.Unmarshal(frame, &msg); err != nil {
				t.Fatal("connect_request failed decoding:", err)
			}
			p := msg.Payload.(*ConnectRequest)
			conn := &fakeConn{}
			if _, err := b.connectRequest(&Peer{conn: conn}, p.Target, p.Ticket, p.NameAttestation); err != nil {
				t.Fatal("connection refused:", err)
			}
			sp := waitRoster(t, conn, 1, 0)
			want := ""
			if tc.want {
				want = valid.Claims.DisplayName
			}
			if sp.Participants[0].DisplayName != want {
				t.Fatal("unexpected name disclosure")
			}
		})
	}
}

func TestNameAdmissionUsesTicketInstantAcrossRedemption(t *testing.T) {
	a, _ := nameVector(t)
	b, agent := nameTestBroker(t, &fakeConn{})
	now := a.Claims.ExpiresAtMs
	b.nowMs = func() int64 { return now }
	b.redeemer = nameTestRedeemFunc(func(context.Context, TicketClaims) error {
		now++
		return nil
	})
	conn := &fakeConn{}
	if _, err := b.connectRequest(&Peer{conn: conn}, agent.DeviceId,
		mintTicket(t, ticketGoldenClaims()), encodeTestName(t, a)); err != nil {
		t.Fatal(err)
	}
	roster := waitRoster(t, conn, 1, 0)
	if roster.Participants[0].DisplayName != a.Claims.DisplayName {
		t.Fatal("name verification used a later instant than ticket verification")
	}
}

type nameTestRedeemFunc func(context.Context, TicketClaims) error

func (f nameTestRedeemFunc) Redeem(ctx context.Context, claims TicketClaims) error {
	return f(ctx, claims)
}

type nameRosterConn struct {
	fakeConn
	onWrite func(ServerToClient) error
}

func (c *nameRosterConn) WriteJSON(v any) error {
	if c.onWrite != nil {
		if err := c.onWrite(v.(ServerToClient)); err != nil {
			return err
		}
	}
	return c.fakeConn.WriteJSON(v)
}

func namedTestCredentials(t *testing.T, suffix string) (*SignedSessionTicket, json.RawMessage) {
	t.Helper()
	ticket := ticketGoldenClaims()
	ticket.SessionID += suffix
	a := nameAttestation{Claims: nameClaims{
		V: 1, SessionID: ticket.SessionID, TechnicianID: ticket.TechnicianID,
		DisplayName: "Name for " + suffix, ExpiresAtMs: ticket.ExpiresAtMs,
	}}
	a.Sig = signTestName(t, nameSigningBytes(a.Claims))
	return mintTicket(t, ticket), encodeTestName(t, a)
}

func joinNamed(t *testing.T, b *Broker, p *Peer, suffix string) (*Session, error) {
	t.Helper()
	ticket, attestation := namedTestCredentials(t, suffix)
	return b.connectRequest(p, ticket.Claims.DeviceID, ticket, attestation)
}

func TestUnpresentedNamedTicketDoesNotChangeRoster(t *testing.T) {
	b, agent := nameTestBroker(t, &fakeConn{})
	conn := &fakeConn{}
	live, err := joinNamed(t, b, &Peer{conn: conn}, "live")
	if err != nil {
		t.Fatal(err)
	}
	roster := waitRoster(t, conn, 1, 0)
	ticket, attestation := namedTestCredentials(t, "unused")
	if verifyTicket(b.ticketPub, ticket, b.nowMs(), agent.DeviceId) != nil ||
		verifiedDisplayName(b.ticketPub, attestation, ticket.Claims, b.nowMs()) != "Name for unused" {
		t.Fatal("fixture did not issue a valid named ticket")
	}
	probe, err := joinNamed(t, b, &Peer{conn: &fakeConn{}}, "probe")
	if err != nil {
		t.Fatal(err)
	}
	roster = waitRoster(t, conn, 2, roster.Revision)
	for _, entry := range roster.Participants {
		if entry.SessionID != live.Id && entry.SessionID != probe.Id {
			t.Fatal("unpresented ticket changed the live roster")
		}
	}
}

func TestNamedRosterWireAndRecipientEligibility(t *testing.T) {
	agentConn := &fakeConn{}
	b, agent := nameTestBroker(t, agentConn)
	conn := &fakeConn{}
	controller := &Peer{conn: conn}
	// The viewer uses register_agent to request a challenge, but it never
	// completes agent registration. It must remain eligible for names.
	server := &Server{reg: b.reg, broker: b, identity: &fakeResolver{}, now: time.Now}
	server.dispatch(controller, ClientToServer{Payload: &RegisterAgent{
		Device: "browser", Pubkey: "ed25519:browser-controller",
	}})
	if _, ok := findMsg[AgentAuthChallenge](conn.messages()); !ok {
		t.Fatal("viewer did not receive its registration challenge")
	}
	s, err := joinNamed(t, b, controller, "controller")
	if err != nil {
		t.Fatal(err)
	}

	messages := agentConn.messages()
	agentWire, err := json.Marshal(messages[len(messages)-1])
	if err != nil {
		t.Fatal(err)
	}
	// Pin the exact pre-Phase-1 agent wire, including object field order.
	wantAgent := fmt.Sprintf(`{"device_id":%q,"participants":[{"session_id":%q,"technician_id":%q,"access":"control"}],"type":"session_participants"}`,
		agent.DeviceId, s.Id, s.TechnicianID)
	if string(agentWire) != wantAgent {
		t.Fatalf("agent roster bytes changed: %s", agentWire)
	}

	roster := waitRoster(t, conn, 1, 0)
	controllerWire, err := json.Marshal(ServerToClient{Type: "session_participants", Payload: roster})
	if err != nil || !bytes.Contains(controllerWire, []byte(`"display_name":"Name for controller"`)) ||
		!bytes.Contains(controllerWire, []byte(`"revision":`)) {
		t.Fatal("controller wire missing name or revision")
	}

	otherConn := &fakeConn{}
	otherAgent := &Peer{DeviceId: "other-agent", Tenant: agent.Tenant, conn: otherConn}
	b.reg.Register(otherAgent)
	other, err := joinNamed(t, b, otherAgent, "agent requester")
	if err != nil {
		t.Fatal(err)
	}
	roster = waitRoster(t, otherConn, 2, 0)
	// The broker's map can emit either participant order.
	entry := func(s *Session) string {
		return fmt.Sprintf(`{"session_id":%q,"technician_id":%q,"access":"control"}`, s.Id, s.TechnicianID)
	}
	assertLegacy := func(snapshot SessionParticipants, participants ...string) {
		t.Helper()
		wire, err := json.Marshal(ServerToClient{Type: "session_participants", Payload: snapshot})
		want := func(entries []string) string {
			return fmt.Sprintf(`{"device_id":%q,"participants":[%s],"type":"session_participants"}`,
				agent.DeviceId, strings.Join(entries, ","))
		}
		if err != nil || (string(wire) != want(participants) &&
			(len(participants) != 2 || string(wire) != want([]string{participants[1], participants[0]}))) {
			t.Fatalf("agent requester roster bytes changed: %s (%v)", wire, err)
		}
	}
	assertLegacy(roster, entry(s), entry(other))
	b.reg.Remove(agent.DeviceId, agent.conn)
	assertLegacy(waitRoster(t, otherConn, 0, 0))
}

func TestFailedJoinIsNeverInControllerRoster(t *testing.T) {
	b, agent := nameTestBroker(t, &fakeConn{})
	conn := &fakeConn{}
	if _, err := joinNamed(t, b, &Peer{conn: conn}, "existing"); err != nil {
		t.Fatal(err)
	}
	failing := &nameRosterConn{onWrite: func(m ServerToClient) error {
		if m.Type == "brokered" {
			// Another roster push races the in-flight join.
			b.mu.Lock()
			b.reg.mu.RLock()
			updates := b.rosterUpdatesLocked(agent, nil)
			b.reg.mu.RUnlock()
			b.mu.Unlock()
			for _, update := range updates {
				if len(update.snapshot.Participants) != 1 {
					t.Error("controller snapshot included a join before both brokered sends completed")
				}
			}
			return errors.New("brokered write failed")
		}
		return nil
	}}
	if _, err := joinNamed(t, b, &Peer{conn: failing}, "failed"); err == nil {
		t.Fatal("expected the failed brokered send to abort the join")
	}
	for _, m := range conn.messages() {
		if roster, ok := m.Payload.(SessionParticipants); ok && len(roster.Participants) != 1 {
			t.Fatal("controller saw a session before both brokered sends completed")
		}
	}
}

func TestTargetReplacementPreventsNamePublication(t *testing.T) {
	b, agent := nameTestBroker(t, &fakeConn{})
	conn := &nameRosterConn{onWrite: func(m ServerToClient) error {
		if m.Type == "brokered" {
			b.reg.Register(&Peer{DeviceId: agent.DeviceId, Tenant: agent.Tenant, conn: &fakeConn{}})
		}
		return nil
	}}
	session, err := joinNamed(t, b, &Peer{conn: conn}, "replaced")
	if err != nil {
		t.Fatal(err)
	}
	if session.published || session.displayName != "" {
		t.Fatal("join published after its target was replaced")
	}
	if _, ok := findMsg[SessionParticipants](conn.messages()); ok {
		t.Fatal("requester received a roster from the replaced target")
	}
}

func TestControllerRosterRemovalRacesPush(t *testing.T) {
	b, _ := nameTestBroker(t, &fakeConn{})
	started := make(chan SessionParticipants, 1)
	resume := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer release()
	conn := &nameRosterConn{onWrite: func(m ServerToClient) error {
		if roster, ok := m.Payload.(SessionParticipants); ok && len(roster.Participants) == 2 {
			started <- roster
			<-resume
		}
		return nil
	}}
	remaining := &Peer{conn: conn}
	departing := &Peer{conn: &fakeConn{}}
	if _, err := joinNamed(t, b, remaining, "remaining"); err != nil {
		t.Fatal(err)
	}
	if _, err := joinNamed(t, b, departing, "departing"); err != nil {
		t.Fatal(err)
	}

	var stale SessionParticipants
	select {
	case stale = <-started:
	case <-time.After(time.Second):
		t.Fatal("roster write did not start")
	}
	runWhileRosterStalled(t, "remove peer sessions", func() {
		b.RemovePeerSessions(departing)
	})
	release()
	final := waitRoster(t, &conn.fakeConn, 1, stale.Revision)
	if final.Participants[0].DisplayName != "Name for remaining" {
		t.Fatal("final roster included the departing session")
	}
}

func TestSessionEndRemovesOnlyTheMatchingTargetMembership(t *testing.T) {
	b, agent := nameTestBroker(t, &fakeConn{})
	conn, endedConn := &fakeConn{}, &fakeConn{}
	if _, err := joinNamed(t, b, &Peer{conn: conn}, "remaining"); err != nil {
		t.Fatal(err)
	}
	ended, err := joinNamed(t, b, &Peer{conn: endedConn}, "ended")
	if err != nil {
		t.Fatal(err)
	}
	before := waitRoster(t, conn, 2, 0)
	endedBefore := waitRoster(t, endedConn, 2, 0)
	b.endTargetSession(&Peer{DeviceId: agent.DeviceId}, ended.controlPlaneID)
	b.mu.Lock()
	stillLive := b.sessions[ended.Id] == ended
	b.mu.Unlock()
	if !stillLive {
		t.Fatal("another connection ended the target's session")
	}
	// The registration is still present when session_ended arrives.
	b.reg.mu.Lock()
	agent.LastSeen = b.reg.now().Add(-2 * b.reg.ttl)
	b.reg.mu.Unlock()
	b.endTargetSession(agent, ended.controlPlaneID)
	roster := waitRoster(t, conn, 1, before.Revision)
	if roster.Participants[0].DisplayName != "Name for remaining" {
		t.Fatal("session end did not remove exactly the ended membership")
	}
	if empty := waitRoster(t, endedConn, 0, endedBefore.Revision); empty.Participants == nil || endedConn.closed {
		t.Fatal("ended controller did not receive an empty roster on its open connection")
	}
}

func TestSessionEndKeepsOtherMembershipOnSameController(t *testing.T) {
	b, agent := nameTestBroker(t, &fakeConn{})
	conn := &fakeConn{}
	peer := &Peer{conn: conn}
	ended, err := joinNamed(t, b, peer, "ended")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := joinNamed(t, b, peer, "remaining"); err != nil {
		t.Fatal(err)
	}
	before := waitRoster(t, conn, 2, 0)
	b.endTargetSession(agent, ended.controlPlaneID)
	final := waitRoster(t, conn, 1, before.Revision)
	if final.Participants[0].DisplayName != "Name for remaining" {
		t.Fatal("controller lost its other live membership")
	}
}

func TestDelayedTargetGoneKeepsRequesterOnReplacement(t *testing.T) {
	b, agent := nameTestBroker(t, &fakeConn{})
	conn := &fakeConn{}
	peer := &Peer{conn: conn}
	defer peer.stopRoster()
	if _, err := joinNamed(t, b, peer, "old"); err != nil {
		t.Fatal(err)
	}
	before := waitRoster(t, conn, 1, 0)

	var removed *Peer
	b.reg.targetGone = func(p *Peer) { removed = p }
	b.reg.Register(&Peer{DeviceId: agent.DeviceId, Tenant: agent.Tenant, conn: &fakeConn{}})
	replacement, err := joinNamed(t, b, peer, "replacement")
	if err != nil {
		t.Fatal(err)
	}
	current := waitRoster(t, conn, 1, before.Revision)
	if removed != agent {
		t.Fatal("superseded target was not reported")
	}
	b.targetGone(removed)
	final := waitRoster(t, conn, 1, current.Revision)
	if final.Participants[0].SessionID != replacement.Id {
		t.Fatal("delayed removal overwrote the replacement roster")
	}
}

func TestTargetTeardownClearsOpenControllerRosters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tearDown func(*Broker, *Peer)
	}{
		{"disconnect", func(b *Broker, agent *Peer) { b.RemovePeerSessions(agent) }},
		{"remove registration", func(b *Broker, agent *Peer) { b.reg.Remove(agent.DeviceId, agent.conn) }},
		{"supersede", func(b *Broker, agent *Peer) {
			b.reg.Register(&Peer{DeviceId: agent.DeviceId, conn: &fakeConn{}})
		}},
		{"retire", func(b *Broker, agent *Peer) {
			b.reg.RegisterRestricted(&Peer{DeviceId: agent.DeviceId, conn: &fakeConn{}})
		}},
		{"revalidate revoke", func(b *Broker, agent *Peer) {
			s := &Server{reg: b.reg, broker: b}
			s.revalidateAgent(context.Background(), agent.DeviceId, time.Second,
				func(context.Context, string) (*DeviceIdentity, error) { return nil, ErrDeviceUnknown })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, agent := nameTestBroker(t, &fakeConn{})
			conns := []*fakeConn{{}, {}}
			for i, conn := range conns {
				if _, err := joinNamed(t, b, &Peer{conn: conn}, fmt.Sprintf("controller %d", i)); err != nil {
					t.Fatal(err)
				}
			}
			before := make([]SessionParticipants, len(conns))
			for i, conn := range conns {
				before[i] = waitRoster(t, conn, 2, 0)
			}
			tc.tearDown(b, agent)
			for i, conn := range conns {
				last := waitRoster(t, conn, 0, before[i].Revision)
				if conn.closed || last.DeviceID != agent.DeviceId || last.Participants == nil {
					t.Fatal("open controller did not receive a newer, empty roster after target teardown")
				}
			}
		})
	}
}

func TestNamedRosterWriteFailureDoesNotLogPayload(t *testing.T) {
	out := &rosterLogBuffer{}
	previous := log.Writer()
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(previous) })

	b, _ := nameTestBroker(t, &fakeConn{})
	conn := &nameRosterConn{onWrite: func(m ServerToClient) error {
		if m.Type == "session_participants" {
			return fmt.Errorf("write failed with payload: %+v", m.Payload)
		}
		return nil
	}}
	if _, err := joinNamed(t, b, &Peer{conn: conn}, "log marker"); err != nil {
		t.Fatal(err)
	}
	diagnostic := "session_participants: failed to notify requester"
	deadline := time.Now().Add(time.Second)
	output := out.String()
	for !strings.Contains(output, diagnostic) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		output = out.String()
	}
	if !strings.Contains(output, diagnostic) || strings.Contains(output, "Name for log marker") ||
		strings.Contains(output, "display_name") {
		t.Fatal("roster failure log is missing or contains roster data")
	}
}

type rosterLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *rosterLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *rosterLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
