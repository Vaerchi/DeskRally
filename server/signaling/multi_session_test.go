package main

// Multi-session signaling tests (Tech-Many + Multi-Tech).
//
// Covers:
//  - Two independent controllers can each hold a session targeting the same agent.
//  - SessionParticipants is delivered to both controllers and the agent on join/leave.
//  - Disconnecting one controller sends an updated SessionParticipants to the remaining one.
//  - Old agent (no multi_session_capable field) still registers successfully.
//  - multi_session_capable propagates through the presence snapshot.
//  - SessionParticipants is NOT sent for unrelated devices.

import (
	"testing"
	"time"
)

func boolPtr(b bool) *bool { return &b }

// newBrokerNoTicket builds a broker without ticket enforcement (dev mode) for unit tests.
func newBrokerNoTicket(reg *Registry) *Broker {
	return NewBroker(reg, "ed25519:server", "relay-1:4444", nil)
}

// TestConcurrentSessionsTwoControllersSameAgent verifies that two controllers can each hold
// independent sessions with the same agent. This is the fundamental multi-tech precondition:
// the signaling broker must not reject or evict the first session when the second arrives.
func TestConcurrentSessionsTwoControllersSameAgent(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := newBrokerNoTicket(reg)

	agentConn := &fakeConn{}
	agent := mkPeer("agent-1", "ed25519:agent", NatFullCone, agentConn)
	agent.MultiSessionCapable = boolPtr(true) // multi-session agent: must allow concurrent sessions
	reg.Register(agent)

	ctrl1Conn := &fakeConn{}
	ctrl1 := &Peer{DeviceId: "ctrl-1", Pubkey: "ed25519:ctrl1", conn: ctrl1Conn}

	ctrl2Conn := &fakeConn{}
	ctrl2 := &Peer{DeviceId: "ctrl-2", Pubkey: "ed25519:ctrl2", conn: ctrl2Conn}

	sess1, err := broker.ConnectRequest(ctrl1, "agent-1", nil)
	if err != nil {
		t.Fatalf("first ConnectRequest: %v", err)
	}
	sess2, err := broker.ConnectRequest(ctrl2, "agent-1", nil)
	if err != nil {
		t.Fatalf("second ConnectRequest: %v", err)
	}

	if sess1.Id == sess2.Id {
		t.Fatalf("two sessions for the same agent must have distinct ids, got %q for both", sess1.Id)
	}

	// Both sessions must be in the broker's session table.
	broker.mu.Lock()
	_, has1 := broker.sessions[sess1.Id]
	_, has2 := broker.sessions[sess2.Id]
	broker.mu.Unlock()
	if !has1 {
		t.Errorf("session 1 (%q) missing from broker sessions", sess1.Id)
	}
	if !has2 {
		t.Errorf("session 2 (%q) missing from broker sessions", sess2.Id)
	}

	// Both sessions must be tracked under the agent's device.
	broker.mu.Lock()
	deviceSet := broker.deviceSessions["agent-1"]
	broker.mu.Unlock()
	if len(deviceSet) != 2 {
		t.Errorf("deviceSessions[agent-1] has %d entries, want 2", len(deviceSet))
	}

	// Each controller must have received brokered + relay_assignment.
	for name, conn := range map[string]*fakeConn{"ctrl1": ctrl1Conn, "ctrl2": ctrl2Conn} {
		msgs := conn.messages()
		if _, ok := findMsg[Brokered](msgs); !ok {
			t.Errorf("%s did not receive brokered", name)
		}
		if _, ok := findMsg[RelayAssignment](msgs); !ok {
			t.Errorf("%s did not receive relay_assignment", name)
		}
	}
}

// TestSessionParticipantsSentOnJoin verifies that SessionParticipants is sent to the agent and
// the first controller when a second controller joins.
func TestSessionParticipantsSentOnJoin(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := newBrokerNoTicket(reg)

	agentConn := &fakeConn{}
	agent := mkPeer("agent-1", "ed25519:agent", NatFullCone, agentConn)
	agent.MultiSessionCapable = boolPtr(true) // multi-session agent: admits both controllers
	reg.Register(agent)

	ctrl1Conn := &fakeConn{}
	ctrl1 := &Peer{DeviceId: "ctrl-1", Pubkey: "ed25519:ctrl1", conn: ctrl1Conn}

	ctrl2Conn := &fakeConn{}
	ctrl2 := &Peer{DeviceId: "ctrl-2", Pubkey: "ed25519:ctrl2", conn: ctrl2Conn}

	// First connect: all parties get a SessionParticipants with 1 participant.
	if _, err := broker.ConnectRequest(ctrl1, "agent-1", nil); err != nil {
		t.Fatalf("first ConnectRequest: %v", err)
	}
	sp1Agent, ok1 := findMsg[SessionParticipants](agentConn.messages())
	if !ok1 {
		t.Fatal("agent did not receive SessionParticipants after first connect")
	}
	if len(sp1Agent.Participants) != 1 {
		t.Fatalf("agent SessionParticipants after first connect: got %d participants, want 1", len(sp1Agent.Participants))
	}
	if sp1Agent.DeviceID != "agent-1" {
		t.Errorf("SessionParticipants.DeviceID = %q, want %q", sp1Agent.DeviceID, "agent-1")
	}

	// Second connect: agent and ctrl1 should each receive an updated SessionParticipants.
	if _, err := broker.ConnectRequest(ctrl2, "agent-1", nil); err != nil {
		t.Fatalf("second ConnectRequest: %v", err)
	}

	// Agent should now have received TWO SessionParticipants (one per connect).
	allAgentMsgs := agentConn.messages()
	var spMsgs []SessionParticipants
	for _, m := range allAgentMsgs {
		if p, ok := m.Payload.(SessionParticipants); ok {
			spMsgs = append(spMsgs, p)
		}
		if p, ok := m.Payload.(*SessionParticipants); ok {
			spMsgs = append(spMsgs, *p)
		}
	}
	if len(spMsgs) < 2 {
		t.Fatalf("agent received %d SessionParticipants, want at least 2 (one per connect)", len(spMsgs))
	}
	lastAgentSP := spMsgs[len(spMsgs)-1]
	if len(lastAgentSP.Participants) != 2 {
		t.Fatalf("agent final SessionParticipants: got %d participants, want 2", len(lastAgentSP.Participants))
	}

	// ctrl1 must also have been notified of ctrl2 joining.
	ctrl1Msgs := ctrl1Conn.messages()
	var ctrl1SPs []SessionParticipants
	for _, m := range ctrl1Msgs {
		if p, ok := m.Payload.(SessionParticipants); ok {
			ctrl1SPs = append(ctrl1SPs, p)
		}
		if p, ok := m.Payload.(*SessionParticipants); ok {
			ctrl1SPs = append(ctrl1SPs, *p)
		}
	}
	if len(ctrl1SPs) < 2 {
		t.Fatalf("ctrl1 received %d SessionParticipants, want at least 2", len(ctrl1SPs))
	}
	lastCtrl1SP := ctrl1SPs[len(ctrl1SPs)-1]
	if len(lastCtrl1SP.Participants) != 2 {
		t.Fatalf("ctrl1 final SessionParticipants: got %d participants, want 2", len(lastCtrl1SP.Participants))
	}
}

// TestSessionParticipantsUpdatedOnDisconnect verifies that when one controller disconnects,
// the remaining controller and the agent receive an updated SessionParticipants.
func TestSessionParticipantsUpdatedOnDisconnect(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := newBrokerNoTicket(reg)

	agentConn := &fakeConn{}
	agent := mkPeer("agent-1", "ed25519:agent", NatFullCone, agentConn)
	agent.MultiSessionCapable = boolPtr(true) // multi-session agent: admits both controllers
	reg.Register(agent)

	ctrl1Conn := &fakeConn{}
	ctrl1 := &Peer{DeviceId: "ctrl-1", Pubkey: "ed25519:ctrl1", conn: ctrl1Conn}

	ctrl2Conn := &fakeConn{}
	ctrl2 := &Peer{DeviceId: "ctrl-2", Pubkey: "ed25519:ctrl2", conn: ctrl2Conn}

	if _, err := broker.ConnectRequest(ctrl1, "agent-1", nil); err != nil {
		t.Fatalf("first ConnectRequest: %v", err)
	}
	if _, err := broker.ConnectRequest(ctrl2, "agent-1", nil); err != nil {
		t.Fatalf("second ConnectRequest: %v", err)
	}

	// ctrl1 disconnects. The broker removes ctrl1's sessions.
	broker.RemovePeerSessions(ctrl1)

	// Agent should have received a new SessionParticipants with 1 participant.
	allAgentMsgs := agentConn.messages()
	var spMsgs []SessionParticipants
	for _, m := range allAgentMsgs {
		if p, ok := m.Payload.(SessionParticipants); ok {
			spMsgs = append(spMsgs, p)
		}
		if p, ok := m.Payload.(*SessionParticipants); ok {
			spMsgs = append(spMsgs, *p)
		}
	}
	if len(spMsgs) == 0 {
		t.Fatal("agent received no SessionParticipants messages at all")
	}
	lastSP := spMsgs[len(spMsgs)-1]
	if len(lastSP.Participants) != 1 {
		t.Fatalf("agent final SessionParticipants after ctrl1 disconnect: got %d participants, want 1", len(lastSP.Participants))
	}

	// ctrl2 should also have been notified that ctrl1 left.
	ctrl2Msgs := ctrl2Conn.messages()
	var ctrl2SPs []SessionParticipants
	for _, m := range ctrl2Msgs {
		if p, ok := m.Payload.(SessionParticipants); ok {
			ctrl2SPs = append(ctrl2SPs, p)
		}
		if p, ok := m.Payload.(*SessionParticipants); ok {
			ctrl2SPs = append(ctrl2SPs, *p)
		}
	}
	if len(ctrl2SPs) == 0 {
		t.Fatal("ctrl2 received no SessionParticipants messages")
	}
	lastCtrl2SP := ctrl2SPs[len(ctrl2SPs)-1]
	if len(lastCtrl2SP.Participants) != 1 {
		t.Fatalf("ctrl2 final SessionParticipants after ctrl1 disconnect: got %d, want 1", len(lastCtrl2SP.Participants))
	}

	// Broker's deviceSessions must now have only 1 entry for agent-1.
	broker.mu.Lock()
	deviceSet := broker.deviceSessions["agent-1"]
	broker.mu.Unlock()
	if len(deviceSet) != 1 {
		t.Errorf("deviceSessions[agent-1] has %d entries after ctrl1 disconnect, want 1", len(deviceSet))
	}
}

// TestSessionParticipantsNotSentForUnrelatedDevice verifies isolation: ctrl2 targeting a
// DIFFERENT device must not appear in agent-1's SessionParticipants.
func TestSessionParticipantsNotSentForUnrelatedDevice(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := newBrokerNoTicket(reg)

	agentConn1 := &fakeConn{}
	reg.Register(mkPeer("agent-1", "ed25519:a1", NatFullCone, agentConn1))

	agentConn2 := &fakeConn{}
	reg.Register(mkPeer("agent-2", "ed25519:a2", NatFullCone, agentConn2))

	ctrl1Conn := &fakeConn{}
	ctrl1 := &Peer{DeviceId: "ctrl-1", Pubkey: "ed25519:ctrl1", conn: ctrl1Conn}

	ctrl2Conn := &fakeConn{}
	ctrl2 := &Peer{DeviceId: "ctrl-2", Pubkey: "ed25519:ctrl2", conn: ctrl2Conn}

	if _, err := broker.ConnectRequest(ctrl1, "agent-1", nil); err != nil {
		t.Fatalf("ConnectRequest agent-1: %v", err)
	}
	if _, err := broker.ConnectRequest(ctrl2, "agent-2", nil); err != nil {
		t.Fatalf("ConnectRequest agent-2: %v", err)
	}

	// agent-1's SessionParticipants must have exactly 1 participant (ctrl1 only).
	sp, ok := findMsg[SessionParticipants](agentConn1.messages())
	if !ok {
		t.Fatal("agent-1 did not receive SessionParticipants")
	}
	if len(sp.Participants) != 1 {
		t.Fatalf("agent-1 SessionParticipants: got %d participants, want 1", len(sp.Participants))
	}
	if sp.DeviceID != "agent-1" {
		t.Errorf("agent-1 SessionParticipants.DeviceID = %q, want agent-1", sp.DeviceID)
	}
}

// TestMultiSessionCapableBackcompat verifies that an agent that does NOT send multi_session_capable
// still registers successfully and its presence entry has nil for the field.
func TestMultiSessionCapableBackcompat(t *testing.T) {
	reg := NewRegistry(time.Minute)
	// Old agent: no multi_session_capable field (nil).
	old := mkPeer("old-agent", "ed25519:old", NatOpen, nil)
	old.MultiSessionCapable = nil // explicit nil — "not sent"
	reg.Register(old)

	p, ok := reg.Lookup("old-agent")
	if !ok {
		t.Fatal("old agent not in registry")
	}
	if p.MultiSessionCapable != nil {
		t.Errorf("MultiSessionCapable = %v, want nil for old agent", *p.MultiSessionCapable)
	}
}

// TestMultiSessionCapablePropagatesThroughPresence verifies that an agent announcing
// multi_session_capable=true appears as such in the presence snapshot.
func TestMultiSessionCapablePropagatesThroughPresence(t *testing.T) {
	reg := NewRegistry(time.Minute)

	p := mkPeer("new-agent", "ed25519:new", NatOpen, nil)
	p.MultiSessionCapable = boolPtr(true)
	reg.Register(p)

	snapshot := reg.Snapshot()
	var found *PresenceEntry
	for i := range snapshot {
		if snapshot[i].DeviceID == "new-agent" {
			found = &snapshot[i]
			break
		}
	}
	if found == nil {
		t.Fatal("new-agent not in presence snapshot")
	}
	if found.MultiSessionCapable == nil {
		t.Fatal("MultiSessionCapable is nil in presence entry, want *true")
	}
	if !*found.MultiSessionCapable {
		t.Errorf("MultiSessionCapable = false in presence entry, want true")
	}
}

// TestMultiSessionCapableFalseIsDistinctFromNil verifies that an agent explicitly sending
// false is distinguishable from one that sent nothing (backward compat rule).
func TestMultiSessionCapableFalseIsDistinctFromNil(t *testing.T) {
	reg := NewRegistry(time.Minute)

	pFalse := mkPeer("agent-false", "ed25519:f", NatOpen, nil)
	pFalse.MultiSessionCapable = boolPtr(false)
	reg.Register(pFalse)

	pNil := mkPeer("agent-nil", "ed25519:n", NatOpen, nil)
	pNil.MultiSessionCapable = nil
	reg.Register(pNil)

	snapshot := reg.Snapshot()
	counts := map[string]*bool{}
	for _, e := range snapshot {
		counts[e.DeviceID] = e.MultiSessionCapable
	}

	if counts["agent-false"] == nil {
		t.Error("agent-false presence entry: MultiSessionCapable should be *false, got nil")
	} else if *counts["agent-false"] {
		t.Error("agent-false presence entry: MultiSessionCapable should be *false, got *true")
	}

	if counts["agent-nil"] != nil {
		t.Errorf("agent-nil presence entry: MultiSessionCapable should be nil, got %v", *counts["agent-nil"])
	}
}

// TestSessionParticipantsMessageType verifies the wire tag for SessionParticipants.
func TestSessionParticipantsMessageType(t *testing.T) {
	sp := SessionParticipants{
		DeviceID:     "dev-1",
		Participants: []SessionParticipantEntry{{SessionID: "sess-1"}},
	}
	tag, ok := serverTag(sp)
	if !ok {
		t.Fatal("serverTag did not recognize SessionParticipants")
	}
	if tag != "session_participants" {
		t.Errorf("serverTag(SessionParticipants) = %q, want session_participants", tag)
	}

	// Pointer form.
	tag2, ok2 := serverTag(&sp)
	if !ok2 || tag2 != "session_participants" {
		t.Errorf("serverTag(*SessionParticipants) = %q, %v", tag2, ok2)
	}
}
