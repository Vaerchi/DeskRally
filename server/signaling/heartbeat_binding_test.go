package main

// A heartbeat refreshes the device THIS connection proved it owns — never one it merely names.
//
// PREMISE, declared locally: the registry's freshness window is not bookkeeping, it is an
// authorization input. Lookup treats a peer whose heartbeats lapsed as ABSENT, and the broker will
// not pair a session to an absent peer. So "keep this device looking alive" is a privileged act.
//
// The dispatcher already refused a heartbeat from an UNREGISTERED peer, with a comment naming the
// exact risk: "an unproven connection could keep a stale incumbent alive for a device it does not
// own". But it then passed the message's own `device` field to Registry.Heartbeat — so any peer that
// had completed its own registration could keep ANY other device's entry warm. The defence was
// built and then handed the attacker-controlled value, which reaches the same outcome the comment
// was written to prevent.
//
// Concretely: agent B goes offline. Attacker A (a legitimately enrolled agent in any tenant, holding
// only its own key) heartbeats B's device id, so B never expires out of the registry and stays a
// valid broker target after the real machine is gone.

import (
	"testing"
	"time"
)

func TestHeartbeatFromEvictedRegisteredDeviceRejected(t *testing.T) {
	// Branch 3 of the heartbeat dispatch (main.go:237-239): the peer completed registration
	// (registered=true, device matches) but its registry entry was evicted between registration
	// and the heartbeat. reg.Heartbeat returns false → Rejected must be sent.
	srv := authServer(t, nil) // dev/nil resolver; RegisterAgent succeeds immediately without challenge
	conn := &fakeConn{}
	peer := &Peer{conn: conn}

	// Establish registration through dispatch so that the peer's registered field and registry
	// entry are set by the same path production traffic takes.
	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: "evicted-device", Pubkey: "ed25519:rmt-agent", Tenant: "tenant-1", Nat: NatOpen,
	}})
	if _, ok := srv.reg.Lookup(peer.DeviceId); !ok {
		t.Fatal("premise not met: dispatch(RegisterAgent) did not add the registry entry")
	}
	if !peer.registered {
		t.Fatal("premise not met: dispatch(RegisterAgent) did not set peer.registered")
	}

	// Evict the entry while the peer struct still carries registered=true.
	srv.reg.Remove(peer.DeviceId, peer.conn)
	if _, ok := srv.reg.Lookup(peer.DeviceId); ok {
		t.Fatal("premise not met: Remove did not evict the entry")
	}

	// Dispatch a heartbeat. The peer IS registered (field = true) and the device matches
	// (branches 1 and 2 pass), but reg.Heartbeat returns false → branch 3 must Reject.
	srv.dispatch(peer, ClientToServer{Payload: &Heartbeat{Device: peer.DeviceId}})

	if reason := rejectionReason(t, conn); reason != "heartbeat for unregistered device" {
		t.Fatalf("reason %q, want %q", reason, "heartbeat for unregistered device")
	}
}

func TestHeartbeatCannotRefreshAnotherDevice(t *testing.T) {
	// A registry with a real TTL, and a clock we control, so "expired" is a fact we can produce
	// rather than something to sleep for.
	srv := authServer(t, goldenResolver())
	now := time.Now()
	srv.reg.now = func() time.Time { return now }

	// The victim: a registered, proven agent that then goes silent.
	victimConn := &fakeConn{}
	registerAndProve(t, srv, victimConn, agentAuthGoldenSeedHex)
	victim, ok := srv.reg.Lookup(agentAuthGoldenDevice)
	if !ok {
		t.Fatalf("premise not met: the victim did not register")
	}
	staleAt := victim.LastSeen

	// The attacker: a separate connection that completes its OWN registration, so it is a fully
	// legitimate peer and the `registered` gate cannot be what refuses it below.
	attacker := &Peer{conn: &fakeConn{}, DeviceId: "attacker-device", registered: true}

	// Time passes — enough that the victim's entry is now stale.
	now = now.Add(10 * time.Minute)

	// Negative control FIRST: the attacker CAN refresh its own entry (once it has one). Without this
	// leg, a dispatcher that rejected every heartbeat would satisfy the assertion below.
	srv.reg.Register(attacker)
	srv.dispatch(attacker, ClientToServer{Payload: &Heartbeat{Device: attacker.DeviceId}})
	if _, rejected := findMsg[Rejected](attacker.conn.(*fakeConn).messages()); rejected {
		t.Fatalf("premise not met: a peer's heartbeat for its OWN device was rejected")
	}

	// The measurement: heartbeat naming the VICTIM's device.
	attackerConn2 := &fakeConn{}
	attacker2 := &Peer{conn: attackerConn2, DeviceId: "attacker-device", registered: true}
	srv.dispatch(attacker2, ClientToServer{Payload: &Heartbeat{Device: agentAuthGoldenDevice}})

	if _, rejected := findMsg[Rejected](attackerConn2.messages()); !rejected {
		t.Fatal("SECURITY: a heartbeat naming another peer's device was accepted")
	}
	after, ok := srv.reg.Lookup(agentAuthGoldenDevice)
	if ok && after.LastSeen != staleAt {
		t.Fatalf("SECURITY: another peer's heartbeat refreshed the victim's LastSeen (%v -> %v)",
			staleAt, after.LastSeen)
	}
}
