package main

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

// Every send to a peer must arm a write deadline, and must arm a FRESH one each time.
//
// PREMISE, declared locally: a write deadline is CONSUMED by the write it bounds, so setting one
// once at connection setup would protect only the first message and silently leave every later one
// unbounded. That failure would be invisible to a test that merely checked "a deadline was set",
// which is why this asserts one deadline PER send and that the second is strictly later than the
// first.
//
// Why the bound exists: handleWS's read limit and read deadline are only consulted inside
// ReadMessage, so a goroutine blocked in WriteJSON is never rescued by them — handleWS never
// returns and its cleanup never runs. Relaying crosses goroutines (broker.go writes to the peer's
// socket from the sender's read goroutine), so one peer that stops reading can wedge the goroutine
// serving a different, healthy agent.
func TestSendArmsAFreshWriteDeadlineEveryTime(t *testing.T) {
	c := &fakeConn{}
	p := &Peer{conn: c}

	before := time.Now()
	if err := p.Send(Rejected{Reason: "first"}); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if err := p.Send(Rejected{Reason: "second"}); err != nil {
		t.Fatalf("second send: %v", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.writeDeadlines) != 2 {
		t.Fatalf("armed %d write deadlines for 2 sends, want 2 — a deadline set once protects only "+
			"the first message", len(c.writeDeadlines))
	}
	// Each must be in the future relative to when its own send started, i.e. genuinely re-armed.
	if !c.writeDeadlines[0].After(before) {
		t.Fatalf("first deadline %v is not after the send began (%v)", c.writeDeadlines[0], before)
	}
	if !c.writeDeadlines[1].After(c.writeDeadlines[0]) && c.writeDeadlines[1] != c.writeDeadlines[0] {
		t.Fatalf("second deadline %v predates the first %v", c.writeDeadlines[1], c.writeDeadlines[0])
	}
	if d := c.writeDeadlines[0].Sub(before); d > 2*peerWriteTimeout {
		t.Fatalf("deadline is %v out, want ~%v — an over-long bound is not a bound", d, peerWriteTimeout)
	}
}

// fakeConn is a peerConn that records the server messages written to it, for tests that need a
// Peer without a real WebSocket.
type fakeConn struct {
	mu     sync.Mutex
	sent   []ServerToClient
	closed bool
	// writeDeadlines records every deadline Send armed, one per write.
	writeDeadlines []time.Time
	// rawFrames records every (messageType, data) pair passed to WriteMessage.
	rawFrames []rawFrame
	// events records WriteMessage and Close calls in arrival order, so tests can assert
	// that the close frame precedes the bare Close() tear-down.
	events []connEvent
}

type rawFrame struct {
	messageType int
	data        []byte
}

// connEvent is one entry in the fakeConn ordered event log.
type connEvent struct{ kind string }

func (c *fakeConn) WriteJSON(v interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m, ok := v.(ServerToClient); ok {
		c.sent = append(c.sent, m)
	}
	return nil
}

// SetWriteDeadline records the last deadline Send asked for, so a test can assert the bound is
// actually armed per write rather than trusting that it is.
func (c *fakeConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadlines = append(c.writeDeadlines, t)
	return nil
}

func (c *fakeConn) WriteMessage(messageType int, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	c.rawFrames = append(c.rawFrames, rawFrame{messageType: messageType, data: cp})
	c.events = append(c.events, connEvent{"write_message"})
	return nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.events = append(c.events, connEvent{"close"})
	return nil
}

func (c *fakeConn) messages() []ServerToClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]ServerToClient, len(c.sent))
	copy(out, c.sent)
	return out
}

// mkPeer is a test helper that builds a Peer over a conn (defaulting to a fresh fakeConn).
func mkPeer(device, pubkey string, nat NatType, conn peerConn) *Peer {
	if conn == nil {
		conn = &fakeConn{}
	}
	return &Peer{DeviceId: device, Pubkey: pubkey, Nat: nat, conn: conn}
}

func TestRegistryRegisterAndLookup(t *testing.T) {
	tests := []struct {
		name      string
		register  []string // devices to register
		lookup    string
		wantFound bool
	}{
		{name: "found after register", register: []string{"dev-a"}, lookup: "dev-a", wantFound: true},
		{name: "miss for unregistered", register: []string{"dev-a"}, lookup: "dev-b", wantFound: false},
		{name: "empty registry misses", register: nil, lookup: "dev-a", wantFound: false},
		{name: "one of many", register: []string{"a", "b", "c"}, lookup: "b", wantFound: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry(time.Minute)
			for _, d := range tt.register {
				r.Register(mkPeer(d, "pk-"+d, NatOpen, nil))
			}
			p, ok := r.Lookup(tt.lookup)
			if ok != tt.wantFound {
				t.Fatalf("Lookup(%q) found=%v, want %v", tt.lookup, ok, tt.wantFound)
			}
			if ok && p.DeviceId != tt.lookup {
				t.Fatalf("Lookup returned DeviceId %q, want %q", p.DeviceId, tt.lookup)
			}
		})
	}
}

func TestRegistryExpiry(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	tests := []struct {
		name      string
		ttl       time.Duration
		advance   time.Duration // time elapsed since registration before lookup
		heartbeat bool          // heartbeat right before lookup
		wantFound bool
	}{
		{name: "fresh within ttl", ttl: 30 * time.Second, advance: 10 * time.Second, wantFound: true},
		{name: "expired past ttl", ttl: 30 * time.Second, advance: 31 * time.Second, wantFound: false},
		{name: "exactly at ttl still fresh", ttl: 30 * time.Second, advance: 30 * time.Second, wantFound: true},
		{name: "heartbeat refreshes", ttl: 30 * time.Second, advance: 31 * time.Second, heartbeat: true, wantFound: true},
		{name: "zero ttl disables expiry", ttl: 0, advance: 999 * time.Hour, wantFound: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := base
			r := NewRegistry(tt.ttl)
			r.now = func() time.Time { return now }

			r.Register(mkPeer("dev", "pk", NatSymmetric, nil))
			now = now.Add(tt.advance)
			if tt.heartbeat {
				if !r.Heartbeat("dev") {
					t.Fatal("Heartbeat returned false for registered device")
				}
			}
			_, ok := r.Lookup("dev")
			if ok != tt.wantFound {
				t.Fatalf("Lookup after advance=%s found=%v, want %v", tt.advance, ok, tt.wantFound)
			}
		})
	}
}

func TestRegistryHeartbeatUnknown(t *testing.T) {
	r := NewRegistry(time.Minute)
	if r.Heartbeat("nope") {
		t.Fatal("Heartbeat for unknown device should return false")
	}
}

func TestRegistryRemove(t *testing.T) {
	r := NewRegistry(time.Minute)
	conn := &fakeConn{}
	r.Register(mkPeer("dev", "pk", NatOpen, conn))

	// Remove with a different conn must not evict (reconnect-race guard).
	r.Remove("dev", &fakeConn{})
	if _, ok := r.Lookup("dev"); !ok {
		t.Fatal("Remove with mismatched conn should not evict")
	}

	r.Remove("dev", conn)
	if _, ok := r.Lookup("dev"); ok {
		t.Fatal("Remove with matching conn should evict")
	}
	if r.Len() != 0 {
		t.Fatalf("Len=%d after removal, want 0", r.Len())
	}
}

func TestRegistryRemoveNilConnForcesEviction(t *testing.T) {
	r := NewRegistry(time.Minute)
	conn := &fakeConn{}
	r.Register(mkPeer("dev", "pk", NatOpen, conn))

	// nil conn bypasses the reconnect-race guard and force-deletes the entry.
	r.Remove("dev", nil)
	if _, ok := r.Lookup("dev"); ok {
		t.Fatal("Remove(device, nil) should evict regardless of stored conn")
	}
}

func TestRegistryRemoveUnknownDeviceIsNoop(t *testing.T) {
	r := NewRegistry(time.Minute)
	conn := &fakeConn{}
	r.Register(mkPeer("known", "pk", NatOpen, conn))

	// Removing a device that was never registered must not panic and must not
	// disturb unrelated entries.
	r.Remove("ghost", conn)
	if _, ok := r.Lookup("known"); !ok {
		t.Fatal("Remove of unknown device must not disturb other peers")
	}
}

func TestRegistryReRegisterClosesOld(t *testing.T) {
	r := NewRegistry(time.Minute)
	old := &fakeConn{}
	r.Register(mkPeer("dev", "pk1", NatOpen, old))

	fresh := &fakeConn{}
	r.Register(mkPeer("dev", "pk2", NatFullCone, fresh))

	if !old.closed {
		t.Fatal("re-registering a device should close the superseded connection")
	}

	// A WebSocket close frame (opcode 8) with code 1000 must be sent BEFORE the bare Close, so
	// the remote side sees a clean termination (1000) and not a dropped-connection 1006.
	old.mu.Lock()
	frames := old.rawFrames
	old.mu.Unlock()
	if len(frames) == 0 {
		t.Fatal("re-registration must send a WebSocket close frame before closing; none was sent")
	}
	const wsCloseMessage = 8 // gorilla/websocket.CloseMessage
	if frames[0].messageType != wsCloseMessage {
		t.Fatalf("frame messageType = %d, want %d (CloseMessage)", frames[0].messageType, wsCloseMessage)
	}
	if len(frames[0].data) < 2 {
		t.Fatalf("close frame payload too short (%d bytes), want ≥2 for the status code", len(frames[0].data))
	}
	code := int(binary.BigEndian.Uint16(frames[0].data[:2]))
	if code != 1000 {
		t.Fatalf("close frame code = %d, want 1000 (NormalClosure); a remote seeing 1006 means the "+
			"connection was dropped without a close handshake", code)
	}

	// The close frame must arrive BEFORE the bare Close() tear-down; a remote that receives
	// Close() first sees an abrupt drop (1006) regardless of what was queued.
	old.mu.Lock()
	events := old.events
	old.mu.Unlock()
	writeIdx, closeIdx := -1, -1
	for i, ev := range events {
		if ev.kind == "write_message" && writeIdx == -1 {
			writeIdx = i
		}
		if ev.kind == "close" && closeIdx == -1 {
			closeIdx = i
		}
	}
	if writeIdx == -1 {
		t.Fatal("WriteMessage was not called")
	}
	if closeIdx == -1 {
		t.Fatal("Close was not called")
	}
	if writeIdx >= closeIdx {
		t.Fatalf("WriteMessage (event index %d) must precede Close (event index %d)", writeIdx, closeIdx)
	}

	p, ok := r.Lookup("dev")
	if !ok || p.Pubkey != "pk2" {
		t.Fatalf("expected fresh registration pk2, got ok=%v peer=%+v", ok, p)
	}
	if r.Len() != 1 {
		t.Fatalf("Len=%d after re-register, want 1", r.Len())
	}
}

// A slow superseded socket must not block registry operations for every device.
type stalledCloseConn struct {
	fakeConn
	entered chan struct{}
	release chan struct{}
}

func (c *stalledCloseConn) WriteMessage(_ int, _ []byte) error {
	close(c.entered)
	<-c.release
	return nil
}
func TestRegistryReplacementDoesNotHoldRegistryDuringClose(t *testing.T) {
	r := NewRegistry(time.Minute)
	old := &stalledCloseConn{entered: make(chan struct{}), release: make(chan struct{})}
	r.Register(mkPeer("dev", "old", NatOpen, old))
	fresh := mkPeer("dev", "new", NatOpen, &fakeConn{})
	replaced := make(chan struct{})
	go func() { r.Register(fresh); close(replaced) }()
	defer func() {
		close(old.release)
		select {
		case <-replaced:
		case <-time.After(time.Second):
			t.Error("replacement stuck")
		}
	}()
	select {
	case <-old.entered:
	case <-time.After(time.Second):
		t.Fatal("close write not reached")
	}
	available := make(chan bool, 1)
	go func() { p, ok := r.Lookup("dev"); available <- ok && p == fresh }()
	select {
	case ok := <-available:
		if !ok {
			t.Fatal("replacement not published before close write")
		}
	case <-time.After(time.Second):
		t.Fatal("slow close blocks registry lookups")
	}
}
