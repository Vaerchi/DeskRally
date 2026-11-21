package main

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func waitRoster(t *testing.T, conn *fakeConn, count int, after uint64) SessionParticipants {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	var last SessionParticipants
	for time.Now().Before(deadline) {
		messages := conn.messages()
		for i := len(messages) - 1; i >= 0; i-- {
			if snapshot, ok := messages[i].Payload.(SessionParticipants); ok {
				last = snapshot
				if len(last.Participants) == count && (after == 0 || last.Revision > after) {
					return last
				}
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("wanted roster with %d participants after revision %d; got %d at %d",
		count, after, len(last.Participants), last.Revision)
	return SessionParticipants{}
}

func runWhileRosterStalled(t *testing.T, operation string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s blocked on a controller roster write", operation)
	}
}

func TestRosterMailboxCoalescesAndRejectsOlderRevisions(t *testing.T) {
	started, resume := make(chan struct{}), make(chan struct{})
	held := true
	defer func() {
		if held {
			close(resume)
		}
	}()
	conn := &nameRosterConn{onWrite: func(m ServerToClient) error {
		if m.Payload.(SessionParticipants).Revision == 1 {
			close(started)
			<-resume
		}
		return nil
	}}
	peer := &Peer{conn: conn}
	defer peer.stopRoster()
	enqueue := func(revision uint64) {
		peer.enqueueRoster(SessionParticipants{
			Revision: revision, Participants: make([]SessionParticipantEntry, 0),
		})
	}
	enqueue(1)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first roster write did not start")
	}
	runWhileRosterStalled(t, "enqueue roster updates", func() {
		enqueue(2)
		enqueue(4)
		enqueue(3)
	})
	close(resume)
	held = false
	if last := waitRoster(t, &conn.fakeConn, 0, 3); last.Revision != 4 {
		t.Fatal("mailbox lost the latest snapshot")
	}
	enqueue(2)
	enqueue(5)
	waitRoster(t, &conn.fakeConn, 0, 4)
	var revisions []uint64
	for _, m := range conn.messages() {
		revisions = append(revisions, m.Payload.(SessionParticipants).Revision)
	}
	if !reflect.DeepEqual(revisions, []uint64{1, 4, 5}) {
		t.Fatalf("mailbox wrote revisions %v", revisions)
	}
}

func TestStalledControllerRosterDoesNotBlockSignaling(t *testing.T) {
	for _, operation := range []string{"register replacement", "revalidate", "connect", "wake"} {
		t.Run(operation, func(t *testing.T) {
			s, _ := wakeFixture(t)
			agent := wakeTestPeer(&fakeConn{})
			agent.MultiSessionCapable = boolPtr(true)
			wakeTestReady(agent)
			s.reg.Register(agent)
			started, resume := make(chan struct{}, 1), make(chan struct{})
			defer close(resume)
			conn := &nameRosterConn{onWrite: func(m ServerToClient) error {
				if m.Type == "session_participants" {
					select {
					case started <- struct{}{}:
					default:
					}
					<-resume
				}
				return nil
			}}
			peer := &Peer{conn: conn}
			defer peer.stopRoster()
			var joinErr error
			runWhileRosterStalled(t, "initial connect", func() {
				_, joinErr = s.broker.ConnectRequest(peer, agent.DeviceId, nil)
			})
			if joinErr != nil {
				t.Fatal(joinErr)
			}
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("controller roster write did not start")
			}
			body := wakeTestBody(t, agent, nil)
			runWhileRosterStalled(t, operation, func() {
				switch operation {
				case "register replacement":
					if s.reg.Register(&Peer{DeviceId: agent.DeviceId, conn: &fakeConn{}}) == nil {
						t.Error("replacement registration failed")
					}
				case "revalidate":
					dropped, failed := s.revalidateAgent(context.Background(), agent.DeviceId, time.Second,
						func(context.Context, string) (*DeviceIdentity, error) { return nil, ErrDeviceUnknown })
					if !dropped || failed {
						t.Error("revalidation did not drop the target")
					}
				case "connect":
					other := &Peer{conn: &fakeConn{}}
					defer other.stopRoster()
					if _, err := s.broker.ConnectRequest(other, agent.DeviceId, nil); err != nil {
						t.Error(err)
					}
				case "wake":
					if rec := wakeTestRequest(s, agent.DeviceId, true, body); rec.Code != http.StatusAccepted {
						t.Errorf("Wake delivery returned %d", rec.Code)
					}
				}
			})
		})
	}
}

func TestRosterMailboxKeepsInvalidationForEachDevice(t *testing.T) {
	started, resume := make(chan struct{}), make(chan struct{})
	defer func() {
		if resume != nil {
			close(resume)
		}
	}()
	release := resume
	conn := &nameRosterConn{onWrite: func(m ServerToClient) error {
		if m.Payload.(SessionParticipants).Revision == 1 {
			close(started)
			<-release
		}
		return nil
	}}
	peer := &Peer{conn: conn}
	defer peer.stopRoster()
	peer.enqueueRoster(SessionParticipants{
		DeviceID: "a", Revision: 1, Participants: []SessionParticipantEntry{{SessionID: "ended"}},
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first roster write did not start")
	}
	peer.enqueueRoster(SessionParticipants{DeviceID: "a", Revision: 2, Participants: []SessionParticipantEntry{}})
	peer.enqueueRoster(SessionParticipants{
		DeviceID: "b", Revision: 3, Participants: []SessionParticipantEntry{{SessionID: "joined"}},
	})
	close(resume)
	resume = nil

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		last := make(map[string]SessionParticipants)
		for _, m := range conn.messages() {
			snapshot := m.Payload.(SessionParticipants)
			last[snapshot.DeviceID] = snapshot
		}
		if last["a"].Revision == 2 && len(last["a"].Participants) == 0 &&
			last["b"].Revision == 3 && len(last["b"].Participants) == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("both devices did not receive their final roster")
}

func TestRosterPublishesAfterHeartbeatLapsesDuringJoin(t *testing.T) {
	b, agent := nameTestBroker(t, &fakeConn{})
	conn := &nameRosterConn{onWrite: func(m ServerToClient) error {
		if m.Type == "brokered" {
			b.reg.mu.Lock()
			agent.LastSeen = b.reg.now().Add(-2 * b.reg.ttl)
			b.reg.mu.Unlock()
		}
		return nil
	}}
	peer := &Peer{conn: conn}
	defer peer.stopRoster()
	session, err := joinNamed(t, b, peer, "lapsed")
	if err != nil {
		t.Fatal(err)
	}
	roster := waitRoster(t, &conn.fakeConn, 1, 0)
	if roster.Participants[0].SessionID != session.Id {
		t.Fatal("roster did not include the published join")
	}
}

type failedRosterConn struct {
	nameRosterConn
	closedSignal chan struct{}
	closes       atomic.Int32
}

func (c *failedRosterConn) Close() error {
	c.closes.Add(1)
	err := c.fakeConn.Close()
	select {
	case c.closedSignal <- struct{}{}:
	default:
	}
	return err
}

func TestRosterWriteFailureClosesConnectionForCleanup(t *testing.T) {
	b, _ := nameTestBroker(t, &fakeConn{})
	s := &Server{reg: b.reg, broker: b}
	conn := &failedRosterConn{closedSignal: make(chan struct{}, 1)}
	conn.onWrite = func(m ServerToClient) error {
		if m.Type == "session_participants" {
			return errors.New("roster write failed")
		}
		return nil
	}
	peer := &Peer{conn: conn}
	defer peer.stopRoster()
	session, err := joinNamed(t, b, peer, "failed-write")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.closedSignal:
	case <-time.After(time.Second):
		t.Fatal("failed roster write did not close the connection")
	}
	// The fake has no read loop. Run the cleanup that socket closure triggers.
	s.cleanup(peer)
	b.mu.Lock()
	_, stillLive := b.sessions[session.Id]
	b.mu.Unlock()
	if stillLive {
		t.Fatal("cleanup left the disconnected controller's session live")
	}
	if n := conn.closes.Load(); n != 1 {
		t.Fatalf("transport closed %d times, want exactly 1 (roster failure and cleanup share one close)", n)
	}
}
