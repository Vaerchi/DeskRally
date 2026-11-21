package main

import (
	"log"
	"sync"
)

// rosterMailbox retains the newest pending snapshot and revision watermark
// per target device. Its mutex never covers a socket write.
type rosterMailbox struct {
	mu      sync.Mutex
	ready   chan struct{}
	pending map[string]SessionParticipants
	newest  map[string]uint64
}

func (p *Peer) enqueueRoster(snapshot SessionParticipants) {
	m := &p.roster
	m.mu.Lock()
	defer m.mu.Unlock()
	device := snapshot.DeviceID
	if p.wake.disconnected.Load() || snapshot.Revision <= m.newest[device] {
		return
	}
	if m.ready == nil {
		m.pending = make(map[string]SessionParticipants)
		m.newest = make(map[string]uint64)
		m.ready = make(chan struct{}, 1)
		go p.writeRosters(m.ready)
	}
	m.newest[device] = snapshot.Revision
	m.pending[device] = snapshot
	select {
	case m.ready <- struct{}{}:
	default:
	}
}

// closeTransport closes the connection's transport exactly once, whoever gets there first
// (a failed roster write or the read loop's cleanup).
func (p *Peer) closeTransport() {
	p.transportClose.Do(func() {
		if p.conn != nil {
			_ = p.conn.Close()
		}
	})
}

func (p *Peer) stopRoster() {
	p.wake.disconnected.Store(true)
	m := &p.roster
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending = nil
	m.newest = nil
	if m.ready != nil {
		select {
		case m.ready <- struct{}{}:
		default:
		}
	}
}

func (p *Peer) writeRosters(ready <-chan struct{}) {
	m := &p.roster
	for range ready {
		for {
			m.mu.Lock()
			var snapshot SessionParticipants
			for device, pending := range m.pending {
				snapshot = pending
				delete(m.pending, device)
				break
			}
			m.mu.Unlock()
			if p.wake.disconnected.Load() {
				return
			}
			if snapshot.Revision == 0 {
				break
			}
			if err := p.Send(snapshot); err != nil {
				log.Print("session_participants: failed to notify requester")
				p.stopRoster()
				// The write already failed, so no close frame: close the transport once and let the
				// read loop run the normal cleanup (which shares the same one-shot close).
				p.closeTransport()
				return
			}
		}
	}
}
