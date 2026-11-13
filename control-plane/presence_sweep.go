package controlplane

// The background presence sweep (migrations/0079). GET /machines stamps machine.last_seen only when a
// console user of the machine's tenant happens to list machines, so a machine that was online all week
// while nobody looked was never recorded: "offline since" was wrong, and the Adoption card's "active in
// the last 30 days" undercounted. This sweep reads the same signaling feed on a timer and stamps every
// online device the control plane knows, in every tenant.
//
// It follows presence.go's rules: the feed is only ever used as "is THIS id online", nothing from it is
// returned to anyone, and a failure (signaling down, database error) is logged and retried next tick,
// never fatal. It writes only last_seen; the inventory refreshes (os, agent_version, the policy floor)
// stay on the console path, tenant-scoped under RLS.

import (
	"context"
	"errors"
	"log"
	"sort"
	"time"
)

// DefaultPresenceSweepInterval is how often the sweep runs. "Offline since" is accurate to about this,
// for machines nobody was looking at (a console listing still stamps the moment it sees one). Every
// online machine's row is rewritten once per interval, so this trades precision against row churn.
const DefaultPresenceSweepInterval = 2 * time.Minute

// presenceStampBatch is how many device ids go to the store per call; cp_presence_stamp refuses more
// than 100000, and smaller statements keep each row-lock window short.
const presenceStampBatch = 5000

// SweepPresenceOnce stamps last_seen for every device the presence feed reports online, and returns how
// many rows moved. No feed configured is not an error: there is simply nothing to record.
func (s *Server) SweepPresenceOnce(ctx context.Context) (int, error) {
	if s.Presence == nil || s.Machines == nil {
		return 0, nil
	}
	snapshot, err := s.Presence.FetchPresence(ctx)
	if err != nil {
		return 0, err
	}
	if snapshot == nil || len(snapshot.Online) == 0 {
		return 0, nil
	}
	ids := make([]string, 0, len(snapshot.Online))
	for id := range snapshot.Online {
		ids = append(ids, id)
	}
	// Map order is random; sorting makes the batches (and a test's view of them) deterministic.
	sort.Strings(ids)
	// The snapshot's clock, as on the console path: last_seen is when signaling observed the device.
	at := snapshot.AsOf
	if at.IsZero() {
		at = time.Now().UTC()
	}
	total := 0
	for start := 0; start < len(ids); start += presenceStampBatch {
		end := min(start+presenceStampBatch, len(ids))
		n, err := s.Machines.StampPresence(ctx, ids[start:end], at)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// RunPresenceSweeper sweeps every interval until ctx ends. An unavailable feed is logged once per
// outage rather than every tick, so a control plane without signaling does not fill its log.
func (s *Server) RunPresenceSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultPresenceSweepInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	feedDown := false
	for {
		_, err := s.SweepPresenceOnce(ctx)
		switch {
		case err == nil:
			if feedDown {
				log.Printf("presence sweep: feed available again")
			}
			feedDown = false
		case errors.Is(err, ErrPresenceUnavailable):
			if !feedDown {
				log.Printf("presence sweep: %v (last_seen is not recorded until it returns)", err)
			}
			feedDown = true
		default:
			log.Printf("presence sweep failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
