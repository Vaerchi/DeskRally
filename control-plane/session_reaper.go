package controlplane

// Background session reaper (docs/01 §5 seat metering follow-up).
//
// The lazy reaper (handleStartSession) ends expired session_record rows at session-start time so they
// do not pin seats against the concurrency cap. That is correct but leaves zombie rows sitting in the
// table between starts: a tenant that never starts a new session accumulates open rows indefinitely,
// and a tenant with a concurrency cap that crashes during a session cannot start a new one until it
// either starts another session (triggering the lazy reap) or an operator ends the stale rows by hand.
//
// The background reaper calls RunReaperSweep on a ticker, proactively closing expired rows for every
// tenant with a configured max_session_seconds. It is best-effort: a sweep failure is logged and
// skipped, not propagated. The lazy per-start reap is the reliable safety net; this is the proactive
// layer that keeps the table clean between starts.

import (
	"context"
	"log"
	"time"
)

// RunReaperSweep performs one pass of the background session reaper: it lists all tenants with a
// configured MaxSessionSeconds and reaps expired sessions for each. Calls are idempotent and safe
// to make concurrently. Returns immediately when SessionRecords or SessionPolicies is nil (e.g. DEV
// mode without the relevant stores wired).
//
// Exposed for testing so tests can trigger a sweep without waiting for the ticker.
func (s *Server) RunReaperSweep(ctx context.Context) {
	// Central-recording retention + orphan quarantine (docs/63) rides the same tick but is independent
	// of the session stores below, so it runs however this function returns.
	defer s.runRecordingSweep(ctx)
	if s.SessionRecords == nil || s.SessionPolicies == nil {
		return
	}
	tenants, err := s.SessionPolicies.ListTenantsWithMaxAge(ctx)
	if err != nil {
		log.Printf("background reap: list tenants: %v", err)
		return
	}
	for _, t := range tenants {
		reaped, err := s.SessionRecords.ReapExpiredSessions(ctx, t.TenantID, t.MaxAge)
		if err != nil {
			log.Printf("background reap: tenant %s: %v", t.TenantID, err)
			continue
		}
		if reaped > 0 {
			log.Printf("background reap: tenant %s: reaped %d expired session(s)", t.TenantID, reaped)
		}
		// Session-transfer cleanup (docs/51): stale offers are marked expired/failed. Correctness never
		// depends on this; the rules are enforced in DB time on every transition.
		if s.SessionTransfers != nil {
			if _, err := s.SessionTransfers.ExpireStale(ctx, t.TenantID); err != nil {
				log.Printf("background reap: tenant %s: expire transfers: %v", t.TenantID, err)
			}
		}
	}
}

// StartBackgroundReaper starts a goroutine that calls RunReaperSweep on the given interval. The
// goroutine exits when ctx is done. Returns immediately without blocking. A zero or negative
// interval is a no-op (the reaper is disabled).
func (s *Server) StartBackgroundReaper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.RunReaperSweep(ctx)
				s.RunHelpRequestSweep(ctx) // docs/64 H-C6: expire due help requests, prune old ones
			}
		}
	}()
}
