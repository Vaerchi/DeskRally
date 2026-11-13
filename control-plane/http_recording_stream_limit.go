package controlplane

// Concurrency caps for recording content streams (security review 2026-11-01 #5).
//
// A recording stream or evidence download is a LONG response: the per-write deadline is refreshed on
// every chunk, so a client that drains just enough bytes keeps one for hours. Nothing bounded how
// many such streams one user or tenant could hold open, so a single low-privilege viewer with a
// playable recording could pile up dozens of slow reads and tie up the server's goroutines, file
// handles and (before the connection is released, see releaseBoundConn) its pooled database
// connections. Each stream/download now takes a slot, per tenant and per user, for its whole
// duration; beyond the cap the request is refused with 429 + Retry-After. HEAD requests release no
// content and take no slot.

import (
	"net/http"
	"sync"
)

const (
	// recStreamsPerTenantDefault / recStreamsPerUserDefault apply when the wiring leaves the
	// override at zero.
	recStreamsPerTenantDefault = 4
	recStreamsPerUserDefault   = 2
)

type recStreamLimiter struct {
	mu     sync.Mutex
	tenant map[string]int
	user   map[string]int
}

// acquire takes one slot for (tenant, user) or reports false when either cap is reached. The
// returned release is idempotent-safe to call exactly once.
func (l *recStreamLimiter) acquire(tenantID, userID string, perTenant, perUser int) (func(), bool) {
	if perTenant <= 0 {
		perTenant = recStreamsPerTenantDefault
	}
	if perUser <= 0 {
		perUser = recStreamsPerUserDefault
	}
	uk := tenantID + "|" + userID
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tenant == nil {
		l.tenant = map[string]int{}
		l.user = map[string]int{}
	}
	if l.tenant[tenantID] >= perTenant || l.user[uk] >= perUser {
		return nil, false
	}
	l.tenant[tenantID]++
	l.user[uk]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if l.tenant[tenantID]--; l.tenant[tenantID] <= 0 {
				delete(l.tenant, tenantID)
			}
			if l.user[uk]--; l.user[uk] <= 0 {
				delete(l.user, uk)
			}
		})
	}, true
}

// recAcquireStream takes a stream slot for a content-releasing request (not HEAD). It writes the 429
// itself and returns ok=false when the caller is over a cap; otherwise the caller must defer the
// returned release.
func (s *Server) recAcquireStream(w http.ResponseWriter, r *http.Request, p *Principal) (func(), bool) {
	if r.Method == http.MethodHead {
		return func() {}, true
	}
	wiring := &s.Recording
	release, ok := wiring.streams.acquire(p.TenantID, p.UserID, wiring.StreamsPerTenant, wiring.StreamsPerUser)
	if !ok {
		w.Header().Set("Retry-After", "5")
		recErr(w, http.StatusTooManyRequests, "too_many_streams", nil)
		return nil, false
	}
	return release, true
}

// auditExportPerTenant caps concurrent management/backstage audit exports and archives per tenant
// (and per user): each one streams a large body, so a slow reader must not be able to pile them up.
const auditExportPerTenant = 2

// acquireAuditStream takes an export slot for the caller or writes a 429 and reports false.
func (s *Server) acquireAuditStream(w http.ResponseWriter, p *Principal) (func(), bool) {
	release, ok := s.auditStreams.acquire(p.TenantID, p.UserID, auditExportPerTenant, auditExportPerTenant)
	if !ok {
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusTooManyRequests, "too many audit exports in progress; retry shortly")
		return nil, false
	}
	return release, true
}
