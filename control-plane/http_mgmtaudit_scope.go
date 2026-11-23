package controlplane

// GROUP SCOPE for the MANAGEMENT audit trail (security review 2026-11-01 #4).
//
// The backstage trail has always been narrowed to the caller's CapViewAudit scope; the management
// trail was not, so an Auditor scoped to one customer's group could read session.*, machine.* and
// command.run_requested rows (with up to 2 KiB of command preview) for machines they have no
// authority over. POLICY, decided by the coordinator:
//
//   - A tenant-wide holder (scope.All) is unchanged on every route.
//   - A SCOPED holder of GET /audit and GET /audit/summary sees only events attributable to a
//     machine or machine group inside their current scope (see auditEventGroup). Events that name
//     neither (tenant-level user / role / settings / auth events) are HIDDEN from them, and so is
//     any event whose machine no longer resolves: fail closed.
//   - The hash-chain routes (GET /audit/export, /audit/verify, /audit/archive) exist for chain
//     verification, which only means something over the whole tenant chain, so they are
//     TENANT-WIDE ONLY: a scoped holder gets 403.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
)

// errAuditTenantWide is the 403 a scoped holder gets from the chain routes.
var errAuditTenantWide = errors.New("this audit view requires tenant-wide audit access")

// These are variables so tests can shrink them; production never changes them.
var (
	// scopedAuditPage is how many raw events one scan step reads for a scoped caller.
	scopedAuditPage = 500
	// scopedAuditScanCap bounds how many raw tenant events one scoped request may examine. Hitting
	// it is REPORTED (truncated + next_cursor on the list, partial on the summary), never silent.
	scopedAuditScanCap = 20000
)

// requireTenantWideAudit answers (and writes the 403 for) a request that needs an unscoped
// CapViewAudit membership. Callers must already have passed Require(CapViewAudit).
func requireTenantWideAudit(w http.ResponseWriter, p *Principal) bool {
	scope, _ := p.Grant.ScopeFor(CapViewAudit)
	if scope.All {
		return true
	}
	writeDenied(w, errAuditTenantWide)
	return false
}

// mgmtAuditScoper decides which management events a scoped caller may see. It memoizes the machine
// and session lookups for the lifetime of one request.
type mgmtAuditScoper struct {
	s        *Server
	p        *Principal
	machGrp  map[string]string // machine id -> group id ("" = unresolvable)
	sessGrp  map[string]string // session id -> group id ("" = unresolvable)
	examined int
}

func (s *Server) newMgmtAuditScoper(p *Principal) *mgmtAuditScoper {
	return &mgmtAuditScoper{s: s, p: p, machGrp: map[string]string{}, sessGrp: map[string]string{}}
}

func (sc *mgmtAuditScoper) machineGroup(ctx context.Context, id string) (string, error) {
	if g, ok := sc.machGrp[id]; ok {
		return g, nil
	}
	if sc.s.Machines == nil {
		return "", errors.New("machine store not configured")
	}
	g := ""
	m, err := sc.s.Machines.GetMachineByID(ctx, sc.p.TenantID, id)
	switch {
	case err == nil && m != nil:
		g = m.GroupID
	case err == nil || errors.Is(err, ErrMachineNotFound):
	default:
		return "", err
	}
	sc.machGrp[id] = g
	return g, nil
}

func (sc *mgmtAuditScoper) sessionGroup(ctx context.Context, id string) (string, error) {
	if g, ok := sc.sessGrp[id]; ok {
		return g, nil
	}
	if sc.s.SessionRecords == nil {
		return "", errors.New("session store not configured")
	}
	g := ""
	rec, err := sc.s.SessionRecords.GetSession(ctx, sc.p.TenantID, id)
	switch {
	case err == nil && rec != nil:
		g = rec.MachineGroupID
	case err == nil || errors.Is(err, ErrSessionRecordNotFound):
	default:
		return "", err
	}
	sc.sessGrp[id] = g
	return g, nil
}

// auditEventGroup resolves the machine group an event is ABOUT, in this order: a machine target;
// the machine_id the event recorded (session.*, command.run_requested, recording.*, grant.mint);
// a session target (looked up); a group target; a recorded group_id. "" means the event is not
// attributable to any group (tenant-level) or its subject no longer resolves.
func (sc *mgmtAuditScoper) auditEventGroup(ctx context.Context, e *MgmtAuditEvent) (string, error) {
	var meta struct {
		MachineID string `json:"machine_id"`
		GroupID   string `json:"group_id"`
	}
	if len(e.Metadata) > 0 {
		_ = json.Unmarshal(e.Metadata, &meta) // not an object: simply no machine/group hints
	}
	switch {
	case e.TargetKind == "machine" && e.TargetID != "":
		return sc.machineGroup(ctx, e.TargetID)
	case meta.MachineID != "":
		return sc.machineGroup(ctx, meta.MachineID)
	case e.TargetKind == "session" && e.TargetID != "":
		return sc.sessionGroup(ctx, e.TargetID)
	case (e.TargetKind == "machine_group" || e.TargetKind == "group") && e.TargetID != "":
		return e.TargetID, nil
	case meta.GroupID != "":
		return meta.GroupID, nil
	}
	return "", nil
}

// visible reports whether the caller may see e.
func (sc *mgmtAuditScoper) visible(ctx context.Context, e *MgmtAuditEvent) (bool, error) {
	gid, err := sc.auditEventGroup(ctx, e)
	if err != nil {
		return false, err
	}
	if gid == "" {
		return false, nil
	}
	return sc.p.Grant.AllowsInGroup(CapViewAudit, gid), nil
}

// scan walks the tenant's matching events newest-first in pages, using the store's composite
// (seq, occurred_at, id) cursor, so pages chain exactly even when thousands of events share one
// timestamp. It calls keep for each VISIBLE event until keep returns false (the caller has what it
// wanted: cut == nil), the trail is exhausted (cut == nil), or the scan cap is reached with events
// possibly remaining, in which case cut is the cursor to continue from.
func (sc *mgmtAuditScoper) scan(ctx context.Context, filter AuditFilter, keep func(MgmtAuditEvent) bool) (cut *AuditCursor, err error) {
	examined := 0
	for {
		page, err := sc.s.MgmtAudit.ListEventsFiltered(ctx, sc.p.TenantID, scopedAuditPage, filter)
		if err != nil {
			return nil, err
		}
		for i := range page {
			e := page[i]
			examined++
			ok, err := sc.visible(ctx, &e)
			if err != nil {
				return nil, err
			}
			if ok && !keep(e) {
				return nil, nil
			}
		}
		if len(page) < scopedAuditPage {
			return nil, nil // exhausted
		}
		filter.Before = CursorOf(&page[len(page)-1])
		if examined >= scopedAuditScanCap {
			return filter.Before, nil // truncated: more may remain beyond the cap
		}
	}
}

// listScoped is GET /audit for a scoped caller. A non-nil cut means the scan cap was reached before
// the trail was exhausted or the limit filled: the answer is TRUNCATED and cut continues it.
func (sc *mgmtAuditScoper) listScoped(ctx context.Context, limit int, filter AuditFilter) ([]MgmtAuditEvent, *AuditCursor, error) {
	if limit <= 0 {
		limit = defaultMgmtAuditListLimit
	}
	out := make([]MgmtAuditEvent, 0, min(limit, 64))
	cut, err := sc.scan(ctx, filter, func(e MgmtAuditEvent) bool {
		out = append(out, e)
		return len(out) < limit
	})
	return out, cut, err
}

// summarizeScoped is GET /audit/summary for a scoped caller: per-action counts over visible events
// only, ordered like the store's (count DESC, action ASC). partial is true when the scan cap cut
// the walk short, so the counts are a lower bound, not the full total.
func (sc *mgmtAuditScoper) summarizeScoped(ctx context.Context, filter AuditFilter) (out []AuditActionCount, partial bool, err error) {
	counts := map[string]int64{}
	cut, err := sc.scan(ctx, filter, func(e MgmtAuditEvent) bool {
		counts[e.Action]++
		return true
	})
	if err != nil {
		return nil, false, err
	}
	out = make([]AuditActionCount, 0, len(counts))
	for a, n := range counts {
		out = append(out, AuditActionCount{Action: a, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Action < out[j].Action
	})
	return out, cut != nil, nil
}

// encodeAuditCursor / decodeAuditCursor carry an AuditCursor through the ?cursor= query parameter.
func encodeAuditCursor(c *AuditCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeAuditCursor(s string) (*AuditCursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var c AuditCursor
	if err := json.Unmarshal(b, &c); err != nil || c.ID == "" || !isUUID(c.ID) {
		return nil, errors.New("malformed cursor")
	}
	return &c, nil
}
