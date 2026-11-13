package controlplane

// Backstage audit-chain EXPORT — the read half of the H2 trail (docs/01 §5).
//
//	GET /audit/backstage/export?session_id=&after_ingest_seq=&limit=
//	    → NDJSON (application/x-ndjson), one stored AuditEvent per line in the tenant's INGEST
//	      order, plus an `X-Rmt-Next-After-Ingest-Seq` response header carrying the cursor to
//	      resume from.
//
// Until this existed the backstage chain was **ingested but never re-emitted**: `POST
// /audit/ingest` was the only route that touched `backstage_audit_event`, so the tamper-evident
// trail of what a technician actually did on a customer's machine could only be read with a psql
// prompt. The management trail has had `GET /audit/export` since migration 0014; this is its
// counterpart, and the two deliberately share a shape (NDJSON, cursor-paged, bounded page size) so
// one SIEM collector configuration covers both.
//
// Two things differ from the management export:
//
//  1. **The cursor is a separate column, and it is not `seq`.** `mgmt_audit_event.seq` is a
//     tenant-wide monotonic counter, so it doubles as the cursor. The backstage table has one
//     chain per session and every chain restarts at seq 0, so `seq` orders nothing globally —
//     paging is over `ingest_seq` (migration 0019), a per-tenant append counter. Because
//     `ingest_seq` is not part of the hashed event, it travels as a response header rather than in
//     the body. See AuditExportQuery for why an obvious `(session_id, seq)` cursor is wrong.
//  2. **The capability is CapViewAudit, not CapBackstageShell.** Ingest is gated on
//     CapBackstageShell because writing the trail is part of doing backstage work. Reading it is an
//     auditor's job, and an auditor is deliberately read-only — gating the export on the same
//     capability as ingest would mean the only people who could read the trail are the people it
//     exists to hold accountable.
//
// GROUP SCOPE. `Require(CapViewAudit)` is a TENANT-WIDE check, and for a long time it was the only
// one here: an auditor whose membership covered one machine group could export every group's
// backstage trail — keystroke-level records of work on machines they have no authority over
// (docs/07 loops 11–12, "returns every group's events to a group-scoped auditor"). The scope is now
// consulted, with a `scope.All` FAST PATH that leaves the SIEM-collector case byte-for-byte as it
// was: a tenant-wide auditor runs exactly today's query and pays for exactly nothing.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

// handleExportBackstageAudit streams a page of the tenant's stored backstage audit chain(s).
func (s *Server) handleExportBackstageAudit(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewAudit); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Audit == nil {
		writeError(w, http.StatusInternalServerError, "backstage audit store not configured")
		return
	}
	// Where may this caller use CapViewAudit? Require() above already proved they hold it somewhere,
	// so `held` is necessarily true and the union is what matters. Taken BEFORE the query so the
	// tenant-wide case can be answered without touching the machine repository at all.
	scope, _ := p.Grant.ScopeFor(CapViewAudit)

	// NewAuditExportQuery, not a bare literal: the struct's zero AfterIngestSeq is 0, which would
	// exclude the tenant's very first event.
	q := NewAuditExportQuery(r.URL.Query().Get("session_id"), 0)
	if q.SessionID != "" && !isUUID(q.SessionID) {
		writeError(w, http.StatusBadRequest, "session_id must be a uuid")
		return
	}
	// `after_seq` is the MANAGEMENT export's cursor parameter. Silently ignoring it here would let
	// a collector copied from that endpoint's configuration re-read the whole trail on every poll
	// forever, with a 200 every time and nothing to indicate the cursor was never applied. Name the
	// right parameter instead.
	if r.URL.Query().Has("after_seq") {
		writeError(w, http.StatusBadRequest,
			"after_seq is the management export's cursor; this endpoint pages on after_ingest_seq "+
				"(backstage seq restarts at 0 for every session, so it cannot be a cursor)")
		return
	}
	if v := r.URL.Query().Get("after_ingest_seq"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < auditExportStart {
			writeError(w, http.StatusBadRequest,
				"after_ingest_seq must be an integer >= "+strconv.FormatInt(auditExportStart, 10))
			return
		}
		q.AfterIngestSeq = n
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > maxAuditExportLimit {
			writeError(w, http.StatusBadRequest,
				"limit must be a positive integer <= "+strconv.Itoa(maxAuditExportLimit))
			return
		}
		q.Limit = n
	}

	releaseSlot, ok := s.acquireAuditStream(w, p)
	if !ok {
		return
	}
	defer releaseSlot()
	events, next, err := s.Audit.ListAuditEventsAsc(r.Context(), p.TenantID, q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not export backstage audit events")
		return
	}
	// GROUP FILTERING, and note WHAT IS NOT TOUCHED: `next`. The cursor returned by the store is the
	// ingest_seq of the last row on the RAW page, filtered or not, and it stays that way.
	//
	// That is the whole trap in this endpoint. Recomputing the cursor from the SURVIVING rows is the
	// obvious thing to write and it wedges a scoped collector permanently: a page whose rows all
	// belong to other groups would hand back the caller's own cursor, the collector would re-request
	// the identical page, and it would spin on that page forever — never reaching the events it IS
	// entitled to, which sit just beyond it. Advancing past filtered-out rows is safe because the
	// cursor names a POSITION IN THE INGEST LOG, not a returned record.
	//
	// The consequence for a scoped collector, worth stating because it differs from the tenant-wide
	// contract above: an EMPTY page no longer means "caught up". Caught up is `next` == the cursor
	// you sent; an empty page with an advanced cursor means "nothing of yours in that stretch, keep
	// going".
	if !scope.All {
		events, err = s.backstageEventsInScope(r.Context(), p, events)
		if err != nil {
			// Fail CLOSED: if the machine repository cannot say which group an event belongs to, the
			// only safe answer is to serve nothing, not to serve everything.
			writeError(w, http.StatusInternalServerError, "could not resolve machine groups for the audit scope")
			return
		}
	}
	// The cursor rides in a HEADER, not in the event bodies. Each NDJSON line is exactly the
	// AuditEvent the agent hashed, so a collector re-verifies the chain by hashing the line as it
	// stands; `ingest_seq` is control-plane metadata the agent's SHA-256 never covered, and
	// smuggling it into the body would invite the collector to hash bytes that were never hashed
	// and report tampering on an untampered trail.
	//
	// Always set, including for an empty page: a collector that has caught up must be able to
	// store a cursor and resume later without re-reading the whole trail. When the page is empty
	// this echoes the caller's own cursor back.
	// Every read (page and machine-group lookups) is done: free the pinned connection before the
	// body is written to a possibly slow client (review #5).
	releaseBoundConn(r.Context())
	w.Header().Set("X-Rmt-Next-After-Ingest-Seq", strconv.FormatInt(next, 10))
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store") // audit trail: sensitive tenant data (docs/25 F10)
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w) // Encode appends the newline NDJSON wants
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return // client went away mid-stream; nothing sensible left to send
		}
	}
}

// backstageEventsInScope drops the events recorded on machines outside the caller's audit scope.
//
// The rows carry no group of their own — an AuditEvent names a MACHINE (the agent's device id, the
// same identity the grant was minted for; see handleMintGrant) — so the group comes from the
// machine repository, which is where every other handler on this surface gets it: GET /machines
// filters with `AllowsInGroup(CapViewMachines, m.GroupID)`, GET /sessions with
// `AllowsInGroup(CapViewSessions, rec.MachineGroupID)`, /grant/mint resolves the machine and gates
// on `m.GroupID`. Same helper, same question, so an auditor cannot see through this endpoint what
// they cannot see through those.
//
// `AllowsInGroup` rather than `scope.Covers`: they agree by construction (the scope IS the union
// over memberships granting the capability), but AllowsInGroup is the check the sibling handlers
// make, and one mechanism with one meaning is the point. The scope is used only to decide whether
// any of this is needed.
//
// One lookup per DISTINCT machine, memoized for the page: a backstage chain belongs to a single
// machine and a page is typically a handful of chains, so this is a couple of indexed reads, not
// one per event. A machine that no longer resolves (retired, or an expired attended guest) has no
// group to scope against and is therefore NOT visible to a scoped auditor — fail closed. A
// tenant-wide auditor never reaches this function, so the SIEM path pays none of it.
func (s *Server) backstageEventsInScope(ctx context.Context, p *Principal, events []AuditEvent) ([]AuditEvent, error) {
	if len(events) == 0 {
		return events, nil
	}
	if s.Machines == nil {
		return nil, errors.New("machine store not configured")
	}
	const unresolvable = "" // sentinel: memoized "this machine has no group we can scope against"
	groupOf := make(map[string]string, 4)
	visible := make([]AuditEvent, 0, len(events))
	for _, e := range events {
		gid, seen := groupOf[e.MachineID]
		if !seen {
			m, err := s.Machines.GetMachine(ctx, p.TenantID, e.MachineID)
			switch {
			case err == nil:
				gid = m.GroupID
			case errors.Is(err, ErrMachineNotFound):
				gid = unresolvable
			default:
				// A store failure is NOT "no group": answering it as invisible would quietly turn an
				// outage into a truncated audit export, which is the one output nobody re-checks.
				return nil, err
			}
			groupOf[e.MachineID] = gid
		}
		if gid == unresolvable {
			continue
		}
		if p.Grant.AllowsInGroup(CapViewAudit, gid) {
			visible = append(visible, e)
		}
	}
	return visible, nil
}

// isUUID reports whether s is a canonical 8-4-4-4-12 hex uuid.
//
// The uuid-shaped query parameters are validated HERE rather than left to PostgreSQL because they
// reach a `::uuid` cast: a malformed value would otherwise surface as a 500 ("could not export"),
// which reads as a server fault and tells the caller nothing about the typo in their cursor. It
// also keeps the in-memory and pg stores agreeing on what a caller may pass.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
