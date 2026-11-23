package controlplane

// Management-plane audit — who did what in the CONSOLE (machine enrolled, session started,
// grant minted, tenant created), over the `audit_event` table in migrations/0001_core.sql.
//
// DISTINCT from the backstage audit chain (audit.go / backstage_audit_event): that is the
// agent's hash-chained record of what a technician did ON a machine, ingested via
// POST /audit/ingest. This is the record of management API actions, written server-side by the
// handlers themselves and read back via GET /audit.
//
// Since migration 0014 this trail is HASH-CHAINED PER TENANT, mirroring the backstage chain's
// tamper-evidence: each event carries seq (0-based, contiguous per tenant), prev_hash (the
// previous event's hash; "" at genesis) and hash (SHA-256 of the canonical mgmt-audit v1
// preimage, mgmtaudit_canonical.go). The STORE computes the chain at append time — callers pass
// content fields only. VerifyMgmtAuditChain re-walks a tenant's chain and recomputes every hash,
// so any edit, reorder, deletion, or insertion inside the chain is detectable
// (GET /audit/verify); tail truncation is countered by the DB-level append-only REVOKE (0006),
// not the chain itself. ListEventsAsc is the ascending, cursor-paged read that both the verifier
// and the SIEM export (GET /audit/export, NDJSON) walk.
//
// Follows the repo's interface-plus-fakes pattern: MgmtAuditStore interface, in-memory fake,
// pgx implementation (PgMgmtAuditStore, pgstore_dataplane.go).

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MgmtAuditEvent is one management-plane audit entry. ActorUserID/TargetID may be empty
// (stored as NULL): system-initiated actions have no actor, and some actions have no single
// target row. Seq/PrevHash/Hash are chain fields assigned by the store; Seq is nil only for
// legacy rows recorded before migration 0014.
type MgmtAuditEvent struct {
	ID          string          `json:"id"`
	TenantID    string          `json:"tenant_id"`
	ActorUserID string          `json:"actor_user_id,omitempty"`
	Action      string          `json:"action"`                // e.g. "machine.enroll", "session.start"
	TargetKind  string          `json:"target_kind,omitempty"` // "machine" | "session" | "tenant" | ...
	TargetID    string          `json:"target_id,omitempty"`
	OccurredAt  time.Time       `json:"occurred_at"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	Seq         *int64          `json:"seq,omitempty"`
	PrevHash    string          `json:"prev_hash,omitempty"`
	Hash        string          `json:"hash,omitempty"`
	// SourceIP is the request's trusted client address (audit_event.source_ip; see sourceip.go), empty
	// when the event was not recorded in an HTTP request context. Stamped by the STORE from the context
	// so no caller can set it, and deliberately NOT part of the hash preimage: the chain format is
	// frozen (mgmtAuditDomainTag) and verifiers of existing exports must keep passing.
	SourceIP string `json:"source_ip,omitempty"`
}

// AuditActionCount is one row of the §5 Reports summary: an action and how many of the tenant's audit
// events (matching the filter) carried it. Mirrors the Go/TS shape field for field.
type AuditActionCount struct {
	Action string `json:"action"`
	Count  int64  `json:"count"`
}

// MgmtAuditStore is the persistence seam for management-plane audit. Append-only: there is
// deliberately no update/delete method, and migration 0006 revokes UPDATE/DELETE on the table
// from the app role.
type MgmtAuditStore interface {
	// RecordEvent persists one event, assigning ID and OccurredAt when unset and ALWAYS
	// assigning the chain fields (Seq, PrevHash, Hash) — the tenant's next link. The passed
	// event is updated with everything assigned.
	RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error
	// ListEvents returns up to limit events for the tenant, most recent first (limit <= 0
	// means a server-chosen default). Equivalent to ListEventsFiltered with a zero AuditFilter.
	ListEvents(ctx context.Context, tenantID string, limit int) ([]MgmtAuditEvent, error)
	// ListEventsFiltered is ListEvents narrowed to the events matching filter (docs/01 §5 — audit
	// search): a non-empty Action and/or TargetKind restricts to exact matches, applied BEFORE the
	// limit so `limit` bounds the MATCHING events, not the pre-filter window. A zero filter lists
	// everything, so ListEvents delegates here.
	ListEventsFiltered(ctx context.Context, tenantID string, limit int, filter AuditFilter) ([]MgmtAuditEvent, error)
	// SummarizeByAction groups the tenant's audit events matching filter BY ACTION, returning each
	// action with its event count, ordered by count DESC then action ASC (the §5 Reports aggregation).
	// A pure read — no chain interaction, no limit (bounded by the number of distinct actions). A zero
	// filter summarizes every event; the same filter predicate as ListEventsFiltered applies.
	SummarizeByAction(ctx context.Context, tenantID string, filter AuditFilter) ([]AuditActionCount, error)
	// ListEventsAsc returns up to limit CHAINED events with seq > afterSeq in ascending seq
	// order (pass afterSeq = -1 to start at the genesis event). Legacy pre-0014 rows have no
	// seq and are not returned — the chain walker and the SIEM export both page through this.
	ListEventsAsc(ctx context.Context, tenantID string, afterSeq int64, limit int) ([]MgmtAuditEvent, error)
	// CountUnchained returns how many of the tenant's events carry NO chain fields. Legacy
	// pre-0014 rows are the benign case; a count that GROWS afterwards means rows are being
	// inserted outside the chain, which the walk alone cannot see (see VerifyMgmtAuditChain).
	CountUnchained(ctx context.Context, tenantID string) (int64, error)
}

// AuditFilter narrows an audit listing (docs/01 §5). Each set field is a restriction; an unset
// field (empty string / zero time) does not filter on it. A zero AuditFilter matches everything.
type AuditFilter struct {
	// Action restricts to events with this exact action (e.g. "machine.enroll", "session.start").
	Action string
	// TargetKind restricts to events about this kind of target ("machine" | "session" | "tenant" | …).
	TargetKind string
	// Actor restricts to events with this exact actor_user_id (a user id, or an API-token id — the
	// opaque recorded identifier 0016 made actor into). Empty does not filter on the actor.
	Actor string
	// Since restricts to events at or after this instant (occurred_at >= Since). Zero = no lower bound.
	Since time.Time
	// Until restricts to events at or before this instant (occurred_at <= Until). Zero = no upper
	// bound. Since/Until form a CLOSED range [Since, Until]; an inverted range simply matches nothing.
	Until time.Time
	// Before, when set, restricts a LIST to events strictly after this position in the listing
	// order (i.e. older), so a caller can page without relying on timestamps (many events can share
	// one). Ignored by SummarizeByAction.
	Before *AuditCursor
}

// AuditCursor is a position in the management listing order: seq DESC (NULLS LAST for legacy
// unchained rows), then occurred_at DESC, then id DESC. It is a COMPOSITE key, so it identifies
// one row exactly even when thousands of rows share an OccurredAt; both stores implement the same
// "strictly after" predicate (AuditCursor.precedes in memory, the row comparison in pg).
type AuditCursor struct {
	Seq        *int64    `json:"s,omitempty"`
	OccurredAt time.Time `json:"t"`
	ID         string    `json:"i"`
}

// CursorOf returns the position of e in the listing order.
func CursorOf(e *MgmtAuditEvent) *AuditCursor {
	c := &AuditCursor{OccurredAt: e.OccurredAt, ID: e.ID}
	if e.Seq != nil {
		s := *e.Seq
		c.Seq = &s
	}
	return c
}

// precedes reports whether e sorts strictly AFTER the cursor in the listing order (is older).
func (c *AuditCursor) precedes(e *MgmtAuditEvent) bool {
	if c.Seq != nil {
		if e.Seq == nil {
			return true // legacy rows sort last
		}
		if *e.Seq != *c.Seq {
			return *e.Seq < *c.Seq
		}
	} else if e.Seq != nil {
		return false
	}
	if !e.OccurredAt.Equal(c.OccurredAt) {
		return e.OccurredAt.Before(c.OccurredAt)
	}
	return e.ID < c.ID
}

// defaultMgmtAuditListLimit bounds GET /audit responses when no explicit limit is given.
const defaultMgmtAuditListLimit = 200

// mgmtAuditVerifyPageSize is how many events VerifyMgmtAuditChain pulls per ListEventsAsc page.
const mgmtAuditVerifyPageSize = 500

// maxMgmtAuditVerifyEvents bounds how many events ONE GET /audit/verify request will hash.
// Verification is the most expensive read on the management surface — a SHA-256 per event plus a
// paged scan — and the chain grows without limit, so an unbounded walk lets any CapViewAudit
// holder turn a single cheap request into a full-table scan and repeat it. The walk is therefore
// resumable: a response that stops at the cap reports completed=false plus the cursor to continue
// from, which is the same paging discipline GET /audit/export already uses.
const maxMgmtAuditVerifyEvents = 10000

// stampMgmtChainFields fills the caller-optional fields (ID, OccurredAt) and computes the chain
// link onto the supplied tail. OccurredAt is truncated to milliseconds so the value that feeds
// the hash survives the timestamptz (µs) round-trip exactly. Returns the event ready to store.
func stampMgmtChainFields(e *MgmtAuditEvent, tenantID string, tailSeq int64, tailHash string) error {
	e.TenantID = tenantID
	if e.ID == "" {
		e.ID = newUUID()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now()
	}
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Millisecond)
	seq := tailSeq + 1
	e.Seq = &seq
	if seq == 0 {
		e.PrevHash = MgmtGenesisPrevHash
	} else {
		e.PrevHash = tailHash
	}
	h, err := recomputeMgmtAuditHash(*e)
	if err != nil {
		return err
	}
	e.Hash = h
	return nil
}

// MgmtAuditVerifyResult is the outcome of a full chain walk for one tenant.
type MgmtAuditVerifyResult struct {
	// OK is true when every chained event links and re-hashes correctly.
	OK bool `json:"ok"`
	// CheckedEvents is how many chained events were verified.
	CheckedEvents int64 `json:"checked_events"`
	// UnchainedEvents is how many of the tenant's events sit OUTSIDE the chain (no seq/hash).
	// It is reported unconditionally — including when OK is true — because those rows are
	// exactly what the walk cannot attest: legacy pre-0014 rows are expected, but a count that
	// grows after the migration means something is inserting rows around the chain, and an
	// auditor reading only `ok` would never see it. Coverage is CheckedEvents of
	// CheckedEvents+UnchainedEvents.
	UnchainedEvents int64 `json:"unchained_events"`
	// FirstBadSeq is the seq of the first broken link (present only when !OK).
	FirstBadSeq *int64 `json:"first_bad_seq,omitempty"`
	// Reason says what broke (present only when !OK).
	Reason string `json:"reason,omitempty"`
	// Completed is false when the walk stopped at its event cap with more chain left. OK then
	// means "nothing wrong in the part that was checked" — NOT that the chain is intact — so a
	// caller that treats an incomplete result as a clean bill of health is reading it wrong.
	Completed bool `json:"completed"`
	// NextAfterSeq is the cursor to resume from, set only when Completed is false.
	NextAfterSeq *int64 `json:"next_after_seq,omitempty"`
}

// VerifyMgmtAuditChain walks a tenant's whole chain in ascending order, checking seq contiguity
// from 0, prev_hash linkage, and recomputed content hashes, and counts any events lying outside
// the chain. It is store-agnostic (pages through ListEventsAsc), so the in-memory and pgx stores
// share one verifier.
//
// What this does and does NOT prove: any edit, reorder, deletion or insertion INSIDE the chain is
// detected. Two things are not, by construction — truncating the newest events (a hash chain has
// no external anchor; the DB-level append-only REVOKE in 0006 is the guard there), and rows
// inserted with no chain fields at all, which is why UnchainedEvents is reported.
func VerifyMgmtAuditChain(ctx context.Context, store MgmtAuditStore, tenantID string) (MgmtAuditVerifyResult, error) {
	return VerifyMgmtAuditChainFrom(ctx, store, tenantID, -1, 0)
}

// VerifyMgmtAuditChainFrom is the resumable, bounded form behind GET /audit/verify.
//
// afterSeq is the cursor: -1 starts at genesis, and any other value resumes immediately after
// that seq. Resuming is ANCHORED — the walk re-reads event afterSeq to recover the hash the next
// event must chain onto, rather than trusting whatever prev_hash the first row of the new page
// happens to carry. That is what makes consecutive pages COMPOSE: page 2 must attach to the very
// event page 1 ended on, so a forgery cannot hide in the seam between two requests.
//
// It does NOT make a mid-chain walk equivalent to a full one: starting at afterSeq attests only
// the suffix after it, and the anchor event's own content is not re-hashed here (the page that
// covered it did that). A caller wanting a full attestation must page from -1 to completion.
//
// maxEvents caps how many events this call will hash; 0 means unbounded, which is for internal
// callers and tests — every request-driven path passes a cap.
func VerifyMgmtAuditChainFrom(ctx context.Context, store MgmtAuditStore, tenantID string,
	afterSeq int64, maxEvents int) (MgmtAuditVerifyResult, error) {
	unchained, err := store.CountUnchained(ctx, tenantID)
	if err != nil {
		return MgmtAuditVerifyResult{}, err
	}
	bad := func(seq int64, reason string) MgmtAuditVerifyResult {
		return MgmtAuditVerifyResult{
			OK: false, FirstBadSeq: &seq, Reason: reason, UnchainedEvents: unchained,
			Completed: true,
		}
	}
	var (
		checked  int64
		nextSeq  int64 // the seq the next event must carry
		prevHash = MgmtGenesisPrevHash
	)
	if afterSeq >= 0 {
		anchor, err := store.ListEventsAsc(ctx, tenantID, afterSeq-1, 1)
		if err != nil {
			return MgmtAuditVerifyResult{}, err
		}
		if len(anchor) == 0 || anchor[0].Seq == nil || *anchor[0].Seq != afterSeq {
			return bad(afterSeq, fmt.Sprintf(
				"cannot resume at seq %d: that event is missing (deleted, or a cursor past the end of the chain)",
				afterSeq)), nil
		}
		nextSeq = afterSeq + 1
		prevHash = anchor[0].Hash
	}
	after := afterSeq
	for {
		if maxEvents > 0 && checked >= int64(maxEvents) {
			// The cap is reached — but reaching it exactly at the end of the chain is a
			// COMPLETE walk, and reporting that as incomplete would send every caller back for
			// a pointless extra request. One 1-row lookahead settles it.
			more, err := store.ListEventsAsc(ctx, tenantID, after, 1)
			if err != nil {
				return MgmtAuditVerifyResult{}, err
			}
			if len(more) == 0 {
				break
			}
			cursor := after
			return MgmtAuditVerifyResult{
				OK: true, CheckedEvents: checked, UnchainedEvents: unchained,
				Completed: false, NextAfterSeq: &cursor,
			}, nil
		}
		pageSize := mgmtAuditVerifyPageSize
		if maxEvents > 0 {
			if remaining := int64(maxEvents) - checked; remaining < int64(pageSize) {
				pageSize = int(remaining)
			}
		}
		page, err := store.ListEventsAsc(ctx, tenantID, after, pageSize)
		if err != nil {
			return MgmtAuditVerifyResult{}, err
		}
		for _, e := range page {
			if e.Seq == nil {
				return bad(nextSeq, "unchained event returned by ascending scan"), nil
			}
			if *e.Seq != nextSeq {
				return bad(*e.Seq, fmt.Sprintf("seq gap: got %d, expected %d (a chained event was deleted or reordered)", *e.Seq, nextSeq)), nil
			}
			if e.PrevHash != prevHash {
				return bad(*e.Seq, "broken link: prev_hash does not match the previous event's hash"), nil
			}
			got, err := recomputeMgmtAuditHash(e)
			if err != nil {
				return bad(*e.Seq, "cannot canonicalize event fields: "+err.Error()), nil
			}
			if got != e.Hash {
				return bad(*e.Seq, "recomputed content hash does not match hash (a field was altered)"), nil
			}
			checked++
			nextSeq = *e.Seq + 1
			prevHash = e.Hash
			after = *e.Seq
		}
		if len(page) < pageSize {
			break
		}
	}
	return MgmtAuditVerifyResult{
		OK: true, CheckedEvents: checked, UnchainedEvents: unchained, Completed: true,
	}, nil
}

// -------------------------------------------------------------------------------------
// InMemoryMgmtAuditStore — concurrency-safe fake for tests and DEV mode.
// -------------------------------------------------------------------------------------

type mgmtChainTail struct {
	seq  int64
	hash string
}

type InMemoryMgmtAuditStore struct {
	mu     sync.Mutex
	events []MgmtAuditEvent
	tails  map[string]mgmtChainTail // per-tenant chain tail
}

// NewInMemoryMgmtAuditStore constructs an empty in-memory management audit store.
func NewInMemoryMgmtAuditStore() *InMemoryMgmtAuditStore {
	return &InMemoryMgmtAuditStore{tails: make(map[string]mgmtChainTail)}
}

var _ MgmtAuditStore = (*InMemoryMgmtAuditStore)(nil)

// RecordEvent implements MgmtAuditStore.
func (s *InMemoryMgmtAuditStore) RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *e
	cp.SourceIP = sourceIPFrom(ctx)
	tail, ok := s.tails[tenantID]
	if !ok {
		tail = mgmtChainTail{seq: -1}
	}
	if err := stampMgmtChainFields(&cp, tenantID, tail.seq, tail.hash); err != nil {
		return err
	}
	s.events = append(s.events, cp)
	s.tails[tenantID] = mgmtChainTail{seq: *cp.Seq, hash: cp.Hash}
	*e = cp
	return nil
}

// appendBatch appends the events in order as ONE atomic unit, the in-memory twin of a Postgres transaction:
// under the store's mutex each event is chained onto a STAGED tail, and only when every event has stamped does
// anything become visible (events and tail together). On any failure nothing is committed, and no other writer
// can have appended between the batch's events (so a rollback never has to delete a link a later event chains to).
func (s *InMemoryMgmtAuditStore) appendBatch(ctx context.Context, tenantID string, events []*MgmtAuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tail, ok := s.tails[tenantID]
	if !ok {
		tail = mgmtChainTail{seq: -1}
	}
	staged := make([]MgmtAuditEvent, 0, len(events))
	for _, e := range events {
		cp := *e
		cp.SourceIP = sourceIPFrom(ctx)
		if err := stampMgmtChainFields(&cp, tenantID, tail.seq, tail.hash); err != nil {
			return err
		}
		tail = mgmtChainTail{seq: *cp.Seq, hash: cp.Hash}
		staged = append(staged, cp)
	}
	s.events = append(s.events, staged...)
	if len(staged) > 0 {
		s.tails[tenantID] = tail
	}
	for i, e := range events {
		*e = staged[i]
	}
	return nil
}

// ListEvents implements MgmtAuditStore: the unfiltered listing (delegates to ListEventsFiltered).
func (s *InMemoryMgmtAuditStore) ListEvents(ctx context.Context, tenantID string, limit int) ([]MgmtAuditEvent, error) {
	return s.ListEventsFiltered(ctx, tenantID, limit, AuditFilter{})
}

// ListEventsFiltered implements MgmtAuditStore. Newest first — events are appended in occurrence
// order, so reverse insertion order is the correct ordering even when several events share a
// clock timestamp (coarse OS clocks make same-instant events common in tests). The filter is applied
// BEFORE counting toward limit, so `limit` bounds the MATCHING events.
func (s *InMemoryMgmtAuditStore) ListEventsFiltered(_ context.Context, tenantID string, limit int, filter AuditFilter) ([]MgmtAuditEvent, error) {
	if limit <= 0 {
		limit = defaultMgmtAuditListLimit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []MgmtAuditEvent
	for i := len(s.events) - 1; i >= 0 && len(out) < limit; i-- {
		e := s.events[i]
		if e.TenantID != tenantID {
			continue
		}
		if filter.Action != "" && e.Action != filter.Action {
			continue
		}
		if filter.TargetKind != "" && e.TargetKind != filter.TargetKind {
			continue
		}
		if filter.Actor != "" && e.ActorUserID != filter.Actor {
			continue
		}
		// Closed time range [Since, Until]: skip anything strictly before Since or strictly after Until.
		if !filter.Since.IsZero() && e.OccurredAt.Before(filter.Since) {
			continue
		}
		if !filter.Until.IsZero() && e.OccurredAt.After(filter.Until) {
			continue
		}
		if filter.Before != nil && !filter.Before.precedes(&e) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// SummarizeByAction implements MgmtAuditStore: group the tenant's matching events by action. The filter
// predicate is IDENTICAL to ListEventsFiltered's so the two agree on what "matching" means.
func (s *InMemoryMgmtAuditStore) SummarizeByAction(_ context.Context, tenantID string, filter AuditFilter) ([]AuditActionCount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := map[string]int64{}
	for _, e := range s.events {
		if e.TenantID != tenantID {
			continue
		}
		if filter.Action != "" && e.Action != filter.Action {
			continue
		}
		if filter.TargetKind != "" && e.TargetKind != filter.TargetKind {
			continue
		}
		if filter.Actor != "" && e.ActorUserID != filter.Actor {
			continue
		}
		if !filter.Since.IsZero() && e.OccurredAt.Before(filter.Since) {
			continue
		}
		if !filter.Until.IsZero() && e.OccurredAt.After(filter.Until) {
			continue
		}
		counts[e.Action]++
	}
	out := make([]AuditActionCount, 0, len(counts))
	for a, c := range counts {
		out = append(out, AuditActionCount{Action: a, Count: c})
	}
	// count DESC, then action ASC — matches the pg ORDER BY count(*) DESC, action.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Action < out[j].Action
	})
	return out, nil
}

// ListEventsAsc implements MgmtAuditStore: chained events with seq > afterSeq, ascending.
// Events are appended in seq order, so one forward pass suffices.
func (s *InMemoryMgmtAuditStore) ListEventsAsc(_ context.Context, tenantID string, afterSeq int64, limit int) ([]MgmtAuditEvent, error) {
	if limit <= 0 {
		limit = defaultMgmtAuditListLimit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []MgmtAuditEvent
	for _, e := range s.events {
		if e.TenantID != tenantID || e.Seq == nil || *e.Seq <= afterSeq {
			continue
		}
		out = append(out, e)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// CountUnchained implements MgmtAuditStore.
func (s *InMemoryMgmtAuditStore) CountUnchained(_ context.Context, tenantID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, e := range s.events {
		if e.TenantID == tenantID && e.Seq == nil {
			n++
		}
	}
	return n, nil
}

// tamperEvent mutates a stored event in place — TEST ONLY, reaching past the append-only seam
// to simulate what chain verification exists to catch. Selector matches on seq.
func (s *InMemoryMgmtAuditStore) tamperEvent(tenantID string, seq int64, mutate func(*MgmtAuditEvent)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.events {
		e := &s.events[i]
		if e.TenantID == tenantID && e.Seq != nil && *e.Seq == seq {
			mutate(e)
			return true
		}
	}
	return false
}

// dropEvent removes a stored event — TEST ONLY, simulating a deleted chain link.
func (s *InMemoryMgmtAuditStore) dropEvent(tenantID string, seq int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.events {
		e := s.events[i]
		if e.TenantID == tenantID && e.Seq != nil && *e.Seq == seq {
			s.events = append(s.events[:i], s.events[i+1:]...)
			return true
		}
	}
	return false
}

// discardEvents removes the given events (by chain hash) of one tenant and rewinds that tenant's chain tail.
// It exists for in-memory FAKES that must be atomic like a Postgres transaction (the help-request fake rolls
// back the audit rows of a transition that failed part-way); production stores never call it.
func (s *InMemoryMgmtAuditStore) discardEvents(tenantID string, hashes map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.events[:0]
	for _, e := range s.events {
		if e.TenantID == tenantID && hashes[e.Hash] {
			continue
		}
		kept = append(kept, e)
	}
	s.events = kept
	tail := mgmtChainTail{seq: -1}
	for _, e := range s.events {
		if e.TenantID == tenantID && e.Seq != nil {
			tail = mgmtChainTail{seq: *e.Seq, hash: e.Hash}
		}
	}
	if tail.seq < 0 {
		delete(s.tails, tenantID)
	} else {
		s.tails[tenantID] = tail
	}
}
