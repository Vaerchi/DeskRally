package controlplane

// Session transfer / escalation (docs/51, design accepted at v4; §7-§9 supersede §3-§5).
//
// A technician (A) hands a live unattended session S1 to a named colleague or to anyone who may
// start sessions in the machine's group. The handoff is two sessions, not a mutation: S1 ends and the
// receiver's S2 starts on the same machine, linked by session_record.transferred_from. Nothing about a
// live session can be re-bound (the ticket, the agent's brokered technician and its audit chain are all
// per-session), so a transfer is an ordinary new session started only AFTER the agent has reported S1
// gone. The states:
//
//	pending    an offer exists (expires 5 minutes after it was made)
//	releasing  accepted; S1 stays open and keeps its seat until the agent's end report arrives
//	accepted   the agent reported S1 gone; S2 was admitted (new_session_id) in the same transaction
//	failed     the release timed out (60 s) or S2's admission/authorization failed on finalize
//	cancelled / expired / superseded   the offer ended without a transfer
//
// Terminal states are terminal: a late end report after failed or expired may close S1 but never
// revives an offer or admits an S2.
//
// LOCK ORDER (docs/51 §9.2), the same in every store method that touches an offer: the per-tenant
// admission lock (session_start:<tenant>, the one every POST /sessions takes) FIRST, then the offer
// row, then S1's row, then the management-audit chain. The in-memory store keeps the same order with
// its own mutex first and the session store's second.
//
// Follows the repo's interface-plus-fakes pattern: SessionTransferStore here with an in-memory fake
// (which must agree with the pg store, pgstore_session_transfer.go), the handlers in
// http_session_transfer.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type TransferState string

const (
	TransferPending    TransferState = "pending"
	TransferReleasing  TransferState = "releasing"
	TransferAccepted   TransferState = "accepted"
	TransferFailed     TransferState = "failed"
	TransferCancelled  TransferState = "cancelled"
	TransferExpired    TransferState = "expired"
	TransferSuperseded TransferState = "superseded"
)

const (
	// transferOfferTTL is how long a pending offer stays acceptable. Enforced in DB time at accept.
	transferOfferTTL = 5 * time.Minute
	// transferReleaseTimeout is how long a releasing offer waits for the agent's end report before it
	// fails. Nothing is worse than before the offer: S1's renewals stay refused, so S1 ends on
	// lease-enforcing agents and on any other agent A keeps exactly the access A already had.
	transferReleaseTimeout = 60 * time.Second
	// maxTransferNoteRunes bounds the free-text note on an offer (the column is capped at 500).
	maxTransferNoteRunes = 500
	// transferListLimit bounds the incoming / outgoing listings.
	transferListLimit = 200
)

const (
	transferFailReleaseTimeout = "the machine did not confirm the previous session closed"
)

// transferMinAgent is the first agent release that reports EVERY session end (docs/49 `session_ended`
// for viewer_left, lease_lapsed, service_stop and the rest). Offers are refused for older agents.
var transferMinAgent = [3]uint64{0, 1, 6}

// transferAgentSupported reports whether an agent version is new enough to hand off a live session.
// Parsed exactly like the observer gate: a release, optionally with SemVer build metadata;
// prereleases and anything unparseable are refused.
func transferAgentSupported(version string) bool {
	return agentVersionAtLeast(version, transferMinAgent)
}

var (
	ErrTransferNotFound = errors.New("session transfer not found")
	// ErrTransferForbidden: the actor may not perform this transition (sender accepting their own
	// offer, someone else's cancel, an acceptor the offer does not address).
	ErrTransferForbidden = errors.New("not permitted on this session transfer")
	// ErrTransferNotPending: the offer is not (or no longer) pending; the returned transfer carries state.
	ErrTransferNotPending = errors.New("session transfer is not pending")
	ErrTransferExpired    = errors.New("session transfer offer expired")
	// ErrTransferSessionEnded: S1 is closed, so the offer cannot be used.
	ErrTransferSessionEnded = errors.New("the session being transferred has ended")
	// ErrTransferReleasing: S1 already has a transfer being released; a second offer is refused.
	ErrTransferReleasing = errors.New("session already has a transfer in progress")
	// ErrTransferSessionNotHeld: S1 is not open, not a control session, or not held by the offerer.
	ErrTransferSessionNotHeld = errors.New("session is not open and held by the sender")
)

// TransferRefusedError is what a TransferAdmitter returns when the acceptor's authority (or the
// machine) no longer admits an S2: the offer goes `failed` with Reason. Any OTHER error from an
// admitter is infrastructure: the finalize rolls back untouched and is retried.
type TransferRefusedError struct{ Reason string }

func (e *TransferRefusedError) Error() string { return "session transfer refused: " + e.Reason }

// SessionTransfer is one offer. MachineID is the machine PRIMARY KEY, GroupID the machine's group
// when the offer was made (informational: authority is always re-derived against the CURRENT group).
type SessionTransfer struct {
	ID            string        `json:"id"`
	TenantID      string        `json:"-"`
	SessionID     string        `json:"session_id"`
	MachineID     string        `json:"machine_id"`
	GroupID       string        `json:"group_id,omitempty"`
	FromUserID    string        `json:"from_user_id"`
	ToUserID      string        `json:"to_user_id,omitempty"` // empty = escalate to anyone in the group
	Note          string        `json:"note"`
	State         TransferState `json:"state"`
	CreatedAt     time.Time     `json:"created_at"`
	ExpiresAt     time.Time     `json:"expires_at"`
	ReleasingAt   *time.Time    `json:"releasing_at,omitempty"`
	AcceptedBy    string        `json:"accepted_by,omitempty"`
	NewSessionID  string        `json:"new_session_id,omitempty"`
	FailureReason string        `json:"failure_reason,omitempty"`
}

// TransferOfferInput is an offer request. Only SessionID, FromUserID, ToUserID and Note come from the
// caller; machine and group are DERIVED from the locked S1 row inside the store.
type TransferOfferInput struct {
	SessionID  string
	FromUserID string
	ToUserID   string
	Note       string
}

// TransferAdmission is what a TransferAdmitter hands the store to admit S2: the record to insert, the
// seat limits to admit it under, and the metadata of its session.start audit event.
type TransferAdmission struct {
	Rec       *SessionRecord
	Limits    SessionStartLimits
	StartMeta map[string]any
}

// TransferAdmitter re-derives the acceptor's FULL authority at finalize time (docs/51 §9.2): active
// tenant membership, CapStartSession on the machine's CURRENT group, quarantine, group policy and the
// agent gates. The store calls it under the admission lock, offer and S1 locks, before admitting S2.
// It returns a *TransferRefusedError to fail the offer.
type TransferAdmitter func(ctx context.Context, t *SessionTransfer) (*TransferAdmission, error)

// SessionTransferStore is the persistence seam for transfer offers. Every method is tenant-scoped; the
// pg implementation additionally runs under RLS and takes the locks in the order documented above.
// Each transition writes its management-audit rows INSIDE the same transaction (docs/51 §7.6).
type SessionTransferStore interface {
	// CreateOffer re-validates S1 under lock (open, control, held by FromUserID), supersedes an older
	// PENDING offer for it, and refuses while one is releasing (ErrTransferReleasing).
	// ErrSessionRecordNotFound for an unknown S1; ErrTransferSessionNotHeld otherwise.
	CreateOffer(ctx context.Context, tenantID string, in TransferOfferInput) (*SessionTransfer, error)
	// Cancel moves the sender's PENDING offer to cancelled. ErrTransferForbidden for anyone else;
	// ErrTransferNotPending (with the transfer) for any other state.
	Cancel(ctx context.Context, tenantID, id, actor string) (*SessionTransfer, error)
	// Get returns one offer or ErrTransferNotFound. It never mutates.
	Get(ctx context.Context, tenantID, id string) (*SessionTransfer, error)
	// ListIncoming returns unexpired PENDING offers for userID whose S1 is still open: those addressed
	// to them and group escalations (to_user NULL), never their own. The caller re-checks authority.
	ListIncoming(ctx context.Context, tenantID, userID string) ([]SessionTransfer, error)
	// ListOutgoing returns userID's live offers (pending and unexpired, or releasing).
	ListOutgoing(ctx context.Context, tenantID, userID string) ([]SessionTransfer, error)
	// Accept moves a pending offer to releasing under the admission lock (S1 stays open). A repeat by
	// the RECORDED acceptor on releasing/accepted/failed is a status read: no mutation, no audit.
	// ErrTransferForbidden (sender, or not the addressee), ErrTransferNotPending, ErrTransferExpired
	// (the offer is marked expired) and ErrTransferSessionEnded return the transfer too.
	Accept(ctx context.Context, tenantID, id, acceptor string) (*SessionTransfer, error)
	// Reconcile applies the time rules to one offer (pending past its expiry -> expired, releasing past
	// the timeout without an agent report -> failed) and, when admit is non-nil and the agent has
	// reported S1 gone, finalizes it. It returns the offer as it now stands.
	Reconcile(ctx context.Context, tenantID, id string, admit TransferAdmitter) (*SessionTransfer, error)
	// RecordAgentEnded stamps session_record.agent_ended_at for sessionID (first report wins; a
	// duplicate changes nothing) and finalizes the session's releasing offer, if any, through admit.
	// Called only after the authenticated end report has been accepted.
	RecordAgentEnded(ctx context.Context, tenantID, sessionID string, at time.Time, admit TransferAdmitter) error
	// LiveForSession returns the releasing or accepted transfer of S1, or nil. Used to answer S1's
	// renewal with "session transferred".
	LiveForSession(ctx context.Context, tenantID, sessionID string) (*SessionTransfer, error)
	// ExpireStale is the reaper's cleanup: pending offers past expiry -> expired, releasing offers past
	// the timeout without an agent report -> failed. Correctness never depends on it (the rules are
	// enforced in DB time on every transition); it only keeps the table tidy.
	ExpireStale(ctx context.Context, tenantID string) (int, error)
}

// -------------------------------------------------------------------------------------
// InMemorySessionTransferStore — concurrency-safe fake that must agree with the pg store.
// -------------------------------------------------------------------------------------

type InMemorySessionTransferStore struct {
	mu        sync.Mutex // the admission + offer lock: ALWAYS taken before the session store's
	transfers map[string]*SessionTransfer
	records   *InMemorySessionRecordStore
	audit     MgmtAuditStore

	// Now is the clock (DB time in pg), swappable in tests. Nil means time.Now.
	Now func() time.Time
}

// NewInMemorySessionTransferStore wires the fake over the session store whose records it hands
// over, and the audit store it writes the management-audit rows to (nil = no audit).
func NewInMemorySessionTransferStore(records *InMemorySessionRecordStore, audit MgmtAuditStore) *InMemorySessionTransferStore {
	return &InMemorySessionTransferStore{transfers: map[string]*SessionTransfer{}, records: records, audit: audit}
}

var _ SessionTransferStore = (*InMemorySessionTransferStore)(nil)

func (s *InMemorySessionTransferStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func transferKey(tenantID, id string) string { return tenantID + "\x00" + id }

func (s *InMemorySessionTransferStore) get(tenantID, id string) *SessionTransfer {
	return s.transfers[transferKey(tenantID, id)]
}

func (s *InMemorySessionTransferStore) liveFor(tenantID, sessionID string) *SessionTransfer {
	for _, t := range s.transfers {
		if t.TenantID == tenantID && t.SessionID == sessionID && (t.State == TransferPending || t.State == TransferReleasing) {
			return t
		}
	}
	return nil
}

func (s *InMemorySessionTransferStore) recordAudit(ctx context.Context, tenantID, actor, action string, t *SessionTransfer, meta map[string]any) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.RecordEvent(ctx, tenantID, newTransferAuditEvent(actor, action, t, meta))
}

// newTransferAuditEvent builds one session.transfer_* management-audit event. An empty actor is the
// system (the 5-minute expiry and the 60-second release timeout have no human behind them).
func newTransferAuditEvent(actor, action string, t *SessionTransfer, meta map[string]any) *MgmtAuditEvent {
	m := map[string]any{
		"transfer_id": t.ID, "session_id": t.SessionID, "machine_id": t.MachineID,
		"from_user_id": t.FromUserID,
	}
	if t.GroupID != "" {
		m["group_id"] = t.GroupID
	}
	if t.ToUserID != "" {
		m["to_user_id"] = t.ToUserID
	}
	if t.AcceptedBy != "" {
		m["accepted_by"] = t.AcceptedBy
	}
	if t.NewSessionID != "" {
		m["new_session_id"] = t.NewSessionID
	}
	if actor == "" {
		m["actor_kind"] = "system"
	}
	for k, v := range meta {
		m[k] = v
	}
	raw, _ := json.Marshal(m)
	return &MgmtAuditEvent{ActorUserID: actor, Action: action, TargetKind: "session_transfer", TargetID: t.ID, Metadata: raw}
}

// transferSessionEndEvent is S1's session.end row, written when finalize itself closes S1. (When the
// agent's end report already closed it, that report wrote the session.end with the agent's own reason,
// and finalize only adds end_reason='transferred' to the row: one end, one audit row.)
func transferSessionEndEvent(t *SessionTransfer) *MgmtAuditEvent {
	raw, _ := json.Marshal(map[string]any{
		"machine_id": t.MachineID, "reason": "transferred", "via_transfer": t.ID, "transferred_to": t.AcceptedBy,
	})
	return &MgmtAuditEvent{ActorUserID: t.AcceptedBy, Action: "session.end", TargetKind: "session", TargetID: t.SessionID, Metadata: raw}
}

// transferSessionStartEvent is S2's session.start row, linked to S1 and the offer.
func transferSessionStartEvent(t *SessionTransfer, newSessionID string, startMeta map[string]any) *MgmtAuditEvent {
	meta := map[string]any{"transferred_from": t.SessionID, "transfer_id": t.ID, "machine_id": t.MachineID}
	for k, v := range startMeta {
		meta[k] = v
	}
	raw, _ := json.Marshal(meta)
	return &MgmtAuditEvent{ActorUserID: t.AcceptedBy, Action: "session.start", TargetKind: "session", TargetID: newSessionID, Metadata: raw}
}

func (s *InMemorySessionTransferStore) CreateOffer(ctx context.Context, tenantID string, in TransferOfferInput) (*SessionTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s1, err := s.records.GetSession(ctx, tenantID, in.SessionID)
	if err != nil {
		return nil, err
	}
	if s1.EndedAt != nil || s1.Access != "control" && s1.Access != "" || !sameUserID(s1.TechnicianID, in.FromUserID) {
		return nil, ErrTransferSessionNotHeld
	}
	now := s.now()
	if old := s.liveFor(tenantID, s1.ID); old != nil {
		switch {
		case old.State == TransferReleasing:
			return nil, ErrTransferReleasing
		case !now.Before(old.ExpiresAt):
			old.State = TransferExpired
			if err := s.recordAudit(ctx, tenantID, "", "session.transfer_expired", old, nil); err != nil {
				return nil, err
			}
		default:
			old.State = TransferSuperseded
			if err := s.recordAudit(ctx, tenantID, in.FromUserID, "session.transfer_superseded", old, nil); err != nil {
				return nil, err
			}
		}
	}
	t := &SessionTransfer{
		ID: newUUID(), TenantID: tenantID, SessionID: s1.ID, MachineID: s1.MachineID, GroupID: s1.MachineGroupID,
		FromUserID: s1.TechnicianID, ToUserID: in.ToUserID, Note: in.Note, State: TransferPending,
		CreatedAt: now, ExpiresAt: now.Add(transferOfferTTL),
	}
	s.transfers[transferKey(tenantID, t.ID)] = t
	if err := s.recordAudit(ctx, tenantID, in.FromUserID, "session.transfer_offered", t, nil); err != nil {
		return nil, err
	}
	cp := *t
	return &cp, nil
}

func (s *InMemorySessionTransferStore) Cancel(ctx context.Context, tenantID, id, actor string) (*SessionTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.get(tenantID, id)
	if t == nil {
		return nil, ErrTransferNotFound
	}
	if !sameUserID(t.FromUserID, actor) {
		return nil, ErrTransferForbidden
	}
	if t.State != TransferPending {
		cp := *t
		return &cp, ErrTransferNotPending
	}
	t.State = TransferCancelled
	if err := s.recordAudit(ctx, tenantID, actor, "session.transfer_cancelled", t, nil); err != nil {
		return nil, err
	}
	cp := *t
	return &cp, nil
}

func (s *InMemorySessionTransferStore) Get(_ context.Context, tenantID, id string) (*SessionTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.get(tenantID, id)
	if t == nil {
		return nil, ErrTransferNotFound
	}
	cp := *t
	return &cp, nil
}

func (s *InMemorySessionTransferStore) list(ctx context.Context, tenantID string, keep func(t *SessionTransfer, now time.Time) bool) []SessionTransfer {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := []SessionTransfer{}
	for _, t := range s.transfers {
		if t.TenantID == tenantID && keep(t, now) {
			out = append(out, *t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > transferListLimit {
		out = out[:transferListLimit]
	}
	return out
}

func (s *InMemorySessionTransferStore) ListIncoming(ctx context.Context, tenantID, userID string) ([]SessionTransfer, error) {
	return s.list(ctx, tenantID, func(t *SessionTransfer, now time.Time) bool {
		if t.State != TransferPending || !now.Before(t.ExpiresAt) || sameUserID(t.FromUserID, userID) {
			return false
		}
		if t.ToUserID != "" && !sameUserID(t.ToUserID, userID) {
			return false
		}
		s1, err := s.records.GetSession(ctx, tenantID, t.SessionID)
		return err == nil && s1.EndedAt == nil
	}), nil
}

func (s *InMemorySessionTransferStore) ListOutgoing(ctx context.Context, tenantID, userID string) ([]SessionTransfer, error) {
	return s.list(ctx, tenantID, func(t *SessionTransfer, now time.Time) bool {
		if !sameUserID(t.FromUserID, userID) {
			return false
		}
		return t.State == TransferReleasing || t.State == TransferPending && now.Before(t.ExpiresAt)
	}), nil
}

func (s *InMemorySessionTransferStore) Accept(ctx context.Context, tenantID, id, acceptor string) (*SessionTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.get(tenantID, id)
	if t == nil {
		return nil, ErrTransferNotFound
	}
	cp := func() *SessionTransfer { c := *t; return &c }
	if sameUserID(t.FromUserID, acceptor) || t.ToUserID != "" && !sameUserID(t.ToUserID, acceptor) {
		return nil, ErrTransferForbidden
	}
	switch t.State {
	case TransferReleasing, TransferAccepted, TransferFailed:
		if t.AcceptedBy != "" && sameUserID(t.AcceptedBy, acceptor) {
			return cp(), nil // a repeat accept is a status read
		}
	}
	if t.State != TransferPending {
		return cp(), ErrTransferNotPending
	}
	now := s.now()
	if !now.Before(t.ExpiresAt) {
		t.State = TransferExpired
		if err := s.recordAudit(ctx, tenantID, "", "session.transfer_expired", t, nil); err != nil {
			return nil, err
		}
		return cp(), ErrTransferExpired
	}
	s1, err := s.records.GetSession(ctx, tenantID, t.SessionID)
	if err != nil || s1.EndedAt != nil {
		return cp(), ErrTransferSessionEnded
	}
	t.State, t.AcceptedBy, t.ReleasingAt = TransferReleasing, acceptor, &now
	if err := s.recordAudit(ctx, tenantID, acceptor, "session.transfer_accepted", t, nil); err != nil {
		return nil, err
	}
	return cp(), nil
}

func (s *InMemorySessionTransferStore) Reconcile(ctx context.Context, tenantID, id string, admit TransferAdmitter) (*SessionTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.get(tenantID, id)
	if t == nil {
		return nil, ErrTransferNotFound
	}
	if err := s.reconcileLocked(ctx, tenantID, t, admit); err != nil {
		return nil, err
	}
	c := *t
	return &c, nil
}

// reconcileLocked is the in-memory twin of the pg reconcileTx. The caller holds s.mu.
func (s *InMemorySessionTransferStore) reconcileLocked(ctx context.Context, tenantID string, t *SessionTransfer, admit TransferAdmitter) error {
	now := s.now()
	switch t.State {
	case TransferPending:
		if !now.Before(t.ExpiresAt) {
			t.State = TransferExpired
			return s.recordAudit(ctx, tenantID, "", "session.transfer_expired", t, nil)
		}
	case TransferReleasing:
		s1, err := s.records.GetSession(ctx, tenantID, t.SessionID)
		if err != nil {
			return err
		}
		if s1.AgentEndedAt != nil {
			// Judged by when the report arrived, not when this runs (see the pg reconcileTx).
			if t.ReleasingAt != nil && s1.AgentEndedAt.After(t.ReleasingAt.Add(transferReleaseTimeout)) {
				return s.failLocked(ctx, tenantID, t, transferFailReleaseTimeout)
			}
			if admit == nil {
				return nil // the acceptor's poll (or the end report) finalizes
			}
			return s.finalizeLocked(ctx, tenantID, t, admit)
		}
		if t.ReleasingAt != nil && !now.Before(t.ReleasingAt.Add(transferReleaseTimeout)) {
			return s.failLocked(ctx, tenantID, t, transferFailReleaseTimeout)
		}
	}
	return nil
}

func (s *InMemorySessionTransferStore) failLocked(ctx context.Context, tenantID string, t *SessionTransfer, reason string) error {
	t.State, t.FailureReason = TransferFailed, reason
	return s.recordAudit(ctx, tenantID, "", "session.transfer_failed", t, map[string]any{"reason": reason})
}

// finalizeLocked ends S1 if it is still open, authorizes and admits S2, and completes the offer (or
// fails it) — the in-memory twin of the pg finalizeTx. The caller holds s.mu and has checked that the
// offer is releasing and S1 carries agent_ended_at.
func (s *InMemorySessionTransferStore) finalizeLocked(ctx context.Context, tenantID string, t *SessionTransfer, admit TransferAdmitter) error {
	adm, aerr := admit(ctx, t)
	var refused *TransferRefusedError
	if aerr != nil && !errors.As(aerr, &refused) {
		return aerr
	}
	var s2 *SessionRecord
	var limits SessionStartLimits
	if aerr == nil {
		s2, limits = adm.Rec, adm.Limits
	}
	now := s.now()
	// The pg finalizeTx is ONE transaction: a failure after its first write rolls back everything (S1's end,
	// S2's insert, the audit rows, the offer). The fake gets the same by running the offer + audit commit
	// INSIDE the session store's critical section: on an error there, the store restores S1 and removes S2,
	// and the offer is restored here; the audit rows go in as one atomic batch, so none survive either.
	prev := *t
	err := s.records.endAndAdmitForTransfer(tenantID, t.SessionID, s2, limits, now, func(endedS1 bool, admitErr error) error {
		var events []*MgmtAuditEvent
		if endedS1 {
			events = append(events, transferSessionEndEvent(t))
		}
		switch {
		case refused != nil:
			t.State, t.FailureReason = TransferFailed, refused.Reason
		case admitErr != nil:
			t.State, t.FailureReason = TransferFailed, admissionFailureReason(admitErr)
		default:
			t.State, t.NewSessionID = TransferAccepted, s2.ID
		}
		if t.State == TransferFailed {
			events = append(events, newTransferAuditEvent("", "session.transfer_failed", t, map[string]any{"reason": t.FailureReason}))
		} else {
			events = append(events, transferSessionStartEvent(t, s2.ID, adm.StartMeta))
		}
		if s.audit == nil {
			return nil
		}
		if err := appendAuditBatch(ctx, s.audit, tenantID, events); err != nil {
			*t = prev
			return err
		}
		return nil
	})
	// A non-business admission error (the pg finalizeTx returns it and rolls back) or a failed commit:
	// the store call has already undone S1 and S2, nothing was audited, the offer is unchanged.
	return err
}

// admissionFailureReason words an S2 admission failure for the offer's failure_reason.
func admissionFailureReason(err error) string {
	switch {
	case errors.Is(err, ErrConcurrentSessionLimit):
		return "concurrent session limit reached for this tenant"
	case errors.Is(err, ErrGroupConcurrentSessionLimit):
		return "concurrent session limit reached for this machine group"
	default:
		return fmt.Sprintf("the new session could not be started: %v", err)
	}
}

func (s *InMemorySessionTransferStore) RecordAgentEnded(ctx context.Context, tenantID, sessionID string, at time.Time, admit TransferAdmitter) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The store's own clock, like ReleasingAt: the release deadline compares the two (the pg store uses DB time).
	_ = at
	if err := s.records.stampAgentEnded(tenantID, sessionID, s.now()); err != nil {
		return err
	}
	for _, t := range s.transfers {
		if t.TenantID == tenantID && t.SessionID == sessionID && t.State == TransferReleasing {
			return s.reconcileLocked(ctx, tenantID, t, admit)
		}
	}
	return nil
}

func (s *InMemorySessionTransferStore) LiveForSession(_ context.Context, tenantID, sessionID string) (*SessionTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best *SessionTransfer
	for _, t := range s.transfers {
		if t.TenantID == tenantID && t.SessionID == sessionID && (t.State == TransferReleasing || t.State == TransferAccepted ||
			t.State == TransferFailed && t.ReleasingAt != nil) {
			if best == nil || t.CreatedAt.After(best.CreatedAt) {
				best = t
			}
		}
	}
	if best == nil {
		return nil, nil
	}
	c := *best
	return &c, nil
}

func (s *InMemorySessionTransferStore) ExpireStale(ctx context.Context, tenantID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	now := s.now()
	for _, t := range s.transfers {
		if t.TenantID != tenantID {
			continue
		}
		switch {
		case t.State == TransferPending && !now.Before(t.ExpiresAt):
			t.State = TransferExpired
			if err := s.recordAudit(ctx, tenantID, "", "session.transfer_expired", t, nil); err != nil {
				return n, err
			}
			n++
		case t.State == TransferReleasing && t.ReleasingAt != nil && !now.Before(t.ReleasingAt.Add(transferReleaseTimeout)):
			s1, err := s.records.GetSession(ctx, tenantID, t.SessionID)
			if err == nil && s1.AgentEndedAt == nil {
				if err := s.failLocked(ctx, tenantID, t, transferFailReleaseTimeout); err != nil {
					return n, err
				}
				n++
			}
		}
	}
	return n, nil
}

// stampAgentEnded records the agent's end report on S1: first report wins, a duplicate changes nothing.
func (s *InMemorySessionRecordStore) stampAgentEnded(tenantID, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[sessionRecordKey(tenantID, id)]
	if !ok {
		return ErrSessionRecordNotFound
	}
	if r.AgentEndedAt == nil {
		t := at
		r.AgentEndedAt = &t
	}
	return nil
}

// endAndAdmitForTransfer is the in-memory twin of the pg finalize's single transaction: under ONE lock
// it ends S1 if still open (end_reason 'transferred'; an S1 the report already closed only gets the
// reason), then admits s2 (when non-nil) with the counts seeing S1 ended. S1's end stands even when the
// admission is refused for a business reason: the agent has already said it is gone.
//
// Like the pg transaction, an admission error that is not a business refusal (isBusinessAdmissionFailure)
// discards S1's end too, and so does an error from commit (the caller's offer + audit writes, run under
// the same lock once admission is settled): S1 is restored, S2 removed, and the error is returned. A refusal
// (s2 == nil) never takes the group-tree lock, as pg only takes it inside admitSessionTx.
func (s *InMemorySessionRecordStore) endAndAdmitForTransfer(tenantID, s1ID string, s2 *SessionRecord, limits SessionStartLimits, at time.Time,
	commit func(endedS1 bool, admitErr error) error) (err error) {
	var endedS1 bool
	var admitErr error
	body := func(tree GroupTree) error {
		var undo func()
		if r, ok := s.records[sessionRecordKey(tenantID, s1ID)]; ok {
			prevEnded, prevReason := r.EndedAt, r.EndReason
			undo = func() { r.EndedAt, r.EndReason = prevEnded, prevReason }
			if r.EndedAt == nil {
				end := at
				r.EndedAt = &end
				endedS1 = true
			}
			if r.EndReason == "" {
				r.EndReason = "transferred"
			}
		}
		discard := func() {
			if undo != nil {
				undo()
			}
			endedS1 = false
		}
		inserted := false
		if s2 != nil {
			if aerr := normalizeSessionRecordAccess(s2); aerr != nil {
				admitErr = aerr
			} else {
				admitErr = s.admitLocked(tenantID, s2, s.authoritativeLimits(tenantID, s2, limits, tree))
				inserted = admitErr == nil
			}
		}
		if admitErr != nil && !isBusinessAdmissionFailure(admitErr) {
			discard()
			err = admitErr // pg returns it and rolls back; the offer stays releasing for a retry
			return nil
		}
		if cerr := commit(endedS1, admitErr); cerr != nil {
			if inserted {
				delete(s.records, sessionRecordKey(tenantID, s2.ID))
			}
			discard()
			err = cerr
		}
		return nil
	}
	if s2 == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = body(nil)
		return err
	}
	ran := false
	treeErr := s.admitWithCurrentTree(tenantID, func(tree GroupTree) error {
		ran = true
		return body(tree)
	})
	if !ran && treeErr != nil {
		return treeErr // the tree lock failed before anything was touched (pg: ErrGroupTreeChanged rolls back)
	}
	return err
}
