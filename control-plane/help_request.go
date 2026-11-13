package controlplane

// Guest-initiated help requests from enrolled machines (docs/64, binding contracts H-C1..H-C7).
//
// An enrolled agent that holds an AUTHENTICATED signaling socket asks for help; signaling forwards the
// request with the identity it already verified (the same hop and the same authorization as
// guest_end.go). The request lands in a group-scoped queue; a technician whose CURRENT coverage of the
// machine's CURRENT group allows starting a session accepts it, and accepting creates the session bound
// to that one request in the same transaction (H-C1).
//
// What this file owns: the request model, the contract constants, the store seam and its in-memory fake.
// The Postgres twin is pgstore_help_request.go; the two are driven by ONE shared test suite
// (help_request_test.go). The HTTP surface is http_help_request.go.

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// HelpRequestFeature is advertised by GET /internal/capabilities when the help-request internal routes
// are mounted. Signaling advertises "help_request_v1" to agents only after a positive probe.
const HelpRequestFeature = "help_request_v1"

// Help request lifecycle (help_request.status, migration 0069).
const (
	HelpStatusOpen      = "open"
	HelpStatusAccepted  = "accepted"
	HelpStatusCancelled = "cancelled"
	HelpStatusExpired   = "expired"
)

// Delivery states of an accepted request (help_request.delivery).
const (
	HelpDeliveryPending   = "pending"
	HelpDeliveryDelivered = "delivered"
)

// Cancel reasons recorded on a cancelled request.
const (
	HelpCancelGuest       = "guest"
	HelpCancelRetired     = "machine_retired"
	HelpCancelQuarantined = "machine_quarantined"
	HelpCancelSuperseded  = "superseded"
	// HelpCancelReactivated: the machine went from retired / quarantined back to active; a request still
	// open from before the change is closed rather than becoming acceptable again.
	HelpCancelReactivated = "machine_reactivated"
	// HelpCancelCapacity: a compensating reopen would have pushed the tenant's open queue above its cap.
	HelpCancelCapacity = "capacity"
)

// The audit actions this feature records (recordMgmtAudit / appended in the transition's transaction).
const (
	AuditHelpRequested = "help.requested"
	AuditHelpCancelled = "help.cancelled"
	AuditHelpAccepted  = "help.accepted"
	AuditHelpExpired   = "help.expired"
	AuditHelpReopened  = "help.reopened"
)

// The contract numbers (docs/64 D4, H-C2, H-C3, H-C6). Variables only so tests can read them; nothing
// reassigns them.
const (
	helpRequestTTL        = 30 * time.Minute
	helpNoteMaxRunes      = 200
	helpOpMaxLen          = 64
	helpOpDedupWindow     = 24 * time.Hour
	helpDeviceHourlyLimit = 3
	helpDeviceDailyLimit  = 10
	// helpDeviceCallsPerHour meters EVERY create call of a device (replay, already-open or fresh) per UTC
	// hour: the creation budgets above never see a device that loops on a replayed op_id.
	helpDeviceCallsPerHour = 30
	helpLimitScopeDevCalls = "device_calls"
	helpTenantHourlyLimit  = 200
	helpTenantOpenCap      = 100
	helpClosedRetention    = 30 * 24 * time.Hour
	helpCurrentLookback    = 24 * time.Hour
	helpExpireBatch        = 500
	helpLimitScopeDevHour  = "device_hour"
	helpLimitScopeDevDay   = "device_day"
	helpLimitScopeTenHour  = "tenant_hour"
	helpLimitScopeTenOpen  = "tenant_open"
	helpSweepTenantsPerRun = 200
)

var (
	// ErrHelpRequestNotFound: the id does not name a request this caller may address (unknown, another
	// tenant's, or another device's - deliberately indistinguishable).
	ErrHelpRequestNotFound = errors.New("help request not found")
	// ErrHelpMachineIneligible: the device has no machine, or the machine is retired, quarantined or an
	// ephemeral attended guest.
	ErrHelpMachineIneligible = errors.New("machine cannot request help")
	// ErrHelpTenantSuspended: the tenant is suspended; nothing is created.
	ErrHelpTenantSuspended = errors.New("tenant suspended")
	// ErrHelpInvalidOp: op_id is empty, too long or has characters outside [A-Za-z0-9._:-].
	ErrHelpInvalidOp = errors.New("invalid op_id")
)

// HelpLimitError is the explicit overload refusal (H-C2): which budget is spent and when it frees up.
type HelpLimitError struct {
	Scope      string
	RetryAfter time.Duration
}

func (e *HelpLimitError) Error() string { return "help request limit reached (" + e.Scope + ")" }

// HelpRequest is one request. Group scope is NEVER read from GroupID: it is the group the machine had
// when the request was made, kept for display. Authorization evaluates the machine's current group.
type HelpRequest struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	MachineID    string     `json:"machine_id"`
	DeviceID     string     `json:"device_id"`
	GroupID      string     `json:"group_id,omitempty"`
	Note         string     `json:"note"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	ClosedAt     *time.Time `json:"closed_at,omitempty"`
	AcceptedBy   string     `json:"accepted_by,omitempty"`
	AcceptedAt   *time.Time `json:"accepted_at,omitempty"`
	SessionID    string     `json:"session_id,omitempty"`
	CancelReason string     `json:"cancel_reason,omitempty"`
	// Delivery is the persisted outcome of issuing the accepted request's session ticket: HelpDeliveryPending
	// from the accept until the accepting handler marks it delivered (or claims it to compensate).
	Delivery string `json:"delivery,omitempty"`
	// acceptOp is the accepting technician's idempotency key (fake only; pg: help_request.accept_op).
	acceptOp string
}

// HelpRequestWithMachine is a request joined with the machine's CURRENT state: the row the technician
// side authorizes and renders from.
type HelpRequestWithMachine struct {
	HelpRequest
	MachineName    string
	MachineAlias   string
	MachineGroupID string // the machine's CURRENT group (authorization key)
	MachineStatus  string
	MachineDevice  string
}

// HelpResult carries the audit events a store call committed, so the caller can dispatch webhooks
// after the commit (at-least-once; never promised exactly-once, H-C6).
type HelpResult struct {
	Events []*MgmtAuditEvent
}

// HelpCreateResult is the outcome of CreateForDevice.
type HelpCreateResult struct {
	HelpResult
	Request *HelpRequest
	// Created is true only when this call inserted a new row. A replayed op_id or a second request while
	// one is open returns the existing row with Created == false (and counts against no budget).
	Created  bool
	Replayed bool
}

// HelpTransitionResult is the outcome of a cancel / reopen / current-state call.
type HelpTransitionResult struct {
	HelpResult
	Request *HelpRequest // current state after the call (nil only for "none")
	Changed bool         // this call performed the transition
	// Conflict: the request is in a state this call may not change (accepted / expired for a cancel). The
	// first committed transition wins; the rest get this, with the current state in Request (H-C3).
	Conflict bool
}

// HelpAcceptInput is everything the handler resolved BEFORE the transaction (admission against the
// machine's group at that moment). The store re-reads the machine inside the transaction and refuses
// when its group moved (HelpAcceptGroupChanged), so the admission the handler computed is never applied
// to a machine that has since changed hands.
type HelpAcceptInput struct {
	RequestID        string
	TechnicianID     string
	OpID             string // optional idempotency key: a retry with the same key returns the same session
	Record           *SessionRecord
	Limits           SessionStartLimits
	AdmissionGroupID string
	Now              time.Time
	// Presence answers whether a device is online RIGHT NOW. A FRESH accept (not a replay of the caller's own
	// accept) requires POSITIVE online evidence, evaluated inside the accept admission after the request and
	// machine rows are locked: nil, an error or a missing snapshot is HelpPresenceUnknown and refuses.
	Presence func(device string) HelpPresence
}

// HelpPresence is the answer to "is this machine online": only HelpPresenceOnline lets a fresh accept proceed.
type HelpPresence int

const (
	HelpPresenceUnknown HelpPresence = iota
	HelpPresenceOnline
	HelpPresenceOffline
)

func (in *HelpAcceptInput) presenceOf(device string) HelpPresence {
	if in.Presence == nil {
		return HelpPresenceUnknown
	}
	return in.Presence(device)
}

// HelpAcceptOutcome says what an accept did.
type HelpAcceptOutcome string

const (
	HelpAcceptAccepted        HelpAcceptOutcome = "accepted"
	HelpAcceptReplayed        HelpAcceptOutcome = "replayed"
	HelpAcceptNotFound        HelpAcceptOutcome = "not_found"
	HelpAcceptConflict        HelpAcceptOutcome = "conflict" // not open any more; Request holds the current state
	HelpAcceptIneligible      HelpAcceptOutcome = "ineligible"
	HelpAcceptGroupChanged    HelpAcceptOutcome = "group_changed"
	HelpAcceptOffline         HelpAcceptOutcome = "offline"          // presence says the machine is offline
	HelpAcceptPresenceUnknown HelpAcceptOutcome = "presence_unknown" // no positive online evidence: retryable
)

// HelpAcceptResult is the outcome of Accept. Record is the bound session on accepted / replayed.
type HelpAcceptResult struct {
	HelpResult
	Outcome HelpAcceptOutcome
	Request *HelpRequest
	Record  *SessionRecord
}

// HelpSweepEvent is an audit event a sweep committed, with the tenant to dispatch it for.
type HelpSweepEvent struct {
	TenantID string
	Event    *MgmtAuditEvent
}

// HelpSweepResult is one background sweep's work.
type HelpSweepResult struct {
	Tenants int
	Expired int
	Pruned  int
	Events  []HelpSweepEvent
}

// HelpRequestStore is the persistence seam. Every method is tenant-scoped by the caller-supplied tenant
// id (and, in pgx, by RLS); `now` is passed in so the fake and the database agree on one clock.
//
// EXPIRY IS APPLIED LAZILY INSIDE EVERY METHOD THAT COUNTS OR DECIDES (H-C6): an `open` row whose
// expires_at has passed is transitioned to `expired` (with its audit row, in the same transaction)
// BEFORE the method counts, lists or accepts. The background Sweep only keeps the table tidy.
type HelpRequestStore interface {
	// CreateForDevice makes the device's request. Order: the durable per-device CALL budget (every call,
	// whatever it ends up doing, H-C2); expire; op_id replay (24 h) returns the same request whatever its
	// state; an existing OPEN request for the machine is returned unchanged and records NO op row; only when
	// a row must be INSERTED is the per-tenant lock taken, and the durable creation budgets (H-C2) and the
	// tenant open cap are checked under it. Errors: ErrHelpMachineIneligible, ErrHelpTenantSuspended,
	// ErrHelpInvalidOp, *HelpLimitError.
	CreateForDevice(ctx context.Context, tenantID, deviceID, opID, note string, now time.Time) (*HelpCreateResult, error)
	// CancelForDevice cancels exactly one request, only if it belongs to the device's machine.
	CancelForDevice(ctx context.Context, tenantID, deviceID, requestID string, now time.Time) (*HelpTransitionResult, error)
	// CurrentForDevice is the agent's state query: its open request, else its most recent one within
	// 24 h, else Request == nil.
	CurrentForDevice(ctx context.Context, tenantID, deviceID string, now time.Time) (*HelpTransitionResult, error)
	// ListOpen lists the tenant's open requests joined with each machine's CURRENT group. The caller
	// filters by AllowsInGroup; the store never decides who may see a row.
	ListOpen(ctx context.Context, tenantID string, now time.Time) ([]HelpRequestWithMachine, *HelpResult, error)
	// Get resolves one request (any state) joined with its machine, after lazy expiry.
	Get(ctx context.Context, tenantID, requestID string, now time.Time) (*HelpRequestWithMachine, *HelpResult, error)
	// Accept is H-C1: recheck open + unexpired, the machine's eligibility and current group, admit and
	// insert the session, and mark the request accepted with that session id - one transaction.
	Accept(ctx context.Context, tenantID string, in HelpAcceptInput) (*HelpAcceptResult, error)
	// MarkDelivered is the compare-and-swap pending -> delivered of an accepted request's session ticket.
	// Not Changed: the request is no longer accepted-and-pending for that session; Request is the current state.
	MarkDelivered(ctx context.Context, tenantID, requestID, sessionID string, now time.Time) (*HelpTransitionResult, error)
	// ReopenAfterFailedStart returns an accepted request whose session never reached the technician to
	// `open` (or expired / cancelled-as-superseded), with an audit row.
	ReopenAfterFailedStart(ctx context.Context, tenantID, requestID, sessionID string, now time.Time) (*HelpTransitionResult, error)
	// CancelForMachine cancels the machine's open request (retire / quarantine, H-C5).
	CancelForMachine(ctx context.Context, tenantID, machineID, reason string, now time.Time) (*HelpResult, error)
	// Sweep expires due requests, prunes closed requests older than 30 days and the op ledger.
	Sweep(ctx context.Context, now time.Time) (*HelpSweepResult, error)
}

// ---------------------------------------------------------------------------------------------------
// Shared normalization and helpers (used by BOTH stores, so they cannot drift).
// ---------------------------------------------------------------------------------------------------

// normalizeHelpNote makes the guest's note safe to store and render: invalid UTF-8 replaced, whitespace
// controls turned into spaces, every other control and format character (bidi overrides included)
// dropped, trimmed, and capped at helpNoteMaxRunes RUNES. It is ALWAYS rendered as plain text labelled
// "from the guest's machine".
func normalizeHelpNote(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			r = ' '
		case r == 0x7f || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) ||
			unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r):
			continue
		}
		b.WriteRune(r)
	}
	out := []rune(strings.TrimSpace(b.String()))
	if len(out) > helpNoteMaxRunes {
		out = out[:helpNoteMaxRunes]
	}
	return strings.TrimSpace(string(out))
}

// validHelpOpID: 1..64 bytes of [A-Za-z0-9._:-] (UUIDs and ULIDs pass).
func validHelpOpID(op string) bool {
	if op == "" || len(op) > helpOpMaxLen {
		return false
	}
	for i := 0; i < len(op); i++ {
		c := op[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

// helpAuditEvent builds one help-request audit event (target kind help_request).
func helpAuditEvent(action, requestID, actor string, meta map[string]any) *MgmtAuditEvent {
	raw, err := json.Marshal(meta)
	if err != nil {
		raw = json.RawMessage("{}")
	}
	return &MgmtAuditEvent{
		ActorUserID: actor, Action: action, TargetKind: "help_request", TargetID: requestID, Metadata: raw,
	}
}

// helpDeviceMeta is the metadata every DEVICE-initiated transition carries: an enrolled-device assertion
// relayed by signaling, never proof of a person or of consent (H-C7).
func helpDeviceMeta(req *HelpRequest, extra map[string]any) map[string]any {
	m := map[string]any{
		"actor_kind": "device", "device_id": req.DeviceID, "machine_id": req.MachineID,
		"via": "signaling", "requested_from": "machine",
	}
	if req.GroupID != "" {
		m["group_id"] = req.GroupID
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// helpAcceptedMeta is the metadata of an accept: a USER action on a request the machine made.
func helpAcceptedMeta(req *HelpRequest, groupID, sessionID string) map[string]any {
	return map[string]any{
		"actor_kind": "user", "machine_id": req.MachineID, "device_id": req.DeviceID,
		"group_id": groupID, "session_id": sessionID, "requested_from": "machine",
	}
}

// helpRetryAfter: with `times` the creations still inside the window (all >= now-window), how long until
// fewer than `limit` remain.
func helpRetryAfter(times []time.Time, limit int, window time.Duration, now time.Time) time.Duration {
	if len(times) < limit {
		return 0
	}
	asc := append([]time.Time(nil), times...)
	sort.Slice(asc, func(i, j int) bool { return asc[i].Before(asc[j]) })
	k := len(asc) - limit // index of the entry whose expiry frees a slot
	d := asc[k].Add(window).Sub(now)
	if d < time.Second {
		d = time.Second
	}
	return d
}

func helpClip(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

// helpCallBucket is the UTC hour a create call is counted in.
func helpCallBucket(now time.Time) time.Time { return now.UTC().Truncate(time.Hour) }

// helpCallLimitError is the 429 for a device whose create calls in this hour exceed the budget: it frees up
// when the hour turns over.
func helpCallLimitError(now time.Time) *HelpLimitError {
	d := helpCallBucket(now).Add(time.Hour).Sub(now)
	if d < time.Second {
		d = time.Second
	}
	return &HelpLimitError{Scope: helpLimitScopeDevCalls, RetryAfter: d}
}

// ---------------------------------------------------------------------------------------------------
// InMemoryHelpRequestStore - the fake. It agrees with the Postgres store on every rule above; the shared
// suite runs against both.
// ---------------------------------------------------------------------------------------------------

type helpOpKey struct{ tenant, device, op string }
type helpCallKey struct {
	tenant, device string
	bucket         time.Time
}
type helpOpVal struct {
	requestID string
	at        time.Time
}

type helpPending struct {
	tenant string
	e      *MgmtAuditEvent
}

// helpTxn tracks what ONE fake call has written outside its own tables, so a failure part-way can undo it:
// audit rows (by chain hash) and admitted sessions. The fake must be atomic like the Postgres transaction.
type helpTxn struct {
	pending  []helpPending              // audit rows staged by record, appended at commit (atomically per tenant)
	events   map[string]map[string]bool // tenant -> event hashes already committed (undone if a later tenant's batch fails)
	sessions []struct{ tenant, id string }
}

type InMemoryHelpRequestStore struct {
	txn      *helpTxn
	mu       sync.Mutex
	machines MachineStore
	sessions SessionRecordStore
	audit    MgmtAuditStore
	reqs     []*HelpRequest
	ops      map[helpOpKey]helpOpVal
	calls    map[helpCallKey]int
}

// NewInMemoryHelpRequestStore wires the fake to the stores it consults: machines (eligibility and the
// CURRENT group), sessions (accept admits through the same store POST /sessions uses) and audit
// (optional; nil records nothing).
func NewInMemoryHelpRequestStore(machines MachineStore, sessions SessionRecordStore, audit MgmtAuditStore) *InMemoryHelpRequestStore {
	return &InMemoryHelpRequestStore{machines: machines, sessions: sessions, audit: audit,
		ops: map[helpOpKey]helpOpVal{}, calls: map[helpCallKey]int{}}
}

var _ HelpRequestStore = (*InMemoryHelpRequestStore)(nil)

// begin snapshots the fake's tables and returns the guard every transactional method defers with its named
// error: on failure the requests and the op ledger are restored, the audit rows this call recorded are removed
// and the sessions it admitted are discarded. (The per-device CALL counter is deliberately NOT restored: in
// Postgres it is its own committed transaction.) The caller holds s.mu.
func (s *InMemoryHelpRequestStore) begin() func(*error) {
	reqs := make([]*HelpRequest, len(s.reqs))
	for i, r := range s.reqs {
		reqs[i] = s.copyOf(r)
		reqs[i].acceptOp = r.acceptOp
	}
	ops := make(map[helpOpKey]helpOpVal, len(s.ops))
	for k, v := range s.ops {
		ops[k] = v
	}
	t := &helpTxn{events: map[string]map[string]bool{}}
	s.txn = t
	return func(errp *error) {
		s.txn = nil
		if *errp == nil {
			*errp = s.flush(t)
		}
		if *errp == nil {
			return
		}
		s.reqs, s.ops = reqs, ops
		if a, ok := s.audit.(interface {
			discardEvents(string, map[string]bool)
		}); ok {
			for tenant, hashes := range t.events {
				a.discardEvents(tenant, hashes)
			}
		}
		if ss, ok := s.sessions.(interface{ discardSession(string, string) }); ok {
			for _, x := range t.sessions {
				ss.discardSession(x.tenant, x.id)
			}
		}
	}
}

// flush appends the staged audit rows, one atomic batch per tenant in first-seen order. A failing batch commits
// nothing of its own; the batches of tenants already flushed are recorded in t.events so the rollback in begin
// discards them (only a multi-tenant sweep can have more than one).
func (s *InMemoryHelpRequestStore) flush(t *helpTxn) error {
	var order []string
	by := map[string][]*MgmtAuditEvent{}
	for _, p := range t.pending {
		if _, ok := by[p.tenant]; !ok {
			order = append(order, p.tenant)
		}
		by[p.tenant] = append(by[p.tenant], p.e)
	}
	for _, tenant := range order {
		if err := appendAuditBatch(context.Background(), s.audit, tenant, by[tenant]); err != nil {
			return err
		}
		t.events[tenant] = map[string]bool{}
		for _, e := range by[tenant] {
			t.events[tenant][e.Hash] = true
		}
	}
	return nil
}

func (s *InMemoryHelpRequestStore) record(ctx context.Context, tenantID string, res *HelpResult, e *MgmtAuditEvent) error {
	if s.audit != nil {
		if s.txn != nil {
			// Staged, not appended: the transition's rows go in together at commit (flush), so a concurrent
			// same-tenant writer cannot land between them and a rollback never deletes a link others chain to.
			s.txn.pending = append(s.txn.pending, helpPending{tenantID, e})
		} else if err := s.audit.RecordEvent(ctx, tenantID, e); err != nil {
			return err
		}
	}
	res.Events = append(res.Events, e)
	return nil
}

func (s *InMemoryHelpRequestStore) find(tenantID, id string) *HelpRequest {
	id = canonicalUUIDish(id)
	for _, r := range s.reqs {
		if r.TenantID == tenantID && r.ID == id {
			return r
		}
	}
	return nil
}

func (s *InMemoryHelpRequestStore) openFor(tenantID, machineID string) *HelpRequest {
	for _, r := range s.reqs {
		if r.TenantID == tenantID && r.MachineID == machineID && r.Status == HelpStatusOpen {
			return r
		}
	}
	return nil
}

func (s *InMemoryHelpRequestStore) closeAs(r *HelpRequest, status, reason string, now time.Time) {
	t := helpClip(now)
	r.Status, r.CancelReason, r.ClosedAt = status, reason, &t
}

// expireLocked transitions every due open request of the tenant to expired, with its audit row.
func (s *InMemoryHelpRequestStore) expireLocked(ctx context.Context, tenantID string, now time.Time, res *HelpResult) error {
	for _, r := range s.reqs {
		if r.TenantID == tenantID && r.Status == HelpStatusOpen && !now.Before(r.ExpiresAt) {
			s.closeAs(r, HelpStatusExpired, "", now)
			if err := s.record(ctx, tenantID, res, helpAuditEvent(AuditHelpExpired, r.ID, "",
				helpDeviceMeta(r, map[string]any{"reason": "ttl"}))); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *InMemoryHelpRequestStore) copyOf(r *HelpRequest) *HelpRequest {
	if r == nil {
		return nil
	}
	c := *r
	if r.ClosedAt != nil {
		t := *r.ClosedAt
		c.ClosedAt = &t
	}
	if r.AcceptedAt != nil {
		t := *r.AcceptedAt
		c.AcceptedAt = &t
	}
	return &c
}

// CreateForDevice implements HelpRequestStore.
func (s *InMemoryHelpRequestStore) CreateForDevice(ctx context.Context, tenantID, deviceID, opID, note string, now time.Time) (_ *HelpCreateResult, err error) {
	if !validHelpOpID(opID) {
		return nil, ErrHelpInvalidOp
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.begin()(&err)
	// The CALL budget comes first and counts every call, including refused and replayed ones.
	ck := helpCallKey{tenantID, deviceID, helpCallBucket(now)}
	s.calls[ck]++
	if s.calls[ck] > helpDeviceCallsPerHour {
		return nil, helpCallLimitError(now)
	}
	m, err := s.machines.GetMachine(ctx, tenantID, deviceID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			return nil, ErrHelpMachineIneligible
		}
		return nil, err
	}
	if m.Ephemeral || (m.Status != "" && m.Status != MachineStatusActive) {
		return nil, ErrHelpMachineIneligible
	}
	out := &HelpCreateResult{}
	if err := s.expireLocked(ctx, tenantID, now, &out.HelpResult); err != nil {
		return nil, err
	}
	key := helpOpKey{tenantID, m.DeviceID, opID}
	if op, ok := s.ops[key]; ok && now.Sub(op.at) < helpOpDedupWindow {
		if r := s.find(tenantID, op.requestID); r != nil {
			out.Request, out.Replayed = s.copyOf(r), true
			return out, nil
		}
	}
	if r := s.openFor(tenantID, m.ID); r != nil {
		// Records NO op row: a device cannot grow the ledger by cycling op ids against its open request.
		out.Request, out.Replayed = s.copyOf(r), true
		return out, nil
	}
	var devHour, devDay, tenHour []time.Time
	open := 0
	for _, r := range s.reqs {
		if r.TenantID != tenantID {
			continue
		}
		if r.Status == HelpStatusOpen {
			open++
		}
		if r.CreatedAt.After(now.Add(-time.Hour)) {
			tenHour = append(tenHour, r.CreatedAt)
		}
		if r.DeviceID == m.DeviceID {
			if r.CreatedAt.After(now.Add(-time.Hour)) {
				devHour = append(devHour, r.CreatedAt)
			}
			if r.CreatedAt.After(now.Add(-24 * time.Hour)) {
				devDay = append(devDay, r.CreatedAt)
			}
		}
	}
	switch {
	case len(devHour) >= helpDeviceHourlyLimit:
		return nil, &HelpLimitError{helpLimitScopeDevHour, helpRetryAfter(devHour, helpDeviceHourlyLimit, time.Hour, now)}
	case len(devDay) >= helpDeviceDailyLimit:
		return nil, &HelpLimitError{helpLimitScopeDevDay, helpRetryAfter(devDay, helpDeviceDailyLimit, 24*time.Hour, now)}
	case len(tenHour) >= helpTenantHourlyLimit:
		return nil, &HelpLimitError{helpLimitScopeTenHour, helpRetryAfter(tenHour, helpTenantHourlyLimit, time.Hour, now)}
	case open >= helpTenantOpenCap:
		return nil, &HelpLimitError{helpLimitScopeTenOpen, time.Minute}
	}
	r := &HelpRequest{
		ID: newUUID(), TenantID: tenantID, MachineID: m.ID, DeviceID: m.DeviceID, GroupID: m.GroupID,
		Note: normalizeHelpNote(note), Status: HelpStatusOpen,
		CreatedAt: helpClip(now), ExpiresAt: helpClip(now.Add(helpRequestTTL)),
	}
	s.reqs = append(s.reqs, r)
	s.ops[key] = helpOpVal{r.ID, now}
	if err := s.record(ctx, tenantID, &out.HelpResult, helpAuditEvent(AuditHelpRequested, r.ID, "",
		helpDeviceMeta(r, map[string]any{"note_length": len([]rune(r.Note))}))); err != nil {
		return nil, err
	}
	out.Request, out.Created = s.copyOf(r), true
	return out, nil
}

// machineForDevice resolves the device's machine row or ErrHelpRequestNotFound.
func (s *InMemoryHelpRequestStore) machineForDevice(ctx context.Context, tenantID, deviceID string) (*Machine, error) {
	m, err := s.machines.GetMachine(ctx, tenantID, deviceID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			return nil, ErrHelpRequestNotFound
		}
		return nil, err
	}
	return m, nil
}

// CancelForDevice implements HelpRequestStore.
func (s *InMemoryHelpRequestStore) CancelForDevice(ctx context.Context, tenantID, deviceID, requestID string, now time.Time) (_ *HelpTransitionResult, err error) {
	if _, ok := parsePgUUID(requestID); !ok {
		return nil, ErrHelpRequestNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.begin()(&err)
	m, err := s.machineForDevice(ctx, tenantID, deviceID)
	if err != nil {
		return nil, err
	}
	out := &HelpTransitionResult{}
	if err := s.expireLocked(ctx, tenantID, now, &out.HelpResult); err != nil {
		return nil, err
	}
	r := s.find(tenantID, requestID)
	if r == nil || r.MachineID != m.ID {
		return nil, ErrHelpRequestNotFound
	}
	switch r.Status {
	case HelpStatusOpen:
		s.closeAs(r, HelpStatusCancelled, HelpCancelGuest, now)
		if err := s.record(ctx, tenantID, &out.HelpResult, helpAuditEvent(AuditHelpCancelled, r.ID, "",
			helpDeviceMeta(r, map[string]any{"reason": HelpCancelGuest}))); err != nil {
			return nil, err
		}
		out.Changed = true
	case HelpStatusCancelled:
		// the same transition repeated (a retried cancel): idempotent
	default:
		out.Conflict = true
	}
	out.Request = s.copyOf(r)
	return out, nil
}

// CurrentForDevice implements HelpRequestStore.
func (s *InMemoryHelpRequestStore) CurrentForDevice(ctx context.Context, tenantID, deviceID string, now time.Time) (_ *HelpTransitionResult, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.begin()(&err)
	m, err := s.machineForDevice(ctx, tenantID, deviceID)
	if err != nil {
		if errors.Is(err, ErrHelpRequestNotFound) {
			return &HelpTransitionResult{}, nil
		}
		return nil, err
	}
	out := &HelpTransitionResult{}
	if err := s.expireLocked(ctx, tenantID, now, &out.HelpResult); err != nil {
		return nil, err
	}
	var best *HelpRequest
	for _, r := range s.reqs {
		if r.TenantID != tenantID || r.MachineID != m.ID || !r.CreatedAt.After(now.Add(-helpCurrentLookback)) {
			continue
		}
		if r.Status == HelpStatusOpen {
			best = r
			break
		}
		if best == nil || r.CreatedAt.After(best.CreatedAt) {
			best = r
		}
	}
	out.Request = s.copyOf(best)
	return out, nil
}

func (s *InMemoryHelpRequestStore) withMachine(ctx context.Context, r *HelpRequest) (*HelpRequestWithMachine, error) {
	m, err := s.machines.GetMachineByID(ctx, r.TenantID, r.MachineID)
	if err != nil {
		return nil, err
	}
	return &HelpRequestWithMachine{HelpRequest: *s.copyOf(r), MachineName: m.Name, MachineAlias: m.Alias,
		MachineGroupID: m.GroupID, MachineStatus: m.Status, MachineDevice: m.DeviceID}, nil
}

// ListOpen implements HelpRequestStore.
func (s *InMemoryHelpRequestStore) ListOpen(ctx context.Context, tenantID string, now time.Time) (_ []HelpRequestWithMachine, _ *HelpResult, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.begin()(&err)
	res := &HelpResult{}
	if err := s.expireLocked(ctx, tenantID, now, res); err != nil {
		return nil, nil, err
	}
	var out []HelpRequestWithMachine
	for _, r := range s.reqs {
		if r.TenantID != tenantID || r.Status != HelpStatusOpen {
			continue
		}
		v, err := s.withMachine(ctx, r)
		if err != nil {
			if errors.Is(err, ErrMachineNotFound) {
				continue
			}
			return nil, nil, err
		}
		out = append(out, *v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, res, nil
}

// Get implements HelpRequestStore.
func (s *InMemoryHelpRequestStore) Get(ctx context.Context, tenantID, requestID string, now time.Time) (_ *HelpRequestWithMachine, _ *HelpResult, err error) {
	if _, ok := parsePgUUID(requestID); !ok {
		return nil, nil, ErrHelpRequestNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.begin()(&err)
	res := &HelpResult{}
	if err := s.expireLocked(ctx, tenantID, now, res); err != nil {
		return nil, nil, err
	}
	r := s.find(tenantID, requestID)
	if r == nil {
		return nil, res, ErrHelpRequestNotFound
	}
	v, err := s.withMachine(ctx, r)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			return nil, res, ErrHelpRequestNotFound
		}
		return nil, nil, err
	}
	return v, res, nil
}

// Accept implements HelpRequestStore.
func (s *InMemoryHelpRequestStore) Accept(ctx context.Context, tenantID string, in HelpAcceptInput) (_ *HelpAcceptResult, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.begin()(&err)
	out := &HelpAcceptResult{Outcome: HelpAcceptNotFound}
	r := s.find(tenantID, in.RequestID)
	if r == nil {
		return out, nil
	}
	// A retry of the SAME accept (same technician, same idempotency key) returns the same session.
	if r.Status == HelpStatusAccepted && in.OpID != "" && r.AcceptedBy == in.TechnicianID && r.acceptOp == in.OpID {
		rec, err := s.sessions.GetSession(ctx, tenantID, r.SessionID)
		if err == nil {
			out.Outcome, out.Request, out.Record = HelpAcceptReplayed, s.copyOf(r), rec
			return out, nil
		}
	}
	if r.Status == HelpStatusOpen && !in.Now.Before(r.ExpiresAt) {
		s.closeAs(r, HelpStatusExpired, "", in.Now)
		if err := s.record(ctx, tenantID, &out.HelpResult, helpAuditEvent(AuditHelpExpired, r.ID, "",
			helpDeviceMeta(r, map[string]any{"reason": "ttl"}))); err != nil {
			return nil, err
		}
	}
	if r.Status != HelpStatusOpen {
		out.Outcome, out.Request = HelpAcceptConflict, s.copyOf(r)
		return out, nil
	}
	m, err := s.machines.GetMachineByID(ctx, tenantID, r.MachineID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			out.Outcome = HelpAcceptNotFound
			return out, nil
		}
		return nil, err
	}
	if m.Ephemeral || (m.Status != "" && m.Status != MachineStatusActive) {
		out.Outcome, out.Request = HelpAcceptIneligible, s.copyOf(r)
		return out, nil
	}
	if m.GroupID != in.AdmissionGroupID || in.Record.MachineID != r.MachineID {
		out.Outcome, out.Request = HelpAcceptGroupChanged, s.copyOf(r)
		return out, nil
	}
	switch in.presenceOf(m.DeviceID) {
	case HelpPresenceOffline:
		out.Outcome, out.Request = HelpAcceptOffline, s.copyOf(r)
		return out, nil
	case HelpPresenceUnknown:
		out.Outcome, out.Request = HelpAcceptPresenceUnknown, s.copyOf(r)
		return out, nil
	}
	if err := s.sessions.StartSessionWithinLimit(ctx, tenantID, in.Record, in.Limits); err != nil {
		return nil, err
	}
	s.txn.sessions = append(s.txn.sessions, struct{ tenant, id string }{tenantID, in.Record.ID})
	t := helpClip(in.Now)
	r.Status, r.AcceptedBy, r.AcceptedAt, r.ClosedAt, r.SessionID = HelpStatusAccepted, in.TechnicianID, &t, &t, in.Record.ID
	r.Delivery = HelpDeliveryPending
	r.acceptOp = in.OpID
	if err := s.record(ctx, tenantID, &out.HelpResult, helpAuditEvent(AuditHelpAccepted, r.ID, in.TechnicianID,
		helpAcceptedMeta(r, m.GroupID, in.Record.ID))); err != nil {
		return nil, err
	}
	out.Outcome, out.Request, out.Record = HelpAcceptAccepted, s.copyOf(r), in.Record
	return out, nil
}

// MarkDelivered implements HelpRequestStore.
func (s *InMemoryHelpRequestStore) MarkDelivered(ctx context.Context, tenantID, requestID, sessionID string, now time.Time) (_ *HelpTransitionResult, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.begin()(&err)
	out := &HelpTransitionResult{}
	r := s.find(tenantID, requestID)
	if r == nil {
		return out, nil
	}
	if r.Status == HelpStatusAccepted && r.SessionID == canonicalUUIDish(sessionID) && r.Delivery == HelpDeliveryPending {
		r.Delivery = HelpDeliveryDelivered
		out.Changed, out.Request = true, s.copyOf(r)
		return out, nil
	}
	out.Request, out.Conflict = s.copyOf(r), true
	return out, nil
}

// ReopenAfterFailedStart implements HelpRequestStore.
func (s *InMemoryHelpRequestStore) ReopenAfterFailedStart(ctx context.Context, tenantID, requestID, sessionID string, at time.Time) (_ *HelpTransitionResult, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.begin()(&err)
	out := &HelpTransitionResult{}
	r := s.find(tenantID, requestID)
	if r == nil {
		return out, nil
	}
	if r.Status != HelpStatusAccepted || r.SessionID != canonicalUUIDish(sessionID) || r.Delivery != HelpDeliveryPending {
		out.Request, out.Conflict = s.copyOf(r), true
		return out, nil
	}
	meta := func(extra map[string]any) map[string]any {
		extra["session_id"] = r.SessionID
		return helpDeviceMeta(r, extra)
	}
	switch {
	case !at.Before(r.ExpiresAt):
		s.clearAccept(r)
		s.closeAs(r, HelpStatusExpired, "", at)
		if err := s.record(ctx, tenantID, &out.HelpResult, helpAuditEvent(AuditHelpExpired, r.ID, "",
			helpDeviceMeta(r, map[string]any{"reason": "accept_failed"}))); err != nil {
			return nil, err
		}
	case s.machineOutOfService(ctx, tenantID, r.MachineID) != "":
		// Retired / quarantined while the accept was in flight: never reopen onto it (H-C5).
		reason := s.machineOutOfService(ctx, tenantID, r.MachineID)
		failed := r.SessionID
		s.clearAccept(r)
		s.closeAs(r, HelpStatusCancelled, reason, at)
		if err := s.record(ctx, tenantID, &out.HelpResult, helpAuditEvent(AuditHelpCancelled, r.ID, "",
			helpDeviceMeta(r, map[string]any{"reason": reason, "failed_session_id": failed, "actor_kind": "system"}))); err != nil {
			return nil, err
		}
	case s.openCount(tenantID) >= helpTenantOpenCap && s.openFor(tenantID, r.MachineID) == nil:
		failed := r.SessionID
		s.clearAccept(r)
		s.closeAs(r, HelpStatusCancelled, HelpCancelCapacity, at)
		if err := s.record(ctx, tenantID, &out.HelpResult, helpAuditEvent(AuditHelpCancelled, r.ID, "",
			helpDeviceMeta(r, map[string]any{"reason": HelpCancelCapacity, "failed_session_id": failed, "actor_kind": "system"}))); err != nil {
			return nil, err
		}
	case s.openFor(tenantID, r.MachineID) != nil:
		failed := r.SessionID
		s.clearAccept(r)
		s.closeAs(r, HelpStatusCancelled, HelpCancelSuperseded, at)
		if err := s.record(ctx, tenantID, &out.HelpResult, helpAuditEvent(AuditHelpCancelled, r.ID, "",
			helpDeviceMeta(r, map[string]any{"reason": HelpCancelSuperseded, "failed_session_id": failed}))); err != nil {
			return nil, err
		}
	default:
		ev := helpAuditEvent(AuditHelpReopened, r.ID, "", meta(map[string]any{"reason": "accept_failed"}))
		s.clearAccept(r)
		r.Status, r.ClosedAt = HelpStatusOpen, nil
		if err := s.record(ctx, tenantID, &out.HelpResult, ev); err != nil {
			return nil, err
		}
	}
	out.Changed, out.Request = true, s.copyOf(r)
	return out, nil
}

// machineOutOfService returns the cancel reason when the machine is retired / quarantined (or ephemeral),
// "" when it is in service.
func (s *InMemoryHelpRequestStore) machineOutOfService(ctx context.Context, tenantID, machineID string) string {
	m, err := s.machines.GetMachineByID(ctx, tenantID, machineID)
	if err != nil {
		return ""
	}
	switch {
	case m.Status == MachineStatusQuarantined:
		return HelpCancelQuarantined
	case m.Ephemeral || (m.Status != "" && m.Status != MachineStatusActive):
		return HelpCancelRetired
	}
	return ""
}

func (s *InMemoryHelpRequestStore) openCount(tenantID string) int {
	n := 0
	for _, r := range s.reqs {
		if r.TenantID == tenantID && r.Status == HelpStatusOpen {
			n++
		}
	}
	return n
}

func (s *InMemoryHelpRequestStore) clearAccept(r *HelpRequest) {
	r.AcceptedBy, r.AcceptedAt, r.SessionID, r.Delivery = "", nil, "", ""
	r.acceptOp = ""
}

// CancelForMachine implements HelpRequestStore.
func (s *InMemoryHelpRequestStore) CancelForMachine(ctx context.Context, tenantID, machineID, reason string, now time.Time) (_ *HelpResult, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.begin()(&err)
	res := &HelpResult{}
	machineID = canonicalUUIDish(machineID)
	for _, r := range s.reqs {
		if r.TenantID == tenantID && r.MachineID == machineID && r.Status == HelpStatusOpen {
			s.closeAs(r, HelpStatusCancelled, reason, now)
			if err := s.record(ctx, tenantID, res, helpAuditEvent(AuditHelpCancelled, r.ID, "",
				helpDeviceMeta(r, map[string]any{"reason": reason, "actor_kind": "system"}))); err != nil {
				return nil, err
			}
		}
	}
	return res, nil
}

// Sweep implements HelpRequestStore.
func (s *InMemoryHelpRequestStore) Sweep(ctx context.Context, now time.Time) (_ *HelpSweepResult, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.begin()(&err)
	out := &HelpSweepResult{}
	tenants := map[string]struct{}{}
	for _, r := range s.reqs {
		tenants[r.TenantID] = struct{}{}
	}
	touched := map[string]struct{}{}
	for t := range tenants {
		var res HelpResult
		if err := s.expireLocked(ctx, t, now, &res); err != nil {
			return nil, err
		}
		for _, e := range res.Events {
			out.Events = append(out.Events, HelpSweepEvent{TenantID: t, Event: e})
			out.Expired++
			touched[t] = struct{}{}
		}
	}
	kept := s.reqs[:0]
	for _, r := range s.reqs {
		if r.Status != HelpStatusOpen && r.ClosedAt != nil && r.ClosedAt.Before(now.Add(-helpClosedRetention)) {
			out.Pruned++
			touched[r.TenantID] = struct{}{}
			continue
		}
		kept = append(kept, r)
	}
	s.reqs = kept
	live := map[string]struct{}{}
	for _, r := range s.reqs {
		live[r.ID] = struct{}{}
	}
	for k, v := range s.ops {
		if _, ok := live[v.requestID]; !ok || now.Sub(v.at) >= helpOpDedupWindow {
			delete(s.ops, k)
		}
	}
	for k := range s.calls {
		if k.bucket.Before(helpCallBucket(now.Add(-helpOpDedupWindow))) {
			delete(s.calls, k)
		}
	}
	out.Tenants = len(touched)
	return out, nil
}
