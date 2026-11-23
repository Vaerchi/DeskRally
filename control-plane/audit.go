package controlplane

// Backstage audit-chain ingestion (Milestone H2).
//
// The agent builds a SHA-256 hash-chained audit trail per backstage session
// (agent/src/backstage/audit.rs: AuditChain + AuditEvent) and returns each AuditEvent to the
// controller inside the backstage Envelope (agent/src/transport/backstage_api.rs). H2 forwards
// that chain to the control plane for central, tamper-evident storage: an authenticated
// technician (the controller, on behalf of the operator) POSTs batches of AuditEvents to
// /audit/ingest; the control plane verifies the chain LINKAGE against what it has already stored
// and appends atomically, or rejects the whole batch.
//
// Tamper-evidence = chain LINKAGE (seq monotonicity + prev_hash/hash pointer integrity, detecting
// reordering, deletion, gaps, replays) PLUS, since H2b, CONTENT re-hashing: audit_canonical.go
// reproduces the Rust SHA-256 preimage (agent/src/backstage/canonical.rs) byte-for-byte and
// verifyLinkage confirms recomputeHash(event) == event.hash for every event, so a field-level edit
// that keeps the pointers consistent is still rejected. The Rust/Go agreement is pinned by shared
// golden vectors (audit_test.go TestAuditGoldenVectorV1 == audit.rs audit_golden_vector_v1).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// jsonNULEscape is the six-character JSON escape for U+0000, assembled byte by byte so the
// sequence never appears literally in this file (a Go source file containing it would be its own
// small hazard). See the storability check in verifyLinkage.
var jsonNULEscape = []byte{'\\', 'u', '0', '0', '0', '0'}

// GenesisPrevHash is the prev_hash the agent writes for the first event of a session's chain
// (seq 0). In audit.rs the chain starts with `last_hash: String::new()`, so event 0 carries an
// empty prev_hash. A batch that starts a fresh chain MUST begin at seq 0 with this value.
const GenesisPrevHash = ""

// Batch/size bounds for the ingest endpoint. A single backstage session's chain is forwarded in
// bounded batches; these cap the work an authenticated request can force.
const (
	maxAuditBatchEvents = 1024
	maxAuditBodyBytes   = 1 << 20 // 1 MiB
)

// AuditEvent mirrors the Rust `AuditEvent` (agent/src/backstage/audit.rs) field-for-field so the
// JSON the agent's Envelope carries deserializes directly. UUIDs are kept as strings (the Rust
// side serializes uuid::Uuid as a hyphenated string); `action` and `outcome` are kept as opaque
// JSON (they are internally-tagged Rust enums — `{"kind":...}` / `{"result":...}`) because H2
// stores them verbatim and does not interpret them. Hashes are the Rust hex SHA-256 encoding.
type AuditEvent struct {
	ID               string          `json:"id"`
	Seq              uint64          `json:"seq"`
	SessionID        string          `json:"session_id"`
	TechnicianID     string          `json:"technician_id"`
	MachineID        string          `json:"machine_id"`
	OccurredAtUnixMs int64           `json:"occurred_at_unix_ms"`
	Action           json.RawMessage `json:"action"`
	Outcome          json.RawMessage `json:"outcome"`
	PrevHash         string          `json:"prev_hash"`
	Hash             string          `json:"hash"`
	AgentPubkey      string          `json:"agent_pubkey,omitempty"`
	AgentSignature   string          `json:"agent_signature,omitempty"`
}

// AuditTail is the current end of a session's stored chain: the highest seq appended and its
// hash, which the next batch must chain onto. Exists is false when nothing is stored yet for the
// session (so the next batch must start the chain at seq 0 / GenesisPrevHash).
type AuditTail struct {
	Exists bool
	Seq    uint64
	Hash   string
}

// AuditStore is the persistence seam for the forwarded backstage audit chain, alongside the
// existing UserStore/SessionStore abstractions. Implementations: InMemoryAuditStore (tests / dev,
// authstore_mem.go) and PgAuditStore (pgx, pgstore.go). The store is append-only: there is no
// update or delete. AppendAudit verifies linkage against the current tail and appends atomically,
// so it is the authoritative choke point even under concurrent ingests.
type AuditStore interface {
	// AppendAudit verifies the batch links onto the session's stored tail (or starts a fresh
	// chain) and appends it atomically. On any linkage break it returns a *LinkageError and
	// stores nothing. On success it returns the new tail. tenantID scopes the session.
	AppendAudit(ctx context.Context, tenantID, sessionID string, events []AuditEvent) (AuditTail, error)
	// AuditTail returns the current tail of a session's chain (Exists=false if empty).
	AuditTail(ctx context.Context, tenantID, sessionID string) (AuditTail, error)
	// ListAuditEventsAsc returns one page of stored events for export, in the tenant's INGEST
	// order (see AuditExportQuery), plus the cursor to resume from: the `ingest_seq` of the last
	// row returned, or the caller's own cursor when the page is empty.
	ListAuditEventsAsc(ctx context.Context, tenantID string, q AuditExportQuery) ([]AuditEvent, int64, error)
}

// AuditExportQuery selects one page of stored backstage audit events for `GET
// /audit/backstage/export`.
//
// **The cursor is `ingest_seq` — an APPEND order, not a snapshot order.** The obvious cursor here
// is `(session_id, seq)`, and it is wrong: `session_id` is a random v4 uuid and `seq` restarts at
// 0 for every chain (each grant install builds a fresh `AuditChain` in the agent — docs/07 loop 4
// §5), so that pair totally orders a point-in-time SNAPSHOT but bears no relation to when a row
// arrived. A collector that stored the last pair and resumed from it would never again see
// anything appended under a lower-sorting session_id — about half of all subsequent events,
// silently. Backstage chains grow continuously (the console's forwarder flushes every 10s), so
// that is the normal case.
//
// `ingest_seq` (migration 0019) is a dense, gapless, monotonic per-tenant counter assigned at
// append under a per-tenant advisory lock, exactly as `audit_event.seq` is for the management
// trail. Ordering by it IS ingest order, so a resuming collector cannot miss a row — and the two
// exports genuinely do share a cursor shape now.
//
// Ordering by ingest_seq also preserves per-session chain order for free: a chain is only ever
// appended to, so within one session_id, ingest order and `seq` order are the same sequence.
type AuditExportQuery struct {
	// SessionID limits the page to ONE chain — the "replay this session" case. Empty ⇒ every
	// chain the tenant owns.
	//
	// Filtering does not change the ORDERING, but the returned cursor is only valid for resuming
	// the SAME query shape. A filtered page's cursor is the ingest_seq of the last row that
	// SURVIVED the filter, so feeding it back to an unfiltered request skips every other session's
	// events in between. Filtered and unfiltered streams are separate subscriptions; a collector
	// must not mix their cursors.
	SessionID string
	// AfterIngestSeq is the EXCLUSIVE cursor: the ingest_seq of the last row already returned.
	// The zero VALUE of this field is 0, which would skip the tenant's very first event, so
	// callers that mean "from the beginning" must pass auditExportStart — normalize() cannot
	// distinguish an unset field from a deliberate 0. Use NewAuditExportQuery to get that right.
	AfterIngestSeq int64
	// Limit caps the page. Zero or negative means defaultAuditExportLimit.
	Limit int
}

// Bounds for the backstage audit export, matching the management export's.
const (
	defaultAuditExportLimit = 1000
	maxAuditExportLimit     = 10000
)

// auditExportStart is the cursor meaning "before every row". ingest_seq starts at 0 for each
// tenant, so the exclusive cursor that admits row 0 is -1 — the same convention `after_seq` uses
// on the management export.
const auditExportStart int64 = -1

// NewAuditExportQuery builds a query positioned at the START of the tenant's trail. Prefer it to a
// bare `AuditExportQuery{}`: the struct's zero AfterIngestSeq is 0, which EXCLUDES the tenant's
// first event — the genesis event of its first chain, the one carrying prev_hash "" that proves
// where the trail began.
func NewAuditExportQuery(sessionID string, limit int) AuditExportQuery {
	return AuditExportQuery{SessionID: sessionID, AfterIngestSeq: auditExportStart, Limit: limit}
}

// normalize fills in the default page size. It deliberately does NOT touch AfterIngestSeq: 0 is a
// legitimate cursor ("I have consumed event 0"), indistinguishable from an unset field, so silently
// rewriting it would trade one silent data-loss bug for another. Returned by value.
func (q AuditExportQuery) normalize() AuditExportQuery {
	if q.Limit <= 0 {
		q.Limit = defaultAuditExportLimit
	}
	return q
}

// LinkageError describes why a batch was rejected. At is the batch index of the offending event
// (-1 for whole-batch problems). Reason is a human-readable explanation surfaced in the 400 body.
type LinkageError struct {
	At     int
	Reason string
}

func (e *LinkageError) Error() string {
	if e.At < 0 {
		return "audit chain linkage error: " + e.Reason
	}
	return fmt.Sprintf("audit chain linkage error at index %d: %s", e.At, e.Reason)
}

// UnstorableError says an event is well-formed and correctly hashed but contains a value the
// audit store physically cannot hold, so it will never be accepted no matter how often it is
// retried. It is deliberately DISTINCT from LinkageError and ContentTamperError: those two mean
// "your chain is wrong", while this means "your chain is fine but this value cannot be stored" —
// and it must be a 4xx precisely so the agent stops retrying and the operator sees the field.
type UnstorableError struct {
	At    int
	Field string
}

func (e *UnstorableError) Error() string {
	return fmt.Sprintf("audit event at index %d cannot be stored: %s contains a U+0000 character, "+
		"which PostgreSQL jsonb cannot represent; the agent must strip it before hashing the event",
		e.At, e.Field)
}

// containsNUL reports whether a decoded JSON value contains U+0000 anywhere PostgreSQL's jsonb
// would choke on it — in any string, at any depth, object KEYS included.
//
// Decoding is what makes it exact. `bytes.Contains(raw, jsonNULEscape)` cannot distinguish a real
// U+0000 escape from six literal characters of ordinary text. The six characters `\u0000` typed
// by a human JSON-encode to the raw bytes `\\u0000`, whose tail is a byte-for-byte match for
// the needle.
func containsNUL(raw json.RawMessage) bool {
	// A raw 0x00 byte: the JSON decoder rejects one inside a string, so this only arises when a
	// caller reaches a store directly (tests do). Cheap, and checked first.
	if bytes.IndexByte(raw, 0) >= 0 {
		return true
	}
	// Fast path, and the reason decoding costs nothing in practice: U+0000 has exactly one JSON
	// spelling, so no escape sequence at all means no U+0000 is possible. Almost every event takes
	// this branch.
	if !bytes.Contains(raw, jsonNULEscape) {
		return false
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Unreachable through the HTTP handler, where encoding/json has already validated the whole
		// body before these RawMessages exist. Malformed JSON is genuinely unstorable in a jsonb
		// column, so refusing it here keeps the 400-with-a-named-field shape rather than letting it
		// become a 500 on INSERT — which is the stuck-chain failure this guard exists to prevent.
		return true
	}
	return jsonValueHasNUL(v)
}

func jsonValueHasNUL(v any) bool {
	switch t := v.(type) {
	case string:
		return strings.IndexByte(t, 0) >= 0
	case map[string]any:
		for k, elem := range t {
			// Keys as well as values: jsonb rejects U+0000 in either.
			if strings.IndexByte(k, 0) >= 0 || jsonValueHasNUL(elem) {
				return true
			}
		}
	case []any:
		for _, elem := range t {
			if jsonValueHasNUL(elem) {
				return true
			}
		}
	}
	return false
}

// verifyLinkage checks that events form a valid continuation of tail. It enforces BOTH the H2
// structural rules (seq + hash pointers) AND the H2b content rule (recomputed SHA-256 == hash):
//
//   - first event: if the session has a stored tail, it must continue it (seq == tail.Seq+1 AND
//     prev_hash == tail.Hash); a seq <= tail.Seq is a duplicate/replay, a larger seq is a gap.
//     If the session is empty, it must start the chain (seq == 0 AND prev_hash == GenesisPrevHash).
//   - within the batch: each event's seq strictly increments by 1 and its prev_hash equals the
//     previous event's hash.
//   - every event's hash must be a 64-char hex SHA-256 (a cheap sanity guard on the pointer).
//   - H2b: every event's `hash` must equal recomputeHash(event) — the SHA-256 of the canonical
//     audit v1 preimage (auditPreimage), which is a byte-for-byte port of the Rust encoder. This
//     detects a field-level edit even when the chain pointers were kept self-consistent. A pointer
//     break returns *LinkageError; a content mismatch returns *ContentTamperError; both store
//     nothing (400).
func verifyLinkage(tail AuditTail, events []AuditEvent) error {
	if len(events) == 0 {
		return &LinkageError{At: -1, Reason: "empty batch"}
	}
	if err := verifyEventShapes(events); err != nil {
		return err
	}
	first := events[0]
	if tail.Exists {
		if first.Seq <= tail.Seq {
			return &LinkageError{At: 0, Reason: fmt.Sprintf("duplicate/replayed seq %d (stored tail is seq %d)", first.Seq, tail.Seq)}
		}
		if first.Seq != tail.Seq+1 {
			return &LinkageError{At: 0, Reason: fmt.Sprintf("seq gap: got %d, expected %d", first.Seq, tail.Seq+1)}
		}
		if first.PrevHash != tail.Hash {
			return &LinkageError{At: 0, Reason: "broken link: prev_hash does not match the stored tail hash"}
		}
	} else {
		if first.Seq != 0 {
			return &LinkageError{At: 0, Reason: fmt.Sprintf("a fresh chain must start at seq 0, got %d", first.Seq)}
		}
		if first.PrevHash != GenesisPrevHash {
			return &LinkageError{At: 0, Reason: "first event prev_hash must be the genesis value (empty string)"}
		}
	}
	if err := verifyInBatchLinks(events); err != nil {
		return err
	}
	return verifyContentHashes(events)
}

// verifyEventShapes: the per-event guards (hash shape, no NUL in jsonb fields).
func verifyEventShapes(events []AuditEvent) error {
	for i, e := range events {
		if !isHex64(e.Hash) {
			return &LinkageError{At: i, Reason: "hash is not a 64-char hex SHA-256"}
		}
		// `action` and `outcome` are jsonb columns (0004_audit.sql), and PostgreSQL's jsonb
		// cannot represent U+0000 inside a string — but Go's JSON decoder accepts it happily. An
		// event carrying one therefore hashes and verifies perfectly here and then dies on the
		// INSERT. Rejecting it at this seam makes that a 400 naming the field; without it the
		// failure surfaced as a generic 500, and because the agent's chain is strictly sequential
		// (it cannot skip event N) the agent re-POSTs the identical batch forever and that
		// session's audit trail is never persisted at all — a stuck chain, not a lost event.
		//
		// The check must look at the DECODED value, not the raw bytes. Scanning the raw bytes for
		// jsonNULEscape looks complete — JSON can express U+0000 only as that six-character escape —
		// but it also matches text that merely CONTAINS those six characters: a command like
		// `echo "\u0000"` encodes as the raw bytes `\\u0000`, whose tail is a byte-for-byte match.
		//
		// That false positive was not cosmetic. Per the paragraph above, the agent's chain is
		// strictly sequential and cannot skip event N, so a wrongly-rejected event is re-POSTed
		// forever and the session's audit trail NEVER persists. Anyone who wanted their session
		// unaudited only had to type those six characters into any command.
		for _, f := range []struct {
			name string
			raw  json.RawMessage
		}{{"action", e.Action}, {"outcome", e.Outcome}} {
			if containsNUL(f.raw) {
				return &UnstorableError{At: i, Field: f.name}
			}
		}
	}
	return nil
}

// verifyInBatchLinks: consecutive seqs and prev_hash links inside the batch.
func verifyInBatchLinks(events []AuditEvent) error {
	for i := 1; i < len(events); i++ {
		prev, cur := events[i-1], events[i]
		if cur.Seq != prev.Seq+1 {
			return &LinkageError{At: i, Reason: fmt.Sprintf("in-batch seq gap: got %d, expected %d", cur.Seq, prev.Seq+1)}
		}
		if cur.PrevHash != prev.Hash {
			return &LinkageError{At: i, Reason: "in-batch broken link: prev_hash does not match the previous event's hash"}
		}
	}
	return nil
}

// verifyContentHashes: every hash equals the recomputed canonical content hash.
func verifyContentHashes(events []AuditEvent) error {
	// H2b CONTENT tamper-evidence: recompute each event's SHA-256 over the exact canonical audit v1
	// preimage (auditPreimage) and confirm it equals the carried `hash`. This catches a field-level
	// edit that keeps the chain pointers self-consistent (which the structural checks above miss).
	// Runs after the linkage checks so a pointer break still surfaces as a *LinkageError.
	for i, e := range events {
		got, err := recomputeHash(e)
		if err != nil {
			return &ContentTamperError{At: i, Reason: "cannot canonicalize event fields: " + err.Error()}
		}
		if got != e.Hash {
			return &ContentTamperError{At: i, Reason: "recomputed content hash does not match hash (a field was altered)"}
		}
	}
	return nil
}

// resolveOverlap makes ingest IDEMPOTENT for a batch that re-sends events already stored, and
// returns how many leading events of `events` are already on the stored chain (0 = none). The
// caller appends only events[skip:] (nothing at all when skip == len(events)) after the ordinary
// verifyLinkage of that suffix against the tail.
//
// WHY: a forwarder that loses the 2xx for a batch the server DID commit keeps the batch and
// re-sends it. Before this, that re-send was a 400 "duplicate/replayed seq" forever, and the agent's
// chain is strictly sequential, so nothing after it could ever be stored: one lost response wedged
// the session's audit trail permanently.
//
// WHY IT IS SAFE WITHOUT READING STORED ROWS: the batch is first checked as a self-consistent chain
// (every hash recomputed from its content, every prev_hash linking to its predecessor). If the event
// at the stored tail's seq carries the stored tail's HASH, then by the chain's linkage that event and
// every one before it in the batch are exactly the stored events (a different prefix would need a
// SHA-256 collision). A batch that overlaps the stored range but either ends BEFORE the tail (nothing
// in it can be proven stored) or disagrees with the tail's hash (a fork) is still refused, as before.
func resolveOverlap(tail AuditTail, events []AuditEvent) (int, error) {
	if !tail.Exists || len(events) == 0 || events[0].Seq > tail.Seq {
		return 0, nil // no overlap: verifyLinkage alone decides
	}
	if err := verifyBatchInternal(events); err != nil {
		return 0, err
	}
	first, last := events[0], events[len(events)-1]
	if last.Seq < tail.Seq {
		return 0, &LinkageError{At: 0, Reason: fmt.Sprintf("duplicate/replayed seq %d (stored tail is seq %d)", first.Seq, tail.Seq)}
	}
	k := int(tail.Seq - first.Seq) // in-batch seqs are contiguous (verifyBatchInternal)
	if events[k].Hash != tail.Hash {
		return 0, &LinkageError{At: k, Reason: fmt.Sprintf("conflicts with the stored chain at seq %d (different hash)", tail.Seq)}
	}
	return k + 1, nil
}

// verifyBatchInternal checks a batch as a self-consistent chain, independent of any stored tail:
// the per-event guards, in-batch seq/prev_hash continuity, and the content hash of every event.
// verifyLinkage runs the same checks around its tail check, in its original order.
func verifyBatchInternal(events []AuditEvent) error {
	if len(events) == 0 {
		return &LinkageError{At: -1, Reason: "empty batch"}
	}
	if err := verifyEventShapes(events); err != nil {
		return err
	}
	if err := verifyInBatchLinks(events); err != nil {
		return err
	}
	return verifyContentHashes(events)
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// -------------------------------------------------------------------------------------
// HTTP endpoint: POST /audit/ingest
// -------------------------------------------------------------------------------------

// auditIngestRequest is the body of POST /audit/ingest: a session id and the ordered batch of
// AuditEvents to append to that session's chain.
type auditIngestRequest struct {
	SessionID string       `json:"session_id"`
	Events    []AuditEvent `json:"events"`
}

// auditIngestResponse reports how many events were accepted and the new chain tail.
type auditIngestResponse struct {
	Accepted int    `json:"accepted"`
	TailSeq  uint64 `json:"tail_seq"`
	TailHash string `json:"tail_hash"`
}

// handleIngestAudit ingests a forwarded session audit batch. It runs behind the SAME auth → tenant
// (RLS) middleware chain as every other protected route, so the caller is an authenticated
// technician session and the tenant is already pinned for storage.
//
// GATE: CapBackstageShell **or** CapStartSession (widened in loop 91 — the decision, and why).
//
// It used to be CapBackstageShell alone, on the reasoning that "the same capability that authorizes
// running backstage authorizes forwarding its trail". That stopped being true when the agent's audit
// chain was lifted from the GRANT to the SESSION: the batch now also carries session-recording
// events and file-transfer denials from sessions where no backstage grant was ever installed. Under
// the old gate a technician who may record but not open a shell had their whole batch answered 403 —
// and the console SWALLOWS flush failures by design (App.tsx: a briefly-unreachable control plane
// must not tear down a live support session), so the feature would have looked like it worked and
// recorded nothing, centrally, forever.
//
// The alternative considered and REJECTED was a new per-action capability (`record_session`). It
// cannot work here, and the reason is structural rather than a matter of taste: the forwarded batch
// is ONE hash-linked sequence per session, in seq order, mixing every producer in that session. To
// gate per event kind the server would have to accept some events and refuse others — which gaps the
// chain, and `verifyLinkage` rejects a gapped chain permanently, so a partial accept would destroy
// the trail it was trying to protect. A per-event capability would also just move the problem one
// level down: a custom role could hold `record_session` without the new one too.
//
// So the question this gate can actually ask is "is this principal one who legitimately runs
// sessions on this tenant?", and both capabilities answer yes. Widening adds no privilege that
// matters: the identity bind below already restricts every caller to events naming THEMSELVES, and
// CapStartSession holders can already generate real audit simply by running a session. On the stock
// presets the two sets are identical (Owner/Admin/Technician hold both) — this only ever differs for
// a CUSTOM role, which is exactly the case the old gate got wrong. Auditors (read-only, CapViewAudit)
// still cannot write the trail.
func (s *Server) handleIngestAudit(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.RequireAny(CapBackstageShell, CapStartSession); err != nil {
		writeDenied(w, err)
		return
	}

	// The cap and the decode are one call since docs/25 F05, so an over-limit batch is answered 413
	// instead of a 400 that carried the runtime's own "http: request body too large" text. The limit
	// itself is unchanged; maxAuditBatchEvents is what actually sizes this endpoint.
	var req auditIngestRequest
	if err := decodeJSONBodyDetailed(w, r, maxAuditBodyBytes, &req, "malformed audit ingest body"); err != nil {
		return
	}
	if req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "session_id is required")
		return
	}
	if len(req.Events) == 0 {
		writeError(w, http.StatusBadRequest, "events is empty")
		return
	}
	if len(req.Events) > maxAuditBatchEvents {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("batch too large: %d events (max %d)", len(req.Events), maxAuditBatchEvents))
		return
	}
	// Every event must belong to the session named in the request — a batch never mixes sessions.
	for i, e := range req.Events {
		if e.SessionID != req.SessionID {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("event %d session_id %q does not match request session_id %q", i, e.SessionID, req.SessionID))
			return
		}
		// Bind the batch to the CALLER. `technician_id` arrives in the body, and without this the
		// capability check above is the only gate — a tenant-wide one — so any CapBackstageShell
		// holder could append correctly-hash-chained events attributing backstage actions to a
		// DIFFERENT technician. The chain would verify, and the export would re-emit the forgery as
		// an authentic, tamper-evident record. Tamper-evidence only means anything if the identity
		// in the record is the one the server authenticated.
		//
		// Equality is the right rule because it is exactly the production relationship: handleMintGrant
		// mints the grant as `s.Grants.Mint(p.UserID, ...)` (http.go), the agent copies that
		// technician id into every audit record it emits, and the console forwards the batch as the
		// same authenticated user. A mismatch is therefore never a legitimate flow.
		//
		// NOTE: this deliberately does NOT try to authorize `machine_id` by resolving the session's
		// group.
		//
		// The historical reason was that `session_id` here was a BROWSER-minted uuid never written to
		// `session_record`, so there was no row to resolve and the check would 404 every legitimate
		// ingest. **Loop 91 changed the input**: the agent's chain is now keyed on the CONTROL-PLANE
		// session id that signaling vouched for, and the console forwards under that same id — so for
		// a ticketed session there IS a `session_record` row now, and the group could be resolved.
		//
		// It is still not done here, for a different reason, recorded so a later hunt does not read
		// the change as an oversight: the batch is one hash-linked sequence, so a machine-scope
		// refusal has to reject the WHOLE batch, and `verifyLinkage` makes a rejected batch a
		// permanent hole. Worse, group access can be REVOKED while a session is in flight, which
		// would turn a legitimate half-written trail into exactly that. A scope check therefore
		// belongs at the point the session is BROKERED, where refusing costs nothing, rather than at
		// the point its trail is durably persisted.
		//
		// What CAN live here is anything decidable without a revocable authorization: the identity
		// bind immediately below, and the session-ownership bind after the loop, which compares
		// against `session_record.technician_id` — a value that has exactly one writer and never
		// changes for the life of the session.
		if e.TechnicianID != p.UserID {
			writeError(w, http.StatusForbidden, fmt.Sprintf(
				"event %d technician_id %q is not the authenticated caller", i, e.TechnicianID))
			return
		}
	}

	// Bind the batch to a session the caller actually RAN, whenever the control plane knows about
	// one. The identity bind above stops A from attributing events to B; this stops A from writing
	// their own events into B's session chain.
	//
	// Why that matters beyond tidiness: a chain is strictly sequential, so an intruder who appends a
	// valid continuation to another technician's session CONSUMES the seq numbers that session's real
	// events were going to use. Those real events then fail verifyLinkage forever — the trail is not
	// merely polluted, it stops recording. Wedging someone else's audit is the interesting attack,
	// not forging entries in it.
	//
	// UNLIKE the machine-scope check argued against above, this one is safe to enforce here because
	// it is STABLE. Group access can be revoked mid-session, which would turn a legitimate in-flight
	// trail into a permanent hole; `session_record.technician_id` cannot change — handleStartSession
	// is the only writer and always sets it to the authenticated caller (http.go). Session transfer
	// (docs/51) does not change that: it never re-binds a session, it ends S1 (still A's) and starts a
	// NEW session S2 (the receiver's, linked by transferred_from), so a record's technician never changes
	// and the invariant holds. So a refusal here can only ever hit a caller who was never the
	// session's technician.
	//
	// It FAILS OPEN in both uncertain directions, deliberately, because the cost of a wrong refusal
	// is a destroyed audit trail and the cost of a wrong accept is one intra-tenant forgery that the
	// identity bind has already stamped with its author:
	//
	//   * no row  ⇒ allowed. An unticketed/dev session has no session_record at all, and refusing
	//     those would break every deployment that has not enabled tickets.
	//   * store error ⇒ allowed, with a log. A transient database blip must not cost the trail.
	bound := false
	if s.SessionRecords != nil {
		switch rec, serr := s.SessionRecords.GetSession(r.Context(), p.TenantID, req.SessionID); {
		case errors.Is(serr, ErrSessionRecordNotFound):
			// No record — an unticketed or ATTENDED session. Attended is handled below; it is not
			// "nothing to check against", which is what this branch used to assume.
		case serr != nil:
			log.Printf("audit ingest: cannot resolve session %s to check ownership (%v); "+
				"checking remaining session bindings", req.SessionID, serr)
		case rec.TechnicianID != p.UserID:
			writeError(w, http.StatusForbidden, fmt.Sprintf(
				"session %s belongs to a different technician", req.SessionID))
			return
		default:
			bound = true
			// The MACHINE bind. The comment above argues no scope check belongs here, and for a
			// GROUP check that is right — group access is revocable mid-session, so refusing on it
			// could turn a legitimate half-written trail into a permanent hole.
			//
			// But that argument proves "no GROUP check", not "no check". `session_record.machine_id`
			// passes the very stability test this handler already applies to `technician_id`: one
			// writer (handleStartSession), and no UPDATE anywhere ever touches it — the only
			// statements against that table set `ended_at` and `note`. It is as unrevocable as the
			// technician, so binding to it cannot break a legitimate flow.
			//
			// Without it a technician can seal backstage/file-transfer records naming ANY machine
			// uuid they know — one whose group access was revoked, or one leaked through a CSV
			// export — and the export re-emits the forgery as an authentic, tamper-evident record a
			// SIEM's own re-hash confirms.
			for i, e := range req.Events {
				if e.MachineID != rec.MachineID && (rec.MachineDeviceID == "" || e.MachineID != rec.MachineDeviceID) {
					writeError(w, http.StatusForbidden, fmt.Sprintf(
						"event %d names machine %q, but session %s ran against a different machine",
						i, e.MachineID, req.SessionID))
					return
				}
			}
		}
	}

	// ATTENDED sessions never create a session_record — the only writer is handleStartSession, and
	// the attended flow mints its ticket against the attended-session id instead. So every attended
	// session took the "no row" branch above and was accepted unbound, which reopened exactly the
	// attack the ownership bind exists to stop, on the one session type a GUEST initiates.
	//
	// A technician who can list attended sessions in a group could post a fabricated seq 0..N chain
	// under a pending session's id before the assigned technician's first flush. Every genuine event
	// then fails verifyLinkage forever, and the console swallows flush failures by design — the
	// session records nothing, centrally, permanently, with nothing surfacing.
	if !bound && s.Attended != nil {
		switch att, aerr := s.Attended.Get(r.Context(), p.TenantID, req.SessionID); {
		case aerr != nil:
			// Legacy/dev mode may accept an unbound chain. Production's mandatory
			// signature mode also requires a known session, checked below.
		case att.TechnicianID != "" && att.TechnicianID != p.UserID:
			writeError(w, http.StatusForbidden, fmt.Sprintf(
				"attended session %s belongs to a different technician", req.SessionID))
			return
		default:
			bound = true
			if s.RequireAgentAuditSignatures {
				for _, e := range req.Events {
					if att.DeviceID == "" || e.MachineID != att.DeviceID {
						writeError(w, http.StatusForbidden, "audit machine does not match attended session")
						return
					}
				}
			}
		}
	}

	if s.RequireAgentAuditSignatures && !bound {
		writeError(w, http.StatusForbidden, "audit requires a known control-plane session")
		return
	}
	if err := s.verifyAgentAudit(r.Context(), p.TenantID, req.SessionID, req.Events); err != nil {
		writeError(w, http.StatusForbidden, "agent audit signature could not be verified")
		return
	}

	tail, err := s.Audit.AppendAudit(r.Context(), p.TenantID, req.SessionID, req.Events)
	if err != nil {
		var le *LinkageError
		if errors.As(err, &le) {
			writeError(w, http.StatusBadRequest, le.Error())
			return
		}
		var ce *ContentTamperError
		if errors.As(err, &ce) {
			writeError(w, http.StatusBadRequest, ce.Error())
			return
		}
		var ue *UnstorableError
		if errors.As(err, &ue) {
			writeError(w, http.StatusBadRequest, ue.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not store audit batch")
		return
	}
	writeJSON(w, http.StatusOK, auditIngestResponse{
		Accepted: len(req.Events),
		TailSeq:  tail.Seq,
		TailHash: tail.Hash,
	})
}
