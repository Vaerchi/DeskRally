package controlplane

// Central recording storage: policy, rows, the upload state machine and quota reservation
// (docs/63 §2a C2, C3, C10; migration 0066).
//
// Same shape as the other tenant stores: an interface, an in-memory fake for tests/DEV and a pgx
// implementation (pgstore_recording.go). FAKE AND PG MUST AGREE, so every business rule — the create
// decision tree, the reservation arithmetic, the expiry anchor, the sweep classification — is a pure
// function in THIS file that both stores call; the stores differ only in how they read and write rows.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Recording states (C2). expired / deleted / abandoned / refused are TOMBSTONES: the row is kept so a
// recording id can never be resurrected.
const (
	RecUploading        = "uploading"
	RecEvidenceComplete = "evidence_complete"
	RecPlaybackReady    = "playback_ready"
	RecPlaybackFailed   = "playback_failed"
	// RecLost: a row that promised evidence on disk whose files are missing after a restore (migration 0077,
	// docs/63 C6/C11). Never served; ages out by retention; may return if the files reappear.
	RecLost      = "lost"
	RecExpired   = "expired"
	RecDeleted   = "deleted"
	RecAbandoned = "abandoned"
	RecRefused   = "refused"
)

// Provenance labels (C4). There is deliberately no "verified".
const (
	ProvMatchesAudit = "matches_session_audit"
	ProvNoStopEvent  = "no_matching_stop_event"
)

func recIsTombstone(state string) bool {
	switch state {
	case RecExpired, RecDeleted, RecAbandoned, RecRefused:
		return true
	}
	return false
}

// recPromisesBlob: the states whose row says the evidence copy is on the volume, i.e. the only ones that
// can become lost. uploading holds only .incoming; expired is already being unlinked (a missing file is the
// goal); deleted / abandoned / refused hold nothing.
func recPromisesBlob(state string) bool {
	return state == RecEvidenceComplete || state == RecPlaybackReady || state == RecPlaybackFailed
}

// recReleasesQuota reports whether a state no longer holds a quota reservation. expired still does:
// the bytes are on disk until deletion is confirmed.
func recReleasesQuota(state string) bool {
	return state == RecDeleted || state == RecAbandoned || state == RecRefused
}

// Limits.
const (
	RecChunkSize           = 1 << 20 // 1 MiB (C3)
	RecMaxSegments         = 64
	RecHardMaxBytes        = int64(1) << 30 // the agent's own ceiling
	RecMaxUploadLifetime   = 24 * time.Hour // C3: an upload still 'uploading' after this is abandoned
	RecMaxFinishFailures   = 3
	recEnvelopeHeaderBound = 512 // generous bound on an envelope header, for reservations
	// recMaxPlaybackDim is the muxer's dimension ceiling (DefaultMuxLimits.MaxDimension, C7) and the bound
	// migration 0067 enforces on a playback segment: the stores validate it too, so fake and pg agree.
	recMaxPlaybackDim = 8192
)

// ---- policy -----------------------------------------------------------------------------------

// RecordingPolicy is a tenant's central-recording policy. The ZERO VALUE is OFF (RetentionDays 0), and a
// tenant with no row has it.
type RecordingPolicy struct {
	RetentionDays     int   `json:"retention_days"`
	MaxRecordingBytes int64 `json:"max_recording_bytes"`
	QuotaBytes        int64 `json:"quota_bytes"`
}

// DefaultRecordingPolicy is what a tenant with no row gets: storage OFF, with the table's defaults for
// the caps so that turning retention on later does not need to invent them.
func DefaultRecordingPolicy() RecordingPolicy {
	return RecordingPolicy{RetentionDays: 0, MaxRecordingBytes: RecHardMaxBytes, QuotaBytes: 20 << 30}
}

// Enabled reports whether new recordings may be stored.
func (p RecordingPolicy) Enabled() bool { return p.RetentionDays > 0 }

// NormalizeRecordingPolicy validates a policy against the migration's CHECK ranges. Out-of-range input
// is refused, never clamped: a clamped value could silently turn storage on or widen a cap.
func NormalizeRecordingPolicy(p RecordingPolicy) error {
	switch {
	case p.RetentionDays != 0 && (p.RetentionDays < 1 || p.RetentionDays > 365):
		return errors.New("retention_days must be 0 (do not store) or 1..365")
	case p.MaxRecordingBytes < 1 || p.MaxRecordingBytes > RecHardMaxBytes:
		return errors.New("max_recording_bytes must be between 1 and 1 GiB")
	case p.QuotaBytes < 0 || p.QuotaBytes > 1125899906842624:
		return errors.New("quota_bytes is out of range")
	}
	return nil
}

// DecodeRecordingPolicyPut parses a policy PUT body. It is the FAIL-CLOSED half of the policy design
// (docs/63 D5): EVERY field must be present and named exactly, unknown fields are refused, and a JSON
// null counts as absent. A stale console that does not know the setting — or any full-overwrite client
// that sends a body without retention_days — therefore gets a 400 and cannot switch storage ON by
// omission or by a default; and a body that merely lacks the other caps cannot be used to flip
// retention either. Switching storage on takes a positive retention_days that someone typed.
func DecodeRecordingPolicyPut(body []byte) (RecordingPolicy, error) {
	var in struct {
		RetentionDays     *int   `json:"retention_days"`
		MaxRecordingBytes *int64 `json:"max_recording_bytes"`
		QuotaBytes        *int64 `json:"quota_bytes"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return RecordingPolicy{}, fmt.Errorf("invalid policy body: %w", err)
	}
	if dec.More() {
		return RecordingPolicy{}, errors.New("invalid policy body: trailing data")
	}
	if in.RetentionDays == nil || in.MaxRecordingBytes == nil || in.QuotaBytes == nil {
		return RecordingPolicy{}, errors.New("retention_days, max_recording_bytes and quota_bytes are all required")
	}
	p := RecordingPolicy{RetentionDays: *in.RetentionDays, MaxRecordingBytes: *in.MaxRecordingBytes, QuotaBytes: *in.QuotaBytes}
	if err := NormalizeRecordingPolicy(p); err != nil {
		return RecordingPolicy{}, err
	}
	return p, nil
}

// ---- reservation ------------------------------------------------------------------------------

func recDiskBound(n int64) int64 {
	frames := (n + EnvFrameSize - 1) / EnvFrameSize
	return recEnvelopeHeaderBound + n + frames*envTagSize
}

// recPlaybackMaxPlain is the LARGEST playback plaintext the muxer will ever write for an evidence segment of
// n bytes: the plan refuses output above 1.2 x input + 4 KiB (C7: muxOutNum/muxOutDen/muxOutSlack), so
// that bound — not an estimate — is what the reservation covers.
func recPlaybackMaxPlain(n int64) int64 {
	return (n*muxOutNum+muxOutDen-1)/muxOutDen + muxOutSlack
}

// RecordingReservation is the durable quota reservation for a recording of the given declared segment
// lengths: BOTH stored copies — the IVF evidence copy and the WebM playback copy at the MAXIMUM size the
// muxer is allowed to produce — each with its envelope header and per-frame AEAD overhead (C3). The
// playback file is written whole into a temp upload directory and then renamed into place, never copied,
// so the evidence copy plus one maximum-size playback file is also the peak the volume ever holds for the
// recording: the reservation is the peak, and the conversion cannot outgrow it.
func RecordingReservation(segLens []int64) int64 {
	var total int64
	for _, n := range segLens {
		total += recDiskBound(n)
		total += recDiskBound(recPlaybackMaxPlain(n))
	}
	return total
}

// ---- errors -----------------------------------------------------------------------------------

var (
	ErrRecordingNotFound        = errors.New("recording not found")
	ErrRecordingStorageOff      = errors.New("central recording storage is off for this tenant")
	ErrRecordingTooLarge        = errors.New("recording exceeds the per-recording cap")
	ErrRecordingQuota           = errors.New("tenant recording quota would be exceeded")
	ErrRecordingServerFull      = errors.New("recording volume has no room (disk floor)")
	ErrRecordingTombstoned      = errors.New("recording id was used and is no longer available")
	ErrRecordingConflict        = errors.New("recording already exists with different immutable metadata")
	ErrRecordingAlreadyComplete = errors.New("recording upload is already complete")
	ErrRecordingState           = errors.New("recording is not in a state that allows this")
	ErrRecordingOffset          = errors.New("segment offset may only advance, up to the declared length")
)

// ---- rows -------------------------------------------------------------------------------------

// RecordingSegment is one segment's upload progress.
type RecordingSegment struct {
	Index           int
	DeclaredLen     int64
	CommittedOffset int64
	SHA256          string // server-computed plaintext digest, set at evidence_complete
	// Playback copy (R1b): set together with the row's move to playback_ready, zero before.
	Playback *PlaybackSegment
}

// PlaybackSegment describes one segment's WebM playback copy (docs/63 D7, C7).
type PlaybackSegment struct {
	Index      int
	WebMLen    int64 // plaintext length of the stored WebM file
	Width      int
	Height     int
	StartMs    int64 // absolute time of the segment's first frame, ms from the recording epoch
	DurationMs int64
	Frames     int64
}

// PlaybackResult is what the muxer reports to the store: ready (with every segment) or failed (with a
// code from the closed Mux* set — never free text from the input).
type PlaybackResult struct {
	OK       bool
	Reason   string
	Segments []PlaybackSegment
}

// RecordingRow is one recording (session_recording + its segments).
type RecordingRow struct {
	TenantID, ID, SessionID, MachineID, UploadID string
	EnrollmentFP                                 [32]byte
	Generation                                   int64
	State                                        string
	DeclaredBytes, ReservedBytes                 int64
	KeyID                                        uint32
	WrappedDEK                                   []byte
	RetentionDays                                int
	FinishFailures                               int
	Provenance                                   string
	MatchedAuditSeq                              *int64
	Truncated                                    *string
	DroppedFrames, Frames, PayloadBytes          *int64
	CreatedAt                                    time.Time
	EvidenceCompleteAt, ExpiresAt                *time.Time
	ExpiredAt, DeletedAt                         *time.Time
	Segments                                     []RecordingSegment
	SegmentCount                                 int
	PlaybackError                                string // closed Mux* code when state is playback_failed
	// LostFrom / LostAt: set when the row became lost (the state it was in, and when); kept as history if
	// the files later reappear.
	LostFrom string
	LostAt   *time.Time
}

// Key returns the envelope key material of the row.
func (r *RecordingRow) Key() EnvelopeKey { return EnvelopeKey{KeyID: r.KeyID, Wrapped: r.WrappedDEK} }

func (r *RecordingRow) clone() *RecordingRow {
	c := *r
	c.WrappedDEK = append([]byte(nil), r.WrappedDEK...)
	c.Segments = make([]RecordingSegment, len(r.Segments))
	for i, sg := range r.Segments {
		if sg.Playback != nil {
			pb := *sg.Playback
			sg.Playback = &pb
		}
		c.Segments[i] = sg
	}
	return &c
}

// NewRecording is the immutable create-time metadata.
type NewRecording struct {
	ID, SessionID, MachineID, UploadID string
	EnrollmentFP                       [32]byte
	Generation                         int64
	SegmentLens                        []int64
	Key                                EnvelopeKey
}

// RecordingCreateLimits is the server-wide state a create is measured against.
type RecordingCreateLimits struct {
	FreeBytes  uint64
	FreeKnown  bool // false = the volume could not be measured: refuse (fail closed)
	FloorBytes uint64
}

// EvidenceCompletion is what finish records.
type EvidenceCompletion struct {
	Digests                             []string
	Truncated                           *string
	DroppedFrames, Frames, PayloadBytes *int64
	Provenance                          string
	MatchedAuditSeq                     *int64
}

// SegmentUpdateFn runs with the segment row locked. It returns the new committed offset (equal to the
// current one for "no change"); a non-nil error aborts and persists nothing.
type SegmentUpdateFn func(rec *RecordingRow, seg RecordingSegment) (int64, error)

// RecordingSweepRow is the sweeper's cross-tenant view of a non-terminal recording.
type RecordingSweepRow struct {
	TenantID, ID, UploadID, State string
	CreatedAt                     time.Time
	EvidenceCompleteAt, ExpiresAt *time.Time
	ExpiredAt                     *time.Time
	PolicyRetentionDays           int
}

// RecordingStore is the persistence seam for central recordings.
type RecordingStore interface {
	GetPolicy(ctx context.Context, tenantID string) (RecordingPolicy, error)
	SetPolicy(ctx context.Context, tenantID string, p RecordingPolicy) error

	// CreateRecording is idempotent on the recording id: the second return is true when a row was
	// created. It makes the quota reservation atomically with the insert (C3).
	CreateRecording(ctx context.Context, tenantID string, in NewRecording, lim RecordingCreateLimits) (*RecordingRow, bool, error)
	GetRecording(ctx context.Context, tenantID, id string) (*RecordingRow, error)
	// UpdateSegment serialises per segment (pg: row lock) and refuses unless the recording is uploading.
	UpdateSegment(ctx context.Context, tenantID, id string, idx int, fn SegmentUpdateFn) error
	// ResetSegment sets one segment's committed offset back to 0 WITHOUT counting a finish failure: the
	// reconciliation path, for when the bytes the database acknowledged are no longer on the volume.
	ResetSegment(ctx context.Context, tenantID, id string, idx int) error
	// RecordFinishFailure resets the listed segments to offset 0, counts the failure, and moves the
	// recording to refused after RecMaxFinishFailures. It returns the resulting state.
	RecordFinishFailure(ctx context.Context, tenantID, id string, resetIdx []int) (string, error)
	// CompleteEvidence moves uploading -> evidence_complete (all segments fully committed), stamping
	// evidence_complete_at with SERVER time and expires_at = that + retention (C10).
	CompleteEvidence(ctx context.Context, tenantID, id string, c EvidenceCompletion) (*RecordingRow, error)
	// RefuseRecording / AbandonRecording move uploading -> refused / abandoned and release the reservation.
	RefuseRecording(ctx context.Context, tenantID, id string) error
	AbandonRecording(ctx context.Context, tenantID, id string) error
	// SetPlaybackState is the R1b hook: evidence_complete|playback_* -> playback_ready|playback_failed.
	SetPlaybackState(ctx context.Context, tenantID, id, state string) error
	// RecordPlayback is the muxer's outcome: evidence_complete (or a retry from playback_failed) ->
	// playback_ready with the per-segment metadata, or -> playback_failed with a reason code. A recording
	// already ready cannot be recorded again (ErrRecordingState: a concurrent job won).
	RecordPlayback(ctx context.Context, tenantID, id string, res PlaybackResult) error
	// ListRecordings pages a tenant's COMPLETED recordings (evidence_complete .. deleted), newest first.
	ListRecordings(ctx context.Context, tenantID string, f RecordingListFilter) ([]RecordingListItem, error)
	// RecordingIDsBySession maps each given session id to the id of its NEWEST completed recording (the list's
	// states, newest by (evidence_complete_at, id)); a session with none is absent. It performs NO authorization:
	// the caller must decide which sessions it may name a recording for (the session list gates it on
	// CapViewRecordings over the machine's current group). At most RecIDsBySessionMax ids are looked up per call.
	RecordingIDsBySession(ctx context.Context, tenantID string, sessionIDs []string) (map[string]string, error)
	// ApplyRetention persists the shortened retention deadline of one completed recording under the row lock:
	// expires_at = LEAST(stored, evidence_complete_at + the tenant's CURRENT positive retention). It returns
	// the durable expires_at after the call and whether it moved; a row not in a completed state is left
	// alone (ErrRecordingState). It can only move the deadline earlier.
	ApplyRetention(ctx context.Context, tenantID, id string) (expiresAt time.Time, changed bool, err error)
	// MarkExpired / MarkDeleted are the retention steps (durable mark, unlink, durable confirm).
	MarkExpired(ctx context.Context, tenantID, id string) error
	MarkDeleted(ctx context.Context, tenantID, id string) error
	// MarkLost moves a recording whose evidence files are missing to lost (docs/63 C11), remembering the state it
	// was in, and returns that state. A row already lost is left alone (idempotent, returns its lost_from); a row
	// in any state that does not promise a blob is ErrRecordingState. Reconcile mode only (the caller decides).
	MarkLost(ctx context.Context, tenantID, id string) (from string, err error)
	// RestoreLost moves a lost recording back to `to` (evidence_complete, playback_ready or playback_failed)
	// because its files are present again; any other state, or a row that is not lost, is ErrRecordingState.
	RestoreLost(ctx context.Context, tenantID, id, to string) error
	// SweepList is the narrow cross-tenant lister behind the retention + orphan sweeper (C6).
	SweepList(ctx context.Context) ([]RecordingSweepRow, error)
	// LockRecording takes the PER-RECORDING exclusive lock (pg: a session advisory lock keyed by tenant and
	// recording id, valid across processes; fake: a per-recording mutex) and returns the unlock function.
	// finish verification, refusal, promotion + its rollback, abandonment, retention expiry/deletion and the
	// playback publish all run under it, so a filesystem transition and the state commit that acknowledges it
	// are one step as seen by every other holder. It is NOT reentrant: never take it while holding it. It
	// waits for ctx; a cancelled wait returns the context's error and holds nothing.
	LockRecording(ctx context.Context, tenantID, id string) (unlock func(), err error)
}

// RecIDsBySessionMax bounds one RecordingIDsBySession lookup (a session list is far longer than a page).
const RecIDsBySessionMax = 5000

// RecordingListItem is one row of the list: no key material, no upload id, no segment detail.
type RecordingListItem struct {
	ID, SessionID, MachineID, State, Provenance string
	SegmentCount                                int
	DeclaredBytes                               int64
	Truncated                                   *string
	DroppedFrames                               *int64
	PlaybackError                               string
	EvidenceCompleteAt                          time.Time
	ExpiresAt                                   time.Time
}

// RecordingListFilter selects and pages the list. The cursor is a POSITION in the (evidence_complete_at,
// id) order — the item after which the next page starts — so a page can be filtered further by the
// caller (group scope) without the cursor ever depending on what the caller was shown.
type RecordingListFilter struct {
	SessionID, MachineID string // empty = any
	Limit                int    // 1..RecListMax
	After                *RecordingCursor
}

// RecordingCursor is the position of the last row of a page.
type RecordingCursor struct {
	At time.Time
	ID string
}

const (
	RecListDefault = 50
	RecListMax     = 200
)

// recListStates are the states a list shows: completed uploads and their tombstones. Uploading,
// abandoned and refused recordings never completed and hold no content.
func recListState(state string) bool {
	switch state {
	case RecEvidenceComplete, RecPlaybackReady, RecPlaybackFailed, RecLost, RecExpired, RecDeleted:
		return true
	}
	return false
}

// cursorAfter reports whether (at, id) sorts strictly AFTER the cursor in the newest-first order, i.e.
// belongs to the next page.
func cursorAfter(at time.Time, id string, c *RecordingCursor) bool {
	if c == nil {
		return true
	}
	if at.Before(c.At) {
		return true
	}
	return at.Equal(c.At) && id < c.ID
}

func clampListLimit(n int) int {
	switch {
	case n <= 0:
		return RecListDefault
	case n > RecListMax:
		return RecListMax
	}
	return n
}

// playbackTransition is the C2/C7 rule for the muxer's outcome: it may only be recorded from
// evidence_complete, or as a retry from playback_failed, or to demote ready -> failed. ready -> ready is
// refused so that two racing jobs (two replicas) cannot both claim the win.
func playbackTransition(from string, ok bool) error {
	switch {
	case from == RecEvidenceComplete,
		from == RecPlaybackFailed && ok,
		from == RecPlaybackFailed && !ok,
		from == RecPlaybackReady && !ok:
		return nil
	}
	return ErrRecordingState
}

// validPlaybackReason accepts only the closed set of muxer failure codes: what is stored is shown to
// operators, so it must never be free text derived from the input.
func validPlaybackReason(r string) bool {
	switch r {
	case MuxInvalid, MuxLimit, MuxTimeBudget, MuxIO, MuxInconsistent, "internal":
		return true
	}
	return false
}

// validatePlaybackSegments requires exactly one well-formed entry per segment, in order.
func validatePlaybackSegments(segs []PlaybackSegment, want int) error {
	if len(segs) != want {
		return ErrRecordingState
	}
	for i, p := range segs {
		if p.Index != i || p.WebMLen < 1 || p.Width < 1 || p.Width > recMaxPlaybackDim || p.Height < 1 || p.Height > recMaxPlaybackDim ||
			p.StartMs < 0 || p.DurationMs < 0 || p.Frames < 1 {
			return ErrRecordingState
		}
	}
	return nil
}

// ---- shared rules -----------------------------------------------------------------------------

func createMatches(r *RecordingRow, in NewRecording) bool {
	if r.SessionID != in.SessionID || r.MachineID != in.MachineID || r.Generation != in.Generation ||
		r.EnrollmentFP != in.EnrollmentFP || len(r.Segments) != len(in.SegmentLens) {
		return false
	}
	for i, s := range r.Segments {
		if s.DeclaredLen != in.SegmentLens[i] {
			return false
		}
	}
	return true
}

// createContext is everything decideCreate needs besides the request.
type createContext struct {
	existing        *RecordingRow
	policy          RecordingPolicy
	tenantReserved  int64
	globalUnwritten int64
	lim             RecordingCreateLimits
}

// decideCreate is the create decision tree, shared by both stores. It returns (reserve, existingRow,
// error): a nil error with a non-nil existingRow means "idempotent replay of an uploading recording";
// with a nil row it means "insert, reserving `reserve` bytes".
func decideCreate(in NewRecording, c createContext) (int64, *RecordingRow, error) {
	if c.existing != nil {
		switch {
		case recIsTombstone(c.existing.State):
			return 0, nil, ErrRecordingTombstoned
		case !createMatches(c.existing, in):
			return 0, nil, ErrRecordingConflict
		case c.existing.State != RecUploading:
			return 0, nil, ErrRecordingAlreadyComplete
		}
		return 0, c.existing, nil
	}
	if !c.policy.Enabled() {
		return 0, nil, ErrRecordingStorageOff
	}
	var total int64
	for _, n := range in.SegmentLens {
		total += n
	}
	if total > c.policy.MaxRecordingBytes || total > RecHardMaxBytes {
		return 0, nil, ErrRecordingTooLarge
	}
	reserve := RecordingReservation(in.SegmentLens)
	if c.tenantReserved+reserve > c.policy.QuotaBytes {
		return 0, nil, ErrRecordingQuota
	}
	if !c.lim.FreeKnown {
		return 0, nil, ErrRecordingServerFull
	}
	// The floor is measured against RESERVATIONS: what live uploads have promised but not yet written
	// is subtracted from the free space before the new reservation and the floor are applied.
	need := uint64(c.globalUnwritten) + uint64(reserve) + c.lim.FloorBytes
	if need < uint64(reserve) || need > c.lim.FreeBytes {
		return 0, nil, ErrRecordingServerFull
	}
	return reserve, nil, nil
}

// completionExpiry is the retention anchor (C10): SERVER time at evidence_complete + retention. The
// retention used is the create-time snapshot, shortened (never lengthened) to the tenant's CURRENT
// policy when that is positive and smaller.
func completionExpiry(evidenceAt time.Time, snapshotDays, policyDays int) time.Time {
	days := snapshotDays
	if policyDays > 0 && policyDays < days {
		days = policyDays
	}
	return evidenceAt.Add(time.Duration(days) * 24 * time.Hour)
}

// shortenedExpiry is the durable retention rule (C10): the stored deadline pulled EARLIER, never later, to
// evidence_complete_at + the tenant's CURRENT retention when that is positive. changed reports whether the
// stored value must be rewritten. Both stores persist the result under the row lock on every sweep, so a
// shortened deadline survives a later lengthening of the policy or switching storage off.
func shortenedExpiry(stored, evidenceAt time.Time, policyDays int) (time.Time, bool) {
	if policyDays <= 0 {
		return stored, false
	}
	if p := evidenceAt.Add(time.Duration(policyDays) * 24 * time.Hour); p.Before(stored) {
		return p, true
	}
	return stored, false
}

// recRetentionLive: the states whose schedule retention may still move (lost included: it ages out too).
func recRetentionLive(state string) bool {
	return recPromisesBlob(state) || state == RecLost // a lost row still ages out (and shortens) by retention
}

// SweepAction is what the sweeper should do with one row.
type SweepAction int

const (
	SweepNone      SweepAction = iota
	SweepAbandon               // uploading longer than the max upload lifetime
	SweepExpire                // retention has run out
	SweepDeleteNow             // already expired; physical deletion still owed
)

// EffectiveExpiry is when a row logically expires: its stored schedule, pulled EARLIER (never later) by
// the tenant's current retention when that is positive. Turning storage off (0) leaves the stored
// schedule alone, so existing rows expire on their own timetable (C10). The sweeper persists this value
// (RecordingStore.ApplyRetention) before it classifies, so what it acts on is the DURABLE deadline; this
// computation is only the fallback when that write failed (never a later deadline than the stored one).
func (r RecordingSweepRow) EffectiveExpiry() (time.Time, bool) {
	if r.ExpiresAt == nil || r.EvidenceCompleteAt == nil {
		return time.Time{}, false
	}
	exp, _ := shortenedExpiry(*r.ExpiresAt, *r.EvidenceCompleteAt, r.PolicyRetentionDays)
	return exp, true
}

// ClassifySweep decides the sweeper's action for a row at `now`.
func ClassifySweep(r RecordingSweepRow, now time.Time) SweepAction {
	switch r.State {
	case RecUploading:
		if now.Sub(r.CreatedAt) >= RecMaxUploadLifetime {
			return SweepAbandon
		}
	case RecEvidenceComplete, RecPlaybackReady, RecPlaybackFailed, RecLost:
		if exp, ok := r.EffectiveExpiry(); ok && !now.Before(exp) {
			return SweepExpire
		}
	case RecExpired:
		return SweepDeleteNow
	}
	return SweepNone
}

// ---- in-memory fake ---------------------------------------------------------------------------

// InMemoryRecordingStore is the concurrency-safe fake: same decisions (the shared functions above),
// one coarse mutex instead of row locks.
type InMemoryRecordingStore struct {
	mu       sync.Mutex
	policies map[string]RecordingPolicy
	rows     map[string]*RecordingRow
	// Now is the SERVER clock (tests inject one; nil = time.Now).
	Now func() time.Time

	lockMu sync.Mutex
	locks  map[string]*recLockEntry
}

type recLockEntry struct {
	ch   chan struct{}
	refs int
}

// NewInMemoryRecordingStore constructs an empty fake.
func NewInMemoryRecordingStore() *InMemoryRecordingStore {
	return &InMemoryRecordingStore{policies: map[string]RecordingPolicy{}, rows: map[string]*RecordingRow{}}
}

var _ RecordingStore = (*InMemoryRecordingStore)(nil)

// LockRecording is the fake's per-recording mutex (a one-slot channel, so a waiter honours ctx).
func (s *InMemoryRecordingStore) LockRecording(ctx context.Context, tenantID, id string) (func(), error) {
	k := recKey(tenantID, id)
	s.lockMu.Lock()
	if s.locks == nil {
		s.locks = map[string]*recLockEntry{}
	}
	e := s.locks[k]
	if e == nil {
		e = &recLockEntry{ch: make(chan struct{}, 1)}
		s.locks[k] = e
	}
	e.refs++
	s.lockMu.Unlock()
	drop := func() {
		s.lockMu.Lock()
		if e.refs--; e.refs == 0 {
			delete(s.locks, k)
		}
		s.lockMu.Unlock()
	}
	select {
	case e.ch <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-e.ch; drop() }) }, nil
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}
}

func (s *InMemoryRecordingStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func recKey(tenant, id string) string { return tenant + "/" + id }

func (s *InMemoryRecordingStore) GetPolicy(_ context.Context, tenantID string) (RecordingPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.policies[tenantID]; ok {
		return p, nil
	}
	return DefaultRecordingPolicy(), nil
}

func (s *InMemoryRecordingStore) SetPolicy(_ context.Context, tenantID string, p RecordingPolicy) error {
	if err := NormalizeRecordingPolicy(p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[tenantID] = p
	return nil
}

func (s *InMemoryRecordingStore) globalUnwrittenLocked() int64 {
	var total int64
	for _, r := range s.rows {
		if r.State != RecUploading && r.State != RecEvidenceComplete {
			continue
		}
		var written int64
		for _, sg := range r.Segments {
			written += sg.CommittedOffset
		}
		if d := r.ReservedBytes - written; d > 0 {
			total += d
		}
	}
	return total
}

func (s *InMemoryRecordingStore) CreateRecording(_ context.Context, tenantID string, in NewRecording, lim RecordingCreateLimits) (*RecordingRow, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var existing *RecordingRow
	if r, ok := s.rows[recKey(tenantID, in.ID)]; ok {
		existing = r
	}
	policy := DefaultRecordingPolicy()
	if p, ok := s.policies[tenantID]; ok {
		policy = p
	}
	var tenantReserved int64
	for _, r := range s.rows {
		if r.TenantID == tenantID && !recReleasesQuota(r.State) {
			tenantReserved += r.ReservedBytes
		}
	}
	reserve, replay, err := decideCreate(in, createContext{existing: existing, policy: policy,
		tenantReserved: tenantReserved, globalUnwritten: s.globalUnwrittenLocked(), lim: lim})
	if err != nil {
		return nil, false, err
	}
	if replay != nil {
		return replay.clone(), false, nil
	}
	row := &RecordingRow{
		TenantID: tenantID, ID: in.ID, SessionID: in.SessionID, MachineID: in.MachineID, UploadID: in.UploadID,
		EnrollmentFP: in.EnrollmentFP, Generation: in.Generation, State: RecUploading,
		ReservedBytes: reserve, KeyID: in.Key.KeyID, WrappedDEK: append([]byte(nil), in.Key.Wrapped...),
		RetentionDays: policy.RetentionDays, CreatedAt: s.now(),
	}
	for i, n := range in.SegmentLens {
		row.DeclaredBytes += n
		row.Segments = append(row.Segments, RecordingSegment{Index: i, DeclaredLen: n})
	}
	s.rows[recKey(tenantID, in.ID)] = row
	return row.clone(), true, nil
}

func (s *InMemoryRecordingStore) GetRecording(_ context.Context, tenantID, id string) (*RecordingRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[recKey(tenantID, id)]; ok {
		return r.clone(), nil
	}
	return nil, ErrRecordingNotFound
}

func (s *InMemoryRecordingStore) get(tenantID, id string) (*RecordingRow, error) {
	if r, ok := s.rows[recKey(tenantID, id)]; ok {
		return r, nil
	}
	return nil, ErrRecordingNotFound
}

func (s *InMemoryRecordingStore) UpdateSegment(_ context.Context, tenantID, id string, idx int, fn SegmentUpdateFn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.get(tenantID, id)
	if err != nil {
		return err
	}
	if r.State != RecUploading {
		return ErrRecordingState
	}
	if idx < 0 || idx >= len(r.Segments) {
		return ErrRecordingNotFound
	}
	seg := r.Segments[idx]
	n, err := fn(r.clone(), seg)
	if err != nil {
		return err
	}
	if n == seg.CommittedOffset {
		return nil
	}
	if n < seg.CommittedOffset || n > seg.DeclaredLen {
		return ErrRecordingOffset
	}
	r.Segments[idx].CommittedOffset = n
	return nil
}

func (s *InMemoryRecordingStore) RecordFinishFailure(_ context.Context, tenantID, id string, resetIdx []int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.get(tenantID, id)
	if err != nil {
		return "", err
	}
	if r.State != RecUploading {
		return r.State, ErrRecordingState
	}
	for _, i := range resetIdx {
		if i >= 0 && i < len(r.Segments) {
			r.Segments[i].CommittedOffset = 0
			r.Segments[i].SHA256 = ""
		}
	}
	r.FinishFailures++
	if r.FinishFailures >= RecMaxFinishFailures {
		r.State = RecRefused
	}
	return r.State, nil
}

func (s *InMemoryRecordingStore) ResetSegment(_ context.Context, tenantID, id string, idx int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.get(tenantID, id)
	if err != nil {
		return err
	}
	if r.State != RecUploading {
		return ErrRecordingState
	}
	if idx < 0 || idx >= len(r.Segments) {
		return ErrRecordingNotFound
	}
	r.Segments[idx].CommittedOffset = 0
	r.Segments[idx].SHA256 = ""
	return nil
}

func (s *InMemoryRecordingStore) CompleteEvidence(_ context.Context, tenantID, id string, c EvidenceCompletion) (*RecordingRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.get(tenantID, id)
	if err != nil {
		return nil, err
	}
	if r.State != RecUploading {
		return nil, ErrRecordingState
	}
	if len(c.Digests) != len(r.Segments) {
		return nil, ErrRecordingState
	}
	for _, sg := range r.Segments {
		if sg.CommittedOffset != sg.DeclaredLen {
			return nil, ErrRecordingState
		}
	}
	policy := DefaultRecordingPolicy()
	if p, ok := s.policies[tenantID]; ok {
		policy = p
	}
	// Microsecond precision, like the pg column, so list cursors taken from a stored time round-trip.
	now := s.now().Truncate(time.Microsecond)
	exp := completionExpiry(now, r.RetentionDays, policy.RetentionDays)
	for i := range r.Segments {
		r.Segments[i].SHA256 = c.Digests[i]
	}
	r.State, r.Provenance, r.MatchedAuditSeq = RecEvidenceComplete, c.Provenance, c.MatchedAuditSeq
	r.Truncated, r.DroppedFrames, r.Frames, r.PayloadBytes = c.Truncated, c.DroppedFrames, c.Frames, c.PayloadBytes
	r.EvidenceCompleteAt, r.ExpiresAt = &now, &exp
	return r.clone(), nil
}

func (s *InMemoryRecordingStore) leaveUploading(tenantID, id, to string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.get(tenantID, id)
	if err != nil {
		return err
	}
	if r.State != RecUploading {
		return ErrRecordingState
	}
	r.State = to
	return nil
}

func (s *InMemoryRecordingStore) RefuseRecording(_ context.Context, tenantID, id string) error {
	return s.leaveUploading(tenantID, id, RecRefused)
}

func (s *InMemoryRecordingStore) AbandonRecording(_ context.Context, tenantID, id string) error {
	return s.leaveUploading(tenantID, id, RecAbandoned)
}

func (s *InMemoryRecordingStore) SetPlaybackState(_ context.Context, tenantID, id, state string) error {
	if state != RecPlaybackReady && state != RecPlaybackFailed {
		return ErrRecordingState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.get(tenantID, id)
	if err != nil {
		return err
	}
	switch {
	case r.State == RecEvidenceComplete,
		r.State == RecPlaybackReady && state == RecPlaybackFailed,
		r.State == RecPlaybackFailed && state == RecPlaybackReady:
		r.State = state
		return nil
	}
	return ErrRecordingState
}

func (s *InMemoryRecordingStore) RecordPlayback(_ context.Context, tenantID, id string, res PlaybackResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.get(tenantID, id)
	if err != nil {
		return err
	}
	if err := playbackTransition(r.State, res.OK); err != nil {
		return err
	}
	if res.OK {
		if err := validatePlaybackSegments(res.Segments, len(r.Segments)); err != nil {
			return err
		}
		for _, ps := range res.Segments {
			pb := ps
			r.Segments[ps.Index].Playback = &pb
		}
		r.State, r.PlaybackError = RecPlaybackReady, ""
		return nil
	}
	if !validPlaybackReason(res.Reason) {
		return ErrRecordingState
	}
	r.State, r.PlaybackError = RecPlaybackFailed, res.Reason
	return nil
}

func (s *InMemoryRecordingStore) RecordingIDsBySession(_ context.Context, tenantID string, sessionIDs []string) (map[string]string, error) {
	if len(sessionIDs) > RecIDsBySessionMax {
		return nil, errors.New("too many sessions in one recording lookup")
	}
	want := make(map[string]bool, len(sessionIDs))
	for _, id := range sessionIDs {
		want[id] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	best := map[string]*RecordingRow{}
	for _, r := range s.rows {
		if r.TenantID != tenantID || !want[r.SessionID] || !recListState(r.State) || r.EvidenceCompleteAt == nil {
			continue
		}
		b := best[r.SessionID]
		if b == nil || r.EvidenceCompleteAt.After(*b.EvidenceCompleteAt) || (r.EvidenceCompleteAt.Equal(*b.EvidenceCompleteAt) && r.ID > b.ID) {
			best[r.SessionID] = r
		}
	}
	out := make(map[string]string, len(best))
	for sid, r := range best {
		out[sid] = r.ID
	}
	return out, nil
}

func (s *InMemoryRecordingStore) ListRecordings(_ context.Context, tenantID string, f RecordingListFilter) ([]RecordingListItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []RecordingListItem
	for _, r := range s.rows {
		if r.TenantID != tenantID || !recListState(r.State) || r.EvidenceCompleteAt == nil || r.ExpiresAt == nil {
			continue
		}
		if (f.SessionID != "" && r.SessionID != f.SessionID) || (f.MachineID != "" && r.MachineID != f.MachineID) {
			continue
		}
		if !cursorAfter(*r.EvidenceCompleteAt, r.ID, f.After) {
			continue
		}
		out = append(out, RecordingListItem{ID: r.ID, SessionID: r.SessionID, MachineID: r.MachineID, State: r.State,
			Provenance: r.Provenance, SegmentCount: len(r.Segments), DeclaredBytes: r.DeclaredBytes,
			Truncated: r.Truncated, DroppedFrames: r.DroppedFrames, PlaybackError: r.PlaybackError,
			EvidenceCompleteAt: *r.EvidenceCompleteAt, ExpiresAt: *r.ExpiresAt})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].EvidenceCompleteAt.Equal(out[j].EvidenceCompleteAt) {
			return out[i].EvidenceCompleteAt.After(out[j].EvidenceCompleteAt)
		}
		return out[i].ID > out[j].ID
	})
	if n := clampListLimit(f.Limit); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (s *InMemoryRecordingStore) ApplyRetention(_ context.Context, tenantID, id string) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.get(tenantID, id)
	if err != nil {
		return time.Time{}, false, err
	}
	if !recRetentionLive(r.State) || r.ExpiresAt == nil || r.EvidenceCompleteAt == nil {
		return time.Time{}, false, ErrRecordingState
	}
	exp, changed := shortenedExpiry(*r.ExpiresAt, *r.EvidenceCompleteAt, s.policies[tenantID].RetentionDays)
	if changed {
		r.ExpiresAt = &exp
	}
	return exp, changed, nil
}

func (s *InMemoryRecordingStore) MarkExpired(_ context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.get(tenantID, id)
	if err != nil {
		return err
	}
	switch r.State {
	case RecEvidenceComplete, RecPlaybackReady, RecPlaybackFailed, RecLost:
		now := s.now()
		r.State, r.ExpiredAt = RecExpired, &now
		return nil
	case RecExpired, RecDeleted:
		return nil // idempotent
	}
	return ErrRecordingState
}

func (s *InMemoryRecordingStore) MarkDeleted(_ context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.get(tenantID, id)
	if err != nil {
		return err
	}
	switch r.State {
	case RecExpired:
		now := s.now()
		r.State, r.DeletedAt = RecDeleted, &now
		return nil
	case RecDeleted:
		return nil
	}
	return ErrRecordingState
}

func (s *InMemoryRecordingStore) MarkLost(_ context.Context, tenantID, id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.get(tenantID, id)
	if err != nil {
		return "", err
	}
	switch {
	case r.State == RecLost:
		return r.LostFrom, nil
	case recPromisesBlob(r.State):
		now := s.now().Truncate(time.Microsecond)
		r.LostFrom, r.LostAt, r.State = r.State, &now, RecLost
		return r.LostFrom, nil
	}
	return "", ErrRecordingState
}

func (s *InMemoryRecordingStore) RestoreLost(_ context.Context, tenantID, id, to string) error {
	if !recPromisesBlob(to) {
		return ErrRecordingState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.get(tenantID, id)
	if err != nil {
		return err
	}
	if r.State != RecLost {
		return ErrRecordingState
	}
	r.State = to
	return nil
}

func (s *InMemoryRecordingStore) SweepList(_ context.Context) ([]RecordingSweepRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []RecordingSweepRow
	for _, r := range s.rows {
		if recReleasesQuota(r.State) {
			continue
		}
		pol := 0
		if p, ok := s.policies[r.TenantID]; ok {
			pol = p.RetentionDays
		}
		out = append(out, RecordingSweepRow{TenantID: r.TenantID, ID: r.ID, UploadID: r.UploadID, State: r.State,
			CreatedAt: r.CreatedAt, EvidenceCompleteAt: r.EvidenceCompleteAt, ExpiresAt: r.ExpiresAt,
			ExpiredAt: r.ExpiredAt, PolicyRetentionDays: pol})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID+out[i].ID < out[j].TenantID+out[j].ID })
	return out, nil
}
