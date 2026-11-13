package controlplane

// PgRecordingStore — the pgx RecordingStore over migrations/0066. Every tenant-scoped operation runs
// inside withTenant (RLS pinned). The create path takes one global advisory lock so the quota and disk
// floor checks and the insert are atomic across tenants (creates are rare; serialising them is cheap).
// Chunk commits lock the SEGMENT row (FOR UPDATE) and share-lock the recording row, so a commit cannot
// race an abandon/complete. The sweeper's two cross-tenant reads go through the narrow SECURITY DEFINER
// functions, never through a bypass.

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgRecordingStore is the pgx-backed RecordingStore.
type PgRecordingStore struct {
	Pool *pgxpool.Pool
	// LockPoolMax bounds the connections dedicated to per-recording advisory locks (default 16). They come
	// from a SEPARATE pool built from Pool's own configuration: a lock holder or waiter must never take a
	// connection the locked operations themselves need, or a saturated query pool deadlocks every holder.
	LockPoolMax int
	// LockWait bounds how long LockRecording waits for a lock connection AND for the lock (default 15s);
	// beyond it the call fails with ErrRecordingLockBusy instead of queueing without limit.
	LockWait time.Duration

	lockOnce sync.Once
	lockPool *pgxpool.Pool
	lockErr  error
}

// ErrRecordingLockBusy: the per-recording lock could not be taken within the bounded wait (lock pool
// saturated, or another holder kept the lock).
var ErrRecordingLockBusy = errors.New("recording lock busy")

// Close releases the dedicated lock pool (the query pool belongs to the caller).
func (s *PgRecordingStore) Close() {
	if s.lockPool != nil {
		s.lockPool.Close()
	}
}

func (s *PgRecordingStore) lockPoolFor() (*pgxpool.Pool, error) {
	s.lockOnce.Do(func() {
		cfg := s.Pool.Config() // a copy: same database, role and TLS, its own connections
		cfg.MaxConns = int32(s.LockPoolMax)
		if cfg.MaxConns <= 0 {
			cfg.MaxConns = 16
		}
		cfg.MinConns = 0
		cfg.MaxConnIdleTime = 30 * time.Second
		s.lockPool, s.lockErr = pgxpool.NewWithConfig(context.Background(), cfg)
	})
	return s.lockPool, s.lockErr
}

// NewPgRecordingStore constructs a PgRecordingStore.
func NewPgRecordingStore(pool *pgxpool.Pool) *PgRecordingStore { return &PgRecordingStore{Pool: pool} }

var _ RecordingStore = (*PgRecordingStore)(nil)

// recUUIDOK guards every id that reaches a uuid column: a malformed id is "not found", never a 22P02
// that would read as a server fault (pathid.go).
func recUUIDOK(ids ...string) bool {
	for _, id := range ids {
		if namesNoUUIDRow(id) {
			return false
		}
	}
	return true
}

func (s *PgRecordingStore) GetPolicy(ctx context.Context, tenantID string) (RecordingPolicy, error) {
	p := DefaultRecordingPolicy()
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT retention_days, max_recording_bytes, quota_bytes
			FROM tenant_recording_policy WHERE tenant_id = $1`, tenantID).
			Scan(&p.RetentionDays, &p.MaxRecordingBytes, &p.QuotaBytes)
		if errors.Is(err, pgx.ErrNoRows) {
			p = DefaultRecordingPolicy()
			return nil
		}
		return err
	})
	if err != nil {
		return DefaultRecordingPolicy(), err
	}
	return p, nil
}

func (s *PgRecordingStore) SetPolicy(ctx context.Context, tenantID string, p RecordingPolicy) error {
	if err := NormalizeRecordingPolicy(p); err != nil {
		return err
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO tenant_recording_policy (tenant_id, retention_days, max_recording_bytes, quota_bytes, updated_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (tenant_id) DO UPDATE
			SET retention_days = EXCLUDED.retention_days, max_recording_bytes = EXCLUDED.max_recording_bytes,
			    quota_bytes = EXCLUDED.quota_bytes, updated_at = now()`,
			tenantID, p.RetentionDays, p.MaxRecordingBytes, p.QuotaBytes)
		return err
	})
}

const recRowCols = `r.session_id::text, r.machine_id::text, r.upload_id::text, r.enrollment_fp, r.generation, r.state,
	r.declared_bytes, r.reserved_bytes, r.key_id, r.wrapped_dek, r.retention_days, r.finish_failures,
	COALESCE(r.provenance, ''), r.matched_audit_seq, r.truncated, r.dropped_frames, r.frames, r.payload_bytes,
	r.created_at, r.evidence_complete_at, r.expires_at, r.expired_at, r.deleted_at, COALESCE(r.playback_error, ''),
	COALESCE(r.lost_from, ''), r.lost_at`

// loadRecording reads a row and its segments within tx. lock is "", "FOR SHARE" or "FOR UPDATE" (the
// lock applies to the recording row).
func loadRecording(ctx context.Context, tx pgx.Tx, tenantID, id, lock string) (*RecordingRow, error) {
	r := &RecordingRow{TenantID: tenantID, ID: id}
	var fp []byte
	var keyID int64
	err := tx.QueryRow(ctx, `SELECT `+recRowCols+` FROM session_recording r WHERE r.tenant_id = $1 AND r.id = $2 `+lock,
		tenantID, id).Scan(&r.SessionID, &r.MachineID, &r.UploadID, &fp, &r.Generation, &r.State,
		&r.DeclaredBytes, &r.ReservedBytes, &keyID, &r.WrappedDEK, &r.RetentionDays, &r.FinishFailures,
		&r.Provenance, &r.MatchedAuditSeq, &r.Truncated, &r.DroppedFrames, &r.Frames, &r.PayloadBytes,
		&r.CreatedAt, &r.EvidenceCompleteAt, &r.ExpiresAt, &r.ExpiredAt, &r.DeletedAt, &r.PlaybackError, &r.LostFrom, &r.LostAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRecordingNotFound
	}
	if err != nil {
		return nil, err
	}
	copy(r.EnrollmentFP[:], fp)
	r.KeyID = uint32(keyID)
	rows, err := tx.Query(ctx, `SELECT idx, declared_len, committed_offset, COALESCE(sha256, ''),
			webm_len, width, height, start_ms, duration_ms, frames
		FROM session_recording_segment WHERE tenant_id = $1 AND recording_id = $2 ORDER BY idx`, tenantID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sg RecordingSegment
		var webm, start, dur, frames *int64
		var w, h *int32
		if err := rows.Scan(&sg.Index, &sg.DeclaredLen, &sg.CommittedOffset, &sg.SHA256,
			&webm, &w, &h, &start, &dur, &frames); err != nil {
			return nil, err
		}
		if webm != nil && w != nil && h != nil && start != nil && dur != nil && frames != nil {
			sg.Playback = &PlaybackSegment{Index: sg.Index, WebMLen: *webm, Width: int(*w), Height: int(*h),
				StartMs: *start, DurationMs: *dur, Frames: *frames}
		}
		r.Segments = append(r.Segments, sg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	r.SegmentCount = len(r.Segments)
	return r, nil
}

func (s *PgRecordingStore) GetRecording(ctx context.Context, tenantID, id string) (*RecordingRow, error) {
	if !recUUIDOK(id) {
		return nil, ErrRecordingNotFound
	}
	var r *RecordingRow
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var err error
		r, err = loadRecording(ctx, tx, tenantID, id, "")
		return err
	})
	return r, err
}

func (s *PgRecordingStore) CreateRecording(ctx context.Context, tenantID string, in NewRecording, lim RecordingCreateLimits) (*RecordingRow, bool, error) {
	if !recUUIDOK(in.ID, in.SessionID, in.MachineID, in.UploadID) {
		return nil, false, ErrRecordingNotFound
	}
	var out *RecordingRow
	created := false
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// One lock for all creates: the quota and the disk-floor checks below read sums that a
		// concurrent create would change.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('rmt-recording-create'))`); err != nil {
			return err
		}
		existing, err := loadRecording(ctx, tx, tenantID, in.ID, "FOR UPDATE")
		if errors.Is(err, ErrRecordingNotFound) {
			existing, err = nil, nil
		}
		if err != nil {
			return err
		}
		policy := DefaultRecordingPolicy()
		if err := tx.QueryRow(ctx, `SELECT retention_days, max_recording_bytes, quota_bytes
			FROM tenant_recording_policy WHERE tenant_id = $1`, tenantID).
			Scan(&policy.RetentionDays, &policy.MaxRecordingBytes, &policy.QuotaBytes); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		} else if errors.Is(err, pgx.ErrNoRows) {
			policy = DefaultRecordingPolicy()
		}
		var tenantReserved, globalUnwritten int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(SUM(reserved_bytes), 0)::bigint FROM session_recording
			WHERE tenant_id = $1 AND state NOT IN ('deleted', 'abandoned', 'refused')`, tenantID).Scan(&tenantReserved); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT cp_recording_global_unwritten()`).Scan(&globalUnwritten); err != nil {
			return err
		}
		reserve, replay, derr := decideCreate(in, createContext{existing: existing, policy: policy,
			tenantReserved: tenantReserved, globalUnwritten: globalUnwritten, lim: lim})
		if derr != nil {
			return derr
		}
		if replay != nil {
			out = replay
			return nil
		}
		var declared int64
		for _, n := range in.SegmentLens {
			declared += n
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO session_recording (tenant_id, id, session_id, machine_id, upload_id, enrollment_fp, generation,
				state, segment_count, declared_bytes, reserved_bytes, key_id, wrapped_dek, retention_days)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'uploading', $8, $9, $10, $11, $12, $13)`,
			tenantID, in.ID, in.SessionID, in.MachineID, in.UploadID, in.EnrollmentFP[:], in.Generation,
			len(in.SegmentLens), declared, reserve, int64(in.Key.KeyID), in.Key.Wrapped, policy.RetentionDays); err != nil {
			return err
		}
		for i, n := range in.SegmentLens {
			if _, err := tx.Exec(ctx, `INSERT INTO session_recording_segment (tenant_id, recording_id, idx, declared_len)
				VALUES ($1, $2, $3, $4)`, tenantID, in.ID, i, n); err != nil {
				return err
			}
		}
		row, err := loadRecording(ctx, tx, tenantID, in.ID, "")
		if err != nil {
			return err
		}
		out, created = row, true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, created, nil
}

func (s *PgRecordingStore) UpdateSegment(ctx context.Context, tenantID, id string, idx int, fn SegmentUpdateFn) error {
	if !recUUIDOK(id) {
		return ErrRecordingNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// Share-lock the recording first: abandon/complete/refuse take it FOR UPDATE, so they wait for
		// this commit and this commit sees their result.
		r, err := loadRecording(ctx, tx, tenantID, id, "FOR SHARE")
		if err != nil {
			return err
		}
		if r.State != RecUploading {
			return ErrRecordingState
		}
		var seg RecordingSegment
		seg.Index = idx
		err = tx.QueryRow(ctx, `SELECT declared_len, committed_offset, COALESCE(sha256, '')
			FROM session_recording_segment WHERE tenant_id = $1 AND recording_id = $2 AND idx = $3 FOR UPDATE`,
			tenantID, id, idx).Scan(&seg.DeclaredLen, &seg.CommittedOffset, &seg.SHA256)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRecordingNotFound
		}
		if err != nil {
			return err
		}
		n, err := fn(r, seg)
		if err != nil {
			return err
		}
		if n == seg.CommittedOffset {
			return nil
		}
		if n < seg.CommittedOffset || n > seg.DeclaredLen {
			return ErrRecordingOffset
		}
		_, err = tx.Exec(ctx, `UPDATE session_recording_segment SET committed_offset = $4
			WHERE tenant_id = $1 AND recording_id = $2 AND idx = $3`, tenantID, id, idx, n)
		return err
	})
}

func (s *PgRecordingStore) RecordFinishFailure(ctx context.Context, tenantID, id string, resetIdx []int) (string, error) {
	if !recUUIDOK(id) {
		return "", ErrRecordingNotFound
	}
	state := ""
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		r, err := loadRecording(ctx, tx, tenantID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		state = r.State
		if r.State != RecUploading {
			return ErrRecordingState
		}
		if len(resetIdx) > 0 {
			idxs := make([]int32, 0, len(resetIdx))
			for _, i := range resetIdx {
				idxs = append(idxs, int32(i))
			}
			if _, err := tx.Exec(ctx, `UPDATE session_recording_segment SET committed_offset = 0, sha256 = NULL
				WHERE tenant_id = $1 AND recording_id = $2 AND idx = ANY($3)`, tenantID, id, idxs); err != nil {
				return err
			}
		}
		failures := r.FinishFailures + 1
		next := RecUploading
		if failures >= RecMaxFinishFailures {
			next = RecRefused
		}
		if _, err := tx.Exec(ctx, `UPDATE session_recording SET finish_failures = $3, state = $4
			WHERE tenant_id = $1 AND id = $2`, tenantID, id, failures, next); err != nil {
			return err
		}
		state = next
		return nil
	})
	return state, err
}

func (s *PgRecordingStore) ResetSegment(ctx context.Context, tenantID, id string, idx int) error {
	if !recUUIDOK(id) {
		return ErrRecordingNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		r, err := loadRecording(ctx, tx, tenantID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		if r.State != RecUploading {
			return ErrRecordingState
		}
		tag, err := tx.Exec(ctx, `UPDATE session_recording_segment SET committed_offset = 0, sha256 = NULL
			WHERE tenant_id = $1 AND recording_id = $2 AND idx = $3`, tenantID, id, idx)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrRecordingNotFound
		}
		return nil
	})
}

func (s *PgRecordingStore) CompleteEvidence(ctx context.Context, tenantID, id string, c EvidenceCompletion) (*RecordingRow, error) {
	if !recUUIDOK(id) {
		return nil, ErrRecordingNotFound
	}
	var out *RecordingRow
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		r, err := loadRecording(ctx, tx, tenantID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		if r.State != RecUploading || len(c.Digests) != len(r.Segments) {
			return ErrRecordingState
		}
		for _, sg := range r.Segments {
			if sg.CommittedOffset != sg.DeclaredLen {
				return ErrRecordingState
			}
		}
		policyDays := 0
		if err := tx.QueryRow(ctx, `SELECT retention_days FROM tenant_recording_policy WHERE tenant_id = $1`, tenantID).
			Scan(&policyDays); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// Server time, taken from the database clock inside this transaction (C10).
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
			return err
		}
		exp := completionExpiry(now, r.RetentionDays, policyDays)
		for i, d := range c.Digests {
			if _, err := tx.Exec(ctx, `UPDATE session_recording_segment SET sha256 = $4
				WHERE tenant_id = $1 AND recording_id = $2 AND idx = $3`, tenantID, id, i, d); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE session_recording SET state = 'evidence_complete', provenance = $3,
				matched_audit_seq = $4, truncated = $5, dropped_frames = $6, frames = $7, payload_bytes = $8,
				evidence_complete_at = $9, expires_at = $10
			WHERE tenant_id = $1 AND id = $2`, tenantID, id, c.Provenance, c.MatchedAuditSeq, c.Truncated,
			c.DroppedFrames, c.Frames, c.PayloadBytes, now, exp); err != nil {
			return err
		}
		out, err = loadRecording(ctx, tx, tenantID, id, "")
		return err
	})
	return out, err
}

func (s *PgRecordingStore) leaveUploading(ctx context.Context, tenantID, id, to string) error {
	if !recUUIDOK(id) {
		return ErrRecordingNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		r, err := loadRecording(ctx, tx, tenantID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		if r.State != RecUploading {
			return ErrRecordingState
		}
		_, err = tx.Exec(ctx, `UPDATE session_recording SET state = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, to)
		return err
	})
}

func (s *PgRecordingStore) RefuseRecording(ctx context.Context, tenantID, id string) error {
	return s.leaveUploading(ctx, tenantID, id, RecRefused)
}

func (s *PgRecordingStore) AbandonRecording(ctx context.Context, tenantID, id string) error {
	return s.leaveUploading(ctx, tenantID, id, RecAbandoned)
}

func (s *PgRecordingStore) SetPlaybackState(ctx context.Context, tenantID, id, state string) error {
	if state != RecPlaybackReady && state != RecPlaybackFailed {
		return ErrRecordingState
	}
	if !recUUIDOK(id) {
		return ErrRecordingNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		r, err := loadRecording(ctx, tx, tenantID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		ok := r.State == RecEvidenceComplete ||
			(r.State == RecPlaybackReady && state == RecPlaybackFailed) ||
			(r.State == RecPlaybackFailed && state == RecPlaybackReady)
		if !ok {
			return ErrRecordingState
		}
		_, err = tx.Exec(ctx, `UPDATE session_recording SET state = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, state)
		return err
	})
}

func (s *PgRecordingStore) RecordPlayback(ctx context.Context, tenantID, id string, res PlaybackResult) error {
	if !recUUIDOK(id) {
		return ErrRecordingNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		r, err := loadRecording(ctx, tx, tenantID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		if err := playbackTransition(r.State, res.OK); err != nil {
			return err
		}
		if !res.OK {
			if !validPlaybackReason(res.Reason) {
				return ErrRecordingState
			}
			_, err = tx.Exec(ctx, `UPDATE session_recording SET state = 'playback_failed', playback_error = $3, playback_at = now()
				WHERE tenant_id = $1 AND id = $2`, tenantID, id, res.Reason)
			return err
		}
		if err := validatePlaybackSegments(res.Segments, len(r.Segments)); err != nil {
			return err
		}
		for _, ps := range res.Segments {
			if _, err := tx.Exec(ctx, `UPDATE session_recording_segment
				SET webm_len = $4, width = $5, height = $6, start_ms = $7, duration_ms = $8, frames = $9
				WHERE tenant_id = $1 AND recording_id = $2 AND idx = $3`, tenantID, id, ps.Index,
				ps.WebMLen, ps.Width, ps.Height, ps.StartMs, ps.DurationMs, ps.Frames); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE session_recording SET state = 'playback_ready', playback_error = NULL, playback_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		return err
	})
}

func (s *PgRecordingStore) RecordingIDsBySession(ctx context.Context, tenantID string, sessionIDs []string) (map[string]string, error) {
	if len(sessionIDs) > RecIDsBySessionMax {
		return nil, errors.New("too many sessions in one recording lookup")
	}
	ids := make([]string, 0, len(sessionIDs))
	for _, id := range sessionIDs {
		if recUUIDOK(id) { // an id no uuid column can hold names no row
			ids = append(ids, id)
		}
	}
	out := map[string]string{}
	if len(ids) == 0 {
		return out, nil
	}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT ON (r.session_id) r.session_id::text, r.id::text
			FROM session_recording r
			WHERE r.tenant_id = $1
			  AND r.session_id = ANY($2::uuid[])
			  AND r.state IN ('evidence_complete', 'playback_ready', 'playback_failed', 'lost', 'expired', 'deleted')
			  AND r.evidence_complete_at IS NOT NULL
			ORDER BY r.session_id, r.evidence_complete_at DESC, r.id DESC`, tenantID, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sid, rid string
			if err := rows.Scan(&sid, &rid); err != nil {
				return err
			}
			out[sid] = rid
		}
		return rows.Err()
	})
	return out, err
}

func (s *PgRecordingStore) ListRecordings(ctx context.Context, tenantID string, f RecordingListFilter) ([]RecordingListItem, error) {
	if (f.SessionID != "" && !recUUIDOK(f.SessionID)) || (f.MachineID != "" && !recUUIDOK(f.MachineID)) {
		return nil, nil // an id no uuid column can hold names no row
	}
	var out []RecordingListItem
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// NULL parameters switch a predicate off; the cursor compares the (evidence_complete_at, id) pair
		// in the same newest-first order the sort uses. The state list is the closed "completed" set.
		var afterAt *time.Time
		var afterID *string
		if f.After != nil {
			afterAt, afterID = &f.After.At, &f.After.ID
			if !recUUIDOK(f.After.ID) {
				return nil
			}
		}
		var sess, mach *string
		if f.SessionID != "" {
			sess = &f.SessionID
		}
		if f.MachineID != "" {
			mach = &f.MachineID
		}
		rows, err := tx.Query(ctx, `
			SELECT r.id::text, r.session_id::text, r.machine_id::text, r.state, COALESCE(r.provenance, ''),
			       r.segment_count, r.declared_bytes, r.truncated, r.dropped_frames, COALESCE(r.playback_error, ''),
			       r.evidence_complete_at, r.expires_at
			FROM session_recording r
			WHERE r.tenant_id = $1
			  AND r.state IN ('evidence_complete', 'playback_ready', 'playback_failed', 'lost', 'expired', 'deleted')
			  AND r.evidence_complete_at IS NOT NULL
			  AND ($2::uuid IS NULL OR r.session_id = $2::uuid)
			  AND ($3::uuid IS NULL OR r.machine_id = $3::uuid)
			  AND ($4::timestamptz IS NULL OR (r.evidence_complete_at, r.id) < ($4::timestamptz, $5::uuid))
			ORDER BY r.evidence_complete_at DESC, r.id DESC
			LIMIT $6`, tenantID, sess, mach, afterAt, afterID, clampListLimit(f.Limit))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var it RecordingListItem
			if err := rows.Scan(&it.ID, &it.SessionID, &it.MachineID, &it.State, &it.Provenance, &it.SegmentCount,
				&it.DeclaredBytes, &it.Truncated, &it.DroppedFrames, &it.PlaybackError,
				&it.EvidenceCompleteAt, &it.ExpiresAt); err != nil {
				return err
			}
			out = append(out, it)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PgRecordingStore) ApplyRetention(ctx context.Context, tenantID, id string) (time.Time, bool, error) {
	if !recUUIDOK(id) {
		return time.Time{}, false, ErrRecordingNotFound
	}
	var exp time.Time
	changed := false
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		r, err := loadRecording(ctx, tx, tenantID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		if !recRetentionLive(r.State) || r.ExpiresAt == nil || r.EvidenceCompleteAt == nil {
			return ErrRecordingState
		}
		policyDays := 0
		if err := tx.QueryRow(ctx, `SELECT retention_days FROM tenant_recording_policy WHERE tenant_id = $1`, tenantID).
			Scan(&policyDays); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		exp, changed = shortenedExpiry(*r.ExpiresAt, *r.EvidenceCompleteAt, policyDays)
		if !changed {
			return nil
		}
		// The 0066 trigger only lets expires_at move earlier; this is exactly that.
		_, err = tx.Exec(ctx, `UPDATE session_recording SET expires_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, exp)
		return err
	})
	return exp, changed, err
}

func (s *PgRecordingStore) MarkExpired(ctx context.Context, tenantID, id string) error {
	if !recUUIDOK(id) {
		return ErrRecordingNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		r, err := loadRecording(ctx, tx, tenantID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		switch r.State {
		case RecEvidenceComplete, RecPlaybackReady, RecPlaybackFailed, RecLost:
			_, err = tx.Exec(ctx, `UPDATE session_recording SET state = 'expired', expired_at = now()
				WHERE tenant_id = $1 AND id = $2`, tenantID, id)
			return err
		case RecExpired, RecDeleted:
			return nil
		}
		return ErrRecordingState
	})
}

func (s *PgRecordingStore) MarkDeleted(ctx context.Context, tenantID, id string) error {
	if !recUUIDOK(id) {
		return ErrRecordingNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		r, err := loadRecording(ctx, tx, tenantID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		switch r.State {
		case RecExpired:
			_, err = tx.Exec(ctx, `UPDATE session_recording SET state = 'deleted', deleted_at = now()
				WHERE tenant_id = $1 AND id = $2`, tenantID, id)
			return err
		case RecDeleted:
			return nil
		}
		return ErrRecordingState
	})
}

func (s *PgRecordingStore) MarkLost(ctx context.Context, tenantID, id string) (string, error) {
	if !recUUIDOK(id) {
		return "", ErrRecordingNotFound
	}
	var from string
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		r, err := loadRecording(ctx, tx, tenantID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		switch {
		case r.State == RecLost:
			from = r.LostFrom
			return nil
		case recPromisesBlob(r.State):
			from = r.State
			_, err = tx.Exec(ctx, `UPDATE session_recording SET state = 'lost', lost_from = state, lost_at = now()
				WHERE tenant_id = $1 AND id = $2`, tenantID, id)
			return err
		}
		return ErrRecordingState
	})
	return from, err
}

func (s *PgRecordingStore) RestoreLost(ctx context.Context, tenantID, id, to string) error {
	if !recPromisesBlob(to) {
		return ErrRecordingState
	}
	if !recUUIDOK(id) {
		return ErrRecordingNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		r, err := loadRecording(ctx, tx, tenantID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		if r.State != RecLost {
			return ErrRecordingState
		}
		_, err = tx.Exec(ctx, `UPDATE session_recording SET state = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, to)
		return err
	})
}

// LockRecording takes a SESSION advisory lock keyed by tenant and recording id on a connection of the
// separate, bounded LOCK POOL and holds that connection until unlock. The lock is exclusive across every
// process that shares the database. Every other store call made while it is held uses the QUERY pool, so
// holders and waiters (which sit in pg_advisory_lock holding a lock-pool connection) can never starve the
// operations that would let a holder finish; a full lock pool or a long-held lock makes the NEXT caller fail
// with ErrRecordingLockBusy after LockWait. None of the locked operations takes this lock again, and the
// chunk path takes only row locks, so there is no cycle.
func (s *PgRecordingStore) LockRecording(ctx context.Context, tenantID, id string) (func(), error) {
	if !recUUIDOK(id) {
		return nil, ErrRecordingNotFound
	}
	lp, err := s.lockPoolFor()
	if err != nil {
		return nil, err
	}
	wait := s.LockWait
	if wait <= 0 {
		wait = 15 * time.Second
	}
	wctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	conn, err := lp.Acquire(wctx)
	if err != nil {
		return nil, lockWaitErr(ctx, err)
	}
	key := "rmt-recording:" + tenantID + "/" + id
	if _, err := conn.Exec(wctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, key); err != nil {
		// An interrupted wait leaves the session in an unknown state: never return it to the pool.
		_ = conn.Hijack().Close(context.Background())
		return nil, lockWaitErr(ctx, err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var ok bool
			if err := conn.QueryRow(uctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key).Scan(&ok); err != nil || !ok {
				_ = conn.Hijack().Close(context.Background()) // closing the session releases its locks
				return
			}
			conn.Release()
		})
	}, nil
}

// lockWaitErr says "busy" when only the bounded wait ran out (the caller's own context is still live).
func lockWaitErr(ctx context.Context, err error) error {
	if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
		return ErrRecordingLockBusy
	}
	return err
}

// SweepList reads cp_recording_sweep_list() (migration 0066) ON THE POOL: it is the deliberate
// cross-tenant read, answered by a SECURITY DEFINER function that returns only what the sweeper needs.
func (s *PgRecordingStore) SweepList(ctx context.Context) ([]RecordingSweepRow, error) {
	rows, err := s.Pool.Query(ctx, `SELECT tenant_id::text, id::text, upload_id::text, state, created_at,
		evidence_complete_at, expires_at, expired_at, policy_retention_days FROM cp_recording_sweep_list()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RecordingSweepRow
	for rows.Next() {
		var r RecordingSweepRow
		if err := rows.Scan(&r.TenantID, &r.ID, &r.UploadID, &r.State, &r.CreatedAt, &r.EvidenceCompleteAt,
			&r.ExpiresAt, &r.ExpiredAt, &r.PolicyRetentionDays); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
