package controlplane

// Console routes for central session recordings (docs/63 D6, D7, §2a C8). All on the PROTECTED chain
// (cookie session, CSRF, tenant-pinned RLS), all behind CapViewRecordings, none reachable by an API token:
//
//	GET /recordings                          list (completed recordings, newest first, group-scoped)
//	GET /recordings/{id}                     detail: state, provenance, integrity, per-segment metadata
//	GET /recordings/{id}/playlist            the per-segment WebM playlist           (playback start: audited)
//	GET /recordings/{id}/segments/{n}/stream one segment's WebM, Range-capable       (playback start: audited)
//	GET /recordings/{id}/download            evidence IVF + manifest (ZIP)           (EVERY download audited)
//
// THE C8 RULES, in the order every route applies them:
//
//  1. Cache-Control: private, no-store is set before ANYTHING else is decided, so no refusal and no
//     redirect-ish response is ever stored by a shared cache either.
//  2. Not an API token (Principal.APIToken) and holds CapViewRecordings. Checked on EVERY route, every
//     request — nothing is remembered from an earlier call (a Range request is a new request).
//  3. The recording must exist in this tenant (RLS) and be a completed recording.
//  4. GROUP SCOPE on the machine's CURRENT group: AllowsInGroup(CapViewRecordings, group). A machine that
//     no longer resolves has no group to scope against, so it is visible only to a TENANT-WIDE holder; a
//     store failure is a 500, never "allowed". Out-of-scope and unknown recordings are both 404, so an id
//     reveals nothing to someone who may not see it.
//  5. Only now is the recording's state looked at, and only after authorization is any conditional or
//     Range header interpreted: no validators (ETag / Last-Modified) are ever sent, so a conditional
//     request can never turn into a bodyless 304 for a viewer who has since lost access.
//  6. The AUDIT ROW IS PERSISTED BEFORE content is released. "Playback started" is deduplicated per
//     recording per viewer for 10 minutes across all routes (a Range seek must not write a row per
//     request); every evidence download is audited. An audit store that cannot be written is a 503 and no
//     content. (Metadata routes — list, detail — release no recording content and write no row.)

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	recAuditPlayback = "recording.playback"
	recAuditDownload = "recording.download"
	recAuditKind     = "recording"

	// recPlaybackDedup is the window inside which a viewer's "playback started" is recorded once.
	recPlaybackDedup = 10 * time.Minute

	recProvenanceNote = "Neither label is independent capture verification: whoever controls the endpoint's agent key can fabricate either."

	recStreamChunk = 4 * EnvFrameSize // decrypt and write in 256 KiB steps
)

func recProvenanceLabel(code string) string {
	switch code {
	case ProvMatchesAudit:
		return "Agent-signed; matches session audit"
	case ProvNoStopEvent:
		return "Agent-signed; no matching stop event"
	}
	return ""
}

// recJSON writes a JSON response with the recording cache policy (writeJSON's plain no-store would
// replace the header the C8 rules require).
func recJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func recErr(w http.ResponseWriter, status int, code string, extra map[string]any) {
	body := map[string]any{"error": code}
	for k, v := range extra {
		body[k] = v
	}
	recJSON(w, status, body)
}

func recNoStore(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "private, no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

// mountRecordingConsole registers the console routes. They exist only when central recording is fully
// wired AND the management audit store and machine store are present: content must never be served on a
// deployment that cannot audit it or scope it.
func (s *Server) mountRecordingConsole(protected *http.ServeMux) {
	if s.Recording.Store != nil {
		protected.HandleFunc("GET /tenant/recording-policy", s.handleGetRecordingPolicy)
		protected.HandleFunc("PUT /tenant/recording-policy", s.handleSetRecordingPolicy)
	}
	if !s.Recording.ready() || s.MgmtAudit == nil || s.Machines == nil {
		return
	}
	protected.HandleFunc("GET /recordings", s.handleListRecordings)
	protected.HandleFunc("GET /recordings/{id}", s.handleGetRecording)
	protected.HandleFunc("GET /recordings/{id}/playlist", s.handleRecordingPlaylist)
	protected.HandleFunc("GET /recordings/{id}/segments/{n}/stream", s.handleRecordingStream)
	protected.HandleFunc("GET /recordings/{id}/download", s.handleRecordingDownload)
}

// ---- authorization ----------------------------------------------------------------------------

// recViewer applies rules 1 and 2. It writes the refusal itself.
func (s *Server) recViewer(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	recNoStore(w)
	p := principalFrom(r.Context())
	if p == nil || p.Grant == nil {
		recErr(w, http.StatusUnauthorized, "unauthenticated", nil)
		return nil, false
	}
	if p.APIToken {
		recErr(w, http.StatusForbidden, "recordings are not available to API tokens", nil)
		return nil, false
	}
	if err := p.Grant.Require(CapViewRecordings); err != nil {
		recJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return nil, false
	}
	return p, true
}

// recMachineAllowed is rule 4 for one machine (by primary key). groups memoises per request.
func (s *Server) recMachineAllowed(ctx context.Context, p *Principal, machineID string, groups map[string]string) (bool, error) {
	scope, _ := p.Grant.ScopeFor(CapViewRecordings)
	if scope.All {
		return true, nil // tenant-wide: needs no group, and a deleted machine stays visible
	}
	gid, seen := groups[machineID]
	if !seen {
		if s.Machines == nil {
			return false, errors.New("machine store not configured")
		}
		m, err := s.Machines.GetMachineByID(ctx, p.TenantID, machineID)
		switch {
		case err == nil:
			gid = m.GroupID
		case errors.Is(err, ErrMachineNotFound):
			gid = "" // no group to scope against: invisible to a scoped holder
		default:
			return false, err // an outage is not "no group"
		}
		groups[machineID] = gid
	}
	if gid == "" {
		return false, nil
	}
	return p.Grant.AllowsInGroup(CapViewRecordings, gid), nil
}

// recVisible applies rules 3 and 4 to the recording named in the path.
func (s *Server) recVisible(w http.ResponseWriter, r *http.Request, p *Principal) (*RecordingRow, bool) {
	id := r.PathValue("id")
	if !recIsUUID(id) {
		recErr(w, http.StatusNotFound, "not_found", nil)
		return nil, false
	}
	row, err := s.Recording.Store.GetRecording(r.Context(), p.TenantID, id)
	if errors.Is(err, ErrRecordingNotFound) {
		recErr(w, http.StatusNotFound, "not_found", nil)
		return nil, false
	}
	if err != nil {
		log.Printf("recording console: load %s: %v", id, err)
		recErr(w, http.StatusInternalServerError, "internal", nil)
		return nil, false
	}
	if !recListState(row.State) {
		recErr(w, http.StatusNotFound, "not_found", nil)
		return nil, false
	}
	s.recApplyLogicalExpiry(row)
	ok, err := s.recMachineAllowed(r.Context(), p, row.MachineID, map[string]string{})
	if err != nil {
		log.Printf("recording console: scope check for %s: %v", id, err)
		recErr(w, http.StatusInternalServerError, "internal", nil)
		return nil, false
	}
	if !ok {
		recErr(w, http.StatusNotFound, "not_found", nil)
		return nil, false
	}
	return row, true
}

// ---- audit (rule 6) ---------------------------------------------------------------------------

// recAudit persists the audit row for releasing content, or reports why it could not. With dedup, a row
// already recorded for this viewer and recording inside the window counts as persisted — checked first
// in a small per-process cache (an optimisation only: it is filled solely from rows that really exist)
// and then against the audit store itself, so another replica's row, or a restart, is honoured too.
func (s *Server) recAudit(ctx context.Context, p *Principal, row *RecordingRow, action string, dedup bool, meta map[string]any) error {
	w := &s.Recording
	if s.MgmtAudit == nil {
		return errors.New("management audit store not configured")
	}
	now := w.now()
	key := p.TenantID + "|" + p.UserID + "|" + row.ID + "|" + action
	if dedup {
		w.auditMu.Lock()
		at, hit := w.auditSeen[key]
		w.auditMu.Unlock()
		if hit && now.Sub(at) < recPlaybackDedup && !now.Before(at) {
			return nil
		}
		evs, err := s.MgmtAudit.ListEventsFiltered(ctx, p.TenantID, 500, AuditFilter{
			Action: action, TargetKind: recAuditKind, Actor: p.UserID, Since: now.Add(-recPlaybackDedup)})
		if err != nil {
			return err
		}
		for _, e := range evs {
			if e.TargetID == row.ID {
				w.noteAudit(key, e.OccurredAt, now)
				return nil
			}
		}
	}
	m := map[string]any{"recording_id": row.ID, "session_id": row.SessionID, "machine_id": row.MachineID}
	for k, v := range meta {
		m[k] = v
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	e := &MgmtAuditEvent{ActorUserID: p.UserID, Action: action, TargetKind: recAuditKind, TargetID: row.ID,
		Metadata: raw, OccurredAt: now}
	if err := s.MgmtAudit.RecordEvent(ctx, p.TenantID, e); err != nil {
		return err
	}
	if dedup {
		w.noteAudit(key, now, now)
	}
	if s.Dispatcher != nil {
		s.Dispatcher.Dispatch(p.TenantID, e)
	}
	return nil
}

func (w *RecordingWiring) noteAudit(key string, at, now time.Time) {
	w.auditMu.Lock()
	defer w.auditMu.Unlock()
	if w.auditSeen == nil {
		w.auditSeen = make(map[string]time.Time)
	}
	if len(w.auditSeen) >= 10000 { // bounded: drop everything stale, then everything if still full
		for k, t := range w.auditSeen {
			if now.Sub(t) >= recPlaybackDedup {
				delete(w.auditSeen, k)
			}
		}
		if len(w.auditSeen) >= 10000 {
			w.auditSeen = make(map[string]time.Time)
		}
	}
	w.auditSeen[key] = at
}

func (s *Server) recAuditOrFail(w http.ResponseWriter, r *http.Request, p *Principal, row *RecordingRow, action string, dedup bool, meta map[string]any) bool {
	if err := s.recAudit(r.Context(), p, row, action, dedup, meta); err != nil {
		log.Printf("recording console: audit %s for %s failed, withholding content: %v", action, row.ID, err)
		recErr(w, http.StatusServiceUnavailable, "audit_unavailable", nil)
		return false
	}
	return true
}

// ---- list / detail ----------------------------------------------------------------------------

type recListJSON struct {
	ID                 string    `json:"id"`
	SessionID          string    `json:"session_id"`
	MachineID          string    `json:"machine_id"`
	State              string    `json:"state"`
	Playable           bool      `json:"playable"`
	Provenance         string    `json:"provenance"`
	ProvenanceLabel    string    `json:"provenance_label"`
	SegmentCount       int       `json:"segment_count"`
	DeclaredBytes      int64     `json:"declared_bytes"`
	Truncated          *string   `json:"truncated"`
	DroppedFrames      *int64    `json:"dropped_frames"`
	PlaybackError      string    `json:"playback_error,omitempty"`
	EvidenceCompleteAt time.Time `json:"evidence_complete_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	recContextJSON
}

// recContextJSON is what the console used to join client-side: the session and machine the recording belongs to.
// Every field is omitted when it is not known (a purged user, a session the store cannot resolve), and every one
// is a field of a session/machine the caller was ALREADY authorized to see this recording for (rule 4 ran first).
// There is no capture time in the schema (the agent's timestamps are not stored), so the times are the SESSION's.
type recContextJSON struct {
	MachineName      string     `json:"machine_name,omitempty"`
	MachineAlias     string     `json:"machine_alias,omitempty"`
	TechnicianID     string     `json:"technician_id,omitempty"`
	TechnicianName   string     `json:"technician_name,omitempty"`
	SessionStartedAt *time.Time `json:"session_started_at,omitempty"`
	SessionEndedAt   *time.Time `json:"session_ended_at,omitempty"`
}

// recJoin resolves recContextJSON per request, memoised by session and user id. It is best effort: a lookup
// failure omits the fields (the console shows ids) and never fails or widens the response.
type recJoin struct {
	s        *Server
	ctx      context.Context
	tenant   string
	sessions map[string]recContextJSON
	users    map[string]string
}

func (s *Server) newRecJoin(ctx context.Context, tenant string) *recJoin {
	return &recJoin{s: s, ctx: ctx, tenant: tenant, sessions: map[string]recContextJSON{}, users: map[string]string{}}
}

func (j *recJoin) technician(id string) string {
	if id == "" || j.s.AuthAPI == nil || j.s.AuthAPI.Users == nil {
		return ""
	}
	if n, ok := j.users[id]; ok {
		return n
	}
	name := ""
	if u, err := j.s.AuthAPI.Users.FindUserByID(j.ctx, j.tenant, id); err == nil && u != nil {
		if name = strings.TrimSpace(u.DisplayName); name == "" {
			name = u.Email
		}
	}
	j.users[id] = name
	return name
}

func (j *recJoin) forSession(sessionID string) recContextJSON {
	if c, ok := j.sessions[sessionID]; ok {
		return c
	}
	var c recContextJSON
	if j.s.SessionRecords != nil && sessionID != "" {
		if sess, err := j.s.SessionRecords.GetSession(j.ctx, j.tenant, sessionID); err == nil && sess != nil {
			started := sess.StartedAt
			c = recContextJSON{MachineName: sess.MachineName, MachineAlias: sess.MachineAlias, TechnicianID: sess.TechnicianID,
				TechnicianName: j.technician(sess.TechnicianID), SessionStartedAt: &started, SessionEndedAt: sess.EndedAt}
		}
	}
	j.sessions[sessionID] = c
	return c
}

// recLogicallyExpired: a completed recording whose stored deadline has passed is EXPIRED for every reader,
// even before the sweeper has flipped its state (the sweep runs every few minutes and can fall behind or
// fail; content must not outlive its retention because of that). The stored deadline is the durable one
// (the sweeper persists a shortened retention into it, ApplyRetention).
func (s *Server) recLogicallyExpired(state string, expiresAt *time.Time) bool {
	return recRetentionLive(state) && expiresAt != nil && !s.Recording.now().Before(*expiresAt)
}

// recApplyLogicalExpiry presents a logically expired row as expired to the routes that follow.
func (s *Server) recApplyLogicalExpiry(row *RecordingRow) {
	if s.recLogicallyExpired(row.State, row.ExpiresAt) {
		row.State = RecExpired
	}
}

func recToList(it RecordingListItem, c recContextJSON) recListJSON {
	return recListJSON{recContextJSON: c, ID: it.ID, SessionID: it.SessionID, MachineID: it.MachineID, State: it.State,
		Playable: it.State == RecPlaybackReady, Provenance: it.Provenance, ProvenanceLabel: recProvenanceLabel(it.Provenance),
		SegmentCount: it.SegmentCount, DeclaredBytes: it.DeclaredBytes, Truncated: it.Truncated,
		DroppedFrames: it.DroppedFrames, PlaybackError: it.PlaybackError,
		EvidenceCompleteAt: it.EvidenceCompleteAt, ExpiresAt: it.ExpiresAt}
}

func parseRecCursor(tok string) (*RecordingCursor, bool) {
	if tok == "" {
		return nil, true
	}
	i := strings.IndexByte(tok, '.')
	if i < 1 {
		return nil, false
	}
	us, err := strconv.ParseInt(tok[:i], 10, 64)
	id := tok[i+1:]
	if err != nil || us < 0 || !recIsUUID(id) {
		return nil, false
	}
	return &RecordingCursor{At: time.UnixMicro(us).UTC(), ID: id}, true
}

func recCursorToken(c RecordingCursor) string {
	return strconv.FormatInt(c.At.UnixMicro(), 10) + "." + c.ID
}

// recListRounds bounds how many raw pages one request may examine while looking for rows in scope.
const recListRounds = 20

func (s *Server) handleListRecordings(w http.ResponseWriter, r *http.Request) {
	p, ok := s.recViewer(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := RecordingListFilter{Limit: RecListDefault}
	if v := q.Get("session_id"); v != "" {
		if !recIsUUID(v) {
			recErr(w, http.StatusBadRequest, "session_id must be a lower-case uuid", nil)
			return
		}
		f.SessionID = v
	}
	if v := q.Get("machine_id"); v != "" {
		if !recIsUUID(v) {
			recErr(w, http.StatusBadRequest, "machine_id must be a lower-case uuid", nil)
			return
		}
		f.MachineID = v
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > RecListMax {
			recErr(w, http.StatusBadRequest, "limit must be 1.."+strconv.Itoa(RecListMax), nil)
			return
		}
		f.Limit = n
	}
	cur, okc := parseRecCursor(q.Get("cursor"))
	if !okc {
		recErr(w, http.StatusBadRequest, "malformed cursor", nil)
		return
	}
	f.After = cur
	want := f.Limit

	groups := map[string]string{}
	join := s.newRecJoin(r.Context(), p.TenantID)
	out := make([]recListJSON, 0, want)
	var next *RecordingCursor
	exhausted := false
	for round := 0; round < recListRounds && len(out) < want && !exhausted; round++ {
		page, err := s.Recording.Store.ListRecordings(r.Context(), p.TenantID, f)
		if err != nil {
			log.Printf("recording console: list: %v", err)
			recErr(w, http.StatusInternalServerError, "internal", nil)
			return
		}
		for _, it := range page {
			allowed, err := s.recMachineAllowed(r.Context(), p, it.MachineID, groups)
			if err != nil { // fail CLOSED: an unresolvable scope serves nothing, never everything
				log.Printf("recording console: list scope check: %v", err)
				recErr(w, http.StatusInternalServerError, "internal", nil)
				return
			}
			c := RecordingCursor{At: it.EvidenceCompleteAt, ID: it.ID}
			next, f.After = &c, &c // the cursor names a position in the log, not a returned row
			if allowed {
				if s.recLogicallyExpired(it.State, &it.ExpiresAt) {
					it.State = RecExpired
				}
				out = append(out, recToList(it, join.forSession(it.SessionID)))
				if len(out) == want {
					break
				}
			}
		}
		if len(page) < clampListLimit(f.Limit) {
			exhausted = true
		}
	}
	resp := map[string]any{"recordings": out}
	if next != nil && !(exhausted && len(out) < want) {
		resp["next_cursor"] = recCursorToken(*next)
	} else {
		resp["next_cursor"] = ""
	}
	recJSON(w, http.StatusOK, resp)
}

type recSegmentJSON struct {
	Index         int    `json:"index"`
	DeclaredBytes int64  `json:"declared_bytes"`
	SHA256        string `json:"sha256"`
	Playback      *struct {
		Bytes      int64 `json:"bytes"`
		Width      int   `json:"width"`
		Height     int   `json:"height"`
		StartMs    int64 `json:"start_ms"`
		DurationMs int64 `json:"duration_ms"`
		Frames     int64 `json:"frames"`
	} `json:"playback"`
}

func recDetailJSON(row *RecordingRow, c recContextJSON) map[string]any {
	segs := make([]recSegmentJSON, len(row.Segments))
	for i, sg := range row.Segments {
		segs[i] = recSegmentJSON{Index: sg.Index, DeclaredBytes: sg.DeclaredLen, SHA256: sg.SHA256}
		if pb := sg.Playback; pb != nil {
			segs[i].Playback = &struct {
				Bytes      int64 `json:"bytes"`
				Width      int   `json:"width"`
				Height     int   `json:"height"`
				StartMs    int64 `json:"start_ms"`
				DurationMs int64 `json:"duration_ms"`
				Frames     int64 `json:"frames"`
			}{pb.WebMLen, pb.Width, pb.Height, pb.StartMs, pb.DurationMs, pb.Frames}
		}
	}
	m := map[string]any{
		"id": row.ID, "session_id": row.SessionID, "machine_id": row.MachineID, "state": row.State,
		"playable":   row.State == RecPlaybackReady,
		"provenance": row.Provenance, "provenance_label": recProvenanceLabel(row.Provenance),
		"provenance_note": recProvenanceNote,
		"segment_count":   len(row.Segments), "declared_bytes": row.DeclaredBytes, "segments": segs,
		"truncated": row.Truncated, "dropped_frames": row.DroppedFrames, "frames": row.Frames, "payload_bytes": row.PayloadBytes,
		"evidence_complete_at": row.EvidenceCompleteAt, "expires_at": row.ExpiresAt,
		"expired_at": row.ExpiredAt, "deleted_at": row.DeletedAt,
	}
	if row.PlaybackError != "" {
		m["playback_error"] = row.PlaybackError
	}
	if row.LostAt != nil {
		m["lost_at"] = row.LostAt
	}
	if c.MachineName != "" {
		m["machine_name"] = c.MachineName
	}
	if c.MachineAlias != "" {
		m["machine_alias"] = c.MachineAlias
	}
	if c.TechnicianID != "" {
		m["technician_id"] = c.TechnicianID
	}
	if c.TechnicianName != "" {
		m["technician_name"] = c.TechnicianName
	}
	if c.SessionStartedAt != nil {
		m["session_started_at"] = c.SessionStartedAt
	}
	if c.SessionEndedAt != nil {
		m["session_ended_at"] = c.SessionEndedAt
	}
	return m
}

func (s *Server) handleGetRecording(w http.ResponseWriter, r *http.Request) {
	p, ok := s.recViewer(w, r)
	if !ok {
		return
	}
	row, ok := s.recVisible(w, r, p)
	if !ok {
		return
	}
	recJSON(w, http.StatusOK, recDetailJSON(row, s.newRecJoin(r.Context(), p.TenantID).forSession(row.SessionID)))
}

// ---- playlist / stream ------------------------------------------------------------------------

// recPlayable answers rule 5's state question for a playback route; it writes the refusal.
func recPlayable(w http.ResponseWriter, row *RecordingRow) bool {
	switch row.State {
	case RecPlaybackReady:
		return true
	case RecEvidenceComplete:
		recErr(w, http.StatusConflict, "playback_pending", map[string]any{"state": row.State})
	case RecPlaybackFailed:
		recErr(w, http.StatusConflict, "playback_failed", map[string]any{"state": row.State, "reason": row.PlaybackError})
	case RecLost:
		// The row survived a restore but its files did not (docs/63 C11): a definite 410 before storage is touched.
		recErr(w, http.StatusGone, RecLost, map[string]any{"state": row.State})
	default: // expired, deleted
		recErr(w, http.StatusGone, row.State, map[string]any{"state": row.State})
	}
	return false
}

func (s *Server) handleRecordingPlaylist(w http.ResponseWriter, r *http.Request) {
	p, ok := s.recViewer(w, r)
	if !ok {
		return
	}
	row, ok := s.recVisible(w, r, p)
	if !ok {
		return
	}
	if !recPlayable(w, row) {
		return
	}
	for _, sg := range row.Segments {
		if sg.Playback == nil { // ready with no segment metadata cannot happen; refuse rather than guess
			recErr(w, http.StatusInternalServerError, "internal", nil)
			return
		}
	}
	if !s.recAuditOrFail(w, r, p, row, recAuditPlayback, true, map[string]any{"route": "playlist"}) {
		return
	}
	type item struct {
		Index      int    `json:"index"`
		URL        string `json:"url"` // relative to this playlist's URL
		StartMs    int64  `json:"start_ms"`
		DurationMs int64  `json:"duration_ms"`
		Width      int    `json:"width"`
		Height     int    `json:"height"`
		Bytes      int64  `json:"bytes"`
	}
	items := make([]item, len(row.Segments))
	var end int64
	for i, sg := range row.Segments {
		pb := sg.Playback
		items[i] = item{Index: i, URL: "segments/" + strconv.Itoa(i) + "/stream", StartMs: pb.StartMs,
			DurationMs: pb.DurationMs, Width: pb.Width, Height: pb.Height, Bytes: pb.WebMLen}
		if e := pb.StartMs + pb.DurationMs; e > end {
			end = e
		}
	}
	recJSON(w, http.StatusOK, map[string]any{
		"recording_id": row.ID, "mime": `video/webm; codecs="vp8"`, "segments": items, "total_duration_ms": end,
		"provenance": row.Provenance, "provenance_label": recProvenanceLabel(row.Provenance),
		"provenance_note": recProvenanceNote, "truncated": row.Truncated, "dropped_frames": row.DroppedFrames})
}

// parseRecRange parses a single-range Range header against a known length. ok=false means "serve the
// whole body" (absent, malformed or multi-range: all of which RFC 9110 lets a server ignore); unsat=true
// means a syntactically valid range that lies outside the representation (416).
func parseRecRange(h string, length int64) (start, end int64, ok, unsat bool) {
	if h == "" || !strings.HasPrefix(h, "bytes=") {
		return 0, 0, false, false
	}
	spec := strings.TrimPrefix(h, "bytes=")
	if strings.ContainsAny(spec, ", ") {
		return 0, 0, false, false
	}
	i := strings.IndexByte(spec, '-')
	if i < 0 {
		return 0, 0, false, false
	}
	a, b := spec[:i], spec[i+1:]
	switch {
	case a == "": // suffix: the last n bytes
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil || n < 0 || b == "" || b[0] == '+' {
			return 0, 0, false, false
		}
		if n == 0 {
			return 0, 0, false, true
		}
		if n > length {
			n = length
		}
		return length - n, length - 1, true, false
	default:
		s, err := strconv.ParseInt(a, 10, 64)
		if err != nil || s < 0 || a[0] == '+' {
			return 0, 0, false, false
		}
		e := length - 1
		if b != "" {
			v, err := strconv.ParseInt(b, 10, 64)
			if err != nil || v < s || b[0] == '+' {
				return 0, 0, false, false
			}
			if v < e {
				e = v
			}
		}
		if s >= length {
			return 0, 0, false, true
		}
		return s, e, true, false
	}
}

// deadlineWriter pushes the connection's write deadline forward on every write, so a long stream is
// bounded by PROGRESS (a stalled reader still times out) rather than by the server-wide total. It FAILS
// CLOSED: newDeadlineWriter establishes the first deadline and reports whether the connection can honour
// one — the routes call it BEFORE any header or byte is written and refuse (500) when it cannot — and a
// refresh that fails is returned from Write, so nothing is sent without a deadline in force.
type deadlineWriter struct {
	w   io.Writer
	rc  *http.ResponseController
	per time.Duration
}

func newDeadlineWriter(w http.ResponseWriter, per time.Duration) (*deadlineWriter, error) {
	d := &deadlineWriter{w: w, rc: http.NewResponseController(w), per: per}
	if err := d.rc.SetWriteDeadline(time.Now().Add(per)); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	if err := d.rc.SetWriteDeadline(time.Now().Add(d.per)); err != nil {
		return 0, err
	}
	return d.w.Write(p)
}

func (s *Server) handleRecordingStream(w http.ResponseWriter, r *http.Request) {
	p, ok := s.recViewer(w, r)
	if !ok {
		return
	}
	row, ok := s.recVisible(w, r, p)
	if !ok {
		return
	}
	idx, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || strconv.Itoa(idx) != r.PathValue("n") || idx < 0 || idx >= len(row.Segments) {
		recErr(w, http.StatusNotFound, "not_found", nil)
		return
	}
	if !recPlayable(w, row) {
		return
	}
	pb := row.Segments[idx].Playback
	if pb == nil {
		recErr(w, http.StatusInternalServerError, "internal", nil)
		return
	}
	// Range is interpreted only now, after authorization. No validators are sent, so If-None-Match /
	// If-Modified-Since / If-Range have nothing to compare with and are ignored (a Range with If-Range is
	// served whole: the safe reading when we cannot prove the representation is unchanged).
	start, end, partial, unsat := int64(0), pb.WebMLen-1, false, false
	if r.Header.Get("If-Range") == "" {
		start, end, partial, unsat = parseRecRange(r.Header.Get("Range"), pb.WebMLen)
		if !partial && !unsat {
			start, end = 0, pb.WebMLen-1
		}
	}
	if unsat {
		w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(pb.WebMLen, 10))
		recErr(w, http.StatusRequestedRangeNotSatisfiable, "range_not_satisfiable", nil)
		return
	}
	releaseStream, ok := s.recAcquireStream(w, r, p)
	if !ok {
		return
	}
	defer releaseStream()
	if r.Method != http.MethodHead { // a HEAD releases no content
		if !s.recAuditOrFail(w, r, p, row, recAuditPlayback, true, map[string]any{"route": "stream", "segment": idx}) {
			return
		}
	}
	// Every database read and the audit write are done; what follows is file I/O and a body that
	// may take minutes to drain. Give the pinned tenant connection back first (review #5).
	releaseBoundConn(r.Context())

	f, size, err := s.Recording.Files.OpenFinal(row.TenantID, row.ID, uint32(idx), RepWebM)
	if err != nil {
		log.Printf("recording console: open playback %s/%d: %v", row.ID, idx, err)
		recErr(w, http.StatusInternalServerError, "internal", nil)
		return
	}
	defer f.Close()
	meta, err := recEnvMeta(row, idx, pb.WebMLen, RepWebM)
	if err != nil {
		recErr(w, http.StatusInternalServerError, "internal", nil)
		return
	}
	rd, err := OpenEnvelope(f, size, s.Recording.Keys, EnvelopeExpect{TenantID: meta.TenantID, RecordingID: meta.RecordingID,
		Segment: meta.Segment, Rep: RepWebM, Generation: meta.Generation}, false)
	if err != nil || rd.Len() != pb.WebMLen {
		log.Printf("recording console: playback envelope %s/%d unusable: %v", row.ID, idx, err)
		recErr(w, http.StatusInternalServerError, "internal", nil)
		return
	}

	n := end - start + 1
	// Decrypt the FIRST chunk before any header is sent: a tampered or truncated file then ends as a clean
	// 500 with no content, not as a 200 that dies half way.
	first := n
	if first > recStreamChunk {
		first = recStreamChunk
	}
	if off := start % EnvFrameSize; off != 0 && first > EnvFrameSize-off {
		first = EnvFrameSize - off // align the following reads to frame boundaries
	}
	var chunk []byte
	if r.Method != http.MethodHead {
		chunk, err = rd.ReadRange(start, first)
		if err != nil {
			log.Printf("recording console: playback read %s/%d: %v", row.ID, idx, err)
			recErr(w, http.StatusInternalServerError, "internal", nil)
			return
		}
	}
	// The write deadline is established (and checked) BEFORE the first header: a connection that cannot
	// enforce one never starts a stream.
	dw, derr := newDeadlineWriter(w, 30*time.Second)
	if derr != nil {
		log.Printf("recording console: no write deadline for the stream of %s: %v", row.ID, derr)
		recErr(w, http.StatusInternalServerError, "deadlines_unavailable", nil)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "video/webm")
	h.Set("Accept-Ranges", "bytes")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Content-Length", strconv.FormatInt(n, 10))
	status := http.StatusOK
	if partial {
		status = http.StatusPartialContent
		h.Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10)+"/"+strconv.FormatInt(pb.WebMLen, 10))
	}
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := dw.Write(chunk); err != nil {
		return
	}
	pos, remaining := start+int64(len(chunk)), n-int64(len(chunk))
	for remaining > 0 {
		if r.Context().Err() != nil {
			return
		}
		step := remaining
		if step > recStreamChunk {
			step = recStreamChunk
		}
		b, err := rd.ReadRange(pos, step)
		if err != nil { // mid-stream failure: abort the connection so the client sees a failure, not a short 200
			log.Printf("recording console: playback read %s/%d at %d: %v", row.ID, idx, pos, err)
			panic(http.ErrAbortHandler)
		}
		if _, err := dw.Write(b); err != nil {
			return
		}
		pos += int64(len(b))
		remaining -= int64(len(b))
	}
}

// ---- evidence download ------------------------------------------------------------------------

type recManifestSegment struct {
	Index  int    `json:"index"`
	File   string `json:"file"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

func (s *Server) handleRecordingDownload(w http.ResponseWriter, r *http.Request) {
	p, ok := s.recViewer(w, r)
	if !ok {
		return
	}
	row, ok := s.recVisible(w, r, p)
	if !ok {
		return
	}
	switch row.State {
	case RecEvidenceComplete, RecPlaybackReady, RecPlaybackFailed:
	default: // expired, deleted, lost (410 code "lost"): the evidence is gone (or going) — say so rather than 404
		recErr(w, http.StatusGone, row.State, map[string]any{"state": row.State})
		return
	}
	if r.Method == http.MethodHead {
		if _, derr := newDeadlineWriter(w, 60*time.Second); derr != nil {
			recErr(w, http.StatusInternalServerError, "deadlines_unavailable", nil)
			return
		}
		w.WriteHeader(http.StatusOK) // no content, no audit row
		return
	}
	releaseStream, ok := s.recAcquireStream(w, r, p)
	if !ok {
		return
	}
	defer releaseStream()
	// EVERY download is audited, before the first byte (no dedup).
	if !s.recAuditOrFail(w, r, p, row, recAuditDownload, false, map[string]any{"route": "download", "segments": len(row.Segments)}) {
		return
	}
	// All database work is done: free the pinned tenant connection before the long ZIP stream.
	releaseBoundConn(r.Context())

	// Open every segment BEFORE any header is sent: a missing, tampered or truncated evidence file is a
	// clean 500, not a ZIP that is silently short.
	type opened struct {
		rd *EnvelopeReader
	}
	var segs []opened
	for i := range row.Segments {
		rd, closeFn, err := s.recOpenSegmentReader(row, i, false)
		if err != nil {
			log.Printf("recording console: open evidence %s/%d: %v", row.ID, i, err)
			recErr(w, http.StatusInternalServerError, "internal", nil)
			return
		}
		defer closeFn()
		segs = append(segs, opened{rd})
	}

	manifest := map[string]any{
		"format": "deskrally-recording-evidence/1", "recording_id": row.ID, "tenant_id": row.TenantID,
		"session_id": row.SessionID, "machine_id": row.MachineID, "generation": row.Generation,
		"provenance": row.Provenance, "provenance_label": recProvenanceLabel(row.Provenance),
		"provenance_note": recProvenanceNote, "truncated": row.Truncated, "dropped_frames": row.DroppedFrames,
		"frames": row.Frames, "payload_bytes": row.PayloadBytes,
		"evidence_complete_at": row.EvidenceCompleteAt, "expires_at": row.ExpiresAt,
		"digest_algorithm": "sha256", "container": "IVF (VP8), one file per segment",
	}
	ms := make([]recManifestSegment, len(row.Segments))
	for i, sg := range row.Segments {
		ms[i] = recManifestSegment{Index: i, File: segmentFileName(i), Bytes: sg.DeclaredLen, SHA256: sg.SHA256}
	}
	manifest["segments"] = ms
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		recErr(w, http.StatusInternalServerError, "internal", nil)
		return
	}

	dw, derr := newDeadlineWriter(w, 60*time.Second)
	if derr != nil {
		log.Printf("recording console: no write deadline for the download of %s: %v", row.ID, derr)
		recErr(w, http.StatusInternalServerError, "deadlines_unavailable", nil)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", `attachment; filename="recording-`+row.ID+`.zip"`)
	w.WriteHeader(http.StatusOK)
	zw := zip.NewWriter(dw)
	modified := time.Time{}
	if row.EvidenceCompleteAt != nil {
		modified = *row.EvidenceCompleteAt
	}
	abort := func(why string, err error) {
		log.Printf("recording console: download %s aborted (%s): %v", row.ID, why, err)
		panic(http.ErrAbortHandler) // no central directory is written: the client holds an invalid ZIP, not a short one
	}
	mw, err := zw.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Store, Modified: modified})
	if err != nil {
		abort("manifest header", err)
	}
	if _, err := mw.Write(mb); err != nil {
		return // the client went away
	}
	for i, sg := range segs {
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: segmentFileName(i), Method: zip.Store, Modified: modified})
		if err != nil {
			abort("segment header", err)
		}
		sum := sha256.New()
		n, err := sg.rd.WriteTo(io.MultiWriter(fw, sum))
		if err != nil {
			abort("segment read", err)
		}
		if n != row.Segments[i].DeclaredLen || hex.EncodeToString(sum.Sum(nil)) != row.Segments[i].SHA256 {
			abort("segment digest", errors.New("segment bytes do not match the verified digest"))
		}
	}
	if err := zw.Close(); err != nil {
		return
	}
}

func segmentFileName(i int) string {
	s := strconv.Itoa(i)
	return "segment-" + strings.Repeat("0", 4-len(s)) + s + ".ivf"
}
