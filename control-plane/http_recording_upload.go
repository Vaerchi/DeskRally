package controlplane

// Agent recording upload API (docs/63 D1, §2a C1–C5). Four ROOT routes, outside the cookie/CSRF/tenant
// chain — the agent has no session; its Ed25519 signature IS the authorization:
//
//	POST /agent/recordings                          create     (immutable metadata, quota reservation)
//	PUT  /agent/recordings/{id}/segments/{n}        put        (one 1 MiB chunk at the next offset)
//	HEAD /agent/recordings/{id}/segments/{n}        head       (committed offset, for resume)
//	POST /agent/recordings/{id}/finish              finish     (digests -> evidence_complete)
//
// (Behind Caddy these are /cp/agent/recordings…; the proxy strips /cp, and the signed canonical path is
// the stripped one.)
//
// THE PIPELINE (C3), in this order, every route:
//
//	1  deadlines: per-route read/write deadlines set through http.NewResponseController. If the server
//	   cannot honour them the request FAILS CLOSED (500) — an upload route without enforceable
//	   deadlines is a slow-loris handle. They override the server-wide 30 s/60 s timeouts, which are
//	   far too short for a chunk over a slow link and far too long for a header.
//	2  cheap pre-auth per-source-IP rate (no DB, no body)
//	3  parse + bound the headers (C1 canonicalisation) and the declared body length
//	4  timestamp window, then identity lookup (device -> tenant + pinned key) and SIGNATURE VERIFY
//	   against the pinned key and the machine's CURRENT enrollment (retired / quarantined / ephemeral
//	   machines are refused)
//	5  per-device rate (only now, after identity — see recording_admission.go) and the concurrency
//	   admission (global / tenant / device, bounded queue)
//	6  the handler: the body is read into a bounded buffer under a progress deadline and its sha256 and
//	   length are checked against the SIGNED values BEFORE anything is committed; then short, scoped
//	   database operations. No pool connection is ever held while bytes flow from the client.
//
// Local disk IO (writing the already-received chunk, fsync) happens inside the segment row lock — that
// is what serialises commits and makes "fsync before ack" and "advance the offset" one step.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// RecordingUploadConfig tunes the upload pipeline; the zero value means "use the defaults".
type RecordingUploadConfig struct {
	GlobalConcurrency int           // default 8
	TenantConcurrency int           // default 4
	DeviceConcurrency int           // default 2
	QueueMax          int           // default 32
	QueueWait         time.Duration // default 3s
	DeviceRatePerSec  float64       // default 20 requests/s
	DeviceBurst       int           // default 40
	IPRatePerSec      float64       // FAILED-authentication budget per source address: refill per second, default 5
	IPBurst           int           // ... and its burst, default 50
	FloorBytes        uint64        // disk-free floor, default 5 GiB (RECORDING_DISK_FLOOR_MIB)
	HeaderDeadline    time.Duration // default 15s
	SmallTotal        time.Duration // create/finish body total, default 30s
	SmallProgress     time.Duration // create/finish body progress, default 10s
	PutTotal          time.Duration // chunk body total, default 3m
	PutProgress       time.Duration // chunk body progress (no bytes for this long = dead), default 20s
	FinishWork        time.Duration // finish verification budget, default 10m
	// FreeBytes reports the volume's free bytes; nil = RecordingStorage.FreeBytes.
	FreeBytes func() (uint64, error)
}

func (c RecordingUploadConfig) withDefaults() RecordingUploadConfig {
	d := func(v *time.Duration, def time.Duration) {
		if *v <= 0 {
			*v = def
		}
	}
	i := func(v *int, def int) {
		if *v <= 0 {
			*v = def
		}
	}
	i(&c.GlobalConcurrency, 8)
	i(&c.TenantConcurrency, 4)
	i(&c.DeviceConcurrency, 2)
	i(&c.QueueMax, 32)
	d(&c.QueueWait, 3*time.Second)
	if c.DeviceRatePerSec == 0 {
		c.DeviceRatePerSec = 20
	}
	i(&c.DeviceBurst, 40)
	if c.IPRatePerSec == 0 {
		c.IPRatePerSec = 5
	}
	i(&c.IPBurst, 50)
	if c.FloorBytes == 0 {
		c.FloorBytes = RecordingDefaultFloorBytes
	}
	d(&c.HeaderDeadline, 15*time.Second)
	d(&c.SmallTotal, 30*time.Second)
	d(&c.SmallProgress, 10*time.Second)
	d(&c.PutTotal, 3*time.Minute)
	d(&c.PutProgress, 20*time.Second)
	d(&c.FinishWork, 10*time.Minute)
	return c
}

// RecordingWiring is the central-recording part of the Server. The upload routes mount only when
// Store, Files, Keys and Audience are all set (and the server has Machines and SessionRecords).
type RecordingWiring struct {
	Store RecordingStore
	Files *RecordingStorage
	Keys  *RecordingKeyring
	// Audience is the control plane's public origin (e.g. https://main.deskrally.com): signed into every
	// request so a signature for one deployment is worthless at another.
	Audience string
	Config   RecordingUploadConfig
	// SweepConfig tunes the retention + orphan sweeper (recording_sweeper.go).
	SweepConfig RecordingSweepConfig
	// Now is the server clock; nil = time.Now. The retention anchor does NOT use it (the store stamps
	// evidence_complete_at itself); this one drives the signature window, deadlines and the sweeper.
	Now func() time.Time
	// ReconcileMode disables the orphan pass and quarantine purge (a restore is being reconciled, C6/C11).
	// In reconcile mode the lost pass (recording_reconcile.go) marks rows whose files are missing as lost.
	ReconcileMode bool
	// ReconcileAcceptMissing (RECORDING_RECONCILE_ACCEPT_MISSING) lets that pass go ahead when most files are
	// missing or the volume looks empty: the operator's statement that the volume is mounted and the loss is real.
	ReconcileAcceptMissing bool
	// OnEvidenceComplete is called once a recording reaches evidence_complete, in addition to the playback
	// remux being queued (recording_playback.go) — it is an observation hook, not the remux trigger.
	OnEvidenceComplete func(ctx context.Context, tenantID string, rec *RecordingRow)
	// MuxConfig tunes the playback worker pool and the muxer's server-owned bounds.
	MuxConfig RecordingMuxConfig
	mux       recMux

	// wrapIncoming is a TEST SEAM: it lets a test observe the in-flight file's Sync calls (fsync must
	// happen before the offset is acknowledged). Always nil in production.
	wrapIncoming func(f EnvFile) EnvFile

	// reconcileBeforeMark is a TEST SEAM called inside the recording lock just before the lost pass re-checks
	// the volume root (recording_reconcile.go). Always nil in production.
	reconcileBeforeMark func()

	admOnce sync.Once
	adm     *uploadAdmission
	devRate *rateLimiter
	ipFail  *rateLimiter
	cfg     RecordingUploadConfig

	statsMu sync.Mutex
	stats   RecordingHealth

	// floorAlertAt rate-limits the create-refusal ALERT (alertFloorRefusal).
	floorAlertMu sync.Mutex
	floorAlertAt time.Time

	// auditSeen remembers recent "playback started" audit rows (http_recording_playback.go); an
	// optimisation filled only from rows that exist — the audit store remains the authority.
	auditMu   sync.Mutex
	auditSeen map[string]time.Time

	// StreamsPerTenant / StreamsPerUser cap concurrent content streams and downloads
	// (http_recording_stream_limit.go); zero selects the defaults (4 / 2).
	StreamsPerTenant int
	StreamsPerUser   int
	streams          recStreamLimiter
}

func (w *RecordingWiring) ready() bool {
	return w.Store != nil && w.Files != nil && w.Keys != nil && w.Audience != ""
}

func (w *RecordingWiring) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *RecordingWiring) init() {
	w.admOnce.Do(func() {
		w.cfg = w.Config.withDefaults()
		w.adm = newUploadAdmission(w.cfg.GlobalConcurrency, w.cfg.TenantConcurrency, w.cfg.DeviceConcurrency, w.cfg.QueueMax)
		w.devRate = newRateLimiter(w.cfg.DeviceRatePerSec, w.cfg.DeviceBurst, 100000)
		w.ipFail = newRateLimiter(w.cfg.IPRatePerSec, w.cfg.IPBurst, 100000)
	})
}

func (w *RecordingWiring) freeBytes() (uint64, error) {
	if w.cfg.FreeBytes != nil {
		return w.cfg.FreeBytes()
	}
	return w.Files.FreeBytes()
}

// mountRecordingUpload registers the four routes on the root mux (never on the protected chain).
func (s *Server) mountRecordingUpload(root *http.ServeMux) {
	w := &s.Recording
	if !w.ready() || s.Machines == nil || s.SessionRecords == nil {
		return
	}
	w.init()
	root.HandleFunc("POST "+recRoutePrefix, s.recRoute(UploadOpCreate, s.recCreate))
	root.HandleFunc("PUT "+recRoutePrefix+"/{id}/segments/{n}", s.recRoute(UploadOpPut, s.recPut))
	root.HandleFunc("HEAD "+recRoutePrefix+"/{id}/segments/{n}", s.recRoute(UploadOpHead, s.recHead))
	root.HandleFunc("POST "+recRoutePrefix+"/{id}/finish", s.recRoute(UploadOpFinish, s.recFinish))
}

// ---- response helpers -------------------------------------------------------------------------

func recFail(w http.ResponseWriter, status int, code string, extra map[string]any) {
	body := map[string]any{"error": code}
	for k, v := range extra {
		body[k] = v
	}
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable || code == "server_full" {
		w.Header().Set("Retry-After", "30")
	}
	writeJSON(w, status, body)
}

// recCall is an authenticated request.
type recCall struct {
	w       http.ResponseWriter
	r       *http.Request
	rc      *http.ResponseController
	p       *ParsedUpload
	machine *Machine
	pub     ed25519.PublicKey
}

type recHandler func(c *recCall)

// recRoute wraps a handler in the authentication and admission pipeline.
func (s *Server) recRoute(op UploadOp, h recHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		wiring := &s.Recording
		wiring.init()
		cfg := wiring.cfg
		now := wiring.now()

		// 1. Deadlines, fail closed.
		rc := http.NewResponseController(w)
		writeBound := cfg.HeaderDeadline + cfg.SmallTotal
		switch op {
		case UploadOpPut:
			writeBound = cfg.HeaderDeadline + cfg.PutTotal + cfg.SmallTotal
		case UploadOpFinish:
			writeBound = cfg.HeaderDeadline + cfg.SmallTotal + cfg.FinishWork
		}
		if rc.SetReadDeadline(now.Add(cfg.HeaderDeadline)) != nil || rc.SetWriteDeadline(now.Add(writeBound)) != nil {
			log.Printf("recording upload: server cannot enforce per-route deadlines; refusing %s", r.Method)
			recFail(w, http.StatusInternalServerError, "deadlines_unavailable", nil)
			return
		}

		// 2. Source throttle: an address that has exhausted its budget of FAILED authentications gets no
		// database work at all. Only failures are charged (authFail below); successes never are.
		ip := recClientKey(r)
		if !wiring.ipFail.peek(ip, now) {
			recFail(w, http.StatusTooManyRequests, "rate_limited", nil)
			return
		}
		authFail := func(status int, code string) {
			wiring.ipFail.spend(ip, now)
			recFail(w, status, code, nil)
		}

		// 3. Parse and bound.
		if r.ContentLength < 0 {
			recFail(w, http.StatusLengthRequired, "length_required", nil)
			return
		}
		limit := int64(0)
		switch op {
		case UploadOpCreate, UploadOpFinish:
			limit = 16 << 10
		case UploadOpPut:
			limit = RecChunkSize
		}
		if r.ContentLength > limit {
			recFail(w, http.StatusRequestEntityTooLarge, "body_too_large", nil)
			return
		}
		p, err := ParseUploadRequest(r, op, wiring.Audience)
		if err != nil {
			authFail(http.StatusBadRequest, "bad_request")
			return
		}

		// 4. Authenticate: window, identity, signature, current enrollment.
		if !UploadTimestampOK(now.UnixMilli(), p.Fields.TimestampMs) {
			authFail(http.StatusUnauthorized, "unauthorized")
			return
		}
		ident, err := s.Machines.LookupDeviceIdentity(r.Context(), p.Fields.DeviceID)
		if err != nil || ident.TenantID != p.TenantID {
			authFail(http.StatusUnauthorized, "unauthorized")
			return
		}
		pub, err := hex.DecodeString(ident.Pubkey)
		if err != nil || len(pub) != ed25519.PublicKeySize || UploadKeyFingerprint(pub) != p.Fields.KeyFP ||
			!VerifyUploadSignature(pub, p.Fields, p.Signature) {
			authFail(http.StatusUnauthorized, "unauthorized")
			return
		}
		machine, err := s.Machines.GetMachine(r.Context(), p.TenantID, p.Fields.DeviceID)
		if err != nil || machine.Pubkey != ident.Pubkey || machine.Ephemeral || !recIsUUID(machine.ID) {
			authFail(http.StatusUnauthorized, "unauthorized")
			return
		}
		if machine.Status != "" && machine.Status != MachineStatusActive {
			recFail(w, http.StatusForbidden, "machine_not_active", nil)
			return
		}

		// 5. Per-device rate (identity is proven now), then concurrency admission.
		if !wiring.devRate.allow(p.TenantID+"/"+p.Fields.DeviceID, now) {
			recFail(w, http.StatusTooManyRequests, "rate_limited", nil)
			return
		}
		release, err := wiring.adm.acquire(r.Context(), p.TenantID, p.Fields.DeviceID, cfg.QueueWait)
		if err != nil {
			recFail(w, http.StatusServiceUnavailable, "busy", nil)
			return
		}
		defer release()

		h(&recCall{w: w, r: r, rc: rc, p: p, machine: machine, pub: pub})
	}
}

func recClientKey(r *http.Request) string {
	if ip := clientIP(r); ip != "" {
		return ip
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// readSignedBody reads exactly the declared Content-Length under a PROGRESS deadline (no bytes for
// `progress` = the peer is dead) inside a TOTAL bound, and refuses unless its sha256 equals the signed
// value. Nothing is committed by the caller before this returns nil.
func (c *recCall) readSignedBody(total, progress time.Duration, nowFn func() time.Time) ([]byte, int, string) {
	n := c.r.ContentLength
	buf := make([]byte, n)
	hardStop := nowFn().Add(total)
	body := http.MaxBytesReader(c.w, c.r.Body, n+1)
	var read int64
	for read < n {
		dl := nowFn().Add(progress)
		if dl.After(hardStop) {
			dl = hardStop
		}
		if c.rc.SetReadDeadline(dl) != nil {
			return nil, http.StatusInternalServerError, "deadlines_unavailable"
		}
		m, err := body.Read(buf[read:])
		read += int64(m)
		if err != nil {
			if errors.Is(err, io.EOF) && read == n {
				break
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, http.StatusRequestTimeout, "timeout"
			}
			return nil, http.StatusBadRequest, "short_body"
		}
	}
	// Exactly n bytes: one more byte (or anything past n) is a lie about the length.
	var extra [1]byte
	_ = c.rc.SetReadDeadline(nowFn().Add(progress))
	if k, _ := body.Read(extra[:]); k > 0 {
		return nil, http.StatusBadRequest, "long_body"
	}
	sum := sha256.Sum256(buf)
	if sum != c.p.Fields.BodySHA256 {
		return nil, http.StatusBadRequest, "body_digest_mismatch"
	}
	return buf, 0, ""
}

func (s *Server) recSmallBody(c *recCall) ([]byte, bool) {
	w := &s.Recording
	b, status, code := c.readSignedBody(w.cfg.SmallTotal, w.cfg.SmallProgress, w.now)
	if status != 0 {
		recFail(c.w, status, code, nil)
		return nil, false
	}
	return b, true
}

func recStrictJSON(b []byte, dst any) error {
	if !jsonTextIsStrict(b) {
		return errStrictJSONText
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// recState is the upload state returned by create.
func recState(row *RecordingRow) map[string]any {
	segs := make([]map[string]any, len(row.Segments))
	for i, sg := range row.Segments {
		segs[i] = map[string]any{"index": sg.Index, "length": sg.DeclaredLen, "committed_offset": sg.CommittedOffset}
	}
	return map[string]any{"recording_id": row.ID, "generation": row.Generation, "state": row.State,
		"chunk_size": RecChunkSize, "segments": segs}
}

func recEnvMeta(row *RecordingRow, idx int, declared int64, rep EnvRep) (EnvelopeMeta, error) {
	t, ok1 := recParseUUID(row.TenantID)
	r, ok2 := recParseUUID(row.ID)
	if !ok1 || !ok2 {
		return EnvelopeMeta{}, errors.New("non-canonical ids")
	}
	return EnvelopeMeta{TenantID: t, RecordingID: r, Segment: uint32(idx), Rep: rep,
		Generation: uint64(row.Generation), TotalLen: uint64(declared)}, nil
}

// ---- create -----------------------------------------------------------------------------------

type recCreateBody struct {
	RecordingID string `json:"recording_id"`
	SessionID   string `json:"session_id"`
	Generation  uint64 `json:"generation"`
	Segments    []struct {
		Index  int   `json:"index"`
		Length int64 `json:"length"`
	} `json:"segments"`
}

func (s *Server) recCreate(c *recCall) {
	raw, ok := s.recSmallBody(c)
	if !ok {
		return
	}
	var in recCreateBody
	if err := recStrictJSON(raw, &in); err != nil || in.RecordingID != c.p.RecordingID ||
		in.Generation != c.p.Fields.Generation || !recIsUUID(in.SessionID) ||
		len(in.Segments) < 1 || len(in.Segments) > RecMaxSegments {
		recFail(c.w, http.StatusBadRequest, "bad_request", nil)
		return
	}
	lens := make([]int64, len(in.Segments))
	for i, sg := range in.Segments {
		if sg.Index != i || sg.Length < 1 || sg.Length > RecHardMaxBytes {
			recFail(c.w, http.StatusBadRequest, "bad_request", nil)
			return
		}
		lens[i] = sg.Length
	}
	if in.Generation > 1<<62 {
		recFail(c.w, http.StatusBadRequest, "bad_request", nil)
		return
	}
	ctx := c.r.Context()
	sess, err := s.SessionRecords.GetSession(ctx, c.p.TenantID, in.SessionID)
	if errors.Is(err, ErrSessionRecordNotFound) {
		recFail(c.w, http.StatusNotFound, "session_unknown", nil)
		return
	}
	if err != nil {
		recFail(c.w, http.StatusInternalServerError, "internal", nil)
		return
	}
	if sess.MachineID != c.machine.ID {
		recFail(c.w, http.StatusForbidden, "session_not_on_this_machine", nil)
		return
	}
	tn, _ := recParseUUID(c.p.TenantID)
	wrapped, keyID, err := s.Recording.Keys.NewDEK(tn, c.p.Fields.RecordingID)
	if err != nil {
		recFail(c.w, http.StatusInternalServerError, "internal", nil)
		return
	}
	lim := RecordingCreateLimits{FloorBytes: s.Recording.cfg.FloorBytes}
	if free, ferr := s.Recording.freeBytes(); ferr == nil {
		lim.FreeBytes, lim.FreeKnown = free, true
	} else {
		log.Printf("recording upload: cannot measure free space: %v", ferr)
	}
	row, created, err := s.Recording.Store.CreateRecording(ctx, c.p.TenantID, NewRecording{
		ID: in.RecordingID, SessionID: in.SessionID, MachineID: c.machine.ID, UploadID: newUUID(),
		EnrollmentFP: c.p.Fields.KeyFP, Generation: int64(in.Generation), SegmentLens: lens,
		Key: EnvelopeKey{KeyID: keyID, Wrapped: wrapped},
	}, lim)
	switch {
	case err == nil:
	case errors.Is(err, ErrRecordingStorageOff):
		recFail(c.w, http.StatusForbidden, "storage_off", nil)
		return
	case errors.Is(err, ErrRecordingTooLarge):
		recFail(c.w, http.StatusRequestEntityTooLarge, "too_large", nil)
		return
	case errors.Is(err, ErrRecordingQuota):
		recFail(c.w, http.StatusInsufficientStorage, "tenant_quota", nil)
		return
	case errors.Is(err, ErrRecordingServerFull):
		s.Recording.alertFloorRefusal(lim)
		recFail(c.w, http.StatusInsufficientStorage, "server_full", nil)
		return
	case errors.Is(err, ErrRecordingTombstoned):
		recFail(c.w, http.StatusGone, "gone", nil)
		return
	case errors.Is(err, ErrRecordingConflict):
		recFail(c.w, http.StatusConflict, "conflict", nil)
		return
	case errors.Is(err, ErrRecordingAlreadyComplete):
		recFail(c.w, http.StatusConflict, "already_complete", nil)
		return
	default:
		log.Printf("recording upload: create: %v", err)
		recFail(c.w, http.StatusInternalServerError, "internal", nil)
		return
	}
	if !created && s.recUploadExpired(row) { // an idempotent replay cannot revive a dead upload
		recFail(c.w, http.StatusGone, "upload_expired", nil)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(c.w, status, recState(row))
}

// loadOwned loads the recording a signed request names and checks it belongs to the signing device,
// enrollment key and generation. It writes the failure response itself.
func (s *Server) recLoadOwned(c *recCall) (*RecordingRow, bool) {
	return s.recLoadOwnedCtx(c, c.r.Context())
}

// recLoadOwnedCtx is recLoadOwned under an explicit context: the finish passes its budget context for the
// authoritative post-lock read, so a database that stalls there ends with the finish budget, not never.
func (s *Server) recLoadOwnedCtx(c *recCall, ctx context.Context) (*RecordingRow, bool) {
	row, err := s.Recording.Store.GetRecording(ctx, c.p.TenantID, c.p.RecordingID)
	if errors.Is(err, ErrRecordingNotFound) {
		recFail(c.w, http.StatusNotFound, "not_found", nil)
		return nil, false
	}
	if err != nil && ctx.Err() != nil {
		log.Printf("recording upload: load: %v", err)
		recFail(c.w, http.StatusServiceUnavailable, "busy", nil)
		return nil, false
	}
	if err != nil {
		log.Printf("recording upload: load: %v", err)
		recFail(c.w, http.StatusInternalServerError, "internal", nil)
		return nil, false
	}
	if row.MachineID != c.machine.ID || row.EnrollmentFP != c.p.Fields.KeyFP {
		recFail(c.w, http.StatusForbidden, "forbidden", nil)
		return nil, false
	}
	if recIsTombstone(row.State) {
		recFail(c.w, http.StatusGone, "gone", map[string]any{"state": row.State})
		return nil, false
	}
	if row.Generation != int64(c.p.Fields.Generation) {
		recFail(c.w, http.StatusConflict, "generation_mismatch", nil)
		return nil, false
	}
	if s.recUploadExpired(row) {
		recFail(c.w, http.StatusGone, "upload_expired", nil)
		return nil, false
	}
	return row, true
}

// recUploadExpired enforces the C3 upload lifetime on EVERY request: an upload still 'uploading' at
// RecMaxUploadLifetime is dead from that instant, whether or not the sweep has abandoned its row yet.
// Retries never extend it (it is anchored on the row's creation).
func (s *Server) recUploadExpired(row *RecordingRow) bool {
	return row.State == RecUploading && s.Recording.now().Sub(row.CreatedAt) >= RecMaxUploadLifetime
}

// ---- head -------------------------------------------------------------------------------------

func (s *Server) recHead(c *recCall) {
	if c.p.Fields.BodySHA256 != sha256.Sum256(nil) { // a HEAD has no body: the signed digest must say so
		recFail(c.w, http.StatusBadRequest, "bad_request", nil)
		return
	}
	row, ok := s.recLoadOwned(c)
	if !ok {
		return
	}
	idx := int(c.p.Fields.Segment)
	if idx >= len(row.Segments) {
		c.w.WriteHeader(http.StatusNotFound)
		return
	}
	sg := row.Segments[idx]
	h := c.w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Rmt-Committed-Offset", strconv.FormatInt(sg.CommittedOffset, 10))
	h.Set("X-Rmt-Segment-Length", strconv.FormatInt(sg.DeclaredLen, 10))
	h.Set("X-Rmt-State", row.State)
	c.w.WriteHeader(http.StatusOK)
}

// ---- put --------------------------------------------------------------------------------------

type recBadOffset struct{ committed int64 }

func (recBadOffset) Error() string { return "offset is not the next expected offset" }

var (
	errRecChunkConflict = errors.New("a different chunk was already committed at this offset")
	errRecInconsistent  = errors.New("the stored bytes do not match the committed offset")
)

func (s *Server) recPut(c *recCall) {
	row, ok := s.recLoadOwned(c)
	if !ok {
		return
	}
	idx := int(c.p.Fields.Segment)
	if idx >= len(row.Segments) {
		recFail(c.w, http.StatusNotFound, "not_found", nil)
		return
	}
	seg := row.Segments[idx]
	offset := int64(c.p.Fields.Offset)
	// The chunk geometry is fully determined by (declared length, offset): 1 MiB chunks, the last one
	// short. That keeps every chunk on a frame boundary and leaves nothing for the client to choose.
	if c.p.Fields.Offset > uint64(seg.DeclaredLen) || offset >= seg.DeclaredLen || offset%RecChunkSize != 0 {
		recFail(c.w, http.StatusConflict, "bad_offset", map[string]any{"committed_offset": seg.CommittedOffset})
		return
	}
	want := seg.DeclaredLen - offset
	if want > RecChunkSize {
		want = RecChunkSize
	}
	if c.r.ContentLength != want {
		recFail(c.w, http.StatusBadRequest, "bad_chunk_length", map[string]any{"expected": want})
		return
	}
	chunk, status, code := c.readSignedBody(s.Recording.cfg.PutTotal, s.Recording.cfg.PutProgress, s.Recording.now)
	if status != 0 {
		recFail(c.w, status, code, nil)
		return
	}

	// A completed recording accepts only an exact re-send of bytes it already holds.
	if row.State != RecUploading {
		if s.recChunkMatchesDisk(row, idx, offset, chunk) {
			writeJSON(c.w, http.StatusOK, map[string]any{"committed_offset": seg.DeclaredLen, "resent": true})
			return
		}
		recFail(c.w, http.StatusConflict, "already_complete", nil)
		return
	}

	var resent bool
	var newOffset int64
	err := s.Recording.Store.UpdateSegment(c.r.Context(), c.p.TenantID, c.p.RecordingID, idx,
		func(cur *RecordingRow, cs RecordingSegment) (int64, error) {
			n, rs, err := s.recCommitChunk(cur, cs, offset, chunk)
			resent = rs
			newOffset = n
			return n, err
		})
	var bad recBadOffset
	switch {
	case err == nil:
		writeJSON(c.w, http.StatusOK, map[string]any{"committed_offset": newOffset, "resent": resent})
	case errors.As(err, &bad):
		recFail(c.w, http.StatusConflict, "bad_offset", map[string]any{"committed_offset": bad.committed})
	case errors.Is(err, errRecChunkConflict):
		recFail(c.w, http.StatusConflict, "chunk_conflict", nil)
	case errors.Is(err, errRecInconsistent):
		// The bytes the database acknowledged are not (all) on the volume. Forget them so the agent can
		// re-send from zero; this is NOT counted as a finish failure.
		log.Printf("recording upload: segment %d of %s: stored bytes inconsistent; resetting", idx, c.p.RecordingID)
		if rerr := s.Recording.Store.ResetSegment(c.r.Context(), c.p.TenantID, c.p.RecordingID, idx); rerr != nil {
			log.Printf("recording upload: reset: %v", rerr)
		}
		recFail(c.w, http.StatusConflict, "bad_offset", map[string]any{"committed_offset": 0})
	case errors.Is(err, ErrRecordingState):
		recFail(c.w, http.StatusConflict, "already_complete", nil)
	case errors.Is(err, ErrRecordingNotFound):
		recFail(c.w, http.StatusNotFound, "not_found", nil)
	default:
		log.Printf("recording upload: put: %v", err)
		recFail(c.w, http.StatusInternalServerError, "internal", nil)
	}
}

// recCommitChunk runs INSIDE the segment row lock: it either appends the chunk at the committed offset
// (bytes written and fsynced before it returns, so the offset the store then persists is already
// durable), or recognises an exact re-send, or refuses. It returns the new committed offset.
func (s *Server) recCommitChunk(row *RecordingRow, seg RecordingSegment, offset int64, chunk []byte) (int64, bool, error) {
	w := &s.Recording
	committed := seg.CommittedOffset
	switch {
	case offset == committed:
		meta, err := recEnvMeta(row, seg.Index, seg.DeclaredLen, RepIVF)
		if err != nil {
			return 0, false, err
		}
		f, err := w.Files.OpenIncoming(row.UploadID, uint32(seg.Index), RepIVF, true)
		if err != nil {
			return 0, false, err
		}
		defer f.Close()
		var ef EnvFile = f
		if w.wrapIncoming != nil {
			ef = w.wrapIncoming(f)
		}
		var env *EnvelopeWriter
		if committed == 0 {
			env, err = CreateEnvelope(ef, w.Keys, row.Key(), meta)
		} else {
			env, err = ResumeEnvelope(ef, w.Keys, row.Key(), meta, uint64(committed))
			if errors.Is(err, ErrEnvelopeFormat) || errors.Is(err, ErrEnvelopeTruncate) || errors.Is(err, ErrEnvelopeDirty) {
				return 0, false, errRecInconsistent
			}
		}
		if err != nil {
			return 0, false, err
		}
		if _, err := env.Write(chunk); err != nil {
			return 0, false, err
		}
		if env.Buffered() != 0 {
			return 0, false, errors.New("chunk did not end on a frame boundary")
		}
		if err := env.Sync(); err != nil { // fsync BEFORE the offset is acknowledged
			return 0, false, err
		}
		return committed + int64(len(chunk)), false, nil
	case offset < committed:
		if offset+int64(len(chunk)) > committed {
			return 0, false, errRecChunkConflict
		}
		if !s.recChunkMatchesDisk(row, seg.Index, offset, chunk) {
			return 0, false, errRecChunkConflict
		}
		return committed, true, nil
	default:
		return 0, false, recBadOffset{committed: committed}
	}
}

// recOpenSegmentReader opens a segment's envelope from the in-flight file, or from the promoted final
// one when the upload already finished.
func (s *Server) recOpenSegmentReader(row *RecordingRow, idx int, allowPartial bool) (*EnvelopeReader, func(), error) {
	w := &s.Recording
	seg := row.Segments[idx]
	meta, err := recEnvMeta(row, idx, seg.DeclaredLen, RepIVF)
	if err != nil {
		return nil, nil, err
	}
	expect := EnvelopeExpect{TenantID: meta.TenantID, RecordingID: meta.RecordingID, Segment: meta.Segment, Rep: RepIVF, Generation: meta.Generation}
	f, size, err := w.Files.OpenIncomingRead(row.UploadID, uint32(idx), RepIVF)
	if errors.Is(err, os.ErrNotExist) {
		f, size, err = w.Files.OpenFinal(row.TenantID, row.ID, uint32(idx), RepIVF)
	}
	if err != nil {
		return nil, nil, err
	}
	rd, err := OpenEnvelope(f, size, w.Keys, expect, allowPartial)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return rd, func() { f.Close() }, nil
}

func (s *Server) recChunkMatchesDisk(row *RecordingRow, idx int, offset int64, chunk []byte) bool {
	rd, closeFn, err := s.recOpenSegmentReader(row, idx, true)
	if err != nil {
		return false
	}
	defer closeFn()
	have, err := rd.ReadRange(offset, int64(len(chunk)))
	if err != nil {
		return false
	}
	a, b := sha256.Sum256(have), sha256.Sum256(chunk)
	return a == b
}

// ---- finish -----------------------------------------------------------------------------------

type recFinishBody struct {
	RecordingID   string   `json:"recording_id"`
	Generation    uint64   `json:"generation"`
	Digests       []string `json:"digests"`
	Truncated     *string  `json:"truncated"`
	DroppedFrames *uint64  `json:"dropped_frames"`
	Frames        *uint64  `json:"frames"`
	PayloadBytes  *uint64  `json:"payload_bytes"`
}

func recFinishAck(row *RecordingRow) map[string]any {
	digests := make([]string, len(row.Segments))
	for i, sg := range row.Segments {
		digests[i] = sg.SHA256
	}
	return map[string]any{"recording_id": row.ID, "generation": row.Generation, "state": RecEvidenceComplete,
		"digests": digests, "provenance": row.Provenance}
}

// recFinishFieldsOK bounds the finish counters (C7's server-owned limits: <= RecMaxSegments segments of
// <= 500k frames; the dropped counter gets a generous fixed ceiling) and restricts the truncation reason
// to a short lower-case code ([a-z0-9_], no NUL or other control characters).
func recFinishFieldsOK(in *recFinishBody) bool {
	maxFrames := uint64(RecMaxSegments) * uint64(DefaultMuxLimits().MaxFrames)
	if in.Frames != nil && *in.Frames > maxFrames {
		return false
	}
	if *in.DroppedFrames > recMaxDroppedFrames {
		return false
	}
	if in.PayloadBytes != nil && *in.PayloadBytes > uint64(RecMaxSegments)*uint64(RecHardMaxBytes) {
		return false
	}
	if in.Truncated != nil {
		for _, ch := range []byte(*in.Truncated) {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_') {
				return false
			}
		}
	}
	return true
}

// recMaxDroppedFrames is far above anything a real recorder drops and far below MaxInt64.
const recMaxDroppedFrames = uint64(1) << 40

func isHexDigest(s string) bool {
	var b [32]byte
	return decodeFixedHex(b[:], s)
}

func (s *Server) recFinish(c *recCall) {
	raw, ok := s.recSmallBody(c)
	if !ok {
		return
	}
	var in recFinishBody
	if err := recStrictJSON(raw, &in); err != nil || in.RecordingID != c.p.RecordingID ||
		in.Generation != c.p.Fields.Generation || in.DroppedFrames == nil ||
		len(in.Digests) < 1 || len(in.Digests) > RecMaxSegments ||
		(in.Truncated != nil && (len(*in.Truncated) == 0 || len(*in.Truncated) > 64)) {
		recFail(c.w, http.StatusBadRequest, "bad_request", nil)
		return
	}
	for _, d := range in.Digests {
		if !isHexDigest(d) {
			recFail(c.w, http.StatusBadRequest, "bad_request", nil)
			return
		}
	}
	// Every claimed number and label is validated here, before the row is loaded, any digest pass or any
	// Promote: nothing the agent says may reach the database (an int64 column) or the audit trail unchecked.
	if !recFinishFieldsOK(&in) {
		recFail(c.w, http.StatusBadRequest, "bad_request", nil)
		return
	}
	fin := recFinishMeta{Digests: in.Digests, Truncated: in.Truncated, DroppedFrames: *in.DroppedFrames,
		Frames: in.Frames, PayloadBytes: in.PayloadBytes}
	// Cheap pre-checks on an unlocked read (ownership, tombstone, generation, shape). The authoritative
	// work below re-reads the row under the per-recording lock.
	row, ok := s.recLoadOwned(c)
	if !ok {
		return
	}
	if !recFinishShapeOK(c, row, &in) {
		return
	}

	// A bounded finish: the lock wait, the digest passes and the provenance scan share ONE budget. The
	// HTTP write deadline only bounds the response; this context is what stops the work.
	fctx, cancel := context.WithTimeout(c.r.Context(), s.Recording.cfg.FinishWork)
	defer cancel()
	unlock, err := s.Recording.Store.LockRecording(fctx, c.p.TenantID, row.ID)
	if err != nil {
		log.Printf("recording upload: finish %s: lock: %v", row.ID, err)
		recFail(c.w, http.StatusServiceUnavailable, "busy", nil)
		return
	}
	defer unlock()
	// Whoever held the lock before us may have finished, refused or abandoned the recording.
	row, ok = s.recLoadOwnedCtx(c, fctx)
	if !ok {
		return
	}
	s.recFinishLocked(c, fctx, row, &in, fin)
}

// recFinishShapeOK checks the finish against the loaded row's shape; it writes the refusal.
func recFinishShapeOK(c *recCall, row *RecordingRow, in *recFinishBody) bool {
	if len(in.Digests) != len(row.Segments) {
		recFail(c.w, http.StatusConflict, "conflict", nil)
		return false
	}
	// The payload cannot exceed the plaintext the segments declared (known only once the row is loaded).
	var declared int64
	for _, sg := range row.Segments {
		declared += sg.DeclaredLen // each is <= RecHardMaxBytes and there are <= RecMaxSegments
	}
	if in.PayloadBytes != nil && *in.PayloadBytes > uint64(declared) {
		recFail(c.w, http.StatusBadRequest, "bad_request", nil)
		return false
	}
	return true
}

// recFinishLocked runs with the recording's lock held and ctx bounded by the finish budget. Everything that
// moves files or commits state for this recording happens here, so no other finish, refusal, abandonment
// or rollback interleaves with it.
func (s *Server) recFinishLocked(c *recCall, ctx context.Context, row *RecordingRow, in *recFinishBody, fin recFinishMeta) {
	if !recFinishShapeOK(c, row, in) {
		return
	}
	// Idempotent replay of a finish that already succeeded: same answer; a different claim is a conflict.
	if row.State != RecUploading {
		if recFinishMatchesStored(row, fin) {
			writeJSON(c.w, http.StatusOK, recFinishAck(row))
		} else {
			recFail(c.w, http.StatusConflict, "conflict", nil)
		}
		return
	}

	// Every byte must have been committed.
	var incomplete []map[string]any
	for _, sg := range row.Segments {
		if sg.CommittedOffset != sg.DeclaredLen {
			incomplete = append(incomplete, map[string]any{"index": sg.Index, "committed_offset": sg.CommittedOffset, "length": sg.DeclaredLen})
		}
	}
	if len(incomplete) > 0 {
		recFail(c.w, http.StatusConflict, "incomplete", map[string]any{"segments": incomplete})
		return
	}

	// Verify the plaintext digests by decrypting what is actually on disk (cancellable per frame).
	var bad []int
	for i := range row.Segments {
		d, err := s.recSegmentDigest(ctx, row, i)
		if ctx.Err() != nil {
			log.Printf("recording upload: finish %s: verification budget exhausted: %v", row.ID, ctx.Err())
			recFail(c.w, http.StatusServiceUnavailable, "busy", nil)
			return
		}
		if err != nil || d != in.Digests[i] {
			if err != nil {
				log.Printf("recording upload: finish %s segment %d: %v", row.ID, i, err)
			}
			bad = append(bad, i)
		}
	}
	if len(bad) > 0 {
		state, err := s.Recording.Store.RecordFinishFailure(ctx, c.p.TenantID, row.ID, bad)
		if err != nil && !errors.Is(err, ErrRecordingState) {
			recFail(c.w, http.StatusInternalServerError, "internal", nil)
			return
		}
		if state == RecRefused {
			s.recDropIncoming(row)
		}
		recFail(c.w, http.StatusUnprocessableEntity, "digest_mismatch", map[string]any{"segments": bad, "state": state})
		return
	}

	// Provenance (C4): a conflicting signed stop event refuses the upload outright.
	label, seq, err := s.recordingProvenance(ctx, c.p.TenantID, row, c.machine, fin)
	switch {
	case errors.Is(err, errProvenanceConflict):
		if rerr := s.Recording.Store.RefuseRecording(ctx, c.p.TenantID, row.ID); rerr != nil && !errors.Is(rerr, ErrRecordingState) {
			log.Printf("recording upload: refuse: %v", rerr)
		}
		s.recDropIncoming(row)
		recFail(c.w, http.StatusConflict, "audit_conflict", nil)
		return
	case err != nil:
		log.Printf("recording upload: provenance for %s: %v", row.ID, err)
		recFail(c.w, http.StatusServiceUnavailable, "audit_unavailable", nil)
		return
	}

	// Promote the verified generation (atomic rename; idempotent), then record the state. The row flips to
	// evidence_complete only after every file is final (C2). If the database step then fails, the promotion
	// is undone (files back to incoming) so a failed finish never leaves an 'uploading' row whose files sit
	// in the final directory. The whole sequence runs under the recording's lock, so no other finish can
	// commit between the undo's state check and the undo itself; a crash in this window is still
	// recoverable because the reader falls back to the final file and Promote is idempotent.
	for i := range row.Segments {
		if err := s.Recording.Files.Promote(row.UploadID, row.TenantID, row.ID, uint32(i), RepIVF); err != nil {
			log.Printf("recording upload: promote %s segment %d: %v", row.ID, i, err)
			s.recUndoPromote(ctx, c.p.TenantID, row)
			recFail(c.w, http.StatusInternalServerError, "internal", nil)
			return
		}
	}
	done, err := s.Recording.Store.CompleteEvidence(ctx, c.p.TenantID, row.ID, EvidenceCompletion{
		Digests: in.Digests, Truncated: in.Truncated,
		DroppedFrames: u64p(in.DroppedFrames), Frames: u64p(in.Frames), PayloadBytes: u64p(in.PayloadBytes),
		Provenance: label, MatchedAuditSeq: seq})
	if err != nil && !errors.Is(err, ErrRecordingState) {
		s.recUndoPromote(ctx, c.p.TenantID, row)
	}
	if errors.Is(err, ErrRecordingState) { // another process finished outside our lock: answer from what is stored
		if cur, gerr := s.Recording.Store.GetRecording(ctx, c.p.TenantID, row.ID); gerr == nil &&
			cur.State != RecUploading && recFinishMatchesStored(cur, fin) {
			writeJSON(c.w, http.StatusOK, recFinishAck(cur))
			return
		}
		recFail(c.w, http.StatusConflict, "conflict", nil)
		return
	}
	if err != nil {
		log.Printf("recording upload: complete %s: %v", row.ID, err)
		recFail(c.w, http.StatusInternalServerError, "internal", nil)
		return
	}
	s.recDropIncoming(done) // the generation was promoted; this removes the now-empty upload directory
	if s.Recording.OnEvidenceComplete != nil {
		s.Recording.OnEvidenceComplete(context.WithoutCancel(ctx), c.p.TenantID, done)
	}
	// Queue the playback remux (C7). Never blocks and never fails the finish: the evidence is complete and
	// acknowledged either way; if the queue is full or not running the sweep offers it again.
	s.EnqueuePlayback(c.p.TenantID, done.ID)
	writeJSON(c.w, http.StatusOK, recFinishAck(done))
}

func u64p(v *uint64) *int64 {
	if v == nil {
		return nil
	}
	n := int64(*v)
	return &n
}

// recFinishMatchesStored: the replayed finish carries exactly the digests and metadata that were
// recorded.
func recFinishMatchesStored(row *RecordingRow, fin recFinishMeta) bool {
	if len(row.Segments) != len(fin.Digests) {
		return false
	}
	for i, sg := range row.Segments {
		if sg.SHA256 != fin.Digests[i] {
			return false
		}
	}
	if !strPtrEq(row.Truncated, fin.Truncated) {
		return false
	}
	if row.DroppedFrames == nil || uint64(*row.DroppedFrames) != fin.DroppedFrames {
		return false
	}
	// frames / payload_bytes are optional claims: an absent value matches only an absent stored value.
	if !u64PtrMatches(row.Frames, fin.Frames) || !u64PtrMatches(row.PayloadBytes, fin.PayloadBytes) {
		return false
	}
	return true
}

// u64PtrMatches compares a stored optional counter with a claimed one, nil meaning "not supplied".
func u64PtrMatches(stored *int64, claimed *uint64) bool {
	if stored == nil || claimed == nil {
		return stored == nil && claimed == nil
	}
	return *stored >= 0 && uint64(*stored) == *claimed
}

// ctxWriter refuses a write once its context is done, so a long frame-by-frame decrypt stops promptly.
type ctxWriter struct {
	ctx context.Context
	dst io.Writer
}

func (c ctxWriter) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.dst.Write(p)
}

// recSegmentDigest decrypts a segment end to end (every frame authenticated, exact EOF) and returns the
// sha256 of its plaintext.
func (s *Server) recSegmentDigest(ctx context.Context, row *RecordingRow, idx int) (string, error) {
	rd, closeFn, err := s.recOpenSegmentReader(row, idx, false)
	if err != nil {
		return "", err
	}
	defer closeFn()
	h := sha256.New()
	n, err := rd.WriteTo(ctxWriter{ctx: ctx, dst: h}) // one frame at a time: cancellation is checked between frames
	if err != nil {
		return "", err
	}
	if n != row.Segments[idx].DeclaredLen {
		return "", errors.New("segment length differs from the declared length")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// recUndoPromote moves any promoted segment files of a still-'uploading' row back to the incoming area.
// Best effort: a failure is logged and the retried finish (which tolerates either location) repairs it.
func (s *Server) recUndoPromote(ctx context.Context, tenantID string, row *RecordingRow) {
	// Only while the row is provably still 'uploading': if the commit may have landed (or the state cannot
	// be read), leave the files where they are; the final location is what an evidence_complete row needs.
	// Not cancelled with the finish budget (the rollback must still look), but bounded on its own.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	cur, err := s.Recording.Store.GetRecording(rctx, tenantID, row.ID)
	if err != nil || cur.State != RecUploading {
		return
	}
	for i := range row.Segments {
		if err := s.Recording.Files.Unpromote(row.UploadID, row.TenantID, row.ID, uint32(i), RepIVF); err != nil {
			log.Printf("recording upload: undo promote %s segment %d: %v", row.ID, i, err)
		}
	}
}

func (s *Server) recDropIncoming(row *RecordingRow) {
	if _, err := s.Recording.Files.RemoveIncoming(row.UploadID); err != nil {
		log.Printf("recording upload: remove incoming %s: %v", row.UploadID, err)
	}
}

// recFloorAlertEvery is the minimum gap between create-refusal ALERT lines: a burst of refused uploads
// (every agent retrying) must not flood the log, but the first refusal must be visible at once rather
// than waiting for the next 5-minute sweep tick (noteDisk).
const recFloorAlertEvery = time.Minute

// alertFloorRefusal logs the same ALERT the sweeper logs when a CREATE is refused because the volume has no
// room (the floor, the reservations, or a volume that could not be measured), at most once a minute.
func (w *RecordingWiring) alertFloorRefusal(lim RecordingCreateLimits) {
	now := w.now()
	w.floorAlertMu.Lock()
	// now.Sub uses the MONOTONIC reading when both times carry one (the default clock does), so a wall-clock
	// step backwards cannot reopen the window; for a wall-only clock a backward step gives a negative gap,
	// which is < the window and therefore also suppresses (never a flood).
	if !w.floorAlertAt.IsZero() && now.Sub(w.floorAlertAt) < recFloorAlertEvery {
		w.floorAlertMu.Unlock()
		return
	}
	w.floorAlertAt = now
	w.floorAlertMu.Unlock()
	if !lim.FreeKnown {
		log.Printf("recording upload: ALERT a create was refused (507 server_full): the recordings volume could not be measured; floor %d", lim.FloorBytes)
		return
	}
	log.Printf("recording upload: ALERT a create was refused (507 server_full): recordings volume free space %d does not cover the floor %d plus reservations; new uploads are refused", lim.FreeBytes, lim.FloorBytes)
}
