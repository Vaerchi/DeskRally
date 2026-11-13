package controlplane

// Test harness for the recording upload API: a real control-plane Handler behind a real HTTP server
// (the route deadlines are http.NewResponseController calls, which only a real connection exercises),
// an enrolled device with a real Ed25519 key that SIGNS its requests exactly as the agent will, and the
// fake stores with the real storage layer on a temp directory.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// denyAllAuth is the authenticated chain's front door in these tests: it refuses everyone, so a request
// that falls through the upload routes to the catch-all is visibly refused (401), never served.
type denyAllAuth struct{}

func (denyAllAuth) Authenticate(*http.Request) (*Principal, error) { return nil, errors.New("no") }

type recH struct {
	t        *testing.T
	srv      *Server
	ts       *httptest.Server
	store    *InMemoryRecordingStore
	files    *RecordingStorage
	dir      string
	keys     *RecordingKeyring
	machines *InMemoryMachineStore
	sessions *InMemorySessionRecordStore
	audit    *InMemoryAuditStore
	tenant   string
	machine  *Machine
	device   string
	priv     ed25519.PrivateKey
	session  string
	audience string
}

type recHOpts struct {
	cfg         RecordingUploadConfig
	noPolicy    bool
	wireUp      func(h *recH)
	readTimeout time.Duration
}

func newRecH(t *testing.T, o recHOpts) *recH {
	t.Helper()
	h := &recH{t: t, tenant: newUUID(), device: "dev-rec-" + newUUID()[:8], audience: "https://cp.example.test"}
	seed := bytes.Repeat([]byte{42}, ed25519.SeedSize)
	h.priv = ed25519.NewKeyFromSeed(seed)
	h.machines = NewInMemoryMachineStore()
	h.machine = &Machine{DeviceID: h.device, GroupID: newUUID(), Name: "rec-box", Pubkey: hex.EncodeToString(h.priv.Public().(ed25519.PublicKey))}
	if err := h.machines.EnrollMachine(context.Background(), h.tenant, h.machine); err != nil {
		t.Fatal(err)
	}
	h.sessions = NewInMemorySessionRecordStore()
	sr := &SessionRecord{TenantID: h.tenant, MachineID: h.machine.ID, TechnicianID: auditTechUser, StartedAt: time.Now()}
	if err := h.sessions.StartSession(context.Background(), h.tenant, sr); err != nil {
		t.Fatal(err)
	}
	h.session = sr.ID
	h.audit = NewInMemoryAuditStore()
	h.store = NewInMemoryRecordingStore()
	if !o.noPolicy {
		if err := h.store.SetPolicy(context.Background(), h.tenant, RecordingPolicy{RetentionDays: 30, MaxRecordingBytes: 1 << 30, QuotaBytes: 20 << 30}); err != nil {
			t.Fatal(err)
		}
	}
	h.dir = t.TempDir()
	var err error
	if h.files, err = OpenRecordingStorage(h.dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.files.Close() })
	if h.keys, err = NewRecordingKeyring(1, bytes.Repeat([]byte{5}, 32), nil); err != nil {
		t.Fatal(err)
	}
	cfg := o.cfg
	if cfg.IPRatePerSec == 0 {
		cfg.IPRatePerSec, cfg.IPBurst = 100000, 100000
	}
	if cfg.DeviceRatePerSec == 0 {
		cfg.DeviceRatePerSec, cfg.DeviceBurst = 100000, 100000
	}
	if cfg.FreeBytes == nil {
		cfg.FreeBytes = func() (uint64, error) { return 1 << 40, nil }
	}
	if cfg.FloorBytes == 0 {
		cfg.FloorBytes = 1 << 20
	}
	h.srv = &Server{Machines: h.machines, SessionRecords: h.sessions, Audit: h.audit, Auth: denyAllAuth{}}
	h.srv.Recording = RecordingWiring{Store: h.store, Files: h.files, Keys: h.keys, Audience: h.audience, Config: cfg}
	if o.wireUp != nil {
		o.wireUp(h)
	}
	h.ts = httptest.NewUnstartedServer(h.srv.Handler())
	if o.readTimeout > 0 {
		h.ts.Config.ReadTimeout = o.readTimeout
	}
	h.ts.Start()
	t.Cleanup(h.ts.Close)
	return h
}

// restart builds a second Server over the SAME store, volume and keys (a process restart).
func (h *recH) restart() *recH {
	h2 := *h
	h2.srv = &Server{Machines: h.machines, SessionRecords: h.sessions, Audit: h.audit, Auth: denyAllAuth{}}
	files, err := OpenRecordingStorage(h.dir)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { files.Close() })
	h2.files = files
	h2.srv.Recording = RecordingWiring{Store: h.store, Files: files, Keys: h.keys, Audience: h.audience, Config: h.srv.Recording.Config}
	h2.ts = httptest.NewServer(h2.srv.Handler())
	h.t.Cleanup(h2.ts.Close)
	return &h2
}

// call describes one signed request. Zero fields take sensible defaults; the *Override fields let a
// test sign one thing and send another.
type call struct {
	op       UploadOp
	rec      string
	seg      uint32
	offset   uint64
	gen      uint64
	body     []byte
	device   string
	tenant   string
	priv     ed25519.PrivateKey
	tsMs     int64 // 0 = now
	audience string
	path     string // signed AND requested path override
	// request-side tampering after signing
	mutate func(r *http.Request)
	// sign different facts than the ones sent
	signLen  *uint64
	signSHA  *[32]byte
	signOp   UploadOp
	signPath string
	// sendBody replaces the actual body bytes (the signature still covers `body`)
	sendBody []byte
	noSign   bool
}

func (h *recH) fields(c call) UploadSigFields {
	if c.gen == 0 {
		c.gen = 1
	}
	if c.device == "" {
		c.device = h.device
	}
	if c.tenant == "" {
		c.tenant = h.tenant
	}
	if c.audience == "" {
		c.audience = h.audience
	}
	tn, _ := recParseUUID(c.tenant)
	rc, _ := recParseUUID(c.rec)
	priv := c.priv
	if priv == nil {
		priv = h.priv
	}
	f := UploadSigFields{
		Audience: c.audience, Op: c.op, TenantID: tn, DeviceID: c.device,
		KeyFP: UploadKeyFingerprint(priv.Public().(ed25519.PublicKey)), RecordingID: rc,
		Generation: c.gen, Segment: c.seg, Offset: c.offset, BodyLen: uint64(len(c.body)),
		BodySHA256: sha256.Sum256(c.body),
	}
	if c.tsMs == 0 {
		f.TimestampMs = uint64(time.Now().UnixMilli())
	} else {
		f.TimestampMs = uint64(c.tsMs)
	}
	f.Path = c.urlPath()
	if c.signOp != 0 {
		f.Op = c.signOp
	}
	if c.signPath != "" {
		f.Path = c.signPath
	}
	if c.signLen != nil {
		f.BodyLen = *c.signLen
	}
	if c.signSHA != nil {
		f.BodySHA256 = *c.signSHA
	}
	return f
}

func (h *recH) request(c call) *http.Request {
	h.t.Helper()
	f := h.fields(c)
	priv := c.priv
	if priv == nil {
		priv = h.priv
	}
	method := map[UploadOp]string{UploadOpCreate: "POST", UploadOpPut: "PUT", UploadOpHead: "HEAD", UploadOpFinish: "POST"}[c.op]
	send := c.body
	if c.sendBody != nil {
		send = c.sendBody
	}
	var rd io.Reader
	if len(send) > 0 || c.op != UploadOpHead {
		rd = bytes.NewReader(send)
	}
	req, err := http.NewRequest(method, h.ts.URL+c.urlPath(), rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if rd != nil && len(send) == 0 {
		req.ContentLength = 0
	}
	req.Header.Set(HdrUploadDevice, c.deviceOr(h))
	req.Header.Set(HdrUploadTenant, recFormatUUID(f.TenantID))
	req.Header.Set(HdrUploadKeyFP, hex.EncodeToString(f.KeyFP[:]))
	req.Header.Set(HdrUploadRecording, c.rec)
	req.Header.Set(HdrUploadGen, strconv.FormatUint(f.Generation, 10))
	req.Header.Set(HdrUploadSegment, strconv.FormatUint(uint64(f.Segment), 10))
	req.Header.Set(HdrUploadOffset, strconv.FormatUint(f.Offset, 10))
	req.Header.Set(HdrUploadBodySHA, hex.EncodeToString(f.BodySHA256[:]))
	req.Header.Set(HdrUploadTimestamp, strconv.FormatUint(f.TimestampMs, 10))
	if !c.noSign {
		req.Header.Set(HdrUploadSignature, hex.EncodeToString(SignUpload(priv, f)))
	} else {
		req.Header.Set(HdrUploadSignature, hex.EncodeToString(make([]byte, 64)))
	}
	if c.mutate != nil {
		c.mutate(req)
	}
	return req
}

// urlPath is the path actually requested: canonical unless the test overrides it.
func (c call) urlPath() string {
	if c.path != "" {
		return c.path
	}
	return uploadCanonicalPath(c.op, c.rec, c.seg)
}

func (c call) deviceOr(h *recH) string {
	if c.device != "" {
		return c.device
	}
	return h.device
}

func (h *recH) do(c call) (int, map[string]any, http.Header) {
	h.t.Helper()
	resp, err := http.DefaultClient.Do(h.request(c))
	if err != nil {
		h.t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, resp.Header
}

func jnum(m map[string]any, k string) int64 {
	f, _ := m[k].(float64)
	return int64(f)
}

func jstr(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// ---- scenario helpers -------------------------------------------------------------------------

type recUpload struct {
	id     string
	lens   []int
	data   [][]byte
	digest []string
}

func newRecUpload(lens ...int) *recUpload {
	u := &recUpload{id: newUUID(), lens: lens}
	for _, n := range lens {
		d := randBytes(n)
		u.data = append(u.data, d)
		s := sha256.Sum256(d)
		u.digest = append(u.digest, hex.EncodeToString(s[:]))
	}
	return u
}

func (h *recH) createBodyFor(u *recUpload, session string, gen uint64) []byte {
	type seg struct {
		Index  int `json:"index"`
		Length int `json:"length"`
	}
	segs := make([]seg, len(u.lens))
	for i, n := range u.lens {
		segs[i] = seg{i, n}
	}
	b, _ := json.Marshal(map[string]any{"recording_id": u.id, "session_id": session, "generation": gen, "segments": segs})
	return b
}

func (h *recH) create(u *recUpload) (int, map[string]any) {
	h.t.Helper()
	st, m, _ := h.do(call{op: UploadOpCreate, rec: u.id, body: h.createBodyFor(u, h.session, 1)})
	return st, m
}

func (h *recH) mustCreate(u *recUpload) {
	h.t.Helper()
	if st, m := h.create(u); st != http.StatusCreated {
		h.t.Fatalf("create: %d %v", st, m)
	}
}

func chunkOf(data []byte, off int) []byte {
	end := off + RecChunkSize
	if end > len(data) {
		end = len(data)
	}
	return data[off:end]
}

func (h *recH) put(u *recUpload, seg int, off int) (int, map[string]any) {
	h.t.Helper()
	st, m, _ := h.do(call{op: UploadOpPut, rec: u.id, seg: uint32(seg), offset: uint64(off), body: chunkOf(u.data[seg], off)})
	return st, m
}

func (h *recH) putAll(u *recUpload) {
	h.t.Helper()
	for s := range u.data {
		for off := 0; off < len(u.data[s]); off += RecChunkSize {
			if st, m := h.put(u, s, off); st != http.StatusOK {
				h.t.Fatalf("put seg %d off %d: %d %v", s, off, st, m)
			}
		}
	}
}

func (h *recH) finishBody(u *recUpload, digests []string, truncated any, dropped int) []byte {
	b, _ := json.Marshal(map[string]any{"recording_id": u.id, "generation": 1, "digests": digests,
		"truncated": truncated, "dropped_frames": dropped})
	return b
}

func (h *recH) finish(u *recUpload) (int, map[string]any) {
	h.t.Helper()
	st, m, _ := h.do(call{op: UploadOpFinish, rec: u.id, body: h.finishBody(u, u.digest, nil, 0)})
	return st, m
}

func (h *recH) head(u *recUpload, seg int) (int, http.Header) {
	h.t.Helper()
	st, _, hd := h.do(call{op: UploadOpHead, rec: u.id, seg: uint32(seg)})
	return st, hd
}

func (h *recH) row(u *recUpload) *RecordingRow {
	h.t.Helper()
	r, err := h.store.GetRecording(context.Background(), h.tenant, u.id)
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

// readFinal decrypts a finished evidence segment from the volume.
func (h *recH) readFinal(r *RecordingRow, idx int) []byte {
	h.t.Helper()
	f, size, err := h.files.OpenFinal(r.TenantID, r.ID, uint32(idx), RepIVF)
	if err != nil {
		h.t.Fatalf("open final %d: %v", idx, err)
	}
	defer f.Close()
	meta, _ := recEnvMeta(r, idx, r.Segments[idx].DeclaredLen, RepIVF)
	rd, err := OpenEnvelope(f, size, h.keys, EnvelopeExpect{TenantID: meta.TenantID, RecordingID: meta.RecordingID, Segment: meta.Segment, Rep: RepIVF, Generation: meta.Generation}, false)
	if err != nil {
		h.t.Fatalf("open envelope %d: %v", idx, err)
	}
	var out bytes.Buffer
	if _, err := rd.WriteTo(&out); err != nil {
		h.t.Fatalf("decrypt %d: %v", idx, err)
	}
	return out.Bytes()
}

// ---- audit chain helpers ----------------------------------------------------------------------

type stopOpts struct {
	digests  []string
	trunc    any
	dropped  int
	frames   int
	unsigned bool
	signer   ed25519.PrivateKey
	session  string
	machine  string
}

func (h *recH) auditEvent(seq uint64, prev string, action json.RawMessage, session, machine string, signer ed25519.PrivateKey) AuditEvent {
	e := AuditEvent{
		ID: fmt.Sprintf("00000000-0000-0000-0000-%012d", seq+uint64(len(h.audit.ingest[h.tenant]))+1), Seq: seq,
		SessionID: session, TechnicianID: auditTechUser, MachineID: machine,
		OccurredAtUnixMs: int64(1000 + seq), Action: action, Outcome: defaultAuditOutcome, PrevHash: prev,
	}
	hash, err := recomputeHash(e)
	if err != nil {
		h.t.Fatalf("hash: %v", err)
	}
	e.Hash = hash
	if signer != nil {
		e.AgentPubkey = hex.EncodeToString(signer.Public().(ed25519.PublicKey))
		e.AgentSignature = hex.EncodeToString(ed25519.Sign(signer, agentAuditSigningBytes(hash)))
	}
	return e
}

// addStopEvent appends recording_started + recording_stopped to the session's chain.
func (h *recH) addStopEvent(o stopOpts) AuditEvent {
	h.t.Helper()
	session := o.session
	if session == "" {
		session = h.session
	}
	machine := o.machine
	if machine == "" {
		machine = h.machine.ID
	}
	signer := o.signer
	if signer == nil && !o.unsigned {
		signer = h.priv
	}
	started, _ := json.Marshal(map[string]any{"kind": "recording_started", "started_at_unix_ms": int64(1730000000000), "directory": `C:\rmt-agent\recordings\x`})
	frames := o.frames
	if frames == 0 {
		frames = 913
	}
	stopped, _ := json.Marshal(map[string]any{"kind": "recording_stopped", "frames": frames, "payload_bytes": 4211337,
		"truncated": o.trunc, "dropped_frames": o.dropped, "segment_sha256": o.digests, "directory": `C:\rmt-agent\recordings\x`})
	tail, err := h.audit.AuditTail(context.Background(), h.tenant, session)
	if err != nil {
		h.t.Fatal(err)
	}
	var evs []AuditEvent
	seq, prev := uint64(0), GenesisPrevHash
	if tail.Exists {
		seq, prev = tail.Seq+1, tail.Hash
	}
	e1 := h.auditEvent(seq, prev, started, session, machine, signer)
	e2 := h.auditEvent(seq+1, e1.Hash, stopped, session, machine, signer)
	evs = append(evs, e1, e2)
	if _, err := h.audit.AppendAudit(context.Background(), h.tenant, session, evs); err != nil {
		h.t.Fatalf("append audit: %v", err)
	}
	return e2
}
