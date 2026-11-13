package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const mib = RecChunkSize

// ---- the whole flow ---------------------------------------------------------------------------

func TestRecordingUploadHappyPath(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(2*mib+mib/2, 100)

	st, m := h.create(u)
	if st != http.StatusCreated || jstr(m, "state") != RecUploading || jnum(m, "chunk_size") != mib {
		t.Fatalf("create: %d %v", st, m)
	}
	if st, hd := h.head(u, 0); st != 200 || hd.Get("X-Rmt-Committed-Offset") != "0" || hd.Get("X-Rmt-State") != RecUploading {
		t.Fatalf("head before: %d %v", st, hd)
	}
	if st, m := h.put(u, 0, 0); st != 200 || jnum(m, "committed_offset") != mib {
		t.Fatalf("put 0: %d %v", st, m)
	}
	if _, hd := h.head(u, 0); hd.Get("X-Rmt-Committed-Offset") != "1048576" {
		t.Fatalf("head after first chunk: %v", hd)
	}
	h.putAll(u) // re-sends chunk 0 (exact re-send), then the rest
	st, m = h.finish(u)
	if st != 200 || jstr(m, "state") != RecEvidenceComplete || jstr(m, "provenance") != ProvNoStopEvent {
		t.Fatalf("finish: %d %v", st, m)
	}
	acked, _ := m["digests"].([]any)
	if len(acked) != 2 || acked[0] != u.digest[0] || acked[1] != u.digest[1] {
		t.Fatalf("ack does not bind the digest list: %v", m)
	}

	r := h.row(u)
	if r.State != RecEvidenceComplete || r.ExpiresAt == nil || !r.ExpiresAt.Equal(r.EvidenceCompleteAt.Add(30*24*time.Hour)) {
		t.Fatalf("row after finish: %+v", r)
	}
	for i := range u.data {
		if got := h.readFinal(r, i); !bytes.Equal(got, u.data[i]) {
			t.Fatalf("segment %d does not decrypt to what was uploaded", i)
		}
		raw, _ := os.ReadFile(filepath.Join(h.dir, r.TenantID, r.ID, segName(uint32(i), RepIVF)))
		if bytes.Contains(raw, u.data[i][:64]) {
			t.Fatalf("segment %d is stored in plaintext", i)
		}
	}
	if ents, _ := os.ReadDir(filepath.Join(h.dir, ".incoming")); len(ents) != 0 {
		t.Fatalf("incoming not cleaned up: %v", ents)
	}
	// Replays are idempotent: same ack for finish, 409 already_complete for create, 410-free HEAD.
	if st2, m2 := h.finish(u); st2 != 200 || jstr(m2, "provenance") != ProvNoStopEvent {
		t.Fatalf("finish replay: %d %v", st2, m2)
	}
	if st2, m2 := h.create(u); st2 != 409 || jstr(m2, "error") != "already_complete" {
		t.Fatalf("create after complete: %d %v", st2, m2)
	}
}

func TestRecordingUploadFinishHookRunsOnce(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	h := newRecH(t, recHOpts{wireUp: func(h *recH) {
		h.srv.Recording.OnEvidenceComplete = func(_ context.Context, tenant string, rec *RecordingRow) {
			mu.Lock()
			seen = append(seen, tenant+"/"+rec.ID+"/"+rec.State)
			mu.Unlock()
		}
	}})
	u := newRecUpload(100)
	h.mustCreate(u)
	h.putAll(u)
	h.finish(u)
	h.finish(u) // replay: the hook must not fire again
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != h.tenant+"/"+u.id+"/"+RecEvidenceComplete {
		t.Fatalf("hook calls = %v", seen)
	}
}

// ---- authentication ----------------------------------------------------------------------------

func TestRecordingUploadRefusesEveryTamperedField(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(mib + 10)
	h.mustCreate(u)
	good := call{op: UploadOpPut, rec: u.id, seg: 0, offset: 0, body: chunkOf(u.data[0], 0)}

	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	var otherSHA [32]byte
	otherSHA[0] = 1
	badLen := uint64(5)
	cases := []struct {
		name string
		c    func() call
		want []int
	}{
		{"signed by a different key", func() call { c := good; c.priv = other; return c }, []int{401}},
		{"no signature", func() call { c := good; c.noSign = true; return c }, []int{401}},
		{"signature bit flipped", func() call {
			c := good
			c.mutate = func(r *http.Request) {
				s := []byte(r.Header.Get(HdrUploadSignature))
				if s[0] == '0' {
					s[0] = '1'
				} else {
					s[0] = '0'
				}
				r.Header.Set(HdrUploadSignature, string(s))
			}
			return c
		}, []int{401}},
		{"audience", func() call { c := good; c.audience = "https://other.example.test"; return c }, []int{401}},
		{"device header", func() call {
			c := good
			c.mutate = func(r *http.Request) { r.Header.Set(HdrUploadDevice, "dev-someone-else") }
			return c
		}, []int{401}},
		{"tenant header", func() call {
			c := good
			c.mutate = func(r *http.Request) { r.Header.Set(HdrUploadTenant, newUUID()) }
			return c
		}, []int{401}},
		{"key fingerprint", func() call {
			c := good
			c.mutate = func(r *http.Request) { r.Header.Set(HdrUploadKeyFP, strings.Repeat("ab", 32)) }
			return c
		}, []int{401}},
		{"generation header", func() call { c := good; c.mutate = func(r *http.Request) { r.Header.Set(HdrUploadGen, "2") }; return c }, []int{401}},
		{"offset header", func() call {
			c := good
			c.mutate = func(r *http.Request) { r.Header.Set(HdrUploadOffset, "1048576") }
			return c
		}, []int{401}},
		{"body digest header", func() call {
			c := good
			c.mutate = func(r *http.Request) { r.Header.Set(HdrUploadBodySHA, strings.Repeat("00", 32)) }
			return c
		}, []int{401}},
		{"timestamp header", func() call {
			c := good
			c.mutate = func(r *http.Request) { r.Header.Set(HdrUploadTimestamp, "1790000000001") }
			return c
		}, []int{401}},
		{"recording header", func() call {
			c := good
			c.mutate = func(r *http.Request) { r.Header.Set(HdrUploadRecording, newUUID()) }
			return c
		}, []int{400}},
		{"segment header", func() call {
			c := good
			c.mutate = func(r *http.Request) { r.Header.Set(HdrUploadSegment, "1") }
			return c
		}, []int{400}},
		{"signed for a different body digest", func() call { c := good; c.signSHA = &otherSHA; return c }, []int{400}},
		{"signed for a different body length", func() call { c := good; c.signLen = &badLen; return c }, []int{401}},
		{"signed for another operation", func() call { c := good; c.signOp = UploadOpHead; return c }, []int{401}},
		{"signed for another path", func() call { c := good; c.signPath = "/agent/recordings/" + u.id + "/segments/1"; return c }, []int{401}},
		{"body differs from the signed digest", func() call {
			c := good
			b := append([]byte(nil), c.body...)
			b[0] ^= 1
			c.sendBody = b
			return c
		}, []int{400}},
		{"query string", func() call { c := good; c.mutate = func(r *http.Request) { r.URL.RawQuery = "offset=0" }; return c }, []int{400}},
		{"duplicate signed header", func() call {
			c := good
			c.mutate = func(r *http.Request) { r.Header.Add(HdrUploadOffset, "0") }
			return c
		}, []int{400}},
		{"upper-case recording id", func() call {
			c := good
			c.mutate = func(r *http.Request) {
				r.Header.Set(HdrUploadRecording, strings.ToUpper(u.id))
				r.URL.Path = strings.ToUpper(r.URL.Path)
			}
			return c
		}, []int{401}}, // not an upload route at all: it falls through to the authenticated chain
	}
	for _, tc := range cases {
		st, m, _ := h.do(tc.c())
		ok := false
		for _, w := range tc.want {
			ok = ok || st == w
		}
		if !ok {
			t.Errorf("%s: status %d %v, want one of %v", tc.name, st, m, tc.want)
		}
	}
	// Nothing was committed by any of them.
	if r := h.row(u); r.Segments[0].CommittedOffset != 0 {
		t.Fatalf("a refused request moved the committed offset to %d", r.Segments[0].CommittedOffset)
	}
	if _, err := os.Stat(filepath.Join(h.dir, ".incoming", h.row(u).UploadID)); !os.IsNotExist(err) {
		t.Fatalf("a refused request left bytes on disk: %v", err)
	}
	// And the genuine request still works.
	if st, m, _ := h.do(good); st != 200 {
		t.Fatalf("good request after the refusals: %d %v", st, m)
	}
}

func TestRecordingUploadTimestampWindow(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(100)
	h.mustCreate(u)
	now := time.Now().UnixMilli()
	for _, tc := range []struct {
		name string
		d    int64
		want int
	}{
		{"now", 0, 200}, {"4m55s ahead", 295_000, 200}, {"4m55s behind", -295_000, 200},
		{"5m10s ahead", 310_000, 401}, {"5m10s behind", -310_000, 401}, {"an hour old", -3_600_000, 401},
	} {
		st, _, _ := h.do(call{op: UploadOpHead, rec: u.id, tsMs: now + tc.d})
		if st != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, st, tc.want)
		}
	}
}

func (h *recH) enroll(tenant string, seed byte) (device string, priv ed25519.PrivateKey, m *Machine) {
	h.t.Helper()
	priv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	device = "dev-extra-" + newUUID()[:8]
	m = &Machine{DeviceID: device, GroupID: newUUID(), Name: "x", Pubkey: hex.EncodeToString(priv.Public().(ed25519.PublicKey))}
	if err := h.machines.EnrollMachine(context.Background(), tenant, m); err != nil {
		h.t.Fatal(err)
	}
	return
}

func TestRecordingUploadIsBoundToTheSigningDeviceAndTenant(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(100)
	h.mustCreate(u)

	// A second device of the SAME tenant, with its own key, cannot touch the first one's recording.
	dev2, key2, _ := h.enroll(h.tenant, 11)
	for _, c := range []call{
		{op: UploadOpHead, rec: u.id, device: dev2, priv: key2},
		{op: UploadOpPut, rec: u.id, device: dev2, priv: key2, body: u.data[0]},
		{op: UploadOpFinish, rec: u.id, device: dev2, priv: key2, body: h.finishBody(u, u.digest, nil, 0)},
	} {
		if st, m, _ := h.do(c); st != http.StatusForbidden {
			t.Errorf("op %d by another device of the tenant: %d %v, want 403", c.op, st, m)
		}
	}
	// A device of ANOTHER tenant: its recording namespace is its own tenant's, so the id is unknown, and
	// naming the first tenant's session is a 404 (RLS in production; the tenant key in the fake).
	tenantB := newUUID()
	devB, keyB, _ := h.enroll(tenantB, 12)
	if st, m, _ := h.do(call{op: UploadOpHead, rec: u.id, device: devB, priv: keyB, tenant: tenantB}); st != 404 {
		t.Errorf("other tenant's HEAD: %d %v, want 404", st, m)
	}
	cb := newRecUpload(10)
	if st, m, _ := h.do(call{op: UploadOpCreate, rec: cb.id, device: devB, priv: keyB, tenant: tenantB, body: h.createBodyFor(cb, h.session, 1)}); st != 404 {
		t.Errorf("other tenant created a recording naming this tenant's session: %d %v, want 404", st, m)
	}
	// A device cannot sign for a tenant it does not belong to.
	if st, _, _ := h.do(call{op: UploadOpHead, rec: u.id, device: devB, priv: keyB, tenant: h.tenant}); st != 401 {
		t.Errorf("device of tenant B claiming tenant A: %d, want 401", st)
	}
	// An unknown device is indistinguishable from a bad signature.
	if st, _, _ := h.do(call{op: UploadOpHead, rec: u.id, device: "dev-nobody", priv: key2}); st != 401 {
		t.Errorf("unknown device: %d, want 401", st)
	}
	// The recording itself is untouched.
	if r := h.row(u); r.State != RecUploading || r.Segments[0].CommittedOffset != 0 {
		t.Fatalf("recording changed: %+v", r)
	}
}

func TestRecordingUploadRefusesNonActiveMachines(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(100)
	h.mustCreate(u)
	for _, status := range []string{MachineStatusQuarantined, MachineStatusRetired} {
		if err := h.machines.SetMachineStatus(context.Background(), h.tenant, h.machine.ID, status); err != nil {
			t.Fatal(err)
		}
		if st, _, _ := h.do(call{op: UploadOpHead, rec: u.id}); st != 403 { // a HEAD answer has no body
			t.Errorf("%s machine: %d, want 403", status, st)
		}
		if st, m, _ := h.do(call{op: UploadOpPut, rec: u.id, body: u.data[0]}); st != 403 || jstr(m, "error") != "machine_not_active" {
			t.Errorf("%s machine PUT: %d %v, want 403 machine_not_active", status, st, m)
		}
	}
	if err := h.machines.SetMachineStatus(context.Background(), h.tenant, h.machine.ID, MachineStatusActive); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := h.do(call{op: UploadOpHead, rec: u.id}); st != 200 {
		t.Errorf("reactivated machine: %d", st)
	}
}

func TestRecordingUploadRefusesAttendedEphemeralMachines(t *testing.T) {
	h := newRecH(t, recHOpts{})
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32))
	exp := time.Now().Add(time.Hour)
	if err := h.machines.enrollEphemeral(h.tenant, "dev-attended", newUUID(), "guest", hex.EncodeToString(priv.Public().(ed25519.PublicKey)), exp); err != nil {
		t.Fatal(err)
	}
	if st, m, _ := h.do(call{op: UploadOpHead, rec: newUUID(), device: "dev-attended", priv: priv}); st != 401 {
		t.Errorf("attended guest machine: %d %v, want 401", st, m)
	}
}

func TestRecordingUploadRefusesUnknownLengthBodies(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(100)
	h.mustCreate(u)
	req := h.request(call{op: UploadOpPut, rec: u.id, body: u.data[0]})
	req.ContentLength = -1 // chunked: the length cannot be bound to the signature before it is read
	req.Body = nopCloser{bytes.NewReader(u.data[0])}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusLengthRequired {
		t.Fatalf("chunked body: %d, want 411", resp.StatusCode)
	}
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

// ---- create -----------------------------------------------------------------------------------

func TestRecordingUploadCreateRules(t *testing.T) {
	t.Run("storage off", func(t *testing.T) {
		h := newRecH(t, recHOpts{noPolicy: true})
		st, m := h.create(newRecUpload(100))
		if st != 403 || jstr(m, "error") != "storage_off" {
			t.Fatalf("%d %v", st, m)
		}
		// Turned on, it works; turned off again, new creates stop but a replay of an existing one works.
		h.store.SetPolicy(context.Background(), h.tenant, RecordingPolicy{RetentionDays: 30, MaxRecordingBytes: mib, QuotaBytes: 1 << 30})
		u := newRecUpload(100)
		h.mustCreate(u)
		h.store.SetPolicy(context.Background(), h.tenant, RecordingPolicy{RetentionDays: 0, MaxRecordingBytes: mib, QuotaBytes: 1 << 30})
		if st, m := h.create(u); st != 200 {
			t.Fatalf("replay after off: %d %v", st, m)
		}
		if st, m := h.create(newRecUpload(100)); st != 403 {
			t.Fatalf("new create after off: %d %v", st, m)
		}
	})
	t.Run("per-recording cap and tenant quota", func(t *testing.T) {
		h := newRecH(t, recHOpts{})
		one := RecordingReservation([]int64{mib})
		h.store.SetPolicy(context.Background(), h.tenant, RecordingPolicy{RetentionDays: 30, MaxRecordingBytes: mib, QuotaBytes: one + one/2})
		if st, m := h.create(newRecUpload(mib + 1)); st != 413 || jstr(m, "error") != "too_large" {
			t.Fatalf("over the cap: %d %v", st, m)
		}
		h.mustCreate(newRecUpload(mib))
		if st, m := h.create(newRecUpload(mib)); st != 507 || jstr(m, "error") != "tenant_quota" {
			t.Fatalf("over quota: %d %v", st, m)
		}
	})
	t.Run("server disk floor, unmeasurable disk", func(t *testing.T) {
		free := uint64(1 << 40)
		var mu sync.Mutex
		var freeErr error
		h := newRecH(t, recHOpts{cfg: RecordingUploadConfig{FloorBytes: 100 << 20, FreeBytes: func() (uint64, error) {
			mu.Lock()
			defer mu.Unlock()
			return free, freeErr
		}}})
		res := uint64(RecordingReservation([]int64{1000}))
		mu.Lock()
		free = res + 100<<20 - 1
		mu.Unlock()
		u := newRecUpload(1000)
		st2, m2, hd2 := h.do(call{op: UploadOpCreate, rec: u.id, body: h.createBodyFor(u, h.session, 1)})
		if st2 != 507 || jstr(m2, "error") != "server_full" || hd2.Get("Retry-After") == "" {
			t.Fatalf("below the floor: %d %v %v", st2, m2, hd2)
		}
		mu.Lock()
		free = res + 100<<20
		mu.Unlock()
		if st, m := h.create(u); st != 201 {
			t.Fatalf("exactly at the floor: %d %v", st, m)
		}
		mu.Lock()
		freeErr = errors.New("statfs failed")
		mu.Unlock()
		if st, m := h.create(newRecUpload(1000)); st != 507 {
			t.Fatalf("unmeasurable disk must refuse: %d %v", st, m)
		}
	})
	t.Run("idempotent, conflict, tombstone, already complete", func(t *testing.T) {
		h := newRecH(t, recHOpts{})
		u := newRecUpload(100, 200)
		h.mustCreate(u)
		if st, m := h.create(u); st != 200 || jstr(m, "state") != RecUploading {
			t.Fatalf("replay: %d %v", st, m)
		}
		other := &recUpload{id: u.id, lens: []int{100, 201}}
		if st, m := h.create(other); st != 409 || jstr(m, "error") != "conflict" {
			t.Fatalf("changed lengths: %d %v", st, m)
		}
		if st, m, _ := h.do(call{op: UploadOpCreate, rec: u.id, gen: 2, body: h.createBodyFor(u, h.session, 2)}); st != 409 {
			t.Fatalf("changed generation: %d %v", st, m)
		}
		if err := h.store.AbandonRecording(context.Background(), h.tenant, u.id); err != nil {
			t.Fatal(err)
		}
		if st, m := h.create(u); st != 410 || jstr(m, "error") != "gone" {
			t.Fatalf("create of an abandoned id: %d %v", st, m)
		}
		if st, _ := h.put(u, 0, 0); st != 410 {
			t.Fatalf("PUT to an abandoned recording: %d, want 410", st)
		}
	})
	t.Run("the session must exist, be on the signing machine", func(t *testing.T) {
		h := newRecH(t, recHOpts{})
		u := newRecUpload(100)
		if st, m, _ := h.do(call{op: UploadOpCreate, rec: u.id, body: h.createBodyFor(u, newUUID(), 1)}); st != 404 || jstr(m, "error") != "session_unknown" {
			t.Fatalf("unknown session: %d %v", st, m)
		}
		_, _, m2 := h.enroll(h.tenant, 13)
		sr := &SessionRecord{TenantID: h.tenant, MachineID: m2.ID, TechnicianID: auditTechUser, StartedAt: time.Now()}
		if err := h.sessions.StartSession(context.Background(), h.tenant, sr); err != nil {
			t.Fatal(err)
		}
		if st, m, _ := h.do(call{op: UploadOpCreate, rec: u.id, body: h.createBodyFor(u, sr.ID, 1)}); st != 403 || jstr(m, "error") != "session_not_on_this_machine" {
			t.Fatalf("another machine's session: %d %v", st, m)
		}
		if _, err := h.store.GetRecording(context.Background(), h.tenant, u.id); err == nil {
			t.Fatal("a refused create left a row")
		}
	})
	t.Run("malformed bodies", func(t *testing.T) {
		h := newRecH(t, recHOpts{})
		id := newUUID()
		ok := func(extra string) []byte {
			return []byte(`{"recording_id":"` + id + `","session_id":"` + h.session + `","generation":1,"segments":[{"index":0,"length":10}]` + extra + `}`)
		}
		many := `{"recording_id":"` + id + `","session_id":"` + h.session + `","generation":1,"segments":[`
		for i := 0; i < RecMaxSegments+1; i++ {
			if i > 0 {
				many += ","
			}
			many += `{"index":` + itoa(i) + `,"length":1}`
		}
		many += `]}`
		bodies := map[string][]byte{
			"unknown field":     ok(`,"extra":1`),
			"zero length":       []byte(strings.Replace(string(ok("")), `"length":10`, `"length":0`, 1)),
			"huge length":       []byte(strings.Replace(string(ok("")), `"length":10`, `"length":2147483648`, 1)),
			"index gap":         []byte(strings.Replace(string(ok("")), `"index":0`, `"index":1`, 1)),
			"no segments":       []byte(strings.Replace(string(ok("")), `[{"index":0,"length":10}]`, `[]`, 1)),
			"too many segments": []byte(many),
			"recording id swap": []byte(strings.Replace(string(ok("")), id, newUUID(), 1)),
			"bad session":       []byte(strings.Replace(string(ok("")), h.session, "not-a-uuid", 1)),
			"not json":          []byte(`recording`),
			"trailing":          append(ok(""), []byte(`{}`)...),
			"generation swap":   []byte(strings.Replace(string(ok("")), `"generation":1`, `"generation":9`, 1)),
		}
		for name, b := range bodies {
			if st, m, _ := h.do(call{op: UploadOpCreate, rec: id, body: b}); st != 400 {
				t.Errorf("%s: %d %v, want 400", name, st, m)
			}
		}
		if st, m, _ := h.do(call{op: UploadOpCreate, rec: id, body: ok("")}); st != 201 {
			t.Fatalf("well-formed body: %d %v", st, m)
		}
	})
}

// ---- put --------------------------------------------------------------------------------------

func (h *recH) incomingPath(u *recUpload, seg int) string {
	return filepath.Join(h.dir, ".incoming", h.row(u).UploadID, segName(uint32(seg), RepIVF))
}

func TestRecordingUploadPutRules(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(3*mib, 50)
	h.mustCreate(u)

	if st, m := h.put(u, 0, mib); st != 409 || jstr(m, "error") != "bad_offset" || jnum(m, "committed_offset") != 0 {
		t.Fatalf("gap: %d %v", st, m)
	}
	if st, m, _ := h.do(call{op: UploadOpPut, rec: u.id, offset: 5, body: chunkOf(u.data[0], 0)}); st != 409 {
		t.Fatalf("unaligned offset: %d %v", st, m)
	}
	if st, m, _ := h.do(call{op: UploadOpPut, rec: u.id, offset: 0, body: chunkOf(u.data[0], 0)[:mib/2]}); st != 400 || jstr(m, "error") != "bad_chunk_length" {
		t.Fatalf("short chunk: %d %v", st, m)
	}
	if st, m, _ := h.do(call{op: UploadOpPut, rec: u.id, seg: 9, body: u.data[1]}); st != 404 {
		t.Fatalf("no such segment: %d %v", st, m)
	}
	if st, m, _ := h.do(call{op: UploadOpPut, rec: u.id, gen: 2, body: chunkOf(u.data[0], 0)}); st != 409 || jstr(m, "error") != "generation_mismatch" {
		t.Fatalf("generation: %d %v", st, m)
	}
	if st, m, _ := h.do(call{op: UploadOpPut, rec: newUUID(), body: u.data[1]}); st != 404 {
		t.Fatalf("unknown recording: %d %v", st, m)
	}

	if st, m := h.put(u, 0, 0); st != 200 || jnum(m, "committed_offset") != mib {
		t.Fatalf("chunk 0: %d %v", st, m)
	}
	before, _ := os.ReadFile(h.incomingPath(u, 0))
	// An exact re-send is a no-op: 200, resent, the file byte-for-byte unchanged, offset unchanged.
	if st, m := h.put(u, 0, 0); st != 200 || m["resent"] != true || jnum(m, "committed_offset") != mib {
		t.Fatalf("exact re-send: %d %v", st, m)
	}
	after, _ := os.ReadFile(h.incomingPath(u, 0))
	if !bytes.Equal(before, after) {
		t.Fatal("an exact re-send rewrote the stored bytes")
	}
	// A DIFFERENT chunk at an already-committed offset is refused and changes nothing.
	evil := append([]byte(nil), chunkOf(u.data[0], 0)...)
	evil[17] ^= 0xff
	if st, m, _ := h.do(call{op: UploadOpPut, rec: u.id, offset: 0, body: evil}); st != 409 || jstr(m, "error") != "chunk_conflict" {
		t.Fatalf("different bytes at a committed offset: %d %v", st, m)
	}
	if c, _ := os.ReadFile(h.incomingPath(u, 0)); !bytes.Equal(c, before) {
		t.Fatal("a conflicting chunk altered committed bytes")
	}
	// Past-the-end offset.
	if st, m, _ := h.do(call{op: UploadOpPut, rec: u.id, seg: 1, offset: 50, body: nil}); st != 409 && st != 400 {
		t.Fatalf("offset at the declared length: %d %v", st, m)
	}
	h.putAll(u)
	if st, m := h.finish(u); st != 200 {
		t.Fatalf("finish: %d %v", st, m)
	}
	// After completion: an exact re-send is acknowledged, anything else is refused.
	if st, m := h.put(u, 0, 0); st != 200 || m["resent"] != true {
		t.Fatalf("re-send after completion: %d %v", st, m)
	}
	if st, m, _ := h.do(call{op: UploadOpPut, rec: u.id, offset: 0, body: evil}); st != 409 || jstr(m, "error") != "already_complete" {
		t.Fatalf("different bytes after completion: %d %v", st, m)
	}
	if got := h.readFinal(h.row(u), 0); !bytes.Equal(got, u.data[0]) {
		t.Fatal("evidence changed after the refused writes")
	}
}

func TestRecordingUploadResumeAfterRestartRestartsSegmentUnderFreshNonces(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(4*mib, 100)
	h.mustCreate(u)
	h.put(u, 0, 0)
	h.put(u, 0, mib)

	// A crash between the fsync and the database commit leaves bytes beyond the acknowledged offset:
	// simulate it by appending a third chunk's frames to the file without telling the database.
	f, err := os.OpenFile(h.incomingPath(u, 0), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	r := h.row(u)
	meta, _ := recEnvMeta(r, 0, r.Segments[0].DeclaredLen, RepIVF)
	ew, err := ResumeEnvelope(f, h.keys, r.Key(), meta, 2*mib)
	if err != nil {
		t.Fatal(err)
	}
	ew.Write(bytes.Repeat([]byte{0xEE}, mib)) // garbage "third chunk", never acknowledged
	f.Close()
	oldHdr, _ := os.ReadFile(h.incomingPath(u, 0))
	oldH, _, _ := readEnvHeader(bytes.NewReader(oldHdr))

	// "Restart": new Server, new storage handle, same database.
	h2 := h.restart()
	if st, hd := h2.head(u, 0); st != 200 || hd.Get("X-Rmt-Committed-Offset") != "2097152" {
		t.Fatalf("head after restart: %d %v", st, hd)
	}
	// The agent re-sends from the acknowledged offset; the file now carries unacknowledged frames, and
	// re-sealing those indexes under the same nonce prefix would reuse nonces, so the server restarts the
	// segment: bad_offset 0, then the whole segment goes in under a fresh prefix.
	if st, m := h2.put(u, 0, 2*mib); st != 409 || jnum(m, "committed_offset") != 0 {
		t.Fatalf("resume over an unacknowledged tail: %d %v", st, m)
	}
	h2.putAll(u)
	newImg, _ := os.ReadFile(h2.incomingPath(u, 0))
	if newH, _, err := readEnvHeader(bytes.NewReader(newImg)); err != nil || newH.NoncePrefix == oldH.NoncePrefix {
		t.Fatalf("the restarted segment reused the nonce prefix (err %v)", err)
	}
	if st, m := h2.finish(u); st != 200 {
		t.Fatalf("finish after restart: %d %v", st, m)
	}
	if got := h2.readFinal(h2.row(u), 0); !bytes.Equal(got, u.data[0]) {
		t.Fatal("the unacknowledged tail survived into the evidence copy")
	}
}

func TestRecordingUploadStorageLostForgetsAcknowledgedBytes(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(3*mib, 100)
	h.mustCreate(u)
	h.put(u, 0, 0)
	if err := os.Remove(h.incomingPath(u, 0)); err != nil {
		t.Fatal(err)
	}
	// The database says 1 MiB is committed; the volume says otherwise. The next chunk must not be
	// appended to nothing: the server resets the segment and tells the agent where to restart.
	st, m := h.put(u, 0, mib)
	if st != 409 || jnum(m, "committed_offset") != 0 {
		t.Fatalf("append to a lost file: %d %v", st, m)
	}
	if h.row(u).Segments[0].CommittedOffset != 0 {
		t.Fatal("the lost bytes are still acknowledged")
	}
	if h.row(u).FinishFailures != 0 {
		t.Fatal("a lost file was counted as a finish failure")
	}
	h.putAll(u)
	if st, m := h.finish(u); st != 200 {
		t.Fatalf("finish after re-upload: %d %v", st, m)
	}
}

func TestRecordingReconcileUploadsTruncatesAndResets(t *testing.T) {
	h := newRecH(t, recHOpts{})
	keep := newRecUpload(3*mib, 100)
	lost := newRecUpload(2*mib, 100)
	h.mustCreate(keep)
	h.mustCreate(lost)
	h.put(keep, 0, 0)
	h.put(lost, 0, 0)
	// keep: unacknowledged garbage past the committed frames; lost: file gone.
	f, _ := os.OpenFile(h.incomingPath(keep, 0), os.O_RDWR, 0o600)
	st, _ := f.Stat()
	f.WriteAt(bytes.Repeat([]byte{9}, 5000), st.Size())
	f.Close()
	os.Remove(h.incomingPath(lost, 0))

	checked, reset, err := h.srv.Recording.ReconcileUploads(context.Background())
	if err != nil || checked != 2 || reset != 2 {
		t.Fatalf("reconcile: checked=%d reset=%d err=%v", checked, reset, err)
	}
	// The unacknowledged tail is never truncated-and-overwritten (nonce reuse): the segment restarts at 0.
	if fi, _ := os.Stat(h.incomingPath(keep, 0)); fi.Size() <= st.Size() {
		t.Fatalf("reconcile truncated the incoming file: %d", fi.Size())
	}
	if h.row(keep).Segments[0].CommittedOffset != 0 || h.row(lost).Segments[0].CommittedOffset != 0 {
		t.Fatalf("offsets after reconcile: keep=%d lost=%d", h.row(keep).Segments[0].CommittedOffset, h.row(lost).Segments[0].CommittedOffset)
	}
	// A clean segment (no tail) keeps its acknowledged bytes.
	clean := newRecUpload(3*mib, 100)
	h.mustCreate(clean)
	h.put(clean, 0, 0)
	if checked, reset, err := h.srv.Recording.ReconcileUploads(context.Background()); err != nil || reset != 0 {
		t.Fatalf("clean reconcile: %d %d %v", checked, reset, err)
	}
	if h.row(clean).Segments[0].CommittedOffset != mib {
		t.Fatal("a clean segment lost its acknowledged bytes")
	}
}

// ---- finish and provenance -------------------------------------------------------------------

func TestRecordingUploadFinishRules(t *testing.T) {
	t.Run("incomplete", func(t *testing.T) {
		h := newRecH(t, recHOpts{})
		u := newRecUpload(2*mib, 100)
		h.mustCreate(u)
		h.put(u, 0, 0)
		st, m := h.finish(u)
		segs, _ := m["segments"].([]any)
		if st != 409 || jstr(m, "error") != "incomplete" || len(segs) != 2 {
			t.Fatalf("%d %v", st, m)
		}
		if h.row(u).State != RecUploading {
			t.Fatal("state changed")
		}
	})
	t.Run("digest mismatch resets the segment and the third failure refuses", func(t *testing.T) {
		h := newRecH(t, recHOpts{})
		u := newRecUpload(mib+5, 100)
		h.mustCreate(u)
		h.putAll(u)
		wrong := append([]string(nil), u.digest...)
		wrong[1] = strings.Repeat("0", 64)
		for i := 1; i <= RecMaxFinishFailures; i++ {
			st, m, _ := h.do(call{op: UploadOpFinish, rec: u.id, body: h.finishBody(u, wrong, nil, 0)})
			if i < RecMaxFinishFailures {
				if st != 422 || jstr(m, "error") != "digest_mismatch" {
					t.Fatalf("attempt %d: %d %v", i, st, m)
				}
				if r := h.row(u); r.Segments[1].CommittedOffset != 0 || r.Segments[0].CommittedOffset != r.Segments[0].DeclaredLen || r.State != RecUploading {
					t.Fatalf("attempt %d did not reset exactly the mismatching segment: %+v", i, r.Segments)
				}
				h.putAll(u) // the agent re-sends it
			} else if st != 422 || jstr(m, "state") != RecRefused {
				t.Fatalf("third failure: %d %v", st, m)
			}
		}
		if h.row(u).State != RecRefused {
			t.Fatalf("state %s, want refused", h.row(u).State)
		}
		if ents, _ := os.ReadDir(filepath.Join(h.dir, ".incoming")); len(ents) != 0 {
			t.Fatalf("a refused upload left its bytes: %v", ents)
		}
		if st, _ := h.create(u); st != 410 {
			t.Fatalf("create after refusal: %d", st)
		}
	})
	t.Run("corrupt bytes on disk fail the digest, never complete", func(t *testing.T) {
		h := newRecH(t, recHOpts{})
		u := newRecUpload(mib, 100)
		h.mustCreate(u)
		h.putAll(u)
		p := h.incomingPath(u, 0)
		b, _ := os.ReadFile(p)
		b[len(b)-40] ^= 0xff // inside the last frame
		os.WriteFile(p, b, 0o600)
		st, m := h.finish(u)
		if st != 422 || h.row(u).State != RecUploading {
			t.Fatalf("%d %v state=%s", st, m, h.row(u).State)
		}
	})
	t.Run("replay, conflicting replay, bad bodies", func(t *testing.T) {
		h := newRecH(t, recHOpts{})
		u := newRecUpload(100)
		h.mustCreate(u)
		h.putAll(u)
		if st, m := h.finish(u); st != 200 {
			t.Fatalf("%d %v", st, m)
		}
		bad := []string{strings.Repeat("1", 64)}
		if st, m, _ := h.do(call{op: UploadOpFinish, rec: u.id, body: h.finishBody(u, bad, nil, 0)}); st != 409 {
			t.Fatalf("conflicting replay: %d %v", st, m)
		}
		if st, m, _ := h.do(call{op: UploadOpFinish, rec: u.id, body: h.finishBody(u, u.digest, "size_limit", 0)}); st != 409 {
			t.Fatalf("replay with different truncation: %d %v", st, m)
		}
		for name, b := range map[string][]byte{
			"missing dropped_frames": []byte(`{"recording_id":"` + u.id + `","generation":1,"digests":["` + u.digest[0] + `"]}`),
			"non-hex digest":         h.finishBody(u, []string{strings.Repeat("g", 64)}, nil, 0),
			"upper-case digest":      h.finishBody(u, []string{strings.ToUpper(u.digest[0])}, nil, 0),
			"no digests":             h.finishBody(u, nil, nil, 0),
			"empty truncated":        h.finishBody(u, u.digest, "", 0),
			"unknown field":          []byte(`{"recording_id":"` + u.id + `","generation":1,"digests":["` + u.digest[0] + `"],"dropped_frames":0,"x":1}`),
		} {
			if st, m, _ := h.do(call{op: UploadOpFinish, rec: u.id, body: b}); st != 400 {
				t.Errorf("%s: %d %v, want 400", name, st, m)
			}
		}
	})
}

type failingAudit struct {
	AuditStore
	err error
}

func (f *failingAudit) ListAuditEventsAsc(ctx context.Context, tenantID string, q AuditExportQuery) ([]AuditEvent, int64, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	return f.AuditStore.ListAuditEventsAsc(ctx, tenantID, q)
}

func TestRecordingProvenance(t *testing.T) {
	run := func(t *testing.T, setup func(h *recH, u *recUpload), finish func(h *recH, u *recUpload) (int, map[string]any)) (*recH, *recUpload, int, map[string]any) {
		h := newRecH(t, recHOpts{})
		u := newRecUpload(mib/2, 100)
		h.mustCreate(u)
		h.putAll(u)
		setup(h, u)
		st, m := finish(h, u)
		return h, u, st, m
	}
	plain := func(h *recH, u *recUpload) (int, map[string]any) { return h.finish(u) }

	t.Run("a signed matching stop event labels it matches_session_audit", func(t *testing.T) {
		var seq uint64
		h, u, st, m := run(t, func(h *recH, u *recUpload) { seq = h.addStopEvent(stopOpts{digests: u.digest}).Seq }, plain)
		if st != 200 || jstr(m, "provenance") != ProvMatchesAudit {
			t.Fatalf("%d %v", st, m)
		}
		if r := h.row(u); r.MatchedAuditSeq == nil || uint64(*r.MatchedAuditSeq) != seq || r.Provenance != ProvMatchesAudit {
			t.Fatalf("row: %+v", r)
		}
	})
	t.Run("no stop event: the weaker label, never 'verified'", func(t *testing.T) {
		_, _, st, m := run(t, func(*recH, *recUpload) {}, plain)
		if st != 200 || jstr(m, "provenance") != ProvNoStopEvent {
			t.Fatalf("%d %v", st, m)
		}
	})
	t.Run("a stop event for a different recording does not match and does not conflict", func(t *testing.T) {
		_, _, st, m := run(t, func(h *recH, u *recUpload) {
			h.addStopEvent(stopOpts{digests: []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}})
		}, plain)
		if st != 200 || jstr(m, "provenance") != ProvNoStopEvent {
			t.Fatalf("%d %v", st, m)
		}
	})
	t.Run("matching digests but different truncation is a conflict: refused, not relabelled", func(t *testing.T) {
		h, u, st, m := run(t, func(h *recH, u *recUpload) { h.addStopEvent(stopOpts{digests: u.digest, trunc: "size_limit"}) }, plain)
		if st != 409 || jstr(m, "error") != "audit_conflict" {
			t.Fatalf("%d %v", st, m)
		}
		if h.row(u).State != RecRefused {
			t.Fatalf("state %s, want refused", h.row(u).State)
		}
		if _, err := os.Stat(filepath.Join(h.dir, h.tenant, u.id)); !os.IsNotExist(err) {
			t.Fatal("a refused recording was promoted to the evidence store")
		}
		if ents, _ := os.ReadDir(filepath.Join(h.dir, ".incoming")); len(ents) != 0 {
			t.Fatalf("incoming not removed: %v", ents)
		}
	})
	t.Run("different dropped-frame count is a conflict", func(t *testing.T) {
		_, _, st, m := run(t, func(h *recH, u *recUpload) { h.addStopEvent(stopOpts{digests: u.digest, dropped: 4}) }, plain)
		if st != 409 || jstr(m, "error") != "audit_conflict" {
			t.Fatalf("%d %v", st, m)
		}
	})
	t.Run("different frame count is a conflict when the finish states one", func(t *testing.T) {
		_, _, st, m := run(t, func(h *recH, u *recUpload) { h.addStopEvent(stopOpts{digests: u.digest, frames: 5}) }, func(h *recH, u *recUpload) (int, map[string]any) {
			b := []byte(`{"recording_id":"` + u.id + `","generation":1,"digests":["` + u.digest[0] + `","` + u.digest[1] + `"],"truncated":null,"dropped_frames":0,"frames":913}`)
			st, m, _ := h.do(call{op: UploadOpFinish, rec: u.id, body: b})
			return st, m
		})
		if st != 409 || jstr(m, "error") != "audit_conflict" {
			t.Fatalf("%d %v", st, m)
		}
	})
	t.Run("a stop event that shares a digest but not the whole list is a conflict", func(t *testing.T) {
		_, _, st, m := run(t, func(h *recH, u *recUpload) {
			h.addStopEvent(stopOpts{digests: []string{u.digest[0], strings.Repeat("c", 64)}})
		}, plain)
		if st != 409 || jstr(m, "error") != "audit_conflict" {
			t.Fatalf("%d %v", st, m)
		}
	})
	t.Run("the same digests in another order are a conflict", func(t *testing.T) {
		_, _, st, m := run(t, func(h *recH, u *recUpload) { h.addStopEvent(stopOpts{digests: []string{u.digest[1], u.digest[0]}}) }, plain)
		if st != 409 {
			t.Fatalf("%d %v", st, m)
		}
	})
	t.Run("unsigned, foreign-key and foreign-machine events are ignored (they can neither match nor block)", func(t *testing.T) {
		other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, 32))
		for name, o := range map[string]stopOpts{
			"unsigned":        {unsigned: true},
			"signed by other": {signer: other},
			"other machine":   {machine: newUUID()},
		} {
			o := o
			_, _, st, m := run(t, func(h *recH, u *recUpload) {
				o.digests, o.trunc = u.digest, "size_limit" // would CONFLICT if it counted
				h.addStopEvent(o)
			}, plain)
			if st != 200 || jstr(m, "provenance") != ProvNoStopEvent {
				t.Errorf("%s: %d %v", name, st, m)
			}
		}
		// And an ignored event does not stop a genuine match from being found next to it.
		h, u, st, m := run(t, func(h *recH, u *recUpload) {
			h.addStopEvent(stopOpts{digests: u.digest, trunc: "size_limit", unsigned: true})
			h.addStopEvent(stopOpts{digests: u.digest})
		}, plain)
		if st != 200 || jstr(m, "provenance") != ProvMatchesAudit {
			t.Fatalf("%d %v", st, m)
		}
		_ = h
		_ = u
	})
	t.Run("an event on another session's chain is not considered", func(t *testing.T) {
		_, _, st, m := run(t, func(h *recH, u *recUpload) {
			h.addStopEvent(stopOpts{digests: u.digest, trunc: "size_limit", session: newUUID()})
		}, plain)
		if st != 200 || jstr(m, "provenance") != ProvNoStopEvent {
			t.Fatalf("%d %v", st, m)
		}
	})
	t.Run("an unreadable chain is a 503 retry, never the weaker label", func(t *testing.T) {
		h, u, st, m := run(t, func(h *recH, u *recUpload) {
			h.srv.Audit = &failingAudit{AuditStore: h.audit, err: errors.New("db down")}
		}, plain)
		if st != 503 || jstr(m, "error") != "audit_unavailable" || h.row(u).State != RecUploading {
			t.Fatalf("%d %v state=%s", st, m, h.row(u).State)
		}
		h.srv.Audit = h.audit
		if st, m := h.finish(u); st != 200 {
			t.Fatalf("retry: %d %v", st, m)
		}
	})
}

// ---- deadlines and slow clients ---------------------------------------------------------------

// writerWithoutDeadlines is a ResponseWriter that cannot honour http.NewResponseController deadlines.
type writerWithoutDeadlines struct{ *httptest.ResponseRecorder }

func TestRecordingUploadFailsClosedWithoutDeadlineSupport(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(100)
	h.mustCreate(u)
	req := h.request(call{op: UploadOpPut, rec: u.id, body: u.data[0]})
	req.RequestURI = ""
	rec := &writerWithoutDeadlines{httptest.NewRecorder()}
	h.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "deadlines_unavailable") {
		t.Fatalf("a writer that cannot set deadlines got %d %s; the route must fail closed", rec.Code, rec.Body.String())
	}
	if h.row(u).Segments[0].CommittedOffset != 0 {
		t.Fatal("bytes were accepted without enforceable deadlines")
	}
	// The same for operations that carry no body (nothing later would notice the missing deadlines).
	for _, c := range []call{{op: UploadOpHead, rec: u.id}, {op: UploadOpFinish, rec: u.id, body: h.finishBody(u, u.digest, nil, 0)}} {
		hreq := h.request(c)
		hreq.RequestURI = ""
		hrec := &writerWithoutDeadlines{httptest.NewRecorder()}
		h.srv.Handler().ServeHTTP(hrec, hreq)
		if hrec.Code != http.StatusInternalServerError || !strings.Contains(hrec.Body.String(), "deadlines_unavailable") {
			t.Fatalf("op %d on a writer without deadline support: %d %s; every route must fail closed", c.op, hrec.Code, hrec.Body.String())
		}
	}
}

func TestRecordingProvenanceRefusesAKeyThatChangedSinceCreate(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(100)
	h.mustCreate(u)
	row := h.row(u)
	machine, _ := h.machines.GetMachine(context.Background(), h.tenant, h.device)
	fin := recFinishMeta{Digests: u.digest}
	if _, _, err := h.srv.recordingProvenance(context.Background(), h.tenant, row, machine, fin); err != nil {
		t.Fatalf("matching key: %v", err)
	}
	row.EnrollmentFP[0] ^= 1 // the upload was created under a different enrollment key
	if _, _, err := h.srv.recordingProvenance(context.Background(), h.tenant, row, machine, fin); err == nil {
		t.Fatal("provenance was computed for a key other than the one the upload was created under")
	}
}

// rawSend writes the wire form of req to a fresh connection in `slices`, with `pause` between them, and
// returns the status line of whatever comes back (or "" if the server hung up).
func rawConn(t *testing.T, h *recH) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func wireForm(t *testing.T, req *http.Request) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := req.Write(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func readStatus(conn net.Conn, within time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	return string(buf[:n])
}

func TestRecordingUploadStalledClientIsCutOffByTheProgressDeadline(t *testing.T) {
	h := newRecH(t, recHOpts{cfg: RecordingUploadConfig{PutProgress: 300 * time.Millisecond, PutTotal: 30 * time.Second}})
	u := newRecUpload(mib)
	h.mustCreate(u)
	wire := wireForm(t, h.request(call{op: UploadOpPut, rec: u.id, body: u.data[0]}))
	conn := rawConn(t, h)
	conn.Write(wire[:len(wire)-mib/2]) // headers + half the body, then silence
	start := time.Now()
	status := readStatus(conn, 5*time.Second)
	if !strings.HasPrefix(status, "HTTP/1.1 408") {
		t.Fatalf("stalled upload: got %q, want a 408", status)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("the stall took %v to be cut off", time.Since(start))
	}
	if h.row(u).Segments[0].CommittedOffset != 0 {
		t.Fatal("a half-received chunk was committed")
	}
	// The slot is free again and a good upload still works.
	if st, m := h.put(u, 0, 0); st != 200 {
		t.Fatalf("after the stall: %d %v", st, m)
	}
}

func TestRecordingUploadTotalDeadlineBoundsATrickle(t *testing.T) {
	h := newRecH(t, recHOpts{cfg: RecordingUploadConfig{PutProgress: 2 * time.Second, PutTotal: 400 * time.Millisecond}})
	u := newRecUpload(mib)
	h.mustCreate(u)
	wire := wireForm(t, h.request(call{op: UploadOpPut, rec: u.id, body: u.data[0]}))
	conn := rawConn(t, h)
	hdrLen := len(wire) - mib
	conn.Write(wire[:hdrLen])
	go func() { // a byte every 100 ms keeps the progress deadline alive but not the total
		for i := 0; i < 100; i++ {
			if _, err := conn.Write([]byte{wire[hdrLen+i]}); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	status := readStatus(conn, 5*time.Second)
	if !strings.HasPrefix(status, "HTTP/1.1 408") {
		t.Fatalf("trickling upload: got %q, want a 408 from the total bound", status)
	}
}

func TestRecordingUploadRouteDeadlineOverridesTheServerWideTimeout(t *testing.T) {
	// The server-wide ReadTimeout (150 ms here, 30 s in production) would kill a body that takes longer
	// than that to arrive. The route's own deadline REPLACES it, so a slow-but-alive client succeeds.
	h := newRecH(t, recHOpts{readTimeout: 150 * time.Millisecond, cfg: RecordingUploadConfig{PutProgress: 2 * time.Second}})
	u := newRecUpload(mib)
	h.mustCreate(u)
	wire := wireForm(t, h.request(call{op: UploadOpPut, rec: u.id, body: u.data[0]}))
	conn := rawConn(t, h)
	hdrLen := len(wire) - mib
	conn.Write(wire[:hdrLen])
	body := wire[hdrLen:]
	start := time.Now()
	for off := 0; off < len(body); off += 128 << 10 {
		end := off + 128<<10
		if end > len(body) {
			end = len(body)
		}
		conn.Write(body[off:end])
		time.Sleep(60 * time.Millisecond)
	}
	status := readStatus(conn, 5*time.Second)
	if time.Since(start) < 300*time.Millisecond {
		t.Fatal("the test did not outlast the server-wide ReadTimeout; it proves nothing")
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("slow-but-alive upload: got %q, want 200 (the route deadline must override the server timeout)", status)
	}
	if h.row(u).Segments[0].CommittedOffset != mib {
		t.Fatal("chunk not committed")
	}
}

func TestRecordingUploadDisconnectMidBodyCommitsNothing(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(mib)
	h.mustCreate(u)
	wire := wireForm(t, h.request(call{op: UploadOpPut, rec: u.id, body: u.data[0]}))
	conn := rawConn(t, h)
	conn.Write(wire[:len(wire)-mib/3])
	time.Sleep(50 * time.Millisecond)
	conn.Close()
	time.Sleep(200 * time.Millisecond)
	if h.row(u).Segments[0].CommittedOffset != 0 {
		t.Fatal("a disconnected upload advanced the offset")
	}
	if _, err := os.Stat(filepath.Join(h.dir, ".incoming", h.row(u).UploadID)); !os.IsNotExist(err) {
		t.Fatal("a disconnected upload left bytes on the volume")
	}
	if st, m := h.put(u, 0, 0); st != 200 {
		t.Fatalf("retry after disconnect: %d %v", st, m)
	}
}

// ---- admission --------------------------------------------------------------------------------

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRecordingUploadAdmissionLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  RecordingUploadConfig
	}{
		{"global", RecordingUploadConfig{GlobalConcurrency: 1, QueueMax: 1, QueueWait: 150 * time.Millisecond}},
		{"per tenant", RecordingUploadConfig{TenantConcurrency: 1, QueueMax: 1, QueueWait: 150 * time.Millisecond}},
		{"per device", RecordingUploadConfig{DeviceConcurrency: 1, QueueMax: 1, QueueWait: 150 * time.Millisecond}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRecH(t, recHOpts{cfg: tc.cfg})
			u := newRecUpload(mib)
			h.mustCreate(u)
			wire := wireForm(t, h.request(call{op: UploadOpPut, rec: u.id, body: u.data[0]}))
			conn := rawConn(t, h)
			conn.Write(wire[:len(wire)-100]) // holds a slot: admitted, body unfinished
			waitFor(t, "the slot to be taken", func() bool {
				h.srv.Recording.adm.mu.Lock()
				defer h.srv.Recording.adm.mu.Unlock()
				return h.srv.Recording.adm.global == 1
			})
			start := time.Now()
			st, _, _ := h.do(call{op: UploadOpHead, rec: u.id})
			if st != 503 {
				t.Fatalf("second request while the slot is held: %d, want 503", st)
			}
			if time.Since(start) < 100*time.Millisecond {
				t.Fatalf("the busy answer came after %v: the request did not wait in the queue", time.Since(start))
			}
			conn.Close() // frees the slot (the server sees the disconnect)
			waitFor(t, "the slot to be released", func() bool {
				h.srv.Recording.adm.mu.Lock()
				defer h.srv.Recording.adm.mu.Unlock()
				return h.srv.Recording.adm.global == 0
			})
			if st, _, _ := h.do(call{op: UploadOpHead, rec: u.id}); st != 200 {
				t.Fatalf("after release: %d", st)
			}
		})
	}
}

func TestRecordingUploadQueueBoundIsImmediate(t *testing.T) {
	a := newUploadAdmission(1, 1, 1, 0) // no queue at all
	rel, err := a.acquire(context.Background(), "t", "d", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := a.acquire(context.Background(), "t", "d", 5*time.Second); !errors.Is(err, errAdmissionBusy) || time.Since(start) > time.Second {
		t.Fatalf("full queue: err=%v after %v; want an immediate busy", err, time.Since(start))
	}
	rel()
	if r2, err := a.acquire(context.Background(), "t", "d", time.Second); err != nil {
		t.Fatal(err)
	} else {
		r2()
	}
	// A waiter is admitted as soon as a slot frees.
	b := newUploadAdmission(1, 1, 1, 4)
	r1, _ := b.acquire(context.Background(), "t", "d", time.Second)
	got := make(chan error, 1)
	go func() {
		r, err := b.acquire(context.Background(), "t", "d", 3*time.Second)
		if err == nil {
			r()
		}
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)
	r1()
	if err := <-got; err != nil {
		t.Fatalf("queued waiter: %v", err)
	}
}

// countingMachines counts identity lookups: the database work an unauthenticated caller can cause.
type countingMachines struct {
	MachineStore
	lookups atomic.Int64
}

func (c *countingMachines) LookupDeviceIdentity(ctx context.Context, id string) (*DeviceIdentity, error) {
	c.lookups.Add(1)
	return c.MachineStore.LookupDeviceIdentity(ctx, id)
}

func TestRecordingUploadSourceThrottleChargesFailuresOnly(t *testing.T) {
	var cm *countingMachines
	h := newRecH(t, recHOpts{cfg: RecordingUploadConfig{IPRatePerSec: 0.0001, IPBurst: 3}, wireUp: func(h *recH) {
		cm = &countingMachines{MachineStore: h.machines}
		h.srv.Machines = cm
	}})
	u := newRecUpload(100)
	h.mustCreate(u)
	// Successful, authenticated traffic from this address never spends the budget: the whole fleet may
	// arrive from one proxy address, and it must not throttle itself.
	for i := 0; i < 30; i++ {
		if st, _, _ := h.do(call{op: UploadOpHead, rec: u.id}); st != 200 {
			t.Fatalf("authenticated request %d: %d (successful requests must not be charged)", i, st)
		}
	}
	// Failed authentications do spend it: three are answered 401 ...
	for i := 0; i < 3; i++ {
		if st, _, _ := h.do(call{op: UploadOpHead, rec: u.id, noSign: true}); st != 401 {
			t.Fatalf("failed attempt %d: %d", i, st)
		}
	}
	// ... and then the address gets 429 with NO database work, whatever it sends.
	before := cm.lookups.Load()
	st, m, hd := h.do(call{op: UploadOpHead, rec: u.id, noSign: true})
	if st != 429 || hd.Get("Retry-After") == "" {
		t.Fatalf("over the failure budget: %d %v", st, m)
	}
	if cm.lookups.Load() != before {
		t.Fatalf("an address over its failure budget still caused %d identity lookups", cm.lookups.Load()-before)
	}
}

func TestRecordingUploadDeviceRateIsNotSpentByAnonymousCallers(t *testing.T) {
	// A rate limiter must not become an off switch: someone who only NAMES a device in a header (and so
	// cannot sign) must not be able to use up that device's budget.
	h := newRecH(t, recHOpts{cfg: RecordingUploadConfig{DeviceRatePerSec: 0.0001, DeviceBurst: 3}})
	u := newRecUpload(100)
	h.mustCreate(u) // authenticated request 1 of 3
	for i := 0; i < 25; i++ {
		if st, _, _ := h.do(call{op: UploadOpHead, rec: u.id, noSign: true}); st != 401 {
			t.Fatalf("unsigned request: %d", st)
		}
	}
	for i := 0; i < 2; i++ { // authenticated requests 2 and 3: the budget must still be there
		if st, _, _ := h.do(call{op: UploadOpHead, rec: u.id}); st != 200 {
			t.Fatalf("authenticated request %d after 25 anonymous ones: %d (the anonymous callers spent the device's budget)", i+2, st)
		}
	}
	if st, _, _ := h.do(call{op: UploadOpHead, rec: u.id}); st != 429 {
		t.Fatalf("the device's own budget must still run out: %d", st)
	}
}

// ---- mounting ---------------------------------------------------------------------------------

func TestRecordingUploadRoutesMountOnlyWhenFullyWired(t *testing.T) {
	for name, mut := range map[string]func(h *recH){
		"no keys":     func(h *recH) { h.srv.Recording.Keys = nil },
		"no store":    func(h *recH) { h.srv.Recording.Store = nil },
		"no volume":   func(h *recH) { h.srv.Recording.Files = nil },
		"no audience": func(h *recH) { h.srv.Recording.Audience = "" },
		"no machines": func(h *recH) { h.srv.Machines = nil },
		"no sessions": func(h *recH) { h.srv.SessionRecords = nil },
	} {
		h := newRecH(t, recHOpts{wireUp: mut})
		st, m, _ := h.do(call{op: UploadOpHead, rec: newUUID()})
		// Unmounted, the request falls through to the authenticated chain (the catch-all), never to the
		// upload pipeline: the pipeline initialises its admission state when it mounts.
		if h.srv.Recording.adm != nil || st == 200 {
			t.Errorf("%s: the upload routes are mounted (%d %v)", name, st, m)
		}
	}
}

// ---- durability order --------------------------------------------------------------------------

// syncSpy wraps the in-flight file and logs every fsync; orderSpy logs when the store acknowledges a
// commit. The bytes must be durable BEFORE the offset that acknowledges them moves, so the log must read
// "sync" then "ack".
type syncSpy struct {
	EnvFile
	log *orderLog
}

func (s syncSpy) Sync() error {
	s.log.add("sync")
	return s.EnvFile.Sync()
}

type orderLog struct {
	mu sync.Mutex
	ev []string
}

func (o *orderLog) add(e string) { o.mu.Lock(); o.ev = append(o.ev, e); o.mu.Unlock() }
func (o *orderLog) get() string  { o.mu.Lock(); defer o.mu.Unlock(); return strings.Join(o.ev, ",") }

type orderSpyStore struct {
	RecordingStore
	log *orderLog
}

func (o orderSpyStore) UpdateSegment(ctx context.Context, tenantID, id string, idx int, fn SegmentUpdateFn) error {
	err := o.RecordingStore.UpdateSegment(ctx, tenantID, id, idx, fn)
	if err == nil {
		o.log.add("ack") // the store has persisted the new offset by the time it returns
	}
	return err
}

func TestRecordingUploadFsyncsBeforeTheOffsetIsAcknowledged(t *testing.T) {
	log := &orderLog{}
	h := newRecH(t, recHOpts{wireUp: func(h *recH) {
		h.srv.Recording.Store = orderSpyStore{RecordingStore: h.store, log: log}
		h.srv.Recording.wrapIncoming = func(f EnvFile) EnvFile { return syncSpy{EnvFile: f, log: log} }
	}})
	u := newRecUpload(2 * mib)
	h.mustCreate(u)
	if st, m := h.put(u, 0, 0); st != 200 {
		t.Fatalf("put: %d %v", st, m)
	}
	if got := log.get(); got != "sync,ack" {
		t.Fatalf("event order %q, want \"sync,ack\": the chunk must be fsynced before its offset is acknowledged", got)
	}
	if r := h.row(u); r.Segments[0].CommittedOffset != mib {
		t.Fatalf("offset %d", r.Segments[0].CommittedOffset)
	}
}

// ---- provenance: content that no longer matches what was signed ----------------------------------

func TestRecordingProvenanceIgnoresAnEventWhoseContentWasAlteredAfterSigning(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(100)
	h.mustCreate(u)
	h.putAll(u)
	// A genuinely signed stop event that matches the upload...
	ev := h.addStopEvent(stopOpts{digests: u.digest})
	// ...whose stored fields are then altered (a database-level edit keeping hash and signature intact).
	// The signature signs the HASH, so only re-hashing the fields ties it to what we read: the event must
	// stop counting — it can neither match nor conflict.
	list := h.audit.ingest[h.tenant]
	for i := range list {
		if list[i].ID == ev.ID {
			list[i].Action = []byte(strings.Replace(string(list[i].Action), `"truncated":null`, `"truncated":"size_limit"`, 1))
			if string(list[i].Action) == string(ev.Action) {
				t.Fatal("test bug: the action was not altered")
			}
		}
	}
	st, m := h.finish(u)
	if st != 200 || jstr(m, "provenance") != ProvNoStopEvent {
		t.Fatalf("%d %v: an event whose fields no longer hash to what was signed must be ignored", st, m)
	}
}
