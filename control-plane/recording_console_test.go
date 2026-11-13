package controlplane

// The console side of central recording (docs/63 D6, §2a C8), driven through the REAL protected handler
// chain (auth -> tenant -> routes) over a real HTTP server, with real encrypted files on a temp volume.
// The principal comes from a test header so one server can be asked the same question as every role.

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// hdrAuth resolves the principal named by X-Test-Principal.
type hdrAuth struct{ m map[string]*Principal }

func (a hdrAuth) Authenticate(r *http.Request) (*Principal, error) {
	if p := a.m[r.Header.Get("X-Test-Principal")]; p != nil {
		return p, nil
	}
	return nil, errors.New("no principal")
}

// failableAudit is a management audit store that can be made to fail, or to stall inside RecordEvent.
type failableAudit struct {
	*InMemoryMgmtAuditStore
	failRecord atomic.Bool
	failList   atomic.Bool
	mu         sync.Mutex
	gate       chan struct{} // when non-nil, RecordEvent waits on it
	entered    chan struct{}
}

func (f *failableAudit) RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	if f.failRecord.Load() {
		return errors.New("audit store down")
	}
	f.mu.Lock()
	gate, entered := f.gate, f.entered
	f.mu.Unlock()
	if gate != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate
	}
	return f.InMemoryMgmtAuditStore.RecordEvent(ctx, tenantID, e)
}

func (f *failableAudit) ListEventsFiltered(ctx context.Context, tenantID string, limit int, flt AuditFilter) ([]MgmtAuditEvent, error) {
	if f.failList.Load() {
		return nil, errors.New("audit store down")
	}
	return f.InMemoryMgmtAuditStore.ListEventsFiltered(ctx, tenantID, limit, flt)
}

type consoleH struct {
	*recH
	audit      *failableAudit
	principals map[string]*Principal
	otherGroup string
	clock      atomic.Int64 // unix nanos; 0 = real time
}

func newConsoleH(t *testing.T) *consoleH {
	t.Helper()
	c := &consoleH{audit: &failableAudit{InMemoryMgmtAuditStore: NewInMemoryMgmtAuditStore()}, principals: map[string]*Principal{}, otherGroup: newUUID()}
	c.recH = newRecH(t, recHOpts{wireUp: func(h *recH) {
		c.recH = h
		g := h.machine.GroupID
		mk := func(id string, m ...Membership) *Principal {
			return &Principal{UserID: id, TenantID: h.tenant, Grant: NewGrant(id, h.tenant, m...)}
		}
		c.principals["owner"] = mk("u-owner", NewMembership(RoleOwner, AllGroups()))
		c.principals["admin"] = mk("u-admin", NewMembership(RoleAdmin, AllGroups()))
		c.principals["auditor"] = mk("u-auditor", NewMembership(RoleAuditor, AllGroups()))
		c.principals["technician"] = mk("u-tech", NewMembership(RoleTechnician, AllGroups()))
		c.principals["readonly"] = mk("u-ro", NewMembership(RoleReadOnly, AllGroups()))
		c.principals["scoped"] = mk("u-scoped", NewMembership(RoleAuditor, Groups(g)))
		c.principals["scoped-other"] = mk("u-scoped2", NewMembership(RoleAuditor, Groups(c.otherGroup)))
		// A technician tenant-wide PLUS an auditor scoped elsewhere: capabilities must not be mixed
		// across memberships (the technician half does not hold view_recordings anywhere).
		c.principals["tech+scoped-auditor"] = mk("u-mix", NewMembership(RoleTechnician, AllGroups()), NewMembership(RoleAuditor, Groups(c.otherGroup)))
		// An API token principal that HOLDS the capability (as a future change to the grantable set could
		// make it): refusal must come from the token flag, not from the missing capability.
		tok := mk("tok-1", NewMembership(RoleOwner, AllGroups()))
		tok.APIToken = true
		c.principals["token"] = tok
		c.principals["other-tenant"] = &Principal{UserID: "u-x", TenantID: newUUID(), Grant: NewGrant("u-x", "other", NewMembership(RoleOwner, AllGroups()))}
		h.srv.Auth = hdrAuth{c.principals}
		h.srv.Binder = NoopBinder{}
		h.srv.MgmtAudit = c.audit
		h.srv.Recording.Now = func() time.Time {
			if n := c.clock.Load(); n != 0 {
				return time.Unix(0, n)
			}
			return time.Now()
		}
	}})
	return c
}

func (c *consoleH) advance(d time.Duration) {
	base := time.Now()
	if n := c.clock.Load(); n != 0 {
		base = time.Unix(0, n)
	}
	c.clock.Store(base.Add(d).UnixNano())
}

func (c *consoleH) do(who, method, path string, hdr map[string]string) (int, http.Header, []byte) {
	c.t.Helper()
	req, err := http.NewRequest(method, c.ts.URL+path, nil)
	if err != nil {
		c.t.Fatal(err)
	}
	if who != "" {
		req.Header.Set("X-Test-Principal", who)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("%s %s: reading the body: %v", method, path, err)
	}
	return resp.StatusCode, resp.Header, body
}

func (c *consoleH) get(who, path string) (int, http.Header, []byte) {
	c.t.Helper()
	return c.do(who, "GET", path, nil)
}

func jsonOf(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not JSON: %v: %s", err, b)
	}
	return m
}

func (c *consoleH) rows(action string) []MgmtAuditEvent {
	c.t.Helper()
	evs, err := c.audit.InMemoryMgmtAuditStore.ListEventsFiltered(context.Background(), c.tenant, 1000, AuditFilter{Action: action})
	if err != nil {
		c.t.Fatal(err)
	}
	return evs
}

func bigFrames(n, size int) []tFrame {
	var f []tFrame
	for i := 0; i < n; i++ {
		fr := tFrame{size: size + i%7, pts: uint64(i) * 3000}
		if i%50 == 0 {
			fr.key = true
		}
		f = append(f, fr)
	}
	return f
}

type fixture struct {
	u      *recUpload
	row    *RecordingRow
	frames []tFrame
	webm   []byte
}

// ready uploads one IVF segment and remuxes it.
func (c *consoleH) ready(frames []tFrame) *fixture {
	c.t.Helper()
	u := ivfUpload(buildIVF(320, 200, 90000, 1, frames, uint32(len(frames))))
	c.completeUpload(u)
	if err := c.srv.MuxRecording(context.Background(), c.tenant, u.id); err != nil {
		c.t.Fatalf("mux: %v", err)
	}
	r := c.row(u)
	if r.State != RecPlaybackReady {
		c.t.Fatalf("not ready: %s", r.State)
	}
	return &fixture{u: u, row: r, frames: frames, webm: c.readPlayback(r, 0)}
}

func (f *fixture) path(suffix string) string { return "/recordings/" + f.u.id + suffix }

var allViewers = []string{"owner", "admin", "auditor", "scoped"}

func wantNoStore(t *testing.T, what string, h http.Header) {
	t.Helper()
	if got := h.Get("Cache-Control"); got != "private, no-store" {
		t.Errorf("%s: Cache-Control = %q, want %q", what, got, "private, no-store")
	}
}

// ---- authorization ----------------------------------------------------------------------------

func TestConsoleEveryRouteChecksTheCapabilityTheTokenFlagAndTheTenant(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	routes := map[string]string{
		"list": "/recordings", "detail": fx.path(""), "playlist": fx.path("/playlist"),
		"stream": fx.path("/segments/0/stream"), "download": fx.path("/download"),
	}
	for name, path := range routes {
		t.Run(name, func(t *testing.T) {
			for _, who := range allViewers {
				if st, h, b := c.get(who, path); st != http.StatusOK {
					t.Errorf("%s: %d %s", who, st, b)
				} else {
					wantNoStore(t, who, h)
				}
			}
			// Roles WITHOUT the capability, and a token that has everything: 403, no-store, and no content.
			for _, who := range []string{"technician", "readonly", "token"} {
				st, h, b := c.get(who, path)
				if st != http.StatusForbidden {
					t.Errorf("%s: %d, want 403 (%s)", who, st, b)
				}
				wantNoStore(t, who+" refusal", h)
				if bytes.Contains(b, []byte(fx.u.id)) && name != "list" {
					t.Errorf("%s: the refusal names the recording: %s", who, b)
				}
			}
			// No principal at all.
			if st, _, _ := c.get("", path); st != http.StatusUnauthorized {
				t.Errorf("anonymous: %d, want 401", st)
			}
			// Another tenant's owner: the recording does not exist for them (RLS), never 200.
			st, h, b := c.get("other-tenant", path)
			if name == "list" {
				if st != http.StatusOK || strings.Contains(string(b), fx.u.id) {
					t.Errorf("other tenant list: %d %s", st, b)
				}
			} else if st != http.StatusNotFound {
				t.Errorf("other tenant: %d, want 404", st)
			}
			wantNoStore(t, "other tenant", h)
		})
	}
	// Refused requests wrote no audit row and released nothing: playback/download rows come only from
	// the viewers that were served.
	for _, e := range append(c.rows(recAuditPlayback), c.rows(recAuditDownload)...) {
		switch e.ActorUserID {
		case "u-tech", "u-ro", "u-mix", "tok-1", "u-x":
			t.Errorf("a refused principal left an audit row: %+v", e)
		}
	}
}

func TestConsoleRefusesAPITokensByFlagEvenWhenTheCapabilityIsHeld(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	// Through the REAL token authenticator with a token that (against the grantable set) holds the capability.
	store := NewInMemoryAPITokenStore()
	plain, tok, err := store.Mint(context.Background(), c.tenant, "t", []Capability{CapViewRecordings, CapViewAudit, CapManageTenant}, "u", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.srv.Auth = &APITokenAuthenticator{Tokens: store, Next: hdrAuth{c.principals}}
	for _, path := range []string{"/recordings", fx.path(""), fx.path("/playlist"), fx.path("/segments/0/stream"), fx.path("/download"), "/tenant/recording-policy"} {
		st, h, b := c.do("", "GET", path, map[string]string{"Authorization": "Bearer " + plain})
		if st != http.StatusForbidden {
			t.Errorf("GET %s with an API token: %d %s", path, st, b)
		}
		wantNoStore(t, path, h)
	}
	if st, _, _ := c.do("", "PUT", "/tenant/recording-policy", map[string]string{"Authorization": "Bearer " + plain}); st != http.StatusForbidden {
		t.Errorf("PUT policy with an API token: %d", st)
	}
	if len(c.rows(recAuditPlayback))+len(c.rows(recAuditDownload)) != 0 {
		t.Error("an API token request left an audit row (it was served)")
	}
	// The authenticator marks every token principal.
	p, err := (&APITokenAuthenticator{Tokens: store, Next: hdrAuth{}}).Authenticate(func() *http.Request {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+plain)
		return r
	}())
	if err != nil || !p.APIToken || p.UserID != tok.ID {
		t.Fatalf("token principal: %+v %v", p, err)
	}
}

// ---- group scope ------------------------------------------------------------------------------

// hiddenMachines makes chosen machine ids resolve as deleted.
type hiddenMachines struct {
	MachineStore
	hidden map[string]bool
}

func (h hiddenMachines) GetMachineByID(ctx context.Context, tenantID, id string) (*Machine, error) {
	if h.hidden[id] {
		return nil, ErrMachineNotFound
	}
	return h.MachineStore.GetMachineByID(ctx, tenantID, id)
}

type brokenMachines struct{ MachineStore }

func (brokenMachines) GetMachineByID(context.Context, string, string) (*Machine, error) {
	return nil, errors.New("machine store down")
}

func TestConsoleGroupScopeUsesTheMachinesCurrentGroup(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	routes := []string{fx.path(""), fx.path("/playlist"), fx.path("/segments/0/stream"), fx.path("/download")}
	listed := func(who string) bool {
		st, _, b := c.get(who, "/recordings")
		return st == http.StatusOK && strings.Contains(string(b), fx.u.id)
	}

	// In scope: a viewer scoped to the machine's group.
	for _, p := range routes {
		if st, _, b := c.get("scoped", p); st != http.StatusOK {
			t.Errorf("scoped (right group) %s: %d %s", p, st, b)
		}
	}
	if !listed("scoped") || !listed("owner") {
		t.Fatal("the in-scope viewers do not see it in the list")
	}
	// Out of scope: the same role scoped to ANOTHER group. 404 everywhere (an id reveals nothing).
	for _, who := range []string{"scoped-other", "tech+scoped-auditor"} {
		for _, p := range routes {
			if st, h, _ := c.get(who, p); st != http.StatusNotFound {
				t.Errorf("%s %s: %d, want 404", who, p, st)
			} else {
				wantNoStore(t, who, h)
			}
		}
		if listed(who) {
			t.Errorf("%s lists a recording outside their scope", who)
		}
	}

	// The machine MOVES to another group after the recording was made: scope follows the CURRENT group.
	if err := c.machines.SetMachineGroup(context.Background(), c.tenant, c.machine.ID, c.otherGroup); err != nil {
		t.Fatal(err)
	}
	for _, p := range routes {
		if st, _, _ := c.get("scoped", p); st != http.StatusNotFound {
			t.Errorf("after the move the old group's auditor still reaches %s (%d)", p, st)
		}
		if st, _, b := c.get("scoped-other", p); st != http.StatusOK {
			t.Errorf("after the move the new group's auditor is refused %s (%d %s)", p, st, b)
		}
	}
	if listed("scoped") || !listed("scoped-other") {
		t.Error("the list does not follow the machine's current group")
	}

	// The machine is DELETED: only a tenant-wide holder can still see it.
	c.srv.Machines = hiddenMachines{MachineStore: c.machines, hidden: map[string]bool{c.machine.ID: true}}
	for _, p := range routes {
		for _, who := range []string{"scoped", "scoped-other"} {
			if st, _, _ := c.get(who, p); st != http.StatusNotFound {
				t.Errorf("a deleted machine's recording is visible to scoped %s on %s (%d)", who, p, st)
			}
		}
		for _, who := range []string{"owner", "auditor", "admin"} {
			if st, _, b := c.get(who, p); st != http.StatusOK {
				t.Errorf("a tenant-wide %s lost a deleted machine's recording on %s (%d %s)", who, p, st, b)
			}
		}
	}
	if listed("scoped-other") || !listed("auditor") {
		t.Error("list visibility for a deleted machine is wrong")
	}

	// A machine store FAILURE fails closed for a scoped viewer (never "allowed", never an empty list).
	c.srv.Machines = brokenMachines{c.machines}
	for _, p := range routes {
		if st, _, _ := c.get("scoped", p); st != http.StatusInternalServerError {
			t.Errorf("machine store down: scoped %s = %d, want 500", p, st)
		}
	}
	if st, _, _ := c.get("scoped", "/recordings"); st != http.StatusInternalServerError {
		t.Errorf("machine store down: scoped list = %d, want 500", st)
	}
	if st, _, _ := c.get("owner", fx.path("")); st != http.StatusOK { // a tenant-wide holder needs no group
		t.Errorf("machine store down: tenant-wide owner = %d", st)
	}
}

// ---- audit (C8: persisted BEFORE content) -----------------------------------------------------

func TestConsolePlaybackIsAuditedOncePerViewerPerRecordingPer10Minutes(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	fx2 := c.ready(framesB(0))

	// Playlist, stream, a Range seek and another stream: one row, across routes.
	c.get("auditor", fx.path("/playlist"))
	c.get("auditor", fx.path("/segments/0/stream"))
	c.do("auditor", "GET", fx.path("/segments/0/stream"), map[string]string{"Range": "bytes=10-99"})
	c.get("auditor", fx.path("/playlist"))
	rows := c.rows(recAuditPlayback)
	if len(rows) != 1 {
		t.Fatalf("%d playback rows after four requests, want 1", len(rows))
	}
	e := rows[0]
	if e.ActorUserID != "u-auditor" || e.TargetKind != "recording" || e.TargetID != fx.u.id || e.Seq == nil || e.Hash == "" {
		t.Fatalf("row = %+v", e)
	}
	var meta map[string]any
	_ = json.Unmarshal(e.Metadata, &meta)
	if meta["recording_id"] != fx.u.id || meta["session_id"] != fx.row.SessionID || meta["machine_id"] != fx.row.MachineID {
		t.Errorf("metadata = %v", meta)
	}
	// A different viewer, and a different recording, each get their own row.
	c.get("owner", fx.path("/playlist"))
	c.get("auditor", fx2.path("/playlist"))
	if n := len(c.rows(recAuditPlayback)); n != 3 {
		t.Fatalf("%d rows after a second viewer and a second recording, want 3", n)
	}
	// Metadata routes release no recording content and write no row.
	c.get("auditor", "/recordings")
	c.get("auditor", fx.path(""))
	if n := len(c.rows(recAuditPlayback)); n != 3 {
		t.Fatalf("list/detail wrote audit rows (%d)", n)
	}
	// Inside the window nothing more; after it, playback starts again and is recorded again.
	c.advance(9 * time.Minute)
	c.get("auditor", fx.path("/playlist"))
	if n := len(c.rows(recAuditPlayback)); n != 3 {
		t.Fatalf("a request 9 minutes later wrote a row (%d)", n)
	}
	c.advance(2 * time.Minute)
	c.get("auditor", fx.path("/segments/0/stream"))
	if n := len(c.rows(recAuditPlayback)); n != 4 {
		t.Fatalf("a request 11 minutes later wrote %d rows total, want 4", n)
	}
	// The dedup survives a process restart / another replica: with the in-process cache empty, the audit
	// store itself answers "already recorded".
	c.srv.Recording.auditMu.Lock()
	c.srv.Recording.auditSeen = nil
	c.srv.Recording.auditMu.Unlock()
	c.get("auditor", fx.path("/playlist"))
	if n := len(c.rows(recAuditPlayback)); n != 4 {
		t.Fatalf("an empty cache re-recorded playback (%d rows)", n)
	}
}

func TestConsoleEveryDownloadIsAuditedAndAHeadIsNot(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	for i := 1; i <= 3; i++ {
		if st, _, b := c.get("owner", fx.path("/download")); st != http.StatusOK {
			t.Fatalf("download %d: %d %s", i, st, b)
		}
		if n := len(c.rows(recAuditDownload)); n != i {
			t.Fatalf("%d download rows after %d downloads: downloads must NOT be deduplicated", n, i)
		}
	}
	if st, _, body := c.do("owner", "HEAD", fx.path("/download"), nil); st != http.StatusOK || len(body) != 0 {
		t.Errorf("HEAD download: %d with %d bytes", st, len(body))
	}
	if n := len(c.rows(recAuditDownload)); n != 3 {
		t.Errorf("a HEAD (no content) wrote a row: %d", n)
	}
	if n := len(c.rows(recAuditPlayback)); n != 0 {
		t.Errorf("a download wrote playback rows: %d", n)
	}
}

func TestConsoleAuditFailureWithholdsAllContent(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	for _, mode := range []string{"record fails", "dedup lookup fails"} {
		t.Run(mode, func(t *testing.T) {
			c.audit.failRecord.Store(mode == "record fails")
			c.audit.failList.Store(mode == "dedup lookup fails")
			defer c.audit.failRecord.Store(false)
			defer c.audit.failList.Store(false)
			routes := map[string]bool{ // route -> is the dedup lookup on its path
				fx.path("/playlist"): true, fx.path("/segments/0/stream"): true, fx.path("/download"): false,
			}
			for p, dedup := range routes {
				if mode == "dedup lookup fails" && !dedup {
					continue // downloads never look: they always write
				}
				st, h, b := c.get("owner", p)
				if st != http.StatusServiceUnavailable {
					t.Errorf("%s: %d, want 503", p, st)
				}
				wantNoStore(t, p, h)
				if bytes.HasPrefix(b, []byte("PK")) || bytes.Contains(b, c.webmPrefix(fx)) || bytes.Contains(b, []byte(`"segments"`)) {
					t.Errorf("%s released content although the audit failed: %q", p, b[:min(len(b), 80)])
				}
			}
			// Metadata routes need no audit and keep working.
			if st, _, _ := c.get("owner", fx.path("")); st != http.StatusOK {
				t.Errorf("detail with the audit store down: %d", st)
			}
			if st, _, _ := c.get("owner", "/recordings"); st != http.StatusOK {
				t.Errorf("list with the audit store down: %d", st)
			}
		})
	}
	// And once the store is back, the same requests are served and recorded.
	if st, _, _ := c.get("owner", fx.path("/playlist")); st != http.StatusOK || len(c.rows(recAuditPlayback)) != 1 {
		t.Errorf("after recovery: %d, %d rows", st, len(c.rows(recAuditPlayback)))
	}
}

func (c *consoleH) webmPrefix(fx *fixture) []byte { return fx.webm[:16] }

func TestConsoleContentWaitsForTheAuditRowToBePersisted(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	c.audit.mu.Lock()
	c.audit.gate = make(chan struct{})
	c.audit.entered = make(chan struct{}, 1)
	gate, entered := c.audit.gate, c.audit.entered
	c.audit.mu.Unlock()

	for _, p := range []string{fx.path("/playlist"), fx.path("/segments/0/stream"), fx.path("/download")} {
		got := make(chan int, 1)
		go func() {
			req, _ := http.NewRequest("GET", c.ts.URL+p, nil)
			req.Header.Set("X-Test-Principal", "owner")
			resp, err := http.DefaultClient.Do(req) // returns when the RESPONSE HEADERS arrive
			if err != nil {
				got <- -1
				return
			}
			resp.Body.Close()
			got <- resp.StatusCode
		}()
		select {
		case <-entered: // the handler is inside RecordEvent
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the handler never reached the audit write", p)
		}
		select {
		case st := <-got:
			t.Fatalf("%s: response headers (%d) arrived while the audit row was still being written", p, st)
		case <-time.After(300 * time.Millisecond):
		}
		gate <- struct{}{}
		select {
		case st := <-got:
			if st != http.StatusOK {
				t.Fatalf("%s: %d", p, st)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no response after the audit row was persisted", p)
		}
		if p == fx.path("/playlist") { // the dedup'd routes below must not wait again
			c.audit.mu.Lock()
			c.audit.gate = nil
			c.audit.mu.Unlock()
			break
		}
	}
}

// ---- stream ranges and integrity --------------------------------------------------------------

func TestConsoleStreamServesExactBytesAndRanges(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(bigFrames(300, 900)) // ~280 KB of WebM: several 64 KiB frames
	want := fx.webm
	L := int64(len(want))
	if L < 3*EnvFrameSize {
		t.Fatalf("fixture too small (%d) to cross frame boundaries", L)
	}
	path := fx.path("/segments/0/stream")

	st, h, b := c.get("auditor", path)
	if st != http.StatusOK || !bytes.Equal(b, want) {
		t.Fatalf("full stream: %d, %d bytes (want %d)", st, len(b), L)
	}
	if h.Get("Content-Type") != "video/webm" || h.Get("Accept-Ranges") != "bytes" || h.Get("Content-Length") != fmt.Sprint(L) {
		t.Errorf("headers: %v", h)
	}
	wantNoStore(t, "stream", h)
	if h.Get("ETag") != "" || h.Get("Last-Modified") != "" {
		t.Errorf("a validator is sent (%q %q): conditional requests would need authorization-aware handling", h.Get("ETag"), h.Get("Last-Modified"))
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff missing")
	}

	rng := func(spec string) (int, http.Header, []byte) {
		return c.do("auditor", "GET", path, map[string]string{"Range": spec})
	}
	for _, tc := range []struct {
		spec       string
		start, end int64
	}{
		{"bytes=0-99", 0, 99},
		{"bytes=100-", 100, L - 1},
		{"bytes=-50", L - 50, L - 1},
		{"bytes=65500-65700", 65500, 65700},                    // across the first 64 KiB frame boundary
		{"bytes=65536-65536", 65536, 65536},                    // exactly the first byte of frame 1
		{"bytes=65535-65536", 65535, 65536},                    // the last byte of frame 0 and the first of frame 1
		{"bytes=100000-300000", 100000, min64(300000, L-1)},    // spans several chunks
		{fmt.Sprintf("bytes=%d-%d", L-3, L+500), L - 3, L - 1}, // end past EOF is clamped
		{fmt.Sprintf("bytes=-%d", L+1000), 0, L - 1},           // suffix larger than the file
	} {
		st, h, b := rng(tc.spec)
		if st != http.StatusPartialContent || !bytes.Equal(b, want[tc.start:tc.end+1]) {
			t.Errorf("%s: %d, %d bytes", tc.spec, st, len(b))
			continue
		}
		if cr := h.Get("Content-Range"); cr != fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end, L) {
			t.Errorf("%s: Content-Range = %q", tc.spec, cr)
		}
		wantNoStore(t, tc.spec, h)
	}
	// Unsatisfiable: 416 with the length, no body content.
	for _, spec := range []string{fmt.Sprintf("bytes=%d-", L), "bytes=999999999-", "bytes=-0"} {
		st, h, _ := rng(spec)
		if st != http.StatusRequestedRangeNotSatisfiable || h.Get("Content-Range") != fmt.Sprintf("bytes */%d", L) {
			t.Errorf("%s: %d %q", spec, st, h.Get("Content-Range"))
		}
	}
	// Not a single satisfiable range: served whole (RFC 9110 lets the server ignore it).
	for _, spec := range []string{"bytes=0-10,20-30", "bytes=abc", "items=0-5", "bytes=5-2", "bytes=+1-5"} {
		if st, _, b := rng(spec); st != http.StatusOK || !bytes.Equal(b, want) {
			t.Errorf("%q: %d, %d bytes (want the whole body)", spec, st, len(b))
		}
	}
	// No validators are ever sent, so conditionals are ignored: never a bodyless 304, and If-Range makes
	// the server answer with the whole representation.
	for name, hdr := range map[string]map[string]string{
		"If-None-Match":     {"If-None-Match": `"anything"`},
		"If-Modified-Since": {"If-Modified-Since": time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)},
		"If-Range":          {"If-Range": `"x"`, "Range": "bytes=0-9"},
		"If-Match":          {"If-Match": `"x"`},
	} {
		if st, _, b := c.do("auditor", "GET", path, hdr); st != http.StatusOK || !bytes.Equal(b, want) {
			t.Errorf("%s: %d, %d bytes", name, st, len(b))
		}
	}
	// A conditional request from someone who has LOST access gets the authorization answer, not a 304.
	if st, _, _ := c.do("technician", "GET", path, map[string]string{"If-None-Match": `"anything"`}); st != http.StatusForbidden {
		t.Errorf("conditional from an unauthorized role: %d", st)
	}
	// HEAD: headers, no body, no audit row of its own beyond what GETs wrote.
	before := len(c.rows(recAuditPlayback))
	if st, h, b := c.do("owner", "HEAD", path, nil); st != http.StatusOK || len(b) != 0 || h.Get("Content-Length") != fmt.Sprint(L) {
		t.Errorf("HEAD: %d %d bytes cl=%s", st, len(b), h.Get("Content-Length"))
	}
	if len(c.rows(recAuditPlayback)) != before {
		t.Error("a HEAD (no content) wrote an audit row")
	}
	// Bad segment indexes.
	for _, n := range []string{"1", "-1", "00", "x", "99999999999999999999"} {
		if st, _, _ := c.get("auditor", fx.path("/segments/"+n+"/stream")); st != http.StatusNotFound {
			t.Errorf("segment %q: %d, want 404", n, st)
		}
	}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (c *consoleH) flipByte(rel string, fromEnd int64) {
	c.t.Helper()
	p := filepath.Join(c.dir, filepath.FromSlash(rel))
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		c.t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	var one [1]byte
	f.ReadAt(one[:], st.Size()-fromEnd)
	one[0] ^= 0xff
	if _, err := f.WriteAt(one[:], st.Size()-fromEnd); err != nil {
		c.t.Fatal(err)
	}
}

func TestConsoleTamperedFilesNeverReleaseUnauthenticatedBytes(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(bigFrames(600, 1000)) // > 256 KiB of WebM and of IVF: more than one stream chunk
	if len(fx.webm) < int(2*recStreamChunk) {
		t.Fatalf("fixture too small: %d", len(fx.webm))
	}
	rel := func(rep string) string { return c.tenant + "/" + fx.u.id + "/0000." + rep + ".enc" }

	// Tamper with the FIRST chunk's frame: a clean 500, no body bytes at all.
	c.flipByte(rel("webm"), int64(len(fx.webm))+100) // inside the first frames
	st, _, b := c.get("owner", fx.path("/segments/0/stream"))
	if st != http.StatusInternalServerError || bytes.Contains(b, fx.webm[:32]) {
		t.Errorf("early tamper: %d, %d bytes", st, len(b))
	}
	c.flipByte(rel("webm"), int64(len(fx.webm))+100) // restore
	// Tamper with a LATE frame: the client must NOT receive a complete-looking 200.
	c.flipByte(rel("webm"), 50)
	req, _ := http.NewRequest("GET", c.ts.URL+fx.path("/segments/0/stream"), nil)
	req.Header.Set("X-Test-Principal", "owner")
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		body, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr == nil && len(body) == len(fx.webm) {
			t.Error("a tampered playback file was delivered in full with a 200")
		}
		if rerr == nil && resp.StatusCode == http.StatusOK && int64(len(body)) == resp.ContentLength {
			t.Error("the client saw a clean, complete response for a tampered file")
		}
	}
	c.flipByte(rel("webm"), 50) // restore

	// The evidence download: tamper -> the ZIP must be invalid or the transfer must fail, never complete.
	c.flipByte(rel("ivf"), 50)
	req, _ = http.NewRequest("GET", c.ts.URL+fx.path("/download"), nil)
	req.Header.Set("X-Test-Principal", "owner")
	resp, err = http.DefaultClient.Do(req)
	if err == nil {
		body, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr == nil {
			if _, zerr := zip.NewReader(bytes.NewReader(body), int64(len(body))); zerr == nil {
				t.Error("a tampered evidence file produced a valid ZIP")
			}
		}
	}
	c.flipByte(rel("ivf"), 50) // restore
	if st, _, b := c.get("owner", fx.path("/download")); st != http.StatusOK {
		t.Errorf("restored evidence is refused: %d", st)
	} else if _, err := zip.NewReader(bytes.NewReader(b), int64(len(b))); err != nil {
		t.Errorf("restored evidence ZIP invalid: %v", err)
	}
}

// ---- state gating, detail, download -----------------------------------------------------------

func TestConsoleStateGating(t *testing.T) {
	c := newConsoleH(t)
	// evidence_complete: not playable yet, but the evidence can be downloaded.
	pending := ivfUpload(buildIVF(64, 48, 90000, 1, framesA(), 0))
	c.completeUpload(pending)
	pp := func(u *recUpload, suffix string) string { return "/recordings/" + u.id + suffix }
	for _, s := range []string{"/playlist", "/segments/0/stream"} {
		st, _, b := c.get("owner", pp(pending, s))
		if st != http.StatusConflict || jsonOf(t, b)["error"] != "playback_pending" {
			t.Errorf("pending %s: %d %s", s, st, b)
		}
	}
	if st, _, _ := c.get("owner", pp(pending, "/download")); st != http.StatusOK {
		t.Errorf("pending download: %d", st)
	}
	d := jsonOf(t, func() []byte { _, _, b := c.get("owner", pp(pending, "")); return b }())
	if d["state"] != RecEvidenceComplete || d["playable"] != false {
		t.Errorf("pending detail: %v", d)
	}

	// playback_failed: 409 with the closed reason; evidence still downloadable.
	bad := ivfUpload(randBytes(4000))
	c.completeUpload(bad)
	_ = c.srv.MuxRecording(context.Background(), c.tenant, bad.id)
	for _, s := range []string{"/playlist", "/segments/0/stream"} {
		st, _, b := c.get("owner", pp(bad, s))
		m := jsonOf(t, b)
		if st != http.StatusConflict || m["error"] != "playback_failed" || m["reason"] != MuxInvalid {
			t.Errorf("failed %s: %d %s", s, st, b)
		}
	}
	if st, _, _ := c.get("owner", pp(bad, "/download")); st != http.StatusOK {
		t.Errorf("failed-playback download: %d", st)
	}
	if d := jsonOf(t, func() []byte { _, _, b := c.get("owner", pp(bad, "")); return b }()); d["playback_error"] != MuxInvalid {
		t.Errorf("failed detail: %v", d)
	}

	// expired: gone for playback and download; the row still reads "expired", never "missing".
	fx := c.ready(framesA())
	if err := c.store.MarkExpired(context.Background(), c.tenant, fx.u.id); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"/playlist", "/segments/0/stream", "/download"} {
		st, _, b := c.get("owner", fx.path(s))
		if st != http.StatusGone || jsonOf(t, b)["state"] != RecExpired {
			t.Errorf("expired %s: %d %s", s, st, b)
		}
	}
	if d := jsonOf(t, func() []byte { _, _, b := c.get("owner", fx.path("")); return b }()); d["state"] != RecExpired || d["expired_at"] == nil {
		t.Errorf("expired detail: %v", d)
	}
	if err := c.store.MarkDeleted(context.Background(), c.tenant, fx.u.id); err != nil {
		t.Fatal(err)
	}
	if st, _, b := c.get("owner", fx.path("/playlist")); st != http.StatusGone || jsonOf(t, b)["state"] != RecDeleted {
		t.Errorf("deleted playlist: %d %s", st, b)
	}
	// Recordings that never completed are not visible at all.
	up := ivfUpload(buildIVF(64, 48, 90000, 1, framesA(), 0))
	c.mustCreate(up)
	if st, _, _ := c.get("owner", pp(up, "")); st != http.StatusNotFound {
		t.Errorf("an uploading recording: %d, want 404", st)
	}
	// Malformed and unknown ids.
	for _, id := range []string{"not-a-uuid", "00000000-0000-0000-0000-000000000000", strings.ToUpper(pending.id)} {
		if st, _, _ := c.get("owner", "/recordings/"+id); st != http.StatusNotFound {
			t.Errorf("id %q: %d, want 404", id, st)
		}
	}
	// No audit rows for any refusal above.
	for _, e := range c.rows(recAuditPlayback) {
		if e.TargetID == fx.u.id || e.TargetID == bad.id {
			t.Errorf("a refused playback request was audited: %+v", e)
		}
	}
}

func TestConsoleDetailAndPlaylistShapes(t *testing.T) {
	c := newConsoleH(t)
	u := ivfUpload(buildIVF(320, 200, 90000, 1, framesA(), 0), buildIVF(640, 360, 90000, 1, framesB(90000*10), 0))
	c.completeUpload(u)
	if err := c.srv.MuxRecording(context.Background(), c.tenant, u.id); err != nil {
		t.Fatal(err)
	}
	st, _, b := c.get("auditor", "/recordings/"+u.id)
	if st != http.StatusOK {
		t.Fatalf("detail: %d %s", st, b)
	}
	d := jsonOf(t, b)
	if d["state"] != RecPlaybackReady || d["playable"] != true || d["segment_count"].(float64) != 2 ||
		d["provenance"] != ProvNoStopEvent || d["provenance_label"] != "Agent-signed; no matching stop event" {
		t.Errorf("detail = %v", d)
	}
	if note, _ := d["provenance_note"].(string); !strings.Contains(note, "independent capture verification") {
		t.Errorf("the no-independent-verification statement is missing: %q", note)
	}
	for _, leak := range []string{"wrapped", "dek", "upload_id", "enrollment", "key_id", "RMTREC"} {
		if strings.Contains(strings.ToLower(string(b)), strings.ToLower(leak)) {
			t.Errorf("detail leaks %q: %s", leak, b)
		}
	}
	segs := d["segments"].([]any)
	if s1 := segs[1].(map[string]any); s1["sha256"] != u.digest[1] || s1["playback"].(map[string]any)["width"].(float64) != 640 ||
		s1["playback"].(map[string]any)["start_ms"].(float64) != 10000 {
		t.Errorf("segment 1 = %v", s1)
	}

	st, _, b = c.get("auditor", "/recordings/"+u.id+"/playlist")
	if st != http.StatusOK {
		t.Fatalf("playlist: %d %s", st, b)
	}
	pl := jsonOf(t, b)
	items := pl["segments"].([]any)
	if pl["mime"] != `video/webm; codecs="vp8"` || len(items) != 2 {
		t.Fatalf("playlist = %v", pl)
	}
	for i, it := range items {
		m := it.(map[string]any)
		if m["url"] != fmt.Sprintf("segments/%d/stream", i) || m["bytes"].(float64) <= 0 {
			t.Errorf("item %d = %v", i, m)
		}
	}
	// The relative URL resolves to a real, playable route.
	if st, _, _ := c.get("auditor", "/recordings/"+u.id+"/"+items[1].(map[string]any)["url"].(string)); st != http.StatusOK {
		t.Errorf("playlist url does not resolve: %d", st)
	}
	if total := pl["total_duration_ms"].(float64); total < 10000 {
		t.Errorf("total_duration_ms = %v", total)
	}
}

func TestConsoleDownloadIsAZipOfTheVerifiedEvidenceWithAManifest(t *testing.T) {
	c := newConsoleH(t)
	a, b := buildIVF(320, 200, 90000, 1, framesA(), 0), buildIVF(640, 360, 90000, 1, framesB(90000*10), 0)
	u := ivfUpload(a, b)
	c.completeUpload(u)
	st, h, body := c.get("auditor", "/recordings/"+u.id+"/download")
	if st != http.StatusOK || h.Get("Content-Type") != "application/zip" ||
		h.Get("Content-Disposition") != `attachment; filename="recording-`+u.id+`.zip"` {
		t.Fatalf("download: %d %v", st, h)
	}
	wantNoStore(t, "download", h)
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		files[f.Name], _ = io.ReadAll(rc)
		rc.Close()
	}
	if len(files) != 3 || !bytes.Equal(files["segment-0000.ivf"], a) || !bytes.Equal(files["segment-0001.ivf"], b) {
		t.Fatalf("zip entries = %v", func() []string {
			var n []string
			for k, v := range files {
				n = append(n, fmt.Sprintf("%s(%d)", k, len(v)))
			}
			return n
		}())
	}
	var man struct {
		Format     string `json:"format"`
		Recording  string `json:"recording_id"`
		Provenance string `json:"provenance"`
		Note       string `json:"provenance_note"`
		Segments   []struct {
			File   string `json:"file"`
			SHA256 string `json:"sha256"`
			Bytes  int64  `json:"bytes"`
		} `json:"segments"`
	}
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	if man.Format != "deskrally-recording-evidence/1" || man.Recording != u.id || man.Provenance != ProvNoStopEvent ||
		len(man.Segments) != 2 || man.Segments[0].SHA256 != u.digest[0] || man.Segments[1].SHA256 != u.digest[1] ||
		man.Segments[1].File != "segment-0001.ivf" || man.Segments[1].Bytes != int64(len(b)) ||
		!strings.Contains(man.Note, "independent capture verification") {
		t.Errorf("manifest = %+v", man)
	}
	for _, leak := range []string{"wrapped", "dek", "upload_id", "enrollment", "key_id"} {
		if strings.Contains(strings.ToLower(string(files["manifest.json"])), leak) {
			t.Errorf("manifest leaks %q", leak)
		}
	}
}

// ---- list -------------------------------------------------------------------------------------

func TestConsoleListPagingFiltersAndScope(t *testing.T) {
	c := newConsoleH(t)
	// Recordings on two machines in two groups, inserted through the store (the list needs no files).
	other := &Machine{DeviceID: "dev-other-" + newUUID()[:6], GroupID: c.otherGroup, Name: "other", Pubkey: hex.EncodeToString(bytes.Repeat([]byte{9}, 32))}
	if err := c.machines.EnrollMachine(context.Background(), c.tenant, other); err != nil {
		t.Fatal(err)
	}
	mk := func(machine string) string {
		in := NewRecording{ID: newUUID(), SessionID: newUUID(), MachineID: machine, UploadID: newUUID(), Generation: 1,
			SegmentLens: []int64{100}, Key: EnvelopeKey{KeyID: 1, Wrapped: make([]byte, stdWrappedDEKLen)}}
		in.EnrollmentFP[0] = 1
		r, _, err := c.store.CreateRecording(context.Background(), c.tenant, in, recFree)
		if err != nil {
			t.Fatal(err)
		}
		c.commitStore(r)
		if _, err := c.store.CompleteEvidence(context.Background(), c.tenant, r.ID, completion(r)); err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	var mine, theirs []string
	for i := 0; i < 5; i++ {
		mine = append(mine, mk(c.machine.ID))
		theirs = append(theirs, mk(other.ID))
	}
	ids := func(b []byte) []string {
		var out []string
		for _, r := range jsonOf(t, b)["recordings"].([]any) {
			out = append(out, r.(map[string]any)["id"].(string))
		}
		return out
	}
	// A tenant-wide viewer sees all ten, paged by cursor, each exactly once.
	var seen []string
	cursor := ""
	for page := 0; page < 20; page++ {
		st, _, b := c.get("auditor", "/recordings?limit=3&cursor="+cursor)
		if st != http.StatusOK {
			t.Fatalf("page %d: %d %s", page, st, b)
		}
		seen = append(seen, ids(b)...)
		cursor, _ = jsonOf(t, b)["next_cursor"].(string)
		if cursor == "" {
			break
		}
	}
	if len(seen) != 10 || len(uniq(seen)) != 10 {
		t.Fatalf("tenant-wide paging saw %d rows (%d unique), want 10", len(seen), len(uniq(seen)))
	}
	// A viewer scoped to one group sees exactly that group's five — across pages, even though the raw log
	// interleaves the two groups — and the cursor never wedges on a page of foreign rows.
	var scopedSeen []string
	cursor = ""
	for page := 0; page < 30; page++ {
		st, _, b := c.get("scoped", "/recordings?limit=2&cursor="+cursor)
		if st != http.StatusOK {
			t.Fatalf("scoped page %d: %d %s", page, st, b)
		}
		scopedSeen = append(scopedSeen, ids(b)...)
		cursor, _ = jsonOf(t, b)["next_cursor"].(string)
		if cursor == "" {
			break
		}
	}
	if len(scopedSeen) != 5 || !sameSet(scopedSeen, mine) {
		t.Fatalf("scoped viewer saw %v, want exactly %v", scopedSeen, mine)
	}
	for _, id := range theirs {
		for _, s := range scopedSeen {
			if s == id {
				t.Fatalf("the scoped viewer was shown %s from another group", id)
			}
		}
	}
	// Filters and validation.
	st, _, b := c.get("auditor", "/recordings?machine_id="+other.ID+"&limit=200")
	if st != http.StatusOK || !sameSet(ids(b), theirs) {
		t.Errorf("machine filter: %d %v", st, ids(b))
	}
	for _, q := range []string{"limit=0", "limit=201", "limit=x", "session_id=zzz", "machine_id=ZZZ", "cursor=abc", "cursor=1.not-a-uuid", "cursor=-5." + newUUID()} {
		if st, _, _ := c.get("auditor", "/recordings?"+q); st != http.StatusBadRequest {
			t.Errorf("?%s: %d, want 400", q, st)
		}
	}
	// Items carry the label, not key material.
	_, _, b = c.get("auditor", "/recordings?limit=1")
	if s := string(b); !strings.Contains(s, "provenance_label") || strings.Contains(strings.ToLower(s), "wrapped") || strings.Contains(s, "upload_id") {
		t.Errorf("list item shape: %s", s)
	}
}

func (c *consoleH) commitStore(r *RecordingRow) {
	c.t.Helper()
	for _, sg := range r.Segments {
		err := c.store.UpdateSegment(context.Background(), c.tenant, r.ID, sg.Index, func(_ *RecordingRow, cur RecordingSegment) (int64, error) {
			return cur.DeclaredLen, nil
		})
		if err != nil {
			c.t.Fatal(err)
		}
	}
}

func uniq(in []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range in {
		m[s] = true
	}
	return m
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := uniq(b)
	for _, s := range a {
		if !m[s] {
			return false
		}
	}
	return true
}

// ---- policy -----------------------------------------------------------------------------------

func (c *consoleH) put(who, path, body string) (int, []byte) {
	c.t.Helper()
	req, _ := http.NewRequest("PUT", c.ts.URL+path, strings.NewReader(body))
	if who != "" {
		req.Header.Set("X-Test-Principal", who)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestConsolePolicyGetPutIsAuditedAndFailClosed(t *testing.T) {
	c := newConsoleH(t)
	ctx := context.Background()
	const path = "/tenant/recording-policy"
	cur := func() RecordingPolicy { p, _ := c.store.GetPolicy(ctx, c.tenant); return p }
	c.store.SetPolicy(ctx, c.tenant, DefaultRecordingPolicy()) // OFF

	// READ: Owner (manage_tenant) and the viewers (view_recordings); not technician / read-only.
	for who, want := range map[string]int{"owner": 200, "auditor": 200, "admin": 200, "technician": 403, "readonly": 403, "token": 403} {
		st, h, b := c.get(who, path)
		if st != want {
			t.Errorf("GET as %s: %d %s", who, st, b)
		}
		wantNoStore(t, who, h)
	}
	st, _, b := c.get("owner", path)
	m := jsonOf(t, b)
	if m["enabled"] != false || m["retention_days"].(float64) != 0 || m["storage_available"] != true {
		t.Errorf("default policy = %v (storage must be OFF by default)", m)
	}

	good := `{"retention_days":30,"max_recording_bytes":1073741824,"quota_bytes":21474836480}`
	// WRITE: manage_tenant only. Auditors, admins (no manage_tenant), technicians and tokens are refused,
	// and a refused write changes nothing and is not audited.
	for _, who := range []string{"auditor", "admin", "technician", "readonly", "token", "scoped"} {
		if st, _ := c.put(who, path, good); st != http.StatusForbidden {
			t.Errorf("PUT as %s: %d, want 403", who, st)
		}
	}
	if cur().Enabled() || len(c.rows("tenant.recording_policy.set")) != 0 {
		t.Fatal("a refused PUT changed the policy or wrote an audit row")
	}

	// FAIL-CLOSED naming: every field must be present and named exactly; none of these may switch storage ON.
	for name, body := range map[string]string{
		"empty object":         `{}`,
		"missing retention":    `{"max_recording_bytes":1,"quota_bytes":1}`,
		"missing max":          `{"retention_days":30,"quota_bytes":1}`,
		"missing quota":        `{"retention_days":30,"max_recording_bytes":1}`,
		"null retention":       `{"retention_days":null,"max_recording_bytes":1,"quota_bytes":1}`,
		"unknown field":        `{"retention_days":30,"max_recording_bytes":1,"quota_bytes":1,"enabled":true}`,
		"renamed field":        `{"retentionDays":30,"max_recording_bytes":1,"quota_bytes":1}`,
		"retention 366":        `{"retention_days":366,"max_recording_bytes":1,"quota_bytes":1}`,
		"retention -1":         `{"retention_days":-1,"max_recording_bytes":1,"quota_bytes":1}`,
		"max over the ceiling": `{"retention_days":30,"max_recording_bytes":1073741825,"quota_bytes":1}`,
		"max zero":             `{"retention_days":30,"max_recording_bytes":0,"quota_bytes":1}`,
		"negative quota":       `{"retention_days":30,"max_recording_bytes":1,"quota_bytes":-1}`,
		"string retention":     `{"retention_days":"30","max_recording_bytes":1,"quota_bytes":1}`,
		"float retention":      `{"retention_days":30.5,"max_recording_bytes":1,"quota_bytes":1}`,
		"trailing data":        good + ` {}`,
		"not JSON":             `retention_days=30`,
		"empty body":           ``,
	} {
		if st, _ := c.put("owner", path, body); st != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, st)
		}
	}
	if cur().Enabled() || len(c.rows("tenant.recording_policy.set")) != 0 {
		t.Fatal("a rejected body changed the policy or was audited")
	}
	if st, _ := c.put("owner", path, `{"retention_days":30,"max_recording_bytes":1,"quota_bytes":1,"x":"`+strings.Repeat("a", 5000)+`"}`); st != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize body: %d, want 413", st)
	}

	// A proper PUT: applied, answered with the new policy, audited with old and new.
	st, b = c.put("owner", path, good)
	if st != http.StatusOK || jsonOf(t, b)["retention_days"].(float64) != 30 || jsonOf(t, b)["enabled"] != true {
		t.Fatalf("PUT: %d %s", st, b)
	}
	if p := cur(); p.RetentionDays != 30 || p.QuotaBytes != 21474836480 {
		t.Fatalf("stored policy = %+v", p)
	}
	rows := c.rows("tenant.recording_policy.set")
	if len(rows) != 1 || rows[0].ActorUserID != "u-owner" || rows[0].TargetKind != "tenant" {
		t.Fatalf("audit rows = %+v", rows)
	}
	var meta struct {
		Old, New map[string]float64
	}
	_ = json.Unmarshal(rows[0].Metadata, &meta)
	if meta.Old["retention_days"] != 0 || meta.New["retention_days"] != 30 || meta.New["quota_bytes"] != 21474836480 {
		t.Errorf("audit metadata = %s", rows[0].Metadata)
	}
	// 0 turns it off again (allowed), also audited.
	if st, _ := c.put("owner", path, `{"retention_days":0,"max_recording_bytes":1073741824,"quota_bytes":21474836480}`); st != http.StatusOK || cur().Enabled() {
		t.Fatalf("PUT 0: %d enabled=%v", st, cur().Enabled())
	}
	if len(c.rows("tenant.recording_policy.set")) != 2 {
		t.Error("turning storage off was not audited")
	}

	// AUDIT FIRST: when the audit row cannot be written the policy does not change.
	c.audit.failRecord.Store(true)
	st, b = c.put("owner", path, good)
	c.audit.failRecord.Store(false)
	if st != http.StatusInternalServerError || cur().Enabled() {
		t.Fatalf("PUT with the audit store down: %d enabled=%v (%s) — the change must not be applied unaudited", st, cur().Enabled(), b)
	}
}

// failPolicyStore fails SetPolicy (a database error after the audit row was written).
type failPolicyStore struct{ RecordingStore }

func (failPolicyStore) SetPolicy(context.Context, string, RecordingPolicy) error {
	return errors.New("simulated policy write failure")
}

func TestConsolePolicyWriteFailureWritesACompensatingAuditRow(t *testing.T) {
	c := newConsoleH(t)
	ctx := context.Background()
	c.store.SetPolicy(ctx, c.tenant, DefaultRecordingPolicy())
	c.srv.Recording.Store = failPolicyStore{c.store}
	good := `{"retention_days":30,"max_recording_bytes":1073741824,"quota_bytes":21474836480}`
	st, b := c.put("owner", "/tenant/recording-policy", good)
	if st != http.StatusInternalServerError {
		t.Fatalf("PUT with a failing store: %d %s", st, b)
	}
	if p, _ := c.store.GetPolicy(ctx, c.tenant); p.Enabled() {
		t.Fatal("the policy changed")
	}
	if n := len(c.rows("tenant.recording_policy.set")); n != 1 {
		t.Fatalf("audit-first row missing: %d", n)
	}
	rows := c.rows("tenant.recording_policy.set_failed")
	if len(rows) != 1 || rows[0].ActorUserID != "u-owner" || rows[0].TargetKind != "tenant" {
		t.Fatalf("compensating rows = %+v", rows)
	}
	var meta struct {
		Reason   string
		Old, New map[string]float64
	}
	_ = json.Unmarshal(rows[0].Metadata, &meta)
	if meta.Reason != "store_write_failed" || meta.New["retention_days"] != 30 || meta.Old["retention_days"] != 0 {
		t.Errorf("compensating metadata = %s", rows[0].Metadata)
	}
	if strings.Contains(string(rows[0].Metadata), "simulated") {
		t.Error("the error text leaked into the audit row")
	}
	// If that audit write fails too, the answer is still the 500 and nothing panics.
	c.audit.failRecord.Store(true)
	st, _ = c.put("owner", "/tenant/recording-policy", good)
	c.audit.failRecord.Store(false)
	if st != http.StatusInternalServerError {
		t.Fatalf("audit down: %d", st)
	}
}

func TestConsoleRoutesAreAbsentWhenRecordingIsNotFullyWired(t *testing.T) {
	// No management audit store: recordings could be served unaudited, so the routes do not exist.
	c := newConsoleH(t)
	c.srv.MgmtAudit = nil
	srvTS := httptestFor(t, c)
	for _, p := range []string{"/recordings", "/recordings/" + newUUID(), "/recordings/" + newUUID() + "/playlist"} {
		if st := srvTS(p); st != http.StatusNotFound {
			t.Errorf("without an audit store, GET %s = %d, want 404 (route absent)", p, st)
		}
	}
	// No recording store at all: not even the policy routes.
	c2 := newConsoleH(t)
	c2.srv.Recording.Store = nil
	if st := httptestFor(t, c2)("/tenant/recording-policy"); st != http.StatusNotFound {
		t.Errorf("without a store, GET policy = %d, want 404", st)
	}
}

// httptestFor serves c.srv's CURRENT handler (routes mount when Handler() is built) and returns a GET
// helper that reports the status for the owner principal.
func httptestFor(t *testing.T, c *consoleH) func(path string) int {
	ts := newTestHTTPServer(t, c.srv.Handler())
	return func(path string) int {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		req.Header.Set("X-Test-Principal", "owner")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
}

func newTestHTTPServer(t *testing.T, h http.Handler) *httptest.Server {
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

// A handler that has already sent part of a response aborts with http.ErrAbortHandler; the recover layer
// must let that through (the connection is dropped) and keep turning every OTHER panic into a 500.
func TestRecoverMiddlewareLetsErrAbortHandlerThrough(t *testing.T) {
	s := &Server{}
	abort := s.recoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("partial"))
		panic(http.ErrAbortHandler)
	}))
	func() {
		defer func() {
			if rec := recover(); rec != http.ErrAbortHandler {
				t.Fatalf("recover() = %v, want http.ErrAbortHandler to propagate", rec)
			}
		}()
		abort.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	}()
	boom := s.recoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	w := httptest.NewRecorder()
	boom.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("an ordinary panic gave %d, want 500", w.Code)
	}
}

// The nostore guard (nostore_test.go) allow-lists the recording stream writers on the promise that every
// recording route sets `Cache-Control: private, no-store` itself. Pin the promise at the source: the
// helper sets it, and EVERY handler in the file starts by calling it (directly or through recViewer).
func TestRecordingRoutesAreNoStoreAndTheRawWritersSayWhy(t *testing.T) {
	for _, f := range []string{"http_recording_playback.go", "http_recording_policy.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		if f == "http_recording_playback.go" && !strings.Contains(src, `h.Set("Cache-Control", "private, no-store")`) {
			t.Errorf("%s: recNoStore no longer sets Cache-Control: private, no-store", f)
		}
		for _, h := range regexp.MustCompile(`(?m)^func \(s \*Server\) (handle\w+)\(w http\.ResponseWriter, r \*http\.Request\) \{\n(.*)\n`).FindAllStringSubmatch(src, -1) {
			if !strings.Contains(h[2], "s.recViewer(w, r)") && !strings.Contains(h[2], "recNoStore(w)") {
				t.Errorf("%s: %s does not begin with recViewer / recNoStore: %q", f, h[1], h[2])
			}
		}
	}
}

// The ZIP is only ever the verified evidence: if the bytes that decrypt no longer match the digest finish
// verified (the database says something else than the volume holds), the transfer must fail rather than
// complete — AEAD alone cannot catch that, the digest comparison can.
func TestConsoleDownloadAbortsWhenTheEvidenceNoLongerMatchesItsVerifiedDigest(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	c.store.mu.Lock()
	c.store.rows[recKey(c.tenant, fx.u.id)].Segments[0].SHA256 = strings.Repeat("ab", 32)
	c.store.mu.Unlock()
	req, _ := http.NewRequest("GET", c.ts.URL+fx.path("/download"), nil)
	req.Header.Set("X-Test-Principal", "owner")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return // the connection was dropped before headers: also a failed transfer
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(resp.Body)
	if rerr == nil {
		if _, zerr := zip.NewReader(bytes.NewReader(body), int64(len(body))); zerr == nil {
			t.Fatal("evidence that does not match its verified digest was delivered as a valid ZIP")
		}
	}
}

// ---- session context on the list/detail, and recording_id on the session list ----------------

// enrichSession gives the harness's session the fields a real one has (the in-memory store keeps whatever it is
// handed; pg resolves the machine columns by JOIN) and makes its technician a real user.
func (c *consoleH) enrichSession(displayName string) {
	c.t.Helper()
	c.sessions.mu.Lock()
	r := c.sessions.records[sessionRecordKey(c.tenant, c.session)]
	ended := r.StartedAt.Add(30 * time.Minute)
	r.MachineGroupID, r.MachineName, r.MachineAlias, r.EndedAt = c.machine.GroupID, "rec-box", "Front desk", &ended
	c.sessions.mu.Unlock()
	us := NewInMemoryUserStore()
	us.AddUser(&AuthUser{ID: auditTechUser, TenantID: c.tenant, Email: "tess@example.test", DisplayName: displayName},
		NewGrant(auditTechUser, c.tenant, NewMembership(RoleTechnician, AllGroups())))
	c.srv.AuthAPI = &AuthService{Users: us}
}

func TestConsoleListAndDetailCarryTheSessionContext(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	c.enrichSession("Tess Tech")

	check := func(what string, m map[string]any, tech string) {
		t.Helper()
		for k, want := range map[string]any{"machine_name": "rec-box", "machine_alias": "Front desk", "technician_id": auditTechUser, "technician_name": tech} {
			if m[k] != want {
				t.Errorf("%s: %s = %v, want %v", what, k, m[k], want)
			}
		}
		for _, k := range []string{"session_started_at", "session_ended_at"} {
			if s, _ := m[k].(string); s == "" {
				t.Errorf("%s: %s missing", what, k)
			}
		}
	}
	st, _, b := c.get("auditor", "/recordings")
	if st != http.StatusOK {
		t.Fatalf("list: %d %s", st, b)
	}
	check("list", jsonOf(t, b)["recordings"].([]any)[0].(map[string]any), "Tess Tech")
	st, _, b = c.get("scoped", fx.path(""))
	if st != http.StatusOK {
		t.Fatalf("detail: %d %s", st, b)
	}
	check("detail", jsonOf(t, b), "Tess Tech")

	// No display name: the email stands in. An unresolvable user: the id stays, the name is simply absent.
	c.enrichSession("")
	_, _, b = c.get("auditor", "/recordings")
	if got := jsonOf(t, b)["recordings"].([]any)[0].(map[string]any)["technician_name"]; got != "tess@example.test" {
		t.Errorf("technician_name without a display name = %v", got)
	}
	c.srv.AuthAPI = &AuthService{Users: NewInMemoryUserStore()}
	_, _, b = c.get("auditor", "/recordings")
	row := jsonOf(t, b)["recordings"].([]any)[0].(map[string]any)
	if _, has := row["technician_name"]; has || row["technician_id"] != auditTechUser {
		t.Errorf("unknown user: %v", row)
	}
	// A scoped viewer of ANOTHER group still gets nothing (the join runs only after rule 4).
	if st, _, b := c.get("scoped-other", "/recordings"); st != http.StatusOK || strings.Contains(string(b), "rec-box") || strings.Contains(string(b), auditTechUser) {
		t.Errorf("out-of-scope list leaks session context: %d %s", st, b)
	}
}

func TestSessionListNamesTheRecordingOnlyToViewRecordingsInThatGroup(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	c.enrichSession("Tess Tech")

	rowFor := func(who string) (map[string]any, bool, string) {
		t.Helper()
		st, _, b := c.get(who, "/sessions")
		if st != http.StatusOK {
			t.Fatalf("%s: GET /sessions = %d %s", who, st, b)
		}
		for _, r := range jsonOf(t, b)["sessions"].([]any) {
			if m := r.(map[string]any); m["id"] == c.session {
				return m, true, string(b)
			}
		}
		return nil, false, string(b)
	}
	// Holders of view_recordings over the machine's group get the id (and only the id of THIS session's recording).
	for _, who := range []string{"owner", "admin", "auditor", "scoped"} {
		row, ok, _ := rowFor(who)
		if !ok || row["recording_id"] != fx.u.id {
			t.Errorf("%s: recording_id = %v (listed=%v), want %s", who, row["recording_id"], ok, fx.u.id)
		}
	}
	// The ASYMMETRIC cases: they can list the session (view_sessions on its group) but hold no view_recordings
	// over it, so the field is ABSENT (not null, not empty) and the id appears nowhere in the body.
	for _, who := range []string{"technician", "readonly", "tech+scoped-auditor", "token"} {
		row, ok, body := rowFor(who)
		if !ok {
			t.Errorf("%s cannot list the session at all; the case proves nothing", who)
			continue
		}
		if _, has := row["recording_id"]; has {
			t.Errorf("%s: recording_id present for a caller without view_recordings on that group: %v", who, row["recording_id"])
		}
		if strings.Contains(body, fx.u.id) || strings.Contains(body, "recording_id") {
			t.Errorf("%s: the recording leaks into the session list: %s", who, body)
		}
	}
	// A scoped viewer of another group does not even see the session.
	if _, ok, body := rowFor("scoped-other"); ok || strings.Contains(body, fx.u.id) {
		t.Errorf("scoped-other: listed=%v body=%s", ok, body)
	}
	// A session with no recording has no field, for a holder too.
	other := &SessionRecord{TenantID: c.tenant, MachineID: c.machine.ID, TechnicianID: auditTechUser, StartedAt: time.Now(), MachineGroupID: c.machine.GroupID}
	if err := c.sessions.StartSession(context.Background(), c.tenant, other); err != nil {
		t.Fatal(err)
	}
	_, _, b := c.get("owner", "/sessions")
	for _, r := range jsonOf(t, b)["sessions"].([]any) {
		if m := r.(map[string]any); m["id"] == other.ID {
			if _, has := m["recording_id"]; has {
				t.Errorf("a session with no recording carries recording_id: %v", m)
			}
		}
	}
	// Not fully wired (no audit store): the field is gone for everyone.
	c.srv.MgmtAudit = nil
	if row, ok, _ := rowFor("owner"); !ok {
		t.Fatal("owner lost the session list")
	} else if _, has := row["recording_id"]; has {
		t.Error("recording_id served while recording is not fully wired")
	}
}

// The session row keeps its session-time group, but recording_id follows the machine's CURRENT group like the
// recording routes do: a move out of scope, a deleted machine or a machine-store failure hides it from a scoped
// viewer who can still list the session, while a tenant-wide holder keeps it.
func TestSessionListRecordingIDFollowsTheMachinesCurrentGroup(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	c.enrichSession("Tess Tech")

	rowFor := func(who string) (map[string]any, string) {
		t.Helper()
		st, _, b := c.get(who, "/sessions")
		if st != http.StatusOK {
			t.Fatalf("%s: GET /sessions = %d %s", who, st, b)
		}
		for _, r := range jsonOf(t, b)["sessions"].([]any) {
			if m := r.(map[string]any); m["id"] == c.session {
				return m, string(b)
			}
		}
		t.Fatalf("%s cannot list the session at all; the case proves nothing", who)
		return nil, ""
	}
	expect := func(when string) {
		t.Helper()
		if row, _ := rowFor("owner"); row["recording_id"] != fx.u.id {
			t.Errorf("%s: tenant-wide owner recording_id = %v, want %s", when, row["recording_id"], fx.u.id)
		}
		if row, body := rowFor("scoped"); row["recording_id"] != nil || strings.Contains(body, fx.u.id) {
			t.Errorf("%s: the old group's auditor still learns the recording: %v", when, row["recording_id"])
		}
	}
	if row, _ := rowFor("scoped"); row["recording_id"] != fx.u.id {
		t.Fatalf("premise: scoped recording_id = %v before the move, want %s", row["recording_id"], fx.u.id)
	}
	if err := c.machines.SetMachineGroup(context.Background(), c.tenant, c.machine.ID, c.otherGroup); err != nil {
		t.Fatal(err)
	}
	expect("after the move")
	c.srv.Machines = hiddenMachines{MachineStore: c.machines, hidden: map[string]bool{c.machine.ID: true}}
	expect("machine deleted")
	c.srv.Machines = brokenMachines{c.machines}
	expect("machine store down")
}
