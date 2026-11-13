package controlplane

// Handler-level and dispatcher proofs for the webhook subsystem (docs/01 §8, migration 0047).
//
// What is covered here:
//   - Capability gate: CapManageTenant required for all three HTTP verbs
//   - Lifecycle: POST creates + returns secret once; GET lists without secret; DELETE idempotent
//   - Input validation: blank URL, non-http/https URL, blank event, per-tenant cap
//   - Dispatcher routing: fires on matching event, skips non-matching, subscribes to all when empty
//   - HMAC: signature header value is correct and mutation-testable
//   - Store isolation: tenant-A's webhooks are invisible to tenant-B
//
// RLS / SQL column-agreement properties live in the pgstore integration suite.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- helpers ---------------------------------------------------------------

// webhookOwnerServer creates a single-server-instance with an Owner principal for lifecycle tests.
func webhookOwnerServer(t *testing.T) *Server {
	t.Helper()
	p := &Principal{
		UserID:   "owner-1",
		TenantID: "tenant-wh",
		Grant:    NewGrant("owner-1", "tenant-wh", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)
	return srv
}

// doWhReq fires a single one-shot request under the given role.
func doWhReq(t *testing.T, role Role, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(role, AllGroups())),
	}
	srv, _ := newTestServer(p)
	rec := httptest.NewRecorder()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// ---- capability gate -------------------------------------------------------

func TestWebhookRequiresManageTenant(t *testing.T) {
	const validBody = `{"url":"https://example.com/hook","events":["session.start"]}`
	cases := []struct {
		role   Role
		method string
		path   string
		body   string
		want   int
	}{
		// GET
		{RoleOwner, "GET", "/tenant/webhooks", "", http.StatusOK},
		{RoleAdmin, "GET", "/tenant/webhooks", "", http.StatusForbidden},
		{RoleTechnician, "GET", "/tenant/webhooks", "", http.StatusForbidden},
		{RoleReadOnly, "GET", "/tenant/webhooks", "", http.StatusForbidden},
		// POST — Owner passes the cap gate, then hits validation (any non-403 means the gate opened)
		{RoleOwner, "POST", "/tenant/webhooks", validBody, http.StatusCreated},
		{RoleAdmin, "POST", "/tenant/webhooks", validBody, http.StatusForbidden},
		{RoleTechnician, "POST", "/tenant/webhooks", validBody, http.StatusForbidden},
		// DELETE — Owner passes the cap gate, then returns 204 for a non-existent id (idempotent)
		{RoleOwner, "DELETE", "/tenant/webhooks/no-such-id", "", http.StatusNoContent},
		{RoleAdmin, "DELETE", "/tenant/webhooks/no-such-id", "", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(string(tc.role)+"_"+tc.method, func(t *testing.T) {
			rec := doWhReq(t, tc.role, tc.method, tc.path, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("%s %s as %s = %d, want %d (body %s)",
					tc.method, tc.path, tc.role, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// ---- lifecycle: create → list → delete → delete-again ---------------------

func TestWebhookLifecycle(t *testing.T) {
	srv := webhookOwnerServer(t)
	h := srv.Handler()

	// CREATE — expect 201 with the secret field present.
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, httptest.NewRequest("POST", "/tenant/webhooks",
		strings.NewReader(`{"url":"https://hooks.example.com/recv","events":["session.start","session.end"]}`)))
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (body %s)", createRec.Code, createRec.Body.String())
	}
	var createResp struct {
		Webhook struct {
			ID        string   `json:"id"`
			URL       string   `json:"url"`
			Events    []string `json:"events"`
			CreatedAt string   `json:"created_at"`
			Secret    string   `json:"secret"`
		} `json:"webhook"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	wh := createResp.Webhook
	if wh.ID == "" {
		t.Fatal("create response must include id")
	}
	if wh.URL != "https://hooks.example.com/recv" {
		t.Fatalf("url = %q, want the submitted value", wh.URL)
	}
	if len(wh.Events) != 2 {
		t.Fatalf("events = %v, want 2", wh.Events)
	}
	if wh.Secret == "" {
		t.Fatal("create response must include secret (shown once)")
	}
	// 32 random bytes → 64 hex characters.
	if len(wh.Secret) != webhookSecretLen*2 {
		t.Fatalf("secret length = %d, want %d hex characters", len(wh.Secret), webhookSecretLen*2)
	}
	id := wh.ID

	// LIST — webhook appears, secret field must be absent.
	listRec := httptest.NewRecorder()
	h.ServeHTTP(listRec, httptest.NewRequest("GET", "/tenant/webhooks", nil))
	if listRec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body %s)", listRec.Code, listRec.Body.String())
	}
	var listResp struct {
		Webhooks []json.RawMessage `json:"webhooks"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listResp.Webhooks) != 1 {
		t.Fatalf("list count = %d, want 1", len(listResp.Webhooks))
	}
	rawItem := string(listResp.Webhooks[0])
	if strings.Contains(rawItem, `"secret"`) {
		t.Fatalf("list response must NOT contain secret field; got: %s", rawItem)
	}

	// DELETE — expect 204.
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, httptest.NewRequest("DELETE", "/tenant/webhooks/"+id, nil))
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204 (body %s)", delRec.Code, delRec.Body.String())
	}

	// DELETE again — idempotent: still 204.
	del2Rec := httptest.NewRecorder()
	h.ServeHTTP(del2Rec, httptest.NewRequest("DELETE", "/tenant/webhooks/"+id, nil))
	if del2Rec.Code != http.StatusNoContent {
		t.Fatalf("delete (idempotent) = %d, want 204", del2Rec.Code)
	}

	// LIST after delete — must be empty.
	list2Rec := httptest.NewRecorder()
	h.ServeHTTP(list2Rec, httptest.NewRequest("GET", "/tenant/webhooks", nil))
	var list2Resp struct {
		Webhooks []json.RawMessage `json:"webhooks"`
	}
	if err := json.Unmarshal(list2Rec.Body.Bytes(), &list2Resp); err != nil {
		t.Fatalf("decode list2 response: %v", err)
	}
	if len(list2Resp.Webhooks) != 0 {
		t.Fatalf("after delete, list count = %d, want 0", len(list2Resp.Webhooks))
	}
}

// ---- input validation ------------------------------------------------------

func TestWebhookCreateValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing url", `{"events":["session.start"]}`},
		{"blank url", `{"url":"   ","events":[]}`},
		{"ftp scheme", `{"url":"ftp://example.com/hook","events":[]}`},
		// http:// is blocked to prevent SSRF probing of internal endpoints (IMDS, Postgres, etc.)
		{"http scheme blocked", `{"url":"http://example.com/hook","events":[]}`},
		{"no host", `{"url":"https://","events":[]}`},
		{"blank event string", `{"url":"https://example.com","events":["session.start",""]}`},
		{"event string too long", `{"url":"https://example.com","events":["` + strings.Repeat("x", maxWebhookEventLen+1) + `"]}`},
		{"too many events", `{"url":"https://example.com","events":["e1","e2","e3","e4","e5","e6","e7","e8","e9","e10","e11","e12","e13","e14","e15","e16","e17","e18","e19","e20","e21"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doWhReq(t, RoleOwner, "POST", "/tenant/webhooks", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%q = %d, want 400 (body %s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestWebhookPerTenantCap creates maxWebhooksPerTenant webhooks and verifies the next one returns 409.
func TestWebhookPerTenantCap(t *testing.T) {
	srv := webhookOwnerServer(t)
	h := srv.Handler()

	createOne := func(i int) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/tenant/webhooks",
			strings.NewReader(`{"url":"https://example.com/hook","events":[]}`)))
		return rec.Code
	}

	for i := 0; i < maxWebhooksPerTenant; i++ {
		if code := createOne(i); code != http.StatusCreated {
			t.Fatalf("webhook %d/%d: create = %d, want 201", i+1, maxWebhooksPerTenant, code)
		}
	}
	if code := createOne(maxWebhooksPerTenant); code != http.StatusConflict {
		t.Fatalf("webhook %d (over cap): create = %d, want 409", maxWebhooksPerTenant+1, code)
	}
}

// ---- dispatcher: event routing & HMAC signature ---------------------------

// captureServer returns a test HTTP server that records all received POST requests.
type webhookCapture struct {
	mu   sync.Mutex
	reqs []struct {
		signature string
		webhookID string
		body      []byte
	}
}

func (c *webhookCapture) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reqs)
}

func (c *webhookCapture) at(i int) (sig, id string, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.reqs[i]
	return r.signature, r.webhookID, r.body
}

func newWebhookCaptureServer(t *testing.T) (*httptest.Server, *webhookCapture) {
	t.Helper()
	cap := &webhookCapture{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		cap.mu.Lock()
		cap.reqs = append(cap.reqs, struct {
			signature string
			webhookID string
			body      []byte
		}{
			signature: r.Header.Get("X-DeskRally-Signature"),
			webhookID: r.Header.Get("X-DeskRally-Webhook-ID"),
			body:      body,
		})
		cap.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return ts, cap
}

func TestDispatcherFiresOnMatchingEvent(t *testing.T) {
	ts, cap := newWebhookCaptureServer(t)

	store := NewInMemoryWebhookStore()
	const tenantID = "t-fire"
	const secret = "deadbeefcafe"
	wh := &TenantWebhook{
		ID:        "wh-fire",
		URL:       ts.URL,
		Events:    []string{"session.start"},
		CreatedAt: time.Now().UTC(),
	}
	if err := store.Create(context.Background(), tenantID, wh, secret, maxWebhooksPerTenant); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	d := &WebhookDispatcher{Store: store, Client: ts.Client()}
	e := &MgmtAuditEvent{
		ID:         "evt-fire",
		TenantID:   tenantID,
		Action:     "session.start",
		OccurredAt: time.Now().UTC(),
	}
	if err := d.dispatchSync(tenantID, e); err != nil {
		t.Fatalf("dispatchSync: %v", err)
	}

	if cap.len() != 1 {
		t.Fatalf("delivery count = %d, want 1", cap.len())
	}
	sig, whID, body := cap.at(0)

	// Webhook ID header must match.
	if whID != "wh-fire" {
		t.Fatalf("X-DeskRally-Webhook-ID = %q, want wh-fire", whID)
	}

	// HMAC signature must be correct.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig != wantSig {
		t.Fatalf("X-DeskRally-Signature = %q, want %q", sig, wantSig)
	}

	// Body must deserialize to the sent event.
	var decoded MgmtAuditEvent
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode webhook body: %v", err)
	}
	if decoded.ID != e.ID || decoded.Action != "session.start" {
		t.Fatalf("decoded event = %+v, want id=%s action=session.start", decoded, e.ID)
	}
}

func TestDispatcherSkipsNonMatchingEvent(t *testing.T) {
	ts, cap := newWebhookCaptureServer(t)

	store := NewInMemoryWebhookStore()
	const tenantID = "t-skip"
	wh := &TenantWebhook{
		ID:        "wh-skip",
		URL:       ts.URL,
		Events:    []string{"machine.enroll"}, // only machine.enroll, not session.start
		CreatedAt: time.Now().UTC(),
	}
	if err := store.Create(context.Background(), tenantID, wh, "secret", maxWebhooksPerTenant); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	d := &WebhookDispatcher{Store: store, Client: ts.Client()}
	e := &MgmtAuditEvent{Action: "session.start", TenantID: tenantID}
	if err := d.dispatchSync(tenantID, e); err != nil {
		t.Fatalf("dispatchSync: %v", err)
	}

	if cap.len() != 0 {
		t.Fatalf("webhook subscribed to machine.enroll received session.start: %d deliveries, want 0", cap.len())
	}
}

func TestDispatcherSubscribeAll(t *testing.T) {
	ts, cap := newWebhookCaptureServer(t)

	store := NewInMemoryWebhookStore()
	const tenantID = "t-all"
	wh := &TenantWebhook{
		ID:        "wh-all",
		URL:       ts.URL,
		Events:    []string{}, // empty = subscribe to every event
		CreatedAt: time.Now().UTC(),
	}
	if err := store.Create(context.Background(), tenantID, wh, "secret", maxWebhooksPerTenant); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	d := &WebhookDispatcher{Store: store, Client: ts.Client()}
	events := []string{"session.start", "machine.enroll", "webhook.delete"}
	for _, action := range events {
		e := &MgmtAuditEvent{Action: action, TenantID: tenantID}
		if err := d.dispatchSync(tenantID, e); err != nil {
			t.Fatalf("dispatchSync(%s): %v", action, err)
		}
	}

	if cap.len() != len(events) {
		t.Fatalf("subscribe-all: delivery count = %d, want %d", cap.len(), len(events))
	}
}

// ---- HMAC mutation probe ---------------------------------------------------

// TestHMACSignatureCorrectness verifies the signature value against raw HMAC-SHA256.
// Any mutation that returns a constant, empty string, or wrong key breaks this test.
func TestHMACSignatureCorrectness(t *testing.T) {
	body := []byte(`{"action":"session.start","id":"evt-1"}`)
	const secret = "test-secret-value"

	got := webhookSignature(secret, body)

	if got == "" {
		t.Fatal("webhookSignature returned empty string")
	}

	// Compute expected value independently.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("webhookSignature = %q, want %q", got, want)
	}
}

// TestHMACDifferentSecretsDifferentSignatures kills mutations that ignore the secret.
func TestHMACDifferentSecretsDifferentSignatures(t *testing.T) {
	body := []byte(`{"action":"session.start"}`)
	sigA := webhookSignature("secret-alpha", body)
	sigB := webhookSignature("secret-beta", body)

	if sigA == sigB {
		t.Fatal("different secrets must produce different HMAC signatures")
	}
}

// ---- concurrent cap enforcement --------------------------------------------

// TestWebhookCreateConcurrentCapEnforcement proves that concurrent Creates cannot exceed
// the cap. This is the race that the TOCTOU fix targets: without the mutex-guarded count
// in InMemoryWebhookStore.Create, goroutines that pass the pre-insert check simultaneously
// all succeed, pushing the final count above maxWebhooksPerTenant.
//
// Mutation kill:
//   M1 — remove the `n >= cap` guard in Create → all concurrent Creates succeed →
//        successes > maxWebhooksPerTenant → t.Fatalf fires.
//   M2 — move the count loop outside the lock → race detector fires on s.rows read.
func TestWebhookCreateConcurrentCapEnforcement(t *testing.T) {
	const tenantID = "t-race"
	const total = maxWebhooksPerTenant + 5 // more requestors than the cap allows

	store := NewInMemoryWebhookStore()
	ctx := context.Background()

	type result struct{ err error }
	results := make(chan result, total)

	var ready sync.WaitGroup
	ready.Add(total)
	start := make(chan struct{})

	for i := 0; i < total; i++ {
		i := i
		go func() {
			ready.Done()
			<-start // wait until all goroutines are ready to maximise contention
			wh := &TenantWebhook{
				ID:        fmt.Sprintf("wh-%d", i),
				URL:       "https://race.example.com/hook",
				Events:    []string{},
				CreatedAt: time.Now().UTC(),
			}
			err := store.Create(ctx, tenantID, wh, "secret", maxWebhooksPerTenant)
			results <- result{err: err}
		}()
	}
	ready.Wait()
	close(start) // release all goroutines simultaneously

	var successes, capErrors int
	for i := 0; i < total; i++ {
		r := <-results
		switch {
		case r.err == nil:
			successes++
		case errors.Is(r.err, ErrWebhookCapExceeded):
			capErrors++
		default:
			t.Fatalf("unexpected error from Create: %v", r.err)
		}
	}
	if successes != maxWebhooksPerTenant {
		t.Fatalf("concurrent creates: %d succeeded, want exactly %d (cap)", successes, maxWebhooksPerTenant)
	}
	if capErrors != total-maxWebhooksPerTenant {
		t.Fatalf("concurrent creates: %d cap errors, want %d", capErrors, total-maxWebhooksPerTenant)
	}
	list, err := store.List(ctx, tenantID)
	if err != nil {
		t.Fatalf("List after concurrent creates: %v", err)
	}
	if len(list) != maxWebhooksPerTenant {
		t.Fatalf("final webhook count = %d, want %d (cap)", len(list), maxWebhooksPerTenant)
	}
}

// ---- delivery ring buffer --------------------------------------------------

func TestDeliveryRingBufferEmpty(t *testing.T) {
	d := &WebhookDispatcher{}
	recs := d.RecentDeliveries("wh-unknown")
	if recs == nil {
		t.Fatal("RecentDeliveries returned nil, want empty slice")
	}
	if len(recs) != 0 {
		t.Fatalf("RecentDeliveries = %d records, want 0", len(recs))
	}
}

func TestDeliveryRingBufferNewestFirst(t *testing.T) {
	d := &WebhookDispatcher{}
	const wid = "wh-order"
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	for _, ts := range []time.Time{t1, t2, t3} {
		d.recordDelivery(WebhookDeliveryRecord{WebhookID: wid, AttemptedAt: ts, Success: true})
	}
	recs := d.RecentDeliveries(wid)
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
	if !recs[0].AttemptedAt.Equal(t3) || !recs[1].AttemptedAt.Equal(t2) || !recs[2].AttemptedAt.Equal(t1) {
		t.Fatalf("records not newest-first: %v %v %v",
			recs[0].AttemptedAt, recs[1].AttemptedAt, recs[2].AttemptedAt)
	}
}

func TestDeliveryRingBufferCap(t *testing.T) {
	d := &WebhookDispatcher{}
	const wid = "wh-cap"
	for i := 0; i < webhookDeliveryRingSize+5; i++ {
		d.recordDelivery(WebhookDeliveryRecord{
			WebhookID: wid,
			Event:     fmt.Sprintf("evt-%d", i),
			Success:   true,
		})
	}
	recs := d.RecentDeliveries(wid)
	if len(recs) != webhookDeliveryRingSize {
		t.Fatalf("got %d records, want %d (cap)", len(recs), webhookDeliveryRingSize)
	}
	// Newest (last inserted) must be first.
	wantNewest := fmt.Sprintf("evt-%d", webhookDeliveryRingSize+4)
	if recs[0].Event != wantNewest {
		t.Fatalf("recs[0].Event = %q, want %q (newest)", recs[0].Event, wantNewest)
	}
	// Oldest (evt-0) must have been evicted.
	for _, r := range recs {
		if r.Event == "evt-0" {
			t.Fatal("oldest record evt-0 was not evicted")
		}
	}
}

func TestDeliveryRingBufferIsolation(t *testing.T) {
	d := &WebhookDispatcher{}
	d.recordDelivery(WebhookDeliveryRecord{WebhookID: "wh-iso-a", Event: "evt-a"})
	d.recordDelivery(WebhookDeliveryRecord{WebhookID: "wh-iso-b", Event: "evt-b"})

	ra := d.RecentDeliveries("wh-iso-a")
	rb := d.RecentDeliveries("wh-iso-b")
	if len(ra) != 1 || ra[0].Event != "evt-a" {
		t.Fatalf("wh-iso-a ring = %+v, want one evt-a record", ra)
	}
	if len(rb) != 1 || rb[0].Event != "evt-b" {
		t.Fatalf("wh-iso-b ring = %+v, want one evt-b record", rb)
	}
}

func TestDeleteRingEvictsEntry(t *testing.T) {
	d := &WebhookDispatcher{}
	d.recordDelivery(WebhookDeliveryRecord{WebhookID: "wh-evict", Event: "evt"})

	// Sanity: record is present before delete.
	if len(d.RecentDeliveries("wh-evict")) != 1 {
		t.Fatal("expected 1 record before DeleteRing")
	}
	d.DeleteRing("wh-evict")

	// After eviction: RecentDeliveries returns empty, not nil.
	recs := d.RecentDeliveries("wh-evict")
	if recs == nil {
		t.Fatal("RecentDeliveries returned nil after DeleteRing, want empty slice")
	}
	if len(recs) != 0 {
		t.Fatalf("got %d records after DeleteRing, want 0", len(recs))
	}
	// DeleteRing on an unknown ID is a no-op.
	d.DeleteRing("wh-nonexistent") // must not panic
}

// TestHandleDeleteWebhookEvictsDispatcherRing proves the HTTP delete path calls DeleteRing so
// the dispatcher's map entry is removed when the webhook is deleted.
func TestHandleDeleteWebhookEvictsDispatcherRing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	p := &Principal{
		UserID:   "owner-evict",
		TenantID: "tenant-evict",
		Grant:    NewGrant("owner-evict", "tenant-evict", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)
	ctx := context.Background()
	wh := &TenantWebhook{ID: "wh-to-delete", URL: ts.URL, Events: []string{}, CreatedAt: time.Now().UTC()}
	_ = srv.Webhooks.Create(ctx, "tenant-evict", wh, "secret", maxWebhooksPerTenant)

	d := &WebhookDispatcher{Store: srv.Webhooks, Client: ts.Client()}
	srv.Dispatcher = d
	// Plant a delivery record.
	d.recordDelivery(WebhookDeliveryRecord{WebhookID: "wh-to-delete", Event: "session.start"})
	if len(d.RecentDeliveries("wh-to-delete")) != 1 {
		t.Fatal("expected 1 record before delete")
	}

	// Delete the webhook via the HTTP handler.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/tenant/webhooks/wh-to-delete", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", rec.Code)
	}

	// Ring must be evicted.
	if len(d.RecentDeliveries("wh-to-delete")) != 0 {
		t.Fatal("delivery ring not evicted after webhook delete")
	}
}

// ---- dispatcher delivery recording ----------------------------------------

func TestDispatcherRecordsSuccessfulDelivery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	store := NewInMemoryWebhookStore()
	wh := &TenantWebhook{ID: "wh-ok", URL: ts.URL, Events: []string{}, CreatedAt: time.Now().UTC()}
	_ = store.Create(context.Background(), "t-ok", wh, "secret", maxWebhooksPerTenant)

	d := &WebhookDispatcher{Store: store, Client: ts.Client()}
	_ = d.dispatchSync("t-ok", &MgmtAuditEvent{Action: "session.start", TenantID: "t-ok"})

	recs := d.RecentDeliveries("wh-ok")
	if len(recs) != 1 {
		t.Fatalf("got %d delivery records, want 1", len(recs))
	}
	r := recs[0]
	if !r.Success {
		t.Error("Success = false, want true")
	}
	if r.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", r.StatusCode)
	}
	if r.Error != "" {
		t.Errorf("Error = %q, want empty", r.Error)
	}
	if r.Attempt != 1 {
		t.Errorf("Attempt = %d, want 1", r.Attempt)
	}
	if r.Event != "session.start" {
		t.Errorf("Event = %q, want session.start", r.Event)
	}
	if r.WebhookID != "wh-ok" {
		t.Errorf("WebhookID = %q, want wh-ok", r.WebhookID)
	}
}

func TestDispatcherRecordsBothAttemptsOnFailure(t *testing.T) {
	// Server always responds 500; both attempts are recorded.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(ts.Close)

	store := NewInMemoryWebhookStore()
	wh := &TenantWebhook{ID: "wh-fail", URL: ts.URL, Events: []string{}, CreatedAt: time.Now().UTC()}
	_ = store.Create(context.Background(), "t-fail", wh, "secret", maxWebhooksPerTenant)

	d := &WebhookDispatcher{Store: store, Client: ts.Client()}
	_ = d.dispatchSync("t-fail", &MgmtAuditEvent{Action: "session.start", TenantID: "t-fail"})

	recs := d.RecentDeliveries("wh-fail")
	if len(recs) != 2 {
		t.Fatalf("got %d delivery records, want 2 (attempt 1 + retry)", len(recs))
	}
	// Newest-first: attempt 2 at index 0.
	if recs[0].Attempt != 2 || recs[0].Success {
		t.Errorf("recs[0]: Attempt=%d Success=%v, want Attempt=2 Success=false", recs[0].Attempt, recs[0].Success)
	}
	if recs[1].Attempt != 1 || recs[1].Success {
		t.Errorf("recs[1]: Attempt=%d Success=%v, want Attempt=1 Success=false", recs[1].Attempt, recs[1].Success)
	}
	for _, r := range recs {
		if r.StatusCode != http.StatusInternalServerError {
			t.Errorf("attempt %d: StatusCode = %d, want 500", r.Attempt, r.StatusCode)
		}
		if r.Error == "" {
			t.Errorf("attempt %d: Error is empty, want non-empty", r.Attempt)
		}
	}
}

// TestDispatcherRecordsSuccessOnRetry proves attempt-1 failure + attempt-2 success
// each get their own record with the correct Success field.
func TestDispatcherRecordsSuccessOnRetry(t *testing.T) {
	var mu sync.Mutex
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n := callCount
		callCount++
		mu.Unlock()
		if n == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(ts.Close)

	store := NewInMemoryWebhookStore()
	wh := &TenantWebhook{ID: "wh-retry", URL: ts.URL, Events: []string{}, CreatedAt: time.Now().UTC()}
	_ = store.Create(context.Background(), "t-retry", wh, "secret", maxWebhooksPerTenant)

	d := &WebhookDispatcher{Store: store, Client: ts.Client()}
	_ = d.dispatchSync("t-retry", &MgmtAuditEvent{Action: "machine.enroll", TenantID: "t-retry"})

	recs := d.RecentDeliveries("wh-retry")
	if len(recs) != 2 {
		t.Fatalf("got %d delivery records, want 2", len(recs))
	}
	// Newest-first: attempt 2 (success) at index 0.
	if !recs[0].Success || recs[0].Attempt != 2 {
		t.Errorf("recs[0]: Success=%v Attempt=%d, want Success=true Attempt=2", recs[0].Success, recs[0].Attempt)
	}
	if recs[1].Success || recs[1].Attempt != 1 {
		t.Errorf("recs[1]: Success=%v Attempt=%d, want Success=false Attempt=1", recs[1].Success, recs[1].Attempt)
	}
}

// ---- handler: GET /tenant/webhooks/{id}/deliveries -------------------------

func TestHandleListWebhookDeliveries_RequiresManageTenant(t *testing.T) {
	rec := doWhReq(t, RoleTechnician, http.MethodGet, "/tenant/webhooks/any-id/deliveries", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestHandleListWebhookDeliveries_NotFound(t *testing.T) {
	rec := doWhReq(t, RoleOwner, http.MethodGet, "/tenant/webhooks/nonexistent-wh/deliveries", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleListWebhookDeliveries_EmptyNoDispatcher(t *testing.T) {
	p := &Principal{
		UserID:   "owner-d1",
		TenantID: "tenant-d1",
		Grant:    NewGrant("owner-d1", "tenant-d1", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)
	ctx := context.Background()
	wh := &TenantWebhook{ID: "wh-nd", URL: "https://recv.example.com/hook", Events: []string{}, CreatedAt: time.Now().UTC()}
	_ = srv.Webhooks.Create(ctx, "tenant-d1", wh, "secret", maxWebhooksPerTenant)
	// srv.Dispatcher is nil.

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tenant/webhooks/wh-nd/deliveries", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Deliveries []WebhookDeliveryRecord `json:"deliveries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Deliveries == nil {
		t.Fatal("deliveries field is null, want empty array []")
	}
	if len(resp.Deliveries) != 0 {
		t.Fatalf("got %d deliveries, want 0", len(resp.Deliveries))
	}
}

func TestHandleListWebhookDeliveries_WithRecords(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	p := &Principal{
		UserID:   "owner-d2",
		TenantID: "tenant-d2",
		Grant:    NewGrant("owner-d2", "tenant-d2", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)
	ctx := context.Background()
	wh := &TenantWebhook{ID: "wh-d2", URL: ts.URL, Events: []string{}, CreatedAt: time.Now().UTC()}
	_ = srv.Webhooks.Create(ctx, "tenant-d2", wh, "secret", maxWebhooksPerTenant)

	d := &WebhookDispatcher{Store: srv.Webhooks, Client: ts.Client()}
	srv.Dispatcher = d
	_ = d.dispatchSync("tenant-d2", &MgmtAuditEvent{Action: "session.start", TenantID: "tenant-d2"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tenant/webhooks/wh-d2/deliveries", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Deliveries []WebhookDeliveryRecord `json:"deliveries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Deliveries) != 1 {
		t.Fatalf("got %d deliveries, want 1", len(resp.Deliveries))
	}
	dr := resp.Deliveries[0]
	if !dr.Success || dr.Event != "session.start" || dr.WebhookID != "wh-d2" {
		t.Fatalf("delivery = %+v, want success, event=session.start, webhook=wh-d2", dr)
	}
}

// ---- store isolation -------------------------------------------------------

func TestWebhookStoreIsolation(t *testing.T) {
	store := NewInMemoryWebhookStore()
	ctx := context.Background()

	whA := &TenantWebhook{ID: "wh-a", URL: "https://a.example.com", Events: []string{}, CreatedAt: time.Now().UTC()}
	whB := &TenantWebhook{ID: "wh-b", URL: "https://b.example.com", Events: []string{}, CreatedAt: time.Now().UTC()}

	if err := store.Create(ctx, "tenant-a", whA, "secA", maxWebhooksPerTenant); err != nil {
		t.Fatalf("Create A: %v", err)
	}
	if err := store.Create(ctx, "tenant-b", whB, "secB", maxWebhooksPerTenant); err != nil {
		t.Fatalf("Create B: %v", err)
	}

	aList, _ := store.List(ctx, "tenant-a")
	if len(aList) != 1 || aList[0].ID != "wh-a" {
		t.Fatalf("tenant-a list = %+v, want just wh-a", aList)
	}

	bList, _ := store.List(ctx, "tenant-b")
	if len(bList) != 1 || bList[0].ID != "wh-b" {
		t.Fatalf("tenant-b list = %+v, want just wh-b", bList)
	}

	// ListDeliveriesForEvent is also tenant-scoped.
	delA, _ := store.ListDeliveriesForEvent(ctx, "tenant-a", "any.event")
	if len(delA) != 1 || delA[0].ID != "wh-a" || delA[0].Secret != "secA" {
		t.Fatalf("tenant-a deliveries = %+v, want just wh-a with secret secA", delA)
	}

	delB, _ := store.ListDeliveriesForEvent(ctx, "tenant-b", "any.event")
	if len(delB) != 1 || delB[0].ID != "wh-b" || delB[0].Secret != "secB" {
		t.Fatalf("tenant-b deliveries = %+v, want just wh-b with secret secB", delB)
	}

	// Delete in tenant-A must not affect tenant-B.
	if found, err := store.Delete(ctx, "tenant-a", "wh-a"); err != nil || !found {
		t.Fatalf("Delete A: found=%v err=%v", found, err)
	}
	bList2, _ := store.List(ctx, "tenant-b")
	if len(bList2) != 1 {
		t.Fatalf("tenant-b list after deleting tenant-a's webhook = %d rows, want 1", len(bList2))
	}
}
