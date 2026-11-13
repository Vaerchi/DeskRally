package controlplane

// Webhook delivery infrastructure — per-tenant HTTP endpoints that receive a POST whenever
// a management-plane audit event occurs (docs/01 §8 "Webhooks / event-driven triggers").
//
// The design is fire-and-forget with one retry:
//   1. Dispatch is called from recordMgmtAudit (after the audit write succeeds); it only ENQUEUES onto a
//      bounded per-tenant queue drained by a fixed worker pool (a full queue drops the event: webhook_dropped).
//   2. The dispatcher fetches matching webhook URLs + secrets via WebhookStore.ListDeliveriesForEvent.
//   3. Each delivery gets a 5 s HTTP timeout, one retry after 1 s on failure, then gives up; one event's
//      whole fan-out shares a 20 s deadline.
//
// A persistent delivery queue is intentionally NOT built: this is an automation convenience
// for operators, not a guaranteed-delivery message bus. Operators who need guaranteed delivery
// should consume the audit trail via GET /audit/export (an append-only, cursor-paged NDJSON export).

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ErrWebhookCapExceeded is returned by WebhookStore.Create when the per-tenant cap
// (maxWebhooksPerTenant) has already been reached. The check and the insert happen
// in the same atomic operation so concurrent creates cannot exceed the cap.
var ErrWebhookCapExceeded = errors.New("webhook cap exceeded")

// --- types ------------------------------------------------------------------

// TenantWebhook is a registered webhook endpoint. The secret field is withheld from all
// API responses (it is only returned once, in CreatedWebhook, at creation time).
type TenantWebhook struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"`    // empty = subscribe to all events
	CreatedAt time.Time `json:"created_at"`
}

// CreatedWebhook wraps TenantWebhook with the one-time signing secret.
// Only returned by the POST /tenant/webhooks handler; never by GET.
type CreatedWebhook struct {
	TenantWebhook
	Secret string `json:"secret"`
}

// WebhookDelivery is a dispatch-time view: the id, URL, and signing secret needed to deliver
// one event. Returned by WebhookStore.ListDeliveriesForEvent. The secret is withheld from
// TenantWebhook (the API-visible type) but must be present here for HMAC signing.
type WebhookDelivery struct {
	ID     string
	URL    string
	Secret string
}

// --- limits -----------------------------------------------------------------

const (
	// maxWebhooksPerTenant caps how many webhook endpoints one tenant may register.
	maxWebhooksPerTenant = 10
	// maxWebhookEvents caps how many event strings one webhook subscription may list.
	maxWebhookEvents = 20
	// maxWebhookEventLen is the maximum length (bytes) of one event name string.
	// Prevents unbounded strings being stored in the TEXT[] column and scanned on every audit event.
	maxWebhookEventLen = 128
	// maxWebhookURLLen is the maximum URL length (matched by the DB CHECK constraint in 0047).
	maxWebhookURLLen = 2048
	// webhookSecretLen is the number of random bytes used for the signing secret.
	// 32 bytes = 64 hex chars — same entropy as a session token.
	webhookSecretLen = 32
	// webhookDeliveryTimeout is the per-attempt HTTP timeout.
	webhookDeliveryTimeout = 5 * time.Second
	// webhookDeliveryRingSize is the maximum number of delivery records kept per webhook.
	// Oldest entries are evicted once the ring is full. This is an in-memory, ephemeral log
	// for debugging purposes — it is cleared on server restart.
	webhookDeliveryRingSize = 50
)

// WebhookDeliveryRecord captures the outcome of one HTTP delivery attempt made by
// WebhookDispatcher. Records are kept in an in-memory ring (up to webhookDeliveryRingSize
// per webhook) and cleared on server restart — they are for debugging only.
type WebhookDeliveryRecord struct {
	WebhookID   string    `json:"webhook_id"`
	Event       string    `json:"event"`
	AttemptedAt time.Time `json:"attempted_at"`
	Attempt     int       `json:"attempt"`     // 1 (initial) or 2 (retry)
	Success     bool      `json:"success"`
	StatusCode  int       `json:"status_code"` // 0 when no HTTP response was received
	DurationMs  int64     `json:"duration_ms"`
	Error       string    `json:"error,omitempty"` // empty on success
}

// --- store interface --------------------------------------------------------

// WebhookStore is the persistence seam for tenant_webhook rows (migration 0047).
// The in-memory implementation (InMemoryWebhookStore) is used in tests and DEV mode;
// PgWebhookStore is wired in production.
type WebhookStore interface {
	// Create atomically checks the per-tenant count and, if count < cap, inserts the
	// new webhook row. Returns ErrWebhookCapExceeded when the cap is already reached.
	// The check and insert are one atomic operation — concurrent Creates for the same
	// tenant cannot both succeed when the cap is exactly full.
	Create(ctx context.Context, tenantID string, w *TenantWebhook, secret string, cap int) error
	// List returns all webhooks for the tenant, newest-first, without the secret field.
	List(ctx context.Context, tenantID string) ([]TenantWebhook, error)
	// Delete removes the webhook with the given id. Returns (true, nil) when found and
	// deleted; (false, nil) when not found (idempotent); (false, err) on store failure.
	Delete(ctx context.Context, tenantID, id string) (bool, error)
	// ListDeliveriesForEvent returns (id, url, secret) for every webhook in tenantID that
	// subscribed to event — either by naming it in their events list, or by subscribing to
	// everything (empty events list). Used exclusively by WebhookDispatcher.
	ListDeliveriesForEvent(ctx context.Context, tenantID, event string) ([]WebhookDelivery, error)
}

// --- in-memory store --------------------------------------------------------

type webhookRow struct {
	wh       TenantWebhook
	tenantID string
	secret   string
}

// InMemoryWebhookStore is a concurrency-safe in-memory implementation for tests and DEV mode.
type InMemoryWebhookStore struct {
	mu   sync.Mutex
	rows []webhookRow
}

// NewInMemoryWebhookStore constructs an empty in-memory webhook store.
func NewInMemoryWebhookStore() *InMemoryWebhookStore {
	return &InMemoryWebhookStore{}
}

var _ WebhookStore = (*InMemoryWebhookStore)(nil)

// Create implements WebhookStore. Count and insert are atomic under the mutex so
// concurrent Creates for the same tenant cannot exceed cap.
func (s *InMemoryWebhookStore) Create(_ context.Context, tenantID string, w *TenantWebhook, secret string, cap int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.rows {
		if r.tenantID == tenantID {
			n++
		}
	}
	if n >= cap {
		return ErrWebhookCapExceeded
	}
	events := w.Events
	if events == nil {
		events = []string{}
	}
	s.rows = append(s.rows, webhookRow{
		tenantID: tenantID,
		secret:   secret,
		wh: TenantWebhook{
			ID:        w.ID,
			URL:       w.URL,
			Events:    events,
			CreatedAt: w.CreatedAt,
		},
	})
	return nil
}

// List implements WebhookStore. Newest-first (reverse insertion order).
func (s *InMemoryWebhookStore) List(_ context.Context, tenantID string) ([]TenantWebhook, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []TenantWebhook
	for i := len(s.rows) - 1; i >= 0; i-- {
		r := s.rows[i]
		if r.tenantID != tenantID {
			continue
		}
		out = append(out, r.wh)
	}
	if out == nil {
		out = []TenantWebhook{}
	}
	return out, nil
}

// Delete implements WebhookStore.
func (s *InMemoryWebhookStore) Delete(_ context.Context, tenantID, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.rows {
		if r.tenantID == tenantID && r.wh.ID == id {
			s.rows = append(s.rows[:i], s.rows[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

// ListDeliveriesForEvent implements WebhookStore.
func (s *InMemoryWebhookStore) ListDeliveriesForEvent(_ context.Context, tenantID, event string) ([]WebhookDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []WebhookDelivery
	for _, r := range s.rows {
		if r.tenantID != tenantID {
			continue
		}
		if len(r.wh.Events) == 0 || sliceContains(r.wh.Events, event) {
			out = append(out, WebhookDelivery{ID: r.wh.ID, URL: r.wh.URL, Secret: r.secret})
		}
	}
	return out, nil
}

// sliceContains reports whether ss contains s.
func sliceContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// --- dispatcher -------------------------------------------------------------

// WebhookDispatcher fires webhook deliveries after audit events are recorded.
// It is a best-effort delivery mechanism: fire-and-forget, one retry, then give up.
type WebhookDispatcher struct {
	Store WebhookStore
	// Client is used for HTTP delivery. When nil, a private client with webhookDeliveryTimeout
	// is used. Tests inject a custom Client backed by an httptest.Server.
	Client *http.Client

	deliveryMu  sync.Mutex
	deliveryLog map[string][]WebhookDeliveryRecord // webhookID → records, newest last, capped at webhookDeliveryRingSize

	// Bounded asynchronous delivery (security review 2026-11-01 #17). Dispatch used to start one
	// goroutine per audited mutation, each able to block ~100 s on a tarpit endpoint, so goroutines
	// grew as (event rate x 100 s). Now a fixed worker pool drains per-tenant queues; a tenant whose
	// queue is full has its NEW events dropped (counted + logged as webhook_dropped) and Dispatch
	// NEVER blocks the request path. Zero values select the defaults below.
	Workers           int           // pool size (default webhookWorkersDefault)
	PerTenantQueue    int           // queued jobs per tenant (default webhookQueuePerTenantDefault)
	PerTenantInflight int           // jobs of one tenant running at once (default webhookInflightPerTenantDefault)
	JobDeadline       time.Duration // total budget for one event's whole fan-out (default webhookJobDeadlineDefault)
	retryDelay        time.Duration // pause before the single retry (default 1s)

	startOnce sync.Once
	qmu       sync.Mutex
	qcond     *sync.Cond
	queues    map[string][]webhookJob // tenant -> pending jobs, oldest first
	inflight  map[string]int          // tenant -> running jobs
	ring      []string                // tenants with pending jobs, round-robin order
	queued    int                     // total pending across tenants
	stopped   bool
	dropped   atomic.Int64
	dropLogAt atomic.Int64 // unix nanos of the last webhook_dropped log line
}

type webhookJob struct {
	tenantID string
	ev       MgmtAuditEvent
}

const (
	webhookWorkersDefault           = 4
	webhookQueuePerTenantDefault    = 64
	webhookInflightPerTenantDefault = 2
	webhookJobDeadlineDefault       = 20 * time.Second
	// webhookQueueGlobalMax bounds the total pending jobs across every tenant.
	webhookQueueGlobalMax = 4096
)

func (d *WebhookDispatcher) workers() int {
	if d.Workers > 0 {
		return d.Workers
	}
	return webhookWorkersDefault
}
func (d *WebhookDispatcher) perTenantQueue() int {
	if d.PerTenantQueue > 0 {
		return d.PerTenantQueue
	}
	return webhookQueuePerTenantDefault
}
func (d *WebhookDispatcher) perTenantInflight() int {
	if d.PerTenantInflight > 0 {
		return d.PerTenantInflight
	}
	return webhookInflightPerTenantDefault
}
func (d *WebhookDispatcher) jobDeadline() time.Duration {
	if d.JobDeadline > 0 {
		return d.JobDeadline
	}
	return webhookJobDeadlineDefault
}
func (d *WebhookDispatcher) retryPause() time.Duration {
	if d.retryDelay > 0 {
		return d.retryDelay
	}
	return time.Second
}

// Dropped is how many events were discarded because a queue was full (webhook_dropped).
func (d *WebhookDispatcher) Dropped() int64 { return d.dropped.Load() }

// Stop ends the worker pool after the in-flight jobs finish (tests; the process never stops it).
func (d *WebhookDispatcher) Stop() {
	d.qmu.Lock()
	d.stopped = true
	if d.qcond != nil {
		d.qcond.Broadcast()
	}
	d.qmu.Unlock()
}

// Dispatch enqueues delivery of event e for tenantID and returns immediately: it takes a lock for
// a few map operations and never waits for a worker, the network or the database. When the
// tenant's queue (or the global bound) is full the event is dropped and counted. e is copied
// before returning so the caller may reuse or discard it.
func (d *WebhookDispatcher) Dispatch(tenantID string, e *MgmtAuditEvent) {
	d.startOnce.Do(func() {
		d.qcond = sync.NewCond(&d.qmu)
		d.queues = map[string][]webhookJob{}
		d.inflight = map[string]int{}
		for i := 0; i < d.workers(); i++ {
			go d.worker()
		}
	})
	job := webhookJob{tenantID: tenantID, ev: *e}
	d.qmu.Lock()
	if d.stopped || len(d.queues[tenantID]) >= d.perTenantQueue() || d.queued >= webhookQueueGlobalMax {
		d.qmu.Unlock()
		n := d.dropped.Add(1)
		// One line per second at most: the drop path must not itself become the flood.
		now := time.Now().UnixNano()
		if last := d.dropLogAt.Load(); now-last > int64(time.Second) && d.dropLogAt.CompareAndSwap(last, now) {
			log.Printf("webhook_dropped: tenant %s event %s dropped, delivery queue full (total dropped %d)", tenantID, job.ev.Action, n)
		}
		return
	}
	if len(d.queues[tenantID]) == 0 {
		d.ring = append(d.ring, tenantID)
	}
	d.queues[tenantID] = append(d.queues[tenantID], job)
	d.queued++
	d.qcond.Signal()
	d.qmu.Unlock()
}

// next blocks until a job can run: round-robin across tenants that have pending work and fewer
// than perTenantInflight jobs running, so one tenant's slow endpoints cannot occupy every worker.
func (d *WebhookDispatcher) next() (webhookJob, bool) {
	d.qmu.Lock()
	defer d.qmu.Unlock()
	for {
		if d.stopped {
			return webhookJob{}, false
		}
		for i, tid := range d.ring {
			if d.inflight[tid] >= d.perTenantInflight() {
				continue
			}
			q := d.queues[tid]
			job := q[0]
			if len(q) == 1 {
				delete(d.queues, tid)
				d.ring = append(d.ring[:i], d.ring[i+1:]...)
			} else {
				d.queues[tid] = q[1:]
				// rotate this tenant to the back for fairness
				d.ring = append(append(d.ring[:i:i], d.ring[i+1:]...), tid)
			}
			d.queued--
			d.inflight[tid]++
			return job, true
		}
		d.qcond.Wait()
	}
}

func (d *WebhookDispatcher) worker() {
	for {
		job, ok := d.next()
		if !ok {
			return
		}
		d.runJob(job)
	}
}

func (d *WebhookDispatcher) runJob(job webhookJob) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("webhook worker recovered from panic (tenant %s): %v", job.tenantID, r)
		}
		d.qmu.Lock()
		if d.inflight[job.tenantID]--; d.inflight[job.tenantID] <= 0 {
			delete(d.inflight, job.tenantID)
		}
		d.qcond.Broadcast() // a tenant just became eligible again
		d.qmu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), d.jobDeadline())
	defer cancel()
	if err := d.dispatchCtx(ctx, job.tenantID, &job.ev); err != nil {
		log.Printf("webhook dispatch error for tenant %s event %s: %v", job.tenantID, job.ev.Action, err)
	}
}

// recordDelivery appends rec to the in-memory ring for rec.WebhookID.
// The ring is capped at webhookDeliveryRingSize: the oldest entries are evicted when full.
func (d *WebhookDispatcher) recordDelivery(rec WebhookDeliveryRecord) {
	d.deliveryMu.Lock()
	defer d.deliveryMu.Unlock()
	if d.deliveryLog == nil {
		d.deliveryLog = make(map[string][]WebhookDeliveryRecord)
	}
	ring := d.deliveryLog[rec.WebhookID]
	ring = append(ring, rec)
	if len(ring) > webhookDeliveryRingSize {
		ring = ring[len(ring)-webhookDeliveryRingSize:]
	}
	d.deliveryLog[rec.WebhookID] = ring
}

// DeleteRing removes all delivery records for webhookID from the ring buffer.
// Called by handleDeleteWebhook after a confirmed delete so the map entry is
// evicted and the ephemeral log stays bounded across webhook lifecycle churn.
func (d *WebhookDispatcher) DeleteRing(webhookID string) {
	d.deliveryMu.Lock()
	defer d.deliveryMu.Unlock()
	delete(d.deliveryLog, webhookID)
}

// RecentDeliveries returns the last N delivery records for webhookID, newest-first.
// Returns an empty (non-nil) slice when no records exist.
func (d *WebhookDispatcher) RecentDeliveries(webhookID string) []WebhookDeliveryRecord {
	d.deliveryMu.Lock()
	defer d.deliveryMu.Unlock()
	ring := d.deliveryLog[webhookID]
	if len(ring) == 0 {
		return []WebhookDeliveryRecord{}
	}
	out := make([]WebhookDeliveryRecord, len(ring))
	for i, r := range ring {
		out[len(ring)-1-i] = r
	}
	return out
}

// dispatchSync fetches matching targets and delivers to each. Exported for testing.
func (d *WebhookDispatcher) dispatchSync(tenantID string, e *MgmtAuditEvent) error {
	return d.dispatchCtx(context.Background(), tenantID, e)
}

// dispatchCtx is dispatchSync under a deadline: the store lookup, every HTTP attempt and the retry
// pause all stop when ctx does, so one event's whole fan-out has a short total budget.
func (d *WebhookDispatcher) dispatchCtx(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	targets, err := d.Store.ListDeliveriesForEvent(ctx, tenantID, e.Action)
	if err != nil {
		return fmt.Errorf("list targets: %w", err)
	}
	if len(targets) == 0 {
		return nil
	}
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	// One client per fan-out: reuses the transport's connection pool across all targets.
	// When Client is nil (production path), use the SSRF-safe transport that rejects
	// loopback/private/link-local destinations at connection time. Tests inject their own
	// Client via the Client field to reach httptest.Server (which uses 127.0.0.1).
	client := d.Client
	if client == nil {
		client = webhookSafeClient()
	}
	for _, t := range targets {
		if ctx.Err() != nil {
			log.Printf("webhook %s: delivery budget exhausted, skipping (tenant %s event %s)", t.ID, tenantID, e.Action)
			continue
		}
		d.deliverCtx(ctx, t, e.Action, body, client)
	}
	return nil
}

// deliver makes one HTTP POST to the webhook URL, retrying once on failure.
// client must be non-nil; the caller (dispatchSync) allocates exactly one per fan-out.
// Each attempt (initial + retry) is recorded in the dispatcher's delivery ring.
func (d *WebhookDispatcher) deliver(t WebhookDelivery, event string, body []byte, client *http.Client) {
	d.deliverCtx(context.Background(), t, event, body, client)
}

func (d *WebhookDispatcher) deliverCtx(ctx context.Context, t WebhookDelivery, event string, body []byte, client *http.Client) {
	send := func() (statusCode int, err error) {
		sig := webhookSignature(t.Secret, body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
		if err != nil {
			return 0, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DeskRally-Signature", "sha256="+sig)
		req.Header.Set("X-DeskRally-Webhook-ID", t.ID)
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return resp.StatusCode, fmt.Errorf("non-2xx status %d", resp.StatusCode)
		}
		return resp.StatusCode, nil
	}
	doAttempt := func(attempt int) (bool, error) {
		start := time.Now()
		code, err := send()
		rec := WebhookDeliveryRecord{
			WebhookID:   t.ID,
			Event:       event,
			AttemptedAt: start,
			Attempt:     attempt,
			Success:     err == nil,
			StatusCode:  code,
			DurationMs:  time.Since(start).Milliseconds(),
		}
		if err != nil {
			rec.Error = err.Error()
		}
		d.recordDelivery(rec)
		return err == nil, err
	}
	if ok, err := doAttempt(1); !ok {
		log.Printf("webhook %s: delivery failed, retrying in %s: %v", t.ID, d.retryPause(), err)
		select {
		case <-time.After(d.retryPause()):
		case <-ctx.Done():
			log.Printf("webhook %s: delivery budget exhausted before the retry, giving up", t.ID)
			return
		}
		if ok, err = doAttempt(2); !ok {
			log.Printf("webhook %s: delivery failed after retry, giving up: %v", t.ID, err)
		}
	}
}

// webhookSignature returns hex(HMAC-SHA256(body, secret)).
// Receivers verify by computing the same value and comparing with the X-DeskRally-Signature header.
func webhookSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// generateWebhookSecret returns a hex-encoded 32-byte random signing secret.
func generateWebhookSecret() (string, error) {
	b := make([]byte, webhookSecretLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
