package controlplane

// The PUBLIC branding routes (docs/66 2a.4, 2a.6, 2b.7, 2c.3, 2c.4, 2d, 2e, 2f):
//
//	GET /public/branding        the published branding of the HOST the guest opened, as JSON
//	GET /public/branding/logo   the PNG of the published revision whose hash is ?rev=
//
// Reached by browsers as /cp/public/branding[/logo]. Keyed by Host ONLY (a query parameter, header or body
// never selects a tenant). Only authorities listed in CP_PUBLIC_AUTHORITIES (default hosts, legacy hosts and
// the tenant hosts the operator added) ever reach the database; every other authority is answered neutral
// with no lookup.
//
// ONE neutral contract for default, legacy, unmapped, pending, unapproved, disabled, theming-off and
// failed-lookup hosts: HTTP 200, identical body bytes, identical header set, Cache-Control: no-store, the same
// schedule. The logo route answers the SAME neutral JSON for every failure (wrong hash, no approved revision,
// released host, disabled tenant, no logo). The body has no `scope` field and no tenant, revision or
// assignment id. A published response differs only in values.
//
// THE SCHEDULE (2d.1, 2e.1, 2f). t = 0 at ADMISSION:
//
//	t = 0           admitted (pool slot taken); the prebuilt neutral response is the default content
//	0 < t <= 100 ms the lookup runs on its OWN goroutine under a 100 ms context and a 100 ms statement
//	                timeout, through the bounded lifecycle (pgbounded.go); content is chosen and BUFFERED there
//	t = 100 ms      cutoff: the handler stops waiting and keeps the prebuilt neutral response (the lookup
//	                goroutine keeps its permit until it exits, bounded to about 1.1 s by 2f, and its connection is
//	                destroyed, not pooled)
//	t = 150 ms + j  RELEASE: status, headers and the buffered body are written together (j uniform in 0..10 ms)
//	t = 2 s         transport-level termination only: the write deadline, never a substitution of content
//
// No header byte is written before release. The floor sleep holds no database connection.
//
// ADMISSION (2c.4, 2d.2): at most 128 admitted in flight per PROCESS (requests asleep in the floor count) and
// 4 per client IP, with a ZERO-length queue; anything else is an immediate uniform 429 with Retry-After, no
// database touch, no failure recorded. Behind that sits a per-IP request RATE budget (default 120 per minute,
// both routes together), separate from every credential bucket; exceeding it is the same uniform 429. With N
// replicas the service-wide bound is N x 128 (the operator documentation says so).
//
// GET only. A request with a body (Content-Length above 0, or any Transfer-Encoding) is refused with a uniform
// 400 BEFORE admission. Conditional headers (If-None-Match, If-Modified-Since, Range) are ignored: the answer
// is always a full 200 with no ETag and no Last-Modified.
//
// CP_HOST_THEMING off (or no host policy, or no store): the routes answer the neutral DeskRally branding on
// the same schedule and never touch the database. Turning theming off never removes redemption scope (2a.1).
//
// There is NO cache and NO coalescing: every request performs its own fresh authoritative read (2b.1, 2c.1).

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Public branding defaults (docs/66 2c.3, 2c.4, 2d.1).
const (
	DefaultBrandingAdmitGlobal   = 128
	DefaultBrandingAdmitPerIP    = 4
	DefaultBrandingWorkDeadline  = 100 * time.Millisecond
	DefaultBrandingFloor         = 150 * time.Millisecond
	DefaultBrandingJitter        = 10 * time.Millisecond
	DefaultBrandingRatePerMinute = 120
	// brandingExchangeLimit is the 2 s bound from admission to the last byte; the write deadline at release is
	// release_time + (2 s - 160 ms).
	brandingExchangeLimit = 2 * time.Second
	brandingWriteSlack    = 160 * time.Millisecond
)

// BrandingTuning overrides the public branding schedule and admission. Zero = the documented defaults. A
// negative Floor switches the floor and jitter off, a negative RatePerMinute switches the rate budget off
// (tests that hammer the route).
type BrandingTuning struct {
	AdmitGlobal   int
	AdmitPerIP    int
	WorkDeadline  time.Duration
	Floor         time.Duration
	Jitter        time.Duration
	RatePerMinute int
}

func (t BrandingTuning) workDeadline() time.Duration {
	if t.WorkDeadline <= 0 {
		return DefaultBrandingWorkDeadline
	}
	return t.WorkDeadline
}

func (t BrandingTuning) floor() time.Duration {
	if t.Floor < 0 {
		return 0
	}
	if t.Floor == 0 {
		return DefaultBrandingFloor
	}
	return t.Floor
}

func (t BrandingTuning) jitter() time.Duration {
	if t.Floor < 0 {
		return 0
	}
	if t.Jitter == 0 {
		return DefaultBrandingJitter
	}
	return t.Jitter
}

// brandResponse is a fully built response: nothing about it is decided after it is chosen.
type brandResponse struct {
	status      int
	contentType string
	csp         bool
	retryAfter  string
	body        []byte
}

// publicBrandingBody is the one body schema. strings, empty when neutral.
type publicBrandingBody struct {
	ProductName    string       `json:"product_name"`
	AccentColor    string       `json:"accent_color"`
	LogoRev        string       `json:"logo_rev"`
	SupportText    string       `json:"support_text"`
	SupportContact BrandContact `json:"support_contact"`
}

func mustMarshalBrand(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// The prebuilt responses (built once, before any work, shared read-only).
var (
	neutralBrandingResponse = &brandResponse{status: http.StatusOK, contentType: "application/json", csp: true,
		body: mustMarshalBrand(publicBrandingBody{})}
	tooManyBrandingResponse = &brandResponse{status: http.StatusTooManyRequests, contentType: "application/json", csp: true,
		retryAfter: "1", body: mustMarshalBrand(map[string]string{"error": "too many requests"})}
	badBrandingRequestResponse = &brandResponse{status: http.StatusBadRequest, contentType: "application/json", csp: true,
		body: mustMarshalBrand(map[string]string{"error": "bad request"})}
)

// NeutralBrandingBody is the neutral object's exact bytes (tests and the operator documentation).
func NeutralBrandingBody() []byte { return append([]byte(nil), neutralBrandingResponse.body...) }

func writeBrandResponse(w http.ResponseWriter, resp *brandResponse) {
	h := w.Header()
	h.Set("Content-Type", resp.contentType)
	h.Set("Cache-Control", "no-store")
	h.Set("Vary", "Host")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	if resp.retryAfter != "" {
		h.Set("Retry-After", resp.retryAfter)
	}
	h.Set("Content-Length", strconv.Itoa(len(resp.body)))
	w.WriteHeader(resp.status)
	_, _ = w.Write(resp.body)
}

// rateBudget is a small in-process fixed-window request budget per key (a RATE over time, not a failure
// lockout): the per-IP public branding budget and the per-tenant logo upload budget. Bounded: stale windows
// are swept and, when the map is still full of LIVE windows, an unseen key is refused (never an eviction).
type rateBudget struct {
	mu      sync.Mutex
	window  time.Duration
	max     int
	maxKeys int
	m       map[string]*rateWindow
	now     func() time.Time
}

type rateWindow struct {
	start time.Time
	n     int
}

func newRateBudget(max int, window time.Duration, maxKeys int) *rateBudget {
	return &rateBudget{window: window, max: max, maxKeys: maxKeys, m: map[string]*rateWindow{}, now: time.Now}
}

// Allow charges one request to key and reports whether it is within the budget.
func (b *rateBudget) Allow(key string) bool {
	if b == nil || b.max <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	w := b.m[key]
	if w == nil && len(b.m) >= b.maxKeys {
		// Full: drop only EXPIRED windows. A live counter is never evicted (that would hand its owner a fresh
		// budget whenever someone else churns keys). If only live windows remain, an unseen key is refused
		// (the uniform 429) until one expires (repair C1).
		for k, v := range b.m {
			if now.Sub(v.start) >= b.window {
				delete(b.m, k)
			}
		}
		if len(b.m) >= b.maxKeys {
			return false
		}
	}
	if w == nil || now.Sub(w.start) >= b.window {
		w = &rateWindow{start: now}
		b.m[key] = w
	}
	w.n++
	return w.n <= b.max
}

func (b *rateBudget) size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.m)
}

func (s *Server) brandingPool() *admissionPool {
	s.brandAdmitOnce.Do(func() {
		s.brandAdmit = newAdmissionPool(s.BrandingTuning.AdmitGlobal, s.BrandingTuning.AdmitPerIP)
		if s.BrandingTuning.AdmitGlobal <= 0 {
			s.brandAdmit.maxGlobal = DefaultBrandingAdmitGlobal
		}
		if s.BrandingTuning.AdmitPerIP <= 0 {
			s.brandAdmit.maxPerKey = DefaultBrandingAdmitPerIP
		}
		rate := s.BrandingTuning.RatePerMinute
		if rate == 0 {
			rate = DefaultBrandingRatePerMinute
		}
		s.brandRate = newRateBudget(rate, time.Minute, 100_000)
	})
	return s.brandAdmit
}

// BrandingCutoffTotal is the branding_cutoff_total metric (docs/66 2d.1): lookups cut at the work deadline, by
// route ("json" or "logo"). The cutoff is invisible to the caller by design; this is how an operator sees a
// degraded database.
func (s *Server) BrandingCutoffTotal(route string) int64 {
	if route == "logo" {
		return s.brandCutoffLogo.Load()
	}
	return s.brandCutoffJSON.Load()
}

// permitHolders releases an admission permit when the LAST of its holders is done: the handler (until the
// response is written, floor sleep included) and the lookup goroutine (until it has exited).
type permitHolders struct {
	n       atomic.Int32
	release func()
}

func newPermitHolders(n int32, release func()) *permitHolders {
	p := &permitHolders{release: release}
	p.n.Store(n)
	return p
}

func (p *permitHolders) done() {
	if p.n.Add(-1) == 0 {
		p.release()
	}
}

// handlePublicBranding serves the JSON route (logo=false) or the logo route (logo=true).
func (s *Server) handlePublicBranding(logo bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		// A body on a GET is refused before admission with the uniform 400 (docs/66 2e.2).
		if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
			_ = rc.SetWriteDeadline(time.Now().Add(brandingExchangeLimit))
			writeBrandResponse(w, badBrandingRequestResponse)
			return
		}
		pool := s.brandingPool()
		ip := clientIP(r)
		// Immediate, uniform 429s: the per-IP rate budget and the zero-queue admission caps. No database
		// touch, no failure recorded, no queue.
		if !s.brandRate.Allow(ip) {
			_ = rc.SetWriteDeadline(time.Now().Add(brandingExchangeLimit))
			writeBrandResponse(w, tooManyBrandingResponse)
			return
		}
		release, admitted := pool.Acquire(ip)
		if !admitted {
			_ = rc.SetWriteDeadline(time.Now().Add(brandingExchangeLimit))
			writeBrandResponse(w, tooManyBrandingResponse)
			return
		}
		admittedAt := time.Now()
		_ = rc.SetWriteDeadline(admittedAt.Add(brandingExchangeLimit))
		holders := newPermitHolders(1, release)
		defer holders.done()

		content := neutralBrandingResponse // chosen BEFORE any work: the default is the prebuilt neutral response
		if host, ok := s.publicBrandingHost(r.Host); ok {
			holders.n.Add(1) // the lookup goroutine is a second holder
			workDeadline := s.BrandingTuning.workDeadline()
			lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), workDeadline)
			rev := r.URL.Query().Get("rev")
			type result struct {
				resp *brandResponse
				cut  bool
			}
			out := make(chan result, 1)
			go func() {
				defer holders.done()
				defer cancel()
				resp := s.lookupBranding(lookupCtx, host, logo, rev)
				out <- result{resp, lookupCtx.Err() != nil}
			}()
			timer := time.NewTimer(workDeadline)
			cut := false
			select {
			case o := <-out:
				content, cut = o.resp, o.cut
			case <-timer.C:
				cut = true
			case <-r.Context().Done():
				timer.Stop()
				return
			}
			timer.Stop()
			if cut {
				content = neutralBrandingResponse
				if logo {
					s.brandCutoffLogo.Add(1)
				} else {
					s.brandCutoffJSON.Add(1)
				}
			}
		}

		// RELEASE at exactly floor + jitter after admission, with no database connection held.
		if floor := s.BrandingTuning.floor(); floor > 0 {
			target := admittedAt.Add(floor)
			if j := s.BrandingTuning.jitter(); j > 0 {
				target = target.Add(time.Duration(rand.Int64N(int64(j) + 1)))
			}
			if d := time.Until(target); d > 0 {
				t := time.NewTimer(d)
				select {
				case <-t.C:
				case <-r.Context().Done():
					t.Stop()
					return
				}
			}
		}
		// release_time + (2 s - 160 ms), but never past the absolute admission + 2 s bound: a late release must not
		// extend the exchange or hold the permit longer than the binding 2 s (repair C2).
		dl := time.Now().Add(brandingExchangeLimit - brandingWriteSlack)
		if abs := admittedAt.Add(brandingExchangeLimit); dl.After(abs) {
			dl = abs
		}
		_ = rc.SetWriteDeadline(dl)
		writeBrandResponse(w, content)
	}
}

// publicBrandingHost reports the normalised host to look up, or false when the request is answered neutral
// without a lookup: theming is off, there is no store, or the authority is not a configured public authority.
func (s *Server) publicBrandingHost(raw string) (string, bool) {
	if s.HostPolicy == nil || !s.HostPolicy.Theming() || s.BrandingRevisions == nil {
		return "", false
	}
	h, class := s.HostPolicy.Classify(raw)
	if class == HostRefused || !s.HostPolicy.IsPublicAuthority(h) {
		return "", false
	}
	return h, true
}

// lookupBranding runs on the lookup goroutine: ONE lookup, then a pure in-memory render. Any failure,
// no-row, or content that fails re-validation is the neutral response.
func (s *Server) lookupBranding(ctx context.Context, host string, logo bool, rev string) *brandResponse {
	res, err := s.BrandingRevisions.PublicLookup(ctx, host, logo)
	if s.brandRenderHook != nil {
		s.brandRenderHook(ctx, logo)
	}
	if err != nil || res == nil {
		return neutralBrandingResponse
	}
	return renderPublishedBranding(res, logo, rev)
}

// renderPublishedBranding is the pure render: it re-validates the stored values (defence in depth against rows
// written under older rules) and picks the content. Nothing here does I/O.
func renderPublishedBranding(res *PublishedBranding, logo bool, rev string) *brandResponse {
	name, e1 := NormalizeBrandName(res.ProductName)
	text, e2 := NormalizeBrandSupportText(res.SupportText)
	contact, e3 := NormalizeBrandContact(res.Contact)
	accent, e4 := NormalizeBrandAccent(res.AccentColor)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || name != res.ProductName || text != res.SupportText ||
		contact != res.Contact || accent != res.AccentColor {
		return neutralBrandingResponse
	}
	if res.LogoSHA256 != "" && !validSHA256Hex(res.LogoSHA256) {
		return neutralBrandingResponse
	}
	if logo {
		// Bytes ONLY for the requested hash of the published revision; never another hash's, never current bytes
		// substituted (docs/66 2a.4).
		if res.LogoSHA256 == "" || rev != res.LogoSHA256 || len(res.LogoPNG) == 0 || len(res.LogoPNG) > LogoMaxOutputBytes ||
			logoSHA(res.LogoPNG) != res.LogoSHA256 {
			return neutralBrandingResponse
		}
		return &brandResponse{status: http.StatusOK, contentType: "image/png", csp: true, body: res.LogoPNG}
	}
	return &brandResponse{status: http.StatusOK, contentType: "application/json", csp: true,
		body: mustMarshalBrand(publicBrandingBody{ProductName: name, AccentColor: accent, LogoRev: res.LogoSHA256, SupportText: text, SupportContact: contact})}
}

func validSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
