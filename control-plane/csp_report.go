package controlplane

// Content-Security-Policy violation reports (docs/26 F10). The console's policy ships Report-Only because a
// wrong directive blanks the whole console, and nothing in the gate exercises the edge headers. This endpoint
// lets the LIVE browsers say what the policy would have blocked, so it can be promoted to enforcing on
// evidence. Report-Only cannot break a page, so collecting reports is risk-free for the console.
//
// The endpoint is public by necessity (browsers send reports without credentials) and therefore treats every
// byte as hostile: the body is capped; only a handful of fields are kept; URLs are reduced to fixed shapes
// (cspURL: no host, path, userinfo, query or fragment value an attacker could choose survives; allowlisted
// keywords and schemes only); every field is stripped of control
// and format characters and clipped; the log line is %q-quoted; and a budget bounds how many reports are
// logged per minute in total and per source address, checked BEFORE the body is read (the rest are counted,
// and the count is logged once the window turns). Nothing is stored or echoed. Reports are untrusted evidence:
// promote the policy only with controlled browser checks as well.

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	cspReportMaxBody      = 16 << 10 // one browser report is well under 2 KiB
	cspReportField        = 200
	cspReportPerWindow    = 6 // log lines per window, all sources: ~2.6 MB/day at worst, so the CP log keeps days
	cspReportPerSource    = 3 // log lines per window per source, so one source cannot occupy the window
	cspRequestPerWindow   = 600
	cspRequestPerSource   = 10 // requests (valid or not) per window per source, reserved BEFORE the body is read
	cspReportMaxSources   = 1024
	cspReportWindowLength = time.Minute
)

// cspReportBudget holds two separate budgets per window. The REQUEST budget is reserved atomically before the
// body is read and charged for every request, malformed or oversized included, so neither concurrency nor
// garbage buys a source more reads and parses than cspRequestPerSource. The LOG budget bounds what is written.
// Sources beyond cspReportMaxSources in one window share one bucket, so both maps stay bounded under a spray of
// addresses. `suppressed` is approximate: a refused request counts once, however many reports it carried.
type cspReportBudget struct {
	mu         sync.Mutex
	now        func() time.Time
	start      time.Time
	requests   int
	perReqSrc  map[string]int
	logged     int
	perLogSrc  map[string]int
	suppressed int
}

const cspOverflowSource = "\x00overflow"

// roll starts a new window when the current one has ended and returns the previous window's suppressed count.
// Callers hold b.mu.
func (b *cspReportBudget) roll() int {
	t := b.now()
	if !b.start.IsZero() && t.Sub(b.start) < cspReportWindowLength {
		return 0
	}
	dropped := b.suppressed
	b.start, b.requests, b.logged, b.suppressed = t, 0, 0, 0
	b.perReqSrc, b.perLogSrc = map[string]int{}, map[string]int{}
	return dropped
}

func bucket(m map[string]int, source string) string {
	if _, known := m[source]; !known && len(m) >= cspReportMaxSources {
		return cspOverflowSource
	}
	return source
}

// reserve spends one request from source's budget, atomically, before anything is read. It returns whether the
// request may proceed and the previous window's suppressed count (non-zero once, as the window turns).
func (b *cspReportBudget) reserve(source string) (ok bool, droppedBefore int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	droppedBefore = b.roll()
	source = bucket(b.perReqSrc, source)
	if b.requests >= cspRequestPerWindow || b.perReqSrc[source] >= cspRequestPerSource {
		b.suppressed++
		return false, droppedBefore
	}
	b.requests++
	b.perReqSrc[source]++
	return true, droppedBefore
}

// take spends one log line from source's budget.
func (b *cspReportBudget) take(source string) (ok bool, droppedBefore int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	droppedBefore = b.roll()
	source = bucket(b.perLogSrc, source)
	if b.logged >= cspReportPerWindow || b.perLogSrc[source] >= cspReportPerSource {
		b.suppressed++
		return false, droppedBefore
	}
	b.logged++
	b.perLogSrc[source]++
	return true, droppedBefore
}

var defaultCSPReportBudget = &cspReportBudget{now: time.Now}

// cspField makes one untrusted non-URL report value safe to log: strip control and format characters, clip.
func cspField(v any) string {
	s, _ := v.(string)
	if f, ok := v.(float64); ok {
		s = strconv.FormatFloat(f, 'f', -1, 64)
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	if len(s) > cspReportField {
		s = s[:cspReportField]
	}
	return s
}

// The only CSP keywords and non-network schemes a report may name; anything else is a fixed marker.
var (
	cspKeywords = map[string]bool{"inline": true, "eval": true, "wasm-eval": true, "self": true,
		"trusted-types-policy": true, "trusted-types-sink": true}
	cspSchemes = map[string]bool{"data": true, "blob": true, "filesystem": true, "about": true,
		"chrome-extension": true, "moz-extension": true, "safari-extension": true, "mediastream": true}
	// Paths kept only on THIS site's own host, and only in these exact shapes: a bundle file, a docs page, or a
	// bare console route. No percent-encoding, no dot segments, no other suffix.
	cspAssetPath = regexp.MustCompile(`^/assets/[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\.(js|css|woff2?|png|svg|ico|webp|wasm)$`)
	cspDocsPath  = regexp.MustCompile(`^/docs(/[a-z0-9-]{1,64})?$`)
	cspRoutePath = regexp.MustCompile(`^/(console|join|cp|download|machines)?$`)
)

// cspURL reduces an untrusted URL from a report to what is safe to log, given the host the report was sent to
// (this site): an allowlisted CSP keyword or non-network scheme as-is; an http(s)/ws(s) URL on this site's
// host as scheme://(this-site) plus a fixed path shape (a bundle file's extension, /docs/*, a bare console
// route, else the first known route segment and "(redacted)"); any other origin as "(other-origin)". Userinfo, query and fragment are never kept,
// and nothing attacker-chosen survives except through the allowlisted shapes.
func cspURL(s, siteHost string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, ":") {
		if cspKeywords[strings.ToLower(s)] {
			return strings.ToLower(s)
		}
		return "(redacted)"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		return "(unparsable)"
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https", "ws", "wss":
	default:
		if cspSchemes[scheme] {
			return scheme + ":"
		}
		return "(other-scheme)"
	}
	if siteHost == "" || !strings.EqualFold(u.Hostname(), siteHost) {
		return scheme + "://(other-origin)"
	}
	// This site's host is NOT echoed: the Host header can be forged, so its value proves nothing. Paths keep
	// only fixed shapes: the extension of a bundle file, the docs area, or a bare console route.
	const own = "://(this-site)"
	p := u.EscapedPath()
	switch {
	case p == "" || p == "/":
		return scheme + own + "/"
	case cspRoutePath.MatchString(p):
		return scheme + own + p
	case cspDocsPath.MatchString(p):
		return scheme + own + "/docs/*"
	}
	if m := cspAssetPath.FindStringSubmatch(p); m != nil {
		return scheme + own + "/assets/*." + m[len(m)-1]
	}
	first := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)[0]
	if cspRoutePath.MatchString("/" + first) {
		return scheme + own + "/" + first + "/(redacted)"
	}
	return scheme + own + "/(redacted)"
}

// cspViolation is what is kept of one report, in either wire format.
type cspViolation struct {
	Directive, Blocked, Document, Source, Line, Disposition string
}

// parseCSPReports accepts the legacy `report-uri` body ({"csp-report": {...}}, application/csp-report) and the
// Reporting API body (a JSON array of {"type": "csp-violation", "body": {...}}, application/reports+json).
func parseCSPReports(raw []byte, siteHost string) []cspViolation {
	pick := func(m map[string]any, keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				if s := cspField(v); s != "" {
					return s
				}
			}
		}
		return ""
	}
	pickURL := func(m map[string]any, keys ...string) string {
		for _, k := range keys {
			if s, ok := m[k].(string); ok && s != "" {
				return cspField(cspURL(s, siteHost))
			}
		}
		return ""
	}
	one := func(m map[string]any) cspViolation {
		return cspViolation{
			Directive:   pick(m, "effective-directive", "effectiveDirective", "violated-directive"),
			Blocked:     pickURL(m, "blocked-uri", "blockedURL"),
			Document:    pickURL(m, "document-uri", "documentURL"),
			Source:      pickURL(m, "source-file", "sourceFile"),
			Line:        pick(m, "line-number", "lineNumber"),
			Disposition: pick(m, "disposition"),
		}
	}
	var legacy struct {
		Report map[string]any `json:"csp-report"`
	}
	if json.Unmarshal(raw, &legacy) == nil && legacy.Report != nil {
		return []cspViolation{one(legacy.Report)}
	}
	var batch []struct {
		Type string         `json:"type"`
		Body map[string]any `json:"body"`
	}
	if json.Unmarshal(raw, &batch) != nil {
		return nil
	}
	var out []cspViolation
	for _, r := range batch {
		if r.Type == "csp-violation" && r.Body != nil && len(out) < 10 {
			out = append(out, one(r.Body))
		}
	}
	return out
}

func handleCSPReport(budget *cspReportBudget) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		source := sourceIPFrom(r.Context())
		if source == "" {
			source = "unknown"
		}
		// Reserve before any read or parse, for every request (malformed and oversized included).
		ok, dropped := budget.reserve(source)
		if dropped > 0 {
			log.Printf("csp-report: about %d reports were not logged in the previous minute (budgets: %d lines, %d requests per source)", dropped, cspReportPerWindow, cspRequestPerSource)
		}
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// The host the browser sent the report to is this site; Caddy's reverse_proxy keeps the Host header.
		siteHost := r.Host
		if h, _, err := net.SplitHostPort(siteHost); err == nil {
			siteHost = h
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cspReportMaxBody))
		if err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		for _, v := range parseCSPReports(raw, siteHost) {
			ok, dropped := budget.take(source)
			if dropped > 0 {
				log.Printf("csp-report: about %d reports were not logged in the previous minute (budgets: %d lines, %d requests per source)", dropped, cspReportPerWindow, cspRequestPerSource)
			}
			if !ok {
				continue
			}
			log.Printf("csp-report: directive=%q blocked=%q document=%q source=%q line=%q disposition=%q",
				v.Directive, v.Blocked, v.Document, v.Source, v.Line, v.Disposition)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
