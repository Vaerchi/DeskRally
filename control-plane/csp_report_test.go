package controlplane

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func captureCSPLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return &buf
}

func postCSP(t *testing.T, h http.Handler, ctype, body string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/csp-report", strings.NewReader(body))
	req.Header.Set("Content-Type", ctype)
	req.Host = "main.example:443"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestCSPReportLegacyFormatIsLoggedSanitized(t *testing.T) {
	buf := captureCSPLog(t)
	h := handleCSPReport(&cspReportBudget{now: time.Now})
	body := `{"csp-report":{"document-uri":"https://main.example/console?ref=PRIVATEVALUE#x","effective-directive":"script-src-elem",` +
		`"blocked-uri":"https://evil.example/assets/x.js?k=v","source-file":"https://main.example/assets/a.js","line-number":12,` +
		`"disposition":"report","original-policy":"default-src 'self'"}}`
	if code := postCSP(t, h, "application/csp-report", body); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	got := buf.String()
	for _, want := range []string{`directive="script-src-elem"`, `blocked="https://(other-origin)"`, `source="https://(this-site)/assets/*.js"`, `document="https://(this-site)/console"`, `line="12"`, `disposition="report"`} {
		if !strings.Contains(got, want) {
			t.Errorf("log %q lacks %s", got, want)
		}
	}
	if strings.Contains(got, "PRIVATEVALUE") || strings.Contains(got, "k=v") || strings.Contains(got, "original-policy") {
		t.Errorf("query strings or unkept fields reached the log: %q", got)
	}
}

func TestCSPReportReportingAPIBatch(t *testing.T) {
	buf := captureCSPLog(t)
	h := handleCSPReport(&cspReportBudget{now: time.Now})
	body := `[{"type":"csp-violation","body":{"effectiveDirective":"img-src","blockedURL":"https://cdn.example/i.png","documentURL":"https://main.example/console","disposition":"report"}},` +
		`{"type":"deprecation","body":{"id":"x"}}]`
	if code := postCSP(t, h, "application/reports+json", body); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	if n := strings.Count(buf.String(), "csp-report:"); n != 1 {
		t.Fatalf("want exactly the one csp-violation logged, got %d: %q", n, buf.String())
	}
	if !strings.Contains(buf.String(), `directive="img-src"`) {
		t.Errorf("log: %q", buf.String())
	}
}

func TestCSPReportCannotForgeLogLines(t *testing.T) {
	buf := captureCSPLog(t)
	h := handleCSPReport(&cspReportBudget{now: time.Now})
	body := `{"csp-report":{"effective-directive":"script-src\ncsp-report: directive=\"forged\"‮","blocked-uri":"` + strings.Repeat("a", 5000) + `"}}`
	postCSP(t, h, "application/csp-report", body)
	got := buf.String()
	if strings.Count(got, "\n") != 1 {
		t.Fatalf("a report produced more than one log line: %q", got)
	}
	if strings.Contains(got, "‮") || len(got) > 2*cspReportField+400 {
		t.Errorf("format characters or an unclipped field reached the log (%d bytes)", len(got))
	}
}

func TestCSPReportRejectsOversizedBodies(t *testing.T) {
	buf := captureCSPLog(t)
	h := handleCSPReport(&cspReportBudget{now: time.Now})
	big := `{"csp-report":{"blocked-uri":"` + strings.Repeat("a", cspReportMaxBody) + `"}}`
	if code := postCSP(t, h, "application/csp-report", big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", code)
	}
	if buf.Len() != 0 {
		t.Errorf("an oversized body was logged: %q", buf.String())
	}
}

func TestCSPReportBudgetCountsWhatItDrops(t *testing.T) {
	now := time.Unix(1000, 0)
	b := &cspReportBudget{now: func() time.Time { return now }}
	for i := 0; i < cspReportPerWindow; i++ {
		src := "10.0.0." + string(rune('a'+i/cspReportPerSource))
		if ok, _ := b.take(src); !ok {
			t.Fatalf("report %d refused inside the budget", i)
		}
	}
	for i := 0; i < 5; i++ {
		if ok, _ := b.take("fresh-source"); ok {
			t.Fatal("a report beyond the global budget was allowed")
		}
	}
	now = now.Add(cspReportWindowLength)
	ok, dropped := b.take("x")
	if !ok || dropped != 5 {
		t.Fatalf("new window: ok=%v dropped=%d, want true and 5", ok, dropped)
	}
	if _, again := b.take("x"); again != 0 {
		t.Fatalf("the dropped count must be reported once, got %d again", again)
	}
}

func TestCSPReportOneSourceCannotTakeTheWholeBudget(t *testing.T) {
	b := &cspReportBudget{now: time.Now}
	for i := 0; i < cspReportPerSource; i++ {
		if ok, _ := b.take("attacker"); !ok {
			t.Fatalf("report %d refused inside the per-source budget", i)
		}
	}
	if ok, _ := b.take("attacker"); ok {
		t.Fatal("one source exceeded its per-source budget")
	}

	if ok, _ := b.take("real-browser"); !ok {
		t.Fatal("another source was starved by the first")
	}
}

func TestCSPReportSourceMapStaysBounded(t *testing.T) {
	b := &cspReportBudget{now: time.Now}
	for i := 0; i < cspReportMaxSources+500; i++ {
		b.take("src-" + strings.Repeat("x", i%7) + string(rune(i)))
	}
	for i := 0; i < cspReportMaxSources+500; i++ {
		b.reserve("src-" + strings.Repeat("x", i%7) + string(rune(i)))
	}
	if len(b.perLogSrc) > cspReportMaxSources+1 || len(b.perReqSrc) > cspReportMaxSources+1 {
		t.Fatalf("per-source maps grew to %d / %d entries", len(b.perLogSrc), len(b.perReqSrc))
	}
}

func TestCSPRequestBudgetIsReservedBeforeReadingAndChargesGarbage(t *testing.T) {
	buf := captureCSPLog(t)
	b := &cspReportBudget{now: time.Now}
	h := handleCSPReport(b)
	// Garbage and oversized bodies spend the source's request budget like valid ones.
	big := `{"csp-report":{"blocked-uri":"` + strings.Repeat("a", cspReportMaxBody) + `"}}`
	for i := 0; i < cspRequestPerSource; i++ {
		body := "not json"
		if i%2 == 1 {
			body = big
		}
		postCSP(t, h, "application/csp-report", body)
	}
	if b.perReqSrc["unknown"] != cspRequestPerSource {
		t.Fatalf("request budget spent %d, want %d", b.perReqSrc["unknown"], cspRequestPerSource)
	}
	// Once spent, even a valid report is refused without being read or logged.
	valid := `{"csp-report":{"effective-directive":"img-src","document-uri":"https://main.example/console"}}`
	if code := postCSP(t, h, "application/csp-report", valid); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	if strings.Contains(buf.String(), "img-src") {
		t.Fatalf("a report beyond the request budget was logged: %q", buf.String())
	}
}

func TestCSPRequestReservationIsAtomicUnderConcurrency(t *testing.T) {
	b := &cspReportBudget{now: time.Now}
	var mu sync.Mutex
	admitted := 0
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := b.reserve("same-source"); ok {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != cspRequestPerSource {
		t.Fatalf("%d concurrent requests admitted, want exactly %d", admitted, cspRequestPerSource)
	}
}

func TestCSPURLRedaction(t *testing.T) {
	for in, want := range map[string]string{
		"https://main.example/join/AB12CD?x=1":                     "https://(this-site)/join/(redacted)",
		"https://user" + ":" + "pw" + "@main.example/console#frag": "https://(this-site)/console", // userinfo (split so the export scan does not read a credential)
		"https://main.example/assets/index-abc.js":                 "https://(this-site)/assets/*.js",
		"https://main.example/assets/CAPABILITY.js":                "https://(this-site)/assets/*.js",
		"https://main.example/docs/backups":                        "https://(this-site)/docs/*",
		"https://main.example/docs/capability":                     "https://(this-site)/docs/*",
		"https://main.example/cp/recordings/r1/download":           "https://(this-site)/cp/(redacted)",
		"https://main.example/secret-capability-token":             "https://(this-site)/(redacted)",
		"https://main.example/":                                    "https://(this-site)/",
		"https://MAIN.example:443/console":                         "https://(this-site)/console",
		"https://evil.example/assets/CAPABILITY.js":                "https://(other-origin)",
		"https://cap-token.main.example/console":                   "https://(other-origin)",
		"https://main.example/assets/../join/CAP":                  "https://(this-site)/(redacted)",
		"https://main.example/assets/a%2Fb.js":                     "https://(this-site)/(redacted)",
		"https://main.example/docs/Backups_SECRET":                 "https://(this-site)/(redacted)",
		"wss://main.example/ws":                                    "wss://(this-site)/(redacted)",
		"data:image/png;base64,AAAA":                               "data:",
		"blob:https://main.example/1234-5678":                      "blob:",
		"weird-scheme:payload":                                     "(other-scheme)",
		"inline":                                                   "inline",
		"eval":                                                     "eval",
		"wasm-eval":                                                "wasm-eval",
		"secretkeyword":                                            "(redacted)",
		"Not A Keyword!":                                           "(redacted)",
		"://broken":                                                "(unparsable)",
	} {
		if got := cspURL(in, "main.example"); got != want {
			t.Errorf("cspURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// A forged Host only decides which origin counts as "this site"; its VALUE must never reach the log.
func TestCSPReportForgedHostValueIsNeverLogged(t *testing.T) {
	buf := captureCSPLog(t)
	h := handleCSPReport(&cspReportBudget{now: time.Now})
	req := httptest.NewRequest(http.MethodPost, "/csp-report", strings.NewReader(
		`{"csp-report":{"effective-directive":"img-src","document-uri":"https://cap-value.example/","blocked-uri":"https://cap-value.example/console"}}`))
	req.Host = "cap-value.example"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got := buf.String(); !strings.Contains(got, "csp-report:") || strings.Contains(got, "cap-value") {
		t.Fatalf("the forged host value reached the log (or nothing was logged): %q", got)
	}
}
func TestCSPReportIgnoresGarbage(t *testing.T) {
	buf := captureCSPLog(t)
	h := handleCSPReport(&cspReportBudget{now: time.Now})
	for _, body := range []string{"", "not json", `{"other":1}`, `[1,2,3]`, `{"csp-report":null}`} {
		if code := postCSP(t, h, "application/csp-report", body); code != http.StatusNoContent {
			t.Fatalf("%q: status %d", body, code)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("garbage was logged: %q", buf.String())
	}
}
