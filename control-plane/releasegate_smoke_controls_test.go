//go:build releasegate

package controlplane

// Negative controls for the real-binary smoke stage (plan step 7): each hard-gate check is pointed at a target that
// breaks the rule and must report failure, and at a correct in-test target and must pass. None needs the binary or a
// database, so they are quick; they run in the same release-gate invocation.
//
//	go test -tags releasegate -run TestReleaseGateSmokeControl -count=1 .

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func smokeOKHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			buf := make([]byte, 4096)
			for {
				if _, err := r.Body.Read(buf); err != nil {
					break
				}
			}
		}
		_, _ = w.Write([]byte("ok"))
	})
}

// smokeServe starts srv on 127.0.0.1:0 (through LimitListener when limit) and returns its address.
func smokeServe(t *testing.T, srv *http.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(LimitListener(ln, 64)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func smokeFailed(cases []smokeH2Case, name string) (found, failed bool) {
	for _, c := range cases {
		if c.Name == name {
			return true, !c.Pass
		}
	}
	return false, false
}

// A listener that DOES speak h2c (prior knowledge, via the standard library's unencrypted HTTP/2) and answers the
// Upgrade with 101 must fail the h2c, Upgrade and Go-client attempts.
func TestReleaseGateSmokeControlHTTP2SpeakingServerFails(t *testing.T) {
	protos := new(http.Protocols)
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 1 && strings.EqualFold(r.Header.Get("Upgrade"), "h2c") {
			if hj, ok := w.(http.Hijacker); ok {
				c, _, err := hj.Hijack()
				if err == nil {
					_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"))
					_ = c.Close()
					return
				}
			}
		}
		_, _ = w.Write([]byte("ok"))
	})
	addr := smokeServe(t, &http.Server{Handler: h, Protocols: protos})
	cases := smokeHTTP2Check(addr)
	for _, name := range []string{"h2c prior knowledge", "h2c Upgrade", "Go client, unencrypted HTTP/2 only"} {
		found, failed := smokeFailed(cases, name)
		if !found || !failed {
			t.Errorf("the check %q did not fail against an h2c-speaking server (found=%v): %+v", name, found, cases)
		}
	}
}

// A TLS listener that negotiates h2 must fail the ALPN attempt.
func TestReleaseGateSmokeControlTLSH2ServerFails(t *testing.T) {
	srv := httptest.NewUnstartedServer(smokeOKHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	cases := smokeHTTP2Check(srv.Listener.Addr().String())
	if found, failed := smokeFailed(cases, "TLS ALPN h2 hello"); !found || !failed {
		t.Errorf("the ALPN check did not fail against a TLS server that negotiates h2 (found=%v): %+v", found, cases)
	}
}

// The check passes every case on a correct target: the production constructor, HTTP/1.1 only.
func TestReleaseGateSmokeControlHTTP2RefusingServerPasses(t *testing.T) {
	mux := http.NewServeMux() // the binary routes through a mux, which refuses the h2 preface target "*" with 400
	mux.Handle("/", smokeOKHandler())
	addr := smokeServe(t, NewPublicServer("", mux, PublicServerConfig{}))
	for _, c := range smokeHTTP2Check(addr) {
		if !c.Pass {
			t.Errorf("a correct HTTP/1.1-only target failed %q: %s", c.Name, c.Outcome)
		}
	}
}

// A server with no ReadHeaderTimeout, no ReadTimeout and no exchange bound never cuts a slow connection: the check
// must report both kinds as not cut within the bound. The bound is 1 s here only to keep the control short.
func TestReleaseGateSmokeControlNoTimeoutsFailsSlowloris(t *testing.T) {
	addr := smokeServe(t, &http.Server{Handler: smokeOKHandler()})
	slow, _, failures := smokeSlowlorisCheck(addr, "x", time.Second, time.Second, time.Second, 2)
	for _, kind := range []string{"header", "body"} {
		var hit bool
		for _, f := range failures {
			if strings.Contains(f, "slowloris "+kind+":") && strings.Contains(f, "still open") {
				hit = true
			}
		}
		if !hit {
			t.Errorf("the %s check did not report 'still open' against a server with no timeouts; failures=%v slow=%+v", kind, failures, slow)
		}
	}
}

// And it passes against the production constructor with the same small bound (header and body cut at 1 s), with
// ordinary requests succeeding throughout.
func TestReleaseGateSmokeControlTimeoutsPassSlowloris(t *testing.T) {
	addr := smokeServe(t, NewPublicServer("", smokeOKHandler(), PublicServerConfig{ReadHeaderTimeout: time.Second, ReadTimeout: time.Second}))
	slow, probes, failures := smokeSlowlorisCheck(addr, "x", time.Second, time.Second, time.Second, 2)
	if len(failures) > 0 {
		t.Errorf("a server with 1 s timeouts failed the slowloris check: %v (slow=%+v probes=%+v)", failures, slow, probes)
	}
}

func TestReleaseGateSmokeControlColdVerdict(t *testing.T) {
	good := smokeColdObs{Cycle: 2, Status: 200, Took: 160 * time.Millisecond, Body: []byte(`{"n":1}`), Body2: []byte(`{"n":1}`),
		FirstBody: []byte(`{"n":1}`), Forged: 421, Healthz: 200}
	if f := smokeColdVerdict(good); len(f) != 0 {
		t.Fatalf("a correct observation failed: %v", f)
	}
	cases := map[string]func(o *smokeColdObs){
		"first response before the 150 ms floor":  func(o *smokeColdObs) { o.Took = 40 * time.Millisecond },
		"first body differs from the warm body":   func(o *smokeColdObs) { o.Body2 = []byte(`{"n":2}`) },
		"first body differs from the first start": func(o *smokeColdObs) { o.FirstBody = []byte(`{"n":9}`) },
		"forged authority not refused":            func(o *smokeColdObs) { o.Forged = 200 },
		"first request not 200":                   func(o *smokeColdObs) { o.Status = 503 },
		"healthz down":                            func(o *smokeColdObs) { o.Healthz = 500 },
	}
	for name, mutate := range cases {
		o := good
		o.Body, o.Body2, o.FirstBody = bytes.Clone(good.Body), bytes.Clone(good.Body2), bytes.Clone(good.FirstBody)
		mutate(&o)
		if f := smokeColdVerdict(o); len(f) == 0 {
			t.Errorf("%s: the verdict passed it", name)
		}
	}
}
