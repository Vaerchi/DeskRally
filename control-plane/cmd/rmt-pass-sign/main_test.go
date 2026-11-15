package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	controlplane "rmt/controlplane"
)

const testGrant = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

// challengeServer serves body at the challenge path; the origin is https://127.0.0.1:<port>.
func challengeServer(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	orig := challengeClient
	challengeClient = func() *http.Client {
		c := orig()
		c.Transport = srv.Client().Transport // trust the test certificate; keep no-redirects
		return c
	}
	t.Cleanup(func() { challengeClient = orig })
	return srv.URL
}

func TestDomainCheck(t *testing.T) {
	nonce := newNonce()
	cases := []struct {
		name    string
		handler http.HandlerFunc
		ok      bool
	}{
		{"serves the nonce", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == challengePath {
				w.Write([]byte(nonce + "\n"))
			} else {
				http.NotFound(w, r)
			}
		}, true},
		{"serves the nonce with CRLF", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(nonce + "\r\n")) }, true},
		{"serves another nonce", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(newNonce())) }, false},
		{"serves the nonce plus more", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(nonce + " extra")) }, false},
		{"404", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }, false},
		{"redirects elsewhere", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == challengePath {
				http.Redirect(w, r, "/elsewhere", http.StatusFound)
				return
			}
			w.Write([]byte(nonce))
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			origin := challengeServer(t, c.handler)
			err := checkDomain(context.Background(), origin, nonce)
			if (err == nil) != c.ok {
				t.Fatalf("ok=%v, want %v (%v)", err == nil, c.ok, err)
			}
		})
	}
	if err := checkDomain(context.Background(), "https://127.0.0.1:1", "not-a-nonce"); err == nil {
		t.Error("a malformed nonce was accepted")
	}
}

func TestLabHost(t *testing.T) {
	for origin, want := range map[string]bool{
		"https://localhost": true, "https://localhost:8443": true, "https://cp.localhost": true,
		"https://lab.deskrally.test": true, "https://remote.example.com": false,
		"https://test.example.com": false, "https://localhost.example.com": false, "https://evil.test.com": false,
	} {
		if labHost(origin) != want {
			t.Errorf("labHost(%s) = %v", origin, !want)
		}
	}
}

func run(t *testing.T, f func([]string) error, args ...string) error {
	t.Helper()
	return f(args)
}

// TestIssueAttestVerifyEndToEnd drives the real commands, including the DPAPI key file.
func TestIssueAttestVerifyEndToEnd(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the root key store is Windows DPAPI only")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "root.key")
	if err := run(t, cmdGenKey, "-key", key); err != nil {
		t.Fatal(err)
	}
	if err := run(t, cmdGenKey, "-key", key); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("second gen-key at the same path: %v", err)
	}
	raw, _ := os.ReadFile(key)
	if strings.Count(string(raw), "\n") != 2 || !strings.HasPrefix(string(raw), keyFileHeader+"\n") {
		t.Fatalf("unexpected key file layout: %q", raw)
	}
	k, err := loadKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := controlplane.DeploymentRootKeyHex(&k.PublicKey)

	// Lab skip is refused for a real domain, and the refusal comes before any key use or output.
	out := filepath.Join(dir, "pass.json")
	err = run(t, cmdIssue, "-key", key, "-to", "Lab", "-origin", "https://remote.example.com",
		"-grant-issuer-pubkey", testGrant, "-min-agent-version", "1.3.5", "-lab-skip-domain-check", "-out", out)
	if err == nil || !strings.Contains(err.Error(), "only for localhost") {
		t.Fatalf("lab skip for a real domain: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("a refused issue wrote a pass")
	}
	if err := run(t, cmdIssue, "-key", key, "-to", "Lab", "-origin", "https://lab.deskrally.test",
		"-grant-issuer-pubkey", testGrant, "-min-agent-version", "1.3.5", "-days", "32", "-lab-skip-domain-check", "-out", out); err == nil {
		t.Fatal("-days 32 was accepted")
	}

	// A real issue through a recorded challenge and the domain check. The server serves whatever
	// `serving` holds, so each case below controls exactly which nonce the origin shows.
	var serving string
	// barrier, when set, holds each challenge request until a second one is in flight (or 400 ms
	// pass). Under the challenge lock only one request can be in flight, so a racer waits out the
	// timeout alone; without the lock two racers meet here and both pass the domain check. That
	// makes the race below deterministic instead of a matter of scheduling luck.
	var barrier atomic.Bool
	var inFlight atomic.Int32
	origin := challengeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if barrier.Load() {
			inFlight.Add(1)
			for deadline := time.Now().Add(400 * time.Millisecond); inFlight.Load() < 2 && time.Now().Before(deadline); {
				time.Sleep(5 * time.Millisecond)
			}
			defer inFlight.Add(-1)
		}
		w.Write([]byte(serving))
	})
	state := challengeStatePath(key)
	issue := func(nonce, out string) error {
		return run(t, cmdIssue, "-key", key, "-to", "Example MSP, LLC", "-origin", origin,
			"-grant-issuer-pubkey", testGrant, "-min-agent-version", "1.3.5", "-challenge", nonce, "-out", out)
	}
	// A nonce this workstation never issued is refused even though the origin serves it.
	serving = newNonce()
	if err := issue(serving, out); err == nil || !strings.Contains(err.Error(), "no challenge has been issued") {
		t.Fatalf("an unrecorded nonce: %v", err)
	}
	other, err := createChallenge(state, "https://other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	serving = other
	if err := issue(other, out); err == nil || !strings.Contains(err.Error(), "issued for https://other.example.com") {
		t.Fatalf("a nonce issued for another origin: %v", err)
	}
	// With a challenge record present, a nonce that is not in it is still refused.
	serving = newNonce()
	if err := issue(serving, out); err == nil || !strings.Contains(err.Error(), "was not issued") {
		t.Fatalf("an unrecorded nonce with a record present: %v", err)
	}
	nonce, err := createChallenge(state, origin)
	if err != nil {
		t.Fatal(err)
	}
	serving = newNonce() // the origin does NOT serve our nonce: no control shown, and not consumed
	if err := issue(nonce, out); err == nil || !strings.Contains(err.Error(), "does not serve this nonce") {
		t.Fatalf("origin not serving the nonce: %v", err)
	}
	serving = nonce
	if err := issue(nonce, out); err != nil {
		t.Fatal(err)
	}
	if err := issue(nonce, out+".replay"); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("a replayed nonce: %v", err)
	}
	// Concurrent issues racing one fresh nonce, to different outputs: exactly one may succeed.
	race, err := createChallenge(state, origin)
	if err != nil {
		t.Fatal(err)
	}
	serving = race
	barrier.Store(true)
	defer barrier.Store(false)
	const racers = 6
	errs := make(chan error, racers)
	for i := 0; i < racers; i++ {
		go func(i int) { errs <- issue(race, fmt.Sprintf("%s.race%d", out, i)) }(i)
	}
	wins := 0
	for i := 0; i < racers; i++ {
		if err := <-errs; err == nil {
			wins++
		} else if !strings.Contains(err.Error(), "already used") {
			t.Errorf("a losing racer failed for the wrong reason: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d concurrent issues succeeded with one nonce, want exactly 1", wins)
	}
	// An expired challenge is refused: move the clock past the 72 h window.
	late, err := createChallenge(state, origin)
	if err != nil {
		t.Fatal(err)
	}
	serving = late
	realNow := now
	now = func() time.Time { return realNow().Add(challengeTTL) }
	err = issue(late, out+".late")
	now = realNow
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired nonce: %v", err)
	}
	if err := run(t, cmdVerify, "-kind", "pass", "-in", out, "-pubkey", pub); err != nil {
		t.Fatalf("verify the issued pass: %v", err)
	}
	if err := run(t, cmdVerify, "-kind", "release", "-in", out, "-pubkey", pub); controlplane.SignedObjectErrorKindOf(err) != controlplane.SignedObjectBadSignature {
		t.Fatalf("a pass verified as a release attestation: %v", err)
	}
	if err := run(t, cmdVerify, "-kind", "pass", "-in", out, "-pubkey", pub, "-at", now().Add(32*24*time.Hour).Format(controlplane.PassTimeLayout)); controlplane.SignedObjectErrorKindOf(err) != controlplane.SignedObjectNotValidNow {
		t.Fatalf("the pass verified 32 days later: %v", err)
	}
	logRaw, err := os.ReadFile(filepath.Join(dir, "pass-issuance-log.jsonl"))
	if err != nil || strings.Count(string(logRaw), "\n") != 2 || !strings.Contains(string(logRaw), `"domain_check":true`) { // the issue + the race winner
		t.Fatalf("issuance log: %v %q", err, logRaw)
	}
	// The logged digest is the digest of the file actually written.
	passRaw, _ := os.ReadFile(out)
	sum := sha256.Sum256(passRaw)
	if !strings.Contains(string(logRaw), `"pass_sha256":"`+hex.EncodeToString(sum[:])+`"`) {
		t.Fatalf("the log's pass_sha256 is not the written file's digest: %s", logRaw)
	}
	fresh, _ := createChallenge(state, origin)
	serving = fresh
	if err := issue(fresh, out); err == nil {
		t.Fatal("issue overwrote an existing pass file")
	}
	if again, _ := os.ReadFile(filepath.Join(dir, "pass-issuance-log.jsonl")); string(again) != string(logRaw) {
		t.Fatal("a refused issue (existing -out) still appended to the issuance log")
	}

	// attest
	msi := filepath.Join(dir, "DeskRallyAgent.msi")
	os.WriteFile(msi, []byte("not really an msi, but bytes to hash"), 0o644)
	rel := filepath.Join(dir, "agent-release.json")
	if err := run(t, cmdAttest, "-key", key, "-msi", msi, "-product-version", "1.3.5",
		"-product-code", "{0F347057-1A2B-4C3D-8E9F-0123456789AB}", "-upgrade-code", "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}", "-out", rel); err != nil {
		t.Fatal(err)
	}
	relRaw, _ := os.ReadFile(rel)
	r, err := controlplane.VerifyAgentRelease(&k.PublicKey, relRaw, now())
	if err != nil {
		t.Fatal(err)
	}
	if c := r.Claims(); c.MSISize != 36 || c.ProductVersion != "1.3.5" {
		t.Fatalf("attested %+v", r)
	}
	if err := run(t, cmdAttest, "-key", key, "-msi", msi, "-product-version", "1.3.5",
		"-product-code", "{0f347057-1a2b-4c3d-8e9f-0123456789ab}", "-upgrade-code", "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}", "-out", rel+"2"); err == nil {
		t.Fatal("attest accepted a lowercase product code")
	}
}
