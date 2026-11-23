package controlplane

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Audit 2026-11-01 #11/#15. MUTATIONS: make acquireSupportFor skip the per-IP take -> the first two
// tests fail; skip the per-code take -> TestSupportBundleOneCodeCannotBeHammered fails; unbounded
// table (maxKeys huge) -> TestKeyedBucketsTableIsBounded fails.

func postSupportBundle(srv *Server, ip, code string) int {
	r := httptest.NewRequest("POST", "/attended-sessions/support-bundle", strings.NewReader(`{"code":"`+code+`"}`))
	r.RemoteAddr = ip + ":4000"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, r)
	return rec.Code
}

func codeN(i int) string {
	const a = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	return "00000000" + string(a[(i/1024)%32]) + string(a[(i/32)%32]) + string(a[i%32]) + "00"
}

func TestSupportBundleAnonymousFloodCannotStarveOtherCallers(t *testing.T) {
	srv, _ := supportBundleServer(t)
	denied := 0
	for i := 0; i < 200; i++ {
		if postSupportBundle(srv, "203.0.113.9", codeN(i)) == 429 {
			denied++
		}
	}
	if denied < 190 {
		t.Fatalf("attacker was denied only %d/200 times by its own budget", denied)
	}
	// The global backstop is untouched by the attacker's refused requests: other guests still work.
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		if c := postSupportBundle(srv, ip, codeN(1000+i)); c != 200 {
			t.Fatalf("legitimate guest %s got %d after another source's flood, want 200", ip, c)
		}
	}
}

func TestSupportBundleInvalidCodesCostOnlyTheCallersBudget(t *testing.T) {
	srv, _ := supportBundleServer(t)
	for i := 0; i < 50; i++ {
		postSupportBundle(srv, "203.0.113.9", codeN(i))
	}
	// Global bucket: only the attacker's few admitted requests could have spent it.
	g := srv.ManagedInstaller.supportLimiter().global
	g.mu.Lock()
	left := g.m["global"].tokens
	g.mu.Unlock()
	if left < supportGlobalBurst-supportIPBurst-1 {
		t.Fatalf("global backstop had only %.1f tokens left; the attacker's refused requests drained it", left)
	}
}

func TestSupportBundleOneCodeCannotBeHammered(t *testing.T) {
	srv, _ := supportBundleServer(t)
	ok := 0
	for i := 0; i < 20; i++ {
		if postSupportBundle(srv, "198.51.100."+string(rune('1'+i%9))+string(rune('0'+i/9)), "0123456789ABC") == 200 {
			ok++
		}
	}
	if ok != int(supportCodeBurst) {
		t.Fatalf("one code from many IPs got %d downloads, want the per-code burst %d", ok, int(supportCodeBurst))
	}
}

func TestKeyedBucketsTableIsBounded(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newKeyedBuckets(2, time.Minute, 0)
	k.maxKeys = 40
	for i := 0; i < 5000; i++ {
		k.take(codeN(i), now)
	}
	if len(k.m) > 41 {
		t.Fatalf("table grew to %d", len(k.m))
	}
	if _, ok := k.take(codeN(9000), now); ok {
		// overflow bucket shared: 2 tokens total, already consumed by earlier overflow callers
		t.Fatal("overflow bucket still granting after saturation")
	}
}
