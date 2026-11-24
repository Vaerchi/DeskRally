package controlplane

import (
	"os"
	"strings"
	"testing"
)

func TestCheckServingWiringRefusesStubsWithoutInsecureDev(t *testing.T) {
	real := &SessionAuthenticator{}
	cases := []struct {
		name        string
		auth        Authenticator
		binder      TenantBinder
		insecureDev bool
		dsn         string
		wantErr     string
	}{
		{"production wiring", real, &recordingBinder{}, false, "postgres://x", ""},
		{"dev wiring declared", &APITokenAuthenticator{Next: StubAuthenticator{}}, NoopBinder{}, true, "", ""},
		{"stub auth, not declared", StubAuthenticator{}, &recordingBinder{}, false, "postgres://x", "stub authenticator=true"},
		{"stub behind api-token wrapper, not declared", &APITokenAuthenticator{Next: StubAuthenticator{}}, &recordingBinder{}, false, "", "stub authenticator=true"},
		{"stub behind guarded wrapper, not declared", &GuardedAuthenticator{Next: &APITokenAuthenticator{Next: StubAuthenticator{}}}, &recordingBinder{}, false, "", "stub authenticator=true"},
		{"noop binder, not declared", real, NoopBinder{}, false, "", "no-op tenant binder=true"},
		{"noop binder with a database, even in dev", real, NoopBinder{}, true, "postgres://x", "DATABASE_URL is set"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewServer(tc.auth, tc.binder)
			err := CheckServingWiring(srv, tc.insecureDev, tc.dsn)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want serve, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want refusal containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// devstubs.go (cpdev builds) and devstubs_test.go (plain go test) must declare the same code.
func TestDevStubCopiesMatch(t *testing.T) {
	norm := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
			s := strings.TrimSpace(line)
			if s == "" || strings.HasPrefix(s, "//") {
				continue
			}
			out = append(out, s)
		}
		return strings.Join(out, "\n")
	}
	if a, b := norm("devstubs.go"), norm("devstubs_test.go"); a != b {
		t.Fatalf("devstubs.go and devstubs_test.go have drifted:\n--- devstubs.go\n%s\n--- devstubs_test.go\n%s", a, b)
	}
}
