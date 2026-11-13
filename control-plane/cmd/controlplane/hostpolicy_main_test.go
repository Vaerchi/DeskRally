package main

import "testing"

const testSecret = "0123456789abcdef0123456789abcdef"

func clearHostEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"CP_DEFAULT_HOSTS", "CP_LEGACY_UNSCOPED_HOSTS", "CP_PUBLIC_AUTHORITIES", "CP_EDGE_SECRET", "CP_HOST_THEMING"} {
		t.Setenv(k, "")
	}
}

// PRODUCTION TODAY: CP_TENANT_HOST_SUFFIX is set (SSO tenant hosts) and there is no edge secret or Caddy marker.
// The control plane must start and behave exactly as before: no policy, so redemption is unscoped and there is
// no authority gate and no secret requirement.
func TestSuffixAloneNeverEnablesTheHostPolicy(t *testing.T) {
	clearHostEnv(t)
	for _, theming := range []string{"", "off", "0", "false"} {
		t.Setenv("CP_HOST_THEMING", theming)
		p, err := buildHostPolicy(".deskrally.com")
		if p != nil || err != nil {
			t.Fatalf("CP_HOST_THEMING=%q with a suffix: %v %v, want a nil policy and no error", theming, p, err)
		}
	}
	// Even a stray edge secret or authority list does not switch it on.
	t.Setenv("CP_EDGE_SECRET", testSecret)
	t.Setenv("CP_PUBLIC_AUTHORITIES", "main.deskrally.com")
	if p, err := buildHostPolicy(".deskrally.com"); p != nil || err != nil {
		t.Fatalf("secret/authorities without the switch: %v %v", p, err)
	}
	if p, err := buildHostPolicy(""); p != nil || err != nil {
		t.Fatalf("no configuration: %v %v", p, err)
	}
}

func TestThemingOnWithoutAValidEdgeSecretRefusesToStart(t *testing.T) {
	clearHostEnv(t)
	t.Setenv("CP_HOST_THEMING", "on")
	for _, bad := range []string{"", "short", testSecret[:31]} {
		t.Setenv("CP_EDGE_SECRET", bad)
		if p, err := buildHostPolicy(".deskrally.com"); err == nil || p != nil {
			t.Fatalf("theming on, secret %q: %v %v, want a startup error", bad, p, err)
		}
	}
	// An explicit default host enables it too, and then also needs the secret.
	t.Setenv("CP_HOST_THEMING", "")
	t.Setenv("CP_DEFAULT_HOSTS", "support.corp.example")
	t.Setenv("CP_EDGE_SECRET", "")
	if p, err := buildHostPolicy(""); err == nil || p != nil {
		t.Fatalf("explicit default host without a secret: %v %v", p, err)
	}
	// Theming on with nothing naming the default host is a configuration error.
	t.Setenv("CP_DEFAULT_HOSTS", "")
	t.Setenv("CP_HOST_THEMING", "on")
	t.Setenv("CP_EDGE_SECRET", testSecret)
	if p, err := buildHostPolicy(""); err == nil || p != nil {
		t.Fatalf("theming on without a default host or suffix: %v %v", p, err)
	}
}

func TestThemingOnWithASecretActivatesThePolicy(t *testing.T) {
	clearHostEnv(t)
	t.Setenv("CP_HOST_THEMING", "on")
	t.Setenv("CP_EDGE_SECRET", testSecret)
	p, err := buildHostPolicy(".deskrally.com")
	if err != nil || p == nil {
		t.Fatalf("theming on with a secret: %v %v", p, err)
	}
	if !p.GateInstalled() || !p.Theming() {
		t.Error("the gate and the theming flag must be on")
	}
	// main is the default, loam and vc are the named legacy hosts, everything else is scoped.
	for host, unscoped := range map[string]bool{
		"main.deskrally.com": true, "loam.deskrally.com": true, "vc.deskrally.com": true,
		"acme.deskrally.com": false, "evil.example.com": false,
	} {
		if got := p.ScopeFor(host).Unscoped; got != unscoped {
			t.Errorf("%s: unscoped = %v, want %v", host, got, unscoped)
		}
	}
	// "none" empties the legacy list; an explicit list replaces the default.
	t.Setenv("CP_LEGACY_UNSCOPED_HOSTS", "none")
	p, _ = buildHostPolicy(".deskrally.com")
	if p.ScopeFor("loam.deskrally.com").Unscoped {
		t.Error("CP_LEGACY_UNSCOPED_HOSTS=none must leave no legacy host")
	}
	t.Setenv("CP_LEGACY_UNSCOPED_HOSTS", "old.deskrally.com, older.deskrally.com")
	p, _ = buildHostPolicy(".deskrally.com")
	if !p.ScopeFor("older.deskrally.com").Unscoped || p.ScopeFor("vc.deskrally.com").Unscoped {
		t.Error("an explicit legacy list replaces the default")
	}
	// A self-hosted deployment on its own domain opts in with an explicit default host.
	t.Setenv("CP_HOST_THEMING", "")
	t.Setenv("CP_LEGACY_UNSCOPED_HOSTS", "")
	t.Setenv("CP_DEFAULT_HOSTS", "support.corp.example")
	p, err = buildHostPolicy("")
	if err != nil || p == nil || !p.ScopeFor("support.corp.example").Unscoped || p.ScopeFor("x.corp.example").Unscoped {
		t.Fatalf("explicit default host: %v %v", p, err)
	}
	// Garbage is a startup error, not a silently ignored line.
	t.Setenv("CP_DEFAULT_HOSTS", "bad host")
	if _, err := buildHostPolicy(""); err == nil {
		t.Error("a malformed default host must be refused")
	}
}
