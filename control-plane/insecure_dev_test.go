package controlplane

import (
	"strings"
	"testing"
)

// The two seeds are DELIBERATELY DIFFERENT everywhere in this file. A test that passed the same
// value as both the production and the dev seed would pass just as happily against code that read
// the wrong one, which is the whole defect F13 describes (21 unit tests once passed against fully
// inverted control wiring on this project for exactly that reason).
const (
	prodSeedSentinel = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	devSeedSentinel  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func mustDecide(t *testing.T, cfg StartupConfig) StartupDecision {
	t.Helper()
	dec, err := DecideStartup(cfg)
	if err != nil {
		t.Fatalf("DecideStartup(%+v): unexpected error: %v", cfg, err)
	}
	return dec
}

func decideErr(t *testing.T, cfg StartupConfig) string {
	t.Helper()
	dec, err := DecideStartup(cfg)
	if err == nil {
		t.Fatalf("DecideStartup(%+v): expected refusal, got mode=%s listen=%q", cfg, dec.Mode, dec.Listen)
	}
	return err.Error()
}

// THE HEADLINE FIX. An absent DSN used to select a full-owner stub authenticator; it must now stop
// the process. The message has to name both the missing variable and the flag that means it, since
// an operator meeting this on a restart needs to know which of the two they intended.
func TestNoDatabaseURLAndNoDevFlagIsFatal(t *testing.T) {
	msg := decideErr(t, StartupConfig{Listen: ":8081"})
	for _, want := range []string{"DATABASE_URL", EnvInsecureDev} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal must name %q; got: %s", want, msg)
		}
	}
}

// The NEGATIVE CONTROL for the case above, and the one that keeps the fix from being a brick: a
// real DSN with no flag is the ordinary production path and must be untouched.
func TestProductionIsTheDefaultAndIsPassedThroughUnchanged(t *testing.T) {
	dec := mustDecide(t, StartupConfig{
		DatabaseURL:     "postgres://rmt_app@db/rmt",
		Listen:          "0.0.0.0:8081",
		GrantIssuerSeed: prodSeedSentinel,
		DevGrantSeed:    devSeedSentinel,
	})
	if dec.Mode != ModeProduction {
		t.Fatalf("mode = %s, want production", dec.Mode)
	}
	// Production must NOT be confined to loopback: the real deployment binds a routable address
	// behind Caddy, and narrowing it here would break every deployment.
	if dec.Listen != "0.0.0.0:8081" {
		t.Errorf("production listen = %q, want it passed through unchanged", dec.Listen)
	}
	// Asymmetric: production reads the PRODUCTION seed even though a dev seed is also present.
	if dec.GrantSeed != prodSeedSentinel {
		t.Errorf("production seed = %q, want the GRANT_ISSUER_SEED value %q", dec.GrantSeed, prodSeedSentinel)
	}
}

// Whitespace must not smuggle a value past the emptiness checks in either direction.
func TestWhitespaceOnlyDatabaseURLIsStillAbsent(t *testing.T) {
	msg := decideErr(t, StartupConfig{DatabaseURL: "   \t ", Listen: ":8081"})
	if !strings.Contains(msg, "DATABASE_URL") {
		t.Errorf("a whitespace-only DSN must be treated as absent; got: %s", msg)
	}
	// And the same string must not be read as a real DSN by the dev-mode contradiction check.
	dec := mustDecide(t, StartupConfig{InsecureDev: true, DatabaseURL: "  ", Listen: ":8081"})
	if dec.Mode != ModeInsecureDev {
		t.Errorf("mode = %s, want insecure-dev", dec.Mode)
	}
}

func TestDevFlagWithARealDSNIsRefusedAsContradictory(t *testing.T) {
	msg := decideErr(t, StartupConfig{
		InsecureDev: true,
		DatabaseURL: "postgres://rmt_app@db/rmt",
		Listen:      ":8081",
	})
	if !strings.Contains(msg, "contradictory") {
		t.Errorf("refusal should explain the contradiction; got: %s", msg)
	}
}

// THE SEED REFUSAL. Measured at HEAD: a supplied GRANT_ISSUER_SEED produced a deterministic issuer
// key in dev mode, so a retained production seed signed grants that production agents accept while
// the server answered anonymous requests as owner.
func TestProductionSeedIsRefusedInDevModeAndPointsAtTheDevVariable(t *testing.T) {
	msg := decideErr(t, StartupConfig{
		InsecureDev:     true,
		Listen:          ":8081",
		GrantIssuerSeed: prodSeedSentinel,
	})
	if !strings.Contains(msg, EnvInsecureDevGrantSeed) {
		t.Errorf("refusal must name the dev-only variable %q so the operator knows the way out; got: %s",
			EnvInsecureDevGrantSeed, msg)
	}
}

// Asymmetric counterpart: dev mode reads the DEV seed and nothing else.
func TestDevModeUsesTheDevSeed(t *testing.T) {
	dec := mustDecide(t, StartupConfig{
		InsecureDev:  true,
		Listen:       "127.0.0.1:8081",
		DevGrantSeed: devSeedSentinel,
	})
	if dec.GrantSeed != devSeedSentinel {
		t.Errorf("dev seed = %q, want %q", dec.GrantSeed, devSeedSentinel)
	}
	for _, w := range dec.Warnings {
		if strings.Contains(w, EnvInsecureDevGrantSeed) && strings.Contains(w, "ephemeral") {
			t.Errorf("must not warn about an ephemeral key when a dev seed WAS supplied: %s", w)
		}
	}
}

func TestDevModeWithNoSeedWarnsThatTheKeyIsEphemeral(t *testing.T) {
	dec := mustDecide(t, StartupConfig{InsecureDev: true, Listen: "127.0.0.1:8081"})
	if dec.GrantSeed != "" {
		t.Errorf("GrantSeed = %q, want empty so main() generates an ephemeral key", dec.GrantSeed)
	}
	if !warnsAbout(dec, "ephemeral") {
		t.Errorf("expected an ephemeral-key warning; got %v", dec.Warnings)
	}
}

// A bare `:port` is what the default and nearly every harness passes, and it means ALL INTERFACES
// to Go. Narrowed rather than refused, on purpose: an annoying safe path gets switched off.
func TestBarePortIsNarrowedToLoopbackWithAWarning(t *testing.T) {
	dec := mustDecide(t, StartupConfig{InsecureDev: true, Listen: ":8081"})
	if dec.Listen != "127.0.0.1:8081" {
		t.Fatalf("listen = %q, want 127.0.0.1:8081", dec.Listen)
	}
	if !warnsAbout(dec, "narrowed") {
		t.Errorf("a silently changed bind address must be announced; got %v", dec.Warnings)
	}
}

func TestAnEmptyListenGetsAnExplicitLoopbackAddress(t *testing.T) {
	dec := mustDecide(t, StartupConfig{InsecureDev: true, Listen: ""})
	if dec.Listen != "127.0.0.1:8081" {
		t.Errorf("listen = %q, want an explicit loopback default", dec.Listen)
	}
}

func TestExplicitlyRoutableBindIsRefusedInDevMode(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8081", "192.168.1.50:8081", "[::]:8081"} {
		msg := decideErr(t, StartupConfig{InsecureDev: true, Listen: addr})
		if !strings.Contains(msg, EnvInsecureDevListenAny) {
			t.Errorf("%s: refusal must name the opt-out; got: %s", addr, msg)
		}
	}
}

// The VM lab genuinely needs a bind another host can reach, so the opt-out must work — and must
// say plainly what it just did.
func TestListenAnyPermitsARoutableBindButShouts(t *testing.T) {
	dec := mustDecide(t, StartupConfig{
		InsecureDev:      true,
		AllowNonLoopback: true,
		Listen:           "0.0.0.0:9443",
	})
	if dec.Listen != "0.0.0.0:9443" {
		t.Fatalf("listen = %q, want the address honoured", dec.Listen)
	}
	if !warnsAbout(dec, "DANGER") {
		t.Errorf("an anonymous-owner server on a routable address must warn loudly; got %v", dec.Warnings)
	}
}

// The opt-out must not manufacture a scary warning when the bind is loopback anyway. Otherwise the
// DANGER line appears in ordinary local runs and stops meaning anything.
func TestListenAnyWithALoopbackBindDoesNotWarn(t *testing.T) {
	dec := mustDecide(t, StartupConfig{
		InsecureDev:      true,
		AllowNonLoopback: true,
		Listen:           "127.0.0.1:8081",
	})
	if warnsAbout(dec, "DANGER") {
		t.Errorf("loopback bind must not raise DANGER; got %v", dec.Warnings)
	}
}

func TestLoopbackFormsAreAcceptedUnchanged(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8081", "127.0.0.53:8081", "[::1]:8081", "localhost:8081", "LOCALHOST:8081"} {
		dec := mustDecide(t, StartupConfig{InsecureDev: true, Listen: addr})
		if dec.Listen != addr {
			t.Errorf("listen %q was rewritten to %q; loopback forms must pass through", addr, dec.Listen)
		}
		if warnsAbout(dec, "narrowed") {
			t.Errorf("%s: must not claim to have narrowed an already-loopback address", addr)
		}
	}
}

// A hostname is NOT trusted to be loopback even if it resolves there today. A confinement check
// that believes DNS confines nothing.
func TestAHostnameIsNotTreatedAsLoopback(t *testing.T) {
	msg := decideErr(t, StartupConfig{InsecureDev: true, Listen: "cp.internal.example:8081"})
	if !strings.Contains(msg, EnvInsecureDevListenAny) {
		t.Errorf("a resolvable name must not be assumed loopback; got: %s", msg)
	}
}

// An unparseable bind address must stop rather than be guessed at, in the one mode whose entire
// job is confinement.
func TestUnparseableListenIsRefusedInDevMode(t *testing.T) {
	msg := decideErr(t, StartupConfig{InsecureDev: true, Listen: "8081"})
	if !strings.Contains(msg, "host:port") {
		t.Errorf("refusal should say what shape it wanted; got: %s", msg)
	}
}

func warnsAbout(dec StartupDecision, needle string) bool {
	for _, w := range dec.Warnings {
		if strings.Contains(w, needle) {
			return true
		}
	}
	return false
}
