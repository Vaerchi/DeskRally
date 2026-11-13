package controlplane_test

import (
	"testing"
	"time"

	cp "rmt/controlplane"
)

// From outside the package, the only verified values are the ones Verify* returns. A zero value
// (what a caller holds after ignoring a verification error) must be refused, never evaluated, and
// never panic.
func TestUnverifiedZeroValuesAreRefused(t *testing.T) {
	var p cp.DeploymentPass
	var r cp.AgentRelease
	if p.Verified() || r.Verified() {
		t.Fatal("a zero value reports itself verified")
	}
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	if err := p.CheckValidAt(now); err == nil {
		t.Error("a zero pass is valid now")
	}
	if err := r.CheckValidAt(now); err == nil {
		t.Error("a zero release is valid now")
	}
	for name, f := range map[string]func() error{
		"zero pass":    func() error { return cp.PassAdmitsRelease(cp.DeploymentPass{}, r) },
		"zero release": func() error { return cp.PassAdmitsRelease(p, cp.AgentRelease{}) },
		"both zero":    func() error { return cp.PassAdmitsRelease(cp.DeploymentPass{}, cp.AgentRelease{}) },
	} {
		func() {
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("%s: panicked: %v", name, v)
				}
			}()
			if err := f(); err == nil {
				t.Errorf("%s: admitted", name)
			}
		}()
	}
}
