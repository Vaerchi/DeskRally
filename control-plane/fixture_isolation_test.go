package controlplane

// ISOLATION GUARD for the hostname-theming e2e fixture (docs/66 stage 2).
//
// cmd/cpthemefixture lets a browser test choose the authority a request "arrived on" with a routing header, because
// the e2e reaches the control plane through the Vite dev proxy, which rewrites Host. That is acceptable ONLY because
// the header exists in the fixture binary and nowhere else: the production handler reads r.Host and nothing a client
// can put in a header or a query (tenantFromHost's own rule, "never use a query parameter to select a tenant", applies
// to headers too). If a future change taught the production code, the production binary or the deploy files to honour
// that header, a forged request could pick its own tenant host, so this test scans every production Go source and
// the Caddyfiles for the header's name.
//
// The scan has a NEGATIVE CONTROL: the fixture's own source must contain the name, or the needle is misspelled and
// the scan is vacuous.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The name is split so that this file does not match itself.
var fixtureRoutingHeader = "X-Fixture" + "-Host"

func TestFixtureRoutingHeaderIsAbsentFromProductionCode(t *testing.T) {
	needle := strings.ToLower(fixtureRoutingHeader)

	fixtureSrc, err := os.ReadFile(filepath.Join("cmd", "cpthemefixture", "main.go"))
	if err != nil {
		t.Fatalf("the fixture source must exist (negative control): %v", err)
	}
	if !strings.Contains(strings.ToLower(string(fixtureSrc)), needle) {
		t.Fatalf("negative control failed: cmd/cpthemefixture/main.go does not contain %q, so this scan would prove nothing", fixtureRoutingHeader)
	}

	var scanned int
	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// The fixture binaries are test-only by construction; every other directory is production code.
			if path == filepath.Join("cmd", "cpthemefixture") || path == filepath.Join("cmd", "cptestfixture") || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		if strings.Contains(strings.ToLower(string(src)), needle) {
			t.Errorf("%s mentions the e2e fixture's routing header %q: production code must never honour a header to pick the authority (docs/66 2a.2)", path, fixtureRoutingHeader)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d production sources: the walk is not reaching the control plane (wrong working directory?)", scanned)
	}

	// The deploy files the control plane is reached through in production.
	for _, rel := range []string{"../deploy/Caddyfile", "../deploy/native/Caddyfile", "../deploy/docker-compose.prod.yml"} {
		src, err := os.ReadFile(rel)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if strings.Contains(strings.ToLower(string(src)), needle) {
			t.Errorf("%s mentions the e2e fixture's routing header %q", rel, fixtureRoutingHeader)
		}
	}
}
