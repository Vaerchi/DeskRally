package main

// Guard: an environment variable this binary reads must reach it in the production compose stack.
//
// Production runs deploy/docker-compose.yml merged with deploy/docker-compose.prod.yml, and `environment:`
// maps merge per key. A container sees ONLY the keys the merged files name, so a variable the server reads
// but no file forwards is a .env line that silently does nothing. That happened twice (signaling's TURN
// credential caps, most recently); the symptom is the default quietly applying while the operator believes
// the knob is set. Optional overlays (docker-compose.installer.yml) are NOT production: what only an
// overlay forwards is listed in composeOverlayClaims, and the test checks the overlay still names it.
//
// The scanner and the rule live in envscan_test.go (identical across the three server binaries).

import (
	"os"
	"testing"
)

const composeDir = "../../deploy/"

// prodComposeFiles are the files production runs (and only them).
var prodComposeFiles = []string{composeDir + "docker-compose.yml", composeDir + "docker-compose.prod.yml"}

// composeServices are the services built from this binary.
var composeServices = []string{"relay"}

// scanDirs are the directories whose non-test files this binary compiles (package main; the module has no
// other source package).
var scanDirs = []string{"."}

// servicesForFunc: this binary has one mode, so every read belongs to its one service.
func servicesForFunc(string) []string { return composeServices }

// composeOverlayClaims: variables an optional overlay alone forwards. None for this binary.
var composeOverlayClaims = map[string]overlayClaim{}

// composeEnvAllowlist: variables the binary reads that are DELIBERATELY not forwarded, with the reason.
// An entry that is forwarded after all, or no longer read, fails the test so the list cannot rot.
var composeEnvAllowlist = map[string]string{}

// sanityFloor: reads the scan must always find, or it has gone blind.
var sanityFloor = []string{"RELAY_MAX_CONNECTIONS"}

// scannerCopies are the other binaries' copies of envscan_test.go; they must stay byte-identical to this one.
var scannerCopies = []string{"../../control-plane/cmd/controlplane/envscan_test.go", "../signaling/envscan_test.go"}

func TestComposeForwardsEveryEnvVarTheServerReads(t *testing.T) {
	fset, files := parseNonTestFiles(t, scanDirs)
	res := scanEnvFiles(fset, files, scanConfig{Imports: moduleImportDirs(t), Exemptions: readerExemptions})
	for _, u := range res.Unresolved {
		t.Errorf("unresolved env read: %s", u)
	}
	readNames := readNamesOf(res.Reads)
	for _, must := range sanityFloor {
		if !readNames[must] {
			t.Fatalf("scan did not find %s: the scanner no longer sees this binary's env reads", must)
		}
	}
	prod := composeEnvKeys(t, prodComposeFiles)
	for _, s := range composeServices {
		if prod[s] == nil {
			t.Fatalf("service %q not found in the production compose files: the compose scan is blind", s)
		}
	}
	overlayKeys := map[string]map[string]map[string]bool{}
	overlay := map[string]map[string]bool{}
	for name, c := range composeOverlayClaims {
		if overlayKeys[c.File] == nil {
			overlayKeys[c.File] = composeEnvKeys(t, []string{c.File})
		}
		if overlay[c.Service] == nil {
			overlay[c.Service] = map[string]bool{}
		}
		overlay[c.Service][name] = true
	}
	for _, p := range checkOverlayClaims(composeOverlayClaims, overlayKeys, prod, readNames) {
		t.Error(p)
	}
	for _, p := range checkComposeEnv(res.Reads, servicesForFunc, composeEnvRules{Prod: prod, Overlay: overlay, Allow: composeEnvAllowlist}) {
		t.Error(p)
	}
}

func TestEnvScannerCopiesAreIdentical(t *testing.T) {
	mine, err := os.ReadFile("envscan_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range scannerCopies {
		other, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if string(other) != string(mine) {
			t.Errorf("%s differs from envscan_test.go: the shared env scanner must be changed in all three binaries together", p)
		}
	}
}
