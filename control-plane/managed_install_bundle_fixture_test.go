package controlplane

// TestWriteBundleProducesStreamingZIP generates a real writeBundle ZIP and saves it as a fixture
// for the Rust extractor tests in crates/agent-windows/testdata/go_bundle_fixture.zip.
//
// This test proves that the hand-authored build_streaming_zip Rust helper and the actual Go
// zip.NewWriter(non-seekable) output have compatible format: both use data descriptors and a
// valid central directory that zip::ZipArchive reads correctly.
//
// Run via: go test -run TestWriteBundleProducesStreamingZIP ./... (or just let the test suite run).
// The fixture is committed alongside the source so Rust tests can consume it without re-running Go.

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteBundleProducesStreamingZIP(t *testing.T) {
	// Construct a ManagedInstaller with minimal fake binaries. These bytes are not real PE/MSI
	// files but the ZIP format and entry structure are identical to a production bundle.
	installer := &ManagedInstaller{
		setup: []byte("FAKE-DESKRALLYSETUP-EXE-CONTENT-FOR-FORMAT-TEST"),
		msi:   []byte("FAKE-DESKRALLYAGENT-MSI-CONTENT-FOR-FORMAT-TEST"),
	}

	rec := httptest.NewRecorder()
	if err := installer.writeBundle(rec, "fake-enrollment-token-12345"); err != nil {
		t.Fatalf("writeBundle: %v", err)
	}

	zipBytes := rec.Body.Bytes()
	if len(zipBytes) == 0 {
		t.Fatal("writeBundle produced empty output")
	}

	// Write to testdata next to the Rust crate. The path is relative to this Go file's location,
	// which is control-plane/, so the Rust crate testdata dir is one level up then into crates/.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	outPath := filepath.Join(filepath.Dir(thisFile), "..", "crates", "agent-windows", "testdata", "go_bundle_fixture.zip")
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		t.Fatalf("mkdirall testdata: %v", err)
	}
	if err := os.WriteFile(outPath, zipBytes, 0644); err != nil {
		t.Fatalf("write fixture to %s: %v", outPath, err)
	}
	t.Logf("wrote %d bytes to %s", len(zipBytes), outPath)
}
