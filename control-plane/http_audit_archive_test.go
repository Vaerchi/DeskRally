package controlplane

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func seedMgmt(t *testing.T, srv *Server, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		e := &MgmtAuditEvent{Action: "machine.enroll", TargetKind: "machine"}
		if err := srv.MgmtAudit.RecordEvent(context.Background(), "tenant-123", e); err != nil {
			t.Fatalf("seed mgmt %d: %v", i, err)
		}
	}
}

// fetchArchive issues GET /audit/archive and returns the raw response.
func fetchArchive(srv *Server, p *Principal) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/audit/archive", nil))
	return rec
}

// readZip parses a ZIP body into {name: bytes}.
func readZip(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("not a valid zip (%d bytes): %v", len(body), err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %s (crc/truncation?): %v", f.Name, err)
		}
		out[f.Name] = b
	}
	return out
}

func parseManifest(t *testing.T, b []byte) archiveManifest {
	t.Helper()
	var m archiveManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("manifest not json: %v (%s)", err, b)
	}
	return m
}

func ndjsonLines(b []byte) int {
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

func TestAuditArchiveRequiresViewAudit(t *testing.T) {
	// A technician (no CapViewAudit) is refused BEFORE any zip bytes.
	p := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleTechnician, AllGroups()))}
	srv, _ := newTestServer(p)
	rec := fetchArchive(srv, p)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("technician GET /audit/archive = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "application/zip") {
		t.Fatalf("a denied request must not start a zip stream (ct=%q)", ct)
	}
}

func TestAuditArchiveBundlesBothTrails(t *testing.T) {
	srv, _ := newTestServer(auditorPrincipal())
	srv.Audit = NewInMemoryAuditStore()
	seedMgmt(t, srv, 3)
	if _, err := srv.Audit.AppendAudit(context.Background(), "tenant-123", testSession, chainRange(testSession, 0, 2)); err != nil {
		t.Fatalf("seed backstage: %v", err)
	}

	rec := fetchArchive(srv, auditorPrincipal())
	if rec.Code != http.StatusOK {
		t.Fatalf("archive = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("content-type = %q, want application/zip", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("cache-control = %q, want no-store (sensitive)", cc)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("content-disposition = %q, want attachment", cd)
	}

	files := readZip(t, rec.Body.Bytes())
	for _, name := range []string{"manifest.json", "management-audit.ndjson", "backstage-audit.ndjson"} {
		if _, ok := files[name]; !ok {
			t.Fatalf("archive missing %s (has %v)", name, zipNames(files))
		}
	}
	if got := ndjsonLines(files["management-audit.ndjson"]); got != 3 {
		t.Errorf("management ndjson lines = %d, want 3", got)
	}
	if got := ndjsonLines(files["backstage-audit.ndjson"]); got != 2 {
		t.Errorf("backstage ndjson lines = %d, want 2", got)
	}
	m := parseManifest(t, files["manifest.json"])
	if m.TenantID != "tenant-123" {
		t.Errorf("manifest tenant = %q", m.TenantID)
	}
	if !m.Management.Included || m.Management.Count != 3 || m.Management.Truncated {
		t.Errorf("manifest management = %+v, want included count=3 not truncated", m.Management)
	}
	if !m.Backstage.Included || m.Backstage.Count != 2 || m.Backstage.Scoped {
		t.Errorf("manifest backstage = %+v, want included count=2 not scoped", m.Backstage)
	}
}

func TestAuditArchiveOmitsBackstageWhenUnwired(t *testing.T) {
	srv, _ := newTestServer(auditorPrincipal())
	srv.Audit = nil // no backstage store wired
	seedMgmt(t, srv, 1)
	files := readZip(t, fetchArchive(srv, auditorPrincipal()).Body.Bytes())
	if _, ok := files["backstage-audit.ndjson"]; ok {
		t.Errorf("backstage entry present with no store wired")
	}
	m := parseManifest(t, files["manifest.json"])
	if m.Backstage.Included {
		t.Errorf("manifest backstage.included = true with no store")
	}
	if m.Management.Count != 1 {
		t.Errorf("management count = %d, want 1", m.Management.Count)
	}
}

func TestAuditArchivePagesThroughEveryEvent(t *testing.T) {
	// Shrink the page so a handful of events spans several pages — proves the walk loop advances.
	defer restoreArchiveBounds(archivePageSize, maxArchivePages)
	archivePageSize, maxArchivePages = 2, 1000
	srv, _ := newTestServer(auditorPrincipal())
	seedMgmt(t, srv, 5) // 3 pages of 2,2,1
	files := readZip(t, fetchArchive(srv, auditorPrincipal()).Body.Bytes())
	if got := ndjsonLines(files["management-audit.ndjson"]); got != 5 {
		t.Fatalf("paged export lines = %d, want 5 (lost events across a page boundary)", got)
	}
	if m := parseManifest(t, files["manifest.json"]); m.Management.Count != 5 || m.Management.Truncated {
		t.Fatalf("manifest management = %+v, want count=5 not truncated", m.Management)
	}
}

func TestAuditArchiveTruncatesAtPageCeiling(t *testing.T) {
	defer restoreArchiveBounds(archivePageSize, maxArchivePages)
	archivePageSize, maxArchivePages = 2, 1 // one page of 2, then stop
	srv, _ := newTestServer(auditorPrincipal())
	seedMgmt(t, srv, 5)
	files := readZip(t, fetchArchive(srv, auditorPrincipal()).Body.Bytes())
	if got := ndjsonLines(files["management-audit.ndjson"]); got != 2 {
		t.Fatalf("truncated export lines = %d, want 2", got)
	}
	m := parseManifest(t, files["manifest.json"])
	if !m.Management.Truncated || m.Management.Count != 2 {
		t.Fatalf("manifest management = %+v, want truncated count=2", m.Management)
	}
	if !strings.HasPrefix(m.Management.ResumeCursor, "after_seq=") {
		t.Fatalf("resume cursor = %q, want after_seq=…", m.Management.ResumeCursor)
	}
}

func TestAuditArchiveScopedAuditorExcludesOutOfScopeBackstage(t *testing.T) {
	// Backstage events live on a machine that the permissive store resolves to the DEFAULT group. An
	// auditor scoped to "group-a" does not cover that group, so EVERY backstage event must be dropped
	// (count 0) and the trail marked scoped — proving actual exclusion, not just the flag. The same
	// events are visible to a tenant-wide auditor (TestAuditArchiveBundlesBothTrails, count 2).
	p := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleAuditor, Groups("group-a")))}
	srv, _ := newTestServer(p)
	srv.Audit = NewInMemoryAuditStore()
	seedMgmt(t, srv, 1)
	if _, err := srv.Audit.AppendAudit(context.Background(), "tenant-123", testSession, chainRange(testSession, 0, 2)); err != nil {
		t.Fatalf("seed backstage: %v", err)
	}
	// Security review 2026-11-01 #4: the archive's value is whole-chain verification, so it is now
	// TENANT-WIDE ONLY. A group-scoped auditor is refused outright (403, no ZIP) instead of getting
	// the unfiltered management trail next to a filtered backstage one.
	rec := fetchArchive(srv, p)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("scoped auditor archive = %d, want 403", rec.Code)
	}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/zip") {
		t.Fatalf("a refused archive must not be a ZIP stream")
	}
}

func TestAuditArchiveIsolatesTenants(t *testing.T) {
	// Events under another tenant must never appear in tenant-123's archive.
	srv, _ := newTestServer(auditorPrincipal())
	srv.Audit = NewInMemoryAuditStore()
	seedMgmt(t, srv, 2) // tenant-123
	otherSession := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	for i := 0; i < 3; i++ {
		e := &MgmtAuditEvent{Action: "machine.enroll"}
		if err := srv.MgmtAudit.RecordEvent(context.Background(), "tenant-OTHER", e); err != nil {
			t.Fatalf("seed other-tenant mgmt: %v", err)
		}
	}
	if _, err := srv.Audit.AppendAudit(context.Background(), "tenant-OTHER", otherSession, chainRange(otherSession, 0, 4)); err != nil {
		t.Fatalf("seed other-tenant backstage: %v", err)
	}
	files := readZip(t, fetchArchive(srv, auditorPrincipal()).Body.Bytes())
	m := parseManifest(t, files["manifest.json"])
	if m.Management.Count != 2 {
		t.Errorf("management count = %d, want 2 (other tenant's 3 must be excluded)", m.Management.Count)
	}
	if m.Backstage.Count != 0 {
		t.Errorf("backstage count = %d, want 0 (other tenant's 4 must be excluded)", m.Backstage.Count)
	}
}

func TestAuditArchiveLimitsConcurrency(t *testing.T) {
	// Saturate the global archive slots; a further request is refused with 429 rather than piling on
	// (the security review's DoS fix). Drained on exit even on a fatal (t.Fatalf runs defers).
	for i := 0; i < cap(archiveSlots); i++ {
		archiveSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(archiveSlots); i++ {
			<-archiveSlots
		}
	}()
	srv, _ := newTestServer(auditorPrincipal())
	rec := fetchArchive(srv, auditorPrincipal())
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("archive while all slots busy = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("the 429 should carry a Retry-After header")
	}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/zip") {
		t.Error("a throttled request must not start a zip stream")
	}
}

func TestAuditArchiveStopsOnCancelledContext(t *testing.T) {
	// A cancelled context stops the walk with an error even though the in-memory store ignores ctx —
	// the per-page ctx check bounds the encode loop (and makes the request deadline effective).
	srv, _ := newTestServer(auditorPrincipal())
	seedMgmt(t, srv, 5)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	sum := srv.archiveMgmtTrail(ctx, zw, "tenant-123")
	_ = zw.Close()
	if sum.Error == "" {
		t.Fatalf("a cancelled context should stop the walk with an error, got %+v", sum)
	}
}

func restoreArchiveBounds(page, pages int) {
	archivePageSize, maxArchivePages = page, pages
}

func zipNames(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
