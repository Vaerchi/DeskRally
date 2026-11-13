package controlplane

// Packaged compliance archive (docs/01 §7 P1 "Compliance/audit export archives"): a single ZIP
// bundling BOTH audit trails as NDJSON plus a manifest — a one-file SOC2/HIPAA evidence download,
// instead of a collector paging two endpoints separately.
//
//	GET /audit/archive → application/zip, attachment, containing:
//	  - management-audit.ndjson  (the tenant's chained management trail, ascending seq)
//	  - backstage-audit.ndjson   (the backstage trail, ascending ingest order; only when wired)
//	  - manifest.json            (tenant, export time, per-trail counts, truncation + scope flags)
//
// Gated on CapViewAudit, the SAME gate as the per-trail exports. The backstage trail is GROUP-SCOPED
// exactly as GET /audit/backstage/export — a group-scoped auditor's archive carries only their scope,
// and the manifest records that it was scoped. The archive walks each trail to completion by reusing
// the stores' own ascending-cursor paging; both walks are page-bounded so one request cannot trigger
// an unbounded scan — if a trail exceeds the bound the manifest marks it truncated and names the
// cursor to resume from on the paged export endpoint.

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Walk bounds + abuse limits. Vars, not consts, so a test can shrink them; production never reassigns.
var (
	// Each trail is walked in pages of this size (the per-trail export's max page).
	archivePageSize = maxAuditExportLimit // 10000
	// Page ceiling per trail: a single request reads at most this many pages (archivePageSize each),
	// so one archive cannot become an unbounded table scan. Kept well below "the whole table" on
	// purpose — the archive is a best-effort compliance snapshot, and a trail larger than this is
	// marked truncated with a resume cursor for the paged export endpoint. (A security review flagged
	// the old 1000-page / 10M-row ceiling as a resource amplifier; 100 pages = up to 1M rows/trail is
	// ample for real audit volume while capping the worst case ~10×.)
	maxArchivePages = 100
	// archiveDeadline bounds a SINGLE archive's wall-clock, propagated to the DB queries: a request
	// that runs long is cut off and its trail marked incomplete, so neither a huge trail nor a slow
	// database lets one request tie up resources indefinitely.
	archiveDeadline = 90 * time.Second
	// maxConcurrentArchives caps how many archive requests run AT ONCE across the whole process. The
	// export is expensive and repeatable by any view_audit holder (user OR api token), so without this
	// a handful of concurrent requests could exhaust CPU / DB (the review's high finding). Excess
	// requests get 429 + Retry-After rather than piling on. Compliance pulls are rare, so 2 is ample.
	maxConcurrentArchives = 2
)

// archiveSlots is the global concurrency gate for GET /audit/archive (see maxConcurrentArchives).
var archiveSlots = make(chan struct{}, maxConcurrentArchives)

// archiveManifest is the machine-readable index written into every archive.
type archiveManifest struct {
	TenantID   string              `json:"tenant_id"`
	ExportedAt string              `json:"exported_at"` // RFC3339 UTC
	Format     string              `json:"format"`      // "ndjson"
	Management archiveTrailSummary `json:"management"`
	Backstage  archiveTrailSummary `json:"backstage"`
	Note       string              `json:"note"`
}

type archiveTrailSummary struct {
	Included bool `json:"included"`
	Count    int  `json:"count"`
	// Truncated is true when the page ceiling was hit before the trail was exhausted.
	Truncated bool `json:"truncated"`
	// ResumeCursor names the query parameter to continue from on the paged export endpoint when truncated.
	ResumeCursor string `json:"resume_cursor,omitempty"`
	// Scoped is true when a group-scoped auditor's backstage trail was filtered to their scope.
	Scoped bool `json:"scoped,omitempty"`
	// Error, when non-empty, records a read/write failure encountered mid-stream: the headers and the
	// ZIP are already committed by then, so the failure is reported HERE rather than as an HTTP status,
	// and this trail's NDJSON entry is partial.
	Error string `json:"error,omitempty"`
}

// handleAuditArchive streams the ZIP archive of the tenant's audit trails.
func (s *Server) handleAuditArchive(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewAudit); err != nil {
		writeDenied(w, err)
		return
	}
	// The archive's value is chain verification over the whole tenant trail, so it is tenant-wide
	// only (http_mgmtaudit_scope.go); a group-scoped auditor gets 403, not a filtered archive.
	if !requireTenantWideAudit(w, p) {
		return
	}
	if s.MgmtAudit == nil {
		writeError(w, http.StatusInternalServerError, "audit store not configured")
		return
	}

	// Per-tenant cap (2) on top of the global gate below.
	releaseSlot, ok := s.acquireAuditStream(w, p)
	if !ok {
		return
	}
	defer releaseSlot()

	// Global concurrency gate: the archive is expensive and repeatable by any view_audit holder, so
	// bound how many run at once. Non-blocking acquire → a 429 (not a pile-up) when the process is
	// already busy archiving. Released when this request finishes.
	select {
	case archiveSlots <- struct{}{}:
		defer func() { <-archiveSlots }()
	default:
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusTooManyRequests, "too many audit archives in progress; retry shortly")
		return
	}

	// The archive reads page after page WHILE writing to the client, so it must not pin one of the few
	// pooled connections for the whole stream (review #5): release the request's binding now; every
	// page query below then takes a pool connection for just that query (withTenant re-pins the
	// tenant per transaction).
	releaseBoundConn(r.Context())

	// Per-request deadline, propagated to the DB queries below: one archive cannot run unbounded, so
	// neither a very large trail nor a slow database ties up a slot indefinitely. A cut-off trail is
	// reported incomplete in the manifest (its Error), not as a silent clean export.
	ctx, cancel := context.WithTimeout(r.Context(), archiveDeadline)
	defer cancel()

	// A WRITE deadline on the connection too: the context deadline cancels DB queries but NOT a
	// blocked ResponseWriter.Write, so without this a SLOW CLIENT could hold an archive slot
	// indefinitely (reading the stream a byte at a time) and starve every tenant of the two slots.
	// The deadline makes a stalled Write fail, the trail records the write error, and the slot frees.
	// Best-effort: the middleware chain passes the ResponseWriter through unwrapped, so the real
	// connection's deadline applies; if a future wrapper hides it, SetWriteDeadline just no-ops.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(archiveDeadline))

	// Commit the headers BEFORE any ZIP bytes: once the stream starts the status cannot change, so
	// mid-stream failures are reported inside manifest.json instead (see archiveTrailSummary.Error).
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Cache-Control", "no-store") // audit trail: sensitive tenant data (docs/25 F10)
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="audit-archive-%s.zip"`, time.Now().UTC().Format("20060102T150405Z")))
	w.WriteHeader(http.StatusOK)

	zw := zip.NewWriter(w)
	defer func() { _ = zw.Close() }()

	manifest := archiveManifest{
		TenantID:   p.TenantID,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Format:     "ndjson",
		Note: "Each *.ndjson file is one JSON event per line, as emitted by GET /audit/export and " +
			"GET /audit/backstage/export; the events carry their own chain fields for independent " +
			"verification. This archive is NOT a single-instant snapshot: the two trails are read " +
			"sequentially, so an archive taken during active ingestion may span slightly different " +
			"intervals per trail. Completeness is attested by this manifest (per-trail count, truncated, " +
			"error) together with a successful ZIP integrity check — not by the HTTP status alone.",
	}
	manifest.Management = s.archiveMgmtTrail(ctx, zw, p.TenantID)
	if s.Audit != nil {
		manifest.Backstage = s.archiveBackstageTrail(ctx, zw, p)
	}

	// Manifest LAST, so it carries the final per-trail counts. A failure to write it cannot be
	// signalled (the ZIP is mid-stream); the archive is simply missing its manifest, which a consumer
	// treats as an incomplete download.
	if mw, err := zw.Create("manifest.json"); err == nil {
		enc := json.NewEncoder(mw)
		enc.SetIndent("", "  ")
		_ = enc.Encode(manifest)
	}
}

// archiveMgmtTrail walks the management trail ascending by seq into one NDJSON entry.
func (s *Server) archiveMgmtTrail(ctx context.Context, zw *zip.Writer, tenantID string) archiveTrailSummary {
	sum := archiveTrailSummary{Included: true}
	ew, err := zw.Create("management-audit.ndjson")
	if err != nil {
		sum.Included = false
		sum.Error = "create entry: " + err.Error()
		return sum
	}
	enc := json.NewEncoder(ew)
	afterSeq := int64(-1) // genesis
	for page := 0; page < maxArchivePages; page++ {
		// Honour cancellation/deadline between pages, so the walk stops promptly even for a store that
		// does not itself check ctx — bounding the CPU of the encode loop, not just the DB query.
		if err := ctx.Err(); err != nil {
			sum.Error = "deadline: " + err.Error()
			return sum
		}
		events, err := s.MgmtAudit.ListEventsAsc(ctx, tenantID, afterSeq, archivePageSize)
		if err != nil {
			sum.Error = "read: " + err.Error()
			return sum
		}
		for i := range events {
			if err := enc.Encode(events[i]); err != nil {
				sum.Error = "write: " + err.Error()
				return sum
			}
			sum.Count++
		}
		if len(events) < archivePageSize {
			return sum // exhausted → complete
		}
		// Advance by the last event's seq. ListEventsAsc returns only seq-bearing rows in ascending
		// seq order (both the in-memory and the pg stores filter out legacy nil-seq rows), so Seq is
		// non-nil by contract. If that contract were ever violated we cannot advance the cursor, and
		// stopping must NOT be reported as a clean, complete export — fail loud via Error instead.
		last := events[len(events)-1].Seq
		if last == nil {
			sum.Error = "store returned a seq-less event; export stopped and is INCOMPLETE"
			return sum
		}
		afterSeq = *last
	}
	sum.Truncated = true
	sum.ResumeCursor = "after_seq=" + strconv.FormatInt(afterSeq, 10)
	return sum
}

// archiveBackstageTrail walks the backstage trail into one NDJSON entry, applying the SAME group
// scoping as GET /audit/backstage/export. "Caught up" is next == the cursor sent (an empty page is
// NOT caught up — the scope filter can empty a page whose cursor still advanced).
func (s *Server) archiveBackstageTrail(ctx context.Context, zw *zip.Writer, p *Principal) archiveTrailSummary {
	sum := archiveTrailSummary{Included: true}
	scope, _ := p.Grant.ScopeFor(CapViewAudit)
	sum.Scoped = !scope.All
	ew, err := zw.Create("backstage-audit.ndjson")
	if err != nil {
		sum.Included = false
		sum.Error = "create entry: " + err.Error()
		return sum
	}
	enc := json.NewEncoder(ew)
	cursor := auditExportStart // -1: before every row
	for page := 0; page < maxArchivePages; page++ {
		if err := ctx.Err(); err != nil {
			sum.Error = "deadline: " + err.Error()
			return sum
		}
		q := NewAuditExportQuery("", archivePageSize)
		q.AfterIngestSeq = cursor
		events, next, err := s.Audit.ListAuditEventsAsc(ctx, p.TenantID, q)
		if err != nil {
			sum.Error = "read: " + err.Error()
			return sum
		}
		if !scope.All {
			events, err = s.backstageEventsInScope(ctx, p, events)
			if err != nil {
				// Fail CLOSED: if the machine repository cannot resolve a group, serve nothing further.
				sum.Error = "scope: " + err.Error()
				return sum
			}
		}
		for i := range events {
			if err := enc.Encode(events[i]); err != nil {
				sum.Error = "write: " + err.Error()
				return sum
			}
			sum.Count++
		}
		if next == cursor {
			return sum // caught up
		}
		cursor = next
	}
	sum.Truncated = true
	sum.ResumeCursor = "after_ingest_seq=" + strconv.FormatInt(cursor, 10)
	return sum
}
