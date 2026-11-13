package reach

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Agg is one (day, artifact, class) row's DELTA for a batch of lines. Counts are added to what is stored;
// Uniq and Partial are not (see Store.Commit).
type Agg struct {
	Day      string // YYYY-MM-DD, UTC
	Artifact string
	Class    Class

	Requests int64
	Bytes    int64
	// Completed is the number of requests that looked like whole downloads. CompletedKnown is false when no
	// line of the delta had a known artifact size: the stored value then stays NULL ("unknown", not zero).
	Completed      int64
	CompletedKnown bool
	// Uniq is the cardinality of the day's in-memory client set for a human row, or -1 when this delta has no
	// figure (non-human rows, or lines the salt could not cover).
	Uniq int64
	// Partial marks the row's unique-ish figure as a lower bound (a restart, a missing salt, a capped set).
	Partial bool
}

// Cursor is how far one log SEGMENT has been consumed. FileID is the segment's identity (a hash of its first
// line's server timestamp TEXT only, never of anything a client sent; see segments.go), so it survives Caddy renaming access.log to access-<ts>.log and gzipping it.
type Cursor struct {
	FileID string
	Name   string // the file name when last read; informational only
	Offset int64  // bytes of the (decompressed) segment already consumed, complete lines only
	// Complete: a rolled (non-active) segment that was read to its clean end, or given up on at the size cap. It is
	// never opened again, so already-counted history cannot eat the re-read budget (docs/68 Codex round 2).
	Complete bool
}

// Batch is committed atomically: the aggregates and the cursor that produced them, so a crash between the two
// can neither lose nor double-count lines.
type Batch struct {
	Aggs   []Agg
	Cursor Cursor
}

// Store is the ingest's only database surface.
type Store interface {
	Cursors(ctx context.Context) (map[string]Cursor, error)
	Commit(ctx context.Context, b Batch) error
	// Prune deletes aggregate rows with day < keepFrom and cursors that are not in seenIDs and have not been
	// updated since staleBefore. seenIDs empty means "the log directory looked empty": no cursor is deleted then.
	Prune(ctx context.Context, keepFrom string, seenIDs []string, staleBefore time.Time) error
}

// Row is a stored aggregate, as the report reads it.
type Row struct {
	Day, Artifact string
	Class         Class
	Requests      int64
	Completed     *int64
	Uniq          *int64
	Bytes         int64
	Partial       bool
}

// MemStore is the in-memory Store the ingest tests run against. It implements EXACTLY the semantics the SQL
// upsert has (TestPgReachStoreAgreesWithMemStore in platform_reach_pgstore_test.go runs one script against both), so the two cannot drift.
type MemStore struct {
	mu      sync.Mutex
	rows    map[[3]string]*Row
	cursors map[string]Cursor
	updated map[string]time.Time
	Now     func() time.Time
	// FailNextCommit makes the next Commit fail once without changing anything (a crash before the commit).
	FailNextCommit bool
}

func NewMemStore() *MemStore {
	return &MemStore{rows: map[[3]string]*Row{}, cursors: map[string]Cursor{}, updated: map[string]time.Time{}, Now: time.Now}
}

func (m *MemStore) Cursors(context.Context) (map[string]Cursor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Cursor, len(m.cursors))
	for k, v := range m.cursors {
		out[k] = v
	}
	return out, nil
}

func (m *MemStore) Commit(_ context.Context, b Batch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNextCommit {
		m.FailNextCommit = false
		return errFailedCommit
	}
	for _, a := range b.Aggs {
		k := [3]string{a.Day, a.Artifact, string(a.Class)}
		r := m.rows[k]
		if r == nil {
			r = &Row{Day: a.Day, Artifact: a.Artifact, Class: a.Class}
			m.rows[k] = r
		}
		r.Requests += a.Requests
		r.Bytes += a.Bytes
		if a.CompletedKnown {
			c := a.Completed
			if r.Completed != nil {
				c += *r.Completed
			}
			r.Completed = &c
		}
		if a.Uniq >= 0 && (r.Uniq == nil || a.Uniq > *r.Uniq) { // GREATEST: a restart's smaller set never lowers it
			u := a.Uniq
			r.Uniq = &u
		}
		r.Partial = r.Partial || a.Partial
	}
	m.cursors[b.Cursor.FileID] = b.Cursor
	m.updated[b.Cursor.FileID] = m.Now()
	return nil
}

func (m *MemStore) Prune(_ context.Context, keepFrom string, seenIDs []string, staleBefore time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.rows {
		if k[0] < keepFrom {
			delete(m.rows, k)
		}
	}
	if len(seenIDs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, id := range seenIDs {
		seen[id] = true
	}
	for id := range m.cursors {
		if !seen[id] && m.updated[id].Before(staleBefore) {
			delete(m.cursors, id)
			delete(m.updated, id)
		}
	}
	return nil
}

// Rows returns every stored aggregate, ordered by day, class, artifact.
func (m *MemStore) Rows() []Row {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Row
	for _, r := range m.rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Day != b.Day {
			return a.Day < b.Day
		}
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		return a.Artifact < b.Artifact
	})
	return out
}
