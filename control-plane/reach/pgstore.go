package reach

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgStore writes the aggregates as the dedicated ingest role (migration 0078): it can reach download_daily and
// download_ingest_cursor and nothing else in the database.
type PgStore struct{ Pool *pgxpool.Pool }

func (s *PgStore) Cursors(ctx context.Context) (map[string]Cursor, error) {
	rows, err := s.Pool.Query(ctx, `SELECT file_id, last_name, byte_offset, complete FROM download_ingest_cursor`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Cursor{}
	for rows.Next() {
		var c Cursor
		if err := rows.Scan(&c.FileID, &c.Name, &c.Offset, &c.Complete); err != nil {
			return nil, err
		}
		out[c.FileID] = c
	}
	return out, rows.Err()
}

// upsertSQL is the ONE place the delta semantics live (MemStore mirrors it): counts add, completed stays NULL
// until some line knew the artifact size, uniq only ever rises (a restarted process's smaller set must not
// lower the day's figure), partial only ever becomes true.
const upsertSQL = `
INSERT INTO download_daily (day, artifact, class, requests, completed, uniq, bytes, partial)
VALUES ($1::date, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (day, artifact, class) DO UPDATE SET
    requests  = download_daily.requests + EXCLUDED.requests,
    completed = CASE WHEN EXCLUDED.completed IS NULL THEN download_daily.completed
                     ELSE COALESCE(download_daily.completed, 0) + EXCLUDED.completed END,
    uniq      = GREATEST(download_daily.uniq, EXCLUDED.uniq),
    bytes     = download_daily.bytes + EXCLUDED.bytes,
    partial   = download_daily.partial OR EXCLUDED.partial`

const cursorSQL = `
INSERT INTO download_ingest_cursor (file_id, last_name, byte_offset, complete, updated_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (file_id) DO UPDATE SET last_name = EXCLUDED.last_name, byte_offset = EXCLUDED.byte_offset, complete = EXCLUDED.complete, updated_at = now()`

func (s *PgStore) Commit(ctx context.Context, b Batch) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, a := range b.Aggs {
		var completed, uniq *int64
		if a.CompletedKnown {
			c := a.Completed
			completed = &c
		}
		if a.Uniq >= 0 {
			u := a.Uniq
			uniq = &u
		}
		if _, err := tx.Exec(ctx, upsertSQL, a.Day, a.Artifact, string(a.Class), a.Requests, completed, uniq, a.Bytes, a.Partial); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, cursorSQL, b.Cursor.FileID, truncate(b.Cursor.Name, 255), b.Cursor.Offset, b.Cursor.Complete); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *PgStore) Prune(ctx context.Context, keepFrom string, seenIDs []string, staleBefore time.Time) error {
	if _, err := s.Pool.Exec(ctx, `DELETE FROM download_daily WHERE day < $1::date`, keepFrom); err != nil {
		return err
	}
	if len(seenIDs) == 0 {
		return nil
	}
	_, err := s.Pool.Exec(ctx, `DELETE FROM download_ingest_cursor WHERE updated_at < $1 AND NOT (file_id = ANY($2))`, staleBefore, seenIDs)
	return err
}
