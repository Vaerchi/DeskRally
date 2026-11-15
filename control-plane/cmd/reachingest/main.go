// Command reachingest is the opt-in download-report ingest (docs/68, docs/20 section 16). It reads Caddy's JSON
// access log from a READ-ONLY mount, folds it into per-day COUNTS and upserts them as the dedicated
// rmt_reach_ingest database role. It has no network listener and runs no other program.
//
// A LOOP, NOT A CRON ONE-SHOT: the unique-ish figure is the size of an in-memory set of salted client hashes
// for the UTC day (reach/salt.go). A one-shot every hour would have to discard that set each time and could
// never report a daily figure; a long-lived process keeps it, and a restart is handled by reloading the salt
// from its tmpfs file and flagging the day as a lower bound. The loop runs once at start and then every
// REACH_INTERVAL (default 1h; the Caddy log rolls by size, 20 MiB x 10, so hourly is far inside the window).
//
// Environment (all forwarded by the reach-ingest service in deploy/docker-compose.prod.yml):
//
//	REACH_DATABASE_URL   required: the rmt_reach_ingest DSN
//	REACH_LOG_DIR        default /data           the Caddy data volume, read-only
//	REACH_LOG_NAME       default access.log
//	REACH_ARTIFACT_DIR   default /srv/artifacts  read-only; artifact sizes for the completed-download count.
//	                     Empty or missing: completed is stored as NULL (unknown), never as 0
//	REACH_SALT_FILE      default /run/reach/salt  a tmpfs path
//	REACH_INTERVAL       default 1h (minimum 1m)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"rmt/controlplane/reach"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	once := flag.Bool("once", false, "run one ingest pass and exit (the figure is then a lower bound)")
	flag.Parse()

	dsn := os.Getenv("REACH_DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "reachingest: REACH_DATABASE_URL is required (the rmt_reach_ingest DSN, docs/20 section 16)")
		os.Exit(2)
	}
	interval := time.Hour
	if v := os.Getenv("REACH_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			fmt.Fprintln(os.Stderr, "reachingest: REACH_INTERVAL must be a duration of at least 1m")
			os.Exit(2)
		}
		interval = d
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("reachingest: connect: %v", err)
	}
	defer pool.Close()

	in, err := reach.New(reach.Config{
		Dir:      env("REACH_LOG_DIR", "/data"),
		LogName:  env("REACH_LOG_NAME", "access.log"),
		Sizes:    reach.DirSizes(env("REACH_ARTIFACT_DIR", "/srv/artifacts")),
		SaltFile: reach.SaltFile{Path: env("REACH_SALT_FILE", "/run/reach/salt")},
		Store:    &reach.PgStore{Pool: pool},
	})
	if err != nil {
		log.Fatalf("reachingest: %v", err)
	}
	log.Printf("reachingest: started; salt day %s, interval %s", in.SaltDay(), interval)

	run := func() {
		st, err := in.RunOnce(ctx)
		if err != nil {
			log.Printf("reachingest: run failed after %d segments, %d lines: %v (next run resumes from the last committed cursor)", st.Segments, st.Lines, err)
			return
		}
		// Counts only: nothing from a log line is ever printed.
		log.Printf("reachingest: ok segments=%d lines=%d malformed=%d oversize=%d capped=%d budget_stopped=%t human=%d update=%d other=%d noise=%d",
			st.Segments, st.Lines, st.Malformed, st.Oversize, st.Capped, st.BudgetStopped,
			st.Counted[reach.ClassHuman], st.Counted[reach.ClassUpdate], st.Counted[reach.ClassOther], st.Counted[reach.ClassNoise])
	}
	run()
	if *once {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
