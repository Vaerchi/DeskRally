package main

// The compose guard for the opt-in reach-ingest service (docs/68, docs/20 section 16). The cmd/controlplane
// guard only scans that binary's environment reads; this binary's reads, and the properties that keep the
// feature OFF and NARROW, are pinned here: a variable it reads but the service does not forward is a .env line
// that silently does nothing, and a routine deploy must not start it or give the control plane the log.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const prodCompose = "../../../deploy/docker-compose.prod.yml"

func serviceBlock(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(prodCompose)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	start := strings.Index(s, "\n  "+name+":\n")
	if start < 0 {
		t.Fatalf("service %s not found in %s", name, prodCompose)
	}
	rest := s[start+1:]
	// the block ends at the next 2-space-indented service key or the top-level volumes: key
	end := regexp.MustCompile(`\n(  [a-z][a-z-]*:\n|volumes:\n)`).FindStringIndex(rest[1:])
	if end == nil {
		return rest
	}
	return rest[:end[0]+1]
}

func TestComposeForwardsEveryVariableTheIngestReads(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	reads := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?:Getenv|env)\("([A-Z_]+)"`).FindAllStringSubmatch(string(src), -1) {
		reads[m[1]] = true
	}
	if !reads["REACH_DATABASE_URL"] || len(reads) < 5 {
		t.Fatalf("the scan found only %v: the pattern no longer matches how main.go reads its environment", reads)
	}
	block := serviceBlock(t, "reach-ingest")
	for k := range reads {
		if !strings.Contains(block, "\n      "+k+":") {
			t.Errorf("main.go reads %s but the reach-ingest service does not forward it", k)
		}
	}
	envExample, err := os.ReadFile("../../../deploy/.env.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"REACH_DATABASE_URL", "REACH_INTERVAL"} {
		if !regexp.MustCompile(`(?m)^` + k + `=`).Match(envExample) {
			t.Errorf(".env.example has no %s= line", k)
		}
	}
}

func TestReachIngestShipsOffAndNarrow(t *testing.T) {
	block := serviceBlock(t, "reach-ingest")
	for _, want := range []string{
		`profiles: ["reach"]`,                           // not started by a routine `up -d`
		"- caddydata:/data:ro",                          // the log, read-only
		"/srv/artifacts:ro",                             // artifact sizes, read-only
		"/run/reach:mode=0700",                          // the salt lives on a tmpfs
		"- /data/caddy:mode=0000",                       // Caddy's TLS/ACME keys are masked
		"condition: service_started",                    // ...which needs /data/caddy to exist: caddy ran once
		"read_only: true",                               //
		"cap_drop: [ALL]",                               //
		"no-new-privileges:true",                        //
		`REACH_DATABASE_URL: "${REACH_DATABASE_URL:-}"`, // empty by default, never `:?` (that would break compose config with the profile off)
	} {
		if !strings.Contains(block, want) {
			t.Errorf("reach-ingest lacks %q", want)
		}
	}
	if strings.Contains(block, "ports:") {
		t.Error("the ingest must have no listener")
	}
	// The control plane never mounts the log volume (docs/68 section 4).
	if strings.Contains(serviceBlock(t, "controlplane"), "caddydata") {
		t.Error("the controlplane service mounts caddydata")
	}
	// And the image carries the binary the service runs.
	df, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(df), "/usr/local/bin/reachingest") || !strings.Contains(block, `entrypoint: ["/usr/local/bin/reachingest"]`) {
		t.Error("the Dockerfile and the compose entrypoint disagree about the reachingest binary")
	}
}
