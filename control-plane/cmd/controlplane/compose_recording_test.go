package main

// Guard for docs/63 R4: central recording storage ships OFF in the production stack, and everything it needs once
// switched on is wired consistently. These read the deploy files as text (the compose scan in envscan_test.go is
// key-only and the three server binaries share it, so recording-specific rules live here).
//
//   - OFF by default: every secret / switch forwarded to the control plane defaults to EMPTY, so a routine deploy of
//     the file enables nothing (RecordingKeyringFromEnv treats an empty RECORDING_MASTER_KEY as "off").
//   - ON works: RECORDING_DIR (the code reads it, with a default) equals the target of the `recordings` named volume,
//     the volume is declared, and the image creates that directory owned by the runtime user so a fresh volume copies
//     up a writable root (otherwise startup dies with permission denied the day the key is set).
//   - The edge cap on the upload route is never LOWER than the server's chunk (RecChunkSize).

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	controlplane "rmt/controlplane"
)

func readDeployFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// serviceBlock returns the lines of one top-level service (indent-2 key) of a compose file.
func serviceBlock(t *testing.T, compose, name string) []string {
	t.Helper()
	var out []string
	in := false
	for _, line := range strings.Split(compose, "\n") {
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(strings.TrimSpace(line), ":") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			in = strings.TrimSpace(line) == name+":"
			continue
		}
		if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") {
			in = false // a new top-level key (volumes:, networks:) ends the services
		}
		if in {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		t.Fatalf("service %q not found", name)
	}
	return out
}

// envValue finds `KEY: "value"` among a service's lines (not a comment).
func envValue(lines []string, key string) (string, bool) {
	re := regexp.MustCompile(`^\s{6}` + regexp.QuoteMeta(key) + `:\s*(.*?)\s*$`)
	for _, l := range lines {
		if m := re.FindStringSubmatch(l); m != nil {
			return strings.Trim(m[1], `"'`), true
		}
	}
	return "", false
}

func TestRecordingShipsOffInProdCompose(t *testing.T) {
	prod := readDeployFile(t, composeDir+"docker-compose.prod.yml")
	cp := serviceBlock(t, prod, "controlplane")
	for _, k := range []string{"RECORDING_MASTER_KEY", "RECORDING_MASTER_KEY_ID", "RECORDING_MASTER_KEY_PREVIOUS", "RECORDING_RECONCILE_MODE", "RECORDING_RECONCILE_ACCEPT_MISSING", "RECORDING_DISK_FLOOR_MIB", "CP_PUBLIC_ORIGIN"} {
		v, ok := envValue(cp, k)
		if !ok {
			t.Errorf("%s is not forwarded to the controlplane service (a .env line would do nothing)", k)
			continue
		}
		if v != "${"+k+":-}" {
			t.Errorf("%s = %q: it must default to EMPTY (%q) so a routine deploy leaves central recording off", k, v, "${"+k+":-}")
		}
	}
	// Nothing else about recording may be unconditional-and-required: no `:?` anywhere on a RECORDING_ line.
	for _, l := range cp {
		if strings.Contains(l, "RECORDING_") && !strings.HasPrefix(strings.TrimSpace(l), "#") && strings.Contains(l, ":?") {
			t.Errorf("a required (:?) recording variable would stop an existing deployment starting: %s", strings.TrimSpace(l))
		}
	}
}

func TestRecordingVolumeMatchesRecordingDir(t *testing.T) {
	prod := readDeployFile(t, composeDir+"docker-compose.prod.yml")
	cp := serviceBlock(t, prod, "controlplane")
	dir, ok := envValue(cp, "RECORDING_DIR")
	if !ok || dir == "" || strings.Contains(dir, "$") {
		t.Fatalf("RECORDING_DIR must be a fixed in-container path in docker-compose.prod.yml, got %q (found=%v)", dir, ok)
	}
	// The code's own default is the same path, so unsetting it can never point at a different place.
	mainSrc := readDeployFile(t, "main.go")
	m := regexp.MustCompile(`getenv\("RECORDING_DIR",\s*"([^"]+)"\)`).FindStringSubmatch(mainSrc)
	if m == nil || m[1] != dir {
		t.Errorf("RECORDING_DIR in compose (%q) differs from the control plane's default (%v)", dir, m)
	}
	mounted := false
	for _, l := range cp {
		if strings.TrimSpace(l) == "- recordings:"+dir {
			mounted = true
		}
	}
	if !mounted {
		t.Errorf("the controlplane service must mount the NAMED volume `recordings` at RECORDING_DIR (%s)", dir)
	}
	if !regexp.MustCompile(`(?m)^volumes:\n(?:[ \t]+.*\n|\n)*?  recordings:\s*$`).MatchString(prod) {
		t.Errorf("the top-level volumes: block does not declare `recordings`")
	}
	// A bind mount or an anonymous volume at this path would be root-owned / lost on down: it must stay the named volume.
	for _, l := range cp {
		if strings.Contains(l, dir) && strings.Contains(l, "/") && strings.HasPrefix(strings.TrimSpace(l), "- ") && !strings.HasPrefix(strings.TrimSpace(l), "- recordings:") {
			t.Errorf("RECORDING_DIR is mounted some way other than the named volume: %s", strings.TrimSpace(l))
		}
	}
	// The image must create the mount point owned by the runtime user (uid 10001, user `app`) BEFORE `USER app`.
	df := readDeployFile(t, "../../Dockerfile")
	if !regexp.MustCompile(`adduser -D -u 10001 app`).MatchString(df) {
		t.Fatalf("Dockerfile no longer creates the runtime user with uid 10001; update this guard and docs/63 D8")
	}
	iMk := strings.Index(df, "mkdir -p "+dir)
	iCh := strings.Index(df, "chown app:app "+dir)
	iUser := strings.Index(df, "\nUSER app")
	if iMk < 0 || iCh < 0 || iUser < 0 || !(iMk < iUser && iCh < iUser) {
		t.Errorf("Dockerfile must `mkdir -p %s` and `chown app:app %s` before `USER app` so a fresh named volume copies up an app-owned root", dir, dir)
	}
}

func TestCaddyRecordingUploadCapIsNotBelowTheServerChunk(t *testing.T) {
	cf := readDeployFile(t, composeDir+"Caddyfile")
	m := regexp.MustCompile(`(?m)^\s*@recUpload path (.+)$`).FindStringSubmatch(cf)
	if m == nil || !strings.Contains(m[1], "/agent/recordings") {
		t.Fatalf("the Caddyfile has no @recUpload matcher for /agent/recordings")
	}
	c := regexp.MustCompile(`(?s)handle @recUpload \{\s*request_body \{\s*max_size (\d+)(KiB|MiB|KB|MB)\s*\}`).FindStringSubmatch(cf)
	if c == nil {
		t.Fatalf("the recording upload handle has no request_body max_size")
	}
	n, _ := strconv.ParseInt(c[1], 10, 64)
	mult := map[string]int64{"KiB": 1 << 10, "MiB": 1 << 20, "KB": 1000, "MB": 1000 * 1000}[c[2]]
	if got := n * mult; got < controlplane.RecChunkSize {
		t.Errorf("Caddy caps a recording upload at %d bytes, BELOW the control plane's chunk (%d): every full chunk would be refused at the edge", got, controlplane.RecChunkSize)
	}
	if !strings.Contains(cf, "@recStream path_regexp") {
		t.Errorf("the Caddyfile lost the @recStream handle (stream/download timeouts)")
	}
}
