package reach

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	long := "/download/DeskRallySupport.exe?" + strings.Repeat("a", MaxURIBytes)
	cases := []struct {
		name, method, uri string
		status            int
		want              Result
	}{
		// human artifacts: only a GET that delivered counts
		{"support exe 200", "GET", "/download/DeskRallySupport.exe", 200, Result{ClassHuman, "DeskRallySupport.exe"}},
		{"support exe 206 resume", "GET", "/download/DeskRallySupport.exe", 206, Result{ClassHuman, "DeskRallySupport.exe"}},
		{"support exe query is cut", "GET", "/download/DeskRallySupport.exe?utm=x#frag", 200, Result{ClassHuman, "DeskRallySupport.exe"}},
		{"support exe HEAD", "HEAD", "/download/DeskRallySupport.exe", 200, Result{ClassNoise, NoiseArtifact}},
		{"support exe 304 is not a download", "GET", "/download/DeskRallySupport.exe", 304, Result{ClassNoise, NoiseArtifact}},
		{"support exe 404", "GET", "/download/DeskRallySupport.exe", 404, Result{ClassNoise, NoiseArtifact}},
		{"support exe 416", "GET", "/download/DeskRallySupport.exe", 416, Result{ClassNoise, NoiseArtifact}},
		{"support exe POST", "POST", "/download/DeskRallySupport.exe", 200, Result{ClassNoise, NoiseArtifact}},
		{"server tarball", "GET", "/download/server/deskrally-server-1.4.2.tar.gz", 200, Result{ClassHuman, "server/deskrally-server-1.4.2.tar.gz"}},
		{"server tarball leading zero", "GET", "/download/server/deskrally-server-01.4.2.tar.gz", 200, Result{ClassNoise, NoiseArtifact}},
		{"provisioning script", "GET", "/download/agent/new-msi-provisioning.ps1", 200, Result{ClassHuman, "agent/new-msi-provisioning.ps1"}},
		// other bucket
		{"sidecar hash", "GET", "/download/DeskRallySupport.exe.sha256.txt", 200, Result{ClassOther, "sidecar"}},
		{"server sidecar", "GET", "/download/server/deskrally-server-1.4.2.tar.gz.sha256.txt", 200, Result{ClassOther, "sidecar"}},
		{"script sidecar", "GET", "/download/agent/new-msi-provisioning.ps1.sha256.txt", 200, Result{ClassOther, "sidecar"}},
		{"server latest", "GET", "/download/server/latest.json", 200, Result{ClassOther, "server-latest"}},
		{"server latest 304", "GET", "/download/server/latest.json", 304, Result{ClassOther, "server-latest"}},
		// the update feed, never a download
		{"agent v2 manifest", "GET", "/download/agent/v2/canary/manifest.json", 200, Result{ClassUpdate, "agent-manifest"}},
		{"agent v1 manifest 304", "GET", "/download/agent/general/manifest.json", 304, Result{ClassUpdate, "agent-manifest"}},
		{"client manifest", "GET", "/download/client/manifest.json", 200, Result{ClassUpdate, "client-manifest"}},
		{"agent msi payload", "GET", "/download/agent/releases/1.3.19/DeskRallyAgent.msi", 200, Result{ClassUpdate, "agent-payload"}},
		{"agent host payload", "GET", "/download/agent/releases/1.3.19/agent_host.exe", 206, Result{ClassUpdate, "agent-payload"}},
		{"client payload", "GET", "/download/client/releases/2.0.0/DeskRallyClient.exe", 200, Result{ClassUpdate, "client-payload"}},
		{"manifest HEAD", "HEAD", "/download/agent/v2/canary/manifest.json", 200, Result{ClassNoise, NoiseArtifact}},
		{"unknown ring", "GET", "/download/agent/v2/nightly/manifest.json", 200, Result{ClassNoise, NoiseArtifact}},
		{"unknown ring, format 1", "GET", "/download/agent/nightly/manifest.json", 200, Result{ClassNoise, NoiseArtifact}},
		{"payload other name", "GET", "/download/agent/releases/1.3.19/evil.msi", 200, Result{ClassNoise, NoiseArtifact}},
		// noise and hostile URIs
		{"console root", "GET", "/", 200, Result{ClassNoise, NoiseArtifact}},
		{"scanner", "GET", "/wp-login.php", 404, Result{ClassNoise, NoiseArtifact}},
		{"dot segments", "GET", "/download/../download/DeskRallySupport.exe", 200, Result{ClassNoise, NoiseArtifact}},
		{"percent escape", "GET", "/download/DeskRallySupport%2eexe", 200, Result{ClassNoise, NoiseArtifact}},
		{"double slash", "GET", "/download//DeskRallySupport.exe", 200, Result{ClassNoise, NoiseArtifact}},
		{"trailing slash", "GET", "/download/DeskRallySupport.exe/", 200, Result{ClassNoise, NoiseArtifact}},
		{"backslash", "GET", `/download\DeskRallySupport.exe`, 200, Result{ClassNoise, NoiseArtifact}},
		{"control byte", "GET", "/download/DeskRallySupport.exe\x00", 200, Result{ClassNoise, NoiseArtifact}},
		{"case differs", "GET", "/download/deskrallysupport.exe", 200, Result{ClassNoise, NoiseArtifact}},
		{"empty", "GET", "", 200, Result{ClassNoise, NoiseArtifact}},
		{"oversize uri", "GET", long, 200, Result{ClassNoise, NoiseArtifact}},
	}
	for _, c := range cases {
		if got := Classify(c.method, c.uri, c.status); got != c.want {
			t.Errorf("%s: Classify(%s %q %d) = %+v, want %+v", c.name, c.method, c.uri, c.status, got, c.want)
		}
	}
}

func TestCompleted(t *testing.T) {
	cases := []struct {
		name                string
		status              int
		size, art           int64
		sizeKnown           bool
		wantDone, wantKnown bool
	}{
		{"whole file", 200, 10_000_000, 10_000_000, true, true, true},
		{"within the 1 KiB slack", 200, 10_000_000 - 1024, 10_000_000, true, true, true},
		{"one byte past the slack", 200, 10_000_000 - 1025, 10_000_000, true, false, true},
		{"truncated: client went away", 200, 4096, 10_000_000, true, false, true},
		{"a 206 is never complete", 206, 10_000_000, 10_000_000, true, false, true},
		{"size unknown is unknown, not no", 200, 10_000_000, 0, false, false, false},
		{"zero artifact size is unknown", 200, 5, 0, true, false, false},
		{"logged size missing (0) on a known artifact", 200, 0, 10_000_000, true, false, true},
	}
	for _, c := range cases {
		done, known := Completed(c.status, c.size, c.art, c.sizeKnown)
		if done != c.wantDone || known != c.wantKnown {
			t.Errorf("%s: Completed = (%v, %v), want (%v, %v)", c.name, done, known, c.wantDone, c.wantKnown)
		}
	}
}
