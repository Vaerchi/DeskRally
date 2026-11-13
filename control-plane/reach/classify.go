package reach

import (
	"regexp"
	"strings"
)

// Class is the bucket a request lands in (docs/68 section 3). The word "download" never labels a raw
// request: only ClassHuman rows are "download requests", and even those include bots and retries.
type Class string

const (
	ClassHuman  Class = "human"  // a person-facing artifact: the support exe, the server tarball, the provisioning script
	ClassUpdate Class = "update" // the agent / client update feed: manifests and payloads (machine traffic)
	ClassOther  Class = "other"  // sidecar hashes and the server latest.json
	ClassNoise  Class = "noise"  // everything else, and every request that is not a counted GET
)

// NoiseArtifact is the artifact label of a noise row: only the total is kept.
const NoiseArtifact = "-"

// Result is the classification of one request.
type Result struct {
	Class    Class
	Artifact string // a fixed label, or for ClassHuman the path under /download/ (it is regex-validated, so the set is bounded)
}

const semver = `(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})`

// These mirror the Caddyfile's /download handlers (deploy/Caddyfile), nothing looser: a path the Caddyfile
// answers 404 for is not an artifact here either.
var (
	humanServer   = regexp.MustCompile(`^/download/server/deskrally-server-` + semver + `\.tar\.gz$`)
	sidecarServer = regexp.MustCompile(`^/download/(server/deskrally-server-` + semver + `\.tar\.gz\.sha256\.txt|agent/new-msi-provisioning\.ps1\.sha256\.txt|DeskRallySupport\.exe\.sha256\.txt)$`)
	updateMan     = regexp.MustCompile(`^/download/(client/manifest\.json|agent/(canary|early|general)/manifest\.json|agent/v2/(canary|early|general)/manifest\.json)$`)
	updatePayload = regexp.MustCompile(`^/download/(client/releases/` + semver + `/DeskRallyClient\.exe|agent/releases/` + semver + `/(agent_host\.exe|DeskRallyAgent\.msi))$`)
)

// Classify decides the bucket from the METHOD, URI and STATUS alone (the User-Agent cannot be a marker: the
// agent sends none of its own). The URI is data: it is cut at the query, bounded, refused if it carries an
// escape or a dot-segment, and matched against fixed patterns; it is never opened as a path (DirSizes later joins only the regex-validated artifact NAME under a fixed directory).
func Classify(method, uri string, status int) Result {
	noise := Result{ClassNoise, NoiseArtifact}
	if len(uri) == 0 || len(uri) > MaxURIBytes {
		return noise
	}
	path := uri
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	// Percent escapes, dot segments, doubled slashes, backslashes and control bytes never name an artifact
	// the Caddyfile serves; refuse them rather than guess what a decoder would make of them.
	if strings.ContainsAny(path, "%\\") || strings.Contains(path, "..") || strings.Contains(path, "//") {
		return noise
	}
	for i := 0; i < len(path); i++ {
		if path[i] < 0x20 || path[i] == 0x7f {
			return noise
		}
	}

	var res Result
	switch {
	case path == "/download/DeskRallySupport.exe":
		res = Result{ClassHuman, "DeskRallySupport.exe"}
	case path == "/download/agent/new-msi-provisioning.ps1":
		res = Result{ClassHuman, "agent/new-msi-provisioning.ps1"}
	case humanServer.MatchString(path):
		res = Result{ClassHuman, strings.TrimPrefix(path, "/download/")}
	case path == "/download/server/latest.json":
		res = Result{ClassOther, "server-latest"}
	case sidecarServer.MatchString(path):
		res = Result{ClassOther, "sidecar"}
	case updateMan.MatchString(path):
		if strings.Contains(path, "/client/") {
			res = Result{ClassUpdate, "client-manifest"}
		} else {
			res = Result{ClassUpdate, "agent-manifest"}
		}
	case updatePayload.MatchString(path):
		if strings.Contains(path, "/client/") {
			res = Result{ClassUpdate, "client-payload"}
		} else {
			res = Result{ClassUpdate, "agent-payload"}
		}
	default:
		return noise
	}

	// Only a GET that delivered (or began delivering) the file counts. A HEAD, a 404, a 403, a redirect and a
	// 416 are scanner or probe traffic and land in the noise total. A 304 is a revalidation: it counts for the
	// machine feeds and the other bucket, never as a person's download.
	if method != "GET" {
		return noise
	}
	switch res.Class {
	case ClassHuman:
		if status != 200 && status != 206 {
			return noise
		}
	default:
		if status != 200 && status != 206 && status != 304 {
			return noise
		}
	}
	return res
}

// completedSlack is how much smaller than the artifact a 200's logged size may be and still count as complete.
const completedSlack = 1024

// Completed reports whether a counted human request looks like a whole download: a 200 whose logged size is
// within 1 KiB of the artifact's. known is false when the artifact's size is not available (then the answer is
// "unknown", never "no"). A 206 is never complete: resumed ranges are not stitched together.
func Completed(status int, size, artifactSize int64, sizeKnown bool) (complete, known bool) {
	if !sizeKnown || artifactSize <= 0 {
		return false, false
	}
	return status == 200 && size >= artifactSize-completedSlack, true
}
