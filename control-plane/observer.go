package controlplane

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
)

// An omitted field keeps the legacy default. Present values, including null and "",
// must be valid explicitly: silently defaulting a malformed observation request changes mode.
type startSessionAccess string

func (a *startSessionAccess) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if value != "control" && value != "view_only" {
		return errors.New("access must be control or view_only")
	}
	*a = startSessionAccess(value)
	return nil
}

// Only an omitted access is normalized. Unknown store inputs fail closed rather than
// becoming control sessions; legacy writers that omit access retain their existing behavior.
func normalizeSessionRecordAccess(rec *SessionRecord) error {
	if rec.Access == "" {
		rec.Access = "control"
	}
	if rec.Access != "control" && rec.Access != "view_only" {
		return errors.New("access must be control or view_only")
	}
	return nil
}

// Release versions may include SemVer build metadata (e.g. 0.1.3+sha). Prereleases
// are deliberately refused: a 0.1.3 prerelease does not establish observer support.
var observerAgentRelease = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func observerAgentSupported(version string) bool {
	return agentVersionAtLeast(version, [3]uint64{0, 1, 3})
}

// agentVersionAtLeast reports whether version is a release (SemVer build metadata allowed, prereleases
// and anything unparseable refused) at or above minimum. The one parse behind every agent-version gate:
// observers (0.1.3) and session transfer (0.1.6).
func agentVersionAtLeast(version string, minimum [3]uint64) bool {
	parts := observerAgentRelease.FindStringSubmatch(version)
	if parts == nil {
		return false
	}
	var release [3]uint64
	for i := range release {
		v, err := strconv.ParseUint(parts[i+1], 10, 64)
		if err != nil {
			return false
		}
		release[i] = v
	}
	for i := range release {
		if release[i] != minimum[i] {
			return release[i] > minimum[i]
		}
	}
	return true
}
