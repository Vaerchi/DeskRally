// Package reach turns Caddy's JSON access log into per-day download and update COUNTS (docs/68).
//
// Everything here treats the log as untrusted data: a line is attacker-influenced (the URI and the
// User-Agent are chosen by whoever sends the request), so the parser bounds every field, the classifier
// matches the URI against fixed patterns and never uses the URI itself as a path or a SQL fragment (the one
// filesystem use is a regex-validated artifact NAME, joined under a fixed directory, see DirSizes), and the only
// things that ever leave the process are counts. No IP, User-Agent or client hash is stored anywhere (see salt.go
// for the one in-memory use of them); the only hash stored is a cursor id, a hash of a server timestamp.
package reach

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	// MaxLineBytes bounds one log line. A real Caddy access line is under 2 KiB; anything longer is a
	// probe stuffing a header and is skipped (counted, never parsed).
	MaxLineBytes = 32 << 10
	// MaxURIBytes bounds the logged URI. A longer one is classified as noise without being matched.
	MaxURIBytes = 2048
	// MaxUABytes bounds the User-Agent that is fed to the keyed hash.
	MaxUABytes = 512
)

// Entry is the part of one access-log line the report uses.
type Entry struct {
	TS     time.Time
	IP     string
	Method string
	URI    string
	UA     string
	Status int
	Size   int64
}

// ErrMalformed marks a line that is not a usable access record. The ingest counts these and moves on.
var ErrMalformed = errors.New("reach: malformed access-log line")

// rawLine mirrors Caddy's access-log shape (format json). Unknown fields are ignored; every field the
// report does not name is never decoded into memory.
type rawLine struct {
	TS      float64 `json:"ts"`
	Status  int     `json:"status"`
	Size    int64   `json:"size"`
	Request struct {
		RemoteIP string              `json:"remote_ip"`
		Method   string              `json:"method"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
}

// ParseLine decodes one line. It never panics on hostile input and never keeps the line.
func ParseLine(line []byte) (Entry, error) {
	var e Entry
	if len(line) == 0 || len(line) > MaxLineBytes {
		return e, ErrMalformed
	}
	var r rawLine
	if err := json.Unmarshal(line, &r); err != nil {
		return e, ErrMalformed
	}
	// A timestamp is required: the day bucket and the roll-over order both come from it. Caddy writes
	// seconds with a fraction; reject anything that is not a plausible epoch (zero, negative, NaN, absurd).
	if !(r.TS > 1e9 && r.TS < 1e11) {
		return e, ErrMalformed
	}
	if r.Status < 100 || r.Status > 599 {
		return e, ErrMalformed
	}
	if r.Size < 0 {
		r.Size = 0
	}
	sec := int64(r.TS)
	e.TS = time.Unix(sec, int64((r.TS-float64(sec))*1e9)).UTC()
	e.Status = r.Status
	e.Size = r.Size
	e.Method = strings.ToUpper(r.Request.Method)
	if len(e.Method) > 16 {
		e.Method = e.Method[:16]
	}
	e.URI = r.Request.URI
	e.IP = r.Request.RemoteIP
	if len(e.IP) > 64 {
		e.IP = ""
	}
	for k, v := range r.Request.Headers {
		if strings.EqualFold(k, "User-Agent") && len(v) > 0 {
			e.UA = v[0]
			if len(e.UA) > MaxUABytes {
				e.UA = e.UA[:MaxUABytes]
			}
			break
		}
	}
	return e, nil
}
