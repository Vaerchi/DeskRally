package reach

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// logLine renders a Caddy-shaped access-log line.
func logLine(ts float64, ip, method, uri, ua string, status int, size int64) string {
	hdr := map[string][]string{}
	if ua != "" {
		hdr["User-Agent"] = []string{ua}
	}
	b, _ := json.Marshal(map[string]any{
		"level": "info", "ts": ts, "logger": "http.log.access.log0", "msg": "handled request",
		"request":    map[string]any{"remote_ip": ip, "proto": "HTTP/2.0", "method": method, "host": "main.deskrally.com", "uri": uri, "headers": hdr},
		"bytes_read": 0, "duration": 0.001, "size": size, "status": status,
		"resp_headers": map[string][]string{"Content-Type": {"application/octet-stream"}},
	})
	return string(b)
}

func TestParseLine(t *testing.T) {
	good := logLine(1793880000.25, "203.0.113.7", "get", "/download/DeskRallySupport.exe", "Mozilla/5.0 X", 200, 12345)
	e, err := ParseLine([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if e.Method != "GET" || e.URI != "/download/DeskRallySupport.exe" || e.IP != "203.0.113.7" || e.UA != "Mozilla/5.0 X" ||
		e.Status != 200 || e.Size != 12345 || !e.TS.Equal(time.Unix(1793880000, 250_000_000).UTC()) {
		t.Fatalf("parsed %+v", e)
	}

	// A lower-case header name still yields the UA; a missing UA is empty, not an error.
	if e, err := ParseLine([]byte(`{"ts":1793880000.5,"status":200,"size":1,"request":{"method":"GET","uri":"/","headers":{"user-agent":["lc"]}}}`)); err != nil || e.UA != "lc" {
		t.Fatalf("lower-case header: %+v %v", e, err)
	}
	if e, err := ParseLine([]byte(logLine(1793880000, "1.1.1.1", "GET", "/", "", 200, 1))); err != nil || e.UA != "" {
		t.Fatalf("no UA: %+v %v", e, err)
	}
	// A negative size is clamped; an over-long UA is bounded.
	if e, err := ParseLine([]byte(logLine(1793880000, "1.1.1.1", "GET", "/", strings.Repeat("u", 5000), 200, -5))); err != nil || e.Size != 0 || len(e.UA) != MaxUABytes {
		t.Fatalf("clamps: size=%d ua=%d %v", e.Size, len(e.UA), err)
	}

	bad := map[string]string{
		"empty":             ``,
		"not json":          `GET /download/x 200`,
		"truncated mid-key": good[:len(good)/2],
		"truncated tail":    good[:len(good)-3],
		"no ts":             `{"status":200,"size":1,"request":{"method":"GET","uri":"/"}}`,
		"ts zero":           `{"ts":0,"status":200,"size":1,"request":{"method":"GET","uri":"/"}}`,
		"ts absurd":         `{"ts":1e15,"status":200,"size":1,"request":{"method":"GET","uri":"/"}}`,
		"ts is a string":    `{"ts":"1793880000","status":200,"size":1,"request":{"method":"GET","uri":"/"}}`,
		"status zero":       `{"ts":1793880000,"status":0,"size":1,"request":{"method":"GET","uri":"/"}}`,
		"status 700":        `{"ts":1793880000,"status":700,"size":1,"request":{"method":"GET","uri":"/"}}`,
		"size not a number": `{"ts":1793880000,"status":200,"size":"big","request":{"method":"GET","uri":"/"}}`,
		"array not object":  `[1,2,3]`,
		"oversized line":    `{"ts":1793880000,"status":200,"size":1,"request":{"method":"GET","uri":"/` + strings.Repeat("a", MaxLineBytes) + `"}}`,
	}
	for name, l := range bad {
		if _, err := ParseLine([]byte(l)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}
