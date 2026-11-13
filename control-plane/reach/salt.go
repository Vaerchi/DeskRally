package reach

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The unique-ish count (docs/68 section 5). A client is HMAC-SHA256(daily_salt, ip|ua); the hashes live in an
// in-process set per UTC day and ONLY THE SET'S SIZE is ever written. The salt is held in memory and in one
// 0600 file on a tmpfs path, and it is OVERWRITTEN when the UTC day changes, so once a day is over nothing on
// the box can map yesterday's hashes back to an (ip, ua) pair, and a hash from one day cannot be linked to the
// same client on another day. The database never receives an IP, a User-Agent or a client hash (the cursor id is a hash of a server timestamp, see segments.go).

// Salt is one UTC day's key.
type Salt struct {
	Day string // YYYY-MM-DD, UTC
	Key [32]byte
}

// DayString is the UTC calendar day of t, the form Salt.Day and the day buckets use.
func DayString(t time.Time) string { return t.UTC().Format("2006-01-02") }

func newSalt(day string) (Salt, error) {
	s := Salt{Day: day}
	if _, err := rand.Read(s.Key[:]); err != nil {
		return Salt{}, fmt.Errorf("reach: salt entropy: %w", err)
	}
	return s, nil
}

// ClientHash is the keyed hash of a client for the salt's day. ip and ua are hashed with an unambiguous
// separator and never stored.
func (s Salt) ClientHash(ip, ua string) [32]byte {
	m := hmac.New(sha256.New, s.Key[:])
	m.Write([]byte(ip))
	m.Write([]byte{0})
	m.Write([]byte(ua))
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// SaltFile persists the current day's salt so a restart in the middle of the day reloads it. Path should be on
// a tmpfs: the salt must not survive a reboot or reach a backup.
type SaltFile struct {
	Path string

	// test seams (unexported: only the package's own tests set them)
	storeHook func(Salt) error
	eraseHook func() error
	lstatHook func(string) (os.FileInfo, error)
}

// Load returns the stored salt, or ok=false when the file is missing or unusable (any parse problem is the
// same as missing: the caller then makes a new salt and marks the day partial).
func (f SaltFile) Load() (s Salt, ok bool) {
	b, err := os.ReadFile(f.Path)
	if err != nil || len(b) > 256 {
		return Salt{}, false
	}
	parts := strings.Fields(string(b))
	if len(parts) != 2 {
		return Salt{}, false
	}
	if _, err := time.Parse("2006-01-02", parts[0]); err != nil {
		return Salt{}, false
	}
	raw, err := hex.DecodeString(parts[1])
	if err != nil || len(raw) != 32 {
		return Salt{}, false
	}
	s.Day = parts[0]
	copy(s.Key[:], raw)
	return s, true
}

// Store overwrites the file IN PLACE (truncate, then write), so the previous day's key is not left behind in a
// second file or a rename target. Mode 0600.
func (f SaltFile) Store(s Salt) error {
	if f.storeHook != nil {
		return f.storeHook(s)
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	fh, err := os.OpenFile(f.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	// Tighten BEFORE writing: the open's mode only applies to a new file, and the file is empty here (O_TRUNC), so a
	// pre-existing looser file never holds the key at a looser mode.
	if err := fh.Chmod(0o600); err != nil {
		fh.Close()
		return err
	}
	_, werr := fmt.Fprintf(fh, "%s\n%s\n", s.Day, hex.EncodeToString(s.Key[:]))
	if werr == nil {
		werr = fh.Sync()
	}
	if cerr := fh.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	return nil
}

// Erase removes the file. A missing file is success: there is nothing left to leak. It is the fallback when the
// file cannot be overwritten with the new day's key: an expired key must not stay on disk.
func (f SaltFile) Erase() error {
	if f.eraseHook != nil {
		return f.eraseHook()
	}
	if err := os.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Exists reports whether something MAY be at the path (a key may be there). Only a definite "does not exist"
// answer means absent: a permission or I/O error says nothing about the file, so it counts as present and the
// caller stays fail closed (it must not resume hashing while an expired key could remain).
func (f SaltFile) Exists() bool {
	lstat := os.Lstat
	if f.lstatHook != nil {
		lstat = f.lstatHook
	}
	_, err := lstat(f.Path)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}
