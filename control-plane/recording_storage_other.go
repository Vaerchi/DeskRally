//go:build !linux && !darwin && !freebsd && !windows

package controlplane

import (
	"errors"
	"io/fs"
)

func devOf(fi fs.FileInfo) (uint64, bool) { return 0, false }

// FreeBytes is unsupported on this platform; the server-full floor then needs an injected reader.
func (s *RecordingStorage) FreeBytes() (uint64, error) {
	return 0, errors.New("free-space query unsupported on this platform")
}
