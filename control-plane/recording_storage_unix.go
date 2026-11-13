//go:build linux || darwin || freebsd

package controlplane

import (
	"io/fs"
	"syscall"
)

func devOf(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true
}

// FreeBytes returns the bytes available to an unprivileged writer on the volume holding dir.
func (s *RecordingStorage) FreeBytes() (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(s.rootDir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
