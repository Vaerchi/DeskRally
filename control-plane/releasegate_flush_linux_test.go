package controlplane

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// gateBlockDeviceOf returns the name of the whole disk that holds path (the name /proc/diskstats uses): the file's device
// number resolved through /sys/dev/block, and for a partition the disk above it (flush counts are kept per disk).
func gateBlockDeviceOf(path string) (string, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return "", fmt.Errorf("the database data directory %s is not on this machine's filesystem: %v", path, err)
	}
	dev := uint64(st.Dev)
	major := ((dev >> 8) & 0xfff) | ((dev >> 32) &^ 0xfff)
	minor := (dev & 0xff) | ((dev >> 12) &^ 0xff)
	link := fmt.Sprintf("/sys/dev/block/%d:%d", major, minor)
	real, err := filepath.EvalSymlinks(link)
	if err != nil {
		return "", fmt.Errorf("device %d:%d has no entry in /sys/dev/block: %v", major, minor, err)
	}
	if _, err := os.Stat(filepath.Join(real, "partition")); err == nil {
		return filepath.Base(filepath.Dir(real)), nil
	}
	return filepath.Base(real), nil
}
