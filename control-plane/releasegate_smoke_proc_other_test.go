//go:build releasegate && !windows && !linux

package controlplane

import "errors"

// smokeProcStats: no per-process reader on this OS; the smoke records the reason instead of numbers.
func smokeProcStats(pid int) (uint64, int, error) {
	return 0, 0, errors.New("process stats are implemented for windows and linux only")
}
