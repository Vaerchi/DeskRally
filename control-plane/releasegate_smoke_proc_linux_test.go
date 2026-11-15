//go:build releasegate

package controlplane

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// smokeProcStats reads another process's VmRSS (/proc/<pid>/status, bytes) and its open descriptor count.
func smokeProcStats(pid int) (rssBytes uint64, handles int, err error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	found := false
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "VmRSS:"); ok {
			fields := strings.Fields(rest)
			if len(fields) < 1 {
				return 0, 0, fmt.Errorf("VmRSS line malformed: %q", sc.Text())
			}
			kb, perr := strconv.ParseUint(fields[0], 10, 64)
			if perr != nil {
				return 0, 0, perr
			}
			rssBytes, found = kb*1024, true
		}
	}
	if !found {
		return 0, 0, fmt.Errorf("no VmRSS in /proc/%d/status", pid)
	}
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return 0, 0, err
	}
	return rssBytes, len(ents), nil
}
