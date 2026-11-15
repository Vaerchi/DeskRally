package controlplane

import "os"

// gateOpenFDs counts this process's open file descriptors (/proc/self/fd; the directory read itself holds one).
func gateOpenFDs() (n int, ok bool, why string) {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false, "/proc/self/fd: " + err.Error()
	}
	return len(ents) - 1, true, ""
}

// gateHandlesPerOSThread: a thread is no descriptor here, so the "open_fds_net" series equals "open_fds".
const gateHandlesPerOSThread = 0
