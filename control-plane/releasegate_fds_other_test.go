//go:build !windows && !linux

package controlplane

// gateOpenFDs is not measured on this platform; the sampler reports that rather than omitting the series.
func gateOpenFDs() (n int, ok bool, why string) {
	return 0, false, "open descriptors are measured on Linux and Windows only"
}

// gateHandlesPerOSThread: a thread is no descriptor here, so the "open_fds_net" series equals "open_fds".
const gateHandlesPerOSThread = 0
