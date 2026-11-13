//go:build linux

package controlplane

import "syscall"

// childLimitsSupported: Linux applies RLIMIT_DATA and RLIMIT_CPU to the child itself (docs/66 2b.3).
const childLimitsSupported = true

// applyChildLimits caps the child's private writable memory at 256 MiB and its CPU time at 3 s before it reads a
// byte of input.
//
// WHY RLIMIT_DATA AND NOT RLIMIT_AS (repair B1, measured on the Linux CI VM, kernel 6.8, Go 1.26): a Go process
// reserves about 1.2 GB of VIRTUAL address space at startup (VmSize 1227448 kB on an idle program), and
// RLIMIT_AS counts all of it, including PROT_NONE reservations. With RLIMIT_AS at 256, 512 or even 1024 MiB a
// Go child could not allocate a 60 MiB slice ("fatal error: out of memory"), so valid conversions failed.
// RLIMIT_DATA (Linux 4.7 and later) counts only private writable mappings, which is what an image decode really
// uses (VmData 40 MB idle): at 256 MiB the same child allocates 60 MiB normally and dies on a 400 MiB request.
// The pre-decode dimension gate (4 megapixels) and the parent's wall-time kill are the other two layers.
// On a kernel older than 4.7 RLIMIT_DATA only covers the brk heap and is not a bound for a Go process; Docker
// hosts run far newer kernels.
func applyChildLimits() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_DATA, &syscall.Rlimit{Cur: logoChildMemoryBytes, Max: logoChildMemoryBytes}); err != nil {
		return err
	}
	return syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: logoChildCPUSeconds, Max: logoChildCPUSeconds})
}
