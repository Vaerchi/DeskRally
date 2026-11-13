//go:build windows

package controlplane

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// childLimitsSupported: native Windows applies a Job Object to the child itself (docs/66 2b.3).
const childLimitsSupported = true

// applyChildLimits puts the CURRENT process into a new Job Object with a 256 MiB process memory limit and a
// 3 s user-time limit, before it reads any input (the Linux child does the same to itself with setrlimit).
// Nested jobs are supported from Windows 8; if the assignment is refused the child exits without reading and
// conversion fails closed.
func applyChildLimits() error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | windows.JOB_OBJECT_LIMIT_PROCESS_TIME
	info.BasicLimitInformation.PerProcessUserTimeLimit = int64(logoChildCPUSeconds) * 10_000_000 // 100 ns units
	info.ProcessMemoryLimit = logoChildMemoryBytes
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return err
	}
	return windows.AssignProcessToJobObject(job, windows.CurrentProcess())
}
