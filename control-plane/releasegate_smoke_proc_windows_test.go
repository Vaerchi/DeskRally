//go:build releasegate

package controlplane

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	smokeKernel32            = windows.NewLazySystemDLL("kernel32.dll")
	smokeProcGetHandleCount  = smokeKernel32.NewProc("GetProcessHandleCount")
	smokeProcGetMemoryInfo   = smokeKernel32.NewProc("K32GetProcessMemoryInfo")
	smokeProcMemoryCountersK = uint32(unsafe.Sizeof(smokeMemCounters{}))
)

// smokeMemCounters is PROCESS_MEMORY_COUNTERS.
type smokeMemCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// smokeProcStats reads another process's resident set (the working set, bytes) and open handle count.
func smokeProcStats(pid int) (rssBytes uint64, handles int, err error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, 0, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)
	var mc smokeMemCounters
	mc.Cb = smokeProcMemoryCountersK
	if r, _, e := smokeProcGetMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&mc)), uintptr(mc.Cb)); r == 0 {
		return 0, 0, fmt.Errorf("K32GetProcessMemoryInfo: %v", e)
	}
	var c uint32
	if r, _, e := smokeProcGetHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(&c))); r == 0 {
		return 0, 0, fmt.Errorf("GetProcessHandleCount: %v", e)
	}
	return uint64(mc.WorkingSetSize), int(c), nil
}
