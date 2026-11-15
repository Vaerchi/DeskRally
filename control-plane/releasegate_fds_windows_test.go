package controlplane

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var gateProcGetProcessHandleCount = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")

// gateOpenFDs counts this process's open handles (the Windows analogue of file descriptors).
func gateOpenFDs() (n int, ok bool, why string) {
	var c uint32
	h, err := windows.GetCurrentProcess()
	if err != nil {
		return 0, false, "GetCurrentProcess: " + err.Error()
	}
	r, _, e := gateProcGetProcessHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(&c)))
	if r == 0 {
		return 0, false, "GetProcessHandleCount: " + e.Error()
	}
	return int(c), true, ""
}

// gateHandlesPerOSThread: on Windows every OS thread the Go runtime creates holds handles (the thread, its wake
// semaphore, its high-resolution timer and the rest), and the runtime never ends a thread, so a burst of load leaves the
// handle count on a plateau that is the thread count and not a leak. Measured, not assumed: across hostile-mix runs
// (slow headers, slow bodies, slow readers, churn) the handle growth was 7.5 to 8.3 handles per thread created
// (98/12, 91/11, 84/11, 32/4, 30/4), with the goroutine count and the connection count back at baseline. The no-growth
// bound judges handles net of this (the "open_fds_net" series); on Linux a thread is no descriptor, so it is 0.
const gateHandlesPerOSThread = 8
