//go:build windows

package controlplane

import (
	"io/fs"
	"syscall"
	"unsafe"
)

// Windows exposes no st_dev through os.FileInfo; the cross-device check is skipped there (Docker
// volumes — the production shape — run on Linux).
func devOf(fi fs.FileInfo) (uint64, bool) { return 0, false }

var getDiskFreeSpaceEx = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

// FreeBytes returns the bytes available to the caller on the volume holding dir.
func (s *RecordingStorage) FreeBytes() (uint64, error) {
	p, err := syscall.UTF16PtrFromString(s.rootDir)
	if err != nil {
		return 0, err
	}
	var avail, total, free uint64
	r, _, e := getDiskFreeSpaceEx.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&avail)),
		uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&free)))
	if r == 0 {
		return 0, e
	}
	return avail, nil
}
