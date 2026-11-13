//go:build linux

package controlplane

import (
	"os"

	"golang.org/x/sys/unix"
)

// renameBetween is renameat(2) on the two PINNED directory descriptors: neither path is resolved again, so a
// directory swapped for a link after it was pinned cannot redirect the move.
func renameBetween(_ *RecordingStorage, srcDir *os.Root, _, srcName string, dstDir *os.Root, _, dstName string) error {
	sf, err := srcDir.Open(".")
	if err != nil {
		return err
	}
	defer sf.Close()
	df, err := dstDir.Open(".")
	if err != nil {
		return err
	}
	defer df.Close()
	for {
		err = unix.Renameat(int(sf.Fd()), srcName, int(df.Fd()), dstName)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return &os.LinkError{Op: "renameat", Old: srcName, New: dstName, Err: err}
	}
	return nil
}
