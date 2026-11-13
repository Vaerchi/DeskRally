//go:build !linux

package controlplane

import "os"

// renameBetween has no two-handle rename to use here (os.Root renames within one root only), so it renames
// through the volume root by volume-relative path. os.Root cannot leave the volume; the caller VERIFIES
// afterwards that the entry arrived in the pinned destination (moveEntry), so a directory substituted
// inside this one call is reported as ErrUnsafePath rather than silently accepted. Production runs on
// Linux, which takes the renameat path.
func renameBetween(s *RecordingStorage, _ *os.Root, srcRel, _ string, _ *os.Root, dstRel, _ string) error {
	return s.root.Rename(srcRel, dstRel)
}
