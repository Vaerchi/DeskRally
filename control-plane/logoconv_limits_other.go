//go:build !linux && !windows

package controlplane

import "errors"

// childLimitsSupported is false where no resource limit is applied to the child: uploads are REFUSED there
// (ErrLogoUnsupported) and the console hides the field, rather than decoding an image without a memory cap.
const childLimitsSupported = false

func applyChildLimits() error { return errors.New("no child resource limits on this platform") }
