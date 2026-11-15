//go:build !linux

package controlplane

import "errors"

// gateBlockDeviceOf: /proc/diskstats exists on Linux only.
func gateBlockDeviceOf(path string) (string, error) {
	return "", errors.New("block-device flush counters are read on Linux only")
}
