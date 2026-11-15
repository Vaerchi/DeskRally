//go:build !windows

package main

import "errors"

// The root key is held only on DeskRally's Windows signing workstation, under DPAPI (docs/48).
var errNoKeyStore = errors.New("the pass root key store needs Windows DPAPI; run rmt-pass-sign on the signing workstation")

func writeKeyFile(string, []byte) error  { return errNoKeyStore }
func readKeyFile(string) ([]byte, error) { return nil, errNoKeyStore }

func lockFile(string) (func(), error) { return nil, errNoKeyStore }

func readPassphraseFromConsole(string) (string, error) { return "", errNoKeyStore }

func writeOwnerOnlyFile(string, []byte) error { return errNoKeyStore }
