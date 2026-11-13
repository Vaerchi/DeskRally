//go:build windows

package main

// The root key file (docs/48 "Key custody"): the 32-byte P-256 scalar, DPAPI-protected for the
// CURRENT USER with purpose-binding entropy, in a file created exclusively and given an owner-only,
// protected DACL before a byte of it is written. Copying the file to another account or machine
// yields nothing usable; a backup is a separate, deliberate export (not provided in v1).

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var keyEntropy = []byte("DeskRally deployment-pass root key v1")

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func takeBlob(out *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	b := make([]byte, out.Size)
	copy(b, unsafe.Slice(out.Data, out.Size))
	return b
}

func protect(secret []byte) ([]byte, error) {
	var out windows.DataBlob
	desc, _ := windows.UTF16PtrFromString("DeskRally pass root key")
	if err := windows.CryptProtectData(blob(secret), desc, blob(keyEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("DPAPI protect: %w", err)
	}
	return takeBlob(&out), nil
}

func unprotect(sealed []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(sealed), nil, blob(keyEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("DPAPI unprotect (is this the account that ran gen-key?): %w", err)
	}
	return takeBlob(&out), nil
}

// createOwnerOnly creates path with CREATE_NEW and its final security in one call: a protected
// DACL (nothing inherited) granting full control to the current user only, and no sharing while
// this handle is open. There is no moment when the file exists with the parent's permissions, and
// CREATE_NEW fails on anything already at path, including a link or reparse point.
func createOwnerOnly(path string) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("current user: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil, fmt.Errorf("%s already exists: refusing to overwrite it", path)
		}
		return nil, fmt.Errorf("create %s: %w", path, err)
	}
	return os.NewFile(uintptr(h), path), nil
}

// writeKeyFile creates path exclusively and owner-only (an existing key is never replaced), then
// writes the sealed scalar through the same handle.
func writeKeyFile(path string, scalar []byte) error {
	f, err := createOwnerOnly(path)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	sealed, err := protect(scalar)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(keyFileHeader + "\n" + base64.StdEncoding.EncodeToString(sealed) + "\n"); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}

func readKeyFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	lines := strings.Split(strings.TrimRight(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n"), "\n")
	if len(lines) != 2 || lines[0] != keyFileHeader {
		return nil, fmt.Errorf("%s is not a DeskRally pass root key file", path)
	}
	sealed, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return unprotect(sealed)
}

// lockFile takes an exclusive OS lock on path (created if absent) until the returned unlock is
// called. Windows releases it if the process dies, so a crash never leaves a stale lock.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	h := windows.Handle(f.Fd())
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		windows.UnlockFileEx(h, 0, 1, 0, ol)
		f.Close()
	}, nil
}

// readPassphraseFromConsole prompts on the console and reads one line with echo OFF, restoring the
// console mode afterwards. It reads CONIN$ directly, so redirected stdin cannot supply it.
func readPassphraseFromConsole(prompt string) (string, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("a passphrase needs an interactive console: %w", err)
	}
	defer in.Close()
	h := windows.Handle(in.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return "", fmt.Errorf("a passphrase needs an interactive console: %w", err)
	}
	if err := windows.SetConsoleMode(h, (mode&^windows.ENABLE_ECHO_INPUT)|windows.ENABLE_LINE_INPUT); err != nil {
		return "", err
	}
	defer windows.SetConsoleMode(h, mode)
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// writeOwnerOnlyFile creates path exclusively with the owner-only protected DACL (as the key file)
// and writes data through that handle; a failed write removes the file.
func writeOwnerOnlyFile(path string, data []byte) error {
	f, err := createOwnerOnly(path)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}
