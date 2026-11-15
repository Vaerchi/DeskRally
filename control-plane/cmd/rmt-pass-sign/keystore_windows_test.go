//go:build windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestKeyFileIsOwnerOnly: the DACL is protected (nothing inherited) and has exactly one ACE, for
// the current user; and the sealed file does not contain the scalar.
func TestKeyFileIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.key")
	scalar := []byte("0123456789abcdef0123456789abcdef")
	if err := writeKeyFile(path, scalar); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ctl, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if ctl&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the DACL is not protected: inherited ACEs apply")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("no DACL: %v", err)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("DACL has %d ACEs, want exactly 1 (the owner)", dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	user, _ := windows.GetCurrentProcessToken().GetTokenUser()
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !sid.Equals(user.User.Sid) {
		t.Errorf("the ACE is for %s, not the current user %s", sid, user.User.Sid)
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, scalar) {
		t.Error("the key file contains the scalar in the clear")
	}
	back, err := readKeyFile(path)
	if err != nil || string(back) != string(scalar) {
		t.Fatalf("read back %q, %v", back, err)
	}
}
