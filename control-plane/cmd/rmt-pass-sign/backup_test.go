package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	controlplane "rmt/controlplane"
)

const testPass = "correct horse battery staple"

func newScalar(t *testing.T) ([]byte, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := k.Bytes()
	pub, _ := controlplane.DeploymentRootKeyHex(&k.PublicKey)
	return s, pub
}

func TestBackupRoundTripAndRefusals(t *testing.T) {
	scalar, pub := newScalar(t)
	sealed, err := sealBackup(scalar, testPass)
	if err != nil {
		t.Fatal(err)
	}
	// The file is JSON with hex fields, so a leaked scalar would appear as hex.
	if bytes.Contains(sealed, []byte(hex.EncodeToString(scalar))) {
		t.Fatal("scalar in the clear")
	}
	got, gotPub, err := openBackup(sealed, testPass)
	if err != nil || !bytes.Equal(got, scalar) || gotPub != pub {
		t.Fatalf("round trip: %v", err)
	}
	if _, _, err := openBackup(sealed, testPass+"x"); err == nil {
		t.Fatal("a wrong passphrase opened the backup")
	}

	edit := func(f func(*keyBackup)) []byte {
		var b keyBackup
		if err := json.Unmarshal(sealed, &b); err != nil {
			t.Fatal(err)
		}
		f(&b)
		out, _ := json.Marshal(b)
		return out
	}
	_, otherPub := newScalar(t)
	if _, _, err := openBackup(edit(func(b *keyBackup) { b.Pubkey = otherPub }), testPass); err == nil {
		t.Fatal("a backup with an edited public key opened")
	}
	if _, _, err := openBackup(edit(func(b *keyBackup) { b.Time = 3 }), testPass); err == nil {
		t.Fatal("a backup with an edited KDF parameter opened")
	}
	// Out-of-range parameters are refused BEFORE any derivation (no unbounded work from a file).
	start := time.Now()
	if _, _, err := openBackup(edit(func(b *keyBackup) { b.MemoryKiB = 64 * 1024 * 1024 }), testPass); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("a huge memory parameter: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the refusal spent time deriving")
	}
	if _, err := sealBackup(scalar, "too short"); err == nil {
		t.Fatal("a short passphrase was accepted")
	}
	var raw map[string]any
	_ = json.Unmarshal(sealed, &raw)
	raw["extra"] = 1
	withExtra, _ := json.Marshal(raw)
	if _, _, err := openBackup(withExtra, testPass); err == nil {
		t.Fatal("an unknown field was accepted")
	}
}

func TestExportImportEndToEnd(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the root key store is Windows DPAPI only")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "root.key")
	if err := cmdGenKey([]string{"-key", key}); err != nil {
		t.Fatal(err)
	}
	k, _ := loadKey(key)
	pub, _ := controlplane.DeploymentRootKeyHex(&k.PublicKey)

	answers := []string{}
	orig := askPassphrase
	askPassphrase = func(string) (string, error) { a := answers[0]; answers = answers[1:]; return a, nil }
	defer func() { askPassphrase = orig }()

	backup := filepath.Join(dir, "root.backup.json")
	answers = []string{testPass, testPass + "!"}
	if err := cmdExportKey([]string{"-key", key, "-out", backup}); err == nil {
		t.Fatal("mismatched passphrases exported")
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatal("a refused export wrote a file")
	}
	answers = []string{testPass, testPass}
	if err := cmdExportKey([]string{"-key", key, "-out", backup}); err != nil {
		t.Fatal(err)
	}
	answers = []string{testPass, testPass}
	if err := cmdExportKey([]string{"-key", key, "-out", backup}); err == nil {
		t.Fatal("export overwrote an existing backup")
	}

	restored := filepath.Join(dir, "restored.key")
	answers = []string{testPass + "?"}
	if err := cmdImportKey([]string{"-backup", backup, "-key", restored}); err == nil {
		t.Fatal("a wrong passphrase imported")
	}
	if _, err := os.Stat(restored); !os.IsNotExist(err) {
		t.Fatal("a refused import wrote a key file")
	}
	answers = []string{testPass}
	if err := cmdImportKey([]string{"-backup", backup, "-key", restored}); err != nil {
		t.Fatal(err)
	}
	back, err := loadKey(restored)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := controlplane.DeploymentRootKeyHex(&back.PublicKey); got != pub {
		t.Fatalf("restored key %s, want %s", got, pub)
	}
}

func TestBackupStrictDecoding(t *testing.T) {
	scalar, _ := newScalar(t)
	sealed, err := sealBackup(scalar, testPass)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := bytes.TrimSpace(sealed)
	cases := map[string][]byte{
		"trailing data":   append(append([]byte{}, trimmed...), []byte(` {}`)...),
		"duplicate field": bytes.Replace(trimmed, []byte(`"kdf"`), []byte(`"kdf": "argon2id", "kdf"`), 1),
		"oversize":        append(append([]byte{}, trimmed...), bytes.Repeat([]byte(" "), maxBackupBytes)...),
	}
	var b keyBackup
	_ = json.Unmarshal(sealed, &b)
	b.Ciphertext += "00"
	cases["long ciphertext"], _ = json.Marshal(b)
	for name, raw := range cases {
		start := time.Now()
		if _, _, err := openBackup(raw, testPass); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("%s: refused only after deriving", name)
		}
	}
}

func TestBackupFileIsOwnerOnlyAndRefusesHugeInput(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("owner-only DACL is Windows")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "b.json")
	if err := writeOwnerOnlyFile(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyFile(p, []byte("y")); err == nil {
		t.Fatal("overwrote an existing backup")
	}
	big := filepath.Join(dir, "big.json")
	os.WriteFile(big, bytes.Repeat([]byte("a"), maxBackupBytes+1), 0o600)
	if _, err := readBackupFile(big); err == nil {
		t.Fatal("read an oversize backup")
	}
}
