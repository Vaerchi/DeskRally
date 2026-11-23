package main

// Passphrase-encrypted backup of the pass root key (docs/48 "Key custody").
//
// The live key is DPAPI-bound to one Windows account on one machine, so losing that profile would
// otherwise mean a new root key and new generic builds for every customer. A backup is the scalar
// sealed with AES-256-GCM under a key derived from a human passphrase by argon2id. It is meant to
// be stored OFFLINE (a USB stick in a safe, a password manager), with the passphrase kept apart
// from the file.
//
// The public key is stored in the clear so a backup can be identified without the passphrase, and
// it is bound into the ciphertext (with every KDF parameter) as authenticated data: a backup whose
// public key or parameters were edited does not decrypt. Restoring re-derives the public key from
// the decrypted scalar and refuses unless it equals the recorded one.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"

	controlplane "rmt/controlplane"
)

const (
	backupFormat = "deskrally-pass-root-key-backup"
	// argon2id cost for a key that is restored perhaps once in its life: deliberately expensive.
	backupTime      = 4
	backupMemoryKiB = 256 * 1024
	backupThreads   = 4
	// Bounds on parameters READ from a file, so a crafted backup cannot demand unbounded work.
	maxBackupTime      = 16
	maxBackupMemoryKiB = 1024 * 1024
	minPassphraseLen   = 16
)

type keyBackup struct {
	Format     string `json:"format"`
	V          int    `json:"v"`
	Pubkey     string `json:"pass_root_pubkey"`
	KDF        string `json:"kdf"`
	Time       uint32 `json:"time"`
	MemoryKiB  uint32 `json:"memory_kib"`
	Threads    uint8  `json:"threads"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// aad binds the public key and every KDF parameter to the ciphertext.
func (b keyBackup) aad() []byte {
	return []byte(fmt.Sprintf("%s v%d %s %s t=%d m=%d p=%d", b.Format, b.V, b.Pubkey, b.KDF, b.Time, b.MemoryKiB, b.Threads))
}

func checkPassphrase(p string) error {
	if len([]rune(p)) < minPassphraseLen {
		return fmt.Errorf("the passphrase must be at least %d characters (a few unrelated words work well)", minPassphraseLen)
	}
	return nil
}

func gcmFor(passphrase string, salt []byte, t, m uint32, threads uint8) (cipher.AEAD, error) {
	key := argon2.IDKey([]byte(passphrase), salt, t, m, threads, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealBackup encrypts a 32-byte P-256 scalar under passphrase.
func sealBackup(scalar []byte, passphrase string) ([]byte, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, err
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		return nil, fmt.Errorf("not a valid P-256 key: %w", err)
	}
	pub, err := controlplane.DeploymentRootKeyHex(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	b := keyBackup{Format: backupFormat, V: 1, Pubkey: pub, KDF: "argon2id", Time: backupTime,
		MemoryKiB: backupMemoryKiB, Threads: backupThreads, Salt: hex.EncodeToString(salt), Nonce: hex.EncodeToString(nonce)}
	aead, err := gcmFor(passphrase, salt, b.Time, b.MemoryKiB, b.Threads)
	if err != nil {
		return nil, err
	}
	b.Ciphertext = hex.EncodeToString(aead.Seal(nil, nonce, scalar, b.aad()))
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// maxBackupBytes bounds a backup read; a real one is about 600 bytes.
const maxBackupBytes = 4096

func readBackupFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read backup: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxBackupBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read backup: %w", err)
	}
	if len(raw) > maxBackupBytes {
		return nil, fmt.Errorf("not a DeskRally pass root key backup (over %d bytes)", maxBackupBytes)
	}
	return raw, nil
}

// noDuplicateKeys walks the top-level object and refuses a repeated key: encoding/json would
// silently keep the last one.
func noDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		k, _ := t.(string)
		if seen[k] {
			return fmt.Errorf("duplicate field %q", k)
		}
		seen[k] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}

func decodeBackup(raw []byte) (keyBackup, error) {
	var b keyBackup
	if len(raw) > maxBackupBytes {
		return b, errors.New("not a DeskRally pass root key backup (too large)")
	}
	if err := noDuplicateKeys(raw); err != nil {
		return b, fmt.Errorf("not a DeskRally pass root key backup: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, fmt.Errorf("not a DeskRally pass root key backup: %w", err)
	}
	if dec.Decode(new(json.RawMessage)) != io.EOF {
		return b, errors.New("not a DeskRally pass root key backup: trailing data")
	}
	// Exact sizes BEFORE any decoding or derivation: 16-byte salt, 12-byte nonce, and a 32-byte
	// scalar plus the 16-byte GCM tag.
	if len(b.Salt) != 32 || len(b.Nonce) != 24 || len(b.Ciphertext) != 96 {
		return b, errors.New("the backup is damaged (wrong field lengths)")
	}
	if b.Format != backupFormat || b.V != 1 || b.KDF != "argon2id" {
		return b, errors.New("not a version-1 DeskRally pass root key backup")
	}
	if b.Time < 1 || b.Time > maxBackupTime || b.MemoryKiB < 8*1024 || b.MemoryKiB > maxBackupMemoryKiB || b.Threads < 1 {
		return b, errors.New("the backup's key-derivation parameters are out of range")
	}
	if _, err := controlplane.ParseDeploymentRootKey(b.Pubkey); err != nil {
		return b, fmt.Errorf("the backup's public key is invalid: %w", err)
	}
	return b, nil
}

// askPassphrase reads a passphrase from the console without echo (keystore_windows.go). Tests
// replace it. It is never taken from a flag or the environment, for the reason the key itself is
// not: command lines and environments leak.
var askPassphrase = readPassphraseFromConsole

func cmdExportKey(args []string) error {
	fs := flag.NewFlagSet("export-key", flag.ExitOnError)
	keyPath := fs.String("key", "", "the root key file to back up")
	out := fs.String("out", "", "write the encrypted backup here (must not exist)")
	fs.Parse(args)
	if err := mustNotExist(*out); err != nil {
		return err
	}
	k, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	scalar, err := k.Bytes()
	if err != nil {
		return err
	}
	p1, err := askPassphrase("Backup passphrase (at least 16 characters): ")
	if err != nil {
		return err
	}
	if err := checkPassphrase(p1); err != nil {
		return err
	}
	p2, err := askPassphrase("Type it again: ")
	if err != nil {
		return err
	}
	if p1 != p2 {
		return errors.New("the two passphrases differ; nothing was written")
	}
	sealed, err := sealBackup(scalar, p1)
	if err != nil {
		return err
	}
	// Prove the backup restores BEFORE writing it: a backup that cannot be opened is worse than
	// none, because it is only discovered on the day it is needed.
	if _, pub, err := openBackup(sealed, p1); err != nil || pub == "" {
		return fmt.Errorf("the backup just made does not restore (%v): refusing to write it", err)
	}
	// Owner-only from creation (an encrypted backup is still an offline guessing target), then
	// read back FROM DISK and opened again: the check that matters is on the file that was written.
	if err := writeOwnerOnlyFile(*out, sealed); err != nil {
		return err
	}
	onDisk, err := readBackupFile(*out)
	if err == nil {
		_, _, err = openBackup(onDisk, p1)
	}
	if err != nil {
		os.Remove(*out)
		return fmt.Errorf("the written backup does not restore (%v): removed it", err)
	}
	pub, _ := controlplane.DeploymentRootKeyHex(&k.PublicKey)
	fmt.Printf("wrote %s (encrypted; restore with import-key)\npass_root_pubkey = %s\n", *out, pub)
	fmt.Println("Store it OFFLINE in two places, and keep the passphrase apart from the file.")
	return nil
}

func cmdImportKey(args []string) error {
	fs := flag.NewFlagSet("import-key", flag.ExitOnError)
	backupPath := fs.String("backup", "", "an encrypted backup made by export-key")
	keyPath := fs.String("key", "", "path to CREATE the restored root key file at (must not exist)")
	fs.Parse(args)
	if strings.TrimSpace(*keyPath) == "" {
		return errors.New("-key is required")
	}
	raw, err := readBackupFile(*backupPath)
	if err != nil {
		return err
	}
	pass, err := askPassphrase("Backup passphrase: ")
	if err != nil {
		return err
	}
	scalar, pub, err := openBackup(raw, pass)
	if err != nil {
		return err
	}
	if err := writeKeyFile(*keyPath, scalar); err != nil {
		return err
	}
	back, err := loadKey(*keyPath)
	if err != nil {
		return fmt.Errorf("the restored key file does not read back: %w", err)
	}
	if got, _ := controlplane.DeploymentRootKeyHex(&back.PublicKey); got != pub {
		return errors.New("the restored key file does not match the backup")
	}
	fmt.Printf("restored %s (DPAPI, this Windows account only)\npass_root_pubkey = %s\n", *keyPath, pub)
	return nil
}

// openBackup decrypts a backup and proves the scalar is the recorded key. A wrong passphrase, an
// edited file and a mismatched key all fail; none of them yields a different key.
func openBackup(raw []byte, passphrase string) ([]byte, string, error) {
	b, err := decodeBackup(raw)
	if err != nil {
		return nil, "", err
	}
	salt, err1 := hex.DecodeString(b.Salt)
	nonce, err2 := hex.DecodeString(b.Nonce)
	ct, err3 := hex.DecodeString(b.Ciphertext)
	if err1 != nil || err2 != nil || err3 != nil || len(salt) != 16 || len(nonce) != 12 {
		return nil, "", errors.New("the backup is damaged")
	}
	aead, err := gcmFor(passphrase, salt, b.Time, b.MemoryKiB, b.Threads)
	if err != nil {
		return nil, "", err
	}
	scalar, err := aead.Open(nil, nonce, ct, b.aad())
	if err != nil {
		return nil, "", errors.New("wrong passphrase, or the backup was changed")
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		return nil, "", errors.New("the backup does not hold a valid P-256 key")
	}
	pub, _ := controlplane.DeploymentRootKeyHex(&k.PublicKey)
	if pub != b.Pubkey {
		return nil, "", errors.New("the decrypted key does not match the backup's public key")
	}
	return scalar, pub, nil
}
