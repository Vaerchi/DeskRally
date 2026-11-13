package controlplane

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	const pw = "correct horse battery staple"
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("unexpected hash encoding: %q", hash)
	}
	// Never the plaintext.
	if strings.Contains(hash, pw) {
		t.Fatal("hash must not contain the plaintext password")
	}
	ok, err := VerifyPassword(hash, pw)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("correct password did not verify")
	}
}

func TestVerifyPasswordRejectsWrong(t *testing.T) {
	hash, err := HashPassword("s3cret-value")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := VerifyPassword(hash, "not-the-password")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Fatal("wrong password verified as correct")
	}
}

func TestHashesAreSaltedAndUnique(t *testing.T) {
	a, _ := HashPassword("same-password")
	b, _ := HashPassword("same-password")
	if a == b {
		t.Fatal("two hashes of the same password are identical — salt not applied")
	}
	// Both must still verify.
	for _, h := range []string{a, b} {
		ok, err := VerifyPassword(h, "same-password")
		if err != nil || !ok {
			t.Fatalf("salted hash failed to verify: ok=%v err=%v", ok, err)
		}
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	cases := []string{
		"",
		"not-a-phc-string",
		"$argon2id$v=19$m=65536,t=1,p=4$only-four-parts",
		"$bcrypt$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA", // wrong algorithm
	}
	for _, c := range cases {
		ok, err := VerifyPassword(c, "whatever")
		if ok {
			t.Fatalf("malformed hash %q verified as ok", c)
		}
		if err == nil {
			t.Fatalf("malformed hash %q returned nil error", c)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	// A hash at weaker-than-default params should want a rehash.
	weak := Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}
	h, err := HashPasswordWith("pw", weak)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	if !NeedsRehash(h) {
		t.Fatal("hash under weak params should need rehash")
	}
	// A default hash should not.
	def, _ := HashPassword("pw")
	if NeedsRehash(def) {
		t.Fatal("default-params hash should not need rehash")
	}
}
